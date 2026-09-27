<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — the access log, and CrowdSec detecting something (v2.50.0)

Spec: `docs/superpowers/specs/2026-09-27-access-log-for-crowdsec-design.md`.

**Read this first.** The unit tests prove the emitted config loads, that
both servers carry `default_logger_name`, and that the `include` is the
name Caddy composes. **They do not prove a single request reaches the
file**, and running a real Caddy inside the suite was rejected on purpose
— it would bind :8080/:8443 on a developer's machine and fight
`make run`. So the end-to-end proof is here, and until §4 passes this
feature is unproven however green CI is.

The failure this is built to catch: a logger the config declares, the
file created, and not one line ever written. It loads perfectly.

---

## 0. Before you start

| | |
|---|---|
| Version | `v2.50.0` |
| Install | do this on **both** topologies if you run both; the path differs |
| Needed for §4 | a CrowdSec agent that can read the file |

Timestamp every action.

---

## 1. Non-regression: off means off

1. Upgrade. Do not touch the setting.
2. `Settings → Security` shows **HTTP access log** with the badge **Off**,
   and no path or rotation fields.
3. No file appears at either candidate path.
4. Traffic still flows. Nothing in the Caddy config changed — if you want
   to be sure, compare the emitted config before and after; it is
   byte-identical, which a test also asserts.

---

## 2. Turning it on

1. Tick **Write an access log**. The card reveals the path it will use.
2. **Read that path.** It is the one thing only the server can tell you:
   - systemd → `/var/log/arenet/access.log`
   - Docker → `/var/lib/arenet/logs/access.log` *inside the container*
   - dev → `./data/logs/access.log`
3. Note the ceiling sentence. With the defaults it says about **60 MB**.
   Change *Rotate at* to 20 and it says 120. This is the number that
   matters; "10 MB, 5 files" is not.
4. Save. The toast confirms, and **Caddy reloads** — the log is part of
   the emitted config, so nothing happens without a reload.

### The file appears and grows

```bash
# systemd
sudo ls -l /var/log/arenet/
sudo tail -f /var/log/arenet/access.log

# Docker
docker exec arenet ls -l /var/lib/arenet/logs/   # distroless has no shell:
# if that fails, check from the host via the volume:
docker volume inspect arenet-data
```

Load any route through Arenet. A line must appear **immediately**.

> **If the file exists but stays empty, stop.** That is exactly the
> failure mode described at the top: the sink is declared and no server
> feeds it. Report it — do not work around it.

### The line is JSON, and carries client_ip

```bash
sudo tail -1 /var/log/arenet/access.log | python3 -m json.tool | head -30
```

Check, by eye:

- it is **JSON**, not console text. If it is text, the encoder is not
  pinned and the parser will read nothing.
- `request.client_ip` is **present**. This is the field the CrowdSec
  parser reads for the source address — not `remote_ip`. Its absence
  means CrowdSec sees requests with no attacker.
- `request.host`, `request.uri`, `request.method`, `status` and
  `request.headers` are there too.

---

## 3. Rotation actually bounds it

The point of the ceiling is that a homelab disk does not fill.

1. Set *Rotate at* to **1** MB and *Files kept* to **2**. Save.
2. Generate traffic until the file rolls — a loop of a few thousand
   requests, or `while true; do curl -s -o /dev/null http://…; done` for a
   while.
3. `sudo ls -l /var/log/arenet/` shows the live file plus at most 2
   rotated ones, gzipped if compression is on.
4. Keep going. The count must **stop growing**. A directory that keeps
   accumulating is the bug this step exists for.
5. Put the settings back.

---

## 4. G5 — CrowdSec actually parses it

**This is the gate.** Everything above can pass while CrowdSec still
learns nothing.

### Wire the agent

```bash
sudo cscli collections install crowdsecurity/caddy
```

Acquisition — systemd:

```yaml
# /etc/crowdsec/acquis.d/arenet.yaml
filenames:
  - /var/log/arenet/access.log
labels:
  type: caddy
```

Docker: mount the volume read-only into the CrowdSec container instead
(`arenet-data:/var/lib/arenet:ro`) and point `filenames` at
`/var/lib/arenet/logs/access.log`.

```bash
sudo systemctl restart crowdsec
```

### Prove the parser accepts an Arenet line

```bash
sudo cscli explain --file /var/log/arenet/access.log --type caddy | head -40
```

Expected: the line is parsed, `crowdsecurity/caddy-logs` appears, and
fields are extracted. A line that reaches `parser failure` means the
format or a field name is wrong — that is a real finding, not a
configuration detail.

### Prove lines are being read continuously

```bash
sudo cscli metrics | grep -A 5 Acquisition
```

The Arenet file must appear with a **non-zero and rising** line count.
Zero means the agent cannot read it — almost always **permissions**:
Caddy writes the file `0600`, so the agent must be root.

```bash
systemctl show crowdsec -p User      # expect root (or empty = root)
sudo -u crowdsec head -1 /var/log/arenet/access.log   # if it runs non-root
```

### Prove a decision is created

Trigger something a scenario catches — a burst of 404s from another
machine is the easiest:

```bash
for i in $(seq 1 60); do curl -s -o /dev/null "https://<your-host>/nonexistent-$i"; done
```

Then:

```bash
sudo cscli decisions list
```

A decision for your source IP, with a `crowdsecurity/http-*` scenario, is
the loop closing. **Arenet then refuses that IP itself** — on its routes,
on the catch-all, and on the layer-4 relays.

> If §4 produces a decision, this feature works. If it does not, say so
> plainly rather than accepting "the file looks right".

---

## 5. Turning it off again

1. Untick and save. Caddy reloads.
2. The file stops growing. It is **not deleted** — deleting an operator's
   log on a settings change would be presumptuous. Remove it yourself if
   you want the disk back.
3. The audit trail carries `access_log_updated` for both directions:
   enabling starts recording people, disabling blinds CrowdSec, and both
   are worth a trace.

---

## Verdict

| # | Step | Result | Notes |
|---|---|---|---|
| 1 | Non-regression, off | | |
| 2 | Path shown, file grows, JSON with `client_ip` | | |
| 3 | Rotation bounds the directory | | |
| 4 | **G5** — `cscli explain` parses, metrics rise, decision created | | |
| 5 | Off again, audited | | |

Findings go in `docs/backlog-*.md` with the timestamp of the action that
produced them.
