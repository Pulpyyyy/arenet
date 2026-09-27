<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — layer-4 protocol filtering and refusal counters (v2.49.0)

Spec: `docs/superpowers/specs/2026-09-26-l4-protocol-filter-design.md`.

**Why this document exists.** The unit tests prove the emitted config
loads in a real Caddy for every offered protocol, that each gate owns
its cause, and that the form does not drop the field on save. They prove
**nothing** about whether a matcher recognises real traffic, because
that needs real traffic. Everything below is the half a test cannot
reach — and it is the half that found six defects the last time.

---

## 0. Before you start

| | |
|---|---|
| Version | `v2.49.0` |
| Host | the test host, not production |
| Needed | `nc` / `openssl`, and an SSH server or any TCP backend |

Timestamp each action. The 2026-09-24 session lost an hour to comparing
a `curl -I` with a `curl -i` — two different requests — so write down
exactly what you ran.

---

## 1. Non-regression first

An existing relay must behave exactly as it did in v2.48.

1. Pick a relay that already works. Do **not** touch it.
2. Reload the page. The new **Refused** column shows `none`, not `—`.
   `—` means the service has no counters at all, which is a different
   thing and would be a finding.
3. Use the service. Traffic still flows, and `Refused` stays at `none`.

> **A refusal must never inflate the traffic figures.** The counters mean
> "reached the backend"; if `Refused` climbs and `conn.` climbs with it,
> that is a bug — report it.

---

## 2. The protocol gate accepts what it should

Set up a relay in front of something that speaks a protocol on the list,
SSH being the easiest.

1. New service, TCP, listen on a spare port, backend = your SSH server.
2. **Accepted protocol** = `ssh`. Save.
3. `ssh -p <port> user@<arenet-host>` → **the session opens normally**.
4. `Refused` stays at `none`.

If the session does *not* open, stop: the matcher is rejecting real
traffic, and the gate is emitted as a negation, so it would refuse
everything. That is the failure this step exists to catch.

---

## 3. The protocol gate refuses what it should, and says so

Same relay, still `ssh`.

```bash
# Speak something that is plainly not SSH.
printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' | nc <arenet-host> <port>
```

Expected: the connection is **closed** with no reply.

Then reload the services page:

- **Refused** shows `1 wrong protocol`;
- `conn.` did **not** move;
- the bytes did not move either.

Repeat twice. The counter reaches 3. A counter that jumps by two per
attempt would mean the refusal is being counted on more than one route.

---

## 4. Each cause is attributed separately

This is the whole point of the change, so test the causes together.

1. On the same service, add a **source filter** in allow mode listing a
   CIDR that does **not** contain your client.
2. Connect from your client. Expected: closed, and `Refused` gains
   `1 source filter` — **not** `wrong protocol`. The address gate runs
   first, which is deliberate: it decides from the socket alone.
3. Remove the filter. Ban your own client IP in CrowdSec — and read
   §"Banning yourself" below, because the obvious command bans the wrong
   host.
4. Connect. Expected: closed, and `Refused` gains `1 CrowdSec`.

A refusal landing under the wrong cause is a finding: the operator would
be sent to fix the wrong field.

### Banning yourself

`curl -s ifconfig.me` run **on the Arenet host** returns the *server's*
address, not your client's. Get yours from the machine you will connect
from, and mind the address family:

```bash
# on your laptop
curl -4 -s https://ifconfig.me
curl -6 -s https://ifconfig.me
# then, on the Arenet host
sudo cscli decisions add --ip <that address> --duration 60s
sudo cscli decisions list        # check Scope:Value
```

A ban on the wrong family does nothing at all.

---

## 5. UDP

1. New service, **UDP**, listen on a spare port.
2. Open the **Accepted protocol** list. It must offer `wireguard`, `dns`
   and `openvpn`, and **must not** offer `tls` or `ssh`.
3. Choose `wireguard`, then switch the transport back to **TCP**. The
   protocol must clear itself rather than stay on a value TCP cannot
   carry.
4. With `dns` on a UDP relay pointed at a resolver, `dig @<arenet-host>
   -p <port> example.com` resolves, and `Refused` stays at `none`.

---

## 6. The catch-all consults CrowdSec (D8)

Only meaningful with a bouncer configured.

1. With **no** ban in place, browse a hostname Arenet does not serve →
   the usual **404** page.
2. Ban your client IP (§"Banning yourself"). Browse that same unknown
   hostname → **403**, not 404.
3. Let the ban expire → 404 again.
4. Stop the CrowdSec agent (`sudo systemctl stop crowdsec`). Browse the
   unknown host → still **404**. **This is the important one**: a dead
   LAPI must not turn the catch-all into a wall. Restart the agent.

> Step 1 is what confused the operator on 2026-09-26: the bouncer used
> to sit only in each route's chain, so an unknown host never reached it.
> Test on a host Arenet does not serve, which is exactly what the
> catch-all is.

---

## 7. Refusals survive a reload, and reset on restart

1. Note a non-zero `Refused`.
2. Change something unrelated and save, so Caddy reloads. The counter
   **keeps** its value: the registry is only re-synced for services that
   changed.
3. Restart Arenet. The counter is back to `none` — these are
   process-lifetime counters, by decision (D9), not persisted history.

---

## Verdict

| # | Step | Result | Notes |
|---|---|---|---|
| 1 | Non-regression | | |
| 2 | Protocol accepted | | |
| 3 | Protocol refused + counted | | |
| 4 | Causes attributed separately | | |
| 5 | UDP offer and clearing | | |
| 6 | Catch-all + CrowdSec, incl. LAPI down | | |
| 7 | Counter lifetime | | |

Findings go in `docs/backlog-*.md` with the timestamp of the action that
produced them.
