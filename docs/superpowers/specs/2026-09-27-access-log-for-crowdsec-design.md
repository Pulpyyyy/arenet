<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# An access log CrowdSec can read — design

**Target version**: v2.50.0
**Date**: 2026-09-27
**Origin**: the operator, after testing the CrowdSec integration: *"pour
que CrowdSec puisse fonctionner il faut qu'il puisse lire les logs de
Arenet"*. They are right, and it exposes a gap nothing else had.

---

## The gap

Arenet emits **no access log at all**. Verified: no `logs` field on any
emitted HTTP server, no `logging` block anywhere in `internal/caddymgr`.
What appears in `journalctl -u arenet` is Caddy's *runtime* log plus
Arenet's own `slog` text output — neither carries a single request.

So a CrowdSec agent installed next to Arenet has **nothing to parse**.
It still enforces the community blocklist, which is worth having, but it
detects nothing about what is actually attacking this host. The detection
half of CrowdSec is switched off and nothing says so.

This corrects something I told the operator on 2026-09-26: that the
*backend* must feed CrowdSec its logs. True for a mail server and its
IMAP auth failures. **False for HTTP routes** — there, Arenet is the
front door. It is the only component that sees every request, every
scanning 404, every auth attempt; the backend sees only what Arenet
chose to forward.

## What the loop looks like once closed

Nothing needs to be written on the detection side, which is the good news:

1. Arenet writes a JSON access log.
2. A CrowdSec agent parses it with the **existing** `crowdsecurity/caddy`
   collection (v0.2: the `caddy-logs` parser + `base-http-scenarios`).
3. Scanning and brute force produce a decision in LAPI.
4. Arenet's bouncer refuses that IP — on routes, on the catch-all since
   v2.49, and on the layer-4 relays.

**The missing brick is the log, not the detection.**

### Why the format is not a choice

The parser reads specific fields (`parsers/s01-parse/crowdsecurity/caddy-logs.yaml`):
`request.client_ip`, `status`, `request.uri`, `request.method`,
`request.headers['User-Agent'][0]`, `request.host`,
`resp_headers['Www-Authenticate']`, `logger`, `ts`.

Caddy's own access log emits all of them. The one worth checking was
`client_ip`, which is written only when a context var is set
(`caddyhttp/marshalers.go:44`) — and `PrepareRequest` sets it
unconditionally for every request, falling back to the remote address
when no trusted proxy is configured (`caddyhttp/server.go:987-990`). So
it is always present.

Conclusion: emit Caddy's **stock JSON access log**, unmodified. Any
Arenet-specific shape would mean maintaining a parser too.

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Off by default, enabled by a settings toggle** | The log records every visitor's IP and every URL they asked for. That is personal data and a disk cost; both are the operator's call, not a default. The toggle's own text says what it is for, so enabling it is an informed act rather than a discovered one |
| D2 | **Default path `<data-dir>/logs/access.log`**, operator-overridable | Not `/var/log/arenet/`, however conventional: the systemd unit runs `ProtectSystem=strict` with `ReadWritePaths=/var/lib/arenet` (arenet.service:60,66), so **everything under /var/log is read-only to the service** and a log configured there would fail at runtime with nothing on screen to explain it. The data dir is also the Docker volume, so the log survives a container being replaced |
| D3 | **Rotation is always on and not optional**, with a ceiling the UI computes and shows | Caddy's own defaults are 100 MB × 10 files ≈ **1 GB** (`modules/logging/filewriter.go:251-262`) — fine for a server, not for a homelab SSD. Arenet defaults to 10 MB × 5, gzipped, and the form prints the worst case in megabytes, because that is the number the operator actually wants to know |
| D4 | **Encoder pinned to `json` explicitly** | Caddy picks console or JSON at runtime depending on whether stderr is a terminal (`logging.go:735-748`). The whole point here is machine parsing, so the format must not depend on how Arenet happens to be started |
| D5 | **Both the HTTP and HTTPS servers log to it**, under one logger name | A scanner probes port 80 as readily as 443. One file keeps the CrowdSec acquisition to a single entry |
| D6 | **Arenet does not write CrowdSec's acquisition file** | That file belongs to the agent, which may be a container or another host entirely. Arenet showing the exact snippet to paste is honest; Arenet reaching into `/etc/crowdsec` is not |
| D7 | **The admin plane is not in this log, and the UI says so** | The admin API is served by chi on :8001, not by Caddy, so admin login attempts never reach it. They are already covered: auth failures land in the audit store and feed the auto-classify engine, which pushes its own bans |
| D8 | **Enabling, disabling or repathing reloads Caddy and is audited** | Same contract as every other setting that changes emission |

### On D1, and saying it plainly

An operator who leaves this off gets CrowdSec's community blocklist and
nothing else. That is a real, useful layer — but it is not detection, and
the toggle's help text has to say so rather than implying CrowdSec is
"working" either way. The UI should state the trade in one sentence: what
it writes down, and what it buys.

---

## Shape

A new settings singleton, alongside the route-check config:

```json
{"enabled": false,
 "path": "",
 "rollSizeMB": 10,
 "rollKeep": 5,
 "compress": true}
```

`path` empty means the default under the data dir; the resolved absolute
path is returned by the API so the UI can print exactly what to hand to
CrowdSec.

Emitted config, when enabled:

```json
"logging": {"logs": {"arenet_access": {
  "writer": {"output": "file", "filename": "…/logs/access.log",
             "roll_size_mb": 10, "roll_keep": 5, "roll_gzip": true},
  "encoder": {"format": "json"},
  "include": ["http.log.access.arenet_access"]
}}}
```

and `"logs": {"default_logger_name": "arenet_access"}` on both servers.

The exact `include` name and the server-side field are an **empirical
gate**, not an assumption — see G1.

---

## Where the file actually lands

The operator asked this directly, and the answer differs per install
method because the data dir does. Verified against the unit, the compose
file and the config defaults rather than assumed.

| Install | Data dir | Access log | Owner / mode |
|---|---|---|---|
| **systemd** | `/var/lib/arenet` (`arenet.service:43`) | `/var/lib/arenet/logs/access.log` | `arenet:arenet`, file `0600`, dir `0700` |
| **Docker** | `/var/lib/arenet` in the container = named volume `arenet-data` (`docker-compose.yml:85,102`) | `/var/lib/arenet/logs/access.log` **inside** the container | uid `65532` (distroless nonroot), file `0600`, dir `0700` |
| **dev** (`make run`) | `./data` (`internal/config/config.go:139`) | `./data/logs/access.log` | the developer's own user |

`0600` / `0700` are Caddy's, not a choice of ours
(`modules/logging/filewriter.go:190,201`).

### What that means for the CrowdSec agent

**systemd.** Acquisition reads the path directly:

```yaml
filenames: [/var/lib/arenet/logs/access.log]
labels: { type: caddy }
```

The file is `0600` owned by `arenet`, so the agent must be **root** —
which the package install is by default. The operator confirms with
`systemctl show crowdsec -p User` rather than taking our word for it.

**Docker.** The file lives inside the `arenet-data` volume, whose host
path is an implementation detail of the Docker daemon
(`docker volume inspect arenet-data`) and must not be hard-coded in docs.
A CrowdSec **container** mounts the volume read-only instead:

```yaml
crowdsec:
  volumes:
    - arenet-data:/var/lib/arenet:ro
```

and must run as root to read a `0600` file owned by uid 65532. The
official CrowdSec image does.

| # | Decision | Rationale |
|---|---|---|
| D9 | **Keep Caddy's `0600`/`0700`; do not expose a mode setting** | The log is a list of every visitor's IP and the URLs they asked for. A knob inviting `0644` would turn a restrictive default into a world-readable one on someone's shared host. Both supported topologies run the agent as root, so nothing needs widening — and where it does, that is a prerequisite to document, not a default to weaken |
| D10 | **The settings panel prints the resolved absolute path and the acquisition snippet** | Arenet knows its own data dir, so it can state the exact path instead of leaving the operator to work out which of three it is. This is the difference between a feature that works and one that silently never fires, which is the failure mode this whole subject keeps producing |

---

## Documentation to update

Not an afterthought: a feature whose entire value is "a second program
reads this file" is documentation-shaped, and the wiki is what operators
actually read (the v2.49 CrowdSec page was Docker-only for months
precisely because nobody checked).

- `docs/wiki-seed/CrowdSec.md` + `-FR.md` — a section on turning
  detection on: the toggle, the resolved path per install method, the
  acquisition snippet, the collection to install
  (`cscli collections install crowdsecurity/caddy`), and the permission
  note. Both languages, in real French.
- `docs/setup/crowdsec.md` — the same wiring at the level of detail that
  file already uses, including the Docker sibling-container case.
- `docs/operations/env-vars.md` — any `ARENET_*` variable this adds.
- `docs/wiki-seed/Troubleshooting.md` + `-FR.md` — "CrowdSec bans
  nothing": check the toggle, check the file is growing, check
  `cscli metrics` shows the acquisition reading lines, check the agent
  can read the file at all.
- `docs/roadmap.md` — stays uncommitted per the operator's standing rule.

---

## Empirical validation gates

1. **G1 — the emitted config loads and actually routes.** `caddy.Validate`
   on the config with the logger, plus a real request against a running
   instance that must appear in the file. Validate alone would pass on a
   logger nothing writes to; the wiring between a server's
   `default_logger_name` and a `logging.logs` entry is exactly the kind
   of thing that looks right and does nothing.
2. **G2 — `request.client_ip` is present in a real line.** The whole
   feature rests on it: the CrowdSec parser reads that field and no
   other for the source address. Asserted against a line Arenet actually
   wrote, not against the Caddy source.
3. **G3 — rotation bounds the directory.** Write past the roll size and
   assert the file count stops growing and old files are removed. A log
   that fills a homelab disk is worse than no log.
4. **G4 — non-regression.** Disabled, the emitted config is
   byte-identical to v2.49.
5. **G5 — the CrowdSec parser accepts an Arenet line.** The real gate,
   and it needs a live agent: `cscli explain --file <arenet line>` must
   parse it and reach a scenario. Smoke, not unit test — and until it
   passes, this feature is unproven however green the suite is.

---

## Non-goals

**Per-host opt-out, custom fields, log levels.** A scanner does not
respect a filter list, and every knob here is a way to produce a log
CrowdSec cannot use.

**Shipping or editing the CrowdSec acquisition config.** See D6.

**A log viewer in the UI.** `/logs` already shows WAF, rate-limit, auth
and certificate events from the observability store; a raw request log is
for machines, and duplicating it on screen would invite the operator to
read what they should be filtering.

**Writing to stdout instead of a file.** Defensible in Docker, and it is
what a container purist would want — but the CrowdSec collection expects
a file, journald parsing needs a different datasource, and mixing request
JSON into the stream that already carries Arenet's text log is how the
current confusion started. A file keeps one thing in one place.
