<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# CrowdSec — Setup guide for Arenet

> Configure the CrowdSec bouncer that ships embedded in Arenet
> (Step CS.1). Arenet is **deployment-agnostic**: it talks to
> any reachable LAPI HTTP endpoint. The doc below walks through
> the three common topologies, the bouncer-key generation, and
> a tiered list of recommended scenarios.

## What Arenet does with CrowdSec

Arenet embeds the `caddy-crowdsec-bouncer` module
(`github.com/hslatman/caddy-crowdsec-bouncer v0.12.1`) and wires
it into the Caddy request chain at **position #2**, between the
metrics counter (#1) and the country-block gate (#3, when
enabled). The full pre-WAF chain order is:

```
metrics  →  country_block  →  crowdsec  →  WAF / auth / route
```

**Important implication**: if you configure both country-block
and CrowdSec on the same route, the country-block decision
fires FIRST. An IP from a blocked country is rejected before
the CrowdSec bouncer ever sees the request. This is intentional
— geo lookups are local (cheap, deterministic); LAPI calls cross
a process boundary (expensive, fail-open if LAPI is down). The
trade-off: you'll see fewer CrowdSec decisions on routes with
country-block enabled, because country-block already filtered
those sources upstream. For full CrowdSec visibility, leave
country-block off on at least one observability-target route.

The bouncer's decisions feed Arenet's GeoEvent sink and land in
`/observability/logs` alongside WAF + country-block events, with
the existing geo enricher attaching country / city / lat / lon.

## A — Deployment options

Arenet does not assume any deployment topology. The LAPI URL
field accepts any `http(s)` URL the Arenet process can reach.

### Option A.1 — apt install on the same host

Recommended when Arenet runs as a systemd service or directly
as a binary on a Linux host.

```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec
sudo systemctl enable --now crowdsec
```

Verify the engine is listening on the default LAPI port:

```bash
ss -tlnp | grep 8080
# tcp  LISTEN  0  4096  127.0.0.1:8080  0.0.0.0:*  users:(("crowdsec",pid=...,fd=...))
```

LAPI URL to use in Arenet Settings → CrowdSec bouncer:
`http://127.0.0.1:8080`

### Option A.2 — Docker container with ports mapping

Recommended for homelab Docker deployments where Arenet runs on
the host and CrowdSec runs in a container with port 8080 mapped
back to the host.

```yaml
# docker-compose.yml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
      - /var/log:/var/log:ro
    restart: unless-stopped

volumes:
  crowdsec-config:
  crowdsec-data:
```

LAPI URL to use: `http://127.0.0.1:8080` (same as Option A.1,
because the port is mapped to loopback).

### Option A.3 — Arenet + CrowdSec as sibling containers

Recommended when both Arenet and CrowdSec run as containers in
the same Docker compose network.

```yaml
# docker-compose.yml
services:
  arenet:
    image: ghcr.io/barto95100/arenet:latest
    depends_on: [crowdsec]
    networks: [arenet-net]
    # ... other Arenet config

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    networks: [arenet-net]
    volumes:
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    restart: unless-stopped

networks:
  arenet-net:

volumes:
  crowdsec-config:
  crowdsec-data:
```

LAPI URL to use: `http://crowdsec:8080` (Docker DNS resolves
the `crowdsec` service name to the container IP within the
shared network).

## A.4 — Enable the access log (the detection half)

Everything in §A gets the **bouncer** working: Arenet reads
decisions from LAPI and refuses the IPs they name. That alone
gives you the community blocklist.

It does not make CrowdSec detect anything about *this* host.
For that the agent needs requests to parse, and until v2.50
Arenet emitted **no access log at all** — no `logs` on any
server, no `logging` block. An agent installed beside it
therefore enforced the community list and detected nothing
local, with nothing saying so.

Turn it on in **Settings → Security → HTTP access log**. It is
off by default: the file records every visitor's IP address
and the URLs they request, which is the operator's decision to
make rather than a default to inherit.

The card prints the **resolved path**, and that is the value to
use below — the default depends on how Arenet is installed,
and only the running process knows which applied:

| Deployment | Access log | Owner / mode |
|---|---|---|
| A.1 — apt / systemd | `/var/log/arenet/access.log` | `arenet:arenet`, dir `0755`, file `0600` |
| A.2 — Arenet on the host, CrowdSec in a container | `/var/log/arenet/access.log` | same; mount it into the agent read-only |
| A.3 — both in containers | `/var/lib/arenet/logs/access.log` **inside** the Arenet container, i.e. in the `arenet-data` volume | uid `65532`, dir `0700`, file `0600` |

Under systemd the directory comes from `LogsDirectory=arenet`
in the unit, which creates it with the service's ownership and
is implicitly exempt from `ProtectSystem=strict`. That is why
the log can live in `/var/log` at all: without that directive
the whole hierarchy is read-only to the service and the write
would fail at runtime.

In a container the log deliberately stays inside the volume.
`/var/log` there belongs to the writable layer, so the file
would be destroyed by the next container replacement — which
is what an upgrade is.

Rotation is not optional. The defaults are 10 MB across 5
files, gzipped, and the form prints the resulting ceiling in
megabytes. Caddy's own defaults would be 100 MB × 10, about a
gigabyte, which is not a homelab default.

Then install the collection and wire acquisition:

```bash
sudo cscli collections install crowdsecurity/caddy
```

```yaml
# /etc/crowdsec/acquis.d/arenet.yaml — systemd (A.1, A.2)
filenames:
  - /var/log/arenet/access.log
labels:
  type: caddy
```

For A.3, mount the volume read-only into the agent
(`arenet-data:/var/lib/arenet:ro`) and read
`/var/lib/arenet/logs/access.log` instead.

The format is Caddy's stock JSON, unmodified, because that is
what `crowdsecurity/caddy` already parses — it reads
`request.client_ip`, `status`, `request.uri`,
`request.method`, `request.host` and the headers. Inventing an
Arenet-shaped log would have meant shipping a parser too.

Verify before trusting it — see §E "Acquisition wiring".

## B — Generate a bouncer API key

The bouncer key is the credential Arenet uses to authenticate
against LAPI. Generated once via `cscli`; if lost, you must
delete the bouncer entry and create a new one (the secret is
displayed only at creation time).

```bash
# On the host running CrowdSec (or `docker exec` into the container)
sudo cscli bouncers add arenet
# Api key for 'arenet':
#
#    abc123def456ghi789jkl0123456789mnopqrstuvwxyz
#
# Please keep this key since you will not be able to retrieve it!
```

Paste the key into Arenet UI: **Settings → CrowdSec bouncer →
Bouncer API key**, save & apply. Click **Test connection** to
verify; the badge should turn green and show the LAPI version.

The bouncer name (default `arenet`) is cosmetic — LAPI
identifies the bouncer by its API key, not its name. The name
shows up in `cscli bouncers list`, useful for the operator
auditing which bouncer connected to LAPI.

## C — Verify connectivity from Arenet

If the **Test connection** button in the UI returns a failure,
verify the LAPI is reachable from the Arenet process:

### From the Arenet host (Option A.1, A.2):

```bash
curl -i \
  -H "X-Api-Key: <YOUR_BOUNCER_KEY>" \
  http://127.0.0.1:8080/v1/decisions
# HTTP/1.1 200 OK
# Content-Type: application/json
# [...]
# []   (or a non-empty array if there are active decisions)
```

### From the Arenet container (Option A.3):

```bash
docker exec arenet sh -c \
  'curl -sS -i -H "X-Api-Key: <YOUR_BOUNCER_KEY>" http://crowdsec:8080/v1/decisions'
```

Expected response shapes:
- **`200 OK`** with a JSON array body → success, bouncer
  authenticated correctly
- **`204 No Content`** → success, no active decisions in LAPI
  (also accepted as "connected" by Arenet)
- **`403 Forbidden`** → wrong API key
- **`Connection refused`** → LAPI not running or wrong port
- **`no such host`** → DNS resolution failed (in Option A.3,
  check the compose network names)

## D — Recommended scenarios

CrowdSec scenarios are the detection rules that produce ban
decisions. Without scenarios, the local LAPI only emits
decisions from the CAPI (the CrowdSec community consensus
blocklist). Bouncer-only deployments work fine — see the
**Bouncer-only mode** note below.

### Tier 1 — Essential (install on every deployment)

Detection rules every Arenet operator benefits from. These run
against incoming HTTP requests + auth log patterns + the host
firewall.

```bash
sudo cscli collections install crowdsecurity/http-cve
sudo cscli collections install crowdsecurity/base-http-scenarios
sudo cscli collections install crowdsecurity/iptables
```

- `http-cve` — known-CVE pattern detection (Log4Shell,
  Spring4Shell, etc.).
- `base-http-scenarios` — generic HTTP attack patterns
  (path traversal, scanner fingerprints, etc.).
- `iptables` — protects against host-level abuse (SSH brute
  force, port scans).

### Tier 2 — Strongly recommended

Higher-noise scenarios that catch broader attack classes.
Enable when the Tier 1 baseline is stable and you want deeper
coverage.

```bash
sudo cscli collections install crowdsecurity/http-generic-bf
sudo cscli collections install crowdsecurity/http-dos
```

- `http-generic-bf` — generic brute force (login pages,
  password-spray patterns).
- `http-dos` — HTTP-layer DoS attempts (rate-bound floods).

### Tier 3 — Per-application

Install only when the corresponding upstream service exists in
the routes you proxy. Each adds parsers + scenarios tuned to a
specific app's log format.

```bash
# Home Assistant
sudo cscli collections install crowdsecurity/home-assistant

# Jellyfin
sudo cscli collections install crowdsecurity/jellyfin

# Many more — browse the hub:
#   https://app.crowdsec.net/hub/
```

After installing a collection, reload the engine:

```bash
sudo systemctl reload crowdsec
# or, in Docker:
docker restart crowdsec
```

### Bouncer-only mode (no local scenarios)

If installing scenarios feels like too much for a first
deployment, the bouncer works fine on its own. Without local
scenarios:

- No locally-generated decisions (no `arenet` will see `0` on
  scenarios installed)
- Arenet still receives the **CAPI consensus blocklist** — a
  community-aggregated list of malicious IPs updated every
  few minutes
- Active decisions visible via the CS.2 decisions list will be
  `source: CAPI`, type `ban`

This gives you immediate value (community blocklist) without
the operational complexity of tuning scenarios. Add scenarios
incrementally as the deployment stabilises.

## E — Troubleshooting

### "Connection refused"

LAPI is not running on the configured URL. Common causes:

- The CrowdSec service isn't started: `sudo systemctl status crowdsec`
- The Docker container has crashed: `docker logs crowdsec | tail -50`
- The LAPI is bound to a different interface than expected. By
  default it binds to `127.0.0.1:8080`; check
  `/etc/crowdsec/config.yaml` → `api.server.listen_uri`. If you
  changed it, update the Arenet Settings field to match.

### "Authentication failed (invalid bouncer API key)"

The key Arenet has doesn't match what LAPI knows. Common causes:

- Wrong key pasted (e.g. captured a trailing whitespace, missed
  characters)
- Bouncer was deleted from LAPI (`cscli bouncers list` will not
  show `arenet`) — re-create with `cscli bouncers add arenet`
- The key was rotated on LAPI (no UI for this; would have
  required `cscli bouncers delete arenet && cscli bouncers add arenet`)

Generate a fresh key with `cscli bouncers add arenet-new` (or
just `arenet` after deleting the old entry) and paste into
Arenet Settings.

### "Timeout (LAPI did not respond in time)"

LAPI is reachable but slow. Common causes:

- LAPI engine is under heavy load (large bucket population, slow
  disk)
- Network path between Arenet and LAPI is congested (only
  possible in Option A.3 cross-network setups)

Mitigations:
- Increase the timeout field in Arenet Settings (max 60s)
- Check LAPI logs: `journalctl -u crowdsec` for slow-query
  warnings

### "No decisions visible in the UI"

Expected on a fresh deployment with no threats yet. The CS.2
decisions panel (shipped after CS.1) will show:

- Empty state when there are no active CAPI consensus decisions
  AND no local scenario fires have produced bans yet
- A growing list as the CAPI sync runs (~every 2-15 minutes
  depending on the LAPI's pull cadence)

To confirm the bouncer IS connected even when empty: the
**Configured** badge in Arenet Settings → CrowdSec bouncer will
be green, and clicking **Test connection** will show
"Connected to LAPI v1.6.x".

### "Scenarios" tab is empty

The Scenarios tab in `/security/decisions` aggregates LAPI's
`/v1/alerts` response over a 24h window. An empty state means
**no scenario fired in the last 24h** — which can happen for
three reasons:

1. **No attacks landed.** The most common case on a quiet
   homelab. The Live LAPI tab + CAPI consensus blocklist may
   still be working (the blocklist is loaded; nothing local
   has triggered a scenario fire).
2. **Arenet logs aren't acquired by CrowdSec.** Scenarios fire
   only when CrowdSec sees a log line that matches a parser.
   By default, CrowdSec doesn't tail Arenet's stdout; you have
   to wire an acquisition source. See
   [§Acquisition wiring](#acquisition-wiring) below.
3. **Security Automation not configured.** The Scenarios tab
   uses the watcher credentials from Settings → Security
   Automation. The tab will surface a clear "Security
   Automation non configurée" card with a direct link rather
   than the empty state in this case.

### "Scenarios" tab shows "machine credentials rejected"

The Security Automation watcher creds were accepted at write-
time but LAPI now rejects them. Common causes:

- The watcher was deleted on the LAPI host (`cscli machines
  delete arenet-writer`) and re-added with a different
  password.
- LAPI was restored from a backup that pre-dates the watcher.
- The password was rotated outside the Arenet UI.

Fix: regenerate the watcher (`cscli machines delete arenet-writer
&& cscli machines add arenet-writer`) and paste the new
credentials in Settings → Security Automation. The Scenarios
tab will auto-recover on the next poll (the JWT cache
invalidates on the first 401).

### Acquisition wiring

To get scenario fires from Arenet traffic, CrowdSec needs to
parse Arenet's access log — which §A.4 turns on. Point the
agent at the path that section resolves. Example
`/etc/crowdsec/acquis.yaml` entry for a systemd install:

```yaml
filenames:
  - /var/log/arenet/access.log
labels:
  type: caddy
```

Then `sudo systemctl reload crowdsec` and tail
`journalctl -u crowdsec -f` while running curl against your
routes — you should see `parsing line ...` entries. Once a
scenario like `crowdsecurity/http-cve` matches enough events
to overflow its bucket, an alert is created and the
Scenarios tab populates within 30 minutes (the next poll
after `since=24h` shifts past it).

Arenet still bundles no parser and writes no acquisition file
— CrowdSec's parser ecosystem is its own concern, and the
agent may well live on another host. What changed in v2.50 is
the other half: **Arenet now writes the log**, which until
then it did not, so this section described a file the operator
had to conjure themselves. See §A.4.

If the acquisition reads zero lines, it is nearly always
permissions rather than format: Caddy creates the file `0600`
owned by the Arenet user, so the agent has to be root. Check
with `systemctl show crowdsec -p User` and confirm with
`sudo cscli metrics | grep -A 5 Acquisition` — a file listed
with a count that stays at zero is the symptom.

## F — Settings precedence (env vs. UI)

Arenet reads CrowdSec config from two sources, with this
precedence:

1. **Stored row** (BoltDB, written via Settings UI) — highest
   priority. Once you save anything from the UI, the stored
   value is source of truth.
2. **Environment variables** — `ARENET_CROWDSEC_API_URL` and
   `ARENET_CROWDSEC_API_KEY` — used as bootstrap default for
   first-boot or as an emergency override when the operator
   cannot log in.

To revert to env-driven config: PUT an all-empty row from the
UI (or delete the BoltDB row directly), then restart Arenet
with the env vars set.

To rotate the key from env to UI: log in, paste the new key in
the Settings UI, click Save & apply. Remove the env vars on the
next deploy (they'll be ignored as long as a stored row exists,
but removing avoids accidental future regression).

### Disabling the bouncer

Settings → CrowdSec bouncer has a **Réinitialiser** button at
the bottom-left of the form (only visible when the bouncer is
currently configured). It is the operator-recommended way to
disable the IP-reputation gate cleanly:

- BoltDB row is wiped via `DELETE /api/v1/settings/crowdsec`.
- Embedded Caddy hot-reloads with `apps.crowdsec` omitted —
  the bouncer module drops out of the request chain
  immediately.
- Audit log emits `crowdsec_reset` (distinct from
  `crowdsec_updated`) so the deliberate "I want this off"
  intent is traceable in `/audit`.
- Confirm dialog warns: "Le bouncer s'arrêtera immédiatement
  de gater le trafic. Les routes resteront protégées par le
  WAF + rate-limiter, mais la gate IP-reputation sera
  désactivée."
- **Security Automation watcher credentials are NOT touched**
  — those persist across a bouncer reset so the auto-classify
  config + the Scenarios tab keep working. If you also want
  to wipe Security Automation, that's a separate action via
  Settings → Security Automation submitting all-blank.

To rollback after a Reset, paste the bouncer API key again
into the UI and click Save & apply — the row + audit
`crowdsec_configured` event will recreate cleanly.

The legacy "PUT with all fields blank" path still works
(idempotent) but emits `crowdsec_updated`, which is less
discoverable in the audit log. Reset is preferred.

## G — Why the Scenarios tab needs Security Automation

The Scenarios tab in `/security/decisions` queries LAPI's
`/v1/alerts` endpoint to aggregate per-scenario activity over
the last 24h. **Important**: that endpoint is part of LAPI's
`MachineRoutes` group and requires **JWT authentication** —
the bouncer API key configured in CS.1 does NOT work on
`/v1/alerts` (empirical: LAPI returns
`401 cookie token is empty`).

LAPI's `MachineRoutes` are authenticated via a **watcher
credential** (a `cscli machines add <name>` pair) — exactly
the credential type already configured by **Security
Automation** for the auto-write path (POST
`/v1/alerts` to push decisions back to LAPI).

Rather than ask the operator to register a second watcher
just for read access, Arenet reuses the Security Automation
credentials for both:

- **Write path** (auto-classify): POST `/v1/alerts` to LAPI.
- **Read path** (Scenarios tab): GET `/v1/alerts` from LAPI.

CrowdSec's auth model doesn't distinguish read-machine vs
write-machine — one login grants both. The coupling has one
operator-visible consequence: if you want the Scenarios tab
but NOT the auto-writer, you still have to register a
watcher and provide its credentials. The auto-writer's
behaviour is controlled by **per-category rule toggles**
(Settings → Security Automation → Trigger rules); leave all
toggles off if you want creds-only-no-writes.

Lifecycle:

- The JWT is **cached in-memory** per Arenet process, valid
  for ~1 hour per LAPI's expiry.
- **Singleflight dedupes** concurrent Scenarios polls during
  a JWT refresh — 5 simultaneous browser tabs → 1 login
  round-trip, not 5.
- On a **401 from `/v1/alerts`** (LAPI rotated keys, watcher
  password changed, etc.), Arenet **automatically refreshes**
  the JWT once and retries. A second 401 surfaces as a
  502 with the message "machine credentials rejected by
  LAPI — re-verify Settings → Security Automation".
- The Live LAPI tab + Local snapshot tab work
  **independently** of this coupling — they use the bouncer
  API key (CS.1), not the watcher credentials.

If you only need bouncer-side decision visibility (Live LAPI
+ Local snapshot tabs) and don't intend to use the Scenarios
tab, you can leave Security Automation unconfigured. The
Scenarios tab will surface "Security Automation non
configurée" with a CTA to Settings, the other two tabs work
normally.

## H — Audit trail

Every CrowdSec settings change emits an audit event:

- First PUT of a stored row → `crowdsec_configured`
- Subsequent PUTs → `crowdsec_updated`
- The audit payload carries the LAPI URL + bouncer name; the
  API key is **always blanked** before the audit write (secret
  scrubbing mirror of OIDC / DNS provider)

View audit entries at `/audit` or via `GET /api/v1/audit`.

## I — Useful references

- CrowdSec docs: https://docs.crowdsec.net/
- Scenario hub: https://app.crowdsec.net/hub/
- `cscli` reference: https://docs.crowdsec.net/u/user_guides/cscli/
- caddy-crowdsec-bouncer: https://github.com/hslatman/caddy-crowdsec-bouncer
