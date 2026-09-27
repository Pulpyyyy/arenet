# CrowdSec

**🌐 English** · [Français](CrowdSec-FR)

[CrowdSec](https://www.crowdsec.net) is a community-powered IP reputation service : a collaborative IDS that lets your hosts share threat intelligence. Arenet ships a native [CrowdSec bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) that blocks requests from IPs the CrowdSec community has flagged.

**The CrowdSec agent itself runs separately** — as a Linux service installed from the CrowdSec repository, or as a Docker container. Both are covered below. Arenet only embeds the *bouncer* — the component that queries the agent's Local API (LAPI) and enforces decisions.

---

## Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│  Arenet         │ ────▶ │  CrowdSec       │ ◀──── │  CrowdSec Hub    │
│  (bouncer)      │ LAPI  │  agent          │       │  (community      │
│                 │ poll  │  (your host)    │       │   blocklists)    │
└─────────────────┘       └─────────────────┘       └──────────────────┘
   │                          │
   │ if IP in decision        │ scenarios trigger
   │ → reject with 403        │ on parsed log lines
   ▼                          ▼
   Client                     Local decisions
                              (banned IPs)
```

The agent parses your local logs (auth, web server, etc.), triggers on scenarios (brute-force, scanning, exploitation), and creates **decisions** (ban X for Y minutes). The bouncer polls the agent every N seconds and enforces.

You also get **community decisions** for free : the agent fetches the CrowdSec hub's curated blocklist of IPs currently abusive in the global community. Effectively a real-time blocklist updated by thousands of operators worldwide.

---

## Quick start

### 1. Install + run the CrowdSec agent

The agent runs on the same host as Arenet, or on any host Arenet can
reach. Pick the path that matches how Arenet itself is installed.

#### Linux package — systemd or bare-binary Arenet

```bash
curl -s https://install.crowdsec.net | sudo sh   # add the CrowdSec repository
sudo apt install crowdsec                        # Debian / Ubuntu
# sudo yum install crowdsec                      # RHEL / CentOS / Fedora
sudo systemctl enable --now crowdsec
```

The package starts the agent and its Local API. Check it is listening :

```bash
ss -tlnp | grep 8080
# tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("crowdsec",pid=…))
```

Configuration lives in `/etc/crowdsec/`, the database in
`/var/lib/crowdsec/data/`. Agent logs : `sudo journalctl -u crowdsec -f`.

See the [official Linux install guide](https://docs.crowdsec.net/u/getting_started/installation/linux/)
for other distributions.

#### Docker — containerised Arenet

```bash
docker run -d --name crowdsec \
  -e GID="$(getent group docker | cut -d: -f3)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/log:/var/log:ro \
  -v crowdsec-db:/var/lib/crowdsec/data \
  -v crowdsec-config:/etc/crowdsec \
  -p 127.0.0.1:8080:8080 \
  crowdsecurity/crowdsec
```

Either way, the agent's LAPI is now on `http://127.0.0.1:8080`.

> **Every `cscli` command below is written for the package install.**
> With the Docker agent, prefix it with `docker exec crowdsec` —
> `sudo cscli decisions list` becomes
> `docker exec crowdsec cscli decisions list`.

### 2. Register the Arenet bouncer

```bash
sudo cscli bouncers add arenet
```

The command prints an API key — copy it.

### 3. Configure Arenet

1. Sidebar → **Settings** → **CrowdSec** section
2. **LAPI URL** : `http://127.0.0.1:8080` (or your agent's address)
3. **API key** : paste the key from step 2
4. **Bouncer name** : `arenet` (matches the cscli registration)
5. **Timeout** : `5s` (default ; how long the bouncer waits for LAPI response)
6. **Test connection** → should return ✅
7. **Save**

Within ~30 seconds the bouncer is active. Any inbound request whose source IP is in CrowdSec's current decision list returns **403 Forbidden** before reaching the WAF / route handlers.

Since **v2.26.0**, blocked visitors get Arenet's **branded error page** instead of an empty response: a `ban` decision serves the route's **403** page, a `throttle` decision its **429** page (with a `Retry-After` header matching the decision duration). The page is the one selected for the route in its error-page settings, or the Arenet default — the same pages as the IP filter and upstream errors (see [Custom error pages](Custom-Error-Pages)).

---

## Three parts, and which one you have

This is the question the settings screen does not answer on its own, because CrowdSec appears in Arenet in **three** places that do different things.

| Part | Direction | Credentials | What it does |
|---|---|---|---|
| **Bouncer** (Settings → CrowdSec) | Arenet **reads** | `cscli bouncers add arenet` | Refuses IPs that LAPI says are bad. Enforcement. |
| **Access log** (Settings → Security) | Arenet **writes a file** | none | Gives CrowdSec requests to parse, so *it* can detect things. |
| **Security Automation** (Settings → Security) | Arenet **writes to LAPI** | `cscli machines add arenet-writer` | Arenet decides on its own and pushes bans. |

**Why two sets of credentials for the same LAPI.** That is CrowdSec's auth model, not an Arenet quirk: a *bouncer* may only read decisions, while a *machine* (watcher) may create alerts. A bouncer key cannot write, so pushing a ban needs the second one.

**With only the bouncer**, you get the community blocklist. That is a real layer — thousands of operators reporting IPs that are abusive right now — but nothing about *your* host is ever detected.

**The access log** is what lets CrowdSec's own scenarios see your traffic: scanning, brute force against the apps behind Arenet, known exploit attempts. Arenet emitted no access log at all before **v2.50**, which is why an agent could sit next to it for months and never fire a scenario.

**Security Automation** is the other detector, and it works from what Arenet already understands rather than from raw requests: WAF events, rate-limit events, and failed logins to Arenet's own admin. When one source IP crosses a threshold inside a window, Arenet pushes a ban to LAPI with `origin=arenet` and a scenario named `arenet/…`. It deduplicates, and if you lift a ban by hand it backs off instead of immediately re-pushing it.

> **Every automation rule is disabled by default.** If you filled in the watcher credentials and never saw an `arenet/…` decision, that is almost certainly why — the credentials alone do nothing.

The two detectors do not overlap: Security Automation sees what Arenet has already classified, CrowdSec sees what Arenet merely forwards.

### A word on "watcher"

It means two unrelated things in Arenet. A CrowdSec **watcher** is a machine allowed to write to LAPI. The **watcher** on the [Alerting](Alerting) page is the loop that evaluates your alert rules every 30 seconds. Same word, no relation.

---

## Turning detection on

1. **Settings → Security → HTTP access log** → tick *Write an access log*.
2. Read the **path the card prints**. Do not guess it: the default is `/var/log/arenet/access.log` on a systemd install and `/var/lib/arenet/logs/access.log` inside the container on Docker, and only the running process knows which applied.
3. Save. Arenet reloads Caddy — the log is part of the emitted configuration, so nothing appears until it does.
4. On the CrowdSec host:

```bash
sudo cscli collections install crowdsecurity/caddy
```

```yaml
# /etc/crowdsec/acquis.d/arenet.yaml
filenames:
  - /var/log/arenet/access.log      # the path from step 2
labels:
  type: caddy
```

```bash
sudo systemctl restart crowdsec
```

5. Check it is actually reading:

```bash
sudo cscli metrics | grep -A 5 Acquisition
```

The file must appear with a line count that **rises**. Zero means the agent cannot read it — see [Troubleshooting](Troubleshooting).

**The log is off by default on purpose.** It records every visitor's IP address and the URLs they request. That is what a detection engine needs, and it is also personal data on your disk; which of the two matters more is your call, not a default. Rotation is not optional — 10 MB across 5 gzipped files by default, and the form prints the resulting ceiling.

**Docker**: mount the volume read-only into the agent instead of using a host path —

```yaml
crowdsec:
  volumes:
    - arenet-data:/var/lib/arenet:ro
```

**Not in this log**: Arenet's own admin interface, which is served separately and never reaches Caddy. Failed admin logins are covered by Security Automation instead.

---

## Several hosts, one decision list

Arenet is the reverse proxy, so every request arrives through it. That makes it the natural place to **enforce** — and it means detection can happen anywhere, because whatever any host works out, Arenet is where the block actually saves work.

Concretely: another host running Traefik and containers detects an attack, writes the decision into the LAPI Arenet reads, and **Arenet refuses that IP at reception**. The request never reaches the other host at all.

This is CrowdSec's own multi-server model: several agents may report to one LAPI, and several bouncers may read it. Nothing about it is Arenet-specific.

> **Arenet reads exactly one LAPI.** It cannot aggregate two. So the other hosts' agents must report *into* the LAPI Arenet reads — not the other way round.

### Wiring another host

On the other host, run an agent with **no local LAPI**:

```bash
sudo cscli lapi register -u http://<arenet-host>:8080
# then in /etc/crowdsec/config.yaml, under api.server:
#   enable: false
sudo systemctl restart crowdsec
```

Credentials land in `/etc/crowdsec/local_api_credentials.yaml`. On the Arenet host, validate the machine and let LAPI listen beyond loopback:

```bash
sudo cscli machines list
sudo cscli machines validate <machine-name>
# /etc/crowdsec/config.yaml — api.server.listen_uri
```

**Do not publish LAPI on the internet.** It accepts writes and hands out your blocking policy. Put a WireGuard tunnel between the hosts and have LAPI listen on the tunnel address only; failing that, TLS plus a firewall restricted to the other host's address.

### ⚠️ The mistake that takes everything down

If all traffic reaches the other host **through Arenet**, then its web server no longer sees your visitors — it sees **Arenet**. Its CrowdSec agent parses logs where every attack appears to come from Arenet, bans Arenet, writes that into the shared LAPI, and Arenet's own bouncer enforces it against itself.

Every container behind it stops being reachable, and the cause looks like nothing at all.

Three things, in this order of importance:

1. **Whitelist Arenet first, as a safety net.** Do this *before* connecting the second agent, so nothing can ban your entry point even if the rest is misconfigured.

   ```bash
   sudo cscli postoverflows install crowdsecurity/whitelists
   # then add Arenet's address in
   # /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
   ```

2. **Make the other server log the real client IP**, by trusting Arenet as an upstream proxy — `forwardedHeaders.trustedIPs` in Traefik, `set_real_ip_from` in nginx. Arenet always sends `X-Forwarded-For`, so the information is there; it is the backend's job to use it instead of the connection address.

3. **Check its parser reads that field**, not the socket address:

   ```bash
   sudo cscli explain --file /var/log/traefik/access.log --type traefik | head -20
   ```

   If the extracted source IP is Arenet's, stop and fix step 2 before going further.

### Why bother, if everything passes through Arenet anyway

Because the two layers see different things. Arenet sees the **shape** of HTTP traffic — scanning, bursts of 404s, a wrong protocol on a layer-4 relay. The applications behind it see the **meaning**: a failed WordPress login, an application-level 401, an API being abused in a way that looks perfectly well-formed from the outside.

Detection belongs where the information is. Enforcement belongs at the door.

---

## What gets blocked

The bouncer enforces **whatever decisions the agent has**. Default scenarios (after `cscli scenarios install crowdsecurity/http-cve` etc.) include :

- Brute-force on SSH / web auth pages
- Scanning (nmap, masscan, web vuln scanners)
- Known exploit attempts (CVE-tagged scenarios)
- Community blocklist : IPs currently abusive across the CrowdSec network

You can extend with custom scenarios — see [CrowdSec docs](https://docs.crowdsec.net/docs/scenarios/intro).

---

## Observability

Every CrowdSec block emits a `decision_event` row in the SQLite `decision_event` table :

- `ts` — timestamp
- `src_ip` — banned IP
- `reason` — scenario name (e.g. `crowdsecurity/http-bf`)
- `duration` — ban length
- `origin` — `local` (your agent's scenarios) or `crowdsec` (community blocklist)

The `/security/decisions` page renders these with filter by origin + scenario + time. The unified `/logs` shows them alongside WAF / auth / rate-limit events.

---

## Verifying the integration is live

Ban your own IP for a minute and watch a route refuse you.

**1. Find your address — from the machine you will browse with, not from
the server.**

`curl -s ifconfig.me` run *on the Arenet host* returns the **server's**
public address, not the one your browser arrives on. Banning that bans
the server. Run it where you are sitting :

```bash
curl -s https://ifconfig.me        # on your laptop, NOT on the server
curl -4 -s https://ifconfig.me     # your IPv4, specifically
curl -6 -s https://ifconfig.me     # your IPv6, specifically
```

If your browser reaches the site over IPv6, ban the IPv6 address — a ban
on the wrong family does nothing at all, and this is the most common
reason the test appears to fail.

**2. Ban it, on the Arenet host :**

```bash
sudo cscli decisions add --ip <the address from step 1> --duration 60s
sudo cscli decisions list          # check Scope:Value is what you expect
```

**3. Load one of your configured routes** from that machine → **403**.
After 60 s the ban expires and the route answers normally again.

> **A 404 instead of a 403 is not a failure.** The bouncer runs inside
> each route's handler chain, so it only sees requests that match a
> route you configured. Anything else — an unknown host, a path on no
> route — is answered by Arenet's catch-all 404 before CrowdSec is ever
> consulted. Test against a route that exists.

---

## Tuning : what to do when CrowdSec blocks legitimate users

CrowdSec is communal — sometimes an IP gets banned globally for behaviour your local users aren't doing. You have two safety valves :

### Whitelist a specific IP

```bash
sudo cscli decisions delete --ip <your-user-ip>
sudo cscli postoverflows install crowdsecurity/whitelists
# Then edit /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
# to add your user's IP / CIDR.
# Docker : that file is inside the crowdsec-config volume, so edit it with
#   docker exec -it crowdsec vi /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
```

### Disable the bouncer per-route

Currently CrowdSec is **global** in Arenet (all routes or no routes). If you need to bypass it on a specific route, the workaround is to put that route on a different Arenet instance OR to whitelist the source IPs at the CrowdSec agent layer.

A per-route CrowdSec toggle is on the V3 backlog ; open an issue if you'd find it useful.

---

## Fallback behaviour (LAPI down)

When the agent is unreachable — network blip, crash, restart — the bouncer **fails open by default** : requests pass through as if CrowdSec were disabled. That is deliberate (`enable_hard_fails: false`) : legitimate traffic should not go down because the agent is having a bad day.

The dashboard's CrowdSec card shows the agent status (✅ reachable / ⚠️ unreachable + last-success timestamp). Wire an [Alerting](Alerting) rule on `system_health == degraded` to get a Discord/email ping when the agent drops.

---

## See also

- [WAF](WAF) — layered defense ; WAF catches what CrowdSec doesn't
- [Country Block](Country-Block) — geo-fence layer above CrowdSec
- [Alerting](Alerting) — pager when the agent is down
- [CrowdSec official docs](https://docs.crowdsec.net) — agent install, scenarios, hub
- [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) — the Caddy module Arenet uses
- `internal/crowdsec/` — Arenet's wrapping (sink, observability adapter)
