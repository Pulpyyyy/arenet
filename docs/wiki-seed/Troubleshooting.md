# Troubleshooting

**🌐 English** · [Français](Troubleshooting-FR)

Diagnostic playbook for common Arenet symptoms. Each section names the symptom, the likely cause(s), and the empirical commands to confirm + fix.

For boot-message-specific diagnostics, see [`docs/operations/troubleshooting.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/troubleshooting.md) which covers the "expected-but-surprising" log lines.

---

## Is it the host, or is it Arenet? (v2.45)

**Settings → System** now reports the machine Arenet runs on, refreshed
every five seconds: processor usage and load, memory, free space on
the **data directory**, plus Arenet's own memory, goroutines and
uptime. It is the first place to look when relays slow down or a
reload fails for no visible reason — it separates "the host is out of
something" from "Arenet is misbehaving" before you go digging.

The disk figure is deliberately the **data directory**, not `/`. The
database, the backups and the logs all live there, and on any install
that gives it its own volume a healthy root filesystem says nothing
about whether the next backup will fit.

**In a container, read the source label.** `/proc` reports the *host*,
so a container limited to 512 MiB would otherwise show the machine's
64 GiB — literally correct, and useless when you are working out why
Arenet keeps being OOM-killed. When a cgroup limit exists Arenet shows
that limit instead and says so, and a CPU quota is displayed beside
the machine's real core count so it reads as a restriction rather than
as a smaller machine.

**CPU usage shows a dash for the first few seconds after a restart.**
Usage is a rate, and a rate needs two readings; the panel would rather
show nothing than invent a number.

---

## Admin UI not reachable

### Symptom
`http://<host>:8001` times out or refuses connection.

### Diagnostic
```bash
# Is the binary even running ?
sudo systemctl status arenet      # native
docker compose ps                  # docker

# Is the port bound ?
sudo ss -tlnp | grep 8001

# From inside the host
curl http://127.0.0.1:8001/healthz
```

### Likely causes
- **Default loopback bind** : admin UI binds `127.0.0.1:8001` by default. From LAN you need `ARENET_ADMIN_BIND=0.0.0.0:8001` (systemd) or the published `8001:8001` port (docker)
- **Service not started** : `sudo systemctl start arenet` (native) or `docker compose up -d` (docker)
- **Firewall** : `sudo ufw status` or `sudo nft list ruleset | grep 8001`

---

## Routes return 502 Bad Gateway

### Symptom
A route returns 502 even though Arenet itself is healthy.

### Diagnostic
```bash
# Test the upstream directly from the Arenet host
sudo -u arenet curl -v --max-time 5 <upstream-url-from-route-config>

# Compare upstream URL in the route config
curl -b /tmp/jar http://127.0.0.1:8001/api/v1/routes | jq '.[] | select(.host=="<your-host>") | .upstreams'

# Check Caddy is reaching the upstream
docker logs arenet 2>&1 | grep "<upstream-host>" | tail -10
```

### Likely causes
- **Upstream down** : the backend service is offline. Check `systemctl status <backend>` or the container's status
- **Upstream port wrong** : the route's upstream URL has the wrong port. E.g. authentik is on `:9000` HTTP or `:9443` HTTPS, not `:80`
- **HTTPS-to-HTTPS without TLS skip** : the upstream is HTTPS but uses a self-signed cert. Enable **Insecure skip verify** in the route's TLS section
- **Active health check marked it down** : check `/topology` — if the upstream node is red, the HC failed N times. Verify the HC URI + expected status are sensible for that backend
- **Network unreachable** : `ping <upstream-ip>` from the Arenet host. Firewall in between ?

---

## HTTPS cert won't issue

### Symptom
A new route with TLS enabled never serves HTTPS ; browser shows "no cert" or self-signed warning.

### Diagnostic
```bash
# What does Caddy say about the ACME process ?
docker logs arenet 2>&1 | grep -iE "acme|certificate|tls" | tail -20

# Is port 80 reachable from outside (HTTP-01 challenge needs it) ?
curl http://<your-public-ip>/.well-known/acme-challenge/test
# Should return 404 (Arenet handles the path but no challenge active right now)
# If it times out, port forwarding broken
```

### Likely causes
- **Port 80 not forwarded** : HTTP-01 challenge requires inbound TCP/80. Open the firewall + router NAT rule
- **DNS not pointing at your host** : `dig <your-route-host> +short` should return your public IP. If not, ACME can't validate
- **Let's Encrypt rate limit hit** : the staging environment exists for testing ; production limits are 50 certs/week/domain. Check `docker logs arenet | grep "rateLimited"`. Wait, or use DNS-01 with a wildcard apex
- **DNS-01 missing provider creds** : route's `acmeChallenge` is `dns-01` but no provider configured. Settings → DNS Providers → wire OVH
- **Wildcard inheritance broken** : route is under a managed apex but `acmeChallenge` is `http-01` instead of `inherited` (or wildcard cert not yet issued)

---

## OIDC SSO login fails

### Symptom
Click "Sign in with SSO" → either get an error page from the IdP, or land back on `/login?error=invalid_state` / `idp_unreachable`.

### Diagnostic
```bash
# Check the discovery fetch from Arenet's side
sudo -u arenet curl -v --max-time 10 \
  "https://<your-idp>/<path>/.well-known/openid-configuration" 2>&1 | tail -20

# Check the Arenet logs
sudo journalctl -u arenet --since "5 min ago" | grep -i oidc
```

### Likely causes
- **Discovery fetch timeout** : IdP unreachable. See [OIDC SSO](OIDC-SSO) common pitfalls
- **`invalid_state`** : the state cookie didn't survive the IdP round-trip. Usually a domain mismatch (the redirect_uri must be on the same domain as the Arenet UI you initiated login from)
- **`idp_unreachable`** : same as discovery fetch timeout, or the IdP returned an error on the code exchange
- **Identity not in allowlist** : check Users page. Add the email + role

The OIDC log lines since v2.8.3 enrich every failure with `issuer_url=...` + `client_id=...` so you know exactly which config is failing.

---

## WAF blocking legitimate requests (false positives)

### Symptom
A specific request that should pass gets 403 with the Arenet branded error page.

### Diagnostic
1. Identify which CRS rule fired : `/security` → filter by route + recent time → look at the events
2. Note the `rule_id` (e.g. `942100`, `920170`)
3. Note the `category` (SQLi, attack-protocol, ...) and look at the matched payload

### Fix
Three escape hatches, increasing scope (see [WAF](WAF) for details) :

- **Exclude one rule ID** : Route → WAF → Excluded rule IDs → add the ID
- **Exclude a whole tag family** : Route → WAF → Excluded tags → pick the tag from autocomplete
- **Disable CRS entirely** : Route → WAF → Disable OWASP CRS ✅ (last resort, security-reducing)

If your route is genuinely public-facing, prefer the tightest scope (rule ID > tag > full disable).

---

## Alert never fires despite the condition tripping

### Symptom
A rule's condition is true (verified via the source's manual evaluation) but no alert lands in Discord / email.

### Diagnostic
1. `/alerting` → Rules tab → click your rule → **Test rule** → does the test message land ?
2. If test works : check the **History** tab → was the rule evaluated recently ? What was the value ?
3. Check cooldown : the rule may have fired earlier and be in cooldown
4. `journalctl -u arenet --since "10 min ago" | grep -i alerting`

### Likely causes
- **Cooldown active** : the default is 300s. Wait, or temporarily lower the cooldown for testing
- **Source returning unexpected value** : the source params may not match the current state. E.g. `cert_renewal_failed` with `domain=specific.example.com` filters strictly — make sure the domain string is exact
- **Channel disabled** : Channels tab → check the channel's Enabled toggle
- **Watcher not running** : extremely rare ; would mean Arenet didn't boot the alerting watcher (check logs for `alerting: watcher started`)
- **Rule disabled** : Rules tab → check the rule's Enabled toggle

---

## High CPU / RAM usage

### Symptom
Arenet using more resources than expected.

### Diagnostic
```bash
# Per-process CPU + RAM
top -p $(pgrep -f arenet)

# Per-route metrics : which is hot ?
curl -b /tmp/jar "http://127.0.0.1:8001/api/v1/metrics/per-host?windowSecs=300" | jq

# Goroutine + heap profile (if pprof exposed)
curl http://127.0.0.1:8001/debug/pprof/goroutine?debug=1
```

### Likely causes
- **WAF on every route** : Coraza is the heaviest consumer (~10-30 MB per unique WAF config). N routes with N distinct WAF configs = N × 30 MB. The WAF pool dedups by directives-string SHA — routes with identical config share one Coraza instance. Reduce by setting the same WAF profile across similar routes
- **Large upload without streaming mode** : a 4GB Docker registry push without `uploadStreamingMode=true` will balloon RAM to 3.5GB. Enable upload streaming on registry / file-server routes
- **CrowdSec decision list very large** : if you have millions of community decisions cached, the bouncer can use 100+ MB. Tune the agent's decision retention
- **SQLite event table growth** : `du -sh /var/lib/arenet/observability.db` — if huge, the retention loop may have stalled. Check `journalctl | grep -i prune`

---

## Restore fails with `sentinel:...` errors

### Symptom
Restore returns 400 with a message like : "Restore rejected: sentinel `oidc-config:default:client_secret` could not be resolved from the live store..."

### Cause
You exported a **redacted** snapshot (Export without secrets) and are trying to restore on a fresh instance OR on an instance that doesn't have the original live values to inherit.

### Fix
Two paths forward :

1. **Tick "Allow incomplete restore"** before clicking Restore. The sentinels that can't inherit will be CLEARED ; the next boot will print a WARN listing the cleared fields. You then manually re-save those secrets via the UI.

2. **Re-export from the source instance with secrets included** (Export with secrets…) and use that file. Restores anywhere, no inheritance needed.

See [Backup & Restore](Backup-Restore) for the full sentinel resolution explainer.

---

## CrowdSec bouncer blocking your own IP

### Symptom
You can't reach Arenet UI from your home connection.

### Diagnostic
```bash
# Check if your IP is in the decision list
docker exec crowdsec cscli decisions list | grep $(curl -s ifconfig.me)
```

### Fix
```bash
# Delete the decision
docker exec crowdsec cscli decisions delete --ip $(curl -s ifconfig.me)

# Whitelist permanently (recommended for your home IPs)
docker exec crowdsec cscli postoverflows install crowdsecurity/whitelists
# Then edit /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
```

If you locked yourself out completely, you can temporarily disable the CrowdSec integration in Arenet (Settings → CrowdSec → Disable + Save) which leaves the bouncer off until you re-enable.

---

## Moving the LAPI address silently stops all blocking

### Symptom
You changed the LAPI URL in Settings → CrowdSec, saved, and CrowdSec no longer blocks anything. The log shows the new address but the errors name the old one:

```
"address":"http://10.66.0.1:8080"
"error":"... Get \"http://127.0.0.1:8080/v1/decisions/stream?...\": connection refused"
```

### Cause
A save reloads Caddy and the bouncer is re-provisioned with the new URL, but its streaming client keeps dialling the previous one until the **process** restarts. It reports the new address while using the old.

The bouncer **fails open** by design, so while this lasts traffic flows entirely unprotected and nothing else in the UI says so.

### Fix
```bash
sudo systemctl restart arenet          # systemd
docker compose restart arenet          # Docker
```

Since v2.51 the settings panel shows a warning saying exactly this after a save that moved the address. On an older version, restart after any LAPI URL change as a matter of course.

Then confirm the bouncer really moved — and read the **log**, not `cscli bouncers list`:

```bash
journalctl -u arenet --since "2 min ago" | grep -i crowdsec
```

No `connection refused` and a `using API key auth` line carrying the new address means it worked.

`cscli bouncers list` is misleading here: CrowdSec keys a bouncer by name **and IP**, so after the move the pulls land on a second row (`arenet@<new-ip>`) while the original row stays frozen at its last pull forever. A stale timestamp on the old row is not a failure — it is a row nothing writes to any more.

---

## CrowdSec bans nothing of your own

### Symptom
CrowdSec is configured, the bouncer says connected, but no decision ever appears that you did not import from the community blocklist. Nothing local is ever detected.

### Diagnostic
```bash
# 1. Is Arenet writing an access log at all? (off by default)
#    Settings → Security → HTTP access log — read the path it prints.
sudo ls -l /var/log/arenet/access.log

# 2. Is it growing? Load one of your routes while this runs.
sudo tail -f /var/log/arenet/access.log

# 3. Is the agent reading it?
sudo cscli metrics | grep -A 5 Acquisition

# 4. Can the agent read it at all? Caddy writes the file 0600.
systemctl show crowdsec -p User
sudo cscli explain --file /var/log/arenet/access.log --type caddy | head -20
```

### Fix
The four checks above fail in four different ways, and each has its own answer.

1. **No file.** The access log is off by default — it records every visitor's IP and URL, so Arenet does not turn it on for you. Enable it in Settings → Security, and note that the path shown there is the one to use: it differs between a systemd install (`/var/log/arenet/access.log`) and a container (inside the data volume).
2. **File exists but stays empty.** Requests are not reaching the sink. Check that saving the setting actually reloaded Caddy — the log is part of the emitted config. Report this: it is a bug, not a configuration.
3. **Acquisition count stays at zero.** The agent is not reading. Confirm the path in `/etc/crowdsec/acquis.d/` matches exactly, and that `labels: type: caddy` is set. On Docker the agent needs the volume mounted read-only (`arenet-data:/var/lib/arenet:ro`).
4. **`cscli explain` reports a parser failure.** Install the collection: `sudo cscli collections install crowdsecurity/caddy`.

The most common cause by far is **permissions**: Caddy creates the file `0600` owned by the Arenet user, so the agent has to be root. It is by default on a package install, but not if you changed it.

Worth knowing: failed logins to Arenet's **own admin interface** are never in this log — the admin plane is served separately and never reaches Caddy. Those are covered by Security Automation, whose rules are all **disabled by default**, which is the other reason an operator sees no `arenet/…` decisions. See [CrowdSec](CrowdSec).

---

## Backup file is huge (> 10 MB)

### Symptom
Your config backup is much larger than expected.

### Cause
The export includes every user + every cert event metadata + every error page template body. The largest contributors :
- Custom error page templates (1 MiB cap per body × 8 codes × N templates)
- Many users with custom display names + emails

### Fix
- Trim unused error page templates : `/settings/error-pages` → delete templates no route uses
- Trim stale users : `/users` → remove ex-collaborators

Cert files + SQLite event tables are NOT in the backup so they don't contribute.

---

## "Looking at this from outside Arenet"

If none of the above match your symptom :

1. **Reproduce empirically** — exact request + exact response + exact log lines
2. **Inspect the audit log** at `/audit` — every config change is there with actor + before/after
3. **Check the unified `/logs`** — WAF / rate-limit / auth / cert events for the affected route, filter by time + source IP
4. **Open an issue** at https://github.com/barto95100/arenet/issues with :
   - Arenet version (`docker exec arenet arenet --version` or `arenet --version`)
   - Reproduction recipe
   - Relevant log snippet (`journalctl -u arenet --since "10 min ago" | grep <route-host>`)
   - Sanitized snapshot if it helps (export → redact your secrets manually before sharing)

---

## See also

- [`docs/operations/troubleshooting.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/troubleshooting.md) — boot warnings + expected log lines that look scary but aren't
- [`docs/operations/http3.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/http3.md) — HTTP/3 specific debugging
- [Installation](Installation) — install-side issues
- [WAF](WAF) — WAF false-positive triage
- [OIDC SSO](OIDC-SSO) — OIDC-specific common pitfalls
- [Backup & Restore](Backup-Restore) — restore failure modes
