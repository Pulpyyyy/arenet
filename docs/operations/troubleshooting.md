# Troubleshooting

A short list of expected-but-surprising boot messages and the
"my install is broken" first-aid checklist. If your issue isn't
here, open an issue with the relevant log snippets.

## Boot warnings that are NOT errors

### "tee not found in $PATH" (dev mode only)

```
level=error msg="failed to install root certificate"
error="failed to execute tee: exec: \"tee\": executable file not found in $PATH"
```

**What it means**: in `--dev` mode Caddy attempts to install
its local-CA root cert by shelling out to `/usr/bin/tee`. The
distroless container image has no shell tools, so the install
fails non-fatally. The binary keeps running; the local-CA cert
just isn't trusted by the host (which doesn't matter in dev).

**Action**: none. In production (`--dev` not set) the local-CA
flow isn't used — ACME via Let's Encrypt is used instead, no
tee dependency.

### Admin port in old smoke logs: `:9994`

If you find log snippets from Step M / N / O / P / Q showing
admin on `:9994`, those are smoke-test artefacts. The
**production default is `:8001`** — that's what the binary's
`--admin-port` flag has defaulted to since Step D. Each
previous smoke explicitly passed `-admin-port=:9994` to avoid
collision with whatever else was running on the dev box; that
override was smoke-local, not the production default.

**Action**: none. Use `:8001` everywhere unless you've
explicitly set `ARENET_ADMIN_BIND` to something else.

### "no trusted proxies configured (X-Forwarded-For will be ignored)"

```
level=INFO msg="auth: no trusted proxies configured (X-Forwarded-For will be ignored)"
```

**What it means**: Arenet IS the reverse proxy in this
deployment; the operator hasn't told it to trust any upstream
proxy's X-Forwarded-For headers. Source IPs come from the
TCP connection directly.

**Action**: none unless you're running Arenet behind another
reverse proxy / CDN (Cloudflare, etc.). In that case, set
`ARENET_TRUSTED_PROXIES` to a comma-separated CIDR list of
the upstream proxies.

### "crowdsec bouncer not configured"

```
level=INFO msg="crowdsec bouncer not configured (set ARENET_CROWDSEC_API_KEY to enable the IP-reputation gate)"
```

**What it means**: you haven't wired Arenet to a CrowdSec
LAPI. The proxy still serves traffic; the IP-reputation
defence layer is just inactive.

**Action**: none unless you want to enable it. See
`docs/install/docker-quickstart.md` for the wiring.

## "I can't reach the admin port"

Checklist in priority order:

1. **The admin port is loopback-bound by default.** From a LAN
   machine, `curl http://<host>:8001/healthz` will fail.
   Either SSH-tunnel, or open it to the LAN: publish
   `8001:8001` instead of `127.0.0.1:8001:8001` (Docker), or
   set `ARENET_ADMIN_BIND=0.0.0.0:8001` (systemd). See
   `docs/install/docker-quickstart.md`.
2. **Healthcheck reports unhealthy in `docker compose ps`?**
   Check the logs:
   ```bash
   docker compose logs arenet | tail -50
   ```
   Usual culprits: another service on :80/:443, volume mount
   permissions, malformed env var values.
3. **Service won't start at all (systemd)?**
   ```bash
   sudo journalctl -u arenet -n 50
   ```
   Common: `/usr/local/bin/arenet` missing or not executable;
   `/var/lib/arenet` permissions drifted; env file has a typo.
4. **Port collision?**
   ```bash
   sudo ss -tlnp | grep -E ':(80|443|8001)'
   ```
   If something else is bound to one of those, change either
   the other thing or Arenet's bind via env vars.

## "I'm getting 429 Too Many Requests"

Step Q + S.4 rate-limit failed auth attempts per source IP.
10 wrong passwords in a row triggers a 15-minute block; the
next batch triggers a 1-hour block.

If you've locked yourself out:

1. Wait for the Retry-After window (the 429 response header
   tells you).
2. From the same source IP, a successful login resets the
   counter — so if you remember the password, retry once the
   window passes.
3. Last resort (if you've truly lost the admin password):
   stop the binary, use `arenet --restore` with a fresh user
   file (see `docs/operations/backup.md` for the restore
   path), restart.

## "I changed config but nothing happened"

Config precedence is `flag > env > TOML > default` per-field.
If you edited the TOML but the binary still uses an env value,
the env wins. The first INFO log line shows the resolved
values:

```
level=INFO msg="Arenet starting" version=v1.0.0 admin_port=:8001 data_dir=/var/lib/arenet dev=false
```

Compare those to what you expected; the field that differs
points at which precedence layer is overriding.

## "Schema migration failed on upgrade"

Step D8 auto-migrates schemas forward on first boot of a new
binary version. If a migration errors out, the binary refuses
to start.

1. Capture the error from the journal:
   ```bash
   sudo journalctl -u arenet --since "5 min ago" | grep -i migrat
   ```
2. **Restore from your backup** (the cold-stop + tar
   procedure documented in `docs/operations/backup.md`).
3. Open an issue with the migration error + your version
   transition path (e.g. v1.0.0 → v1.1.0).

If you didn't take a backup before upgrading, downgrade the
binary to the previous version — most schema migrations are
forward-only but the rollback is at the operator's discretion;
older binaries refuse to start against a newer schema (would
silently corrupt). The safe path is restore.

## "SSO login fails with invalid_state or hangs after the IdP"

A common homelab gotcha when your IdP (Authentik, Keycloak,
Authelia, etc.) is exposed via a **public DNS name** AND Arenet
runs on the **same LAN** as the IdP.

### Symptom

- Click "Sign in with SSO" on the Arenet login page.
- The IdP login page appears and you authenticate successfully.
- Browser redirects back to Arenet's
  `/api/v1/auth/oidc/callback`.
- You see `invalid_state` or a generic error and land on
  `/login?error=internal`. Arenet logs show
  `oidc: token exchange failed` or `oidc: state mismatch`.

### Root cause

The OIDC flow requires **two** HTTPS round trips to the IdP:

1. The **browser** redirects to the IdP (authorization request)
   — works because the browser resolves the public DNS name and
   reaches the IdP via the router's NAT loopback.
2. The **Arenet backend** then talks to the IdP directly to
   exchange the authorization code for tokens (token request).
   This is a *server-to-server* call from inside the LAN, and
   it takes the same NAT loopback path.

If your router does not support NAT loopback (a.k.a. hairpin
NAT), or if firewall rules block intra-LAN traffic to the
router's WAN IP, step 2 fails silently and the callback never
completes.

### Diagnosis

On the host running `arenet`:

```bash
curl -v https://auth.example.com/application/o/<slug>/.well-known/openid-configuration
```

- Connection refused / timeout / TLS error → NAT loopback is
  the culprit. Apply one of the fixes below.
- Valid JSON response → the network path is fine. Likely a
  `redirect_uri` mismatch instead. Check that the `Redirect URL`
  set in Settings → OIDC matches **exactly** one of the allowed
  redirect URIs registered with the IdP — schemes, ports, and
  trailing slashes count.

### Fix A — Split-horizon DNS (recommended)

Make the LAN-side resolver return the IdP's **internal IP** for
the public hostname. The browser keeps hitting the public DNS,
but the backend resolves to the internal IP and bypasses the
NAT loopback entirely.

Pi-hole, AdGuard Home, or dnsmasq:

```
address=/auth.example.com/192.168.1.10
```

Unbound:

```yaml
local-data: "auth.example.com IN A 192.168.1.10"
```

Verify on the Arenet host:

```bash
dig auth.example.com +short
# → should print the LAN IP (e.g. 192.168.1.10)
```

### Fix B — Enable NAT loopback / hairpin on the router

Some routers (OpenWrt, OPNsense, pfSense, EdgeRouter…) can
enable hairpin NAT globally or per port-forward rule. Consult
your router's documentation. Avoid this on consumer ISP-supplied
routers — many advertise the feature but implement it
inconsistently.

### Fix C — Point Arenet at the internal IdP URL directly

If you control the IdP, set Arenet's `Issuer URL` (Settings →
OIDC) to the IdP's internal address — e.g.
`http://192.168.1.10:9000/application/o/<slug>/`. The IdP must
accept this issuer; most validate that the issuer string in the
ID token matches what Arenet expects. For Authentik you may
need to add the internal URL under the application's *Advanced
settings → Trusted OIDC sources*.

## Where to find logs

| Install | Command |
|---|---|
| Docker compose | `docker compose logs -f arenet` |
| systemd | `sudo journalctl -u arenet -f` |
| Local dev | binary's stdout/stderr in your terminal |

Log level defaults to `info`. Bump to `debug` via
`ARENET_LOG_LEVEL=debug` for boot diagnostics; do not leave
debug enabled in production (verbose + leaks request paths).
