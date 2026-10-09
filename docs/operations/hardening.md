# Hardening checklist

10 actionable items for an Arenet homelab install. Each has a
**verify** command. Read time: ~10 minutes. Apply time depends
on how many you already have right.

For each item: ✓ if applied, with the verify command's output
as evidence.

---

## 1. Admin port is loopback by default — keep it that way

The compose example binds admin to `127.0.0.1:8001` only.
Reach it from a workstation via SSH tunnel:

```bash
ssh -L 8001:localhost:8001 <homelab-host>
```

**Verify** (from a LAN machine — should fail):

```bash
curl -m 3 http://<homelab-LAN-IP>:8001/healthz
# expected: connection refused / timeout, NOT a 401
```

If you've intentionally opened admin to LAN (published
`8001:8001` in Docker, or `ARENET_ADMIN_BIND=0.0.0.0:8001` on
systemd), apply items 2 + 3 below.

## 2. Put TLS in front of LAN-exposed admin

Admin runs plain HTTP. If you expose it on LAN, terminate TLS
with a reverse proxy in front (Caddy, Nginx, Cloudflare Tunnel).

**Verify**:

```bash
curl -I https://admin.<your-domain>/healthz
# expected: HTTP/2 200 with the proxy's cert
```

Recipe (Caddy in front):

```
admin.<your-domain> {
    reverse_proxy 127.0.0.1:8001
}
```

## 3. Rotate the admin TLS cert (advanced)

If you skip path 2 and use Arenet's direct-TLS option,
generate a cert and supply both:

```bash
ARENET_ADMIN_TLS_CERT=/etc/arenet/admin.crt
ARENET_ADMIN_TLS_KEY=/etc/arenet/admin.key
```

**Verify**:

```bash
echo | openssl s_client -connect <host>:8001 -servername admin 2>/dev/null \
    | openssl x509 -noout -dates
# expected: notAfter > 30 days from now
```

Rotate on a calendar reminder; Arenet doesn't ACME its own
admin cert (chicken-egg — auto-TLS for admin is on the
roadmap).

## 4. Confirm the rate-limit is active

Step Q rate-limit protects all `/api/v1/*` endpoints against
credential stuffing (Step S.4 lifted it from `/auth` only to
the whole admin tree).

**Verify** (don't run against a real install — block-out is
1 hour):

```bash
# Manually trigger 11 wrong logins from a test IP. The 11th
# should return 429 with Retry-After header.
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://127.0.0.1:8001/api/v1/auth/login \
    -d '{"username":"wrong","password":"wrong"}' \
    -H "Content-Type: application/json"
done
# expected: 401×10 then 429
```

## 5. Secrets via env vars or Docker secrets — NOT in TOML

The config file at `/etc/arenet/config.toml` is fine for
non-secret tuning (ports, log levels). Anything sensitive
(`ARENET_CROWDSEC_API_KEY`, OVH DNS provider creds, etc.)
goes via:

- env vars (`/etc/arenet/arenet.env`, mode 0600, root-owned).
- Docker secrets (file at `/run/secrets/<name>`).

**Verify**:

```bash
sudo stat -c '%a %U:%G' /etc/arenet/arenet.env
# expected: 600 root:root
```

Never check secrets into git. Add `arenet.env` to your
deployment's `.gitignore`.

## 6. Run as non-root

The Docker image's USER is `nonroot` (uid 65532). The systemd
unit's User is `arenet`. Privileged ports (80/443) bind via
`CAP_NET_BIND_SERVICE`, not root.

**Verify (Docker)**:

```bash
docker inspect arenet --format '{{.Config.User}}'
# expected: nonroot:nonroot
```

**Verify (systemd)**:

```bash
sudo systemctl show arenet --property=User
# expected: User=arenet
```

## 7. Filesystem hardening on systemd

The unit ships `ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp=true`, `NoNewPrivileges=true`,
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. Only
`/var/lib/arenet` is writable; everything else is RO or
hidden.

**Verify**:

```bash
sudo systemctl show arenet --property=ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges
# expected: ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes, NoNewPrivileges=yes
```

## 8. Backup before every upgrade

Step S.D8 auto-migrates schemas forward on first boot of a
new version. Migrations are tested, but the operator owns the
backup.

```bash
# See docs/operations/backup.md for the exact commands.
```

**Verify**: a backup &lt; 7 days old exists in
`/var/backups/` (or wherever you snapshot to).

## 9. Restrict outbound network if you don't use CrowdSec / ACME

Arenet's outbound needs:

- ACME (Let's Encrypt: `:80` + `:443` to `acme-v02.api.
  letsencrypt.org`) — only if any route has TLS enabled.
- CrowdSec LAPI — only if `ARENET_CROWDSEC_API_KEY` is set.
- DNS provider (OVH `:443`) — only for DNS-01 wildcards.

If none of those apply, your firewall can deny outbound
entirely.

**Verify**:

```bash
sudo iptables -L OUTPUT -v -n | grep arenet
# (or your firewall's equivalent)
```

## 10. Disable dev mode in production

`--dev` enables verbose logging + skips TLS auto-issuance +
serves a dev landing page. Never set in production.

**Verify**:

```bash
sudo journalctl -u arenet --since "5 min ago" | grep -i "dev=true"
# expected: no matches
```

In compose, make sure your environment block does NOT contain
`ARENET_DEV=true`.

## 11. Idle lock

Sessions lock after **15 minutes without user activity** (password or SSO
sign-in to resume). Since v2.32 only user-triggered requests count:
automatic polling carries `X-Arenet-Background: 1`, and the server still
enforces the lock on it but does not refresh the session. Nothing to
configure — just don't expect an open, untouched tab to stay unlocked.

## 12. Know what the access log keeps

The access log records every request's headers. Three layers decide what of
that reaches disk, and the gaps between them are worth knowing:

| Redacted by | What |
| ----------- | ---- |
| Caddy, always | `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization` |
| Arenet, always (v2.58.4) | any header whose **name** contains `key`, `token`, `secret`, `password`, `credential` or `signature`, case-insensitive, in requests **and** responses |
| Arenet, if you list them | query-string parameters (Settings → Access log) |

The middle row exists because the first is narrower than it looks. Caddy
redacts four header names; a homelab authenticates with names it has never
heard of. An operator's log held a live Dolibarr key under `Dolapikey`, one
field away from a `Cookie` that had been dutifully replaced.

Matching is on the name, by substring, and the value is replaced rather than
the header removed — so you still see *that* a caller presented an API key,
which is what makes "the backend started refusing them" diagnosable, without
seeing the key.

Two consequences to accept rather than discover:

- **A header named after a secret is redacted even when it is not one.**
  `X-Monkey-Business` ends with `key`. No substring rule catches `Dolapikey`
  — one word, no separator — while sparing it. Losing a field of a log line
  is cheaper than leaving a credential on disk through every rotation.
- **`api` and `auth` are deliberately NOT patterns.** `Api-Version` is not a
  secret, and `X-authentik-username` is an identity you want to read.
  Credentials spelled with "api" carry "key" or "token" anyway.

```bash
# What is actually on disk right now — check before trusting the above.
sudo grep -oE '"[A-Za-z-]*[Kk]ey"[^,]*' /var/log/arenet/access.log | sort -u | head
# expected: every match reads "REDACTED"
```

If you find a plaintext credential from a version before v2.58.4, **rotate
it**: the log is rolled and kept, and it may be in a backup or shipped to a
log collector. Upgrading stops new ones; it does not rewrite history.

---

---

## Quick scorecard

After applying all 10, count your ✓s:

- 10 ✓: hardened production posture.
- 7–9 ✓: solid, with documented exceptions.
- &lt; 7 ✓: still in dev-mode territory — pick the lowest-
  hanging items and apply them first (1, 6, 8, 10 are the
  highest-impact / lowest-effort).
