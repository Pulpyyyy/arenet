# Arenet Wiki

**🌐 English** · [Français](Home-FR)

Welcome. This wiki is the **how-to** companion to the [README](https://github.com/barto95100/arenet/blob/main/README.md) — task-oriented guides for every feature, written for the operator running Arenet on their homelab.

If you're new : start with [Installation](Installation), then follow [Routes](Routes) to get your first proxied host live. Everything else is feature-by-feature reference.

---

## Quick navigation

### Get started
- **[Installation](Installation)** — Docker, native systemd, first-boot wizard
- **[Routes](Routes)** — your first reverse proxy route, TLS, upstreams, aliases, source IP filter, path rules, Caddyfile import
- **[TCP / UDP services](TCP-Services)** — relay raw TCP or UDP (mail, databases, SSH, WireGuard) with the real client IP preserved
- **[DNS Providers](DNS-Providers)** — 9 DNS providers (OVHcloud, Cloudflare, Hetzner, Route 53…) for wildcard (DNS-01) certificates, with a connection test
- **[Topology](Topology)** — live dashboard with real-time traffic visualization

### Security stack
- **[WAF](WAF)** — Coraza + OWASP CRS, per-route opt-out, targeted exclusions from an event, guided rules, SecLang editor with a request tester
- **[CrowdSec](CrowdSec)** — community IP reputation, LAPI bouncer setup
- **[Country Block](Country-Block)** — GeoIP-based allow/deny lists per route
- **[Rate Limit](Rate-Limit)** — events/window throttling per route
- **[OIDC SSO](OIDC-SSO)** — authentik / Keycloak / Authelia integration + RBAC, for signing in to Arenet itself
- **[Forward auth](Forward-Auth)** — put your IdP in front of a backend application that has no login of its own

### Operations
- **[Updating Arenet](Updates)** — manual upgrade workflow (Docker + binary), rollback, security notes
- **[Backup & Restore](Backup-Restore)** — full config export, sentinel-resolution import, disaster recovery
- **[Alerting](Alerting)** — channels, threshold + state rules, Discord/email/webhook
- **[Custom Error Pages](Custom-Error-Pages)** — per-route HTML templates with Caddy placeholders
- **[API (OpenAPI)](API)** — the admin API, service-account tokens, the in-app docs page
- **[Troubleshooting](Troubleshooting)** — symptoms diagnostic, common pitfalls, log decoding

---

## What is Arenet ?

Arenet is a **single-binary reverse proxy** that combines [Caddy v2](https://caddyserver.com) (the HTTP engine, auto-HTTPS + HTTP/3 + ACME) with :

- An **admin UI** to configure routes, certificates, security settings
- An **integrated security stack** : WAF (Coraza + OWASP CRS), IP reputation (CrowdSec), country blocking, rate limiting
- A **live observability surface** : topology dashboard with real-time particles, per-route metrics, unified activity log, audit trail
- A **native alerting subsystem** with multi-channel routing (Discord, email, webhook)
- **Backup/restore** of the entire config via UI

All as **one Go binary** (~100 MB) backed by BoltDB + SQLite — no sidecars, no external dependencies beyond the operator's own infra (DNS, optional CrowdSec instance, optional SMTP server, optional IdP).

## Who is it for ?

Designed for the operator running **5 to 50 routes on a single host** (homelab, small business, freelance). Not designed for multi-tenant cloud deployments, not designed for k8s ingress controller scenarios. If you want production posture without production complexity, Arenet is the target audience.

## How is this wiki organized ?

- **Get-started pages** are tutorials with copy-paste commands you can follow top-to-bottom.
- **Feature pages** explain a single capability in depth : what it does, when to use it, how to configure it, common pitfalls.
- **Operations pages** cover lifecycle tasks (backup, recovery, alerting wiring).
- Every page ends with a "**See also**" linking related topics and the relevant files in the `docs/` folder of the main repo (for operators who want to dig into the architecture).

If you find a gap or want to contribute a page, [open an issue](https://github.com/barto95100/arenet/issues).

## Version coverage

This wiki tracks **Arenet v2.40.x** (the current stable release line). Older versions may differ in feature surface ; check the [release notes](https://github.com/barto95100/arenet/releases) when in doubt.

## Where things live (cheat sheet)

| Concept | UI path | API path | Storage |
| ------- | ------- | -------- | ------- |
| Routes | `/routes` | `/api/v1/routes` | BoltDB `routes` bucket |
| TCP / UDP services | `/tcp-services` | `/api/v1/tcp-services` | BoltDB `tcp_services` bucket |
| Certificates | `/certs` | `/api/v1/certificates` | Caddy storage + cert tracker |
| DNS providers | `/settings` (DNS Providers) | `/api/v1/settings/dns-providers` | BoltDB `dns_providers` bucket |
| WAF events | `/security` | `/api/v1/security/events` | SQLite `waf_event` table |
| Cert events | `/logs` (CERT badge) | `/api/v1/observability/cert-events` | SQLite `cert_event` table |
| Audit log | `/audit` | `/api/v1/audit/events` | BoltDB `audit` bucket |
| Alerting rules | `/alerting` (Rules tab) | `/api/v1/alerting/rules` | BoltDB `alert_rules` bucket |
| OIDC config | `/settings` | `/api/v1/settings/oidc` | BoltDB `oidc_config` key |
| Users | `/users` | `/api/v1/users` | BoltDB `users` bucket |
| Backup snapshot | `/settings` (Backup section) | `/api/v1/admin/backup` + `/admin/restore` | All buckets serialized to JSON |

Default admin port : `:8001` (loopback by default ; set `ARENET_ADMIN_BIND=0.0.0.0:8001` for LAN access).

---

## Environment variables (cheat sheet)

All optional — every variable has a safe default. Set them the same way in **both** deploy modes:

- **Docker** — an `environment:` block in `docker-compose.yml` (or `-e VAR=value` on `docker run`).
- **systemd / binary** — lines in `/etc/arenet/arenet.env` (sourced by the unit via `EnvironmentFile=`), or `Environment="VAR=value"` in the unit file.

| Variable | Default | What |
| -------- | ------- | ---- |
| `ARENET_ADMIN_BIND` | `127.0.0.1:8001` | Admin UI/API bind address (`0.0.0.0:8001` for LAN). |
| `ARENET_DATA_DIR` | `/var/lib/arenet` | State directory (BoltDB + SQLite). |
| `ARENET_HTTP_PORT` / `ARENET_HTTPS_PORT` | `:80` / `:443` | Public data-plane listen ports. |
| `ARENET_ACME_EMAIL` | _(none)_ | Contact email for the ACME issuer (Let's Encrypt notices). |
| `ARENET_UPDATE_CHECK_INTERVAL` | `24h` | Update-checker cadence (Go duration, min `1h`; the check is enabled in *Settings → Updates*, not by env). |
| `ARENET_TRUSTED_PROXIES` | _(none)_ | CIDRs whose `X-Forwarded-For` is trusted (behind a front proxy / LB). |
| `ARENET_UI_ORIGIN` | _(none)_ | SPA origin for OIDC callback redirects when the UI is served separately. |
| `ARENET_CROWDSEC_API_URL` / `ARENET_CROWDSEC_API_KEY` | _(none)_ | CrowdSec LAPI wiring — see [CrowdSec](CrowdSec). |
| `ARENET_GEOIP_MMDB` | `/var/lib/arenet/GeoLite2-City.mmdb` | Path to the operator-supplied (or auto-downloaded via *Settings → GeoIP*) GeoLite2-City database. |
| `ARENET_GEOIP_ASN_MMDB` | `GeoLite2-ASN.mmdb` next to the City database | Path to the GeoLite2-ASN database used by the [ASN rules](Country-Block#asn-networks-v2280) (auto-downloaded with the City database). |
| `ARENET_PUBLIC_IP` | _(auto)_ | Override the server's detected public IP (topology / geo map). |
| `ARENET_TOPOLOGY_TICK_MS` | `2000` | Topology WebSocket push interval, in ms (snapped up to a multiple of 1000). |

> **When you upgrade:** environment variables are **provided by you** — Arenet never writes to your `.env` or compose file (a network-facing service should not edit its own system config; same reasoning as [why there's no auto-update](Updates#security-notes)). New variables in a release are listed in that release's notes; add the ones you want to your `.env` / compose. Every variable has a safe default, so an upgrade never *requires* editing your config — unset just means "use the default".
