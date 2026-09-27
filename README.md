<div align="center">

<img src="web/frontend/src/lib/assets/arenet-logo.png" alt="Arenet" width="120" />

# Arenet

**🌐 English** · [Français](README.fr.md)

**A homelab-friendly reverse proxy with integrated security**

[![Release](https://img.shields.io/github/v/release/barto95100/arenet?style=flat-square&color=2563eb)](https://github.com/barto95100/arenet/releases)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?style=flat-square&logo=go)](https://go.dev)
[![Caddy](https://img.shields.io/badge/caddy-v2.11-1f88c0?style=flat-square)](https://caddyserver.com)
[![Coraza](https://img.shields.io/badge/coraza-v3.7%20%2B%20CRS%20v4-d62828?style=flat-square)](https://coraza.io)

Single-binary reverse proxy combining Caddy v2's production-grade HTTP engine with a homelab-friendly admin UI and native security integrations — WAF, IP reputation, country blocking, rate limiting — usually found only in commercial products.

[Quickstart](#-quickstart) · [Features](#-features) · [Screenshots](#-screenshots) · [Comparison](#-vs-alternatives) · [Documentation](#-documentation)

</div>

---

## ✨ Why Arenet

Most homelab reverse proxies (Nginx Proxy Manager, Zoraxy) give you an admin UI on top of an HTTP engine, then stop. Production-grade tools (Caddy, Traefik) give you the engine but leave the security stack as homework — wire your own WAF, your own IP reputation feed, your own alert pipeline.

Arenet is the **engine + UI + security stack as one binary**. Configure a route, pick a TLS mode, toggle a WAF profile, attach an OIDC SSO, wire a Discord alert on cert renewal failures — all from the same admin UI, all served by one Go binary, all backed by a single embedded BoltDB.


## 🚀 Quickstart

Two install paths, both under 5 minutes.

### Docker (recommended)

```bash
# Grab the reference compose file and bring the stack up. It wires
# the data volume, the NET_BIND_SERVICE cap for :80/:443, and the
# in-binary healthcheck for you.
curl -O https://raw.githubusercontent.com/barto95100/arenet/main/docker-compose.yml
docker compose up -d
```

The admin UI on `:8001` binds to `127.0.0.1` only by default. Grab
the setup token with `docker compose logs arenet | grep 'Setup token'`,
then reach the admin via an SSH tunnel (`ssh -L 8001:localhost:8001 <host>`)
and open `http://localhost:8001`.

Full guide: [docs/install/docker-quickstart.md](docs/install/docker-quickstart.md)

### Native Linux + systemd

```bash
# Downloads the release binary + systemd unit, creates the arenet
# user + data dir, then enables & starts the service. One command.
curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh | sudo bash
```

Then grab the setup token: `sudo journalctl -u arenet | grep 'Setup token'`.

Full guide: [docs/install/systemd-native.md](docs/install/systemd-native.md)

### ⚠️ Back up `arenet.key`

On first boot Arenet generates `arenet.key` in its data directory
(`/var/lib/arenet`). It encrypts every secret stored in `arenet.db`
(DNS credentials, private keys, CrowdSec / OIDC / MaxMind secrets…).
**Copy it somewhere safe, away from the server** — without it those
secrets cannot be recovered and Arenet refuses to start on the
encrypted database. `ARENET_SECRET_KEY_FILE` moves it (e.g. to a
Docker secret). Details: [wiki → Updates](https://github.com/barto95100/arenet/wiki/Updates#5-migration-safety).

## 🎯 Features

### Routing & TLS
- 🔀 **Per-route reverse proxy** with weighted load balancing, alias hostnames, advanced active health checks (status code + body regex)
- 🔒 **Auto-HTTPS** via Caddy ACME (Let's Encrypt + ZeroSSL fallback) — HTTP-01, DNS-01 with 9 native providers (OVHcloud, Cloudflare, DigitalOcean, Gandi, Hetzner, Infomaniak, Porkbun, Route 53, Scaleway) + connection test, wildcard via managed-domain apex
- 🌐 **HTTP/3 (QUIC)** active by default on every HTTPS route — zero config required
- 🔄 **Host header preservation** by default — works out of the box with OIDC IdPs, multi-tenant SaaS, and any backend that builds URLs from `Host:`
- 🩹 **Hot-reload** every route change without dropping in-flight connections
- 📦 **HTTPS-to-HTTPS upstream support** with optional TLS verification skip for self-signed internal backends
- 📥 **Import a Caddyfile** — paste it, preview what would be created (with every directive that could not be translated, and its line), pick the hosts, import
- 🎨 **Custom error pages** per route via HTML templates (401/403/404/429/500/502/503/504), with optional **branded catch-all** for unmatched hosts (template-promotable via a single checkbox)
- 🚦 **3-state route lifecycle** — one control per route toggles **Active / Maintenance / Disabled**. Maintenance serves a branded 503 page + `Retry-After` (friendly number+unit input) + an optional global message, with a per-route **client-IP bypass allow-list** so you can verify the app is back before flipping everyone over ; Disabled parks the route (config preserved) and drops it from Caddy

### Security
- 🛡️ **Integrated WAF** via Coraza v3 + OWASP CRS v4 with per-route opt-out, per-rule and per-tag exclusion, **targeted exclusions** created from a WAF event (one rule stops inspecting one field, on one path), **guided rules** (block on path / method / User-Agent / header without writing SecLang) and a **SecLang editor** with commented templates and a request tester — all checked against a strict allowlist
- 🚦 **Rate limiting** per route (events/window/key, e.g. "60 req/min per remote IP on /api/login")
- 🌍 **Country blocking** via embedded MaxMind GeoLite2 (allow-list / deny-list per route)
- 🔐 **Secrets encrypted at rest** — DNS credentials, private keys and API keys are sealed (AES-256-GCM) inside `arenet.db` with a key kept apart; session IDs are stored hashed
- 🔥 **CrowdSec integration** for community threat intelligence (LAPI bouncer, auto-ban on community decisions)
- 🔐 **OIDC SSO** with allowlist (email + sub canonicalisation, accept-unverified-email opt-in, authentik/Keycloak/Authelia tested)
- 👥 **RBAC** with `viewer` / `admin` roles + local break-glass account preserved when OIDC is wired
- 🚪 **Forward auth** (Authelia / oauth2-proxy / Authentik external auth) wired per route
- 🔒 **Basic auth** per route (Argon2id, preserve-on-edit secret semantic)

### API
- 📗 **OpenAPI 3.1 description** of the whole admin API, served at `/api/v1/openapi.json` and browsable in the UI (**API docs** page) with schemas, examples and a **Try it** button
- 🔑 **Service accounts** — API tokens (`Authorization: Bearer …`) with a role and an optional expiry, for scripts and CI

### Observability
- 📊 **Live topology dashboard** (SvelteKit + D3.js) with real-time req/s particles, per-route metrics, alias clustering
- 📈 **Per-route timeseries** (req/s, 4xx/5xx rate, p95 latency, WAF detect/block rate) — Step L
- 🔍 **Unified activity log** (`/logs`) — WAF + rate-limit + auth + throttle + cert events with source histogram, level filter, search, GeoIP per remote IP
- 🛡️ **WAF event drilldown** per route — CRS category distribution, rule history, false-positive triage
- 🗺️ **GeoIP world map** showing live blocked-by-country distribution
- 📋 **Audit log** for every config change with before/after diff and actor attribution
- 🎫 **Cert lifecycle observability** — track every `cert_obtained`, `cert_failed`, `cert_ocsp_revoked` event with 90d retention, and **delete an orphan certificate** from the dashboard

### Alerting (Step AL)
- 🔔 **Multi-channel routing** — Discord, generic webhook, SMTP email
- 📐 **Threshold + state rules** — `waf_event_rate > 10`, `cert_expiry < 14d`, `system_health == degraded`, `cert_renewal_failed > 0`
- ⏱️ **30s polling watcher** with per-rule cooldown to prevent alert storms
- 📜 **Alert history** with rule pinpointing + channel delivery status
- 🧪 **Test mode** — fire a synthetic alert through any channel to validate the wiring

### Operations
- 💾 **Backup/Restore via UI** — full config snapshot (routes, users, OIDC, DNS providers, forward-auth, allowlists) with sentinel-resolution for secrets and atomic rollback on Caddy reload failure
- 🌓 **Dark + Light themes** with system-preference detection and per-user persistence
- 🎨 **Branded error pages** + custom HTML templates with Caddy placeholder support (`{http.request.uri}`, `{http.request.uuid}`, etc.), including a brandable catch-all for requests landing on hostnames not configured on any route
- ⚙️ **Initial setup wizard** with one-time setup token for cold-boot bootstrap
- 🐳 **Single binary** (~100 MB) — no sidecars, no agents, no external Redis/PostgreSQL dependency

## 📸 Screenshots

> Screenshots coming soon. For a live preview, follow the [quickstart](#-quickstart) and open `http://<host>:8001`.

## 🆚 vs Alternatives

| Feature                       | Arenet | Zoraxy | NPM     | Traefik | Caddy raw |
| ----------------------------- | ------ | ------ | ------- | ------- | --------- |
| Single-binary install         | ✅     | ✅     | ❌      | ✅      | ✅        |
| Web admin UI                  | ✅     | ✅     | ✅      | Limited | ❌        |
| Integrated WAF (OWASP CRS)    | ✅     | ❌     | ❌      | Plugin  | Plugin    |
| CrowdSec bouncer              | ✅     | ❌     | ❌      | Plugin  | Plugin    |
| Country blocking              | ✅     | ✅     | ❌      | Plugin  | Plugin    |
| Live topology graph           | ✅     | ✅     | ❌      | ❌      | ❌        |
| OIDC SSO + RBAC               | ✅     | Limited| ❌      | Limited | ❌        |
| Backup/restore via UI         | ✅     | Limited| ✅      | ❌      | ❌        |
| Per-route alerting rules      | ✅     | ❌     | ❌      | ❌      | ❌        |
| Auto-HTTPS + HTTP/3           | ✅     | ✅     | ✅      | ✅      | ✅        |
| Cert lifecycle observability  | ✅     | Limited| ❌      | Limited | Logs only |
| AGPL-3.0 (truly open-source)  | ✅     | ✅     | MIT     | MIT     | Apache    |

Arenet's positioning : **production-grade security + observability that ships in the box**, not as N plugins to wire together.

## 📚 Documentation

| Section | Where |
| ------- | ----- |
| Installation (Docker + systemd) | [docs/install/](docs/install/) |
| Operations (backup, config, hardening) | [docs/operations/](docs/operations/) |
| HTTP/3 verification + firewall | [docs/operations/http3.md](docs/operations/http3.md) |
| Alerting subsystem (channels, rules, watcher) | [docs/alerting.md](docs/alerting.md) |
| Troubleshooting | [docs/operations/troubleshooting.md](docs/operations/troubleshooting.md) |
| **User Wiki** (how-to guides) | [GitHub Wiki](https://github.com/barto95100/arenet/wiki) |
| API reference | in-app **API docs** page, `/api/v1/openapi.json`, [wiki: API](https://github.com/barto95100/arenet/wiki/API) |
| Engineering practices | [docs/ENGINEERING-PRACTICES.md](docs/ENGINEERING-PRACTICES.md) |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Arenet (single Go binary)                              │
├─────────────────────────────────────────────────────────┤
│  SvelteKit Admin UI (static build, embed.FS)            │
│           ↓                                             │
│  REST API + WebSocket (chi + gorilla/websocket)         │
│           ↓                                             │
│  BoltDB (config, users, audit) + SQLite (event store)   │
│           ↓                                             │
│  Caddy Manager (routes → Caddy JSON config)             │
│           ↓                                             │
│  Caddy v2 (embedded library)                            │
│   + Coraza WAF (OWASP CRS v4)                           │
│   + CrowdSec bouncer                                    │
│   + caddy-ratelimit                                     │
└─────────────────────────────────────────────────────────┘
```

Caddy is embedded as a **library**, not run as a sidecar — one process, one network stack, one shutdown path.

## 🛠️ Built with

- **[Caddy v2.11](https://caddyserver.com)** — HTTP engine, auto-HTTPS, ACME
- **[Coraza v3.7](https://coraza.io)** + **[OWASP CRS v4.25](https://coreruleset.org)** — WAF
- **[CrowdSec bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer)** — IP reputation
- **[caddy-ratelimit](https://github.com/mholt/caddy-ratelimit)** — per-route throttling
- **[BoltDB](https://github.com/etcd-io/bbolt)** — config + audit storage
- **[SvelteKit 5](https://kit.svelte.dev)** + **[Tailwind CSS](https://tailwindcss.com)** + **[D3.js](https://d3js.org)** — frontend
- **Go 1.26+** — single-binary toolchain

## 🤝 Contributing

Arenet is currently a single-developer project but contributions are welcome.

- Bug reports + feature requests → [GitHub Issues](https://github.com/barto95100/arenet/issues)
- Engineering practices + coding conventions → [docs/ENGINEERING-PRACTICES.md](docs/ENGINEERING-PRACTICES.md)
- All source files MUST carry the AGPL-3.0 header — see `CLAUDE.md` § "AGPLv3 Header"
- Empirical verification rule — any claim about Caddy / Coraza / CrowdSec runtime behaviour must cite source or be backed by a test

## 🌐 Translations

Arenet's UI, README, and Wiki are i18n complete end-to-end in **English** and **French** as of v2.10.x.

- App UI : EN + FR (Phase 3 frontend i18n, v2.9.x ships)
- README : [English](README.md) · [Français](README.fr.md)
- Wiki : [English](https://github.com/barto95100/arenet/wiki/Home) · [Français](https://github.com/barto95100/arenet/wiki/Home-FR)

Contributions for additional languages (DE, ES, IT, etc.) welcome — see the wiki's [`Home`](https://github.com/barto95100/arenet/wiki/Home) and `web/frontend/src/lib/i18n/locales/` for the existing bundle structure. Open an issue first to coordinate.

## 📜 License

[AGPL-3.0](LICENSE) — copyleft for the network-served use case. Modifications served over a network must be made available under the same license.

## 🙏 Inspired by

[Zoraxy](https://github.com/tobychui/zoraxy) by tobychui — the homelab-UI-on-reverse-proxy pattern that proved the audience exists. Arenet rebuilds the concept on top of Caddy with native security integrations and an observability stack designed for the operator who runs a homelab seriously.

---

<div align="center">

**Made for homelab operators who want production posture without production complexity.**

[⬆ back to top](#arenet)

</div>
