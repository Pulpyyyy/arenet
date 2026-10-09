# Installation

**🌐 English** · [Français](Installation-FR)

Two supported install paths : **Docker** (recommended for most homelabs) and **native systemd** on Linux. Pick one — both end at the same place : a running Arenet instance with the admin UI accessible on `:8001` and the public listener on `:80` + `:443`.

This page is the condensed guide. For per-OS details, see the [docs/install/](https://github.com/barto95100/arenet/tree/main/docs/install) folder in the main repo.

---

## Prerequisites

| Requirement | Why |
| ----------- | --- |
| Linux host (amd64 or arm64) | Native binary target ; Docker image is multi-arch |
| Public DNS pointing at the host | For ACME HTTP-01 challenge to work for auto-HTTPS |
| TCP/80 + TCP/443 open inbound | HTTP-to-HTTPS redirect + HTTPS serving |
| **UDP/443 open inbound** | HTTP/3 over QUIC ([see HTTP/3 doc](https://github.com/barto95100/arenet/blob/main/docs/operations/http3.md)) |
| Optional : DNS provider API creds | DNS-01 challenge for wildcard certs — configure one or more OVH accounts, see [DNS Providers](DNS-Providers) |

Hardware target : 2 vCPU + 1 GB RAM is comfortable for 50 routes. The Coraza WAF is the heaviest consumer — disable it per-route on low-resource hosts if needed (see [WAF](WAF)).

---

## Path 1 : Docker (recommended)

### 1. Grab the compose file

```bash
mkdir -p ~/arenet && cd ~/arenet
curl -O https://raw.githubusercontent.com/barto95100/arenet/main/docker-compose.yml
```

### 2. Pull + start

```bash
docker compose pull
docker compose up -d
```

A named volume `arenet-data` holds the BoltDB + SQLite state + Caddy certs. Backup the whole volume (or use the [Backup UI](Backup-Restore)) for disaster recovery.

### 3. Get the setup token

On first boot, Arenet generates a one-time setup token to bootstrap the admin account. Find it in the logs :

```bash
docker compose logs arenet | grep "setup token"
```

You'll see a line like : `setup token : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### 4. Open the wizard

Open `http://<your-host>:8001` in a browser. The setup wizard asks for :
- The setup token (from step 3)
- An admin username + password (Argon2id-hashed)
- An admin email (for alerting + recovery)

Click **Submit** → you're in. The setup token is consumed (one-time use), the admin account is created with role `admin`, and the setup wizard disappears on subsequent visits.

### Data directory setup (named volume vs bind mount)

The data directory holds `arenet.db` (routes, users, audit, and **secrets** — OIDC client secrets, DNS API keys, the admin password hash) plus the TLS private keys under `certmagic/`. Since v2.30 those secrets are **encrypted** with `arenet.key`, generated next to the database on first boot — back it up separately (see [Updates → Migration safety](Updates#5-migration-safety); `ARENET_SECRET_KEY_FILE` moves it, e.g. to a Docker secret). Arenet keeps it **owner-only (`0700`)**, owned by the distroless `nonroot` user (UID **65532**).

**Named volume (the default) — nothing to do.** Docker seeds a fresh named volume's ownership and permissions from the image's `/var/lib/arenet`, which ships as `65532:65532` mode `0700`. It just works, and secrets are owner-only from the first boot.

**Bind mount (`./data:/var/lib/arenet`) — needs a one-time ownership fix.** A host directory is owned by whoever created it (usually root or your login user), **not** UID 65532. The distroless container has no shell and can't `chown` its own mount, so it crash-loops with `permission denied`. Pick one:

**Option A — manual (simplest):** create the dir with the right owner and mode before `docker compose up` :

```bash
mkdir -p ./data
sudo chown -R 65532:65532 ./data   # distroless 'nonroot' UID
sudo chmod 700 ./data              # owner-only: secrets + TLS keys
```

Then edit `docker-compose.yml` to mount `./data:/var/lib/arenet` instead of the named volume.

**Option B — init container (automatic, idempotent):** add a one-shot service that fixes ownership before Arenet starts. It also **tightens a directory left at `0755` by a pre-v2.15.1 install**. Add to `docker-compose.yml` :

```yaml
services:
  arenet:
    # ... existing config ...
    volumes:
      - ./data:/var/lib/arenet     # bind mount instead of the named volume
    depends_on:
      arenet-init:
        condition: service_completed_successfully

  arenet-init:
    image: busybox:1.37
    user: "0:0"                    # runs as root only to chown the mount
    command: ["sh", "-c", "chown -R 65532:65532 /data && chmod 700 /data"]
    volumes:
      - ./data:/data               # SAME host dir as arenet's bind mount
    restart: "no"
    security_opt:
      - no-new-privileges:true
```

`arenet-init` runs once, fixes the mount, and exits; `depends_on … service_completed_successfully` makes Arenet wait for it. It's safe to leave in place — re-running it is a no-op.

> **Why 65532 / 0700?** `65532` is the distroless `nonroot` user Arenet runs as. `0700` means only that user can read or write the directory — so the secrets in `arenet.db` and the TLS private keys aren't exposed to other users or containers sharing the host. See [Updates → Migration safety](Updates#5-migration-safety) if you're upgrading an older install, and [Troubleshooting → permission denied](Troubleshooting) if a boot fails on the data dir.

---

## Path 2 : Native Linux + systemd

For operators who don't want Docker, or want to integrate Arenet with the host's existing systemd unit graph (e.g. `WantedBy` your monitoring stack).

### 1. Run the install script

```bash
curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh \
  | sudo bash
```

The script :
- Downloads the latest release binary (multi-arch) from GitHub releases
- Creates the `arenet` system user (no shell, locked password)
- Installs the binary at `/usr/local/bin/arenet`
- Installs the systemd unit at `/etc/systemd/system/arenet.service`
- Creates `/var/lib/arenet/` for BoltDB + SQLite state
- Reloads systemd (`systemctl daemon-reload`)

Arenet creates and keeps `/var/lib/arenet` at mode **`0700`** (owner-only) — it holds secrets and TLS private keys. Fresh installs get this automatically; if you're **upgrading from before v2.15.1**, the binary tightens the dir to `0700` on its next boot. To confirm : `stat -c '%a' /var/lib/arenet` → `700`.

### 2. Start the service

```bash
sudo systemctl enable --now arenet
```

### 3. Get the setup token

```bash
sudo journalctl -u arenet --since "1 min ago" | grep "setup token"
```

### 4. Open the wizard

Same as Docker path step 4 — `http://<your-host>:8001`, paste the token, create the admin account.

---

## Post-install : exposing the admin UI

By default the admin UI binds to `127.0.0.1:8001` (loopback only) for safety. To access it from your LAN :

**Docker** : the `docker-compose.yml` already publishes `8001:8001` so it's reachable on `http://<docker-host>:8001` from your LAN. Restrict via Docker network policies or your firewall.

**systemd** : edit `/etc/systemd/system/arenet.service` and set the env var :

```ini
[Service]
Environment="ARENET_ADMIN_BIND=0.0.0.0:8001"
```

Then `systemctl daemon-reload && systemctl restart arenet`.

⚠️ **Don't expose the admin UI publicly**. Use [OIDC SSO](OIDC-SSO) + a route that targets `127.0.0.1:8001` so the admin sits behind your auth chain.

---

## Environment variables (optional)

All of these are optional overrides — set them via `environment:` in `docker-compose.yml` or `Environment="..."` in the systemd unit.

| Variable | Default | What |
| -------- | ------- | ---- |
| `ARENET_ADMIN_BIND` | `127.0.0.1:8001` | Admin UI/API bind address. Set `0.0.0.0:8001` for LAN access (see above). |
| `ARENET_ADMIN_ALLOWED_CIDRS` | _(private networks)_ | Client IPs allowed to reach the admin (CIDRs or bare IPs, comma-separated). Empty = loopback, RFC 1918, Tailscale, IPv6 ULA/link-local; anything else gets a 403. Example: `192.168.1.50,127.0.0.1` (systemd) — on Docker the SSH tunnel arrives from the network gateway, so use e.g. `192.168.1.50,172.20.0.1`. |
| `ARENET_DATA_DIR` | `/var/lib/arenet` | Where the binary stores its BoltDB/SQLite state. |
| `ARENET_UPDATE_CHECK_INTERVAL` | `24h` | Cadence of the opt-in update checker (Go duration, min `1h`). The check must still be **enabled in Settings → Updates** — there is no env toggle for that. See [DNS Providers → Stay updated](DNS-Providers#stay-updated). |
| `ARENET_ACME_EMAIL` | _(none)_ | Contact email passed to the ACME issuer for Let's Encrypt notices. |

More operational env vars (`ARENET_CROWDSEC_*`, `ARENET_UI_ORIGIN`, …) are documented in the relevant feature pages.

---

## Verifying the install

```bash
# Healthz endpoint
curl http://localhost:8001/healthz

# Expected output : {"status":"ok"}
```

If you see `{"status":"ok"}`, Arenet is running and the embedded Caddy + BoltDB + Coraza + CrowdSec bouncer have all booted cleanly. If not, see [Troubleshooting](Troubleshooting).

---

## See also

- [Routes](Routes) — wire your first proxied host
- [Backup & Restore](Backup-Restore) — save your config before/after upgrades
- [Troubleshooting](Troubleshooting) — common install pitfalls + log decoding
- [`docs/install/docker-quickstart.md`](https://github.com/barto95100/arenet/blob/main/docs/install/docker-quickstart.md) — extended Docker guide with troubleshooting
- [`docs/install/systemd-native.md`](https://github.com/barto95100/arenet/blob/main/docs/install/systemd-native.md) — extended systemd guide
