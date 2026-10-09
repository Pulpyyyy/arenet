# Quickstart — Docker (5 minutes)

This is the fastest path to a running Arenet instance. The whole
thing fits in five terminal commands and the `/setup` browser
wizard.

**You'll need**: a Linux host with Docker + Docker Compose v2
(Docker Desktop on macOS/Windows works for testing, but the
homelab deploy target is Linux).

---

## 1. Grab the compose file

```bash
mkdir -p ~/arenet && cd ~/arenet
curl -O https://raw.githubusercontent.com/barto95100/arenet/main/docker-compose.yml
```

(Alternatively, clone the repo and `cd` into it — the file lives
at the root.)

## 2. Pull the image

```bash
docker compose pull
```

The image is multi-arch (linux/amd64 + linux/arm64); your machine
gets the right variant automatically. Image size: ~22 MB
compressed, ~94 MB uncompressed on disk.


**If pull fails with `denied`** (image not yet published for your
version, or you're an early adopter building before the first
release): if you cloned the repo in step 1, you can build the
image locally instead. Run this once from the repo root:

```bash
docker build -t ghcr.io/barto95100/arenet:latest .
```

The build takes 2-3 minutes (frontend bundle + Go binary). Once
it completes, the local image satisfies `docker compose up -d`
in step 3 — no further changes needed.

## 3. Start the stack

```bash
docker compose up -d
```

A named volume `arenet-data` is created on first boot to hold
Arenet's state (routes, users, certs, audit log, observability
counters). Cold-stop + tar of that volume is the canonical
backup procedure — see `docs/operations/backup.md`.

**Using a bind mount instead?** If you've modified the compose
file to use a bind mount (e.g. `./data:/var/lib/arenet` or
`/home/you/arenet/data:/var/lib/arenet`) for easier backup or
inspection, you must pre-create the host directory with the
correct ownership *before* the first `docker compose up`:

```bash
mkdir -p ./data
sudo chown -R 65532:65532 ./data
```

The container runs as user 65532 (distroless `nonroot`); without
this chown the container can't write to your bind mount and will
restart-loop with `permission denied`. Named volumes don't need
this step — Docker inherits the correct ownership from the image
automatically.

### Where files live

Everything Arenet writes goes under `/var/lib/arenet` inside the
container — the database, the certificates, and the HTTP access
log at `/var/lib/arenet/logs/access.log` once you enable it.

That is deliberate rather than conventional: `/var/log` inside a
container belongs to the writable layer, not to a mount, so a log
written there would be destroyed the next time the container is
replaced — which is what an upgrade is.

The access log is **off by default**; it records every visitor's
IP and the URLs they request. Enable it in Settings → Security
when you want CrowdSec to detect attacks against this host. A
CrowdSec agent in a sibling container reads it by mounting the
same volume read-only:

```yaml
crowdsec:
  volumes:
    - arenet-data:/var/lib/arenet:ro
```

The agent must run as root to read it: Caddy creates the file
`0600` owned by uid 65532, the same `nonroot` user as above. The
official CrowdSec image does. See
[CrowdSec](../wiki-seed/CrowdSec.md).

## 4. Get the setup token

On first boot Arenet generates a one-shot setup token. Tail the
logs to grab it:

```bash
docker compose logs arenet | grep "Setup token"
```

You'll see a line like:

```
time=2026-06-01T15:24:48.451Z level=INFO msg="Setup token: 822305f5fce4c05b39a5c4915b32f77a9637ae0379c3d25fa9e2938b45a24863"
```

Copy that token — you'll paste it into the browser in a moment.

## 5. Open the admin UI

**By default Arenet's admin port :8001 binds to 127.0.0.1 only**
(your data plane on :80 / :443 is fully LAN-accessible — only
the admin UI is loopback-restricted, to avoid serving a plaintext
admin endpoint on your LAN by accident).

To reach the admin from a workstation on your LAN, pick one of:

### Option 1 — SSH tunnel (recommended, no config change)

From your workstation:

```bash
ssh -L 8001:localhost:8001 <homelab-host>
```

Leave that terminal running. Then in your browser, open:

```
http://localhost:8001
```

The browser hits your local tunnel; the tunnel forwards to the
homelab box's loopback :8001.

### Option 2 — Bind admin to the LAN (less secure)

If you don't want the SSH tunnel, edit your `docker-compose.yml`
on the homelab box:

```yaml
ports:
  - "80:80"
  - "443:443"
  - "443:443/udp"
  - "8001:8001"                    # was: "127.0.0.1:8001:8001"
```

The port mapping is the only change: inside the container the
admin always listens on `:8001` (Docker forwards published ports
to the container's network interface, not its loopback), so
`ARENET_ADMIN_BIND` stays unset in Docker installs.

Then `docker compose up -d` to apply. Now anyone on your LAN can
reach the admin port over plain HTTP — put a TLS terminator
(Caddy / Nginx / Cloudflare Tunnel) in front before relying on
this for anything sensitive.

### Finish setup

In the browser:

1. Paste the setup token from step 4.
2. Create your first admin user (username + password).
3. The wizard logs you in automatically.

You're done. Add your first route from the Routes page and
Arenet starts proxying.

---

## What's next

- **Add a route**: from the Routes page, click "+ Add route".
  Hostname + upstream URL is the minimum; TLS + WAF + auth are
  per-route toggles.
- **Backup your data**: see `docs/operations/backup.md`.
- **Harden the install**: see `docs/operations/hardening.md`
  (admin TLS options, rate limits, secret storage).
- **Troubleshooting**: `docs/operations/troubleshooting.md`
  covers log levels, common boot warnings, and the "I can't
  reach the admin port" checklist.

## If something went wrong

```bash
docker compose logs arenet | tail -50    # last 50 log lines
docker compose ps arenet                 # container state
docker exec arenet /usr/local/bin/arenet --healthcheck=http://127.0.0.1:8001/healthz
                                         # in-container probe
```

If `docker compose ps` shows the container unhealthy, the
healthcheck is failing — check the logs above for the cause
(usually a port collision, a missing env var, or the volume
mount being unwritable).
