# Quickstart — systemd native install (5 minutes)

If you prefer running Arenet as a native systemd service rather
than in Docker (lighter footprint, no Docker daemon, integrates
with the rest of your Linux box's logging + monitoring), this is
the path. Same 5-minute target as the Docker quickstart.

**You'll need**: a Linux host with systemd (any distro from the
last decade works) + the ability to run `sudo`.

---

## 0. One-liner (fastest path)

If you just want it running on amd64/arm64, the install script
does everything — downloads the release binary + systemd unit,
creates the `arenet` user and data dir, then enables & starts the
service:

```bash
curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh | sudo bash
```

Then jump to [step 4](#4-grab-the-setup-token) to grab the setup
token. Useful environment overrides:

| Var | Effect |
|-----|--------|
| `ARENET_VERSION=v1.2.3` | Pin a release tag (default: latest). |
| `ARENET_SKIP_BINARY=1` | Don't download the binary — you'll build/copy it yourself (see step 1). |
| `ARENET_NO_START=1` | Install everything but don't enable/start the service. |

Prefer to do it by hand (build from source, air-gapped box,
custom binary)? Follow steps 1–3 below instead — the same script
run locally (`sudo ./install.sh`) reuses an existing binary and
the sibling unit file.

---

## 1. Get the binary onto the box

Three options:

### Option A — download from releases (recommended)

```bash
# Replace VERSION + ARCH for your target. v1.0.0 + linux-amd64
# is the typical desktop / x86 server combo; linux-arm64 covers
# Raspberry Pi 4/5 + ARM mini-PCs.
VERSION=v1.0.0
ARCH=linux-amd64

curl -L -o /tmp/arenet \
    "https://github.com/barto95100/arenet/releases/download/${VERSION}/arenet-${ARCH}"
chmod +x /tmp/arenet
sudo mv /tmp/arenet /usr/local/bin/arenet
```

### Option B — build from source

Requires Go 1.26+ and Node 20+ on the build host.

```bash
git clone https://github.com/barto95100/arenet.git
cd arenet/web/frontend && npm ci && npm run build && cd ../..
go build -ldflags "-s -w -X main.version=local" \
    -trimpath -o /usr/local/bin/arenet ./cmd/arenet
sudo chown root:root /usr/local/bin/arenet
```

### Option C — copy out of the Docker image

If you've already pulled the Docker image:

```bash
docker create --name _arenet_extract ghcr.io/barto95100/arenet:latest
docker cp _arenet_extract:/usr/local/bin/arenet /tmp/arenet
docker rm _arenet_extract
sudo mv /tmp/arenet /usr/local/bin/arenet
sudo chmod +x /usr/local/bin/arenet
```

## 2. Run the install script

Clone (or download just the packaging directory) and run the
script:

```bash
git clone https://github.com/barto95100/arenet.git
cd arenet/packaging/systemd
sudo ./install.sh
```

Run locally from a checkout, the script detects the binary you
placed in step 1 (it won't re-download), installs the sibling
`arenet.service`, creates the `arenet` system user, sets up
`/var/lib/arenet/` with the right permissions, drops a sample
env file at `/etc/arenet/arenet.env`, then **enables and starts
the service**. It's idempotent — safe to re-run.

Pass `ARENET_NO_START=1` if you'd rather stage everything and
start it yourself later.

### Where files live

| What | Path |
|---|---|
| Binary | `/usr/local/bin/arenet` |
| State (database, certificates) | `/var/lib/arenet/` |
| Env overrides | `/etc/arenet/arenet.env` |
| HTTP access log, when enabled | `/var/log/arenet/access.log` |

The unit declares `LogsDirectory=arenet`, so systemd creates
`/var/log/arenet` owned by the `arenet` user. That directive is
what makes the path writable at all: the unit also runs
`ProtectSystem=strict`, under which the whole filesystem is
read-only to the service except what is explicitly granted.

The access log is **off by default** — it records every
visitor's IP and the URLs they request. Enable it in
Settings → Security when you want CrowdSec to detect attacks
against this host; see [CrowdSec](../wiki-seed/CrowdSec.md).
Override the location with `ARENET_ACCESS_LOG_PATH` in the env
file, but keep in mind that a different directory under
`/var/log` will not be writable unless you add it to the unit.

Note that backups cover `/var/lib/arenet`, so the access log is
deliberately outside them. It is observability data, not state:
losing it costs nothing, and including request logs in a backup
you might email yourself would be a poor trade.

## 3. Confirm it's running

```bash
sudo systemctl status arenet
```

You should see `Active: active (running)`. If not, check the
logs:

```bash
sudo journalctl -u arenet -f
```

## 4. Grab the setup token

On first boot Arenet generates a one-shot setup token. It lands
in the journal:

```bash
sudo journalctl -u arenet | grep "Setup token"
```

## 5. Open the admin UI

**Arenet's admin port :8001 binds to 127.0.0.1 only by default.**
The data plane on :80 / :443 is LAN-accessible (that's the
point); only the admin UI is loopback-restricted.

To reach the admin from a workstation on your LAN, pick one of:

### Option 1 — SSH tunnel (recommended, no config change)

```bash
ssh -L 8001:localhost:8001 <homelab-host>
```

Then in your browser: `http://localhost:8001`.

### Option 2 — Bind admin to the LAN (less secure)

Edit `/etc/arenet/arenet.env` and uncomment the bind line:

```ini
ARENET_ADMIN_BIND=0.0.0.0:8001
```

Then restart:

```bash
sudo systemctl restart arenet
```

Now anyone on your LAN can reach the admin port over plain
HTTP. Put a TLS terminator in front before relying on this for
anything sensitive — see `docs/operations/hardening.md` for the
recipes.

### Finish setup

In the browser:

1. Paste the setup token from step 4.
2. Create your first admin user.
3. The wizard logs you in automatically.

You're done.

---

## What's next

- **Add a route**: Routes page → "+ Add route".
- **Backup**: see `docs/operations/backup.md` (cold-stop + tar
  of `/var/lib/arenet`).
- **Hardening**: see `docs/operations/hardening.md`.
- **Troubleshooting**: see `docs/operations/troubleshooting.md`.

## If something went wrong

```bash
sudo systemctl status arenet            # service state
sudo journalctl -u arenet -n 50         # last 50 log lines
sudo journalctl -u arenet -f            # live tail
/usr/local/bin/arenet --healthcheck=http://127.0.0.1:8001/healthz
                                        # ad-hoc probe
```

If the service won't start, the most common causes are:

1. **Port :80 / :443 already in use** by another service (nginx,
   apache, podman). Stop the other service or change Arenet's
   bind via env vars in `/etc/arenet/arenet.env`.
2. **Binary not at `/usr/local/bin/arenet`**: the unit's
   `ExecStart` hardcodes the path. Either put the binary there
   or edit the unit file's `ExecStart`.
3. **Data dir permissions**: `/var/lib/arenet` should be owned
   by `arenet:arenet` (0750). Re-run `install.sh` if you
   suspect drift.
