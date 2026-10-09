# Config reference

Arenet reads configuration from four sources, in this priority
order:

```
--flag    (highest priority)
ARENET_*  env vars
config.toml file
hardcoded defaults  (lowest priority)
```

A higher-priority source overrides a lower one **per-field**.
You can mix sources: set `data-dir` in the TOML file, override
`admin-bind` via env var, and pass `--dev` on the CLI — each
field independently picks the highest-priority source that
defined it.

## Quick reference

| Field | Default | Env var | TOML key |
|---|---|---|---|
| Admin bind | `:8001` (loopback) | `ARENET_ADMIN_BIND` | `admin-bind` |
| Data dir | `./data` | `ARENET_DATA_DIR` | `data-dir` |
| Dev mode | `false` | `ARENET_DEV` | `dev` |
| Test route | `false` | `ARENET_INSERT_TEST_ROUTE` | `insert-test-route` |
| UI origin (dev SPA) | `""` | `ARENET_UI_ORIGIN` | `ui-origin` |
| Config file path | `""` | `ARENET_CONFIG` | (n/a — self-referential) |

Plus the K.3 backup/restore flags (`--export`, `--restore`,
`--include-secrets`, `--passphrase-file`, `--allow-incomplete-restore`,
`--allow-empty-users`) and the S.1 healthcheck flag
(`--healthcheck`); these all have matching `ARENET_*` env vars
and TOML keys, see `arenet --help` for the canonical list.

## Decentralised env-only settings

For historical reasons (predating the S.3 centralised config
layer), a few settings are read directly via `os.Getenv` at
their call sites. They work the same as the centralised ones
above, but they are NOT exposed in the TOML file or as
`--flag`. Use the env var.

| Setting | Env var |
|---|---|
| ACME contact email | `ARENET_ACME_EMAIL` |
| CrowdSec LAPI URL | `ARENET_CROWDSEC_API_URL` |
| CrowdSec API key | `ARENET_CROWDSEC_API_KEY` |
| Trusted reverse-proxies (CIDR) | `ARENET_TRUSTED_PROXIES` |
| Admin source allowlist (CIDR) | `ARENET_ADMIN_ALLOWED_CIDRS` |
| Data plane HTTP override | `ARENET_HTTP_PORT` |
| Data plane HTTPS override | `ARENET_HTTPS_PORT` |
| HIBP password check | `ARENET_HIBP_DISABLED` |

Consolidating these into the central config layer is tracked
in `docs/backlog-step-s.md` #S-1.

## TOML file shape

```toml
# /etc/arenet/config.toml — Arenet config file
#
# Keys are kebab-case; values use TOML 1.0 syntax. Strings,
# bools, integers as expected. Anything you don't set falls
# through to env > default.

admin-bind = "127.0.0.1:8001"
data-dir   = "/var/lib/arenet"
dev        = false
```

## Loading the config file

The path is resolved from (in order): `--config <path>`, then
`ARENET_CONFIG`. If neither is set, no file is loaded — the
binary runs on env + defaults only.

A missing file (path set but file absent on disk) is **not an
error** — operators may run with the env file present and no
TOML file. A malformed TOML file IS an error and the binary
refuses to start.

## Docker compose pattern

Compose passes env vars via the `environment:` block. To use a
TOML file in a container, mount it as a read-only file:

```yaml
services:
  arenet:
    # ... existing config ...
    environment:
      ARENET_CONFIG: /etc/arenet/config.toml
    volumes:
      - arenet-data:/var/lib/arenet
      - ./config.toml:/etc/arenet/config.toml:ro
```

## systemd pattern

The unit ships `EnvironmentFile=-/etc/arenet/arenet.env`. Edit
that file to override defaults; uncomment the lines you want.
For a TOML file, set `ARENET_CONFIG` in `arenet.env`:

```ini
# /etc/arenet/arenet.env
ARENET_CONFIG=/etc/arenet/config.toml
ARENET_ADMIN_BIND=127.0.0.1:8001
```

Restart after editing:

```bash
sudo systemctl restart arenet
```

## Verify the effective config

The first INFO log line on boot shows the resolved values:

```
time=2026-06-01T18:35:11.951Z level=INFO msg="Arenet starting" version=v1.0.0 admin_port=:8001 data_dir=/var/lib/arenet dev=false
```

If a value looks wrong, check the precedence stack from top
down (flag → env → TOML → default).
