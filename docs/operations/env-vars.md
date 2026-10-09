# Environment variables reference

Arenet's runtime behaviour is configured through environment
variables (or the optional TOML config file — see
[config.md](config.md)). Every `ARENET_*` variable recognised by
the binary as of v1.0.0 is documented below, grouped by purpose.

## When and where to set them

- **Precedence**: `--flag` > `ARENET_*` env > TOML config file >
  hardcoded default. A higher source overrides a lower one
  **per-field**. Mixed sources work fine — you can pin
  `data-dir` in the TOML and override `admin-bind` via env on
  the same install.
- **Docker compose**: pass via the `environment:` block on the
  `arenet` service. See `docker-compose.yml` at the repo root
  for the canonical example.
- **systemd**: edit `/etc/arenet/arenet.env` (sourced by the
  unit via `EnvironmentFile=-/etc/arenet/arenet.env`).
- **Shell / dev**: `export ARENET_FOO=value` before running
  `./arenet`, or pass inline: `ARENET_FOO=value ./arenet`.
- **Verify what was loaded**: the first INFO log line on boot
  echoes the resolved primary values:

  ```
  level=INFO msg="Arenet starting" version=v1.0.0 admin_port=:8001 data_dir=/var/lib/arenet dev=false
  ```

  If a value isn't what you set, walk the precedence stack from
  the top (flag → env → TOML → default) to find which layer is
  winning.

## A note on naming

The flag-backed variables (10 of them) are routed through the
centralised `internal/config` package introduced in Step S.3.
The remaining 9 are read directly via `os.Getenv` at their call
sites — this is acknowledged backlog debt (#S-1 in
`docs/backlog-step-s.md`) and a future step may consolidate
them. Either way, the variable names and semantics documented
below are the public contract: they will not be silently
renamed or removed.

## Boolean parsing

Most boolean variables in this reference go through Go's
`strconv.ParseBool`, which accepts:

- **Truthy**: `1`, `t`, `T`, `TRUE`, `true`, `True`.
- **Falsy**: `0`, `f`, `F`, `FALSE`, `false`, `False`.
- **Invalid input**: silently ignored, the previous value
  (typically the default) is kept.

The single exception is `ARENET_HIBP_DISABLED`, which only
recognises the exact literal `true` (see its entry for the
rationale).

---

## Runtime config (always-on)

These variables shape every Arenet boot. Most have sensible
defaults; you'll typically touch 2–3 on a real install.

### `ARENET_DEV`

- **Purpose**: enables development mode — verbose logging, no
  TLS auto-issuance (Caddy's internal CA serves localhost /
  .local), dev-only landing page on the admin root.
- **Default**: `false` (unset = production behaviour).
- **Format**: boolean.
- **Example**: `ARENET_DEV=true`
- **Notes**: never set in production. The hardening doc's
  scorecard counts dev-mode-disabled as a baseline check.
- **Source**: `internal/config/config.go:269`.

### `ARENET_DATA_DIR`

- **Purpose**: filesystem path where Arenet stores its
  persistent state — `arenet.db` (BoltDB: routes, users,
  audit), `metrics.db` (SQLite: observability counters), the
  `certmagic/` cert + ACME state, and `audit.db` if the
  audit-overflow store is in use.
- **Default**: `./data` (dev convenience). Docker compose
  + systemd both override to `/var/lib/arenet`.
- **Format**: absolute or relative directory path.
- **Example**: `ARENET_DATA_DIR=/var/lib/arenet`
- **Notes**: the directory is created on first boot if absent
  (mode 0o755). If you point at a wrong/empty volume, a fresh
  database is silently created — watch the boot log for the
  "Initialised new database" line.
- **Source**: `internal/config/config.go:266`.

### `ARENET_SECRET_KEY_FILE`

- **Purpose**: path of the key that encrypts the secrets stored
  in `arenet.db` (DNS credentials, private keys of uploaded
  certificates, CrowdSec / MaxMind / OIDC / forward-auth secrets,
  alert channel credentials, sensitive route headers) — v2.30.
- **Default**: `<data dir>/arenet.key`, generated on first boot
  (32 random bytes, base64, mode 0600).
- **Format**: file path. The file holds the base64 encoding of a
  32-byte key (`openssl rand -base64 32` produces one).
- **Example**: `ARENET_SECRET_KEY_FILE=/run/secrets/arenet_key`
- **Notes**: **back the key up, separately from `arenet.db`** —
  without it the encrypted secrets cannot be recovered. Arenet
  refuses to start when the database is encrypted and the key is
  missing or different; it never generates a new key over
  encrypted data. Pointing this at a Docker secret or another
  disk keeps a copied data directory from carrying its own key.
- **Source**: `cmd/arenet/secrets_wiring.go`.

### `ARENET_CONFIG`

- **Purpose**: path to an optional TOML config file. When set,
  the file is loaded after defaults and before env-var
  overrides (env still wins).
- **Default**: unset (no config file loaded).
- **Format**: absolute or relative path to a `.toml` file.
- **Example**: `ARENET_CONFIG=/etc/arenet/config.toml`
- **Notes**: a missing file (path set, file absent on disk) is
  **not** an error — the binary proceeds on env + defaults
  alone. A malformed TOML file IS an error and the binary
  refuses to start. See [`config.md`](config.md) for the file
  shape.
- **Source**: `internal/config/config.go:182`.

### `ARENET_ADMIN_BIND`

- **Purpose**: address:port the admin REST API + WebSocket
  binds to.
- **Default**: `:8001` (binds all interfaces). systemd
  overrides to `127.0.0.1:8001` (loopback only) per spec D6.
  Docker keeps `:8001` inside the container (a loopback bind
  there is unreachable through a published port) and applies
  D6 on the host side by publishing `127.0.0.1:8001:8001`.
- **Format**: `host:port` or just `:port` (binds all
  interfaces). `127.0.0.1:8001` for loopback, `0.0.0.0:8001`
  for explicit all-interfaces, `[::]:8001` for IPv6.
- **Example**: `ARENET_ADMIN_BIND=127.0.0.1:8001`
- **Notes**: this is the **security boundary** for the admin
  surface. Loopback default is intentional — exposing admin to
  the LAN requires an explicit override AND a TLS terminator
  in front (see hardening doc item 2). Plain HTTP admin on a
  LAN-reachable bind is a real footgun.
- **Source**: `internal/config/config.go:263`.

### `ARENET_HTTP_PORT`

- **Purpose**: overrides the data-plane HTTP listen port (port
  80 in prod, 8080 in dev).
- **Default**: `80` when `ARENET_DEV=false`, `8080` when dev
  mode is on. Unset OR an invalid value falls back to the
  mode-based default.
- **Format**: integer in [1, 65535].
- **Example**: `ARENET_HTTP_PORT=8081`
- **Notes**: parsed leniently — invalid (non-numeric,
  out-of-range, empty) silently falls back to the default with
  no warning. The actual bound port is echoed in the boot log
  (`http=:8081`), so check that line if a typo is suspected.
- **Source**: `internal/caddymgr/manager.go:1490`,
  parser at `:1505`.

### `ARENET_HTTPS_PORT`

- **Purpose**: overrides the data-plane HTTPS listen port (port
  443 in prod, 8443 in dev).
- **Default**: `443` (prod) / `8443` (dev). Same fallback shape
  as `ARENET_HTTP_PORT`.
- **Format**: integer in [1, 65535].
- **Example**: `ARENET_HTTPS_PORT=8444`
- **Notes**: same lenient-parse caveat as `ARENET_HTTP_PORT` —
  verify against the boot log (`https=:8444`). Changing this
  affects only the listener; the ACME challenge path is
  independent.
- **Source**: `internal/caddymgr/manager.go:1491`,
  parser at `:1505`.

### `ARENET_UI_ORIGIN`

- **Purpose**: dev-only override that tells the OIDC callback
  handler to emit **absolute** redirects to the given origin
  on success and failure, instead of relative paths. Needed
  when the SPA is served by a separate dev server (Vite on
  `:5173`) while the API runs on `:8001`.
- **Default**: empty (production default). With no override,
  the OIDC callback emits relative redirects, which is correct
  when the static SPA is served by Arenet itself from the same
  origin as the API.
- **Format**: absolute origin (scheme + host + port, no
  trailing slash). E.g. `http://localhost:5173`.
- **Example**: `ARENET_UI_ORIGIN=http://localhost:5173`
- **Notes**: never set in production. If you do, the OIDC
  callback emits absolute redirects to an origin the
  production browser may not be able to reach.
- **Source**: `internal/config/config.go:300`.

### `ARENET_TRUSTED_PROXIES`

- **Purpose**: comma-separated CIDR allow-list for upstream
  reverse proxies whose `X-Forwarded-For` header Arenet should
  trust when resolving the client IP. Used by the auth /
  audit / rate-limit / WAF event source-IP attribution.
- **Default**: empty. **Loopback (`127.0.0.0/8`, `::1/128`) is
  always trusted** and the list below is added to it — it is not
  an external proxy being trusted, it is Arenet's own embedded
  Caddy, which proxies the admin API over loopback whenever the
  UI is reached through an Arenet route (the documented way).
  Before v2.56.2 loopback was untrusted by default, so every
  remote operator resolved to `127.0.0.1`: audit rows named the
  loopback, and the login rate limiter — keyed on the same value
  — put every attempt from every source into one shared bucket,
  which is no per-IP protection at all.
- **Format**: comma-separated CIDR list. Single IPs as `/32`
  (IPv4) or `/128` (IPv6).
- **Example**: `ARENET_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12`
- **Notes**: a malformed CIDR causes Arenet to **fail-fast at
  boot** (`auth: invalid CIDR in ARENET_TRUSTED_PROXIES: ...`).
  Set this when Arenet runs behind a FURTHER reverse proxy or
  CDN (Cloudflare, etc.); otherwise rate-limiting and audit logs
  attribute everything to that proxy's IP. Arenet's own embedded
  Caddy needs no entry — see the default above.
  **Security implication**: anyone whose source IP matches a
  listed CIDR can spoof `X-Forwarded-For` — keep the list as
  tight as possible. That applies to loopback too: a process
  already running on the Arenet host can reach the admin API and
  forge the header, which pollutes the audit IP and lets it
  rotate rate-limit buckets. It is a local-attacker scenario, on
  a host where reading the BoltDB file directly is already
  available, and it is the price of recording the real remote
  client at all.
- **Source**: `cmd/arenet/main.go:490`, parser at
  `internal/auth/ipextract.go:46`.

### `ARENET_HIBP_DISABLED`

- **Purpose**: disables the HaveIBeenPwned k-anonymity
  password check that runs at user-create + password-change
  time.
- **Default**: unset (HIBP check enabled).
- **Format**: **exactly the literal string `true`**. No other
  truthy value is accepted.
- **Example**: `ARENET_HIBP_DISABLED=true`
- **Notes**: unlike the other booleans in this reference,
  `True`, `TRUE`, `1`, `yes`, etc. **leave HIBP enabled**. The
  strict literal is intentional per spec §7.8 / AC-CONFIG-04 —
  disabling a credential-leak check should require a
  deliberate value, not an ambient truthy. Use to support
  offline / air-gapped installs where the HIBP API is
  unreachable.
- **Source**: `internal/auth/hibp.go:66`.

### `ARENET_ACME_EMAIL`

- **Purpose**: contact email registered on the Let's Encrypt /
  ACME account. Required by Let's Encrypt for expiry
  reminders + CAA identity.
- **Default**: empty (Arenet runs but warns if any route has
  TLS enabled — see Notes).
- **Format**: a single RFC-5321 email address.
- **Example**: `ARENET_ACME_EMAIL=ops@example.com`
- **Notes**: an empty value is accepted by Let's Encrypt
  (account is email-free) but Arenet logs a `WARN` at boot if
  any persisted route has `tlsEnabled=true` — the operator
  almost certainly wants expiry notifications. Set this before
  flipping TLS on the first public-domain route.
- **Source**: `cmd/arenet/main.go:180`.

### `ARENET_TOPOLOGY_TICK_MS`

- **Purpose**: emit cadence of the `/api/v1/topology/stream`
  WebSocket in milliseconds. Each tick the server re-builds
  the topology snapshot (route list × sliding-window metrics
  × Caddy upstream status) and pushes a frame to every
  connected client. The source metrics ticker stays at 1 Hz;
  this knob only changes how often the WS emits.
- **Default**: `2000` (2-second emit). 1 s reads too jumpy for
  eyeball metric rates, 5 s feels stale during an incident,
  2 s is the standard ops-dashboard cadence.
- **Format**: positive integer (milliseconds).
- **Example**: `ARENET_TOPOLOGY_TICK_MS=2000`
- **Notes**: the WS handler snaps the value UP to the nearest
  multiple of 1000 (since the source ticker is 1 Hz, smaller
  multiples would duplicate-emit the same data). Non-positive
  / non-numeric / empty values are ignored and the default
  survives — protects against footgun configurations that
  would either spam the WS or freeze it. Phase 2 #R-TOPO-v2.
- **Source**: `internal/config/config.go` (struct field
  `TopologyTickMs`; env parser around the `LookupEnv` block).

### `ARENET_ACCESS_LOG_PATH`

- **Purpose**: file the HTTP access log is written to, when
  the operator enables it in **Settings → Security → HTTP
  access log**. The log exists so a CrowdSec agent has
  requests to parse: before v2.50 Arenet emitted none, so an
  agent beside it enforced the community blocklist and
  detected nothing local. This variable only decides *where*;
  it does not switch the log on.
- **Default**: empty, which derives
  `<ARENET_DATA_DIR>/logs/access.log`. The systemd unit sets
  `/var/log/arenet/access.log` via `Environment=`, and Docker
  keeps the derived path — `/var/log` in a container is the
  writable layer, so a log there dies with the container.
- **Format**: absolute file path. A relative path is refused:
  it would resolve against Caddy's working directory, which
  is neither documented nor your shell.
- **Example**: `ARENET_ACCESS_LOG_PATH=/var/log/arenet/access.log`
- **Notes**: a path under `/var/log` only works if systemd is
  allowed to write there. The unit ships
  `LogsDirectory=arenet`, which creates `/var/log/arenet` with
  the service's ownership and is implicitly exempt from
  `ProtectSystem=strict`; point this somewhere else under
  `/var/log` and the write fails at runtime with nothing on
  screen to explain it. The unit declares `Environment=`
  *before* `EnvironmentFile=`, so setting this in
  `/etc/arenet/arenet.env` still wins. Caddy creates the file
  `0600`, so a CrowdSec agent must run as root to read it.
  An operator override typed in the settings UI beats this
  variable.
- **Source**: `internal/config/config.go` (struct field
  `AccessLogPath`), resolved by
  `caddymgr.ResolveAccessLogPath`.

---

## CrowdSec integration

Both variables must be set together to activate CrowdSec. Setting
only one logs a warning and disables the integration entirely.

### `ARENET_CROWDSEC_API_KEY`

- **Purpose**: bouncer API key authenticating Arenet to the
  CrowdSec LAPI. Activates two things: (a) the IP-reputation
  gate in front of the data plane, (b) the parallel
  StreamBouncer consumer that populates the dashboard's
  decision mirror.
- **Default**: unset (CrowdSec integration disabled — boot
  log says "crowdsec bouncer not configured ...").
- **Format**: opaque API key string (issued by `cscli bouncers
  add ...`).
- **Example**: `ARENET_CROWDSEC_API_KEY=abc123def456...`
- **Notes**: **secret** — store via Docker secrets
  (`/run/secrets/<name>`) or an env file with mode 0600,
  never in the TOML config file. Setting this without also
  setting `ARENET_CROWDSEC_API_URL` lands the bouncer on its
  default URL (`http://127.0.0.1:8080/`), which is rarely
  what the operator wants.
- **Source**: `cmd/arenet/main.go:219`.

### `ARENET_CROWDSEC_API_URL`

- **Purpose**: base URL of the CrowdSec LAPI.
- **Default**: bouncer-internal default
  (`http://127.0.0.1:8080/`).
- **Format**: absolute URL with scheme + host + port. Trailing
  slash optional but recommended for clarity.
- **Example**: `ARENET_CROWDSEC_API_URL=http://crowdsec.lan:8080/`
- **Notes**: needed when CrowdSec runs on a different host or
  port from Arenet. Has no effect unless
  `ARENET_CROWDSEC_API_KEY` is also set.
- **Source**: `cmd/arenet/main.go:218`.

---

## Operational / maintenance one-shots

These flip the binary into a one-shot tool mode (or, in the
case of `ARENET_INSERT_TEST_ROUTE`, modify boot-time behaviour).
Caddy and the admin API are NOT served when a one-shot variable
takes effect — the binary opens BoltDB, runs the action, and
exits.

### `ARENET_HEALTHCHECK`

- **Purpose**: turns the binary into a one-shot HTTP probe
  used as the Docker compose `healthcheck.test` command.
  Distroless has no curl/wget, so the binary probes itself.
- **Default**: unset (normal boot path).
- **Format**: absolute URL to probe.
- **Example**: `ARENET_HEALTHCHECK=http://127.0.0.1:8001/healthz`
- **Notes**: GETs the URL with a 3 s timeout; exit 0 on any 2xx,
  exit 1 on anything else (network error, non-2xx, timeout).
  Never starts the server. Operationally exposed as the
  `--healthcheck=<url>` flag too; the env var is the form the
  compose healthcheck uses.
- **Source**: `internal/config/config.go:303`,
  CLI logic at `cmd/arenet/healthcheck_cli.go`.

### `ARENET_EXPORT`

- **Purpose**: one-shot export of the configuration to a JSON
  file. The binary opens BoltDB, writes the export, and exits.
  Caddy and the admin API are NOT served.
- **Default**: unset (normal boot path).
- **Format**: absolute or relative path to the output file.
- **Example**: `ARENET_EXPORT=/backup/arenet-config.json`
- **Notes**: secrets (basic-auth passwords, OIDC client
  secrets, OVH API keys, etc.) are **redacted by default** —
  see `ARENET_INCLUDE_SECRETS` to keep them. Mutually
  exclusive with `ARENET_RESTORE`; setting both is a usage
  error (exit 2).
- **Source**: `internal/config/config.go:279`,
  CLI logic at `cmd/arenet/backup_cli.go`.

### `ARENET_RESTORE`

- **Purpose**: one-shot restore from a JSON file produced by
  `ARENET_EXPORT`. Runs before Caddy starts; the binary
  applies the restore and exits.
- **Default**: unset (normal boot path).
- **Format**: absolute or relative path to the input file.
- **Example**: `ARENET_RESTORE=/backup/arenet-config.json`
- **Notes**: mutually exclusive with `ARENET_EXPORT`. The
  restore replaces BoltDB content; back up the current state
  before running. See also `ARENET_ALLOW_INCOMPLETE_RESTORE`
  and `ARENET_ALLOW_EMPTY_USERS` for the leniency flags.
- **Source**: `internal/config/config.go:282`,
  CLI logic at `cmd/arenet/backup_cli.go`.

### `ARENET_INCLUDE_SECRETS`

- **Purpose**: modifier on `ARENET_EXPORT` — when truthy, the
  secrets are kept in the export output, **encrypted with the
  backup passphrase** (v2.31), instead of being redacted.
- **Default**: `false` (secrets redacted by default).
- **Format**: boolean.
- **Example**: `ARENET_INCLUDE_SECRETS=true`
- **Notes**: requires a passphrase (`ARENET_BACKUP_PASSPHRASE`,
  `ARENET_BACKUP_PASSPHRASE_FILE` or `--passphrase-file`); the
  export fails without one. The file is written `0o600`.
- **Source**: `internal/config/config.go`.

### `ARENET_BACKUP_PASSPHRASE`

- **Purpose**: the passphrase that encrypts the secrets of an
  `--export --include-secrets`, and decrypts an encrypted
  `--restore` (v2.31).
- **Default**: unset.
- **Format**: string, at least 12 characters.
- **Notes**: read by the backup CLI only, never stored.
  `ARENET_BACKUP_PASSPHRASE_FILE` / `--passphrase-file` take
  precedence and keep it out of the process environment.
- **Source**: `cmd/arenet/backup_cli.go`.

### `ARENET_BACKUP_PASSPHRASE_FILE`

- **Purpose**: path of a file holding the backup passphrase
  (trailing newline ignored) — same role as
  `ARENET_BACKUP_PASSPHRASE`, preferred for cron jobs.
- **Default**: unset. Flag: `--passphrase-file`.
- **Example**: `ARENET_BACKUP_PASSPHRASE_FILE=/root/.arenet-backup-pass`
- **Source**: `internal/config/config.go`.

### `ARENET_ALLOW_INCOMPLETE_RESTORE`

- **Purpose**: modifier on `ARENET_RESTORE` — accepts inputs
  whose secret sentinels (`$$ARENET_REDACTED$$`) cannot be
  inherited from the existing data dir; the affected secret
  fields are cleared instead of failing the restore.
- **Default**: `false` (strict — sentinel mismatches abort).
- **Format**: boolean.
- **Example**: `ARENET_ALLOW_INCOMPLETE_RESTORE=true`
- **Notes**: needed when restoring an export from one install
  into a fresh install that has none of the original secrets
  to inherit. The cleared fields surface in the audit log
  post-restore.
- **Source**: `internal/config/config.go:290`.

### `ARENET_ALLOW_EMPTY_USERS`

- **Purpose**: modifier on `ARENET_RESTORE` — accepts inputs
  with zero users; on next boot the setup-token flow is
  re-triggered so a fresh admin user can be created.
- **Default**: `false` (strict — refuses to restore an empty
  user set, which would otherwise lock everyone out).
- **Format**: boolean.
- **Example**: `ARENET_ALLOW_EMPTY_USERS=true`
- **Notes**: pairs naturally with
  `ARENET_ALLOW_INCOMPLETE_RESTORE` for "migrate config, redo
  users from scratch" workflows.
- **Source**: `internal/config/config.go:295`.

### `ARENET_INSERT_TEST_ROUTE`

- **Purpose**: insert a fixture route (`test.local` →
  `http://127.0.0.1:9999`) into BoltDB at boot, if no route
  with that host already exists. Used for local smoke testing.
- **Default**: `false`.
- **Format**: boolean.
- **Example**: `ARENET_INSERT_TEST_ROUTE=true`
- **Notes**: has no effect in production. Idempotent — running
  multiple times doesn't duplicate the route. There is no
  matching "remove test route" knob; delete the route via the
  admin UI if you no longer want it.
- **Source**: `internal/config/config.go:274`.

---

## Footnotes

### No defaults missing

Every variable documented above has an explicit default in
the codebase. There are no variables whose default behaviour
is unclear or undefined.

### No extra `ARENET_*` variables in the binary

A `grep -rhEo 'ARENET_[A-Z_]+' --include='*.go'` over the
codebase finds two additional matches that are **not**
environment variables:

- `ARENET_CROWDSEC_` — a comment-block substring in
  `internal/config/config.go:31`, not a variable.
- `ARENET_REDACTED` — part of the literal
  `$$ARENET_REDACTED$$` (the export-redaction sentinel) in
  `internal/backup/types.go:54`, not a variable.

If you find an `ARENET_*` mentioned elsewhere (logs, support
threads) that isn't covered here, open an issue — it's either
a typo, a planned variable from a draft spec that didn't ship,
or a regression in this reference.
