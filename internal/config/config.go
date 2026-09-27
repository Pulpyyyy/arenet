// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// Package config implements the Step S.3 config-loading layer.
//
// Precedence (per spec D5): flag > env > file > default.
//
//   - Default: hardcoded in NewDefault().
//   - File: optional TOML at the path given by --config (or
//     ARENET_CONFIG); silently absent files are not an error
//     (operators may run without one).
//   - Env: ARENET_<UPPER_SNAKE_CASE> for each field.
//   - Flag: the existing CLI flag set.
//
// Scope: this package centralises the settings already exposed
// as flags in cmd/arenet/main.go's parseFlags(). The scattered
// env-only reads in other packages (ARENET_ACME_EMAIL,
// ARENET_CROWDSEC_*, ARENET_HTTP_PORT, etc.) are NOT migrated
// here — a follow-up step can consolidate them.
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/BurntSushi/toml"
)

// Config is the resolved runtime configuration. Every field maps
// 1:1 to a CLI flag + env var + TOML key. The struct mirrors the
// existing parseFlags() shape so the wire-in at cmd/arenet/main.go
// is a near-mechanical swap.
//
// TOML field names are derived from the `toml` struct tag; they
// use kebab-case to match the env-var naming convention (just
// lower-cased).
type Config struct {
	// AdminPort is the bind address:port for the admin REST API
	// + WebSocket. Default ":8001" (matches the historical
	// production default since Step D). Loopback is the v1.4+
	// security default (D6); LAN exposure requires an explicit
	// "0.0.0.0:8001" override.
	AdminPort string `toml:"admin-bind"`

	// DataDir is the path where Arenet stores its persistent
	// state (arenet.db, metrics.db, audit.db, certmagic/).
	// Default "./data" for the dev path; production installs
	// override to "/var/lib/arenet" via env or systemd unit.
	DataDir string `toml:"data-dir"`

	// AccessLogPath is where the HTTP access log goes when the
	// operator enables it (v2.50). Empty means the derived default
	// "<DataDir>/logs/access.log", which is right everywhere except a
	// systemd install — there /var/log/arenet is the conventional place
	// and the unit's LogsDirectory= provides it, so install.sh sets
	// ARENET_ACCESS_LOG_PATH=/var/log/arenet/access.log.
	//
	// It lives in the config layer rather than being chosen by the
	// binary at runtime on purpose: sniffing for systemd would be magic
	// that breaks the day someone runs the binary by hand, and the
	// precedence flag > env > file > default already exists for exactly
	// this kind of per-topology default.
	//
	// The log is written by Caddy, not by Arenet: /var/log is read-only
	// under ProtectSystem=strict unless LogsDirectory= grants it, so a
	// path under /var/log with no matching unit change fails at runtime.
	AccessLogPath string `toml:"access-log-path"`

	// Dev enables development mode: verbose logging, no TLS
	// auto-issuance, dev-only landing page. Default false.
	Dev bool `toml:"dev"`

	// InsertTestRoute inserts a fixture route at boot for
	// local-only smoke testing. Default false. Has no effect
	// in production.
	InsertTestRoute bool `toml:"insert-test-route"`

	// ExportPath, RestorePath: K.3 backup/restore short-circuits.
	// When either is set, the binary becomes a one-shot CLI;
	// Caddy and the admin API never start. Mutually exclusive.
	ExportPath  string `toml:"export"`
	RestorePath string `toml:"restore"`

	// IncludeSecrets: K.3 flag on --export to keep the secrets in
	// the output (default redacts them). Since v2.31 the secrets are
	// encrypted with a passphrase: PassphraseFile or the
	// ARENET_BACKUP_PASSPHRASE env var is required.
	IncludeSecrets bool `toml:"include-secrets"`

	// PassphraseFile: v2.31 path of a file holding the backup
	// passphrase (--export --include-secrets, --restore of an
	// encrypted backup). The passphrase itself is never a config
	// field, so it cannot end up in a dumped config.
	PassphraseFile string `toml:"passphrase-file"`

	// AllowIncompleteRestore: K.3 flag on --restore allowing
	// imports whose secret sentinels cannot be inherited from
	// the existing data dir; affected fields are cleared.
	AllowIncompleteRestore bool `toml:"allow-incomplete-restore"`

	// AllowEmptyUsers: K.3 flag on --restore allowing imports
	// with zero users (the next boot re-triggers the setup-
	// token flow).
	AllowEmptyUsers bool `toml:"allow-empty-users"`

	// UIOrigin: K.2 dev override for the SPA dev server origin.
	// Empty in production (static SPA served by Arenet).
	UIOrigin string `toml:"ui-origin"`

	// HealthcheckURL: S.1 one-shot HTTP probe URL. When set,
	// the binary GETs the URL and exits 0 on 2xx, 1 otherwise.
	// Used as the Docker compose healthcheck command.
	HealthcheckURL string `toml:"healthcheck"`

	// TopologyTickMs (Phase 2 #R-TOPO-v2) is the emit cadence of
	// the /api/v1/topology/stream WebSocket in milliseconds. The
	// source metrics ticker stays at 1 Hz (metrics.TickInterval);
	// the stream handler aggregates ceil(TopologyTickMs / 1000)
	// source ticks per emit. Snapped to a positive multiple of
	// 1000 by the WS handler (a non-multiple is accepted and
	// rounded UP at handler init time, not here, to keep this
	// struct a pure data carrier).
	//
	// Default 2000 (2 s emit) per spec discussion: 1 s too jumpy,
	// 5 s too stale during an incident, 2 s standard for ops
	// dashboards.
	TopologyTickMs int `toml:"topology-tick-ms"`

	// ConfigPath is the path to the TOML config file. NOT a
	// TOML field itself (would be self-referential); only a
	// flag + env. The default empty string means "no config
	// file" — operators add it via --config /etc/arenet/
	// config.toml or ARENET_CONFIG=...
	ConfigPath string `toml:"-"`
}

// NewDefault returns a Config populated with the hardcoded
// defaults. This is the "level 4" of the precedence stack.
func NewDefault() *Config {
	return &Config{
		AdminPort:      ":8001",
		DataDir:        "./data",
		Dev:            false,
		TopologyTickMs: 2000,
	}
}

// Load resolves the runtime config from the four precedence
// layers (flag > env > file > default). The args slice is the
// CLI arguments excluding the program name (typically os.Args[1:]).
//
// Resolution order:
//  1. Start from NewDefault().
//  2. If a config file path is set (via --config flag OR
//     ARENET_CONFIG env), load + decode it onto the default.
//  3. Overlay env vars on top.
//  4. Overlay CLI flags on top (flags also carry the ConfigPath
//     read in step 2 — re-parsing isolates the precedence
//     contract from argument-order accidents).
//
// Returns a usable Config. The flag set is internal to Load; the
// caller does NOT pass a *flag.FlagSet.
func Load(args []string) (*Config, error) {
	cfg := NewDefault()

	// --- Phase 1: parse flags to a side struct so we can read
	// --config BEFORE applying the file layer. We need ConfigPath
	// (which itself comes from --config OR ARENET_CONFIG) before
	// we know which file to load.
	//
	// Flag descriptions are kept here so `arenet --help` prints
	// them; the parseFlags() function in cmd/arenet/main.go used
	// to own them pre-S.3 but the precedence logic lives here
	// now.
	flagSet := flag.NewFlagSet("arenet", flag.ContinueOnError)
	var (
		fAdminPort      = flagSet.String("admin-port", "", "address:port for the admin API (e.g. :8001). Loopback default per spec D6; override with 0.0.0.0:8001 for LAN admin access.")
		fDataDir        = flagSet.String("data-dir", "", "directory where Arenet stores its persistent state (arenet.db, metrics.db, audit.db, certmagic/).")
		fAccessLogPath  = flagSet.String("access-log-path", "", "file the HTTP access log is written to when enabled in settings (default <data-dir>/logs/access.log).")
		fDev            = flagSet.Bool("dev", false, "enable development mode (verbose logging, no TLS auto-issuance).")
		fInsertTest     = flagSet.Bool("insert-test-route", false, "insert a fixture test route at boot (local smoke only).")
		fExport         = flagSet.String("export", "", "Step K.3: export the configuration to PATH and exit (default redacts secrets).")
		fRestore        = flagSet.String("restore", "", "Step K.3: restore the configuration from PATH and exit (before Caddy starts).")
		fInclSec        = flagSet.Bool("include-secrets", false, "Step K.3: include the secrets in --export output, encrypted with the backup passphrase (--passphrase-file or ARENET_BACKUP_PASSPHRASE).")
		fPassFile       = flagSet.String("passphrase-file", "", "v2.31: file holding the backup passphrase (--export --include-secrets, --restore of an encrypted backup).")
		fAllowIncRes    = flagSet.Bool("allow-incomplete-restore", false, "Step K.3: accept --restore inputs whose sentinels cannot be inherited; affected secret fields are cleared.")
		fAllowEmptyU    = flagSet.Bool("allow-empty-users", false, "Step K.3: accept --restore inputs with zero users (next boot re-triggers the setup-token flow).")
		fUIOrigin       = flagSet.String("ui-origin", "", "Step K.2 dev: absolute origin of the SPA dev server (e.g. http://localhost:5173); empty in prod (static SPA served by Arenet).")
		fHealthcheck    = flagSet.String("healthcheck", "", "Step S.1: probe URL (e.g. http://127.0.0.1:8001/healthz) and exit 0 on 2xx, 1 otherwise. Used as the Docker compose healthcheck command since distroless has no curl. Never starts the server.")
		fTopologyTickMs = flagSet.Int("topology-tick-ms", 0, "Phase 2 #R-TOPO-v2: emit cadence of the /api/v1/topology/stream WebSocket in milliseconds. Default 2000. Snapped UP to the nearest multiple of 1000 (source metrics tick is 1 Hz).")
		fConfig         = flagSet.String("config", "", "Step S.3: path to a TOML config file. Optional; env vars + flags override file values (precedence: flag > env > file > default).")
	)
	// Track which flags were explicitly set so we can apply ONLY
	// those (vs zero-value defaults that should NOT override file
	// or env layers).
	flagSet.SetOutput(os.Stderr)
	if err := flagSet.Parse(args); err != nil {
		// flag.ErrHelp (when the user passed --help) is returned
		// by Parse with output already written to stderr; surface
		// it as a sentinel so main() can exit 0 instead of 2.
		return nil, err
	}
	wasSet := map[string]bool{}
	flagSet.Visit(func(f *flag.Flag) { wasSet[f.Name] = true })

	// --- Phase 2: resolve ConfigPath (flag > env > default-empty).
	configPath := ""
	if wasSet["config"] {
		configPath = *fConfig
	} else if v, ok := os.LookupEnv("ARENET_CONFIG"); ok {
		configPath = v
	}
	cfg.ConfigPath = configPath

	// --- Phase 3: file layer (if any).
	if configPath != "" {
		if err := loadFile(configPath, cfg); err != nil {
			return nil, fmt.Errorf("config: load file %q: %w", configPath, err)
		}
	}

	// --- Phase 4: env layer (overrides file).
	applyEnv(cfg)

	// --- Phase 5: flag layer (overrides env). Only flags that
	// were EXPLICITLY set on the command line are applied — a
	// caller running `arenet` with no flags and an env-defined
	// AdminPort should not have that env value clobbered by the
	// flag's zero-value default.
	if wasSet["admin-port"] {
		cfg.AdminPort = *fAdminPort
	}
	if wasSet["data-dir"] {
		cfg.DataDir = *fDataDir
	}
	if wasSet["dev"] {
		cfg.Dev = *fDev
	}
	if wasSet["insert-test-route"] {
		cfg.InsertTestRoute = *fInsertTest
	}
	if wasSet["export"] {
		cfg.ExportPath = *fExport
	}
	if wasSet["restore"] {
		cfg.RestorePath = *fRestore
	}
	if wasSet["include-secrets"] {
		cfg.IncludeSecrets = *fInclSec
	}
	if wasSet["passphrase-file"] {
		cfg.PassphraseFile = *fPassFile
	}
	if wasSet["allow-incomplete-restore"] {
		cfg.AllowIncompleteRestore = *fAllowIncRes
	}
	if wasSet["allow-empty-users"] {
		cfg.AllowEmptyUsers = *fAllowEmptyU
	}
	if wasSet["ui-origin"] {
		cfg.UIOrigin = *fUIOrigin
	}
	if wasSet["healthcheck"] {
		cfg.HealthcheckURL = *fHealthcheck
	}
	if wasSet["topology-tick-ms"] {
		cfg.TopologyTickMs = *fTopologyTickMs
	}
	if wasSet["access-log-path"] {
		cfg.AccessLogPath = *fAccessLogPath
	}

	return cfg, nil
}

// loadFile decodes the TOML file at path onto cfg. An absent file
// is NOT an error — operators may run without one, and silently-
// missing makes the systemd unit's `EnvironmentFile=-` pattern
// work consistently across env file + config file.
//
// A present-but-malformed file IS an error (decoding fails).
func loadFile(path string, cfg *Config) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil // silently absent — not an error
	} else if err != nil {
		return fmt.Errorf("stat: %w", err)
	}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return fmt.Errorf("decode toml: %w", err)
	}
	return nil
}

// applyEnv overlays ARENET_ env vars on top of cfg. Each field
// has an explicit case so renames + additions stay grep-able.
// Boolean parsing tolerates "1" / "true" / "yes" / "on" (and
// their negations) via strconv.ParseBool's behaviour on a
// canonical subset.
func applyEnv(cfg *Config) {
	if v, ok := os.LookupEnv("ARENET_ADMIN_BIND"); ok {
		cfg.AdminPort = v
	}
	if v, ok := os.LookupEnv("ARENET_DATA_DIR"); ok {
		cfg.DataDir = v
	}
	if v, ok := os.LookupEnv("ARENET_ACCESS_LOG_PATH"); ok {
		cfg.AccessLogPath = v
	}
	if v, ok := os.LookupEnv("ARENET_DEV"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Dev = b
		}
	}
	if v, ok := os.LookupEnv("ARENET_INSERT_TEST_ROUTE"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.InsertTestRoute = b
		}
	}
	if v, ok := os.LookupEnv("ARENET_EXPORT"); ok {
		cfg.ExportPath = v
	}
	if v, ok := os.LookupEnv("ARENET_RESTORE"); ok {
		cfg.RestorePath = v
	}
	if v, ok := os.LookupEnv("ARENET_BACKUP_PASSPHRASE_FILE"); ok {
		cfg.PassphraseFile = v
	}
	if v, ok := os.LookupEnv("ARENET_INCLUDE_SECRETS"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.IncludeSecrets = b
		}
	}
	if v, ok := os.LookupEnv("ARENET_ALLOW_INCOMPLETE_RESTORE"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AllowIncompleteRestore = b
		}
	}
	if v, ok := os.LookupEnv("ARENET_ALLOW_EMPTY_USERS"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.AllowEmptyUsers = b
		}
	}
	if v, ok := os.LookupEnv("ARENET_UI_ORIGIN"); ok {
		cfg.UIOrigin = v
	}
	if v, ok := os.LookupEnv("ARENET_HEALTHCHECK"); ok {
		cfg.HealthcheckURL = v
	}
	if v, ok := os.LookupEnv("ARENET_TOPOLOGY_TICK_MS"); ok {
		// strconv.Atoi rejects empty / non-numeric / negative-with-
		// non-leading-minus. We additionally guard against
		// non-positive values — a zero or negative tick would
		// either spam the WS or freeze it; safer to ignore and
		// keep the default than to honour a footgun.
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.TopologyTickMs = n
		}
	}
}
