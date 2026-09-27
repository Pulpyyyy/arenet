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

// Package storage provides a BoltDB-backed persistence layer for Arenet.
package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/barto95100/arenet/internal/secrets"
	bolt "go.etcd.io/bbolt"
)

// Bucket names used inside the BoltDB file.
const (
	bucketRoutes    = "routes"
	bucketUsers     = "users"
	bucketSessions  = "sessions"
	bucketAudit     = "audit"
	bucketAPITokens = "api_tokens" // Phase 4 — service-account bearer tokens
	// Step J.4 — instance-level DNS provider configurations, keyed
	// by provider name (v1.0: only "ovh"). Parallel to the existing
	// settings storage rather than mixed in, so the secret scan is
	// isolated. See dns_provider.go.
	bucketDNSProviders = "dns_providers"
	// Step K.1 — instance-level forward-auth provider configurations,
	// keyed by provider name (slug-shaped). See forward_auth_provider.go.
	bucketForwardAuthProviders = "forward_auth_providers"
	// Step K.2 — instance-level OIDC SSO config (single row,
	// keyed "default"). Future-proof for multi-IdP without a
	// schema rewrite. See oidc_config.go.
	bucketOIDCConfig = "oidc_config"
	// Step O.1 — instance-level wildcard-certificate managed-domain
	// declarations, keyed by apex (e.g. "example.com"). One row per
	// managed domain; multiple domains coexist (spec D6.A). See
	// managed_domain.go.
	bucketManagedDomains = "managed_domains"
	// Step P.1 — instance-level auto-classify (write-side LAPI)
	// configuration: the watcher credentials (machine-id + password)
	// + the per-category rule set. Single bucket, two keys
	// ("credentials" + "rules"). See automation_config.go.
	bucketAutomation = "automation"
	// Step V.4 — instance-level server geographic position
	// (where the Mercator is centered + the central pin is
	// placed on the /map page). Single row, keyed "default" —
	// same convention as bucketOIDCConfig. See
	// server_position.go.
	bucketServerPosition = "server_position"
	// Step CS.1 — instance-level CrowdSec bouncer config
	// (LAPI URL + API key + name + timeout). Single row,
	// keyed "default" — same convention as bucketOIDCConfig.
	// See crowdsec_config.go.
	bucketCrowdSecConfig = "crowdsec_config"
	// Brick 2 Task 1 — instance-level MaxMind GeoIP credentials
	// (account_id + license_key + edition_id). Single row,
	// keyed "default" — same convention as bucketCrowdSecConfig.
	// See maxmind_config.go.
	bucketMaxMindConfig = "maxmind_config"
	// Step AL.1.a — instance-level alerting channel
	// registry (webhook + email V1; slack + discord
	// deferred V2). One row per Channel, keyed by
	// Channel.ID (UUID v4). Stable across renames so
	// rule → channel references survive operator-facing
	// relabels. See alerting_channel.go.
	bucketAlertingChannels = "alerting_channels"
	// Step AL.2.a — instance-level alert rule registry.
	// One row per AlertRule, keyed by Rule.ID (UUID v4).
	// The AL.2.b watcher reads this bucket per polling
	// tick + writes the LastFiredAt / LastEvalAt /
	// LastError fields back via MarkAlertRuleEval. The
	// AL.3b CRUD layer wires the operator-facing
	// endpoints. See alert_rule.go.
	bucketAlertRules = "alert_rules"
	// Step R — operator-defined HTML error pages keyed by
	// status code. One row per ErrorPageTemplate, keyed by
	// Template.ID (UUID v4). Routes reference a template
	// via Route.ErrorPageTemplateID ; if the reference is
	// dangling (template deleted) the caddymgr emit falls
	// back to the built-in arenetDefaultErrorPages map.
	// See error_template.go.
	bucketErrorTemplates = "error_templates"
	// v2.12.3 — opt-in update-checker config (single row, keyed
	// "config"). Enabled defaults to false (no external call
	// without consent). See update_check_config.go.
	bucketUpdateCheck = "update_check"
	// Brick 3 Task 3 — opt-in GeoIP auto-update scheduler config
	// (single row, keyed "config"). Enabled defaults to false, same
	// convention as bucketUpdateCheck. Kept separate from
	// bucketMaxMindConfig so the scheduler toggles independently of
	// the MaxMind credentials. See geoip_update_config.go.
	bucketGeoIPUpdate = "geoip_update"
	// Task 2 — global single-slot maintenance-page HTML template
	// (single row, keyed "config"). Empty HTML = serve the branded
	// default, same convention as bucketGeoIPUpdate. See
	// maintenance_page_config.go.
	bucketMaintenancePage = "maintenance_page"
	// Task 1 (v2.19.0) — operator-uploaded TLS certificates served on
	// a route via load_pem. See external_cert.go.
	bucketExternalCertificates = "external_certificates"
)

// ErrNotFound is returned when a requested record does not exist.
var ErrNotFound = errors.New("storage: record not found")

// ErrConflict is returned when an operation would violate a
// uniqueness constraint at the storage layer (e.g. creating a
// ForwardAuthProvider with a Name that already exists).
var ErrConflict = errors.New("storage: conflict")

// ErrProviderInUse is returned by DeleteDNSProvider when at least one
// managed domain still references the provider by its ProviderID.
// The API maps it to 409 Conflict.
var ErrProviderInUse = errors.New("storage: dns provider is referenced by one or more managed domains")

// boltOpenTimeout bounds the wait for the BoltDB file lock.
const boltOpenTimeout = 3 * time.Second

// Store is the BoltDB-backed persistence layer for Arenet.
type Store struct {
	db *bolt.DB
	// secretsKey seals / opens secret fields (v2.30); nil until
	// EnableEncryption, in which case secrets stay in clear.
	secretsKey atomic.Pointer[secrets.Keyring]
}

// NewStore opens (or creates) a BoltDB database at dbPath and ensures
// all required buckets exist.
func NewStore(dbPath string) (*Store, error) {
	if dbPath == "" {
		return nil, errors.New("storage: dbPath must not be empty")
	}

	// The data dir holds arenet.db (routes, users, audit, secrets) and,
	// in production, the certmagic TLS material. Keep it owner-only
	// (0o700). MkdirAll applies the mode only when it CREATES the
	// directory — on an existing dir it is a no-op on perms (verified
	// empirically), so a pre-hardening install (0o755) needs an explicit
	// Chmod to be tightened in place on the next boot. A failed Chmod is
	// a warning, not fatal: an over-permissive dir should not stop Arenet
	// from starting (e.g. dir owned by another user under a bind mount).
	dataDir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("storage: create data dir: %w", err)
	}
	if err := os.Chmod(dataDir, 0o700); err != nil {
		slog.Warn("could not enforce 0700 on data dir; secrets may be readable by other users",
			"data_dir", dataDir, "err", err)
	}

	db, err := bolt.Open(dbPath, 0o600, &bolt.Options{Timeout: boltOpenTimeout})
	if err != nil {
		return nil, fmt.Errorf("storage: open bbolt %q: %w", dbPath, err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{
			[]byte(bucketRoutes),               // Step B/C
			[]byte(bucketUsers),                // Step D
			[]byte(bucketSessions),             // Step D
			[]byte(bucketAudit),                // Step D
			[]byte(bucketAPITokens),            // Phase 4 — service-account tokens
			[]byte(bucketDNSProviders),         // Step J.4
			[]byte(bucketForwardAuthProviders), // Step K.1
			[]byte(bucketOIDCConfig),           // Step K.2
			[]byte(bucketManagedDomains),       // Step O.1
			[]byte(bucketAutomation),           // Step P.1
			[]byte(bucketServerPosition),       // Step V.4
			[]byte(bucketCrowdSecConfig),       // Step CS.1
			[]byte(bucketMaxMindConfig),        // Brick 2 Task 1
			[]byte(bucketAlertingChannels),     // Step AL.1.a
			[]byte(bucketAlertRules),           // Step AL.2.a
			[]byte(bucketErrorTemplates),       // Step R
			[]byte(bucketUpdateCheck),          // v2.12.3
			[]byte(bucketGeoIPUpdate),          // Brick 3 Task 3
			[]byte(bucketMaintenancePage),      // Task 2
			[]byte(bucketExternalCertificates), // v2.19.0
			[]byte(bucketMeta),                 // v2.30 — secrets key fingerprint
			[]byte(bucketBackupSchedule),       // v2.33 — scheduled backups
			[]byte(bucketRouteCheck),           // v2.35 — post-apply route check
			[]byte(bucketAccessLog),            // v2.50 — HTTP access log for CrowdSec
			[]byte(bucketTCPServices),          // v2.42 — layer-4 services
		} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return fmt.Errorf("create bucket %q: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: init buckets: %w", err)
	}

	// Step I.4 boot migration: convert pre-I.4 routes' WAFEnabled
	// bool into the new WAFMode string enum. Runs idempotently —
	// already-migrated rows are left as-is, so re-running on every
	// boot after the first is a cheap no-op.
	if err := migrateWAFEnabledToWAFMode(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate route schema: %w", err)
	}

	// Step J.1 boot migration: convert pre-J.1 routes' UpstreamURL
	// string into the new Upstreams pool + LBPolicy enum. Same
	// shape-based idempotency as Step I.4 (sentinel: Upstreams
	// non-empty ⇒ already migrated).
	//
	// ORDER MATTERS — DO NOT REORDER: migrateUpstreamURLToPool MUST
	// run AFTER migrateWAFEnabledToWAFMode. The J.1 migration does a
	// full-Route round-trip through json.Unmarshal, which silently
	// drops every key absent from the current Route struct — including
	// the legacy `waf_enabled` field that Step I.4 still needs to read.
	// If J.1 ran first on a doubly-legacy row (waf_enabled + upstream_url,
	// no waf_mode + no upstreams), the re-marshal would drop waf_enabled
	// before Step I.4 ever saw it, leaving waf_mode silently set to "off"
	// — i.e. the WAF would be turned off without anyone noticing. The
	// chained-migration test in migrate_test.go pins this ordering.
	if err := migrateUpstreamURLToPool(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate upstream pool: %w", err)
	}

	// Step K.1 boot migration: replace the flat BasicAuthEnabled /
	// BasicAuthUsername / BasicAuthPasswordHash fields with the
	// nested BasicAuth struct under a new AuthMode enum. Passthrough-
	// map per the backlog rule (this migration REMOVES legacy keys,
	// not just adds them).
	//
	// Ordering: runs LAST. Both I.4 (waf_enabled → waf_mode) and J.1
	// (upstream_url → upstreams pool) are pure restructurings of
	// different keys; this migration touches only the basic_auth_*
	// triplet, so the ordering is independent. Placed last for
	// chronological clarity.
	if err := migrateBasicAuthToAuthMode(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate auth mode: %w", err)
	}

	// Step K.2 boot migration: add AuthSource + Role + OIDCSub
	// to every user row. Pure-additions migration on a different
	// bucket (users) — independent of the routes bucket
	// migrations above. Passthrough-map per §6 (defence-in-depth
	// for forward-compat across downgrade cycles).
	if err := migrateUsersAuthSourceAndRole(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: migrate users role: %w", err)
	}

	return &Store{db: db}, nil
}

// DB returns the underlying bbolt handle. Reserved for the auth and
// audit packages, which share the same database file per bbolt's
// single-writer constraint. Other consumers MUST NOT call this and
// MUST use the typed methods on Store.
func (s *Store) DB() *bolt.DB {
	return s.db
}

// Close releases the underlying BoltDB file.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// withTimeout returns ctx unchanged if it already has a deadline;
// otherwise it wraps it with a 5 second timeout to bound DB calls.
func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 5*time.Second)
}
