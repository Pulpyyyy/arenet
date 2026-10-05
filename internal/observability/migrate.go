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

package observability

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/barto95100/arenet/internal/waf"
)

// currentSchemaVersion is the latest schema version this
// build of Arenet writes. Bumped per Step that touches the
// schema:
//
//   - v1: Step L bootstrap (bucket_1m + bucket_1h).
//
//   - v2: Step M (waf_block_count column on both bucket
//     tables + waf_event table + indexes).
//
//   - v3: Step Q (throttle_block_count column on both bucket
//     tables + throttle_event table + indexes).
//
//   - v4: Step N (crowdsec_decision_count column on both
//     bucket tables + decision_event table + indexes).
//
//   - v5: Step U.1 (cert_event table + indexes).
//
//   - v6: Step V.2 (auth_event table + indexes). 30 d
//     retention per spec §3.6 (short-window security
//     signal, not lifecycle record).
//
//   - v7: Step W.bugfix Fix #1 (action + status_code
//     columns on waf_event so the sink can distinguish
//     block-mode from detect-mode events).
//
//   - v8: Step W.4 (country_block_event table + indexes).
//
//   - v9: #R-DASHBOARD-WAF-COUNTERS-ZERO (waf_detect_count
//     column on both bucket tables so detect-mode events
//     surface in the dashboard counters as a sibling to
//     waf_block_count).
//
//   - v13: v2.36 targeted WAF exclusions (matched_var column
//     on waf_event: the "VARIABLE:key" that triggered the rule).
//
// Downgrade is not supported.
const currentSchemaVersion = 15

// migrate brings db from currentVersion to currentSchemaVersion
// by replaying every intervening migration step in a single
// transaction (so a partial failure leaves the DB at the
// previous version, never half-applied).
//
// Idempotent: when currentVersion equals currentSchemaVersion,
// migrate returns nil without touching the DB. Called from
// Open() after the bootstrap schemaSQL has run.
//
// This is the first real exercise of the L spec §6 migrate-
// chain. Future bumps add their step here; the chain pattern
// keeps each step focused on one delta.
func migrate(ctx context.Context, db *sql.DB, currentVersion int) error {
	if currentVersion == currentSchemaVersion {
		return nil
	}
	if currentVersion < 0 || currentVersion > currentSchemaVersion {
		return fmt.Errorf("observability: unsupported schema version %d (this build knows up to %d)", currentVersion, currentSchemaVersion)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin migrate tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	for v := currentVersion; v < currentSchemaVersion; v++ {
		step := migrateSteps[v]
		if step == nil {
			return fmt.Errorf("observability: missing migrate step for v%d→v%d", v, v+1)
		}
		if err := step(ctx, tx); err != nil {
			return fmt.Errorf("observability: migrate v%d→v%d: %w", v, v+1, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE schema_version SET version = ?`, currentSchemaVersion); err != nil {
		return fmt.Errorf("observability: bump schema_version to %d: %w", currentSchemaVersion, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit migrate: %w", err)
	}
	return nil
}

// migrateSteps maps a starting version V to the function that
// brings the DB from V to V+1. Each function operates inside
// the caller's transaction.
//
// Convention: index N is the v(N)→v(N+1) step. Index 0
// (v0→v1) is intentionally nil because v1 is the bootstrap
// shape produced by schemaSQL — a fresh DB never starts at
// v0. The first real step is index 1 (v1→v2) for Step M.
var migrateSteps = map[int]func(context.Context, *sql.Tx) error{
	1:  migrateV1toV2,
	2:  migrateV2toV3,
	3:  migrateV3toV4,
	4:  migrateV4toV5,
	5:  migrateV5toV6,
	6:  migrateV6toV7,
	7:  migrateV7toV8,
	8:  migrateV8toV9,
	9:  migrateV9toV10,
	10: migrateV10toV11,
	11: migrateV11toV12,
	12: migrateV12toV13,
	13: migrateV13toV14,
	14: migrateV14toV15,
}

// migrateV1toV2 — Step M. Adds the waf_block_count column on
// both bucket tables (default 0 so existing rows get a
// sensible value) AND creates the waf_event table with its
// three indexes (ts for time-range scans, route_id+ts for
// drill-down filters, category+ts for the summary
// breakdown).
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — it does NOT rewrite the
// table, so the migration is O(1) regardless of row count.
func migrateV1toV2(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN waf_block_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS waf_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  route_id TEXT NOT NULL,
		  rule_id TEXT NOT NULL,
		  category TEXT NOT NULL,
		  severity INTEGER NOT NULL,
		  src_ip TEXT NOT NULL,
		  request_method TEXT NOT NULL,
		  request_path TEXT NOT NULL,
		  payload_sample TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_event_ts          ON waf_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_event_route_ts    ON waf_event (route_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_waf_event_category_ts ON waf_event (category, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV2toV3 — Step Q. Adds the throttle_block_count column on
// both bucket tables (default 0 so existing rows get a
// sensible value) AND creates the throttle_event table with
// its two indexes (ts for time-range scans, src_ip+ts for
// per-IP drill-down filters). Unlike waf_event, there is no
// category dimension to index — tier is a small enum (1 or 2)
// and SQLite will scan it cheaply.
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — it does NOT rewrite the
// table, so the migration is O(1) regardless of row count.
func migrateV2toV3(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN throttle_block_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS throttle_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  tier INTEGER NOT NULL,
		  src_ip TEXT NOT NULL,
		  attempted_username TEXT NOT NULL,
		  blocked_until INTEGER NOT NULL,
		  block_duration_seconds INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_throttle_event_ts       ON throttle_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_throttle_event_srcip_ts ON throttle_event (src_ip, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV3toV4 — Step N. Adds the crowdsec_decision_count
// column on both bucket tables AND creates the decision_event
// table with three indexes (ts for time-range scans,
// value+ts for per-IP-or-CIDR drill-down, scenario+ts for
// per-scenario aggregation).
//
// `uuid` is declared UNIQUE so duplicate-poll insertion
// surfaces as a constraint violation that the Sink's
// dedupe-before-bump path normally prevents — defence-in-
// depth against a future stream-consumer bug.
// `value` is the bouncer-observed IP / CIDR / country / AS
// (the LAPI decision's `Value` field interpreted per `Scope`).
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation; the migration is O(1) regardless of row count.
func migrateV3toV4(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN crowdsec_decision_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN crowdsec_decision_count INTEGER NOT NULL DEFAULT 0`,
		`CREATE TABLE IF NOT EXISTS decision_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  uuid TEXT NOT NULL UNIQUE,
		  ts INTEGER NOT NULL,
		  scope TEXT NOT NULL,
		  value TEXT NOT NULL,
		  type TEXT NOT NULL,
		  scenario TEXT NOT NULL,
		  expires_at INTEGER NOT NULL,
		  duration_seconds INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_decision_event_ts          ON decision_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_decision_event_value_ts    ON decision_event (value, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_decision_event_scenario_ts ON decision_event (scenario, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV4toV5 — Step U.1. Creates the cert_event table
// with the three indexes that match the read patterns the
// Activity log handler needs (ts for the time-ordered list,
// domain+ts for per-domain history drill-down, event_type+ts
// for filtered queries like "show me all failures").
//
// Unlike v2/v3/v4 there is no bucket-table column to add: cert
// events don't aggregate into per-minute counters (volume is
// too low; a single domain produces a handful of rows per day,
// per the §3.2 retention rationale). The schema is purely the
// per-event table.
//
// Columns chosen to match the wire shape from spec §5.2
// (camelCase JSON tags map to snake_case columns). `ts` is
// seconds-since-epoch consistent with waf_event /
// throttle_event / decision_event; the brief's "ts_unix_ns"
// proposal was a transcription drift — uniformity with the
// existing tables wins so an operator querying metrics.db
// reads the same unit everywhere.
//
// SQLite's CREATE TABLE IF NOT EXISTS makes the migration
// idempotent under partial-failure replay (a v4→v5 that died
// after the CREATE but before the schema_version bump
// re-applies cleanly on next boot).
func migrateV4toV5(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS cert_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  level TEXT NOT NULL,
		  event_type TEXT NOT NULL,
		  domain TEXT NOT NULL,
		  issuer TEXT NOT NULL DEFAULT '',
		  challenge TEXT NOT NULL DEFAULT '',
		  renewal INTEGER NOT NULL DEFAULT 0,
		  error_msg TEXT NOT NULL DEFAULT '',
		  details TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cert_event_ts            ON cert_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_cert_event_domain_ts     ON cert_event (domain, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_cert_event_event_type_ts ON cert_event (event_type, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV5toV6 — Step V.2. Creates the auth_event table with
// the three indexes that match the read patterns spec §3.6
// anticipates: ts for the time-ordered list, src_ip+ts for
// per-IP drill-down (the geo map and the future per-IP
// timeline), kind+ts for filtered queries like "show me all
// session_expired events".
//
// Column shape locked at spec §3.6: kind (NOT "reason"),
// src_ip (NOT "source_ip"), username (NOT "user"). These names
// match the audit-bucket vocabulary so an operator joining
// auth_event with audit.Event on src_ip / username sees the
// same identifier on both sides.
//
// Indexes mirror cert_event's shape (Step U.1) so this table
// reads identically to its siblings — same ts-desc walks, same
// per-value drill-down strategy.
//
// SQLite's CREATE TABLE IF NOT EXISTS makes the migration
// idempotent under partial-failure replay.
func migrateV5toV6(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS auth_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  kind TEXT NOT NULL,
		  src_ip TEXT NOT NULL,
		  username TEXT NOT NULL DEFAULT '',
		  path TEXT NOT NULL DEFAULT '',
		  details TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_ts        ON auth_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_src_ip_ts ON auth_event (src_ip, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_auth_event_kind_ts   ON auth_event (kind, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV6toV7 — Step W.bugfix Fix #1. Adds the action +
// status_code columns to waf_event so the sink can record
// whether a matched rule actually blocked the request
// (ActionBlock + 403) or merely detected it (ActionDetect +
// 0). Pre-migration rows are backfilled to ("BLOCK", 403)
// because every WAF event row in the legacy schema was
// emitted by a block-mode handler — the frontend's
// hardcoded "BLOCK 403" label was correct for legacy rows
// but lied for detect-mode rows that started being emitted
// once detect-mode existed (the regression that originally
// produced operator confusion). Backfilling to BLOCK keeps
// the historical attribution honest: those rows really did
// correspond to blocked requests.
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — O(1) regardless of row
// count.
func migrateV6toV7(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE waf_event ADD COLUMN action TEXT NOT NULL DEFAULT 'BLOCK'`,
		`ALTER TABLE waf_event ADD COLUMN status_code INTEGER NOT NULL DEFAULT 403`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV7toV8 — Step W.4. Creates the country_block_event
// table + its two indexes (ts for time-range scans, route_id
// + ts for per-route drill-down). Mirrors the v5→v6
// (auth_event) + v6→v7 (waf_event extension) shape.
//
// Pre-W rows are absent (the table doesn't exist), so no
// backfill is needed — a v7 → v8 upgrade just adds the table.
// SQLite's CREATE TABLE IF NOT EXISTS makes the migration
// idempotent under partial-failure replay.
//
// Column rationale:
//   - ts (INTEGER): seconds-since-epoch, indexed for time-range
//     scans + retention prune. Matches the existing waf /
//     auth / throttle schemas.
//   - route_id, src_ip, country, mode, status_code, reason:
//     verbatim from countryblock.BlockMatch. country is
//     NULL-tolerable for the §D5 fail-open path that doesn't
//     currently emit but is reserved by the W.1 contract.
//   - mode: "allow" / "deny" — the route's enforcement mode
//     at decision time. Persisted so the W.5 activity log
//     can filter without a routes-table join.
//   - reason: W.1's matcher kebab-case enum ("allow-miss",
//     "deny-match", etc.). Frontend keys off this for
//     tooltip wording without parsing free text.
func migrateV7toV8(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS country_block_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  route_id TEXT NOT NULL,
		  src_ip TEXT NOT NULL,
		  country TEXT NOT NULL DEFAULT '',
		  mode TEXT NOT NULL,
		  status_code INTEGER NOT NULL,
		  reason TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_country_block_event_ts       ON country_block_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_country_block_event_route_ts ON country_block_event (route_id, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV8toV9 — #R-DASHBOARD-WAF-COUNTERS-ZERO. Adds the
// waf_detect_count column to both bucket_1m and bucket_1h
// so detect-mode WAF events surface in the dashboard
// counters as a sibling to the existing waf_block_count
// (block-mode events only). Default 0 on pre-fix rows: the
// column didn't exist when those buckets were written, so
// "no data" is the operator-honest answer rather than
// fabricating a value.
//
// SQLite's ALTER TABLE ADD COLUMN is a metadata-only
// operation in modern versions — O(1) regardless of row
// count, so this migration runs in constant time on the
// production AreNET-test database (~287 WAF events / 8
// days of trafic).
//
// Companion: the waf.Sink switch (sink.go absorb) is
// extended to BumpWafDetects on ActionDetect events,
// symmetric to the existing BumpWafBlocks on ActionBlock.
// Bumps happen BEFORE LRU dedup so the counter reflects
// attack volume (AC #3), not the deduplicated event-log
// count.
func migrateV8toV9(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN waf_detect_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN waf_detect_count INTEGER NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV9toV10 — Step AL.1.a. Creates the alert_event
// table + its three indexes (ts for time-range scans,
// rule_id+ts for per-rule drill-down, severity+ts for
// the activity log's severity filter).
//
// Schema rationale:
//   - event_id is the application-generated UUID v4 (the
//     AlertEvent.ID field); UNIQUE so a re-fire from a
//     watcher restart can't double-insert.
//   - ts is Unix seconds — cohérent with waf_event,
//     throttle_event, decision_event, cert_event.
//   - rule_id is a snapshot (the rule may be deleted
//     later; the FK is intentionally weak).
//   - rule_name is also a snapshot so a future rename
//     doesn't retroactively relabel old events.
//   - severity is the 0-3 int form of alerting.Severity.
//   - category is free-form taxonomy (waf / crowdsec /
//     cert / system / ...).
//   - context_json + labels_json hold the structured
//     payload; SQLite reads them as TEXT so the
//     activity log can render them without a schema
//     change when a new context key shows up.
//   - channels_fired_json + channels_failed_json are
//     JSON arrays of channel IDs (post-send state from
//     the dispatch layer, AL.1.d). Empty arrays on rows
//     written before the dispatch fan-out completes.
//
// Retention: 30 days, mirrors the other event tables.
// Pruning lands in AL.3b alongside the read endpoint
// (PruneAlertEventsOlderThan, called by the existing
// retention runner).
func migrateV9toV10(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS alert_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  event_id TEXT NOT NULL UNIQUE,
		  ts INTEGER NOT NULL,
		  rule_id TEXT NOT NULL,
		  rule_name TEXT NOT NULL,
		  severity INTEGER NOT NULL,
		  category TEXT NOT NULL,
		  subject TEXT NOT NULL,
		  body TEXT NOT NULL DEFAULT '',
		  context_json TEXT NOT NULL DEFAULT '',
		  labels_json TEXT NOT NULL DEFAULT '',
		  channels_fired_json TEXT NOT NULL DEFAULT '',
		  channels_failed_json TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_alert_event_ts          ON alert_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_alert_event_rule_ts     ON alert_event (rule_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_alert_event_severity_ts ON alert_event (severity, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV10toV11 — Step Z.1 (2026-06-18). Creates the
// rate_limit_event table for the per-route 429 capture
// pipeline. Mirrors the country_block_event shape
// (v7→v8) — same retention contract, same per-route +
// per-IP drill-down indexes.
//
// Column rationale :
//   - ts (INTEGER) : seconds-since-epoch, indexed for
//     time-range scans + retention prune.
//   - route_id : extracted from the Caddy event's "zone"
//     field via the Step Q "route-<UUID>" convention.
//     Empty string when the operator hand-crafted a
//     custom rate-limit zone bypassing Arenet's emit
//     path — the row still persists for forensic value
//     with the full zone string in the zone column.
//   - zone : the upstream caddy-ratelimit zone name
//     ("route-<UUID>" for routes managed via Arenet).
//     Kept alongside route_id so the operator can
//     correlate with Caddy's own zap log lines if needed.
//   - remote_ip : the {http.request.remote.host}
//     resolution captured at the 429 emit time.
//   - wait_ms : the Retry-After milliseconds the
//     upstream handler told the client to wait. 0 when
//     the wait field wasn't present in the event.
func migrateV10toV11(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS rate_limit_event (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  ts INTEGER NOT NULL,
		  route_id TEXT NOT NULL DEFAULT '',
		  zone TEXT NOT NULL DEFAULT '',
		  remote_ip TEXT NOT NULL DEFAULT '',
		  wait_ms INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limit_event_ts        ON rate_limit_event (ts)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limit_event_route_ts  ON rate_limit_event (route_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_rate_limit_event_remote_ts ON rate_limit_event (remote_ip, ts)`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV11toV12 — Step Z.3 (2026-06-18). Adds the
// rate_limit_count column to both bucket_1m and bucket_1h
// so the per-route 429 rate gets its own dashboard
// timeseries (mirror of the waf_block_count + the v8→v9
// waf_detect_count additions). Default 0 on pre-fix rows
// — the column didn't exist when those buckets were
// written, so "no data" is the operator-honest answer
// rather than fabricating a value.
//
// Companion : the ratelimit.Sink.absorb path bumps the
// per-route bucket counter on every event (mirror of
// waf.Sink.absorb BumpWafBlocks). Bumps happen BEFORE
// SQLite persistence so a flush failure doesn't
// suppress the per-minute timeseries point — the
// dashboard tile reflects attack volume, not just
// successfully-persisted event count.
func migrateV11toV12(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN rate_limit_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN rate_limit_count INTEGER NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}

// migrateV12toV13 — v2.36 (2026-09-22). Adds matched_var to
// waf_event: the "VARIABLE:key" of the field that triggered the
// rule (e.g. "ARGS:content"), used to offer a targeted exclusion
// from the event. Pre-v13 rows get ” — the field was not recorded.
func migrateV12toV13(ctx context.Context, tx *sql.Tx) error {
	const stmt = `ALTER TABLE waf_event ADD COLUMN matched_var TEXT NOT NULL DEFAULT ''`
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("exec %q: %w", stmt, err)
	}
	return nil
}

// migrateV13toV14 — v2.56. Re-redacts the WAF events already stored.
//
// The redaction pattern was anchored on `?` or `&`, so the name `token`
// never matched `?access_token=`: what precedes `token=` there is
// `access_`, not a separator. Vaultwarden puts the user's access token in
// the URI, so the parameter most worth masking was the one that got
// through, and every event recorded before this migration may carry a
// live credential in request_path or payload_sample.
//
// Fixing the pattern only protects events recorded from now on. This step
// applies it to what is already on disk, because a secret in a database
// is not less of a secret for having been written last week.
//
// Redact is idempotent, so a row that was already clean is left alone and
// re-running this is harmless. Only rows that actually change are
// written, which keeps a large table from being rewritten wholesale.
func migrateV13toV14(ctx context.Context, tx *sql.Tx) error {
	const sel = `SELECT id, request_path, payload_sample FROM waf_event`
	rows, err := tx.QueryContext(ctx, sel)
	if err != nil {
		return fmt.Errorf("exec %q: %w", sel, err)
	}
	type row struct {
		id      int64
		path    string
		payload string
	}
	// Collected before updating: SQLite will not accept writes on the
	// same connection while a result set is still open.
	var changed []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.path, &r.payload); err != nil {
			rows.Close()
			return fmt.Errorf("scan waf_event: %w", err)
		}
		redactedPath := waf.Redact(r.path)
		redactedPayload := waf.Redact(r.payload)
		if redactedPath == r.path && redactedPayload == r.payload {
			continue
		}
		changed = append(changed, row{id: r.id, path: redactedPath, payload: redactedPayload})
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate waf_event: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close waf_event rows: %w", err)
	}
	if len(changed) == 0 {
		return nil
	}

	const upd = `UPDATE waf_event SET request_path = ?, payload_sample = ? WHERE id = ?`
	stmt, err := tx.PrepareContext(ctx, upd)
	if err != nil {
		return fmt.Errorf("prepare %q: %w", upd, err)
	}
	defer stmt.Close()
	for _, r := range changed {
		if _, err := stmt.ExecContext(ctx, r.path, r.payload, r.id); err != nil {
			return fmt.Errorf("redact waf_event %d: %w", r.id, err)
		}
	}
	return nil
}

// firstLine returns the first non-empty line of s, trimmed.
// Used to keep migration error messages compact (the full
// DDL is verbose; the first line is the operator's cue).
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// migrateV14toV15 — the latency-truth design (spec
// docs/superpowers/specs/2026-10-05-latency-truth-design.md, D6).
//
// Adds, on both bucket tables:
//
//   - total_hist / ttfb_hist: the latency DISTRIBUTIONS, 68-byte blobs
//     of 17 little-endian uint32 counts (histogram.Encode). Storing the
//     distribution instead of a scalar percentile is the whole point:
//     percentiles cannot be summed, averaged or maximised, and the
//     pipeline that received a scalar did all three. Bucket counts sum
//     exactly, so the quantile is taken once at read time over the
//     whole window.
//   - bytes_out: response body bytes served. Volume was recorded
//     nowhere, so the cause of a slow transfer was reachable only by
//     reading a raw access log.
//   - hijacked_count: requests whose connection was taken over (a
//     WebSocket upgrade), whose TTFB and bytes are unobservable by
//     construction rather than zero.
//
// The two blob columns are NULLABLE ON PURPOSE and are not
// back-filled. Rows written before this version have no histogram —
// the information was discarded a second after it was produced and
// cannot be recovered. NULL is how the read path recognises them, and
// the alternative (defaulting to 68 zero bytes) would make every
// historical row read as a route that served nothing, which is the
// exact confusion this design exists to remove.
//
// latency_p95_ms is left in place and keeps being written, now
// computed correctly from the distribution at flush time, so every
// existing reader keeps working through the upgrade.
//
// SQLite's ALTER TABLE ADD COLUMN is metadata-only, so this is cheap
// on a large DB: no row rewrite, no table copy.
func migrateV14toV15(ctx context.Context, tx *sql.Tx) error {
	stmts := []string{
		`ALTER TABLE bucket_1m ADD COLUMN total_hist BLOB`,
		`ALTER TABLE bucket_1m ADD COLUMN ttfb_hist BLOB`,
		`ALTER TABLE bucket_1m ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1m ADD COLUMN hijacked_count INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN total_hist BLOB`,
		`ALTER TABLE bucket_1h ADD COLUMN ttfb_hist BLOB`,
		`ALTER TABLE bucket_1h ADD COLUMN bytes_out INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE bucket_1h ADD COLUMN hijacked_count INTEGER NOT NULL DEFAULT 0`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(s), err)
		}
	}
	return nil
}
