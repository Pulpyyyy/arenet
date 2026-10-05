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

// Package observability implements Step L's per-route metrics
// history: in-memory bucket aggregator + SQLite persistence +
// retention rollup. See docs/superpowers/specs/2026-05-28-step-l-observability.md.
package observability

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/barto95100/arenet/internal/histogram"
)

// schemaSQL is the schema applied at every Open. All statements
// are idempotent via IF NOT EXISTS / INSERT OR IGNORE, so calling
// Open on an existing DB file is a no-op (AC #11).
const schemaSQL = `
CREATE TABLE IF NOT EXISTS bucket_1m (
  route_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  req_count INTEGER NOT NULL,
  fourxx_count INTEGER NOT NULL,
  fivexx_count INTEGER NOT NULL,
  latency_p95_ms INTEGER NOT NULL,
  PRIMARY KEY (route_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_bucket_1m_ts ON bucket_1m (ts);

CREATE TABLE IF NOT EXISTS bucket_1h (
  route_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  req_count INTEGER NOT NULL,
  fourxx_count INTEGER NOT NULL,
  fivexx_count INTEGER NOT NULL,
  latency_p95_ms INTEGER NOT NULL,
  PRIMARY KEY (route_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_bucket_1h_ts ON bucket_1h (ts);

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY
);
-- Seed the bootstrap version 1 ONLY when the table is empty.
-- Using INSERT OR IGNORE here would inject a phantom row at
-- version=1 on every reopen of an already-migrated DB (e.g.
-- one at v2 or v3). That phantom row breaks the next
-- migration's UPDATE-all-rows-to-N statement with a PK
-- collision. Latent until the first time we bump past v2 —
-- caught by TestMigrate_V2ToV3_PreservesExistingData.
INSERT INTO schema_version (version)
  SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);
`

// Store owns the SQLite handle for the metrics database. Safe
// for concurrent use — the underlying *sql.DB has its own pool.
type Store struct {
	db   *sql.DB
	path string
}

// Open initialises the metrics DB at the given file path and
// applies the schema. Returns an error so the caller in main.go
// can implement the AC #13 degraded-mode policy (log + continue
// without metrics rather than abort the data plane).
//
// path may be ":memory:" for in-process tests.
func Open(ctx context.Context, path string) (*Store, error) {
	// _busy_timeout makes the driver wait on a locked write
	// instead of returning SQLITE_BUSY immediately — useful when
	// the aggregator flush and the retention loop touch the DB
	// concurrently. _journal=WAL gives us readers that don't
	// block writers, important for the future read API (L.2).
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("observability: sql.Open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: ping: %w", err)
	}
	// Single writer is what SQLite guarantees in WAL mode anyway;
	// pin the pool to 1 writer to avoid spurious "database is
	// locked" under concurrent INSERTs from aggregator + retention.
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: schema init: %w", err)
	}
	// Step M.1: run the migrate chain. Reads the current
	// schema_version (bootstrap leaves it at 1 on a fresh DB)
	// and applies every step up to currentSchemaVersion in a
	// single transaction. Idempotent on an already-current DB.
	var current int
	row := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`)
	if err := row.Scan(&current); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: read current schema_version: %w", err)
	}
	if err := migrate(ctx, db, current); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("observability: migrate: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the underlying handle. Safe to call on a nil
// store (no-op) so the main.go degraded-mode path can defer it
// unconditionally.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the on-disk path the store was opened with.
// Returns ":memory:" for in-process test stores.
func (s *Store) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// SchemaVersion returns the current schema version stored in the
// schema_version table. Always 1 in Step L; future bumps wire
// through a migrate chain. Returns 0 on a fresh / unreadable DB.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var v int
	row := s.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_version`)
	if err := row.Scan(&v); err != nil {
		return 0, fmt.Errorf("observability: schema version: %w", err)
	}
	return v, nil
}

// InsertBatch writes a slice of MetricBucket rows into the table
// selected by gran, inside a single transaction. Rows that
// already exist on (route_id, ts) are overwritten — this gives
// the aggregator a safe re-flush semantic if a previous flush
// partially failed.
//
// Empty batch is a no-op (returns nil). The whole batch is
// rolled back on first error so a failed flush leaves the DB
// untouched. AC #13: the aggregator caller logs the error and
// continues; it never propagates to the request path.
func (s *Store) InsertBatch(ctx context.Context, gran Granularity, rows []MetricBucket) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO `+gran.tableName()+` (route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, waf_detect_count, throttle_block_count, crowdsec_decision_count, rate_limit_count, latency_p95_ms, total_hist, ttfb_hist, bytes_out, hijacked_count)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(route_id, ts) DO UPDATE SET
  req_count               = excluded.req_count,
  fourxx_count            = excluded.fourxx_count,
  fivexx_count            = excluded.fivexx_count,
  waf_block_count         = excluded.waf_block_count,
  waf_detect_count        = excluded.waf_detect_count,
  throttle_block_count    = excluded.throttle_block_count,
  crowdsec_decision_count = excluded.crowdsec_decision_count,
  rate_limit_count        = excluded.rate_limit_count,
  latency_p95_ms          = excluded.latency_p95_ms,
  total_hist              = excluded.total_hist,
  ttfb_hist               = excluded.ttfb_hist,
  bytes_out               = excluded.bytes_out,
  hijacked_count          = excluded.hijacked_count
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx,
			r.RouteID,
			r.Ts.UTC().Unix(),
			r.ReqCount,
			r.FourxxCount,
			r.FivexxCount,
			r.WafBlockCount,
			r.WafDetectCount,
			r.ThrottleBlockCount,
			r.CrowdSecDecisionCount,
			r.RateLimitCount,
			r.LatencyP95Ms,
			// A nil histogram writes SQL NULL, not 68 zero bytes:
			// "we have no distribution for this row" must stay
			// distinguishable from "a distribution of nothing".
			encodeHistOrNil(r.TotalHist),
			encodeHistOrNil(r.TTFBHist),
			r.BytesOut,
			r.HijackedCount,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert row (route=%s ts=%s): %w", r.RouteID, r.Ts, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit: %w", err)
	}
	return nil
}

// Query returns every MetricBucket for routeID with timestamps
// in [from, to), in timestamp-ascending order. Missing buckets
// are NOT gap-filled here — the API layer at L.2 applies the
// AC #5 projection rule (0 for counts, null for p95) when
// shaping the JSON response.
//
// Returning the dense slice from the API layer would force a
// 1440-element walk per timeseries request; returning the
// sparse rows here keeps the storage layer cheap and lets the
// caller decide the gap-fill policy.
func (s *Store) Query(ctx context.Context, gran Granularity, routeID string, from, to time.Time) ([]MetricBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT route_id, ts, req_count, fourxx_count, fivexx_count, waf_block_count, waf_detect_count, throttle_block_count, crowdsec_decision_count, rate_limit_count, latency_p95_ms, total_hist, ttfb_hist, bytes_out, hijacked_count
FROM `+gran.tableName()+`
WHERE route_id = ? AND ts >= ? AND ts < ?
ORDER BY ts ASC
`, routeID, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("observability: query: %w", err)
	}
	defer rows.Close()
	var out []MetricBucket
	for rows.Next() {
		var b MetricBucket
		var tsUnix int64
		var totalBlob, ttfbBlob []byte
		if err := rows.Scan(&b.RouteID, &tsUnix, &b.ReqCount, &b.FourxxCount, &b.FivexxCount, &b.WafBlockCount, &b.WafDetectCount, &b.ThrottleBlockCount, &b.CrowdSecDecisionCount, &b.RateLimitCount, &b.LatencyP95Ms, &totalBlob, &ttfbBlob, &b.BytesOut, &b.HijackedCount); err != nil {
			return nil, fmt.Errorf("observability: scan: %w", err)
		}
		// NULL on a pre-v15 row leaves these nil, which is how the
		// caller tells "no distribution recorded" from "a distribution
		// of nothing". A malformed blob is an error, not a silent zero.
		if b.TotalHist, err = decodeHistOrNil(totalBlob); err != nil {
			return nil, fmt.Errorf("observability: total_hist (route=%s ts=%d): %w", b.RouteID, tsUnix, err)
		}
		if b.TTFBHist, err = decodeHistOrNil(ttfbBlob); err != nil {
			return nil, fmt.Errorf("observability: ttfb_hist (route=%s ts=%d): %w", b.RouteID, tsUnix, err)
		}
		b.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: query iterate: %w", err)
	}
	return out, nil
}

// QueryAggregated returns one MetricBucket per `ts` aggregated
// across ALL routes, for the table selected by gran. Per
// Spec-1 §10.1 (added during L.3):
//
//   - req_count, fourxx_count, fivexx_count: SUM across routes
//     within each bucket. AC #3 holds: each counter is summed
//     independently — they NEVER collapse into a single
//     "errors" number.
//   - latency_p95_ms: req-weighted percentile-of-percentiles
//     across the routes that landed rows in the bucket. Same
//     approximation as the hourly rollup (AC #2 acknowledged).
//     Returned as 0 when the bucket has no traffic; the API
//     layer maps that to JSON null per AC #5.
//
// The returned RouteID is the empty string ("") on every row —
// these buckets are system-wide, not tied to a specific route.
// The API layer rewrites it to "all" for the wire response.
func (s *Store) QueryAggregated(ctx context.Context, gran Granularity, from, to time.Time) ([]MetricBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	// Integer arithmetic in SQLite: the weighted-p95
	// numerator is Σ(latency_p95_ms × req_count) and the
	// denominator is Σ(req_count) when req_count > 0. Without
	// the CASE guard, a bucket with no traffic but a phantom
	// LatencyP95Ms > 0 would skew the average; the guard
	// keeps the math honest.
	rows, err := s.db.QueryContext(ctx, `
SELECT
  ts,
  SUM(req_count)              AS req_total,
  SUM(fourxx_count)           AS fourxx_total,
  SUM(fivexx_count)           AS fivexx_total,
  SUM(waf_block_count)        AS waf_total,
  SUM(waf_detect_count)       AS waf_detect_total,
  SUM(throttle_block_count)   AS throttle_total,
  SUM(crowdsec_decision_count) AS crowdsec_total,
  SUM(rate_limit_count)       AS rate_limit_total,
  CASE
    WHEN SUM(CASE WHEN req_count > 0 THEN req_count ELSE 0 END) > 0
    THEN SUM(latency_p95_ms * CASE WHEN req_count > 0 THEN req_count ELSE 0 END) / SUM(CASE WHEN req_count > 0 THEN req_count ELSE 0 END)
    ELSE 0
  END AS p95_weighted
FROM `+gran.tableName()+`
WHERE ts >= ? AND ts < ?
GROUP BY ts
ORDER BY ts ASC
`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("observability: query aggregated: %w", err)
	}
	defer rows.Close()
	var out []MetricBucket
	for rows.Next() {
		var b MetricBucket
		var tsUnix int64
		var p95 int64 // SQLite SUM/CASE returns INTEGER; scan as int64 then narrow
		if err := rows.Scan(&tsUnix, &b.ReqCount, &b.FourxxCount, &b.FivexxCount, &b.WafBlockCount, &b.WafDetectCount, &b.ThrottleBlockCount, &b.CrowdSecDecisionCount, &b.RateLimitCount, &p95); err != nil {
			return nil, fmt.Errorf("observability: scan aggregated: %w", err)
		}
		b.Ts = time.Unix(tsUnix, 0).UTC()
		b.LatencyP95Ms = int32(p95)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: query aggregated iterate: %w", err)
	}
	return out, nil
}

// PruneOlderThan deletes rows from the table selected by gran
// where ts < cutoff. Returns the number of rows deleted. Called
// by the retention loop; safe to call concurrently with inserts
// (SQLite serialises writers).
func (s *Store) PruneOlderThan(ctx context.Context, gran Granularity, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM `+gran.tableName()+` WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune rows affected: %w", err)
	}
	return n, nil
}

// --- Step M: waf_event store ------------------------------------------------

// WafEvent is the observability-layer mirror of waf.Event
// (same fields). Defined here so observability does not have
// to import internal/waf (dependency direction stays clean:
// the wiring layer in cmd/arenet/main.go bridges the two via
// a small adapter). The fields are storage-flat: all data
// already capped + redacted by the time it reaches Insert.
//
// See docs/superpowers/specs/2026-05-28-step-m-security.md
// §3.1 for the field-level semantics.
type WafEvent struct {
	ID            int64
	Ts            time.Time
	RouteID       string
	RuleID        string
	Category      string // matches waf.OwaspCategory at the type level
	Severity      int
	SrcIP         string
	RequestMethod string
	RequestPath   string
	PayloadSample string

	// Action ("BLOCK" / "DETECT") and StatusCode are the
	// W.bugfix Fix #1 mode-aware label fields. Pre-W.bugfix
	// rows are migrated to ("BLOCK", 403) since that was the
	// implicit universal behavior when the columns didn't
	// exist (every WAF event row in the legacy schema was
	// emitted by a block-mode handler — detect-mode events
	// were silently mislabeled at the frontend, NOT
	// suppressed at the sink). See migrateV6toV7.
	Action     string
	StatusCode int

	// MatchedVar (v2.36) is the "VARIABLE:key" of the field that
	// triggered the rule ("ARGS:content"); empty when the variable
	// has no key or the row predates v13.
	MatchedVar string
}

// WafEventFilter narrows a QueryWafEvents call. All fields
// are optional; the API layer at M.2 maps query-string
// parameters into this struct. Limit > 100 is clamped by the
// store as a defence-in-depth on top of the API-layer cap.
// WafActionBlock and WafActionDetect are the two values of WafEvent.Action.
// BLOCK means the WAF refused the request; DETECT means it recorded the match
// and let the request through.
const (
	WafActionBlock  = "BLOCK"
	WafActionDetect = "DETECT"
)

type WafEventFilter struct {
	RouteID  string
	Category string
	// Action, when set, narrows in SQL to WafActionBlock or
	// WafActionDetect.
	//
	// v2.58.4 — this said "Only CountWafEvents honours it: QueryWafEvents
	// is the events-page reader and its callers filter presentation-side".
	// That was wrong: both go through wafEventPredicates, which has always
	// added the predicate. The claim mattered, because it is why Security
	// Automation counted detect-mode events — nobody passed Action, having
	// read that passing it would do nothing.
	Action string
	From   time.Time // inclusive
	To     time.Time // exclusive; zero = open-ended (now)
	Limit  int
}

// wafEventLimitCap bounds the result set defensively. The
// API layer caps at 100 before calling; this is the
// belt-and-braces for any future internal caller that forgets.
const wafEventLimitCap = 100

// InsertWafEventBatch persists a slice of WafEvent rows in a
// single transaction. Errors are returned to the caller —
// the production caller (waf.Sink) logs + counts + swallows
// per AC #13 (the sink wraps this call; the store stays
// honest about failures so test fakes can simulate them).
//
// Empty batch is a no-op.
func (s *Store) InsertWafEventBatch(ctx context.Context, events []WafEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin waf_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO waf_event (ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample, action, status_code, matched_var)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare waf_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		action := e.Action
		if action == "" {
			// Defense in depth — the sink should always set
			// this post-W.bugfix, but a bogus internal call
			// with a zero Event shouldn't break the insert.
			action = "BLOCK"
		}
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.RouteID,
			e.RuleID,
			e.Category,
			e.Severity,
			e.SrcIP,
			e.RequestMethod,
			e.RequestPath,
			e.PayloadSample,
			action,
			e.StatusCode,
			e.MatchedVar,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert waf_event (route=%s rule=%s): %w", e.RouteID, e.RuleID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit waf_event: %w", err)
	}
	return nil
}

// wafEventPredicates renders the shared WHERE clause and its args.
// Extracted (v2.52) so counting and listing cannot drift: they used to be
// one function, and the count was derived by fetching rows and taking
// len() — which silently inherited the row cap. See CountWafEvents.
func wafEventPredicates(filter WafEventFilter) (string, []any) {
	q := ` WHERE 1=1`
	args := []any{}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	if filter.Category != "" {
		q += ` AND category = ?`
		args = append(args, filter.Category)
	}
	if filter.Action != "" {
		q += ` AND action = ?`
		args = append(args, filter.Action)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	return q, args
}

// CountWafEvents returns how many waf_event rows match filter, counted in
// SQL.
//
// v2.52 — the alert source used to count by asking QueryWafEvents for
// 10 000 rows and taking len(). That silently returned at most
// wafEventLimitCap = 100, because the cap exists to bound a RESULT SET
// and a count is not one. Every WAF alert threshold above 100 was
// therefore unreachable, and the "query capped" label meant to warn about
// it could never be set either.
//
// Filter.Limit is ignored here on purpose: a count has no result set to
// bound, and honouring it would recreate the bug.
func (s *Store) CountWafEvents(ctx context.Context, filter WafEventFilter) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	where, args := wafEventPredicates(filter)
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM waf_event`+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("observability: count waf_event: %w", err)
	}
	return n, nil
}

// QueryWafEvents returns the waf_event rows matching filter,
// ts-descending (most recent first — the /security/events
// endpoint's natural ordering). Empty filter returns the most
// recent `wafEventLimitCap` rows. Limit > cap is silently
// clamped down.
//
// The route_id / category filters short-circuit via the
// matching index when set; the from/to filters use the ts
// index. Pure read, safe to call concurrently with inserts.
func (s *Store) QueryWafEvents(ctx context.Context, filter WafEventFilter) ([]WafEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > wafEventLimitCap {
		limit = wafEventLimitCap
	}
	where, args := wafEventPredicates(filter)
	q := `SELECT id, ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample, action, status_code, matched_var
	      FROM waf_event` + where
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query waf_event: %w", err)
	}
	defer rows.Close()
	var out []WafEvent
	for rows.Next() {
		var e WafEvent
		var tsUnix int64
		if err := rows.Scan(
			&e.ID, &tsUnix, &e.RouteID, &e.RuleID, &e.Category, &e.Severity,
			&e.SrcIP, &e.RequestMethod, &e.RequestPath, &e.PayloadSample,
			&e.Action, &e.StatusCode, &e.MatchedVar,
		); err != nil {
			return nil, fmt.Errorf("observability: scan waf_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate waf_event: %w", err)
	}
	return out, nil
}

// PruneWafEventsOlderThan deletes waf_event rows with ts <
// cutoff. Returns the number of rows deleted. Called by the
// retention loop on the same hourly cadence as the bucket
// prunes.
func (s *Store) PruneWafEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM waf_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune waf_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune waf_event rows affected: %w", err)
	}
	return n, nil
}

// WafEventRuleAggregate is one row of the per-rule breakdown
// surfaced by AggregateWafEventsByRule and consumed by the M.4
// drill-down's per-rule table.
//
// Group key is (RuleID, Category). Two CRS rules sharing an ID
// are theoretically possible across upstream config drift, so
// the SQL groups by both — in practice the (rule_id → category)
// mapping is stable, but the query stays honest.
type WafEventRuleAggregate struct {
	RuleID   string
	Category string
	Count    int64
	LastSeen time.Time
}

// WafEventAggregateFilter narrows AggregateWafEventsByRule.
//
// Phase Y (2026-06-18) — added Category for the cross-route
// drill-down on /waf. The pre-Y "filtering by category defeats
// the purpose" docstring was about the per-ROUTE drill-down
// (where the user has already picked a route and wants the
// rule breakdown ; filtering by category there is redundant
// because each row already carries its category). For the
// /waf page's category-focused drill-down the opposite is
// true : the operator clicks one category card and wants the
// rule breakdown for THAT category across all routes. RouteID
// stays optional ; Category is the new optional filter ;
// both empty = unfiltered aggregate (every (rule, category)
// pair the SQLite window holds).
//
// Limit stays absent — an aggregated result is bounded by the
// number of distinct rules tripped in the window (typically
// << 100), so no client-driven cap is needed.
type WafEventAggregateFilter struct {
	RouteID  string
	Category string    // Phase Y — cross-route per-category drill-down filter
	From     time.Time // inclusive
	To       time.Time // exclusive; zero = open-ended (now)
}

// --- Step Q: throttle_event store -------------------------------------------

// ThrottleEvent is the observability-layer mirror of
// throttle.Event (same fields). Defined here so observability
// does not have to import internal/throttle (dependency
// direction stays clean: the wiring layer in cmd/arenet/main.go
// bridges the two via a small adapter — same pattern as the
// WafEvent adapter from Step M).
//
// AttemptedUsername is stored verbatim — parity with the audit
// log per spec §1.3 D8.A. SrcIP is the request's effective
// remote address (after the shared trusted-proxy chain).
type ThrottleEvent struct {
	ID                   int64
	Ts                   time.Time
	Tier                 int // 1 or 2 per spec §1.3 D1
	SrcIP                string
	AttemptedUsername    string
	BlockedUntil         time.Time
	BlockDurationSeconds int
}

// ThrottleEventFilter narrows a QueryThrottleEvents call. All
// fields are optional; the API layer at Q.3 maps query-string
// parameters into this struct.
type ThrottleEventFilter struct {
	SrcIP string
	Tier  int       // 0 = any tier, 1 or 2 = exact
	From  time.Time // inclusive
	To    time.Time // exclusive; zero = open-ended (now)
	Limit int
}

// throttleEventLimitCap bounds the result set defensively.
// API layer caps at 100; this is the belt-and-braces.
const throttleEventLimitCap = 100

// InsertThrottleEventBatch persists a slice of ThrottleEvent
// rows in a single transaction. Errors are returned to the
// caller — the production caller (throttle.Sink) logs +
// counts + swallows per AC #13. Empty batch is a no-op.
func (s *Store) InsertThrottleEventBatch(ctx context.Context, events []ThrottleEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin throttle_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO throttle_event (ts, tier, src_ip, attempted_username, blocked_until, block_duration_seconds)
VALUES (?, ?, ?, ?, ?, ?)
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare throttle_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.Ts.UTC().Unix(),
			e.Tier,
			e.SrcIP,
			e.AttemptedUsername,
			e.BlockedUntil.UTC().Unix(),
			e.BlockDurationSeconds,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert throttle_event (ip=%s tier=%d): %w", e.SrcIP, e.Tier, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit throttle_event: %w", err)
	}
	return nil
}

// QueryThrottleEvents returns the throttle_event rows matching
// filter, ts-descending (most-recent first — natural ordering
// for the timeline UI). Empty filter returns the most-recent
// `throttleEventLimitCap` rows.
func (s *Store) QueryThrottleEvents(ctx context.Context, filter ThrottleEventFilter) ([]ThrottleEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > throttleEventLimitCap {
		limit = throttleEventLimitCap
	}
	q := `SELECT id, ts, tier, src_ip, attempted_username, blocked_until, block_duration_seconds
	      FROM throttle_event WHERE 1=1`
	args := []any{}
	if filter.SrcIP != "" {
		q += ` AND src_ip = ?`
		args = append(args, filter.SrcIP)
	}
	if filter.Tier != 0 {
		q += ` AND tier = ?`
		args = append(args, filter.Tier)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query throttle_event: %w", err)
	}
	defer rows.Close()
	var out []ThrottleEvent
	for rows.Next() {
		var e ThrottleEvent
		var tsUnix, blockedUntilUnix int64
		if err := rows.Scan(
			&e.ID, &tsUnix, &e.Tier, &e.SrcIP, &e.AttemptedUsername,
			&blockedUntilUnix, &e.BlockDurationSeconds,
		); err != nil {
			return nil, fmt.Errorf("observability: scan throttle_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		e.BlockedUntil = time.Unix(blockedUntilUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate throttle_event: %w", err)
	}
	return out, nil
}

// PruneThrottleEventsOlderThan deletes throttle_event rows
// with ts < cutoff. Returns the number of rows deleted. Called
// by the retention loop on the same hourly cadence as the
// bucket and waf_event prunes.
func (s *Store) PruneThrottleEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM throttle_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune throttle_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune throttle_event rows affected: %w", err)
	}
	return n, nil
}

// ThrottleEventIPAggregate is one row of the per-IP breakdown
// surfaced by AggregateThrottleEventsByIP. Mirror of
// WafEventRuleAggregate — Step Q spec §3.3 lists "top blocked
// IPs over the window" as a server-side aggregation, matching
// the M.4 lesson that client-side aggregation over a 30d
// window silently degrades.
type ThrottleEventIPAggregate struct {
	SrcIP    string
	Tier1    int64
	Tier2    int64
	Total    int64
	LastSeen time.Time
}

// ThrottleEventAggregateFilter narrows
// AggregateThrottleEventsByIP. Same shape as
// ThrottleEventFilter minus Tier (the aggregation is BY tier
// already — Tier1 and Tier2 are separate columns) and minus
// Limit (number of distinct IPs in a window is small; the API
// layer applies a top-N if it wants one).
type ThrottleEventAggregateFilter struct {
	From time.Time // inclusive
	To   time.Time // exclusive; zero = open-ended (now)
}

// AggregateThrottleEventsByIP returns one row per src_ip in
// the window, with Tier-1 + Tier-2 counts + the most-recent
// ts. Ordered by total DESC so the API layer can hand it to
// the frontend table as-is.
func (s *Store) AggregateThrottleEventsByIP(ctx context.Context, filter ThrottleEventAggregateFilter) ([]ThrottleEventIPAggregate, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT
	        src_ip,
	        SUM(CASE WHEN tier = 1 THEN 1 ELSE 0 END) AS tier1,
	        SUM(CASE WHEN tier = 2 THEN 1 ELSE 0 END) AS tier2,
	        COUNT(*)                                   AS total,
	        MAX(ts)                                    AS last_ts
	      FROM throttle_event WHERE 1=1`
	args := []any{}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	q += ` GROUP BY src_ip ORDER BY total DESC, last_ts DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate throttle_event by ip: %w", err)
	}
	defer rows.Close()
	var out []ThrottleEventIPAggregate
	for rows.Next() {
		var agg ThrottleEventIPAggregate
		var lastUnix int64
		if err := rows.Scan(&agg.SrcIP, &agg.Tier1, &agg.Tier2, &agg.Total, &lastUnix); err != nil {
			return nil, fmt.Errorf("observability: scan throttle_event aggregate: %w", err)
		}
		agg.LastSeen = time.Unix(lastUnix, 0).UTC()
		out = append(out, agg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate throttle_event aggregate: %w", err)
	}
	return out, nil
}

// DistinctWafEventSrcIPs returns the set of distinct source
// IPs that appeared in waf_event rows within [from, to).
// Powers the Step Q.3 /security/attackers-summary union: the
// per-source IP set is small (capped by attacker diversity,
// typically << 100 even on a noisy week), so the caller
// merges this slice into a Go set rather than paying for a
// SQL UNION across heterogeneous schemas.
//
// Either bound may be zero (open-ended) — same shape as
// WafEventFilter. Empty result is not an error.
func (s *Store) DistinctWafEventSrcIPs(ctx context.Context, from, to time.Time) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT DISTINCT src_ip FROM waf_event WHERE 1=1`
	args := []any{}
	if !from.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, from.UTC().Unix())
	}
	if !to.IsZero() {
		q += ` AND ts < ?`
		args = append(args, to.UTC().Unix())
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: distinct waf_event src_ip: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("observability: scan distinct waf_event src_ip: %w", err)
		}
		out = append(out, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate distinct waf_event src_ip: %w", err)
	}
	return out, nil
}

// DistinctThrottleEventSrcIPs is the throttle_event-side
// mirror of DistinctWafEventSrcIPs. Same contract.
func (s *Store) DistinctThrottleEventSrcIPs(ctx context.Context, from, to time.Time) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT DISTINCT src_ip FROM throttle_event WHERE 1=1`
	args := []any{}
	if !from.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, from.UTC().Unix())
	}
	if !to.IsZero() {
		q += ` AND ts < ?`
		args = append(args, to.UTC().Unix())
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: distinct throttle_event src_ip: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, fmt.Errorf("observability: scan distinct throttle_event src_ip: %w", err)
		}
		out = append(out, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate distinct throttle_event src_ip: %w", err)
	}
	return out, nil
}

// AggregateWafEventsByRule returns one row per (rule_id,
// category) tuple in the window, with the count of matching
// events + the most-recent ts. Ordered by count DESC so the
// API layer can hand it to the frontend table as-is.
//
// Closes the M.4 drift the spec §5.4 wording calls out:
// "per-rule breakdown table for the route's blocks OVER THE
// WINDOW". The M.4 frontend used to derive this client-side
// from the most-recent-100 events, which silently degraded on
// a 30d window. This endpoint computes it server-side from the
// full row set, honouring the window boundaries.
func (s *Store) AggregateWafEventsByRule(ctx context.Context, filter WafEventAggregateFilter) ([]WafEventRuleAggregate, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT rule_id, category, COUNT(*) AS cnt, MAX(ts) AS last_ts
	      FROM waf_event WHERE 1=1`
	args := []any{}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	// Phase Y — optional category filter for the /waf
	// per-category drill-down.
	if filter.Category != "" {
		q += ` AND category = ?`
		args = append(args, filter.Category)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	q += ` GROUP BY rule_id, category ORDER BY cnt DESC, last_ts DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate waf_event by rule: %w", err)
	}
	defer rows.Close()
	var out []WafEventRuleAggregate
	for rows.Next() {
		var agg WafEventRuleAggregate
		var lastUnix int64
		if err := rows.Scan(&agg.RuleID, &agg.Category, &agg.Count, &lastUnix); err != nil {
			return nil, fmt.Errorf("observability: scan waf_event aggregate: %w", err)
		}
		agg.LastSeen = time.Unix(lastUnix, 0).UTC()
		out = append(out, agg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate waf_event aggregate: %w", err)
	}
	return out, nil
}

// WafEventCategoryAggregate is one row of the by-category
// breakdown surfaced by AggregateWafEventsByCategory.
// Mirrors WafEventRuleAggregate but groups by category
// only — used by the /metrics/summary handler to populate
// WafBlocksByCategory + WafDetectsByCategory over a
// non-trivial window (24h+) where row-by-row iteration of
// waf_event would hit the wafEventLimitCap=100.
type WafEventCategoryAggregate struct {
	Category string
	Count    int64
}

// WafEventCategoryFilter narrows AggregateWafEventsByCategory.
// Action is the discriminator that lets the summary endpoint
// run two queries — one for action="BLOCK" populating
// WafBlocksByCategory, one for action="DETECT" populating
// WafDetectsByCategory. Empty action = both populations
// (operator-rare; reserved for future combined views).
type WafEventCategoryFilter struct {
	Action  string    // "BLOCK", "DETECT", or "" for all
	RouteID string    // optional per-route filter
	From    time.Time // inclusive
	To      time.Time // exclusive; zero = open-ended (now)
}

// AggregateWafEventsByCategory returns one row per category
// for events matching filter, with the count of matching
// events. Ordered by count DESC.
//
// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — the missing
// server-side aggregator that lets /metrics/summary cover
// a 24h window without iterating the per-event log under
// the wafEventLimitCap=100 ceiling. Mirror of the
// AggregateWafEventsByRule shape; smaller result set
// (handful of OWASP categories rather than ~dozens of
// rules) so no Limit param needed.
//
// SQLite uses the (category, ts) index when the filter
// touches category or ts; the GROUP BY happens in-memory
// on the small post-filter set — cheap for typical homelab
// volumes and bounded by the COUNT(DISTINCT category)
// arithmetic ceiling even on storms.
func (s *Store) AggregateWafEventsByCategory(ctx context.Context, filter WafEventCategoryFilter) ([]WafEventCategoryAggregate, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT category, COUNT(*) AS cnt
	      FROM waf_event WHERE 1=1`
	args := []any{}
	if filter.Action != "" {
		q += ` AND action = ?`
		args = append(args, filter.Action)
	}
	if filter.RouteID != "" {
		q += ` AND route_id = ?`
		args = append(args, filter.RouteID)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	q += ` GROUP BY category ORDER BY cnt DESC`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate waf_event by category: %w", err)
	}
	defer rows.Close()
	var out []WafEventCategoryAggregate
	for rows.Next() {
		var agg WafEventCategoryAggregate
		if err := rows.Scan(&agg.Category, &agg.Count); err != nil {
			return nil, fmt.Errorf("observability: scan waf_event category aggregate: %w", err)
		}
		out = append(out, agg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate waf_event category aggregate: %w", err)
	}
	return out, nil
}

// WafEventRouteCounts holds the per-action event counts
// for one route over a window. Used as the value type of
// AggregateWafEventsByRoute's result map.
type WafEventRouteCounts struct {
	Block  uint64
	Detect uint64
}

// AggregateWafEventsByRoute returns the per-route Block /
// Detect event counts in the time range [from, to). The
// keys of the result map are route IDs that had at least
// one event in the window; routes with zero events are
// absent (callers should treat absent keys as zero on
// both fields).
//
// Follow-up to commit 579f695 — the summary endpoint
// previously sourced per-route WAF counters from
// bucket_1h.waf_{block,detect}_count, which created a
// historical asymmetry: BumpWafDetects shipped in
// e7e2905 (yesterday), so DETECT events older than that
// commit never reached the bucket counter and the
// summary's totalWafDetected was a strict undercount
// versus the same window's wafDetectsByCategory map
// (sourced from waf_event GROUP BY). Switching every
// WAF read to waf_event gives a single source of truth
// across the response — the row table is the
// authoritative inventory of every event the sink ever
// absorbed regardless of the bucket-counter migration
// history.
//
// SQL: SELECT route_id, action, COUNT(*) FROM waf_event
//
//	WHERE ts BETWEEN ? AND ?
//	GROUP BY route_id, action
//
// Covered by idx_waf_event_route_ts (route_id, ts).
// Empty window → empty map (graceful, no error).
//
// The action filter is intentionally absent on the
// receiving side — callers want both populations in a
// single round-trip; SQL groups by (route_id, action)
// so the same scan delivers both. Rows with unexpected
// Action ("" or future enum values) are silently
// dropped, mirroring the same dispatch shape as
// metrics_handlers.go's category loop.
func (s *Store) AggregateWafEventsByRoute(ctx context.Context, from, to time.Time) (map[string]WafEventRouteCounts, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT route_id, action, COUNT(*) AS cnt
	      FROM waf_event WHERE 1=1`
	args := []any{}
	if !from.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, from.UTC().Unix())
	}
	if !to.IsZero() {
		q += ` AND ts < ?`
		args = append(args, to.UTC().Unix())
	}
	q += ` GROUP BY route_id, action`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate waf_event by route: %w", err)
	}
	defer rows.Close()
	out := map[string]WafEventRouteCounts{}
	for rows.Next() {
		var routeID, action string
		var cnt int64
		if err := rows.Scan(&routeID, &action, &cnt); err != nil {
			return nil, fmt.Errorf("observability: scan waf_event route aggregate: %w", err)
		}
		entry := out[routeID]
		switch action {
		case "BLOCK":
			entry.Block += uint64(cnt)
		case "DETECT":
			entry.Detect += uint64(cnt)
			// Other actions ("" / future) silently dropped — the
			// W.bugfix v6→v7 migration backfilled every legacy
			// row to "BLOCK", so an empty action would indicate a
			// data-layer bug we'd rather surface as a missing
			// count than mis-categorise.
		}
		out[routeID] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate waf_event route aggregate: %w", err)
	}
	return out, nil
}

// --- Step N: decision_event store ------------------------------------------

// DecisionEvent is the observability-layer mirror of
// crowdsec.Decision (storage-flat shape, narrowed per Step N
// spec D5.B: drop `id` + `origin`). Defined here so the
// observability package does NOT import internal/crowdsec —
// the cmd/arenet/main.go wiring bridges the two via a small
// adapter (same pattern as M's wafInserterAdapter +
// Q's throttleInserterAdapter).
type DecisionEvent struct {
	ID              int64
	UUID            string
	Ts              time.Time
	Scope           string // "ip" | "range" | "country" | "as"
	Value           string // IP, CIDR, country code, AS
	Type            string // "ban" | "captcha" | "throttle"
	Scenario        string
	ExpiresAt       time.Time
	DurationSeconds int
}

// DecisionEventFilter narrows a QueryDecisionEvents call. All
// fields optional; the API layer at N.3 maps query-string
// parameters into this struct. Limit > 100 is clamped by the
// store as a defence-in-depth on top of the API-layer cap
// (mirror of WafEventFilter / ThrottleEventFilter discipline).
type DecisionEventFilter struct {
	Scope      string
	Value      string // exact match on the LAPI decision's value (IP / CIDR / country code)
	Scenario   string
	From       time.Time
	To         time.Time
	Limit      int
	OnlyActive bool // when true, exclude rows whose expires_at <= now (revoked or expired)
}

const decisionEventLimitCap = 100

// InsertDecisionEventBatch persists a slice of DecisionEvent
// rows in a single transaction. UPSERT on `uuid` because the
// stream consumer's LRU is in-memory only — a process restart
// drops the LRU, the next ?startup=true response re-sends every
// active decision, and our sink would re-Emit them. UPSERT
// keeps the row identity stable across restarts (idempotent
// insert) without needing a pre-INSERT existence check.
//
// On UPSERT, `expires_at` and `duration_seconds` are refreshed
// — LAPI may have extended a decision via `cscli decisions add`
// with a longer duration on the same UUID.
//
// Empty batch is a no-op. Errors returned to caller — the
// production caller (crowdsec.Sink) logs + counts + swallows
// per AC #13.
func (s *Store) InsertDecisionEventBatch(ctx context.Context, events []DecisionEvent) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("observability: begin decision_event tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO decision_event (uuid, ts, scope, value, type, scenario, expires_at, duration_seconds)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(uuid) DO UPDATE SET
  expires_at       = excluded.expires_at,
  duration_seconds = excluded.duration_seconds
`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("observability: prepare decision_event insert: %w", err)
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx,
			e.UUID,
			e.Ts.UTC().Unix(),
			e.Scope,
			e.Value,
			e.Type,
			e.Scenario,
			e.ExpiresAt.UTC().Unix(),
			e.DurationSeconds,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("observability: insert decision_event (uuid=%s value=%s): %w", e.UUID, e.Value, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("observability: commit decision_event: %w", err)
	}
	return nil
}

// MarkDecisionExpired flags a decision row as inactive by
// setting `expires_at` to NOW. The row stays in the table for
// the operator dashboard's historical view; the
// retention.go prune step removes it after the 30d horizon
// (Step N spec D8.A).
//
// Soft delete rather than DELETE because forensic operators
// need to see "the IP 1.2.3.4 WAS banned for 2 hours
// yesterday under scenario http-probing" even after the ban
// is revoked.
//
// No-op when the uuid is not in the table — same defensive
// posture as the sink's Tombstone path (LAPI may signal
// deletion of a decision we never persisted, e.g. dropped on
// the channel via droppedByChannel).
func (s *Store) MarkDecisionExpired(ctx context.Context, uuid string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("observability: store closed")
	}
	if uuid == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE decision_event SET expires_at = ? WHERE uuid = ?`,
		time.Now().UTC().Unix(), uuid)
	if err != nil {
		return fmt.Errorf("observability: mark decision_event expired: %w", err)
	}
	return nil
}

// QueryDecisionEvents returns decision_event rows matching the
// filter, ts-descending (most-recent first). Empty filter
// returns the most-recent decisionEventLimitCap rows.
func (s *Store) QueryDecisionEvents(ctx context.Context, filter DecisionEventFilter) ([]DecisionEvent, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	limit := filter.Limit
	if limit <= 0 || limit > decisionEventLimitCap {
		limit = decisionEventLimitCap
	}
	q := `SELECT id, uuid, ts, scope, value, type, scenario, expires_at, duration_seconds
	      FROM decision_event WHERE 1=1`
	args := []any{}
	if filter.Scope != "" {
		q += ` AND scope = ?`
		args = append(args, filter.Scope)
	}
	if filter.Value != "" {
		q += ` AND value = ?`
		args = append(args, filter.Value)
	}
	if filter.Scenario != "" {
		q += ` AND scenario = ?`
		args = append(args, filter.Scenario)
	}
	if !filter.From.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, filter.From.UTC().Unix())
	}
	if !filter.To.IsZero() {
		q += ` AND ts < ?`
		args = append(args, filter.To.UTC().Unix())
	}
	if filter.OnlyActive {
		q += ` AND expires_at > ?`
		args = append(args, time.Now().UTC().Unix())
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: query decision_event: %w", err)
	}
	defer rows.Close()
	var out []DecisionEvent
	for rows.Next() {
		var e DecisionEvent
		var tsUnix, expiresAtUnix int64
		if err := rows.Scan(&e.ID, &e.UUID, &tsUnix, &e.Scope, &e.Value, &e.Type, &e.Scenario, &expiresAtUnix, &e.DurationSeconds); err != nil {
			return nil, fmt.Errorf("observability: scan decision_event: %w", err)
		}
		e.Ts = time.Unix(tsUnix, 0).UTC()
		e.ExpiresAt = time.Unix(expiresAtUnix, 0).UTC()
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate decision_event: %w", err)
	}
	return out, nil
}

// PruneDecisionEventsOlderThan deletes decision_event rows
// with ts < cutoff. Called by the retention loop on the same
// hourly cadence as the bucket and waf_event / throttle_event
// prunes.
func (s *Store) PruneDecisionEventsOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("observability: store closed")
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM decision_event WHERE ts < ?`, cutoff.UTC().Unix())
	if err != nil {
		return 0, fmt.Errorf("observability: prune decision_event: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("observability: prune decision_event rows affected: %w", err)
	}
	return n, nil
}

// DistinctDecisionSrcIPs returns the set of distinct `value`
// strings (CrowdSec's IP / CIDR / country code) seen in
// decision_event rows within [from, to). Powers the Step N.3
// extension to /security/attackers-summary that adds CrowdSec
// as a 4th union source (Q.3 had 3: waf, throttle, audit).
//
// The result is naturally bounded: even a noisy LAPI returns
// at most a few thousand distinct attackers in a 30d window.
// No further cap applied.
func (s *Store) DistinctDecisionSrcIPs(ctx context.Context, from, to time.Time) ([]string, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	q := `SELECT DISTINCT value FROM decision_event WHERE 1=1`
	args := []any{}
	if !from.IsZero() {
		q += ` AND ts >= ?`
		args = append(args, from.UTC().Unix())
	}
	if !to.IsZero() {
		q += ` AND ts < ?`
		args = append(args, to.UTC().Unix())
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("observability: distinct decision_event value: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("observability: scan distinct decision_event value: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: iterate distinct decision_event value: %w", err)
	}
	return out, nil
}

// encodeHistOrNil returns the blob for h, or nil so the driver writes
// SQL NULL.
//
// The nil case is load-bearing. Writing 68 zero bytes instead would
// make a row with no recorded distribution indistinguishable from a
// route that genuinely served nothing — the confusion this whole
// design exists to remove, reintroduced at the storage layer.
func encodeHistOrNil(h *histogram.BucketCounts) any {
	if h == nil {
		return nil
	}
	return histogram.Encode(*h)
}

// decodeHistOrNil turns a nullable blob column into an optional
// histogram.
//
// A NULL column (pre-v15 row) yields nil. A malformed blob is an
// error rather than a silent zero: it means the row was written by a
// different build or truncated, and reporting it as "served nothing"
// would be a lie the operator cannot see through.
func decodeHistOrNil(blob []byte) (*histogram.BucketCounts, error) {
	h, ok, err := histogram.Decode(blob)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	return &h, nil
}

// HistogramAggregate is a window's summed distributions for one route.
//
// Returned by AggregateHistogram, which exists because summing is the
// only valid way to combine distributions and SQLite cannot sum a
// blob. The SQL layer hands over the rows; the addition happens here,
// where histogram.BucketCounts.Add is exact.
type HistogramAggregate struct {
	// Total and TTFB are the summed distributions. Samples counts the
	// observations behind Total.
	Total histogram.BucketCounts
	TTFB  histogram.BucketCounts

	// Rows is how many bucket rows contributed, and RowsWithHistogram
	// how many of those actually carried one.
	//
	// They differ when the window straddles the v15 upgrade: rows
	// written before it have no distribution and cannot be
	// back-filled, because the data was discarded a second after it
	// was produced. The caller needs to know its answer is partial
	// rather than being handed a quantile over whatever survived.
	Rows              int
	RowsWithHistogram int

	BytesOut      int64
	HijackedCount int64
	ReqCount      int64
}

// AggregateHistogram sums one route's distributions over a window.
//
// routeID is matched exactly; pass the empty string to aggregate every
// route in the window (the system-wide view). Summation is exact and
// order-independent, so the result is identical however the rows are
// grouped — which is what makes the hourly and daily rollups lossless
// and the whole design sound.
func (s *Store) AggregateHistogram(ctx context.Context, gran Granularity, routeID string, from, to time.Time) (HistogramAggregate, error) {
	var agg HistogramAggregate
	if s == nil || s.db == nil {
		return agg, fmt.Errorf("observability: store closed")
	}

	query := `
SELECT total_hist, ttfb_hist, bytes_out, hijacked_count, req_count
FROM ` + gran.tableName() + `
WHERE ts >= ? AND ts < ?`
	args := []any{from.UTC().Unix(), to.UTC().Unix()}
	if routeID != "" {
		query += ` AND route_id = ?`
		args = append(args, routeID)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return agg, fmt.Errorf("observability: aggregate histogram: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var totalBlob, ttfbBlob []byte
		var bytesOut, hijacked, reqCount int64
		if err := rows.Scan(&totalBlob, &ttfbBlob, &bytesOut, &hijacked, &reqCount); err != nil {
			return agg, fmt.Errorf("observability: aggregate scan: %w", err)
		}
		agg.Rows++
		agg.BytesOut += bytesOut
		agg.HijackedCount += hijacked
		agg.ReqCount += reqCount

		total, err := decodeHistOrNil(totalBlob)
		if err != nil {
			return agg, fmt.Errorf("observability: aggregate total_hist: %w", err)
		}
		ttfb, err := decodeHistOrNil(ttfbBlob)
		if err != nil {
			return agg, fmt.Errorf("observability: aggregate ttfb_hist: %w", err)
		}
		if total != nil {
			agg.Total.Add(*total)
			agg.RowsWithHistogram++
		}
		if ttfb != nil {
			agg.TTFB.Add(*ttfb)
		}
	}
	if err := rows.Err(); err != nil {
		return agg, fmt.Errorf("observability: aggregate iterate: %w", err)
	}
	return agg, nil
}

// AggregateHistogramByBucket returns one MetricBucket per timestamp in
// the range, with the distributions and byte counts SUMMED across every
// route.
//
// It exists because QueryAggregated cannot do this. That query groups
// in SQL, and SQLite has no way to add two blobs — so the aggregated
// timeseries for a distribution-backed metric has to group in Go. The
// returned shape matches Query's deliberately, so the handler's
// gap-filling needs no special case.
//
// Only the histogram-backed fields are populated: TotalHist, TTFBHist,
// BytesOut, HijackedCount and ReqCount. The counter columns are left
// zero, because a caller asking for this is asking about latency or
// volume and QueryAggregated already answers the rest — filling them
// in would invite someone to read a half-populated row as complete.
//
// Summing across routes is exact here where a weighted average of
// per-route percentiles never was: the elementwise sum of two
// histograms is the histogram of the union of their samples.
func (s *Store) AggregateHistogramByBucket(ctx context.Context, gran Granularity, from, to time.Time) ([]MetricBucket, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("observability: store closed")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT ts, total_hist, ttfb_hist, bytes_out, hijacked_count, req_count
FROM `+gran.tableName()+`
WHERE ts >= ? AND ts < ?
ORDER BY ts ASC
`, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("observability: aggregate histogram by bucket: %w", err)
	}
	defer rows.Close()

	// Accumulate per ts. A map plus a slice of keys in first-seen
	// order keeps the SQL ordering without a second sort.
	type acc struct {
		total    histogram.BucketCounts
		ttfb     histogram.BucketCounts
		bytesOut int64
		hijacked int64
		reqs     int64
	}
	byTs := make(map[int64]*acc)
	order := make([]int64, 0)

	for rows.Next() {
		var tsUnix, bytesOut, hijacked, reqCount int64
		var totalBlob, ttfbBlob []byte
		if err := rows.Scan(&tsUnix, &totalBlob, &ttfbBlob, &bytesOut, &hijacked, &reqCount); err != nil {
			return nil, fmt.Errorf("observability: aggregate by bucket scan: %w", err)
		}
		a, ok := byTs[tsUnix]
		if !ok {
			a = &acc{}
			byTs[tsUnix] = a
			order = append(order, tsUnix)
		}
		a.bytesOut += bytesOut
		a.hijacked += hijacked
		a.reqs += reqCount

		total, derr := decodeHistOrNil(totalBlob)
		if derr != nil {
			return nil, fmt.Errorf("observability: aggregate by bucket total_hist (ts=%d): %w", tsUnix, derr)
		}
		ttfb, derr := decodeHistOrNil(ttfbBlob)
		if derr != nil {
			return nil, fmt.Errorf("observability: aggregate by bucket ttfb_hist (ts=%d): %w", tsUnix, derr)
		}
		if total != nil {
			a.total.Add(*total)
		}
		if ttfb != nil {
			a.ttfb.Add(*ttfb)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("observability: aggregate by bucket iterate: %w", err)
	}

	out := make([]MetricBucket, 0, len(order))
	for _, tsUnix := range order {
		a := byTs[tsUnix]
		b := MetricBucket{
			Ts:            time.Unix(tsUnix, 0).UTC(),
			ReqCount:      a.reqs,
			BytesOut:      a.bytesOut,
			HijackedCount: a.hijacked,
		}
		// nil stays nil: a bucket where no route recorded a
		// distribution has none, and an all-zero histogram would read
		// as "measured, and empty".
		if a.total.Total() > 0 {
			t := a.total
			b.TotalHist = &t
		}
		if a.ttfb.Total() > 0 {
			t := a.ttfb
			b.TTFBHist = &t
		}
		out = append(out, b)
	}
	return out, nil
}
