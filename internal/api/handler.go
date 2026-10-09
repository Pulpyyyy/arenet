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

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/certinfo"
	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/geoipupdate"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/routecheck"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/updatecheck"
)

// AlertingDispatcher (Step AL.1.b) is the seam the /test
// endpoint + the future AL.2 rule engine use to fan an
// AlertEvent out to channels. Implemented by
// *alerting.Dispatcher; declared on the API side so the
// handler tests can inject a stub without booting the
// production dispatcher wiring.
type AlertingDispatcher interface {
	Dispatch(ctx context.Context, evt alerting.AlertEvent, channelIDs []string) alerting.DispatchResult
}

// timestampFormat is RFC 3339 with millisecond precision, trailing zeros
// stripped. Matches the wire shape defined in spec §5.2.
const timestampFormat = "2006-01-02T15:04:05.999Z07:00"

// CaddyReloader is the subset of internal/caddymgr the API depends on. Defined
// here (consumer side) so tests can inject a fake without booting Caddy.
type CaddyReloader interface {
	ReloadFromStore(ctx context.Context) error
}

// MetricsReader is the read surface the /api/v1/metrics/* handlers
// depend on. Defined here (consumer side) so tests can inject a
// fake that simulates the AC #13 degraded paths — store=nil
// (boot failure) or Query returning an error (locked / corrupt
// DB at runtime).
//
// *observability.Store satisfies this interface. The API layer
// holds the interface type rather than the concrete *Store so the
// handler tolerates a nil sentinel cleanly (no nil-pointer
// dereference on method dispatch).
//
// QueryAggregated (Spec-1 §10.1) is the system-wide view: one
// MetricBucket per ts with SUM-aggregated counters and weighted
// p95 across all routes. Used by the dashboard's three timeline
// charts so they line up with the global stat cards.
type MetricsReader interface {
	Query(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error)
	QueryAggregated(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error)
	// AggregateHistogram (schema v15) sums the window's latency
	// distributions so a quantile can be computed over the whole
	// window rather than derived from per-bucket percentiles.
	// routeID == "" aggregates every route.
	AggregateHistogram(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) (observability.HistogramAggregate, error)
	// AggregateHistogramByBucket returns one row per timestamp with the
	// distributions summed across every route — the "all" sentinel's
	// timeseries for a distribution-backed metric, which
	// QueryAggregated cannot produce because SQLite cannot add blobs.
	AggregateHistogramByBucket(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error)
}

// WafEventReader is the read surface the Step M security
// handlers depend on: per-event WAF rows with optional
// filters (route, category, time range). Defined here
// (consumer side) so tests inject a fake without spinning
// up SQLite, same pattern as MetricsReader.
//
// *observability.Store satisfies this interface. A nil
// reader is the AC #13 degraded-mode case (boot-failed
// observability subsystem); handlers detect nil and return
// 200 with disabled=true rather than 500.
//
// AggregateWafEventsByRule (M.2 amendment #2) returns the
// per-(rule_id, category) aggregate over the window. Used by
// the M.4 drill-down's per-rule table. Server-side aggregation
// rather than client-side group-by on the events list — the
// latter silently truncated to the most-recent 100 events,
// which broke the spec §5.4 promise of "over the window" on
// 30d windows.
type WafEventReader interface {
	QueryWafEvents(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error)
	AggregateWafEventsByRule(ctx context.Context, filter observability.WafEventAggregateFilter) ([]observability.WafEventRuleAggregate, error)
	// AggregateWafEventsByCategory — #R-WAF-METRICS-WINDOW-
	// 1MIN-PROJECTION. Server-side GROUP BY for the per-
	// category counts on /metrics/summary. Action filter
	// lets the handler run BLOCK / DETECT as separate
	// queries so the two response maps stay independent
	// without iterating the event log.
	AggregateWafEventsByCategory(ctx context.Context, filter observability.WafEventCategoryFilter) ([]observability.WafEventCategoryAggregate, error)
	// AggregateWafEventsByRoute — follow-up to commit 579f695.
	// Server-side per-route BLOCK / DETECT counts for the
	// summary endpoint's per-route loop + grand totals.
	// Single source of truth for WAF counts (waf_event row
	// table) — bucket_1h.waf_{block,detect}_count are still
	// written by the sink but the read path bypasses them
	// to avoid the historical asymmetry where BumpWafDetects
	// was added later than BumpWafBlocks (the bucket counter
	// undercounted DETECT events before e7e2905).
	AggregateWafEventsByRoute(ctx context.Context, from, to time.Time) (map[string]observability.WafEventRouteCounts, error)
	// DistinctWafEventSrcIPs is Q.3-only — powers the WAF
	// arm of /security/attackers-summary's per-source union.
	// Returns ALL distinct src IPs in [from, to), unbounded
	// (the result is naturally small: attacker diversity in
	// a 30d window is typically <<100 on a homelab).
	DistinctWafEventSrcIPs(ctx context.Context, from, to time.Time) ([]string, error)
}

// ThrottleEventReader is the read surface the Step Q.3
// /api/v1/security/throttle-events handler depends on, plus
// the per-IP aggregation used by the attackers-summary
// endpoint + the /metrics/summary new fields. *observability.
// Store satisfies it via QueryThrottleEvents and
// AggregateThrottleEventsByIP (Q.1 storage). Interface kept
// for the same reason as WafEventReader — tests inject fakes
// without SQLite.
//
// nil reader = AC #14 degraded-mode (boot-failed
// observability subsystem); handlers detect nil and return
// 200 with disabled=true rather than 503.
type ThrottleEventReader interface {
	QueryThrottleEvents(ctx context.Context, filter observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error)
	AggregateThrottleEventsByIP(ctx context.Context, filter observability.ThrottleEventAggregateFilter) ([]observability.ThrottleEventIPAggregate, error)
	// DistinctThrottleEventSrcIPs powers the throttle arm of
	// /security/attackers-summary's per-source union. Same
	// contract as the WAF mirror on WafEventReader.
	DistinctThrottleEventSrcIPs(ctx context.Context, from, to time.Time) ([]string, error)
}

// DecisionReader is the read surface the Step N.3
// /api/v1/security/decisions handler depends on, plus the
// per-IP aggregation used by the attackers-summary endpoint
// (4th union source) + the /metrics/summary new fields
// (totalCrowdSecDecisionsPerMin, activeCrowdSecIpsUnique).
//
// *observability.Store satisfies it via QueryDecisionEvents
// (Step N.2 storage). Same nil-tolerance contract as
// WafEventReader / ThrottleEventReader — handlers detect nil
// and return 200 with disabled=true (AC #15).
//
// Decisions are sourced from the parallel
// go-cs-bouncer.StreamBouncer consumer wired in N.2; the
// caddy-crowdsec-bouncer enforces them at the proxy edge.
// Both consumers poll the same LAPI; if LAPI is unreachable
// both feeds go quiet but the reader still serves what's
// cached in metrics.db.
type DecisionReader interface {
	QueryDecisionEvents(ctx context.Context, filter observability.DecisionEventFilter) ([]observability.DecisionEvent, error)
	// DistinctDecisionSrcIPs powers the crowdsec arm of
	// /security/attackers-summary's per-source union. Same
	// contract as the WAF + throttle mirrors: the result is
	// naturally bounded (attacker diversity in a 30d window
	// stays small even with community blocklists).
	DistinctDecisionSrcIPs(ctx context.Context, from, to time.Time) ([]string, error)
}

// AuthFailureReader is the read surface the Step Q.2
// /api/v1/security/auth-failures handler depends on. The
// production implementation is a thin adapter over
// *audit.Store.QueryByActionRange — kept as an interface so
// tests can inject a fake without booting bbolt, same pattern
// as WafEventReader.
//
// Spec D2.B + D4.B: auth-failure data is derived from the
// audit log on demand. No bucket counter, no parallel sink —
// the audit table is the canonical single source of truth.
//
// A nil reader is the AC #14 boot-degraded case (boot-failed
// audit store, which is the same bbolt handle the rest of the
// app uses — so this is rare but possible if the bucket is
// missing). Handlers detect nil and return 200 with
// disabled=true, mirror of the M endpoints' degraded-mode
// contract.
type AuthFailureReader interface {
	QueryByActionRange(ctx context.Context, actions []string, from, to time.Time, limit int) ([]audit.Event, bool, error)
}

// AuditAppender is the subset of internal/audit the API depends on. Defined
// here (consumer side, decision D4) so tests can inject a fake without
// booting bbolt. *audit.Store naturally satisfies this interface.
//
// The interface exposes both Append (used by handlers post-success) and
// List (used by /audit endpoint, Commit C). The name AuditAppender is
// kept for Step C/Chunk 3 backwards compatibility despite now covering
// reads as well; a future rename to AuditStore is out of scope for Step D.
type AuditAppender interface {
	Append(ctx context.Context, evt audit.Event) error
	List(ctx context.Context, f audit.Filter) ([]audit.Event, string, error)
}

// Handler owns every dependency the admin API needs (storage, Caddy
// reload, audit, auth stores, HIBP, rate limiter, setup token) and
// exposes the HTTP handlers.
type Handler struct {
	store    *storage.Store
	caddy    CaddyReloader
	audit    AuditAppender
	users    *auth.UserStore
	sessions *auth.SessionStore
	// systemHealthChecker (Step AL.3a) runs the 5-component
	// /system/health probe. nil-tolerant: when nil, the
	// handler returns a coherent degraded response so the
	// external monitoring scrape never sees a 500. Set via
	// SetSystemHealthChecker at boot.
	systemHealthChecker SystemHealthChecker
	// systemInfo (v2.45) reports the host under Arenet — CPU,
	// memory, disk and the process itself. Injected at boot by
	// SetSystemInfoReader; nil answers an honest empty snapshot.
	systemInfo SystemInfoReader

	// updateChecker (v2.12.3) powers GET/POST /api/v1/system/version.
	// nil-tolerant: when nil (never wired, or the opt-in is off at
	// boot), the version endpoint reports enabled=false and no update.
	// Set via SetUpdateChecker.
	updateChecker updateChecker
	// version (v2.39) is the running binary's version, reported as
	// info.version of /api/v1/openapi.json. "" keeps the file's value.
	version string

	// onUpdateConfigChange (v2.12.3) is invoked after a successful
	// version-config PUT so the boot wiring can start/stop the poll
	// loop. nil-tolerant.
	onUpdateConfigChange func(storage.UpdateCheckConfig)

	// onGeoIPConfigChange (GeoIP auto-update Brick 3, Task 4) is
	// invoked after a successful GeoIP-update-config PUT so the boot
	// wiring can start/stop the scheduler loop to match the new
	// enabled/interval, mirroring onUpdateConfigChange. Wired via
	// SetGeoIPConfigHook; the PUT handler that calls this lands in
	// Task 5. nil-tolerant (tests don't wire it).
	onGeoIPConfigChange func(storage.GeoIPUpdateConfig)

	// autoBackup runs scheduled backups (v2.33); nil = endpoints
	// answer 409. onBackupScheduleChange re-applies the schedule.
	autoBackup             AutoBackupRunner
	onBackupScheduleChange func(storage.BackupScheduleConfig)

	// routeProber runs the post-apply route check (v2.35); nil =
	// skipped.
	routeProber RouteProber
	// accessLogPaths (v2.50) resolves where the access log lands,
	// applying the per-install default. nil answers the stored path.
	accessLogPaths AccessLogPathResolver

	// geoIPUpdater (Brick 3, Task 5) powers the
	// /api/v1/system/geoip/{update,status} endpoints. nil-tolerant:
	// when nil (build failed at boot, or unit tests that don't wire
	// it), POST /system/geoip/update reports 409 and GET
	// /system/geoip/status reports a zero-value snapshot. Set via
	// SetGeoIPUpdater.
	geoIPUpdater geoIPUpdater
	// asnLookup (v2.28) backs GET /geo/asn; nil = not wired.
	asnLookup asnSearcher

	// alertingDispatcher (Step AL.1.b) fans an AlertEvent
	// out to a list of channel IDs, owns the per-channel
	// MinSeverity / Enabled gates, and writes the per-send
	// outcome back via MarkAlertChannelSendResult. The
	// /test endpoint uses it as its initial producer; the
	// AL.2 rule engine will add a second producer
	// (watcher → Dispatch on rule fire). nil-tolerant: a
	// handler built without the dispatcher (tests) falls
	// back to a direct SenderFor + Send in the /test
	// endpoint so the existing handler tests don't have to
	// wire a real Dispatcher.
	alertingDispatcher AlertingDispatcher

	// alertingSources (Step AL.3b) is the Source registry
	// the rule CRUD validator reaches into to verify
	// AlertRule.Source is registered + the rule's
	// SourceParams shape is valid for that source.
	// nil-tolerant: when nil, the validator skips the
	// source-registry check (intrinsic + channel + template
	// checks still run). cmd/arenet/main.go wires the
	// production registry via SetAlertingSourceLookup; the
	// handler test env leaves it nil.
	alertingSources alerting.SourceLookup

	// apiTokens (Phase 4) is the read+validate surface for
	// service-account bearer tokens. nil-tolerant: when nil, the
	// SoftAuth middleware skips the Bearer fallback entirely
	// (matches the pre-Phase-4 surface, preserves existing
	// tests that don't wire a token store). Set via
	// SetAPITokenStore after construction. The concrete pointer
	// is kept here so the service-account endpoints (rotate,
	// revoke) can mutate the store; the middleware receives the
	// nil-safe interface view via tokenLookup().
	apiTokens   *auth.APITokenStore
	hibp        *auth.HIBPClient
	rateLimiter *auth.RateLimiter
	setupToken  *SetupTokenHolder
	// oidc (Step K.2) owns the OIDC client state — discovery
	// doc cache, verifier, oauth2 config. Built lazily on first
	// enabled-config PUT. nil-safe: a non-OIDC code path never
	// touches it.
	oidc    *OIDCManager
	devMode bool
	// adminListen (v2.42) is the admin interface's bind address, set
	// at boot via SetAdminListen and read by the TCP-service port
	// guard. Empty only costs that one guard.
	adminListen string
	// adminAllowlist restricts which client IPs reach the admin
	// interface. Set at boot via SetAdminAllowlist; nil (tests that
	// don't call it) mounts no source check.
	adminAllowlist *auth.SourceAllowlist
	logger         *slog.Logger
	// uiOrigin (Step K.2 dev) — when non-empty, the OIDC
	// callback's redirects are emitted as absolute URLs
	// against this origin (e.g. http://localhost:5173) so the
	// browser lands on the Vite dev server, not on the API.
	// Empty in prod: relative redirects resolved against the
	// API origin where the static SPA is served. Set via
	// SetUIOrigin after construction.
	uiOrigin string
	// startTime is captured at NewHandler-time and reported by the
	// /healthz endpoint as uptime_seconds (Step H.3). Read-only after
	// construction.
	startTime time.Time
	// metrics (Step L L.2) is the read surface for per-route
	// metrics history. Set via SetMetricsReader after
	// construction (same pattern as uiOrigin). nil means the
	// observability subsystem failed to open at boot (AC #13
	// degraded-mode) or that this Handler was built in a test
	// that does not exercise the /metrics endpoints — both are
	// expected; the handlers detect nil and emit the
	// "disabled" response without panicking.
	metrics MetricsReader
	// wafEvents (Step M.2) is the read surface for the
	// /api/v1/security/events endpoint + the WafBlocksByCategory
	// field on /metrics/summary. Same nil-tolerance contract as
	// `metrics` — boot-failed observability → degraded-mode
	// response, not 500.
	wafEvents WafEventReader
	// authFailures (Step Q.2) is the read surface for the
	// /api/v1/security/auth-failures endpoint. Backed by the
	// existing audit bucket (spec D2.B + D4.B: single source of
	// truth, no parallel sink). nil-tolerant in the same way as
	// `wafEvents`: a missing reader yields a disabled-mode
	// response, not 500 (AC #14).
	authFailures AuthFailureReader
	// throttleEvents (Step Q.3) is the read surface for the
	// /api/v1/security/throttle-events endpoint + the per-IP
	// aggregation behind /security/attackers-summary +
	// /metrics/summary's totalThrottlePerMin /
	// attackerIpsUnique. Backed by *observability.Store. Same
	// nil-tolerance contract as wafEvents.
	throttleEvents ThrottleEventReader
	// decisions (Step N.3) is the read surface for the
	// /api/v1/security/decisions endpoint + the crowdsec arm
	// of /security/attackers-summary + /metrics/summary's
	// totalCrowdSecDecisionsPerMin / activeCrowdSecIpsUnique.
	// Backed by *observability.Store (decision_event table
	// from N.2 storage). Same nil-tolerance contract as
	// throttleEvents.
	decisions DecisionReader
	// crowdsecApplier (Step CS.1) is the manager-side seam
	// invoked by PUT /api/v1/settings/crowdsec to swap the
	// bouncer LAPI creds + hot-reload Caddy without a process
	// restart. nil → the PUT handler still persists the row
	// + emits audit, but skips the reload (suitable for unit
	// tests that don't boot Caddy). *caddymgr.CaddyManager
	// satisfies CrowdSecApplier via ApplyCrowdSecConfig.
	crowdsecApplier CrowdSecApplier
	// crowdsecJWT (Step CS.2.C) caches the LAPI machine-
	// auth JWT used by the Scenarios tab's /v1/alerts proxy.
	// Always non-nil after NewHandler; singleflight-deduped
	// concurrent logins; lazy-invalidates on 401. See
	// crowdsec_scenarios.go for the rationale.
	crowdsecJWT *crowdSecJWTManager
	// hcStatus (Critique 11 Pack A, 2026-06-05) is the per-
	// upstream live status feed populated by the Stage B
	// caddyhc tracker. Used by listRoutes / getRoute to attach
	// an aggregateStatus to each route's response so the Routes
	// page can paint honest health badges. Same nil-tolerance
	// contract as the other readers: a nil hcStatus collapses
	// the aggregate to "unknown" without erroring.
	hcStatus HCStatusReader
	// certInfo (Step T T.1, 2026-06-05) is the per-domain
	// runtime cert metadata feed populated by internal/certinfo.
	// Backs GET /api/certificates. Same nil-tolerance contract
	// as hcStatus: a nil certInfo returns an empty list (not
	// an error) so the Certificates page renders the "no data
	// yet" empty state rather than 500ing.
	certInfo CertInfoReader
	// certStorageDir is the certmagic storage root
	// (caddy.AppDataDir()); the cert-delete handler needs it to
	// remove on-disk cert material. Empty until SetCertStorageDir.
	certStorageDir string
	// certEvents (Step U.3, 2026-06-06) is the cert_event
	// table read surface. Backs GET /api/v1/observability/
	// cert-events — the Activity log page's cert source.
	// Backed by *observability.Store (cert_event table from
	// U.1 storage); the U.2 sink writes the rows the U.3
	// handler reads. Nil-tolerant per AC #13 of Step T (the
	// degraded-mode contract carried forward): a nil
	// certEvents collapses the response to {events: [],
	// total: 0, hasMore: false, degraded: true} rather than
	// returning 5xx.
	certEvents CertEventReader
	// alertEvents (Step AL.4.a) is the alert_event table
	// read surface. Backs GET /api/v1/observability/
	// alert-events — the AL.4 Alerting page History tab.
	// Backed by *observability.Store; the AL.4.a
	// dispatcher sink writes the rows this handler reads.
	// Nil-tolerant per AC #13: a nil reader collapses the
	// response to {events:[], nextCursor:"", degraded:true}
	// rather than 5xx so the History tab renders the
	// "observability unavailable" empty state.
	alertEvents AlertEventReader
	// countryBlockEvents (Step W.5) is the
	// country_block_event table read surface. Backs GET
	// /api/v1/observability/country-block-events — the
	// Activity log page's country-block source. Backed by
	// *observability.Store (country_block_event table from
	// W.4 schema v8); the W.4 sink writes the rows the W.5
	// handler reads. Nil-tolerant per AC #13: a nil reader
	// collapses the response to {events:[], degraded:true}
	// rather than 5xx.
	countryBlockEvents CountryBlockEventReader
	// rateLimitEvents (Step Z.1) is the rate_limit_event
	// table read surface. Backs GET /api/v1/security/
	// rate-limit-events — the Activity log + dashboard 429
	// counter. Backed by *observability.Store
	// (rate_limit_event table from Z.1 schema v11); the Z.1
	// sink writes the rows this handler reads. Nil-tolerant
	// per AC #13: a nil reader collapses the response to
	// {events:[], degraded:true} rather than 5xx.
	rateLimitEvents RateLimitEventReader
	// authSink (Step V.2, 2026-06-06) is the parallel fan-out
	// sink that receives auth-failure events alongside the
	// existing audit-bucket Append (spec §3.6). The audit log
	// keeps the canonical record; this sink is the real-time
	// stream the V.3 geo bus consumes.
	//
	// Nil-tolerant: a nil sink makes the appendAudit fan-out
	// path a no-op so the auth-failure response is never
	// blocked by degraded observability. Set via
	// SetAuthEventSink after construction; cmd/arenet logs
	// present=<bool> at boot per the HF4 pattern.
	authSink AuthEventSubmitter
	// geoBus (Step V.3, 2026-06-06) is the in-memory event
	// bus + ring buffer (N=500 per spec §3.5) that backs both
	// the WS /api/v1/ws/geo-events live push and the GET
	// /api/v1/observability/geo-events replay endpoint.
	//
	// Nil-tolerant per the AC #13 degraded contract: a nil
	// bus collapses the GET endpoint to {events:[], total:0,
	// degraded:true} and rejects the WS upgrade by returning
	// the same degraded envelope on a one-shot HTTP response.
	geoBus GeoEventReader
	// geoIPDegraded (Step V.3, 2026-06-06) is set at boot
	// when the GeoIP MMDB is absent (V.1's nil Lookup case).
	// Surfaces on the geo-events response as the `degraded`
	// flag so the frontend can render the "GeoIP not
	// configured" banner even when events are still flowing.
	geoIPDegraded bool
	// geoLookup (Step Z.5.3) is the on-demand MMDB lookup
	// surface used by the /api/v1/geo/lookup-batch endpoint
	// to enrich /logs SOURCE IP rendering with a country
	// code suffix ("82.65.x.x · FR"). Distinct from geoBus
	// (event stream) and serverPosition (single-IP self
	// lookup) — this one is per-request enrichment for the
	// activity log.
	//
	// Nil-tolerant per AC #13 : a nil lookup collapses the
	// endpoint to {results: {ip: ""}} for every IP so the
	// frontend keeps rendering the raw IP without country
	// suffix instead of crashing.
	geoLookup GeoIPLookup
	// serverPositionStore (Step V.4, 2026-06-07) is the
	// persistence seam for GET / PUT / POST :redetect on
	// /api/v1/observability/server-position. Backed by
	// *storage.Store in production; tests substitute a stub
	// via SetServerPositionStore. Nil-tolerant per AC #13.
	serverPositionStore ServerPositionStore
	// serverPositionRedetector (Step V.4, 2026-06-07) is
	// the seam the POST :redetect handler uses to re-run
	// V.1's ipify-then-GeoIP path without taking a hard
	// dependency on internal/geo at this package boundary.
	// Production wires a closure around geo.DetectFromPublicIP
	// in cmd/arenet/main.go.
	serverPositionRedetector ServerPositionRedetector
	// bootDetectedPosition (Step V.4, 2026-06-07) is the
	// V.1 auto-detect result captured at boot. Used as the
	// fallback when the persistence store has no row (fresh
	// install) AND the operator has not landed on a manual
	// override yet. Read-only after construction.
	bootDetectedPosition *geo.ServerPosition
}

// AuthEventSubmitter is the seam internal/api/audit_helpers.go
// uses to fan auth failures (401/403 audit actions) into the
// new auth_event sink (Step V.2). Implemented by
// *observability.AuthEventSink; declared here so this package
// does not import internal/observability for a one-method
// dependency (mirror of the CertEventReader pattern). The
// Submit method is non-blocking + nil-receiver-safe at the
// implementation; the audit_helpers caller adds an
// extra nil-check on the field for clarity.
type AuthEventSubmitter interface {
	Submit(e observability.AuthEvent)
}

// HCStatusReader is the read interface the Routes page uses to
// derive per-route aggregate health from per-upstream tracker
// state. Implemented by *caddyhc.HCStatusTracker, but declared
// locally so this package doesn't import caddyhc (the topology
// builder already uses the same minimal-interface pattern via
// its own StatusLookup).
//
// Returns "healthy" / "unhealthy" / "" (empty == unknown / not
// yet observed) for any given normalized upstream address. The
// aggregation logic in computeRouteAggregateHealth maps "" and
// any unrecognised value to the unknown state.
type HCStatusReader interface {
	Status(addr string) string
}

// CertInfoReader is the seam the Certificates page uses to surface
// per-domain runtime cert metadata. Implemented by *certinfo.Tracker.
//
// List() returns a freshly-allocated snapshot sorted by NotAfter
// ascending (closest-to-expiry first); the API layer passes the
// slice through verbatim.
//
// Remove(domain) is a mutating hook the DELETE managed-domain
// handler uses to purge ghost entries after a successful caddy
// reload. Necessary because certmagic / Caddy v2.11.3 emit no
// cert-removal event (verified empirically). Returns true when an
// entry was actually present so the caller can log meaningful
// counts. The "Reader" name is preserved despite the mutating
// method to avoid churn across the existing hookup (SetCertInfoReader,
// h.certInfo field) — the certinfo seam is one logical capability,
// not two.
//
// Unlike HCStatusReader (declared without importing caddyhc to
// avoid pulling Caddy module weight into the API package), this
// interface returns the concrete certinfo.CertRuntimeInfo
// pointer. certinfo is a pure types + state package with no
// Caddy registration footprint at the type level — importing it
// here costs nothing and gives the GET /api/certificates handler
// compile-time JSON-shape guarantees.
type CertInfoReader interface {
	List() []*certinfo.CertRuntimeInfo
	Remove(domain string) bool
}

// CertEventReader is the read surface the Step U.3 Activity
// log endpoint depends on. *observability.Store satisfies it
// via QueryCertEvents + CountCertEvents (U.1 storage shipped
// the QueryCertEvents primitive in commit 05fea9f; U.3 added
// CountCertEvents for the response's `total` + `hasMore`
// envelope).
//
// Same minimal-interface pattern as the WAF / throttle /
// decision readers above — kept narrow so tests can inject a
// fake without booting SQLite. Same nil-tolerance contract as
// the others (AC #13 degraded mode of Step T carried forward):
// handlers detect nil and return 200 with degraded=true rather
// than 5xx, so an observability boot failure doesn't take down
// the Activity log page.
type CertEventReader interface {
	QueryCertEvents(ctx context.Context, filter observability.CertEventFilter) ([]observability.CertEvent, error)
	CountCertEvents(ctx context.Context, filter observability.CertEventFilter) (int64, error)
	// AggregateCertEvents (Phase 5) groups cert_event rows by
	// time bucket within a window. Powers the dashboard's cert
	// lifecycle panel + the Phase 6 alerting rule evaluator.
	// Same nil-tolerance contract — handlers detect nil and
	// return degraded mode rather than 5xx.
	AggregateCertEvents(ctx context.Context, filter observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error)
}

// AlertEventReader is the read surface the Step AL.4.a
// History tab endpoint depends on. *observability.Store
// satisfies it via QueryAlertEvents (alert_event table
// from the AL.1.a v9→v10 schema; the AL.4.a dispatcher
// sink writes the rows). Same minimal-interface +
// nil-tolerance contract as CertEventReader.
type AlertEventReader interface {
	QueryAlertEvents(ctx context.Context, filter observability.AlertEventFilter) ([]observability.AlertEvent, string, error)
}

// NewHandler constructs a Handler. All non-bool arguments must be non-nil.
func NewHandler(
	store *storage.Store,
	caddy CaddyReloader,
	auditAppender AuditAppender,
	users *auth.UserStore,
	sessions *auth.SessionStore,
	hibp *auth.HIBPClient,
	rateLimiter *auth.RateLimiter,
	setupToken *SetupTokenHolder,
	devMode bool,
	logger *slog.Logger,
) *Handler {
	switch {
	case store == nil:
		panic("api.NewHandler: store is nil")
	case caddy == nil:
		panic("api.NewHandler: caddy is nil")
	case auditAppender == nil:
		panic("api.NewHandler: audit is nil")
	case users == nil:
		panic("api.NewHandler: users is nil")
	case sessions == nil:
		panic("api.NewHandler: sessions is nil")
	case hibp == nil:
		panic("api.NewHandler: hibp is nil")
	case rateLimiter == nil:
		panic("api.NewHandler: rateLimiter is nil")
	case setupToken == nil:
		panic("api.NewHandler: setupToken is nil")
	case logger == nil:
		panic("api.NewHandler: logger is nil")
	}
	return &Handler{
		store:       store,
		caddy:       caddy,
		audit:       auditAppender,
		users:       users,
		sessions:    sessions,
		hibp:        hibp,
		rateLimiter: rateLimiter,
		setupToken:  setupToken,
		// Step K.2 — always present; the OIDC handlers tolerate a
		// "never built" state (lazy build on first enabled-config
		// PUT or first login initiate). Tests that don't exercise
		// the OIDC flow leave this untouched; no nil checks needed
		// at the call sites.
		oidc:      NewOIDCManager(),
		devMode:   devMode,
		logger:    logger,
		startTime: time.Now(),
		// Step CS.2.C — always present; the JWT cache
		// tolerates a "never logged in" state. Cold-start
		// boot does not touch LAPI; the first Scenarios
		// poll triggers the initial login.
		crowdsecJWT: newCrowdSecJWTManager(),
	}
}

// SetUIOrigin (Step K.2 dev) configures the SPA origin to use
// for the OIDC callback redirects. Empty (default) keeps
// relative redirects, suitable for production where the static
// SPA is served by Arenet at the same origin as the API.
// Non-empty (e.g. "http://localhost:5173") prefixes every
// callback redirect so the browser lands on the dev server.
// Trailing slashes are stripped; the value is used as-is for
// concatenation with "/routes" / "/login?error=...".
//
// Intentionally a setter (not a NewHandler arg) so the existing
// test scaffolding stays signature-compatible.
func (h *Handler) SetUIOrigin(origin string) {
	h.uiOrigin = strings.TrimRight(strings.TrimSpace(origin), "/")
}

// SetSystemHealthChecker (Step AL.3a) attaches the
// /system/health probe runner. Pass nil to leave the
// endpoint wired but degraded — the handler returns a
// coherent JSON shape regardless.
func (h *Handler) SetSystemHealthChecker(s SystemHealthChecker) {
	h.systemHealthChecker = s
}

// updateChecker is the seam the version endpoint reads through.
// *updatecheck.Checker satisfies it; tests can supply a fake.
type updateChecker interface {
	Status() updatecheck.Status
	Check(ctx context.Context) updatecheck.Status
}

// SetVersion (v2.39) records the running binary's version for the
// OpenAPI document.
func (h *Handler) SetVersion(v string) {
	h.version = v
}

// SetUpdateChecker (v2.12.3) attaches the update checker. Pass nil to
// leave the version endpoint in its enabled=false / no-update state
// (handler tests that don't exercise the checker).
func (h *Handler) SetUpdateChecker(c updateChecker) {
	h.updateChecker = c
}

// SetAdminListen records the address the admin interface is bound to
// (v2.42). The TCP-service port guard needs it: a relay must not be
// allowed to take the port the operator manages Arenet through.
func (h *Handler) SetAdminListen(addr string) {
	h.adminListen = addr
}

// SetAdminAllowlist installs the admin source allowlist. Must be called
// before NewRouter, which mounts the check only when one is set.
func (h *Handler) SetAdminAllowlist(al *auth.SourceAllowlist) {
	h.adminAllowlist = al
}

// reservedTCPPorts is what a TCP service may not listen on.
func (h *Handler) reservedTCPPorts() map[int]string {
	return caddymgr.ReservedTCPPortsFor(h.devMode, h.adminListen)
}

// SetUpdateConfigHook (v2.12.3) registers a callback invoked after the
// version-config PUT persists, so main can start/stop the poll loop to
// match the new enabled/interval. nil-tolerant (tests don't wire it).
func (h *Handler) SetUpdateConfigHook(fn func(storage.UpdateCheckConfig)) {
	h.onUpdateConfigChange = fn
}

// geoIPUpdater is the seam the GeoIP update endpoints read/drive through.
// *geoipupdate.Updater satisfies it; tests can supply a fake.
type geoIPUpdater interface {
	UpdateOnce(ctx context.Context) geoipupdate.UpdateResult
	Status() geoipupdate.UpdateResult
}

// SetGeoIPUpdater (Brick 3, Task 5) attaches the GeoIP updater. Pass nil
// to leave POST /system/geoip/update reporting 409 and GET
// /system/geoip/status reporting a zero-value snapshot (handler tests
// that don't exercise the updater).
func (h *Handler) SetGeoIPUpdater(u geoIPUpdater) {
	h.geoIPUpdater = u
}

// SetASNLookup (v2.28) attaches the GeoLite2-ASN lookup used by
// GET /geo/asn. nil-tolerant: the endpoint then reports loaded=false.
func (h *Handler) SetASNLookup(l asnSearcher) {
	h.asnLookup = l
}

// SetGeoIPConfigHook (GeoIP auto-update Brick 3, Task 4) registers a
// callback invoked after a GeoIP-update-config PUT persists, so main
// can start/stop the scheduler loop to match the new enabled/interval.
// nil-tolerant (tests don't wire it). Mirrors SetUpdateConfigHook; the
// PUT endpoint that calls onGeoIPConfigChange is added in Task 5.
func (h *Handler) SetGeoIPConfigHook(fn func(storage.GeoIPUpdateConfig)) {
	h.onGeoIPConfigChange = fn
}

// SetAlertingDispatcher (Step AL.1.b) attaches the
// per-channel fan-out dispatcher used by the /test
// endpoint. Pass nil to fall back to the legacy direct-
// SenderFor path (used by handler tests that don't wire
// a real dispatcher).
func (h *Handler) SetAlertingDispatcher(d AlertingDispatcher) {
	h.alertingDispatcher = d
}

// SetAlertingSourceLookup (Step AL.3b) attaches the
// Source registry the rule CRUD validator uses to
// confirm a rule's Source name is registered + the
// rule's SourceParams shape is accepted by that source.
// Pass nil to skip the source-side check (handler tests
// that don't wire a registry).
func (h *Handler) SetAlertingSourceLookup(s alerting.SourceLookup) {
	h.alertingSources = s
}

// SetAPITokenStore (Phase 4) attaches the service-account API
// token store. nil-tolerant: when not called or called with nil,
// SoftAuth's Bearer fallback path is skipped (matches the
// pre-Phase-4 surface for tests that don't wire tokens).
func (h *Handler) SetAPITokenStore(t *auth.APITokenStore) {
	h.apiTokens = t
}

// tokenLookup returns the SoftAuth-facing interface view of the
// API-token store, or a typed-nil-safe interface nil when no
// store has been attached. The explicit nil-return prevents the
// classic Go pitfall where assigning a nil *T to an interface
// variable produces a non-nil interface that compares != nil
// even though the underlying value is nil.
func (h *Handler) tokenLookup() auth.APITokenLookup {
	if h.apiTokens == nil {
		return nil
	}
	return h.apiTokens
}

// SetMetricsReader (Step L L.2) attaches the per-route metrics
// history reader. Pass nil if observability boot failed — the
// /api/v1/metrics/* endpoints will return the "disabled"
// response cleanly rather than crashing (AC #13 degraded-mode
// API half).
//
// Intentionally a setter (not a NewHandler arg) so the existing
// test scaffolding stays signature-compatible — same convention
// as SetUIOrigin.
func (h *Handler) SetMetricsReader(m MetricsReader) {
	h.metrics = m
}

// SetWafEventReader (Step M.2) attaches the WAF event reader
// used by /api/v1/security/events + the WafBlocksByCategory
// field of /metrics/summary. Same nil-tolerance contract as
// SetMetricsReader: pass nil if observability boot failed; the
// security endpoints will return disabled-mode responses.
func (h *Handler) SetWafEventReader(r WafEventReader) {
	h.wafEvents = r
}

// SetAuthFailureReader (Step Q.2) attaches the auth-failure
// reader used by /api/v1/security/auth-failures. The reader
// is backed by the audit bucket (spec D2.B + D4.B). Same
// nil-tolerance contract as SetWafEventReader: pass nil to
// keep the endpoint in disabled-mode (AC #14).
//
// Note: this reader is conceptually independent of the
// AuditAppender already on the handler — they share the
// same underlying bbolt store in production, but the API
// surface stays narrow on purpose (the auth-failures
// handler only needs the range-scan path, not Append).
func (h *Handler) SetAuthFailureReader(r AuthFailureReader) {
	h.authFailures = r
}

// SetThrottleEventReader (Step Q.3) attaches the throttle
// event reader used by /api/v1/security/throttle-events,
// /security/attackers-summary, and the new /metrics/summary
// fields. Same nil-tolerance contract as SetWafEventReader.
func (h *Handler) SetThrottleEventReader(r ThrottleEventReader) {
	h.throttleEvents = r
}

// SetHCStatusReader (Critique 11 Pack A, 2026-06-05) attaches
// the per-upstream HC status feed used by listRoutes / getRoute
// to compute aggregateStatus on each route's wire response. Pass
// the *caddyhc.HCStatusTracker singleton that cmd/arenet already
// constructs before mgr.Start; the topology builder consumes the
// same tracker via its own minimal interface, so this is the
// existing Stage B source of truth being shared with a second
// HTTP consumer.
//
// Nil-tolerant: leaving this unset (or passing nil) collapses
// every aggregateStatus to "unknown", which matches the
// pre-Pack-A behaviour and the C13 honest-absence semantics for
// routes without HC configured.
func (h *Handler) SetHCStatusReader(r HCStatusReader) {
	h.hcStatus = r
}

// SetCertInfoReader (Step T T.1, 2026-06-05) attaches the
// per-domain runtime cert metadata feed used by
// GET /api/certificates. Pass the *certinfo.Tracker singleton
// that cmd/arenet constructs and seeds via ReconcileFromDisk
// before mgr.Start.
//
// Nil-tolerant: leaving this unset (or passing nil) makes the
// endpoint respond with an empty list rather than 500ing —
// matches the AC #13 degraded-mode convention used by the
// metrics + security readers above.
func (h *Handler) SetCertInfoReader(r CertInfoReader) {
	h.certInfo = r
}

// SetCertStorageDir attaches the certmagic storage root so the
// cert-delete handler can remove on-disk material. Wired once at
// boot from main.go's certStorageDir (caddy.AppDataDir()).
func (h *Handler) SetCertStorageDir(dir string) {
	h.certStorageDir = dir
}

// HasCertInfoPurger reports whether the cert-info seam is wired
// AND satisfies the post-T.5 purge contract (CertInfoReader was
// widened with Remove() in the e4177e4 hotfix).
//
// cmd/arenet calls this after SetCertInfoReader and logs the
// result at boot so any future wire-up regression — e.g. the
// setter is removed in a refactor, or a reader implementation
// drops the Remove method — is immediately visible in journalctl
// instead of silently no-opping the DELETE managed-domain purge
// path. The 2026-06-05 post-deploy investigation that revealed
// the gap is the reason this exists.
//
// Returns false if the certInfo field is nil (degraded mode
// or boot ordering bug); returns true otherwise. The interface
// guarantees Remove is callable when non-nil — there's no
// halfway state to surface.
func (h *Handler) HasCertInfoPurger() bool {
	return h.certInfo != nil
}

// SetCertEventReader (Step U.3, 2026-06-06) attaches the
// cert_event table reader used by GET /api/v1/observability/
// cert-events. Pass the *observability.Store the U.1 sink
// writes into; same store that backs the existing WAF /
// throttle / decision endpoints.
//
// Nil-tolerant per AC #13: leaving this unset (or passing nil)
// makes the endpoint respond with the degraded envelope
// (empty events, total=0, hasMore=false, degraded=true) rather
// than 500ing — same convention every other observability
// reader honors.
func (h *Handler) SetCertEventReader(r CertEventReader) {
	h.certEvents = r
}

// SetAlertEventReader (Step AL.4.a) attaches the
// alert_event table reader used by GET /api/v1/
// observability/alert-events. Pass the *observability.
// Store the AL.4.a dispatcher sink writes into.
//
// nil-tolerant per AC #13: leaving this unset (or
// passing nil) makes the endpoint respond with the
// degraded envelope ({events:[], nextCursor:"",
// degraded:true}) rather than 500ing.
func (h *Handler) SetAlertEventReader(r AlertEventReader) {
	h.alertEvents = r
}

// HasCertEventReader reports whether the cert-event seam is
// wired. cmd/arenet calls this after SetCertEventReader and
// logs the result at boot so any future wire-up regression
// surfaces as reader_present=false in journalctl instead of
// silent degradation. Generalizes the HF4 purger_present
// pattern (commit 30418ea + backlog #R-API-boot-log-audit).
func (h *Handler) HasCertEventReader() bool {
	return h.certEvents != nil
}

// SetCountryBlockEventReader (Step W.5) attaches the
// country_block_event table reader used by
// GET /api/v1/observability/country-block-events. Pass
// the *observability.Store the W.4 sink writes into;
// same store that backs the WAF / throttle / decision /
// cert / auth readers.
//
// Nil-tolerant per AC #13: leaving this unset makes the
// endpoint respond with the degraded envelope.
func (h *Handler) SetCountryBlockEventReader(r CountryBlockEventReader) {
	h.countryBlockEvents = r
}

// HasCountryBlockEventReader reports whether the
// country-block events seam is wired. cmd/arenet calls
// this at boot so any future wire-up regression surfaces
// as reader_present=false in journalctl.
func (h *Handler) HasCountryBlockEventReader() bool {
	return h.countryBlockEvents != nil
}

// SetRateLimitEventReader (Step Z.1) attaches the
// rate_limit_event table reader used by GET
// /api/v1/security/rate-limit-events. Pass the
// *observability.Store the Z.1 sink writes into ; same
// store that backs the WAF / throttle / decision / cert /
// auth / country-block readers.
//
// Nil-tolerant per AC #13 : leaving this unset makes the
// endpoint respond with the degraded envelope.
func (h *Handler) SetRateLimitEventReader(r RateLimitEventReader) {
	h.rateLimitEvents = r
}

// HasRateLimitEventReader reports whether the rate-limit
// events seam is wired. cmd/arenet calls this at boot so
// any future wire-up regression surfaces as
// reader_present=false in journalctl.
func (h *Handler) HasRateLimitEventReader() bool {
	return h.rateLimitEvents != nil
}

// SetAuthEventSink (Step V.2, 2026-06-06) attaches the auth
// failure sink the appendAudit helper fan-outs to alongside
// the canonical audit-bucket Append. The audit log keeps the
// canonical record per Step Q D2.B; this sink is the real-
// time stream the V.3 geo bus consumes.
//
// Nil-tolerant: a nil sink leaves the fan-out path as a
// no-op so degraded observability never breaks the 401/403
// response. Same convention every other observability seam
// honors.
func (h *Handler) SetAuthEventSink(s AuthEventSubmitter) {
	h.authSink = s
}

// HasAuthEventSink reports whether the auth-event fan-out
// seam is wired. cmd/arenet calls this after
// SetAuthEventSink and logs sink_present=<bool> per the HF4
// boot-log pattern (commit 30418ea) so any future wire-up
// regression surfaces in journalctl.
func (h *Handler) HasAuthEventSink() bool {
	return h.authSink != nil
}

// SetGeoBus (Step V.3, 2026-06-06) attaches the geo event
// bus the WS broadcaster + GET replay handler read from.
// Pass the *geo.Bus the V.3 wiring constructs in main.go.
// Nil-tolerant per AC #13: leaving this unset (or passing
// nil) collapses the GET endpoint to the degraded envelope
// and disables the WS broadcaster.
func (h *Handler) SetGeoBus(b GeoEventReader) {
	h.geoBus = b
}

// HasGeoBus reports whether the geo-event seam is wired.
// cmd/arenet calls this after SetGeoBus and logs
// bus_present=<bool> at boot per the HF4 pattern.
func (h *Handler) HasGeoBus() bool {
	return h.geoBus != nil
}

// SetGeoIPDegraded (Step V.3, 2026-06-06) marks whether the
// GeoIP MMDB lookup is degraded (V.1's nil Lookup case).
// Surfaces on the GET /geo-events response so the frontend
// knows lat/lon/country are sentinel values even when events
// are flowing. Called once at boot.
func (h *Handler) SetGeoIPDegraded(degraded bool) {
	h.geoIPDegraded = degraded
}

// SetGeoLookup (Step Z.5.3) attaches the on-demand MMDB
// lookup used by POST /api/v1/geo/lookup-batch to enrich
// /logs SOURCE IP rendering with country codes. The
// production type is *geo.Lookup ; tests can substitute a
// fake by implementing the narrow GeoIPLookup interface.
//
// Nil-tolerant per AC #13 : leaving this unset makes the
// endpoint return {results:{ip:""}} for every IP so the
// frontend keeps rendering the raw IP cleanly.
func (h *Handler) SetGeoLookup(l GeoIPLookup) {
	h.geoLookup = l
}

// HasGeoLookup reports whether the geo-lookup seam is
// wired. cmd/arenet calls this at boot so any future wire-
// up regression surfaces as lookup_present=false in
// journalctl rather than silent country-suffix degradation
// on the /logs page.
func (h *Handler) HasGeoLookup() bool {
	// geoLookup is now always non-nil (a degraded &geo.Lookup{} when no
	// DB is present), so check Loaded() for a real DB, not just non-nil.
	return h.geoLookup != nil && h.geoLookup.Loaded()
}

// SetServerPositionStore (Step V.4, 2026-06-07) attaches
// the BoltDB-backed persistence the position GET / PUT
// handlers read + write. Nil-tolerant: a nil store
// collapses GET to the boot-auto-detect fallback (or
// degraded shape) and rejects PUT / POST :redetect with
// 503.
func (h *Handler) SetServerPositionStore(s ServerPositionStore) {
	h.serverPositionStore = s
}

// SetServerPositionRedetector (Step V.4, 2026-06-07)
// attaches the redetect seam — typically a closure around
// geo.DetectFromPublicIP captured in cmd/arenet/main.go.
// Nil-tolerant: a nil redetector returns 503 for the POST
// :redetect endpoint while leaving GET / PUT unaffected.
func (h *Handler) SetServerPositionRedetector(r ServerPositionRedetector) {
	h.serverPositionRedetector = r
}

// SetBootDetectedPosition (Step V.4, 2026-06-07) installs
// the V.1 auto-detect result captured at boot. Used by GET
// as the second-best source when no persisted row exists.
// nil is acceptable (fresh install + no network at boot).
func (h *Handler) SetBootDetectedPosition(p *geo.ServerPosition) {
	h.bootDetectedPosition = p
}

// HasServerPositionStore reports whether the position
// persistence seam is wired. cmd/arenet logs the result at
// boot per the HF4 pattern (commit 30418ea).
func (h *Handler) HasServerPositionStore() bool {
	return h.serverPositionStore != nil
}

// HasServerPositionRedetector reports whether the redetect
// seam is wired. cmd/arenet logs this at boot so a missing
// wire-up surfaces in journalctl.
func (h *Handler) HasServerPositionRedetector() bool {
	return h.serverPositionRedetector != nil
}

// SetDecisionReader (Step N.3) attaches the CrowdSec
// decision reader used by /api/v1/security/decisions, the
// 4th-source arm of /security/attackers-summary, and the new
// /metrics/summary fields (totalCrowdSecDecisionsPerMin,
// activeCrowdSecIpsUnique). Same nil-tolerance contract as
// SetThrottleEventReader.
func (h *Handler) SetDecisionReader(r DecisionReader) {
	h.decisions = r
}

// SetCrowdSecApplier (Step CS.1) attaches the manager-side
// hot-reload seam invoked by PUT /api/v1/settings/crowdsec.
// *caddymgr.CaddyManager satisfies this interface via
// ApplyCrowdSecConfig. Nil-tolerant: tests that don't exercise
// the manager leave this unset and the PUT handler skips the
// reload (the row is still persisted; audit still emits).
func (h *Handler) SetCrowdSecApplier(a CrowdSecApplier) {
	h.crowdsecApplier = a
}

// uiURL returns the URL to redirect to for the given SPA path
// (must start with "/"). If uiOrigin is empty, path is returned
// as-is (relative). Otherwise the origin is prefixed.
func (h *Handler) uiURL(path string) string {
	if h.uiOrigin == "" {
		return path
	}
	return h.uiOrigin + path
}

// upstreamReq is the per-element wire shape inside the routeRequest
// upstreams pool. Mirrors storage.Upstream verbatim (URL + Weight)
// but lives in the api package so the wire layer is decoupled from
// the storage struct — pattern Step I established for routeRequest
// vs storage.Route. createRoute / updateRoute map upstreamReq slices
// to storage.Upstream slices before validation; the API materialises
// Weight=0 → 1 in that mapping (§5.1, §1.3 decision 1).
type upstreamReq struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// basicAuthReq is the Step K.1 wire shape for per-route Basic
// Auth on the request side. Password is the PLAIN text on the
// wire — write-only (the response never echoes it; the storage
// hash is derived from it via auth.HashRoutePassword); Username
// round-trips normally.
//
// Active iff routeRequest.AuthMode == "basic". When the parent's
// AuthMode is "none" or "forward_auth", BasicAuth fields are
// ignored by createRoute / updateRoute (the API validates this
// mutual exclusivity at the §1.3 decision 2 boundary).
//
// Preserve-on-edit: Password empty on PUT keeps the existing
// hash — same UX as Step I.5 + Step J.4 secrets.
type basicAuthReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// forwardAuthReq is the Step K.1 wire shape for per-route
// forward-auth on the request side. Carries the reference to one
// of the instance-level providers (the providers themselves are
// CRUD'd via /api/v1/settings/forward-auth/providers).
//
// Active iff routeRequest.AuthMode == "forward_auth". Empty
// ProviderName on PUT preserves the previously stored
// reference; mutually-exclusive with the basic auth fields.
type forwardAuthReq struct {
	ProviderName string `json:"providerName"`
}

// ipFilterReq is the camelCase wire mirror of storage.IPFilter
// (v1 path-based-rules). storage uses snake_case tags for BoltDB,
// so the API layer keeps its own mirror type + mapper — same
// pattern as countryBlockReq / rateLimitReq. Used both as
// routeRequest.IPFilter (whole-domain gate) and inside
// pathRuleReq.IPFilter (per-sub-path gate).
type ipFilterReq struct {
	Mode       string   `json:"mode"`
	CIDRs      []string `json:"cidrs,omitempty"`
	StatusCode int      `json:"statusCode,omitempty"`
}

// toStorage maps the wire shape to storage.IPFilter verbatim.
func (r ipFilterReq) toStorage() storage.IPFilter {
	return storage.IPFilter{Mode: r.Mode, CIDRs: r.CIDRs, StatusCode: r.StatusCode}
}

// mapIPFilterReq nil-safely maps a *ipFilterReq to *storage.IPFilter.
// nil in (field absent from JSON) → nil out, so createRoute /
// updateRoute never manufacture a spurious zero-value gate.
func mapIPFilterReq(r *ipFilterReq) *storage.IPFilter {
	if r == nil {
		return nil
	}
	f := r.toStorage()
	return &f
}

// pathRuleBasicAuthReq is the camelCase wire shape for a
// path-rule's Basic Auth sub-block. Mirrors routeRequest's
// basicAuthReq: Password is the PLAIN text on the wire —
// write-only (the response never echoes it; the storage hash is
// derived from it via auth.HashRoutePassword, same as
// route-level Basic Auth). Username round-trips normally.
//
// Preserve-on-edit: Password empty on PUT keeps the existing
// hash for that PathPrefix — same UX as route-level BasicAuth
// (Step I.5 / K.1), see mapPathRuleReqs.
type pathRuleBasicAuthReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// pathRuleReq is the camelCase wire mirror of storage.PathRule.
type pathRuleReq struct {
	PathPrefix string                `json:"pathPrefix"`
	BasicAuth  *pathRuleBasicAuthReq `json:"basicAuth,omitempty"`
	IPFilter   *ipFilterReq          `json:"ipFilter,omitempty"`
	// Per-path upstream routing (v2.23.0). Empty Upstreams = inherit the
	// route's pool. LBPolicy/HealthCheck are ignored when Upstreams is empty.
	Upstreams          []upstreamReq   `json:"upstreams,omitempty"`
	LBPolicy           string          `json:"lbPolicy,omitempty"`
	HealthCheck        *healthCheckReq `json:"healthCheck,omitempty"`
	InsecureSkipVerify bool            `json:"insecureSkipVerify,omitempty"`
	// UpstreamTLSServerName (v2.60) — this path pool's own TLS
	// identity. Full-replacement like the rest of the path-rule
	// wire: path rules ship whole, so no pointer is needed.
	UpstreamTLSServerName string `json:"upstreamTlsServerName,omitempty"`
	// MatchExact (v2.44) matches the whole path instead of the
	// sub-tree. Required for a "/" rule, whose prefix form would also
	// match the redirect's own target.
	MatchExact bool `json:"matchExact,omitempty"`
	// Redirect (v2.44) answers a redirect for this path instead of
	// proxying it.
	Redirect *pathRedirectReq `json:"redirect,omitempty"`
	// RateLimit (v2.56) throttles THIS path in addition to the route's
	// own limit, in a separate counter zone.
	RateLimit *rateLimitReq `json:"rateLimit,omitempty"`
	// ForwardAuth (v2.57) sends THIS path through an IdP, in addition to
	// whatever gate the route already has. Reuses the route-level wire
	// shape: a reference to one of the instance-level providers, never
	// the provider's own config. Mutually exclusive with BasicAuth on
	// the same rule (refused by storage validation).
	ForwardAuth *forwardAuthReq `json:"forwardAuth,omitempty"`
	// DisableRouteAuth (v2.58) exempts THIS path from the route's own
	// authentication — the one thing a path rule subtracts rather than
	// adds. See storage.PathRule.DisableRouteAuth for why it exists and
	// what it deliberately does not switch off.
	DisableRouteAuth bool `json:"disableRouteAuth,omitempty"`
}

// pathRedirectReq is the wire mirror of storage.PathRedirect.
type pathRedirectReq struct {
	Target     string `json:"target"`
	StatusCode int    `json:"statusCode,omitempty"`
}

// mapPathRuleReqs nil/empty-safely maps the wire slice to
// []storage.PathRule. A nil or empty input slice maps to nil (not
// an empty non-nil slice) so a route with no path rules keeps the
// pre-existing storage zero-value shape.
//
// Password hashing: each path-rule's BasicAuth.Password is a PLAIN
// password on the wire (matches route-level basicAuthReq) — hashed
// here via auth.HashRoutePassword, exactly like the route-level
// create/update paths (routes.go ~1296 / ~1806). Returns an error
// if the underlying argon2id hash fails; callers must surface that
// as a 500 (mirrors the route-level hashErr handling).
//
// Preserve-on-edit: when a path rule's BasicAuth.Password is empty
// on PUT, the previously stored hash for that exact PathPrefix is
// kept rather than wiped — mirrors the route-level BasicAuth
// empty-password-preserves-hash UX (Step I.5 / K.1). existing is
// errPathRuleInvalid marks an error in mapPathRuleReqs that came from the
// OPERATOR'S input rather than from the server.
//
// v2.56.3 — the function used to fail for one reason only, a password that
// would not hash, so both call sites answered 500 "failed to hash
// path-rule password". Adding a validation path made an unusable rate
// limit answer the same: a server error, blaming a password, for a number
// the operator typed. The two kinds have to be told apart at the call
// site, or the UI cannot show what is wrong.
var errPathRuleInvalid = errors.New("path rule is not valid")

// the previous route's PathRules (nil on create).
func mapPathRuleReqs(reqs []pathRuleReq, existing []storage.PathRule) ([]storage.PathRule, error) {
	if len(reqs) == 0 {
		return nil, nil
	}
	prevByPrefix := make(map[string]storage.PathRule, len(existing))
	for _, pr := range existing {
		prevByPrefix[pr.PathPrefix] = pr
	}
	out := make([]storage.PathRule, len(reqs))
	for i, r := range reqs {
		pr := storage.PathRule{PathPrefix: r.PathPrefix, MatchExact: r.MatchExact}
		if r.Redirect != nil {
			pr.Redirect = &storage.PathRedirect{
				Target:     r.Redirect.Target,
				StatusCode: r.Redirect.StatusCode,
			}
		}
		if r.BasicAuth != nil {
			hash := ""
			if r.BasicAuth.Password == "" {
				if prev, ok := prevByPrefix[r.PathPrefix]; ok && prev.BasicAuth != nil {
					hash = prev.BasicAuth.PasswordHash
				}
			} else {
				h, hashErr := auth.HashRoutePassword(r.BasicAuth.Password)
				if hashErr != nil {
					return nil, fmt.Errorf("hash path-rule basic auth password (prefix %q): %w", r.PathPrefix, hashErr)
				}
				hash = h
			}
			pr.BasicAuth = &storage.BasicAuthRouteConfig{
				Username:     r.BasicAuth.Username,
				PasswordHash: hash,
			}
		}
		// v2.58 — the exemption. A plain bool: absent means "inherit the
		// route's authentication", which is what every rule stored before
		// this release means too, so no migration is needed.
		pr.DisableRouteAuth = r.DisableRouteAuth
		// v2.57 — the per-path IdP gate. Only the provider reference
		// crosses the wire; an unknown name is not rejected here because
		// a provider can be deleted after the route was saved, and the
		// emitter answers that with a fail-closed 503 rather than
		// silently dropping the gate.
		if r.ForwardAuth != nil {
			pr.ForwardAuth = &storage.ForwardAuthRouteConfig{
				ProviderName: r.ForwardAuth.ProviderName,
			}
		}
		if r.IPFilter != nil {
			f := r.IPFilter.toStorage()
			pr.IPFilter = &f
		}
		// v2.56 — the per-path limit, validated by the same materialiser
		// as the route's so the two cannot drift apart.
		if r.RateLimit != nil {
			rl, rlErr := materialiseRateLimit(r.RateLimit)
			if rlErr != nil {
				return nil, fmt.Errorf("%w: path rule %q: %s",
					errPathRuleInvalid, r.PathPrefix, rlErr.Error())
			}
			pr.RateLimit = rl
		}
		if len(r.Upstreams) > 0 {
			pool := make([]storage.Upstream, len(r.Upstreams))
			for j, u := range r.Upstreams {
				w := u.Weight
				if w == 0 {
					w = 1 // materialise default (storage validate() requires >= 1)
				}
				pool[j] = storage.Upstream{URL: u.URL, Weight: w}
			}
			pr.Upstreams = pool
			lb := r.LBPolicy
			if lb == "" {
				lb = storage.LBPolicyRoundRobin // default when a pool is present
			}
			pr.LBPolicy = lb
			if r.HealthCheck != nil && r.HealthCheck.Enabled {
				hc := materialiseHealthCheck(*r.HealthCheck)
				pr.HealthCheck = &storage.HealthCheck{
					Enabled:      hc.Enabled,
					URI:          hc.URI,
					Method:       hc.Method,
					Interval:     hc.Interval,
					Timeout:      hc.Timeout,
					ExpectStatus: hc.ExpectStatus,
					ExpectBody:   hc.ExpectBody,
					Passes:       hc.Passes,
					Fails:        hc.Fails,
					HostHeader:   hc.HostHeader,
					Headers:      hc.Headers,
				}
			}
			pr.InsecureSkipVerify = r.InsecureSkipVerify
			pr.UpstreamTLSServerName = r.UpstreamTLSServerName
		}
		out[i] = pr
	}
	return out, nil
}

// routeRequest is the wire shape accepted by POST and PUT /routes. JSON tags
// are camelCase per the spec.
type routeRequest struct {
	Host string `json:"host"`
	// Step J.1 — pool of backends. Replaces the pre-J.1 single
	// UpstreamURL string. At least one element; per-element URL is
	// validated by validateUpstreamURL (the existing Step I logic,
	// applied per element). Per-element Weight defaults to 1 if
	// omitted/zero — materialised by the API before the storage
	// write so the storage validate() rule weight >= 1 is satisfied.
	Upstreams []upstreamReq `json:"upstreams"`
	// Step J.1 — LB selection policy. One of the six storage
	// .LBPolicy* values. Empty on POST is normalised to
	// "round_robin" (the default per §5.1, materialised before
	// validation so the storage row carries the explicit value).
	// Empty on PUT means "preserve the previously stored value",
	// same UX as WAFMode below.
	LBPolicy        string `json:"lbPolicy"`
	TLSEnabled      bool   `json:"tlsEnabled"`
	RedirectToHTTPS bool   `json:"redirectToHttps"`
	// Disabled takes a route out of service without deleting its
	// config (v2.15.0 enable/disable feature). The dedicated
	// /disable + /enable endpoints are the primary toggle, but the
	// route form also sends this on create/update so the wire struct
	// must accept it — without this field dec.DisallowUnknownFields()
	// rejects every POST/PUT that carries "disabled" with a 400. On
	// create/update the value is applied directly: absent or false =
	// enabled (the legacy zero-value), true = created/left disabled.
	// v2.39: a pointer, so PUT preserves the stored value when the
	// field is omitted. It used to be a bool: a partial PUT (a script
	// sending only the fields it changes) re-enabled a disabled route.
	Disabled *bool `json:"disabled,omitempty"`
	// MaintenanceConfig (v2.16.0 maintenance-mode feature) mirrors
	// Disabled's wire-field pattern: the dedicated /maintenance +
	// /maintenance/off endpoints are the primary toggle, but the
	// route form also sends this on create/update, so the wire
	// struct must accept it — without this field
	// dec.DisallowUnknownFields() rejects every POST/PUT that
	// carries "maintenanceConfig" with a 400. nil = not in
	// maintenance (the default); non-nil = maintenance active with
	// the given retry-after + bypass IPs.
	MaintenanceConfig *storage.MaintenanceConfig `json:"maintenanceConfig,omitempty"`
	// RedirectConfig (v2.44) mirrors MaintenanceConfig exactly: the
	// route form sends it on create/update, so DisallowUnknownFields
	// would 400 every payload carrying it otherwise. nil = not
	// redirecting. Mutually exclusive with MaintenanceConfig, which
	// storage.Route.Validate enforces rather than this struct.
	RedirectConfig *storage.RedirectConfig `json:"redirectConfig,omitempty"`
	// CertSource (v2.19.0) selects the cert provider for this route.
	// "" / "acme" (default), "internal", or "manual". When "manual",
	// CertID must reference an uploaded external certificate whose
	// SANs cover the route host (validated at create/update time).
	CertSource string `json:"cert_source"`
	// CertID references an ExternalCertificate.ID; required when
	// CertSource == "manual".
	CertID  string   `json:"cert_id"`
	Aliases []string `json:"aliases"`
	// Step K.1 — per-route auth mode. One of "" / "none" / "basic"
	// / "forward_auth". On POST, empty is normalised to "none". On
	// PUT, empty preserves the previously stored value (same UX as
	// WAFMode). The radio-group enum is materialised before
	// validation so the storage row carries the explicit value.
	AuthMode string `json:"authMode"`
	// Step K.1 — Basic Auth sub-shape (replaces the Step I.5 flat
	// BasicAuthEnabled / BasicAuthUsername / BasicAuthPassword
	// triplet). Active only when AuthMode == "basic". BasicAuth.Password
	// is the PLAIN password, write-only on the wire (the response
	// never echoes it, the storage layer holds only the argon2id
	// PHC hash). On Edit, leaving this empty means "keep the
	// existing hash" — same UX preserve-on-edit pattern Step I.5
	// established.
	BasicAuth basicAuthReq `json:"basicAuth"`
	// Step K.1 — Forward-auth sub-shape. Active only when AuthMode
	// == "forward_auth". The reference to one of the configured
	// instance-level providers (Settings page).
	ForwardAuth forwardAuthReq `json:"forwardAuth"`
	// Step I.6 — custom headers applied to the proxied request /
	// response. Map[name → value] (single value per name in v1.0).
	// Validation rejects CR/LF/control characters and hop-by-hop /
	// framing-critical names — see validateHeaders.
	RequestHeaders  map[string]string `json:"requestHeaders"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// Step I.4 — WAF mode, one of "off" / "detect" / "block".
	// On POST, empty string is normalized to "detect" (the FortiWeb
	// safe-shadow default, L6). On PUT, empty string MEANS "preserve
	// the previously stored value" — mirrors the I.5 password
	// preserve UX so admins can flip unrelated fields without
	// re-typing the WAF mode every time.
	WAFMode string `json:"wafMode"`
	// Step J.4 — ACME challenge type for this route's TLS cert.
	// One of "" / "http-01" / "dns-01" / "inherited" (the Step
	// O.1 addition). On POST and PUT, empty string is normalised
	// to "http-01" (the §5.4 default and the pre-J.4 behaviour)
	// UNLESS the host is covered by a managed domain AND
	// UseDedicatedCert is false, in which case the API rewrites
	// the field to "inherited" so the storage row reflects the
	// derived state. No preserve-on-omit semantic.
	ACMEChallenge string `json:"acmeChallenge"`
	// Step O.1 — opt-out from a covering managed-domain wildcard
	// (spec D1.B). Defaults to false. When the host is NOT
	// covered by any managed domain, this field has no effect.
	UseDedicatedCert bool `json:"useDedicatedCert,omitempty"`
	// Step J.2 — active health check, pointer so nil distinguishes
	// "block absent from JSON" from "block present with explicit
	// disabled" (see healthCheckReq doc-comment). createRoute: nil
	// = HC zero-value (disabled); non-nil = materialise + validate
	// then map to storage. updateRoute: nil = preserve previous
	// stored HealthCheck; non-nil = full replacement. The latter
	// rule matches Step I.5 BasicAuth + Step I.4 WAFMode
	// preserve-on-omission patterns.
	HealthCheck *healthCheckReq `json:"healthCheck,omitempty"`
	// Step W — per-route country-block gate. Mode is one of
	// "" / "off" / "allow" / "deny" (the latter two require a
	// non-empty CountryList). Pointer so nil distinguishes "block
	// absent from JSON" (createRoute: zero-value Off; updateRoute:
	// preserve previous) from "block present" (full replacement).
	// Same preserve-on-omission semantics as healthCheck above.
	//
	// StatusCode is the per-route HTTP status override (one of
	// 0 / 403 / 451 / 444); 0 means "use the env-default from
	// ARENET_COUNTRY_BLOCK_STATUS" (W.3 wires the default).
	//
	// CountryList must be uppercase ISO 3166-1 alpha-2 codes
	// (the API canonicalises lowercase inputs to uppercase
	// before validation — UX nicety mirroring the WAFMode
	// case-insensitive pattern would be confusing here since
	// users type country codes by hand).
	CountryBlock *countryBlockReq `json:"countryBlock,omitempty"`
	// Step #R-PROXMOX-HTTPS-LOOP (commit 1b) — route-level
	// opt-out from upstream TLS cert verification, applies when
	// the route's upstream pool uses `https://`. Pointer so nil
	// distinguishes "field absent from JSON" (createRoute:
	// zero-value false strict; updateRoute: preserve previously
	// stored value) from "field present" (full replacement
	// with either true or false).
	//
	// Same preserve-on-omission UX as HealthCheck and
	// CountryBlock above so operators editing unrelated fields
	// don't have to restate the toggle every time.
	//
	// On HTTP-only routes the flag is meaningless (no
	// transport.tls block emitted by the Caddy builder). The
	// API normalises it to false on PUT when the upstream pool
	// is http-only — same self-heal shape as RedirectToHTTPS
	// auto-clearing when TLSEnabled flips false (routes.go:
	// 1273-1275). A warn-log surfaces the normalisation so an
	// operator typo doesn't silently persist.
	InsecureSkipVerify *bool `json:"insecureSkipVerify,omitempty"`
	// UpstreamTLSServerName (v2.60) sets the name Caddy presents in
	// SNI and verifies the backend certificate against, so a pool
	// addressed by IP can still be authenticated. Pointer for the
	// same reason as InsecureSkipVerify above: nil preserves the
	// stored value on PUT, and an explicit "" clears it. A plain
	// string would make "clear it" indistinguishable from "I did
	// not mention it", and an operator could never remove one.
	//
	// Normalised away on an http-only pool, where no transport.tls
	// block is emitted and the value would be stored but never read.
	UpstreamTLSServerName *string `json:"upstreamTlsServerName,omitempty"`
	// UploadStreamingMode (Phase 4.5) flips the route into
	// streaming-upload mode: WAF body inspection is skipped
	// AND Caddy emits flush_interval:-1 so neither layer
	// buffers the request body in RAM. Optional on the wire;
	// nil-pointer preserves the previously stored value
	// (preserve-on-omit, like InsecureSkipVerify). The two
	// effects are coupled in one toggle on purpose — operators
	// flipping one without the other always wanted both.
	UploadStreamingMode *bool `json:"uploadStreamingMode,omitempty"`
	// WAFDisableCRS (Step X.1, 2026-06-17) opts the route out
	// of the OWASP CRS load. nil pointer = preserve-on-omit
	// (PUT) / default false (POST) — mirror of the
	// UploadStreamingMode shape. See storage.Route.WAFDisableCRS
	// for the runtime semantics + ADR D2 for the polarity
	// rationale. The field stays valid for any WAFMode
	// (off / detect / block) ; for off-mode routes the
	// caddymgr emit short-circuits before WAFDisableCRS is
	// consulted, so the flag is silent until the operator
	// turns the mode on.
	WAFDisableCRS *bool `json:"wafDisableCRS,omitempty"`
	// WAFExcludeRules (Step X Option (c), 2026-06-18) is the
	// per-route CRS rule-ID exclusion list. nil pointer =
	// preserve-on-omit (PUT) / default empty (POST). A
	// non-nil pointer is a full replacement of the stored
	// slice — to clear all exclusions the operator sends
	// `"wafExcludeRules": []` (a non-nil empty slice).
	//
	// Validation : each element MUST be a positive integer
	// in the CRS rule-id range [100000, 999999], NOT in the
	// Arenet-reserved sub-range [100000, 199999]. Duplicates
	// are deduped server-side at write time so the canonical
	// form on disk has no redundant entries (cuts pool blast
	// per ADR D3 since two routes with the same effective
	// exclusion set share a WAF pool).
	WAFExcludeRules *[]int `json:"wafExcludeRules,omitempty"`
	// WAFExcludeTags (Step X Option (e), 2026-06-22) is the
	// per-route CRS tag exclusion list — the operator-
	// friendly sibling of WAFExcludeRules. Same triple-state
	// pointer convention :
	//   nil           → preserve-on-omit (PUT) / default
	//                   empty (POST)
	//   non-nil [...]  → full replacement
	//   non-nil []    → clear all tag exclusions
	//
	// Validation (see normalizeExcludeTags) : entries are
	// lowercased, deduped, sorted ; whitespace/comma/quote
	// in a single tag → 400 (would break the SecAction
	// directive line shape) ; per-tag length cap
	// wafExcludeTagMaxLen (128) ; total count cap
	// wafExcludeTagsMaxCount (64).
	//
	// Cross-rule with WAFDisableCRS : when CRS is disabled
	// the tag exclusions become no-ops at runtime but are
	// still persisted + emitted (caddymgr pool-key stability).
	WAFExcludeTags *[]string `json:"wafExcludeTags,omitempty"`
	// WAFTargetedExclusions (v2.36) — nil preserves on PUT, a
	// slice (even empty) replaces; validated by
	// normalizeTargetedExclusions.
	WAFTargetedExclusions *[]wafTargetedExclusionWire `json:"wafTargetedExclusions,omitempty"`
	// WAFCustomRules (v2.37) — guided rules; nil preserves on PUT, a
	// slice replaces (validated + IDs allocated by normalizeCustomRules).
	WAFCustomRules *[]wafCustomRuleWire `json:"wafCustomRules,omitempty"`
	// WAFSecLang (v2.38) — expert SecLang; nil preserves on PUT, a
	// string replaces ("" clears), checked by waf.CheckSecLang.
	WAFSecLang *string `json:"wafSecLang,omitempty"`
	// RateLimit (Step Q, 2026-06-18) is the per-route rate
	// limiter config. Triple-state pointer per the Phase
	// 4.5 + Step X.1 conventions :
	//   nil pointer    → preserve-on-omit (PUT) / default
	//                    nil (POST) — no rate limit.
	//   empty object   → operator-supplied with default
	//                    values ; validated at the API
	//                    layer (Events >= 1, Window parses).
	//   non-empty obj  → full replace.
	//
	// To CLEAR a stored rate limit via PUT the operator
	// sends `"rateLimit": null` (explicit JSON null, not
	// omission). The Go json package decodes that as
	// (*rateLimitReq)(nil) which we distinguish from
	// "field absent" using a sentinel bool — see the PUT
	// path's rateLimitExplicit flag.
	RateLimit *rateLimitReq `json:"rateLimit,omitempty"`
	// ClearRateLimit (v2.9.13 — Phase Q.2) is the sentinel that
	// lets a PUT or POST explicitly remove a previously-stored
	// rate-limit. The legacy preserve-on-omit semantic (an absent
	// RateLimit field "keeps the previous value") meant the UI
	// rate-limit toggle OFF had no wire-level way to surface the
	// operator's intent — Phase Q.2 was designed but never shipped,
	// leaving operators stuck with delete + recreate the route to
	// get rid of an old rate-limit (operator-reported 2026-06-26
	// against route 8448574c-…).
	//
	// Semantic matrix on PUT:
	//   ClearRateLimit | RateLimit body | Result
	//   ---------------|----------------|----------
	//   false (default)| absent         | preserve previous (legacy)
	//   false          | present        | replace with body
	//   true           | absent         | clear (set to nil)
	//   true           | present        | clear (sentinel wins; body ignored)
	//
	// Backwards-compatible: defaults to false, so any client that
	// doesn't know about the field keeps the legacy behaviour.
	ClearRateLimit bool `json:"clearRateLimit,omitempty"`
	// ErrorPageTemplateID (Step R) is the UUID of an
	// ErrorPageTemplate this route opts into. Empty string
	// or absent field → built-in Arenet default applies.
	// The reference is NOT validated for existence here ;
	// caddymgr falls back to default cleanly when the ref
	// dangles (operator sees a warning in journalctl).
	ErrorPageTemplateID string `json:"errorPageTemplateId,omitempty"`
	// ErrorPageOverrides (Step R) layers per-route HTML body
	// overrides on top of the chosen template. Keys must lie
	// in storage.SupportedErrorStatusCodes ; storage validation
	// rejects out-of-set codes.
	ErrorPageOverrides map[int]string `json:"errorPageOverrides,omitempty"`
	// IPFilter (v1 path-based-rules) — whole-domain source-IP
	// gate. Pointer so nil distinguishes "field absent from
	// JSON" (createRoute: zero-value nil, gate off; updateRoute:
	// preserve previously stored value) from "field present"
	// (full replacement) — same preserve-on-omission convention
	// as CountryBlock / HealthCheck above.
	IPFilter *ipFilterReq `json:"ipFilter,omitempty"`
	// PathRules (v1 path-based-rules) — per-sub-path additive
	// overrides (basic auth and/or IP filter scoped to a URL
	// prefix). Always a full replacement when present; omitted
	// or empty on PUT clears the list (no preserve-on-omission
	// for the list itself — only the per-rule password hash is
	// preserved, see mapPathRuleReqs).
	PathRules []pathRuleReq `json:"pathRules,omitempty"`
}

// rateLimitReq is the wire-side shape of Route.RateLimit.
// Mirrors storage.RouteRateLimit but with camelCase JSON
// tags (API convention ; storage uses snake_case via the
// storage.RouteRateLimit type's own tags).
type rateLimitReq struct {
	Events int    `json:"events"`
	Window string `json:"window"`
	Key    string `json:"key,omitempty"`
}

// countryBlockReq is the wire-side shape of Route.CountryBlock.
// Mirrors countryblock.Config but with camelCase JSON tags (API
// convention; storage uses snake_case via countryblock.Config's
// own tags). createRoute / updateRoute map to/from
// countryblock.Config via newCountryBlockConfigFromReq.
//
// Active iff Mode is one of "allow" / "deny". Empty / "off"
// disables the gate (the W.3 caddymgr handler-emit skips the
// handler entirely for those modes; zero per-request cost).
type countryBlockReq struct {
	Mode        string   `json:"mode"`
	CountryList []string `json:"countryList"`
	// Continents + Exceptions (v2.27), ASNs (v2.28): continent
	// codes, AS numbers, and the countries / ASes a deny gate always
	// accepts. All optional.
	Continents []string                `json:"continents,omitempty"`
	ASNs       []uint32                `json:"asns,omitempty"`
	Exceptions *countryBlockExceptions `json:"exceptions,omitempty"`
	StatusCode int                     `json:"statusCode,omitempty"`
}

// countryBlockExceptions is the wire shape of
// countryblock.Exceptions (request and response).
type countryBlockExceptions struct {
	Countries []string `json:"countries"`
	ASNs      []uint32 `json:"asns"`
}

// countryBlockResp is the wire-side response shape of
// Route.CountryBlock. Always non-pointer on the response
// (storage guarantees the field always exists on a stored
// Route — zero-value reads back as Off). camelCase tags
// mirror countryBlockReq.
type countryBlockResp struct {
	Mode        string                 `json:"mode"`
	CountryList []string               `json:"countryList"`
	Continents  []string               `json:"continents"`
	ASNs        []uint32               `json:"asns"`
	Exceptions  countryBlockExceptions `json:"exceptions"`
	StatusCode  int                    `json:"statusCode,omitempty"`
}

// rateLimitResp (Step Q) — per-route rate-limit on the
// response side. Mirrors rateLimitReq verbatim ; the wire
// shape is identical, only the location (request vs
// response) differs.
type rateLimitResp struct {
	Events int    `json:"events"`
	Window string `json:"window"`
	Key    string `json:"key,omitempty"`
}

// upstreamResp is the per-element wire shape inside the routeResponse
// upstreams pool. Symmetric to upstreamReq — URL + Weight.
type upstreamResp struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// healthCheckReq is the per-route active health check on the API
// request side (Step J.2). Mirrors storage.HealthCheck verbatim
// except the JSON tags are camelCase (the api wire convention)
// rather than snake_case (the storage convention) — pattern Step I
// established for routeRequest vs storage.Route. createRoute /
// updateRoute map healthCheckReq to storage.HealthCheck after
// materialising the five defaultable sub-fields (Method, Interval,
// Timeout, Passes, Fails) and uppercasing Method (§5.2).
//
// On routeRequest the field is a POINTER (*healthCheckReq) so the
// JSON decoder distinguishes:
//   - block ABSENT (`healthCheck` key missing) → ptr is nil →
//     updateRoute preserves the previously stored HealthCheck;
//     createRoute treats as zero-value (disabled).
//   - block PRESENT (any value, including {"enabled": false}) →
//     ptr is non-nil → full replacement (§J.3-backlog).
//
// The "omission ≠ clear" semantic mirrors Step I.5 (empty password
// preserves hash) and Step I.4 (empty wafMode preserves mode).
type healthCheckReq struct {
	Enabled      bool   `json:"enabled"`
	URI          string `json:"uri"`
	Method       string `json:"method"`
	Interval     string `json:"interval"`
	Timeout      string `json:"timeout"`
	ExpectStatus int    `json:"expectStatus"`
	ExpectBody   string `json:"expectBody"`
	Passes       int    `json:"passes"`
	Fails        int    `json:"fails"`
	// HostHeader / Headers (v2.55) — see storage.HealthCheck. Empty
	// HostHeader means the probe carries the route's own host.
	HostHeader string            `json:"hostHeader,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// healthCheckResp is the per-route active health check on the API
// response side. Always non-pointer on the response (storage
// guarantees a HealthCheck field always exists on a stored Route)
// and the camelCase tags mirror healthCheckReq.
type healthCheckResp struct {
	Enabled      bool              `json:"enabled"`
	URI          string            `json:"uri"`
	Method       string            `json:"method"`
	Interval     string            `json:"interval"`
	Timeout      string            `json:"timeout"`
	ExpectStatus int               `json:"expectStatus"`
	ExpectBody   string            `json:"expectBody"`
	Passes       int               `json:"passes"`
	Fails        int               `json:"fails"`
	HostHeader   string            `json:"hostHeader,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
}

// basicAuthResp is the Step K.1 wire shape for per-route Basic
// Auth on the response side. PasswordSet is the secret-redaction
// signal (true if a hash exists in storage; the UI renders the
// "••• set" placeholder accordingly) — Step I.5 pattern preserved
// through K.1.
type basicAuthResp struct {
	Username    string `json:"username"`
	PasswordSet bool   `json:"passwordSet"`
}

// forwardAuthResp is the Step K.1 wire shape for per-route
// forward-auth on the response side. Mirrors forwardAuthReq —
// only the provider reference, no secrets (those live in the
// provider config endpoint).
type forwardAuthResp struct {
	ProviderName string `json:"providerName"`
}

// routeResponse is the wire shape returned by GET / POST / PUT /routes. The
// JSON tags must match routeRequest's camelCase scheme.
type routeResponse struct {
	// Check (v2.35) is the post-apply probe of a create / update /
	// enable; absent on reads.
	Check *routecheck.Result `json:"check,omitempty"`
	ID    string             `json:"id"`
	Host  string             `json:"host"`
	// Step J.1 — pool surfaced on the wire. Always at least one
	// element on a stored route (storage.validate guarantees it).
	Upstreams []upstreamResp `json:"upstreams"`
	// Step J.1 — LB selection policy. Always a non-empty enum value
	// on a stored route (storage.validate guarantees it).
	LBPolicy        string `json:"lbPolicy"`
	TLSEnabled      bool   `json:"tlsEnabled"`
	RedirectToHTTPS bool   `json:"redirectToHttps"`
	// Aliases (Step I.3) is normalized to an empty slice (never nil)
	// so the JSON wire shape is consistently `"aliases": []` rather
	// than `"aliases": null` — frontend callers can read .length
	// without a null check.
	Aliases []string `json:"aliases"`
	// Step K.1 — per-route auth mode. The normalised value is
	// always one of "none" / "basic" / "forward_auth" on the
	// wire (storage zero-value "" is rewritten to "none" by
	// toResponse so the frontend renders a single consistent
	// state).
	AuthMode string `json:"authMode"`
	// Step K.1 — Basic Auth response sub-shape. Active only when
	// AuthMode == "basic". The plaintext password is NEVER
	// echoed; the hash is NEVER echoed either. PasswordSet is a
	// boolean derived from "is the hash non-empty?" so the UI
	// can render the placeholder "••• set" hint in Edit mode
	// without ever seeing the secret. (Step I.5 redaction
	// pattern preserved through K.1.)
	BasicAuth basicAuthResp `json:"basicAuth"`
	// Step K.1 — Forward-auth response sub-shape. Active only
	// when AuthMode == "forward_auth". Carries the provider
	// reference; the provider configuration itself (URL, secret,
	// copy headers) is GET'd via the Settings endpoint.
	ForwardAuth forwardAuthResp `json:"forwardAuth"`
	// Step I.6 — custom headers, normalized to empty maps (never
	// nil) so the JSON wire shape is always {} and frontend can
	// iterate without a null check.
	RequestHeaders  map[string]string `json:"requestHeaders"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// Step I.4 — WAF mode, one of "off" / "detect" / "block".
	WAFMode string `json:"wafMode"`
	// Step J.4 — ACME challenge type, one of "http-01" / "dns-01"
	// / "inherited" (the Step O.1 addition for routes covered by
	// a managed-domain wildcard). Surfaced as the normalised
	// value (a pre-J.4 row read back reports "http-01", not the
	// storage "" zero value), so the frontend has a single,
	// consistent state to render.
	ACMEChallenge string `json:"acmeChallenge"`
	// Step O.1 — per-route opt-out from the managed-domain
	// wildcard (spec D1.B). When true on a covered route, the
	// route emits its OWN per-route ACME policy alongside the
	// wildcard. Default false. Omitempty on the wire — a pre-O
	// route never serialises the field.
	UseDedicatedCert bool `json:"useDedicatedCert,omitempty"`
	// Step O.3 — derived field telling the operator which TLS
	// policy actually serves this route's cert (AC #4). One of:
	//   - "managed-domain:<apex>" (covered by a wildcard)
	//   - "per-route-acme:dns-01" (per-route DNS-01 ACME)
	//   - "per-route-acme:http-01" (per-route HTTP-01 ACME)
	//   - "per-route-internal" (private host → internal CA)
	// Omitempty: routes without TLS, or pre-O computations that
	// don't have managed-domain context, render an empty string
	// and the frontend hides the badge.
	EffectiveCertSource string `json:"effectiveCertSource,omitempty"`
	// Step J.2 — active health check. Always present on a stored
	// route (storage.HealthCheck has no omitempty); when Enabled
	// is false the rest of the sub-fields carry zero values and
	// the generator omits the Caddy `health_checks` block.
	HealthCheck healthCheckResp `json:"healthCheck"`
	// Step W — per-route country-block gate state. Always present
	// on a stored route (zero-value reads back as Mode="off" via
	// toResponse normalisation). The frontend renders this as the
	// "Pays bloqués" form section.
	CountryBlock countryBlockResp `json:"countryBlock"`
	// Step #R-PROXMOX-HTTPS-LOOP (commit 1b) — surfaced as a
	// non-pointer bool because storage always carries a
	// definite value (zero default is false). Always emitted
	// on the wire (no omitempty) so a GET→PUT roundtrip can
	// echo it back without dropping the field. The frontend
	// renders this as the "Ignorer la vérification du
	// certificat upstream" toggle in the advanced TLS
	// disclosure (commit 2).
	InsecureSkipVerify bool `json:"insecureSkipVerify"`
	// UpstreamTLSServerName (v2.60) — echoed on every GET, without
	// omitempty, so a GET→PUT roundtrip carries it back instead of
	// silently clearing it. "" means Caddy's default.
	UpstreamTLSServerName string `json:"upstreamTlsServerName"`
	// UploadStreamingMode (Phase 4.5) — echoed on every GET so
	// the frontend toggle starts from the persisted value. No
	// omitempty: the GET→PUT echo must carry the field even
	// when false (preserve-on-omit at PUT relies on nil to
	// detect omission, false to detect explicit-off).
	UploadStreamingMode bool `json:"uploadStreamingMode"`
	// WAFDisableCRS (Step X.1) — same echo-on-every-GET shape
	// as UploadStreamingMode. The frontend toggle starts from
	// the persisted value; the GET→PUT round-trip echoes the
	// field even when false so the preserve-on-omit semantic
	// (nil = omission, false = explicit off) stays sound.
	WAFDisableCRS bool `json:"wafDisableCRS"`
	// WAFExcludeRules (Step X Option (c)) — per-route CRS
	// rule-ID exclusion list. Always present (zero-length
	// slice when the operator has no exclusions configured)
	// so a downstream GET→PUT round-trip carrying the field
	// verbatim doesn't accidentally trigger preserve-on-
	// omit semantics on the put side.
	WAFExcludeRules []int `json:"wafExcludeRules"`
	// WAFExcludeTags (Step X Option (e)) — per-route CRS
	// tag exclusion list. Always present (zero-length slice
	// when the operator has no exclusions configured) for
	// the same GET→PUT round-trip safety reason as
	// WAFExcludeRules above.
	WAFExcludeTags []string `json:"wafExcludeTags"`
	// WAFTargetedExclusions (v2.36) — always present ([] when none).
	WAFTargetedExclusions []wafTargetedExclusionWire `json:"wafTargetedExclusions"`
	// WAFCustomRules (v2.37) — always present ([] when none).
	WAFCustomRules []wafCustomRuleWire `json:"wafCustomRules"`
	// WAFSecLang (v2.38) — "" when none.
	WAFSecLang string `json:"wafSecLang"`
	// RateLimit (Step Q) — per-route rate-limit config
	// echoed on every GET. nil when the route has no rate
	// limit configured (the frontend toggle reads the nil
	// as "off"). omitempty so pre-Q snapshot byte-equality
	// holds for routes that don't use the feature.
	RateLimit *rateLimitResp `json:"rateLimit,omitempty"`
	// Step R — error-page wiring exposed to the frontend so
	// the RouteForm can pre-populate the template dropdown
	// + the per-code override sub-form on edit. Same
	// camelCase JSON convention as RateLimit above ;
	// omitempty preserves byte-identical responses for pre-R
	// routes that haven't opted in.
	ErrorPageTemplateID string         `json:"errorPageTemplateId,omitempty"`
	ErrorPageOverrides  map[int]string `json:"errorPageOverrides,omitempty"`
	// Critique 11 Pack A (2026-06-05) — derived per-route
	// aggregate from the Stage B HC tracker. One of:
	//   "healthy"   — HC enabled AND every upstream healthy in tracker
	//   "degraded"  — HC enabled, mix of healthy + unhealthy
	//   "down"      — HC enabled AND every upstream unhealthy
	//   "unknown"   — HC disabled, OR at least one upstream
	//                 unobserved (warm-up window) without any
	//                 unhealthy signal yet
	//   "not_monitored" — HC deliberately disabled on the route
	//   "not_applicable" (v2.59) — the route proxies nothing, so
	//                 there is no health to report. Today that is
	//                 a redirecting route: no upstream, no probe,
	//                 ever. Distinct from "unknown", which promises
	//                 an answer once the warm-up window closes.
	// See computeRouteAggregateHealth's docstring for the full
	// precedence table.
	AggregateStatus      string `json:"aggregateStatus"`
	HealthyUpstreamCount int    `json:"healthyUpstreamCount"`
	TotalUpstreamCount   int    `json:"totalUpstreamCount"`
	CreatedAt            string `json:"createdAt"`
	UpdatedAt            string `json:"updatedAt"`
	// Disabled (v2.15.0 field, response serialization fixed v2.17.1) —
	// echoed on every GET so the frontend's 3-state control + the
	// last-HTTPS count read the real state. It was missing from this
	// struct since v2.15.0: storage + the /disable endpoint set it, but
	// the response never carried it, so a disabled route decoded as
	// undefined (falsy) → the UI showed it Active. omitempty keeps
	// enabled routes byte-identical (absent → the FE reads not-disabled).
	Disabled bool `json:"disabled,omitempty"`
	// MaintenanceConfig (v2.16.0) — echoed on every GET so the
	// frontend can render the maintenance banner + preserve the
	// config across an unrelated route edit. nil = not in
	// maintenance (the common case); omitempty keeps pre-existing
	// snapshots byte-identical.
	MaintenanceConfig *storage.MaintenanceConfig `json:"maintenanceConfig,omitempty"`
	// RedirectConfig (v2.44) — echoed on every GET so the form
	// reads back the redirect state it is in. Same omitempty
	// reasoning as above.
	RedirectConfig *storage.RedirectConfig `json:"redirectConfig,omitempty"`
	// CertSource (v2.19.0) — echoed on every GET so the frontend's
	// cert-source selector reads the persisted value and a GET→PUT
	// round-trip carries it back. omitempty keeps pre-v2.19.0 rows
	// (CertSource == "") byte-identical on the wire.
	CertSource string `json:"cert_source,omitempty"`
	// CertID (v2.19.0) — the referenced external cert, echoed alongside
	// CertSource. omitempty for the same byte-identity reason.
	CertID string `json:"cert_id,omitempty"`
	// IPFilter (v1 path-based-rules) — whole-domain source-IP
	// gate, echoed verbatim. nil when not configured; omitempty
	// keeps pre-existing snapshots byte-identical.
	IPFilter *ipFilterReq `json:"ipFilter,omitempty"`
	// PathRules (v1 path-based-rules) — per-sub-path overrides.
	// Each entry's BasicAuth.Password is REDACTED (blanked) before
	// serialisation — see toResponse. omitempty keeps pre-existing
	// snapshots byte-identical for routes without path rules.
	PathRules []pathRuleReq `json:"pathRules,omitempty"`
}

// toResponse converts a storage.Route to its API wire form (RFC 3339 with
// millisecond precision, UTC).
func toResponse(r storage.Route) routeResponse {
	aliases := r.Aliases
	if aliases == nil {
		aliases = []string{} // S6: never emit `"aliases": null` on the wire.
	}
	// Step I.6 — normalize nil maps to empty so the wire JSON never
	// emits `null`. Frontend reads .length / Object.keys safely.
	reqHeaders := r.RequestHeaders
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}
	respHeaders := r.ResponseHeaders
	if respHeaders == nil {
		respHeaders = map[string]string{}
	}
	// Step J.1 — surface the upstream pool 1:1 from storage.
	// storage.validate() guarantees at least one element, so the
	// returned slice is always non-empty for a stored route.
	upstreamsResp := make([]upstreamResp, len(r.Upstreams))
	for i, u := range r.Upstreams {
		upstreamsResp[i] = upstreamResp{URL: u.URL, Weight: u.Weight}
	}
	// Step J.4: surface the normalised ACMEChallenge — a stored row
	// with the zero value "" reads back as "http-01" so the
	// frontend renders a single consistent value (pre-J.4 rows
	// behave identically to a fresh post-J.4 default).
	acmeChallenge := r.ACMEChallenge
	if acmeChallenge == "" {
		acmeChallenge = storage.ACMEChallengeHTTP01
	}
	// Step K.1: surface the normalised AuthMode — a stored row
	// with the zero value "" (a row that somehow bypassed the
	// boot migration) reads back as "none" so the frontend
	// always renders a defined radio-group state.
	authMode := r.AuthMode
	if authMode == "" {
		authMode = storage.RouteAuthNone
	}
	return routeResponse{
		ID:               r.ID,
		Host:             r.Host,
		Upstreams:        upstreamsResp,
		LBPolicy:         r.LBPolicy,
		TLSEnabled:       r.TLSEnabled,
		RedirectToHTTPS:  r.RedirectToHTTPS,
		Aliases:          aliases,
		AuthMode:         authMode,
		UseDedicatedCert: r.UseDedicatedCert,
		BasicAuth: basicAuthResp{
			Username:    r.BasicAuth.Username,
			PasswordSet: r.BasicAuth.PasswordHash != "",
		},
		ForwardAuth: forwardAuthResp{
			ProviderName: r.ForwardAuth.ProviderName,
		},
		RequestHeaders:  reqHeaders,
		ResponseHeaders: respHeaders,
		WAFMode:         r.WAFMode,
		ACMEChallenge:   acmeChallenge,
		HealthCheck: healthCheckResp{
			Enabled:      r.HealthCheck.Enabled,
			URI:          r.HealthCheck.URI,
			Method:       r.HealthCheck.Method,
			Interval:     r.HealthCheck.Interval,
			Timeout:      r.HealthCheck.Timeout,
			ExpectStatus: r.HealthCheck.ExpectStatus,
			ExpectBody:   r.HealthCheck.ExpectBody,
			Passes:       r.HealthCheck.Passes,
			Fails:        r.HealthCheck.Fails,
			HostHeader:   r.HealthCheck.HostHeader,
			Headers:      r.HealthCheck.Headers,
		},
		CountryBlock:          toCountryBlockResp(r.CountryBlock),
		InsecureSkipVerify:    r.InsecureSkipVerify,
		UpstreamTLSServerName: r.UpstreamTLSServerName,
		UploadStreamingMode:   r.UploadStreamingMode,
		WAFDisableCRS:         r.WAFDisableCRS,
		WAFExcludeRules:       emptyIntSliceIfNil(r.WAFExcludeRules),
		WAFExcludeTags:        emptyStringSliceIfNil(r.WAFExcludeTags),
		WAFTargetedExclusions: toTargetedExclusionsWire(r.WAFTargetedExclusions),
		WAFCustomRules:        toCustomRulesWire(r.WAFCustomRules),
		WAFSecLang:            r.WAFSecLang,
		RateLimit:             toRateLimitResp(r.RateLimit),
		// Step R — error-page wiring pass-through (omitempty
		// on the response struct so pre-R routes still emit
		// byte-identical JSON).
		ErrorPageTemplateID: r.ErrorPageTemplateID,
		ErrorPageOverrides:  r.ErrorPageOverrides,
		CreatedAt:           r.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:           r.UpdatedAt.UTC().Format(timestampFormat),
		Disabled:            r.Disabled,
		MaintenanceConfig:   r.MaintenanceConfig,
		RedirectConfig:      r.RedirectConfig,
		CertSource:          r.CertSource,
		CertID:              r.CertID,
		IPFilter:            toIPFilterResp(r.IPFilter),
		PathRules:           toPathRulesResp(r.PathRules),
	}
}

// toIPFilterResp maps storage.IPFilter to the wire response shape.
// nil in → nil out (omitempty drops the field for routes without
// a whole-domain gate).
func toIPFilterResp(f *storage.IPFilter) *ipFilterReq {
	if f == nil {
		return nil
	}
	return &ipFilterReq{Mode: f.Mode, CIDRs: f.CIDRs, StatusCode: f.StatusCode}
}

// toPathRulesResp maps []storage.PathRule to the wire response
// shape, REDACTING each path-rule's basic-auth password — it must
// never be echoed back (mirrors the route-level BasicAuth
// redaction pattern: the response only ever confirms a password
// is set, never its plaintext or its stored hash). nil/empty in →
// nil out.
func toPathRulesResp(rules []storage.PathRule) []pathRuleReq {
	if len(rules) == 0 {
		return nil
	}
	out := make([]pathRuleReq, len(rules))
	for i, pr := range rules {
		out[i] = pathRuleReq{PathPrefix: pr.PathPrefix, MatchExact: pr.MatchExact}
		if pr.Redirect != nil {
			out[i].Redirect = &pathRedirectReq{
				Target:     pr.Redirect.Target,
				StatusCode: pr.Redirect.StatusCode,
			}
		}
		if pr.BasicAuth != nil {
			out[i].BasicAuth = &pathRuleBasicAuthReq{
				Username: pr.BasicAuth.Username,
				Password: "", // SECRET — never echoed (plain or hash)
			}
		}
		out[i].DisableRouteAuth = pr.DisableRouteAuth
		// v2.57 — the provider reference is not a secret (the provider's
		// own credentials live behind the providers endpoint), so unlike
		// the basic-auth password it is echoed back as stored. The form
		// needs it to re-render the gate on edit.
		if pr.ForwardAuth != nil {
			out[i].ForwardAuth = &forwardAuthReq{
				ProviderName: pr.ForwardAuth.ProviderName,
			}
		}
		if pr.IPFilter != nil {
			out[i].IPFilter = &ipFilterReq{
				Mode:       pr.IPFilter.Mode,
				CIDRs:      pr.IPFilter.CIDRs,
				StatusCode: pr.IPFilter.StatusCode,
			}
		}
		if pr.RateLimit != nil {
			out[i].RateLimit = &rateLimitReq{
				Events: pr.RateLimit.Events,
				Window: pr.RateLimit.Window,
				Key:    pr.RateLimit.Key,
			}
		}
		if len(pr.Upstreams) > 0 {
			pool := make([]upstreamReq, len(pr.Upstreams))
			for j, u := range pr.Upstreams {
				pool[j] = upstreamReq{URL: u.URL, Weight: u.Weight}
			}
			out[i].Upstreams = pool
			out[i].LBPolicy = pr.LBPolicy
			if pr.HealthCheck != nil {
				out[i].HealthCheck = &healthCheckReq{
					Enabled:      pr.HealthCheck.Enabled,
					URI:          pr.HealthCheck.URI,
					Method:       pr.HealthCheck.Method,
					Interval:     pr.HealthCheck.Interval,
					Timeout:      pr.HealthCheck.Timeout,
					ExpectStatus: pr.HealthCheck.ExpectStatus,
					ExpectBody:   pr.HealthCheck.ExpectBody,
					Passes:       pr.HealthCheck.Passes,
					Fails:        pr.HealthCheck.Fails,
					HostHeader:   pr.HealthCheck.HostHeader,
					Headers:      pr.HealthCheck.Headers,
				}
			}
			out[i].InsecureSkipVerify = pr.InsecureSkipVerify
			out[i].UpstreamTLSServerName = pr.UpstreamTLSServerName
		}
	}
	return out
}

// toRateLimitResp normalises the storage *RouteRateLimit to
// the wire response shape. nil in → nil out (the omitempty
// JSON tag drops the field for routes without a rate limit
// so pre-Q snapshots stay byte-equal).
func toRateLimitResp(r *storage.RouteRateLimit) *rateLimitResp {
	if r == nil {
		return nil
	}
	return &rateLimitResp{
		Events: r.Events,
		Window: r.Window,
		Key:    r.Key,
	}
}

// emptyIntSliceIfNil returns []int{} when the input is nil so
// the response JSON never carries `null` for WAFExcludeRules.
// The frontend treats the field as always-present (operator
// edits a list, never queries "is this null vs missing"), so
// the nil → [] normalisation here keeps the contract clean.
func emptyIntSliceIfNil(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

// emptyStringSliceIfNil — sibling of emptyIntSliceIfNil for the
// Step X (e) WAFExcludeTags wire field. Same rationale : the
// frontend always edits a list, so nil → [] keeps the response
// JSON contract uniform.
func emptyStringSliceIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// toCountryBlockResp normalises the storage Config for the
// response side. A stored row with the zero value Mode="" reads
// back as "off" so the frontend renders a single consistent
// state. CountryList is normalised to an empty slice (never
// nil) so the wire JSON never emits `null`.
func toCountryBlockResp(c countryblock.Config) countryBlockResp {
	mode := string(c.Mode)
	if mode == "" {
		mode = string(countryblock.ModeOff)
	}
	list := c.CountryList
	if list == nil {
		list = []string{}
	}
	continents := c.Continents
	if continents == nil {
		continents = []string{}
	}
	asns := c.ASNs
	if asns == nil {
		asns = []uint32{}
	}
	exceptions := countryBlockExceptions{Countries: []string{}, ASNs: []uint32{}}
	if c.Exceptions != nil && c.Exceptions.Countries != nil {
		exceptions.Countries = c.Exceptions.Countries
	}
	if c.Exceptions != nil && c.Exceptions.ASNs != nil {
		exceptions.ASNs = c.Exceptions.ASNs
	}
	return countryBlockResp{
		Mode:        mode,
		CountryList: list,
		Continents:  continents,
		ASNs:        asns,
		Exceptions:  exceptions,
		StatusCode:  c.StatusCode,
	}
}

// computeEffectiveCertSource (Step O.3 / AC #4) derives the
// human-readable cert-source label for a route given the current
// set of managed domains. Pure function — no I/O. Mirrors the
// caddymgr partition logic (§3.2 + §3.3): a covered route whose
// UseDedicatedCert is false → "managed-domain:<apex>". Otherwise
// falls back to the per-route ACME path or internal CA.
//
// Empty return value means "no inference made" — emitted on the
// wire as the zero-string (omitempty drops the field) so a
// pre-O frontend doesn't see a misleading state. Reached when:
//   - TLSEnabled is false (no cert needed).
//   - Host is private (certmagic.SubjectQualifiesForPublicCert
//     would reject it — we approximate that here with a simple
//     "is the host a literal IP / .local / loopback?" check
//     would over-engineer this; instead, we let
//     "per-route-internal" be the catch-all for any private
//     host that reaches the catch-all policy in caddymgr).
//
// The function takes the managed-domain slice as input rather
// than reading from the store so it stays cheap to call once
// per route in the list handler (the caller passes the slice
// fetched once at the top of listRoutes).
func computeEffectiveCertSource(r storage.Route, mds []storage.ManagedDomain) string {
	if !r.TLSEnabled {
		return ""
	}
	// v2.19.0: a route pinned to an operator-uploaded external cert
	// serves that material regardless of ACME / managed-domain state.
	if r.CertSource == storage.RouteCertSourceManual {
		return "per-route-manual"
	}
	// Covered + not-opted-out → managed-domain wildcard.
	if !r.UseDedicatedCert {
		for _, h := range r.AllHosts() {
			if md, ok := caddymgr.IsHostCoveredByManagedDomain(h, mds); ok {
				return "managed-domain:" + md.Apex
			}
		}
	}
	// Per-route path. Normalise the storage zero-value "" /
	// "inherited" (defensive — should not occur for non-
	// covered hosts) to "http-01".
	switch r.ACMEChallenge {
	case storage.ACMEChallengeDNS01:
		return "per-route-acme:dns-01"
	case storage.ACMEChallengeHTTP01, "", storage.ACMEChallengeInherited:
		// Private hosts caddymgr filters out of the ACME
		// partitions land on the internal CA. We can't
		// reliably distinguish here without re-implementing
		// certmagic.SubjectQualifiesForPublicCert, so the
		// label is the per-route ACME default. The
		// dashboard surfacing this is honest about
		// "what would be emitted if this host qualified for
		// a public cert" rather than chasing the runtime
		// classification.
		return "per-route-acme:http-01"
	}
	return "per-route-internal"
}

// validateManualCertRef enforces the v2.19.0 manual-cert cross-rules
// on a route about to be written. When CertSource != "manual" it is a
// no-op (returns nil). When CertSource == "manual" it requires:
//   - CertID non-empty (else cert_id_required),
//   - CertID references an existing external cert (else cert_not_found),
//   - the referenced cert has a signed leaf, i.e. is not still a
//     pending_csr row (else cert_not_ready) — a pending row's empty
//     leaf is skipped at emission, so binding a route to it would
//     silently serve NO certificate (v2.20.0 finding),
//   - the referenced cert's SANs cover the route host (else
//     host_not_covered_by_cert).
//
// The returned error's message carries the machine-readable code so
// the API layer can surface it verbatim in the 400 body.
func (h *Handler) validateManualCertRef(ctx context.Context, r *storage.Route) error {
	if r.CertSource != storage.RouteCertSourceManual {
		return nil
	}
	if r.CertID == "" {
		return errors.New("cert_id_required: certSource \"manual\" requires a certId")
	}
	cert, err := h.store.GetExternalCertificate(ctx, r.CertID)
	if errors.Is(err, storage.ErrNotFound) {
		return errors.New("cert_not_found: referenced external certificate does not exist")
	}
	if err != nil {
		return err
	}
	if cert.CertPEM == "" {
		return errors.New("cert_not_ready: the selected certificate is still pending its signed certificate (CSR not yet completed)")
	}
	if !storage.HostMatchesSAN(r.Host, cert.DNSNames) {
		return errors.New("host_not_covered_by_cert: the route host is not present in the certificate SANs")
	}
	return nil
}

// reconcileManagedDomainCoverage (Step O.3 / spec D1.B + D8.A)
// is the cross-rule helper applied at the top of createRoute /
// updateRoute. Returns the (possibly-rewritten) ACMEChallenge
// value the storage row should carry, or a user-facing error
// to surface as a 400.
//
// Rules (in order of evaluation):
//   - Host NOT covered + UseDedicatedCert=true → reject. The
//     opt-out only makes sense when there IS a managed domain
//     to opt out OF. This is a defensive guard; the frontend
//     hides the toggle in this case (AC #12).
//   - Host covered + UseDedicatedCert=true → keep the
//     operator-supplied ACMEChallenge (http-01 / dns-01).
//     The wildcard policy still emits, but this route's per-
//     route policy precedes it in the JSON (caddymgr §3.3) so
//     the dedicated cert serves for THIS host.
//   - Host covered + UseDedicatedCert=false → rewrite the
//     ACMEChallenge to "inherited" regardless of the
//     operator-supplied value. This is the D8.A invariant:
//     the storage row reflects the derived state truthfully.
//   - Host NOT covered + UseDedicatedCert=false → keep the
//     operator-supplied ACMEChallenge unchanged. The J-era
//     per-route path is undisturbed (the spec D5.A invariant
//     surfaced at the API layer).
//
// The mds slice is fetched ONCE at the handler entry — the
// helper itself is pure.
func reconcileManagedDomainCoverage(challenge string, useDedicated bool, host string, aliases []string, mds []storage.ManagedDomain) (string, error) {
	covered := false
	for _, h := range append([]string{host}, aliases...) {
		if _, ok := caddymgr.IsHostCoveredByManagedDomain(h, mds); ok {
			covered = true
			break
		}
	}
	if useDedicated && !covered {
		return "", errors.New("useDedicatedCert can only be true when the route's host is covered by a managed domain")
	}
	if covered && !useDedicated {
		return storage.ACMEChallengeInherited, nil
	}
	return challenge, nil
}
