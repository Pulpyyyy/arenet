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
	"errors"
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// metricName is the enum of metrics the /metrics/timeseries
// endpoint accepts on the `metric` query parameter. Mirrors the
// four columns persisted in bucket_1m / bucket_1h.
type metricName string

const (
	metricReqPerSec    metricName = "req_per_sec"
	metricFourXxRate   metricName = "four_xx_rate"
	metricFiveXxRate   metricName = "five_xx_rate"
	metricP95LatencyMs metricName = "p95_latency_ms"
	// Step M.2 — WAF block rate as a count metric. Routes
	// through the existing timeseries handler unchanged
	// (gap-fill rule = 0 for missing buckets, same as the
	// other count metrics). p95 null semantics do NOT apply.
	metricWafBlockRate metricName = "waf_block_rate"
	// Step Q.3 — throttle block rate. Reads
	// bucket.ThrottleBlockCount, gap-filled with 0. Spec §3.5:
	// throttle blocks aggregate under the sentinel
	// route_id="_throttle"; the handler enforces that, so
	// route=<uuid> returns all zeros (the bucket has no data
	// at that key).
	metricThrottleBlockRate metricName = "throttle_block_rate"
	// Step Q.3 — auth failure rate. SPECIAL-CASED: detours
	// through the AuthFailureReader.QueryByActionRange path
	// (spec D4.B single source of truth) rather than reading
	// a bucket column. The audit log is the canonical source;
	// no bucket counter exists for this metric. Handler
	// projects the audit-scan to the same {points: [{ts,
	// value}]} wire shape as the bucket metrics, gap-filled
	// with 0.
	metricAuthFailureRate metricName = "auth_failure_rate"
	// Step N.3 — crowdsec decision rate. Reads
	// bucket.CrowdSecDecisionCount, gap-filled with 0. Same
	// shape as throttle_block_rate. Spec N §3.5: decisions
	// aggregate under the sentinel route_id="_crowdsec".
	// The dashboard passes route=all (the
	// QueryAggregated path SUMs across all routes including
	// the sentinel — same trick as Q.4 uses for throttle).
	// route=<uuid> returns all zeros (no per-route concept
	// for CrowdSec decisions, mirror of AC #10 for throttle).
	metricCrowdSecDecisionRate metricName = "crowdsec_decision_rate"
	// Step Z.3 — HTTP rate-limit (429) rate. Reads
	// bucket.RateLimitCount, gap-filled with 0. Unlike
	// throttle_block_rate which keys under "_throttle",
	// THIS metric is per-route — the Z.1 sink resolves the
	// upstream caddy-ratelimit zone "route-<UUID>" to the
	// route UUID and bumps the bucket under that real ID.
	// Powers the /security/[routeId] chart panel.
	metricRateLimitRate metricName = "rate_limit_rate"
)

// timeseriesPoint is one point on the timeline. Value is *float64
// so the JSON encoder emits `null` for missing p95 buckets (the
// AC #5 anti-fake-dip rule — a "0 ms p95" rendered as a real data
// point would draw a fake latency dip). Count metrics use a real
// 0 (no traffic = "0 req/sec" is a valid measurement).
type timeseriesPoint struct {
	Ts    string   `json:"ts"`
	Value *float64 `json:"value"`
}

// timeseriesResponse is the wire shape of GET /metrics/timeseries.
// `disabled` is true iff the observability subsystem failed at
// boot (AC #13 degraded mode); the client renders an "empty"
// state instead of an error.
type timeseriesResponse struct {
	RouteID           string            `json:"routeId"`
	Metric            metricName        `json:"metric"`
	Window            string            `json:"window"`
	BucketSizeSeconds int               `json:"bucketSizeSeconds"`
	Disabled          bool              `json:"disabled,omitempty"`
	Points            []timeseriesPoint `json:"points"`
}

// summaryRoute is the per-route entry of the summary
// response. Counters are sums over the configured window
// (see summaryResponse.WindowSeconds — currently 86400 /
// 24 h).
//
// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — the historic
// PerMin suffix was dropped when the window widened from
// just-closed-minute to 24h. The fields name what they
// count (Reqs, WafBlocked, …); the window comes from the
// envelope WindowSeconds. Future window selectors don't
// force another rename.
type summaryRoute struct {
	RouteID     string `json:"routeId"`
	Host        string `json:"host"`
	Reqs        uint64 `json:"reqs"`
	Fourxx      uint64 `json:"fourxx"`
	Fivexx      uint64 `json:"fivexx"`
	WafBlocked  uint64 `json:"wafBlocked"`
	WafDetected uint64 `json:"wafDetected"`
}

// summaryResponse is the wire shape of GET /metrics/summary.
// AC #6: 4xx and 5xx are EXPOSED SEPARATELY. The fields below
// are independent counters; no aggregate "errors" field exists.
//
// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — every Total* field
// (and every field on summaryRoute) is a SUM over the
// configured window (WindowSeconds). Pre-fix the window was
// the just-closed minute and the frontend projected ×60 or
// ×60×24 to display "/h" / "/24h" — bursty homelab traffic
// surfaced as zeros between bursts. Post-fix the window is
// 24h, sourced from bucket_1h (per-route SUM over 24 rows)
// and waf_event aggregator (GROUP BY category over the
// window). The frontend consumes the values raw.
//
// The PerMin suffix on every count field was dropped in the
// same commit — the rate semantics no longer apply, and the
// envelope WindowSeconds tells the consumer the window
// without contaminating each field's name. A future window
// selector (1h / 24h / 7d) is the natural follow-on and
// won't force another rename.
//
// Step M.2 (spec §3.4):
//   - TotalWafBlocked: sum of waf_block_count across all
//     routes over the window. Independent from the L
//     counters — a WAF block increments THIS field, not
//     TotalFourXx / TotalFiveXx (AC #3 / #4).
//   - WafBlocksByCategory: per-OWASP-category breakdown of
//     the BLOCK events over the same window. Server-side
//     GROUP BY in observability.AggregateWafEventsByCategory
//     (was a row-iteration with a 100-row cap pre-fix —
//     incompatible with a 24h window on a busy day).
//
// Step M.2 Spec-1 amendment:
//   - TopAttackedRoute: the single route with the highest
//     WAF block count over the window, computed across ALL
//     routes (NOT filtered to TopRoutes' traffic-ranked
//     set). Critical for the M.3 dashboard headline: a
//     targeted attack on a low-traffic admin / auth surface
//     would otherwise be invisible because the route never
//     reaches the traffic top-5. Nullable when no WAF
//     activity (operator sees an honest zero).
type summaryResponse struct {
	GeneratedAt     string `json:"generatedAt"`
	WindowSeconds   int    `json:"windowSeconds"`
	Disabled        bool   `json:"disabled,omitempty"`
	TotalReq        uint64 `json:"totalReq"`
	TotalFourXx     uint64 `json:"totalFourXx"`
	TotalFiveXx     uint64 `json:"totalFiveXx"`
	TotalWafBlocked uint64 `json:"totalWafBlocked"`
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — sibling counter
	// sourced from waf_detect_count bucket column.
	TotalWafDetected uint64 `json:"totalWafDetected"`
	// Step Q.3 / N.3 — independent counters. AC #15: a
	// throttle / crowdsec event does NOT inflate the 4xx /
	// 5xx / waf fields.
	TotalThrottle uint64 `json:"totalThrottle"`
	// Step Z.2 — rate-limit (429) counter over the window.
	// Sourced from a window-scoped COUNT(*) on the
	// rate_limit_event table (NOT a bucket — the per-route
	// bucket counter from Z.3 powers timeseries chart, not
	// this dashboard total). Independent of the other counters
	// per the same AC #15 principle : a 429 must NOT inflate
	// totalFourXx or totalThrottle.
	TotalRateLimitExceeded uint64 `json:"totalRateLimitExceeded"`
	TotalAuthFailures      uint64 `json:"totalAuthFailures"`
	AttackerIpsUnique      int    `json:"attackerIpsUnique"` // union over WAF + throttle + audit + crowdsec
	TotalCrowdSecDecisions uint64 `json:"totalCrowdSecDecisions"`
	// ActiveCrowdSecIpsUnique counts distinct decision
	// `value` strings (IP / CIDR / country / AS). No time
	// projection involved — name unchanged.
	ActiveCrowdSecIpsUnique int               `json:"activeCrowdSecIpsUnique"`
	GlobalP95LatencyMs      *float64          `json:"globalP95LatencyMs"` // null when no traffic; weighted avg over the window
	ActiveRouteCount        int               `json:"activeRouteCount"`
	TopRoutes               []summaryRoute    `json:"topRoutes"`           // top 5 by reqs over the window
	TopAttackedRoute        *summaryRoute     `json:"topAttackedRoute"`    // single highest WafBlocked, all routes; null if none
	WafBlocksByCategory     map[string]uint64 `json:"wafBlocksByCategory"` // category → count of action=BLOCK events over the window
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — sibling map for
	// action=DETECT events. Semantically distinct from
	// WafBlocksByCategory: the two report DIFFERENT
	// populations (block-mode vs detect-mode rule
	// fires). Operators wanting a combined attack-
	// volume view sum the two maps client-side. Pre-fix
	// WafBlocksByCategory silently aggregated both
	// populations under a misleading name; this commit
	// tightens its semantics to BLOCK-only.
	WafDetectsByCategory map[string]uint64 `json:"wafDetectsByCategory"` // category → count of action=DETECT events; empty when no events
}

// routeAllSentinel selects the global aggregated timeseries (per
// Spec-1 §10.1). Sentinel rather than a separate endpoint to keep
// the URL surface tight — same query shape, same response shape,
// only the data source changes.
//
// Collision analysis: Route IDs are generated by uuid.NewString
// (storage/routes.go:CreateRoute) — v4 UUIDs in the canonical
// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form. "all" is 3 chars
// with no dashes; collision with a generated route ID is
// cryptographically impossible.
//
// The only theoretical path for a route with ID "all" is a
// tampered backup restore (storage/backup_apply.go preserves
// backup-supplied keys verbatim). The handler resolves the
// sentinel BEFORE the per-route 404 lookup, so route=all
// always hits the aggregate even if such a row exists; the
// route's data still flows into the aggregate via SUM. No
// security or data-integrity impact. Pinned by
// TestMetricsTimeseries_RouteAll_SentinelBeatsCollidingRoute.
const routeAllSentinel = "all"

// metricsTimeseries handles GET /api/v1/metrics/timeseries.
// Query parameters:
//   - route  : storage route UUID (per-route) OR "all"
//     (global aggregate, Spec-1 §10.1)
//   - metric : one of req_per_sec / four_xx_rate / five_xx_rate / p95_latency_ms
//   - window : 24h (returns 1-minute buckets) or 30d (1-hour buckets)
//
// Response on success: 200 with timeseriesResponse, gap-filled
// per AC #5 (0 for counts, null for p95).
//
// Degraded paths (AC #13):
//   - h.metrics == nil (observability boot failed) → 200 with
//     disabled=true and points=[]. The UI shows an empty state
//     instead of an error toast.
//   - Query returns an error (locked DB, etc.) → 503 with the
//     canonical error envelope.
func (h *Handler) metricsTimeseries(w http.ResponseWriter, r *http.Request) {
	routeID := r.URL.Query().Get("route")
	metric := metricName(r.URL.Query().Get("metric"))
	window := r.URL.Query().Get("window")

	if routeID == "" {
		writeError(w, http.StatusBadRequest, "route is required (use \"all\" for the global aggregate)")
		return
	}
	if !isValidMetric(metric) {
		writeError(w, http.StatusBadRequest, "metric must be one of req_per_sec, four_xx_rate, five_xx_rate, p95_latency_ms, waf_block_rate, throttle_block_rate, auth_failure_rate, crowdsec_decision_rate")
		return
	}
	gran, step, windowDur, ok := windowParams(window)
	if !ok {
		writeError(w, http.StatusBadRequest, "window must be 24h or 30d")
		return
	}

	aggregated := routeID == routeAllSentinel

	// 404 on unknown route ID. Skipped for the "all" sentinel
	// since it does not correspond to a stored route.
	if !aggregated {
		if _, err := h.store.GetRoute(r.Context(), routeID); err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeError(w, http.StatusNotFound, "route not found")
				return
			}
			h.logger.Error("metrics: route lookup failed", "err", err, "route", routeID)
			writeError(w, http.StatusServiceUnavailable, "storage unavailable")
			return
		}
	}

	resp := timeseriesResponse{
		RouteID:           routeID, // echoed verbatim — "all" or the UUID
		Metric:            metric,
		Window:            window,
		BucketSizeSeconds: int(step.Seconds()),
		Points:            []timeseriesPoint{},
	}

	now := time.Now().UTC()
	to := now.Truncate(step).Add(step) // exclusive upper bound, next bucket boundary
	from := to.Add(-windowDur)

	// Step Q.3 — auth_failure_rate is special-cased per spec
	// D4.B + AC #10: the data lives in the audit log, not in
	// metrics.db. Detour through the AuthFailureReader and
	// return early. Per AC #10, the per-route variant is
	// "N/A — neither signal is per-route, so route=<uuid>
	// returns all-zero". The "all" sentinel returns the real
	// system-wide audit-scan projection.
	if metric == metricAuthFailureRate {
		if !aggregated {
			// route=<uuid>: return the dense zero-filled
			// timeseries WITHOUT scanning audit. AC #10
			// literal contract.
			resp.Points = gapFillAuthFailureZero(from, to, step)
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if h.authFailures == nil {
			// AC #14 degraded shape mirror.
			resp.Disabled = true
			writeJSON(w, http.StatusOK, resp)
			return
		}
		events, _, err := h.authFailures.QueryByActionRange(
			r.Context(),
			audit.AuthFailureActions(),
			from, to,
			authFailuresScanCap,
		)
		if err != nil {
			h.logger.Error("metrics: auth-failure scan failed", "err", err, "window", window)
			writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
			return
		}
		resp.Points = gapFillAuthFailureTimeseries(events, from, to, step)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	if h.metrics == nil {
		// AC #13 degraded mode: respond with disabled=true and
		// empty points so the frontend can render a clean empty
		// state ("metrics history unavailable") rather than a
		// hostile error toast. 200, not 503 — the data plane is
		// healthy; only the history is missing.
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	var (
		rows []observability.MetricBucket
		err  error
	)
	if aggregated {
		rows, err = h.metrics.QueryAggregated(r.Context(), gran, from, to)
	} else {
		rows, err = h.metrics.Query(r.Context(), gran, routeID, from, to)
	}
	if err != nil {
		h.logger.Error("metrics: query failed", "err", err, "route", routeID, "metric", metric)
		writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
		return
	}

	resp.Points = gapFillTimeseries(rows, from, to, step, metric)
	writeJSON(w, http.StatusOK, resp)
}

// summaryWindow is the wall-clock width of the
// /metrics/summary response: a fixed 24-hour rolling
// window ending at "now truncated to the previous hour"
// (the boundary the bucket_1h aggregator writes).
//
// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — pre-fix the
// window was the just-closed minute and the frontend
// projected the 1-min counters to "/h" or "/24h" by
// multiplying. Bursty homelab traffic surfaced as zeros
// between bursts. Post-fix the window is 24h sourced from
// bucket_1h (per-route SUM over 24 rows) so the dashboard
// reflects real activity over the entire day. A future
// user-selectable window is the natural follow-on.
const summaryWindow = 24 * time.Hour

// summaryAuthFailuresScanCap bounds the audit scan inside
// metricsSummary so a 24h window can return correct
// counts even on a noisy day. The /security/auth-failures
// endpoint has its own (smaller) cap for recent-feed
// rendering; this one is summary-specific. Sized large
// enough for a brute-force-storm day on a homelab proxy
// (~10 attempts/sec sustained = 864k/day, way past the
// rate-limiter's hard ceiling). If we ever hit the cap
// the metric undercounts — logged at Debug so an
// operator monitoring growth sees it before users do.
const summaryAuthFailuresScanCap = 10000

// metricsSummary handles GET /api/v1/metrics/summary.
// Aggregates traffic, error, and security counters across
// all routes over a 24h rolling window, surfaces top-5 by
// traffic + global p95.
//
// AC #6: 4xx and 5xx fields stay independent in the JSON
// (no collapse into "errors").
func (h *Handler) metricsSummary(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	// The window's high boundary is the start of the
	// current hour (bucket_1h is written one row per hour
	// at the top of each hour, so the currently-in-flight
	// hour has no row yet). The low boundary is exactly
	// 24h earlier.
	hourTs := now.Truncate(time.Hour)
	from := hourTs.Add(-summaryWindow)
	to := hourTs
	resp := summaryResponse{
		GeneratedAt:          now.Format(time.RFC3339),
		WindowSeconds:        int(summaryWindow / time.Second),
		TopRoutes:            []summaryRoute{},
		WafBlocksByCategory:  map[string]uint64{},
		WafDetectsByCategory: map[string]uint64{},
	}

	if h.metrics == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Pull all routes from BoltDB (route catalog is the
	// authority for what to surface; metrics.db may not have
	// rows for idle routes).
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("metrics: list routes failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}

	type rowAgg struct {
		Host         string
		Req          uint64
		Fourxx       uint64
		Fivexx       uint64
		WafBlocked   uint64
		WafDetected  uint64
		LatencyP95Ms int32
	}
	byID := make(map[string]*rowAgg, len(routes))
	for _, rt := range routes {
		byID[rt.ID] = &rowAgg{Host: rt.Host}
	}

	// One Query per route over the 24h window, reading
	// bucket_1h (up to 24 rows per route). Per-route SUM
	// happens in-handler because we want both the per-
	// route aggregates (TopRoutes / TopAttackedRoute) AND
	// the global totals. On a homelab with <100 routes
	// this is ≤ 2400 indexed SELECTs total, well within
	// SQLite's per-request budget.
	//
	// LatencyP95 is req-weighted across the 24 hourly
	// samples per route (within-route) and then across
	// every route's contribution to the global average
	// (cross-route). Both weightings use req_count.
	//
	// Follow-up to commit 579f695: WAF counters (block /
	// detect) are NOT read from the bucket here. They're
	// loaded once below from waf_event via
	// AggregateWafEventsByRoute so the summary's per-route
	// values match wafBlocksByCategory / wafDetectsByCategory
	// exactly. Pre-fix the bucket sums diverged from the
	// category maps because BumpWafDetects only shipped in
	// e7e2905 — every DETECT event before that commit was
	// silently dropped from waf_detect_count while still
	// landing in waf_event. Switching to waf_event for the
	// read path papers over that historical asymmetry
	// (and any future bucket/event drift) at the cost of
	// one extra GROUP BY query per summary call.
	var latencyWeightedSum, latencyWeightDen uint64
	for id := range byID {
		rows, qerr := h.metrics.Query(r.Context(), observability.Granularity1h, id, from, to)
		if qerr != nil {
			h.logger.Error("metrics: summary query failed", "err", qerr, "route", id)
			writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
			return
		}
		if len(rows) == 0 {
			continue
		}
		agg := byID[id]
		for _, row := range rows {
			agg.Req += uint64(row.ReqCount)
			agg.Fourxx += uint64(row.FourxxCount)
			agg.Fivexx += uint64(row.FivexxCount)
			if row.LatencyP95Ms > 0 && row.ReqCount > 0 {
				latencyWeightedSum += uint64(row.LatencyP95Ms) * uint64(row.ReqCount)
				latencyWeightDen += uint64(row.ReqCount)
			}
			if row.LatencyP95Ms > agg.LatencyP95Ms {
				agg.LatencyP95Ms = row.LatencyP95Ms
			}
		}
		resp.TotalReq += agg.Req
		resp.TotalFourXx += agg.Fourxx
		resp.TotalFiveXx += agg.Fivexx
	}

	// Single-source WAF counter read (follow-up to 579f695).
	// One server-side GROUP BY query yields per-route
	// {Block, Detect} counts for the window.
	//
	// Grand totals sum the ENTIRE map (every route_id with
	// activity in the window), not just routes still present
	// in byID — events emitted under a route_id whose route
	// has since been deleted still count toward the system-
	// wide total, and the resulting sum matches the
	// wafBlocksByCategory / wafDetectsByCategory totals
	// exactly (both maps are derived from the same waf_event
	// scan). Per-route overlay only updates routes that are
	// still in the catalog — the TopRoutes / TopAttackedRoute
	// tables are explicitly per-current-route surfaces.
	if h.wafEvents != nil {
		routeCounts, qerr := h.wafEvents.AggregateWafEventsByRoute(r.Context(), from, to)
		if qerr != nil {
			h.logger.Error("metrics: summary waf route aggregate failed", "err", qerr)
			// Don't fail the whole summary — leave WAF
			// counters at zero. Same AC #13 trade-off as the
			// category aggregator below.
		} else {
			for routeID, counts := range routeCounts {
				resp.TotalWafBlocked += counts.Block
				resp.TotalWafDetected += counts.Detect
				if agg, ok := byID[routeID]; ok {
					agg.WafBlocked = counts.Block
					agg.WafDetected = counts.Detect
				}
			}
		}
	}

	if latencyWeightDen > 0 {
		v := float64(latencyWeightedSum) / float64(latencyWeightDen)
		resp.GlobalP95LatencyMs = &v
	}
	// resp.GlobalP95LatencyMs stays nil → JSON null per AC #5
	// when no traffic landed in the window.

	// Step M.2 / #R-WAF-METRICS-WINDOW-1MIN-PROJECTION —
	// Waf{Blocks,Detects}ByCategory. Sourced from the
	// per-event log because the bucket only carries the
	// total. Pre-fix this iterated waf_event row-by-row
	// under wafEventLimitCap=100, which couldn't service a
	// 24h window on a busy day. Post-fix uses the server-
	// side GROUP BY aggregator
	// (AggregateWafEventsByCategory) — two queries
	// (BLOCK + DETECT) per summary call, no row-count
	// ceiling, indexed scan over the window.
	if h.wafEvents != nil {
		fillCategory := func(action string, dest map[string]uint64) {
			rows, qerr := h.wafEvents.AggregateWafEventsByCategory(r.Context(), observability.WafEventCategoryFilter{
				Action: action,
				From:   from,
				To:     to,
			})
			if qerr != nil {
				h.logger.Error("metrics: summary waf category aggregate failed",
					"err", qerr, "action", action)
				return
			}
			for _, agg := range rows {
				dest[agg.Category] = uint64(agg.Count)
			}
		}
		fillCategory("BLOCK", resp.WafBlocksByCategory)
		fillCategory("DETECT", resp.WafDetectsByCategory)
	}

	// Build top-5 by reqs (over the 24h window).
	top := make([]summaryRoute, 0, len(byID))
	for id, agg := range byID {
		if agg.Req == 0 {
			continue
		}
		resp.ActiveRouteCount++
		top = append(top, summaryRoute{
			RouteID:     id,
			Host:        agg.Host,
			Reqs:        agg.Req,
			Fourxx:      agg.Fourxx,
			Fivexx:      agg.Fivexx,
			WafBlocked:  agg.WafBlocked,
			WafDetected: agg.WafDetected,
		})
	}
	sortTopByReqs(top)
	if len(top) > 5 {
		top = top[:5]
	}
	resp.TopRoutes = top

	// Step M.2 amendment — TopAttackedRoute: the single
	// route with the highest WAF block count over the
	// window, computed across ALL routes (NOT filtered to
	// the traffic-ranked top-5). Stays nil when no WAF
	// activity (operator sees an honest zero).
	var topAttacked *summaryRoute
	for id, agg := range byID {
		if agg.WafBlocked == 0 {
			continue
		}
		if topAttacked == nil || agg.WafBlocked > topAttacked.WafBlocked {
			topAttacked = &summaryRoute{
				RouteID:     id,
				Host:        agg.Host,
				Reqs:        agg.Req,
				Fourxx:      agg.Fourxx,
				Fivexx:      agg.Fivexx,
				WafBlocked:  agg.WafBlocked,
				WafDetected: agg.WafDetected,
			}
		}
	}
	resp.TopAttackedRoute = topAttacked

	// Step Q.3 — TotalThrottle: SUM the sentinel route's
	// bucket_1h rows over the window. The observability
	// aggregator stores throttle blocks under route_id =
	// "_throttle" (spec §3.5); the per-route loop above
	// doesn't iterate this sentinel because it's not in
	// the storage.Route catalog.
	throttleRows, qerr := h.metrics.Query(r.Context(), observability.Granularity1h,
		observability.ThrottleSentinelRouteID, from, to)
	if qerr != nil {
		h.logger.Error("metrics: summary throttle sentinel query failed", "err", qerr)
		// Don't fail the whole summary; leave at zero.
	} else {
		for _, row := range throttleRows {
			resp.TotalThrottle += uint64(row.ThrottleBlockCount)
		}
	}

	// Step Z.2 — TotalRateLimitExceeded: COUNT the
	// rate_limit_event rows over the window.
	//
	// Phase Z.4 hotfix : the window here is `[now-24h, now)`
	// — rolling clock-now, NOT the hour-aligned `[hourTs-24h,
	// hourTs)` shared by the bucket-fed counters above. The
	// hour-alignment is load-bearing for bucket_1h reads
	// (rollupHour writes one row per route at the top of each
	// hour, so reading past hourTs would scan rows that don't
	// exist yet), but a raw event table has no aggregation
	// lag — rows land within milliseconds of the 429 emit.
	//
	// Pre-fix the call passed (from, to) and excluded every
	// event in the current in-flight hour : a burst at HH:MM
	// followed by a /dashboard refresh in the same hour
	// surfaced as "0 / 24h" while the events were visible on
	// /logs and queryable via /api/v1/security/rate-limit-
	// events. Operator-confusing — the dashboard summary's job
	// is to surface fresh signal, and this counter is the
	// freshness story for HTTP rate-limit pressure.
	//
	// Other event-table totals (TotalAuthFailures) keep the
	// hour-aligned window because they're sized by a per-
	// query scan cap (summaryAuthFailuresScanCap=...) and the
	// 1-hour alignment naturally caps the worst-case scan
	// shape ; rate-limit's COUNT is unaffected by row
	// position so no such cap applies.
	if h.rateLimitEvents != nil {
		rlFrom := now.Add(-summaryWindow)
		n, rerr := h.rateLimitEvents.CountRateLimitEventsByWindow(r.Context(), rlFrom, now)
		if rerr != nil {
			h.logger.Error("metrics: summary rate_limit_event count failed", "err", rerr)
		} else {
			resp.TotalRateLimitExceeded = uint64(n)
		}
	}

	// Step N.3 — TotalCrowdSecDecisions: SUM the CrowdSec
	// sentinel row(s) over the window (spec N §3.5:
	// "_crowdsec"). Independent of the throttle counter;
	// AC #N.24 anti-regression: a CrowdSec decision does
	// NOT inflate totalThrottle and vice versa.
	crowdsecRows, qerr := h.metrics.Query(r.Context(), observability.Granularity1h,
		observability.CrowdSecSentinelRouteID, from, to)
	if qerr != nil {
		h.logger.Error("metrics: summary crowdsec sentinel query failed", "err", qerr)
	} else {
		for _, row := range crowdsecRows {
			resp.TotalCrowdSecDecisions += uint64(row.CrowdSecDecisionCount)
		}
	}

	// Step Q.3 — TotalAuthFailures: audit-scan over the 24h
	// window (D4.B single source of truth — no bucket
	// counter for this metric). The summary uses a wider
	// scan cap than the recent-feed endpoint because a 24h
	// window legitimately contains more rows.
	if h.authFailures != nil {
		events, _, aerr := h.authFailures.QueryByActionRange(r.Context(),
			audit.AuthFailureActions(), from, to, summaryAuthFailuresScanCap)
		if aerr != nil {
			h.logger.Error("metrics: summary audit auth-failure scan failed", "err", aerr)
		} else {
			resp.TotalAuthFailures = uint64(len(events))
			if len(events) == summaryAuthFailuresScanCap {
				// Hitting the cap means undercount: log
				// once at Debug so operators monitoring
				// growth see it before the dashboard does.
				h.logger.Debug("metrics: summary auth-failure scan hit cap; metric undercounted",
					"cap", summaryAuthFailuresScanCap, "window_hours", int(summaryWindow/time.Hour))
			}
		}
	}

	// Step Q.3 — AttackerIpsUnique: server-side union of
	// WAF + throttle + audit source IPs over the 24h
	// window. Empty IPs filtered (defence-in-depth on the
	// spec §8.5 case).
	attackers := make(map[string]struct{})
	if h.wafEvents != nil {
		ips, werr := h.wafEvents.DistinctWafEventSrcIPs(r.Context(), from, to)
		if werr != nil {
			h.logger.Error("metrics: summary waf distinct ip query failed", "err", werr)
		} else {
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				attackers[ip] = struct{}{}
			}
		}
	}
	if h.throttleEvents != nil {
		ips, terr := h.throttleEvents.DistinctThrottleEventSrcIPs(r.Context(), from, to)
		if terr != nil {
			h.logger.Error("metrics: summary throttle distinct ip query failed", "err", terr)
		} else {
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				attackers[ip] = struct{}{}
			}
		}
	}
	if h.authFailures != nil {
		events, _, aerr := h.authFailures.QueryByActionRange(r.Context(),
			audit.AuthFailureActions(), from, to, summaryAuthFailuresScanCap)
		if aerr != nil {
			// Already logged above for TotalAuthFailures.
		} else {
			for _, e := range events {
				if e.IP == "" {
					continue
				}
				attackers[e.IP] = struct{}{}
			}
		}
	}
	// Step N.3 — CrowdSec arm of the union + the
	// ActiveCrowdSecIpsUnique count. Same shape as the WAF /
	// throttle distinct-IP branches: storage SELECT DISTINCT
	// value over the window.
	if h.decisions != nil {
		ips, derr := h.decisions.DistinctDecisionSrcIPs(r.Context(), from, to)
		if derr != nil {
			h.logger.Error("metrics: summary decision distinct ip query failed", "err", derr)
		} else {
			// Count first (pre-union) for the per-source
			// dashboard card, then merge into the union.
			activeCrowdSecCount := 0
			for _, ip := range ips {
				if ip == "" {
					continue
				}
				activeCrowdSecCount++
				attackers[ip] = struct{}{}
			}
			resp.ActiveCrowdSecIpsUnique = activeCrowdSecCount
		}
	}
	resp.AttackerIpsUnique = len(attackers)

	writeJSON(w, http.StatusOK, resp)
}

// --- helpers -----------------------------------------------------------------

func isValidMetric(m metricName) bool {
	switch m {
	case metricReqPerSec, metricFourXxRate, metricFiveXxRate, metricP95LatencyMs,
		metricWafBlockRate, metricThrottleBlockRate, metricAuthFailureRate,
		metricCrowdSecDecisionRate, metricRateLimitRate:
		return true
	}
	return false
}

func windowParams(window string) (gran observability.Granularity, step time.Duration, windowDur time.Duration, ok bool) {
	switch window {
	case "24h":
		return observability.Granularity1m, time.Minute, 24 * time.Hour, true
	case "30d":
		return observability.Granularity1h, time.Hour, 30 * 24 * time.Hour, true
	}
	return 0, 0, 0, false
}

// gapFillAuthFailureTimeseries projects a slice of audit
// events (reverse-chronological, action-filtered by the
// caller) into a dense timeseries of count-per-step buckets
// over [from, to). Step Q.3: powers the
// /metrics/timeseries?metric=auth_failure_rate detour. The
// 24h window uses step=1m (1440 buckets), the 30d window uses
// step=1h (720 buckets). Same gap-fill rule as the count
// metrics: empty bucket emits 0 (not nil).
//
// Mirror of projectAuthFailureTimeseries in
// security_handlers.go, generalised for variable step. Kept
// separate so the auth-failures dashboard endpoint stays
// per-minute-only (its frontend chart depends on it) while
// the /metrics/timeseries endpoint can serve both
// granularities through the same path.
func gapFillAuthFailureTimeseries(events []audit.Event, from, to time.Time, step time.Duration) []timeseriesPoint {
	fromBucket := from.UTC().Truncate(step)
	toBucket := to.UTC().Truncate(step)
	if !toBucket.After(fromBucket) {
		return []timeseriesPoint{}
	}
	bucketCount := int(toBucket.Sub(fromBucket) / step)
	if bucketCount <= 0 {
		return []timeseriesPoint{}
	}
	counts := make([]int, bucketCount)
	for _, e := range events {
		ts := e.Timestamp.UTC().Truncate(step)
		if ts.Before(fromBucket) || !ts.Before(toBucket) {
			continue
		}
		idx := int(ts.Sub(fromBucket) / step)
		if idx < 0 || idx >= bucketCount {
			continue
		}
		counts[idx]++
	}
	out := make([]timeseriesPoint, bucketCount)
	for i := 0; i < bucketCount; i++ {
		v := float64(counts[i])
		out[i] = timeseriesPoint{
			Ts:    fromBucket.Add(time.Duration(i) * step).Format(time.RFC3339),
			Value: &v,
		}
	}
	return out
}

// gapFillAuthFailureZero is the all-zero variant of
// gapFillAuthFailureTimeseries — used when route=<uuid> for
// the auth_failure_rate metric (AC #10 "per-route returns
// all-zero"). Cheap: skip the events scan entirely.
func gapFillAuthFailureZero(from, to time.Time, step time.Duration) []timeseriesPoint {
	fromBucket := from.UTC().Truncate(step)
	toBucket := to.UTC().Truncate(step)
	if !toBucket.After(fromBucket) {
		return []timeseriesPoint{}
	}
	bucketCount := int(toBucket.Sub(fromBucket) / step)
	if bucketCount <= 0 {
		return []timeseriesPoint{}
	}
	out := make([]timeseriesPoint, bucketCount)
	for i := 0; i < bucketCount; i++ {
		v := 0.0
		out[i] = timeseriesPoint{
			Ts:    fromBucket.Add(time.Duration(i) * step).Format(time.RFC3339),
			Value: &v,
		}
	}
	return out
}

// gapFillTimeseries projects sparse Store rows into a dense slice
// of timeseriesPoint covering [from, to) at the given step. The
// AC #5 gap-fill rule lives here:
//   - count metrics (req / 4xx / 5xx) → missing buckets emit 0
//   - p95 metric → missing buckets emit null (Value=nil)
//
// The map lookup makes the projection O(N+M) where N is the
// dense slot count and M is the row count.
func gapFillTimeseries(rows []observability.MetricBucket, from, to time.Time, step time.Duration, metric metricName) []timeseriesPoint {
	byTs := make(map[int64]observability.MetricBucket, len(rows))
	for _, r := range rows {
		byTs[r.Ts.Unix()] = r
	}
	slots := int(to.Sub(from) / step)
	out := make([]timeseriesPoint, 0, slots)
	for slot := 0; slot < slots; slot++ {
		ts := from.Add(time.Duration(slot) * step)
		row, hit := byTs[ts.Unix()]
		out = append(out, timeseriesPoint{
			Ts:    ts.Format(time.RFC3339),
			Value: pickMetricValue(row, hit, metric),
		})
	}
	return out
}

// pickMetricValue extracts the requested metric from a bucket
// row, applying the AC #5 null-for-p95-gap rule.
//
//	hit=false (missing bucket):
//	  counts → 0 (real measurement: zero traffic)
//	  p95    → nil (no traffic = no latency; nil renders as null)
//	hit=true:
//	  counts → row value as float64
//	  p95    → row value if > 0, else nil (the row exists but
//	           no latency observation landed in it; treat
//	           identically to a missing bucket)
func pickMetricValue(row observability.MetricBucket, hit bool, metric metricName) *float64 {
	if !hit {
		if metric == metricP95LatencyMs {
			return nil
		}
		v := 0.0
		return &v
	}
	switch metric {
	case metricReqPerSec:
		v := float64(row.ReqCount)
		return &v
	case metricFourXxRate:
		v := float64(row.FourxxCount)
		return &v
	case metricFiveXxRate:
		v := float64(row.FivexxCount)
		return &v
	case metricWafBlockRate:
		v := float64(row.WafBlockCount)
		return &v
	case metricThrottleBlockRate:
		v := float64(row.ThrottleBlockCount)
		return &v
	case metricCrowdSecDecisionRate:
		v := float64(row.CrowdSecDecisionCount)
		return &v
	case metricRateLimitRate:
		v := float64(row.RateLimitCount)
		return &v
	case metricP95LatencyMs:
		if row.LatencyP95Ms <= 0 {
			return nil
		}
		v := float64(row.LatencyP95Ms)
		return &v
	}
	return nil
}

// sortTopByReqs sorts the slice in-place by Reqs
// descending. Inline insertion sort — bounded by the
// number of active routes (typically <100 on a homelab);
// avoids importing sort just for one site.
func sortTopByReqs(s []summaryRoute) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j].Reqs > s[j-1].Reqs; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// routeSummaryResponse is the wire shape of
// GET /api/v1/metrics/route-summary?route=<uuid> — the 24h
// traffic aggregate for ONE route.
//
// Why this exists rather than reading metricsSummary's
// TopRoutes: that list is hard-truncated to the five busiest
// routes (see the `top = top[:5]` above). A per-route surface
// fed from it would show real numbers for five routes and
// silent zeros for every other one, which is worse than no
// numbers at all. The aggregation itself is the same — one
// indexed read of bucket_1h over at most 24 rows — so a
// single-route endpoint costs one SELECT instead of one per
// route plus the WAF, CrowdSec and audit work the full
// summary also does.
//
// The window boundaries are computed exactly as metricsSummary
// computes them (summaryWindow back from the top of the
// current hour) so the two surfaces can never disagree about
// what "last 24 hours" means.
//
// AC #6 carries forward: Fourxx and Fivexx stay independent
// fields, never collapsed into one "errors" number.
type routeSummaryResponse struct {
	RouteID       string `json:"routeId"`
	GeneratedAt   string `json:"generatedAt"`
	WindowSeconds int    `json:"windowSeconds"`
	// Disabled mirrors summaryResponse.Disabled: true when the
	// observability subsystem failed at boot. Counters stay at
	// zero and the UI renders "unavailable", not an error.
	Disabled bool   `json:"disabled,omitempty"`
	Reqs     uint64 `json:"reqs"`
	Fourxx   uint64 `json:"fourxx"`
	Fivexx   uint64 `json:"fivexx"`
	// P95LatencyMs is the request-weighted mean of the hourly
	// p95 samples in the window, using the same weighting as
	// summaryResponse.GlobalP95LatencyMs. It is NOT a true 24h
	// p95: that cannot be recovered from pre-aggregated
	// percentiles. null when the route served no traffic with a
	// recorded latency, so the UI shows "—" rather than 0 ms,
	// which would read as "instant".
	P95LatencyMs *float64 `json:"p95LatencyMs"`
}

// metricsRouteSummary handles
// GET /api/v1/metrics/route-summary?route=<uuid>.
//
// Unlike metricsTimeseries it takes no `window` parameter:
// the single window is summaryWindow, shared with
// metricsSummary. Unlike metricsSummary it takes no "all"
// sentinel — callers wanting the system-wide totals already
// have /metrics/summary, and accepting the sentinel here would
// duplicate that surface with a narrower shape.
func (h *Handler) metricsRouteSummary(w http.ResponseWriter, r *http.Request) {
	routeID := r.URL.Query().Get("route")
	if routeID == "" {
		writeError(w, http.StatusBadRequest, "route is required")
		return
	}
	if routeID == routeAllSentinel {
		writeError(w, http.StatusBadRequest, "route must be a route ID; use /metrics/summary for the global totals")
		return
	}

	// 404 before touching metrics.db: an unknown route ID must
	// not come back as a plausible row of zeros.
	if _, err := h.store.GetRoute(r.Context(), routeID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("metrics: route summary lookup failed", "err", err, "route", routeID)
		writeError(w, http.StatusServiceUnavailable, "storage unavailable")
		return
	}

	now := time.Now().UTC()
	resp := routeSummaryResponse{
		RouteID:       routeID,
		GeneratedAt:   now.Format(time.RFC3339),
		WindowSeconds: int(summaryWindow / time.Second),
	}

	if h.metrics == nil {
		resp.Disabled = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	hourTs := now.Truncate(time.Hour)
	from := hourTs.Add(-summaryWindow)
	to := hourTs

	rows, err := h.metrics.Query(r.Context(), observability.Granularity1h, routeID, from, to)
	if err != nil {
		h.logger.Error("metrics: route summary query failed", "err", err, "route", routeID)
		writeError(w, http.StatusServiceUnavailable, "metrics history unavailable")
		return
	}

	var latencyWeightedSum, latencyWeightDen uint64
	for _, row := range rows {
		resp.Reqs += uint64(row.ReqCount)
		resp.Fourxx += uint64(row.FourxxCount)
		resp.Fivexx += uint64(row.FivexxCount)
		if row.LatencyP95Ms > 0 && row.ReqCount > 0 {
			latencyWeightedSum += uint64(row.LatencyP95Ms) * uint64(row.ReqCount)
			latencyWeightDen += uint64(row.ReqCount)
		}
	}
	if latencyWeightDen > 0 {
		p95 := float64(latencyWeightedSum) / float64(latencyWeightDen)
		resp.P95LatencyMs = &p95
	}

	writeJSON(w, http.StatusOK, resp)
}
