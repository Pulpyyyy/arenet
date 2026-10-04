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

package topology

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// StatusLookup is the interface the snapshot builder uses to
// resolve per-upstream health. CaddyStatusProber satisfies this
// directly; tests pass a stub.
type StatusLookup interface {
	Status(upstreamURL string) string
}

// noopStatusLookup is the fallback when no prober is supplied —
// every upstream reports "unknown", which matches the spec's
// graceful-degradation contract (the field is still present and
// well-typed, just informationless).
type noopStatusLookup struct{}

func (noopStatusLookup) Status(string) string { return StatusUnknown }

// MetricsView is the read-only view of the SlidingWindow that
// BuildSnapshot needs. Defined as an interface so callers can stub
// in tests without standing up a full window.
type MetricsView interface {
	Aggregate(routeID string) Aggregate
	// AggregateByHost is the per-(routeID, host) windowed view.
	// Topology Plan B Phase 2.2 addition. Unknown pairs return
	// the zero Aggregate (idle alias case). *SlidingWindow
	// satisfies this directly; the noopMetricsView fallback
	// satisfies it via the zero return.
	AggregateByHost(routeID, host string) Aggregate
}

// BuildSnapshot joins the storage route list with the windowed
// metrics and per-upstream Caddy status into the wire-shape
// SnapshotResponse. Stage A behaviour for synthesised per-upstream
// fields is locked here:
//
//   - The route-level reqPerSec is split across upstreams
//     proportional to configured Weight (storage.Upstream.Weight).
//     When every weight is the same (round_robin default
//     post-J.1 = Weight 1 per backend), the split is even.
//   - p99LatencyMs on every upstream mirrors the route-level p95
//     (Stage A substitute — see types.go docstring).
//   - fairnessRatio is the same weight share, sums to ≈ 1.0 across
//     the cluster by construction.
//   - status comes from the Caddy admin probe; "unknown" when the
//     probe is unavailable or the upstream hasn't seen traffic yet.
//   - runtime is omitted (no source today).
//   - mtlsRequired stays false (no source today).
//
// The function never returns an error — degraded inputs (empty
// route list, nil metrics view, nil status lookup) all yield a
// well-formed, possibly-empty SnapshotResponse. The caller (HTTP
// handler / WS frame writer) does the I/O.
//
// now is the wall-clock for GeneratedAt. Passing it in rather
// than calling time.Now lets tests pin a deterministic value
// without ambient state.
func BuildSnapshot(
	routes []storage.Route,
	metrics MetricsView,
	status StatusLookup,
	now time.Time,
) SnapshotResponse {
	if metrics == nil {
		metrics = noopMetricsView{}
	}
	if status == nil {
		status = noopStatusLookup{}
	}

	out := SnapshotResponse{
		GeneratedAt: now.UTC(),
		Routes:      make([]Route, 0, len(routes)),
	}
	for i := range routes {
		out.Routes = append(out.Routes, buildRoute(&routes[i], metrics, status))
	}
	return out
}

// buildRoute is the per-route projection. Split out so the
// (route, metrics, status) ternary is testable independently of
// the storage list iteration.
//
// Stage B status policy (post-#R-TOPO-real-health-probe,
// 2026-06-04): routes with HealthCheck.Enabled true consult the
// StatusLookup, now satisfied by *caddyhc.HCStatusTracker. The
// tracker captures Caddy's active-health-checker "healthy" /
// "unhealthy" events as they happen — see caddyhc package docs.
//
// Routes WITHOUT a configured health check still report
// StatusUnknown unconditionally, regardless of any state the
// tracker might be carrying. Two reasons:
//  1. The tracker has no way to forget addresses when the
//     operator removes a health check from a route — stale state
//     could otherwise paint green/red on an upstream that is no
//     longer being probed (the original misleading-green case
//     from #R-TOPO-health-coherence).
//  2. HealthCheckConfigured is the honest signal "this upstream
//     is being watched"; respecting it as the gate keeps the
//     Stage B semantics consistent with the v1.1.0 contract the
//     Activity glyph + accent stripe were built around.
//
// The lookup returns the empty string ("" / StatusUnknown) for
// addresses it hasn't seen yet (warm-up window between Caddy
// reload and the first probe outcome). The builder maps that
// path-through transparently — wire shape stays well-typed.
func buildRoute(r *storage.Route, metrics MetricsView, status StatusLookup) Route {
	if metrics == nil {
		metrics = noopMetricsView{}
	}
	if status == nil {
		status = noopStatusLookup{}
	}
	agg := metrics.Aggregate(r.ID)
	aliasMetrics := buildAliasMetrics(r.ID, r.Aliases, metrics)
	out := Route{
		ID:           r.ID,
		Host:         r.Host,
		Aliases:      cloneStrings(r.Aliases),
		AliasMetrics: aliasMetrics,
		LBPolicy:     r.LBPolicy,
		ReqPerSec:    agg.ReqPerSec,
		P99LatencyMs: agg.P95LatencyMs, // p95 substitute, see types doc
		ErrorRate5xx: agg.ErrorRate5xx,
		TLSEnabled:   r.TLSEnabled,
		Disabled:     r.Disabled,
		WAFLevel:     r.WAFMode,
		// rateLimited and mtlsRequired: see Stage A docstring on
		// types.Route. rateLimited derivation will land when
		// storage.Route exposes a per-route rate-limit flag;
		// today the rate-limit handler is global (Step Q.4 +
		// S.4 lift to /api/v1) so there is no per-route bit to
		// map. We surface false rather than fabricate.
		RateLimited:    false,
		MTLSRequired:   false,
		HTTPRedirect:   r.RedirectToHTTPS,
		HasHealthCheck: r.HealthCheck.Enabled,
		ClusterLabel:   r.Host,
	}

	// v2.61 — a redirecting route's destination, so the canvas can draw
	// where the traffic goes instead of an empty cluster complaining
	// that no upstream is configured.
	if r.RedirectConfig != nil {
		out.RedirectTarget = r.RedirectConfig.Target
	}

	// Build the upstream list via the shared conversion helper (also
	// used by the path-pool loop below).
	out.Upstreams = buildUpstreams(r.Upstreams, r.ID, agg, r.HealthCheck.Enabled, status)

	// Path pools (v2.24.0): one branch per path-rule that declares its own
	// pool (B2 — protection-only rules are skipped). Structure only; the
	// path pool's upstreams reuse the same conversion but there is no
	// per-path metric today, so agg is the route aggregate (the frontend
	// treats path-pool clusters as structural, not traffic-animated).
	for pi, pr := range r.PathRules {
		if len(pr.Upstreams) == 0 {
			continue
		}
		out.PathPools = append(out.PathPools, PathPool{
			PathPrefix:         pr.PathPrefix,
			Upstreams:          buildUpstreams(pr.Upstreams, fmt.Sprintf("%s-path-%d", r.ID, pi), agg, false, status),
			LBPolicy:           pr.LBPolicy,
			InsecureSkipVerify: pr.InsecureSkipVerify,
		})
	}
	return out
}

// buildUpstreams converts a storage upstream pool into topology.Upstream
// rows, applying the weight-split reqPerSec share and the HC-gated status.
// idPrefix namespaces the per-upstream ID (route ID for the root pool,
// "routeID-path-N" for a path pool). agg is the route-level aggregate the
// share is computed against; hcEnabled gates status lookup.
func buildUpstreams(pool []storage.Upstream, idPrefix string, agg Aggregate, hcEnabled bool, status StatusLookup) []Upstream {
	totalWeight := 0
	for _, u := range pool {
		w := u.Weight
		if w <= 0 {
			w = 1 // storage validation guarantees >=1 but be defensive
		}
		totalWeight += w
	}
	if totalWeight == 0 {
		// Zero upstreams is forbidden by storage validation, but be
		// defensive — return an empty upstream slice rather than
		// divide-by-zero.
		return []Upstream{}
	}
	out := make([]Upstream, 0, len(pool))
	for i, u := range pool {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		share := float64(w) / float64(totalWeight)
		// Stage B: consult the tracker only when the pool has a
		// configured probe. The HC-gate avoids the stale-state
		// misleading-green case described in the buildRoute
		// docstring.
		upstreamStatus := StatusUnknown
		if hcEnabled {
			if s := status.Status(u.URL); s != "" {
				upstreamStatus = s
			}
		}
		out = append(out, Upstream{
			ID:                    fmt.Sprintf("%s-%d", idPrefix, i),
			URL:                   u.URL,
			Status:                upstreamStatus,
			HealthCheckConfigured: hcEnabled,
			ReqPerSec:             agg.ReqPerSec * share,
			P99LatencyMs:          agg.P95LatencyMs,
			FairnessRatio:         share,
		})
	}
	return out
}

// cloneStrings deep-copies a []string so the response doesn't
// alias the storage layer's slice. Cheap (single allocation per
// route per emit) and keeps the contract clean.
func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// noopMetricsView is the fallback when no window is supplied.
// Every route looks idle.
type noopMetricsView struct{}

func (noopMetricsView) Aggregate(string) Aggregate               { return Aggregate{} }
func (noopMetricsView) AggregateByHost(string, string) Aggregate { return Aggregate{} }

// buildAliasMetrics assembles the per-alias breakdown for a
// single route. Topology Plan B Phase 2.2.
//
// Returns a non-nil, possibly-empty slice so the wire shape is
// always `aliasMetrics: []` rather than `aliasMetrics: null`
// (the Route.AliasMetrics field is intentionally NOT
// omitempty — see types.go docstring on the empty-vs-absent
// distinction).
//
// Sort order: ReqPerSec descending so the operator-visible
// "top consumers" appear first. Idle aliases (0 req/s — either
// no traffic yet OR a configured-but-never-hit alias) sort to
// the end. A stable secondary sort on the alias hostname
// alphabetically gives the list a deterministic order across
// ticks for aliases that share the same req/s (very common at
// the 0-rate idle case).
//
// Host lookup uses the canonical lowercased form to match the
// Phase 1 middleware's resolveHost — caddymgr emits lowercased
// known_hosts (Phase 2.1) and the middleware bumps cells under
// the lowercased key, so the AggregateByHost lookup MUST
// lowercase the alias too. storage.Route.Aliases may carry
// mixed-case operator input that we lowercase at lookup time.
func buildAliasMetrics(routeID string, aliases []string, metrics MetricsView) []Alias {
	out := make([]Alias, 0, len(aliases))
	for _, a := range aliases {
		key := strings.ToLower(strings.TrimSpace(a))
		if key == "" {
			continue
		}
		agg := metrics.AggregateByHost(routeID, key)
		out = append(out, Alias{
			Host:         a, // preserve the operator's original casing on the wire
			ReqPerSec:    agg.ReqPerSec,
			P99LatencyMs: agg.P95LatencyMs,
			ErrorRate5xx: agg.ErrorRate5xx,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ReqPerSec != out[j].ReqPerSec {
			return out[i].ReqPerSec > out[j].ReqPerSec
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// HostBasename returns the part of host before the first dot.
// Used by callers that want a short cluster label (e.g.
// "api.arenet.fr" -> "api"). Currently the builder doesn't
// strip — frontend can decide. Exported for the (eventual)
// place that wants the short form without re-implementing the
// strip; kept here so the contract has a single owner.
func HostBasename(host string) string {
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[:i]
	}
	return host
}
