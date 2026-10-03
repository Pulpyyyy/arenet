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

import "github.com/barto95100/arenet/internal/storage"

// Aggregate-status enum values for routeResponse.AggregateStatus.
// Kept as untyped string constants so the JSON wire output matches
// exactly what the frontend's Route.aggregateStatus union expects.
const (
	routeStatusHealthy  = "healthy"
	routeStatusDegraded = "degraded"
	routeStatusDown     = "down"
	routeStatusUnknown  = "unknown"
	// routeStatusNotMonitored (2026-06-25) — operator UX
	// improvement. Pre-this : a route whose HC was disabled
	// returned routeStatusUnknown, indistinguishable in the
	// UI from "HC enabled but warm-up window" (no event yet).
	// Operator couldn't tell whether a gray badge meant "I
	// chose not to monitor" or "I monitor but I don't know yet".
	// Splitting the enum lets the frontend render a distinct
	// "HC inactif" label + tooltip for the deliberate-off case
	// while keeping "unknown" for the genuine warm-up case.
	routeStatusNotMonitored = "not_monitored"
	// routeStatusNotApplicable (v2.59) — a route that proxies
	// nothing has no health to report. A redirecting route is the
	// case that exists today: it answers a 301/302 from Caddy
	// itself, it carries no upstream (storage permits an empty pool
	// for it since v2.45.2) and nothing will ever probe anything.
	//
	// It used to return routeStatusUnknown, which the UI renders as
	// "HC enabled but no signal yet (warm-up window)" — a warm-up
	// that can never end, on a route with no HC and no backend. The
	// enum was lying, so every consumer of it lied too; fixing the
	// frontend alone would have left the same wrong value on the
	// wire for the next caller.
	routeStatusNotApplicable = "not_applicable"
)

// computeRouteAggregateHealth derives the per-route health rollup
// from the per-upstream HC tracker. Pure function — no I/O —
// dropped into its own file so the unit tests cover the precedence
// table without needing to stand up the full Handler.
//
// Precedence (mirrors the Critique 11 Pack A spec and the
// Topology C13 gate contract). The key invariant: the unhealthy
// signal is ALWAYS strong enough to suppress green, even when
// some upstreams are still in the warm-up window. We never claim
// "healthy" while any unhealthy upstream is recorded.
//
//   1. Route has no HealthCheck configured           → "unknown"
//      (the C13 gate: don't paint green or red on an upstream
//      the operator chose not to monitor, regardless of any
//      stale state the tracker might be carrying.)
//   2. Route proxies nothing (redirect)             → "not_applicable"
//      (no upstream by design, nothing to probe, ever. A route
//      with no upstream and no redirect either — a shape no
//      endpoint can produce — keeps the old "unknown" fallback.)
//   3. unhealthyCount == total AND no warm-up        → "down"
//      (every upstream observed AND every one unhealthy.)
//   4. unhealthyCount > 0                            → "degraded"
//      (any unhealthy signal degrades the route, whether or not
//      other upstreams are healthy or still warming up.)
//   5. healthyCount == total                         → "healthy"
//      (full confidence — every upstream observed AND healthy.)
//   6. Otherwise — partial coverage with no unhealthy signal
//      yet (warm-up window)                          → "unknown"
//
// Returns (status, healthyCount, totalCount). Counts always
// reflect the actual upstream pool sizes regardless of HC config,
// so the frontend can render "N/M sains" with consistent
// denominators even on unmonitored routes (where N is always 0).
//
// `status` may be nil — callers must tolerate that to keep the
// pre-Pack-A no-tracker-installed code path identical to "no HC
// configured" (collapses to unknown).
func computeRouteAggregateHealth(r storage.Route, status HCStatusReader) (string, int, int) {
	total := len(r.Upstreams)
	// v2.59 — a redirecting route is checked FIRST, and on the
	// redirect itself rather than on the empty pool: the state is
	// what makes health inapplicable, not the arithmetic. The
	// zero-pool branch below stays a genuine defensive fallback.
	if r.RedirectConfig != nil {
		return routeStatusNotApplicable, 0, 0
	}
	if total == 0 {
		return routeStatusUnknown, 0, 0
	}
	// C13 gate: no probe configured → status is honestly
	// "not monitored" (operator deliberately disabled HC).
	// We don't even touch the tracker — what's there can only
	// be stale. Distinct from routeStatusUnknown which is
	// reserved for HC-enabled-but-warm-up-window (we'd know
	// the status if we'd observed enough probes).
	if !r.HealthCheck.Enabled {
		return routeStatusNotMonitored, 0, total
	}
	if status == nil {
		return routeStatusUnknown, 0, total
	}

	healthy := 0
	unhealthy := 0
	for _, u := range r.Upstreams {
		switch status.Status(u.URL) {
		case routeStatusHealthy:
			healthy++
		case "unhealthy":
			unhealthy++
		default:
			// "" (warm-up) or any unrecognised string — not yet
			// observed. Counted as neither healthy nor unhealthy
			// so it can degrade the aggregate to "unknown" if
			// nothing else surfaces.
		}
	}

	// Precedence rules — see docstring for the full table. Order
	// matters: down requires full coverage AND every-unhealthy;
	// any unhealthy at all flips to degraded; full-healthy with
	// zero warm-up is the only path to a green badge.
	switch {
	case unhealthy == total:
		return routeStatusDown, 0, total
	case unhealthy > 0:
		return routeStatusDegraded, healthy, total
	case healthy == total:
		return routeStatusHealthy, healthy, total
	default:
		// Partial warm-up with no unhealthy signal yet. The
		// frontend renders gray + the count of confirmed-healthy
		// upstreams so the operator can see "2/3 sains" even
		// while the route as a whole is still warming up.
		return routeStatusUnknown, healthy, total
	}
}
