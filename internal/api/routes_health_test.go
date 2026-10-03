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
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// stubHCStatus implements HCStatusReader with a canned per-URL
// map. Missing keys return "" (== unknown / warm-up window),
// matching the contract of the real *caddyhc.HCStatusTracker.
type stubHCStatus map[string]string

func (s stubHCStatus) Status(addr string) string { return s[addr] }

func hcRoute(urls ...string) storage.Route {
	ups := make([]storage.Upstream, 0, len(urls))
	for _, u := range urls {
		ups = append(ups, storage.Upstream{URL: u, Weight: 1})
	}
	return storage.Route{
		ID:        "r",
		Host:      "h.example",
		LBPolicy:  "round_robin",
		Upstreams: ups,
		HealthCheck: storage.HealthCheck{
			Enabled: true,
			URI:     "/healthz",
		},
	}
}

func TestComputeRouteAggregateHealth_AllHealthy(t *testing.T) {
	r := hcRoute("http://10.0.0.1:80", "http://10.0.0.2:80")
	s := stubHCStatus{
		"http://10.0.0.1:80": "healthy",
		"http://10.0.0.2:80": "healthy",
	}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusHealthy {
		t.Errorf("status = %q, want %q", got, routeStatusHealthy)
	}
	if healthy != 2 || total != 2 {
		t.Errorf("counts = (%d, %d), want (2, 2)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_AllUnhealthyDown(t *testing.T) {
	r := hcRoute("http://10.0.0.1:80", "http://10.0.0.2:80")
	s := stubHCStatus{
		"http://10.0.0.1:80": "unhealthy",
		"http://10.0.0.2:80": "unhealthy",
	}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusDown {
		t.Errorf("status = %q, want %q", got, routeStatusDown)
	}
	if healthy != 0 || total != 2 {
		t.Errorf("counts = (%d, %d), want (0, 2)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_MixedDegraded(t *testing.T) {
	r := hcRoute("http://10.0.0.1:80", "http://10.0.0.2:80")
	s := stubHCStatus{
		"http://10.0.0.1:80": "healthy",
		"http://10.0.0.2:80": "unhealthy",
	}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusDegraded {
		t.Errorf("status = %q, want %q", got, routeStatusDegraded)
	}
	if healthy != 1 || total != 2 {
		t.Errorf("counts = (%d, %d), want (1, 2)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_UnhealthyWithWarmupStillDegraded(t *testing.T) {
	// Critical edge case: 1 unhealthy + 1 not-yet-observed must
	// NOT collapse to "unknown" — the unhealthy signal is strong
	// enough to flip the aggregate to degraded even when we
	// don't yet have a verdict on every upstream.
	r := hcRoute("http://10.0.0.1:80", "http://10.0.0.2:80")
	s := stubHCStatus{
		"http://10.0.0.1:80": "unhealthy",
		// 10.0.0.2 absent → tracker returns "" (warm-up)
	}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusDegraded {
		t.Errorf("status = %q, want %q (unhealthy + warm-up)", got, routeStatusDegraded)
	}
	if healthy != 0 || total != 2 {
		t.Errorf("counts = (%d, %d), want (0, 2)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_AllUnknownWarmup(t *testing.T) {
	// Boot/warm-up: HC enabled, no events observed yet for any
	// upstream. Must report unknown, not healthy (no green lie)
	// and not down (no red lie).
	r := hcRoute("http://10.0.0.1:80", "http://10.0.0.2:80")
	s := stubHCStatus{} // no entries
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusUnknown {
		t.Errorf("status = %q, want %q", got, routeStatusUnknown)
	}
	if healthy != 0 || total != 2 {
		t.Errorf("counts = (%d, %d), want (0, 2)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_PartialHealthyPartialWarmup(t *testing.T) {
	// 1 healthy + 1 warm-up + 0 unhealthy. Spec: don't claim
	// healthy until every upstream is confirmed; surface unknown
	// with the partial count so the frontend can render "1/2".
	r := hcRoute("http://10.0.0.1:80", "http://10.0.0.2:80")
	s := stubHCStatus{
		"http://10.0.0.1:80": "healthy",
	}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusUnknown {
		t.Errorf("status = %q, want %q (partial coverage)", got, routeStatusUnknown)
	}
	if healthy != 1 || total != 2 {
		t.Errorf("counts = (%d, %d), want (1, 2)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_NoHCConfiguredGate(t *testing.T) {
	// C13 gate: a route without HealthCheck.Enabled must report
	// "not_monitored" — distinct from "unknown" which is reserved
	// for HC-enabled-but-warm-up. The split lets the UI render a
	// clear "HC inactif" label vs the genuine "still observing"
	// gray badge (2026-06-25 operator UX request).
	r := storage.Route{
		ID:        "r",
		Host:      "h.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
		// HealthCheck: zero-value (Enabled = false)
	}
	s := stubHCStatus{
		"http://10.0.0.1:80": "healthy",
	}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusNotMonitored {
		t.Errorf("status = %q, want %q (C13 gate must mask tracker state with the distinct not_monitored label)",
			got, routeStatusNotMonitored)
	}
	// healthyCount stays at 0 for unmonitored routes — we
	// deliberately don't peek at the tracker through the gate.
	if healthy != 0 {
		t.Errorf("healthyCount = %d, want 0 (gated route)", healthy)
	}
	if total != 1 {
		t.Errorf("totalCount = %d, want 1", total)
	}
}

func TestComputeRouteAggregateHealth_NilStatusReader(t *testing.T) {
	// Nil-tolerance: pre-Pack-A wiring left hcStatus unset on the
	// Handler. The aggregate must collapse to unknown, matching
	// the behaviour the gate produces for unmonitored routes.
	r := hcRoute("http://10.0.0.1:80")
	got, healthy, total := computeRouteAggregateHealth(r, nil)
	if got != routeStatusUnknown {
		t.Errorf("status = %q, want %q (nil reader)", got, routeStatusUnknown)
	}
	if healthy != 0 || total != 1 {
		t.Errorf("counts = (%d, %d), want (0, 1)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_SingleUpstreamHealthy(t *testing.T) {
	r := hcRoute("http://10.0.0.1:80")
	s := stubHCStatus{"http://10.0.0.1:80": "healthy"}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusHealthy {
		t.Errorf("status = %q, want %q", got, routeStatusHealthy)
	}
	if healthy != 1 || total != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_SingleUpstreamUnhealthy(t *testing.T) {
	r := hcRoute("http://10.0.0.1:80")
	s := stubHCStatus{"http://10.0.0.1:80": "unhealthy"}
	got, healthy, total := computeRouteAggregateHealth(r, s)
	if got != routeStatusDown {
		t.Errorf("status = %q, want %q (single upstream unhealthy → down, not degraded)", got, routeStatusDown)
	}
	if healthy != 0 || total != 1 {
		t.Errorf("counts = (%d, %d), want (0, 1)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_RedirectRouteNotApplicable(t *testing.T) {
	// v2.59 — a redirecting route answers from Caddy itself and
	// carries no upstream (storage permits the empty pool for it
	// since v2.45.2). It used to fall into the zero-pool branch
	// and come back "unknown", which the UI renders as "HC enabled
	// but no signal yet (warm-up window)": a warm-up that can
	// never close, on a route with neither HC nor backend.
	//
	// HealthCheck.Enabled is deliberately true here: even an
	// operator who left the HC block on gets "not applicable",
	// because the redirect state is what makes health meaningless,
	// not the HC toggle.
	r := storage.Route{
		ID:       "r",
		Host:     "old.example.com",
		LBPolicy: "round_robin",
		RedirectConfig: &storage.RedirectConfig{
			Target: "https://new.example.com",
		},
		HealthCheck: storage.HealthCheck{Enabled: true},
	}
	got, healthy, total := computeRouteAggregateHealth(r, stubHCStatus{})
	if got != routeStatusNotApplicable {
		t.Errorf("status = %q, want %q (redirecting route)", got, routeStatusNotApplicable)
	}
	if healthy != 0 || total != 0 {
		t.Errorf("counts = (%d, %d), want (0, 0)", healthy, total)
	}
}

func TestComputeRouteAggregateHealth_EmptyUpstreams(t *testing.T) {
	// Defensive, and genuinely so: since v2.45.2 storage accepts
	// an empty pool on a REDIRECTING route (covered above), so
	// this branch now means "no upstream and no redirect either" —
	// a shape no endpoint can produce. The helper must not panic
	// on it. Total is 0; no point talking about "healthy/0".
	//
	// The comment here used to read "storage validation forbids
	// empty pools", which stopped being true in v2.45.2 and would
	// have sent the next reader looking for a guarantee that no
	// longer exists.
	r := storage.Route{
		ID:        "r",
		Host:      "h.example",
		LBPolicy:  "round_robin",
		Upstreams: nil,
		HealthCheck: storage.HealthCheck{Enabled: true},
	}
	got, healthy, total := computeRouteAggregateHealth(r, stubHCStatus{})
	if got != routeStatusUnknown {
		t.Errorf("status = %q, want %q (empty pool)", got, routeStatusUnknown)
	}
	if healthy != 0 || total != 0 {
		t.Errorf("counts = (%d, %d), want (0, 0)", healthy, total)
	}
}
