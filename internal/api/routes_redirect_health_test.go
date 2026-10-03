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
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// The wire test for the v2.59 aggregate-status fix. The typed test in
// routes_health_test.go pins computeRouteAggregateHealth; this one pins
// what a client actually reads off the socket, because the frontend
// switches on the literal string and a typed test cannot catch a
// serializer that drops or renames the field. (The lesson of the
// camelCase mismatch that 13 typed tests missed.)
func TestRouteResponse_RedirectRoute_AggregateStatusIsNotApplicable(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:     "old.example.com",
		LBPolicy: storage.LBPolicyRoundRobin,
		RedirectConfig: &storage.RedirectConfig{
			Target:       "https://new.example.com",
			StatusCode:   301,
			PreservePath: true,
		},
	})
	if err != nil {
		t.Fatalf("create redirecting route: %v", err)
	}

	m := getRouteJSON(t, env, created.ID)

	got, present := m["aggregateStatus"]
	if !present {
		t.Fatal(`response has no "aggregateStatus" key`)
	}
	if got != "not_applicable" {
		t.Errorf(`"aggregateStatus" = %v; want "not_applicable" — `+
			`"unknown" here renders as a warm-up window that never closes`, got)
	}
	// The counts must read as "nothing to count", not as "0 of N
	// healthy": the denominator is what the list renders as "N/M
	// sains", and a redirecting route has no M.
	if v := m["totalUpstreamCount"]; v != float64(0) {
		t.Errorf(`"totalUpstreamCount" = %v; want 0`, v)
	}
	if v := m["healthyUpstreamCount"]; v != float64(0) {
		t.Errorf(`"healthyUpstreamCount" = %v; want 0`, v)
	}
}

// Non-regression: a proxying route is untouched by the new branch.
// The redirect check sits FIRST in the precedence table, so this is
// the test that would catch it swallowing an ordinary route.
func TestRouteResponse_ProxyingRoute_AggregateStatusUnchanged(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("create proxying route: %v", err)
	}

	m := getRouteJSON(t, env, created.ID)

	// HC is off on this route, so the honest answer is
	// "not_monitored" — and above all NOT "not_applicable".
	if got := m["aggregateStatus"]; got != "not_monitored" {
		t.Errorf(`"aggregateStatus" = %v; want "not_monitored"`, got)
	}
	if v := m["totalUpstreamCount"]; v != float64(1) {
		t.Errorf(`"totalUpstreamCount" = %v; want 1`, v)
	}
}
