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

package caddymgr

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/metrics"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.55 — the active health check sends the route's Host.
//
// Reported from a real setup: every Arenet route proxied to one backend
// that dispatches on Host. Caddy builds the probe from the DIAL address
// (healthchecks.go:393-396) and only overrides req.Host when a header is
// configured (:452-455) — and Arenet configured none. So the probe asked
// for `Host: 10.66.0.2:80`, the backend had no such virtual host,
// answered 404, and every upstream was marked down while serving its
// route perfectly.
//
// This is a deliberate behaviour change for checks configured before
// v2.55: their probe now carries the route host instead of the dial
// address. The golden snapshot moved with it.

func healthCheckRoute(hc storage.HealthCheck) []storage.Route {
	return []storage.Route{{
		ID:          "r1",
		Host:        "vault.example.com",
		Upstreams:   []storage.Upstream{{URL: "http://10.66.0.2:80", Weight: 1}},
		LBPolicy:    storage.LBPolicyRoundRobin,
		HealthCheck: hc,
	}}
}

func enabledCheck() storage.HealthCheck {
	return storage.HealthCheck{
		Enabled: true, URI: "/alive", Method: "GET",
		Interval: "30s", Timeout: "5s", Passes: 1, Fails: 1,
	}
}

// activeProbe digs out the first health_checks.active in the config.
//
// It recurses through subroutes: a per-path pool's proxy sits nested
// inside one, and a walker that stopped at the first level would report
// "no probe" for a config that has one — a guard that fails for the
// wrong reason is worse than no guard.
func activeProbe(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, s := range servers {
		routes, _ := s.(map[string]any)["routes"].([]any)
		if active := findActiveProbe(routes); active != nil {
			return active
		}
	}
	t.Fatal("no reverse_proxy carrying health_checks.active in the emitted config")
	return nil
}

// findActiveProbe walks routes and their nested subroutes.
func findActiveProbe(routes []any) map[string]any {
	for _, r := range routes {
		route, _ := r.(map[string]any)
		handlers, _ := route["handle"].([]any)
		for _, h := range handlers {
			hm, _ := h.(map[string]any)
			if hm == nil {
				continue
			}
			if hc, ok := hm["health_checks"].(map[string]any); ok {
				if active, ok := hc["active"].(map[string]any); ok {
					return active
				}
			}
			if nested, ok := hm["routes"].([]any); ok {
				if active := findActiveProbe(nested); active != nil {
					return active
				}
			}
		}
	}
	return nil
}

func probeHostOf(t *testing.T, active map[string]any) string {
	t.Helper()
	headers, ok := active["headers"].(map[string]any)
	if !ok {
		return ""
	}
	vals, ok := headers["Host"].([]any)
	if !ok || len(vals) == 0 {
		return ""
	}
	return vals[0].(string)
}

// THE test: without this the probe asks the dial address for a virtual
// host it does not serve.
func TestHealthCheck_ProbeCarriesTheRouteHost(t *testing.T) {
	raw, err := buildConfigJSON(healthCheckRoute(enabledCheck()), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if got := probeHostOf(t, activeProbe(t, raw)); got != "vault.example.com" {
		t.Errorf("probe Host = %q; want the route's host, not the dial address", got)
	}
}

func TestHealthCheck_HostOverrideWins(t *testing.T) {
	hc := enabledCheck()
	hc.HostHeader = "internal.example.com"

	raw, err := buildConfigJSON(healthCheckRoute(hc), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if got := probeHostOf(t, activeProbe(t, raw)); got != "internal.example.com" {
		t.Errorf("probe Host = %q; the operator's override must win over the route host", got)
	}
}

func TestHealthCheck_CustomHeadersTravelWithTheHost(t *testing.T) {
	hc := enabledCheck()
	hc.Headers = map[string]string{"Authorization": "Bearer probe-token"}

	raw, err := buildConfigJSON(healthCheckRoute(hc), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	active := activeProbe(t, raw)
	if got := probeHostOf(t, active); got != "vault.example.com" {
		t.Errorf("probe Host = %q; custom headers must not displace it", got)
	}
	headers := active["headers"].(map[string]any)
	vals, ok := headers["Authorization"].([]any)
	if !ok || len(vals) != 1 || vals[0] != "Bearer probe-token" {
		t.Errorf("Authorization = %v; a health endpoint behind auth needs it", headers["Authorization"])
	}
}

// A route with no check must emit no probe at all — the whole
// health_checks key stays absent, as before v2.55.
func TestHealthCheck_DisabledEmitsNoProbe(t *testing.T) {
	raw, err := buildConfigJSON(healthCheckRoute(storage.HealthCheck{}), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Scoped to health_checks on purpose: "headers" appears all over a
	// Caddy config (the proxy's own request headers, error responses),
	// so a bare substring search would pass for the wrong reason.
	if strings.Contains(string(raw), "health_checks") {
		t.Errorf("health_checks emitted for a route that has no check:\n%s", raw)
	}
}

// The emitted headers have to be something Caddy accepts, not just
// something that looks right — the project's standing rule for anything
// Caddy-facing.
func TestHealthCheck_ProbeHeadersLoadCleanly(t *testing.T) {
	// arenet_routemetrics refuses to provision without a registry; the
	// other LoadsCleanly guards install one the same way.
	metrics.SetRegistry(metrics.NewRegistry())

	hc := enabledCheck()
	hc.HostHeader = "internal.example.com"
	hc.Headers = map[string]string{"Authorization": "Bearer t", "X-Probe": "arenet"}
	hc.ExpectStatus = 3 // Caddy's class shorthand: any 3xx

	raw, err := buildConfigJSON(healthCheckRoute(hc), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate with probe headers: %v\n%s", err, raw)
	}
}

// A per-path pool has its own check but belongs to the same route, so it
// probes for the same host.
func TestHealthCheck_PathRulePoolProbesTheRouteHost(t *testing.T) {
	hc := enabledCheck()
	routes := []storage.Route{{
		ID:        "r1",
		Host:      "vault.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.66.0.2:80", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{{
			PathPrefix:  "/api",
			Upstreams:   []storage.Upstream{{URL: "http://10.66.0.3:80", Weight: 1}},
			LBPolicy:    storage.LBPolicyRoundRobin,
			HealthCheck: &hc,
		}},
	}}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if got := probeHostOf(t, activeProbe(t, raw)); got != "vault.example.com" {
		t.Errorf("path-rule probe Host = %q; a per-path pool still serves the route's host", got)
	}
}
