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

	"github.com/barto95100/arenet/internal/storage"
)

// emitPathSubrouteJSON emits the subroute for a route with the given path
// rules + a route proxy sentinel ("route-pool:80"), wiring a pathProxy
// closure that mirrors the manager.go call site: a rule with no upstream
// pool inherits the sentinel route proxy, a rule with an own pool gets its
// own reverse_proxy via buildReverseProxyHandler (sharing a sentinel
// handle_response). Returns the JSON string for substring assertions.
func emitPathSubrouteJSON(t *testing.T, rules []storage.PathRule) string {
	t.Helper()
	routeProxy := map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]any{{"dial": "route-pool:80"}}}
	sharedHandleResponse := []map[string]any{{"handler": "copy_response"}}
	pathProxy := func(pr storage.PathRule) (map[string]any, error) {
		if len(pr.Upstreams) == 0 {
			return routeProxy, nil
		}
		return buildReverseProxyHandler(proxyPoolParams{
			Upstreams:          pr.Upstreams,
			LBPolicy:           pr.LBPolicy,
			HealthCheck:        pr.HealthCheck,
			UsesHTTPS:          poolUsesHTTPS(pr.Upstreams),
			InsecureSkipVerify: pr.InsecureSkipVerify,
		}, sharedHandleResponse, false)
	}
	sub, err := buildPathRulesSubroute("r-test", rules, routeProxy, func(c storage.BasicAuthRouteConfig) map[string]any {
		return map[string]any{"handler": "authentication"}
	}, noForwardAuthForTest, pathProxy)
	if err != nil {
		t.Fatalf("buildPathRulesSubroute: %v", err)
	}
	b, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// firstRuleHandle emits the subroute for `rules` and returns the handle
// array of the FIRST inner route (the longest-prefix rule after sorting).
// Used to assert intra-rule handler ORDER (e.g. IP block before proxy)
// rather than mere substring presence in the marshalled JSON.
func firstRuleHandle(t *testing.T, rules []storage.PathRule) []map[string]any {
	t.Helper()
	routeProxy := map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]any{{"dial": "route-pool:80"}}}
	sharedHandleResponse := []map[string]any{{"handler": "copy_response"}}
	pathProxy := func(pr storage.PathRule) (map[string]any, error) {
		if len(pr.Upstreams) == 0 {
			return routeProxy, nil
		}
		return buildReverseProxyHandler(proxyPoolParams{
			Upstreams:          pr.Upstreams,
			LBPolicy:           pr.LBPolicy,
			HealthCheck:        pr.HealthCheck,
			UsesHTTPS:          poolUsesHTTPS(pr.Upstreams),
			InsecureSkipVerify: pr.InsecureSkipVerify,
		}, sharedHandleResponse, false)
	}
	sub, err := buildPathRulesSubroute("r-test", rules, routeProxy, func(c storage.BasicAuthRouteConfig) map[string]any {
		return map[string]any{"handler": "authentication"}
	}, noForwardAuthForTest, pathProxy)
	if err != nil {
		t.Fatalf("buildPathRulesSubroute: %v", err)
	}
	inner, ok := sub["routes"].([]map[string]any)
	if !ok || len(inner) == 0 {
		t.Fatalf("subroute has no inner routes: %+v", sub)
	}
	handle, ok := inner[0]["handle"].([]map[string]any)
	if !ok {
		t.Fatalf("first inner route has no handle array: %+v", inner[0])
	}
	return handle
}

func TestPathRulesSubroute_RuleWithOwnUpstream(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "api-a:8080") {
		t.Fatalf("path rule should proxy to its own upstream; got: %s", js)
	}
}

func TestPathRulesSubroute_RuleWithoutUpstreamUsesRoutePool(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/docs",
		BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$h"},
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "route-pool:80") {
		t.Fatalf("protection-only rule must keep the route pool; got: %s", js)
	}
}

func TestPathRulesSubroute_CatchAllKeepsRoutePool(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	// Both the path pool AND the route pool (catch-all) must appear.
	if !strings.Contains(js, "route-pool:80") {
		t.Fatalf("catch-all must keep the route pool; got: %s", js)
	}
}

func TestPathRulesSubroute_HTTPSPathPoolEmitsTransport(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/legacy",
		Upstreams:  []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "\"tls\"") {
		t.Fatalf("https path pool must emit a transport.tls block; got: %s", js)
	}
}

func TestPathRulesSubroute_IPBlockBeforeOwnUpstream(t *testing.T) {
	// fail-closed IP filter still gates BEFORE the path's own proxy. This
	// asserts ORDER, not mere presence: a denied client MUST hit the 403
	// subroute before ever reaching the path's own reverse_proxy, so the
	// IP-block handler must precede the reverse_proxy in the matched rule's
	// handle array. (Presence alone would still pass if a future refactor
	// reordered them — the exact regression this guards against.)
	rules := []storage.PathRule{{
		PathPrefix: "/metrics",
		IPFilter:   &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"10.0.0.0/8"}},
		Upstreams:  []storage.Upstream{{URL: "http://m:9090", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	handle := firstRuleHandle(t, rules)

	ipIdx, proxyIdx := -1, -1
	for i, h := range handle {
		switch h["handler"] {
		case "subroute": // the IP-filter block is emitted as a nested subroute
			if ipIdx == -1 {
				ipIdx = i
			}
		case "reverse_proxy":
			proxyIdx = i
		}
	}
	if ipIdx == -1 {
		t.Fatalf("expected an IP-block subroute in the rule handle; got: %+v", handle)
	}
	if proxyIdx == -1 {
		t.Fatalf("expected the path's own reverse_proxy in the rule handle; got: %+v", handle)
	}
	if ipIdx >= proxyIdx {
		t.Fatalf("fail-closed violated: IP block at index %d must precede reverse_proxy at index %d; handle: %+v", ipIdx, proxyIdx, handle)
	}
	// The own upstream is still the one proxied (not the route pool).
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "m:9090") {
		t.Fatalf("expected the path's own upstream m:9090; got: %s", js)
	}
}

func TestPathRulesSubroute_PathSkipVerifyAutonomous(t *testing.T) {
	// A path with insecureSkipVerify=true + https pool emits
	// transport.tls.insecure_skip_verify=true, driven by the PATH's field
	// (the emitPathSubrouteJSON helper wires InsecureSkipVerify from the
	// rule, mirroring the manager.go call site after this task).
	rules := []storage.PathRule{{
		PathPrefix:         "/legacy",
		Upstreams:          []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:           storage.LBPolicyRoundRobin,
		InsecureSkipVerify: true,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "insecure_skip_verify") {
		t.Fatalf("expected insecure_skip_verify for the path pool; got: %s", js)
	}
}

func TestPathRulesSubroute_PathStrictByDefault(t *testing.T) {
	// A path with insecureSkipVerify=false (default) + https pool emits a
	// strict tls block (no insecure_skip_verify), proving the path does NOT
	// inherit a route-level insecure posture.
	rules := []storage.PathRule{{
		PathPrefix: "/legacy",
		Upstreams:  []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "\"tls\"") {
		t.Fatalf("https path pool must still emit a tls block; got: %s", js)
	}
	if strings.Contains(js, "insecure_skip_verify") {
		t.Fatalf("strict path pool must NOT emit insecure_skip_verify; got: %s", js)
	}
}

// TestBuildConfigJSON_PathSkipVerifyIndependentOfRoute drives the REAL
// buildConfigJSON (not the test helper) to guard the manager.go pathProxy
// source line: the path pool's insecure_skip_verify must come from the PATH
// rule's own field, NOT the route's. Here the route is STRICT
// (InsecureSkipVerify=false) but the /legacy path has its own https pool with
// InsecureSkipVerify=true. If the emission ever reverts to r.InsecureSkipVerify
// (the pre-v2.23.1 bug), the path would be strict and this test fails — which
// the helper-based tests above cannot catch (they bypass the manager.go call
// site). The route's own http pool must stay strict (no tls block at all).
func TestBuildConfigJSON_PathSkipVerifyIndependentOfRoute(t *testing.T) {
	routes := []storage.Route{{
		ID:                 "r-mixed",
		Host:               "api.example.com",
		Upstreams:          []storage.Upstream{{URL: "http://route-backend:8080", Weight: 1}},
		LBPolicy:           storage.LBPolicyRoundRobin,
		InsecureSkipVerify: false, // route is STRICT
		PathRules: []storage.PathRule{{
			PathPrefix:         "/legacy",
			Upstreams:          []storage.Upstream{{URL: "https://legacy-backend:8443", Weight: 1}},
			LBPolicy:           storage.LBPolicyRoundRobin,
			InsecureSkipVerify: true, // but THIS path is insecure
		}},
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if !strings.Contains(string(raw), "insecure_skip_verify") {
		t.Fatalf("path pool with InsecureSkipVerify=true must emit insecure_skip_verify even though the route is strict; got: %s", raw)
	}
}
