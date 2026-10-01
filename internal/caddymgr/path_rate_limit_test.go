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

// v2.56 — a rate limit on one path of a route.
//
// Reason to exist: a login or session endpoint wants a much tighter limit
// than the site around it, and raising the route's limit to protect one
// path is the wrong instrument — it would throttle every asset on the page
// to slow down one form.
//
// The invariant that matters most is counter separation. caddy-ratelimit
// keeps zones in a caddy.NewUsagePool keyed by NAME (handler.go:279),
// reference-counted, and Cleanup deletes by name (:245-250) — so a zone
// whose name is reused after a reload inherits the previous counters.

func rateLimitedPathRoute(prefix string, rl *storage.RouteRateLimit) []storage.Route {
	return []storage.Route{{
		ID:        "rid-1",
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{{PathPrefix: prefix, RateLimit: rl}},
	}}
}

func strictLimit() *storage.RouteRateLimit {
	return &storage.RouteRateLimit{Events: 5, Window: "1m"}
}

// rateLimitZones collects every rate_limit zone in the emitted config,
// mapped to its settings, walking nested subroutes.
func rateLimitZones(t *testing.T, raw []byte) map[string]map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out := map[string]map[string]any{}
	var walk func(handlers []any)
	walk = func(handlers []any) {
		for _, h := range handlers {
			hm, _ := h.(map[string]any)
			if hm == nil {
				continue
			}
			if zones, ok := hm["rate_limits"].(map[string]any); ok {
				for name, z := range zones {
					out[name], _ = z.(map[string]any)
				}
			}
			if nested, ok := hm["routes"].([]any); ok {
				for _, r := range nested {
					rm, _ := r.(map[string]any)
					if inner, ok := rm["handle"].([]any); ok {
						walk(inner)
					}
				}
			}
		}
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, s := range servers {
		routes, _ := s.(map[string]any)["routes"].([]any)
		for _, r := range routes {
			rm, _ := r.(map[string]any)
			if handlers, ok := rm["handle"].([]any); ok {
				walk(handlers)
			}
		}
	}
	return out
}

// pathRuleHandlerOrder returns the handler names of the first path rule in
// the emitted subroute, in order.
func pathRuleHandlerOrder(t *testing.T, raw []byte) []string {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, s := range servers {
		routes, _ := s.(map[string]any)["routes"].([]any)
		for _, r := range routes {
			for _, h := range unwrapHandlers(r.(map[string]any)) {
				hm, _ := h.(map[string]any)
				if hm["handler"] != "subroute" {
					continue
				}
				inner, _ := hm["routes"].([]any)
				if len(inner) == 0 {
					continue
				}
				first, _ := inner[0].(map[string]any)
				handlers, _ := first["handle"].([]any)
				names := make([]string, 0, len(handlers))
				for _, ih := range handlers {
					n, _ := ih.(map[string]any)["handler"].(string)
					names = append(names, n)
				}
				return names
			}
		}
	}
	t.Fatal("no path-rule subroute in the emitted config")
	return nil
}

func TestPathRateLimit_EmittedWithItsOwnZone(t *testing.T) {
	raw, err := buildConfigJSON(rateLimitedPathRoute("/api/v1/auth", strictLimit()), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	zones := rateLimitZones(t, raw)
	if len(zones) != 1 {
		t.Fatalf("want one zone, got %d: %v", len(zones), zones)
	}
	for name, z := range zones {
		if !strings.Contains(name, "rid-1") || !strings.Contains(name, "path") {
			t.Errorf("zone name %q should name the route and say it is a path zone", name)
		}
		if z["max_events"] != float64(5) {
			t.Errorf("max_events = %v", z["max_events"])
		}
		if z["key"] != defaultRateLimitKey {
			t.Errorf("key = %v; want the route-level default", z["key"])
		}
	}
}

// THE separation invariant: the route's limit and the path's are two
// zones, so both budgets apply and neither spends the other's.
func TestPathRateLimit_CountersIndependentOfTheRoute(t *testing.T) {
	routes := rateLimitedPathRoute("/api/v1/auth", strictLimit())
	routes[0].RateLimit = &storage.RouteRateLimit{Events: 500, Window: "1m"}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	zones := rateLimitZones(t, raw)
	if len(zones) != 2 {
		t.Fatalf("want two zones (route + path), got %d: %v", len(zones), zones)
	}
	var routeZone, pathZone map[string]any
	for name, z := range zones {
		if strings.Contains(name, "-path-") {
			pathZone = z
		} else {
			routeZone = z
		}
	}
	if routeZone == nil || pathZone == nil {
		t.Fatalf("expected one route zone and one path zone: %v", zones)
	}
	if routeZone["max_events"] != float64(500) {
		t.Errorf("route zone max_events = %v", routeZone["max_events"])
	}
	if pathZone["max_events"] != float64(5) {
		t.Errorf("path zone max_events = %v; the strict limit must not inherit the route's", pathZone["max_events"])
	}
}

// Two path rules on one route must not share a zone, or a client
// throttled on one arrives throttled on the other.
func TestPathRateLimit_TwoPathsGetTwoZones(t *testing.T) {
	routes := []storage.Route{{
		ID:        "rid-1",
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{
			{PathPrefix: "/api/v1/auth", RateLimit: &storage.RouteRateLimit{Events: 5, Window: "1m"}},
			{PathPrefix: "/ghost/api/admin/session", RateLimit: &storage.RouteRateLimit{Events: 3, Window: "5m"}},
		},
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if zones := rateLimitZones(t, raw); len(zones) != 2 {
		t.Fatalf("want two zones, got %d: %v", len(zones), zones)
	}
}

// The name must not depend on the rule's position: caddy-ratelimit keeps
// zones by name across a reload, so reordering two rules would otherwise
// hand each the other's counters.
func TestPathRateLimit_ZoneNameSurvivesReordering(t *testing.T) {
	a := storage.PathRule{PathPrefix: "/api/v1/auth", RateLimit: &storage.RouteRateLimit{Events: 5, Window: "1m"}}
	b := storage.PathRule{PathPrefix: "/admin", RateLimit: &storage.RouteRateLimit{Events: 3, Window: "1m"}}

	base := func(rules []storage.PathRule) map[string]map[string]any {
		routes := []storage.Route{{
			ID: "rid-1", Host: "app.example.com",
			Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			PathRules: rules,
		}}
		raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
		if err != nil {
			t.Fatalf("buildConfigJSON: %v", err)
		}
		return rateLimitZones(t, raw)
	}

	first := base([]storage.PathRule{a, b})
	second := base([]storage.PathRule{b, a})
	for name, z := range first {
		other, ok := second[name]
		if !ok {
			t.Fatalf("zone %q disappeared when the rules were reordered — its counters would move", name)
		}
		if z["max_events"] != other["max_events"] {
			t.Errorf("zone %q changed limit on reorder: %v vs %v", name, z["max_events"], other["max_events"])
		}
	}
}

// Sanitising alone would collide these two; the hash is what keeps them
// apart.
func TestPathRateLimit_LookalikePrefixesGetDistinctZones(t *testing.T) {
	if a, b := pathRateLimitZoneName("r", "/a/b"), pathRateLimitZoneName("r", "/a-b"); a == b {
		t.Errorf("two different prefixes share a zone name: %q", a)
	}
}

// The limit runs BEFORE auth: the requests worth throttling on a login
// endpoint are the ones that have not authenticated yet.
func TestPathRateLimit_RunsBeforeBasicAuth(t *testing.T) {
	routes := rateLimitedPathRoute("/admin", strictLimit())
	routes[0].PathRules[0].BasicAuth = &storage.BasicAuthRouteConfig{
		Username:     "ops",
		PasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	order := pathRuleHandlerOrder(t, raw)
	rlAt, authAt := -1, -1
	for i, name := range order {
		switch name {
		case "rate_limit":
			rlAt = i
		case "authentication":
			authAt = i
		}
	}
	if rlAt < 0 || authAt < 0 {
		t.Fatalf("want both handlers in the chain, got %v", order)
	}
	if rlAt > authAt {
		t.Errorf("chain = %v; the limit must run before auth or it only counts successful logins", order)
	}
}

// A path rule with nothing but a rate limit is a complete rule: it
// throttles a path the route otherwise serves normally.
func TestPathRateLimit_IsEnoughOnItsOwn(t *testing.T) {
	routes := rateLimitedPathRoute("/api/v1/auth", strictLimit())
	if err := storage.ValidateRoute(routes[0]); err != nil {
		t.Fatalf("a rate-limit-only path rule was refused: %v", err)
	}
}

func TestPathRateLimit_InvalidIsRefused(t *testing.T) {
	for name, rl := range map[string]*storage.RouteRateLimit{
		"zero events":     {Events: 0, Window: "1m"},
		"negative events": {Events: -1, Window: "1m"},
		"empty window":    {Events: 5, Window: ""},
		"bad window":      {Events: 5, Window: "sometime"},
		"zero window":     {Events: 5, Window: "0s"},
	} {
		t.Run(name, func(t *testing.T) {
			routes := rateLimitedPathRoute("/x", rl)
			if err := storage.ValidateRoute(routes[0]); err == nil {
				t.Error("accepted a limit that cannot work")
			}
		})
	}
}

// The emitted config has to be something Caddy loads.
func TestPathRateLimit_LoadsCleanly(t *testing.T) {
	metrics.SetRegistry(metrics.NewRegistry())

	routes := rateLimitedPathRoute("/api/v1/auth", strictLimit())
	routes[0].RateLimit = &storage.RouteRateLimit{Events: 500, Window: "1m"}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate with a per-path rate limit: %v\n%s", err, raw)
	}
}

// A route with no path-level limit must emit exactly what it did before.
func TestPathRateLimit_AbsentChangesNothing(t *testing.T) {
	routes := rateLimitedPathRoute("/api/v1/auth", nil)
	routes[0].PathRules[0].Upstreams = []storage.Upstream{{URL: "http://10.0.0.3:80", Weight: 1}}
	routes[0].PathRules[0].LBPolicy = storage.LBPolicyRoundRobin

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if zones := rateLimitZones(t, raw); len(zones) != 0 {
		t.Errorf("zones emitted with no limit configured: %v", zones)
	}
}

// The ROUTE-level limit had no caddy.Validate coverage at all until v2.56:
// http.handlers.rate_limit was registered only in cmd/arenet, so any
// validate over a config carrying one failed with "unknown module" and no
// test could assert its shape. Arenet has emitted this zone since Step Q.
func TestRouteRateLimit_LoadsCleanly(t *testing.T) {
	metrics.SetRegistry(metrics.NewRegistry())

	routes := []storage.Route{{
		ID: "rid-1", Host: "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		RateLimit: &storage.RouteRateLimit{Events: 100, Window: "1m"},
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate with the route-level rate limit: %v\n%s", err, raw)
	}
}

// v2.56.4 — a path rule's gates ADD to the route's; they do not replace
// them.
//
// The UI called the per-path basic auth an "override", which claimed a
// replacement that does not happen: the route's own auth handler is
// appended before the path-rules subroute, so both run. An operator
// reading "override" could believe they had swapped one protection for
// another — or weakened one. The label was corrected, and this pins the
// behaviour the label now describes.
func TestPathRule_RouteAuthStillRunsBeforeThePathGate(t *testing.T) {
	routes := []storage.Route{{
		ID: "rid-1", Host: "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		AuthMode:  storage.RouteAuthBasic,
		BasicAuth: storage.BasicAuthRouteConfig{
			Username:     "route-user",
			PasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
		},
		PathRules: []storage.PathRule{{
			PathPrefix: "/admin",
			BasicAuth: &storage.BasicAuthRouteConfig{
				Username:     "path-user",
				PasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
			},
		}},
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	var order []string
	for _, s := range servers {
		rts, _ := s.(map[string]any)["routes"].([]any)
		for _, r := range rts {
			names := make([]string, 0, 4)
			for _, h := range unwrapHandlers(r.(map[string]any)) {
				n, _ := h.(map[string]any)["handler"].(string)
				names = append(names, n)
			}
			if len(names) > 0 {
				order = names
				break
			}
		}
		if len(order) > 0 {
			break
		}
	}

	authAt, subAt := -1, -1
	for i, name := range order {
		switch name {
		case "authentication":
			if authAt < 0 {
				authAt = i
			}
		case "subroute":
			subAt = i
		}
	}
	if authAt < 0 || subAt < 0 {
		t.Fatalf("want the route's auth and the path subroute in the chain, got %v", order)
	}
	if authAt > subAt {
		t.Errorf("chain = %v; the route's auth must run before the path gates, which is why a "+
			"path gate adds to it rather than replacing it", order)
	}
}
