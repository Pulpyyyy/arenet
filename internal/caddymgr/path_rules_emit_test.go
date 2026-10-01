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
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildPathRulesSubroute_LongestFirstPlusCatchAll(t *testing.T) {
	proxy := map[string]any{"handler": "reverse_proxy"}
	ba := func(c storage.BasicAuthRouteConfig) map[string]any {
		return map[string]any{"handler": "authentication", "user": c.Username}
	}
	rules := []storage.PathRule{
		{PathPrefix: "/docs", BasicAuth: &storage.BasicAuthRouteConfig{Username: "d"}},
		{PathPrefix: "/docs/admin", IPFilter: &storage.IPFilter{Mode: "allow", CIDRs: []string{"1.2.3.4"}}},
	}
	// Neither rule declares an upstream pool, so pathProxy always
	// inherits the route proxy (mirrors the manager.go closure's
	// len(pr.Upstreams)==0 branch).
	pathProxy := func(pr storage.PathRule) (map[string]any, error) { return proxy, nil }
	sr, err := buildPathRulesSubroute("r-test", rules, proxy, ba, noForwardAuthForTest, pathProxy)
	if err != nil {
		t.Fatalf("buildPathRulesSubroute: %v", err)
	}
	routes := sr["routes"].([]map[string]any)
	// 2 path routes + 1 catch-all = 3
	if len(routes) != 3 {
		t.Fatalf("want 3 inner routes (2 rules longest-first + catch-all), got %d", len(routes))
	}
	// route[0] = the LONGER prefix /docs/admin
	p0 := routes[0]["match"].([]map[string]any)[0]["path"].([]string)
	if p0[0] != "/docs/admin" || p0[1] != "/docs/admin/*" {
		t.Fatalf("route0 must be /docs/admin (longest-first), got %v", p0)
	}
	// route[2] = catch-all: no match, just proxy
	if _, hasMatch := routes[2]["match"]; hasMatch {
		t.Fatalf("catch-all must have no match, got %v", routes[2]["match"])
	}
	if routes[2]["handle"].([]map[string]any)[0]["handler"] != "reverse_proxy" {
		t.Fatal("catch-all must proxy")
	}
}

// noForwardAuthForTest stands in for the resolver in tests that do not
// exercise a per-path IdP gate. It is never called by those fixtures (no
// rule carries ForwardAuth), and returning the fail-closed shape rather
// than nil means a fixture that starts carrying one fails loudly instead
// of emitting a gate that lets everything through.
func noForwardAuthForTest(providerName string) (map[string]any, bool) {
	return buildForwardAuthDenyHandler(providerName), false
}
