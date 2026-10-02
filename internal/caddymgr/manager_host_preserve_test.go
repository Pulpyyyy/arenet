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
	"reflect"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// Quick-win #1 (2026-06-23) — Host header preservation default.
//
// Industry-standard reverse-proxy behaviour is to preserve the
// original client Host header on the upstream request. Caddy's
// reverse_proxy default rewrites Host to the upstream URL's host,
// which breaks any backend that builds absolute URLs from Host
// (IdPs, multi-tenant SaaS, ...). Traefik and nginx both preserve
// Host by default ; this commit aligns Arenet with that convention.
//
// Day 17 empirical motivation : the authentik OIDC route returned
// "issuer": "http://192.168.99.12/..." instead of
// "https://auth.example.com/..." because authentik used the
// rewritten Host header. The {http.request.host} placeholder
// preserves the original.
//
// X-Forwarded-* trio is NOT pinned here because Caddy's
// reverse_proxy injects them automatically (verified empirically
// against caddyserver/caddy/v2@v2.11.4 reverseproxy.go:867).

func TestBuildConfigJSON_ProxyHandler_PreservesHostByDefault(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "host-preserve",
			Host:      "auth.example.com",
			Upstreams: []storage.Upstream{{URL: "http://10.0.0.42:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	if len(httpRoutes) < 1 {
		t.Fatalf("expected ≥1 user route, got %d", len(httpRoutes))
	}

	handlers := unwrapHandlers(httpRoutes[0])
	var proxy map[string]any
	for _, h := range handlers {
		m, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if m["handler"] == "reverse_proxy" {
			proxy = m
			break
		}
	}
	if proxy == nil {
		t.Fatalf("reverse_proxy handler not found ; handlers=%+v", handlers)
	}

	// Drill into headers.request.set.Host. The shape is :
	//   "headers": { "request": { "set": { "Host": ["{http.request.host}"] } } }
	headers, ok := proxy["headers"].(map[string]any)
	if !ok {
		t.Fatalf("reverse_proxy handler missing 'headers' key ; got %+v", proxy)
	}
	req, ok := headers["request"].(map[string]any)
	if !ok {
		t.Fatalf("headers missing 'request' key ; got %+v", headers)
	}
	set, ok := req["set"].(map[string]any)
	if !ok {
		t.Fatalf("headers.request missing 'set' key ; got %+v", req)
	}
	hostVals, ok := set["Host"].([]any)
	if !ok {
		// Fallback : when emitted from typed map[string][]string it
		// may decode as []any in encoding/json's untyped path. Try
		// []string too for defence.
		hostStrSlice, ok2 := set["Host"].([]string)
		if !ok2 {
			t.Fatalf("headers.request.set missing 'Host' key ; got %+v", set)
		}
		if !reflect.DeepEqual(hostStrSlice, []string{"{http.request.host}"}) {
			t.Errorf("Host header value = %v ; want [\"{http.request.host}\"]", hostStrSlice)
		}
		return
	}
	if len(hostVals) != 1 || hostVals[0] != "{http.request.host}" {
		t.Errorf("Host header values = %v ; want [\"{http.request.host}\"] — the Caddy placeholder that preserves the original client Host (industry convention, aligned with Traefik/nginx defaults)",
			hostVals)
	}
}

// TestBuildConfigJSON_ProxyHandler_HostPreservationOnEveryRoute pins
// the invariant across multiple routes — no route should accidentally
// fall through without Host preservation.
func TestBuildConfigJSON_ProxyHandler_HostPreservationOnEveryRoute(t *testing.T) {
	routes := []storage.Route{
		{ID: "r1", Host: "a.example.com", Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "r2", Host: "b.example.com", Upstreams: []storage.Upstream{{URL: "https://10.0.0.2:443", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin},
		{ID: "r3", Host: "c.example.com", Upstreams: []storage.Upstream{{URL: "http://10.0.0.3:8080", Weight: 2}, {URL: "http://10.0.0.4:8080", Weight: 1}}, LBPolicy: storage.LBPolicyWeightedRoundRobin},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	// Skip the catch-all (last entry); only inspect user routes.
	if len(httpRoutes) < len(routes) {
		t.Fatalf("expected ≥%d routes (+ catch-all), got %d", len(routes), len(httpRoutes))
	}

	for i, route := range httpRoutes[:len(routes)] {
		handlers := unwrapHandlers(route)
		var proxy map[string]any
		for _, h := range handlers {
			m, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if m["handler"] == "reverse_proxy" {
				proxy = m
				break
			}
		}
		if proxy == nil {
			t.Errorf("route %d (%s) : reverse_proxy handler not found", i, routes[i].Host)
			continue
		}
		headers, _ := proxy["headers"].(map[string]any)
		req, _ := headers["request"].(map[string]any)
		set, _ := req["set"].(map[string]any)
		hostVals, _ := set["Host"].([]any)
		if len(hostVals) != 1 || hostVals[0] != "{http.request.host}" {
			t.Errorf("route %d (%s) : Host preservation missing or wrong shape ; got %+v",
				i, routes[i].Host, set["Host"])
		}
	}
}
