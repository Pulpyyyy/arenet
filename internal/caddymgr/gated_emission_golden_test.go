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
	"os"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/storage"
)

// Gate G2 of docs/superpowers/specs/2026-10-08-maintenance-bypass-
// serves-the-real-route-design.md.
//
// The operator's constraint on that work is first-class: "il ne faut pas
// que tu casse le fonctionnement de arenet avec ou sans le mode
// maintenance […] c'est primordial". This file is how the "without
// maintenance mode" half gets PROVEN rather than reviewed by eye.
//
// Why a second golden, when testdata/route_emission_golden.json already
// exists: that one's scope is far narrower than its 170 KB suggests.
// representativeRoutes() emits six routes — single upstream, weighted
// pool, https pool, skip-verify, health check, upload streaming — every
// one of them with WAFMode "off" and NO path rules, NO request/response
// headers, and none of IPFilter, RateLimit, CountryBlock, auth or WAF.
// The file contains zero occurrences of "maintenance", "Retry-After" or
// "client_ip". So it pins the proxy-emission shapes and says nothing
// about anything the maintenance branch skips, which is the entire
// surface at risk.
//
// This fixture is deliberately INDEPENDENT of the canonical
// TestBuildConfigJSON_LoadsCleanly fixture rather than derived from it.
// A non-regression golden must not move because somebody edited a
// different test's routes; adding a shape here is meant to be a
// decision, taken with the diff in hand.
//
// DELIBERATELY NO MaintenanceConfig AND NO RedirectConfig in this
// fixture. Byte-identity has to be an absolute requirement here, and
// the maintenance work changes a maintenance route's emitted shape on
// purpose. The behaviour of a maintenance route is asserted by the
// explicit gates (G3-G6), not by this golden.
//
// HAZARD: `go test -update` REWRITES both goldens in this package
// (the flag is declared once, reverse_proxy_emit_test.go:34, and both
// tests read it). Running it to turn a red test green blesses the
// regression as the new expectation, permanently and silently. Capture
// a golden once, from unmodified code, and never regenerate it to make
// a failing run pass — a diff of testdata/ belongs in the review.
func gatedRoutes() []storage.Route {
	const argon = "$argon2id$v=19$m=65536,t=3,p=4$U0FMVFNBTFRTQUxUU0FMVA$S0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0U"

	// Checked against the captured golden rather than assumed. Two
	// findings from that probe, both worth leaving written down:
	//
	//   - "countryblock" came back 0 and this comment already claimed
	//     the gate was covered. The field was simply missing. It is set
	//     now.
	//   - "forward_auth" also came back 0, and that one is CORRECT:
	//     Caddy's forward_auth is not a module name in emitted JSON, it
	//     expands to reverse_proxy + handle_response. The real markers
	//     are the provider's verify URL, its auth_request URI and its
	//     copy_headers, all present. Probe for those, not for the
	//     directive name.
	return []storage.Route{
		// Every route-level gate the maintenance branch currently drops,
		// on one route: rate limit, country block, whole-domain IP
		// filter, WAF, basic auth, request and response headers.
		{
			ID:              "g-gates",
			Host:            "gates.example.com",
			Upstreams:       []storage.Upstream{{URL: "http://127.0.0.1:9100", Weight: 1}},
			LBPolicy:        storage.LBPolicyRoundRobin,
			TLSEnabled:      true,
			RedirectToHTTPS: true,
			Aliases:         []string{"gates-alt.example.com"},
			WAFMode:         "block",
			AuthMode:        storage.RouteAuthBasic,
			BasicAuth: storage.BasicAuthRouteConfig{
				Username:     "admin",
				PasswordHash: argon,
			},
			RequestHeaders:  map[string]string{"X-Real-Foo": "bar"},
			ResponseHeaders: map[string]string{"X-Custom": "x"},
			IPFilter:        &storage.IPFilter{Mode: "deny", CIDRs: []string{"10.0.0.0/8"}},
			RateLimit:       &storage.RouteRateLimit{Events: 100, Window: "1m"},
			CountryBlock: countryblock.Config{
				Mode:        countryblock.ModeDeny,
				CountryList: []string{"CN", "RU"},
			},
		},
		// The path-rule surface, which is what the operator's 404 came
		// from. One rule per emitted shape: its own pool, an inherited
		// pool behind basic auth, a per-path IP filter, a per-path rate
		// limit, an exact-match redirect, and an auth exemption.
		//
		// On a route with NO active health check, mirroring the reason
		// the canonical fixture splits them: a real Caddy health-check
		// goroutine spawned during Provision races against the
		// concurrent provisioning of a PathRules subroute under the same
		// route.
		{
			ID:        "g-pathrules",
			Host:      "pathrules.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9110", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			PathRules: []storage.PathRule{
				{
					PathPrefix: "/api",
					Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9111", Weight: 1}},
					LBPolicy:   storage.LBPolicyRoundRobin,
				},
				{PathPrefix: "/docs", BasicAuth: &storage.BasicAuthRouteConfig{
					Username:     "doc",
					PasswordHash: argon,
				}},
				{PathPrefix: "/metrics", IPFilter: &storage.IPFilter{Mode: "allow", CIDRs: []string{"192.168.1.5"}}},
				{PathPrefix: "/burst", RateLimit: &storage.RouteRateLimit{Events: 5, Window: "10s"}},
				{
					PathPrefix: "/",
					MatchExact: true,
					Redirect:   &storage.PathRedirect{Target: "/admin/login", StatusCode: 302},
				},
			},
		},
		// A path pool that dials https with its own TLS identity, which
		// is autonomous from the route's (v2.23.1 / v2.60). Separate
		// route so the https transport shape is pinned on its own.
		{
			ID:        "g-pathpool-tls",
			Host:      "pathpool.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9120", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			PathRules: []storage.PathRule{
				{
					PathPrefix:            "/secure",
					Upstreams:             []storage.Upstream{{URL: "https://127.0.0.1:9121", Weight: 1}},
					LBPolicy:              storage.LBPolicyRoundRobin,
					InsecureSkipVerify:    true,
					UpstreamTLSServerName: "backend.internal",
				},
			},
		},
		// Route-level forward auth against a provider that RESOLVES,
		// plus a path rule carrying its own forward auth and another
		// exempted from the route's gate. This is the operator's exact
		// shape: "une prefix/header qui match une URI avec forward auth".
		{
			ID:         "g-forwardauth",
			Host:       "fwdauth.example.com",
			Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9130", Weight: 1}},
			LBPolicy:   storage.LBPolicyRoundRobin,
			WAFMode:    "off",
			TLSEnabled: true,
			AuthMode:   storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "authelia-prod",
			},
			PathRules: []storage.PathRule{
				{
					PathPrefix:  "/admin",
					ForwardAuth: &storage.ForwardAuthRouteConfig{ProviderName: "authelia-prod"},
				},
				{PathPrefix: "/webhook/", DisableRouteAuth: true},
			},
		},
		// Route-level forward auth against a provider that does NOT
		// resolve. The emitter short-circuits to a fail-closed deny
		// route and skips the rest of the chain, which is a control-flow
		// path the maintenance work has to keep intact (spec D6).
		{
			ID:        "g-forwardauth-missing",
			Host:      "fwdauth-missing.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9140", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
			AuthMode:  storage.RouteAuthForwardAuth,
			ForwardAuth: storage.ForwardAuthRouteConfig{
				ProviderName: "provider-deleted-since",
			},
		},
	}
}

// gatedOpts resolves one of the two provider names gatedRoutes uses, so
// both the resolvable and the fail-closed branches are exercised.
// AuthPassthroughPrefix is set because the passthrough route is emitted
// BEFORE the main one and must keep that position.
func gatedOpts() buildOpts {
	return buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authelia-prod": {
				Name:           "authelia-prod",
				VerifyURL:      "http://127.0.0.1:9091",
				AuthRequestURI: "/api/authz/forward-auth",
				CopyHeaders:    []string{"Remote-User", "Remote-Email"},
			},
		},
	}
}

// TestBuildConfigJSON_GatedEmissionByteIdentical is gate G2. The golden
// was captured from UNMODIFIED code before the maintenance-bypass work
// began; capturing it afterwards would prove only that the new code
// agrees with itself.
//
// A failure here means a route with no maintenance config now emits
// different bytes than it did before, which is precisely what must not
// happen. Read the diff; do not regenerate the golden.
func TestBuildConfigJSON_GatedEmissionByteIdentical(t *testing.T) {
	got, err := buildConfigJSON(gatedRoutes(), gatedOpts())
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	goldenPath := filepath.Join("testdata", "gated_emission_golden.json")
	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", goldenPath, err)
		}
		t.Logf("wrote golden snapshot (%d bytes) to %s", len(got), goldenPath)
		return
	}

	golden := readGolden(t, goldenPath)
	if string(got) != string(golden) {
		t.Fatalf("gated route emission changed — a route WITHOUT maintenance "+
			"now emits different bytes.\n got: %s\nwant: %s", got, golden)
	}
}

// TestGatedRoutes_CarryNoMaintenanceOrRedirect pins the fixture's own
// contract. The golden above is only an absolute requirement while none
// of its routes is a maintenance or redirect route — those two shapes
// change on purpose. Fold one in and the golden silently stops meaning
// what its name claims.
func TestGatedRoutes_CarryNoMaintenanceOrRedirect(t *testing.T) {
	for _, r := range gatedRoutes() {
		if r.MaintenanceConfig != nil {
			t.Errorf("route %s has a MaintenanceConfig: this fixture's golden must stay "+
				"byte-identical, and a maintenance route's shape changes by design", r.ID)
		}
		if r.RedirectConfig != nil {
			t.Errorf("route %s has a RedirectConfig: same reason", r.ID)
		}
	}
}
