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
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"
)

// v2.58 — exempting a path from the route's authentication.
//
// The operator's case: n8n behind Authentik. The editor must be protected,
// while /webhook/, /form/ and /rest/oauth2-credential/callback must be
// reachable by services that will never hold a session.
//
// This is the only thing a path rule may SUBTRACT, so these tests carry more
// weight than most: a mistake here does not degrade a feature, it opens a
// protected site.

const exemptHash = "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA"

func n8nProvider() storage.ForwardAuthProvider {
	return storage.ForwardAuthProvider{
		Name:           "authentik",
		Kind:           "authentik",
		VerifyURL:      "http://10.0.0.50:9000",
		AuthRequestURI: "/outpost.goauthentik.io/auth/caddy",
		CopyHeaders:    []string{"Remote-User", "Remote-Email", "X-Custom-Identity"},
	}
}

// n8nRoute mirrors the real shape: an IdP on the route, three exempted
// prefixes, and one ordinary rule that is NOT exempted.
func n8nRoute() []storage.Route {
	return []storage.Route{{
		ID:        "rid-n8n",
		Host:      "n8n.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:5678", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		AuthMode:  storage.RouteAuthForwardAuth,
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: "authentik",
		},
		PathRules: []storage.PathRule{
			{PathPrefix: "/webhook", DisableRouteAuth: true},
			{PathPrefix: "/form", DisableRouteAuth: true},
			{PathPrefix: "/rest/oauth2-credential/callback", DisableRouteAuth: true, MatchExact: true},
			{PathPrefix: "/metrics", RateLimit: &storage.RouteRateLimit{Events: 10, Window: "1m"}},
		},
	}}
}

func exemptOpts() buildOpts {
	return buildOpts{
		DevMode:              true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{"authentik": n8nProvider()},
	}
}

// routeHandlerChain returns the top-level handler names for the route whose
// host matches, in order.
func routeHandlerChain(t *testing.T, raw []byte, host string) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, s := range servers {
		routes, _ := s.(map[string]any)["routes"].([]any)
		for _, r := range routes {
			rm := r.(map[string]any)
			matches, _ := rm["match"].([]any)
			hit := false
			for _, m := range matches {
				hosts, _ := m.(map[string]any)["host"].([]any)
				for _, h := range hosts {
					if h == host {
						hit = true
					}
				}
			}
			if !hit {
				continue
			}
			out := make([]map[string]any, 0, 8)
			for _, h := range unwrapHandlers(rm) {
				hm, _ := h.(map[string]any)
				out = append(out, hm)
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	t.Fatalf("no route for host %q in the emitted config", host)
	return nil
}

// findExemptionPair locates the two handlers buildPathAuthExemption emits:
// the header strip (matched ON the exempted paths) and the gate (matched on
// NOT those paths).
func findExemptionPair(t *testing.T, raw []byte, host string) (strip, gate map[string]any) {
	t.Helper()
	for _, h := range routeHandlerChain(t, raw, host) {
		if h["handler"] != "subroute" {
			continue
		}
		routes, _ := h["routes"].([]map[string]any)
		var asAny []any
		if routes == nil {
			if ra, ok := h["routes"].([]any); ok {
				asAny = ra
			}
		}
		if asAny == nil {
			continue
		}
		for _, r := range asAny {
			rm, _ := r.(map[string]any)
			matches, _ := rm["match"].([]any)
			for _, m := range matches {
				mm, _ := m.(map[string]any)
				if _, negated := mm["not"]; negated {
					gate = h
				} else if _, onPath := mm["path"]; onPath {
					// Only the strip subroute matches a bare path at
					// this level; the path-rules subroute is keyed by
					// its own inner shape and carries a proxy.
					if handlers, _ := rm["handle"].([]any); len(handlers) == 1 {
						if hm, _ := handlers[0].(map[string]any); hm["handler"] == "headers" {
							strip = h
						}
					}
				}
			}
		}
	}
	return strip, gate
}

func TestPathAuthExemption_GateSkipsTheExemptedPaths(t *testing.T) {
	raw, err := buildConfigJSON(n8nRoute(), exemptOpts())
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	strip, gate := findExemptionPair(t, raw, "n8n.example.com")
	if gate == nil {
		t.Fatalf("no negated-path gate emitted; the route's auth would still run on the "+
			"exempted paths. config:\n%s", raw)
	}
	if strip == nil {
		t.Fatalf("no identity-header strip emitted for the exempted paths; a client could "+
			"send Remote-User and the backend would believe it. config:\n%s", raw)
	}

	// The negated set must name every exempted pattern and nothing else.
	routes := gate["routes"].([]any)
	match := routes[0].(map[string]any)["match"].([]any)[0].(map[string]any)
	notSets := match["not"].([]any)
	paths := notSets[0].(map[string]any)["path"].([]any)
	got := make([]string, 0, len(paths))
	for _, p := range paths {
		got = append(got, p.(string))
	}
	want := []string{
		"/form", "/form/*",
		"/rest/oauth2-credential/callback",
		"/webhook", "/webhook/*",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("negated paths = %v\nwant %v\n(the exact-match rule contributes its bare "+
			"pattern only; the prefix rules contribute both forms)", got, want)
	}

	// The gate itself is still the forward-auth handler, not something else.
	gateHandle := routes[0].(map[string]any)["handle"].([]any)
	if name, _ := gateHandle[0].(map[string]any)["handler"].(string); name != "reverse_proxy" {
		t.Errorf("gated handler = %q; want the forward-auth reverse_proxy", name)
	}
}

func TestPathAuthExemption_StripsTheIdentityHeaders(t *testing.T) {
	raw, err := buildConfigJSON(n8nRoute(), exemptOpts())
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	strip, _ := findExemptionPair(t, raw, "n8n.example.com")
	if strip == nil {
		t.Fatalf("no header strip emitted. config:\n%s", raw)
	}
	routes := strip["routes"].([]any)
	handle := routes[0].(map[string]any)["handle"].([]any)
	req := handle[0].(map[string]any)["request"].(map[string]any)
	del := req["delete"].([]any)
	got := map[string]bool{}
	for _, d := range del {
		got[d.(string)] = true
	}
	// The conventional set, which an upstream trusts whether or not the
	// provider copies it.
	for _, want := range []string{
		"Remote-User", "Remote-Email", "Remote-Groups", "Remote-Name",
		"X-Authentik-*", "X-Forwarded-User",
	} {
		if !got[want] {
			t.Errorf("%q is not stripped on the exempted paths; an upstream that trusts it "+
				"would accept a forged identity", want)
		}
	}
	// Plus whatever this provider copies, which is the set the upstream was
	// configured to read.
	if !got["X-Custom-Identity"] {
		t.Errorf("the provider's own copied header X-Custom-Identity is not stripped; " +
			"CopyHeaders must be folded into the strip list")
	}
	// Deduplicated: Remote-User is in both lists.
	count := 0
	for _, d := range del {
		if d.(string) == "Remote-User" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Remote-User appears %d times in the delete list; want 1", count)
	}
}

// THE non-regression: a route with no exempted path must emit exactly what it
// emitted before this feature existed — one auth handler, no subroute, no
// header strip.
func TestPathAuthExemption_NoExemptionEmitsTheOldChain(t *testing.T) {
	routes := n8nRoute()
	for i := range routes[0].PathRules {
		routes[0].PathRules[i].DisableRouteAuth = false
	}
	// The rules that only carried the exemption now carry nothing, so drop
	// them rather than emit an empty rule.
	routes[0].PathRules = routes[0].PathRules[3:]

	raw, err := buildConfigJSON(routes, exemptOpts())
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	strip, gate := findExemptionPair(t, raw, "n8n.example.com")
	if gate != nil {
		t.Errorf("a negated-path gate was emitted for a route with no exemption; the config " +
			"must be unchanged from before v2.58")
	}
	if strip != nil {
		t.Errorf("a header strip was emitted for a route with no exemption")
	}
	// The forward-auth handler is still there, plain, in the chain.
	found := false
	for _, h := range routeHandlerChain(t, raw, "n8n.example.com") {
		if h["handler"] == "reverse_proxy" {
			if _, isGate := h["handle_response"]; isGate {
				found = true
			}
		}
	}
	if !found && !jsonContains(raw, "/outpost.goauthentik.io/auth/caddy") {
		t.Errorf("the forward-auth handler disappeared from a non-exempted route:\n%s", raw)
	}
}

// Look-alike prefixes must not bleed: /webhook must not exempt /webhook-test,
// which Caddy's prefix form cannot match.
func TestPathAuthExemption_LookAlikePrefixesStaySeparate(t *testing.T) {
	routes := n8nRoute()
	routes[0].PathRules = []storage.PathRule{
		{PathPrefix: "/webhook", DisableRouteAuth: true},
		{PathPrefix: "/webhook-test", BasicAuth: &storage.BasicAuthRouteConfig{
			Username: "ops", PasswordHash: exemptHash,
		}},
	}
	raw, err := buildConfigJSON(routes, exemptOpts())
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	_, gate := findExemptionPair(t, raw, "n8n.example.com")
	if gate == nil {
		t.Fatalf("no gate emitted:\n%s", raw)
	}
	paths := gate["routes"].([]any)[0].(map[string]any)["match"].([]any)[0].(map[string]any)["not"].([]any)[0].(map[string]any)["path"].([]any)
	for _, p := range paths {
		if p.(string) == "/webhook-test" || p.(string) == "/webhook-test/*" {
			t.Errorf("/webhook-test was exempted, but only /webhook asked to be: %v", paths)
		}
	}
	if len(paths) != 2 {
		t.Errorf("exempted patterns = %v; want exactly /webhook and /webhook/*", paths)
	}
}

// Basic auth on the route gets the same treatment, with no provider to read
// copy-headers from.
func TestPathAuthExemption_WorksForRouteBasicAuth(t *testing.T) {
	routes := n8nRoute()
	routes[0].AuthMode = storage.RouteAuthBasic
	routes[0].ForwardAuth = storage.ForwardAuthRouteConfig{}
	routes[0].BasicAuth = storage.BasicAuthRouteConfig{Username: "ops", PasswordHash: exemptHash}

	raw, err := buildConfigJSON(routes, exemptOpts())
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	strip, gate := findExemptionPair(t, raw, "n8n.example.com")
	if gate == nil || strip == nil {
		t.Fatalf("exemption not emitted for a basic-auth route (strip=%v gate=%v):\n%s",
			strip != nil, gate != nil, raw)
	}
	if name, _ := gate["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["handler"].(string); name != "authentication" {
		t.Errorf("gated handler = %q; want authentication", name)
	}
	// Still strips the conventional set: basic auth sets no identity header,
	// so anything arriving under those names came from the client.
	del := strip["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)["request"].(map[string]any)["delete"].([]any)
	if len(del) < len(conventionalIdentityHeaders) {
		t.Errorf("delete list = %v; want at least the conventional set", del)
	}
}

// The emitted config must survive Caddy's own provisioning, which is where
// an unknown matcher shape or a malformed "not" would surface.
func TestPathAuthExemption_LoadsCleanly(t *testing.T) {
	// The metrics middleware refuses to provision without its registry,
	// which is a process-wide singleton the real binary installs at boot.
	// Same preamble as the other caddy.Validate tests in this package.
	metrics.SetRegistry(metrics.NewRegistry())

	raw, err := buildConfigJSON(n8nRoute(), buildOpts{
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{"authentik": n8nProvider()},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal into caddy.Config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate rejected the exemption config: %v\n\nThis pins that the "+
			"negated path matcher and the headers handler both provision. Config:\n%s", err, raw)
	}
}

// Storage refuses the contradiction, so the emitter never has to resolve it.
func TestPathAuthExemption_ExemptPlusIdPIsRefused(t *testing.T) {
	routes := n8nRoute()
	routes[0].PathRules = []storage.PathRule{{
		PathPrefix:       "/webhook",
		DisableRouteAuth: true,
		ForwardAuth:      &storage.ForwardAuthRouteConfig{ProviderName: "authentik"},
	}}
	if err := storage.ValidateRoute(routes[0]); err == nil {
		t.Error("a rule both exempted from the route's auth and requiring an IdP was accepted")
	}
}

// The exemption alone is complete content: that is the ordinary shape.
func TestPathAuthExemption_IsEnoughOnItsOwn(t *testing.T) {
	routes := n8nRoute()
	routes[0].PathRules = []storage.PathRule{{PathPrefix: "/webhook", DisableRouteAuth: true}}
	if err := storage.ValidateRoute(routes[0]); err != nil {
		t.Errorf("an exemption-only path rule was refused: %v", err)
	}
}

// Exempt + the rule's own basic auth is allowed on purpose: replace the
// route's identity gate with a shared secret on one path.
func TestPathAuthExemption_ExemptPlusOwnBasicAuthIsAllowed(t *testing.T) {
	routes := n8nRoute()
	routes[0].PathRules = []storage.PathRule{{
		PathPrefix:       "/webhook",
		DisableRouteAuth: true,
		BasicAuth:        &storage.BasicAuthRouteConfig{Username: "hook", PasswordHash: exemptHash},
	}}
	if err := storage.ValidateRoute(routes[0]); err != nil {
		t.Errorf("exemption plus the rule's own basic auth was refused: %v", err)
	}
}

// jsonContains is a readability helper for the "did this survive at all"
// assertions above.
func jsonContains(raw []byte, needle string) bool {
	return bytes.Contains(raw, []byte(needle))
}
