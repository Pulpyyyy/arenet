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

// v2.57 — a per-path IdP gate.
//
// For a path with no authentication of its own: an exposed /metrics, a
// debug console, an admin UI with nothing in front of it. Basic auth was
// the only identity gate a path could carry, and a shared password is a
// poor answer when the operator already runs an IdP.
//
// The invariant that matters most is fail-closed. An auth control that
// stops gating without saying so serves the path to anyone, which is worse
// than being unavailable.

func idpProvider() storage.ForwardAuthProvider {
	return storage.ForwardAuthProvider{
		Name:           "authentik",
		Kind:           "authentik",
		VerifyURL:      "http://10.0.0.50:9000",
		AuthRequestURI: "/outpost.goauthentik.io/auth/caddy",
		CopyHeaders:    []string{"Remote-User", "Remote-Email"},
	}
}

func forwardAuthPathRoute(providerName string) []storage.Route {
	return []storage.Route{{
		ID:        "rid-1",
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{{
			PathPrefix:  "/metrics",
			ForwardAuth: &storage.ForwardAuthRouteConfig{ProviderName: providerName},
		}},
	}}
}

// firstPathRuleHandlers returns the handler names of the first path rule in
// the emitted subroute.
func firstPathRuleHandlers(t *testing.T, raw []byte) []string {
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

func TestPathForwardAuth_EmitsTheGateBeforeTheProxy(t *testing.T) {
	raw, err := buildConfigJSON(forwardAuthPathRoute("authentik"), buildOpts{
		DevMode:              true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{"authentik": idpProvider()},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	order := firstPathRuleHandlers(t, raw)
	if len(order) < 2 {
		t.Fatalf("chain = %v; want a gate then the proxy", order)
	}
	// The gate is a reverse_proxy to the IdP, as the route level emits.
	if order[0] != "reverse_proxy" {
		t.Errorf("chain = %v; the IdP gate must come first", order)
	}
	if order[len(order)-1] != "reverse_proxy" {
		t.Errorf("chain = %v; the backend proxy must still be last", order)
	}
	if !strings.Contains(string(raw), "/outpost.goauthentik.io/auth/caddy") {
		t.Errorf("the provider's auth URI is not in the emitted config")
	}
	if !strings.Contains(string(raw), "Remote-User") {
		t.Errorf("the provider's copied headers are not emitted")
	}
}

// THE invariant: a provider that no longer exists must make the path
// unavailable, never open. An auth control that quietly stops gating serves
// the path to anyone.
//
// Two things make that hold, and only one of them is ours. Caddy's
// static_response returns nil instead of calling next for every status but
// 103 Early Hints (caddy v2.11.3 modules/caddyhttp/staticresp.go:253-257),
// so the 503 ends the request on its own. This test asserts the stronger
// structural property — nothing is emitted after the refusal at all — so
// the guarantee does not rest on that upstream detail staying true, and so
// the emitted config cannot be misread as serving the path.
func TestPathForwardAuth_FailsClosedWhenTheProviderIsGone(t *testing.T) {
	raw, err := buildConfigJSON(forwardAuthPathRoute("deleted-idp"), buildOpts{
		DevMode:              true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{"authentik": idpProvider()},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	order := firstPathRuleHandlers(t, raw)
	if len(order) != 1 || order[0] != "static_response" {
		t.Fatalf("chain = %v; a missing provider must emit the refusal and nothing after it", order)
	}
	if !strings.Contains(string(raw), "deleted-idp") {
		t.Errorf("the 503 does not name the missing provider, so nobody can fix it")
	}
	if !strings.Contains(string(raw), "503") {
		t.Errorf("the refusal is not a 503: %s", raw)
	}
}

// The rest of the route keeps working: only the gated path is affected.
func TestPathForwardAuth_LeavesTheRestOfTheRouteAlone(t *testing.T) {
	raw, err := buildConfigJSON(forwardAuthPathRoute("deleted-idp"), buildOpts{
		DevMode:              true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// The subroute's catch-all (no match) still proxies, so a request
	// outside /metrics is served normally.
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(string(raw), "10.0.0.2:80") {
		t.Errorf("the route's own backend disappeared: %s", raw)
	}
}

// Storage refuses two identity gates on one rule, so the emitter never has
// to decide which wins.
func TestPathForwardAuth_BothGatesOnOneRuleIsRefused(t *testing.T) {
	routes := forwardAuthPathRoute("authentik")
	routes[0].PathRules[0].BasicAuth = &storage.BasicAuthRouteConfig{
		Username:     "ops",
		PasswordHash: "$argon2id$v=19$m=65536,t=1,p=4$c29tZXNhbHQ$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA",
	}
	if err := storage.ValidateRoute(routes[0]); err == nil {
		t.Error("a rule carrying both basic auth and forward auth was accepted")
	}
}

func TestPathForwardAuth_EmptyProviderNameIsRefused(t *testing.T) {
	routes := forwardAuthPathRoute("")
	if err := storage.ValidateRoute(routes[0]); err == nil {
		t.Error("a forward-auth gate with no provider name was accepted")
	}
}

// A forward-auth-only rule is complete content: it gates a path the route
// otherwise serves normally.
func TestPathForwardAuth_IsEnoughOnItsOwn(t *testing.T) {
	if err := storage.ValidateRoute(forwardAuthPathRoute("authentik")[0]); err != nil {
		t.Errorf("a forward-auth-only path rule was refused: %v", err)
	}
}
