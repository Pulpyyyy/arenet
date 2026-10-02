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

// v2.58.1 — the forward-auth sub-request and the IdP passthrough route both
// go to the verify host, so they must agree about the Host header.
//
// They did not. buildForwardAuthHandler honoured RewriteVerifyHost and
// buildAuthPassthroughRoute ignored it, so an IdP behind a third-party
// reverse proxy that routes by Host — Authentik behind Traefik, the common
// deployment — had a working auth check and a broken sign-in round trip:
// every browser request to the IdP's own endpoint got that proxy's 404.
//
// Found while helping an operator wire exactly that topology. Arenet is not
// only for the case where it reaches the IdP directly, so both have to work
// from one setting.

func hostRewriteProvider(rewrite bool, verifyURL string) storage.ForwardAuthProvider {
	return storage.ForwardAuthProvider{
		Name:                  "idp",
		Kind:                  "authentik",
		VerifyURL:             verifyURL,
		AuthRequestURI:        "/outpost.goauthentik.io/auth/caddy",
		CopyHeaders:           []string{"X-authentik-username"},
		AuthPassthroughPrefix: "/outpost.goauthentik.io",
		RewriteVerifyHost:     rewrite,
	}
}

// hostOverride returns the Host the handler forces, or "" when it forces none.
func hostOverride(t *testing.T, h map[string]any) string {
	t.Helper()
	hdrs, ok := h["headers"].(map[string]any)
	if !ok {
		return ""
	}
	req, ok := hdrs["request"].(map[string]any)
	if !ok {
		return ""
	}
	set, ok := req["set"].(map[string][]string)
	if !ok {
		return ""
	}
	vals := set["Host"]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// passthroughProxy digs the reverse_proxy out of the emitted passthrough route.
func passthroughProxy(t *testing.T, p storage.ForwardAuthProvider) map[string]any {
	t.Helper()
	route := buildAuthPassthroughRoute(p, []string{"app.example.com"})
	if len(route.Handle) != 1 {
		t.Fatalf("passthrough route has %d handlers; want 1 subroute", len(route.Handle))
	}
	sub, _ := route.Handle[0]["routes"].([]map[string]any)
	if len(sub) != 1 {
		t.Fatalf("subroute has %d inner routes; want 1", len(sub))
	}
	handlers, _ := sub[0]["handle"].([]map[string]any)
	if len(handlers) != 1 {
		t.Fatalf("inner route has %d handlers; want 1", len(handlers))
	}
	return handlers[0]
}

// THE bug: with the rewrite on, both halves must force the IdP's host.
func TestForwardAuth_RewriteVerifyHost_AppliesToThePassthroughToo(t *testing.T) {
	p := hostRewriteProvider(true, "http://sso.example.com")

	gate := hostOverride(t, buildForwardAuthHandler(p))
	if gate != "sso.example.com" {
		t.Errorf("auth sub-request Host = %q; want sso.example.com", gate)
	}

	pass := hostOverride(t, passthroughProxy(t, p))
	if pass != "sso.example.com" {
		t.Errorf("passthrough Host = %q; want sso.example.com.\n\nWithout it, a reverse "+
			"proxy fronting the IdP routes the auth check but 404s every browser request "+
			"to the IdP's own endpoint, so the sign-in round trip cannot complete", pass)
	}
	if gate != pass {
		t.Errorf("the two halves disagree about Host (%q vs %q); they go to the same host, "+
			"so only one of them would arrive", gate, pass)
	}
}

// Arenet reaching the IdP directly: neither half forces a Host, so both carry
// the visitor's, which is what the IdP resolves the application from.
func TestForwardAuth_NoRewrite_NeitherHalfForcesAHost(t *testing.T) {
	p := hostRewriteProvider(false, "http://10.0.0.50:9000")

	if got := hostOverride(t, buildForwardAuthHandler(p)); got != "" {
		t.Errorf("auth sub-request forces Host = %q; want none", got)
	}
	if got := hostOverride(t, passthroughProxy(t, p)); got != "" {
		t.Errorf("passthrough forces Host = %q; want none — this is the direct-to-IdP "+
			"topology and the visitor's Host must reach the IdP untouched", got)
	}
}

// The port travels with the host when the verify URL carries one, because
// that is what a Host header needs to match a proxy's router.
func TestForwardAuth_RewriteVerifyHost_KeepsThePort(t *testing.T) {
	p := hostRewriteProvider(true, "http://sso.example.com:9000")
	if got := hostOverride(t, passthroughProxy(t, p)); got != "sso.example.com:9000" {
		t.Errorf("passthrough Host = %q; want sso.example.com:9000", got)
	}
}

// The HTTPS transport flip still happens, and now coexists with the header
// block rather than being overwritten by it.
func TestForwardAuth_RewriteVerifyHost_KeepsTheTLSTransport(t *testing.T) {
	p := hostRewriteProvider(true, "https://sso.example.com")
	rp := passthroughProxy(t, p)
	if got := hostOverride(t, rp); got != "sso.example.com" {
		t.Errorf("passthrough Host = %q; want sso.example.com", got)
	}
	if _, ok := rp["transport"]; !ok {
		t.Error("the https verify URL lost its TLS transport; the IdP would answer 400 " +
			"\"Client sent an HTTP request to an HTTPS server\"")
	}
}
