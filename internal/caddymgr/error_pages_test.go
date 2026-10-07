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

// Step R — error-pages emit unit tests.
//
// Two layers : (a) pure resolution-order checks on resolveErrorPage,
// (b) caddymgr-side struct emission via buildErrorRoutesForRoute +
// buildErrorRoutesForServer + a full caddy.Validate integration
// check on a route that uses the feature end-to-end.

// --- Resolution order --------------------------------------------------------

func TestResolveErrorPage_OverrideWinsOverTemplate(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {ID: "t1", Pages: map[int]string{403: "<h1>template-403</h1>"}},
	}
	route := storage.Route{
		ErrorPageTemplateID: "t1",
		ErrorPageOverrides:  map[int]string{403: "<h1>override-403</h1>"},
	}
	got := resolveErrorPage(route, 403, templates)
	if got != "<h1>override-403</h1>" {
		t.Errorf("override layer should win ; got %q", got)
	}
}

func TestResolveErrorPage_TemplateWinsOverDefault(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {ID: "t1", Pages: map[int]string{403: "<h1>template-403</h1>"}},
	}
	route := storage.Route{ErrorPageTemplateID: "t1"}
	got := resolveErrorPage(route, 403, templates)
	if got != "<h1>template-403</h1>" {
		t.Errorf("template layer should win over default ; got %q", got)
	}
}

func TestResolveErrorPage_DefaultUsedWhenNothingConfigured(t *testing.T) {
	route := storage.Route{}
	got := resolveErrorPage(route, 403, nil)
	if !strings.Contains(got, "Forbidden") {
		t.Errorf("expected built-in default for 403 ; got %q", got)
	}
}

func TestResolveErrorPage_DanglingTemplateRefFallsBackToDefault(t *testing.T) {
	route := storage.Route{ErrorPageTemplateID: "deleted-template"}
	// Empty templates map → ref dangles → should return default.
	got := resolveErrorPage(route, 404, map[string]storage.ErrorPageTemplate{})
	if !strings.Contains(got, "Not Found") {
		t.Errorf("dangling ref should fall back to default ; got %q", got)
	}
}

func TestResolveErrorPage_EmptyOverrideFallsThroughToTemplate(t *testing.T) {
	// Operator-visible UX : leaving an override empty in the UI
	// means "disable this code's override" — should resolve to
	// the template, NOT to "no body".
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {ID: "t1", Pages: map[int]string{403: "<h1>template-403</h1>"}},
	}
	route := storage.Route{
		ErrorPageTemplateID: "t1",
		ErrorPageOverrides:  map[int]string{403: ""},
	}
	got := resolveErrorPage(route, 403, templates)
	if got != "<h1>template-403</h1>" {
		t.Errorf("empty override should fall through to template ; got %q", got)
	}
}

func TestResolveErrorPage_UnsupportedCodeReturnsEmpty(t *testing.T) {
	route := storage.Route{}
	got := resolveErrorPage(route, 418, nil)
	if got != "" {
		t.Errorf("unsupported code should return empty ; got %q", got)
	}
}

// --- Per-route route emission ------------------------------------------------

func TestBuildErrorRoutesForRoute_EmitsOnePerSupportedCode(t *testing.T) {
	route := storage.Route{
		ID:        "r1",
		Host:      "example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	// Built-in default covers all 8 codes → 8 per-code routes, PLUS the
	// generic fallback route appended last (empty-body-400 class fix).
	wantLen := len(storage.SupportedErrorStatusCodes) + 1
	if len(got) != wantLen {
		t.Fatalf("expected %d routes (8 per-code + 1 generic fallback) ; got %d", wantLen, len(got))
	}
	// The first 8 routes each carry the expression matcher for their code.
	for i, code := range storage.SupportedErrorStatusCodes {
		r := got[i]
		if len(r.Match) != 1 {
			t.Errorf("route[%d] expected 1 matcher set ; got %d", i, len(r.Match))
			continue
		}
		wantExpr := "{http.error.status_code} == " + intToStr(code)
		if r.Match[0].Expression != wantExpr {
			t.Errorf("route[%d] expression = %q ; want %q", i, r.Match[0].Expression, wantExpr)
		}
		// Host is scoped to the route's host (defence-in-depth).
		if len(r.Match[0].Host) != 1 || r.Match[0].Host[0] != "example.com" {
			t.Errorf("route[%d] host scope = %v ; want [example.com]", i, r.Match[0].Host)
		}
		// Handler is static_response.
		if len(r.Handle) != 1 || r.Handle[0]["handler"] != "static_response" {
			t.Errorf("route[%d] handler = %v ; want static_response", i, r.Handle)
		}
	}
	// The final route is the generic fallback: host-scoped, NO per-code
	// Expression (matches any status). Covered in depth by
	// TestBuildErrorRoutesForRoute_EmitsGenericFallback.
	fallback := got[len(got)-1]
	if fallback.Match[0].Expression != "" {
		t.Errorf("final route must be the generic fallback (no Expression); got %q", fallback.Match[0].Expression)
	}
}

func TestBuildErrorRoutesForRoute_NoHostsReturnsNil(t *testing.T) {
	route := storage.Route{} // no Host, no Aliases
	got := buildErrorRoutesForRoute(route, nil, nil)
	if got != nil {
		t.Errorf("expected nil for hostless route ; got %d entries", len(got))
	}
}

func TestBuildErrorRoutesForRoute_HostMatcherIncludesAliases(t *testing.T) {
	route := storage.Route{
		Host:      "primary.example.com",
		Aliases:   []string{"alias1.example.com", "alias2.example.com"},
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	if len(got) == 0 {
		t.Fatal("expected non-empty routes")
	}
	hosts := got[0].Match[0].Host
	if len(hosts) != 3 || hosts[0] != "primary.example.com" {
		t.Errorf("host matcher = %v ; want [primary, alias1, alias2]", hosts)
	}
}

// --- Sanitization -----------------------------------------------------------

// v2.18.0 security — operator-supplied custom page bodies flow into a
// Caddy static_response body, which is placeholder-expanded at serve
// time (repl.ReplaceKnown). {env.*} resolves secrets from Arenet's
// process environment and {file.*} reads arbitrary files off disk,
// regardless of request state — so an admin-typed {env.SECRET} would
// leak into the PUBLIC error/maintenance body. SanitizeErrorPageBody
// must neutralize these dangerous namespaces while leaving the
// documented-safe {http.request.*} and {arenet.*} placeholders intact.
func TestSanitizeErrorPageBody_NeutralizesEnvAndFilePlaceholders(t *testing.T) {
	// The {arenet.*} sample is a sentinel that actually exists, so this
	// asserts the sanitizer against a string the product really emits.
	in := `<p>{env.SECRET_TOKEN}</p><p>{file./etc/passwd}</p><p>host {http.request.host}</p><p>` + maintenanceRetryAfterHumanSentinel + `</p>`
	got := SanitizeErrorPageBody(in)

	// Dangerous namespaces neutralized (the literal live prefix must
	// not survive so Caddy can't expand it).
	if strings.Contains(got, "{env.SECRET_TOKEN}") {
		t.Errorf("{env.*} placeholder survived — secret disclosure vector: %q", got)
	}
	if strings.Contains(got, "{file./etc/passwd}") {
		t.Errorf("{file.*} placeholder survived — file disclosure vector: %q", got)
	}
	// Documented-safe placeholders preserved (still expandable by Caddy).
	if !strings.Contains(got, "{http.request.host}") {
		t.Errorf("documented {http.request.host} was wrongly neutralized: %q", got)
	}
	if !strings.Contains(got, maintenanceRetryAfterHumanSentinel) {
		t.Errorf("documented {arenet.*} placeholder was wrongly neutralized: %q", got)
	}
}

func TestErrorPageSanitizer_StripsScriptTag(t *testing.T) {
	// XSS payload should never reach the emitted body, even from
	// an admin who typed it deliberately. UGCPolicy bans script.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			403: `<h1>403</h1><script>alert(1)</script>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	if len(got) == 0 {
		t.Fatal("expected at least one route")
	}
	// Find the 403 route.
	var body403 string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 403 {
			body403 = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if strings.Contains(body403, "<script>") {
		t.Errorf("sanitizer did not strip <script> ; got %q", body403)
	}
	if !strings.Contains(body403, "<h1>403</h1>") {
		t.Errorf("sanitizer stripped legitimate content ; got %q", body403)
	}
}

func TestErrorPageSanitizer_StripsEventHandlers(t *testing.T) {
	// Inline event handlers are a classic XSS vector. Bluemonday
	// UGCPolicy bans them all.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			404: `<a href="/" onclick="alert(1)">home</a>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	var body string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 404 {
			body = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if strings.Contains(body, "onclick") {
		t.Errorf("sanitizer did not strip onclick ; got %q", body)
	}
}

func TestErrorPageSanitizer_PrependsDoctype(t *testing.T) {
	// bluemonday strips the <!doctype> declaration by design
	// (sanitize.go:241). postSanitize re-prepends it so
	// browsers render in standards mode. Verified empirically
	// at Step R smoke : without the prepend the operator's
	// CSS rendered in quirks mode and looked wrong.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			502: `<!doctype html><html><head><title>x</title></head><body>x</body></html>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	var body string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 502 {
			body = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if !strings.HasPrefix(body, "<!doctype html>") {
		t.Errorf("doctype prefix missing ; got %q", body[:min(80, len(body))])
	}
}

func TestPostSanitize_FragmentNoDoctype(t *testing.T) {
	// Operator wrote just <h1>...</h1> — not a full document.
	// postSanitize must NOT prepend <!doctype html> because
	// the browser would interpret it as a separate document.
	got := postSanitize("<h1>just a fragment</h1>")
	if strings.HasPrefix(got, "<!doctype") {
		t.Errorf("fragment got unwanted doctype prefix: %q", got)
	}
}

func TestErrorPageSanitizer_PreservesCaddyPlaceholders(t *testing.T) {
	// Critical : the sanitizer must not destroy Caddy's
	// {placeholder} syntax — the curly braces are not HTML
	// special chars but a regex-style sanitizer could mangle
	// them. Bluemonday operates on the HTML tree, not on text.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			500: `<p>id: {http.request.uuid}</p>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	var body string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 500 {
			body = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if !strings.Contains(body, "{http.request.uuid}") {
		t.Errorf("sanitizer destroyed Caddy placeholder ; got %q", body)
	}
}

// --- Per-server emission split ----------------------------------------------

func TestBuildErrorRoutesForServer_SplitsByTLS(t *testing.T) {
	routes := []storage.Route{
		{Host: "http.example.com", Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}}, TLSEnabled: false},
		{Host: "https.example.com", Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}}, TLSEnabled: true},
	}
	httpRoutes := buildErrorRoutesForServer(routes, nil, false, nil)
	httpsRoutes := buildErrorRoutesForServer(routes, nil, true, nil)
	if len(httpRoutes) == 0 || len(httpsRoutes) == 0 {
		t.Fatalf("expected both servers populated ; got http=%d https=%d", len(httpRoutes), len(httpsRoutes))
	}
	// Each server should only carry its TLS-scope's hosts.
	for _, r := range httpRoutes {
		if r.Match[0].Host[0] != "http.example.com" {
			t.Errorf("HTTP server got non-HTTP host: %v", r.Match[0].Host)
		}
	}
	for _, r := range httpsRoutes {
		if r.Match[0].Host[0] != "https.example.com" {
			t.Errorf("HTTPS server got non-HTTPS host: %v", r.Match[0].Host)
		}
	}
}

// --- Shape pin (no caddy.Validate spawn — see precedent in
//     manager_https_upstream_test.go:210 explaining why a second
//     caddy.Validate test in this package poisons
//     TestSyncRegistry_NotCalledOnReloadFailure via leftover
//     admin-endpoint state. Step R folds its caddy.Validate
//     coverage into the existing TestBuildConfigJSON_LoadsCleanly
//     fixture via the extra `r-errpages` route declared there ;
//     this file pins the JSON SHAPE separately without spinning
//     up a real Caddy.) ------------------------------------------

// TestBuildConfigJSON_EmitsErrorsBlock_WhenAnyRouteOptsIn pins the
// presence + shape of the apps.http.servers.<*>.errors block in
// the emitted JSON when at least one route declares an override or
// template ref. Uses a raw map decode so a future struct refactor
// can't accidentally rename the field without flagging.
func TestBuildConfigJSON_EmitsErrorsBlock_WhenAnyRouteOptsIn(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-override",
			Host:      "override.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			ErrorPageOverrides: map[int]string{
				404: "<h1>404 — override</h1>",
			},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := generic["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	srv := servers["arenet_http"].(map[string]any)
	errors, has := srv["errors"]
	if !has {
		t.Fatal("apps.http.servers.arenet_http.errors absent ; expected when a route declares overrides")
	}
	errorsMap := errors.(map[string]any)
	errorRoutes, has := errorsMap["routes"].([]any)
	if !has {
		t.Fatal("errors.routes absent or wrong type")
	}
	// 8 codes default + override merges → 8 per-code routes (the
	// override REPLACES the default for code 404, doesn't ADD), PLUS
	// the generic fallback route appended per host (empty-body-400 fix).
	if got := len(errorRoutes); got != len(storage.SupportedErrorStatusCodes)+1 {
		t.Errorf("errors.routes len = %d ; want %d (8 per-code + 1 generic fallback)", got, len(storage.SupportedErrorStatusCodes)+1)
	}
	// Spot-check first route shape : match.expression +
	// handler=static_response.
	r0 := errorRoutes[0].(map[string]any)
	match := r0["match"].([]any)
	m0 := match[0].(map[string]any)
	expr, has := m0["expression"]
	if !has {
		t.Error("first error route lacks `expression` matcher")
	}
	if exprStr, ok := expr.(string); !ok || !strings.Contains(exprStr, "{http.error.status_code}") {
		t.Errorf("expression matcher = %v ; want {http.error.status_code} == <code>", expr)
	}
	handle := r0["handle"].([]any)
	h0 := handle[0].(map[string]any)
	if h0["handler"] != "static_response" {
		t.Errorf("handler = %v ; want static_response", h0["handler"])
	}
}

// TestBuildConfigJSON_EmitsErrorsBlock_ForEveryRoute pins the
// Phase 1.1 invariant : the Errors block is emitted on every
// route regardless of operator opt-in. Phase 1 wrongly gated
// the emit on "at least one route has a template/override" to
// preserve byte-identical JSON for pre-R rollout ; smoke
// caught a freshly-created route serving Caddy's bare
// "404 page not found" plain-text instead of the Arenet
// branded default. The gate was deleted ; this test pins
// the absence of any regression that would re-introduce it.
func TestBuildConfigJSON_EmitsErrorsBlock_ForEveryRoute(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r1",
			Host:      "noerror.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			// No template ref, no overrides : the built-in
			// Arenet default still applies.
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := generic["apps"].(map[string]any)
	http := apps["http"].(map[string]any)
	servers := http["servers"].(map[string]any)
	srv := servers["arenet_http"].(map[string]any)
	errors, has := srv["errors"]
	if !has {
		t.Fatal("arenet_http.errors absent — Phase 1.1 invariant broken (every route gets the branded default)")
	}
	errorsMap := errors.(map[string]any)
	errorRoutes, has := errorsMap["routes"].([]any)
	if !has || len(errorRoutes) != len(storage.SupportedErrorStatusCodes)+1 {
		t.Errorf("errors.routes len = %d ; want %d (one per supported code + 1 generic fallback)",
			len(errorRoutes), len(storage.SupportedErrorStatusCodes)+1)
	}
}

// --- Phase 1.1 FIX 3 : upstream 4xx/5xx catch ------------------------------

// TestBuildConfigJSON_ReverseProxy_HandleResponse4xx5xx pins the
// Phase 1.1 invariant that every reverse_proxy handler carries a
// handle_response block matching upstream errors and re-emitting
// via http.handlers.error so the server's errors.routes chain
// fires on upstream 4xx/5xx (not only on Caddy-generated errors).
//
// 2026-06-24 update — the original `[4, 5]` wildcard match was
// narrowed to an explicit code list EXCLUDING 401 + 407 after the
// operator-reported Harbor / Docker registry bug : the wildcard
// converted the upstream's 401 + Www-Authenticate response into
// a Caddy HandlerError, which replaced the response headers with
// the branded HTML body. Docker registry v2's challenge flow
// can't complete without the Www-Authenticate header reaching
// the client. 401 + 407 now pass through verbatim.
//
// This test pins the narrowed list shape AND the explicit
// non-presence of 401 + 407 in the match.
func TestBuildConfigJSON_ReverseProxy_HandleResponse4xx5xx(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r1",
			Host:      "example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Generic map decode so we don't pull a full Caddy
	// reverseproxy struct in just to find the handle_response
	// nested field.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := generic["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	srv := servers["arenet_http"].(map[string]any)
	srvRoutes := srv["routes"].([]any)

	// Walk the route → subroute → handlers chain to find the
	// reverse_proxy handler. Routes use the wrapInSubroute
	// canonical shape (manager.go:wrapInSubroute) so we have
	// to traverse two levels.
	found := false
	for _, r := range srvRoutes {
		rMap := r.(map[string]any)
		handlers, ok := rMap["handle"].([]any)
		if !ok {
			continue
		}
		for _, h := range handlers {
			hMap := h.(map[string]any)
			if hMap["handler"] != "subroute" {
				continue
			}
			subroutes, ok := hMap["routes"].([]any)
			if !ok {
				continue
			}
			for _, sr := range subroutes {
				srMap := sr.(map[string]any)
				subHandlers, ok := srMap["handle"].([]any)
				if !ok {
					continue
				}
				for _, sh := range subHandlers {
					shMap := sh.(map[string]any)
					if shMap["handler"] != "reverse_proxy" {
						continue
					}
					// Found a reverse_proxy. Pin the
					// handle_response shape.
					hr, ok := shMap["handle_response"].([]any)
					if !ok {
						t.Fatal("reverse_proxy missing handle_response — Phase 1.1 FIX 3 regression")
					}
					// fix/error-template-preserve-json: the proxy now
					// emits TWO handle_response blocks — [0] application/
					// json* response pass-through, [1] status-only whose
					// inner routes are [/api/* → copy_response] then the
					// branding error handler (fall-through). This test
					// pins the branding block's status-code contract, so
					// it reads block [1]'s outer status_code list and its
					// SECOND inner route (the match-less error fallback).
					if len(hr) != 2 {
						t.Fatalf("handle_response len = %d ; want 2 (json passthrough + api-path/branding)", len(hr))
					}
					brandingBlock := hr[1].(map[string]any)
					match := brandingBlock["match"].(map[string]any)
					statusCodes := match["status_code"].([]any)

					// Build a quick lookup set on the
					// emitted codes (JSON decode gives
					// float64 for ints).
					emitted := make(map[int]bool, len(statusCodes))
					for _, sc := range statusCodes {
						emitted[int(sc.(float64))] = true
					}

					// 2026-06-24 contract : 401 + 407 MUST
					// NOT be in the intercept list — they
					// pass through verbatim so the upstream's
					// Www-Authenticate / Proxy-Authenticate
					// headers reach the client.
					for _, mustPassthrough := range []int{401, 407} {
						if emitted[mustPassthrough] {
							t.Errorf("status_code list contains %d but it MUST pass through verbatim (Www-Authenticate / Proxy-Authenticate challenge header) ; got list=%v",
								mustPassthrough, statusCodes)
						}
					}

					// Spot-check : the common branded
					// codes are still intercepted.
					for _, mustIntercept := range []int{403, 404, 429, 500, 502, 503, 504} {
						if !emitted[mustIntercept] {
							t.Errorf("status_code list missing %d (operator branded body should fire) ; got list=%v",
								mustIntercept, statusCodes)
						}
					}

					// The branding error handler is the SECOND (match-less
					// fall-through) inner route; route[0] is the /api/*
					// copy_response pass-through.
					innerRoutes := brandingBlock["routes"].([]any)
					brandRoute := innerRoutes[len(innerRoutes)-1].(map[string]any)
					innerHandlers := brandRoute["handle"].([]any)
					errHandler := innerHandlers[0].(map[string]any)
					if errHandler["handler"] != "error" {
						t.Errorf("inner handler = %v ; want 'error'", errHandler["handler"])
					}
					if errHandler["status_code"] != "{http.reverse_proxy.status_code}" {
						t.Errorf("error.status_code = %v ; want {http.reverse_proxy.status_code}", errHandler["status_code"])
					}
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("no reverse_proxy handler found in emitted config")
	}
}

// intToStr is a tiny helper kept local to avoid pulling strconv
// into the test file's import for a single Sprintf-equivalent.
func intToStr(i int) string {
	switch i {
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 429:
		return "429"
	case 500:
		return "500"
	case 502:
		return "502"
	case 503:
		return "503"
	case 504:
		return "504"
	}
	return "?"
}

// --- Phase 2.2 : AllowUnsafe safety probe + @import strip --------------------
//
// Pinning the empirical findings from the R.2.2 audit. Each
// case here was first verified against a standalone bluemonday
// probe ; the test set protects the invariants from a future
// "let's tighten / loosen the policy" refactor.

func TestSanitizeErrorPageBody_PreservesStyleBlockContent(t *testing.T) {
	// Phase 2.2 fix : <style> rules MUST survive sanitization.
	// Pre-fix the inner CSS was stripped → builtin Arenet
	// branded page rendered as bare HTML in prod.
	input := `<style>body { background:#0d1117; color:#c9d1d9; }</style>`
	got := SanitizeErrorPageBody(input)
	if !strings.Contains(got, "background:#0d1117") {
		t.Errorf("CSS rules stripped ; got %q", got)
	}
	if !strings.Contains(got, "color:#c9d1d9") {
		t.Errorf("CSS rules stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_StripsScriptDespiteAllowUnsafe(t *testing.T) {
	// AllowUnsafe(true) is set on the policy ; the safety
	// invariant is that <script> is STILL stripped because
	// it's not declared in AllowElements. The element policy
	// runs BEFORE the AllowUnsafe gate at sanitize.go:431-440.
	input := `<h1>before</h1><script>alert('xss')</script><h1>after</h1>`
	got := SanitizeErrorPageBody(input)
	if strings.Contains(got, "<script>") || strings.Contains(got, "alert") {
		t.Errorf("script not stripped ; got %q", got)
	}
	// Legitimate content survives.
	if !strings.Contains(got, "<h1>before</h1>") {
		t.Errorf("legitimate content stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_StripsEventHandlersDespiteAllowUnsafe(t *testing.T) {
	// Inline event handlers come from a separate UGCPolicy
	// attribute allowlist ; AllowUnsafe has no impact.
	input := `<a href="/" onclick="hack()">link</a>`
	got := SanitizeErrorPageBody(input)
	if strings.Contains(got, "onclick") {
		t.Errorf("onclick not stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_StripsAtImportFromStyleBlock(t *testing.T) {
	// @import is the classic CSS-based exfil vector
	// (cascades to a remote stylesheet that can ping-back to
	// a tracking server). Operator-typed @import is still
	// stripped defence-in-depth even though the operator
	// role is admin (compromised-admin / reflected-XSS-via-
	// template scenarios).
	input := `<style>@import url("https://evil.example/track"); body { color:red; }</style>`
	got := SanitizeErrorPageBody(input)
	if strings.Contains(got, "@import") {
		t.Errorf("@import not stripped ; got %q", got)
	}
	if strings.Contains(got, "evil.example") {
		t.Errorf("@import target leaked ; got %q", got)
	}
	// Legitimate rules in the same block survive.
	if !strings.Contains(got, "color:red") {
		t.Errorf("non-@import rules stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_StripsAtCharsetFromStyleBlock(t *testing.T) {
	input := `<style>@charset "UTF-8"; body { color:red; }</style>`
	got := SanitizeErrorPageBody(input)
	if strings.Contains(got, "@charset") {
		t.Errorf("@charset not stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_PreservesUrlForBrandingAssets(t *testing.T) {
	// url() in background-image / @font-face / etc. is left
	// untouched because legitimate branding use cases (logo,
	// custom fonts) need it. The admin-only RequireAdmin
	// gate is the trust boundary ; defending here against
	// admin-typed url() would just break the operator's
	// brand image embeds.
	input := `<style>body { background-image: url(https://cdn.example/logo.png); }</style>`
	got := SanitizeErrorPageBody(input)
	if !strings.Contains(got, "url(https://cdn.example/logo.png)") {
		t.Errorf("legitimate url() stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_StripsIframe(t *testing.T) {
	input := `<h1>x</h1><iframe src="evil"></iframe>`
	got := SanitizeErrorPageBody(input)
	if strings.Contains(got, "<iframe") {
		t.Errorf("iframe not stripped ; got %q", got)
	}
}

func TestSanitizeErrorPageBody_BuiltinDefaultRendersStyled(t *testing.T) {
	// End-to-end : run the real builtin 429 page through the
	// pipeline. After 2.2 fix, the resulting body MUST contain
	// the dark-theme background rule. Pre-fix it didn't.
	body, ok := ArenetDefaultErrorPages(429)
	if !ok {
		t.Fatal("builtin 429 missing")
	}
	got := SanitizeErrorPageBody(body)
	// The slate dark theme background lives in a <style> block
	// at the top of the builtin page.
	if !strings.Contains(got, "background:#0d1117") {
		t.Errorf("builtin 429 lost its dark-theme background after sanitize ; "+
			"got first 200 chars:\n%s", got[:min(200, len(got))])
	}
	// Sanity : <!doctype html> still re-prepended by postSanitize.
	if !strings.HasPrefix(got, "<!doctype html>") {
		t.Errorf("doctype prefix lost ; got first 60 chars : %q", got[:min(60, len(got))])
	}
}

func TestStripDangerousAtRules_OnlyTouchesStyleBlocks(t *testing.T) {
	// Defence-in-depth : the regex must NOT mangle
	// @import-shaped strings that appear OUTSIDE <style>
	// blocks (e.g. in a <pre> code sample or in body text
	// explaining how to use the feature).
	input := `<p>To use, write @import url("foo");</p><style>@import url("evil");</style>`
	got := stripDangerousAtRules(input)
	// @import in <p> text body stays untouched.
	if !strings.Contains(got, "<p>To use, write @import url(") {
		t.Errorf("text-body @import was mangled ; got %q", got)
	}
	// @import in <style> is stripped.
	if strings.Contains(got, "@import url(\"evil\")") {
		t.Errorf("style-block @import not stripped ; got %q", got)
	}
}

// TestBuildErrorRoutesForRoute_EmitsGenericFallback pins the fix for
// the empty-body-400 class of bug: the reverse_proxy handle_response
// intercepts ~40 upstream 4xx/5xx codes (manager.go), but only the 8
// SupportedErrorStatusCodes have a branded page. A code like 400
// (Home Assistant returns it for an untrusted X-Forwarded-For proxy),
// 402, 405, 409, 501, ... was re-raised into the errors chain, matched
// no per-code route, and finalized as a bare empty-body response.
//
// The fix appends a GENERIC fallback error route per host: no
// per-code Expression (so it matches any status that reaches the
// errors subroute), serving a branded body that renders the live
// {http.error.status_code}. This guarantees no intercepted code ever
// yields an empty body.
func TestBuildErrorRoutesForRoute_EmitsGenericFallback(t *testing.T) {
	route := storage.Route{
		ID:        "r-fallback",
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	if len(got) == 0 {
		t.Fatal("expected at least the generic fallback route, got none")
	}
	// The LAST route must be the generic fallback: matches the host,
	// carries NO per-code Expression (matches every error status), and
	// serves a non-empty body that uses the live status-code placeholder.
	last := got[len(got)-1]
	if len(last.Match) != 1 {
		t.Fatalf("fallback route: want 1 matcher set, got %d", len(last.Match))
	}
	if last.Match[0].Expression != "" {
		t.Errorf("fallback route must have NO per-code Expression (must match any status); got %q", last.Match[0].Expression)
	}
	if len(last.Match[0].Host) == 0 || last.Match[0].Host[0] != "app.example.com" {
		t.Errorf("fallback route host = %v; want [app.example.com]", last.Match[0].Host)
	}
	if len(last.Handle) == 0 {
		t.Fatal("fallback route has no handler")
	}
	body, _ := last.Handle[0]["body"].(string)
	if body == "" {
		t.Error("fallback route serves an empty body — defeats the purpose")
	}
	sc, _ := last.Handle[0]["status_code"].(string)
	if sc != "{http.error.status_code}" {
		t.Errorf("fallback status_code = %q; want the live placeholder {http.error.status_code}", sc)
	}
}

// TestErrorPages_UseEscapedURIPlaceholder is a security guard: the branded
// error bodies MUST reference {http.request.uri_escaped}, never the raw
// {http.request.uri}. static_response expands placeholders with NO HTML
// escaping (staticresp.go ReplaceKnown), so a raw URI reflects a crafted
// path like /<script>... straight into the error HTML → reflected XSS.
// uri_escaped runs url.QueryEscape (Caddy replacer.go), neutralizing
// <, >, ". Covers both arenetDefaultPage (the 8 per-code bodies) and
// arenetGenericErrorPage (the fallback).
func TestErrorPages_UseEscapedURIPlaceholder(t *testing.T) {
	// The generic fallback body.
	if strings.Contains(arenetGenericErrorPage, "{http.request.uri}") {
		t.Error("arenetGenericErrorPage uses raw {http.request.uri} — reflected-XSS vector; use {http.request.uri_escaped}")
	}
	if !strings.Contains(arenetGenericErrorPage, "{http.request.uri_escaped}") {
		t.Error("arenetGenericErrorPage must reference {http.request.uri_escaped}")
	}
	// Every built-in per-code default page.
	for code, body := range arenetDefaultErrorPages {
		if strings.Contains(body, "{http.request.uri}") {
			t.Errorf("arenetDefaultErrorPages[%d] uses raw {http.request.uri} — reflected-XSS vector; use {http.request.uri_escaped}", code)
		}
	}
}
