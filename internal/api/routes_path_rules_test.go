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

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pathRulesRouteBody builds a route POST/PUT body with the supplied
// extra top-level JSON fields spliced in (e.g. ipFilter/pathRules, or
// an unrelated field to prove an omitted ipFilter is preserved on
// PUT). extraJSON is a raw `,"key":value` fragment or "".
func pathRulesRouteBody(host, extraJSON string) string {
	return `{` +
		`"host":"` + host + `",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},` +
		`"wafMode":"off"` + extraJSON + `}`
}

// TestCreateRoute_WithPathRulesAndIPFilter pins the v1 path-based-rules
// wire contract (Task 3, revised Task 8): POST accepts camelCase
// ipFilter/pathRules (DisallowUnknownFields would otherwise 400 on the
// wire-field gap — see memory route_wire_field_gap_regression), and
// the response never echoes a path-rule's plain basic-auth password.
// It also round-trips the decoded response to confirm the values (not
// just their raw presence in the body) match what was submitted.
//
// Task 8: path-rule basic auth now takes a PLAIN password on the wire
// (matching route-level basicAuthReq) and is hashed server-side via
// auth.HashRoutePassword — see TestCreateRoute_PathRuleBasicAuth_HashedServerSide
// for the dedicated stored-hash assertion.
func TestCreateRoute_WithPathRulesAndIPFilter(t *testing.T) {
	env := newTestEnv(t, false)
	// API wire is camelCase (mirrors countryBlock). Nested keys too.
	body := `{
	  "host":"api.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "ipFilter":{"mode":"deny","cidrs":["10.0.0.0/8"]},
	  "pathRules":[
	    {"pathPrefix":"/metrics","ipFilter":{"mode":"allow","cidrs":["192.168.1.5"]}},
	    {"pathPrefix":"/docs","basicAuth":{"username":"doc","password":"somePlainPassword"}}
	  ]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s (wire-field-gap? DisallowUnknownFields)", rec.Code, rec.Body)
	}
	// GET redacts the path-rule basic-auth password (plain or hash).
	if strings.Contains(rec.Body.String(), "somePlainPassword") {
		t.Errorf("path-rule plain password leaked in response: %s", rec.Body)
	}

	// Round-trip the decoded response: values, not just raw presence.
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.IPFilter == nil || created.IPFilter.Mode != "deny" {
		t.Fatalf("response ipFilter.mode = %+v; want mode=deny", created.IPFilter)
	}
	if len(created.PathRules) != 2 {
		t.Fatalf("response pathRules len = %d; want 2", len(created.PathRules))
	}
	wantPrefixes := map[string]bool{"/metrics": false, "/docs": false}
	for _, pr := range created.PathRules {
		if _, ok := wantPrefixes[pr.PathPrefix]; !ok {
			t.Errorf("unexpected pathPrefix %q in response", pr.PathPrefix)
			continue
		}
		wantPrefixes[pr.PathPrefix] = true
	}
	for prefix, seen := range wantPrefixes {
		if !seen {
			t.Errorf("pathPrefix %q missing from response", prefix)
		}
	}
	for _, pr := range created.PathRules {
		if pr.PathPrefix == "/docs" {
			if pr.BasicAuth == nil {
				t.Fatalf("/docs pathRule missing basicAuth in response")
			}
			if pr.BasicAuth.Username != "doc" {
				t.Errorf("/docs basicAuth.username = %q; want %q", pr.BasicAuth.Username, "doc")
			}
			if pr.BasicAuth.Password != "" {
				t.Errorf("/docs basicAuth.password = %q; want redacted empty string", pr.BasicAuth.Password)
			}
		}
	}
}

// TestUpdateRoute_OmittedIPFilter_Preserved pins the Task 3 review
// Important-finding fix: PUT /api/v1/routes/{id} omitting ipFilter
// MUST preserve the previously stored whole-domain IP filter rather
// than silently clearing a configured security control — same
// preserve-on-omission contract as CountryBlock / HealthCheck (see
// TestUpdateRoute_CountryBlock_NilPreservesPrevious in
// routes_country_block_test.go, the pattern this test mirrors).
func TestUpdateRoute_OmittedIPFilter_Preserved(t *testing.T) {
	env := newTestEnv(t, false)

	// 1. Create with an ipFilter (deny 10.0.0.0/8).
	createBody := pathRulesRouteBody("ipf-preserve.local",
		`,"ipFilter":{"mode":"deny","cidrs":["10.0.0.0/8"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// 2. PUT WITHOUT an ipFilter key, but changing an unrelated field
	// (request headers) — proves an operator editing something else
	// doesn't wipe the IP filter.
	putBody := `{"host":"ipf-preserve.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{"X-Test":"1"},"responseHeaders":{},"wafMode":"off"}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	// 3. Assert the IP filter survived the unrelated edit — read
	// directly from the store (bypasses response serialization).
	got, err := env.store.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if got[0].IPFilter == nil {
		t.Fatalf("IPFilter = nil after PUT omitting ipFilter; want preserved deny 10.0.0.0/8")
	}
	if got[0].IPFilter.Mode != "deny" {
		t.Errorf("IPFilter.Mode = %q; want %q (preserved across PUT)", got[0].IPFilter.Mode, "deny")
	}
	if len(got[0].IPFilter.CIDRs) != 1 || got[0].IPFilter.CIDRs[0] != "10.0.0.0/8" {
		t.Errorf("IPFilter.CIDRs = %v; want [10.0.0.0/8] (preserved across PUT)", got[0].IPFilter.CIDRs)
	}
}

// TestCreateRoute_PathRuleBasicAuth_HashedServerSide pins the Task 8
// fix: path-rule basic auth now accepts a PLAIN password on the wire
// (mirrors route-level basicAuthReq) and Arenet hashes it server-side
// via auth.HashRoutePassword — an operator can no longer accidentally
// store their plaintext password verbatim "as if" it were a hash.
//
// Asserts: 201, the response body never contains the plain password,
// and the STORED route (read directly from env.store, bypassing
// response redaction) carries a real argon2id PHC hash — proving the
// hashing actually happened server-side rather than just accepting
// whatever was on the wire.
func TestCreateRoute_PathRuleBasicAuth_HashedServerSide(t *testing.T) {
	env := newTestEnv(t, false)
	const plainPassword = "somePlainPassword"
	body := `{
	  "host":"hashed-path-rule.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "pathRules":[
	    {"pathPrefix":"/admin","basicAuth":{"username":"admin","password":"` + plainPassword + `"}}
	  ]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), plainPassword) {
		t.Errorf("plain password leaked into create response: %s", rec.Body)
	}

	got, err := env.store.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if len(got[0].PathRules) != 1 {
		t.Fatalf("want 1 path rule, got %d", len(got[0].PathRules))
	}
	pr := got[0].PathRules[0]
	if pr.BasicAuth == nil {
		t.Fatalf("stored path-rule BasicAuth is nil")
	}
	if pr.BasicAuth.PasswordHash == "" {
		t.Fatalf("stored path-rule PasswordHash is empty; want a real argon2id hash")
	}
	if pr.BasicAuth.PasswordHash == plainPassword {
		t.Fatalf("stored path-rule PasswordHash equals the plaintext password verbatim — server-side hashing did NOT happen")
	}
	if !strings.HasPrefix(pr.BasicAuth.PasswordHash, "$argon2id$") {
		t.Errorf("stored PasswordHash = %q; want a $argon2id$ PHC string", pr.BasicAuth.PasswordHash)
	}
}

// TestUpdateRoute_PathRuleBasicAuth_PreservesHashOnEmptyPassword pins
// the preserve-on-edit contract for the Task 8 fix: a PUT that omits
// the path-rule's password (empty string) must keep the previously
// stored hash for that exact PathPrefix, rather than wiping it —
// mirrors the route-level BasicAuth empty-password-preserves-hash UX.
func TestUpdateRoute_PathRuleBasicAuth_PreservesHashOnEmptyPassword(t *testing.T) {
	env := newTestEnv(t, false)

	// 1. Create with a real plain password — hashed server-side.
	createBody := `{
	  "host":"preserve-path-rule.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "pathRules":[
	    {"pathPrefix":"/admin","basicAuth":{"username":"admin","password":"firstPlainPassword"}}
	  ]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	before, err := env.store.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(before) != 1 || len(before[0].PathRules) != 1 || before[0].PathRules[0].BasicAuth == nil {
		t.Fatalf("unexpected stored state after create: %+v", before)
	}
	originalHash := before[0].PathRules[0].BasicAuth.PasswordHash
	if !strings.HasPrefix(originalHash, "$argon2id$") {
		t.Fatalf("originalHash = %q; want $argon2id$ PHC string", originalHash)
	}

	// 2. PUT with the same pathPrefix but an empty password — must
	// preserve the previously stored hash, not wipe/replace it.
	putBody := `{
	  "host":"preserve-path-rule.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],
	  "pathRules":[
	    {"pathPrefix":"/admin","basicAuth":{"username":"admin","password":""}}
	  ]}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	after, err := env.store.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(after) != 1 || len(after[0].PathRules) != 1 || after[0].PathRules[0].BasicAuth == nil {
		t.Fatalf("unexpected stored state after update: %+v", after)
	}
	if after[0].PathRules[0].BasicAuth.PasswordHash != originalHash {
		t.Errorf("hash was rotated despite empty password: before=%q after=%q",
			originalHash, after[0].PathRules[0].BasicAuth.PasswordHash)
	}
}

// TestUpdateRoute_PathRuleNoProtection_Returns400NotServerError pins
// the fix/path-rule-empty-500 dogfooding bug: an operator edited a
// route, left a path-rule with ipFilter mode "off" (a residual CIDR
// but no active gate) and no basic auth — i.e. zero active protection
// — and PUT returned a raw 500 "failed to update route" instead of an
// actionable 400. Root cause: updateRoute called h.store.UpdateRoute
// directly without pre-validating, so storage.Route.validate()'s
// "must declare at least one protection" rejection fell through to
// the handler's generic post-store 500 branch.
//
// This test drives the exact wire shape from the operator's report
// (mode "off" + a residual cidrs entry, no basicAuth) through a real
// PUT and asserts: 400 (not 500), and the body carries the actual
// validation message so the operator knows what to fix.
//
// Note: this pins the BACKEND defense-in-depth path. The frontend fix
// (sanitizePathRules, web/frontend/src/lib/utils/path-rules.ts) means
// the UI itself never sends such a rule — but a direct API client (or
// a future UI regression) must still get a clean 400, not a 500.
func TestUpdateRoute_PathRuleNoProtection_Returns400NotServerError(t *testing.T) {
	env := newTestEnv(t, false)

	// 1. Create a route with no path rules.
	createBody := pathRulesRouteBody("dead-path-rule.example.com", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// 2. PUT a path rule with mode "off" and a residual CIDR, no
	// basicAuth — exactly the operator-reported shape — zero active
	// protection.
	putBody := `{
	  "host":"dead-path-rule.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,
	  "aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},
	  "wafMode":"off",
	  "pathRules":[
	    {"pathPrefix":"/metrics-zabbix","ipFilter":{"mode":"off","cidrs":["8.8.8.8"]}}
	  ]}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)

	if putRec.Code != http.StatusBadRequest {
		t.Fatalf("put status=%d (want 400) body=%s", putRec.Code, putRec.Body)
	}
	// The message lists every kind of content a rule may carry and grows
	// with them (v2.23.0 added upstreams, v2.56 the rate limit, v2.57
	// forward auth), so assert the stable part plus the machine-readable
	// code rather than the full sentence — the point of the test is that
	// an empty rule is refused with a 400 the UI can show, not the
	// enumeration's current wording.
	if !strings.Contains(putRec.Body.String(), "must declare at least one of") {
		t.Errorf("put body = %s; want it to contain the validation message %q",
			putRec.Body.String(), "must declare at least one of")
	}
	if !strings.Contains(putRec.Body.String(), "path_rule_empty") {
		t.Errorf("put body = %s; want the path_rule_empty code", putRec.Body.String())
	}
}

// v2.57 — the per-path IdP gate, exercised through literal JSON written the
// way the SvelteKit form writes it. A test that builds its payload from
// pathRuleReq cannot see a camelCase disagreement, because producer and
// consumer would then agree by construction; that is exactly how the
// v2.56.0 health-check Test button shipped answering `unknown field
// "expectStatus"` on its first real click.
func TestCreateRoute_PathRuleForwardAuth_RoundTrips(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("idp.example.com",
		`,"pathRules":[{"pathPrefix":"/metrics","forwardAuth":{"providerName":"authentik"}}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s (wire-field gap? DisallowUnknownFields)", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if len(created.PathRules) != 1 {
		t.Fatalf("response pathRules len = %d; want 1", len(created.PathRules))
	}
	// Echoed back, unlike the basic-auth password: the form needs the
	// provider name to re-render the gate on edit, and a provider
	// reference is not a secret.
	if created.PathRules[0].ForwardAuth == nil {
		t.Fatalf("forwardAuth absent from the response; the form cannot re-render the gate")
	}
	if got := created.PathRules[0].ForwardAuth.ProviderName; got != "authentik" {
		t.Errorf("forwardAuth.providerName = %q; want %q", got, "authentik")
	}

	// And it survives a reload from storage, not just the create echo.
	id := created.ID
	getRec := httptest.NewRecorder()
	env.router.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+id, nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body)
	}
	var reloaded routeResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &reloaded); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if len(reloaded.PathRules) != 1 || reloaded.PathRules[0].ForwardAuth == nil {
		t.Fatalf("forwardAuth did not survive the round trip to storage: %s", getRec.Body)
	}
	if got := reloaded.PathRules[0].ForwardAuth.ProviderName; got != "authentik" {
		t.Errorf("reloaded forwardAuth.providerName = %q; want %q", got, "authentik")
	}
}

// The wrong spelling must stay refused, or the two naming conventions
// quietly start accepting both and drift again.
//
// Only the OUTER key is misspelled here, with a valid camelCase body
// inside. A payload misspelling both would 400 on the inner key alone, so
// it would keep passing even if the outer field's tag were switched to
// snake_case — the very drift this test exists to catch.
func TestCreateRoute_PathRuleForwardAuth_SnakeCaseIsRefused(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("snake.example.com",
		`,"pathRules":[{"pathPrefix":"/metrics","forward_auth":{"providerName":"authentik"}}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST with snake_case forward_auth status=%d; want 400 so the wire contract stays single-spelled (body=%s)", rec.Code, rec.Body)
	}
}

// Two identity gates on one rule is refused with a 400 naming the reason,
// never a 500 and never a silent drop of one of them. v2.56.1/.2/.3 were
// three releases spent on rules that vanished without a word.
func TestCreateRoute_PathRuleForwardAuthAndBasicAuth_Returns400(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("both.example.com",
		`,"pathRules":[{"pathPrefix":"/metrics",`+
			`"basicAuth":{"username":"ops","password":"somePlainPassword"},`+
			`"forwardAuth":{"providerName":"authentik"}}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST status=%d; want 400 (body=%s)", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "both") && !strings.Contains(rec.Body.String(), "either") {
		t.Errorf("the 400 does not say what is wrong, so the UI cannot show it: %s", rec.Body)
	}
}

// A forward-auth gate with no provider named is refused: it would emit a
// fail-closed 503 for a path the operator believes is protected.
func TestCreateRoute_PathRuleForwardAuth_EmptyProviderReturns400(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("empty.example.com",
		`,"pathRules":[{"pathPrefix":"/metrics","forwardAuth":{"providerName":""}}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST status=%d; want 400 for a gate naming no provider (body=%s)", rec.Code, rec.Body)
	}
}

// Preserve-on-edit: changing an unrelated field must not drop the gate.
// This is the exact shape of the v2.56.2 bug, where a path rule's rate
// limit disappeared because one of the form's field-by-field rebuilds did
// not know the field existed.
func TestUpdateRoute_PathRuleForwardAuth_SurvivesAnUnrelatedEdit(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("edit.example.com",
		`,"pathRules":[{"pathPrefix":"/metrics","forwardAuth":{"providerName":"authentik"}}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Re-send the rule exactly as the response gave it back, with one
	// unrelated change to the route.
	putBody := `{` +
		`"host":"edit.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},` +
		`"wafMode":"off",` +
		`"pathRules":[{"pathPrefix":"/metrics","forwardAuth":{"providerName":"authentik"}}]}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", putRec.Code, putRec.Body)
	}
	var updated routeResponse
	if err := json.Unmarshal(putRec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode PUT: %v", err)
	}
	if len(updated.PathRules) != 1 || updated.PathRules[0].ForwardAuth == nil {
		t.Fatalf("the gate was dropped by an unrelated edit: %s", putRec.Body)
	}
	if got := updated.PathRules[0].ForwardAuth.ProviderName; got != "authentik" {
		t.Errorf("after edit providerName = %q; want %q", got, "authentik")
	}
}

// v2.58 — the auth exemption, end to end through literal JSON written the way
// the form writes it.
//
// The operator asked for this explicitly, "vu les deux bugs récents de
// décalage interface/API sur les règles par chemin": v2.56.1 and v2.56.2 were
// both a path-rule field that the form sent and the API dropped, or stored and
// never read back. For an exemption that failure mode is worse than a lost
// setting — the path silently starts demanding a login again and whatever
// service calls it breaks.
func TestCreateRoute_PathRuleAuthExemption_RoundTrips(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("n8n.example.com",
		`,"pathRules":[`+
			`{"pathPrefix":"/webhook","disableRouteAuth":true},`+
			`{"pathPrefix":"/form","disableRouteAuth":true},`+
			`{"pathPrefix":"/rest/oauth2-credential/callback","disableRouteAuth":true,"matchExact":true}`+
			`]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s (wire-field gap? DisallowUnknownFields)", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if len(created.PathRules) != 3 {
		t.Fatalf("response pathRules len = %d; want 3", len(created.PathRules))
	}
	for _, pr := range created.PathRules {
		if !pr.DisableRouteAuth {
			t.Errorf("rule %q came back with disableRouteAuth=false; the form cannot "+
				"re-render the exemption and the next save would re-protect the path",
				pr.PathPrefix)
		}
	}

	// And it survives the round trip to storage, not just the create echo.
	getRec := httptest.NewRecorder()
	env.router.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+created.ID, nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", getRec.Code, getRec.Body)
	}
	var reloaded routeResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &reloaded); err != nil {
		t.Fatalf("decode GET: %v", err)
	}
	if len(reloaded.PathRules) != 3 {
		t.Fatalf("reloaded pathRules len = %d; want 3: %s", len(reloaded.PathRules), getRec.Body)
	}
	exact := 0
	for _, pr := range reloaded.PathRules {
		if !pr.DisableRouteAuth {
			t.Errorf("rule %q lost its exemption in storage", pr.PathPrefix)
		}
		if pr.MatchExact {
			exact++
		}
	}
	if exact != 1 {
		t.Errorf("matchExact survived on %d rules; want 1 (the OAuth callback)", exact)
	}
}

// The exact shape of the v2.56.2 bug: change something unrelated, and the
// exemption must still be there afterwards.
func TestUpdateRoute_PathRuleAuthExemption_SurvivesAnUnrelatedEdit(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("edit-n8n.example.com",
		`,"pathRules":[{"pathPrefix":"/webhook","disableRouteAuth":true}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	putBody := `{` +
		`"host":"edit-n8n.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:5678","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},` +
		`"wafMode":"off",` +
		`"pathRules":[{"pathPrefix":"/webhook","disableRouteAuth":true}]}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", putRec.Code, putRec.Body)
	}
	var updated routeResponse
	if err := json.Unmarshal(putRec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode PUT: %v", err)
	}
	if len(updated.PathRules) != 1 || !updated.PathRules[0].DisableRouteAuth {
		t.Fatalf("the exemption was dropped by an unrelated edit: %s", putRec.Body)
	}
}

// The wrong spelling stays refused, so the wire contract keeps one spelling.
func TestCreateRoute_PathRuleAuthExemption_SnakeCaseIsRefused(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("snake-n8n.example.com",
		`,"pathRules":[{"pathPrefix":"/webhook","disable_route_auth":true}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST with snake_case disable_route_auth status=%d; want 400 (body=%s)",
			rec.Code, rec.Body)
	}
}

// Exemption plus an IdP gate on one rule is two opposite instructions: a 400
// that says so, never a 500 and never a silent drop of one of them.
func TestCreateRoute_PathRuleAuthExemption_WithIdPReturns400(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("both-n8n.example.com",
		`,"pathRules":[{"pathPrefix":"/webhook","disableRouteAuth":true,`+
			`"forwardAuth":{"providerName":"authentik"}}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST status=%d; want 400 (body=%s)", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "path_rule_exempt_with_idp") {
		t.Errorf("the 400 does not carry the machine-readable code, so the UI cannot "+
			"localise it: %s", rec.Body)
	}
}

// The operator asked for an audit entry when such a rule is created or
// changed. No new code was needed — routeForAudit clones the whole route,
// path rules included — but "no new code was needed" is a claim, so here it
// is as a test. Removing authentication from a path is exactly the change an
// operator will want to find in the log six months later.
func TestAuditRecordsThePathAuthExemption(t *testing.T) {
	env := newTestEnv(t, false)
	body := pathRulesRouteBody("audit-n8n.example.com",
		`,"pathRules":[{"pathPrefix":"/webhook","disableRouteAuth":true}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	ev := lastAuditEvent(t, env, "route_created")
	if !strings.Contains(string(ev.AfterJSON), "disable_route_auth") {
		t.Errorf("the create audit entry does not record the exemption, so the log cannot "+
			"answer \"when did /webhook stop requiring a login\": %s", ev.AfterJSON)
	}

	// And the removal is recorded too: turning protection back ON is just as
	// much a change worth finding.
	putBody := `{` +
		`"host":"audit-n8n.example.com",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},` +
		`"wafMode":"off",` +
		`"pathRules":[{"pathPrefix":"/webhook","basicAuth":{"username":"hook","password":"somePlainPassword"}}]}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", putRec.Code, putRec.Body)
	}
	up := lastAuditEvent(t, env, "route_updated")
	if !strings.Contains(string(up.BeforeJSON), "disable_route_auth") {
		t.Errorf("the update audit entry does not show the exemption in the BEFORE state, "+
			"so the log cannot show it was removed: %s", up.BeforeJSON)
	}
	if strings.Contains(string(up.AfterJSON), "disable_route_auth") {
		t.Errorf("the AFTER state still claims the exemption: %s", up.AfterJSON)
	}
	// And the path-rule password never reaches the log.
	if strings.Contains(string(up.AfterJSON), "somePlainPassword") {
		t.Errorf("a path-rule password leaked into the audit log: %s", up.AfterJSON)
	}
}

// v2.58.4 — a redirecting route needs no upstream, through the API.
//
// Operator report, 2026-10-03, on v2.58.3: State = redirect, a target URL, 301,
// keep-path on, a host — and saving answered "upstreams must contain at least
// one entry". They could not act on it: the Upstreams field is deliberately
// hidden for a redirect, so the form told them nothing was missing while the
// server said something was.
//
// v2.45.2 had already settled that a redirecting route proxies nothing. It
// fixed the form and the storage validator and missed the API in between —
// the same N-places defect that cost v2.44, v2.56.1 and v2.56.2, except this
// time the two fixed layers hid the broken one.
func redirectRouteBody(host, extra string) string {
	return `{` +
		`"host":"` + host + `",` +
		`"upstreams":[],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},` +
		`"wafMode":"off",` +
		// A pathless target, because Arenet refuses "target has a path" +
		// preservePath together (the visitor's path would be appended to the
		// target's own). That rule is separate from this one and still holds.
		`"redirectConfig":{"target":"https://example.org","statusCode":301,"preservePath":true}` +
		extra + `}`
}

func TestCreateRoute_RedirectingRouteNeedsNoUpstream(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes",
		strings.NewReader(redirectRouteBody("redir.example.com", "")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d; want 201.\n\nA redirecting route proxies nothing, and the "+
			"form hides the Upstreams field for it — so a 400 here is an error the operator "+
			"cannot act on.\nbody=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.RedirectConfig == nil || created.RedirectConfig.Target != "https://example.org" {
		t.Errorf("redirectConfig did not survive: %s", rec.Body)
	}
	if len(created.Upstreams) != 0 {
		t.Errorf("upstreams = %v; want none — nothing should be invented", created.Upstreams)
	}
}

func TestUpdateRoute_RedirectingRouteNeedsNoUpstream(t *testing.T) {
	env := newTestEnv(t, false)
	// Start from an ordinary proxying route, then convert it to a redirect
	// and drop the pool — the realistic edit.
	create := httptest.NewRequest(http.MethodPost, "/api/v1/routes",
		strings.NewReader(pathRulesRouteBody("convert.example.com", "")))
	create.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	env.router.ServeHTTP(createRec, create)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("seed POST status=%d body=%s", createRec.Code, createRec.Body)
	}
	var seeded routeResponse
	if err := json.Unmarshal(createRec.Body.Bytes(), &seeded); err != nil {
		t.Fatalf("decode seed: %v", err)
	}

	put := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID,
		strings.NewReader(redirectRouteBody("convert.example.com", "")))
	put.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, put)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status=%d; want 200 — converting a proxying route to a redirect must "+
			"not demand a backend it will never dial.\nbody=%s", putRec.Code, putRec.Body)
	}
}

// The exemption covers an EMPTY pool only. A redirecting route that somehow
// carries a malformed upstream is still rejected, so the relaxation cannot be
// used to smuggle a bad pool past validation.
func TestCreateRoute_RedirectingRouteStillValidatesEntriesItHas(t *testing.T) {
	env := newTestEnv(t, false)
	body := strings.Replace(redirectRouteBody("redir-bad.example.com", ""),
		`"upstreams":[]`, `"upstreams":[{"url":"not-a-url","weight":1}]`, 1)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST status=%d; want 400 — allowing an empty pool must not stop a present "+
			"entry from being checked (body=%s)", rec.Code, rec.Body)
	}
}

// And a NON-redirecting route still needs one, so the rule did not simply
// disappear.
func TestCreateRoute_ProxyingRouteStillNeedsAnUpstream(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"plain.example.com","upstreams":[],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST status=%d; want 400 — a route that proxies still needs somewhere to "+
			"proxy to (body=%s)", rec.Code, rec.Body)
	}
}
