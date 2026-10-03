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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.60 — UpstreamTLSServerName on the wire, built from literal JSON
// rather than Go structs for the reason the InsecureSkipVerify tests
// give: a typed body cannot express "the key is absent", which is the
// whole preserve-on-omit contract, and it cannot catch a camelCase
// mismatch in the tag either.
//
// What is pinned here:
//
//  1. POST with a name → echoed on the response, stored.
//  2. POST without the key → "" (Caddy's default).
//  3. PUT WITHOUT the key preserves the stored name. This is the one
//     that matters in practice: an operator editing the WAF mode must
//     not silently lose the name their backend is verified against.
//  4. PUT with an explicit "" clears it — the only way to remove one.
//  5. An http-only pool normalises the name away instead of storing
//     config that nothing will ever read.
//  6. A name Caddy could not use is refused with 400, naming why.

func tlsNameBodyHTTPS(host, nameJSON string) string {
	tail := ""
	if nameJSON != "" {
		tail = `,"upstreamTlsServerName":` + nameJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"https://194.163.129.255","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func tlsNameBodyHTTP(host, nameJSON string) string {
	tail := ""
	if nameJSON != "" {
		tail = `,"upstreamTlsServerName":` + nameJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.10:8123","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func postRouteRaw(t *testing.T, env *testEnv, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func putRouteRaw(t *testing.T, env *testEnv, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestCreateRoute_UpstreamTLSServerName_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postRouteRaw(t, env, tlsNameBodyHTTPS("forum.example.com", `"forum.example.com"`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}

	// Read the raw map, not the typed struct: this is what catches a
	// renamed or dropped JSON tag.
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, present := m["upstreamTlsServerName"]
	if !present {
		t.Fatal(`response has no "upstreamTlsServerName" key; the frontend would read it as undefined`)
	}
	if got != "forum.example.com" {
		t.Errorf(`"upstreamTlsServerName" = %v; want "forum.example.com"`, got)
	}

	stored, _ := env.store.ListRoutes(context.Background())
	if stored[0].UpstreamTLSServerName != "forum.example.com" {
		t.Errorf("storage = %q; want forum.example.com", stored[0].UpstreamTLSServerName)
	}
}

func TestCreateRoute_UpstreamTLSServerName_AbsentDefaultsEmpty(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postRouteRaw(t, env, tlsNameBodyHTTPS("plain.example.com", ""))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	if got := m["upstreamTlsServerName"]; got != "" {
		t.Errorf(`"upstreamTlsServerName" = %v; want "" (Caddy's default)`, got)
	}
}

func TestUpdateRoute_UpstreamTLSServerName_AbsentPreserves(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postRouteRaw(t, env, tlsNameBodyHTTPS("forum.example.com", `"forum.example.com"`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	// A PUT that says nothing about the name — the shape of every
	// unrelated edit the operator will ever make.
	rec = putRouteRaw(t, env, id, tlsNameBodyHTTPS("forum.example.com", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body)
	}
	var updated map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if got := updated["upstreamTlsServerName"]; got != "forum.example.com" {
		t.Errorf(`"upstreamTlsServerName" = %v after an unrelated PUT; want it preserved. `+
			`Losing it silently points the proxy at an unverifiable backend.`, got)
	}
}

func TestUpdateRoute_UpstreamTLSServerName_EmptyStringClears(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postRouteRaw(t, env, tlsNameBodyHTTPS("forum.example.com", `"forum.example.com"`))
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	rec = putRouteRaw(t, env, id, tlsNameBodyHTTPS("forum.example.com", `""`))
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body)
	}
	var updated map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if got := updated["upstreamTlsServerName"]; got != "" {
		t.Errorf(`"upstreamTlsServerName" = %v; want "" — an explicit empty string is `+
			`the only way an operator can remove a name`, got)
	}
}

func TestCreateRoute_UpstreamTLSServerName_HTTPOnly_NormalisesAway(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postRouteRaw(t, env, tlsNameBodyHTTP("plain.example.com", `"plain.example.com"`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ := env.store.ListRoutes(context.Background())
	if stored[0].UpstreamTLSServerName != "" {
		t.Errorf("storage = %q on an http-only pool; want \"\" — no transport.tls block "+
			"is emitted there, so the value would be stored and never read",
			stored[0].UpstreamTLSServerName)
	}
}

func TestCreateRoute_UpstreamTLSServerName_InvalidIsRefused(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		wantText string
	}{
		{"a whole URL", `"https://forum.example.com"`, "not a URL"},
		{"host:port", `"forum.example.com:443"`, "no port"},
		{"an IP", `"194.163.129.255"`, "cannot be a TLS server name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, false)
			rec := postRouteRaw(t, env, tlsNameBodyHTTPS("bad.example.com", tc.json))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.wantText) {
				t.Errorf("body %q does not say why it was refused (want %q)",
					rec.Body.String(), tc.wantText)
			}
		})
	}
}

func TestCreateRoute_UpstreamTLSServerName_TrimsWhitespace(t *testing.T) {
	// A pasted hostname very often carries a trailing space. Trimming
	// it is kinder than refusing it, and the validator then sees a
	// clean value.
	env := newTestEnv(t, false)
	rec := postRouteRaw(t, env, tlsNameBodyHTTPS("forum.example.com", `"  forum.example.com  "`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ := env.store.ListRoutes(context.Background())
	if stored[0].UpstreamTLSServerName != "forum.example.com" {
		t.Errorf("storage = %q; want the trimmed hostname", stored[0].UpstreamTLSServerName)
	}
}

func TestMapPathRuleReqs_UpstreamTLSServerNameMapped(t *testing.T) {
	// A path pool carries its own name, and only when it has its own
	// pool — the same gate as InsecureSkipVerify.
	reqs := []pathRuleReq{{
		PathPrefix:            "/api",
		Upstreams:             []upstreamReq{{URL: "https://10.0.0.9", Weight: 1}},
		LBPolicy:              "round_robin",
		UpstreamTLSServerName: "api.internal",
	}}
	out, err := mapPathRuleReqs(reqs, nil)
	if err != nil {
		t.Fatalf("mapPathRuleReqs: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("rules = %d; want 1", len(out))
	}
	if out[0].UpstreamTLSServerName != "api.internal" {
		t.Errorf("path rule name = %q; want api.internal", out[0].UpstreamTLSServerName)
	}
}
