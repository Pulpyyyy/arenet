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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.56.3 — a path rule carrying only a rate limit was lost on save.
//
// The reported case: /rl-test, 5 requests per minute, no basic auth and no
// IP filter. The PUT answered 200 and the rule was gone on the next read.
//
// The loss was entirely in the browser — the audit row's Before and After
// were identical but for updated_at, so the API never saw a path rule. The
// guards therefore live on both sides: the frontend ones assert the payload
// is built and kept, these assert the API stores and returns what the form
// now sends.

// putRouteJSON sends literal JSON, the way the form does.
func putRouteJSON(t *testing.T, env *testEnv, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func createRouteJSON(t *testing.T, env *testEnv, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create route: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode created route: %v", err)
	}
	return out.ID
}

// THE case: the reported payload, stored and read back.
func TestPathRateLimit_RateLimitOnlyRuleSurvivesARoundTrip(t *testing.T) {
	env := newTestEnv(t, false)
	id := createRouteJSON(t, env,
		`{"host":"www.example.com","upstreams":[{"url":"http://10.66.0.2:80","weight":1}]}`)

	body := `{
      "host": "www.example.com",
      "upstreams": [{"url": "http://10.66.0.2:80", "weight": 1}],
      "pathRules": [{
        "pathPrefix": "/rl-test",
        "ipFilter": {"mode": "off", "cidrs": [], "statusCode": 0},
        "rateLimit": {"events": 5, "window": "1m"}
      }]
    }`
	if rec := putRouteJSON(t, env, id, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}

	route := getRouteJSON(t, env, id)
	rules, _ := route["pathRules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("the rule did not survive the round trip: pathRules = %v", route["pathRules"])
	}
	rule, _ := rules[0].(map[string]any)
	if rule["pathPrefix"] != "/rl-test" {
		t.Errorf("pathPrefix = %v", rule["pathPrefix"])
	}
	rl, ok := rule["rateLimit"].(map[string]any)
	if !ok {
		t.Fatalf("rateLimit absent from the stored rule: %v", rule)
	}
	if rl["events"] != float64(5) || rl["window"] != "1m" {
		t.Errorf("rateLimit = %v; want 5 per 1m", rl)
	}
}

// A 200 that stores nothing is worse than a refusal: the operator is told
// it worked. An invalid limit must be an error, not a quiet drop.
func TestPathRateLimit_InvalidLimitIsRefusedNotDropped(t *testing.T) {
	env := newTestEnv(t, false)
	id := createRouteJSON(t, env,
		`{"host":"www.example.com","upstreams":[{"url":"http://10.66.0.2:80","weight":1}]}`)

	for name, rl := range map[string]string{
		"zero events": `{"events": 0, "window": "1m"}`,
		"no window":   `{"events": 5, "window": ""}`,
		"bad window":  `{"events": 5, "window": "sometime"}`,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{
              "host": "www.example.com",
              "upstreams": [{"url": "http://10.66.0.2:80", "weight": 1}],
              "pathRules": [{"pathPrefix": "/rl-test", "rateLimit": ` + rl + `}]
            }`
			rec := putRouteJSON(t, env, id, body)
			if rec.Code == http.StatusOK {
				t.Errorf("accepted with 200; an unusable limit must be refused, not stored or dropped")
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status %d; want 400 with a reason the UI can show", rec.Code)
			}
		})
	}
}

// And the combination the report asked about: a limit beside the other
// per-path settings must not displace them.
func TestPathRateLimit_CoexistsWithTheOtherPathSettings(t *testing.T) {
	env := newTestEnv(t, false)
	id := createRouteJSON(t, env,
		`{"host":"www.example.com","upstreams":[{"url":"http://10.66.0.2:80","weight":1}]}`)

	body := `{
      "host": "www.example.com",
      "upstreams": [{"url": "http://10.66.0.2:80", "weight": 1}],
      "pathRules": [{
        "pathPrefix": "/admin",
        "basicAuth": {"username": "ops", "password": "hunter2hunter2"},
        "ipFilter": {"mode": "allow", "cidrs": ["10.0.0.0/8"], "statusCode": 403},
        "rateLimit": {"events": 3, "window": "5m"},
        "matchExact": true
      }]
    }`
	if rec := putRouteJSON(t, env, id, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}

	rules, _ := getRouteJSON(t, env, id)["pathRules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("pathRules = %v", rules)
	}
	rule, _ := rules[0].(map[string]any)
	for _, key := range []string{"basicAuth", "ipFilter", "rateLimit"} {
		if _, ok := rule[key]; !ok {
			t.Errorf("%s was lost when combined with the others: %v", key, rule)
		}
	}
	if rule["matchExact"] != true {
		t.Errorf("matchExact = %v", rule["matchExact"])
	}
}
