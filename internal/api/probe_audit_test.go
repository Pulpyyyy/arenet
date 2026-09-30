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

	"github.com/barto95100/arenet/internal/audit"
)

// v2.56.2 — two defects reported on the audit rows.
//
// The IP was always 127.0.0.1, because the admin API listens on loopback
// and the documented way to reach the UI is an Arenet route: the caller is
// the embedded Caddy. The worse half of the same root cause is that the
// login rate limiter keys on the same value (ratelimit.go:399), so every
// attempt from every source shared one bucket.
//
// The Target column was empty: the probe rows carried their target in the
// free-text message only, where nothing can filter or join on it.

func lastAuditEvent(t *testing.T, env *testEnv, action string) audit.Event {
	t.Helper()
	events := env.audit.Events()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == action {
			return events[i]
		}
	}
	t.Fatalf("no %q audit event; got %+v", action, events)
	return audit.Event{}
}

// postProbe sends an upstream probe with the given headers.
func postProbe(t *testing.T, env *testEnv, body string, headers map[string]string, remoteAddr string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	env.router.ServeHTTP(httptest.NewRecorder(), req)
}

// THE case: the request arrives from the embedded Caddy over loopback,
// carrying the real client. The audit row must name the client, not the
// loopback.
func TestProbeAudit_RecordsTheRealClientBehindTheEmbeddedCaddy(t *testing.T) {
	env := newTestEnv(t, false)
	postProbe(t, env,
		`{"url":"http://127.0.0.1:1"}`,
		map[string]string{"X-Forwarded-For": "31.32.48.58"},
		"127.0.0.1:41234")

	evt := lastAuditEvent(t, env, audit.ActionProbeUpstream)
	if evt.IP != "31.32.48.58" {
		t.Errorf("audit IP = %q; want the real client, not the loopback the proxy dialled from", evt.IP)
	}
}

// And the half that keeps it safe: a caller that is NOT loopback cannot
// claim to be someone else.
func TestProbeAudit_IgnoresForwardedForFromANonLoopbackCaller(t *testing.T) {
	env := newTestEnv(t, false)
	postProbe(t, env,
		`{"url":"http://127.0.0.1:1"}`,
		map[string]string{"X-Forwarded-For": "198.51.100.7"},
		"203.0.113.9:41234")

	evt := lastAuditEvent(t, env, audit.ActionProbeUpstream)
	if evt.IP == "198.51.100.7" {
		t.Errorf("audit IP = %q; an external caller spoofed its address", evt.IP)
	}
	if evt.IP != "203.0.113.9" {
		t.Errorf("audit IP = %q; want the caller's own address", evt.IP)
	}
}

func TestProbeAudit_CarriesAStructuredTarget(t *testing.T) {
	env := newTestEnv(t, false)
	postProbe(t, env,
		`{"url":"http://10.66.0.2:80","routeId":"rid-42"}`,
		map[string]string{"X-Forwarded-For": "31.32.48.58"},
		"127.0.0.1:41234")

	evt := lastAuditEvent(t, env, audit.ActionProbeUpstream)
	if evt.TargetType != "upstream" {
		t.Errorf("TargetType = %q; the Target column was empty before", evt.TargetType)
	}
	if !strings.Contains(evt.TargetID, "10.66.0.2") {
		t.Errorf("TargetID = %q; want the probed address", evt.TargetID)
	}
	// The route is context, recorded alongside rather than instead.
	var detail map[string]any
	if err := json.Unmarshal(evt.AfterJSON, &detail); err != nil {
		t.Fatalf("structured detail is not JSON: %v (%s)", err, evt.AfterJSON)
	}
	if detail["routeId"] != "rid-42" {
		t.Errorf("routeId = %v; want it recorded structurally, not only in the message", detail["routeId"])
	}
}

// A probe from the create form has no route yet; the field is absent
// rather than empty, so nothing reads as "route with no id".
func TestProbeAudit_OmitsTheRouteWhenThereIsNone(t *testing.T) {
	env := newTestEnv(t, false)
	postProbe(t, env, `{"url":"http://127.0.0.1:1"}`, nil, "127.0.0.1:41234")

	evt := lastAuditEvent(t, env, audit.ActionProbeUpstream)
	var detail map[string]any
	if err := json.Unmarshal(evt.AfterJSON, &detail); err != nil {
		t.Fatalf("structured detail is not JSON: %v", err)
	}
	if _, present := detail["routeId"]; present {
		t.Errorf("routeId present with no route: %v", detail)
	}
}

// The health-check probe records the same way.
func TestProbeAudit_HealthCheckCarriesTargetAndClient(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{
      "upstreams": [{"url": "http://10.66.0.2:80", "weight": 1}],
      "healthCheck": {"enabled": true, "uri": "/", "method": "GET",
        "interval": "30s", "timeout": "1s", "passes": 1, "fails": 1},
      "routeId": "rid-7"
    }`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-health-check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "31.32.48.58")
	req.RemoteAddr = "127.0.0.1:41234"
	env.router.ServeHTTP(httptest.NewRecorder(), req)

	evt := lastAuditEvent(t, env, audit.ActionProbeHealthCheck)
	if evt.IP != "31.32.48.58" {
		t.Errorf("audit IP = %q; want the real client", evt.IP)
	}
	if evt.TargetType != "upstream" || !strings.Contains(evt.TargetID, "10.66.0.2") {
		t.Errorf("target = %q/%q; want the probed address", evt.TargetType, evt.TargetID)
	}
	var detail map[string]any
	if err := json.Unmarshal(evt.AfterJSON, &detail); err != nil {
		t.Fatalf("structured detail is not JSON: %v", err)
	}
	if detail["routeId"] != "rid-7" {
		t.Errorf("routeId = %v", detail["routeId"])
	}
}

// The report asked for every audited action, not just the probes. The fix
// is central — appendAudit fills evt.IP from ClientIPFromContext, which
// every action goes through — so this asserts it on a completely different
// one rather than trusting that centrality.
func TestProbeAudit_TheFixAppliesToEveryAuditedAction(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"audit.example.com","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "31.32.48.58")
	req.RemoteAddr = "127.0.0.1:41234"
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create route: %d %s", rec.Code, rec.Body)
	}

	evt := lastAuditEvent(t, env, audit.ActionRouteCreated)
	if evt.IP != "31.32.48.58" {
		t.Errorf("route_created audit IP = %q; the fix must not be probe-specific", evt.IP)
	}
}
