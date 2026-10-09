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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// --- Unit: validators -----------------------------------------

func TestValidateManualBanValue_IPv4(t *testing.T) {
	scope, value, err := validateManualBanValue("203.0.113.42")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Ip" || value != "203.0.113.42" {
		t.Errorf("scope=%q value=%q, want Ip + 203.0.113.42", scope, value)
	}
}

func TestValidateManualBanValue_IPv6(t *testing.T) {
	scope, value, err := validateManualBanValue("2001:db8::42")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Ip" || value != "2001:db8::42" {
		t.Errorf("scope=%q value=%q, want Ip + 2001:db8::42", scope, value)
	}
}

func TestValidateManualBanValue_CIDRv4(t *testing.T) {
	// Non-canonical input gets normalised by net.ParseCIDR.
	scope, value, err := validateManualBanValue("10.0.0.1/8")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Range" || value != "10.0.0.0/8" {
		t.Errorf("scope=%q value=%q, want Range + 10.0.0.0/8 (canonicalised)", scope, value)
	}
}

func TestValidateManualBanValue_CIDRv6(t *testing.T) {
	scope, value, err := validateManualBanValue("2001:db8::/32")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if scope != "Range" || value != "2001:db8::/32" {
		t.Errorf("scope=%q value=%q, want Range + 2001:db8::/32", scope, value)
	}
}

func TestValidateManualBanValue_Rejects(t *testing.T) {
	for _, raw := range []string{
		"",
		"   ",
		"not-an-ip",
		"999.999.999.999",
		"10.0.0.0/33", // bad mask
		"hello/world",
	} {
		t.Run(raw, func(t *testing.T) {
			_, _, err := validateManualBanValue(raw)
			if err == nil {
				t.Errorf("expected error for %q", raw)
			}
		})
	}
}

func TestValidateManualBanDuration(t *testing.T) {
	for _, tt := range []struct {
		raw     string
		wantErr bool
	}{
		{"1h", false},
		{"4h", false},
		{"24h", false},
		{"7d", false},
		{"30d", false},
		{"1h30m", false},
		{"", true},
		{"-1h", true},
		{"0s", true},
		{"forever", true},
		{"abc", true},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			err := validateManualBanDuration(tt.raw)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for %q", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tt.raw, err)
			}
		})
	}
}

func TestValidateManualBanType(t *testing.T) {
	for _, ok := range []string{"ban", "captcha", "throttle"} {
		got, err := validateManualBanType(ok)
		if err != nil || got != ok {
			t.Errorf("type %q: got (%q, %v), want (%q, nil)", ok, got, err, ok)
		}
	}
	for _, bad := range []string{"", "delete", "BAN", "ban "} {
		if bad == "ban " {
			// trimmed by validateManualBanType — should be accepted.
			got, err := validateManualBanType(bad)
			if err != nil || got != "ban" {
				t.Errorf("type %q (whitespace): got (%q, %v)", bad, got, err)
			}
			continue
		}
		if _, err := validateManualBanType(bad); err == nil {
			t.Errorf("type %q should be rejected", bad)
		}
	}
}

func TestValidateManualBanReason(t *testing.T) {
	ok, err := validateManualBanReason("smoke test ban")
	if err != nil || ok != "smoke test ban" {
		t.Errorf("got (%q, %v)", ok, err)
	}
	if _, err := validateManualBanReason(""); err == nil {
		t.Error("empty reason should be rejected")
	}
	if _, err := validateManualBanReason("   "); err == nil {
		t.Error("whitespace-only reason should be rejected")
	}
	long := strings.Repeat("x", crowdSecManualBanReasonMaxLen+1)
	if _, err := validateManualBanReason(long); err == nil {
		t.Error("over-cap reason should be rejected")
	}
	if _, err := validateManualBanReason("has\x00null"); err == nil {
		t.Error("non-printable reason should be rejected")
	}
	// Pipes ALLOWED in reason — they ride through to the
	// frontend parser which splits on the FIRST pipe.
	if _, err := validateManualBanReason("contains | pipe"); err != nil {
		t.Errorf("pipes in reason should be allowed: %v", err)
	}
}

func TestBuildManualBanScenario_FormatPinned(t *testing.T) {
	got := buildManualBanScenario("admin", "smoke test")
	want := "manual:admin|smoke test"
	if got != want {
		t.Errorf("scenario = %q, want %q", got, want)
	}
}

func TestParseLAPIDuration_DSuffix(t *testing.T) {
	d, err := parseLAPIDuration("7d")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if d != 7*24*time.Hour {
		t.Errorf("got %v, want 168h", d)
	}
}

// --- Integration: addManualBan handler ------------------------

// fakeLAPIForBan is a focused fake LAPI exposing /v1/watchers/
// login + POST /v1/alerts. Records the POST body so tests can
// assert payload shape.
type fakeLAPIForBan struct {
	loginCalls   atomic.Int32
	alertsCalls  atomic.Int32
	alertsHandler http.HandlerFunc
	loginHandler  http.HandlerFunc
	lastBody     atomic.Value // string
}

func newFakeLAPIForBan() *fakeLAPIForBan {
	f := &fakeLAPIForBan{}
	f.lastBody.Store("")
	return f
}

func (f *fakeLAPIForBan) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCalls.Add(1)
		if f.loginHandler != nil {
			f.loginHandler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"token":"jwt-ok","expire":"` +
			time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339) + `"}`))
	})
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		f.alertsCalls.Add(1)
		var bodyStr string
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			bodyStr = string(body)
			f.lastBody.Store(bodyStr)
		}
		if f.alertsHandler != nil {
			f.alertsHandler(w, r)
			return
		}
		// HF on 7302a3a — emulate LAPI v1.6.3's swagger
		// validator: if the POST payload's Alert objects miss
		// scenario_hash / scenario_version / simulated, LAPI
		// rejects with 500 "validation failure list: ... is
		// required" (empirically confirmed against LAPI 1.7.8
		// on AreNET-test). Any happy-path test now implicitly
		// catches a regression that drops these fields.
		// Validated only on POST (GET uses since=duration).
		if r.Method == http.MethodPost && !alertPayloadHasRequiredFields(bodyStr) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"validation failure list: scenario_hash/scenario_version/simulated is required"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func seedWatcherCredsForBan(t *testing.T, h *Handler, lapiURL string) {
	t.Helper()
	if err := h.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL:   lapiURL,
		MachineID: "arenet-test",
		Password:  "watcher-secret",
	}); err != nil {
		t.Fatalf("seed creds: %v", err)
	}
}

func TestAddManualBan_HappyPath_IP(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	appender := &fakeAuditAppender{}
	h := newTestHandler(t, appender, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"203.0.113.42","duration":"1h","type":"ban","reason":"smoke test ban"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "user-uuid", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	// Response echo.
	var resp manualBanResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Scenario != "manual:admin|smoke test ban" {
		t.Errorf("Scenario = %q, want manual:admin|smoke test ban", resp.Scenario)
	}
	if resp.Scope != "Ip" {
		t.Errorf("Scope = %q, want Ip", resp.Scope)
	}
	if resp.Value != "203.0.113.42" {
		t.Errorf("Value = %q, want 203.0.113.42", resp.Value)
	}
	if resp.Type != "ban" {
		t.Errorf("Type = %q", resp.Type)
	}
	if resp.Origin != "manual" {
		t.Errorf("Origin = %q, want manual", resp.Origin)
	}
	if resp.ExpiresAt == "" {
		t.Errorf("ExpiresAt empty; should echo expiry")
	}

	// LAPI received the payload.
	lastBody := fake.lastBody.Load().(string)
	if !strings.Contains(lastBody, `"scenario":"manual:admin|smoke test ban"`) {
		t.Errorf("LAPI payload missing scenario: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"origin":"manual"`) {
		t.Errorf("LAPI payload missing origin: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"scope":"Ip"`) {
		t.Errorf("LAPI payload missing scope Ip: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"value":"203.0.113.42"`) {
		t.Errorf("LAPI payload missing value: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"message":"smoke test ban"`) {
		t.Errorf("LAPI payload missing message: %s", lastBody)
	}
	if !strings.Contains(lastBody, `"duration":"1h"`) {
		t.Errorf("LAPI payload missing duration: %s", lastBody)
	}

	// Audit emitted.
	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit count = %d, want 1", len(events))
	}
	evt := events[0]
	if evt.Action != audit.ActionCrowdSecDecisionCreate {
		t.Errorf("audit action = %q, want %q", evt.Action, audit.ActionCrowdSecDecisionCreate)
	}
	if evt.TargetID != "203.0.113.42" {
		t.Errorf("audit target_id = %q, want 203.0.113.42", evt.TargetID)
	}
	if !strings.Contains(string(evt.AfterJSON), "manual:admin|smoke test ban") {
		t.Errorf("audit after_json missing scenario: %s", evt.AfterJSON)
	}
}

func TestAddManualBan_HappyPath_CIDR_CanonicalisedAndScopeRange(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"10.5.6.7/16","duration":"24h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp manualBanResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Scope != "Range" || resp.Value != "10.5.0.0/16" {
		t.Errorf("Scope/Value = (%q, %q), want (Range, 10.5.0.0/16 canonicalised)", resp.Scope, resp.Value)
	}
}

func TestAddManualBan_NotConfigured_Returns412(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// Don't seed credentials.

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Errorf("status = %d, want 412, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Security Automation") {
		t.Errorf("body lacks Security Automation hint: %s", rec.Body.String())
	}
}

func TestAddManualBan_BadJSON_Returns400(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(`{not json`)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddManualBan_BadIP_Returns400(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"not-an-ip","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if fake.alertsCalls.Load() != 0 {
		t.Errorf("LAPI alerts hit despite validation failure: %d", fake.alertsCalls.Load())
	}
}

func TestAddManualBan_BadType_Returns400(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"delete","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestAddManualBan_LAPILoginRejected_Returns502_AfterRetry(t *testing.T) {
	fake := newFakeLAPIForBan()
	fake.loginHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "machine credentials rejected") {
		t.Errorf("body lacks credential-rejected msg: %s", rec.Body.String())
	}
}

func TestAddManualBan_LAPIPost401_RetriesOnce_Success(t *testing.T) {
	fake := newFakeLAPIForBan()
	var postHits atomic.Int32
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		hit := postHits.Add(1)
		if hit == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 after retry, body=%s", rec.Code, rec.Body.String())
	}
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("login calls = %d, want 2 (initial + retry)", got)
	}
	if got := postHits.Load(); got != 2 {
		t.Errorf("post hits = %d, want 2 (first 401 + retry success)", got)
	}
}

func TestAddManualBan_LAPIPost401Twice_Returns502_NoLoop(t *testing.T) {
	fake := newFakeLAPIForBan()
	fake.alertsHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("login calls = %d, want exactly 2 (no loop)", got)
	}
	if got := fake.alertsCalls.Load(); got != 2 {
		t.Errorf("alerts attempts = %d, want exactly 2 (no loop)", got)
	}
}

func TestAddManualBan_LAPIRefused_Returns502(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	// Bad creds pointing at an unbound port.
	if err := h.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL: "http://127.0.0.1:1", MachineID: "arenet", Password: "x",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_ = h.store.PutCrowdSecConfig(context.Background(), storage.CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:1", APIKey: "k", BouncerName: "arenet", TimeoutSeconds: 1,
	})

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

func TestAddManualBan_UsernameFromAuthContext_EncodedInScenario(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"check"}`
	// Note: reqWithAuth signature is (method, target, userID, username, clientIP, userAgent).
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u-uuid", "operator-jane", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}

	// LAPI body carries the username.
	lastBody := fake.lastBody.Load().(string)
	if !strings.Contains(lastBody, "manual:operator-jane|check") {
		t.Errorf("scenario missing username: %s", lastBody)
	}
}

func TestAddManualBan_NoAuthContext_FallsBackToUnknown(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	// httptest.NewRequest does NOT inject auth context. So
	// the handler should fall back to "unknown" without
	// crashing.
	body := `{"value":"1.1.1.1","duration":"1h","type":"ban","reason":"r"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/crowdsec/decisions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	lastBody := fake.lastBody.Load().(string)
	if !strings.Contains(lastBody, "manual:unknown|r") {
		t.Errorf("scenario missing unknown fallback: %s", lastBody)
	}
}

// --- Lapi-with-JWT shared helper (CS.3 Commit C refactor) -----

func TestLapiWithJWT_PassesMethodAndBody_ContentTypeOnPostOnly(t *testing.T) {
	var capturedMethod string
	var capturedBody []byte
	var capturedCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/watchers/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"code":200,"token":"jwt","expire":"` +
				time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339) + `"}`))
		case "/v1/alerts":
			capturedMethod = r.Method
			capturedBody, _ = io.ReadAll(io.LimitReader(r.Body, 1<<20))
			capturedCT = r.Header.Get("Content-Type")
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	creds := storage.WatcherCredentials{LAPIURL: srv.URL, MachineID: "m", Password: "p"}

	// POST path — body + Content-Type expected.
	payload := []byte(`{"hello":"world"}`)
	body, status, err := h.lapiWithJWT(context.Background(), creds, 5*time.Second,
		http.MethodPost, "/v1/alerts", payload, false)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != http.StatusCreated {
		t.Errorf("status = %d, want 201", status)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body on 201, got %q", body)
	}
	if capturedMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", capturedMethod)
	}
	if string(capturedBody) != string(payload) {
		t.Errorf("body = %q, want %q", capturedBody, payload)
	}
	if capturedCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", capturedCT)
	}

	// GET path — no body, no Content-Type.
	capturedMethod = ""
	capturedBody = nil
	capturedCT = ""
	_, _, _ = h.lapiWithJWT(context.Background(), creds, 5*time.Second,
		http.MethodGet, "/v1/alerts", nil, false)
	if capturedMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", capturedMethod)
	}
	if len(capturedBody) != 0 {
		t.Errorf("GET shouldn't carry body, got %q", capturedBody)
	}
	if capturedCT != "" {
		t.Errorf("GET shouldn't set Content-Type, got %q", capturedCT)
	}
}

// --- HF on 7302a3a: required Alert fields wire-shape pin -----
//
// LAPI's swagger Alert schema marks scenario_hash,
// scenario_version, simulated as Required: true. Empirically
// LAPI 1.7.8 rejects POSTs missing any with HTTP 500 in ~1ms.
// The fakeLAPIForBan default handler now mirrors that
// constraint so every existing happy-path test implicitly
// catches a regression. This dedicated pin asserts the wire
// shape directly so a future refactor produces a precise
// failure message rather than the generic "got 502" of the
// existing tests.

func alertPayloadHasRequiredFields(body string) bool {
	// Loose substring check is sufficient — we don't care
	// about ordering or formatting, only that the keys exist
	// at the top-level Alert. A more rigorous test would
	// decode into a struct, but the substring approach is
	// faster to read and the keys are unique enough.
	return strings.Contains(body, `"scenario_hash":`) &&
		strings.Contains(body, `"scenario_version":`) &&
		strings.Contains(body, `"simulated":`)
}

func TestManualBan_PayloadContainsRequiredAlertFields(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)

	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"203.0.113.42","duration":"1h","type":"ban","reason":"smoke"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}

	lastBody := fake.lastBody.Load().(string)

	// Required fields present.
	for _, key := range []string{
		`"scenario_hash":""`,
		`"scenario_version":""`,
		`"simulated":false`,
	} {
		if !strings.Contains(lastBody, key) {
			t.Errorf("payload missing required field %s: %s", key, lastBody)
		}
	}
}

func TestManualBan_FakeLAPIRejectsMissingRequiredFields_AsRegressionGuard(t *testing.T) {
	// Demonstrates the bug shape this HF closes: fakeLAPI's
	// default handler now mirrors LAPI's swagger validator.
	// Direct GET against the alerts endpoint with a manually-
	// crafted body missing the 3 required fields → 500. If
	// someone weakens the mock, this test starts failing.
	fake := newFakeLAPIForBan()
	srv := fake.server(t)

	missingFields := `[{"scenario":"manual:x|y","message":"y"}]`
	resp, err := http.Post(srv.URL+"/v1/alerts", "application/json", strings.NewReader(missingFields))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("fakeLAPI accepted incomplete Alert payload — mock weakened; got %d, want 500", resp.StatusCode)
	}
}

// --- Self-ban guard -------------------------------------------

func TestBanCoversClientIP(t *testing.T) {
	for _, tt := range []struct {
		name, scope, value, client string
		want                       bool
	}{
		{"same IPv4", "Ip", "203.0.113.7", "203.0.113.7", true},
		{"other IPv4", "Ip", "203.0.113.7", "203.0.113.8", false},
		{"range contains", "Range", "203.0.113.0/24", "203.0.113.7", true},
		{"range excludes", "Range", "10.0.0.0/8", "203.0.113.7", false},
		{"everything", "Range", "0.0.0.0/0", "192.0.2.1", true},
		{"v4-mapped client vs IP", "Ip", "203.0.113.7", "::ffff:203.0.113.7", true},
		{"v4-mapped client vs range", "Range", "203.0.113.0/24", "::ffff:203.0.113.7", true},
		{"IPv6 range contains", "Range", "2001:db8::/32", "2001:db8::1", true},
		{"other IPv6", "Ip", "2001:db8::1", "2001:db8::2", false},
		{"IPv6 range vs IPv4 client", "Range", "2001:db8::/32", "203.0.113.7", false},
		{"unknown client IP", "Ip", "203.0.113.7", "", false},
		{"garbage client IP", "Range", "0.0.0.0/0", "not-an-ip", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := banCoversClientIP(tt.scope, tt.value, tt.client); got != tt.want {
				t.Errorf("banCoversClientIP(%q, %q, %q) = %v, want %v", tt.scope, tt.value, tt.client, got, tt.want)
			}
		})
	}
}

func TestAddManualBan_SelfBan_Returns409_NoLAPICall(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	// The range contains the requesting client's IP.
	body := `{"value":"203.0.113.0/24","duration":"1h","type":"ban","reason":"oops"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "203.0.113.7", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Code   string            `json:"code"`
		Params map[string]string `json:"params"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.Code != errCodeCrowdSecSelfBan {
		t.Errorf("code = %q, want %q", resp.Code, errCodeCrowdSecSelfBan)
	}
	if resp.Params["clientIp"] != "203.0.113.7" || resp.Params["value"] != "203.0.113.0/24" {
		t.Errorf("params = %v, want clientIp=203.0.113.7 value=203.0.113.0/24", resp.Params)
	}
	if got := fake.alertsCalls.Load(); got != 0 {
		t.Errorf("LAPI alerts hit %d times despite the self-ban refusal", got)
	}
	if got := len(appender.Events()); got != 0 {
		t.Errorf("audit count = %d, want 0 (nothing was banned)", got)
	}
}

func TestAddManualBan_SelfBan_RefusedEvenWithoutCredentials(t *testing.T) {
	// The guard runs before the credentials lookup: the
	// operator learns about the self-ban before being sent to
	// configure Security Automation.
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)

	body := `{"value":"203.0.113.7","duration":"1h","type":"ban","reason":"r"}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "203.0.113.7", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
}

func TestAddManualBan_SelfBan_ConfirmOverride_Bans_AndAuditSaysSo(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	body := `{"value":"203.0.113.7","duration":"1h","type":"ban","reason":"testing the bouncer on myself","confirmSelfBan":true}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "203.0.113.7", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	if got := fake.alertsCalls.Load(); got != 1 {
		t.Errorf("LAPI alerts calls = %d, want 1", got)
	}
	events := appender.Events()
	if len(events) != 1 {
		t.Fatalf("audit count = %d, want 1", len(events))
	}
	if !strings.Contains(events[0].Message, "self-ban override") {
		t.Errorf("audit message = %q, want it to record the self-ban override", events[0].Message)
	}
}

func TestAddManualBan_NotSelf_AuditHasNoOverrideMessage(t *testing.T) {
	fake := newFakeLAPIForBan()
	srv := fake.server(t)
	appender := &fakeAuditAppender{}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)
	seedWatcherCredsForBan(t, h, srv.URL)

	// confirmSelfBan on a value that does not cover the client:
	// harmless, banned, and the audit row does not claim an
	// override that did not happen.
	body := `{"value":"198.51.100.9","duration":"1h","type":"ban","reason":"r","confirmSelfBan":true}`
	req := reqWithAuth(http.MethodPost, "/api/v1/security/crowdsec/decisions", "u", "admin", "203.0.113.7", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.addManualBan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body=%s", rec.Code, rec.Body.String())
	}
	events := appender.Events()
	if len(events) != 1 || events[0].Message != "" {
		t.Errorf("audit events = %+v, want one with an empty message", events)
	}
}

func TestAddManualBan_SelfBan_ThroughRouter_UsesTheAuditClientIP(t *testing.T) {
	// End to end through the production middleware stack: the
	// client IP is the one IPExtractMiddleware resolves (and the
	// audit log records), here httptest's RemoteAddr 192.0.2.1.
	// No credentials are seeded, so a 412 would mean the guard
	// did not see that IP.
	env := newTestEnv(t, false)
	body := `{"value":"192.0.2.0/24","duration":"1h","type":"ban","reason":"r"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/crowdsec/decisions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"clientIp":"192.0.2.1"`) {
		t.Errorf("body = %s, want clientIp 192.0.2.1", rec.Body.String())
	}
}
