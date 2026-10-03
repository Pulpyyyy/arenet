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
	"net/url"
	"strings"
	"testing"
	"time"
)

// Step #R-PROXMOX-HTTPS-LOOP commit 3 — tests for the
// POST /api/v1/routes/test-upstream handler + the
// probeUpstream core. Most coverage runs against the core
// (probeUpstream) directly with httptest fakes; a small
// envelope of router-level tests pins the wire shape
// (admin guard, BadRequest paths).

// --- Core (probeUpstream) -------------------------------------

func TestProbeUpstream_HTTP_ReachableWithStatusAndPreview(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "test-fake/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Test Upstream</title></head><body>hello</body></html>"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	got := probeUpstream(context.Background(), u, probeOpts{})

	if !got.Reachable {
		t.Errorf("Reachable = false; want true (200 OK)")
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d; want 200", got.StatusCode)
	}
	if got.ServerHeader != "test-fake/1.0" {
		t.Errorf("ServerHeader = %q; want %q", got.ServerHeader, "test-fake/1.0")
	}
	if !strings.Contains(got.BodyPreview, "Test Upstream") {
		t.Errorf("BodyPreview did not capture the title; got %q", got.BodyPreview)
	}
	if got.TLSHandshakeMs != 0 {
		t.Errorf("TLSHandshakeMs = %d on http://; want 0", got.TLSHandshakeMs)
	}
	if got.Cert != nil {
		t.Errorf("Cert populated on http://; want nil (got %+v)", got.Cert)
	}
	if got.Error != "" {
		t.Errorf("Error = %q; want empty", got.Error)
	}
}

func TestProbeUpstream_HTTP_PreservesNonSuccessStatusAsReachable(t *testing.T) {
	// 401 / 403 / 404 are still "the service is up" —
	// the operator's Proxmox legitimately returns 401 on
	// GET / (no auth header). Pin the operator-meaningful
	// summary: reachable=true even on a non-2xx.
	for _, sc := range []int{401, 403, 404, 500} {
		t.Run(http.StatusText(sc), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(sc)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			got := probeUpstream(context.Background(), u, probeOpts{})
			if !got.Reachable {
				t.Errorf("Reachable = false on %d; want true (handshake completed)", sc)
			}
			if got.StatusCode != sc {
				t.Errorf("StatusCode = %d; want %d", got.StatusCode, sc)
			}
		})
	}
}

func TestProbeUpstream_HTTP_DoesNotFollowRedirects(t *testing.T) {
	// A 301 to https:// is a legit datapoint — exactly
	// the symptom that started #R-PROXMOX-HTTPS-LOOP.
	// The probe must surface the 301 directly, not chase
	// it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://elsewhere.invalid/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	got := probeUpstream(context.Background(), u, probeOpts{})
	if got.StatusCode != 301 {
		t.Errorf("StatusCode = %d; want 301 (no auto-follow)", got.StatusCode)
	}
	if !got.Reachable {
		t.Errorf("Reachable = false on 301; want true (the upstream answered)")
	}
}

func TestProbeUpstream_HTTPS_CertCaptured_StrictRejectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	// Strict mode: insecureSkipVerify=false. The httptest
	// TLS server uses a self-signed cert by default, so
	// the probe must FAIL verification.
	got := probeUpstream(context.Background(), u, probeOpts{})
	if got.Reachable {
		t.Errorf("Reachable = true on strict probe of self-signed; want false")
	}
	if got.Error == "" {
		t.Error("Error empty on strict probe of self-signed; want a TLS error")
	}
	if got.Cert == nil {
		t.Fatal("Cert nil on strict probe; want extracted from verification error")
	}
	if !got.Cert.SelfSigned {
		t.Errorf("Cert.SelfSigned = false; want true (httptest TLS cert is self-signed)")
	}
}

func TestProbeUpstream_HTTPS_InsecureSkipVerify_AcceptsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "proxmox-fake/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<title>Proxmox VE Login</title>"))
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	// insecureSkipVerify=true → the self-signed httptest
	// cert is accepted, handshake completes, GET / returns
	// 200 + the body.
	got := probeUpstream(context.Background(), u, probeOpts{InsecureSkipVerify: true})
	if !got.Reachable {
		t.Errorf("Reachable = false with insecureSkipVerify=true; want true (got %+v)", got)
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d; want 200", got.StatusCode)
	}
	if got.Cert == nil {
		t.Fatal("Cert nil on https success; want populated")
	}
	if !got.Cert.SelfSigned {
		t.Errorf("Cert.SelfSigned = false; want true")
	}
	if !strings.Contains(got.BodyPreview, "Proxmox") {
		t.Errorf("BodyPreview did not capture title; got %q", got.BodyPreview)
	}
	if got.TLSHandshakeMs == 0 {
		t.Errorf("TLSHandshakeMs = 0 on https success; want > 0")
	}
}

func TestProbeUpstream_BodyPreviewRespectsCap(t *testing.T) {
	// Sanitise + 200-char cap — synthesise a body larger
	// than 200 visible chars and verify the result is
	// trimmed.
	big := strings.Repeat("ABCDE", 500) // 2500 chars
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := probeUpstream(context.Background(), u, probeOpts{})
	// Cap is 200 runes; ASCII so chars == bytes.
	if got.BodyPreview == "" {
		t.Fatal("BodyPreview empty; want trimmed content")
	}
	if len(got.BodyPreview) > 220 {
		t.Errorf("BodyPreview length = %d; want <= ~200", len(got.BodyPreview))
	}
}

func TestProbeUpstream_BodyPreviewStripsControlChars(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Bell + null + ESC + tabs + visible — visible
		// chars survive, control chars get dropped /
		// collapsed.
		_, _ = w.Write([]byte("HELLO\x07\x00\x1b\tTHERE"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	got := probeUpstream(context.Background(), u, probeOpts{})
	for _, r := range got.BodyPreview {
		if r < 0x20 && r != ' ' { // tab collapses to space
			t.Errorf("control char 0x%02x leaked into BodyPreview: %q", r, got.BodyPreview)
		}
		if r == 0x7f {
			t.Errorf("DEL leaked into BodyPreview: %q", got.BodyPreview)
		}
	}
	if !strings.Contains(got.BodyPreview, "HELLO") || !strings.Contains(got.BodyPreview, "THERE") {
		t.Errorf("printable text lost: %q", got.BodyPreview)
	}
}

func TestProbeUpstream_Timeout_ReturnsHumanError(t *testing.T) {
	// Server that never responds — context deadline
	// fires.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got := probeUpstream(ctx, u, probeOpts{})
	if got.Reachable {
		t.Error("Reachable = true on timeout; want false")
	}
	if got.Error == "" {
		t.Error("Error empty on timeout; want a human-readable message")
	}
}

func TestProbeUpstream_ConnectionRefused_HumanError(t *testing.T) {
	// Bind a server, capture its address, immediately
	// close — subsequent dials get connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()

	u, _ := url.Parse(addr)
	got := probeUpstream(context.Background(), u, probeOpts{})
	if got.Reachable {
		t.Error("Reachable = true on refused conn; want false")
	}
	if !strings.Contains(strings.ToLower(got.Error), "refused") {
		t.Errorf("Error = %q; want to mention connection refused", got.Error)
	}
}

// --- Wire (router envelope) -----------------------------------

func TestTestUpstream_Wire_BadJSONReturns400(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
		strings.NewReader("{not json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestTestUpstream_Wire_EmptyURLReturns400(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
		strings.NewReader(`{"url":"   "}`))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "url must not be empty") {
		t.Errorf("error message did not include reason: %s", rec.Body)
	}
}

func TestTestUpstream_Wire_UnsupportedSchemeReturns400(t *testing.T) {
	env := newTestEnv(t, false)
	for _, scheme := range []string{"file", "gopher", "ftp", "ldap"} {
		t.Run(scheme, func(t *testing.T) {
			body := `{"url":"` + scheme + `://example.com/etc/passwd"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
				strings.NewReader(body))
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s for scheme %q", rec.Code, rec.Body, scheme)
			}
			if !strings.Contains(rec.Body.String(), "http or https") {
				t.Errorf("error message did not mention scheme: %s", rec.Body)
			}
		})
	}
}

func TestTestUpstream_Wire_ExcessivelyLongURLReturns400(t *testing.T) {
	env := newTestEnv(t, false)
	long := "http://" + strings.Repeat("a", 2500) + ".example.com/"
	body := `{"url":` + jsonQuote(long) + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "maximum length") {
		t.Errorf("error did not mention length cap: %s", rec.Body)
	}
}

func TestTestUpstream_Wire_RejectsUnknownFields(t *testing.T) {
	// DisallowUnknownFields — typos like "skipVerify"
	// instead of "insecureSkipVerify" should be rejected,
	// not silently ignored.
	env := newTestEnv(t, false)
	body := `{"url":"http://127.0.0.1:1/","skipVerify":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestTestUpstream_Wire_HappyPath_HTTP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "wire-fake/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	env := newTestEnv(t, false)
	body := `{"url":` + jsonQuote(upstream.URL) + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
		strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp testUpstreamResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Reachable {
		t.Errorf("Reachable = false; want true")
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d; want 200", resp.StatusCode)
	}
}

// jsonQuote returns a JSON-encoded string literal for use
// inside hand-built JSON bodies. Avoids the verbosity of
// pulling in encoding/json.Marshal on a single string.
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
