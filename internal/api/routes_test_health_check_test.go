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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.56 — run the active health check before saving it.
//
// The reported case: a check against Ghost with no X-Forwarded-Proto, so
// Ghost answered 301 to its https URL, the expected 200 never arrived, the
// upstream left the pool and the route served 503 — surfaced only as
// "Change undone…", which protected the site and explained nothing.

func healthProbeBody(t *testing.T, upstreamURL string, hc storage.HealthCheck) string {
	t.Helper()
	raw, err := json.Marshal(healthProbeRequest{
		Upstreams:   []storage.Upstream{{URL: upstreamURL, Weight: 1}},
		HealthCheck: hc,
		RouteHost:   "blog.example.com",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

func probeCheck(uri string) storage.HealthCheck {
	return storage.HealthCheck{
		Enabled: true, URI: uri, Method: "GET",
		Interval: "30s", Timeout: "2s", Passes: 1, Fails: 1,
	}
}

// postHealthProbe calls the endpoint and decodes the first result.
func postHealthProbe(t *testing.T, env *testEnv, body string) (int, healthProbeResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-health-check", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	var out healthProbeResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v\n%s", err, rec.Body)
		}
	}
	return rec.Code, out
}

func firstResult(t *testing.T, out healthProbeResponse) healthProbeResult {
	t.Helper()
	if len(out.Results) != 1 {
		t.Fatalf("want one result, got %d: %+v", len(out.Results), out.Results)
	}
	return out.Results[0]
}

func TestHealthProbe_HealthyUpstream(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The probe must arrive with the route's host and the check's URI.
		if r.Host != "blog.example.com" {
			t.Errorf("probe Host = %q; want the route's host", r.Host)
		}
		if r.URL.Path != "/alive" {
			t.Errorf("probe path = %q; want the check's URI", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	code, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, probeCheck("/alive")))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	res := firstResult(t, out)
	if !res.Healthy {
		t.Fatalf("not healthy: %s", res.Reason)
	}
	if res.Got == nil || res.Got.StatusCode != 200 {
		t.Errorf("got = %+v", res.Got)
	}
	// The request that went out is reported, not inferred.
	if res.Sent.Method != "GET" || !strings.HasSuffix(res.Sent.URL, "/alive") {
		t.Errorf("sent = %+v", res.Sent)
	}
	if res.Sent.Host != "blog.example.com" {
		t.Errorf("sent.Host = %q", res.Sent.Host)
	}
}

func TestHealthProbe_UnexpectedStatus(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, probeCheck("/alive")))
	res := firstResult(t, out)
	if res.Healthy {
		t.Fatal("a 404 was reported healthy")
	}
	if !strings.Contains(res.Reason, "404") || !strings.Contains(res.Reason, "2xx") {
		t.Errorf("reason = %q; it must name what came back and what was expected", res.Reason)
	}
}

// A status class is accepted, which is what an app redirecting to a login
// page needs.
func TestHealthProbe_StatusClassAccepted(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	hc := probeCheck("/")
	hc.ExpectStatus = 3
	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, hc))
	res := firstResult(t, out)
	if !res.Healthy {
		t.Fatalf("a 302 was refused with expectStatus=3: %s", res.Reason)
	}
}

// THE reported case: a redirect to the same URL over https. The hint has to
// name the header, because that is the piece nobody guesses.
func TestHealthProbe_RedirectToHTTPSHintsAtForwardedProto(t *testing.T) {
	env := newTestEnv(t, false)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse(srv.URL)
		w.Header().Set("Location", "https://"+u.Host+r.URL.Path)
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer srv.Close()

	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, probeCheck("/")))
	res := firstResult(t, out)
	if res.Healthy {
		t.Fatal("a 301 was reported healthy; the real check does not follow redirects either")
	}
	if res.Got == nil || !strings.HasPrefix(res.Got.Location, "https://") {
		t.Fatalf("the Location was not surfaced: %+v", res.Got)
	}
	if !strings.Contains(res.Hint, "X-Forwarded-Proto") {
		t.Errorf("hint = %q; a redirect to the same URL over https must name the header", res.Hint)
	}
}

// A redirect somewhere else is reported, but must NOT suggest the header —
// that would be a guess dressed as a diagnosis.
func TestHealthProbe_RedirectElsewhereDoesNotSuggestTheHeader(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://somewhere.else.example/other")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, probeCheck("/")))
	res := firstResult(t, out)
	if strings.Contains(res.Hint, "X-Forwarded-Proto") {
		t.Errorf("hint = %q; the redirect does not point at the same URL", res.Hint)
	}
	if !strings.Contains(res.Hint, "somewhere.else.example") {
		t.Errorf("hint = %q; the redirect target is still worth saying", res.Hint)
	}
}

func TestHealthProbe_BodyDoesNotMatch(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"degraded"}`))
	}))
	defer srv.Close()

	hc := probeCheck("/alive")
	hc.ExpectBody = `"status":"ok"`
	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, hc))
	res := firstResult(t, out)
	if res.Healthy {
		t.Fatal("a non-matching body was reported healthy")
	}
	if res.Got == nil || res.Got.BodyMatched == nil || *res.Got.BodyMatched {
		t.Fatalf("bodyMatched should be present and false: %+v", res.Got)
	}
	// The excerpt is what makes the failure actionable.
	if !strings.Contains(res.Got.BodyExcerpt, "degraded") {
		t.Errorf("the body tested was not returned: %q", res.Got.BodyExcerpt)
	}
}

// No regex configured must leave bodyMatched absent, so the UI can tell
// "no expression" from "did not match".
func TestHealthProbe_NoBodyRegexLeavesMatchUnset(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("anything"))
	}))
	defer srv.Close()

	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, probeCheck("/")))
	if got := firstResult(t, out).Got; got == nil || got.BodyMatched != nil {
		t.Errorf("bodyMatched = %v; want absent with no expression configured", got)
	}
}

// An invalid regex is refused BEFORE any probe goes out: the operator's
// typo is not worth ten seconds of waiting on an innocent upstream.
func TestHealthProbe_InvalidRegexRefusedBeforeProbing(t *testing.T) {
	env := newTestEnv(t, false)
	probed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hc := probeCheck("/")
	hc.ExpectBody = "(unbalanced"
	code, _ := postHealthProbe(t, env, healthProbeBody(t, srv.URL, hc))
	if code != http.StatusBadRequest {
		t.Fatalf("status %d; want 400", code)
	}
	if probed {
		t.Error("the upstream was probed despite an invalid expression")
	}
}

func TestHealthProbe_Timeout(t *testing.T) {
	env := newTestEnv(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(600 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hc := probeCheck("/")
	hc.Timeout = "100ms"
	_, out := postHealthProbe(t, env, healthProbeBody(t, srv.URL, hc))
	res := firstResult(t, out)
	if res.Healthy {
		t.Fatal("a timed-out probe was reported healthy")
	}
	if !strings.Contains(res.Reason, "timed out") {
		t.Errorf("reason = %q; want the timeout named", res.Reason)
	}
}

func TestHealthProbe_UnreachableUpstream(t *testing.T) {
	env := newTestEnv(t, false)
	// A closed port on loopback: allowed by the guard, refused by the OS.
	_, out := postHealthProbe(t, env, healthProbeBody(t, "http://127.0.0.1:1", probeCheck("/")))
	res := firstResult(t, out)
	if res.Healthy {
		t.Fatal("an unreachable upstream was reported healthy")
	}
	if res.Reason == "" {
		t.Error("a failure with no reason is not actionable")
	}
	if res.Got != nil {
		t.Errorf("got = %+v; nothing came back", res.Got)
	}
}

// The guard from #143 applies here too: the metadata endpoint is not
// reachable through this button either.
func TestHealthProbe_RefusesMetadataTarget(t *testing.T) {
	env := newTestEnv(t, false)
	_, out := postHealthProbe(t, env, healthProbeBody(t, "http://169.254.169.254", probeCheck("/latest/meta-data/")))
	res := firstResult(t, out)
	if res.Healthy {
		t.Fatal("the metadata endpoint was probed successfully")
	}
	if !strings.Contains(res.Reason, "not allowed") {
		t.Errorf("reason = %q; want the refusal named", res.Reason)
	}
}

// The cap applies even to a timeout the emitted config would accept.
func TestHealthProbeTimeout_Capped(t *testing.T) {
	cases := map[string]time.Duration{
		"5s":       5 * time.Second,
		"30s":      healthProbeDeadline,
		"1m":       healthProbeDeadline,
		"":         healthProbeDeadline,
		"nonsense": healthProbeDeadline,
	}
	for raw, want := range cases {
		if got := healthProbeTimeout(raw); got != want {
			t.Errorf("healthProbeTimeout(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestHealthProbe_RefusesADisabledCheck(t *testing.T) {
	env := newTestEnv(t, false)
	hc := probeCheck("/")
	hc.Enabled = false
	code, _ := postHealthProbe(t, env, healthProbeBody(t, "http://127.0.0.1:1", hc))
	if code != http.StatusBadRequest {
		t.Errorf("status %d; want 400 — there is nothing to test", code)
	}
}

func TestHealthProbe_RefusesAnEmptyPool(t *testing.T) {
	env := newTestEnv(t, false)
	raw, _ := json.Marshal(healthProbeRequest{HealthCheck: probeCheck("/")})
	code, _ := postHealthProbe(t, env, string(raw))
	if code != http.StatusBadRequest {
		t.Errorf("status %d; want 400", code)
	}
}
