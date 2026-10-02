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

package systemhealth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- CaddyCheck -----------------------------------------------------------

type fakeReloads struct {
	started  bool
	inFlight time.Duration
	timedOut bool
}

func (f fakeReloads) ReloadHealth() (bool, time.Duration, bool) {
	return f.started, f.inFlight, f.timedOut
}

func TestCaddyCheck_ReloadStates(t *testing.T) {
	cases := []struct {
		name string
		r    ReloadStater
		want Status
		msg  string
	}{
		{"healthy idle", fakeReloads{started: true}, StatusHealthy, "healthy"},
		{"short reload in flight", fakeReloads{started: true, inFlight: 2 * time.Second}, StatusHealthy, "healthy"},
		{"stuck reload", fakeReloads{started: true, inFlight: 40 * time.Second}, StatusUnhealthy, "stuck for 40s"},
		{"last reload timed out", fakeReloads{started: true, timedOut: true}, StatusDegraded, "timed out"},
		{"not started", fakeReloads{}, StatusUnhealthy, "not started"},
		{"not wired", nil, StatusUnhealthy, "not wired"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (&CaddyCheck{Reloads: tc.r}).Check(context.Background())
			if got.Status != tc.want || !strings.Contains(got.Message, tc.msg) {
				t.Errorf("got %q %q; want %q containing %q", got.Status, got.Message, tc.want, tc.msg)
			}
		})
	}
}

// --- BoltDBCheck ----------------------------------------------------------

type fakeRoutesCounter struct {
	count int
	err   error
}

func (f *fakeRoutesCounter) CountRoutes(_ context.Context) (int, error) {
	return f.count, f.err
}

func TestBoltDBCheck_HealthyWithCount(t *testing.T) {
	c := &BoltDBCheck{Counter: &fakeRoutesCounter{count: 6}}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy", got.Status)
	}
	if !strings.Contains(got.Message, "6 routes") {
		t.Errorf("message %q should contain '6 routes'", got.Message)
	}
}

func TestBoltDBCheck_UnhealthyOnReadError(t *testing.T) {
	c := &BoltDBCheck{Counter: &fakeRoutesCounter{err: errors.New("bbolt corrupted")}}
	got := c.Check(context.Background())
	if got.Status != StatusUnhealthy {
		t.Errorf("status = %q; want unhealthy on read error", got.Status)
	}
}

func TestBoltDBCheck_UnhealthyOnNilCounter(t *testing.T) {
	c := &BoltDBCheck{}
	got := c.Check(context.Background())
	if got.Status != StatusUnhealthy {
		t.Errorf("status = %q; want unhealthy on nil counter", got.Status)
	}
}

// --- MetricsCheck ---------------------------------------------------------

type fakeMetricsProber struct {
	version int
	err     error
	delay   time.Duration
}

func (f *fakeMetricsProber) SchemaVersion(ctx context.Context) (int, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return f.version, f.err
}

func TestMetricsCheck_HealthyOnFastRead(t *testing.T) {
	c := &MetricsCheck{Prober: &fakeMetricsProber{version: 9}}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy", got.Status)
	}
	if !strings.Contains(got.Message, "v9") {
		t.Errorf("message %q should mention schema v9", got.Message)
	}
}

func TestMetricsCheck_DegradedOnNilProber(t *testing.T) {
	c := &MetricsCheck{}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on nil prober (AC #13 boot-degraded)", got.Status)
	}
}

func TestMetricsCheck_DegradedOnReadError(t *testing.T) {
	c := &MetricsCheck{Prober: &fakeMetricsProber{err: errors.New("locked")}}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on read error", got.Status)
	}
}

// --- CrowdSecCheck --------------------------------------------------------

type fakeCrowdSecConfig struct {
	url, key   string
	configured bool
	err        error
}

func (f *fakeCrowdSecConfig) GetCrowdSecConfig(_ context.Context) (string, string, bool, error) {
	return f.url, f.key, f.configured, f.err
}

func TestCrowdSecCheck_HealthyOn2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{
			url:        srv.URL,
			key:        "secret",
			configured: true,
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy on 200", got.Status)
	}
}

func TestCrowdSecCheck_DegradedOnNotConfigured(t *testing.T) {
	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{configured: false},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded when not configured", got.Status)
	}
}

func TestCrowdSecCheck_DegradedOnLAPIUnreachable(t *testing.T) {
	// Use a port that's not in use by binding briefly + closing.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{url: url, key: "secret", configured: true},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on unreachable LAPI", got.Status)
	}
}

func TestCrowdSecCheck_DegradedOnAuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := &CrowdSecCheck{
		Config: &fakeCrowdSecConfig{url: srv.URL, key: "wrong", configured: true},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on 401", got.Status)
	}
	if !strings.Contains(got.Message, "auth") {
		t.Errorf("message %q should mention auth", got.Message)
	}
}

// --- CertmagicCheck -------------------------------------------------------

type fakeCertLister struct {
	entries []CertEntry
}

func (f *fakeCertLister) ListCertEntries() []CertEntry { return f.entries }

func TestCertmagicCheck_HealthyOnNoExpiry(t *testing.T) {
	c := &CertmagicCheck{
		Lister: &fakeCertLister{
			entries: []CertEntry{
				{Domain: "a.example", NotAfter: time.Now().Add(60 * 24 * time.Hour), StatusValid: true},
				{Domain: "b.example", NotAfter: time.Now().Add(45 * 24 * time.Hour), StatusValid: true},
			},
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusHealthy {
		t.Errorf("status = %q; want healthy (no certs in warning window)", got.Status)
	}
}

func TestCertmagicCheck_DegradedOnExpiryWindow(t *testing.T) {
	c := &CertmagicCheck{
		Lister: &fakeCertLister{
			entries: []CertEntry{
				{Domain: "soon.example", NotAfter: time.Now().Add(10 * 24 * time.Hour), StatusValid: true},
				{Domain: "far.example", NotAfter: time.Now().Add(60 * 24 * time.Hour), StatusValid: true},
			},
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded (1 cert in 14d window)", got.Status)
	}
}

func TestCertmagicCheck_DegradedOnObtainFailed(t *testing.T) {
	c := &CertmagicCheck{
		Lister: &fakeCertLister{
			entries: []CertEntry{
				{Domain: "fail.example", StatusObtainFailed: true},
			},
		},
	}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on obtain-failed cert", got.Status)
	}
	if !strings.Contains(got.Message, "failed") {
		t.Errorf("message %q should mention failure", got.Message)
	}
}

func TestCertmagicCheck_DegradedOnNoCerts(t *testing.T) {
	c := &CertmagicCheck{Lister: &fakeCertLister{}}
	got := c.Check(context.Background())
	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded on empty cert list (no HTTPS routes)", got.Status)
	}
}

// v2.58.3 — the LAPI probe retries once before calling the LAPI down.
//
// Operator report, 2026-10-02: "crowdsec-lapi-down, Arenet is fail-open"
// arrived while the enforcement bouncer was streaming without a single
// error — its log showed it starting at 14:09 and the alert firing at
// 15:06, with both CrowdSec machines heartbeating 35s apart. One sample
// decided, PerCheckTimeout is 2s, and the alerting rule fires on a single
// degraded reading, so one slow response was enough.
//
// The cost is not the inconvenience. An alert that cries wolf about a
// security control teaches the operator to ignore it, and then the real
// outage says nothing new.

// flakyLAPI fails the first n requests at the transport level, then serves
// 200. It counts attempts so a test can assert the probe tried twice.
type flakyLAPI struct {
	failures int
	attempts int
}

func (f *flakyLAPI) RoundTrip(req *http.Request) (*http.Response, error) {
	f.attempts++
	if f.attempts <= f.failures {
		return nil, errors.New("connection refused")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func crowdSecCheckWith(rt http.RoundTripper) *CrowdSecCheck {
	return &CrowdSecCheck{
		Config:     &stubCrowdSecConfig{lapiURL: "http://10.0.0.1:8080", apiKey: "k", configured: true},
		HTTPClient: &http.Client{Transport: rt},
	}
}

type stubCrowdSecConfig struct {
	lapiURL, apiKey string
	configured      bool
}

func (s *stubCrowdSecConfig) GetCrowdSecConfig(context.Context) (string, string, bool, error) {
	return s.lapiURL, s.apiKey, s.configured, nil
}

func TestCrowdSecCheck_OneTransientFailureIsNotAnOutage(t *testing.T) {
	f := &flakyLAPI{failures: 1}
	got := crowdSecCheckWith(f).Check(context.Background())

	if got.Status != StatusHealthy {
		t.Errorf("status = %q (%s); want healthy — a single lost request must not be "+
			"reported as the LAPI being down", got.Status, got.Message)
	}
	if f.attempts != 2 {
		t.Errorf("attempts = %d; want 2 (one retry)", f.attempts)
	}
}

func TestCrowdSecCheck_TwoFailuresIsAnOutage(t *testing.T) {
	f := &flakyLAPI{failures: 2}
	got := crowdSecCheckWith(f).Check(context.Background())

	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded — a LAPI that answers neither attempt is "+
			"genuinely unreachable and the operator must hear about it", got.Status)
	}
	if f.attempts != 2 {
		t.Errorf("attempts = %d; want exactly 2 — the retry must not become a loop", f.attempts)
	}
}

// An answer is not transient: a rejected key is the same on the second try,
// and retrying it just spends the per-check budget twice.
func TestCrowdSecCheck_AuthFailureIsNotRetried(t *testing.T) {
	attempts := 0
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       http.NoBody,
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	got := crowdSecCheckWith(rt).Check(context.Background())

	if got.Status != StatusDegraded {
		t.Errorf("status = %q; want degraded", got.Status)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d; want 1 — an auth rejection is an answer, not a lost packet", attempts)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
