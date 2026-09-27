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

package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/certinfo"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/systemhealth"
)

// AL.2.a — Source registry + 3 bootstrap source impls.

func TestSourceRegistry_AddLookup(t *testing.T) {
	r := NewSourceRegistry()
	src := &passthroughSource{name: "stub"}
	if err := r.Register(src); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, ok := r.Get("stub")
	if !ok {
		t.Fatalf("Get stub: not found after Register")
	}
	if got.Name() != "stub" {
		t.Errorf("Get returned Name=%q want stub", got.Name())
	}
}

func TestSourceRegistry_Duplicate(t *testing.T) {
	r := NewSourceRegistry()
	_ = r.Register(&passthroughSource{name: "stub"})
	err := r.Register(&passthroughSource{name: "stub"})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("err = %v; want duplicate-register error", err)
	}
}

func TestSourceRegistry_NotFound(t *testing.T) {
	r := NewSourceRegistry()
	if _, ok := r.Get("ghost"); ok {
		t.Errorf("Get ghost: ok=true; want false")
	}
}

func TestSourceRegistry_RegisterNil(t *testing.T) {
	r := NewSourceRegistry()
	if err := r.Register(nil); err == nil {
		t.Errorf("Register nil: nil err; want error")
	}
}

func TestSourceRegistry_Names_Sorted(t *testing.T) {
	r := NewSourceRegistry()
	_ = r.Register(&passthroughSource{name: "zeta"})
	_ = r.Register(&passthroughSource{name: "alpha"})
	_ = r.Register(&passthroughSource{name: "mu"})
	got := r.Names()
	want := []string{"alpha", "mu", "zeta"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("Names()[%d] = %q want %q", i, got[i], w)
		}
	}
}

// -- waf_event_rate ---------------------------------------

// stubWafReader counts its canned events, applying the filter's Action in
// the same place the real store now does.
//
// v2.52 — the source used to fetch rows and count them itself; it now
// asks the store for a COUNT, because a result-set cap of 100 made every
// threshold above that unreachable. The stub honours Action so the
// action-filter tests keep testing the thing they were written for.
type stubWafReader struct {
	events []observability.WafEvent
	err    error
	called observability.WafEventFilter
}

func (s *stubWafReader) CountWafEvents(_ context.Context, f observability.WafEventFilter) (int, error) {
	s.called = f
	if s.err != nil {
		return 0, s.err
	}
	n := 0
	for _, e := range s.events {
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		n++
	}
	return n, nil
}

func TestWafEventRateSource_HappyCountsAll(t *testing.T) {
	reader := &stubWafReader{
		events: []observability.WafEvent{
			{Action: "BLOCK"}, {Action: "BLOCK"}, {Action: "DETECT"},
		},
	}
	src := NewWafEventRateSource(reader)
	raw := json.RawMessage(`{"windowSecs":300}`)
	got, err := src.Read(context.Background(), raw)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil || *got.Float != 3 {
		t.Errorf("count = %v; want 3", got.Float)
	}
}

func TestWafEventRateSource_ActionFilter(t *testing.T) {
	reader := &stubWafReader{
		events: []observability.WafEvent{
			{Action: "BLOCK"}, {Action: "BLOCK"}, {Action: "DETECT"},
		},
	}
	src := NewWafEventRateSource(reader)
	raw := json.RawMessage(`{"windowSecs":300,"action":"BLOCK"}`)
	got, err := src.Read(context.Background(), raw)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil || *got.Float != 2 {
		t.Errorf("count = %v; want 2 (BLOCK only)", got.Float)
	}
}

func TestWafEventRateSource_Validate_BadAction(t *testing.T) {
	src := NewWafEventRateSource(&stubWafReader{})
	raw := json.RawMessage(`{"action":"OBSERVE","windowSecs":300}`)
	if err := src.ValidateParams(raw); err == nil {
		t.Errorf("nil err; want bad-action validation error")
	}
}

func TestWafEventRateSource_Validate_WindowTooSmall(t *testing.T) {
	src := NewWafEventRateSource(&stubWafReader{})
	raw := json.RawMessage(`{"windowSecs":10}`)
	if err := src.ValidateParams(raw); err == nil {
		t.Errorf("nil err; want window range error")
	}
}

func TestWafEventRateSource_Read_ReaderNil(t *testing.T) {
	src := NewWafEventRateSource(nil)
	_, err := src.Read(context.Background(), json.RawMessage(`{"windowSecs":300}`))
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Errorf("err = %v; want boot-degraded error", err)
	}
}

// -- cert_expiry ------------------------------------------

type stubCertLister struct {
	list []*certinfo.CertRuntimeInfo
	byID map[string]*certinfo.CertRuntimeInfo
}

func (s *stubCertLister) List() []*certinfo.CertRuntimeInfo {
	return s.list
}
func (s *stubCertLister) Get(domain string) (*certinfo.CertRuntimeInfo, bool) {
	v, ok := s.byID[domain]
	return v, ok
}

func TestCertExpirySource_EarliestExpiringWhenNoHost(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	earliest := &certinfo.CertRuntimeInfo{
		Domain:   "api.example.com",
		NotAfter: now.Add(7 * 24 * time.Hour), // 7 days
	}
	later := &certinfo.CertRuntimeInfo{
		Domain:   "www.example.com",
		NotAfter: now.Add(30 * 24 * time.Hour), // 30 days
	}
	lister := &stubCertLister{list: []*certinfo.CertRuntimeInfo{earliest, later}}
	src := NewCertExpirySource(lister)
	src.now = func() time.Time { return now }

	got, err := src.Read(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil {
		t.Fatalf("Float nil")
	}
	// 7 days ± rounding tolerance.
	if d := *got.Float; d < 6.9 || d > 7.1 {
		t.Errorf("days = %v; want ~7", d)
	}
	if got.Labels["host"] != "api.example.com" {
		t.Errorf("host label = %q; want api.example.com", got.Labels["host"])
	}
}

func TestCertExpirySource_HostNotTracked(t *testing.T) {
	lister := &stubCertLister{byID: map[string]*certinfo.CertRuntimeInfo{}}
	src := NewCertExpirySource(lister)
	_, err := src.Read(context.Background(), json.RawMessage(`{"host":"ghost.example.com"}`))
	if err == nil || !strings.Contains(err.Error(), "not tracked") {
		t.Errorf("err = %v; want not-tracked error", err)
	}
}

func TestCertExpirySource_NoCerts(t *testing.T) {
	lister := &stubCertLister{}
	src := NewCertExpirySource(lister)
	_, err := src.Read(context.Background(), json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "no certs") {
		t.Errorf("err = %v; want no-certs error", err)
	}
}

// -- system_health ----------------------------------------

type stubHealthRunner struct {
	report systemhealth.Report
}

func (s *stubHealthRunner) Run(_ context.Context) systemhealth.Report { return s.report }

func TestSystemHealthSource_GlobalStatus(t *testing.T) {
	runner := &stubHealthRunner{report: systemhealth.Report{Status: systemhealth.StatusDegraded}}
	src := NewSystemHealthSource(runner)
	got, err := src.Read(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.String == nil || *got.String != "degraded" {
		t.Errorf("String = %v; want degraded", got.String)
	}
}

func TestSystemHealthSource_PerComponent(t *testing.T) {
	runner := &stubHealthRunner{report: systemhealth.Report{
		Status: systemhealth.StatusDegraded,
		Components: []systemhealth.NamedReport{
			{Name: "caddy", ComponentStatus: systemhealth.ComponentStatus{Status: systemhealth.StatusHealthy}},
			{Name: "crowdsec", ComponentStatus: systemhealth.ComponentStatus{Status: systemhealth.StatusDegraded, Message: "lapi down"}},
		},
	}}
	src := NewSystemHealthSource(runner)
	got, err := src.Read(context.Background(), json.RawMessage(`{"component":"crowdsec"}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.String == nil || *got.String != "degraded" {
		t.Errorf("String = %v; want degraded", got.String)
	}
	if got.Context["message"] != "lapi down" {
		t.Errorf("context.message = %v; want lapi down", got.Context["message"])
	}
}

func TestSystemHealthSource_ComponentNotFound(t *testing.T) {
	runner := &stubHealthRunner{report: systemhealth.Report{
		Components: []systemhealth.NamedReport{{Name: "caddy"}},
	}}
	src := NewSystemHealthSource(runner)
	_, err := src.Read(context.Background(), json.RawMessage(`{"component":"ghost"}`))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v; want not-found error", err)
	}
}

// Sentinel: errors import is used by every test indirectly,
// keep it explicit so the linter doesn't strip on refactor.
var _ = errors.New
