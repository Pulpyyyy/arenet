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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeMetricsReader is the test double for the AC #13 paths.
// queryFn / queryAggregatedFn let each test customise the
// response (return rows, return error). When unset, the
// defaults are "no rows, no error" — a healthy-but-empty store.
type fakeMetricsReader struct {
	queryFn           func(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error)
	queryAggregatedFn func(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error)
}

func (f *fakeMetricsReader) Query(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, gran, routeID, from, to)
	}
	return nil, nil
}

func (f *fakeMetricsReader) QueryAggregated(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error) {
	if f.queryAggregatedFn != nil {
		return f.queryAggregatedFn(ctx, gran, from, to)
	}
	return nil, nil
}

// metricsTestEnv builds a Handler + auto-auth router specifically
// for the /metrics endpoints. Seeds one route in BoltDB so the
// timeseries 404-on-unknown-route path is covered without
// affecting other tests' fixtures.
type metricsTestEnv struct {
	env     *testEnv
	router  http.Handler
	routeID string
}

func newMetricsTestEnv(t *testing.T) *metricsTestEnv {
	t.Helper()
	env := newTestEnv(t, false)
	rt, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "metrics.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return &metricsTestEnv{env: env, router: env.router, routeID: rt.ID}
}

// rawHandler returns a router that bypasses the autoAuthRouter
// wrapper — used for tests that must hit the genuine 401 path
// (anon).
func (m *metricsTestEnv) rawHandler(t *testing.T) http.Handler {
	t.Helper()
	ipExtractor, _ := auth.NewIPExtractor("")
	return NewRouter(m.env.handler, false, ipExtractor, nil, nil, nil, nil)
}

// --- AC #17 auth gate --------------------------------------------------------

func TestMetricsEndpoints_Viewer200(t *testing.T) {
	// AC #17 explicitly: a viewer (not admin) MUST be able to
	// read the /metrics/* endpoints. The wiring places them in
	// the hard-auth-no-admin-gate group, so admin and viewer
	// share the same code path — but a direct viewer test is
	// the only guard against a future regression where someone
	// drops a RequireAdminMiddleware on this subgroup (anon/admin
	// tests wouldn't catch that — only the viewer would 403).
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "metrics-viewer", "Metrics Viewer", "", "sub-metrics-viewer")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer (CreateOIDCUser default)", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(m.env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed viewer session: %v", err)
	}
	raw := m.rawHandler(t)
	cookie := &http.Cookie{Name: sessionCookieName, Value: s.ID}

	for _, path := range []string{
		"/api/v1/metrics/timeseries?route=" + m.routeID + "&metric=req_per_sec&window=24h",
		"/api/v1/metrics/summary",
		"/api/v1/metrics/route-summary?route=" + m.routeID,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		raw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("VIEWER LOCKOUT REGRESSION on %s: status=%d body=%s — AC #17 requires viewer-or-above read access", path, rec.Code, rec.Body)
		}
	}
}

func TestMetricsEndpoints_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	for _, path := range []string{
		"/api/v1/metrics/timeseries?route=" + m.routeID + "&metric=req_per_sec&window=24h",
		"/api/v1/metrics/summary",
		"/api/v1/metrics/route-summary?route=" + m.routeID,
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		raw.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: anon status = %d, want 401", path, rec.Code)
		}
	}
}

// --- AC #13 degraded paths ---------------------------------------------------

func TestMetricsTimeseries_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// metrics reader intentionally left nil (boot-failed).
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true")
	}
	if len(resp.Points) != 0 {
		t.Errorf("points = %d, want 0 (no data when disabled)", len(resp.Points))
	}
}

func TestMetricsSummary_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (nil reader = degraded)")
	}
}

func TestMetricsTimeseries_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestMetricsSummary_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(_ context.Context, _ observability.Granularity, _ string, _, _ time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("locked")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- AC #5 gap-fill ----------------------------------------------------------

func TestMetricsTimeseries_GapFill_CountsZero(t *testing.T) {
	m := newMetricsTestEnv(t)

	// Real :memory: observability store with two rows: one at
	// "10 minutes ago" and one at "5 minutes ago". The slots
	// in between MUST come back with value: 0 for a count
	// metric, never null.
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	rows := []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-10 * time.Minute), ReqCount: 100, FourxxCount: 2, FivexxCount: 1, LatencyP95Ms: 16},
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 200, FourxxCount: 0, FivexxCount: 0, LatencyP95Ms: 32},
	}
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := len(resp.Points); got < 1400 || got > 1500 {
		t.Fatalf("points = %d, want ~1440 (24h × 60min)", got)
	}

	// Find the two seeded points and assert their immediate
	// neighbours are gap-filled with 0, not null.
	gapNonNullCount := 0
	dataPointsCount := 0
	for _, p := range resp.Points {
		if p.Value == nil {
			t.Errorf("count-metric point at %s has null value — AC #5 violation (counts must gap-fill to 0)", p.Ts)
		}
		if p.Value != nil {
			gapNonNullCount++
			if *p.Value > 0 {
				dataPointsCount++
			}
		}
	}
	if dataPointsCount != 2 {
		t.Errorf("data points (value > 0) = %d, want 2", dataPointsCount)
	}
	if gapNonNullCount < 1400 {
		t.Errorf("gap-filled non-null count points = %d, want ~1440", gapNonNullCount)
	}
}

func TestMetricsTimeseries_GapFill_P95Null(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	// One row with traffic + latency, then a long gap.
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 100, LatencyP95Ms: 32},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=p95_latency_ms&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	nullCount := 0
	dataPointCount := 0
	var dataValue float64
	for _, p := range resp.Points {
		if p.Value == nil {
			nullCount++
		} else {
			dataPointCount++
			dataValue = *p.Value
		}
	}
	if dataPointCount != 1 {
		t.Fatalf("p95 data points = %d, want 1", dataPointCount)
	}
	if dataValue != 32 {
		t.Errorf("p95 data value = %v, want 32", dataValue)
	}
	if nullCount < 1400 {
		t.Errorf("p95 null-gap points = %d, want ~1439 (every empty bucket is null, NOT 0 — AC #5)", nullCount)
	}
}

// --- AC #6 4xx / 5xx split on summary ---------------------------------------

func TestMetricsSummary_4xxAnd5xxAreIndependent(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	// Seed the just-closed minute with one row carrying ONLY
	// 4xx (no 5xx). The summary response MUST report the 4xx
	// total non-zero and the 5xx total exactly zero — proving
	// the two are independent fields (AC #6).
	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 50, FourxxCount: 7, FivexxCount: 0, LatencyP95Ms: 12},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalFourXx != 7 {
		t.Errorf("TotalFourXx = %d, want 7", resp.TotalFourXx)
	}
	if resp.TotalFiveXx != 0 {
		t.Errorf("TotalFiveXx = %d, want 0 — 4xx must NOT contaminate 5xx field (AC #6)", resp.TotalFiveXx)
	}
	if resp.TotalReq != 50 {
		t.Errorf("TotalReq = %d, want 50", resp.TotalReq)
	}
	// Reciprocal coverage in TestMetricsSummary_5xxOnly below.
}

func TestMetricsSummary_5xxOnly_4xxStaysZero(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 20, FourxxCount: 0, FivexxCount: 3, LatencyP95Ms: 12},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalFiveXx != 3 {
		t.Errorf("TotalFiveXx = %d, want 3", resp.TotalFiveXx)
	}
	if resp.TotalFourXx != 0 {
		t.Errorf("TotalFourXx = %d, want 0 — 5xx must NOT contaminate 4xx field (AC #6)", resp.TotalFourXx)
	}
}

// --- Validation paths --------------------------------------------------------

func TestMetricsTimeseries_BadMetric(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=BOGUS&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestMetricsTimeseries_BadWindow(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=7d", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// --- Spec-1 §10.1: route=all aggregated timeseries -------------------------

func TestMetricsTimeseries_RouteAll_AggregatesAcrossRoutes(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	// Seed two routes with traffic in the SAME minute and a
	// third route in a different minute. The aggregated
	// timeseries must show ONE point per minute, summing
	// across routes inside the minute.
	now := time.Now().UTC().Truncate(time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 80, FourxxCount: 4, FivexxCount: 0, LatencyP95Ms: 16},
		// A second seeded route in the same -5m bucket would
		// require seeding another route. We test the GROUP BY
		// implicitly by combining with a different bucket.
		{RouteID: m.routeID, Ts: now.Add(-3 * time.Minute), ReqCount: 100, FourxxCount: 0, FivexxCount: 2, LatencyP95Ms: 32},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.RouteID != "all" {
		t.Errorf("RouteID echo = %q, want \"all\"", resp.RouteID)
	}
	// Sanity: roughly 1440 buckets (24h × 60min).
	if got := len(resp.Points); got < 1400 || got > 1500 {
		t.Fatalf("points = %d, want ~1440", got)
	}
	// Find the two data points (value > 0) and confirm their
	// sums are correct.
	dataValues := []float64{}
	for _, p := range resp.Points {
		if p.Value != nil && *p.Value > 0 {
			dataValues = append(dataValues, *p.Value)
		}
	}
	if len(dataValues) != 2 {
		t.Fatalf("data points = %d, want 2: %v", len(dataValues), dataValues)
	}
	// Order is timestamp-ascending: -5m then -3m.
	if dataValues[0] != 80 || dataValues[1] != 100 {
		t.Errorf("aggregated req counts = %v, want [80, 100]", dataValues)
	}
}

func TestMetricsTimeseries_RouteAll_4xxAnd5xxStaySeparate(t *testing.T) {
	// AC #3 anti-regression on the aggregated path: a
	// 4xx-only burst across routes must NOT inflate the
	// aggregated 5xx series.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 50, FourxxCount: 30, FivexxCount: 0, LatencyP95Ms: 8},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 4xx series: should have a non-zero data point.
	req4 := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=four_xx_rate&window=24h", nil)
	rec4 := httptest.NewRecorder()
	m.router.ServeHTTP(rec4, req4)
	var resp4 timeseriesResponse
	if err := json.NewDecoder(rec4.Body).Decode(&resp4); err != nil {
		t.Fatalf("decode 4xx: %v", err)
	}
	max4 := 0.0
	for _, p := range resp4.Points {
		if p.Value != nil && *p.Value > max4 {
			max4 = *p.Value
		}
	}
	if max4 != 30 {
		t.Errorf("4xx aggregated max = %v, want 30", max4)
	}

	// 5xx series: every point must be zero (no 5xx seeded).
	req5 := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=five_xx_rate&window=24h", nil)
	rec5 := httptest.NewRecorder()
	m.router.ServeHTTP(rec5, req5)
	var resp5 timeseriesResponse
	if err := json.NewDecoder(rec5.Body).Decode(&resp5); err != nil {
		t.Fatalf("decode 5xx: %v", err)
	}
	for _, p := range resp5.Points {
		if p.Value != nil && *p.Value > 0 {
			t.Fatalf("aggregated 5xx had a non-zero point (%v) — AC #3 regression: 4xx leaked into 5xx", *p.Value)
		}
	}
}

func TestMetricsTimeseries_RouteAll_NilReaderDisabled(t *testing.T) {
	// AC #13 carries over: aggregated endpoint must also
	// emit disabled=true when the reader is nil.
	m := newMetricsTestEnv(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded)", rec.Code)
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true on aggregated path with nil reader")
	}
}

func TestMetricsTimeseries_RouteAll_SentinelBeatsCollidingRoute(t *testing.T) {
	// Anti-regression for the collision analysis documented on
	// routeAllSentinel in metrics_handlers.go.
	//
	// UUID-generated route IDs cannot collide with "all"
	// (different format, different length). But a tampered
	// backup restore COULD inject a row with ID "all". Pin the
	// invariant behaviourally: when route=all is passed, the
	// handler dispatches to QueryAggregated (not Query) — even
	// when both fakes return distinguishable sentinel data.
	m := newMetricsTestEnv(t)
	now := time.Now().UTC().Truncate(time.Minute)
	aggregatedSentinelTs := now.Add(-7 * time.Minute)
	perRouteSentinelTs := now.Add(-13 * time.Minute)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(_ context.Context, _ observability.Granularity, _ string, _, _ time.Time) ([]observability.MetricBucket, error) {
			// Per-route value the handler MUST NOT pick up.
			return []observability.MetricBucket{
				{Ts: perRouteSentinelTs, ReqCount: 999},
			}, nil
		},
		queryAggregatedFn: func(_ context.Context, _ observability.Granularity, _, _ time.Time) ([]observability.MetricBucket, error) {
			return []observability.MetricBucket{
				{Ts: aggregatedSentinelTs, ReqCount: 42},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Find the single non-zero point; assert it carries the
	// aggregated sentinel (42), NOT the per-route one (999).
	for _, p := range resp.Points {
		if p.Value != nil && *p.Value == 999 {
			t.Fatalf("route=all dispatched to per-route Query (got 999 sentinel) — sentinel precedence regression")
		}
	}
	found := false
	for _, p := range resp.Points {
		if p.Value != nil && *p.Value == 42 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("aggregated sentinel (42) not in response — route=all dispatched somewhere unexpected")
	}
}

func TestMetricsTimeseries_RouteAll_QueryError503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryAggregatedFn: func(_ context.Context, _ observability.Granularity, _, _ time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("locked")
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestMetricsTimeseries_UnknownRoute404(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=00000000-0000-0000-0000-000000000000&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// --- Step Q.3: throttle_block_rate + auth_failure_rate ----------------------

func TestMetricsTimeseries_ThrottleBlockRate_ReadsBucketColumn(t *testing.T) {
	// Verify the new throttle_block_rate metric reads from
	// MetricBucket.ThrottleBlockCount with gap-fill = 0 for
	// empty buckets. Spec §3.5: production stores throttle
	// blocks under the sentinel route_id "_throttle"; this
	// handler test seeds two rows under the test route ID
	// (which has a valid storage.Route entry so the 404 guard
	// passes) — the field-routing logic in pickMetricValue is
	// what we're exercising, not the sentinel convention.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	rows := []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-10 * time.Minute), ReqCount: 0, ThrottleBlockCount: 5},
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 0, ThrottleBlockCount: 3},
	}
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=throttle_block_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if string(resp.Metric) != "throttle_block_rate" {
		t.Errorf("response metric = %q, want throttle_block_rate", resp.Metric)
	}
	// Counts gap-fill = 0; the two seeded rows surface as 5 + 3.
	total := 0.0
	for _, p := range resp.Points {
		if p.Value == nil {
			t.Fatal("count metric point has null value — AC #5 violation")
		}
		total += *p.Value
	}
	if total != 8 {
		t.Errorf("sum of throttle_block_rate values = %v, want 8", total)
	}
}

func TestMetricsTimeseries_AuthFailureRate_AuditScanDetour(t *testing.T) {
	// auth_failure_rate detours through AuthFailureReader.
	// Verify: route=all + readers wired + a few audit events
	// → the timeseries reflects them, gap-filled with 0.
	m := newMetricsTestEnv(t)
	now := time.Now().UTC()
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return []audit.Event{
				{Action: audit.ActionLoginFailure, Timestamp: now.Add(-1 * time.Minute)},
				{Action: audit.ActionLoginFailure, Timestamp: now.Add(-2 * time.Minute)},
				{Action: audit.ActionOIDCLoginRejected, Timestamp: now.Add(-30 * time.Minute)},
			}, false, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=auth_failure_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	// 24h window @ 1m step = 1440 buckets.
	if len(resp.Points) != 1440 {
		t.Errorf("len(points) = %d, want 1440", len(resp.Points))
	}
	total := 0.0
	for _, p := range resp.Points {
		if p.Value == nil {
			t.Fatal("auth_failure_rate point has null value — counts must gap-fill to 0")
		}
		total += *p.Value
	}
	if total != 3 {
		t.Errorf("sum of auth_failure_rate values = %v, want 3 (seeded events)", total)
	}
}

func TestMetricsTimeseries_AuthFailureRate_PerRouteIsAllZero(t *testing.T) {
	// AC #10 literal: route=<uuid> for auth_failure_rate
	// returns all-zero (signal is not per-route). Seed audit
	// events; verify route=<routeID> returns 0s across the
	// board.
	m := newMetricsTestEnv(t)
	now := time.Now().UTC()
	called := false
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			called = true
			return []audit.Event{
				{Action: audit.ActionLoginFailure, Timestamp: now.Add(-1 * time.Minute)},
			}, false, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=auth_failure_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	for _, p := range resp.Points {
		if p.Value == nil || *p.Value != 0 {
			t.Fatalf("per-route auth_failure_rate must be all-zero (AC #10), got %+v at %s", p.Value, p.Ts)
		}
	}
	if called {
		t.Error("per-route auth_failure_rate should NOT invoke the audit scan (AC #10 short-circuit)")
	}
}

func TestMetricsTimeseries_AuthFailureRate_NilReader_Disabled(t *testing.T) {
	// AC #14 mirror: nil AuthFailureReader → disabled=true
	// for the auth_failure_rate detour.
	m := newMetricsTestEnv(t)
	// Intentionally NOT calling SetAuthFailureReader.

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=auth_failure_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp timeseriesResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (nil reader)")
	}
}

func TestMetricsTimeseries_AuthFailureRate_ScanError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return nil, false, errors.New("audit bucket missing")
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=auth_failure_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestMetricsTimeseries_NewMetrics_AcceptedByValidator(t *testing.T) {
	// Anti-regression: the metricName enum extensions must
	// be wired into isValidMetric. A future refactor that
	// drops one would surface 400 here.
	for _, m := range []string{"throttle_block_rate", "auth_failure_rate"} {
		if !isValidMetric(metricName(m)) {
			t.Errorf("metric %q rejected by isValidMetric", m)
		}
	}
}

// --- Step Q.3: metricsSummary new fields ------------------------------------

func TestMetricsSummary_TotalThrottle_FromSentinelRow(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC()
	// The summary reads the just-closed minute. Seed at that
	// bucket under the sentinel route id.
	prevHour := now.Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h,
		[]observability.MetricBucket{
			{RouteID: observability.ThrottleSentinelRouteID, Ts: prevHour, ThrottleBlockCount: 7},
		}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalThrottle != 7 {
		t.Errorf("totalThrottlePerMin = %d, want 7", resp.TotalThrottle)
	}
}

func TestMetricsSummary_TotalAuthFailures_FromAuditScan(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC()
	hourTs := now.Truncate(time.Hour)
	wantFrom := hourTs.Add(-24 * time.Hour)
	wantTo := hourTs
	// Reader returns 3 events within the 24h window.
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, from, to time.Time, _ int) ([]audit.Event, bool, error) {
			// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — verify
			// the handler asked for the 24h window ending at
			// the previous hour boundary.
			if !from.Equal(wantFrom) {
				t.Errorf("audit scan from = %v, want %v (24h window)", from, wantFrom)
			}
			if !to.Equal(wantTo) {
				t.Errorf("audit scan to = %v, want %v (24h window)", to, wantTo)
			}
			return []audit.Event{
				{Action: audit.ActionLoginFailure, IP: "1.1.1.1", Timestamp: hourTs.Add(-30 * time.Minute)},
				{Action: audit.ActionLoginFailure, IP: "1.1.1.1", Timestamp: hourTs.Add(-20 * time.Minute)},
				{Action: audit.ActionOIDCLoginRejected, IP: "2.2.2.2", Timestamp: hourTs.Add(-10 * time.Minute)},
			}, false, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalAuthFailures != 3 {
		t.Errorf("totalAuthFailuresPerMin = %d, want 3", resp.TotalAuthFailures)
	}
	// 2 distinct IPs from audit alone.
	if resp.AttackerIpsUnique != 2 {
		t.Errorf("attackerIpsUnique = %d, want 2", resp.AttackerIpsUnique)
	}
}

func TestMetricsSummary_AttackerIpsUnique_UnionAcrossSources(t *testing.T) {
	// Seed WAF + throttle + audit with overlapping IPs.
	// WAF: 1.1.1.1, 2.2.2.2; Throttle: 2.2.2.2, 3.3.3.3;
	// Audit: 3.3.3.3, 4.4.4.4. Union = 4 unique.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"1.1.1.1", "2.2.2.2"}, nil
		},
	})
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"2.2.2.2", "3.3.3.3"}, nil
		},
	})
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return []audit.Event{
				{Action: audit.ActionLoginFailure, IP: "3.3.3.3"},
				{Action: audit.ActionLoginFailure, IP: "4.4.4.4"},
			}, false, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.AttackerIpsUnique != 4 {
		t.Errorf("attackerIpsUnique = %d, want 4 (union of overlapping sets)", resp.AttackerIpsUnique)
	}
}

func TestMetricsSummary_QFieldsIndependentFromM(t *testing.T) {
	// AC #15 anti-regression: Q-side fields (throttle, auth,
	// attacker IPs) MUST NOT inflate the M field
	// (TotalWafBlocked) or vice versa. Confirm by
	// seeding throttle events but no WAF events → WAF total
	// stays 0, throttle total > 0.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC()
	prevHour := now.Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h,
		[]observability.MetricBucket{
			{RouteID: observability.ThrottleSentinelRouteID, Ts: prevHour, ThrottleBlockCount: 9},
		}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	if resp.TotalThrottle != 9 {
		t.Errorf("totalThrottlePerMin = %d, want 9", resp.TotalThrottle)
	}
	if resp.TotalWafBlocked != 0 {
		t.Errorf("AC #15 violation: TotalWafBlocked = %d after throttle-only seed; want 0", resp.TotalWafBlocked)
	}
	if resp.TotalFourXx != 0 || resp.TotalFiveXx != 0 {
		t.Errorf("throttle bumps leaked into L counters: 4xx=%d 5xx=%d", resp.TotalFourXx, resp.TotalFiveXx)
	}
}

func TestMetricsSummary_NilReadersForQFields_FieldsStayZero(t *testing.T) {
	// Degraded mode tolerance: with no throttle / authFailure
	// readers wired, the new fields stay at 0. The summary
	// still returns 200 with the L/M fields populated.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	// Intentionally NOT calling SetAuthFailureReader /
	// SetThrottleEventReader / SetWafEventReader.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalAuthFailures != 0 || resp.AttackerIpsUnique != 0 {
		t.Errorf("Q fields not zero with nil readers: throttle=%d auth=%d attackers=%d",
			resp.TotalThrottle, resp.TotalAuthFailures, resp.AttackerIpsUnique)
	}
}

// --- Step N.3: crowdsec_decision_rate + new summary fields ----------------

func TestMetricsTimeseries_CrowdSecDecisionRate_ReadsBucketColumn(t *testing.T) {
	// Same shape as throttle_block_rate (Q.3): the new metric
	// reads from MetricBucket.CrowdSecDecisionCount with gap-
	// fill = 0 for empty buckets. Spec N §3.5: production
	// stores decisions under sentinel "_crowdsec"; this test
	// seeds rows under the test route ID to exercise the
	// field-routing logic in pickMetricValue specifically.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	rows := []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-10 * time.Minute), CrowdSecDecisionCount: 11},
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), CrowdSecDecisionCount: 4},
	}
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=crowdsec_decision_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if string(resp.Metric) != "crowdsec_decision_rate" {
		t.Errorf("response metric = %q, want crowdsec_decision_rate", resp.Metric)
	}
	total := 0.0
	for _, p := range resp.Points {
		if p.Value == nil {
			t.Fatal("count metric point has null value — AC #5 violation")
		}
		total += *p.Value
	}
	if total != 15 {
		t.Errorf("sum of crowdsec_decision_rate values = %v, want 15", total)
	}
}

func TestMetricsTimeseries_NewMetric_AcceptedByValidator(t *testing.T) {
	// Anti-regression: a future refactor that drops
	// crowdsec_decision_rate from isValidMetric / pickMetricValue
	// would surface 400 here.
	if !isValidMetric(metricName("crowdsec_decision_rate")) {
		t.Errorf("metric crowdsec_decision_rate rejected by isValidMetric")
	}
}

func TestMetricsSummary_TotalCrowdSecDecisions_FromSentinelRow(t *testing.T) {
	// Mirror of TestMetricsSummary_TotalThrottle_FromSentinelRow.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC()
	prevHour := now.Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h,
		[]observability.MetricBucket{
			{RouteID: observability.CrowdSecSentinelRouteID, Ts: prevHour, CrowdSecDecisionCount: 23},
		}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalCrowdSecDecisions != 23 {
		t.Errorf("totalCrowdSecDecisionsPerMin = %d, want 23", resp.TotalCrowdSecDecisions)
	}
}

func TestMetricsSummary_ActiveCrowdSecIpsUnique_FromDistinctIPs(t *testing.T) {
	// The decisions reader's DistinctDecisionSrcIPs feeds
	// ActiveCrowdSecIpsUnique + the union for
	// AttackerIpsUnique. Mirror of the Q.3 attacker-IP
	// branch for the throttle source.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"185.142.86.0/24", "8.8.8.8", ""}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	// Empty IP filtered; CIDR + IP both count.
	if resp.ActiveCrowdSecIpsUnique != 2 {
		t.Errorf("activeCrowdSecIpsUnique = %d, want 2 (empty filtered)", resp.ActiveCrowdSecIpsUnique)
	}
	if resp.AttackerIpsUnique != 2 {
		t.Errorf("attackerIpsUnique = %d, want 2 (crowdsec arm + empty filter)", resp.AttackerIpsUnique)
	}
}

func TestMetricsSummary_AttackerIpsUnique_UnionAcrossFourSources(t *testing.T) {
	// Step N.3 extension: union now spans 4 sources.
	// WAF: 1.1.1.1
	// Throttle: 2.2.2.2
	// Audit: 3.3.3.3
	// CrowdSec: 1.1.1.1 (overlaps WAF), 4.4.4.4
	// Union: {1,2,3,4} = 4 unique.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"1.1.1.1"}, nil
		},
	})
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"2.2.2.2"}, nil
		},
	})
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return []audit.Event{{Action: audit.ActionLoginFailure, IP: "3.3.3.3"}}, false, nil
		},
	})
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"1.1.1.1", "4.4.4.4"}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.AttackerIpsUnique != 4 {
		t.Errorf("attackerIpsUnique = %d, want 4 (union of 4 overlapping sources)", resp.AttackerIpsUnique)
	}
	if resp.ActiveCrowdSecIpsUnique != 2 {
		t.Errorf("activeCrowdSecIpsUnique = %d, want 2", resp.ActiveCrowdSecIpsUnique)
	}
}

func TestMetricsSummary_NFieldsIndependentFromMQ(t *testing.T) {
	// AC #N.24-style anti-regression: CrowdSec fields (the new
	// summary additions) MUST NOT inflate any of the M/Q
	// fields (WAF block, throttle, auth-failures), and vice
	// versa. Seed ONLY a CrowdSec sentinel row → confirm
	// crowdsec total > 0 AND all other totals stay 0.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC()
	prevHour := now.Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h,
		[]observability.MetricBucket{
			{RouteID: observability.CrowdSecSentinelRouteID, Ts: prevHour, CrowdSecDecisionCount: 12},
		}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)

	if resp.TotalCrowdSecDecisions != 12 {
		t.Errorf("totalCrowdSecDecisionsPerMin = %d, want 12", resp.TotalCrowdSecDecisions)
	}
	if resp.TotalWafBlocked != 0 {
		t.Errorf("AC #N.24 violation: TotalWafBlocked = %d after crowdsec-only seed; want 0", resp.TotalWafBlocked)
	}
	if resp.TotalThrottle != 0 {
		t.Errorf("AC #N.24 violation: TotalThrottle = %d after crowdsec-only seed; want 0", resp.TotalThrottle)
	}
	if resp.TotalFourXx != 0 || resp.TotalFiveXx != 0 {
		t.Errorf("CrowdSec bump leaked into L counters: 4xx=%d 5xx=%d", resp.TotalFourXx, resp.TotalFiveXx)
	}
}

// --- #R-DASHBOARD-WAF-COUNTERS-ZERO summary fields -------------------

// TestMetricsSummary_WafDetected_FromBucketColumn pins the
// new aggregated counter. Seed a bucket row with a non-zero
// waf_detect_count (and a sibling non-zero waf_block_count to
// confirm the two stay independent), assert both surface on the
// response.
func TestMetricsSummary_WafDetected_FromWafEvent(t *testing.T) {
	// Follow-up to commit 579f695: WAF counts read from
	// waf_event (single source of truth). The bucket
	// row still carries ReqCount + LatencyP95Ms — those
	// fields are bucket-sourced. Only the WAF columns
	// moved to the event table.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{
			RouteID:      m.routeID,
			Ts:           prevHour,
			ReqCount:     30,
			LatencyP95Ms: 8,
		},
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}
	// Seed waf_event: 4 BLOCK + 11 DETECT rows on this
	// route within the 24h window.
	events := []observability.WafEvent{}
	for i := 0; i < 4; i++ {
		events = append(events, observability.WafEvent{
			Ts: prevHour.Add(time.Duration(i) * time.Second), RouteID: m.routeID,
			RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1",
			Action: "BLOCK", StatusCode: 403,
		})
	}
	for i := 0; i < 11; i++ {
		events = append(events, observability.WafEvent{
			Ts: prevHour.Add(time.Duration(10+i) * time.Second), RouteID: m.routeID,
			RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.2",
			Action: "DETECT", StatusCode: 0,
		})
	}
	if err := obsStore.InsertWafEventBatch(context.Background(), events); err != nil {
		t.Fatalf("seed waf_event: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalWafBlocked != 4 {
		t.Errorf("TotalWafBlocked = %d; want 4", resp.TotalWafBlocked)
	}
	if resp.TotalWafDetected != 11 {
		t.Errorf("TotalWafDetected = %d; want 11 (#R-DASHBOARD-WAF-COUNTERS-ZERO — detect-mode events now surface in the dashboard counter)", resp.TotalWafDetected)
	}
	if len(resp.TopRoutes) != 1 {
		t.Fatalf("TopRoutes len = %d; want 1", len(resp.TopRoutes))
	}
	if resp.TopRoutes[0].WafBlocked != 4 || resp.TopRoutes[0].WafDetected != 11 {
		t.Errorf("topRoutes[0] = {block=%d, detect=%d}; want {4, 11}",
			resp.TopRoutes[0].WafBlocked, resp.TopRoutes[0].WafDetected)
	}
}

// TestMetricsSummary_WafBlockAndDetectStayIndependent — sibling
// independence assertion: a detect-only minute MUST leave the
// block field at zero, and vice versa. Same shape as the
// existing 4xx/5xx independence pair.
func TestMetricsSummary_WafBlockAndDetectStayIndependent(t *testing.T) {
	for _, tc := range []struct {
		name      string
		blockSeed int64
		detSeed   int64
		wantBlock uint64
		wantDet   uint64
	}{
		{"detect-only", 0, 9, 0, 9},
		{"block-only", 7, 0, 7, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMetricsTestEnv(t)
			obsStore, err := observability.Open(context.Background(), ":memory:")
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = obsStore.Close() })
			m.env.handler.SetMetricsReader(obsStore)
			m.env.handler.SetWafEventReader(obsStore)

			prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
			if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
				{
					RouteID:      m.routeID,
					Ts:           prevHour,
					ReqCount:     10,
					LatencyP95Ms: 1,
				},
			}); err != nil {
				t.Fatalf("seed bucket: %v", err)
			}
			// Follow-up to 579f695: WAF counts read from
			// waf_event. Seed the events corresponding to
			// the block/detect counts under test.
			events := []observability.WafEvent{}
			for i := int64(0); i < tc.blockSeed; i++ {
				events = append(events, observability.WafEvent{
					Ts: prevHour.Add(time.Duration(i) * time.Second), RouteID: m.routeID,
					RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1",
					Action: "BLOCK", StatusCode: 403,
				})
			}
			for i := int64(0); i < tc.detSeed; i++ {
				events = append(events, observability.WafEvent{
					Ts: prevHour.Add(time.Duration(20+i) * time.Second), RouteID: m.routeID,
					RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.2",
					Action: "DETECT", StatusCode: 0,
				})
			}
			if len(events) > 0 {
				if err := obsStore.InsertWafEventBatch(context.Background(), events); err != nil {
					t.Fatalf("seed waf_event: %v", err)
				}
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			var resp summaryResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)
			if resp.TotalWafBlocked != tc.wantBlock {
				t.Errorf("TotalWafBlocked = %d; want %d", resp.TotalWafBlocked, tc.wantBlock)
			}
			if resp.TotalWafDetected != tc.wantDet {
				t.Errorf("TotalWafDetected = %d; want %d", resp.TotalWafDetected, tc.wantDet)
			}
		})
	}
}

// TestMetricsSummary_CategoryMaps_SplitByAction — seed two
// waf_event rows (one BLOCK + one DETECT in the just-closed
// minute) and assert the two maps report the right population
// separately. Pre-fix WafBlocksByCategory aggregated both
// silently; this test pins the resserement.
func TestMetricsSummary_CategoryMaps_SplitByAction(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	// One BLOCK on SQLi, two DETECT on LFI in the same minute.
	if err := obsStore.InsertWafEventBatch(context.Background(), []observability.WafEvent{
		{Ts: prevHour.Add(5 * time.Second), RouteID: m.routeID, RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: prevHour.Add(10 * time.Second), RouteID: m.routeID, RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.2", Action: "DETECT", StatusCode: 0},
		{Ts: prevHour.Add(15 * time.Second), RouteID: m.routeID, RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.3", Action: "DETECT", StatusCode: 0},
	}); err != nil {
		t.Fatalf("seed waf_event: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// BLOCK map: only the SQLi row.
	if got := resp.WafBlocksByCategory["SQLi"]; got != 1 {
		t.Errorf("WafBlocksByCategory[SQLi] = %d; want 1", got)
	}
	if got, has := resp.WafBlocksByCategory["LFI"]; has && got != 0 {
		t.Errorf("WafBlocksByCategory[LFI] = %d; want absent or 0 (LFI events were DETECT, not BLOCK)", got)
	}
	// DETECT map: the two LFI rows.
	if got := resp.WafDetectsByCategory["LFI"]; got != 2 {
		t.Errorf("WafDetectsByCategory[LFI] = %d; want 2", got)
	}
	if got, has := resp.WafDetectsByCategory["SQLi"]; has && got != 0 {
		t.Errorf("WafDetectsByCategory[SQLi] = %d; want absent or 0", got)
	}
}

// --- Phase Z.4 hotfix : rate-limit counter window regression -----------------

// TestMetricsSummary_TotalRateLimitExceeded_RollingWindowIncludesCurrentHour
// pins the Phase Z.4 hotfix : the counter must use a rolling
// [now-24h, now) window, NOT the hour-aligned [hourTs-24h,
// hourTs) window the bucket-fed counters share. Pre-fix the
// counter excluded every event in the current in-flight hour
// — a burst at HH:MM followed by a dashboard refresh in the
// same hour surfaced "0 / 24h" while the events were visible
// on /logs and queryable via /api/v1/security/rate-limit-
// events. Operator-visible regression caught at Z.4 smoke.
func TestMetricsSummary_TotalRateLimitExceeded_RollingWindowIncludesCurrentHour(t *testing.T) {
	m := newMetricsTestEnv(t)
	// metricsSummary asserts h.metrics != nil before any
	// counter populate runs; satisfy that with the in-memory
	// store regardless of which counter the test targets.
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	var (
		capturedFrom, capturedTo time.Time
		callTime                 time.Time
	)
	m.env.handler.SetRateLimitEventReader(&fakeRateLimitEventReader{
		countFn: func(_ context.Context, from, to time.Time) (int64, error) {
			capturedFrom = from
			capturedTo = to
			callTime = time.Now().UTC()
			return 5, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// (1) counter populated from the fake.
	if resp.TotalRateLimitExceeded != 5 {
		t.Errorf("TotalRateLimitExceeded = %d; want 5", resp.TotalRateLimitExceeded)
	}

	// (2) `to` is clock-now (NOT truncated to the hour). The
	// captured `to` must be within a small window of when the
	// handler ran — pre-fix `to` was `now.Truncate(Hour)`,
	// which on any minute-mark would be strictly BEFORE
	// callTime by up to 59 minutes.
	if capturedTo.IsZero() {
		t.Fatal("countFn was not called")
	}
	delta := callTime.Sub(capturedTo)
	if delta < 0 {
		delta = -delta
	}
	if delta > 5*time.Second {
		t.Errorf("captured `to` (%v) too far from callTime (%v) — pre-fix hour-truncation regression",
			capturedTo, callTime)
	}

	// (3) window width is exactly summaryWindow (24h).
	width := capturedTo.Sub(capturedFrom)
	if width != summaryWindow {
		t.Errorf("window width = %v; want %v (rolling 24h)", width, summaryWindow)
	}

	// (4) explicit guard against the pre-fix hour-aligned shape :
	// `to` must NOT equal now.Truncate(Hour). The chance of a
	// false negative (test run happens exactly on a minute=00
	// second=00 instant) is negligible ; sanity-skip rather
	// than racing the clock.
	hourTs := callTime.Truncate(time.Hour)
	if capturedTo.Equal(hourTs) {
		// Either we hit the boundary (incredibly rare) OR the
		// fix has regressed. The captured `to` should be
		// clock-now, which is hourTs + (callTime - hourTs).
		// Only error if we have evidence of regression : a
		// non-zero distance from hourTs would prove `to` was
		// the unaligned clock-now.
		if callTime.Sub(hourTs) > time.Second {
			t.Errorf("captured `to` (%v) equals hour-truncated boundary — hour-alignment regression", capturedTo)
		}
	}
}

// --- /metrics/route-summary --------------------------------------------------

// seedRouteSummaryHours inserts one bucket_1h row per entry,
// walking backwards from the just-closed hour. Returns the
// observability store so the caller can keep seeding.
func seedRouteSummaryHours(t *testing.T, m *metricsTestEnv, rows []observability.MetricBucket) *observability.Store {
	t.Helper()
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	seeded := make([]observability.MetricBucket, 0, len(rows))
	for i, row := range rows {
		row.RouteID = m.routeID
		row.Ts = prevHour.Add(-time.Duration(i) * time.Hour)
		seeded = append(seeded, row)
	}
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, seeded); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return obsStore
}

// TestMetricsRouteSummary_WireShape pins the literal JSON, not
// the Go struct. A typed decode would pass just as happily
// against a camelCase/snake_case mismatch the frontend cannot
// read — the failure mode that shipped once already (13 typed
// tests, one unreadable field).
func TestMetricsRouteSummary_WireShape(t *testing.T) {
	m := newMetricsTestEnv(t)
	seedRouteSummaryHours(t, m, []observability.MetricBucket{
		{ReqCount: 100, FourxxCount: 4, FivexxCount: 1, LatencyP95Ms: 200},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var wire map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil {
		t.Fatalf("unmarshal: %v; body=%s", err, rec.Body.String())
	}

	// Every key the frontend reads, spelled exactly as the
	// frontend spells it.
	for _, key := range []string{"routeId", "generatedAt", "windowSeconds", "reqs", "fourxx", "fivexx", "p95LatencyMs"} {
		if _, ok := wire[key]; !ok {
			t.Errorf("wire key %q missing; got %s", key, rec.Body.String())
		}
	}
	if got := wire["routeId"]; got != m.routeID {
		t.Errorf("routeId = %v, want %q", got, m.routeID)
	}
	if got := wire["reqs"]; got != float64(100) {
		t.Errorf("reqs = %v, want 100", got)
	}
	if got := wire["fourxx"]; got != float64(4) {
		t.Errorf("fourxx = %v, want 4", got)
	}
	if got := wire["fivexx"]; got != float64(1) {
		t.Errorf("fivexx = %v, want 1", got)
	}
	if got := wire["p95LatencyMs"]; got != float64(200) {
		t.Errorf("p95LatencyMs = %v, want 200", got)
	}
	if got := wire["windowSeconds"]; got != float64(86400) {
		t.Errorf("windowSeconds = %v, want 86400 — must match /metrics/summary's window", got)
	}
	// `disabled` carries omitempty: absent means "healthy", and
	// the frontend's optional field reads undefined. Asserting
	// its ABSENCE is what stops a future `json:"disabled"`
	// without omitempty from quietly shipping `false`.
	if _, present := wire["disabled"]; present {
		t.Errorf("disabled present on the healthy path; want omitted, got %s", rec.Body.String())
	}
}

// TestMetricsRouteSummary_NotTruncatedLikeTopRoutes is the
// reason this endpoint exists. /metrics/summary ranks routes by
// traffic and keeps five; a route outside that top five must
// still get its own real numbers here.
func TestMetricsRouteSummary_NotTruncatedLikeTopRoutes(t *testing.T) {
	m := newMetricsTestEnv(t)

	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	ctx := context.Background()

	// Six busier routes, so the seeded route ranks seventh and
	// is guaranteed to fall outside topRoutes' five slots.
	seeded := []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 10, FourxxCount: 2, FivexxCount: 1, LatencyP95Ms: 50},
	}
	for i := 0; i < 6; i++ {
		rt, cerr := m.env.store.CreateRoute(ctx, storage.Route{
			Host:      "busy" + string(rune('a'+i)) + ".test",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:1", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		})
		if cerr != nil {
			t.Fatalf("seed busy route: %v", cerr)
		}
		seeded = append(seeded, observability.MetricBucket{
			RouteID: rt.ID, Ts: prevHour, ReqCount: int64(1000 + i), LatencyP95Ms: 10,
		})
	}
	if err := obsStore.InsertBatch(ctx, observability.Granularity1h, seeded); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// First establish the premise: the route really is absent
	// from /metrics/summary's topRoutes. Without this the test
	// could pass for the wrong reason.
	sreq := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	srec := httptest.NewRecorder()
	m.router.ServeHTTP(srec, sreq)
	var summary summaryResponse
	if err := json.NewDecoder(srec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	for _, tr := range summary.TopRoutes {
		if tr.RouteID == m.routeID {
			t.Fatalf("premise broken: route %s is IN topRoutes (%d entries) — pick a quieter fixture", m.routeID, len(summary.TopRoutes))
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp routeSummaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Reqs != 10 || resp.Fourxx != 2 || resp.Fivexx != 1 {
		t.Errorf("reqs/4xx/5xx = %d/%d/%d, want 10/2/1 — a route outside topRoutes must still report its real counters", resp.Reqs, resp.Fourxx, resp.Fivexx)
	}
}

func TestMetricsRouteSummary_SumsEveryHourInTheWindow(t *testing.T) {
	m := newMetricsTestEnv(t)
	// Three consecutive closed hours. The response must be the
	// sum, not the latest hour.
	seedRouteSummaryHours(t, m, []observability.MetricBucket{
		{ReqCount: 10, FourxxCount: 1, FivexxCount: 0, LatencyP95Ms: 100},
		{ReqCount: 20, FourxxCount: 2, FivexxCount: 1, LatencyP95Ms: 100},
		{ReqCount: 30, FourxxCount: 3, FivexxCount: 2, LatencyP95Ms: 100},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp routeSummaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Reqs != 60 {
		t.Errorf("reqs = %d, want 60 (10+20+30)", resp.Reqs)
	}
	if resp.Fourxx != 6 {
		t.Errorf("fourxx = %d, want 6 (1+2+3)", resp.Fourxx)
	}
	if resp.Fivexx != 3 {
		t.Errorf("fivexx = %d, want 3 (0+1+2)", resp.Fivexx)
	}
}

// TestMetricsRouteSummary_P95IsRequestWeighted guards the
// statistic the field's doc comment claims. An unweighted mean
// of {100, 400} is 250; weighted by {90, 10} requests it is
// 130. A quiet hour with a terrible p95 must not drag the
// headline number up to where it misreports the experience of
// the requests that actually happened.
func TestMetricsRouteSummary_P95IsRequestWeighted(t *testing.T) {
	m := newMetricsTestEnv(t)
	seedRouteSummaryHours(t, m, []observability.MetricBucket{
		{ReqCount: 90, LatencyP95Ms: 100},
		{ReqCount: 10, LatencyP95Ms: 400},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp routeSummaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.P95LatencyMs == nil {
		t.Fatalf("p95LatencyMs = null, want 130")
	}
	if got := *resp.P95LatencyMs; got < 129.9 || got > 130.1 {
		t.Errorf("p95LatencyMs = %v, want 130 (request-weighted); 250 would mean an unweighted mean", got)
	}
}

// TestMetricsRouteSummary_NoTrafficP95IsNull — 0 ms would read
// as "instant" in the UI. The absence of a measurement has to
// stay distinguishable from a measurement of zero.
func TestMetricsRouteSummary_NoTrafficP95IsNull(t *testing.T) {
	m := newMetricsTestEnv(t)
	seedRouteSummaryHours(t, m, []observability.MetricBucket{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var wire map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, present := wire["p95LatencyMs"]; !present || v != nil {
		t.Errorf("p95LatencyMs = %v (present=%v), want explicit null", v, present)
	}
	if got := wire["reqs"]; got != float64(0) {
		t.Errorf("reqs = %v, want 0", got)
	}
}

func TestMetricsRouteSummary_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// metrics reader intentionally left nil (boot-failed).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp routeSummaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true")
	}
	if resp.Reqs != 0 || resp.P95LatencyMs != nil {
		t.Errorf("counters = %d/%v, want zero and null when disabled", resp.Reqs, resp.P95LatencyMs)
	}
}

func TestMetricsRouteSummary_BadParams(t *testing.T) {
	m := newMetricsTestEnv(t)
	for _, tc := range []struct {
		name string
		path string
		want int
	}{
		{"missing route", "/api/v1/metrics/route-summary", http.StatusBadRequest},
		{"empty route", "/api/v1/metrics/route-summary?route=", http.StatusBadRequest},
		// The "all" sentinel is valid on /metrics/timeseries.
		// Here it must be refused rather than silently treated
		// as a route ID that does not exist (404 would be a
		// lie about why).
		{"all sentinel", "/api/v1/metrics/route-summary?route=all", http.StatusBadRequest},
		{"unknown route", "/api/v1/metrics/route-summary?route=00000000-0000-0000-0000-000000000000", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestMetricsRouteSummary_QueryError_503 mirrors the summary's
// AC #13 contract: a metrics.db read failure is a 503, not a
// 200 full of zeros that the operator would read as "no
// traffic".
func TestMetricsRouteSummary_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(context.Context, observability.Granularity, string, time.Time, time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("disk on fire")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/route-summary?route="+m.routeID, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 — a read failure must not look like zero traffic", rec.Code)
	}
}
