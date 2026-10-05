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

// Schema v15 — persisted latency distributions. Tasks T7 and T8, and
// gate G7 of the 2026-10-05 latency-truth design.
//
// The distinction every test here circles is the same one: a row with
// NO recorded distribution and a row whose distribution contains
// nothing are different facts. Collapsing them is how an unmeasured
// route came to look like an idle one.

package observability

import (
	"context"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/histogram"
)

func openMem(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestBucket_HistogramRoundTripsThroughStorage — the distribution must
// survive the column, or every quantile read back is fiction.
func TestBucket_HistogramRoundTripsThroughStorage(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)

	total := histogram.Of([]float64{2, 2, 2, 40, 900, 5000})
	ttfb := histogram.Of([]float64{1, 1, 1, 3, 8, 12})
	ts := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{{
		RouteID:       "r-1",
		Ts:            ts,
		ReqCount:      6,
		TotalHist:     &total,
		TTFBHist:      &ttfb,
		BytesOut:      2_899_675,
		HijackedCount: 2,
	}}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	rows, err := s.Query(ctx, Granularity1m, "r-1", ts, ts.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	got := rows[0]
	if got.TotalHist == nil {
		t.Fatal("TotalHist came back nil after being written")
	}
	if *got.TotalHist != total {
		t.Errorf("TotalHist changed in storage:\n wrote %v\n read  %v", total, *got.TotalHist)
	}
	if got.TTFBHist == nil || *got.TTFBHist != ttfb {
		t.Errorf("TTFBHist changed in storage: %v", got.TTFBHist)
	}
	if got.BytesOut != 2_899_675 {
		t.Errorf("BytesOut = %d, want 2899675", got.BytesOut)
	}
	if got.HijackedCount != 2 {
		t.Errorf("HijackedCount = %d, want 2", got.HijackedCount)
	}
	// And the quantile a reader would compute must match.
	wantV, wantN := histogram.Quantile(total, 0.95)
	gotV, gotN := histogram.Quantile(*got.TotalHist, 0.95)
	if gotV != wantV || gotN != wantN {
		t.Errorf("p95 after the round trip = (%v,%d), want (%v,%d)", gotV, gotN, wantV, wantN)
	}
}

// TestBucket_NoHistogramStaysNil — a row written without a
// distribution must read back as nil, not as a histogram of zero
// observations. This is the pre-v15 row's shape, and the whole reason
// MetricBucket uses pointers.
func TestBucket_NoHistogramStaysNil(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	ts := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{{
		RouteID: "r-legacy", Ts: ts, ReqCount: 42, LatencyP95Ms: 16,
	}}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	rows, err := s.Query(ctx, Granularity1m, "r-legacy", ts, ts.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].TotalHist != nil {
		t.Errorf("TotalHist = %v, want nil; an absent distribution must not read as a distribution of nothing", *rows[0].TotalHist)
	}
	if rows[0].TTFBHist != nil {
		t.Errorf("TTFBHist = %v, want nil", *rows[0].TTFBHist)
	}
	// The legacy scalar is untouched, so existing readers survive.
	if rows[0].ReqCount != 42 || rows[0].LatencyP95Ms != 16 {
		t.Errorf("legacy columns changed: req=%d p95=%d", rows[0].ReqCount, rows[0].LatencyP95Ms)
	}
}

// TestAggregateHistogram_SumsAcrossRows is the read path T9 builds on,
// and it is the only valid way to combine distributions.
func TestAggregateHistogram_SumsAcrossRows(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	// Three minutes, each with its own distribution.
	minutes := [][]float64{
		{2, 2, 2},
		{40, 40},
		{5000},
	}
	var want histogram.BucketCounts
	rows := make([]MetricBucket, 0, len(minutes))
	for i, ms := range minutes {
		h := histogram.Of(ms)
		want.Add(h)
		rows = append(rows, MetricBucket{
			RouteID: "r-1", Ts: base.Add(time.Duration(i) * time.Minute),
			ReqCount: int64(len(ms)), TotalHist: &h, BytesOut: int64(100 * (i + 1)),
		})
	}
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	agg, err := s.AggregateHistogram(ctx, Granularity1m, "r-1", base, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("AggregateHistogram: %v", err)
	}
	if agg.Total != want {
		t.Errorf("summed histogram:\n got  %v\n want %v", agg.Total, want)
	}
	if agg.Rows != 3 || agg.RowsWithHistogram != 3 {
		t.Errorf("rows=%d withHist=%d, want 3/3", agg.Rows, agg.RowsWithHistogram)
	}
	if agg.BytesOut != 600 {
		t.Errorf("BytesOut = %d, want 600", agg.BytesOut)
	}
	// The p95 over the union: 6 observations, rank ceil(0.95*6) = 6,
	// so the 5000 ms one — which no per-minute percentile could have
	// told us, because the minute holding it had a p95 of 5000 and the
	// other two did not.
	p95, n := histogram.Quantile(agg.Total, 0.95)
	if n != 6 {
		t.Fatalf("count = %d, want 6", n)
	}
	if p95 < 4096 {
		t.Errorf("p95 = %v ms, want the slow observation to be reachable", p95)
	}
}

// TestAggregateHistogram_ReportsPartialCoverage — a window straddling
// the v15 upgrade has rows with no distribution. The caller must be
// able to tell its answer is partial rather than being handed a
// quantile over whatever happened to survive.
func TestAggregateHistogram_ReportsPartialCoverage(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	base := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	h := histogram.Of([]float64{7, 7})
	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{
		{RouteID: "r-1", Ts: base, ReqCount: 10, LatencyP95Ms: 16}, // legacy, no histogram
		{RouteID: "r-1", Ts: base.Add(time.Minute), ReqCount: 2, TotalHist: &h},
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	agg, err := s.AggregateHistogram(ctx, Granularity1m, "r-1", base, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("AggregateHistogram: %v", err)
	}
	if agg.Rows != 2 {
		t.Errorf("Rows = %d, want 2", agg.Rows)
	}
	if agg.RowsWithHistogram != 1 {
		t.Errorf("RowsWithHistogram = %d, want 1 — the caller cannot flag a partial answer it cannot see", agg.RowsWithHistogram)
	}
	// ReqCount counts every row; the histogram only covers one of
	// them. A reader comparing the two knows the quantile describes a
	// fraction of the traffic.
	if agg.ReqCount != 12 {
		t.Errorf("ReqCount = %d, want 12", agg.ReqCount)
	}
	if got := agg.Total.Total(); got != 2 {
		t.Errorf("histogram total = %d, want 2 — only the v15 row contributed", got)
	}
}

// TestAggregateHistogram_AllRoutesWhenRouteIDEmpty — the system-wide
// view sums every route's distribution, which is exact where the old
// SQL weighted-average of per-route percentiles was not.
func TestAggregateHistogram_AllRoutesWhenRouteIDEmpty(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	ts := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	a := histogram.Of([]float64{2, 2})
	b := histogram.Of([]float64{900})
	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{
		{RouteID: "r-a", Ts: ts, ReqCount: 2, TotalHist: &a},
		{RouteID: "r-b", Ts: ts, ReqCount: 1, TotalHist: &b},
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	agg, err := s.AggregateHistogram(ctx, Granularity1m, "", ts, ts.Add(time.Minute))
	if err != nil {
		t.Fatalf("AggregateHistogram: %v", err)
	}
	if agg.Total.Total() != 3 {
		t.Errorf("total observations = %d, want 3 across both routes", agg.Total.Total())
	}

	scoped, err := s.AggregateHistogram(ctx, Granularity1m, "r-a", ts, ts.Add(time.Minute))
	if err != nil {
		t.Fatalf("AggregateHistogram(r-a): %v", err)
	}
	if scoped.Total.Total() != 2 {
		t.Errorf("r-a observations = %d, want 2 — the route filter leaked", scoped.Total.Total())
	}
}

// TestRollupHour_SumsDistributionsExactly — the hour's p95 is now
// computed over the hour's real population, not derived from sixty
// per-minute percentiles.
//
// The fixture is built so the two answers differ sharply: 59 minutes of
// fast traffic and one minute holding a single slow request. Averaging
// the per-minute p95s weights that one minute as heavily as its request
// count allows; summing the distributions puts it where it belongs, in
// the far tail.
func TestRollupHour_SumsDistributionsExactly(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	hour := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	rows := make([]MetricBucket, 0, 60)
	var expect histogram.BucketCounts
	for i := 0; i < 59; i++ {
		h := histogram.Of([]float64{2, 2, 2, 2, 2, 2, 2, 2, 2, 2})
		expect.Add(h)
		rows = append(rows, MetricBucket{
			RouteID: "r-1", Ts: hour.Add(time.Duration(i) * time.Minute),
			ReqCount: 10, TotalHist: &h, LatencyP95Ms: p95FromBuckets(h),
		})
	}
	slow := histogram.Of([]float64{9000})
	expect.Add(slow)
	rows = append(rows, MetricBucket{
		RouteID: "r-1", Ts: hour.Add(59 * time.Minute),
		ReqCount: 1, TotalHist: &slow, LatencyP95Ms: p95FromBuckets(slow),
	})
	if err := s.InsertBatch(ctx, Granularity1m, rows); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	r := &RetentionRunner{store: s}
	if err := r.rollupHour(ctx, hour); err != nil {
		t.Fatalf("rollupHour: %v", err)
	}

	hourly, err := s.Query(ctx, Granularity1h, "r-1", hour, hour.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query 1h: %v", err)
	}
	if len(hourly) != 1 {
		t.Fatalf("hourly rows = %d, want 1", len(hourly))
	}
	if hourly[0].TotalHist == nil {
		t.Fatal("the hourly row carries no distribution")
	}
	if *hourly[0].TotalHist != expect {
		t.Errorf("hourly histogram is not the exact sum of its minutes:\n got  %v\n want %v", *hourly[0].TotalHist, expect)
	}
	if hourly[0].ReqCount != 591 {
		t.Errorf("ReqCount = %d, want 591", hourly[0].ReqCount)
	}
	// 590 of 591 requests took 2 ms, so the honest p95 is in the fast
	// region. A single 9 s request must not set the hour's p95.
	if hourly[0].LatencyP95Ms > 10 {
		t.Errorf("hourly p95 = %d ms; 590/591 requests took 2 ms, so this is the old maximum leaking back", hourly[0].LatencyP95Ms)
	}
	// And the slow request stays reachable at a high quantile.
	if p999, _ := histogram.Quantile(*hourly[0].TotalHist, 0.999); p999 < 4096 {
		t.Errorf("p99.9 = %v ms, want the 9 s request to still be findable", p999)
	}
}

// TestRollupHour_IsIdempotent is gate G7, and it is a real risk only
// now that the operation is addition.
//
// When the hour's value was a max, running the rollup twice was
// harmless. Summing is not self-idempotent, so correctness rests on
// InsertBatch replacing the row rather than adding to it — which is
// exactly the kind of invariant that holds until someone "optimises"
// the upsert.
func TestRollupHour_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	hour := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	h := histogram.Of([]float64{3, 3, 3, 700})
	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{{
		RouteID: "r-1", Ts: hour, ReqCount: 4, TotalHist: &h, BytesOut: 5000, HijackedCount: 1,
	}}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	r := &RetentionRunner{store: s}
	for i := 0; i < 3; i++ {
		if err := r.rollupHour(ctx, hour); err != nil {
			t.Fatalf("rollupHour run %d: %v", i+1, err)
		}
	}

	rows, err := s.Query(ctx, Granularity1h, "r-1", hour, hour.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("hourly rows = %d, want 1", len(rows))
	}
	if rows[0].ReqCount != 4 {
		t.Errorf("ReqCount = %d after three rollups, want 4", rows[0].ReqCount)
	}
	if rows[0].TotalHist == nil || *rows[0].TotalHist != h {
		t.Errorf("histogram = %v after three rollups, want %v — the rollup is accumulating onto itself", rows[0].TotalHist, h)
	}
	if rows[0].BytesOut != 5000 {
		t.Errorf("BytesOut = %d after three rollups, want 5000", rows[0].BytesOut)
	}
	if rows[0].HijackedCount != 1 {
		t.Errorf("HijackedCount = %d after three rollups, want 1", rows[0].HijackedCount)
	}
}

// TestRollupHour_LegacyMinutesKeepTheOldFallback — hours whose minutes
// predate v15 have no distribution to sum, and their rows cannot be
// improved: the data was discarded a second after it was produced.
// They must still roll up rather than reporting a hole.
func TestRollupHour_LegacyMinutesKeepTheOldFallback(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	hour := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

	if err := s.InsertBatch(ctx, Granularity1m, []MetricBucket{
		{RouteID: "r-old", Ts: hour, ReqCount: 100, LatencyP95Ms: 20},
		{RouteID: "r-old", Ts: hour.Add(time.Minute), ReqCount: 100, LatencyP95Ms: 40},
	}); err != nil {
		t.Fatalf("InsertBatch: %v", err)
	}

	r := &RetentionRunner{store: s}
	if err := r.rollupHour(ctx, hour); err != nil {
		t.Fatalf("rollupHour: %v", err)
	}
	rows, err := s.Query(ctx, Granularity1h, "r-old", hour, hour.Add(time.Hour))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].TotalHist != nil {
		t.Errorf("TotalHist = %v, want nil; no minute carried one so none can be invented", *rows[0].TotalHist)
	}
	// The legacy weighted average: (20*100 + 40*100) / 200 = 30.
	if rows[0].LatencyP95Ms != 30 {
		t.Errorf("LatencyP95Ms = %d, want 30 (the pre-v15 weighted fallback)", rows[0].LatencyP95Ms)
	}
}
