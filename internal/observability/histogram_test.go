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

package observability

import (
	"math"
	"math/rand"
	"sort"
	"sync"
	"testing"
)

func TestHistogram_P95Empty(t *testing.T) {
	var h LatencyHistogram
	if got := h.P95(); got != 0 {
		t.Fatalf("empty histogram P95 = %v, want 0", got)
	}
}

func TestHistogram_P95Correct(t *testing.T) {
	// Known distribution: 95 observations at ~10 ms, 5
	// observations at ~1000 ms. p95 must land in the 10 ms
	// region, NOT in the 1000 ms tail. Bucket layout is
	// powers-of-two from 0.5 ms, so 10 ms is in bucket 4
	// (covers [8, 16) ms, upper edge 16) and 1000 ms is in
	// bucket 10 (covers [512, 1024) ms, upper edge 1024).
	var h LatencyHistogram
	for i := 0; i < 95; i++ {
		h.Observe(10)
	}
	for i := 0; i < 5; i++ {
		h.Observe(1000)
	}
	got := h.P95()
	// p95 of this distribution should fall at the upper edge
	// of bucket 4 (16 ms) — the 95th observation lands in the
	// fast region, the slow tail is the remaining 5 %.
	if got > 32 {
		t.Fatalf("P95 = %v ms, expected ~16 ms (within fast bucket region)", got)
	}
	if got <= 0 {
		t.Fatalf("P95 = %v ms, expected positive value", got)
	}
}

func TestHistogram_P95TailDominant(t *testing.T) {
	// Inverse distribution: most observations slow, p95 must
	// land in the slow tail. Anti-regression vs "p95 always
	// returns a fast value" bug.
	var h LatencyHistogram
	for i := 0; i < 90; i++ {
		h.Observe(2000)
	}
	for i := 0; i < 10; i++ {
		h.Observe(10)
	}
	got := h.P95()
	if got < 1024 {
		t.Fatalf("P95 = %v ms, expected >= 1024 ms (slow tail)", got)
	}
}

func TestHistogram_ObserveSaturatesPastTop(t *testing.T) {
	// A 5-minute-long request must not panic and must land in
	// the last bucket — never a negative index or out-of-range.
	var h LatencyHistogram
	h.Observe(5 * 60 * 1000) // 300_000 ms
	snap, total := h.Snapshot()
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	if snap[histogramBuckets-1] != 1 {
		t.Fatalf("saturating obs should land in bucket %d, got counts=%v",
			histogramBuckets-1, snap)
	}
}

func TestHistogram_ObserveBelowBaseClampsBucket0(t *testing.T) {
	// A 0.1 ms observation (or a 0 from a broken clock) must
	// land in bucket 0, not produce a negative index.
	var h LatencyHistogram
	h.Observe(0.1)
	h.Observe(0)
	snap, total := h.Snapshot()
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if snap[0] != 2 {
		t.Fatalf("sub-base obs should land in bucket 0, got counts[0]=%d", snap[0])
	}
}

func TestHistogram_ResetClearsAll(t *testing.T) {
	var h LatencyHistogram
	for i := 0; i < 100; i++ {
		h.Observe(50)
	}
	h.Reset()
	_, total := h.Snapshot()
	if total != 0 {
		t.Fatalf("after Reset total = %d, want 0", total)
	}
	if got := h.P95(); got != 0 {
		t.Fatalf("after Reset P95 = %v, want 0", got)
	}
}

func TestHistogram_ConcurrentObserve(t *testing.T) {
	// Anti-regression for atomic correctness on the hot path
	// (AC #13: hot path is incrementing only — must be safe
	// under arbitrary concurrency).
	var h LatencyHistogram
	const workers = 16
	const perWorker = 1000
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				h.Observe(20)
			}
		}()
	}
	wg.Wait()
	_, total := h.Snapshot()
	if total != workers*perWorker {
		t.Fatalf("total = %d, want %d", total, workers*perWorker)
	}
}

// ---------------------------------------------------------------------------
// Read-time quantiles — spec 2026-10-05-latency-truth
// ---------------------------------------------------------------------------

// TestQuantile_SummingBucketsEqualsHistogrammingTheUnion is gate G1,
// and it is the identity the whole design rests on.
//
// The superseded chain reduced each 1-second tick to a scalar p95 and
// then took the MAX of those across the minute. Neither max nor mean is
// a valid operation on a quantile: max(p95(a), p95(b)) and
// mean(p95(a), p95(b)) are both unequal to p95(a ∪ b) in general.
// Summing bucket counts, by contrast, is EXACTLY equal to histogramming
// the union — so every aggregation step (tick → minute → hour → day →
// API) becomes lossless.
//
// Asserted at p50, p95 and p99 over pseudo-random sets, with equality
// exact rather than approximate: these are the same float operations on
// the same integers, so any difference would mean the merge is not
// associative and the design is unsound.
func TestQuantile_SummingBucketsEqualsHistogrammingTheUnion(t *testing.T) {
	rnd := rand.New(rand.NewSource(0x5eed))
	for trial := 0; trial < 200; trial++ {
		na, nb := rnd.Intn(400), rnd.Intn(400)
		a := make([]float64, na)
		b := make([]float64, nb)
		for i := range a {
			a[i] = rnd.Float64() * 70000 // spans past the top bucket
		}
		for i := range b {
			b[i] = rnd.Float64() * 70000
		}
		if na+nb == 0 {
			continue
		}

		summed := HistogramOf(a)
		summed.Add(HistogramOf(b))
		union := HistogramOf(append(append([]float64{}, a...), b...))

		if summed != union {
			t.Fatalf("trial %d: summed buckets != union buckets\n summed=%v\n union =%v", trial, summed, union)
		}
		for _, q := range []float64{0.5, 0.95, 0.99} {
			gotV, gotN := Quantile(summed, q)
			wantV, wantN := Quantile(union, q)
			if gotV != wantV || gotN != wantN {
				t.Fatalf("trial %d q=%v: summed=(%v,%d) union=(%v,%d) — the merge is not exact",
					trial, q, gotV, gotN, wantV, wantN)
			}
		}
	}
}

// TestQuantile_AddIsCommutativeAndAssociative — rollup idempotence
// (G7) and the hour/day rollups both depend on it, and a future
// refactor that made Add order-sensitive would break them silently.
func TestQuantile_AddIsCommutativeAndAssociative(t *testing.T) {
	a := HistogramOf([]float64{1, 2, 3})
	b := HistogramOf([]float64{10, 20})
	c := HistogramOf([]float64{1000})

	ab := a
	ab.Add(b)
	ba := b
	ba.Add(a)
	if ab != ba {
		t.Errorf("Add is not commutative: %v vs %v", ab, ba)
	}

	left := a
	left.Add(b)
	left.Add(c)
	bc := b
	bc.Add(c)
	right := a
	right.Add(bc)
	if left != right {
		t.Errorf("Add is not associative: %v vs %v", left, right)
	}
}

// TestQuantile_InterpolationAccuracy is gate G9.
//
// It asserts the bound that is provable — the result sits inside the
// resolved bucket, so the error cannot exceed that bucket's width — and
// RECORDS the observed error rather than asserting a guessed figure.
// The first draft of the design claimed "roughly ±20%" from nowhere, in
// a document whose subject is unasserted numbers; the number below is
// whatever this test measures, and it is here so a future reader can
// judge whether finer buckets are worth a migration.
//
// Observed on 2026-10-05, Go 1.27.1, seed 0x9e3779b9, n=20000:
//
//	log-normal  exact 146.2 ms   interpolated 164.8 ms    12.7%
//	uniform     exact 1903.4 ms  interpolated 1943.5 ms    2.1%
//	bimodal     exact 30660.2 ms interpolated 27444.1 ms  10.5%
//
// The two double-digit figures are the factor-2 bucket width showing
// through, not a flaw in the interpolation: both exact values sit near
// a bucket boundary. §8 of the design is the lever if that is ever too
// coarse — finer buckets, not different arithmetic.
//
// Bimodal is the shape a long-polling route actually has (a mass of
// fast responses plus a mass held open for tens of seconds), which is
// why it is covered: the design must not be accurate only on the
// pretty distribution.
func TestQuantile_InterpolationAccuracy(t *testing.T) {
	rnd := rand.New(rand.NewSource(0x9e3779b9))
	const n = 20000

	gen := map[string]func() float64{
		"log-normal": func() float64 { return math.Exp(rnd.NormFloat64()*1.2 + 3) },
		"uniform":    func() float64 { return rnd.Float64() * 2000 },
		"bimodal": func() float64 {
			if rnd.Float64() < 0.85 {
				return 5 + rnd.Float64()*20
			}
			return 28000 + rnd.Float64()*4000
		},
	}

	for name, next := range gen {
		t.Run(name, func(t *testing.T) {
			raw := make([]float64, n)
			for i := range raw {
				raw[i] = next()
			}
			exact := exactQuantile(raw, 0.95)
			got, count := Quantile(HistogramOf(raw), 0.95)
			if count != n {
				t.Fatalf("count = %d, want %d", count, n)
			}

			// The provable bound: the answer must lie inside the
			// bucket the exact value falls in. Anything outside means
			// the bucket search or the interpolation is wrong, not
			// merely coarse.
			idx := bucketIndex(exact)
			lo, hi := bucketLowerEdgeMs(idx), bucketUpperEdgeMs(idx)
			if got < lo || got > hi {
				t.Errorf("interpolated p95 %.1f ms is outside bucket %d [%.1f, %.1f) containing the exact p95 %.1f ms",
					got, idx, lo, hi, exact)
			}
			relErr := math.Abs(got-exact) / exact * 100
			t.Logf("exact p95 %.1f ms, interpolated %.1f ms, relative error %.1f%%", exact, got, relErr)
		})
	}
}

// TestQuantile_EdgeReportingWouldOverstate pins D5 against a
// regression to the superseded behaviour.
//
// drainP95 returned the resolved bucket's UPPER EDGE. For a single
// 5000 ms request that edge is 8192 ms — a 64% overstatement, and
// precisely how the operator came to read a five-second image download
// as eight seconds.
func TestQuantile_EdgeReportingWouldOverstate(t *testing.T) {
	got, n := Quantile(HistogramOf([]float64{5000}), 0.95)
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	edge := bucketUpperEdgeMs(bucketIndex(5000))
	if edge != 8192 {
		t.Fatalf("bucket edge = %v, want 8192 (fixture assumption broken)", edge)
	}
	if got >= edge {
		t.Errorf("Quantile returned %v, the bucket edge or worse — interpolation is not happening", got)
	}
	// And it must still be inside the bucket, not under-corrected.
	if got < bucketLowerEdgeMs(bucketIndex(5000)) {
		t.Errorf("Quantile returned %v, below the bucket's lower edge", got)
	}
}

// TestQuantile_EmptyIsZeroCount — the caller must be able to tell "no
// observations" from "measured 0 ms". 0 ms would read as instant.
func TestQuantile_EmptyIsZeroCount(t *testing.T) {
	v, n := Quantile(BucketCounts{}, 0.95)
	if n != 0 {
		t.Errorf("count = %d, want 0", n)
	}
	if v != 0 {
		t.Errorf("value = %v, want 0 alongside the zero count", v)
	}
}

// TestQuantile_Bucket0StartsAtZero — bucketIndex sends everything
// under 1 ms to bucket 0, so interpolating that bucket from 0.5 ms
// would claim a floor no sub-millisecond response can go below.
func TestQuantile_Bucket0StartsAtZero(t *testing.T) {
	if lo := bucketLowerEdgeMs(0); lo != 0 {
		t.Errorf("bucket 0 lower edge = %v, want 0", lo)
	}
	// A pile of 0.1 ms responses must not report ~1 ms at p50.
	got, _ := Quantile(HistogramOf([]float64{0.1, 0.1, 0.1, 0.1}), 0.5)
	if got >= 1 {
		t.Errorf("p50 of four 0.1 ms responses = %v ms, want below 1", got)
	}
}

// TestQuantile_TopBucketSaturates — above 65536 ms there is nothing to
// interpolate toward, so the edge is the honest answer and means "at
// least".
func TestQuantile_TopBucketSaturates(t *testing.T) {
	got, n := Quantile(HistogramOf([]float64{200000}), 0.95)
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	if want := bucketUpperEdgeMs(HistogramBuckets - 1); got != want {
		t.Errorf("p95 = %v, want the saturating edge %v", got, want)
	}
}

// TestQuantile_LowSampleStillReportsItsCount — D11 lives in the API,
// but it can only be honoured if the count travels with the value.
func TestQuantile_LowSampleStillReportsItsCount(t *testing.T) {
	_, n := Quantile(HistogramOf([]float64{3, 4, 900}), 0.95)
	if n != 3 {
		t.Errorf("count = %d, want 3 — the API cannot suppress a weak quantile it cannot size", n)
	}
}

// TestQuantile_SingleSampleLandsMidBucket is why this package deviates
// from Prometheus's interpolation.
//
// Prometheus places the rank-th observation at (rank - cumBefore) /
// count of the way through the bucket, so the only observation in a
// bucket lands on the bucket's UPPER EDGE. On a route serving a handful
// of requests a minute — Arenet's normal case, and the one that
// produced "p95 35658 ms" — almost every bucket holds one or two
// samples, so that convention reports the top of the bucket almost
// always.
//
// Centring the observation in its share gives the midpoint, which is
// the expected position of a sample known only to be somewhere in the
// bucket.
func TestQuantile_SingleSampleLandsMidBucket(t *testing.T) {
	// 5000 ms lands in the bucket [4096, 8192).
	got, n := Quantile(HistogramOf([]float64{5000}), 0.95)
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	const lo, hi = 4096.0, 8192.0
	want := (lo + hi) / 2
	if got != want {
		t.Errorf("p95 of one 5000 ms request = %v, want the bucket midpoint %v", got, want)
	}
	// And the point of it all: closer to the truth than the edge was.
	if math.Abs(got-5000) >= math.Abs(hi-5000) {
		t.Errorf("midpoint %v is no closer to the real 5000 ms than the edge %v", got, hi)
	}
}

// TestQuantile_MonotoneInQ — a higher quantile can never report a
// lower latency. Cheap to break with an off-by-one in the rank
// arithmetic, and nonsensical to an operator reading p50 above p95.
func TestQuantile_MonotoneInQ(t *testing.T) {
	h := HistogramOf([]float64{1, 2, 3, 7, 9, 40, 70, 300, 900, 5000, 40000})
	var prev float64
	for _, q := range []float64{0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0} {
		got, _ := Quantile(h, q)
		if got < prev {
			t.Errorf("q=%v gave %v, below the previous quantile %v", q, got, prev)
		}
		prev = got
	}
}

// exactQuantile computes the quantile from the raw sample, using the
// same nearest-rank convention as Quantile so the two are comparable.
func exactQuantile(xs []float64, q float64) float64 {
	s := append([]float64{}, xs...)
	sort.Float64s(s)
	rank := int(math.Ceil(q * float64(len(s))))
	if rank < 1 {
		rank = 1
	}
	return s[rank-1]
}
