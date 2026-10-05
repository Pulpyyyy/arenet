// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package histogram

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"sort"
	"testing"
)

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

		summed := Of(a)
		summed.Add(Of(b))
		union := Of(append(append([]float64{}, a...), b...))

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
	a := Of([]float64{1, 2, 3})
	b := Of([]float64{10, 20})
	c := Of([]float64{1000})

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
			got, count := Quantile(Of(raw), 0.95)
			if count != n {
				t.Fatalf("count = %d, want %d", count, n)
			}

			// The provable bound: the answer must lie inside the
			// bucket the exact value falls in. Anything outside means
			// the bucket search or the interpolation is wrong, not
			// merely coarse.
			idx := IndexOf(exact)
			lo, hi := LowerEdgeMs(idx), UpperEdgeMs(idx)
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
	got, n := Quantile(Of([]float64{5000}), 0.95)
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	edge := UpperEdgeMs(IndexOf(5000))
	if edge != 8192 {
		t.Fatalf("bucket edge = %v, want 8192 (fixture assumption broken)", edge)
	}
	if got >= edge {
		t.Errorf("Quantile returned %v, the bucket edge or worse — interpolation is not happening", got)
	}
	// And it must still be inside the bucket, not under-corrected.
	if got < LowerEdgeMs(IndexOf(5000)) {
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

// TestQuantile_Bucket0StartsAtZero — IndexOf sends everything
// under 1 ms to bucket 0, so interpolating that bucket from 0.5 ms
// would claim a floor no sub-millisecond response can go below.
func TestQuantile_Bucket0StartsAtZero(t *testing.T) {
	if lo := LowerEdgeMs(0); lo != 0 {
		t.Errorf("bucket 0 lower edge = %v, want 0", lo)
	}
	// A pile of 0.1 ms responses must not report ~1 ms at p50.
	got, _ := Quantile(Of([]float64{0.1, 0.1, 0.1, 0.1}), 0.5)
	if got >= 1 {
		t.Errorf("p50 of four 0.1 ms responses = %v ms, want below 1", got)
	}
}

// TestQuantile_TopBucketSaturates — above 65536 ms there is nothing to
// interpolate toward, so the edge is the honest answer and means "at
// least".
func TestQuantile_TopBucketSaturates(t *testing.T) {
	got, n := Quantile(Of([]float64{200000}), 0.95)
	if n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	if want := UpperEdgeMs(Buckets - 1); got != want {
		t.Errorf("p95 = %v, want the saturating edge %v", got, want)
	}
}

// TestQuantile_LowSampleStillReportsItsCount — D11 lives in the API,
// but it can only be honoured if the count travels with the value.
func TestQuantile_LowSampleStillReportsItsCount(t *testing.T) {
	_, n := Quantile(Of([]float64{3, 4, 900}), 0.95)
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
	got, n := Quantile(Of([]float64{5000}), 0.95)
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
	h := Of([]float64{1, 2, 3, 7, 9, 40, 70, 300, 900, 5000, 40000})
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

// ---------------------------------------------------------------------------
// Storage encoding
// ---------------------------------------------------------------------------

// TestEncodeDecode_RoundTrips over pseudo-random histograms. This is
// the only code in the design whose failure would corrupt stored data
// rather than merely misreport it, so it gets a property test and not
// an example.
func TestEncodeDecode_RoundTrips(t *testing.T) {
	rnd := rand.New(rand.NewSource(0xC0FFEE))
	for trial := 0; trial < 500; trial++ {
		var in BucketCounts
		for i := range in {
			switch rnd.Intn(4) {
			case 0: // leave it empty — sparse histograms are the norm
			case 1:
				in[i] = uint64(rnd.Intn(10))
			case 2:
				in[i] = uint64(rnd.Intn(1_000_000))
			case 3:
				in[i] = uint64(rnd.Uint32())
			}
		}
		blob := Encode(in)
		if len(blob) != EncodedSize {
			t.Fatalf("trial %d: blob is %d bytes, want %d", trial, len(blob), EncodedSize)
		}
		out, ok, err := Decode(blob)
		if err != nil {
			t.Fatalf("trial %d: Decode: %v", trial, err)
		}
		if !ok {
			t.Fatalf("trial %d: ok=false on a blob we just encoded", trial)
		}
		if out != in {
			t.Fatalf("trial %d: round trip changed the histogram\n in=%v\nout=%v", trial, in, out)
		}
		// And the quantile must survive, which is what actually matters
		// to a reader.
		for _, q := range []float64{0.5, 0.95, 0.99} {
			gv, gn := Quantile(in, q)
			ov, on := Quantile(out, q)
			if gv != ov || gn != on {
				t.Fatalf("trial %d q=%v: quantile changed across the round trip: (%v,%d) -> (%v,%d)", trial, q, gv, gn, ov, on)
			}
		}
	}
}

// TestDecode_EmptyIsNotAHistogramOfNothing — a row written before the
// histogram columns existed has no distribution. Reporting it as a
// histogram of zero observations would make an unmeasured route
// indistinguishable from an idle one, which is the failure this whole
// design exists to remove.
func TestDecode_EmptyIsNotAHistogramOfNothing(t *testing.T) {
	for _, blob := range [][]byte{nil, {}} {
		out, ok, err := Decode(blob)
		if err != nil {
			t.Fatalf("Decode(%v): %v", blob, err)
		}
		if ok {
			t.Errorf("Decode(%v) reported ok=true; an absent histogram must not pass as present", blob)
		}
		if out != (BucketCounts{}) {
			t.Errorf("Decode(%v) = %v, want the zero value", blob, out)
		}
	}
}

// TestDecode_WrongLengthIsRefused — a short or long blob came from a
// different build or a truncated write. Zero-filling it would turn a
// corrupt row into a route that looks like it served nothing.
func TestDecode_WrongLengthIsRefused(t *testing.T) {
	for _, n := range []int{1, EncodedSize - 1, EncodedSize + 1, EncodedSize * 2} {
		_, ok, err := Decode(make([]byte, n))
		if err == nil {
			t.Errorf("Decode(%d bytes) returned no error", n)
		}
		if !errors.Is(err, ErrBadEncoding) {
			t.Errorf("Decode(%d bytes) error = %v, want ErrBadEncoding", n, err)
		}
		if ok {
			t.Errorf("Decode(%d bytes) reported ok=true", n)
		}
	}
}

// TestEncode_SaturatesRatherThanWraps — uint32 caps a bucket at ~4.29
// billion requests in one window. Reaching that needs ~1.2 M req/s to
// one route for a whole hour, so it is not a practical concern; what
// matters is the failure MODE. A clamped count reads as "at least this
// many", a wrapped one reads as almost none.
func TestEncode_SaturatesRatherThanWraps(t *testing.T) {
	var in BucketCounts
	in[3] = uint64(math.MaxUint32) + 1000
	out, _, err := Decode(Encode(in))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out[3] != uint64(math.MaxUint32) {
		t.Errorf("bucket 3 = %d, want it clamped to %d; a wrap would have made a saturated bucket look nearly empty",
			out[3], uint64(math.MaxUint32))
	}
}

// TestEncode_IsStableAcrossBuilds — the encoding is persisted, so a
// change to byte order or width silently misreads every existing row.
// Pinned against a literal so that change cannot pass review as a
// refactor.
func TestEncode_IsStableAcrossBuilds(t *testing.T) {
	var in BucketCounts
	in[0] = 1
	in[1] = 258 // 0x0102 — catches a byte-order flip
	in[16] = 0x04030201

	blob := Encode(in)
	if len(blob) != 68 {
		t.Fatalf("EncodedSize changed to %d; every stored row becomes unreadable", len(blob))
	}
	want := map[int][]byte{
		0:  {0x01, 0x00, 0x00, 0x00},
		4:  {0x02, 0x01, 0x00, 0x00},
		64: {0x01, 0x02, 0x03, 0x04},
	}
	for off, w := range want {
		if got := blob[off : off+4]; !bytes.Equal(got, w) {
			t.Errorf("bytes at offset %d = % x, want % x (little-endian uint32)", off, got, w)
		}
	}
}
