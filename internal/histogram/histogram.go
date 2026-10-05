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

// Package histogram holds the fixed-bucket latency distribution shared
// by the hot path and the read path.
//
// It exists because internal/metrics must not import
// internal/observability — the dependency direction is deliberate
// (metrics depends on nothing). Before this package the bucket layout
// was duplicated in both, with observability/histogram.go's own comment
// conceding the arrangement: "Duplicated rather than imported to keep
// internal/metrics independent ... the bucket layout is identical so a
// future refactor (if we ever move the histogram into a shared
// internal/histogram package) is a rename, not a semantic change."
//
// This is that refactor, and it is no longer optional: the quantile
// arithmetic now lives beside the layout, and two copies of a quantile
// are two chances to drift. A duplicated implementation cannot be
// tested once — the lesson the topology view filter taught the same
// week, where a test carrying a copy of its subject stayed green
// through the whole bug it was written to prevent.
package histogram

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Buckets is the number of log-spaced buckets covering the realistic
// HTTP latency range. With BaseMs=0.5, bucket 16 has upper edge
// 0.5 * 2^17 = 65536 ms (~65 s) — past Caddy's default upstream
// timeout, so anything slower saturates the last bucket and is
// reported as "at least 65 s".
const Buckets = 17

// BaseMs scales the bucket ladder. Bucket i covers
// [BaseMs * 2^i, BaseMs * 2^(i+1)) for i >= 1; bucket 0 covers
// [0, 1) — see LowerEdgeMs.
const BaseMs = 0.5

// IndexOf maps a duration in ms to its bucket. Values below BaseMs
// (including zero, and negatives from a misbehaving clock) land in
// bucket 0; values past the top edge saturate the last bucket.
func IndexOf(durMs float64) int {
	if durMs < BaseMs {
		return 0
	}
	idx := int(math.Log2(durMs / BaseMs))
	if idx < 0 {
		return 0
	}
	if idx >= Buckets {
		return Buckets - 1
	}
	return idx
}

// UpperEdgeMs returns the upper edge of bucket i in ms.
func UpperEdgeMs(i int) float64 {
	return BaseMs * math.Pow(2, float64(i+1))
}

// BucketCounts is a summed latency distribution: counts[i] requests
// landed in bucket i.
//
// Summing two BucketCounts elementwise yields exactly the histogram of
// the union of their samples. That identity is the whole reason this
// type travels instead of a scalar — it holds at every aggregation
// step (tick → minute → hour → day → API), which is false for a
// percentile. See the spec's §1: max and mean are both invalid on
// quantiles, and the chain applied one or the other at every level.
type BucketCounts [Buckets]uint64

// Add folds other into b elementwise. Exact, associative and
// commutative, which is what makes rollup idempotence testable
// (gate G7) rather than merely hoped for.
func (b *BucketCounts) Add(other BucketCounts) {
	for i := range other {
		b[i] += other[i]
	}
}

// Total returns the number of observations in b.
func (b BucketCounts) Total() int64 {
	var t int64
	for _, c := range b {
		t += int64(c)
	}
	return t
}

// LowerEdgeMs returns the lower edge of bucket i.
//
// Bucket 0 starts at ZERO, not at BaseMs: IndexOf sends
// everything below BaseMs to bucket 0, and also everything in
// [0.5, 1) because int(math.Log2(0.7/0.5)) == 0. So bucket 0 covers
// [0, 1) and interpolating it from 0.5 would understate how fast a
// sub-millisecond response actually was.
func LowerEdgeMs(i int) float64 {
	if i <= 0 {
		return 0
	}
	return UpperEdgeMs(i - 1)
}

// Quantile returns the q-quantile of b in milliseconds and the number
// of observations it was computed from.
//
// The count is returned alongside deliberately: a quantile over three
// requests is not a quantile, and the caller needs the sample size to
// honour that (D11) rather than publishing a number it cannot support.
// A zero count means "no observations" — the caller renders null, never
// 0 ms, which would read as "instant".
//
// Interpolation is linear inside the resolved bucket, with the selected
// observation placed at the MIDDLE of its share of the bucket rather
// than at the top of it.
//
// This deviates from Prometheus's histogram_quantile deliberately.
// Prometheus interpolates to (rank - cumBefore) / count, so the last
// observation in a bucket lands exactly on the bucket's upper edge —
// which means a bucket holding a single sample reports that sample as
// the edge, overstating it by up to a factor of two. On a busy service
// that bias is diluted; on a homelab route serving a handful of
// requests a minute, which is Arenet's normal case, it is the whole
// answer. It is how one 5 s image download came to be reported as
// 8192 ms.
//
// Placing the observation at the midpoint of its share is the honest
// estimate: nothing is known about where inside the bucket the request
// actually fell, so its expected position is the centre. The two
// conventions converge as the bucket's count grows (the offset is
// 0.5/count of the bucket's width), so this costs nothing at volume and
// fixes the low-volume case.
//
// A quantile landing in the top bucket is capped at its upper edge and
// means "at least that": the bucket is saturating by construction, so
// there is no information above it to interpolate against, and a
// midpoint would have to invent an upper bound.
func Quantile(b BucketCounts, q float64) (float64, int64) {
	total := b.Total()
	if total == 0 {
		return 0, 0
	}
	if q <= 0 {
		return LowerEdgeMs(firstNonEmpty(b)), total
	}
	if q > 1 {
		q = 1
	}

	// Rank in [1, total]. ceil so that q=1 selects the last
	// observation rather than falling short of it by rounding.
	rank := math.Ceil(q * float64(total))
	if rank < 1 {
		rank = 1
	}

	var cum int64
	for i, c := range b {
		if c == 0 {
			continue
		}
		prev := cum
		cum += int64(c)
		if float64(cum) < rank {
			continue
		}
		if i == Buckets-1 {
			// Saturating bucket: nothing above it to interpolate
			// toward, so report its edge and let it mean "≥".
			return UpperEdgeMs(i), total
		}
		lower := LowerEdgeMs(i)
		upper := UpperEdgeMs(i)
		// Position of the rank-th observation within this bucket, in
		// (0, 1). The -0.5 centres each observation in its share
		// instead of pinning it to the share's top edge: with c == 1
		// this yields the bucket's midpoint, where Prometheus's
		// convention would yield its upper edge.
		frac := (rank - float64(prev) - 0.5) / float64(c)
		return lower + (upper-lower)*frac, total
	}

	// Unreachable while total > 0: some bucket held a count.
	return UpperEdgeMs(Buckets - 1), total
}

// firstNonEmpty returns the index of the lowest occupied bucket, or 0
// when b is empty.
func firstNonEmpty(b BucketCounts) int {
	for i, c := range b {
		if c > 0 {
			return i
		}
	}
	return 0
}

// Of builds a BucketCounts from raw durations. Test and
// read-path helper; the hot path uses LatencyHistogram.Observe.
func Of(durationsMs []float64) BucketCounts {
	var b BucketCounts
	for _, d := range durationsMs {
		b[IndexOf(d)]++
	}
	return b
}

// ---------------------------------------------------------------------------
// Storage encoding (spec 2026-10-05-latency-truth, D6)
// ---------------------------------------------------------------------------

// EncodedSize is the wire size of an encoded BucketCounts: Buckets
// counts at 4 bytes each.
//
// Fixed width rather than varints, so a row's size is knowable without
// decoding it and a truncated blob is detectable by length alone. At
// 68 bytes per row this costs 4.9 MB for 50 routes over bucket_1m's
// 24 h retention — storage was never the reason to throw the
// distribution away.
const EncodedSize = Buckets * 4

// ErrBadEncoding is returned by Decode for a blob that is not
// EncodedSize bytes long.
//
// A wrong length means the row was written by a different build or
// truncated in transit. Refusing it is the point: silently zero-filling
// would turn a corrupt row into a route that looks like it served
// nothing, and "served nothing" is the one thing this design will not
// let a missing measurement pretend to be.
var ErrBadEncoding = errors.New("histogram: blob is not a valid encoded BucketCounts")

// Encode serialises b as little-endian uint32 counts.
//
// uint32 caps a bucket at ~4.29 billion requests in one window. The
// widest window that reaches this encoding is an hour, so saturating a
// single bucket would need about 1.2 million requests per second to one
// route for the whole hour. Saturation clamps rather than wrapping:
// a clamped count reads as "at least this many", where a wrapped one
// would read as almost none.
func Encode(b BucketCounts) []byte {
	out := make([]byte, EncodedSize)
	for i, c := range b {
		if c > math.MaxUint32 {
			c = math.MaxUint32
		}
		binary.LittleEndian.PutUint32(out[i*4:], uint32(c))
	}
	return out
}

// Decode parses a blob written by Encode.
//
// A nil or empty blob decodes to the zero histogram with ok=false,
// which is how a row predating the histogram columns is recognised:
// those rows have no distribution and must not be reported as one.
// Callers distinguish "no histogram here" from "a histogram of nothing"
// by the bool, never by the counts being zero.
func Decode(blob []byte) (BucketCounts, bool, error) {
	var out BucketCounts
	if len(blob) == 0 {
		return out, false, nil
	}
	if len(blob) != EncodedSize {
		return out, false, fmt.Errorf("%w: got %d bytes, want %d", ErrBadEncoding, len(blob), EncodedSize)
	}
	for i := range out {
		out[i] = uint64(binary.LittleEndian.Uint32(blob[i*4:]))
	}
	return out, true, nil
}

// MinSamplesFor returns the smallest number of observations for which
// the q-quantile is distinguishable from the maximum.
//
// It is derived, not chosen. Quantile selects rank ceil(q*n), and that
// rank equals n — i.e. the "quantile" IS the largest observation —
// while q*n > n-1.
//
// The threshold is found by evaluating that exact condition rather
// than by rearranging it to n < 1/(1-q). The closed form looks
// cleaner and is wrong at the boundary: 1-0.9 is 0.09999999999999998
// in binary floating point, so ceil(1/(1-0.9)) is 11 where the real
// answer is 10. Searching with the same expression Quantile uses
// means the two cannot disagree, which a formula derived separately
// cannot promise. My own test caught this on the first run.
//
// Results:
//
//	p50 ->   2 observations
//	p95 ->  20
//	p99 -> 100
//
// Below the threshold the number is not wrong so much as meaningless:
// it answers "what was the slowest request" while being labelled a
// percentile. That is precisely the defect this design was written to
// remove — the superseded pipeline reduced each one-second tick to a
// "p95" over zero or one request — so reintroducing it at the read
// layer, with an arbitrary cutoff picked to feel safe, would be the
// same mistake wearing a threshold.
//
// Callers above this package use it to decide whether to publish a
// figure at all. Returning null for a window with nine requests is not
// a gap in the data; it is the honest report that nine requests cannot
// support a 95th percentile.
func MinSamplesFor(q float64) int64 {
	if q <= 0 || q >= 1 {
		return 1
	}
	// Bounded so a pathological q (0.9999999) cannot spin. The cap is
	// far above any quantile a dashboard offers; reaching it means the
	// caller is asking for a percentile no realistic window can
	// support, and the cap is then the honest answer.
	const maxSearch = int64(1 << 20)
	for n := int64(1); n < maxSearch; n++ {
		if int64(math.Ceil(q*float64(n))) < n {
			return n
		}
	}
	return maxSearch
}
