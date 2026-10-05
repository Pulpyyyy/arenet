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
	"sync/atomic"
)

// histogramBuckets is the number of log-spaced buckets covering
// the realistic HTTP latency range. With histogramBaseMs=0.5 and
// 17 buckets, the top bucket has upper edge 0.5 * 2^17 = 65536 ms
// (~65 s) — past Caddy's default upstream timeout, so anything
// slower than that saturates the last bucket and is reported as
// "≥ 65 s". 17 * 8 bytes = 136 B per route, fits comfortably in
// two cache lines.
const histogramBuckets = 17

// histogramBaseMs is the lower edge of bucket 0. Anything below
// this latency saturates bucket 0; anything above the upper edge
// of bucket 63 saturates the last bucket.
const histogramBaseMs = 0.5

// LatencyHistogram is a fixed-bucket, lock-free latency
// distribution for one route. Bucket i covers
// [histogramBaseMs * 2^i, histogramBaseMs * 2^(i+1)) ms.
//
// Observe is allocation-free and lock-free (one atomic.AddUint64
// per call), making it safe to call from the Caddy request path
// without contention or I/O — the AC #13 invariant.
//
// P95 is read-side only and is called by the background flush
// goroutine, never by request handlers.
type LatencyHistogram struct {
	counts [histogramBuckets]uint64
}

// Observe records one request whose duration was durMs
// milliseconds. Safe for concurrent use from any number of
// goroutines.
func (h *LatencyHistogram) Observe(durMs float64) {
	idx := bucketIndex(durMs)
	atomic.AddUint64(&h.counts[idx], 1)
}

// P95 returns the upper edge of the bucket where the cumulative
// count first crosses 95 % of the total. Returns 0 when no
// observations have been recorded (caller decides whether to
// render that as null on the timeline per AC #5).
func (h *LatencyHistogram) P95() float64 {
	return h.percentile(0.95)
}

// Snapshot returns the current bucket counts and the total count.
// The returned array is a copy — safe to retain across resets.
func (h *LatencyHistogram) Snapshot() ([histogramBuckets]uint64, uint64) {
	var out [histogramBuckets]uint64
	var total uint64
	for i := range h.counts {
		c := atomic.LoadUint64(&h.counts[i])
		out[i] = c
		total += c
	}
	return out, total
}

// Reset clears all buckets. Called by the flush goroutine after
// snapshotting at the minute boundary.
func (h *LatencyHistogram) Reset() {
	for i := range h.counts {
		atomic.StoreUint64(&h.counts[i], 0)
	}
}

func (h *LatencyHistogram) percentile(p float64) float64 {
	snap, total := h.Snapshot()
	if total == 0 {
		return 0
	}
	threshold := uint64(math.Ceil(float64(total) * p))
	if threshold == 0 {
		threshold = 1
	}
	var cum uint64
	for i, c := range snap {
		cum += c
		if cum >= threshold {
			return bucketUpperEdgeMs(i)
		}
	}
	return bucketUpperEdgeMs(histogramBuckets - 1)
}

// bucketIndex maps a duration in ms to its bucket. Values below
// histogramBaseMs (including zero and negatives from a buggy
// clock) land in bucket 0; values past the top edge saturate the
// last bucket.
func bucketIndex(durMs float64) int {
	if durMs < histogramBaseMs {
		return 0
	}
	idx := int(math.Log2(durMs / histogramBaseMs))
	if idx < 0 {
		return 0
	}
	if idx >= histogramBuckets {
		return histogramBuckets - 1
	}
	return idx
}

// bucketUpperEdgeMs returns the upper edge of bucket i in ms.
func bucketUpperEdgeMs(i int) float64 {
	return histogramBaseMs * math.Pow(2, float64(i+1))
}

// ---------------------------------------------------------------------------
// Read-time quantiles (spec 2026-10-05-latency-truth, D3 + D5)
// ---------------------------------------------------------------------------

// HistogramBuckets is the exported bucket count, so callers outside
// this package can declare the fixed-size array the wire and the
// storage layer carry.
const HistogramBuckets = histogramBuckets

// BucketCounts is a summed latency distribution: counts[i] requests
// landed in bucket i.
//
// Summing two BucketCounts elementwise yields exactly the histogram of
// the union of their samples. That identity is the whole reason this
// type travels instead of a scalar — it holds at every aggregation
// step (tick → minute → hour → day → API), which is false for a
// percentile. See the spec's §1: max and mean are both invalid on
// quantiles, and the chain applied one or the other at every level.
type BucketCounts [histogramBuckets]uint64

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

// bucketLowerEdgeMs returns the lower edge of bucket i.
//
// Bucket 0 starts at ZERO, not at histogramBaseMs: bucketIndex sends
// everything below histogramBaseMs to bucket 0, and also everything in
// [0.5, 1) because int(math.Log2(0.7/0.5)) == 0. So bucket 0 covers
// [0, 1) and interpolating it from 0.5 would understate how fast a
// sub-millisecond response actually was.
func bucketLowerEdgeMs(i int) float64 {
	if i <= 0 {
		return 0
	}
	return bucketUpperEdgeMs(i - 1)
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
		return bucketLowerEdgeMs(firstNonEmpty(b)), total
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
		if i == histogramBuckets-1 {
			// Saturating bucket: nothing above it to interpolate
			// toward, so report its edge and let it mean "≥".
			return bucketUpperEdgeMs(i), total
		}
		lower := bucketLowerEdgeMs(i)
		upper := bucketUpperEdgeMs(i)
		// Position of the rank-th observation within this bucket, in
		// (0, 1). The -0.5 centres each observation in its share
		// instead of pinning it to the share's top edge: with c == 1
		// this yields the bucket's midpoint, where Prometheus's
		// convention would yield its upper edge.
		frac := (rank - float64(prev) - 0.5) / float64(c)
		return lower + (upper-lower)*frac, total
	}

	// Unreachable while total > 0: some bucket held a count.
	return bucketUpperEdgeMs(histogramBuckets - 1), total
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

// HistogramOf builds a BucketCounts from raw durations. Test and
// read-path helper; the hot path uses LatencyHistogram.Observe.
func HistogramOf(durationsMs []float64) BucketCounts {
	var b BucketCounts
	for _, d := range durationsMs {
		b[bucketIndex(d)]++
	}
	return b
}
