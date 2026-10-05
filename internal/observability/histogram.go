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

	"github.com/barto95100/arenet/internal/histogram"
)

// The bucket ladder now lives in internal/histogram, imported by both
// this package and internal/metrics. These aliases keep the local
// vocabulary while there is exactly one implementation — see that
// package's doc comment for why the previous duplication had to end.
const histogramBuckets = histogram.Buckets

const histogramBaseMs = histogram.BaseMs

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

func bucketIndex(durMs float64) int { return histogram.IndexOf(durMs) }

func bucketUpperEdgeMs(i int) float64 { return histogram.UpperEdgeMs(i) }
