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
