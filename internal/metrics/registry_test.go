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

package metrics

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/barto95100/arenet/internal/histogram"
)

// --- Inc -------------------------------------------------------------------

func TestRegistry_Inc_UnknownRoute_NoOp(t *testing.T) {
	r := NewRegistry()
	// No Sync, so no cells exist. Inc must not panic, must not
	// silently create a cell.
	r.Inc("unknown-id", 200, 0)
	if got := len(r.cells); got != 0 {
		t.Errorf("cells map grew unexpectedly: %d", got)
	}
}

func TestRegistry_Inc_2xx_OnlyReqs(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.Inc("r1", 200, 0)
	r.Inc("r1", 201, 0)
	r.Inc("r1", 204, 0)

	got := r.Snapshot()
	if got["r1"].Reqs != 3 {
		t.Errorf("Reqs=%d want 3", got["r1"].Reqs)
	}
	if got["r1"].Errs != 0 {
		t.Errorf("Errs=%d want 0 (2xx never bumps errs)", got["r1"].Errs)
	}
}

func TestRegistry_Inc_5xx_BothCounters(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.Inc("r1", 500, 0)
	r.Inc("r1", 502, 0)
	r.Inc("r1", 503, 0)
	r.Inc("r1", 599, 0)

	got := r.Snapshot()
	if got["r1"].Reqs != 4 {
		t.Errorf("Reqs=%d want 4", got["r1"].Reqs)
	}
	if got["r1"].Errs != 4 {
		t.Errorf("Errs=%d want 4 (all 5xx)", got["r1"].Errs)
	}
}

func TestRegistry_Inc_4xx_TrackedSeparatelyFrom5xx(t *testing.T) {
	// Step L AC #3: 4xx and 5xx are tracked separately. A 4xx
	// burst increments Errs4xx, NEVER the 5xx counter (Errs).
	// Reciprocal coverage in TestRegistry_Inc_5xx below.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.Inc("r1", 400, 0)
	r.Inc("r1", 401, 0)
	r.Inc("r1", 403, 0)
	r.Inc("r1", 404, 0)
	r.Inc("r1", 499, 0)

	got := r.Snapshot()
	if got["r1"].Reqs != 5 {
		t.Errorf("Reqs=%d want 5", got["r1"].Reqs)
	}
	if got["r1"].Errs != 0 {
		t.Errorf("Errs (5xx) = %d, want 0 — a 4xx burst MUST NOT increment 5xx (AC #3)", got["r1"].Errs)
	}
	if got["r1"].Errs4xx != 5 {
		t.Errorf("Errs4xx = %d, want 5 (every 4xx should land in Errs4xx)", got["r1"].Errs4xx)
	}
}

func TestRegistry_Inc_5xx_DoesNotIncrement4xx(t *testing.T) {
	// Step L AC #3 reciprocal: a 5xx burst MUST NOT increment Errs4xx.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.Inc("r1", 500, 0)
	r.Inc("r1", 502, 0)
	r.Inc("r1", 503, 0)

	got := r.Snapshot()
	if got["r1"].Errs != 3 {
		t.Errorf("Errs (5xx) = %d, want 3", got["r1"].Errs)
	}
	if got["r1"].Errs4xx != 0 {
		t.Errorf("Errs4xx = %d, want 0 — a 5xx burst MUST NOT increment 4xx (AC #3)", got["r1"].Errs4xx)
	}
}

func TestRegistry_Inc_LatencyP95(t *testing.T) {
	// Step L: Inc records latency into the per-cell histogram;
	// Snapshot drains the p95 in the returned Delta.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	// 95 fast requests + 5 slow ones — the p95 should sit in
	// the fast region, not in the slow tail.
	for i := 0; i < 95; i++ {
		r.Inc("r1", 200, 10) // 10 ms
	}
	for i := 0; i < 5; i++ {
		r.Inc("r1", 200, 1000) // 1000 ms
	}

	got := r.Snapshot()
	if got["r1"].Reqs != 100 {
		t.Fatalf("Reqs=%d, want 100", got["r1"].Reqs)
	}

	// Snapshot now drains the DISTRIBUTION, so this test can assert
	// the thing it always meant: the p95 of 95 requests at 10 ms and
	// 5 at 1000 ms sits in the fast region. It also checks the shape
	// directly, which the old scalar made impossible.
	buckets := got["r1"].LatencyBuckets
	if total := buckets.Total(); total != 100 {
		t.Fatalf("histogram total = %d, want 100 — the drain lost observations", total)
	}
	p95, n := histogram.Quantile(buckets, 0.95)
	if n != 100 {
		t.Fatalf("Quantile count = %d, want 100", n)
	}
	if p95 == 0 {
		t.Fatalf("p95 = 0, want a positive ms value")
	}
	if p95 > 64 {
		t.Errorf("p95 = %v ms, expected the fast region (~10 ms), got the slow tail", p95)
	}
	// The slow tail must still be visible in the distribution — a p95
	// in the fast region is only honest if the 5 slow requests were
	// recorded rather than dropped.
	if slow := buckets[histogram.IndexOf(1000)]; slow != 5 {
		t.Errorf("bucket for 1000 ms holds %d, want 5", slow)
	}
	// And the p99 of the same data must find them.
	if p99, _ := histogram.Quantile(buckets, 0.99); p99 < 512 {
		t.Errorf("p99 = %v ms, want the slow tail — one histogram answers both questions", p99)
	}
}

// --- Sync ------------------------------------------------------------------

func TestRegistry_Sync_AddNewRoutes(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1", "r2", "r3"})

	if got := len(r.cells); got != 3 {
		t.Fatalf("cells=%d want 3", got)
	}
	// Each cell starts at zero.
	for _, id := range []string{"r1", "r2", "r3"} {
		if r.cells[id].reqs != 0 || r.cells[id].errs != 0 {
			t.Errorf("new cell %q not zeroed: %+v", id, r.cells[id])
		}
	}
}

func TestRegistry_Sync_RemoveStaleRoutes(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1", "r2", "r3"})

	r.Sync([]string{"r2"}) // r1 and r3 must disappear

	if got := len(r.cells); got != 1 {
		t.Fatalf("cells=%d want 1", got)
	}
	if _, ok := r.cells["r2"]; !ok {
		t.Errorf("r2 should still exist")
	}
}

func TestRegistry_Sync_PreservesExistingCounters(t *testing.T) {
	// Spec §11.2: route update in-place (same ID) preserves counters.
	r := NewRegistry()
	r.Sync([]string{"r1"})
	r.Inc("r1", 200, 0)
	r.Inc("r1", 503, 0)

	// Re-sync with the same ID — counters MUST be preserved.
	r.Sync([]string{"r1"})

	got := r.Snapshot()
	if got["r1"].Reqs != 2 {
		t.Errorf("Reqs=%d want 2 (preserved across Sync)", got["r1"].Reqs)
	}
	if got["r1"].Errs != 1 {
		t.Errorf("Errs=%d want 1 (preserved across Sync)", got["r1"].Errs)
	}
}

func TestRegistry_Sync_EmptySlice_DrainsAll(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1", "r2", "r3"})

	r.Sync([]string{})

	if got := len(r.cells); got != 0 {
		t.Errorf("cells=%d want 0 (empty slice drains all)", got)
	}
}

func TestRegistry_Sync_NilSlice_DrainsAll(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1", "r2"})

	r.Sync(nil)

	if got := len(r.cells); got != 0 {
		t.Errorf("cells=%d want 0 (nil slice drains all)", got)
	}
}

func TestRegistry_Sync_Idempotent(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1", "r2"})
	r.Inc("r1", 200, 0)

	// Capture pointers; idempotency means the same cells survive.
	r1Before := r.cells["r1"]
	r2Before := r.cells["r2"]

	r.Sync([]string{"r1", "r2"}) // identical second call

	if r.cells["r1"] != r1Before {
		t.Errorf("r1 cell pointer changed on idempotent Sync")
	}
	if r.cells["r2"] != r2Before {
		t.Errorf("r2 cell pointer changed on idempotent Sync")
	}
	// State preserved.
	got := r.Snapshot()
	if got["r1"].Reqs != 1 {
		t.Errorf("Reqs=%d want 1 (Inc value preserved)", got["r1"].Reqs)
	}
}

// --- Snapshot --------------------------------------------------------------

func TestRegistry_Snapshot_ResetsCounters(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.Inc("r1", 200, 0)
	r.Inc("r1", 500, 0)

	first := r.Snapshot()
	if first["r1"].Reqs != 2 || first["r1"].Errs != 1 {
		t.Fatalf("first snapshot wrong: %+v", first["r1"])
	}

	// A second Snapshot with no Inc in between must show zeros.
	second := r.Snapshot()
	if second["r1"].Reqs != 0 || second["r1"].Errs != 0 {
		t.Errorf("second snapshot should be zero: %+v", second["r1"])
	}
}

func TestRegistry_Snapshot_DeltasNotCumulative(t *testing.T) {
	// Spec §11.9 explicit guard: each Snapshot reports the count
	// since the previous one, never the running total.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.Inc("r1", 200, 0)
	r.Inc("r1", 200, 0)
	first := r.Snapshot()

	r.Inc("r1", 200, 0)
	second := r.Snapshot()

	if first["r1"].Reqs != 2 {
		t.Errorf("first.Reqs=%d want 2", first["r1"].Reqs)
	}
	if second["r1"].Reqs != 1 {
		t.Errorf("second.Reqs=%d want 1 (delta, not cumulative)", second["r1"].Reqs)
	}
}

func TestRegistry_Snapshot_AllRoutesIncluded(t *testing.T) {
	// Spec §5.2: idle routes (zero counters) must still be listed.
	r := NewRegistry()
	r.Sync([]string{"r1", "r2", "r3"})

	r.Inc("r1", 200, 0)
	// r2 and r3 are silent.

	got := r.Snapshot()
	if len(got) != 3 {
		t.Fatalf("snapshot len=%d want 3 (idle routes included)", len(got))
	}
	if got["r2"].Reqs != 0 || got["r3"].Reqs != 0 {
		t.Errorf("idle routes should have zero counters")
	}
}

func TestRegistry_Snapshot_OnEmptyRegistry(t *testing.T) {
	r := NewRegistry()
	got := r.Snapshot()
	if got == nil {
		t.Fatal("Snapshot() returned nil; want empty map")
	}
	if len(got) != 0 {
		t.Errorf("Snapshot()=%v want empty", got)
	}
}

// --- Concurrency -----------------------------------------------------------

func TestRegistry_ConcurrentIncAndSnapshot(t *testing.T) {
	// 1000 Inc calls split across goroutines; Snapshot called in
	// parallel a few times. The sum of all Reqs observed across the
	// Snapshots plus the final residual must equal 1000.
	const total = 1000
	r := NewRegistry()
	r.Sync([]string{"r1"})

	var observed uint64
	var snapWg sync.WaitGroup
	stopSnap := make(chan struct{})
	snapWg.Add(1)
	go func() {
		defer snapWg.Done()
		for {
			select {
			case <-stopSnap:
				return
			default:
				snap := r.Snapshot()
				atomic.AddUint64(&observed, snap["r1"].Reqs)
			}
		}
	}()

	var incWg sync.WaitGroup
	for i := 0; i < total; i++ {
		incWg.Add(1)
		go func() {
			defer incWg.Done()
			r.Inc("r1", 200, 0)
		}()
	}
	incWg.Wait()
	close(stopSnap)
	snapWg.Wait()

	// Drain any residual in a final Snapshot.
	final := r.Snapshot()
	observed += final["r1"].Reqs

	if observed != total {
		t.Errorf("observed=%d want %d (no Inc must be lost under -race)", observed, total)
	}
}

func TestRegistry_ConcurrentIncAndSync(t *testing.T) {
	// Inc in a tight loop while Sync adds and removes the same route.
	// Goal: no data race (-race detector), no panic. Inc may be a
	// no-op when the route is gone (spec §11.1); we do not assert
	// counter accuracy here.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	done := make(chan struct{})

	var incWg sync.WaitGroup
	incWg.Add(1)
	go func() {
		defer incWg.Done()
		for {
			select {
			case <-done:
				return
			default:
				r.Inc("r1", 200, 0)
			}
		}
	}()

	var syncWg sync.WaitGroup
	syncWg.Add(1)
	go func() {
		defer syncWg.Done()
		for i := 0; i < 100; i++ {
			r.Sync([]string{"r1", "r2"})
			r.Sync([]string{"r2"})
			r.Sync([]string{"r1"})
		}
	}()
	syncWg.Wait()
	close(done)
	incWg.Wait()
}

// --- Benchmarks (spec §9.3) ------------------------------------------------

func BenchmarkRegistry_Inc(b *testing.B) {
	r := NewRegistry()
	r.Sync([]string{"r1"})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Inc("r1", 200, 0)
	}
}

func BenchmarkRegistry_Snapshot_10Routes(b *testing.B) {
	r := NewRegistry()
	ids := make([]string, 10)
	for i := range ids {
		ids[i] = fmt.Sprintf("r%d", i)
	}
	r.Sync(ids)
	// Seed each cell with some traffic so Snapshot has work to do.
	for _, id := range ids {
		for k := 0; k < 100; k++ {
			r.Inc(id, 200, 0)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Snapshot()
		// Re-seed lightly to keep work non-trivial across iterations.
		for _, id := range ids {
			r.Inc(id, 200, 0)
		}
	}
}

func BenchmarkRegistry_Snapshot_100Routes(b *testing.B) {
	r := NewRegistry()
	ids := make([]string, 100)
	for i := range ids {
		ids[i] = fmt.Sprintf("r%d", i)
	}
	r.Sync(ids)
	for _, id := range ids {
		for k := 0; k < 10; k++ {
			r.Inc(id, 200, 0)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Snapshot()
		for _, id := range ids {
			r.Inc(id, 200, 0)
		}
	}
}
