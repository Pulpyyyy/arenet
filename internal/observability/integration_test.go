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
	"context"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/metrics"
)

// stubLister satisfies metrics.RouteLister with a fixed route list,
// avoiding the storage dependency.
type stubLister struct {
	routes []metrics.RouteMetadata
}

func (s *stubLister) ListRoutesForMetrics(_ context.Context) ([]metrics.RouteMetadata, error) {
	return s.routes, nil
}

// TestIntegration_TickerToAggregatorToStore exercises the full
// Step L L.1 cross-package seam without spawning a binary:
//
//	metrics.Registry.Inc (hot path)
//	      ↓
//	metrics.Ticker.makeSnapshot (per second)
//	      ↓
//	  TickConsumer.Consume (the bridge interface)
//	      ↓
//	observability.Aggregator.Ingest → absorb
//	      ↓
//	     flush at minute boundary
//	      ↓
//	  observability.Store.Query  ← assertion point
//
// The Step E broadcast goes out in parallel: a subscriber on the
// same broadcaster must receive the per-tick Snapshot
// (AC #9 anti-regression: the observability fan-out MUST NOT
// break the existing WS pipeline).
//
// Determinism: we call Ticker.MakeSnapshotForTest (not Run) so
// the test never depends on real time. The minute boundary is
// crossed by advancing the aggregator's synthetic clock between
// calls.
func TestIntegration_TickerToAggregatorToStore(t *testing.T) {
	ctx := context.Background()

	// --- Step E: real registry + broadcaster + ticker ---
	registry := metrics.NewRegistry()
	registry.Sync([]string{"r-a", "r-b"})
	broadcaster := metrics.NewBroadcaster(silentLogger())
	lister := &stubLister{routes: []metrics.RouteMetadata{
		{ID: "r-a", Host: "a.test", Upstream: "http://127.0.0.1:1"},
		{ID: "r-b", Host: "b.test", Upstream: "http://127.0.0.1:2"},
	}}
	ticker := metrics.NewTicker(registry, broadcaster, lister)

	// --- Step L: real store + aggregator ---
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	aggregator := NewAggregator(store, silentLogger(), 256)
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	var clock = t0
	aggregator.SetClock(func() time.Time { return clock })
	aggregator.currentMinute = t0.Truncate(time.Minute)
	ticker.SetConsumer(aggregator)

	// AC #9 sanity: a Step E subscriber MUST receive the WS
	// snapshot in parallel. Subscribe BEFORE the first tick.
	sub := broadcaster.Subscribe()
	defer broadcaster.Unsubscribe(sub)

	// --- Hot path: simulate proxied requests ---
	// 100 OK + 3 4xx for r-a, 50 OK + 2 5xx for r-b. Latencies
	// chosen so the per-tick p95 lands in the fast region.
	for i := 0; i < 100; i++ {
		registry.Inc("r-a", metrics.Observation{Status: 200, DurMs: 10})
	}
	for i := 0; i < 3; i++ {
		registry.Inc("r-a", metrics.Observation{Status: 404, DurMs: 12})
	}
	for i := 0; i < 50; i++ {
		registry.Inc("r-b", metrics.Observation{Status: 200, DurMs: 25})
	}
	for i := 0; i < 2; i++ {
		registry.Inc("r-b", metrics.Observation{Status: 503, DurMs: 200})
	}

	// --- Tick 1 (10:00:00.5) ---
	// Drive the ticker manually to keep the test deterministic.
	// MakeSnapshotForTest mirrors Run's per-tick path: read
	// Registry deltas, build wire Snapshot, fan out to broadcaster
	// AND consumer.
	tick1 := t0.Add(500 * time.Millisecond)
	snap1 := ticker.MakeSnapshotForTest(ctx, tick1)

	// AC #9: WebSocket subscriber received the tick.
	select {
	case wsSnap, ok := <-sub.Ch:
		if !ok {
			t.Fatal("ws subscriber chan closed")
		}
		if len(wsSnap.Routes) != 2 {
			t.Fatalf("ws snapshot routes = %d, want 2", len(wsSnap.Routes))
		}
		// r-a got 103 requests (100 + 3 4xx); r-b got 52.
		gotByID := map[string]uint64{}
		for _, r := range wsSnap.Routes {
			gotByID[r.ID] = r.Reqs
		}
		if gotByID["r-a"] != 103 {
			t.Errorf("ws r-a reqs = %d, want 103", gotByID["r-a"])
		}
		if gotByID["r-b"] != 52 {
			t.Errorf("ws r-b reqs = %d, want 52", gotByID["r-b"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("ws subscriber did not receive snapshot — AC #9 regression")
	}

	// Sanity on the wire snapshot itself: 5xx is r-b's 2, 4xx
	// is r-a's 3 (additive Step L fields, NOT a regression in
	// the legacy Errs field which still counts 5xx).
	if snap1.Routes[0].ID == "r-a" {
		if snap1.Routes[0].Errs != 0 {
			t.Errorf("snap r-a Errs (5xx) = %d, want 0", snap1.Routes[0].Errs)
		}
	}

	// --- Drain the aggregator's Run-less path ---
	// In a real run the goroutine consumes the channel and
	// folds via absorb. Without Run we drain by hand to keep
	// the test deterministic — call absorb directly. The Ingest
	// path is exercised separately in aggregator_test.go.
	drainAggregatorChannel(aggregator)

	// --- Cross the minute boundary (10:01:00) and flush ---
	clock = t0.Add(time.Minute)
	aggregator.maybeFlush(ctx)

	// --- Assert: one bucket per route, correct counts ---
	bucketTs := t0.Truncate(time.Minute) // 10:00:00
	rowsA, err := store.Query(ctx, Granularity1m, "r-a", bucketTs, bucketTs.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query r-a: %v", err)
	}
	if len(rowsA) != 1 {
		t.Fatalf("r-a rows = %d, want 1: %+v", len(rowsA), rowsA)
	}
	if rowsA[0].ReqCount != 103 {
		t.Errorf("r-a ReqCount = %d, want 103 (100 OK + 3 4xx)", rowsA[0].ReqCount)
	}
	if rowsA[0].FourxxCount != 3 {
		t.Errorf("r-a FourxxCount = %d, want 3", rowsA[0].FourxxCount)
	}
	if rowsA[0].FivexxCount != 0 {
		t.Errorf("r-a FivexxCount = %d, want 0 — 4xx must NOT contaminate 5xx (AC #3)", rowsA[0].FivexxCount)
	}
	if rowsA[0].LatencyP95Ms == 0 {
		t.Errorf("r-a LatencyP95Ms = 0, want a positive p95")
	}

	rowsB, err := store.Query(ctx, Granularity1m, "r-b", bucketTs, bucketTs.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query r-b: %v", err)
	}
	if len(rowsB) != 1 {
		t.Fatalf("r-b rows = %d, want 1", len(rowsB))
	}
	if rowsB[0].ReqCount != 52 {
		t.Errorf("r-b ReqCount = %d, want 52", rowsB[0].ReqCount)
	}
	if rowsB[0].FivexxCount != 2 {
		t.Errorf("r-b FivexxCount = %d, want 2", rowsB[0].FivexxCount)
	}
	if rowsB[0].FourxxCount != 0 {
		t.Errorf("r-b FourxxCount = %d, want 0 — 5xx must NOT contaminate 4xx (AC #3)", rowsB[0].FourxxCount)
	}
}

// drainAggregatorChannel pulls every queued TickDelta out of the
// aggregator's ingress channel and folds it into the in-memory
// state, replicating what the Run goroutine would do, but
// synchronously. Used by integration tests that drive everything
// deterministically without starting Run.
func drainAggregatorChannel(a *Aggregator) {
	for {
		select {
		case d := <-a.in:
			a.absorb(d)
		default:
			return
		}
	}
}
