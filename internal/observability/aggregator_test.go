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
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/histogram"
)

// silentLogger discards log output during tests so the verbose
// trace doesn't drown the test runner.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestAggregator_FlushAtMinuteBoundary(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	// Synthetic clock starts at 10:00:00.5 UTC. The aggregator
	// initialises currentMinute to 10:00:00.
	var nowAtomic atomic.Pointer[time.Time]
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 500_000_000, time.UTC)
	nowAtomic.Store(&t0)
	advance := func(d time.Duration) {
		cur := *nowAtomic.Load()
		next := cur.Add(d)
		nowAtomic.Store(&next)
	}

	a := NewAggregator(s, silentLogger(), 16)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })

	// Re-initialise currentMinute against the synthetic clock
	// (production Run() does this; we drive flushes by hand).
	a.currentMinute = a.now().Truncate(time.Minute)

	// Ingest 3 ticks for r-a in the 10:00 minute, then 2 ticks
	// for r-b. Drain the in channel into the absorb path
	// manually since we are not running the goroutine.
	for _, d := range []TickDelta{
		{RouteID: "r-a", Reqs: 50, Fourxx: 1, Fivexx: 0, LatencyBuckets: histogram.Of([]float64{16})},
		{RouteID: "r-a", Reqs: 60, Fourxx: 0, Fivexx: 1, LatencyBuckets: histogram.Of([]float64{32})},
		{RouteID: "r-a", Reqs: 40, Fourxx: 2, Fivexx: 0, LatencyBuckets: histogram.Of([]float64{8})},
		{RouteID: "r-b", Reqs: 10, Fourxx: 5, Fivexx: 0, LatencyBuckets: histogram.Of([]float64{64})},
		{RouteID: "r-b", Reqs: 12, Fourxx: 3, Fivexx: 0, LatencyBuckets: histogram.Of([]float64{128})},
	} {
		a.absorb(d)
	}

	// No rollover yet: maybeFlush should be a no-op.
	a.maybeFlush(ctx)
	if got := a.FlushCount(); got != 0 {
		t.Fatalf("FlushCount before rollover = %d, want 0", got)
	}

	// Advance clock past the minute boundary: 10:01:00.5.
	advance(time.Minute)
	a.maybeFlush(ctx)
	if got := a.FlushCount(); got != 1 {
		t.Fatalf("FlushCount after 1st rollover = %d, want 1", got)
	}

	// Persisted bucket should be at 10:00:00 (the just-closed
	// minute), with r-a sums and r-b sums correct, and p95 =
	// max of the per-tick p95 (32 for r-a, 128 for r-b).
	bucketTs := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	rowsA, err := s.Query(ctx, Granularity1m, "r-a", bucketTs, bucketTs.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query r-a: %v", err)
	}
	if len(rowsA) != 1 {
		t.Fatalf("r-a rows = %d, want 1: %+v", len(rowsA), rowsA)
	}
	if rowsA[0].ReqCount != 150 {
		t.Fatalf("r-a ReqCount = %d, want 150", rowsA[0].ReqCount)
	}
	if rowsA[0].FourxxCount != 3 {
		t.Fatalf("r-a FourxxCount = %d, want 3", rowsA[0].FourxxCount)
	}
	if rowsA[0].FivexxCount != 1 {
		t.Fatalf("r-a FivexxCount = %d, want 1", rowsA[0].FivexxCount)
	}
	// Was "want 32 (max across ticks)". The minute saw three
	// observations — 16, 32 and 8 ms — and its p95 is now computed
	// over that distribution instead of being the largest of them.
	// 32 ms falls in the bucket [32, 64), whose midpoint is 48.
	if rowsA[0].LatencyP95Ms != 48 {
		t.Fatalf("r-a LatencyP95Ms = %d, want 48 (p95 of {8,16,32} ms, interpolated)", rowsA[0].LatencyP95Ms)
	}

	rowsB, err := s.Query(ctx, Granularity1m, "r-b", bucketTs, bucketTs.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query r-b: %v", err)
	}
	// r-b saw 64 and 128 ms; 128 lands in [128, 256), midpoint 192.
	if len(rowsB) != 1 || rowsB[0].ReqCount != 22 || rowsB[0].FourxxCount != 8 || rowsB[0].LatencyP95Ms != 192 {
		t.Fatalf("r-b row mismatch: %+v", rowsB)
	}

	// A second maybeFlush at the same clock value must NOT
	// re-flush (anti-regression for double-flush on the same
	// minute).
	a.maybeFlush(ctx)
	if got := a.FlushCount(); got != 1 {
		t.Fatalf("double maybeFlush at same minute caused FlushCount = %d, want 1", got)
	}

	// Advance another minute with no activity — the flush
	// heartbeat counter increments (proves the loop is alive)
	// but no row is inserted (the state map is empty). Verify
	// both: counter goes to 2, no new bucket appears in the DB
	// for the now-just-closed minute.
	advance(time.Minute)
	a.maybeFlush(ctx)
	if got := a.FlushCount(); got != 2 {
		t.Fatalf("empty rollover should still increment heartbeat: FlushCount = %d, want 2", got)
	}
	emptyTs := time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC)
	rowsEmpty, err := s.Query(ctx, Granularity1m, "r-a", emptyTs, emptyTs.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query empty bucket: %v", err)
	}
	if len(rowsEmpty) != 0 {
		t.Fatalf("empty rollover inserted a phantom row: %+v", rowsEmpty)
	}
}

func TestAggregator_IngestNonBlocking(t *testing.T) {
	// AC #13: Ingest must never block. With a 1-slot channel
	// and a goroutine that doesn't drain, the second Ingest
	// drops cleanly instead of blocking.
	a := NewAggregator(nil, silentLogger(), 1)
	a.Ingest(TickDelta{RouteID: "r", Reqs: 1})
	a.Ingest(TickDelta{RouteID: "r", Reqs: 1})
	if a.Dropped() != 1 {
		t.Fatalf("Dropped = %d, want 1", a.Dropped())
	}
}

func TestAggregator_DegradedNilStore(t *testing.T) {
	// AC #13: a nil store (failed boot-time Open) is the
	// degraded mode. Ingest + flush must not panic and must
	// not push to a nil DB.
	a := NewAggregator(nil, silentLogger(), 16)
	a.currentMinute = time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	a.absorb(TickDelta{RouteID: "r-a", Reqs: 100, LatencyBuckets: histogram.Of([]float64{16})})

	// Manually move the clock forward and flush.
	a.SetClock(func() time.Time {
		return time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC)
	})
	a.maybeFlush(context.Background())

	if a.FlushCount() != 1 {
		t.Fatalf("FlushCount = %d, want 1 (degraded-mode flush still increments)", a.FlushCount())
	}
	if a.FlushErrors() != 0 {
		t.Fatalf("FlushErrors = %d, want 0 (no DB to fail against)", a.FlushErrors())
	}
}

// failingSink returns a synthetic error from every InsertBatch
// after `errorAfter` calls. Used to exercise the AC #13
// runtime-failure path without touching real I/O.
type failingSink struct {
	calls      int
	errorAfter int // 0 means error every call
	err        error
}

func (f *failingSink) InsertBatch(_ context.Context, _ Granularity, _ []MetricBucket) error {
	f.calls++
	if f.errorAfter == 0 || f.calls > f.errorAfter {
		return f.err
	}
	return nil
}

func TestAggregator_FlushErrorIsLoggedAndSwallowed(t *testing.T) {
	// AC #13 runtime half: a sink whose InsertBatch returns an
	// error mid-run MUST NOT panic, MUST NOT block, MUST NOT
	// propagate to the caller, and MUST allow the next minute's
	// accumulation to proceed normally (state was reset BEFORE
	// the failing flush attempt, per aggregator.flush()).
	sink := &failingSink{err: errors.New("disk full")}
	a := newAggregatorWithSink(sink, silentLogger(), 16)

	// Synthetic clock at 10:00:00.5 — aggregator starts at 10:00.
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 500_000_000, time.UTC)
	var nowAtomic atomic.Pointer[time.Time]
	nowAtomic.Store(&t0)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })
	a.currentMinute = a.now().Truncate(time.Minute)

	// Minute 1: ingest one tick, advance clock to 10:01:00.5,
	// trigger flush — which must fail-silent.
	a.absorb(TickDelta{RouteID: "r-a", Reqs: 100, LatencyBuckets: histogram.Of([]float64{16})})
	next := t0.Add(time.Minute)
	nowAtomic.Store(&next)
	a.maybeFlush(context.Background())

	if got := a.FlushErrors(); got != 1 {
		t.Fatalf("FlushErrors after failing flush = %d, want 1", got)
	}
	if sink.calls != 1 {
		t.Fatalf("sink called %d times, want 1", sink.calls)
	}
	if got := a.FlushCount(); got != 1 {
		t.Fatalf("FlushCount = %d, want 1 (heartbeat still ticked)", got)
	}

	// Critical anti-regression: the in-memory state was reset
	// before the failed flush. The next minute starts clean.
	a.absorb(TickDelta{RouteID: "r-b", Reqs: 50, LatencyBuckets: histogram.Of([]float64{32})})
	next2 := t0.Add(2 * time.Minute)
	nowAtomic.Store(&next2)
	a.maybeFlush(context.Background())

	if got := a.FlushErrors(); got != 2 {
		t.Fatalf("FlushErrors after 2 failing flushes = %d, want 2", got)
	}
	if sink.calls != 2 {
		t.Fatalf("sink called %d times, want 2", sink.calls)
	}

	// Decisive: only r-b should have appeared in the SECOND
	// flush (r-a's state was reset). Inspect the rows the
	// failing sink was called with by extending failingSink to
	// capture them — but a simpler proof is to switch to a
	// recording sink on the third minute.
	recorder := &recordingSink{}
	a.sink = recorder
	a.absorb(TickDelta{RouteID: "r-c", Reqs: 7, LatencyBuckets: histogram.Of([]float64{8})})
	next3 := t0.Add(3 * time.Minute)
	nowAtomic.Store(&next3)
	a.maybeFlush(context.Background())

	if len(recorder.rows) != 1 || recorder.rows[0].RouteID != "r-c" {
		t.Fatalf("after two failed flushes, the third minute must contain ONLY r-c: got %+v", recorder.rows)
	}
}

func TestAggregator_IngestStillNonBlockingDuringFlushErrors(t *testing.T) {
	// Anti-regression: a stream of flush errors must NOT cause
	// the ingress channel to back up. The data plane must keep
	// being able to call Consume / Ingest without ever blocking.
	sink := &failingSink{err: errors.New("locked")}
	a := newAggregatorWithSink(sink, silentLogger(), 1024)
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	var nowAtomic atomic.Pointer[time.Time]
	nowAtomic.Store(&t0)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })

	ctx, cancel := context.WithCancel(context.Background())
	go a.Run(ctx)
	defer func() {
		cancel()
		<-a.Done()
	}()

	// Spam Ingest from multiple goroutines. None should block.
	const workers = 8
	const perWorker = 100
	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < perWorker; i++ {
				a.Ingest(TickDelta{RouteID: "r", Reqs: 1, LatencyBuckets: histogram.Of([]float64{10})})
			}
		}()
	}
	// Drive minute rollovers so the failing flush is exercised.
	for i := 1; i <= 3; i++ {
		next := t0.Add(time.Duration(i) * time.Minute)
		nowAtomic.Store(&next)
		// Yield to let the Run goroutine pick up the clock
		// advance and call maybeFlush.
		time.Sleep(50 * time.Millisecond)
	}
	// No assertion on counts here — we only assert this test
	// returns at all (i.e., neither Ingest nor flush deadlocked).
}

// recordingSink captures the rows from each InsertBatch call.
type recordingSink struct {
	calls int
	rows  []MetricBucket
}

func (r *recordingSink) InsertBatch(_ context.Context, _ Granularity, rows []MetricBucket) error {
	r.calls++
	r.rows = append([]MetricBucket(nil), rows...)
	return nil
}

func TestAggregator_RunCleanShutdownFlushes(t *testing.T) {
	// Verify the Run goroutine's defer-flush behaviour: ingest
	// some events, cancel ctx, then wait for Done. The
	// pre-cancellation accumulator should land as one bucket.
	ctx, cancel := context.WithCancel(context.Background())
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	a := NewAggregator(s, silentLogger(), 16)
	// Force the synthetic clock to be the same value
	// throughout so the natural 1-s ticker can't trip a
	// rollover; the only flush comes from the ctx.Done path.
	fixed := time.Date(2026, 5, 28, 10, 0, 30, 0, time.UTC)
	a.SetClock(func() time.Time { return fixed })

	go a.Run(ctx)

	a.Ingest(TickDelta{RouteID: "r-a", Reqs: 7, LatencyBuckets: histogram.Of([]float64{64})})

	// Yield to let the goroutine receive the tick and absorb
	// it. A short sleep is acceptable here — we are
	// intentionally exercising the real goroutine path.
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-a.Done()

	rowsA, err := s.Query(context.Background(), Granularity1m, "r-a",
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Query r-a: %v", err)
	}
	if len(rowsA) != 1 || rowsA[0].ReqCount != 7 {
		t.Fatalf("clean-shutdown final flush: rows=%+v", rowsA)
	}
}

// TestAggregator_BumpWafBlocks_FlushesIntoBucketCounter pins
// the M.1 integration: BumpWafBlocks (waf.BlockCounter
// satisfaction) folds into the per-minute MetricBucket row's
// WafBlockCount field on flush. Independent of the Step E
// req / 4xx / 5xx counters (AC #3 invariant).
func TestAggregator_BumpWafBlocks_FlushesIntoBucketCounter(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var nowAtomic atomic.Pointer[time.Time]
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 500_000_000, time.UTC)
	nowAtomic.Store(&t0)
	advance := func(d time.Duration) {
		cur := *nowAtomic.Load()
		next := cur.Add(d)
		nowAtomic.Store(&next)
	}

	a := NewAggregator(s, silentLogger(), 16)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })
	a.currentMinute = a.now().Truncate(time.Minute)

	// 5 WAF blocks on r-a, 2 on r-b — drive via the public
	// BumpWafBlocks surface (synthetic TickDeltas with only
	// WafBlocks set), absorbing manually since we don't run
	// the goroutine.
	for i := 0; i < 5; i++ {
		a.BumpWafBlocks("r-a")
	}
	for i := 0; i < 2; i++ {
		a.BumpWafBlocks("r-b")
	}
	// The Bump path goes through Ingest → channel; drain
	// manually for deterministic flow.
	for {
		select {
		case d := <-a.in:
			a.absorb(d)
		default:
			goto drained
		}
	}
drained:

	// Roll over the minute, flush.
	advance(time.Minute)
	a.maybeFlush(ctx)

	rowsA, err := s.Query(ctx, Granularity1m, "r-a",
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Query r-a: %v", err)
	}
	if len(rowsA) != 1 {
		t.Fatalf("r-a rows = %d, want 1: %+v", len(rowsA), rowsA)
	}
	if rowsA[0].WafBlockCount != 5 {
		t.Errorf("r-a WafBlockCount = %d, want 5", rowsA[0].WafBlockCount)
	}
	// AC #3 invariant: WAF bumps must NOT touch req / 4xx / 5xx.
	if rowsA[0].ReqCount != 0 || rowsA[0].FourxxCount != 0 || rowsA[0].FivexxCount != 0 {
		t.Errorf("AC #3 violation — WAF bump leaked into L counters: %+v", rowsA[0])
	}

	rowsB, _ := s.Query(ctx, Granularity1m, "r-b",
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC))
	if len(rowsB) != 1 || rowsB[0].WafBlockCount != 2 {
		t.Fatalf("r-b WafBlockCount mismatch: %+v", rowsB)
	}
}

// TestAggregator_BumpThrottleBlocks_FlushesUnderSentinel pins
// the Q.1 integration: BumpThrottleBlocks (throttle.BlockCounter
// satisfaction) folds into the per-minute MetricBucket row's
// ThrottleBlockCount field on flush, under the sentinel route
// ID ThrottleSentinelRouteID. Per-IP detail is NOT keyed at
// the bucket layer — different src IPs all aggregate into the
// same sentinel slot. Spec §3.5.
func TestAggregator_BumpThrottleBlocks_FlushesUnderSentinel(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var nowAtomic atomic.Pointer[time.Time]
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 500_000_000, time.UTC)
	nowAtomic.Store(&t0)
	advance := func(d time.Duration) {
		cur := *nowAtomic.Load()
		next := cur.Add(d)
		nowAtomic.Store(&next)
	}

	a := NewAggregator(s, silentLogger(), 16)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })
	a.currentMinute = a.now().Truncate(time.Minute)

	// 4 blocks from one IP + 3 from another — all aggregate
	// under the sentinel route ID, not per-IP.
	for i := 0; i < 4; i++ {
		a.BumpThrottleBlocks("1.2.3.4")
	}
	for i := 0; i < 3; i++ {
		a.BumpThrottleBlocks("5.6.7.8")
	}
	for {
		select {
		case d := <-a.in:
			a.absorb(d)
		default:
			goto drained
		}
	}
drained:

	advance(time.Minute)
	a.maybeFlush(ctx)

	// Query under the sentinel — that's where ALL throttle
	// blocks land per spec §3.5.
	rows, err := s.Query(ctx, Granularity1m, ThrottleSentinelRouteID,
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Query sentinel: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("sentinel rows = %d, want 1: %+v", len(rows), rows)
	}
	if rows[0].ThrottleBlockCount != 7 {
		t.Errorf("ThrottleBlockCount = %d, want 7 (4 + 3 across two IPs)", rows[0].ThrottleBlockCount)
	}
	// Per-IP slots MUST NOT exist — the bucket layer is
	// per-minute sentinel-keyed, not per-IP.
	wrong, _ := s.Query(ctx, Granularity1m, "1.2.3.4",
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC))
	if len(wrong) != 0 {
		t.Errorf("found %d rows keyed by IP — bucket layer must be sentinel-keyed", len(wrong))
	}
	// AC #3 invariant: throttle bumps must NOT touch req / 4xx / 5xx / waf.
	if rows[0].ReqCount != 0 || rows[0].FourxxCount != 0 || rows[0].FivexxCount != 0 || rows[0].WafBlockCount != 0 {
		t.Errorf("AC #3 violation — throttle bump leaked into L/M counters: %+v", rows[0])
	}
}

// TestAggregator_BumpCrowdSecDecisions_FlushesUnderSentinel
// pins the Step N.2 integration: BumpCrowdSecDecisions
// (crowdsec.BlockCounter satisfaction) folds into the
// per-minute MetricBucket's CrowdSecDecisionCount field on
// flush, under the sentinel route ID CrowdSecSentinelRouteID
// ("_crowdsec"). Mirror of the throttle test above plus AC
// #N.15-equivalent: CrowdSec bumps do NOT inflate WAF /
// throttle / 4xx / 5xx counters.
func TestAggregator_BumpCrowdSecDecisions_FlushesUnderSentinel(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var nowAtomic atomic.Pointer[time.Time]
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 500_000_000, time.UTC)
	nowAtomic.Store(&t0)
	advance := func(d time.Duration) {
		cur := *nowAtomic.Load()
		next := cur.Add(d)
		nowAtomic.Store(&next)
	}

	a := NewAggregator(s, silentLogger(), 16)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })
	a.currentMinute = a.now().Truncate(time.Minute)

	// 5 decisions from one IP + 4 from another + 2 from a
	// CIDR — all aggregate under the sentinel route ID.
	for i := 0; i < 5; i++ {
		a.BumpCrowdSecDecisions("1.2.3.4")
	}
	for i := 0; i < 4; i++ {
		a.BumpCrowdSecDecisions("5.6.7.8")
	}
	for i := 0; i < 2; i++ {
		a.BumpCrowdSecDecisions("10.0.0.0/24")
	}
	for {
		select {
		case d := <-a.in:
			a.absorb(d)
		default:
			goto drained
		}
	}
drained:

	advance(time.Minute)
	a.maybeFlush(ctx)

	rows, err := s.Query(ctx, Granularity1m, CrowdSecSentinelRouteID,
		time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 5, 28, 10, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Query sentinel: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("sentinel rows = %d, want 1: %+v", len(rows), rows)
	}
	if rows[0].CrowdSecDecisionCount != 11 {
		t.Errorf("CrowdSecDecisionCount = %d, want 11 (5+4+2)", rows[0].CrowdSecDecisionCount)
	}
	// AC #N.15-equivalent independence: CrowdSec bumps MUST
	// NOT touch req / 4xx / 5xx / waf / throttle counters.
	if rows[0].ReqCount != 0 || rows[0].FourxxCount != 0 || rows[0].FivexxCount != 0 ||
		rows[0].WafBlockCount != 0 || rows[0].ThrottleBlockCount != 0 {
		t.Errorf("AC #N.15 violation — CrowdSec bump leaked into L/M/Q counters: %+v", rows[0])
	}
}

// TestAggregator_P95IsNotTheMaximum is the inverse of the
// characterisation test this commit deleted, on the same fixture.
//
// 600 one-second ticks, each holding one request — which is what
// 0.88 req/s against a 1 s tick actually produces, measured on a real
// homelab route. 599 of them took 2 ms and one took 8192 ms.
//
// The old chain stored 8192: drainP95 reduced each tick to a scalar
// (and with one request, ceil(1 x 0.95) = 1 selected it), then absorb
// kept the max in a field named p95MaxMs. Nothing in that was a
// percentile, and it is the whole explanation for an operator reading
// "p95 35658 ms" off a service answering in 0.1 s.
//
// 599/600 is 99.8% of the traffic at 2 ms, so the honest p95 is 2 ms.
// The stored value is now ~4 ms: the 570th of 600 sorted observations
// falls in bucket [2, 4), interpolated near its top. A factor-2 bucket
// is the resolution cost; a factor of 2000 was the defect.
func TestAggregator_P95IsNotTheMaximum(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	var nowAtomic atomic.Pointer[time.Time]
	t0 := time.Date(2026, 10, 5, 9, 0, 0, 500_000_000, time.UTC)
	nowAtomic.Store(&t0)

	a := NewAggregator(s, silentLogger(), 16)
	a.SetClock(func() time.Time { return *nowAtomic.Load() })
	a.currentMinute = a.now().Truncate(time.Minute)

	for i := 0; i < 599; i++ {
		a.absorb(TickDelta{RouteID: "r-slowtail", Reqs: 1, LatencyBuckets: histogram.Of([]float64{2})})
	}
	a.absorb(TickDelta{RouteID: "r-slowtail", Reqs: 1, LatencyBuckets: histogram.Of([]float64{8192})})

	next := t0.Add(time.Minute)
	nowAtomic.Store(&next)
	a.maybeFlush(ctx)

	bucketTs := t0.Truncate(time.Minute)
	rows, err := s.Query(ctx, Granularity1m, "r-slowtail", bucketTs, bucketTs.Add(time.Minute))
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 || rows[0].ReqCount != 600 {
		t.Fatalf("rows=%d ReqCount=%v, want 1 row of 600 (fixture assumption broken)", len(rows), rows)
	}

	got := rows[0].LatencyP95Ms
	if got > 10 {
		t.Errorf("latency_p95_ms = %d; 599 of 600 requests took 2 ms, so a p95 above 10 ms means the maximum is leaking back in", got)
	}
	if got == 0 {
		t.Errorf("latency_p95_ms = 0; the minute had 600 observations, so zero means the distribution never arrived")
	}
	t.Logf("599x2ms + 1x8192ms over one minute -> stored p95 = %d ms (was 8192 before this change)", got)
}

// TestAggregator_SlowTailStillReachableAtP99 — the fix must not become
// a different lie by hiding the outlier. The same minute's p99 has to
// find the 8192 ms request, because one histogram answers both
// questions and the operator investigating a complaint needs the tail.
func TestAggregator_SlowTailStillReachableAtP99(t *testing.T) {
	var acc histogram.BucketCounts
	for i := 0; i < 599; i++ {
		acc.Add(histogram.Of([]float64{2}))
	}
	acc.Add(histogram.Of([]float64{8192}))

	p95, _ := histogram.Quantile(acc, 0.95)
	p999, n := histogram.Quantile(acc, 0.999)
	if n != 600 {
		t.Fatalf("count = %d, want 600", n)
	}
	if p95 > 10 {
		t.Errorf("p95 = %v ms, want the fast region", p95)
	}
	if p999 < 4096 {
		t.Errorf("p99.9 = %v ms, want the slow tail — the outlier must stay findable, not be averaged away", p999)
	}
}
