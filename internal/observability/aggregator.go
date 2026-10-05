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
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/barto95100/arenet/internal/histogram"
	"github.com/barto95100/arenet/internal/metrics"
)

// TickDelta is one second of accumulated per-route counters
// produced by the Step E pipeline. Step 7 will wire the Step E
// Broadcaster to emit one of these per tick alongside its
// existing wire snapshot; the aggregator below consumes them
// via Ingest and produces minute buckets without ever touching
// the request path.
//
// Reqs, Fourxx, Fivexx are counts since the previous tick (NOT
// cumulative). LatencyBuckets is the tick's latency DISTRIBUTION.
//
// It replaced LatencyP95Ms, and with it the "percentile-of-
// percentiles approximation" the previous comment here cited from
// spec §3. That approximation was not an approximation: a percentile
// cannot be maximised, and taking max() across sixty one-second
// samples reported the slowest request of the minute under the name
// p95. At 0.88 req/s — measured, not assumed — a one-second tick holds
// zero or one request, so each "sample" was one request's duration
// rounded up to a power of two.
//
// Bucket counts sum exactly: the elementwise sum of two histograms is
// the histogram of the union of their samples. So the minute
// accumulates the distribution and the quantile is taken once, over
// everything, at flush and at read time.
type TickDelta struct {
	RouteID        string
	Reqs           uint64
	Fourxx         uint64
	Fivexx         uint64
	LatencyBuckets histogram.BucketCounts

	// TTFBBuckets is the time-to-first-byte distribution. Kept apart
	// from LatencyBuckets because latency runs to the last byte and so
	// carries the visitor's download time; TTFB stops when the
	// response committed. Its total can sit below Reqs — a hijacked
	// connection has no first byte to time.
	TTFBBuckets histogram.BucketCounts

	// BytesOut is response body bytes the wire accepted this tick.
	BytesOut uint64

	// Hijacked counts connections taken over (a WebSocket upgrade),
	// whose TTFB and bytes are unobservable rather than zero.
	Hijacked uint64

	// WafBlocks is the count of WAF block events to add to
	// the current minute's accumulator. Distinct from the
	// L counters (Reqs/Fourxx/Fivexx) because it flows from
	// a different observation point: the arenet_waf Caddy
	// module calls Aggregator.BumpWafBlocks(routeID) on
	// every block, which enqueues a synthetic TickDelta
	// with only WafBlocks set. Step E's Ticker.Consume
	// path never sets this field.
	WafBlocks uint64

	// WafDetects is the count of detect-mode WAF events to
	// add to the current minute's accumulator. Sibling to
	// WafBlocks; same observation point (waf.Sink.absorb
	// routes ActionBlock to BumpWafBlocks and ActionDetect
	// to BumpWafDetects). #R-DASHBOARD-WAF-COUNTERS-ZERO —
	// before this field, detect-mode events landed in the
	// waf_event table but never reached the bucket counter,
	// so the dashboard "WAF blocks / H" card and Top-Routes
	// column read 0 even when the operator had visible
	// events in /observability/logs.
	WafDetects uint64

	// ThrottleBlocks is the count of rate-limit block events
	// to add to the current minute's accumulator. Same shape
	// as WafBlocks but flows from a different observation
	// point: the auth handler's rate limiter calls
	// Aggregator.BumpThrottleBlocks(srcIP), which enqueues a
	// synthetic TickDelta with only ThrottleBlocks set AND
	// RouteID forced to ThrottleSentinelRouteID. The srcIP
	// is intentionally dropped at the bucket layer (per-IP
	// detail lives in the throttle_event table); the bucket
	// is a per-minute count under the sentinel route.
	// Spec §3.5.
	ThrottleBlocks uint64

	// CrowdSecDecisions is the count of NEW CrowdSec decisions
	// (dedupe-before-bump per Step N spec D4.A) to add to the
	// current minute's accumulator. Same shape as WafBlocks
	// and ThrottleBlocks but flows from a different
	// observation point: the parallel go-cs-bouncer.StreamBouncer
	// consumer in internal/crowdsec/stream.go calls
	// Aggregator.BumpCrowdSecDecisions(srcIP) on EVERY FIRST-
	// SIGHT decision UUID (not every absorb — the LRU in
	// crowdsec.Sink gates the bump). RouteID is forced to
	// CrowdSecSentinelRouteID. srcIP is dropped at the bucket
	// layer (per-IP detail lives in the decision_event table).
	// N spec §3.5.
	CrowdSecDecisions uint64

	// RateLimitExceeded (Step Z.3) is the count of HTTP
	// rate-limit (429) events emitted by mholt/caddy-ratelimit
	// for THIS specific route in the current minute. Unlike
	// ThrottleBlocks which lives under the "_throttle"
	// sentinel, this counter is per-route — the ratelimit.Sink
	// resolves the route via the "route-<UUID>" zone naming
	// convention before bumping. Powers the Z.3 per-route
	// timeseries chart on /security/[routeId]. The Z.1
	// ratelimit.Sink calls BumpRateLimitExceeded(routeID) on
	// every absorbed event ; events with empty routeID (zone
	// not following the convention) are skipped by the sink.
	RateLimitExceeded uint64
}

// ThrottleSentinelRouteID is the load-bearing convention from
// Step Q spec §3.5: throttle blocks aggregate into the bucket
// layer under a sentinel route ID that never collides with a
// real route. UUIDs don't start with an underscore, so
// "_throttle" is safe across the whole lifecycle of the
// system. The frontend's "throttle/min" stat card reads
// bucket rows WHERE route_id = ThrottleSentinelRouteID.
const ThrottleSentinelRouteID = "_throttle"

// CrowdSecSentinelRouteID is the Step N mirror of
// ThrottleSentinelRouteID: decision activity is per-IP (or
// per-CIDR / country / AS), not per-route, so it lands in a
// single per-minute slot keyed by this sentinel. N spec §3.5.
// "_crowdsec" — UUID prefix safety same as Q.
const CrowdSecSentinelRouteID = "_crowdsec"

// routeState is the aggregator's in-memory accumulator for one
// route between two minute boundaries. All access is serialised
// by the aggregator goroutine — no mutex needed.
//
// Step M: wafBlocks is the count of WAF block events emitted by
// the waf.Sink for this route in the current minute, fed via
// BumpWafBlocks (separate observation point from the Step E
// Ticker.Consume path — the new arenet_waf Caddy module owns
// the WAF observation point; see spec §3.3).
//
// Step Q: throttleBlocks is the count of rate-limit block
// events for this route in the current minute. In practice
// "this route" is the sentinel ThrottleSentinelRouteID — the
// throttle layer is per-IP, not per-route, and lands in a
// single per-minute slot under the sentinel. Spec §3.5.
type routeState struct {
	req               int64
	fourxx            int64
	fivexx            int64
	wafBlocks         int64
	wafDetects        int64
	throttleBlocks    int64
	crowdsecDecisions int64
	// Step Z.3 — per-route 429 counter. Bumped by the
	// ratelimit.Sink.absorb path (only when routeID != "" ;
	// zones not following the "route-<UUID>" convention
	// don't reach this counter).
	rateLimits int64
	// latency accumulates every tick's distribution for the minute.
	// Summed, not maximised — see TickDelta's comment for why max()
	// was never an approximation of a percentile.
	latency histogram.BucketCounts
	// ttfb accumulates the same way. Summed, never maximised.
	ttfb     histogram.BucketCounts
	bytesOut int64
	hijacked int64
	samples  int // number of non-empty 1-second samples
}

// bucketSink is the minimal write surface the aggregator depends
// on. Defined as an interface so AC #13 runtime-failure tests can
// inject a sink whose InsertBatch returns a synthetic error,
// proving the aggregator survives a flush error mid-run (the
// alternative — closing a real *Store and racing the test
// against `sql: database is closed`-style state — is brittle and
// touches real I/O).
//
// *Store satisfies this interface in production via its
// existing InsertBatch method. A nil sink is the degraded-mode
// case from AC #13 boot-failure path.
type bucketSink interface {
	InsertBatch(ctx context.Context, gran Granularity, rows []MetricBucket) error
}

// Aggregator accumulates per-second tick deltas into per-minute
// buckets and flushes them to the Store at minute boundaries.
//
// AC #13 invariants:
//   - Ingest is non-blocking: a slow flush goroutine never blocks
//     the producer (caller drops the tick if the channel is full,
//     visible via the Dropped() counter).
//   - Flush errors are logged + counted, never returned. A
//     persistent flush failure (locked DB, disk full) yields lost
//     buckets, not lost requests. The in-memory state is reset
//     BEFORE the flush attempt so a slow / failing flush does not
//     stall the next minute's accumulation.
//   - The Now func is injectable for synthetic-clock tests.
type Aggregator struct {
	sink   bucketSink
	logger *slog.Logger
	now    func() time.Time

	// in is the ingress channel. Buffered so a brief stall in
	// the aggregator goroutine doesn't propagate backpressure
	// to the Broadcaster.
	in chan TickDelta

	// state is owned by the goroutine. Indexed by routeID. A
	// route appears here only after its first non-zero tick.
	state map[string]*routeState

	// currentMinute is the truncated-to-minute timestamp of the
	// bucket currently being accumulated.
	currentMinute time.Time

	// metrics (test/debug only)
	mu        sync.Mutex
	dropped   uint64
	flushes   uint64
	flushErrs uint64

	done chan struct{}
}

// NewAggregator builds a fresh aggregator. store may be nil —
// this is the AC #13 degraded-mode case where the metrics DB
// failed to open at boot. The aggregator still accepts ticks
// (so the producer never blocks) but skips the flush.
//
// chanBuf sizes the ingress channel; 1024 is a sensible default
// (sufficient to ride out a ~1 s flush stall at >1000 events/s).
func NewAggregator(store *Store, logger *slog.Logger, chanBuf int) *Aggregator {
	return newAggregatorWithSink(toSink(store), logger, chanBuf)
}

// toSink lifts a *Store to a bucketSink, returning a nil
// interface (not a non-nil interface wrapping a nil *Store) when
// the store itself is nil. The distinction matters: `var s
// bucketSink = (*Store)(nil)` is non-nil to interface comparisons
// but would crash when InsertBatch is called.
func toSink(s *Store) bucketSink {
	if s == nil {
		return nil
	}
	return s
}

func newAggregatorWithSink(sink bucketSink, logger *slog.Logger, chanBuf int) *Aggregator {
	if logger == nil {
		logger = slog.Default()
	}
	if chanBuf < 1 {
		chanBuf = 1024
	}
	return &Aggregator{
		sink:   sink,
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		in:     make(chan TickDelta, chanBuf),
		state:  make(map[string]*routeState),
		done:   make(chan struct{}),
	}
}

// SetClock overrides the time source. For tests only — production
// uses the default time.Now().UTC().
func (a *Aggregator) SetClock(now func() time.Time) {
	a.now = now
}

// Ingest queues one tick delta for aggregation. Non-blocking:
// if the ingress channel is full, the tick is dropped and the
// dropped counter is incremented. The producer (Broadcaster
// tick) MUST stay on the request-adjacent goroutine and never
// block here — AC #13.
func (a *Aggregator) Ingest(d TickDelta) {
	select {
	case a.in <- d:
	default:
		a.mu.Lock()
		a.dropped++
		a.mu.Unlock()
	}
}

// BumpWafBlocks increments the WAF block counter for routeID
// in the current minute. Implements waf.BlockCounter; called
// by waf.Sink.absorb on every absorbed WAF event (even ones
// the LRU suppresses for event-table persistence). AC #3
// invariant: the per-minute counter reflects attack volume,
// not the de-duplicated event-log count.
//
// Non-blocking by construction: pushes onto the existing
// ingress channel as a synthetic TickDelta with only the
// WAF field set. Drops on full channel (counted via the
// existing Dropped counter). Same AC #13 discipline as
// Consume.
func (a *Aggregator) BumpWafBlocks(routeID string) {
	a.Ingest(TickDelta{RouteID: routeID, WafBlocks: 1})
}

// BumpWafDetects increments the WAF detect-mode counter
// for routeID in the current minute. Sibling to
// BumpWafBlocks; called by waf.Sink.absorb on every
// ActionDetect event (BEFORE the LRU dedup, AC #3
// invariant: the per-minute counter reflects attack
// volume, not the de-duplicated event-log count).
//
// #R-DASHBOARD-WAF-COUNTERS-ZERO — closes the bucket-
// counter gap. Pre-fix, detect-mode events landed in the
// waf_event table but never reached the bucket, so the
// /apercu "WAF blocks / H" and the Top-Routes column
// read 0 on detect-mode routes (the dominant case for
// homelab operators using the recommended I.4 default).
//
// Non-blocking by construction: pushes onto the existing
// ingress channel as a synthetic TickDelta with only the
// WafDetects field set. Drops on full channel (counted
// via the existing Dropped counter). Same AC #13
// discipline as Consume.
func (a *Aggregator) BumpWafDetects(routeID string) {
	a.Ingest(TickDelta{RouteID: routeID, WafDetects: 1})
}

// BumpThrottleBlocks increments the per-minute throttle block
// counter under the sentinel route ID. Implements
// throttle.BlockCounter; called by throttle.Sink.absorb on
// every absorbed rate-limit event (incl. LRU-suppressed) —
// same bump-then-suppress invariant as BumpWafBlocks.
//
// srcIP is accepted to match the throttle.BlockCounter
// signature but is intentionally NOT used as the aggregator
// key. Per-IP detail lives in the throttle_event table; the
// bucket layer is per-minute counts under a sentinel route.
// Spec §3.5: piggy-backs on the existing per-route flush path
// rather than introducing a new top-level aggregator slot.
//
// Non-blocking by construction. Same AC #13 discipline as
// BumpWafBlocks / Consume.
func (a *Aggregator) BumpThrottleBlocks(srcIP string) {
	_ = srcIP // intentionally unused — see doc comment.
	a.Ingest(TickDelta{RouteID: ThrottleSentinelRouteID, ThrottleBlocks: 1})
}

// BumpCrowdSecDecisions increments the per-minute decision
// counter under the sentinel route ID. Implements
// crowdsec.BlockCounter; called by crowdsec.Sink.absorbEmit
// on FIRST SIGHT of a decision UUID (the LRU in the sink
// dedupes BEFORE this counter bump — that's the Step N spec
// D4.A structural inversion vs M/Q where the LRU dedupes
// AFTER the bump).
//
// srcIP is the bouncer-observed `value` from the LAPI
// decision (IP, CIDR, country code, or AS — depends on
// scope). Accepted to match the crowdsec.BlockCounter
// signature but intentionally NOT used as the aggregator
// key. Per-IP / per-CIDR detail lives in the decision_event
// table; the bucket layer is per-minute counts under a
// sentinel route. N spec §3.5: piggy-backs on the existing
// per-route flush path rather than introducing a new
// top-level aggregator slot.
//
// Non-blocking by construction. Same AC #13 discipline as
// BumpThrottleBlocks / BumpWafBlocks / Consume.
func (a *Aggregator) BumpCrowdSecDecisions(srcIP string) {
	_ = srcIP // intentionally unused — see doc comment.
	a.Ingest(TickDelta{RouteID: CrowdSecSentinelRouteID, CrowdSecDecisions: 1})
}

// BumpRateLimitExceeded (Step Z.3) increments the per-route
// HTTP rate-limit counter under the real route UUID. Unlike
// BumpThrottleBlocks / BumpCrowdSecDecisions which key under
// a "_throttle" / "_crowdsec" sentinel, this counter uses
// the actual route UUID — the Z.1 ratelimit.Sink resolves
// the route from the upstream caddy-ratelimit zone name
// ("route-<UUID>" convention) BEFORE calling this method,
// and skips the call when routeID == "" (operator-hand-
// crafted Caddy zones that bypass the Arenet emit path).
//
// Implements ratelimit.BucketCounter ; called by
// ratelimit.Sink.absorb on every absorbed event.
//
// Non-blocking by construction. Same AC #13 discipline as
// BumpThrottleBlocks / BumpWafBlocks / Consume.
func (a *Aggregator) BumpRateLimitExceeded(routeID string) {
	if routeID == "" {
		return
	}
	a.Ingest(TickDelta{RouteID: routeID, RateLimitExceeded: 1})
}

// Consume implements metrics.TickConsumer. Adapter so the Step E
// ticker can fan its per-route deltas out to the observability
// pipeline without an import-direction reversal (internal/metrics
// never imports internal/observability).
//
// Non-blocking by construction: delegates to Ingest, which drops
// silently when the ingress channel is full (AC #13).
func (a *Aggregator) Consume(routeID string, d metrics.Delta) {
	a.Ingest(TickDelta{
		RouteID:        routeID,
		Reqs:           d.Reqs,
		Fourxx:         d.Errs4xx,
		Fivexx:         d.Errs,
		LatencyBuckets: d.LatencyBuckets,
		TTFBBuckets:    d.TTFBBuckets,
		BytesOut:       d.BytesOut,
		Hijacked:       d.Hijacked,
	})
}

// FlushNow flushes whatever has accumulated in the current
// minute, immediately. Used by tests and by a clean shutdown
// path that wants to persist the partial bucket.
func (a *Aggregator) FlushNow(ctx context.Context) {
	a.flush(ctx)
}

// Dropped returns the number of ticks dropped because the
// ingress channel was full. Cumulative since aggregator start.
func (a *Aggregator) Dropped() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// FlushCount returns the number of successful flush cycles
// completed (including empty flushes). Test helper.
func (a *Aggregator) FlushCount() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flushes
}

// FlushErrors returns the number of flush attempts that failed.
// AC #13: failures are counted, never propagated to the request
// path.
func (a *Aggregator) FlushErrors() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flushErrs
}

// Run drives the aggregator goroutine until ctx is cancelled.
// On cancellation, performs one final flush so the partial
// bucket isn't lost.
//
// Wrapped in a recover() per AC #13: a panic inside the
// aggregator must not bring down the proxy. The panic is
// logged at error level and the goroutine exits — the request
// path keeps running with the in-memory Step E counters only.
func (a *Aggregator) Run(ctx context.Context) {
	defer close(a.done)
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("observability: aggregator panic; metrics disabled for the rest of this process",
				slog.Any("panic", r),
			)
		}
	}()

	a.currentMinute = a.now().Truncate(time.Minute)

	// Internal tick at 1 s: drives the minute-boundary check.
	// Production aggregator polls a.now() on each tick rather
	// than relying on time.NewTicker so synthetic-clock tests
	// can advance the clock between Ingest calls without a real
	// goroutine sleep.
	checkTicker := time.NewTicker(time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.flush(context.Background())
			return
		case d := <-a.in:
			a.absorb(d)
			a.maybeFlush(ctx)
		case <-checkTicker.C:
			a.maybeFlush(ctx)
		}
	}
}

// Done returns a channel that closes once Run has exited
// (after the final flush). Test helper for clean teardown.
func (a *Aggregator) Done() <-chan struct{} {
	return a.done
}

// absorb folds one tick delta into the current minute's
// accumulator state. Goroutine-local, no locking.
func (a *Aggregator) absorb(d TickDelta) {
	if d.RouteID == "" {
		return
	}
	rs, ok := a.state[d.RouteID]
	if !ok {
		rs = &routeState{}
		a.state[d.RouteID] = rs
	}
	rs.req += int64(d.Reqs)
	rs.fourxx += int64(d.Fourxx)
	rs.fivexx += int64(d.Fivexx)
	rs.wafBlocks += int64(d.WafBlocks)
	rs.wafDetects += int64(d.WafDetects)
	rs.throttleBlocks += int64(d.ThrottleBlocks)
	rs.crowdsecDecisions += int64(d.CrowdSecDecisions)
	rs.rateLimits += int64(d.RateLimitExceeded)
	rs.latency.Add(d.LatencyBuckets)
	rs.ttfb.Add(d.TTFBBuckets)
	rs.bytesOut += int64(d.BytesOut)
	rs.hijacked += int64(d.Hijacked)
	if d.Reqs > 0 {
		rs.samples++
	}
}

// maybeFlush checks whether the wall-clock minute has rolled
// over since the last flush, and if so, persists the
// accumulator and resets. Cheap when no rollover happened.
func (a *Aggregator) maybeFlush(ctx context.Context) {
	nowMin := a.now().Truncate(time.Minute)
	if !nowMin.After(a.currentMinute) {
		return
	}
	a.flush(ctx)
	a.currentMinute = nowMin
}

// flush serialises the in-memory accumulator to one batched
// insert and resets state. AC #13: errors are logged + counted,
// never returned. A nil store (degraded mode) results in a
// silent no-op flush — the state is still reset so the next
// minute starts clean.
func (a *Aggregator) flush(ctx context.Context) {
	a.mu.Lock()
	a.flushes++
	a.mu.Unlock()

	if len(a.state) == 0 {
		return
	}
	rows := make([]MetricBucket, 0, len(a.state))
	for id, rs := range a.state {
		rows = append(rows, MetricBucket{
			RouteID:               id,
			Ts:                    a.currentMinute,
			ReqCount:              rs.req,
			FourxxCount:           rs.fourxx,
			FivexxCount:           rs.fivexx,
			WafBlockCount:         rs.wafBlocks,
			WafDetectCount:        rs.wafDetects,
			ThrottleBlockCount:    rs.throttleBlocks,
			CrowdSecDecisionCount: rs.crowdsecDecisions,
			RateLimitCount:        rs.rateLimits,
			// A real p95, computed once over the minute's whole
			// distribution. The column keeps its name and its type so
			// every existing reader — the dashboard, the timeseries,
			// the route panel — keeps working and simply starts
			// receiving true values.
			LatencyP95Ms: p95FromBuckets(rs.latency),
		})
	}
	// Reset before the write so a slow / failing flush doesn't
	// stall the next minute's accumulation.
	a.state = make(map[string]*routeState, len(rows))

	if a.sink == nil {
		// Degraded mode: log once per flush at debug level so
		// we don't spam at error level for the whole process
		// lifetime.
		a.logger.Debug("observability: aggregator flush skipped (sink disabled)",
			slog.Int("rows", len(rows)),
		)
		return
	}
	if err := a.sink.InsertBatch(ctx, Granularity1m, rows); err != nil {
		a.mu.Lock()
		a.flushErrs++
		a.mu.Unlock()
		a.logger.Error("observability: aggregator flush failed",
			slog.String("err", err.Error()),
			slog.Int("rows", len(rows)),
		)
	}
}

// p95FromBuckets reduces a minute's accumulated distribution to the
// int32 the bucket row carries.
//
// Rounds rather than truncates: truncation biases every value down by
// up to a millisecond, invisible at 300 ms and absurd at 2 ms. Returns
// 0 when nothing was observed, which is what the column has always
// meant by "no traffic" — and why the API layer must keep reporting
// null rather than 0 for a route with no samples.
func p95FromBuckets(b histogram.BucketCounts) int32 {
	v, n := histogram.Quantile(b, 0.95)
	if n == 0 {
		return 0
	}
	return int32(math.Round(v))
}
