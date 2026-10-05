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
	"context"
	"math"
	"time"

	"github.com/barto95100/arenet/internal/histogram"
)

// RouteLister returns the canonical list of routes for the current
// configuration. The Ticker calls it once per tick to join the
// Registry's deltas with route metadata (host, upstream) for the
// Snapshot wire shape (spec §5.2).
//
// The concrete implementation in production is a thin adapter over
// storage.Store.ListRoutes; an interface keeps this package
// decoupled from internal/storage and trivially mockable in tests.
type RouteLister interface {
	// ListRoutesForMetrics returns one entry per persisted route,
	// in the canonical order produced by storage. The ID, Host, and
	// Upstream fields are the only ones consumed.
	ListRoutesForMetrics(ctx context.Context) ([]RouteMetadata, error)
}

// RouteMetadata is the subset of storage.Route consumed by Ticker.
// Defined here so internal/metrics does not import internal/storage.
type RouteMetadata struct {
	ID       string
	Host     string
	Upstream string
}

// TickConsumer receives per-route deltas at every snapshot tick.
// Step L L.7 wiring: the observability.Aggregator implements this
// interface and folds the per-second deltas into per-minute
// buckets. Defined here so internal/metrics does not import
// internal/observability — the dependency direction stays
// metrics → nothing.
//
// AC #13 contract: Consume MUST be non-blocking and MUST NOT
// perform I/O on the calling goroutine (the ticker). A typical
// implementation pushes the tick onto a buffered channel that a
// separate goroutine drains; channel-full is a dropped tick, not a
// stall.
//
// The last parameter carries the tick's latency DISTRIBUTION rather
// than a percentile over it. A percentile cannot be summed, averaged
// or maximised, and the pipeline that received the old scalar did all
// three in turn. Bucket counts sum exactly, so the consumer can
// accumulate them for as long as it likes and take the quantile once,
// at read time, over the whole window.
//
// Still positional primitives plus the shared histogram type, because
// a struct would have to live somewhere both packages can import and
// the dependency direction above is worth more than the ergonomics.
type TickConsumer interface {
	Consume(routeID string, reqs, errs4xx, errs5xx uint64, latency histogram.BucketCounts)
}

// Ticker drives the per-tick snapshot loop (spec §4.3). On each tick
// it calls Registry.Snapshot, joins the deltas with the current
// route list, and publishes the resulting Snapshot to the broadcaster.
//
// Cancellation: Run honors ctx.Done() and returns promptly. Caller
// typically uses the cmd/arenet process context.
type Ticker struct {
	registry    *Registry
	broadcaster *Broadcaster
	lister      RouteLister
	consumer    TickConsumer // optional; nil disables the L.1 history fan-out
}

// NewTicker constructs a Ticker bound to the given registry,
// broadcaster, and route lister. All three are required; nil
// arguments panic at construction (programmer error, not a runtime
// condition).
func NewTicker(registry *Registry, broadcaster *Broadcaster, lister RouteLister) *Ticker {
	if registry == nil {
		panic("metrics.NewTicker: registry is nil")
	}
	if broadcaster == nil {
		panic("metrics.NewTicker: broadcaster is nil")
	}
	if lister == nil {
		panic("metrics.NewTicker: lister is nil")
	}
	return &Ticker{
		registry:    registry,
		broadcaster: broadcaster,
		lister:      lister,
	}
}

// SetConsumer attaches a TickConsumer that receives per-route
// deltas alongside the WebSocket broadcast. nil clears the
// consumer. Step L L.1 wires the observability.Aggregator here.
// Safe to call before Run; not safe to call after Run has started
// (the consumer is read without synchronisation from the tick
// loop). main.go calls this once during boot.
func (t *Ticker) SetConsumer(c TickConsumer) {
	t.consumer = c
}

// MakeSnapshotForTest is a test-only entry point that runs one
// tick of the Ticker's per-tick logic synchronously:
//   - Read Registry deltas
//   - Join with the route list
//   - Publish to the broadcaster
//   - Fan out to the TickConsumer (if any)
//
// Equivalent to one iteration of Run's select case at the given
// `now` timestamp, but deterministic — the caller controls when
// the snapshot happens. Used by the cross-package integration
// test in internal/observability to exercise the full
// metrics → observability seam without a real timer.
//
// Do NOT call from production code; the Run loop is the only
// caller in prod.
func (t *Ticker) MakeSnapshotForTest(ctx context.Context, now time.Time) Snapshot {
	snap := t.makeSnapshot(ctx, now)
	t.broadcaster.Publish(snap)
	return snap
}

// Run drives the snapshot loop until ctx is cancelled. Blocking;
// caller invokes it in a goroutine. Returns when ctx is done.
func (t *Ticker) Run(ctx context.Context) {
	tick := time.NewTicker(TickInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			snap := t.makeSnapshot(ctx, now)
			t.broadcaster.Publish(snap)
		}
	}
}

// makeSnapshot reads the Registry's deltas, joins them with the
// route list from the lister, and assembles the wire-shape Snapshot
// (spec §5.2). Idle routes — those present in the route list but
// absent from the Registry's snapshot, or present with zero counters
// — are still included with zero counters.
//
// On lister error, the snapshot still goes out but with an empty
// Routes slice. The client sees a tick with zero routes for one
// second; the next tick (when storage is healthy again) restores
// the normal listing. The error is not logged here — the lister
// implementation owns its own error logging.
func (t *Ticker) makeSnapshot(ctx context.Context, now time.Time) Snapshot {
	deltas := t.registry.Snapshot()
	// Topology Plan B Phase 2.2 — drain the per-host deltas
	// alongside the per-route ones. The two drains are
	// independent (each touches its own cells map), so calling
	// them sequentially is correct. Translation to the wire-
	// internal HostSnapshot shape happens here so subscribers
	// see a fully-assembled slice rather than the registry's
	// HostDelta primitive.
	hostDeltas := t.registry.SnapshotHosts()
	hosts := make([]HostSnapshot, 0, len(hostDeltas))
	for _, hd := range hostDeltas {
		hosts = append(hosts, HostSnapshot{
			RouteID: hd.RouteID,
			Host:    hd.Host,
			Reqs:    hd.Reqs,
			Errs:    hd.Errs,
			Errs4xx: hd.Errs4xx,
			// The topology ring still wants a scalar. It now gets a
			// REAL p95 over the tick's distribution, interpolated,
			// instead of the resolved bucket's upper edge. Renaming
			// the topology wire's p99LatencyMs is explicitly out of
			// scope for this change (see the plan's closing note).
			LatencyP95Ms: p95FromBuckets(hd.LatencyBuckets),
		})
	}

	routes, err := t.lister.ListRoutesForMetrics(ctx)
	if err != nil {
		return Snapshot{T: now.UTC(), Routes: []RouteSnapshot{}, Hosts: hosts}
	}

	out := make([]RouteSnapshot, 0, len(routes))
	for _, rt := range routes {
		d := deltas[rt.ID] // zero Delta if absent
		var errRate float64
		if d.Reqs > 0 {
			errRate = float64(d.Errs) / float64(d.Reqs)
			if errRate > 1.0 {
				errRate = 1.0 // §5.2 clamp guarantee
			}
		}
		out = append(out, RouteSnapshot{
			ID:         rt.ID,
			Host:       rt.Host,
			Upstream:   rt.Upstream,
			Reqs:       d.Reqs,
			Errs:       d.Errs,
			ReqPerSec:  d.Reqs, // == reqs since TickInterval == 1s (§5.2)
			ErrRate5xx: errRate,
		})
		// Step L L.7: fan the same delta out to the observability
		// aggregator if one is wired. Skip routes whose tick is
		// fully idle to keep the channel pressure low (the
		// aggregator's absorb() also ignores zero ReqCount).
		if t.consumer != nil && (d.Reqs > 0 || d.Errs > 0 || d.Errs4xx > 0) {
			t.consumer.Consume(rt.ID, d.Reqs, d.Errs4xx, d.Errs, d.LatencyBuckets)
		}
	}
	return Snapshot{T: now.UTC(), Routes: out, Hosts: hosts}
}

// p95FromBuckets reduces a tick's distribution to the int32 the
// topology snapshot wire still carries.
//
// Rounds rather than truncates: truncation would bias every value
// downward by up to a millisecond, which is invisible at 300 ms and
// absurd at 2 ms. Returns 0 for an empty histogram, which is what the
// wire has always meant by "no traffic this tick".
func p95FromBuckets(b histogram.BucketCounts) int32 {
	v, n := histogram.Quantile(b, 0.95)
	if n == 0 {
		return 0
	}
	return int32(math.Round(v))
}
