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
	"sync"
	"sync/atomic"

	"github.com/barto95100/arenet/internal/histogram"
)

// Registry holds per-route request and 5xx-error counters with
// concurrency semantics specified in §4 of the Step E spec:
//
//   - Inc is the hot path: RLock + atomic add. Called once per
//     proxied HTTP request, must not allocate (bench < 200 ns
//     per op, allocs/op == 0).
//   - Snapshot runs at 1 Hz from the Ticker goroutine: RLock +
//     atomic.SwapUint64 per cell, returns a fresh map of Deltas
//     (count since previous tick, NOT cumulative — spec §11.9).
//   - Sync runs on each Caddy reload (rare): Lock, then inserts
//     new cells and deletes stale ones in a single critical
//     section regardless of the diff size (spec §4.1).
//
// The Read/Write mutex pattern lets Inc and Snapshot proceed in
// parallel; Sync is the only writer. Inc and Snapshot are correct
// concurrently because each cell field is mutated with atomic
// operations independently of the lock. The lock only protects the
// map's structure (key add/remove), not the cell contents.
//
// The pair (reqs, errs) is NOT atomic together; spec §11.8 documents
// the rare race and the client-side mitigation (errRate clamp).
type Registry struct {
	mu    sync.RWMutex
	cells map[string]*counterCell

	// hostCells holds per-(routeID, host) counters introduced by
	// Topology Plan B Phase 1. Outer key = routeID, inner key =
	// lowercased + port-stripped host (matched against the route's
	// known-hosts set by the middleware before bumping).
	//
	// Lifecycle:
	//   - Outer key created lazily by IncByHost on the first valid
	//     hit for a (routeID, host) pair the middleware accepts.
	//   - Outer key dropped by Sync when the routeID disappears
	//     (same as the route-level cells map). The inner map is
	//     released with the outer.
	//   - Inner cells are not individually pruned: a route may
	//     stop receiving traffic for one of its aliases without
	//     the operator removing the alias. The host-set is bounded
	//     by storage.Route.Aliases length (max ~tens per route on
	//     a homelab), so unbounded growth is not a risk.
	//
	// Snapshot drains the inner cells alongside the route cells.
	// The per-host counter is ADDITIONAL — the route cell is
	// ALWAYS bumped on every request, the host cell only when
	// the middleware passes a non-empty host argument.
	hostCells map[string]map[string]*counterCell
}

// counterCell holds the atomic counters for a single route. Counter
// fields are accessed exclusively via the sync/atomic package; bare
// reads/writes are forbidden by go vet's copylocks/atomic checks
// (and would race under -race).
//
// counterCell is heap-allocated via NewRegistry and Sync; the map
// stores pointers so Inc can update fields without re-inserting.
//
// Step L additions (additive, no Step E regression):
//   - errs4xx tracks 4xx responses separately from errs (5xx).
//   - latency is a fixed-bucket histogram populated by Inc on the
//     hot path. Snapshot drains it into a per-tick p95 value;
//     hot-path cost stays atomic-only (no allocation, no lock).
type counterCell struct {
	reqs    uint64 // total requests since last Snapshot
	errs    uint64 // 5xx responses since last Snapshot (Step E name preserved)
	errs4xx uint64 // 4xx responses since last Snapshot (Step L)
	latency latencyHist
}

// latencyHist is the metrics-package-internal copy of the
// observability.LatencyHistogram contract. Duplicated rather than
// imported to keep internal/metrics independent of
// internal/observability — preserves the spec's clean dependency
// direction (metrics → nothing; observability → metrics indirectly,
// via main.go wiring, never via import).
//
// 17 log-spaced buckets covering [0.5 ms, 65536 ms). See
// internal/observability/histogram.go for the design rationale —
// the bucket layout is identical so a future refactor (if we ever
// move the histogram into a shared internal/histogram package)
// is a rename, not a semantic change.
type latencyHist struct {
	counts [histogram.Buckets]uint64
}

func (h *latencyHist) observe(durMs float64) {
	const baseMs = histogram.BaseMs
	idx := 0
	switch {
	case durMs < baseMs:
		idx = 0
	default:
		// log2(durMs / baseMs) clamped to [0, Buckets-1].
		x := durMs / baseMs
		// Fast log2-of-float via repeated halving; avoids math.Log2
		// to keep the hot path free of any FP transcendental cost.
		// For our range (0.5 ms .. 65536 ms = factor 131072 = 2^17),
		// 17 iterations is the worst case.
		for x >= 2 && idx < histogram.Buckets-1 {
			x /= 2
			idx++
		}
	}
	atomic.AddUint64(&h.counts[idx], 1)
}

// drainBuckets returns the latency distribution accumulated since the
// previous drain and resets every bucket to zero in one pass.
//
// It replaces drainP95, which reduced each tick to a single scalar
// percentile. That reduction was the first of four invalid aggregation
// steps: a percentile cannot be summed, averaged or maximised, and the
// chain downstream did all three. At the 0.88 req/s measured on a real
// homelab route a one-second tick holds zero or one request, so the
// "p95" it produced was that single request's duration rounded up to a
// power of two — the whole explanation for "p95 35658 ms" on a service
// that was answering in 0.1 s.
//
// Bucket counts, unlike percentiles, sum exactly: the elementwise sum
// of two histograms IS the histogram of the union of their samples
// (proved in internal/histogram's G1 property test). So the quantile is
// computed once, at read time, over everything.
//
// Goroutine-local read pattern (called only by Snapshot, which already
// holds the RLock protecting the map structure); within each cell we
// atomic.Swap each bucket so a concurrent observe() either lands in
// this drain or in the next tick. Nothing is lost either way.
func (h *latencyHist) drainBuckets() histogram.BucketCounts {
	var out histogram.BucketCounts
	for i := range h.counts {
		out[i] = atomic.SwapUint64(&h.counts[i], 0)
	}
	return out
}

// NewRegistry returns an empty Registry. The Caddy module's
// Provision call (Chunk 2) is expected to obtain a *Registry via
// the package-level singleton (global.go), not by calling
// NewRegistry directly except in tests and in cmd/arenet's main.
func NewRegistry() *Registry {
	return &Registry{
		cells:     make(map[string]*counterCell),
		hostCells: make(map[string]map[string]*counterCell),
	}
}

// Inc records a single request against routeID with the given HTTP
// status code and duration. Increments reqs unconditionally;
// classifies 5xx into errs and 4xx into errs4xx separately (Step L
// AC #3: 4xx and 5xx must NEVER share a counter). Records the
// duration into the cell's latency histogram for p95 computation
// at the next Snapshot.
//
// If routeID is unknown to the Registry, the call is a SILENT
// no-op (spec §11.1: the brief race window between route deletion
// and Caddy reload completion is intentionally tolerated rather
// than erroring).
//
// Hot path. Must not allocate, must not perform I/O. AC #13: a
// metrics-DB failure later in the pipeline must not propagate
// here — Inc only mutates in-memory atomic state.
func (r *Registry) Inc(routeID string, status int, durMs float64) {
	r.mu.RLock()
	cell, ok := r.cells[routeID]
	r.mu.RUnlock()
	if !ok {
		return
	}
	atomic.AddUint64(&cell.reqs, 1)
	switch {
	case status >= 500:
		atomic.AddUint64(&cell.errs, 1)
	case status >= 400:
		atomic.AddUint64(&cell.errs4xx, 1)
	}
	cell.latency.observe(durMs)
}

// IncByHost records a single request against routeID AND, when host
// is non-empty, against the (routeID, host) pair. Topology Plan B
// Phase 1.
//
// Semantics:
//   - The route-level cell is ALWAYS bumped (same as Inc), so a
//     request whose Host header doesn't match any known host still
//     counts at the route level. The route counter remains the
//     authoritative request total.
//   - The host-level cell is bumped ONLY when host is non-empty.
//     The middleware passes "" when r.Host fails the membership
//     check against the route's known-hosts set, so the host cell
//     is never created for unrecognised values.
//   - Host string must already be normalised (lowercased,
//     port-stripped). Defensive normalisation here would mask
//     middleware bugs; the contract is that the caller has done
//     the work.
//
// If routeID is unknown to the Registry, the entire call is a
// silent no-op (same semantics as Inc).
//
// Hot path. No allocation in the steady-state (the hostCells inner
// map is created lazily on the first hit for a host; subsequent
// hits use the cached cell pointer via the RLock + atomic add
// pattern).
func (r *Registry) IncByHost(routeID, host string, status int, durMs float64) {
	r.mu.RLock()
	routeCell, ok := r.cells[routeID]
	if !ok {
		r.mu.RUnlock()
		return
	}
	var hostCell *counterCell
	if host != "" {
		if inner, hasInner := r.hostCells[routeID]; hasInner {
			hostCell = inner[host]
		}
	}
	r.mu.RUnlock()

	// Route-level bump (always).
	atomic.AddUint64(&routeCell.reqs, 1)
	switch {
	case status >= 500:
		atomic.AddUint64(&routeCell.errs, 1)
	case status >= 400:
		atomic.AddUint64(&routeCell.errs4xx, 1)
	}
	routeCell.latency.observe(durMs)

	if host == "" {
		return
	}

	// Lazy creation of the host cell on first hit. The double-check
	// pattern under the write lock is necessary because two
	// concurrent first-hits for the same (routeID, host) would
	// otherwise race on map insertion.
	if hostCell == nil {
		r.mu.Lock()
		// Re-check the route cell exists in case Sync ran between
		// the RUnlock above and the Lock here.
		if _, stillOK := r.cells[routeID]; !stillOK {
			r.mu.Unlock()
			return
		}
		inner, hasInner := r.hostCells[routeID]
		if !hasInner {
			inner = make(map[string]*counterCell, 1)
			r.hostCells[routeID] = inner
		}
		hostCell = inner[host]
		if hostCell == nil {
			hostCell = &counterCell{}
			inner[host] = hostCell
		}
		r.mu.Unlock()
	}

	atomic.AddUint64(&hostCell.reqs, 1)
	switch {
	case status >= 500:
		atomic.AddUint64(&hostCell.errs, 1)
	case status >= 400:
		atomic.AddUint64(&hostCell.errs4xx, 1)
	}
	hostCell.latency.observe(durMs)
}

// Sync reconciles the Registry's cells with the canonical list of
// current route IDs. Called by caddymgr after each successful Caddy
// reload (spec §4.1). One write-lock acquisition per reload,
// regardless of how many routes were added or removed.
//
// Cells preserved across the call (same routeID in both old and new
// set) retain their current counter values — a route updated
// in-place (same UUID, new upstream) keeps accumulating per §11.2.
//
// The function tolerates an empty routeIDs slice (drains all cells)
// and a nil slice (treated as empty).
func (r *Registry) Sync(routeIDs []string) {
	wanted := make(map[string]struct{}, len(routeIDs))
	for _, id := range routeIDs {
		wanted[id] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Insert cells for IDs in wanted but absent from r.cells.
	for id := range wanted {
		if _, exists := r.cells[id]; !exists {
			r.cells[id] = &counterCell{}
		}
	}
	// Delete cells for IDs in r.cells but absent from wanted.
	// Safe per Go spec: range over a map allows delete of current key.
	for id := range r.cells {
		if _, keep := wanted[id]; !keep {
			delete(r.cells, id)
		}
	}
	// Phase 1 — Topology Plan B: drop the per-host counters
	// belonging to routes that just disappeared. Inner maps are
	// released wholesale (no per-host pruning required — the host
	// set is bounded by the route's alias list, which the
	// middleware enforces via the KnownHosts membership check).
	for id := range r.hostCells {
		if _, keep := wanted[id]; !keep {
			delete(r.hostCells, id)
		}
	}
}

// Snapshot atomically swaps each cell's counters to zero and
// returns the deltas observed for this tick. Called by the Ticker
// at 1 Hz (spec §4.3).
//
// The RWMutex is read-locked so concurrent Inc calls proceed in
// parallel. The serialization point per cell is the
// atomic.SwapUint64 — the value returned is the count that
// accumulated since the previous Snapshot.
//
// NOT atomic across the (reqs, errs) pair within a single cell:
// spec §11.8 documents the symptom (a tick may show errs > reqs)
// and the client-side clamp that masks it. This implementation
// keeps the simple two-swap form because the next tick auto-corrects
// and the rare cosmetic spike is preferable to a per-cell mutex
// on the hot path.
//
// Returns a fresh, non-nil map; callers may retain it freely. An
// empty Registry returns an empty (non-nil) map.
//
// Step L addition: also drains errs4xx and the per-tick p95 from
// the latency histogram. The drain pattern is the same atomic
// swap-and-zero — consistent with Step E's existing semantics.
func (r *Registry) Snapshot() map[string]Delta {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]Delta, len(r.cells))
	for id, cell := range r.cells {
		reqs := atomic.SwapUint64(&cell.reqs, 0)
		errs := atomic.SwapUint64(&cell.errs, 0)
		errs4xx := atomic.SwapUint64(&cell.errs4xx, 0)
		out[id] = Delta{
			Reqs:           reqs,
			Errs:           errs,
			Errs4xx:        errs4xx,
			LatencyBuckets: cell.latency.drainBuckets(),
		}
	}
	return out
}

// SnapshotHosts returns the per-(routeID, host) deltas drained
// since the previous SnapshotHosts call. Topology Plan B Phase 1
// addition.
//
// Semantics mirror Snapshot exactly:
//   - One entry per (routeID, host) pair that has a cell. A cell
//     with zero counts is still returned — the consumer
//     (Phase 2 sliding window) decides whether to surface zero
//     rows or drop them.
//   - Atomic.Swap drain: a concurrent IncByHost either lands in
//     this drain or the next, no count is lost.
//   - The (Reqs, Errs) pair is not atomic together (same caveat as
//     route-level Snapshot, spec §11.8). Consumers apply the same
//     errRate clamp.
//
// Returns a fresh, non-nil slice. An empty Registry returns an
// empty (non-nil) slice. Iteration order is unspecified.
//
// SnapshotHosts and Snapshot are independent — each maintains its
// own drain state on its own cells. Calling them in either order
// at the same tick is correct; the route counter and the sum of
// its host counters will not strictly agree (the host-counter sum
// is ≤ route-counter, since requests with unrecognised Host
// headers still bump the route but not any host).
func (r *Registry) SnapshotHosts() []HostDelta {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]HostDelta, 0)
	for routeID, inner := range r.hostCells {
		for host, cell := range inner {
			reqs := atomic.SwapUint64(&cell.reqs, 0)
			errs := atomic.SwapUint64(&cell.errs, 0)
			errs4xx := atomic.SwapUint64(&cell.errs4xx, 0)
			out = append(out, HostDelta{
				RouteID:        routeID,
				Host:           host,
				Reqs:           reqs,
				Errs:           errs,
				Errs4xx:        errs4xx,
				LatencyBuckets: cell.latency.drainBuckets(),
			})
		}
	}
	return out
}
