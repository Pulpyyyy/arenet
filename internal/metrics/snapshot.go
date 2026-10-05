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

// Package metrics implements the Step E per-route metrics pipeline:
// a Caddy middleware module increments atomic counters per matched
// route, a ticker snapshots them at 1 Hz, and a broadcaster fans out
// the snapshot to subscribed WebSocket clients.
//
// All public types in this file are pure data; behavior lives in
// registry.go, broadcaster.go, ticker.go.
//
// See docs/superpowers/specs/2026-05-18-step-e-topology-design.md
// (§4 and §5 in particular).
package metrics

import "github.com/barto95100/arenet/internal/histogram"

import "time"

// Delta is the per-route counter difference produced by one Snapshot
// call. Reqs and Errs are counts SINCE THE PREVIOUS TICK, not
// cumulative totals (spec §11.9). Errs counts 5xx responses
// (kept under that name for Step E wire-shape backward compat —
// the WebSocket clients read .Errs as the 5xx counter).
//
// Step L additions (additive, no Step E regression):
//   - Errs4xx tracks 4xx separately from 5xx (Step L spec §1.3 D1:
//     internet-exposed proxies need 4xx as a security/exposure
//     signal, not folded into "errors").
//   - LatencyP95Ms is the p95 over the per-route latency
//     histogram during the tick window. Zero when no samples
//     landed in this tick — the L.2 API projection layer maps
//     that to JSON null per AC #5 (a "0 ms p95" would render as
//     a fake latency dip on the timeline chart).
//
// Errs may transiently exceed Reqs for a single tick due to the
// non-paired-atomic swap in Registry.Snapshot (spec §11.8). The
// WebSocket wire layer is responsible for clamping errRate5xx to
// [0, 1] before sending; consumers of Delta directly must apply the
// same clamp if they compute a rate.
type Delta struct {
	Reqs    uint64 `json:"reqs"`
	Errs    uint64 `json:"errs"` // 5xx (Step E wire-shape name)
	Errs4xx uint64 `json:"errs4xx,omitempty"`
	// LatencyBuckets is the latency DISTRIBUTION observed during the
	// tick, not a percentile over it.
	//
	// It replaced LatencyP95Ms because a percentile is not an
	// aggregatable quantity: the pipeline downstream summed, averaged
	// and maximised it in turn, and all three operations are invalid.
	// Bucket counts sum exactly — the elementwise sum of two
	// histograms is the histogram of the union — so the quantile can
	// be taken once, at read time, over the whole window.
	LatencyBuckets histogram.BucketCounts `json:"-"`

	// TTFBBuckets is the time-to-first-byte distribution for the tick.
	// Separate from LatencyBuckets because the two measure different
	// things: latency runs to the last byte and so carries the
	// visitor's download time, TTFB stops when the response commits.
	// Its total can be below Reqs — a hijacked connection has no
	// first byte to time.
	TTFBBuckets histogram.BucketCounts `json:"-"`

	// BytesOut is response body bytes the wire accepted during the
	// tick. Headers and post-Hijack traffic excluded.
	BytesOut uint64 `json:"bytesOut,omitempty"`

	// Hijacked counts requests whose connection was taken over, whose
	// TTFB and bytes are unobservable rather than zero.
	Hijacked uint64 `json:"hijacked,omitempty"`
}

// HostDelta is the per-(routeID, host) counter difference produced
// by one SnapshotHosts call. Topology Plan B Phase 1 addition.
//
// Same counter semantics as Delta (per-tick reset, non-atomic
// (Reqs, Errs) pair). The RouteID + Host pair is the natural key
// the Phase 2 sliding window will index by; bundling them inside
// the value keeps the API symmetric with the per-route Snapshot
// (which uses the map key for routeID).
//
// HostDelta is emitted only for (routeID, host) pairs that received
// at least one IncByHost call with non-empty host since the cell
// was created. The Phase 1 middleware ensures host is non-empty
// only after a successful membership check against the route's
// KnownHosts set — so HostDelta entries are necessarily
// well-formed hostnames known to the storage layer.
type HostDelta struct {
	RouteID string `json:"routeId"`
	Host    string `json:"host"`
	Reqs    uint64 `json:"reqs"`
	Errs    uint64 `json:"errs"` // 5xx
	Errs4xx uint64 `json:"errs4xx,omitempty"`
	// LatencyBuckets is the latency DISTRIBUTION observed during the
	// tick, not a percentile over it.
	//
	// It replaced LatencyP95Ms because a percentile is not an
	// aggregatable quantity: the pipeline downstream summed, averaged
	// and maximised it in turn, and all three operations are invalid.
	// Bucket counts sum exactly — the elementwise sum of two
	// histograms is the histogram of the union — so the quantile can
	// be taken once, at read time, over the whole window.
	LatencyBuckets histogram.BucketCounts `json:"-"`

	// TTFBBuckets is the time-to-first-byte distribution for the tick.
	// Separate from LatencyBuckets because the two measure different
	// things: latency runs to the last byte and so carries the
	// visitor's download time, TTFB stops when the response commits.
	// Its total can be below Reqs — a hijacked connection has no
	// first byte to time.
	TTFBBuckets histogram.BucketCounts `json:"-"`

	// BytesOut is response body bytes the wire accepted during the
	// tick. Headers and post-Hijack traffic excluded.
	BytesOut uint64 `json:"bytesOut,omitempty"`

	// Hijacked counts requests whose connection was taken over, whose
	// TTFB and bytes are unobservable rather than zero.
	Hijacked uint64 `json:"hijacked,omitempty"`
}

// RouteSnapshot is one route's entry in the per-tick Snapshot. It
// joins the Registry's per-route Delta with the route's metadata
// from storage (host, upstream) so the WebSocket frame is
// self-contained (spec §5.2 — denormalized into every tick to
// save the client a GET /routes).
//
// The frontend interprets reqPerSec == reqs because the tick is
// exactly tickInterval (1 s, spec §8); the dedicated field exists
// so a future tick variation does not break the wire contract.
type RouteSnapshot struct {
	ID         string  `json:"id"`
	Host       string  `json:"host"`
	Upstream   string  `json:"upstream"`
	Reqs       uint64  `json:"reqs"`
	Errs       uint64  `json:"errs"`
	ReqPerSec  uint64  `json:"reqPerSec"`
	ErrRate5xx float64 `json:"errRate5xx"`
}

// Snapshot is what the Ticker produces every tickInterval and what
// the Broadcaster fans out to subscribers. Each Snapshot lists EVERY
// persisted route (spec §5.2), including idle routes at zero
// counters; the frontend uses the full listing for its idle-state
// detection.
//
// T is the wall-clock UTC timestamp of the tick (spec §5.2 "t" field).
// Producers MUST populate T in UTC (time.Now().UTC()) for the default
// JSON marshaler to emit RFC 3339 with the 'Z' suffix the wire
// contract expects; a non-UTC value would render as "+02:00" etc.
// and break clients that parse the suffix strictly. time.Time is
// preserved here rather than a pre-formatted string so downstream
// layers retain full control over encoding.
type Snapshot struct {
	T      time.Time       `json:"t"`
	Routes []RouteSnapshot `json:"routes"`
	// Hosts is the per-(routeID, host) breakdown drained
	// alongside the per-route Routes slice on every tick.
	// Topology Plan B Phase 2.2 addition — populated by
	// Ticker.makeSnapshot from Registry.SnapshotHosts() and
	// consumed by topology_stream.go's pushSnap to feed the
	// SlidingWindow's per-host ring buffers.
	//
	// json:"-" is intentional: the WS broadcast wire shape
	// (spec §5.2) is Routes-only; surfacing per-host data on
	// the WebSocket would break the existing
	// /api/v1/ws/topology and /api/v1/topology/stream
	// consumers. The per-host data is delivered exclusively
	// in-process to subscribers that decode the Snapshot
	// struct field directly. The HTTP /topology/snapshot
	// endpoint surfaces a different per-host shape (Alias
	// objects) via the SlidingWindow's AggregateByHost.
	Hosts []HostSnapshot `json:"-"`
}

// HostSnapshot is one (routeID, host) entry in the per-tick
// Snapshot.Hosts slice. Topology Plan B Phase 2.2 addition.
//
// Fields mirror the per-route RouteSnapshot shape — Reqs / Errs
// / per-tick latency — so the SlidingWindow's per-host ring
// state can reuse the same metricSlot layout. Reqs == ReqPerSec
// here too since TickInterval == 1s.
type HostSnapshot struct {
	RouteID      string
	Host         string
	Reqs         uint64
	Errs         uint64
	Errs4xx      uint64
	LatencyP95Ms int32
}
