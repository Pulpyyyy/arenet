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

import "github.com/barto95100/arenet/internal/histogram"

import "time"

// MetricBucket is one aggregated time window for one route.
// Persisted to SQLite; the same struct shape is used for both
// 1-minute and 1-hour buckets (the destination table tells them
// apart, not the struct).
//
// Note: LatencyP95Ms is stored as 0 when no samples landed in
// the bucket — the REST API projection layer maps that to JSON
// null per AC #5 (a "0 ms p95" would render as a fake latency
// dip on the timeline chart).
type MetricBucket struct {
	RouteID       string
	Ts            time.Time
	ReqCount      int64
	FourxxCount   int64
	FivexxCount   int64
	WafBlockCount int64 // Step M: count of WAF blocks captured this window.
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — count of detect-mode
	// WAF events captured this window. Sibling to WafBlock-
	// Count; populated by the v9 column waf_detect_count.
	// Pre-v9 rows decode to 0 (the SQLite ADD COLUMN default
	// the migration sets), which is the operator-honest
	// "no data" answer for historical buckets.
	WafDetectCount        int64
	ThrottleBlockCount    int64 // Step Q: count of rate-limit blocks (Tier 1 + Tier 2) captured this window. Per-IP rows live under routeID="_throttle" (Q spec §3.5).
	CrowdSecDecisionCount int64 // Step N: count of NEW CrowdSec decisions seen this window (dedupe-before-bump per N spec D4.A). Per-IP rows live under routeID="_crowdsec" (N spec §3.5).
	// RateLimitCount (Step Z.3) is the count of per-route
	// HTTP rate-limit (429) events captured this window. Unlike
	// ThrottleBlockCount which lives under the "_throttle"
	// sentinel, this column is per-route — the zone naming
	// convention "route-<UUID>" lets the Z.1 sink resolve the
	// route, and the bucket flushes under the real route UUID.
	// Powers the Step Z.3 per-route timeseries chart on
	// /security/[routeId]. Pre-v12 rows decode to 0.
	RateLimitCount int64
	// LatencyP95Ms is kept, and from v15 it is computed correctly:
	// a real p95 over the window's whole distribution rather than the
	// max of sixty per-second scalars. Every existing reader keeps
	// working and simply starts receiving true values.
	LatencyP95Ms int32

	// TotalHist and TTFBHist are the window's latency DISTRIBUTIONS —
	// total duration (body transfer included) and time to the response
	// committing. Separate because they answer different questions: an
	// asset measured at 0.108 s TTFB and 24 s total is one request
	// seen by both, and only the second number moves with the
	// visitor's bandwidth.
	//
	// NIL MEANS ABSENT, and that is the whole reason these are
	// pointers. A row written before schema v15 has no histogram — the
	// data was discarded a second after it was produced and cannot be
	// recovered — and a zero-valued histogram would make that
	// historical row read as a route that served nothing. The
	// distinction has to survive in the type, not in a convention.
	TotalHist *histogram.BucketCounts
	TTFBHist  *histogram.BucketCounts

	// BytesOut is response body bytes served in the window. Pre-v15
	// rows decode to 0 from the ADD COLUMN default; unlike the
	// histograms this is harmless, because a byte count of zero and an
	// unrecorded byte count both mean "do not draw a volume here".
	BytesOut int64

	// HijackedCount is requests whose connection was taken over (a
	// WebSocket upgrade). Their TTFB and bytes are unobservable by
	// construction, so the count is carried to stop them reading as
	// instant zero-byte responses.
	HijackedCount int64
}

// Granularity selects the destination table for Insert / Query.
type Granularity int

const (
	// Granularity1m maps to bucket_1m (60-second windows).
	Granularity1m Granularity = iota
	// Granularity1h maps to bucket_1h (3600-second windows).
	Granularity1h
)

func (g Granularity) tableName() string {
	switch g {
	case Granularity1h:
		return "bucket_1h"
	default:
		return "bucket_1m"
	}
}

// Step returns the bucket size for this granularity.
func (g Granularity) Step() time.Duration {
	switch g {
	case Granularity1h:
		return time.Hour
	default:
		return time.Minute
	}
}
