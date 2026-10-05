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
	"fmt"
	"log/slog"
	"time"

	"github.com/barto95100/arenet/internal/histogram"
)

// Retention windows per Step L spec §1.3 D2.
const (
	// Retain1m is how long bucket_1m rows are kept before being
	// pruned. Anything older has already been folded into the
	// hourly bucket.
	Retain1m = 24 * time.Hour
	// Retain1h is how long bucket_1h rows are kept.
	Retain1h = 30 * 24 * time.Hour

	// RetainWafEvents is how long per-event waf_event rows
	// are kept at row granularity (Step M, spec §1.3 D7 +
	// §3.6). Matches the bucket_1h horizon — operators who
	// need post-incident forensics beyond 30 days should
	// snapshot metrics.db externally.
	RetainWafEvents = 30 * 24 * time.Hour

	// RetainThrottleEvents is how long per-event
	// throttle_event rows are kept at row granularity (Step
	// Q, spec §1.3 D9.A). Matches the WAF event horizon for
	// consistency: an operator investigating an incident at
	// day 29 should find both WAF and rate-limit signal,
	// not one without the other.
	RetainThrottleEvents = 30 * 24 * time.Hour

	// RetainDecisionEvents is how long per-event
	// decision_event rows are kept at row granularity (Step
	// N, spec §1.3 D8.A). Matches the WAF + throttle horizon
	// for the same reason: heterogeneous retention windows
	// would create confusing dashboard gaps.
	RetainDecisionEvents = 30 * 24 * time.Hour

	// RetainCountryBlockEvents is how long per-event
	// country_block_event rows live before the retention
	// pruner deletes them. Per W.4 spec §3.5 (30 d at row
	// granularity — same horizon as the waf / throttle /
	// decision security tables; country-block blocks are a
	// real-time signal, not a lifecycle record).
	RetainCountryBlockEvents = 30 * 24 * time.Hour

	// RetainRateLimitEvents is how long per-event
	// rate_limit_event rows live before the retention pruner
	// deletes them. Per Step Z spec (24h at row granularity).
	// Deliberately shorter than the 30 d horizon shared by
	// the other security tables : (i) 429s can be very
	// high-volume during a sustained DoS (tens of thousands /
	// minute), and (ii) the burst-shape forensic value
	// decays fast — once the burst is over the operator
	// looks at aggregate counters, not individual rows.
	RetainRateLimitEvents = 24 * time.Hour

	// RetainAuthEvents is how long per-event auth_event rows
	// are kept at row granularity (Step V.2, spec §3.6). Set
	// to 30 days — auth failures are operationally
	// short-window security signals (login brute-force,
	// session anomalies), not lifecycle records. Mirrors the
	// WAF / throttle / decision horizons; explicitly NOT the
	// 90 d cert horizon.
	RetainAuthEvents = 30 * 24 * time.Hour

	// RetainCertEvents is how long per-event cert_event rows
	// are kept at row granularity (Step U, spec §3.2). Set
	// to 90 days deliberately — matches the Let's Encrypt
	// certificate lifecycle so an operator investigating a
	// renewal failure has the full preceding obtain/renewal
	// history in the Activity log. Longer than the WAF /
	// throttle / decision horizons because cert events are
	// far lower volume (tens per day per domain max) and a
	// renewal cycle is naturally 90d.
	RetainCertEvents = 90 * 24 * time.Hour

	// RetainAlertEvents is how long alert_event rows live
	// (Step AL.4.a). 30 d at row granularity — operator
	// investigation horizon for "what fired in the last
	// month". Matches the WAF / throttle / decision /
	// country_block horizons; explicitly NOT the 90 d cert
	// horizon (alert lifecycle is operationally short, not
	// tied to LE renewal cycles).
	RetainAlertEvents = 30 * 24 * time.Hour
)

// RetentionRunner runs the hourly rollup + prune loop. Like the
// Aggregator, all errors are logged and never propagated to the
// request path (AC #13).
type RetentionRunner struct {
	store  *Store
	logger *slog.Logger
	now    func() time.Time

	// lastRollupHour is the hour timestamp (truncated) for which
	// the rollup has already been performed. The runner skips
	// hours whose bucket_1h row already exists, so a restart in
	// the middle of an hour does not double-aggregate.
	lastRollupHour time.Time

	done chan struct{}
}

// NewRetentionRunner builds a runner. store may be nil (degraded
// mode); Run becomes a no-op loop in that case.
func NewRetentionRunner(store *Store, logger *slog.Logger) *RetentionRunner {
	if logger == nil {
		logger = slog.Default()
	}
	return &RetentionRunner{
		store:  store,
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		done:   make(chan struct{}),
	}
}

// SetClock overrides the time source. For tests only.
func (r *RetentionRunner) SetClock(now func() time.Time) {
	r.now = now
}

// Done returns a channel closed once Run has exited.
func (r *RetentionRunner) Done() <-chan struct{} {
	return r.done
}

// Run drives the retention loop until ctx is cancelled. The
// loop checks for an hour boundary every minute — a 1-minute
// jitter on the rollup is acceptable (the timeline UI never
// reads the current hour from bucket_1h anyway).
//
// Wrapped in recover() per AC #13.
func (r *RetentionRunner) Run(ctx context.Context) {
	defer close(r.done)
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Error("observability: retention loop panic; rollup/prune disabled for the rest of this process",
				slog.Any("panic", rec),
			)
		}
	}()

	// Catch up on the current state at boot so a restart picks
	// up where it left off.
	r.lastRollupHour = r.now().Truncate(time.Hour).Add(-time.Hour)

	check := time.NewTicker(time.Minute)
	defer check.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-check.C:
			r.tick(ctx)
		}
	}
}

// Tick is a manual driver for tests — runs one rollup + prune
// iteration against the current synthetic clock value.
func (r *RetentionRunner) Tick(ctx context.Context) {
	r.tick(ctx)
}

func (r *RetentionRunner) tick(ctx context.Context) {
	if r.store == nil {
		return
	}
	now := r.now()
	currentHour := now.Truncate(time.Hour)

	// Roll up every closed hour we have not yet rolled up. The
	// catch-up case (multiple hours since last run) is small —
	// the gap is bounded by the start delay or a paused
	// process; we loop until we are caught up.
	for h := r.lastRollupHour.Add(time.Hour); h.Before(currentHour); h = h.Add(time.Hour) {
		if err := r.rollupHour(ctx, h); err != nil {
			r.logger.Error("observability: rollup failed",
				slog.Time("hour", h),
				slog.String("err", err.Error()),
			)
			// Don't advance lastRollupHour on failure; we'll
			// retry on the next tick.
			return
		}
		r.lastRollupHour = h
	}

	// Prune. Cutoffs computed relative to now so the test
	// drives them via the synthetic clock.
	if _, err := r.store.PruneOlderThan(ctx, Granularity1m, now.Add(-Retain1m)); err != nil {
		r.logger.Error("observability: prune 1m failed", slog.String("err", err.Error()))
	}
	if _, err := r.store.PruneOlderThan(ctx, Granularity1h, now.Add(-Retain1h)); err != nil {
		r.logger.Error("observability: prune 1h failed", slog.String("err", err.Error()))
	}
	// Step M: prune waf_event rows older than RetainWafEvents
	// (30 d at row granularity — see spec §3.6 + §1.3 D7).
	if _, err := r.store.PruneWafEventsOlderThan(ctx, now.Add(-RetainWafEvents)); err != nil {
		r.logger.Error("observability: prune waf_event failed", slog.String("err", err.Error()))
	}
	// Step Q: prune throttle_event rows older than
	// RetainThrottleEvents (30 d at row granularity — see
	// spec §3.6 + §1.3 D9.A).
	if _, err := r.store.PruneThrottleEventsOlderThan(ctx, now.Add(-RetainThrottleEvents)); err != nil {
		r.logger.Error("observability: prune throttle_event failed", slog.String("err", err.Error()))
	}
	// Step N: prune decision_event rows older than
	// RetainDecisionEvents (30 d at row granularity — see
	// N spec §3.7 + §1.3 D8.A).
	if _, err := r.store.PruneDecisionEventsOlderThan(ctx, now.Add(-RetainDecisionEvents)); err != nil {
		r.logger.Error("observability: prune decision_event failed", slog.String("err", err.Error()))
	}
	// Step U.1: prune cert_event rows older than RetainCertEvents
	// (90 d at row granularity — see Step U spec §3.2). Longer
	// horizon than the security tables because a single LE
	// renewal cycle is 90d, and an operator investigating a
	// renewal-loop incident needs the full cycle's worth of
	// obtained/failed events for correlation.
	if _, err := r.store.PruneCertEventsOlderThan(ctx, now.Add(-RetainCertEvents)); err != nil {
		r.logger.Error("observability: prune cert_event failed", slog.String("err", err.Error()))
	}
	// Step V.2: prune auth_event rows older than
	// RetainAuthEvents (30 d at row granularity — see Step V
	// spec §3.6). Same horizon as the security-event tables;
	// auth failures are a real-time signal, not a lifecycle
	// record.
	if _, err := r.store.PruneAuthEventsOlderThan(ctx, now.Add(-RetainAuthEvents)); err != nil {
		r.logger.Error("observability: prune auth_event failed", slog.String("err", err.Error()))
	}
	// Step W.4: prune country_block_event rows older than
	// RetainCountryBlockEvents (30 d at row granularity —
	// see W.4 spec §3.5). Same horizon as the other security-
	// event tables.
	if _, err := r.store.PruneCountryBlockEventsOlderThan(ctx, now.Add(-RetainCountryBlockEvents)); err != nil {
		r.logger.Error("observability: prune country_block_event failed", slog.String("err", err.Error()))
	}
	// Step Z.1: prune rate_limit_event rows older than
	// RetainRateLimitEvents (24h — much shorter than the
	// other security tables; 429s are high-volume during
	// DoS and burst-shape forensic value decays fast).
	if _, err := r.store.PruneRateLimitEventsOlderThan(ctx, now.Add(-RetainRateLimitEvents)); err != nil {
		r.logger.Error("observability: prune rate_limit_event failed", slog.String("err", err.Error()))
	}
	// Step AL.4.a: prune alert_event rows older than
	// RetainAlertEvents (30 d). Mirror of the other
	// security-event prunes.
	if _, err := r.store.PruneAlertEventsOlderThan(ctx, now.Add(-RetainAlertEvents)); err != nil {
		r.logger.Error("observability: prune alert_event failed", slog.String("err", err.Error()))
	}
}

// rollupHour aggregates every bucket_1m row in [h, h+1h) per
// route, into one bucket_1h row per route.
//
// p95 approximation per spec §2 AC #2: the hourly p95 is the
// **req-count-weighted percentile-of-percentiles** across the
// 60 minute samples. Since we only persisted one p95-int per
// minute, exact recomputation used to be impossible — and the
// comment here said so.
//
// It is possible now. Since schema v15 each minute carries its own
// distribution, and summing distributions is exact: the elementwise
// sum of two histograms is the histogram of the union of their
// samples. The hour's p95 is therefore computed over the hour's real
// population, not derived from sixty per-minute percentiles, which was
// never an approximation of anything — a percentile cannot be averaged
// any more than it can be maximised.
//
// The weighted-average and max fallbacks remain for hours whose
// minutes predate v15 and have no histogram to sum. Those rows cannot
// be improved: the data was discarded a second after it was
// produced.
func (r *RetentionRunner) rollupHour(ctx context.Context, hourStart time.Time) error {
	// One query for the whole hour, all routes.
	rows, err := r.store.db.QueryContext(ctx, `
SELECT route_id, req_count, fourxx_count, fivexx_count, waf_block_count, waf_detect_count, throttle_block_count, crowdsec_decision_count, rate_limit_count, latency_p95_ms, total_hist, ttfb_hist, bytes_out, hijacked_count
FROM bucket_1m
WHERE ts >= ? AND ts < ?
`, hourStart.UTC().Unix(), hourStart.Add(time.Hour).UTC().Unix())
	if err != nil {
		return fmt.Errorf("rollup query: %w", err)
	}
	defer rows.Close()

	type acc struct {
		req       int64
		fourxx    int64
		fivexx    int64
		wafBlock  int64
		wafDetect int64
		throttle  int64
		crowdsec  int64
		rateLimit int64
		p95w      int64 // sum of (req_count * latency_p95_ms)
		p95wDen   int64 // sum of req_count for samples that had latency
		p95plain  int64 // unweighted max as fallback when no traffic

		// total / ttfb are the summed distributions, and anyHist says
		// whether any contributing minute actually carried one.
		//
		// Summing is exact: the elementwise sum of two histograms is
		// the histogram of the union of their samples. So the hour's
		// p95 below is computed over the real hour, not derived from
		// sixty per-minute percentiles — which is what the old
		// weighted-average fallback did, and what the comment above
		// this function used to concede was "impossible" to do
		// exactly.
		total    histogram.BucketCounts
		ttfb     histogram.BucketCounts
		anyHist  bool
		bytesOut int64
		hijacked int64
	}
	byRoute := make(map[string]*acc)
	for rows.Next() {
		var routeID string
		var req, fourxx, fivexx, wafBlock, wafDetect, throttle, crowdsec, rateLimit int64
		var p95 int32
		var totalBlob, ttfbBlob []byte
		var bytesOut, hijacked int64
		if err := rows.Scan(&routeID, &req, &fourxx, &fivexx, &wafBlock, &wafDetect, &throttle, &crowdsec, &rateLimit, &p95, &totalBlob, &ttfbBlob, &bytesOut, &hijacked); err != nil {
			return fmt.Errorf("rollup scan: %w", err)
		}
		a, ok := byRoute[routeID]
		if !ok {
			a = &acc{}
			byRoute[routeID] = a
		}
		a.req += req
		a.fourxx += fourxx
		a.fivexx += fivexx
		a.wafBlock += wafBlock
		a.wafDetect += wafDetect
		a.throttle += throttle
		a.crowdsec += crowdsec
		a.rateLimit += rateLimit
		if req > 0 && p95 > 0 {
			a.p95w += int64(p95) * req
			a.p95wDen += req
		}
		if int64(p95) > a.p95plain {
			a.p95plain = int64(p95)
		}

		a.bytesOut += bytesOut
		a.hijacked += hijacked
		total, derr := decodeHistOrNil(totalBlob)
		if derr != nil {
			return fmt.Errorf("rollup total_hist (route=%s): %w", routeID, derr)
		}
		ttfbH, derr := decodeHistOrNil(ttfbBlob)
		if derr != nil {
			return fmt.Errorf("rollup ttfb_hist (route=%s): %w", routeID, derr)
		}
		if total != nil {
			a.total.Add(*total)
			a.anyHist = true
		}
		if ttfbH != nil {
			a.ttfb.Add(*ttfbH)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rollup iterate: %w", err)
	}
	if len(byRoute) == 0 {
		return nil
	}

	out := make([]MetricBucket, 0, len(byRoute))
	for id, a := range byRoute {
		var p95 int32
		switch {
		case a.anyHist:
			// The hour's own distribution, so this is a real p95 over
			// the real hour. The two branches below are the legacy
			// path, kept only for hours whose minutes predate the
			// histogram columns.
			p95 = p95FromBuckets(a.total)
		case a.p95wDen > 0:
			p95 = int32(a.p95w / a.p95wDen)
		default:
			// No req-weighted data — keep the unweighted max
			// as the representative value rather than 0,
			// which would render as a fake "no latency" gap.
			p95 = int32(a.p95plain)
		}
		out = append(out, MetricBucket{
			RouteID:               id,
			Ts:                    hourStart,
			ReqCount:              a.req,
			FourxxCount:           a.fourxx,
			FivexxCount:           a.fivexx,
			WafBlockCount:         a.wafBlock,
			WafDetectCount:        a.wafDetect,
			ThrottleBlockCount:    a.throttle,
			CrowdSecDecisionCount: a.crowdsec,
			RateLimitCount:        a.rateLimit,
			LatencyP95Ms:          p95,
			TotalHist:             histOrNil(a.total),
			TTFBHist:              histOrNil(a.ttfb),
			BytesOut:              a.bytesOut,
			HijackedCount:         a.hijacked,
		})
	}
	return r.store.InsertBatch(ctx, Granularity1h, out)
}
