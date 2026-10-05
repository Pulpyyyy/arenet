<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Latency that tells the truth — design

**Target version**: v2.63.0 (measurement + storage), v2.64.0 (surfaces)
**Date**: 2026-10-05
**Schema**: observability v15 (corrected — see §9)

## 1. Why

An operator read **p95 35 658 ms** on one route and **p95 6 701 ms** on
another, went to both sites, and found them fast. They asked whether the
numbers were credible. They were not, and finding out why took three
wrong answers and four rounds of their own `jq` output.

What the investigation established, each claim from source or from
measurement:

**The figure labelled `p95` is a maximum.** The chain, in the code's own
words:

| site | what happens |
|---|---|
| `metrics/registry.go:136` `drainP95` | p95 over **one 1-second tick**, returned as the bucket's **upper edge** |
| `observability/aggregator.go:453` | the tick is `time.NewTicker(time.Second)` |
| `observability/aggregator.go:153` | `p95MaxMs int32 // max across all 1-second samples this minute` |
| `observability/aggregator.go:541` | `LatencyP95Ms: rs.p95MaxMs` — that max is stored as the minute's p95 |
| `observability/retention.go:280` | *"exact recomputation is impossible … not equality to a recomputed exact p95"* |
| `api/metrics_handlers.go` route-summary | request-weighted **mean** of those hourly values |

At 0.88 req/s — measured on the operator's blog, 650 requests in 741 s —
a 1-second tick holds **zero or one** request. With `total = 1` the
threshold `ceil(1 × 0.95) = 1`, so the "p95" is that one request's
duration, rounded up to the next power of two. The minute then takes the
**max** of sixty such values.

So on any low-traffic route the reported p95 is *the slowest single
request in the window, rounded up to a power of two*. Both of the
operator's figures reproduce exactly: a 5 MB image at ~5 s lands on the
8192 ms bucket edge; a 30–45 s long-poll lands on 32768 or 65536.

**Percentiles are not averageable, and not max-able.** This is the root
error, not a tuning problem. `max(p95(a), p95(b)) != p95(a ∪ b)` and
`mean(p95(a), p95(b)) != p95(a ∪ b)`. Every aggregation step in the
chain above applies an operation that is invalid on quantiles. The
histogram that *would* make it valid already exists in both packages
(`metrics/registry.go:105` and `observability/histogram.go`) and is
discarded one second after it is filled.

**Duration conflates the server with the network.** `middleware.go:285`
takes `time.Since(start)` in a `defer` that fires after
`next.ServeHTTP` returns, so the whole response body transfer is inside
the measurement. Measured on the operator's host: the same asset served
in **0.108 s TTFB / 0.326 s total** from a fast client appeared in the
access log at **24 s** for a slow one. The server was never slow. The
metric could not say so.

**Volume is invisible.** Nothing records bytes served. The actual cause
of that 24 s — a 2.9 MB file — was reachable only by the operator
running `jq` over a raw access log. A reverse proxy that cannot report
its own egress cannot explain its own latency.

## 2. Scope and audience

Arenet is used by operators whose upstreams are not Ghost and not
Discourse. **The design therefore contains no heuristic about any
particular upstream** — no path lists, no long-poll detection, no
content-type special cases. Those would make the numbers less true, not
more, and would break on the first upstream nobody anticipated.

The principle: **report statistics that are correct, report the sample
size beside them, and let the distribution speak.** A route serving
long-polls has a genuinely bimodal latency distribution. That is
information. A single number can only ever hide it; a histogram shows
it to anyone, on any upstream, with no configuration.

## 3. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **Carry histogram bucket counts, not a scalar**, from registry to aggregator. `TickDelta.LatencyP95Ms int32` becomes `LatencyBuckets [17]uint64`. | Summing histograms is exact and order-independent. Summing or max-ing percentiles is arithmetically invalid — the root defect. |
| D2 | **Aggregate by summing buckets.** `p95MaxMs` and its `max` are deleted. | The sum of two histograms is the histogram of the union. No information is lost at any aggregation step, including the hourly and daily rollups. |
| D3 | **Compute quantiles at read time**, in the API, from the summed histogram. | Decouples "what we store" from "what we ask". p50, p95 and p99 become available from the same rows, and a future quantile needs no migration. |
| D4 | **Keep the existing 17-bucket log2 layout** (0.5 ms → 65536 ms, factor 2). | It already exists, identically, in both packages. Changing edges in the same change would conflate two risks. §8 records how to refine it later without another migration. |
| D5 | **Linear interpolation inside the resolved bucket**, as `histogram_quantile` does. | A factor-2 bucket reported at its upper edge overstates by up to 100% — reporting the edge is what produced "8192 ms". Interpolation is exact in expectation for a uniform intra-bucket distribution and bounded by the bucket width otherwise; the actual error is **not asserted here**, it is whatever G9 measures. If G9 shows it too coarse, §8 is the lever, not a different interpolation. |
| D6 | **Store the histogram as a fixed 68-byte BLOB** (17 × uint32 little-endian) on `bucket_1m` and `bucket_1h`. | 50 routes × 1440 min × 68 B = **4.9 MB** at `Retain1m` (24 h), 2.4 MB at `Retain1h` (30 d). Storage is not an argument against correctness here. A BLOB avoids 17 columns and three migrations' worth of churn. |
| D7 | **Measure TTFB separately** — stamped when the response first commits, in `statusRecorder` at the existing `headerWritten` flip (`middleware.go:536` and `:552`). | That guard is already exactly the moment the response begins. Two assignments, no allocation, nothing new on the hot path. |
| D8 | **Keep total duration too**, as its own histogram. | They answer different questions. TTFB: is my upstream responsive. Total: what are my visitors actually experiencing, bandwidth included. Neither replaces the other. |
| D9 | **Count bytes written**, summed per tick from `statusRecorder.Write`. | Makes egress visible, which is what explains a slow transfer. `len(b)` on a path that already sees every byte. |
| D10 | **A hijacked connection (WebSocket) is excluded and said to be excluded.** | After `Hijack` there is no `WriteHeader` and no `Write`, so TTFB and bytes are unobservable by construction. The API reports the count of hijacked requests rather than letting them silently read as zero. |
| D11 | **Below `MinQuantileSamples` the API returns `null`, never a number**, and always returns the sample count. | A percentile over three requests is not a percentile. This is the same contract as the null p95 shipped in v2.62.0: an absent measurement must stay distinguishable from a measured value. |
| D12 | **No upstream-specific anything.** No path exclusions, no long-poll detection, no content-type rules. | §2. The distribution is the honest answer, and it works for every operator. |
| D13 | **`latency_p95_ms` keeps being written**, now computed correctly from the histogram at flush time. | Existing charts and the v2.62.0 route-summary keep working through the migration, and they get *better* values rather than a hole. Marked legacy; `null` for pre-v16 rows that have no histogram. |
| D14 | **Historical rows are not back-filled.** | The histograms were discarded one second after they were filled; the information does not exist. Pre-v16 rows keep their old scalar and the API flags them, rather than a migration inventing a shape for them. |

## 4. What gets exposed

Per route, over the selected window:

- `ttfbMs` — quantile over the TTFB histogram. The actionable latency.
- `totalMs` — quantile over the total-duration histogram.
- `bytesOut` — sum.
- `samples` — the count the quantiles were computed from. **Always
  present**, so D11 is checkable by the reader and not just trusted.
- `hijacked` — count of requests whose TTFB and bytes are unobservable
  (D10).

`GET /metrics/route-summary` gains these. `GET /metrics/timeseries`
gains `ttfb_ms`, `bytes_out`, and honours a `quantile` parameter
(`p50` | `p95` | `p99`, default `p95`).

## 5. What the operator will see

The two figures that started this become, for the same traffic:

| | today | after |
|---|---|---|
| blog serving a 2.9 MB asset | `p95 6 701 ms` | `TTFB p95 ~110 ms` · `total p95 ~340 ms` · `12 MB out` |
| forum with long-polling | `p95 35 658 ms` | `TTFB p95 ~30 000 ms` · bimodal histogram · low `bytesOut` |

The forum's TTFB stays large, and that is **correct**: the upstream
genuinely takes 30 s to answer a long-poll. The difference is that the
number is now true, the distribution shows the two populations, and
nothing in Arenet had to know what Discourse is.

## 6. Non-goals

- Per-upstream latency attribution. Caddy's `reverse_proxy` does not
  expose it to a wrapping middleware; claiming it would be fabrication.
- Back-filling history (D14).
- Changing the 4xx / 5xx counters, which are correct.
- Request-body / upload timing.
- Any configuration knob for excluding paths (D12).

## 7. Empirical validation gates

Each must fail before the change and pass after, per
`docs/ENGINEERING-PRACTICES.md`.

- **G1 — summing is exact.** Property test: for random latency sets
  `a` and `b`, the quantile of `hist(a) + hist(b)` equals the quantile
  of `hist(a ∪ b)` **exactly** (same bucket, same interpolation).
- **G2 — the current chain is wrong, demonstrably.** A characterisation
  test on today's code: a route with one 8 s request and 599 fast ones
  reports a "p95" in the thousands of ms while the true p95 is a few
  ms. This gate documents the defect and must be deleted, not adapted,
  when the fix lands.
- **G3 — a slow client does not move TTFB.** Harness with a
  deliberately slow reader: total duration rises by seconds, TTFB stays
  flat. This is the gate that proves §1's third claim fixed.
- **G4 — TTFB ≤ total, always**, including on error paths, on a
  bodyless 204, and when the upstream is dead (502 produced by Caddy).
- **G5 — low sample size returns null.** Below `MinQuantileSamples`,
  the API emits `null` and the real count, never a number.
- **G6 — bytes are exact**, including when the handler errors
  mid-body, and byte count equals what the client received.
- **G7 — rollup idempotence.** Running the hourly rollup twice does not
  double the histogram. Summing makes this a real risk and a real test.
- **G8 — hijacked requests are reported, not zeroed.** A WebSocket
  upgrade increments `hijacked` and contributes to neither histogram.
- **G9 — interpolation accuracy, measured not assumed.** Over synthetic
  samples (log-normal, uniform, and bimodal — the shape a long-polling
  route actually has), compute the exact p95 from the raw sample and
  the interpolated p95 from the histogram, and **record the observed
  error in the test's own comment**. The assertion is the bucket-width
  bound, which is provable; the recorded number is what tells a future
  reader whether §8 is needed. Written this way because the first draft
  of D5 asserted "roughly ±20%" from nowhere — in a design whose whole
  subject is unasserted numbers.
- **G10 — no regression in Caddy config or chain order.** The emitted
  JSON and handler order are unchanged; `middleware.go` gains fields,
  not a position.

## 8. Refining resolution later, without a migration

D4 keeps factor-2 buckets. If ±20% proves too coarse, the BLOB of D6
gains a one-byte header naming the bucket schema (`0` = the current
log2/0.5 ms layout, `1` = quarter-octave, and so on), exactly as
Prometheus native histograms carry a schema field. Readers switch on
it; old rows keep reading correctly. This is why D6 stores a BLOB and
not 17 columns.

## 9. Ordering against health history, and two corrections

**Schema version.** This design first claimed v16, on the assumption
that the merged health-history plan would take v15 before it. Health
history has not been implemented, `currentSchemaVersion` is still 14,
so **this takes v15** and the health-history plan renumbers to v16 when
it lands. Recorded rather than quietly edited: the original reasoning
was sound and the facts moved.

**There is no `bucket_1d`.** D6 listed three bucket tables. The
observability store has exactly two — `bucket_1m` (`Retain1m`, 24 h)
and `bucket_1h` (`Retain1h`, 30 d) — and no `Granularity1d` exists.
The third came from conflating these with the health-history spec's
own `health_bucket_1d`, which is a different table in a different
design. Caught by reading `storage.go` before writing the migration,
which is the only reason it is not now a migration against a table
that does not exist.

The health-history plan's target version (`v2.62.0`) is also stale —
v2.62.0 shipped without it.

## 10. Honest accounting

The v2.62.0 route-summary endpoint **inherited this defect and added a
layer to it**. Its doc comment says the value is "the request-weighted
mean of the hourly p95 samples … NOT a true 24h p95", which was honest
about that one layer and blind to the three below it. The figure was
taken to be what its column name claimed.

That is the failure mode this repo already has a name for — correct
code, wrong label — in its sharpest form yet: the label is wrong at
four levels, each of which documented its own approximation, and
nobody added the four together. The fix is not a better average. It is
to stop throwing away the histogram.
