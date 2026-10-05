<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Latency that tells the truth — implementation plan

**Spec**: `docs/superpowers/specs/2026-10-05-latency-truth-design.md`
**Target**: v2.63.0 (T1–T9, measurement + storage), v2.64.0 (T10–T12, surfaces)

The order is chosen so the two load-bearing gates come first and the
hot path changes last. T1 writes down what is currently wrong, in a
test, before anything is touched — otherwise the fix has nothing to be
measured against and the defect's shape gets argued from memory.

---

## v2.63.0 — measurement and storage

**T1. Characterise the defect (G2). Test only, no production change.**
A test in `internal/observability` that drives the real registry →
aggregator path with 600 requests, 599 of them 2 ms and one of 8 s, and
asserts the stored `latency_p95_ms`. It will read in the thousands
where the true p95 is 2 ms. Assert the *wrong* value, with a comment
naming it as the characterisation of a known defect and pointing at
this plan. **This test is deleted by T6, not adapted** — a
characterisation test that survives its own fix becomes a lie.

**T2. Exact-summation property test (G1). Test only.**
`internal/observability/histogram_test.go`: for random latency
multisets `a`, `b`, assert `quantile(hist(a)+hist(b)) ==
quantile(hist(a ∪ b))` exactly, at p50/p95/p99. Fails to compile
first (no exported `quantile` yet), which is the signal to write T3.

**T3. Read-time quantile with interpolation (D3, D5, G9).**
`internal/observability/histogram.go`: `Quantile(buckets [17]uint64, q
float64) (float64, int64)` returning the interpolated value and the
sample count. Linear inside the resolved bucket. Returns
`(0, 0)` on an empty histogram — the caller turns that into `null`,
never 0 ms. G9's log-normal accuracy test lands here.

**T4. Histogram on the wire (D1).**
`metrics.Delta` / `observability.TickDelta`: `LatencyP95Ms int32` →
`LatencyBuckets [17]uint64`. `registry.drainP95` becomes
`drainBuckets`, returning the swapped counts instead of reducing them.
The atomic.Swap drain pattern is unchanged — only what is returned.
Delete `drainP95`; nothing should be able to reduce a histogram to a
scalar inside the registry any more.

**T5. TTFB and bytes on the hot path (D7, D9, D10).**
`statusRecorder` gains `ttfbMs float64`, `bytesOut uint64`,
`hijacked bool`. Stamp TTFB at the existing `headerWritten` flip in
**both** `WriteHeader` (`:536`) and `Write` (`:552`) — both are
response-commit points and only one of them fires. `Write` adds
`len(b)`. `Hijack` sets `hijacked` and the deferred emit then
contributes to neither histogram. Two histograms per cell now: TTFB
and total. G3, G4, G6, G8 land here; **G3 needs a slow-reader harness**
and is the one gate that cannot be faked.

**T6. Sum, don't max (D2).**
`aggregator.absorb`: delete `p95MaxMs` and its `if d.LatencyP95Ms >
…` comparison; sum the two bucket arrays instead. `flush` writes the
BLOBs. **Delete T1's characterisation test here**, in the same commit
that makes it false, and say so in the message.

**T7. Schema v15 (D6, D13, D14).**
`currentSchemaVersion` 14 → 15. Corrected twice against the tree: the
version (health history has not landed, so 15 is free and it
renumbers to 16) and the table list — there is **no `bucket_1d`**, only
`bucket_1m` and `bucket_1h`. `ttfb_hist BLOB`, `total_hist BLOB`,
`bytes_out INTEGER`, `hijacked_count INTEGER` on both. 68-byte fixed
encoding, 17 × uint32 LE. The BLOBs stay nullable: pre-v15 rows have
no histogram and NULL is how the read path knows (D14).
`latency_p95_ms` stays and is now written from `Quantile(total_hist,
0.95)` (D13). Follow the `INSERT … SELECT WHERE NOT EXISTS` seed
pattern at `storage.go:57-64`, not `INSERT OR IGNORE`. No back-fill
(D14): pre-v16 rows keep a NULL histogram and the read path flags
them.

**T8. Rollup by summation (D2, G7).**
`retention.rollupHour` / `rollupDay`: sum the BLOBs, sum `bytes_out`,
sum `hijacked_count`. The comment at `retention.go:280` saying exact
recomputation is impossible **is deleted** — it becomes exact, and
leaving it would misdescribe the new code. G7 (running the rollup
twice does not double) is a real risk once the operation is addition;
it was not one when the operation was max.

**T9. Read path (D11, G5).**
`AggregateHistogram(filter)` summing BLOBs server-side. A
`MinQuantileSamples` constant with its rationale beside it. Below it
the API returns `null` plus the real count — never a number. One
literal-JSON wire test per new field, per
`[[test-the-wire-not-the-struct]]`.

---

## v2.64.0 — surfaces

**T10. API shape (spec §4).**
`/metrics/route-summary`: `ttfbMs`, `totalMs`, `bytesOut`, `samples`,
`hijacked`. `/metrics/timeseries`: `ttfb_ms` and `bytes_out` metrics,
plus a `quantile` parameter (`p50`|`p95`|`p99`, default `p95`).
`TestOpenAPI_CoversEveryRoute` will demand the spec entry — expect it
and write the entry with the null-vs-zero contract spelled out, as
`/metrics/route-summary` already does.

**T11. The route panel strip.**
Replace the single ambiguous p95 with `TTFB p95` and `total p95` as
two figures, plus bytes out. The strip's existing contract holds: no
number while loading, `—` for a null quantile, and *nothing* invented
below `MinQuantileSamples`. The sample count is shown, because a
reader who can see `n = 7` can judge the figure themselves — which is
a control, not advice.

**T12. The latency chart.**
Quantile selector on `/observability/<routeId>`, TTFB and total as two
series. A route whose two curves diverge is reading its own bandwidth
problem off the screen, with no text telling it what to think.

---

## Not in this plan

Renaming `p99LatencyMs` on the topology wire, which is a third
statistic with its own provenance and deserves its own look. Flagged
here so it is not mistaken for covered.
