<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke test — latency that tells the truth (v2.63 → v2.65)

**Spec**: `docs/superpowers/specs/2026-10-05-latency-truth-design.md`
**Plan**: `docs/superpowers/plans/2026-10-05-latency-truth.md` (T1–T12, complete)

This work started with one question from the operator: *"ce p95 à
35658 ms, c'est fiable cette valeur ?"* It was not. Finding out why
took three wrong answers, four rounds of their own `jq` output, and
the discovery that the figure labelled p95 was a maximum.

The procedure below is written to be run on a real instance, because
every important thing this change touched was found there and not in a
fixture.

---

## 0. Before upgrading — capture the lie

On a route with real traffic, note the route panel's figure.

The operator's two were **p95 6921 ms** on a Ghost blog that loads
instantly and **p95 35658 ms** on a Discourse forum that answers
normally. Write yours down; §4 compares against it.

---

## 1. The migration (schema v15)

**Do**: upgrade to v2.63.0 or later and restart. Watch the boot log.

**Proves**: four columns added to `bucket_1m` and `bucket_1h`.
`ALTER TABLE ADD COLUMN` is metadata-only in SQLite, so this is
instant even on a large `metrics.db` — no row rewrite, no table copy.

**Trap**: nothing is rolled up at boot. `rollupHour` sets
`lastRollupHour = currentHour - 1h` and only processes hours strictly
before the current one, so the first post-upgrade hourly row appears
when the clock crosses into the next hour. Until then the API reports
`samples: 0`, and that is correct, not a failure.

---

## 2. The API, before the UI

**Do**:

```
GET /api/v1/metrics/route-summary?route=<uuid>
```

**Proves** the new fields exist and are honest. Immediately after the
upgrade the operator's instance returned:

```json
{ "reqs": 44673, "samples": 0, "totalMs": null, "ttfbMs": null,
  "bytesOut": 0, "partialHistogram": true }
```

Every value there is right. 44,673 requests were counted from the
pre-existing hourly rows; none of those rows carries a distribution,
so there is nothing to take a percentile of.

**Trap this caught**: the first version of the route panel answered
*"too few requests for a p95"* for any sample count under twenty. On
44,673 requests that is a plain lie. The two situations are
indistinguishable on the wire — both have null quantiles and a count
below the threshold — and mean opposite things:

| | meaning |
|---|---|
| `samples 0`, `reqs 44673` | requests counted, distribution never kept, unrecoverable |
| `samples 9`, `reqs 9` | genuinely too few requests |

They are separate branches with separate wording since v2.64.0.

---

## 3. Wait for the hour to turn

**Do**: nothing, for up to an hour. Then re-read §2.

**Proves**: `samples` becomes non-zero, `totalMs` and `ttfbMs` carry
numbers, `bytesOut` starts counting.

`partialHistogram` stays **true for about 24 hours** — until the whole
rolling window is newer than the upgrade. The request counts cover the
full window throughout; the percentiles and the byte figure do not,
and the panel's marker says so.

---

## 4. The two figures (v2.64.0+)

**Do**: open a route in the routes page and read the header strip.

**Proves** the headline result. The operator's instance, same routes
as §0:

| route | before | after |
|---|---|---|
| blog | `p95 6921 ms` | **`212 ms` server · `236 ms` with transfer** |
| forum | `p95 35658 ms` | **`786 ms` server · `995 ms` with transfer** |

**The prediction that was wrong**, and it is the most instructive item
in this document. The forum's TTFB was expected to stay near 30 s
because Discourse holds `/message-bus/*/poll` open. It is 786 ms —
because on 1,787,406 requests the long-polls would have to be **more
than 5% of traffic** to reach p95, and they are a minority, so they
sit in the tail where a real percentile puts them. The prediction was
still reasoning in the language of the maximum.

**What a quiet route shows**: below twenty requests in the window,
both figures are absent and the strip says *why*. Twenty is derived,
not chosen — below it `ceil(0.95 × n) == n` and a "p95" is simply the
slowest request.

---

## 5. The quantile selector (v2.65.0+)

**Do**: open `/observability/<routeId>` and switch p95 → p99.

**Proves** the part that makes the feature useful. At p95 the two
curves nearly coincide on both of the operator's routes, and that is
correct: these are percentiles of **two different distributions**, not
two measurements of one request, so at the p95 point the transfers are
small.

At p99 the gap opens. On a blog it is heavy images to slow clients; on
a Discourse forum the long-polls reappear where they actually live.

**Expect gaps** in the 24h / 1-minute view on a quiet route. Twenty
observations is a lot for a minute and nothing for an hour, so the
line breaks where the data cannot support the statistic, and the 30d /
1-hour view fills in. The gap is the answer, not a defect — a
continuous line there would be maxima labelled as percentiles.

---

## 6. What the operator's data actually explained

Worth recording, because the chain took four rounds of real output and
no fixture would have produced it:

1. `p95 6701 ms` on a blog that loads instantly.
2. Every request over 10 s was `/content/images/...`, all `200`, no
   `504` — so neither Ghost nor Traefik was slow.
3. `curl` on the heaviest asset: **TTFB 0.108 s, total 0.326 s** from
   a fast client. The server was never slow.
4. That asset was **2,879,675 bytes** — a file named `thumbnail`,
   2.9 MB.
5. Inside it: **ten PNGs in base64**, 71 `<path>`. A bitmap collage in
   an SVG container, which Ghost cannot resize, served whole to every
   visitor. base64 alone wasted 730 KB.

The metric had measured 24 seconds faithfully. What it could not say
was that 23.9 of them were transfer and 0.1 was the server. That is
the whole reason TTFB now exists.

---

## 7. Defects this work found in itself

Each was caught by a gate, not by review:

| Defect | Caught by |
|---|---|
| `commit()` guarded on `ttfbMs == 0`, so a sub-microsecond response read as "not stamped" and a slow client's 151 ms overwrote a TTFB already taken | G3 |
| `MinSamplesFor` used `ceil(1/(1-q))`, returning 11 for p90 where the answer is 10, because `1-0.9` is `0.09999999999999998` | its own derivation test |
| `MultiSeriesTimelineChart` coerced a null latency to 0, plotting "instant" where nothing was measured | the subpath-count test |
| the rollup's idempotence rested on the upsert REPLACING rather than adding | G7 |

And twice, fault injection failed the **test** rather than the code: a
SQL fault neutralised by a duplicate assignment, and an empty TTFB
population that the inner guard already suppressed so the threshold
was never exercised. A green test proves nothing until the defect has
been put back.
