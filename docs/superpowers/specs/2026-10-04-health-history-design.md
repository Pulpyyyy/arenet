<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Health history — design

**Target version**: v2.62.0 (persistence + alert) then v2.63.0 (the page)
**Date**: 2026-10-04
**Origin**: operator request, 2026-10-04. The proximate cause is sharper
than the request: during the forum cutover of 2026-10-03 the operator
asked **twice** — for a 502 burst and for four one-second clusters —
"was it down, and when?", and both times the answer required digging
through `journalctl`. Arenet knew. It had no way to say.

---

## The question this answers

> *Was this backend down last night, for how long, and what else was
> happening at the time?*

Nothing in Arenet can answer that today. `caddyhc` holds a single
`map[addr]string` of current state (`tracker.go:69-72`), in memory, with
no timestamp — and `Reset()` wipes it before **every** `caddy.Load`
(`tracker.go:132-136`, called from `manager.go:357`). The current value
is destroyed on each config reload; history never existed.

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| **D1** | Store **transitions**, not samples | Caddy's health events are *already* transition-only — `Upstream.setHealthy` is an atomic compare-and-swap and emits only on a flip (`tracker.go:115-120`). So the arrival is at the right granularity and is simply being discarded. The alternative is the Uptime Kuma model: one row per probe. At a 10 s interval that is 8 640 rows/day/upstream; this instance's ~40 upstreams would write **345 000 rows a day, 126 million a year**. Transitions make a backend that has been up for a month cost **one row**. |
| **D2** | Write a **reload marker** at every `Reset()` | Load-bearing, and the reason this spec exists instead of a patch. Two facts combine badly: `Reset()` empties the tracker on every reload, and an upstream that is **healthy** after a reload **emits no event at all** — the object is born healthy, so the first successful probe flips nobody (`tracker.go:115-126`). Without a marker, a backend that went down at 03:00 and recovered after a config save shows as **down forever**. The operator reloaded roughly ten times during the 2026-10-03 session; the page would have reported a week of outage on services that were running. |
| **D3** | After a reload the state is **`healthy (assumed)`**, not `unknown` | It is the assumption Caddy itself makes, so the history agrees with the data plane rather than inventing a third truth. A distinct marker state also means the UI can say *why* it believes the backend is up — assumed, not observed — which is honest and is information the operator currently has nowhere. |
| **D4** | Roll up through the **existing** `RetentionRunner.tick` | `retention.go:284-371` already folds `bucket_1m → bucket_1h` on a one-minute ticker with a `lastRollupHour` cursor that survives restart. Health gets one more rollup step and one more prune call beside the existing ten. No new scheduler, no new goroutine, no new failure mode. |
| **D5** | Retention ladder: transitions **90 d**, hourly **30 d**, daily **400 d** | Mirrors the existing constants (`RetainCertEvents` is 90 d for the Let's Encrypt lifecycle; `Retain1h` is 30 d). 400 d for the daily grain so a year-over-year comparison is possible at all. Budget: ~720 hourly + ~400 daily rows per upstream per year, plus transitions — **about 1 100 rows/upstream/year**, ~45 000 rows for this instance, a few MB. Against 126 million for D1's alternative. |
| **D6** | Uptime ratio is stored as **up/total milliseconds**, not as a percentage | It then aggregates **exactly**: `SUM(up)/SUM(total)` is the true ratio at any grain. Contrast the honest caveat already in the tree at `retention.go:276-283` — the hourly p95 is a request-weighted percentile of percentiles, i.e. an approximation. Health history is a *better* fit for this architecture than latency was, and that property is worth protecting by storing durations rather than ratios. |
| **D7** | The ribbon's **height carries the route's p95**, not a probe latency | Per-probe latency does not exist: the Caddy event payload is one field, `{"host": "..."}` (`listener.go:132-151`). The original idea is therefore impossible. What replaces it is better — `bucket_1m.latency_p95_ms` is the latency **real visitors experienced**, not a synthetic probe's. A day then reads as a skyline, and "slow but up" stops looking identical to "down". |
| **D8** | A second lane, on the **same time axis**, carries the events Arenet already stores | Eight populated tables: `waf_event`, `throttle_event`, `decision_event`, `cert_event`, `auth_event`, `country_block_event`, `alert_event`, `rate_limit_event` — all `ts INTEGER` Unix seconds. This is the part no competitor can copy: Uptime Kuma knows only its own pings. Arenet knows the whole story of the proxy, so it can put "the 502 burst sits exactly under the config reload" on one screen. That is, literally, the question that cost an hour on 2026-10-03. |
| **D9** | The **"backend pool down" alert source ships with this**, not before | It needs D2 and D3. Without them a poll-and-compare source reads healthy→unknown on every reload and cries wolf; with the silent-healthy case it may never observe the recovery. Ten false "backend down" alerts for one evening's work, on top of the CrowdSec LAPI noise the operator already receives, is worse than no alert. This reverses what was proposed on the morning of 2026-10-04 — the inventory decided it. |
| **D10** | Degraded mode returns **200 with `disabled: true`** | The existing convention (`metrics_handlers.go:337-344`): `metrics.db` may fail to open and the data plane keeps running (`main.go:656-663`). An uptime page that errors when observability is down would be the second-worst screen in the product. |
| **D11** | Resolve the **route ID at ingest**, store both it and the address | Health events key on a normalised `host:port` only. Resolving at read time means a route rename or an upstream edit silently orphans history. Resolving at write time costs one lookup per transition — and transitions are rare by D1. |
| **D12** | New SQL, new table — **no new chart library** | `TimelineChart.svelte:17-24` records the house rule explicitly: the time-series charts are hand-rolled SVG *to keep D3 out of the bundle*, ~3 kB. D3 is a dependency for exactly one component, the geo threat map. The ribbon is a new hand-rolled component in that style. |

---

## Non-goals

**Per-probe latency.** D7 explains why: the data does not exist upstream.
Adding it would mean Arenet probing on its own, in parallel with Caddy —
two sources of truth about the same backend, which is how the "it says
down but it works" class of bug is born.

**Sub-second resolution.** The source is a 1 Hz metrics tick and a
transition stream. A finer axis would be drawn precision over data that
is not there.

**Multi-instance aggregation.** One Arenet, one history. Federating two
instances is a different product.

**SLA reports and exports.** The page answers "what happened". Turning
that into a contractual document is a separate feature with separate
requirements, and shipping half of it invites the half to be quoted.

---

## Data model

Schema **v15**, following the conventions every existing table obeys
(`id INTEGER PRIMARY KEY AUTOINCREMENT`, `ts INTEGER` Unix seconds UTC,
a `(ts)` index plus one `(dimension, ts)` composite per drill-down):

```sql
-- One row per state change. A backend up for a month is one row.
CREATE TABLE health_event (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        INTEGER NOT NULL,          -- stamped at Handle() time (D11)
  route_id  TEXT    NOT NULL,          -- resolved at ingest (D11)
  upstream  TEXT    NOT NULL,          -- NormalizeAddr'd host:port
  state     TEXT    NOT NULL,          -- healthy | unhealthy | assumed | reload
  source    TEXT    NOT NULL           -- caddy_event | reload_marker
);
CREATE INDEX idx_health_event_ts        ON health_event(ts);
CREATE INDEX idx_health_event_route_ts  ON health_event(route_id, ts);
CREATE INDEX idx_health_event_up_ts     ON health_event(upstream, ts);

-- Durations, not ratios (D6). Rolled up by RetentionRunner.tick (D4).
CREATE TABLE health_bucket_1h (
  route_id  TEXT    NOT NULL,
  upstream  TEXT    NOT NULL,
  ts        INTEGER NOT NULL,          -- hour start
  up_ms     INTEGER NOT NULL,
  down_ms   INTEGER NOT NULL,
  assumed_ms INTEGER NOT NULL,         -- D3: believed up, never observed
  flips     INTEGER NOT NULL,          -- transitions in the hour
  PRIMARY KEY (route_id, upstream, ts)
);
CREATE INDEX idx_health_bucket_1h_ts ON health_bucket_1h(ts);
-- health_bucket_1d: identical, ts = day start.
```

`state = 'reload'` is the D2 marker: it closes every open interval and
opens an `assumed` one. `assumed_ms` is tracked separately from `up_ms`
precisely so the page can distinguish *observed healthy* from *believed
healthy*, and so an instance that is reloaded constantly cannot inflate
its own uptime figure.

### Read path

The bucketed-aggregate idiom already in the tree
(`cert_event.go:479-487`) — integer division, no `strftime`, stable
boundaries across calls sharing the same `From`:

```sql
SELECT ((ts - ?) / ?) AS bucket_idx, ...
FROM health_event WHERE ts >= ? AND ts < ?
GROUP BY bucket_idx ORDER BY bucket_idx ASC
```

Empty buckets are emitted as zero rows so the frontend needs no
client-side gap-fill, as `AggregateCertEvents` already does.

---

## Empirical validation gates

Per the project's standing rule, each of these is a test or a measured
probe, not an argument.

**G1 — a reload must not manufacture an outage.** Drive the tracker
through `Reset()` with no subsequent events and assert the history
reports `assumed`, not a continuing `unhealthy`. **This is the gate that
justifies the spec**; if it is not written first, D2 will be forgotten
and the page will lie.

**G2 — uptime is exact.** Insert a known transition sequence, compute
the ratio by hand, assert equality at the minute, hour and day grains.
D6 claims exactness; it has to be demonstrated, not asserted.

**G3 — the rollup is idempotent.** Run `tick()` twice over the same
closed hour and assert the bucket is not double-counted. The existing
`lastRollupHour` cursor is the mechanism; this pins it for the new step.

**G4 — a daily bucket survives the pruning of its source.** Prune
`health_event` past 90 d and assert the daily rows for that period are
intact. A retention ladder whose upper rungs depend on the lower ones
is not a ladder.

**G5 — the disk budget is measured, not estimated.** Insert a year of
synthetic transitions and rollups for 40 upstreams, `VACUUM`, and report
the file size. D5 predicts a few MB; the number goes in the smoke doc.

**G6 — the alert fires on a real outage and NOT on a reload.** Both
halves, in one test. D9 exists because of the second half.

---

## What this does NOT fix

The 2026-10-03 incident had a cause this page would have **explained**
but not prevented: the `/etc/hosts` pin missing before a DNS change,
and Arenet proxying to itself. A history page makes a past outage
legible. It does not make a wrong configuration right — and the thing
that actually prevented a repeat was the upstream TLS server name field
(v2.60.0), which removed the need for the pin at all.

Worth keeping in view when weighing this work against the rest of the
backlog: **this is a diagnostic feature, not a protective one.**
