<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Health history — implementation plan

**Spec**: `docs/superpowers/specs/2026-10-04-health-history-design.md`
**Target**: v2.62.0 (persistence + alert), v2.63.0 (the page)

The order is not arbitrary. Task 1 is the gate the spec calls
load-bearing (G1): if the reload boundary is not pinned before anything
reads this data, D2 gets forgotten and the page reports eternal
outages on services that are running.

---

## v2.62.0 — persistence and the alert

**T1. The reload boundary, test first.**
Write G1 before the feature: drive `caddyhc` through `Reset()` with no
subsequent events and assert the derived history says `assumed`, not a
continuing `unhealthy`. It must fail for the right reason (nothing is
persisted yet), then pass once T2–T4 land. Every other task in this
plan is allowed to be convenient; this one is allowed to be awkward.

**T2. Schema v15.**
`health_event`, `health_bucket_1h`, `health_bucket_1d` per the spec,
added as migration step 15 in `internal/observability/migrate.go`
(`currentSchemaVersion` 14 → 15, one entry in the steps map at
`:118-132`). Follow the `INSERT ... SELECT WHERE NOT EXISTS` seed
pattern documented at `storage.go:57-64`, not `INSERT OR IGNORE`.

**T3. Ingest.**
A `HealthSink` in `internal/observability`, buffered-async like
`auth_sink.go` / `cert_sink.go`. `caddyhc.EventHandler.Handle` stamps
`time.Now()` and resolves the route ID from the normalised address
(D11), then submits. The tracker keeps its current in-memory behaviour
untouched — the sink is a second consumer, not a replacement, so a
failure to persist can never degrade the data plane's health view.

**T4. The reload marker.**
`caddyhc.Reset()` emits one `state = 'reload'` row per known upstream
before clearing, closing every open interval; the derivation then opens
an `assumed` interval. This is the D2/D3 pair and it is what T1 proves.

**T5. Rollup + retention.**
One `rollupHealthHour` step and one `PruneHealthEventsOlderThan` call
inside the existing `RetentionRunner.tick` (`retention.go:186-272`),
beside the current ten. Three new `Retain*` constants (90 d / 30 d /
400 d). Gates G3 (idempotent) and G4 (daily survives its source being
pruned) belong here.

**T6. The read query.**
`AggregateHealth(filter)` following the `((ts - ?) / ?)` idiom from
`cert_event.go:479-487`, emitting zero rows for empty buckets so the
frontend needs no gap-fill. Gate G2 (uptime is exact) belongs here, at
all three grains.

**T7. The alert source.**
`source_pool_down.go` beside the existing six, firing when a route's
pool goes fully unhealthy and **not** on a reload. Gate G6 covers both
halves in one test. This is D9 — it ships here because it needs T4.

**T8. The disk measurement.**
Gate G5: a year of synthetic transitions and rollups for 40 upstreams,
`VACUUM`, report the file size into `docs/smoke-test-health-history.md`.
The spec predicts a few MB; a prediction in a spec is a liability until
it is a number in a smoke doc.

---

## v2.63.0 — the page

**T9. The ribbon.**
A hand-rolled SVG component in the house style (D12 — no D3; see
`TimelineChart.svelte:17-24`). Colour carries state, height carries the
route's p95 from `bucket_1m` (D7).

**T10. The event lane.**
Aligned to the same time axis, reading the eight existing event tables
(D8). This is the half no competitor can reproduce, and the half that
answers the question that cost an hour on 2026-10-03.

**T11. The page itself.**
Per-route, reachable from the row and from the edit panel — the entry
points added in v2.61.0 are the precedent to follow, and the lesson is
already paid for: a page nobody can reach is a page nobody has.

---

## Deliberately deferred

**Grouping redirects by target** in the topology (owed from v2.61.0),
and **the metrics strip** in the route panel header. Both are small and
independent; neither should be bundled into this.
