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
	"testing"
	"time"
)

func seedEvents(t *testing.T, s *Store, events []WafEvent) {
	t.Helper()
	if err := s.InsertWafEventBatch(context.Background(), events); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestWafEvent_InsertAndQuery_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "942100", Category: "SQLi", Severity: 4,
			SrcIP: "1.2.3.4", RequestMethod: "GET", RequestPath: "/?id=1' OR 1=1", PayloadSample: "id=1' OR 1=1"},
		{Ts: t0.Add(time.Minute), RouteID: "r-a", RuleID: "941100", Category: "XSS", Severity: 3,
			SrcIP: "5.6.7.8", RequestMethod: "POST", RequestPath: "/search", PayloadSample: "<script>"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-b", RuleID: "942100", Category: "SQLi", Severity: 4,
			SrcIP: "1.2.3.4", RequestMethod: "GET", RequestPath: "/x", PayloadSample: "x"},
	})

	// Unfiltered → 3 rows, ts-descending.
	got, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("unfiltered rows = %d, want 3", len(got))
	}
	// AC: ordering is ts-descending.
	if !got[0].Ts.After(got[1].Ts) || !got[1].Ts.After(got[2].Ts) {
		t.Errorf("ordering: %v %v %v — want descending", got[0].Ts, got[1].Ts, got[2].Ts)
	}
	// Field round-trip.
	if got[0].RuleID != "942100" && got[0].RuleID != "941100" {
		// Most recent is at t0+2m, route r-b, rule 942100.
		t.Logf("most recent: %+v", got[0])
	}
	if got[0].RouteID != "r-b" || got[0].Category != "SQLi" {
		t.Errorf("most recent row mismatch: %+v", got[0])
	}
}

func TestWafEvent_FilterByRoute(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(time.Minute), RouteID: "r-b", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-a", RuleID: "2", Category: "XSS"},
	})
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{RouteID: "r-a"})
	if len(got) != 2 {
		t.Fatalf("r-a filter rows = %d, want 2", len(got))
	}
	for _, e := range got {
		if e.RouteID != "r-a" {
			t.Errorf("filter leak: %+v", e)
		}
	}
}

func TestWafEvent_FilterByCategory(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "942100", Category: "SQLi"},
		{Ts: t0.Add(time.Minute), RouteID: "r-a", RuleID: "941100", Category: "XSS"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-b", RuleID: "942200", Category: "SQLi"},
	})
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{Category: "SQLi"})
	if len(got) != 2 {
		t.Fatalf("SQLi filter rows = %d, want 2", len(got))
	}
}

func TestWafEvent_FilterByTimeRange(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0.Add(-1 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"},
		{Ts: t0, RouteID: "r", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"},
	})
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{
		From: t0.Add(-30 * time.Minute),
		To:   t0.Add(30 * time.Minute),
	})
	if len(got) != 1 {
		t.Fatalf("time-range rows = %d, want 1 (only t0 falls in [t0-30m, t0+30m))", len(got))
	}
}

func TestWafEvent_LimitClampedToCap(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	// Seed 200 rows; the cap should clamp the result to 100.
	events := make([]WafEvent, 200)
	for i := range events {
		events[i] = WafEvent{
			Ts:      t0.Add(time.Duration(i) * time.Second),
			RouteID: "r", RuleID: "1", Category: "SQLi",
		}
	}
	seedEvents(t, s, events)

	// Ask for 500 → server clamps to wafEventLimitCap (100).
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{Limit: 500})
	if len(got) != wafEventLimitCap {
		t.Fatalf("Limit=500 should clamp to %d, got %d", wafEventLimitCap, len(got))
	}
	// Limit=0 (unset) ALSO defaults to the cap.
	got, _ = s.QueryWafEvents(ctx, WafEventFilter{})
	if len(got) != wafEventLimitCap {
		t.Fatalf("Limit=0 (default) should yield %d rows, got %d", wafEventLimitCap, len(got))
	}
}

func TestWafEvent_PruneOlderThan(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: now.Add(-31 * 24 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"}, // stale
		{Ts: now.Add(-29 * 24 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"}, // kept
		{Ts: now, RouteID: "r", RuleID: "1", Category: "SQLi"},                           // kept
	})
	n, err := s.PruneWafEventsOlderThan(ctx, now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	got, _ := s.QueryWafEvents(ctx, WafEventFilter{})
	if len(got) != 2 {
		t.Fatalf("post-prune rows = %d, want 2", len(got))
	}
}

func TestWafEvent_EmptyBatch_NoOp(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	if err := s.InsertWafEventBatch(ctx, nil); err != nil {
		t.Fatalf("nil batch: %v", err)
	}
	if err := s.InsertWafEventBatch(ctx, []WafEvent{}); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

// --- M.2 amendment #2: AggregateWafEventsByRule -----------------------------

func TestAggregateWafEventsByRule_GroupsByRuleAndCategory(t *testing.T) {
	// 3 rules / 4 categories on the same route over the
	// same window. Aggregation should produce one row per
	// (rule, category) tuple, with correct counts and the
	// most-recent ts per tuple.
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		// rule 942100 / SQLi — 3 events, span 0..2 min.
		{Ts: t0, RouteID: "r", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1"},
		{Ts: t0.Add(1 * time.Minute), RouteID: "r", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.2"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.3"},
		// rule 941100 / XSS — 2 events.
		{Ts: t0.Add(30 * time.Second), RouteID: "r", RuleID: "941100", Category: "XSS", SrcIP: "2.2.2.1"},
		{Ts: t0.Add(90 * time.Second), RouteID: "r", RuleID: "941100", Category: "XSS", SrcIP: "2.2.2.2"},
		// rule 932100 / RCE — 1 event, most recent overall.
		{Ts: t0.Add(3 * time.Minute), RouteID: "r", RuleID: "932100", Category: "RCE", SrcIP: "3.3.3.1"},
	})

	got, err := s.AggregateWafEventsByRule(ctx, WafEventAggregateFilter{
		RouteID: "r",
		From:    t0.Add(-1 * time.Hour),
		To:      t0.Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("rows = %d, want 3 (one per rule+category): %+v", len(got), got)
	}

	// Order: count DESC. Most-counted = 942100 SQLi (3),
	// then 941100 XSS (2), then 932100 RCE (1).
	if got[0].RuleID != "942100" || got[0].Category != "SQLi" || got[0].Count != 3 {
		t.Errorf("row[0] = %+v, want 942100/SQLi/3", got[0])
	}
	if got[1].RuleID != "941100" || got[1].Category != "XSS" || got[1].Count != 2 {
		t.Errorf("row[1] = %+v, want 941100/XSS/2", got[1])
	}
	if got[2].RuleID != "932100" || got[2].Category != "RCE" || got[2].Count != 1 {
		t.Errorf("row[2] = %+v, want 932100/RCE/1", got[2])
	}

	// LastSeen for 942100 must be the third event at t0+2m.
	wantLast := t0.Add(2 * time.Minute)
	if !got[0].LastSeen.Equal(wantLast) {
		t.Errorf("row[0].LastSeen = %v, want %v", got[0].LastSeen, wantLast)
	}
}

func TestAggregateWafEventsByRule_FilterByRoute(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r-a", RuleID: "942100", Category: "SQLi"},
		{Ts: t0.Add(time.Minute), RouteID: "r-b", RuleID: "942100", Category: "SQLi"},
		{Ts: t0.Add(2 * time.Minute), RouteID: "r-a", RuleID: "942100", Category: "SQLi"},
	})

	got, _ := s.AggregateWafEventsByRule(ctx, WafEventAggregateFilter{RouteID: "r-a"})
	if len(got) != 1 {
		t.Fatalf("r-a rows = %d, want 1", len(got))
	}
	if got[0].Count != 2 {
		t.Errorf("r-a aggregate count = %d, want 2 (r-b's row must NOT inflate it)", got[0].Count)
	}
}

func TestAggregateWafEventsByRule_FilterByTimeRange(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0.Add(-2 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"},
		{Ts: t0, RouteID: "r", RuleID: "1", Category: "SQLi"},
		{Ts: t0.Add(2 * time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi"},
	})

	got, _ := s.AggregateWafEventsByRule(ctx, WafEventAggregateFilter{
		RouteID: "r",
		From:    t0.Add(-time.Hour),
		To:      t0.Add(time.Hour),
	})
	if len(got) != 1 || got[0].Count != 1 {
		t.Fatalf("time-range filter wrong: got %+v, want 1 row with count=1", got)
	}
}

func TestAggregateWafEventsByRule_EmptyWindow(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	got, err := s.AggregateWafEventsByRule(ctx, WafEventAggregateFilter{
		From: time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 5, 28, 11, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty window should yield 0 rows, got %d", len(got))
	}
}

func TestAggregateWafEventsByRule_DistinctCategoriesPerRule(t *testing.T) {
	// Defensive check: if the same rule_id ever appears
	// against two categories (config drift), the aggregation
	// emits one row PER (rule, category) tuple. Frontend
	// then shows both — honest about the inconsistency.
	ctx := context.Background()
	s, _ := Open(ctx, ":memory:")
	defer s.Close()
	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		{Ts: t0, RouteID: "r", RuleID: "999999", Category: "OTHER"},
		{Ts: t0.Add(time.Minute), RouteID: "r", RuleID: "999999", Category: "PROTOCOL"},
	})

	got, _ := s.AggregateWafEventsByRule(ctx, WafEventAggregateFilter{RouteID: "r"})
	if len(got) != 2 {
		t.Fatalf("expected 2 rows (one per category), got %d: %+v", len(got), got)
	}
}

// --- Step Q.3: DistinctSrcIPs --------------------------------------------------

func TestDistinctWafEventSrcIPs_DedupesAndRespectsWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		// In-window: three events from two distinct IPs.
		{Ts: t0, RouteID: "r", RuleID: "1", Category: "SQLi", SrcIP: "1.1.1.1"},
		{Ts: t0.Add(time.Second), RouteID: "r", RuleID: "1", Category: "SQLi", SrcIP: "1.1.1.1"},
		{Ts: t0.Add(2 * time.Second), RouteID: "r", RuleID: "1", Category: "SQLi", SrcIP: "2.2.2.2"},
		// Out-of-window: must NOT appear in the distinct set.
		{Ts: t0.Add(-time.Hour), RouteID: "r", RuleID: "1", Category: "SQLi", SrcIP: "9.9.9.9"},
	})

	ips, err := s.DistinctWafEventSrcIPs(ctx, t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("DistinctWafEventSrcIPs: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(ips) = %d, want 2 (window dedupes + excludes 9.9.9.9): %v", len(ips), ips)
	}
	have := map[string]bool{}
	for _, ip := range ips {
		have[ip] = true
	}
	if !have["1.1.1.1"] || !have["2.2.2.2"] {
		t.Errorf("missing expected IPs in distinct set: %v", ips)
	}
	if have["9.9.9.9"] {
		t.Errorf("out-of-window IP leaked: %v", ips)
	}
}

func TestDistinctThrottleEventSrcIPs_DedupesAndRespectsWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 5, 28, 10, 0, 0, 0, time.UTC)
	if err := s.InsertThrottleEventBatch(ctx, []ThrottleEvent{
		{Ts: t0, Tier: 1, SrcIP: "1.1.1.1", AttemptedUsername: "admin", BlockedUntil: t0.Add(15 * time.Minute), BlockDurationSeconds: 900},
		{Ts: t0.Add(time.Second), Tier: 1, SrcIP: "1.1.1.1", AttemptedUsername: "admin", BlockedUntil: t0.Add(15 * time.Minute), BlockDurationSeconds: 900},
		{Ts: t0.Add(2 * time.Second), Tier: 2, SrcIP: "3.3.3.3", AttemptedUsername: "root", BlockedUntil: t0.Add(time.Hour), BlockDurationSeconds: 3600},
		// Out-of-window.
		{Ts: t0.Add(-time.Hour), Tier: 1, SrcIP: "9.9.9.9", AttemptedUsername: "x", BlockedUntil: t0.Add(-time.Minute), BlockDurationSeconds: 900},
	}); err != nil {
		t.Fatalf("seed throttle: %v", err)
	}

	ips, err := s.DistinctThrottleEventSrcIPs(ctx, t0, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("DistinctThrottleEventSrcIPs: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("len(ips) = %d, want 2 (window dedupes + excludes 9.9.9.9): %v", len(ips), ips)
	}
	have := map[string]bool{}
	for _, ip := range ips {
		have[ip] = true
	}
	if !have["1.1.1.1"] || !have["3.3.3.3"] {
		t.Errorf("missing expected IPs: %v", ips)
	}
	if have["9.9.9.9"] {
		t.Errorf("out-of-window IP leaked: %v", ips)
	}
}

// --- #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — AggregateWafEventsByCategory tests

func TestAggregateWafEventsByCategory_GroupsByCategory(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1700000000, 0).UTC()
	if err := s.InsertWafEventBatch(ctx, []WafEvent{
		{Ts: t0, RouteID: "r1", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(1 * time.Second), RouteID: "r1", RuleID: "942110", Category: "SQLi", SrcIP: "1.1.1.2", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(2 * time.Second), RouteID: "r1", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.3", Action: "DETECT", StatusCode: 0},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.AggregateWafEventsByCategory(ctx, WafEventCategoryFilter{
		From: t0.Add(-time.Hour),
		To:   t0.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("AggregateWafEventsByCategory: %v", err)
	}
	// Expect SQLi=2, LFI=1, ordered by cnt DESC.
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2: %+v", len(got), got)
	}
	if got[0].Category != "SQLi" || got[0].Count != 2 {
		t.Errorf("row[0] = %+v, want {SQLi, 2}", got[0])
	}
	if got[1].Category != "LFI" || got[1].Count != 1 {
		t.Errorf("row[1] = %+v, want {LFI, 1}", got[1])
	}
}

func TestAggregateWafEventsByCategory_ActionFilter(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1700000000, 0).UTC()
	if err := s.InsertWafEventBatch(ctx, []WafEvent{
		{Ts: t0, RouteID: "r1", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(1 * time.Second), RouteID: "r1", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.3", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(2 * time.Second), RouteID: "r1", RuleID: "930200", Category: "LFI", SrcIP: "1.1.1.4", Action: "DETECT", StatusCode: 0},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	blocks, err := s.AggregateWafEventsByCategory(ctx, WafEventCategoryFilter{
		Action: "BLOCK",
		From:   t0.Add(-time.Hour),
		To:     t0.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("AggregateWafEventsByCategory BLOCK: %v", err)
	}
	if len(blocks) != 1 || blocks[0].Category != "SQLi" || blocks[0].Count != 1 {
		t.Errorf("BLOCK rows = %+v; want SQLi=1 only", blocks)
	}

	detects, err := s.AggregateWafEventsByCategory(ctx, WafEventCategoryFilter{
		Action: "DETECT",
		From:   t0.Add(-time.Hour),
		To:     t0.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("AggregateWafEventsByCategory DETECT: %v", err)
	}
	if len(detects) != 1 || detects[0].Category != "LFI" || detects[0].Count != 2 {
		t.Errorf("DETECT rows = %+v; want LFI=2 only", detects)
	}
}

func TestAggregateWafEventsByCategory_EmptyWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	got, err := s.AggregateWafEventsByCategory(ctx, WafEventCategoryFilter{
		From: time.Unix(1700000000, 0).UTC(),
		To:   time.Unix(1700003600, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("AggregateWafEventsByCategory empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty window returned %d rows; want 0", len(got))
	}
}

func TestAggregateWafEventsByCategory_RouteFilter(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1700000000, 0).UTC()
	if err := s.InsertWafEventBatch(ctx, []WafEvent{
		{Ts: t0, RouteID: "r1", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(1 * time.Second), RouteID: "r2", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.3", Action: "BLOCK", StatusCode: 403},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.AggregateWafEventsByCategory(ctx, WafEventCategoryFilter{
		RouteID: "r1",
		From:    t0.Add(-time.Hour),
		To:      t0.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("AggregateWafEventsByCategory route-filter: %v", err)
	}
	if len(got) != 1 || got[0].Category != "SQLi" {
		t.Errorf("route-filtered rows = %+v; want only SQLi (route r1)", got)
	}
}

// --- AggregateWafEventsByRoute tests --------------------------------------

// Follow-up to 579f695 — unifies WAF counter reads on the
// waf_event table for cross-source-of-truth consistency.

func TestAggregateWafEventsByRoute_BlocksAndDetects(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1700000000, 0).UTC()
	if err := s.InsertWafEventBatch(ctx, []WafEvent{
		// route r1: 3 BLOCK + 1 DETECT
		{Ts: t0, RouteID: "r1", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(1 * time.Second), RouteID: "r1", RuleID: "942110", Category: "SQLi", SrcIP: "1.1.1.2", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(2 * time.Second), RouteID: "r1", RuleID: "942120", Category: "SQLi", SrcIP: "1.1.1.3", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(3 * time.Second), RouteID: "r1", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.4", Action: "DETECT", StatusCode: 0},
		// route r2: 0 BLOCK + 5 DETECT
		{Ts: t0.Add(4 * time.Second), RouteID: "r2", RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.1", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(5 * time.Second), RouteID: "r2", RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.2", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(6 * time.Second), RouteID: "r2", RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.3", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(7 * time.Second), RouteID: "r2", RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.4", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(8 * time.Second), RouteID: "r2", RuleID: "930100", Category: "LFI", SrcIP: "2.2.2.5", Action: "DETECT", StatusCode: 0},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.AggregateWafEventsByRoute(ctx, t0.Add(-time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("AggregateWafEventsByRoute: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d routes; want 2: %+v", len(got), got)
	}
	r1 := got["r1"]
	if r1.Block != 3 || r1.Detect != 1 {
		t.Errorf("r1 = %+v; want {Block:3 Detect:1}", r1)
	}
	r2 := got["r2"]
	if r2.Block != 0 || r2.Detect != 5 {
		t.Errorf("r2 = %+v; want {Block:0 Detect:5}", r2)
	}
}

func TestAggregateWafEventsByRoute_EmptyWindow(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	got, err := s.AggregateWafEventsByRoute(ctx,
		time.Unix(1700000000, 0).UTC(),
		time.Unix(1700003600, 0).UTC())
	if err != nil {
		t.Fatalf("AggregateWafEventsByRoute: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty window returned %d entries; want 0: %+v", len(got), got)
	}
}

func TestAggregateWafEventsByRoute_WindowFilter(t *testing.T) {
	// Pin the time-range filter — events outside the
	// window must NOT contribute to the result.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1700000000, 0).UTC()
	if err := s.InsertWafEventBatch(ctx, []WafEvent{
		{Ts: t0.Add(-24 * time.Hour), RouteID: "old", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: t0, RouteID: "in-window", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
		{Ts: t0.Add(24 * time.Hour), RouteID: "future", RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1", Action: "BLOCK", StatusCode: 403},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.AggregateWafEventsByRoute(ctx, t0.Add(-time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("AggregateWafEventsByRoute: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d routes; want 1 (window filter dropped old+future): %+v", len(got), got)
	}
	if _, ok := got["in-window"]; !ok {
		t.Errorf("in-window route missing from result: %+v", got)
	}
}

func TestAggregateWafEventsByRoute_UnknownActionsDropped(t *testing.T) {
	// Pin the defence-in-depth: an unexpected action ("",
	// "WARN", future enum) must not show up under Block or
	// Detect. The W.bugfix v6→v7 migration backfilled all
	// legacy rows to "BLOCK", so an empty action would
	// indicate a data-layer bug we'd rather surface as a
	// missing count than mis-categorise.
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Unix(1700000000, 0).UTC()
	// Two real DETECT events + one unknown-action event.
	if err := s.InsertWafEventBatch(ctx, []WafEvent{
		{Ts: t0, RouteID: "r", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.1", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(1 * time.Second), RouteID: "r", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.2", Action: "DETECT", StatusCode: 0},
		{Ts: t0.Add(2 * time.Second), RouteID: "r", RuleID: "930100", Category: "LFI", SrcIP: "1.1.1.3", Action: "WARN", StatusCode: 0},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := s.AggregateWafEventsByRoute(ctx, t0.Add(-time.Hour), t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("AggregateWafEventsByRoute: %v", err)
	}
	r := got["r"]
	if r.Block != 0 || r.Detect != 2 {
		t.Errorf("route counts = %+v; want {Block:0 Detect:2} (WARN dropped)", r)
	}
}

// v2.58.4 — QueryWafEvents honours the Action filter.
//
// It always did: both it and CountWafEvents go through wafEventPredicates.
// But the field's own doc comment said "Only CountWafEvents honours it", and
// that false claim had a cost — Security Automation never passed Action,
// because the comment said passing it would do nothing, so it counted
// detect-mode events and would have banned the sources of every CRS false
// positive. The behaviour is pinned here so the next reader trusts the test
// rather than a sentence.
func TestQueryWafEvents_HonoursTheActionFilter(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	t0 := time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	seedEvents(t, s, []WafEvent{
		// What a real log looks like: the false positives dominate.
		{Ts: t0, RouteID: "r-a", RuleID: "942290", Category: "SQLi", Severity: 2,
			SrcIP: "10.0.0.1", RequestMethod: "GET", RequestPath: "/api/v1/system/version",
			Action: WafActionDetect, StatusCode: 200},
		{Ts: t0.Add(time.Second), RouteID: "r-a", RuleID: "949110", Category: "ANOMALY_REQ", Severity: 2,
			SrcIP: "10.0.0.1", RequestMethod: "GET", RequestPath: "/_app/immutable/chunks/x.js",
			Action: WafActionDetect, StatusCode: 200},
		// And the one that was actually refused.
		{Ts: t0.Add(2 * time.Second), RouteID: "r-a", RuleID: "942100", Category: "SQLi", Severity: 4,
			SrcIP: "203.0.113.9", RequestMethod: "GET", RequestPath: "/?id=1'+OR+1=1",
			Action: WafActionBlock, StatusCode: 403},
	})

	blocked, err := s.QueryWafEvents(ctx, WafEventFilter{Action: WafActionBlock})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(blocked) != 1 {
		t.Fatalf("Action=BLOCK returned %d rows; want 1 — the filter is not applied, and "+
			"Security Automation would count every detect-mode false positive", len(blocked))
	}
	if blocked[0].SrcIP != "203.0.113.9" {
		t.Errorf("blocked row SrcIP = %q; want the one the WAF refused", blocked[0].SrcIP)
	}

	detected, err := s.QueryWafEvents(ctx, WafEventFilter{Action: WafActionDetect})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(detected) != 2 {
		t.Errorf("Action=DETECT returned %d rows; want 2", len(detected))
	}

	// No Action = everything, so the events page keeps showing both.
	all, err := s.QueryWafEvents(ctx, WafEventFilter{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("unfiltered returned %d rows; want 3 — an empty Action must not narrow", len(all))
	}
}
