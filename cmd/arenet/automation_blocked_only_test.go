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

package main

import (
	"context"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/observability"
)

// v2.58.4 — Security Automation only counts what the WAF actually refused.
//
// It counted detect-mode events too, which inverted the severity of the WAF's
// own modes: a route in detect let the request through and then had its
// visitor banned everywhere — a broader consequence than the block it had
// declined to apply.
//
// The fixture is the operator's real log, trimmed: CRS flagging Arenet's own
// version endpoint as SQLi, its own static assets as anomalies, n8n's
// telemetry as RCE, and a reader of a public article as a protocol violation.
// Every one of those is a false positive from an IP that must not be banned.
// With the SQLi and RCE rules enabled, the old behaviour banned the admin IP,
// a backend and a real visitor within minutes.
func TestAutomationWafReader_CountsOnlyBlockedEvents(t *testing.T) {
	ctx := context.Background()
	store, err := observability.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open observability store: %v", err)
	}
	defer store.Close()

	t0 := time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	detected := []observability.WafEvent{
		{Ts: t0, RouteID: "r-admin", RuleID: "942290", Category: "SQLi", Severity: 2,
			SrcIP: "203.0.113.1", RequestMethod: "GET", RequestPath: "/api/v1/system/version",
			Action: observability.WafActionDetect, StatusCode: 200},
		{Ts: t0.Add(time.Second), RouteID: "r-admin", RuleID: "949110", Category: "ANOMALY_REQ", Severity: 2,
			SrcIP: "203.0.113.1", RequestMethod: "GET", RequestPath: "/_app/immutable/chunks/a.js",
			Action: observability.WafActionDetect, StatusCode: 200},
		{Ts: t0.Add(2 * time.Second), RouteID: "r-n8n", RuleID: "932370", Category: "RCE", Severity: 4,
			SrcIP: "203.0.113.1", RequestMethod: "POST", RequestPath: "/rest/ph/i/v0/e/",
			Action: observability.WafActionDetect, StatusCode: 200},
		{Ts: t0.Add(3 * time.Second), RouteID: "r-www", RuleID: "920420", Category: "PROTOCOL", Severity: 2,
			SrcIP: "198.51.100.7", RequestMethod: "GET", RequestPath: "/guide-demarrage/",
			Action: observability.WafActionDetect, StatusCode: 200},
	}
	blockedEvent := observability.WafEvent{
		Ts: t0.Add(4 * time.Second), RouteID: "r-www", RuleID: "942100", Category: "SQLi", Severity: 4,
		SrcIP: "192.0.2.66", RequestMethod: "GET", RequestPath: "/?id=1'+OR+1=1",
		Action: observability.WafActionBlock, StatusCode: 403,
	}
	if err := store.InsertWafEventBatch(ctx, append(detected, blockedEvent)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	reader := automationWafReader{store: store}
	got, err := reader.QueryWafEvents(ctx, automation.WafFilter{
		From:  t0.Add(-time.Minute),
		To:    t0.Add(time.Minute),
		Limit: 100,
	})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}

	if len(got) != 1 {
		var ips []string
		for _, e := range got {
			ips = append(ips, e.SrcIP)
		}
		t.Fatalf("engine saw %d events from %v; want 1.\n\nEvery extra one is a CRS false "+
			"positive whose source would be banned across every route and every L4 service.",
			len(got), ips)
	}
	if got[0].SrcIP != blockedEvent.SrcIP {
		t.Errorf("engine saw %q; want %q — the only request the WAF actually refused",
			got[0].SrcIP, blockedEvent.SrcIP)
	}
	if got[0].Source != automation.SourceWafSQLi {
		t.Errorf("source = %q; want %q", got[0].Source, automation.SourceWafSQLi)
	}
}

// A detect-only window must produce nothing at all, so a route left in detect
// mode never contributes to a ban.
func TestAutomationWafReader_DetectOnlyWindowIsSilent(t *testing.T) {
	ctx := context.Background()
	store, err := observability.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	t0 := time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	noise := make([]observability.WafEvent, 0, 20)
	for i := 0; i < 20; i++ {
		noise = append(noise, observability.WafEvent{
			Ts: t0.Add(time.Duration(i) * time.Second), RouteID: "r", RuleID: "942290",
			Category: "SQLi", Severity: 2, SrcIP: "203.0.113.1", RequestMethod: "GET",
			RequestPath: "/api/v1/system/version",
			Action:      observability.WafActionDetect, StatusCode: 200,
		})
	}
	if err := store.InsertWafEventBatch(ctx, noise); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := automationWafReader{store: store}.QueryWafEvents(ctx, automation.WafFilter{
		From: t0.Add(-time.Minute), To: t0.Add(time.Minute), Limit: 100,
	})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("engine saw %d events; want 0 — twenty detections on one endpoint is what a "+
			"CRS false positive looks like, and it must not ban anyone", len(got))
	}
}
