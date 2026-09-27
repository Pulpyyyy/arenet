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

package alerting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/observability"
)

// v2.52 — a count above 100 must be reachable.
//
// The source used to ask QueryWafEvents for 10 000 rows and take len().
// The store clamps any result-set limit to 100 (a cap that exists to
// bound a result set, which a count is not), so the value saturated at
// 100 and every threshold above it was unreachable: a rule asking for
// "more than 200 WAF events in 5 minutes" could not fire, ever.
//
// This is the regression test for exactly that number.

// countingWafReader answers with a fixed total, ignoring the filter
// except to record it.
type countingWafReader struct {
	total  int
	called observability.WafEventFilter
}

func (c *countingWafReader) CountWafEvents(_ context.Context, f observability.WafEventFilter) (int, error) {
	c.called = f
	return c.total, nil
}

func TestWafEventRateSource_CountIsNotCappedAt100(t *testing.T) {
	reader := &countingWafReader{total: 4271}
	src := NewWafEventRateSource(reader)

	got, err := src.Read(context.Background(), json.RawMessage(`{"windowSecs":300}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil {
		t.Fatal("no float value")
	}
	if *got.Float != 4271 {
		t.Fatalf("count = %v, want 4271 — a value of 100 means the result-set cap is back", *got.Float)
	}
}

// The window and the action must reach SQL, not be applied to an
// already-truncated set afterwards.
func TestWafEventRateSource_FilterReachesTheQuery(t *testing.T) {
	reader := &countingWafReader{total: 7}
	src := NewWafEventRateSource(reader)

	if _, err := src.Read(context.Background(),
		json.RawMessage(`{"windowSecs":600,"action":"block","routeId":"r1","category":"sqli"}`)); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if reader.called.Action != "BLOCK" {
		t.Errorf("Action = %q, want BLOCK (upper-cased into the query)", reader.called.Action)
	}
	if reader.called.RouteID != "r1" || reader.called.Category != "sqli" {
		t.Errorf("route/category did not reach the query: %+v", reader.called)
	}
	// 600s window, so From must be 10 minutes before To.
	if d := reader.called.To.Sub(reader.called.From); d.Minutes() != 10 {
		t.Errorf("window = %v, want 10m", d)
	}
	// And Limit must NOT be set: honouring it would reintroduce the cap.
	if reader.called.Limit != 0 {
		t.Errorf("Limit = %d, want 0 — a count has no result set to bound", reader.called.Limit)
	}
}
