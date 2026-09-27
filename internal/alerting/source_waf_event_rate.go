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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// AL.2.a — waf_event_rate Source.
//
// Counts waf_event rows matching the operator-supplied
// filter over a sliding window ending at "now". Returns
// the count as a SourceValue.Float so a ThresholdEvaluator
// can compare it against a per-rule limit.
//
// Reader audit (see commit body): the *observability.Store
// already exposes QueryWafEvents(ctx, WafEventFilter)
// returning []WafEvent. The Filter supports RouteID +
// Category + From + To + Limit but NOT Action — this
// source filters Action client-side post-query. The
// homelab tick volume (≤ a few hundred rows per minute on
// a busy day) keeps the in-memory filter cost trivial.

// WafEventRateParams is the Source.Read params shape.
type WafEventRateParams struct {
	// RouteID narrows the count to one route. Empty =
	// count across all routes.
	RouteID string `json:"routeId,omitempty"`
	// Category narrows by OWASP CRS category (operator
	// supplies "anomaly", "sqli", ...). Empty = all
	// categories.
	Category string `json:"category,omitempty"`
	// Action filters the rows post-query. Allowed:
	// "BLOCK" (count only block-mode events), "DETECT"
	// (count only detect-mode), "" (count all).
	Action string `json:"action,omitempty"`
	// WindowSecs is the lookback window in seconds. Range
	// [60, 86400]. Defaults to 300 (5 minutes) when zero.
	WindowSecs int `json:"windowSecs"`
}

const (
	wafEventRateDefaultWindowSecs = 300
	wafEventRateMinWindowSecs     = 60
	wafEventRateMaxWindowSecs     = 86400
)

// wafActions enumerates the allowed Action filter tokens.
var wafActions = []string{"", "BLOCK", "DETECT"}

// WafEventReader is the seam the source reads through.
// *observability.Store satisfies it via QueryWafEvents.
// Declared on the consumer side so the alerting package
// doesn't take a structural dep on the store's broader
// surface.
type WafEventReader interface {
	CountWafEvents(ctx context.Context, filter observability.WafEventFilter) (int, error)
}

// WafEventRateSource counts waf_event rows.
type WafEventRateSource struct {
	reader WafEventReader
	now    func() time.Time // injectable for tests
}

// NewWafEventRateSource constructs the source. reader may
// be nil — Read returns an error so the watcher records
// "observability disabled" rather than panicking. This
// matches the AC #13 degraded-observability contract.
func NewWafEventRateSource(reader WafEventReader) *WafEventRateSource {
	return &WafEventRateSource{
		reader: reader,
		now:    time.Now,
	}
}

// Name implements Source.
func (s *WafEventRateSource) Name() string { return "waf_event_rate" }

// ValidateParams implements Source.
func (s *WafEventRateSource) ValidateParams(raw json.RawMessage) error {
	var p WafEventRateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("waf_event_rate: params not valid JSON: %w", err)
	}
	if !stringInSlice(p.Action, wafActions) {
		return fmt.Errorf("waf_event_rate: action %q must be one of %v",
			p.Action, wafActions)
	}
	w := p.WindowSecs
	if w == 0 {
		w = wafEventRateDefaultWindowSecs
	}
	if w < wafEventRateMinWindowSecs || w > wafEventRateMaxWindowSecs {
		return fmt.Errorf("waf_event_rate: windowSecs %d out of range [%d, %d]",
			p.WindowSecs, wafEventRateMinWindowSecs, wafEventRateMaxWindowSecs)
	}
	return nil
}

// Read implements Source.
func (s *WafEventRateSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.reader == nil {
		return SourceValue{}, errors.New("waf_event_rate: observability reader not wired (boot-degraded)")
	}

	var p WafEventRateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return SourceValue{}, fmt.Errorf("waf_event_rate: params decode: %w", err)
	}
	if p.WindowSecs == 0 {
		p.WindowSecs = wafEventRateDefaultWindowSecs
	}

	now := s.now()
	// v2.52 — counted in SQL.
	//
	// This used to fetch rows and take len(), asking for 10 000. The
	// store clamps any result-set limit to 100, so the count could never
	// exceed 100 and EVERY threshold above that was unreachable — a rule
	// asking for "more than 200 WAF events in 5 minutes" could not fire,
	// ever. The saturation label meant to warn about it was equally
	// unreachable, and is gone with the cap.
	//
	// The action filter also moved into SQL: filtering client-side after
	// a capped fetch narrowed an already-truncated set.
	filter := observability.WafEventFilter{
		RouteID:  p.RouteID,
		Category: p.Category,
		Action:   strings.ToUpper(p.Action),
		From:     now.Add(-time.Duration(p.WindowSecs) * time.Second),
		To:       now,
	}
	count, err := s.reader.CountWafEvents(ctx, filter)
	if err != nil {
		return SourceValue{}, fmt.Errorf("waf_event_rate: count: %w", err)
	}

	labels := map[string]string{
		"window_secs": fmt.Sprintf("%d", p.WindowSecs),
	}
	if p.RouteID != "" {
		labels["route_id"] = p.RouteID
	}
	if p.Category != "" {
		labels["category"] = p.Category
	}
	if p.Action != "" {
		labels["action"] = p.Action
	}
	v := FloatValue(float64(count))
	v.Labels = labels
	return v, nil
}
