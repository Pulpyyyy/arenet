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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/crowdsec"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// automationWafReader adapts *observability.Store to the
// automation.WafEventReader interface. Projects WafEvent rows
// to the engine's normalised SourceEvent shape.
type automationWafReader struct {
	store *observability.Store
}

func (a automationWafReader) QueryWafEvents(ctx context.Context, filter automation.WafFilter) ([]automation.SourceEvent, error) {
	if a.store == nil {
		// AC #13 degraded-mode (observability boot-failure).
		// Returning empty is correct: engine ticks see no
		// events, no intents emitted.
		return nil, nil
	}
	rows, err := a.store.QueryWafEvents(ctx, observability.WafEventFilter{
		From: filter.From,
		To:   filter.To,
		// v2.58.4 — only what the WAF actually refused.
		//
		// Security Automation counted detect-mode events too, which inverted
		// the severity of the WAF's own modes: a route in detect let the
		// request through and then had its visitor banned everywhere, a
		// broader consequence than the block it had declined to apply.
		//
		// Detect mode exists so an operator can see what CRS flags before
		// acting on it — it is how exclusions get found. Counting those
		// detections to ban a source acts on exactly the signal that has not
		// been validated yet. An operator's log showed what that costs: CRS
		// flagging Arenet's own /api/v1/system/version as SQLi, its own
		// static assets as anomalies, an OIDC authorize URL as SQLi, n8n's
		// telemetry as RCE, and a stream of real readers of a public article
		// as protocol violations. Enabling the SQLi and RCE rules would have
		// banned the admin IP, the SSO, two backends and those readers within
		// minutes.
		//
		// Filtered in SQL rather than after the read: with detect-mode events
		// outnumbering blocks as heavily as they do, a post-filter would let
		// them consume Limit and starve the blocks that matter.
		Action: observability.WafActionBlock,
		Limit:  filter.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]automation.SourceEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, automation.SourceEvent{
			ID:                strconv.FormatInt(r.ID, 10),
			Ts:                r.Ts,
			SrcIP:             r.SrcIP,
			Source:            automation.SourceFromWafCategory(r.Category),
			TriggeringEventID: strconv.FormatInt(r.ID, 10),
		})
	}
	return out, nil
}

// automationThrottleReader is the throttle-side mirror.
type automationThrottleReader struct {
	store *observability.Store
}

func (a automationThrottleReader) QueryThrottleEvents(ctx context.Context, filter automation.ThrottleFilter) ([]automation.SourceEvent, error) {
	if a.store == nil {
		return nil, nil
	}
	rows, err := a.store.QueryThrottleEvents(ctx, observability.ThrottleEventFilter{
		From:  filter.From,
		To:    filter.To,
		Limit: filter.Limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]automation.SourceEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, automation.SourceEvent{
			ID:                strconv.FormatInt(r.ID, 10),
			Ts:                r.Ts,
			SrcIP:             r.SrcIP,
			Source:            automation.SourceFromThrottleTier(r.Tier),
			TriggeringEventID: strconv.FormatInt(r.ID, 10),
		})
	}
	return out, nil
}

// automationAuditReader adapts *audit.Store via the Q.2
// auth-failure surface (QueryByActionRange against
// audit.AuthFailureActions()). All auth failures roll up
// into the single SourceAuthBurst rule.
type automationAuditReader struct {
	store *audit.Store
}

func (a automationAuditReader) QueryAuthFailureEvents(ctx context.Context, from, to time.Time, limit int) ([]automation.SourceEvent, error) {
	if a.store == nil {
		return nil, nil
	}
	events, _, err := a.store.QueryByActionRange(ctx, audit.AuthFailureActions(), from, to, limit)
	if err != nil {
		return nil, err
	}
	out := make([]automation.SourceEvent, 0, len(events))
	for _, e := range events {
		if e.IP == "" {
			// Skip events without an extractable source IP
			// — we have nothing to ban. Trusted-proxy
			// resolution drift is a known cross-cutting
			// backlog item (Q.5-2); P does not address it.
			continue
		}
		out = append(out, automation.SourceEvent{
			ID:                e.ID,
			Ts:                e.Timestamp,
			SrcIP:             e.IP,
			Source:            automation.SourceAuthBurst,
			TriggeringEventID: e.ID,
		})
	}
	return out, nil
}

// automationDedupeChecker reads the local Step N decision_event
// mirror via *observability.Store.QueryDecisionEvents to answer
// "does LAPI have an active decision for (scope, value,
// scenario)?". Per spec D4 rationale: the mirror IS the
// cached LAPI state (Step N's purpose), so reading it instead
// of round-tripping LAPI on every potential push gives us the
// same source-of-truth semantics with zero extra HTTP.
type automationDedupeChecker struct {
	store *observability.Store
}

func (a automationDedupeChecker) HasActiveDecision(ctx context.Context, scope, value, scenario string) (bool, error) {
	if a.store == nil {
		// Degraded-mode: no mirror to read → assume not
		// active. The push goes through; LAPI itself stacks
		// duplicates harmlessly.
		return false, nil
	}
	now := time.Now().UTC()
	rows, err := a.store.QueryDecisionEvents(ctx, observability.DecisionEventFilter{
		Scope:      scope,
		Value:      value,
		Scenario:   scenario,
		OnlyActive: true,
		Limit:      1,
	})
	if err != nil {
		return false, err
	}
	for _, r := range rows {
		if r.ExpiresAt.After(now) {
			return true, nil
		}
	}
	return false, nil
}

// automationAuditEmitter adapts *audit.Store to the
// automation.AuditEmitter interface. Decouples the package
// dependency: automation/ does not import audit/.
type automationAuditEmitter struct {
	store *audit.Store
}

func (a automationAuditEmitter) EmitDecisionPushed(srcIP, scenario, eventID string, count, dur int) {
	if a.store == nil {
		return
	}
	// Background-emit (no request ctx — the writer goroutine
	// is independent of any HTTP handler). audit.Store.Append
	// is safe to call from background goroutines.
	target := scope_value_pair(srcIP)
	msg := fmt.Sprintf("auto-classified %d event(s) from %s under scenario %s for %ds (triggering event %s)",
		count, srcIP, scenario, dur, eventID)
	evt := audit.Event{
		Action:     audit.ActionAutomationDecisionPushed,
		TargetType: "automation_decision",
		TargetID:   target,
		Message:    msg,
	}
	// Best-effort: errors logged but not propagated. The
	// audit store has its own AC #13 fail-quiet semantics.
	_ = a.store.Append(context.Background(), evt)
}

// scope_value_pair formats the audit target_id field for an
// auto-classify decision. Includes the scope ("Ip" for v1.3)
// even though it's redundant with the convention — keeps the
// audit row self-describing if scope-CIDR lands in v1.4.
func scope_value_pair(srcIP string) string {
	return "Ip:" + srcIP
}

// resolveTombstoneToCooldownArgs translates a LAPI decision
// UUID (received via crowdsec.Sink's tombstone listener) into
// the (srcIP, scenario) tuple the trigger engine's OnTombstone
// expects. Reads the local decision_event mirror — same
// table the N consumer populates.
//
// Returns ("", "") if the UUID isn't in the mirror (orphan
// tombstone — could happen if the operator unbans an IP
// before the N consumer has synced it). The trigger engine's
// OnTombstone is nil-safe on empty srcIP (it's a no-op).
func resolveTombstoneToCooldownArgs(ctx context.Context, store *observability.Store, uuid string) (srcIP, scenario string) {
	if store == nil || uuid == "" {
		return "", ""
	}
	// QueryDecisionEvents by UUID — we can't filter on it
	// directly (the storage filter doesn't expose UUID), so
	// fetch by value-then-filter. The mirror table is small
	// (≤30d retention, ≤10k rows on homelab) so a small
	// limit + linear scan is acceptable.
	rows, err := store.QueryDecisionEvents(ctx, observability.DecisionEventFilter{
		Limit: 100,
	})
	if err != nil {
		return "", ""
	}
	for _, r := range rows {
		if r.UUID == uuid {
			return r.Value, r.Scenario
		}
	}
	return "", ""
}

// wireAutomation constructs the trigger engine + manager,
// wires the tombstone listener, registers the global Manager,
// and spawns the engine goroutine. Returns an error ONLY for
// programmer-error class failures (validator mismatches);
// missing watcher creds / boot-time outages are NOT errors —
// they're the boot-degraded path per AC #15.
//
// The five P.2 commit-body checklist items are honoured here:
//  1. ActiveDecisionChecker → reads obsStore.QueryDecisionEvents
//     (the N mirror = LAPI source-of-truth proxy per D4
//     rationale).
//  2. OnTombstone → crowdsec.Sink.SetTombstoneListener wired
//     via a UUID-resolver that looks up the (srcIP, scenario)
//     from the decision_event mirror.
//  3. Credentials update → DefaultManager.SetCredentials does
//     recreate-and-swap atomically (no engine restart).
//  4. Rules update → DefaultManager.SetRules calls
//     RuleSetHolder.Set (already atomic).
//  5. Audit actions automation_decision_pushed +
//     automation_rule_changed wired via
//     automationAuditEmitter + the API handlers (the latter
//     lives in internal/api/automation_handlers.go).
func wireAutomation(
	ctx context.Context,
	wg *sync.WaitGroup,
	store *storage.Store,
	obsStore *observability.Store,
	auditStore *audit.Store,
	crowdsecSink *crowdsec.Sink,
	logger *slog.Logger,
) error {
	// Load rules from BoltDB (DefaultRuleSet on fresh install).
	rules := automation.DefaultRuleSet()
	if raw, err := store.GetAutomationRulesRaw(ctx); err == nil {
		var envelope struct {
			Rules automation.RuleSet `json:"rules"`
		}
		if uerr := json.Unmarshal(raw, &envelope); uerr == nil && envelope.Rules.Rules != nil {
			rules = envelope.Rules
		} else if uerr != nil {
			logger.Warn("automation: corrupt rules row, using defaults", "err", uerr)
		}
	} else if !errors.Is(err, storage.ErrNotFound) {
		logger.Warn("automation: load rules failed, using defaults", "err", err)
	}
	rulesHolder := automation.NewRuleSetHolder(rules)

	// Load watcher credentials from BoltDB. Empty / not-
	// configured is the boot-degraded path: NewWatcherClient
	// returns ErrCredentialsRequired and we wire a nil
	// initial writer into the Manager. The operator can
	// configure credentials later via PUT, and the
	// recreate-and-swap path picks up the new client without
	// restarting the engine.
	var initialWriter *automation.WatcherClient
	if creds, err := store.GetWatcherCredentials(ctx); err == nil {
		client, cerr := automation.NewWatcherClient(automation.WatcherConfig{
			LAPIURL:   creds.LAPIURL,
			MachineID: creds.MachineID,
			Password:  creds.Password,
		})
		if cerr != nil {
			// Bad shape in storage (shouldn't happen — the
			// API validator + the storage validator agree)
			// or operator wrote a partial row directly.
			logger.Warn("automation: stored credentials rejected by WatcherClient, running in degraded mode", "err", cerr)
		} else {
			initialWriter = client
			logger.Info("automation: watcher client wired", "lapi_url", creds.LAPIURL, "machine_id", creds.MachineID)
		}
	} else if !errors.Is(err, storage.ErrNotFound) {
		logger.Warn("automation: load credentials failed, running in degraded mode", "err", err)
	}

	engine, err := automation.NewEngine(automation.EngineConfig{
		Waf:           automationWafReader{store: obsStore},
		Throttle:      automationThrottleReader{store: obsStore},
		Audit:         automationAuditReader{store: auditStore},
		DedupeChecker: automationDedupeChecker{store: obsStore},
		AuditEmitter:  automationAuditEmitter{store: auditStore},
		Rules:         rulesHolder,
		Logger:        logger,
		// WriterProvider wired below via the manager.
	})
	if err != nil {
		return fmt.Errorf("NewEngine: %w", err)
	}

	manager := automation.NewDefaultManager(engine, rulesHolder, initialWriter)
	// Inject the Manager as the engine's WriterProvider so
	// the recreate-and-swap path takes effect at runtime.
	// (Engine reads currentWriter() per-intent.)
	engine.SetWriterProvider(manager)

	automation.SetManager(manager)

	// Step P.3 wiring #2: install the tombstone listener on
	// the Step N Sink. The listener resolves the UUID to
	// (srcIP, scenario) via the local mirror table, then
	// drives Engine.OnTombstone (records cooldown +
	// invalidates dedupe).
	if crowdsecSink != nil {
		crowdsecSink.SetTombstoneListener(func(uuid string) {
			srcIP, scenario := resolveTombstoneToCooldownArgs(context.Background(), obsStore, uuid)
			if srcIP == "" {
				return
			}
			engine.OnTombstone(srcIP, scenario)
		})
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		engine.Run(ctx)
	}()
	logger.Info("automation engine started", "tick_interval", "5s", "rules_enabled", rules.AnyEnabled())

	return nil
}
