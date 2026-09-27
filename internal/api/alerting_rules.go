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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Step AL.3b — AlertRule CRUD HTTP endpoints.
//
// Routes mounted under /api/v1/settings/alerting/rules
// (admin-only via the existing admin sub-group):
//   POST   /                       create
//   GET    /                       list
//   GET    /{id}                   get
//   PUT    /{id}                   update (full replace, mirrors channels)
//   DELETE /{id}                   delete
//   POST   /{id}/test              force-evaluate now via dispatcher
//
// Pattern mirrors internal/api/alerting_channels.go
// (AL.1.b). No secrets in AlertRule shape (templates
// are operator-supplied text/template strings, not
// secret-bearing per D4), so no redaction step on
// GET / audit blobs — full diff cleartext.
//
// Reference integrity:
//   - Channels[] IDs are verified to exist at the
//     handler layer (the storage layer's validate()
//     only checks intrinsic shape).
//   - Source is verified against the wired
//     SourceRegistry — nil-tolerant: when no registry
//     is wired (tests), the check is skipped.

// alertRuleRequest is the wire shape on POST / PUT.
// Full-replace semantics (mirrors alertChannelRequest);
// the operator's UI fetches the rule, mutates the fields
// they want, PUTs the whole shape back.
type alertRuleRequest struct {
	Name            string          `json:"name"`
	Enabled         bool            `json:"enabled"`
	Kind            string          `json:"kind"`
	Severity        int             `json:"severity"`
	Category        string          `json:"category"`
	Source          string          `json:"source"`
	SourceParams    json.RawMessage `json:"sourceParams"`
	EvalParams      json.RawMessage `json:"evalParams"`
	Channels        []string        `json:"channels"`
	CooldownSecs    int             `json:"cooldownSecs"`
	SubjectTemplate string          `json:"subjectTemplate,omitempty"`
	BodyTemplate    string          `json:"bodyTemplate,omitempty"`
}

// alertRuleResponse is the wire shape on GET. Includes
// the watcher-managed telemetry fields (LastEvalAt /
// LastFiredAt / LastError / LastErrorAt) so the operator
// UI can render "last fired 12m ago" / "evaluating
// cleanly" / "errored: source timeout" without a
// separate endpoint.
type alertRuleResponse struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Enabled         bool            `json:"enabled"`
	Kind            string          `json:"kind"`
	Severity        int             `json:"severity"`
	Category        string          `json:"category"`
	Source          string          `json:"source"`
	SourceParams    json.RawMessage `json:"sourceParams"`
	EvalParams      json.RawMessage `json:"evalParams"`
	Channels        []string        `json:"channels"`
	CooldownSecs    int             `json:"cooldownSecs"`
	SubjectTemplate string          `json:"subjectTemplate,omitempty"`
	BodyTemplate    string          `json:"bodyTemplate,omitempty"`
	CreatedAt       string          `json:"createdAt"`
	UpdatedAt       string          `json:"updatedAt"`
	LastFiredAt     *time.Time      `json:"lastFiredAt,omitempty"`
	LastEvalAt      *time.Time      `json:"lastEvalAt,omitempty"`
	LastError       string          `json:"lastError,omitempty"`
	LastErrorAt     *time.Time      `json:"lastErrorAt,omitempty"`
}

// alertRuleTestResponse reports the outcome of a
// force-evaluate test fire. Per-channel breakdown so the
// operator UI can show "delivered to webhook-ops; failed
// on email-ops: 502".
type alertRuleTestResponse struct {
	// Sent is true when every dispatched channel returned
	// Fired. Partial-success (≥1 Fired AND ≥1 Failed) lands
	// as Sent=false with channelsFired + errors populated.
	Sent          bool              `json:"sent"`
	ChannelsFired []string          `json:"channelsFired"`
	Errors        map[string]string `json:"errors,omitempty"`
	// Skipped surfaces per-channel gate reasons
	// (disabled, minSeverity) so the operator sees why
	// nothing went out.
	Skipped map[string]string `json:"skipped,omitempty"`
}

// alertRuleToResponse converts the storage row to the
// wire shape. Pass-through of every field — no
// redaction needed.
func alertRuleToResponse(r storage.AlertRule) alertRuleResponse {
	channels := r.Channels
	if channels == nil {
		channels = []string{}
	}
	return alertRuleResponse{
		ID:              r.ID,
		Name:            r.Name,
		Enabled:         r.Enabled,
		Kind:            r.Kind,
		Severity:        r.Severity,
		Category:        r.Category,
		Source:          r.Source,
		SourceParams:    r.SourceParams,
		EvalParams:      r.EvalParams,
		Channels:        channels,
		CooldownSecs:    r.CooldownSecs,
		SubjectTemplate: r.SubjectTemplate,
		BodyTemplate:    r.BodyTemplate,
		CreatedAt:       r.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:       r.UpdatedAt.UTC().Format(timestampFormat),
		LastFiredAt:     r.LastFiredAt,
		LastEvalAt:      r.LastEvalAt,
		LastError:       r.LastError,
		LastErrorAt:     r.LastErrorAt,
	}
}

// validateAlertRuleRequest runs the API-layer shape
// checks + the cross-reference checks (source exists,
// channels exist) by routing through alerting.AlertRule.
// Validate (AL.2.a) with the wired RuleValidationDeps.
//
// Returns a friendly error for the API caller. Storage's
// own validate() re-runs at write time as defence in
// depth.
func (h *Handler) validateAlertRuleRequest(ctx context.Context, req alertRuleRequest) error {
	if req.Name == "" {
		return errors.New("name must not be empty")
	}
	// Defensive defaults so the validator's range checks
	// see populated values (the alerting.AlertRule's
	// WithDefaults backfills cooldown, but the handler
	// owns the operator-facing wire shape).
	cooldown := req.CooldownSecs
	if cooldown == 0 {
		cooldown = alerting.RuleCooldownSecsDefault
	}

	// Build the typed alerting.AlertRule shape for
	// Validate. ID is unused by Validate; the storage
	// layer takes it from the wire path.
	typed := alerting.AlertRule{
		Name:            req.Name,
		Enabled:         req.Enabled,
		Kind:            req.Kind,
		Severity:        alerting.Severity(req.Severity),
		Category:        req.Category,
		Source:          req.Source,
		SourceParams:    req.SourceParams,
		EvalParams:      req.EvalParams,
		Channels:        req.Channels,
		CooldownSecs:    cooldown,
		SubjectTemplate: req.SubjectTemplate,
		BodyTemplate:    req.BodyTemplate,
	}

	deps := alerting.RuleValidationDeps{
		Sources:       h.alertingSources, // may be nil — Validate tolerates
		ChannelExists: h.channelExistsLookup(ctx),
	}
	return typed.Validate(deps)
}

// channelExistsLookup returns a closure satisfying
// RuleValidationDeps.ChannelExists. Looks up against the
// channel CRUD storage; returns false on ErrNotFound,
// true on success, and ALSO false on transient storage
// errors so a flaky DB doesn't fail-open on the
// reference-integrity check (operator gets a clear
// "channel X does not exist" instead of a 500 leak).
func (h *Handler) channelExistsLookup(ctx context.Context) func(string) bool {
	return func(id string) bool {
		_, err := h.store.GetAlertChannel(ctx, id)
		return err == nil
	}
}

func (h *Handler) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := h.store.ListAlertRules(r.Context())
	if err != nil {
		h.logger.Error("list alert_rules", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list alert rules")
		return
	}
	out := make([]alertRuleResponse, 0, len(rules))
	for _, rule := range rules {
		out = append(out, alertRuleToResponse(rule))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getAlertRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rule, err := h.store.GetAlertRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alert rule not found")
			return
		}
		h.logger.Error("get alert_rule", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get alert rule")
		return
	}
	writeJSON(w, http.StatusOK, alertRuleToResponse(rule))
}

func (h *Handler) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var req alertRuleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := h.validateAlertRuleRequest(r.Context(), req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	cooldown := req.CooldownSecs
	if cooldown == 0 {
		cooldown = alerting.RuleCooldownSecsDefault
	}
	rule := storage.AlertRule{
		ID:              uuid.NewString(),
		Name:            req.Name,
		Enabled:         req.Enabled,
		Kind:            req.Kind,
		Severity:        req.Severity,
		Category:        req.Category,
		Source:          req.Source,
		SourceParams:    req.SourceParams,
		EvalParams:      req.EvalParams,
		Channels:        req.Channels,
		CooldownSecs:    cooldown,
		SubjectTemplate: req.SubjectTemplate,
		BodyTemplate:    req.BodyTemplate,
	}
	created, err := h.store.CreateAlertRule(r.Context(), rule)
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict,
				fmt.Sprintf("alert rule %q already exists", req.Name))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAlertRuleCreated,
		TargetType: "alert_rule",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(created),
	})

	writeJSON(w, http.StatusCreated, alertRuleToResponse(created))
}

func (h *Handler) updateAlertRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req alertRuleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := h.validateAlertRuleRequest(r.Context(), req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previous, err := h.store.GetAlertRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alert rule not found")
			return
		}
		h.logger.Error("get alert_rule for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load alert rule")
		return
	}

	cooldown := req.CooldownSecs
	if cooldown == 0 {
		cooldown = alerting.RuleCooldownSecsDefault
	}
	// Full-replace shape; watcher-managed fields
	// (LastFiredAt / LastEvalAt / LastError / LastErrorAt)
	// are NOT in the operator wire shape — the storage
	// layer's UpdateAlertRule preserves them implicitly
	// when the request leaves them zero (see
	// internal/storage/alert_rule.go UpdateAlertRule).
	updated, err := h.store.UpdateAlertRule(r.Context(), storage.AlertRule{
		ID:              id,
		Name:            req.Name,
		Enabled:         req.Enabled,
		Kind:            req.Kind,
		Severity:        req.Severity,
		Category:        req.Category,
		Source:          req.Source,
		SourceParams:    req.SourceParams,
		EvalParams:      req.EvalParams,
		Channels:        req.Channels,
		CooldownSecs:    cooldown,
		SubjectTemplate: req.SubjectTemplate,
		BodyTemplate:    req.BodyTemplate,
	})
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict,
				fmt.Sprintf("alert rule %q already exists", req.Name))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAlertRuleUpdated,
		TargetType: "alert_rule",
		TargetID:   updated.ID,
		BeforeJSON: mustMarshalForAudit(previous),
		AfterJSON:  mustMarshalForAudit(updated),
	})

	writeJSON(w, http.StatusOK, alertRuleToResponse(updated))
}

func (h *Handler) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	previous, err := h.store.GetAlertRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alert rule not found")
			return
		}
		h.logger.Error("get alert_rule for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load alert rule")
		return
	}

	if err := h.store.DeleteAlertRule(r.Context(), id); err != nil {
		h.logger.Error("delete alert_rule", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete alert rule")
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAlertRuleDeleted,
		TargetType: "alert_rule",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(previous),
	})

	w.WriteHeader(http.StatusNoContent)
}

// testAlertRule force-evaluates a rule synchronously and
// dispatches a synthetic AlertEvent through every
// configured channel, BYPASSING the cooldown LRU. The
// operator pressed "Test" so the intent is explicitly
// "deliver this regardless of the watcher's silence
// window". Channel.Enabled + MinSeverity gates STILL
// apply via the dispatcher — a disabled channel
// surfaces as a per-channel skip in the response so the
// operator UI explains why nothing reached the receiver.
//
// HTTP status:
//   - 200 + sent=true   → every dispatched channel fired
//   - 502 + sent=false  → at least one channel failed OR
//     the rule's Channels list resolved to zero
//     dispatchable channels (all skipped by gates, or
//     dispatcher returned Failed for all)
//   - 404                → rule not found
//   - 503                → dispatcher not wired (boot-
//     degraded, shouldn't happen in production)
//
// Cooldown bypass is the key operator-facing
// affordance vs. the watcher path: the operator can
// re-test a recently-fired rule without waiting out
// the silence window.
func (h *Handler) testAlertRule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	rule, err := h.store.GetAlertRule(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alert rule not found")
			return
		}
		h.logger.Error("get alert_rule for test", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load alert rule")
		return
	}

	if h.alertingDispatcher == nil {
		writeError(w, http.StatusServiceUnavailable, "alerting dispatcher not wired")
		return
	}

	// 15s ceiling — same upper bound the channel /test
	// endpoint uses (webhook timeout ≤60s, email dial
	// ≤30s; this caps the operator UI wait).
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	evt := syntheticTestAlertEventForRule(rule)
	result := h.alertingDispatcher.Dispatch(ctx, evt, rule.Channels)

	resp := alertRuleTestResponse{
		ChannelsFired: result.Fired,
		Errors:        result.Failed,
		Skipped:       result.Skipped,
	}
	if resp.ChannelsFired == nil {
		resp.ChannelsFired = []string{}
	}
	// Sent = "every channel in the rule landed". Any
	// skip or failure marks the test as not-fully-sent so
	// the UI flags it.
	resp.Sent = len(result.Failed) == 0 &&
		len(result.Skipped) == 0 &&
		len(result.Fired) == len(rule.Channels) &&
		len(rule.Channels) > 0

	status := http.StatusOK
	if !resp.Sent {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, resp)
}

// syntheticTestAlertEventForRule builds the test event
// the /test endpoint dispatches. Severity follows the
// rule's configured severity so dispatcher gates
// (MinSeverity per channel) reflect the real fire
// behaviour. RuleID + RuleName are populated from the
// rule so receivers can correlate to the operator-
// configured rule.
func syntheticTestAlertEventForRule(rule storage.AlertRule) alerting.AlertEvent {
	return alerting.AlertEvent{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		Severity:  alerting.Severity(rule.Severity),
		Category:  rule.Category,
		// %s, not %q — see syntheticTestAlertEvent in
		// alerting_channels.go. Double quotes in a subject break any
		// webhook body template that interpolates it, so the rule test
		// carried exactly the same trap as the channel test: guaranteed
		// invalid JSON, opaque 400, and a channel that actually worked.
		Subject: fmt.Sprintf("[TEST] Arenet alerting rule %s force-fired by operator", rule.Name),
		Body: "This is a synthetic test event sent by the Arenet alerting " +
			"subsystem in response to the operator pressing the \"Test\" " +
			"button on the rule settings page. The rule's evaluator and " +
			"source were NOT consulted; the rule's cooldown was NOT " +
			"checked. If you received this notification, the rule's " +
			"channel routing is wired end-to-end and ready to deliver " +
			"real alerts when the watcher next fires this rule.",
		Labels: map[string]string{
			"source":    "arenet-rule-test",
			"rule_id":   rule.ID,
			"rule_name": rule.Name,
		},
	}
}
