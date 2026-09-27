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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Step AL.1.b — Channel CRUD HTTP endpoints.
//
// Routes mounted under /api/v1/settings/alerting/channels:
//   POST   /                       create
//   GET    /                       list
//   GET    /{id}                   get
//   PUT    /{id}                   update (preserve-on-edit secrets)
//   DELETE /{id}                   delete
//   POST   /{id}/test              fire a synthetic test event
//
// Same J.4 secret discipline as forward_auth_provider.go:
// the SMTP password + the operator's webhook auth header
// values never appear on the GET wire shape, never appear
// in audit BeforeJSON / AfterJSON. The PUT path preserves
// the previously-stored secret when the operator submits
// an empty value (UI sentinel for "I'm not rotating this
// field right now").

// alertChannelRequest is the wire shape on POST / PUT.
// Config is parsed per-kind by the handler — kind+config
// must agree at write time.
type alertChannelRequest struct {
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Enabled     bool            `json:"enabled"`
	MinSeverity int             `json:"minSeverity"`
	Config      json.RawMessage `json:"config"`
}

// alertChannelResponse is the wire shape on GET. Config is
// re-emitted as JSON with secrets blanked per kind. The
// per-kind "*Set" flags tell the UI whether the operator
// has a stored secret so it can render the "••• set"
// placeholder (mirrors ClientSecretSet on forward_auth).
type alertChannelResponse struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Kind        string          `json:"kind"`
	Enabled     bool            `json:"enabled"`
	MinSeverity int             `json:"minSeverity"`
	Config      json.RawMessage `json:"config"`
	LastSentAt  *time.Time      `json:"lastSentAt,omitempty"`
	LastError   string          `json:"lastError,omitempty"`
	LastErrorAt *time.Time      `json:"lastErrorAt,omitempty"`
	CreatedAt   string          `json:"createdAt"`
	UpdatedAt   string          `json:"updatedAt"`
	// SecretsLost (v2.39) flags a webhook channel whose stored URL is
	// the redacted placeholder: an edit made before the fix above
	// overwrote it, so the channel cannot send until the operator
	// retypes the URL.
	SecretsLost bool `json:"secretsLost,omitempty"`
}

// alertChannelTestResponse reports the outcome of a
// synthetic test fire. Send was attempted; ok=true means
// the sender returned nil; ok=false carries the
// operator-readable error.
type alertChannelTestResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// alertChannelForAudit returns a copy of c with kind-
// specific secret fields blanked. Apply to every
// storage.Channel passed into appendAudit's BeforeJSON /
// AfterJSON.
//
// Webhook: Headers map values are redacted (the operator
// often hides bearer tokens or signing secrets there), and
// the URL keeps only scheme + host (v2.30 — a Discord / Slack
// webhook URL is itself the credential).
// Email: SMTPPassword is blanked.
//
// On JSON-parse failure (shouldn't happen — Validate ran
// at write time), the original Config is returned and
// the caller emits a verbose audit row; the failure is
// logged separately so the operator sees the cause.
func alertChannelForAudit(c storage.Channel) storage.Channel {
	switch c.Kind {
	case storage.ChannelKindWebhook:
		var cfg alerting.WebhookConfig
		if err := json.Unmarshal(c.Config, &cfg); err != nil {
			return c
		}
		// Header VALUES are redacted; keys stay so the
		// operator can audit which headers were configured
		// without revealing their secrets.
		if cfg.Headers != nil {
			for k := range cfg.Headers {
				cfg.Headers[k] = auditRedacted
			}
		}
		cfg.URL = redactWebhookURL(cfg.URL)
		redacted, err := json.Marshal(cfg)
		if err != nil {
			return c
		}
		c.Config = redacted
		return c
	case storage.ChannelKindEmail:
		var cfg alerting.EmailConfig
		if err := json.Unmarshal(c.Config, &cfg); err != nil {
			return c
		}
		cfg.SMTPPassword = ""
		redacted, err := json.Marshal(cfg)
		if err != nil {
			return c
		}
		c.Config = redacted
		return c
	case storage.ChannelKindDiscord:
		var cfg alerting.DiscordConfig
		if err := json.Unmarshal(c.Config, &cfg); err != nil {
			return c
		}
		// A Discord webhook URL carries its credential in the path:
		// anyone holding it can post to the channel. Redacted like any
		// other secret, same treatment as the generic webhook URL.
		cfg.WebhookURL = redactWebhookURL(cfg.WebhookURL)
		redacted, err := json.Marshal(cfg)
		if err != nil {
			return c
		}
		c.Config = redacted
		return c
	}
	return c
}

// webhookURLLost reports a webhook channel whose stored URL carries the
// redaction placeholder — the channel is broken until the URL is
// retyped (see mergeAlertChannelSecrets).
func webhookURLLost(c storage.Channel) bool {
	if c.Kind == storage.ChannelKindDiscord {
		var cfg alerting.DiscordConfig
		if err := json.Unmarshal(c.Config, &cfg); err != nil {
			return false
		}
		return strings.Contains(cfg.WebhookURL, auditRedacted)
	}
	if c.Kind != storage.ChannelKindWebhook {
		return false
	}
	var cfg alerting.WebhookConfig
	if err := json.Unmarshal(c.Config, &cfg); err != nil {
		return false
	}
	return strings.Contains(cfg.URL, auditRedacted)
}

// alertChannelToResponse builds the GET wire shape with
// secrets blanked. Mirrors alertChannelForAudit's
// behaviour but emits the redacted JSON as the operator-
// facing API payload, not as an audit blob.
func alertChannelToResponse(c storage.Channel) alertChannelResponse {
	// Re-use the audit redaction — same secret-stripping
	// rules, same per-kind dispatch.
	redacted := alertChannelForAudit(c)
	return alertChannelResponse{
		SecretsLost: webhookURLLost(c),
		ID:          c.ID,
		Name:        c.Name,
		Kind:        c.Kind,
		Enabled:     c.Enabled,
		MinSeverity: c.MinSeverity,
		Config:      redacted.Config,
		LastSentAt:  c.LastSentAt,
		LastError:   c.LastError,
		LastErrorAt: c.LastErrorAt,
		CreatedAt:   c.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:   c.UpdatedAt.UTC().Format(timestampFormat),
	}
}

// validateAlertChannelRequest enforces API-layer shape
// rules with friendlier messages than storage.validate
// returns. Storage runs ValidateAlertChannel after this
// passes so the envelope is checked twice (defence-in-
// depth: a future field add on the wire shape that
// forgets a check here is still caught at the storage
// layer).
func validateAlertChannelRequest(req alertChannelRequest) error {
	if req.Name == "" {
		return errors.New("name must not be empty")
	}
	ok := false
	for _, k := range storage.AlertChannelKinds {
		if req.Kind == k {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("kind %q must be one of %v", req.Kind, storage.AlertChannelKinds)
	}
	if req.MinSeverity < storage.AlertChannelMinSeverityMin ||
		req.MinSeverity > storage.AlertChannelMinSeverityMax {
		return fmt.Errorf("minSeverity %d out of range [%d, %d]",
			req.MinSeverity, storage.AlertChannelMinSeverityMin, storage.AlertChannelMinSeverityMax)
	}
	if len(req.Config) == 0 {
		return errors.New("config must not be empty")
	}
	// Per-kind shape check + template-compile check live in
	// alerting.ParseWebhookConfig / alerting.ParseEmailConfig.
	// We call those here so the operator gets per-kind
	// errors at API entry, not at sender construction.
	switch req.Kind {
	case storage.ChannelKindWebhook:
		if _, err := alerting.ParseWebhookConfig(req.Config); err != nil {
			return err
		}
	case storage.ChannelKindEmail:
		if _, err := alerting.ParseEmailConfig(req.Config); err != nil {
			return err
		}
	case storage.ChannelKindDiscord:
		if _, err := alerting.ParseDiscordConfig(req.Config); err != nil {
			return err
		}
	}
	return nil
}

// mergeAlertChannelSecrets is the preserve-on-edit path:
// when the operator submits an empty secret field on PUT,
// inherit the stored value. Mirrors the forward_auth /
// DNS-provider / OIDC patterns.
//
// Returns the request config with secrets backfilled
// from the previous storage row.
func mergeAlertChannelSecrets(reqConfig json.RawMessage, kind string, previous storage.Channel) (json.RawMessage, error) {
	switch kind {
	case storage.ChannelKindWebhook:
		var incoming alerting.WebhookConfig
		if err := json.Unmarshal(reqConfig, &incoming); err != nil {
			return nil, err
		}
		var stored alerting.WebhookConfig
		_ = json.Unmarshal(previous.Config, &stored)
		// Header values: empty incoming value → inherit
		// stored value (preserve-on-edit per header).
		if incoming.Headers == nil {
			incoming.Headers = map[string]string{}
		}
		for k, v := range incoming.Headers {
			if v == "" || v == auditRedacted {
				if storedV, ok := stored.Headers[k]; ok {
					incoming.Headers[k] = storedV
				}
			}
		}
		// The URL is a secret too (a Discord / Slack webhook URL IS
		// the credential), so GET returns it redacted. The UI sends
		// back what it was shown: without this, editing a channel
		// without retyping the URL stored "https://host/[redacted]"
		// and the channel silently stopped sending (found while
		// writing the OpenAPI doc, v2.39).
		if incoming.URL == "" || incoming.URL == auditRedacted || incoming.URL == redactWebhookURL(stored.URL) {
			incoming.URL = stored.URL
		}
		return json.Marshal(incoming)
	case storage.ChannelKindDiscord:
		var incoming alerting.DiscordConfig
		if err := json.Unmarshal(reqConfig, &incoming); err != nil {
			return nil, err
		}
		var storedDiscord alerting.DiscordConfig
		_ = json.Unmarshal(previous.Config, &storedDiscord)
		// Same trap as the webhook URL above: GET returns it redacted,
		// the UI sends back what it was shown, and without this an edit
		// that did not retype the URL would store the placeholder and
		// silently stop the channel.
		if incoming.WebhookURL == "" || incoming.WebhookURL == auditRedacted ||
			incoming.WebhookURL == redactWebhookURL(storedDiscord.WebhookURL) {
			incoming.WebhookURL = storedDiscord.WebhookURL
		}
		return json.Marshal(incoming)
	case storage.ChannelKindEmail:
		var incoming alerting.EmailConfig
		if err := json.Unmarshal(reqConfig, &incoming); err != nil {
			return nil, err
		}
		if incoming.SMTPPassword == "" {
			var stored alerting.EmailConfig
			_ = json.Unmarshal(previous.Config, &stored)
			incoming.SMTPPassword = stored.SMTPPassword
		}
		return json.Marshal(incoming)
	}
	return reqConfig, nil
}

func (h *Handler) listAlertChannels(w http.ResponseWriter, r *http.Request) {
	channels, err := h.store.ListAlertChannels(r.Context())
	if err != nil {
		h.logger.Error("list alerting_channels", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list alerting channels")
		return
	}
	out := make([]alertChannelResponse, 0, len(channels))
	for _, c := range channels {
		out = append(out, alertChannelToResponse(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getAlertChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := h.store.GetAlertChannel(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alerting channel not found")
			return
		}
		h.logger.Error("get alerting_channel", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get alerting channel")
		return
	}
	writeJSON(w, http.StatusOK, alertChannelToResponse(c))
}

func (h *Handler) createAlertChannel(w http.ResponseWriter, r *http.Request) {
	var req alertChannelRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := validateAlertChannelRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	channel := storage.Channel{
		ID:          uuid.NewString(),
		Name:        req.Name,
		Kind:        req.Kind,
		Enabled:     req.Enabled,
		MinSeverity: req.MinSeverity,
		Config:      req.Config,
	}
	created, err := h.store.CreateAlertChannel(r.Context(), channel)
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict,
				fmt.Sprintf("alerting channel %q already exists", req.Name))
			return
		}
		// storage.validate failure surfaces here too.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAlertChannelCreated,
		TargetType: "alerting_channel",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(alertChannelForAudit(created)),
	})

	writeJSON(w, http.StatusCreated, alertChannelToResponse(created))
}

func (h *Handler) updateAlertChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req alertChannelRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := validateAlertChannelRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	previous, err := h.store.GetAlertChannel(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alerting channel not found")
			return
		}
		h.logger.Error("get alerting_channel for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load alerting channel")
		return
	}

	// Preserve-on-edit secrets — J.4 pattern.
	mergedConfig, err := mergeAlertChannelSecrets(req.Config, req.Kind, previous)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	updated, err := h.store.UpdateAlertChannel(r.Context(), storage.Channel{
		ID:          id,
		Name:        req.Name,
		Kind:        req.Kind,
		Enabled:     req.Enabled,
		MinSeverity: req.MinSeverity,
		Config:      mergedConfig,
		// LastSentAt / LastError / LastErrorAt preserved
		// by storage layer (not part of the operator-facing
		// PUT shape; managed by MarkAlertChannelSendResult).
		LastSentAt:  previous.LastSentAt,
		LastError:   previous.LastError,
		LastErrorAt: previous.LastErrorAt,
	})
	if err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeError(w, http.StatusConflict,
				fmt.Sprintf("alerting channel %q already exists", req.Name))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAlertChannelUpdated,
		TargetType: "alerting_channel",
		TargetID:   updated.ID,
		BeforeJSON: mustMarshalForAudit(alertChannelForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(alertChannelForAudit(updated)),
	})

	writeJSON(w, http.StatusOK, alertChannelToResponse(updated))
}

func (h *Handler) deleteAlertChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	previous, err := h.store.GetAlertChannel(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alerting channel not found")
			return
		}
		h.logger.Error("get alerting_channel for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load alerting channel")
		return
	}

	if err := h.store.DeleteAlertChannel(r.Context(), id); err != nil {
		h.logger.Error("delete alerting_channel", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete alerting channel")
		return
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionAlertChannelDeleted,
		TargetType: "alerting_channel",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(alertChannelForAudit(previous)),
	})

	w.WriteHeader(http.StatusNoContent)
}

// testAlertChannel fires a synthetic AlertEvent through
// the channel and returns the per-call outcome.
//
// When h.alertingDispatcher is wired (production), the
// event goes through Dispatcher.Dispatch so the /test
// path exercises the same fan-out the AL.2 rule engine
// will use. Channel.Enabled / Channel.MinSeverity gates
// apply: a Test on a disabled channel surfaces as
// {"ok":false, "error":"channel disabled"} so the
// operator's UI explains the no-op clearly. The
// dispatcher handles MarkAlertChannelSendResult on every
// real send; the skipped paths leave the row untouched.
//
// When h.alertingDispatcher is nil (handler tests that
// don't wire the dispatcher), fall back to a direct
// SenderFor + Send. Equivalent behaviour for a single
// enabled channel; preserves the existing handler-test
// surface without churn.
//
// Always returns HTTP 200; per-send outcome lands in
// "ok" + "error" fields.
func (h *Handler) testAlertChannel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Probe existence early so a 404 is surfaced as a real
	// 404, not as a Dispatch-Failed map entry.
	if _, err := h.store.GetAlertChannel(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "alerting channel not found")
			return
		}
		h.logger.Error("get alerting_channel for test", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load alerting channel")
		return
	}

	// 15s ceiling — webhook timeout is operator-set (≤60s)
	// and email dial has its own 30s ceiling; this is an
	// upper bound for the HTTP request lifetime so the
	// operator UI never hangs forever on a stuck sender.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	ch, _ := h.store.GetAlertChannel(ctx, id)
	evt := syntheticTestAlertEvent(ch.Name)

	if h.alertingDispatcher != nil {
		result := h.alertingDispatcher.Dispatch(ctx, evt, []string{id})
		resp := alertChannelTestResponse{}
		switch {
		case len(result.Fired) == 1:
			resp.OK = true
		case result.Failed[id] != "":
			resp.OK = false
			resp.Error = result.Failed[id]
		case result.Skipped[id] != "":
			// Per-channel gate filtered the test fire (the
			// operator pressed Test on a disabled or under-
			// severity channel). Surface the reason so the
			// UI can explain why nothing left the box.
			resp.OK = false
			resp.Error = result.Skipped[id]
		default:
			resp.OK = false
			resp.Error = "dispatcher returned no result for this channel"
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// Fallback path (test envs without a dispatcher).
	sender, err := alerting.SenderFor(ch)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	sendErr := sender.Send(ctx, evt)
	if markErr := h.store.MarkAlertChannelSendResult(r.Context(), ch.ID, sendErr); markErr != nil {
		h.logger.Warn("alerting test: mark send result failed",
			"channel_id", ch.ID, "err", markErr)
	}
	resp := alertChannelTestResponse{OK: sendErr == nil}
	if sendErr != nil {
		resp.Error = sendErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// syntheticTestAlertEvent builds a representative event
// the operator can recognise when it lands on the
// receiving end — same shape a real rule fire would
// produce, with a clear "this is a test" subject.
func syntheticTestAlertEvent(channelName string) alerting.AlertEvent {
	return alerting.AlertEvent{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		RuleID:    "",
		RuleName:  "synthetic-test",
		Severity:  alerting.SeverityInfo,
		Category:  "system",
		Subject:   fmt.Sprintf("Arenet alerting test — channel %q", channelName),
		Body: "This is a synthetic test event sent by the Arenet alerting subsystem " +
			"in response to the operator pressing the \"Test\" button on the channel " +
			"settings page. If you received this notification, the channel is wired " +
			"end-to-end and ready to deliver real alerts.",
		Labels: map[string]string{
			"source": "arenet-test",
		},
	}
}
