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
	"log/slog"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// AL.1.b — Dispatcher fans an AlertEvent out to a list of
// channels. Owns the channel.Kind → Sender mapping and
// the per-channel MinSeverity / Enabled gates per ADR D5.
//
// V1 dispatch model: synchronous. Each channel's Send is
// awaited before the next. Total dispatcher budget is the
// caller's ctx — typically the rule engine's 30s polling
// tick. A slow webhook can delay subsequent channels but
// V1's expected channel count (≤5 homelab) keeps this
// tractable. V2 candidate: per-channel goroutine fan-out
// + errgroup for parallel dispatch.

// ChannelLoader is the seam Dispatcher reads channel rows
// through. *storage.Store satisfies it via
// GetAlertChannel + MarkAlertChannelSendResult — the
// narrow interface keeps the dispatcher testable without
// bolt.
type ChannelLoader interface {
	GetAlertChannel(ctx context.Context, id string) (storage.Channel, error)
	MarkAlertChannelSendResult(ctx context.Context, id string, sendErr error) error
}

// AlertEventInserter is the seam Dispatcher uses to
// persist the per-fan-out outcome to the alert_event
// table for the History tab (AL.4.a). Implemented by
// *observability.Store via InsertAlertEvent.
//
// nil-tolerant: when no inserter is wired (boot-degraded
// observability OR test envs that don't care about
// history), the sink path is a silent no-op. The
// dispatch result returned to the caller is unaffected.
type AlertEventInserter interface {
	InsertAlertEvent(ctx context.Context, e AlertEventRecord) error
}

// AlertEventRecord is the wire shape the inserter sees.
// The dispatcher builds one per Dispatch call, populating
// the channels_fired_json + channels_failed_json fields
// from the DispatchResult so the History tab can render
// per-event delivery outcomes.
//
// Defined on the consumer side so the alerting package
// doesn't take a structural dep on the observability
// store's broader surface (mirrors the AlertEventReader
// pattern in internal/api).
type AlertEventRecord struct {
	EventID            string
	Ts                 time.Time
	RuleID             string
	RuleName           string
	Severity           int
	Category           string
	Subject            string
	Body               string
	ContextJSON        string
	LabelsJSON         string
	ChannelsFiredJSON  string
	ChannelsFailedJSON string
}

// Dispatcher routes AlertEvents to the configured channels.
type Dispatcher struct {
	store    ChannelLoader
	logger   *slog.Logger
	inserter AlertEventInserter
}

// NewDispatcher constructs the dispatcher. The history
// sink is unwired by default; cmd/arenet/main.go calls
// SetAlertEventSink after construction to attach it.
func NewDispatcher(store ChannelLoader, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Dispatcher{store: store, logger: logger}
}

// SetAlertEventSink attaches the History tab persistence
// seam. Pass nil to disable history persistence (handler
// tests + boot-degraded observability paths).
func (d *Dispatcher) SetAlertEventSink(s AlertEventInserter) {
	d.inserter = s
}

// DispatchResult captures the per-channel outcome of a
// fan-out. Returned to the rule engine so the alert_event
// row's channels_fired_json / channels_failed_json fields
// can be populated.
type DispatchResult struct {
	// Fired is the set of channel IDs that successfully
	// received the alert (Send returned nil).
	Fired []string
	// Failed maps channel ID → error message for channels
	// where Send returned non-nil OR the channel was
	// skipped for a reason the operator should see (e.g.
	// kind not registered, config malformed). Channels
	// skipped by MinSeverity / Enabled gates are NOT in
	// Failed — those skips are silent by design (operator-
	// configured filtering).
	Failed map[string]string
	// Skipped maps channel ID → reason for channels
	// silently filtered out (disabled, MinSeverity gate).
	// Surfaced to logging for operator debugging but NOT
	// included in the alert_event audit row — the row
	// captures system-side outcomes, not operator-side
	// configuration choices.
	Skipped map[string]string
}

// Dispatch fans evt out to every channel ID in
// channelIDs. Walks them in order; collects per-channel
// outcomes; returns the aggregate result. Never returns
// an error — channel-side failures land in
// result.Failed, not in the function's error return,
// because partial-success is the V1 dispatch contract
// (one bad channel must not block the others).
func (d *Dispatcher) Dispatch(ctx context.Context, evt AlertEvent, channelIDs []string) DispatchResult {
	result := DispatchResult{
		Fired:   make([]string, 0, len(channelIDs)),
		Failed:  make(map[string]string),
		Skipped: make(map[string]string),
	}

	for _, id := range channelIDs {
		ch, err := d.store.GetAlertChannel(ctx, id)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				result.Failed[id] = "channel not found (deleted while rule held a reference?)"
			} else {
				result.Failed[id] = fmt.Sprintf("load channel: %s", err.Error())
			}
			d.logger.Warn("alerting dispatch: channel load failed",
				"channel_id", id, "err", err)
			continue
		}

		// D5 ADR per-channel filters.
		if !ch.Enabled {
			result.Skipped[id] = "channel disabled"
			continue
		}
		if int(evt.Severity) < ch.MinSeverity {
			result.Skipped[id] = fmt.Sprintf("severity %s below channel min %d",
				evt.Severity, ch.MinSeverity)
			continue
		}

		sender, err := SenderFor(ch)
		if err != nil {
			result.Failed[id] = err.Error()
			d.logger.Warn("alerting dispatch: sender construct failed",
				"channel_id", id, "kind", ch.Kind, "err", err)
			continue
		}

		sendErr := sender.Send(ctx, evt)
		// Always record the outcome on the channel row,
		// regardless of success/failure — operator-side
		// "when did this channel last succeed / fail" UI
		// hinges on this write.
		if markErr := d.store.MarkAlertChannelSendResult(ctx, ch.ID, sendErr); markErr != nil {
			// Tertiary failure: the channel write itself
			// errored. Log but don't surface — the primary
			// dispatch outcome is what the caller cares
			// about.
			d.logger.Warn("alerting dispatch: mark send result failed",
				"channel_id", id, "err", markErr)
		}

		if sendErr != nil {
			result.Failed[id] = sendErr.Error()
			d.logger.Warn("alerting dispatch: send failed",
				"channel_id", id, "kind", ch.Kind,
				"event_id", evt.ID, "err", sendErr)
		} else {
			result.Fired = append(result.Fired, id)
			d.logger.Debug("alerting dispatch: send ok",
				"channel_id", id, "kind", ch.Kind,
				"event_id", evt.ID)
		}
	}

	// AL.4.a — sink the assembled outcome to the
	// alert_event table for the History tab. nil-tolerant
	// (boot-degraded observability skips). Insert failures
	// are logged but NEVER surfaced to the caller — the
	// dispatch result must remain authoritative regardless
	// of whether the audit-style sink succeeded.
	d.persistAlertEventRecord(ctx, evt, result)

	return result
}

// persistAlertEventRecord serialises the dispatch outcome
// into the storage-shape and calls the wired inserter.
// Marshalling errors are logged but never block the
// dispatch path; the operator gets the live notification,
// the History tab merely loses one row in the worst case.
func (d *Dispatcher) persistAlertEventRecord(ctx context.Context, evt AlertEvent, result DispatchResult) {
	if d.inserter == nil {
		return
	}
	contextJSON, err := marshalMapOrEmpty(evt.Context)
	if err != nil {
		d.logger.Warn("alerting dispatch: marshal context for history sink failed",
			"event_id", evt.ID, "err", err)
		return
	}
	labelsJSON, err := marshalMapStringOrEmpty(evt.Labels)
	if err != nil {
		d.logger.Warn("alerting dispatch: marshal labels for history sink failed",
			"event_id", evt.ID, "err", err)
		return
	}
	firedJSON, err := marshalSliceOrEmpty(result.Fired)
	if err != nil {
		d.logger.Warn("alerting dispatch: marshal fired for history sink failed",
			"event_id", evt.ID, "err", err)
		return
	}
	failedJSON, err := marshalMapStringOrEmpty(result.Failed)
	if err != nil {
		d.logger.Warn("alerting dispatch: marshal failed for history sink failed",
			"event_id", evt.ID, "err", err)
		return
	}

	rec := AlertEventRecord{
		EventID:            evt.ID,
		Ts:                 evt.Timestamp,
		RuleID:             evt.RuleID,
		RuleName:           evt.RuleName,
		Severity:           int(evt.Severity),
		Category:           evt.Category,
		Subject:            evt.Subject,
		Body:               evt.Body,
		ContextJSON:        contextJSON,
		LabelsJSON:         labelsJSON,
		ChannelsFiredJSON:  firedJSON,
		ChannelsFailedJSON: failedJSON,
	}
	if err := d.inserter.InsertAlertEvent(ctx, rec); err != nil {
		d.logger.Warn("alerting dispatch: history sink insert failed",
			"event_id", evt.ID, "err", err)
	}
}

// marshalMapOrEmpty returns "" for nil/empty maps,
// otherwise the JSON-encoded form. The SQLite schema's
// default is empty string; preserve that contract so a
// row with no labels reads back as "" not "null".
func marshalMapOrEmpty(m map[string]any) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func marshalMapStringOrEmpty(m map[string]string) (string, error) {
	if len(m) == 0 {
		return "", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func marshalSliceOrEmpty(s []string) (string, error) {
	if len(s) == 0 {
		return "", nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// SenderFor constructs an AlertSender for a stored
// Channel. Returns an error if the Channel.Kind isn't
// supported or the per-kind Config fails to parse — a
// stored row that fails to parse should NEVER happen in
// practice (Validate runs at create/update time), but a
// defensive check here catches schema drift across
// arenet versions.
//
// Public so the API /test endpoint can call it directly
// (the test path bypasses Dispatch + ChannelLoader so it
// can return a synchronous result to the operator).
func SenderFor(ch storage.Channel) (AlertSender, error) {
	switch ch.Kind {
	case storage.ChannelKindWebhook:
		cfg, err := ParseWebhookConfig(ch.Config)
		if err != nil {
			return nil, fmt.Errorf("webhook config parse: %w", err)
		}
		return NewWebhookSender(cfg), nil
	case storage.ChannelKindEmail:
		cfg, err := ParseEmailConfig(ch.Config)
		if err != nil {
			return nil, fmt.Errorf("email config parse: %w", err)
		}
		return NewEmailSender(cfg, nil), nil
	case storage.ChannelKindDiscord:
		cfg, err := ParseDiscordConfig(ch.Config)
		if err != nil {
			return nil, fmt.Errorf("discord config parse: %w", err)
		}
		return NewDiscordSender(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported channel kind %q", ch.Kind)
	}
}
