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

package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Step AL.1.a — instance-level alerting channel registry.
//
// One Channel row per operator-configured notification
// destination (webhook URL, SMTP endpoint, ...). Multiple
// channels coexist (e.g. one webhook + one email); the
// rule engine (AL.2) dispatches each fired AlertEvent to
// every channel whose MinSeverity gate it crosses.
//
// Storage layout: BoltDB bucket "alerting_channels", keyed
// by Channel.ID (UUID generated at create time so the
// operator-facing Name can be renamed without breaking
// rule → channel references).
//
// Config is a json.RawMessage so each kind keeps its own
// shape without forcing a discriminated-union storage
// schema. The CRUD layer (AL.1.c) validates the kind-
// specific shape at write time using a kind→validator
// dispatch.
//
// Secret discipline: SMTP passwords + webhook auth tokens
// sit inside Config as cleartext at-rest, behind the
// BoltDB file's POSIX 0o600 permissions. Mirrors the
// existing J.4 DNS provider OVH credentials + CrowdSec
// API key + OIDC ClientSecret patterns — at-rest
// encryption of the BoltDB file is out of scope for the
// per-feature work (it's a single backlog item covering
// the whole file). API GET responses MUST blank the
// secret fields in their wire shape; audit BeforeJSON /
// AfterJSON MUST be redacted via a Channel-specific
// adapter. AL.1.c documents the redaction contract per
// kind.
//
// Kinds: "webhook", "email" and "discord" (v2.53). "slack" may
// follow — the storage schema supports it via the Config raw
// shape; only the kind constant, a sender and the validator
// entry need to land.

// Channel is the persisted shape of one alerting
// destination.
type Channel struct {
	// ID is a UUID v4 string, generated at create time.
	// Stable across renames so rule → channel references
	// survive operator-facing relabels.
	ID string `json:"id"`
	// Name is the operator-facing label, unique across
	// channels. Slug-shaped: lowercase alnum + dash, 1-64
	// chars. Surfaces in the activity log + the Settings
	// channel-list UI.
	Name string `json:"name"`
	// Kind drives the per-kind sender dispatch + the
	// Config shape. Allowed values gated by
	// AlertChannelKinds.
	Kind string `json:"kind"`
	// Enabled is the soft-disable flag. A disabled
	// channel sits in storage but the dispatch layer
	// skips it — operator-meaningful for "pause email
	// while we sort out the SMTP relay".
	Enabled bool `json:"enabled"`
	// MinSeverity gates which AlertEvents reach this
	// channel. Per D5 ADR: channel-level filter using
	// the 4-level enum (info/warning/critical/emergency).
	// An info-level event reaches a channel with
	// MinSeverity=info; a warning-level event reaches
	// channels at info OR warning; etc.
	//
	// Severity-int storage (0..3) matches the alert_event
	// table column type. The wire shape on the API uses
	// the string token via the Severity MarshalJSON in
	// internal/alerting.
	MinSeverity int `json:"min_severity"`
	// Config is the kind-specific opaque shape, JSON-
	// encoded. The CRUD layer validates per kind at
	// write time; the storage layer treats it as a
	// blob.
	//
	// Webhook config shape (V1):
	//   {"url": "https://...", "method": "POST",
	//    "headers": {"X-Auth": "..."},
	//    "timeout_seconds": 10}
	// Email config shape (V1):
	//   {"smtp_host": "smtp.example.com:587",
	//    "smtp_username": "...",
	//    "smtp_password": "...",   // SECRET
	//    "from": "...", "to": ["..."],
	//    "use_tls": true}
	Config json.RawMessage `json:"config"`
	// LastSentAt is nil before the first dispatch
	// attempt. Surfaces in the UI as "last sent: 3
	// minutes ago" / "never sent" — operator-meaningful
	// signal for "is this channel actually working?".
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	// LastError is the operator-readable last failure
	// message. Empty when the most-recent send succeeded.
	// Cleared on next successful send.
	LastError string `json:"last_error,omitempty"`
	// LastErrorAt timestamps the most recent failure.
	// Cleared together with LastError.
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// AlertChannelKinds enumerates the supported channel kinds. The
// API layer reads from here as the single source of truth, so
// widening propagates without touching the validator — but each
// new kind still needs its own sender, its config parser and its
// audit-redaction branch.
var AlertChannelKinds = []string{
	ChannelKindWebhook,
	ChannelKindEmail,
	ChannelKindDiscord,
}

// Channel kind constants. Exported so the CRUD layer +
// the per-kind sender adapters reference them
// symbolically instead of string-typing.
const (
	ChannelKindWebhook = "webhook"
	ChannelKindEmail   = "email"
	// ChannelKindDiscord (v2.53) posts a Discord embed. It exists as
	// its own kind rather than a webhook body template because the
	// template is string interpolation with no JSON escaping: an alert
	// whose subject carries a quote produced an invalid body and an
	// opaque HTTP 400, intermittently. A dedicated sender marshals a
	// struct, so escaping cannot be got wrong.
	ChannelKindDiscord = "discord"
)

// AlertChannelMinSeverityMin / Max bound the int range.
// Mirrors alerting.SeverityInfo .. SeverityEmergency in
// the internal/alerting package — kept as raw ints here
// to avoid importing internal/alerting into internal/
// storage (cyclic-import risk; the alerting package
// depends on storage for the Channel CRUD).
const (
	AlertChannelMinSeverityMin = 0 // info
	AlertChannelMinSeverityMax = 3 // emergency
)

// channelNameRE matches a slug-shaped channel name. Same
// shape as the forward-auth provider name pattern; 64-
// char ceiling so operators can use descriptive labels
// (e.g. "ops-webhook-alertmanager-prod").
var channelNameRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// ValidateAlertChannel runs the storage-layer last-line-
// of-defence checks. Per-kind Config validation lives at
// the CRUD layer (it needs the JSON parser); storage
// validates only the kind-agnostic envelope.
func ValidateAlertChannel(c Channel) error {
	return c.validate()
}

func (c *Channel) validate() error {
	if !channelNameRE.MatchString(c.Name) {
		return fmt.Errorf("alerting_channel: name %q must match %s",
			c.Name, channelNameRE.String())
	}
	ok := false
	for _, k := range AlertChannelKinds {
		if c.Kind == k {
			ok = true
			break
		}
	}
	if !ok {
		return fmt.Errorf("alerting_channel: kind %q is not a recognised channel kind", c.Kind)
	}
	if c.MinSeverity < AlertChannelMinSeverityMin || c.MinSeverity > AlertChannelMinSeverityMax {
		return fmt.Errorf("alerting_channel: min_severity %d out of range [%d,%d]",
			c.MinSeverity, AlertChannelMinSeverityMin, AlertChannelMinSeverityMax)
	}
	if len(c.Config) == 0 {
		return errors.New("alerting_channel: config must not be empty")
	}
	// Light sanity: Config must be valid JSON. Per-kind
	// shape validation is the CRUD layer's job.
	var probe any
	if err := json.Unmarshal(c.Config, &probe); err != nil {
		return fmt.Errorf("alerting_channel: config is not valid JSON: %w", err)
	}
	return nil
}
