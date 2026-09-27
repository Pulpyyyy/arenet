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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// v2.53 — a Discord channel kind.
//
// An operator configured a webhook channel with a Discord URL and got
// `upstream returned HTTP 400`. Discord requires a body carrying at least
// `content` or `embeds`, and the generic webhook posts Arenet's own event
// shape, which it refuses.
//
// The generic webhook CAN be pointed at Discord with a body template, and
// that was the documented workaround. It is a poor one: the template is
// string interpolation with no JSON escaping, so an alert whose subject
// contains a quote or a newline produces an invalid body and the same
// opaque 400 — intermittently, which is worse than always.
//
// This kind exists to remove that class of failure rather than document
// it. The payload is built as a struct and marshalled, so escaping is the
// encoder's job and cannot be got wrong. The operator pastes a URL and
// nothing else.

// DiscordConfig is the stored shape of a Discord channel.
type DiscordConfig struct {
	// WebhookURL is the Discord-provided endpoint, from a channel's
	// Integrations → Webhooks page. It carries the credential in its
	// path, so it is redacted in audit rows like any other secret.
	WebhookURL string `json:"webhookUrl"`
	// Username optionally overrides the display name Discord shows.
	// Empty leaves Discord's own webhook name.
	Username string `json:"username,omitempty"`
	// TimeoutSeconds bounds one send. Same range as the webhook sender.
	TimeoutSeconds int `json:"timeoutSeconds"`
}

const (
	discordDefaultTimeoutSeconds = 10
	discordMinTimeoutSeconds     = 1
	discordMaxTimeoutSeconds     = 60
	// The hosts Discord serves webhooks on.
	// Checked so a mistyped URL is refused while the operator is looking
	// at the form, instead of becoming a 404 at the first real alert.
	discordWebhookHost    = "discord.com"
	discordWebhookHostAlt = "discordapp.com"
	// discordMaxDescription bounds the embed description. Discord's own
	// limit is 4096; past it the API answers 400, so the sender truncates
	// rather than letting a long body cost an alert.
	discordMaxDescription = 4000
)

// Validate checks the shape.
func (c DiscordConfig) Validate() error {
	url := strings.TrimSpace(c.WebhookURL)
	if url == "" {
		return fmt.Errorf("discord: webhookUrl must not be empty")
	}
	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("discord: webhookUrl must start with https://")
	}
	if !strings.Contains(url, discordWebhookHost) && !strings.Contains(url, discordWebhookHostAlt) {
		return fmt.Errorf("discord: webhookUrl must be a %s webhook URL", discordWebhookHost)
	}
	if c.TimeoutSeconds != 0 &&
		(c.TimeoutSeconds < discordMinTimeoutSeconds || c.TimeoutSeconds > discordMaxTimeoutSeconds) {
		return fmt.Errorf("discord: timeoutSeconds %d out of range %d-%d",
			c.TimeoutSeconds, discordMinTimeoutSeconds, discordMaxTimeoutSeconds)
	}
	return nil
}

// WithDefaults fills the optional fields.
func (c DiscordConfig) WithDefaults() DiscordConfig {
	c.WebhookURL = strings.TrimSpace(c.WebhookURL)
	c.Username = strings.TrimSpace(c.Username)
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = discordDefaultTimeoutSeconds
	}
	return c
}

// ParseDiscordConfig unmarshals a raw Channel.Config and validates it.
func ParseDiscordConfig(raw json.RawMessage) (DiscordConfig, error) {
	var c DiscordConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return DiscordConfig{}, fmt.Errorf("discord config not valid JSON: %w", err)
	}
	if err := c.Validate(); err != nil {
		return DiscordConfig{}, err
	}
	return c.WithDefaults(), nil
}

// discordEmbed is one Discord embed. Only the fields Arenet fills.
type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Color       int    `json:"color,omitempty"`
	Timestamp   string `json:"timestamp,omitempty"`
}

// discordPayload is the request body.
type discordPayload struct {
	Username string         `json:"username,omitempty"`
	Embeds   []discordEmbed `json:"embeds"`
}

// discordSeverityColours maps a severity to Discord's decimal colour,
// chosen to read at a glance in a busy channel rather than to be pretty.
//
// Arenet has exactly four severities (types.go:50-70) — there is no
// "error" tier between warning and critical.
var discordSeverityColours = map[Severity]int{
	SeverityEmergency: 0xE74C3C, // red — the data plane may be impaired
	SeverityCritical:  0xE67E22, // orange — act soon
	SeverityWarning:   0xF1C40F, // amber — look at it
	SeverityInfo:      0x95A5A6, // grey — FYI
}

const discordDefaultColour = 0x95A5A6

// truncateRunes shortens s to at most max BYTES without splitting a
// character.
//
// Discord answers 400 past its own description limit, so a truncated
// alert beats a lost one. Slicing by byte offset would be shorter but can
// cut a multi-byte character in half, and json.Marshal then replaces the
// broken pair with U+FFFD — a mangled tail on the very alert someone is
// reading under pressure.
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := 0
	for i := range s {
		if i > max {
			break
		}
		cut = i
	}
	return s[:cut] + "…"
}

// DiscordSender posts an alert to a Discord webhook.
type DiscordSender struct {
	cfg    DiscordConfig
	client *http.Client
}

// NewDiscordSender builds a sender from a validated config.
func NewDiscordSender(cfg DiscordConfig) *DiscordSender {
	cfg = cfg.WithDefaults()
	return &DiscordSender{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
	}
}

// Kind implements AlertSender.
func (s *DiscordSender) Kind() string { return "discord" }

// Send implements AlertSender. One attempt, no retry, matching the
// webhook sender's contract.
func (s *DiscordSender) Send(ctx context.Context, evt AlertEvent) error {
	colour, ok := discordSeverityColours[evt.Severity]
	if !ok {
		colour = discordDefaultColour
	}

	description := evt.Body
	if description == "" {
		description = evt.Subject
	}
	description = truncateRunes(description, discordMaxDescription)

	payload := discordPayload{
		Username: s.cfg.Username,
		Embeds: []discordEmbed{{
			Title:       fmt.Sprintf("[%s] %s", evt.Severity, evt.RuleName),
			Description: description,
			Color:       colour,
			Timestamp:   evt.Timestamp.UTC().Format(time.RFC3339),
		}},
	}

	// Marshalled, never templated: this is the whole reason the kind
	// exists. A subject carrying a quote or a newline is escaped by the
	// encoder instead of producing an invalid body.
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("discord: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("discord: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("User-Agent", "arenet/alerting-discord")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("discord: send: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Quote Discord's own explanation — it names the offending
		// field, which is what was missing when this had to be
		// diagnosed from an opaque 400.
		return fmt.Errorf("discord: webhook returned HTTP %d: %s",
			resp.StatusCode, readErrorSnippet(resp.Body))
	}
	return nil
}

// Interface guard.
var _ AlertSender = (*DiscordSender)(nil)
