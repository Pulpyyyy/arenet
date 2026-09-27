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
	"strconv"
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
	// MentionUserIDs are Discord user IDs to ping on every alert this
	// channel sends. They are IDs, not usernames: Discord resolves
	// `<@306...>`, never `@someone`. Empty means no mention, which is the
	// behaviour before v2.54 and produces a byte-identical payload.
	MentionUserIDs []string `json:"mentionUserIds,omitempty"`
	// MentionRoleIDs are Discord role IDs to ping, same mechanism. A role
	// is usually the better answer than a list of people, because it
	// survives someone leaving the server.
	MentionRoleIDs []string `json:"mentionRoleIds,omitempty"`
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
	// discordMaxMentionsPerList is Discord's documented cap on each
	// allowed_mentions allow-list (100 users, 100 roles).
	discordMaxMentionsPerList = 100
	// discordMaxContent is Discord's limit on the `content` field. The
	// mention line is the only thing Arenet puts there, and 100 user IDs
	// would render past 2000 characters, so the rendered line is measured
	// at validation time instead of trusting the per-list cap alone.
	discordMaxContent = 2000
)

// cleanSnowflakes trims, drops empties and de-duplicates a list of
// Discord IDs, preserving the operator's order.
//
// A duplicate is not an error — it is a copy-paste — but it would render
// the same person twice on the mention line, so it is removed rather
// than refused.
func cleanSnowflakes(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validateSnowflakes checks that every entry could be a Discord ID.
//
// The only mistake worth catching here is the one an operator is most
// likely to make: pasting a username. Discord mentions resolve numeric
// snowflakes and nothing else, so `@someone` would post as literal text
// and silently notify no one — a failure with no error anywhere. The
// check is therefore "is this a number", which is the real constraint,
// rather than a guess at the current ID length, which grows over time.
func validateSnowflakes(kind string, ids []string) error {
	if len(ids) > discordMaxMentionsPerList {
		return fmt.Errorf("discord: at most %d %s mentions, got %d",
			discordMaxMentionsPerList, kind, len(ids))
	}
	for _, id := range ids {
		if _, err := strconv.ParseUint(id, 10, 64); err != nil {
			return fmt.Errorf("discord: %q is not a %s ID — Discord mentions need the numeric ID "+
				"(enable Developer Mode, then right-click → Copy %s ID), not a name", id, kind, kind)
		}
	}
	return nil
}

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
	users := cleanSnowflakes(c.MentionUserIDs)
	roles := cleanSnowflakes(c.MentionRoleIDs)
	if err := validateSnowflakes("user", users); err != nil {
		return err
	}
	if err := validateSnowflakes("role", roles); err != nil {
		return err
	}
	if line := mentionLine(users, roles); len(line) > discordMaxContent {
		return fmt.Errorf("discord: the mention line renders to %d characters, over Discord's limit of %d",
			len(line), discordMaxContent)
	}
	return nil
}

// WithDefaults fills the optional fields.
func (c DiscordConfig) WithDefaults() DiscordConfig {
	c.WebhookURL = strings.TrimSpace(c.WebhookURL)
	c.Username = strings.TrimSpace(c.Username)
	c.MentionUserIDs = cleanSnowflakes(c.MentionUserIDs)
	c.MentionRoleIDs = cleanSnowflakes(c.MentionRoleIDs)
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

// discordAllowedMentions is the allow-list Discord applies to `content`.
//
// `parse` is deliberately absent, not empty: Discord documents it as
// mutually exclusive with these two fields, and sending both is a
// validation error. Omitting it while naming the IDs means exactly those
// IDs notify and nothing else in the text does — so an alert body that
// happens to contain `@everyone` can never ping a whole server.
type discordAllowedMentions struct {
	Users []string `json:"users,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

// discordPayload is the request body.
type discordPayload struct {
	Username string `json:"username,omitempty"`
	// Content carries the mention line, and only ever that.
	//
	// It cannot be folded into the embed. Discord scopes mention
	// notifications to "the message content, or the content of components
	// attached to that message" — a mention written inside an embed
	// renders as a blue name and notifies no one. So a channel with
	// mentions configured posts content + embed; a channel without them
	// posts the embed alone, exactly as before.
	Content         string                  `json:"content,omitempty"`
	Embeds          []discordEmbed          `json:"embeds"`
	AllowedMentions *discordAllowedMentions `json:"allowed_mentions,omitempty"`
}

// mentionLine renders the IDs as Discord's mention tokens: `<@id>` for a
// user, `<@&id>` for a role. Users first, because a named person reads
// as more urgent than a group.
func mentionLine(users, roles []string) string {
	if len(users) == 0 && len(roles) == 0 {
		return ""
	}
	parts := make([]string, 0, len(users)+len(roles))
	for _, id := range users {
		parts = append(parts, "<@"+id+">")
	}
	for _, id := range roles {
		parts = append(parts, "<@&"+id+">")
	}
	return strings.Join(parts, " ")
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
	// Both stay absent when no mention is configured, so an existing
	// channel keeps posting the body it posted before v2.54.
	if line := mentionLine(s.cfg.MentionUserIDs, s.cfg.MentionRoleIDs); line != "" {
		payload.Content = line
		payload.AllowedMentions = &discordAllowedMentions{
			Users: s.cfg.MentionUserIDs,
			Roles: s.cfg.MentionRoleIDs,
		}
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
