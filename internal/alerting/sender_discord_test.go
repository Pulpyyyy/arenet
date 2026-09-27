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
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// v2.53 — the Discord sender.
//
// It exists because the generic webhook posts Arenet's own event shape,
// which Discord refuses with an opaque 400, and the documented workaround
// — a body template — is string interpolation with no JSON escaping. The
// tests below therefore care about two things above all: that the body is
// shaped the way Discord requires, and that a hostile subject cannot
// break it.

func discordEvent() AlertEvent {
	return AlertEvent{
		ID:        "evt-1",
		Timestamp: time.Date(2026, 9, 27, 13, 51, 48, 0, time.UTC),
		RuleID:    "r-1",
		RuleName:  "cert-expiry",
		Severity:  SeverityCritical,
		Subject:   "certificate expires in 9 days",
	}
}

// captureDiscord stands in for Discord and hands back what it received.
func captureDiscord(t *testing.T, status int, respBody string) (*httptest.Server, *[]byte) {
	t.Helper()
	var got []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = b
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestDiscordSender_PostsAnEmbed(t *testing.T) {
	srv, got := captureDiscord(t, 204, "")
	s := NewDiscordSender(DiscordConfig{WebhookURL: srv.URL, Username: "arenet"})

	if err := s.Send(context.Background(), discordEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var payload struct {
		Username string `json:"username"`
		Embeds   []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Color       int    `json:"color"`
			Timestamp   string `json:"timestamp"`
		} `json:"embeds"`
	}
	if err := json.Unmarshal(*got, &payload); err != nil {
		t.Fatalf("the body Discord received is not valid JSON: %v\n%s", err, *got)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("want exactly one embed, got %d", len(payload.Embeds))
	}
	if payload.Username != "arenet" {
		t.Errorf("username = %q", payload.Username)
	}
	e := payload.Embeds[0]
	if !strings.Contains(e.Title, "cert-expiry") || !strings.Contains(e.Title, "critical") {
		t.Errorf("title = %q; want the severity and the rule name", e.Title)
	}
	if e.Description != "certificate expires in 9 days" {
		t.Errorf("description = %q", e.Description)
	}
	if e.Color == 0 {
		t.Error("no colour: a severity must be distinguishable at a glance")
	}
	if e.Timestamp != "2026-09-27T13:51:48Z" {
		t.Errorf("timestamp = %q", e.Timestamp)
	}
}

// THE test. A subject carrying quotes, newlines and a backslash is what
// broke the templated workaround, producing an invalid body and an
// intermittent 400. Marshalling must make that impossible.
func TestDiscordSender_HostileSubjectStaysValidJSON(t *testing.T) {
	srv, got := captureDiscord(t, 204, "")
	s := NewDiscordSender(DiscordConfig{WebhookURL: srv.URL})

	evt := discordEvent()
	evt.Subject = `he said "no" \ then
a newline	and a tab`

	if err := s.Send(context.Background(), evt); err != nil {
		t.Fatalf("Send: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(*got, &payload); err != nil {
		t.Fatalf("a hostile subject produced invalid JSON — the exact bug this kind exists to remove: %v\n%s", err, *got)
	}
}

// Discord's own refusal must reach the operator. An opaque "HTTP 400" is
// what made this take an hour to diagnose.
func TestDiscordSender_QuotesDiscordsExplanation(t *testing.T) {
	srv, _ := captureDiscord(t, 400, `{"message":"Cannot send an empty message","code":50006}`)
	s := NewDiscordSender(DiscordConfig{WebhookURL: srv.URL})

	err := s.Send(context.Background(), discordEvent())
	if err == nil {
		t.Fatal("want an error on HTTP 400")
	}
	if !strings.Contains(err.Error(), "50006") {
		t.Errorf("the error does not quote Discord's explanation: %v", err)
	}
}

// A long body must be truncated rather than costing the alert, and the
// truncation must not split a character.
func TestDiscordSender_TruncatesWithoutBreakingUTF8(t *testing.T) {
	srv, got := captureDiscord(t, 204, "")
	s := NewDiscordSender(DiscordConfig{WebhookURL: srv.URL})

	evt := discordEvent()
	// Three-byte runes, so a byte-offset cut would land mid-character.
	evt.Body = strings.Repeat("é☃", 4000)

	if err := s.Send(context.Background(), evt); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(*got, &payload); err != nil {
		t.Fatalf("truncation produced invalid JSON: %v", err)
	}
	if strings.Contains(string(*got), `�`) {
		t.Error("truncation split a character (U+FFFD in the body)")
	}
}

func TestDiscordConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     DiscordConfig
		wantErr bool
	}{
		{"ok", DiscordConfig{WebhookURL: "https://discord.com/api/webhooks/1/abc"}, false},
		{"ok legacy host", DiscordConfig{WebhookURL: "https://discordapp.com/api/webhooks/1/abc"}, false},
		{"empty", DiscordConfig{}, true},
		{"not https", DiscordConfig{WebhookURL: "http://discord.com/api/webhooks/1/abc"}, true},
		{"wrong host", DiscordConfig{WebhookURL: "https://example.com/hook"}, true},
		{"timeout too large", DiscordConfig{WebhookURL: "https://discord.com/api/webhooks/1/a", TimeoutSeconds: 999}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.cfg.Validate(); (err != nil) != c.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

// v2.54 — mentions.
//
// The operator asked to be pinged "like an @pseudo". Two upstream facts
// shape every test below:
//
//  1. Discord scopes mention notifications to the message content. A
//     mention written into an embed renders as a blue name and notifies
//     nobody — so the mention CANNOT live in the embed Arenet already
//     sends, and a test that only checked the rendered text would pass
//     while the feature did nothing.
//  2. `allowed_mentions.parse` is mutually exclusive with `users` and
//     `roles`; sending both is a validation error, i.e. a 400.

// discordBody is the payload shape the mention tests read back.
type discordBody struct {
	Content string `json:"content"`
	Embeds  []struct {
		Description string `json:"description"`
	} `json:"embeds"`
	AllowedMentions *struct {
		Parse []string `json:"parse"`
		Users []string `json:"users"`
		Roles []string `json:"roles"`
	} `json:"allowed_mentions"`
}

func sendAndDecode(t *testing.T, cfg DiscordConfig) ([]byte, discordBody) {
	t.Helper()
	srv, got := captureDiscord(t, 204, "")
	cfg.WebhookURL = srv.URL
	if err := NewDiscordSender(cfg).Send(context.Background(), discordEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var body discordBody
	if err := json.Unmarshal(*got, &body); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, *got)
	}
	return *got, body
}

// The load-bearing one: the mention must be in `content`, because that is
// the only place Discord raises a notification from.
func TestDiscordSender_MentionsGoInContentNotTheEmbed(t *testing.T) {
	raw, body := sendAndDecode(t, DiscordConfig{
		MentionUserIDs: []string{"306162232765874176"},
		MentionRoleIDs: []string{"847291046728394112"},
	})

	if body.Content != "<@306162232765874176> <@&847291046728394112>" {
		t.Errorf("content = %q; want the user token then the role token", body.Content)
	}
	// A mention inside the embed would look right in the channel and
	// notify no one. Guard against a future "tidy-up" that moves it there.
	if len(body.Embeds) != 1 {
		t.Fatalf("want one embed, got %d", len(body.Embeds))
	}
	if strings.Contains(body.Embeds[0].Description, "306162232765874176") {
		t.Error("the mention leaked into the embed description, where Discord raises no notification")
	}
	if !strings.Contains(string(raw), `"content"`) {
		t.Error("no content field at all — nobody would be notified")
	}
}

// parse must be ABSENT, not empty: Discord documents it as mutually
// exclusive with users/roles and answers 400 when both are sent.
func TestDiscordSender_AllowedMentionsNamesExactlyThoseIDsAndOmitsParse(t *testing.T) {
	raw, body := sendAndDecode(t, DiscordConfig{
		MentionUserIDs: []string{"306162232765874176"},
		MentionRoleIDs: []string{"847291046728394112"},
	})

	if body.AllowedMentions == nil {
		t.Fatal("no allowed_mentions: a role mention would not notify, since a webhook parses only users by default")
	}
	if strings.Contains(string(raw), `"parse"`) {
		t.Errorf("parse was sent alongside users/roles — Discord rejects that combination: %s", raw)
	}
	if len(body.AllowedMentions.Users) != 1 || body.AllowedMentions.Users[0] != "306162232765874176" {
		t.Errorf("allowed users = %v", body.AllowedMentions.Users)
	}
	if len(body.AllowedMentions.Roles) != 1 || body.AllowedMentions.Roles[0] != "847291046728394112" {
		t.Errorf("allowed roles = %v", body.AllowedMentions.Roles)
	}
}

// An allow-list naming only the configured IDs also means an alert body
// carrying @everyone cannot ping a server. Worth a test of its own: it is
// a property of the payload, not a side effect anyone would look for.
func TestDiscordSender_AlertBodyCannotPingEveryone(t *testing.T) {
	srv, got := captureDiscord(t, 204, "")
	evt := discordEvent()
	evt.Body = "@everyone @here the certificate expired"
	cfg := DiscordConfig{WebhookURL: srv.URL, MentionUserIDs: []string{"306162232765874176"}}

	if err := NewDiscordSender(cfg).Send(context.Background(), evt); err != nil {
		t.Fatalf("Send: %v", err)
	}
	var body discordBody
	if err := json.Unmarshal(*got, &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	// The text is still shown — it is the alert. It just cannot notify.
	if !strings.Contains(body.Embeds[0].Description, "@everyone") {
		t.Error("the alert body was altered; it should be delivered verbatim")
	}
	if body.AllowedMentions == nil || len(body.AllowedMentions.Parse) != 0 {
		t.Errorf("parse = %v; an empty/absent parse is what stops @everyone in the body from firing",
			body.AllowedMentions)
	}
}

// Non-regression: a channel configured before v2.54 must post the body it
// posted before. Both new keys have to be absent, not empty.
func TestDiscordSender_NoMentionsLeavesThePayloadUnchanged(t *testing.T) {
	raw, body := sendAndDecode(t, DiscordConfig{Username: "arenet"})

	if strings.Contains(string(raw), `"content"`) {
		t.Errorf("content present with no mention configured: %s", raw)
	}
	if strings.Contains(string(raw), `"allowed_mentions"`) {
		t.Errorf("allowed_mentions present with no mention configured: %s", raw)
	}
	if body.Content != "" || body.AllowedMentions != nil {
		t.Error("decoded payload carries mention fields it should not")
	}
}

func TestDiscordConfig_MentionValidation(t *testing.T) {
	base := func() DiscordConfig {
		return DiscordConfig{WebhookURL: "https://discord.com/api/webhooks/1/abc"}
	}
	tooMany := make([]string, discordMaxMentionsPerList+1)
	for i := range tooMany {
		tooMany[i] = strconv.Itoa(100000000000000000 + i)
	}

	tests := []struct {
		name    string
		mutate  func(*DiscordConfig)
		wantErr string
	}{
		{"a username is refused, with the fix in the message", func(c *DiscordConfig) {
			c.MentionUserIDs = []string{"@ludovic"}
		}, "numeric ID"},
		{"a bare name is refused too", func(c *DiscordConfig) {
			c.MentionUserIDs = []string{"ludovic"}
		}, "numeric ID"},
		{"a role name is refused", func(c *DiscordConfig) {
			c.MentionRoleIDs = []string{"admins"}
		}, "numeric ID"},
		{"past Discord's per-list cap", func(c *DiscordConfig) {
			c.MentionUserIDs = tooMany
		}, "at most 100"},
		{"a real user ID is accepted", func(c *DiscordConfig) {
			c.MentionUserIDs = []string{"306162232765874176"}
		}, ""},
		{"both lists empty stays valid", func(c *DiscordConfig) {}, ""},
		{"blank entries are ignored, not refused", func(c *DiscordConfig) {
			c.MentionUserIDs = []string{"", "  ", "306162232765874176"}
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v; want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil; want an error mentioning %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %q; want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

// A pasted list often repeats someone. Rendering them twice is untidy and
// says Arenet did not look at its input.
func TestDiscordConfig_WithDefaults_DedupesMentions(t *testing.T) {
	cfg := DiscordConfig{
		MentionUserIDs: []string{"306162232765874176", " 306162232765874176 ", "847291046728394112"},
	}.WithDefaults()

	if len(cfg.MentionUserIDs) != 2 {
		t.Fatalf("MentionUserIDs = %v; want the duplicate collapsed", cfg.MentionUserIDs)
	}
	if cfg.MentionUserIDs[0] != "306162232765874176" {
		t.Errorf("order changed: %v", cfg.MentionUserIDs)
	}
}
