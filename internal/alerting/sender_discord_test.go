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
