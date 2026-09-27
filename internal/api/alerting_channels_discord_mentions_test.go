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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.54 — Discord mentions cross the API layer.
//
// CLAUDE.md's Lesson 8: a new config field has to work on BOTH axes.
// Nothing in internal/api names the mention fields — the redaction and
// merge paths round-trip through alerting.DiscordConfig, so they carry
// automatically. That is exactly the kind of "it should just work" that
// is worth a test, because the day someone replaces a typed round-trip
// with a hand-built map, the field disappears with no error anywhere and
// the operator simply stops being pinged.

const discordSeedURL = "https://discord.com/api/webhooks/123/SECRET-TOKEN"

func seedDiscordChannel(t *testing.T, env *testEnv, users, roles []string) storage.Channel {
	t.Helper()
	cfg, _ := json.Marshal(alerting.DiscordConfig{
		WebhookURL:     discordSeedURL,
		TimeoutSeconds: 10,
		MentionUserIDs: users,
		MentionRoleIDs: roles,
	})
	ch, err := env.store.CreateAlertChannel(context.Background(), storage.Channel{
		ID: uuid.NewString(), Name: "ops", Kind: storage.ChannelKindDiscord,
		Enabled: true, MinSeverity: 1, Config: cfg,
	})
	if err != nil {
		t.Fatalf("seed discord channel: %v", err)
	}
	return ch
}

func storedDiscordConfig(t *testing.T, env *testEnv, id string) alerting.DiscordConfig {
	t.Helper()
	ch, err := env.store.GetAlertChannel(context.Background(), id)
	if err != nil {
		t.Fatalf("get stored: %v", err)
	}
	var cfg alerting.DiscordConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		t.Fatalf("decode stored: %v", err)
	}
	return cfg
}

// GET redacts the URL, because it is the credential. It must not redact
// or drop the mentions, which are not secret and which the form has to
// render back to the operator.
func TestDiscordChannel_GETKeepsMentionsAndRedactsOnlyTheURL(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedDiscordChannel(t, env, []string{"306162232765874176"}, []string{"847291046728394112"})

	got := getChannel(t, env, ch.ID)
	var cfg alerting.DiscordConfig
	if err := json.Unmarshal(got.Config, &cfg); err != nil {
		t.Fatalf("decode response config: %v", err)
	}

	if strings.Contains(cfg.WebhookURL, "SECRET-TOKEN") {
		t.Error("the webhook token reached the operator-facing payload")
	}
	if len(cfg.MentionUserIDs) != 1 || cfg.MentionUserIDs[0] != "306162232765874176" {
		t.Errorf("mentionUserIds = %v; the form cannot show what it was not sent", cfg.MentionUserIDs)
	}
	if len(cfg.MentionRoleIDs) != 1 || cfg.MentionRoleIDs[0] != "847291046728394112" {
		t.Errorf("mentionRoleIds = %v", cfg.MentionRoleIDs)
	}
}

// putDiscordChannel saves a Discord channel the way the UI does.
func putDiscordChannel(t *testing.T, env *testEnv, id string, cfg alerting.DiscordConfig) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	body, _ := json.Marshal(map[string]any{
		"name": "ops", "kind": "discord", "enabled": true, "minSeverity": 1,
		"config": json.RawMessage(raw),
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/alerting/channels/"+id, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// The full UI round-trip: the operator opens a channel, adds a mention,
// saves. The redacted URL they were shown must not overwrite the real
// one, and the new mention must land.
func TestDiscordChannel_SaveAfterGETKeepsTheURLAndStoresTheMention(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedDiscordChannel(t, env, nil, nil)

	shown := getChannel(t, env, ch.ID)
	var cfg alerting.DiscordConfig
	if err := json.Unmarshal(shown.Config, &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// What the form now submits: the redacted URL it was given, plus the
	// mention the operator typed.
	cfg.MentionUserIDs = []string{"306162232765874176"}

	if rec := putDiscordChannel(t, env, ch.ID, cfg); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}

	stored := storedDiscordConfig(t, env, ch.ID)
	if stored.WebhookURL != discordSeedURL {
		t.Errorf("stored webhookUrl = %q; the redacted placeholder overwrote the credential", stored.WebhookURL)
	}
	if len(stored.MentionUserIDs) != 1 || stored.MentionUserIDs[0] != "306162232765874176" {
		t.Errorf("stored mentionUserIds = %v; the mention did not survive the save", stored.MentionUserIDs)
	}
}

// Clearing the field must clear the mention — otherwise an operator can
// add a ping but never remove one.
func TestDiscordChannel_SaveCanClearMentions(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedDiscordChannel(t, env, []string{"306162232765874176"}, nil)

	cfg := alerting.DiscordConfig{WebhookURL: discordSeedURL, TimeoutSeconds: 10}
	if rec := putDiscordChannel(t, env, ch.ID, cfg); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}

	if stored := storedDiscordConfig(t, env, ch.ID); len(stored.MentionUserIDs) != 0 {
		t.Errorf("stored mentionUserIds = %v; want empty", stored.MentionUserIDs)
	}
}

// A username must be refused at the API boundary with the reason, not
// accepted and then silently notify no one.
func TestDiscordChannel_RejectsAUsernameAsAMention(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedDiscordChannel(t, env, nil, nil)

	cfg := alerting.DiscordConfig{
		WebhookURL:     discordSeedURL,
		TimeoutSeconds: 10,
		MentionUserIDs: []string{"@someone"},
	}
	rec := putDiscordChannel(t, env, ch.ID, cfg)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT with a username: %d %s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "numeric ID") {
		t.Errorf("body = %s; want it to say a numeric ID is needed", rec.Body)
	}
}
