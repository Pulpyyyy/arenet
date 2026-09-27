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
	"strings"
	"testing"
)

// Step AL.1.a — Channel validation gate tests. Per-kind
// Config shape validation lives at the CRUD layer (it
// needs the JSON parser); these tests cover the kind-
// agnostic envelope only.

func validWebhookConfig() json.RawMessage {
	return json.RawMessage(`{"url":"https://hooks.example.com/x","method":"POST","timeout_seconds":10}`)
}

func TestValidateAlertChannel_AcceptsWebhook(t *testing.T) {
	c := Channel{
		Name:        "ops-webhook",
		Kind:        ChannelKindWebhook,
		Enabled:     true,
		MinSeverity: 1,
		Config:      validWebhookConfig(),
	}
	if err := ValidateAlertChannel(c); err != nil {
		t.Errorf("valid webhook channel rejected: %v", err)
	}
}

func TestValidateAlertChannel_AcceptsEmail(t *testing.T) {
	c := Channel{
		Name: "ops-email",
		Kind: ChannelKindEmail,
		// MinSeverity int 0 (info) explicitly — the zero
		// value is a meaningful operator choice (receive
		// everything), not a validation bug.
		MinSeverity: 0,
		Config:      json.RawMessage(`{"smtp_host":"smtp.example.com:587"}`),
	}
	if err := ValidateAlertChannel(c); err != nil {
		t.Errorf("valid email channel rejected: %v", err)
	}
}

func TestValidateAlertChannel_RejectsBadName(t *testing.T) {
	cases := []struct {
		name      string
		bad       string
		expectMsg string
	}{
		{"empty", "", "name"},
		{"uppercase", "OpsWebhook", "name"},
		{"with-space", "ops webhook", "name"},
		{"too-long", strings.Repeat("a", 65), "name"},
		{"underscore", "ops_webhook", "name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Channel{
				Name:        tc.bad,
				Kind:        ChannelKindWebhook,
				MinSeverity: 0,
				Config:      validWebhookConfig(),
			}
			err := ValidateAlertChannel(c)
			if err == nil {
				t.Fatalf("want error for name %q", tc.bad)
			}
			if !strings.Contains(err.Error(), tc.expectMsg) {
				t.Errorf("error %q should mention %q", err.Error(), tc.expectMsg)
			}
		})
	}
}

func TestValidateAlertChannel_RejectsUnknownKind(t *testing.T) {
	c := Channel{
		Name:        "ops",
		Kind:        "slack",
		MinSeverity: 0,
		Config:      validWebhookConfig(),
	}
	err := ValidateAlertChannel(c)
	if err == nil {
		t.Fatal("want error for unknown kind 'slack' (V2 candidate)")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("error %q should mention kind", err.Error())
	}
}

func TestValidateAlertChannel_RejectsOutOfRangeSeverity(t *testing.T) {
	cases := []int{-1, 4, 99}
	for _, sev := range cases {
		c := Channel{
			Name:        "ops",
			Kind:        ChannelKindWebhook,
			MinSeverity: sev,
			Config:      validWebhookConfig(),
		}
		if err := ValidateAlertChannel(c); err == nil {
			t.Errorf("min_severity=%d should be rejected", sev)
		}
	}
}

func TestValidateAlertChannel_RejectsEmptyConfig(t *testing.T) {
	c := Channel{
		Name:        "ops",
		Kind:        ChannelKindWebhook,
		MinSeverity: 0,
		// Config left nil.
	}
	if err := ValidateAlertChannel(c); err == nil {
		t.Fatal("want error for empty config")
	}
}

func TestValidateAlertChannel_RejectsMalformedConfig(t *testing.T) {
	c := Channel{
		Name:        "ops",
		Kind:        ChannelKindWebhook,
		MinSeverity: 0,
		Config:      json.RawMessage(`{not json`),
	}
	if err := ValidateAlertChannel(c); err == nil {
		t.Fatal("want error for malformed JSON config")
	}
}

func TestAlertChannelKinds_StableOrder(t *testing.T) {
	// Pin the ordering — the API layer reads from
	// AlertChannelKinds for the "valid kinds" wire response.
	// A change here is operator-visible (the order may
	// influence which kind the frontend selects by default).
	// v2.53 — discord APPENDED, deliberately third.
	//
	// The property this test protects is the order of the first entries,
	// because the frontend selects the first as its default. Adding a
	// kind at the end leaves that untouched; inserting one at the front
	// would silently change which kind a new channel starts as.
	if len(AlertChannelKinds) != 3 {
		t.Fatalf("AlertChannelKinds len = %d; want 3 (webhook, email, discord)", len(AlertChannelKinds))
	}
	if AlertChannelKinds[0] != ChannelKindWebhook {
		t.Errorf("AlertChannelKinds[0] = %q; want webhook — the frontend's default", AlertChannelKinds[0])
	}
	if AlertChannelKinds[1] != ChannelKindEmail {
		t.Errorf("AlertChannelKinds[1] = %q; want email", AlertChannelKinds[1])
	}
	if AlertChannelKinds[2] != ChannelKindDiscord {
		t.Errorf("AlertChannelKinds[2] = %q; want discord", AlertChannelKinds[2])
	}
}
