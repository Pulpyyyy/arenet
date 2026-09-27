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
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.53 — a synthetic test subject must not carry double quotes.
//
// It did, via %q. The subject is the field an operator is most likely to
// interpolate into a webhook body template, so the test event was
// GUARANTEED to produce invalid JSON and an opaque HTTP 400 — while the
// real alerts the channel would have sent were fine, because a rule's
// default subject carries no quotes.
//
// The only way to validate a channel was therefore the only case certain
// to break it. Reported 2026-09-27 against a Discord webhook.

func TestSyntheticTestAlertEvent_SubjectHasNoDoubleQuotes(t *testing.T) {
	evt := syntheticTestAlertEvent("discord")

	if strings.Contains(evt.Subject, `"`) {
		t.Errorf("the channel-test subject carries a double quote, which breaks any JSON body template: %q", evt.Subject)
	}
	// The name must still be identifiable — the point was never to drop it.
	if !strings.Contains(evt.Subject, "discord") {
		t.Errorf("the channel name vanished from the subject: %q", evt.Subject)
	}
}

func TestSyntheticTestAlertEventForRule_SubjectHasNoDoubleQuotes(t *testing.T) {
	evt := syntheticTestAlertEventForRule(storage.AlertRule{Name: "cert-expiry", Severity: 2})

	if strings.Contains(evt.Subject, `"`) {
		t.Errorf("the rule-test subject carries a double quote: %q", evt.Subject)
	}
	if !strings.Contains(evt.Subject, "cert-expiry") {
		t.Errorf("the rule name vanished from the subject: %q", evt.Subject)
	}
}

// End to end on the shape that actually failed: the operator's template,
// rendered against the real synthetic event, must now be valid JSON.
//
// This is the regression test for the reported bug, and it is written
// against the template a reasonable operator would type rather than a
// contrived one.
func TestSyntheticTestEvent_RendersValidJSONInADiscordTemplate(t *testing.T) {
	evt := syntheticTestAlertEvent("discord")
	// The body an operator was told to use as a workaround.
	body := `{"content":"**[` + evt.Severity.String() + `] ` + evt.RuleName + `**\n` + evt.Subject + `"}`

	if strings.Count(body, `"`)%2 != 0 {
		t.Fatalf("odd number of quotes — the subject unbalanced them:\n%s", body)
	}
	if !jsonParses(body) {
		t.Fatalf("the workaround template still produces invalid JSON:\n%s", body)
	}
}

// jsonParses reports whether s is a JSON object.
func jsonParses(s string) bool {
	var sink map[string]any
	return json.Unmarshal([]byte(s), &sink) == nil
}
