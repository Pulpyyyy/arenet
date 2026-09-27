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
	"encoding/json"
	"testing"
)

// v2.53 — a body template can escape a value.
//
// Without this, a template writing JSON had no way to quote an operator
// or event string, so an alert whose subject contained a quote or a
// newline produced a body the receiver rejected. Discord answered an
// opaque HTTP 400, and only for the alerts whose text happened to be
// hostile — the hardest kind of failure to chase.

func TestBodyTemplate_JSONFuncEscapes(t *testing.T) {
	tmpl, err := compileBodyTemplate(`{"text": {{ json .Subject }}}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	evt := AlertEvent{Subject: `he said "no" \ and
a newline`}
	out, err := renderTemplate(tmpl, evt)
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var got struct{ Text string }
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("the rendered body is not valid JSON: %v\n%s", err, out)
	}
	if got.Text != evt.Subject {
		t.Errorf("round-trip lost the value:\n got %q\nwant %q", got.Text, evt.Subject)
	}
}

// The failure mode being fixed, kept as a demonstration: the same
// template without `json` produces an invalid body for the same input.
// If this ever starts passing, the hazard has gone away and the guard
// above can be reconsidered.
func TestBodyTemplate_WithoutJSONFuncBreaksOnQuotes(t *testing.T) {
	tmpl, err := compileBodyTemplate(`{"text": "{{ .Subject }}"}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	out, err := renderTemplate(tmpl, AlertEvent{Subject: `he said "no"`})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var sink map[string]any
	if err := json.Unmarshal([]byte(out), &sink); err == nil {
		t.Fatalf("expected invalid JSON without the json func, got a parseable body: %s", out)
	}
}
