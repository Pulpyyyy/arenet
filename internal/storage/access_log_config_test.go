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
	"slices"
	"strings"
	"testing"
)

// v2.56 — the redaction list.

func TestAccessLogConfig_RedactDefaultsOnUpgrade(t *testing.T) {
	// A config stored before v2.56 carries no redactQueryParams key.
	// json.Unmarshal into a pre-filled struct leaves absent fields
	// alone, so the defaults survive and an upgrade starts redacting
	// without the operator doing anything. That is the whole reason no
	// migration is needed on this side.
	out := DefaultAccessLogConfig()
	const stored = `{"enabled":true,"rollSizeMB":10,"rollKeep":5,"compress":true}`
	if err := json.Unmarshal([]byte(stored), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.RedactQueryParams) == 0 {
		t.Fatal("a pre-v2.56 config came back with no redaction list; every existing install would keep leaking")
	}
	if !slices.Contains(out.RedactQueryParams, "access_token") {
		t.Errorf("defaults missing access_token: %v", out.RedactQueryParams)
	}
}

// Clearing the list is a choice and must survive a round trip. With
// omitempty an empty slice is not written, the next read finds the key
// absent, and the struct's pre-filled defaults quietly restore the
// redaction the operator had just removed.
func TestAccessLogConfig_ClearedListSurvivesRoundTrip(t *testing.T) {
	c := DefaultAccessLogConfig()
	c.Enabled = true
	c.RedactQueryParams = []string{}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"redactQueryParams":[]`) {
		t.Fatalf("an emptied list was not written: %s", raw)
	}

	back := DefaultAccessLogConfig()
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.RedactQueryParams == nil {
		t.Fatal("the emptied list came back as nil, which means the defaults")
	}
	if len(back.RedactQueryParams) != 0 {
		t.Errorf("the operator's choice was reverted: %v", back.RedactQueryParams)
	}
}

func TestAccessLogConfig_RedactListNormalised(t *testing.T) {
	c := DefaultAccessLogConfig()
	c.RedactQueryParams = []string{" token ", "TOKEN", "", "  ", "secret"}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Trimmed, blanks dropped, and the case-duplicate collapsed because
	// the match is case-insensitive: two alternatives doing the same job
	// is noise in the emitted pattern.
	want := []string{"token", "secret"}
	if !slices.Equal(c.RedactQueryParams, want) {
		t.Errorf("RedactQueryParams = %v, want %v", c.RedactQueryParams, want)
	}
}

func TestAccessLogConfig_RedactListRefusesSeparators(t *testing.T) {
	for _, bad := range []string{"a=b", "a&b", "a?b", "a#b"} {
		c := DefaultAccessLogConfig()
		c.RedactQueryParams = []string{bad}
		if err := c.Validate(); err == nil {
			t.Errorf("entry %q was accepted; it cannot be a parameter name", bad)
		}
	}
}
