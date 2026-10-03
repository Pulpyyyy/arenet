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

package logredact

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// The case this exists for, from a real access log line: a live Dolibarr API
// key written in full, one field away from a Cookie that Caddy had dutifully
// replaced with REDACTED.
//
// These tests encode the header through the filter the way Caddy does — an
// object marshaler handed to the filter, re-marshalled into a real zap JSON
// encoder — rather than calling IsSecretHeader directly. Asserting on the
// predicate would prove the list and not the wiring, and the wiring is where
// a secret escapes.

// loggableHeader mirrors how Caddy marshals an http.Header into a log:
// one array of values per name (caddy internal/logmarshalers.go).
type loggableHeader http.Header

func (h loggableHeader) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for name, values := range h {
		if err := enc.AddArray(name, loggableValues(values)); err != nil {
			return err
		}
	}
	return nil
}

type loggableValues []string

func (v loggableValues) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, s := range v {
		enc.AppendString(s)
	}
	return nil
}

// encodeThroughFilter renders the header exactly as the access log would,
// and returns the JSON object that lands on disk.
func encodeThroughFilter(t *testing.T, h http.Header) map[string]any {
	t.Helper()
	field := HeaderFilter{}.Filter(zap.Any("headers", loggableHeader(h)))

	enc := zapcore.NewMapObjectEncoder()
	field.AddTo(enc)

	raw, err := json.Marshal(enc.Fields["headers"])
	if err != nil {
		t.Fatalf("marshal encoded headers: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func firstValue(t *testing.T, obj map[string]any, key string) string {
	t.Helper()
	vals, ok := obj[key].([]any)
	if !ok || len(vals) == 0 {
		t.Fatalf("header %q missing from the encoded line: %v", key, obj)
	}
	s, _ := vals[0].(string)
	return s
}

func TestFilter_MasksTheOperatorsRealLeak(t *testing.T) {
	out := encodeThroughFilter(t, http.Header{
		"Dolapikey":  {"a-live-dolibarr-key"},
		"User-Agent": {"n8n"},
		"Accept":     {"application/json"},
	})

	if got := firstValue(t, out, "Dolapikey"); got != Placeholder {
		t.Errorf("Dolapikey = %q; want %q — this exact header carried a live key in an "+
			"operator's access log", got, Placeholder)
	}
	// The name survives: an operator still learns a key was presented,
	// which is what makes a backend refusing them diagnosable.
	if _, present := out["Dolapikey"]; !present {
		t.Error("the header name was removed; only its value should be")
	}
	// And nothing else is touched — a filter that ate the diagnostics
	// would be its own bug.
	if got := firstValue(t, out, "User-Agent"); got != "n8n" {
		t.Errorf("User-Agent = %q; want it untouched", got)
	}
	if got := firstValue(t, out, "Accept"); got != "application/json" {
		t.Errorf("Accept = %q; want it untouched", got)
	}
}

func TestFilter_CoversTheCredentialHeadersInTheWild(t *testing.T) {
	// Names taken from the APIs a homelab actually runs.
	secrets := []string{
		"X-Api-Key", "x-api-key", "X-API-KEY",
		"Dolapikey", "PVEAPIToken", "X-N8N-API-KEY",
		"X-Auth-Token", "X-Vault-Token", "Private-Token",
		"X-Client-Secret", "X-Hub-Signature-256", "X-Credential",
		"X-Password",
	}
	h := http.Header{}
	for _, name := range secrets {
		h.Set(name, "the-secret")
	}
	out := encodeThroughFilter(t, h)

	for _, name := range secrets {
		// http.Header canonicalises names on Set; read them back that way.
		canonical := http.CanonicalHeaderKey(name)
		if got := firstValue(t, out, canonical); got != Placeholder {
			t.Errorf("%s = %q; want %q", canonical, got, Placeholder)
		}
	}
}

// The headers an operator needs to keep reading. Each of these was weighed
// when the pattern list was chosen; a regression here means the list grew
// something too broad.
func TestFilter_LeavesDiagnosticHeadersAlone(t *testing.T) {
	keep := map[string]string{
		"Api-Version":          "3",
		"X-Authentik-Username": "someone",
		"X-Forwarded-For":      "203.0.113.9",
		"X-Forwarded-Proto":    "https",
		"X-Request-Id":         "abc123",
		"Content-Type":         "application/json",
		"Accept-Encoding":      "gzip",
		"Dolapientity":         "1",
	}
	h := http.Header{}
	for name, value := range keep {
		h.Set(name, value)
	}
	out := encodeThroughFilter(t, h)

	for name, want := range keep {
		canonical := http.CanonicalHeaderKey(name)
		got := firstValue(t, out, canonical)
		if got == Placeholder {
			t.Errorf("%s was redacted; it carries no credential and an operator needs to "+
				"read it. If a pattern had to grow, say so in SecretHeaderPatterns and "+
				"change this test deliberately.", canonical)
			continue
		}
		if got != want {
			t.Errorf("%s = %q; want %q", canonical, got, want)
		}
	}
}

// The accepted false positive, recorded rather than discovered later.
//
// "monkey" ends with "key". No substring rule can catch Dolapikey — one word,
// no separator — while sparing monkey, so this is the price of catching the
// header names nobody enumerated. It is the right trade by the same asymmetry
// that chose substrings: a redacted X-Monkey-Business costs one field of one
// log line; a missed credential sits on disk through every rotation.
//
// This is a test and not a comment because the next person to see it in a log
// should find the decision, not re-derive it.
func TestFilter_RedactsFalsePositivesInLongerWords(t *testing.T) {
	out := encodeThroughFilter(t, http.Header{"X-Monkey-Business": {"none"}})
	if got := firstValue(t, out, "X-Monkey-Business"); got != Placeholder {
		t.Errorf("X-Monkey-Business = %q; want %q. Not a bug: see the comment above. If "+
			"this starts passing, the pattern matching was narrowed and Dolapikey needs "+
			"re-checking.", got, Placeholder)
	}
}

// Multi-valued headers collapse to one placeholder rather than leaking the
// count, and stay an array so a log consumer still parses the line.
func TestFilter_MultiValuedSecretCollapses(t *testing.T) {
	out := encodeThroughFilter(t, http.Header{
		"X-Api-Key": {"first", "second", "third"},
	})
	vals, ok := out["X-Api-Key"].([]any)
	if !ok {
		t.Fatalf("X-Api-Key is not an array: %#v", out["X-Api-Key"])
	}
	if len(vals) != 1 || vals[0] != Placeholder {
		t.Errorf("X-Api-Key = %v; want exactly [%q] — the number of values is itself a hint",
			vals, Placeholder)
	}
}

// A field the filter does not understand must pass through, not vanish.
func TestFilter_PassesThroughANonObjectField(t *testing.T) {
	in := zap.String("headers", "not an object")
	if got := (HeaderFilter{}).Filter(in); got.String != "not an object" {
		t.Errorf("filter mangled a non-object field: %+v", got)
	}
}

func TestFilterName_IsTheLastSegmentOfTheModuleID(t *testing.T) {
	if FilterName != "arenet_header_redact" {
		t.Errorf("FilterName = %q; want arenet_header_redact", FilterName)
	}
	if strings.Contains(FilterName, ".") {
		t.Errorf("FilterName = %q; Caddy names a filter by the last segment only, and a "+
			"wrong name here leaves the field unfiltered without failing validation", FilterName)
	}
}
