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
	"slices"
	"testing"

	"github.com/barto95100/arenet/internal/l4metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// The documented enum and the Go table must not drift.
//
// v2.49 — acceptProtocol is the rare field where the documentation being
// wrong is worse than useless. The gate is emitted as a negation, so a
// protocol whose matcher cannot match refuses EVERY connection: an
// operator who trusts a spec that lists one Arenet refuses, or that
// omits one it accepts, is reading a document that can cost them a
// relay.
//
// The Go table is the source of truth (storage.AcceptProtocolsFor); this
// walks the OpenAPI enum against it in both directions.
func TestOpenAPI_AcceptProtocolEnumMatchesStorage(t *testing.T) {
	doc, err := mergedOpenAPI()
	if err != nil {
		t.Fatalf("merge: %v", err)
	}

	schema := resolveRef(doc, "#/components/schemas/TCPServiceInput")
	if schema == nil {
		t.Fatal("TCPServiceInput schema missing")
	}
	props, _ := schema["properties"].(map[string]any)
	field, _ := props["acceptProtocol"].(map[string]any)
	if field == nil {
		t.Fatal("acceptProtocol is not documented on TCPServiceInput")
	}
	rawEnum, _ := field["enum"].([]any)
	if len(rawEnum) == 0 {
		t.Fatal("acceptProtocol has no enum — the offer would be undocumented")
	}

	documented := make([]string, 0, len(rawEnum))
	for _, v := range rawEnum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum carries a non-string value: %#v", v)
		}
		documented = append(documented, s)
	}

	// The union of both transports, plus the empty value that means
	// "accept anything".
	want := []string{storage.AcceptProtocolAny}
	for _, transport := range []string{storage.TCPServiceProtocolTCP, storage.TCPServiceProtocolUDP} {
		for _, p := range storage.AcceptProtocolsFor(transport) {
			if !slices.Contains(want, p) {
				want = append(want, p)
			}
		}
	}

	for _, p := range want {
		if !slices.Contains(documented, p) {
			t.Errorf("accepted by the API but missing from the enum: %q", p)
		}
	}
	for _, p := range documented {
		if !slices.Contains(want, p) {
			t.Errorf("documented but the API refuses it: %q — an operator following the spec gets a 400", p)
		}
	}

	// quic and the SOCKS matchers are named in the description as
	// deliberately unsupported; they must not creep into the enum.
	for _, unsupported := range []string{"quic", "socks4", "socks5"} {
		if slices.Contains(documented, unsupported) {
			t.Errorf("%q is documented as accepted but is deliberately not offered", unsupported)
		}
	}
}

// The counters' cause keys must be the ones the registry actually emits,
// or the UI labels a number nobody produces — and, worse, misses one
// that is produced.
func TestOpenAPI_RefusedCausesDocumented(t *testing.T) {
	doc, err := mergedOpenAPI()
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	schema := resolveRef(doc, "#/components/schemas/TCPServiceCounters")
	if schema == nil {
		t.Fatal("TCPServiceCounters schema missing")
	}
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["refused"].(map[string]any); !ok {
		t.Fatal("refused is not documented on TCPServiceCounters")
	}
	desc, _ := props["refused"].(map[string]any)["description"].(string)
	for _, cause := range l4metrics.Causes() {
		if !slices.Contains(splitWords(desc), cause) {
			t.Errorf("cause %q is emitted but not named in the documentation", cause)
		}
	}
}

// splitWords chops a description into bare words so a cause can be
// looked for without depending on the surrounding punctuation.
func splitWords(s string) []string {
	out := make([]string, 0, 32)
	cur := make([]rune, 0, 16)
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			cur = append(cur, r)
			continue
		}
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}
