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

package caddymgr

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExampleMaintenancePage_SurvivesPipeline guards the shipped example
// custom maintenance page (docs/examples/maintenance-page-example.html)
// against silent rot: it runs the file through the SAME pipeline a real
// operator-uploaded page goes through — SanitizeErrorPageBody (bluemonday
// + at-rule strip + {env}/{file} neutralize) then buildMaintenanceBody
// (placeholder substitution) — and asserts that:
//
//  1. every Arenet placeholder the example relies on is actually
//     substituted (no live sentinel leaks to the browser as literal text),
//  2. the visual CSS the example depends on survives the sanitizer
//     (animations, backdrop-filter, the data-URI noise texture, @media).
//
// If a future sanitizer change strips something the example needs, this
// test fails loudly instead of the example quietly rendering broken for
// every user who copied it. Mirrors the managed-domain fixture test's
// "the shipped artifact is a contract" posture.
func TestExampleMaintenancePage_SurvivesPipeline(t *testing.T) {
	// Both language variants of the shipped example are contracts.
	for _, name := range []string{
		"maintenance-page-example-en.html",
		"maintenance-page-example-fr.html",
	} {
		t.Run(name, func(t *testing.T) {
			assertExampleMaintenancePageSurvives(t, name)
		})
	}
}

func assertExampleMaintenancePageSurvives(t *testing.T, filename string) {
	path := filepath.Join("..", "..", "docs", "examples", filename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example page: %v", err)
	}

	// Exact pipeline a custom maintenance page goes through at serve time.
	sanitized := SanitizeErrorPageBody(string(raw))
	body := buildMaintenanceBody(sanitized, 1800, "Scheduled maintenance in progress.")

	mustContain := map[string]string{
		// Placeholders the example uses are substituted.
		"refresh_meta → auto-refresh tag": `<meta http-equiv="refresh" content="1800">`,
		"message substituted":             "Scheduled maintenance in progress.",
		// Visual CSS the example depends on survives the sanitizer.
		"@keyframes preserved":      "@keyframes",
		"@media preserved":          "@media",
		"backdrop-filter preserved": "backdrop-filter",
		"conic-gradient preserved":  "conic-gradient",
		"data-URI noise preserved":  "data:image/svg+xml",
	}
	for label, needle := range mustContain {
		if !strings.Contains(body, needle) {
			t.Errorf("%s: %q missing from the served body", label, needle)
		}
	}

	// How each example states the delay is a per-file choice, so it is
	// asserted per file rather than in the shared map above.
	//
	// The English example uses {arenet.maintenance.retry_after_human} and
	// must therefore render words, never the raw "1800s" the operator
	// complained about. The French one deliberately keeps the integer:
	// the humanised form is English-only and the served page has no
	// locale, so English words inside French prose would read worse than
	// a number. Both must substitute SOMETHING — a sentinel reaching the
	// browser is the failure either way, and mustNotContain below covers
	// that.
	//
	// Asserted on the rendered ELEMENT, not on the body as a whole. The
	// first version of this looked anywhere in the body and failed
	// against a CSS comment in the French example that merely MENTIONED
	// the English rendering — a true statement in a comment is not a
	// visitor-facing string, and the test could not tell the difference.
	wantDelay := map[string]string{
		"maintenance-page-example-en.html": `<span class="eta-v">30 minutes</span>`,
		"maintenance-page-example-fr.html": `<span class="eta-v">1800s</span>`,
	}
	want, ok := wantDelay[filename]
	if !ok {
		t.Fatalf("no delay expectation defined for %s — add one when shipping a new example", filename)
	}
	if !strings.Contains(body, want) {
		t.Errorf("delay not rendered as expected: %q missing from the served body", want)
	}

	mustNotContain := map[string]string{
		// No unsubstituted Arenet sentinel should reach the browser.
		"message sentinel leaked":      "{arenet.maintenance.message}",
		"refresh_meta sentinel leaked": "{arenet.maintenance.refresh_meta}",
		"retry_after sentinel leaked":  "{arenet.maintenance.retry_after}",
		// The example must not rely on placeholders Arenet doesn't provide
		// (a past draft used {arenet.maintenance.eta}/.contact — those would
		// render as literal text and must never come back).
		"nonexistent eta placeholder":     "{arenet.maintenance.eta}",
		"nonexistent contact placeholder": "{arenet.maintenance.contact}",
	}
	for label, needle := range mustNotContain {
		if strings.Contains(body, needle) {
			t.Errorf("%s: %q must not appear in the served body", label, needle)
		}
	}

	// Empty message must collapse cleanly (the .message:empty rule), so an
	// unconfigured message leaves no stray text — verify the substitution
	// yields an empty <p class="message"></p>, not a leftover sentinel.
	emptyBody := buildMaintenanceBody(sanitized, 1800, "")
	if strings.Contains(emptyBody, "{arenet.maintenance.message}") {
		t.Error("empty message left the sentinel unsubstituted in the example page")
	}
	if !strings.Contains(emptyBody, `<p class="message"></p>`) {
		t.Error("empty message did not yield an empty <p class=\"message\"> (needed for :empty collapse)")
	}
}
