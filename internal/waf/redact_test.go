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

package waf

import (
	"strings"
	"testing"
)

func TestRedact_BearerToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"plain", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.foo.bar"},
		{"lowercase_header", "authorization: bearer abc.def.ghi"},
		{"mixed_case", "AuThOrIzAtIoN: BeArEr tok123"},
		{"with_trailing_text", "Authorization: Bearer sk-xyz More: text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if !strings.Contains(strings.ToLower(got), "[redacted]") {
				t.Fatalf("expected redaction marker; got %q", got)
			}
			// The token MUST be gone.
			for _, fragment := range []string{"eyJhbGciOiJIUzI1NiJ9", "abc.def.ghi", "tok123", "sk-xyz"} {
				if strings.Contains(got, fragment) {
					t.Errorf("token fragment %q survived redaction: %q", fragment, got)
				}
			}
		})
	}
}

func TestRedact_CookieHeader(t *testing.T) {
	in := "Cookie: arenet_session=abc123; csrf=xyz789"
	got := Redact(in)
	if strings.Contains(got, "abc123") || strings.Contains(got, "xyz789") {
		t.Fatalf("cookie value leaked: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("missing redaction marker: %q", got)
	}
	// Header name stays so the operator sees what was scrubbed.
	if !strings.HasPrefix(strings.ToLower(got), "cookie:") {
		t.Fatalf("header name stripped: %q", got)
	}
}

func TestRedact_SetCookieHeader(t *testing.T) {
	in := "Set-Cookie: arenet_session=newvalue; Path=/; HttpOnly"
	got := Redact(in)
	if strings.Contains(got, "newvalue") {
		t.Fatalf("set-cookie value leaked: %q", got)
	}
}

func TestRedact_SensitiveQueryParam(t *testing.T) {
	cases := []struct {
		name string
		in   string
		gone string
	}{
		{"password", "/login?username=admin&password=hunter2", "hunter2"},
		{"passwd_short", "/login?passwd=mypass", "mypass"},
		{"api_key_underscore", "/api?api_key=sk-prod-abc123", "sk-prod-abc123"},
		{"api_key_dash", "/api?api-key=secret", "secret"},
		{"apikey_squashed", "/api?apikey=v3rys3cret", "v3rys3cret"},
		{"token", "/oauth?token=jwt.payload.sig&state=ok", "jwt.payload.sig"},
		{"secret", "/probe?secret=topsecret", "topsecret"},
		{"session", "/restore?session=s3ssion-id", "s3ssion-id"},
		{"auth", "/x?auth=basic-creds", "basic-creds"},
		// v2.56 — the reported case. Vaultwarden puts the user's access
		// token in the URI; the old pattern was anchored on `?` or `&`
		// so `token` never matched `access_token`, and the one
		// parameter most worth redacting was the one that leaked.
		{"access_token_vaultwarden", "/notifications/hub?access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "eyJhbGciOiJIUzI1NiJ9"},
		{"id_token", "/cb?id_token=eyJ.payload.sig", "eyJ.payload.sig"},
		{"refresh_token", "/cb?refresh_token=r3fr3sh-me", "r3fr3sh-me"},
		{"access_token_mid_query", "/hub?x=1&access_token=abc123&y=2", "abc123"},
		{"access_token_uppercase", "/hub?ACCESS_TOKEN=abc123", "abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Redact(tc.in)
			if strings.Contains(got, tc.gone) {
				t.Errorf("sensitive value %q survived: %q", tc.gone, got)
			}
			if !strings.Contains(got, "[REDACTED]") {
				t.Errorf("missing redaction marker: %q", got)
			}
		})
	}
}

func TestRedact_NonSensitivePathPreserved(t *testing.T) {
	// AC anti-regression on the false-positive risk
	// documented in §1.6.2: attack payloads we WANT to keep
	// visible must NOT be touched.
	cases := []string{
		"/api?path=../etc/passwd",      // LFI probe
		"/search?q=<script>alert(1)",   // XSS probe
		"/sql?id=1+OR+1=1+--",          // SQLi probe
		"/cmd?run=%3B+cat+/etc/shadow", // RCE probe
		"/normal?foo=bar&page=2",       // benign
		// v2.56 — the prefixes are explicit for this reason: a suffix
		// match would redact these, and they may be the payload.
		"/x?mytoken=../etc/passwd",
		"/x?csrftoken=<script>",
	}
	for _, in := range cases {
		t.Run("input="+in, func(t *testing.T) {
			got := Redact(in)
			if got != in {
				t.Errorf("non-sensitive input mutated: %q → %q", in, got)
			}
		})
	}
}

func TestRedact_Idempotent(t *testing.T) {
	in := "Authorization: Bearer tok ; Cookie: x=y ; /q?api_key=abc"
	once := Redact(in)
	twice := Redact(once)
	if once != twice {
		t.Fatalf("redact not idempotent: once=%q twice=%q", once, twice)
	}
}

func TestRedact_EmptyPassthrough(t *testing.T) {
	if got := Redact(""); got != "" {
		t.Errorf("empty input mutated to %q", got)
	}
}

func TestRedact_MultiplePatternsInOneString(t *testing.T) {
	// Realistic payload sample combining several patterns.
	in := "POST /login?api_key=sk-abc HTTP/1.1\nAuthorization: Bearer eyJtok\nCookie: sess=xyz"
	got := Redact(in)
	for _, gone := range []string{"sk-abc", "eyJtok", "xyz"} {
		if strings.Contains(got, gone) {
			t.Errorf("fragment %q survived multi-pattern redact: %q", gone, got)
		}
	}
}
