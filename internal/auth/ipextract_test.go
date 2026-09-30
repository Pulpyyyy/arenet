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

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// v2.56.2 — reversed deliberately. This asserted that an empty list means
// no trust at all, which was the old default and is what made the audit
// log record 127.0.0.1 for every remote operator and the login limiter
// bucket every attempt from every source into one shared counter.
//
// Loopback is not an external proxy being trusted: the admin API listens
// on 127.0.0.1 and the documented way to reach the UI is an Arenet route,
// so the caller IS Arenet's own embedded Caddy. The configured list adds
// to loopback rather than replacing it.
func TestNewIPExtractor_EmptyTrustsLoopbackOnly(t *testing.T) {
	for _, in := range []string{"", "   ", " , ,, "} {
		e, err := NewIPExtractor(in)
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", in, err)
		}
		got := e.TrustedCIDRs()
		want := []string{"127.0.0.0/8", "::1/128"}
		if len(got) != len(want) {
			t.Errorf("input %q: got %v, want exactly loopback %v", in, got, want)
			continue
		}
		for i, w := range want {
			if got[i] != w {
				t.Errorf("input %q: CIDR[%d] = %q, want %q", in, i, got[i], w)
			}
		}
	}
}

func TestNewIPExtractor_ValidCIDRs(t *testing.T) {
	e, err := NewIPExtractor("10.0.0.0/8, 192.168.0.0/16,  2001:db8::/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := e.TrustedCIDRs()
	// Loopback first, then the configured list: the env var ADDS to the
	// always-trusted set rather than replacing it, so configuring an
	// external proxy cannot silently break the admin UI's own path.
	want := []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"}
	if len(got) != len(want) {
		t.Fatalf("want %d CIDRs, got %d", len(want), len(got))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("CIDR[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

func TestNewIPExtractor_MalformedCIDRFails(t *testing.T) {
	tests := []string{
		"10.0.0.0/33",
		"10.0.0.0", // bare IP without /32 — spec §8.2 says rejected
		"not-an-ip",
		"10.0.0.0/8,bogus",
	}
	for _, in := range tests {
		t.Run(in, func(t *testing.T) {
			_, err := NewIPExtractor(in)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", in)
			}
		})
	}
}

// TestIPExtractor_ClientIP_SpecWorkedExamples replays the 6 worked
// examples from spec §8.3 verbatim. Assumes ARENET_TRUSTED_PROXIES=10.0.0.0/8.
func TestIPExtractor_ClientIP_SpecWorkedExamples(t *testing.T) {
	e, err := NewIPExtractor("10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string // empty string = header absent
		want       string
	}{
		{
			name:       "RemoteAddr not trusted, any XFF ignored",
			remoteAddr: "203.0.113.5:12345",
			xff:        "10.0.0.99",
			want:       "203.0.113.5",
		},
		{
			name:       "RemoteAddr trusted, XFF used",
			remoteAddr: "10.0.0.1:12345",
			xff:        "198.51.100.42",
			want:       "198.51.100.42",
		},
		{
			name:       "RemoteAddr trusted, leftmost of XFF chain",
			remoteAddr: "10.0.0.1:12345",
			xff:        "198.51.100.42, 10.0.0.7",
			want:       "198.51.100.42",
		},
		{
			name:       "RemoteAddr trusted, XFF malformed → fallback",
			remoteAddr: "10.0.0.1:12345",
			xff:        "not-an-ip",
			want:       "10.0.0.1",
		},
		{
			name:       "RemoteAddr trusted, no XFF → fallback",
			remoteAddr: "10.0.0.1:12345",
			xff:        "",
			want:       "10.0.0.1",
		},
		{
			name:       "Forge attempt: RemoteAddr public, XFF forged",
			remoteAddr: "203.0.113.5:12345",
			xff:        "forged-attacker-input",
			want:       "203.0.113.5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := e.ClientIP(r); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIPExtractor_ClientIP_EdgeCases covers spec §8.4: IPv6, brackets,
// loopback not auto-trusted, empty XFF token, trailing whitespace.
func TestIPExtractor_ClientIP_EdgeCases(t *testing.T) {
	t.Run("IPv6 trusted proxy honors XFF", func(t *testing.T) {
		e, err := NewIPExtractor("2001:db8::/32")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "[2001:db8::1]:12345"
		r.Header.Set("X-Forwarded-For", "198.51.100.42")
		if got := e.ClientIP(r); got != "198.51.100.42" {
			t.Errorf("got %q, want 198.51.100.42", got)
		}
	})

	t.Run("IPv6 in XFF with brackets stripped", func(t *testing.T) {
		e, err := NewIPExtractor("10.0.0.0/8")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		r.Header.Set("X-Forwarded-For", "[2001:db8::42]")
		if got := e.ClientIP(r); got != "2001:db8::42" {
			t.Errorf("got %q, want 2001:db8::42", got)
		}
	})

	// v2.56.2 — reversed. THE case: the admin UI reached through an Arenet
	// route arrives from the embedded Caddy over loopback, carrying the
	// real client in X-Forwarded-For. Ignoring it recorded the loopback in
	// every audit row and collapsed the login limiter to one bucket.
	t.Run("loopback IS trusted with no configuration", func(t *testing.T) {
		e, err := NewIPExtractor("")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("X-Forwarded-For", "203.0.113.5")
		if got := e.ClientIP(r); got != "203.0.113.5" {
			t.Errorf("got %q; the real client behind the embedded Caddy must be recorded", got)
		}
	})

	// And the other half, which is what keeps this safe: a caller that is
	// NOT loopback and not configured cannot claim to be someone else.
	t.Run("an external caller cannot spoof X-Forwarded-For", func(t *testing.T) {
		e, err := NewIPExtractor("")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		for _, caller := range []string{"203.0.113.9:4000", "10.1.2.3:4000", "[2001:db8::99]:4000"} {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = caller
			r.Header.Set("X-Forwarded-For", "198.51.100.7")
			got := e.ClientIP(r)
			if got == "198.51.100.7" {
				t.Errorf("caller %s spoofed its IP through X-Forwarded-For", caller)
			}
		}
	})

	t.Run("loopback trusted when explicitly configured", func(t *testing.T) {
		e, err := NewIPExtractor("127.0.0.1/32, ::1/128")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("X-Forwarded-For", "203.0.113.5")
		if got := e.ClientIP(r); got != "203.0.113.5" {
			t.Errorf("explicit loopback CIDR: got %q, want 203.0.113.5", got)
		}
	})

	t.Run("empty leftmost token falls back to RemoteAddr", func(t *testing.T) {
		e, err := NewIPExtractor("10.0.0.0/8")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		r.Header.Set("X-Forwarded-For", ", 198.51.100.42")
		if got := e.ClientIP(r); got != "10.0.0.1" {
			t.Errorf("empty leftmost: got %q, want 10.0.0.1", got)
		}
	})

	t.Run("trailing whitespace in XFF tokens", func(t *testing.T) {
		e, err := NewIPExtractor("10.0.0.0/8")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.1:12345"
		r.Header.Set("X-Forwarded-For", "  198.51.100.42  , 198.51.100.43")
		if got := e.ClientIP(r); got != "198.51.100.42" {
			t.Errorf("trailing ws: got %q, want 198.51.100.42", got)
		}
	})

	t.Run("RemoteAddr without port uses raw value", func(t *testing.T) {
		e, err := NewIPExtractor("10.0.0.0/8")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.1" // no port (unusual but possible)
		r.Header.Set("X-Forwarded-For", "198.51.100.42")
		if got := e.ClientIP(r); got != "198.51.100.42" {
			t.Errorf("portless trusted: got %q, want 198.51.100.42", got)
		}
	})

	t.Run("RemoteAddr unparseable returns empty", func(t *testing.T) {
		e, err := NewIPExtractor("10.0.0.0/8")
		if err != nil {
			t.Fatalf("NewIPExtractor: %v", err)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "not-an-ip-at-all"
		if got := e.ClientIP(r); got != "" {
			t.Errorf("unparseable: got %q, want empty", got)
		}
	})
}

// TestIPExtractor_Security_XFFIgnoredWhenUntrusted is one of the three
// security-critical sub-tests called out in plan §4.2:
// "X-Forwarded-For is ignored when r.RemoteAddr is not in a trusted CIDR".
// A direct attacker setting XFF to a loopback or internal IP MUST NOT
// have that value reflected as the client IP.
func TestIPExtractor_Security_XFFIgnoredWhenUntrusted(t *testing.T) {
	e, err := NewIPExtractor("10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}

	// Attacker from the public internet sets XFF to a forged source.
	forgedValues := []string{
		"127.0.0.1",
		"10.0.0.1", // even a trusted-range IP
		"::1",
		"198.51.100.99",
		"forged-text",
	}
	for _, forged := range forgedValues {
		t.Run(forged, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "203.0.113.5:12345" // direct public client, NOT trusted
			r.Header.Set("X-Forwarded-For", forged)
			if got := e.ClientIP(r); got != "203.0.113.5" {
				t.Errorf("forged XFF %q honored: got %q, want 203.0.113.5", forged, got)
			}
		})
	}
}

// TestIPExtractMiddleware_PopulatesContext verifies the middleware
// wrapper places the resolved IP into the request context under the
// ClientIPKey, accessible via ClientIPFromContext.
func TestIPExtractMiddleware_PopulatesContext(t *testing.T) {
	e, err := NewIPExtractor("10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}

	var seenIP string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenIP = ClientIPFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw := IPExtractMiddleware(e)
	handler := mw(inner)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:12345"
	r.Header.Set("X-Forwarded-For", "198.51.100.42")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)

	if seenIP != "198.51.100.42" {
		t.Errorf("ctx ClientIP: got %q, want 198.51.100.42", seenIP)
	}
}

func TestIPExtractMiddleware_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic, got none")
		}
	}()
	_ = IPExtractMiddleware(nil)
}
