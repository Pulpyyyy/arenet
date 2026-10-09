// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package auth

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestNewSourceAllowlist_DefaultWhenEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		al, err := NewSourceAllowlist(in)
		if err != nil {
			t.Fatalf("NewSourceAllowlist(%q): %v", in, err)
		}
		if !al.Defaulted() {
			t.Errorf("NewSourceAllowlist(%q).Defaulted() = false; want true", in)
		}
	}

	al, _ := NewSourceAllowlist("")
	// Loopback (SSH tunnel, in-container probe), LAN, Docker bridge
	// gateway, Tailscale, IPv6 ULA and link-local, IPv4-mapped IPv6.
	allowed := []string{
		"127.0.0.1", "::1",
		"192.168.1.5", "10.1.2.3",
		"172.18.0.1",
		"100.100.1.1",
		"fd00::1",
		"fe80::1",
		"::ffff:192.168.1.5",
	}
	for _, ip := range allowed {
		if !al.Allows(ip) {
			t.Errorf("default allowlist refuses %s; want allowed", ip)
		}
	}
	// 172.32.0.1 sits just outside 172.16.0.0/12.
	refused := []string{
		"8.8.8.8", "203.0.113.9", "2001:db8::1",
		"172.32.0.1",
		"", "not-an-ip",
	}
	for _, ip := range refused {
		if al.Allows(ip) {
			t.Errorf("default allowlist allows %q; want refused", ip)
		}
	}
}

func TestNewSourceAllowlist_Custom(t *testing.T) {
	al, err := NewSourceAllowlist(" 192.168.1.50 , 10.0.0.0/8,fd00::5")
	if err != nil {
		t.Fatalf("NewSourceAllowlist: %v", err)
	}
	if al.Defaulted() {
		t.Error("Defaulted() = true for an explicit list")
	}
	want := []string{"192.168.1.50/32", "10.0.0.0/8", "fd00::5/128"}
	if got := al.CIDRs(); !slices.Equal(got, want) {
		t.Errorf("CIDRs() = %v; want %v", got, want)
	}
	for _, ip := range []string{"192.168.1.50", "10.9.9.9", "fd00::5"} {
		if !al.Allows(ip) {
			t.Errorf("Allows(%s) = false; want true", ip)
		}
	}
	// An explicit list replaces the defaults, loopback included.
	for _, ip := range []string{"192.168.1.51", "127.0.0.1", "fd00::6"} {
		if al.Allows(ip) {
			t.Errorf("Allows(%s) = true; want false", ip)
		}
	}
}

func TestNewSourceAllowlist_OpenToAll(t *testing.T) {
	al, err := NewSourceAllowlist("0.0.0.0/0,::/0")
	if err != nil {
		t.Fatalf("NewSourceAllowlist: %v", err)
	}
	for _, ip := range []string{"8.8.8.8", "2001:db8::1"} {
		if !al.Allows(ip) {
			t.Errorf("Allows(%s) = false; want true", ip)
		}
	}
}

func TestNewSourceAllowlist_Invalid(t *testing.T) {
	for _, in := range []string{"192.168.1.0/33", "nope", "10.0.0.0/8,bad", ",,,"} {
		if _, err := NewSourceAllowlist(in); err == nil {
			t.Errorf("NewSourceAllowlist(%q) = nil error; want error", in)
		}
	}
}

func TestSourceAllowlistMiddleware(t *testing.T) {
	extractor, err := NewIPExtractor("")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}
	al, err := NewSourceAllowlist("192.168.1.0/24")
	if err != nil {
		t.Fatalf("NewSourceAllowlist: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Same order as the admin router: extractor first, then allowlist.
	handler := IPExtractMiddleware(extractor)(
		SourceAllowlistMiddleware(al, logger, "/healthz")(ok),
	)

	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		path       string
		want       int
	}{
		{"LAN client allowed", "192.168.1.10:5555", "", "/api/v1/routes", http.StatusOK},
		{"outside client refused", "203.0.113.9:5555", "", "/api/v1/routes", http.StatusForbidden},
		{"SPA refused too", "203.0.113.9:5555", "", "/", http.StatusForbidden},
		{"healthz exempt", "203.0.113.9:5555", "", "/healthz", http.StatusOK},
		// Through an Arenet route: Caddy connects over loopback (always a
		// trusted proxy) and sets X-Forwarded-For to the real client.
		{"routed LAN client allowed", "127.0.0.1:5555", "192.168.1.10", "/", http.StatusOK},
		{"routed outside client refused", "127.0.0.1:5555", "203.0.113.9", "/", http.StatusForbidden},
		// An untrusted caller cannot pick its IP via X-Forwarded-For.
		{"spoofed XFF ignored", "203.0.113.9:5555", "192.168.1.10", "/", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, c.path, nil)
			req.RemoteAddr = c.remoteAddr
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("status = %d; want %d", rec.Code, c.want)
			}
		})
	}
}
