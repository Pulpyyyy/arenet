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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// SSO sign-in comes back to the page asked for. Pins:
//   - safeNextPath accepts what safe-next.ts accepts, refuses the rest
//   - GET /auth/oidc/login keeps a safe ?next= in arenet_oidc_next,
//     never in the IdP URL, and clears a stale cookie otherwise
//   - the callback lands on the stored path, re-validates it (a
//     tampered cookie lands on /routes), and errors still go to /login

func TestSafeNextPath(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain path", "/certs", "/certs"},
		{"path with query and hash", "/certs?tab=acme#top", "/certs?tab=acme#top"},
		{"root", "/", "/"},
		{"nested path", "/routes/42/edit", "/routes/42/edit"},
		{"empty", "", defaultLandingPath},
		{"relative", "certs", defaultLandingPath},
		{"absolute URL", "https://evil.example/", defaultLandingPath},
		{"protocol-relative", "//evil.example", defaultLandingPath},
		{"backslash host", `/\evil.example`, defaultLandingPath},
		{"backslash later", `/certs\x`, defaultLandingPath},
		{"tab", "/\t/evil.example", defaultLandingPath},
		{"newline", "/certs\n", defaultLandingPath},
		{"DEL", "/certs\x7f", defaultLandingPath},
		{"login", "/login", defaultLandingPath},
		{"login trailing slash", "/login/", defaultLandingPath},
		{"login with query", "/login?next=/certs", defaultLandingPath},
		{"setup", "/setup", defaultLandingPath},
		{"setup with hash", "/setup#x", defaultLandingPath},
		{"login prefix is another page", "/login-history", "/login-history"},
		{"too long", "/" + strings.Repeat("a", nextMaxLen), defaultLandingPath},
		{"longest accepted", "/" + strings.Repeat("a", nextMaxLen-1), "/" + strings.Repeat("a", nextMaxLen-1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeNextPath(tc.raw); got != tc.want {
				t.Errorf("safeNextPath(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// startLogin issues GET /api/v1/auth/oidc/login with the given raw
// query (may be empty) and optional request cookies.
func startLogin(t *testing.T, c *callbackEnv, rawQuery string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	target := "/api/v1/auth/oidc/login"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("login start: status = %d, want 302; body=%s", rec.Code, rec.Body)
	}
	return rec
}

// responseCookie returns the Set-Cookie named name, nil if absent.
func responseCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

func encodeNext(p string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(p))
}

func withNextCookie(v string) fireOpt {
	return func(o *fireOpts) { o.nextCookie = v }
}

func TestOIDCLogin_StoresSafeNext(t *testing.T) {
	c := newCallbackEnv(t)
	rec := startLogin(t, c, "next="+url.QueryEscape("/certs?tab=acme"))

	ck := responseCookie(rec, oidcNextCookie)
	if ck == nil {
		t.Fatal("arenet_oidc_next not set for a safe ?next=")
	}
	if ck.Value != encodeNext("/certs?tab=acme") {
		t.Errorf("arenet_oidc_next = %q, want base64url of /certs?tab=acme", ck.Value)
	}
	if !ck.HttpOnly || ck.Path != "/" {
		t.Errorf("arenet_oidc_next: HttpOnly=%t Path=%q, want the flow-cookie shape", ck.HttpOnly, ck.Path)
	}
	// Kept on our side only: the IdP never sees the landing page.
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "certs") {
		t.Errorf("?next= leaked into the IdP redirect: %q", loc)
	}
}

func TestOIDCLogin_IgnoresUnsafeNext(t *testing.T) {
	for _, next := range []string{"//evil.example", "https://evil.example/", `/\evil.example`, "/login", ""} {
		t.Run(next, func(t *testing.T) {
			c := newCallbackEnv(t)
			rec := startLogin(t, c, "next="+url.QueryEscape(next))
			if ck := responseCookie(rec, oidcNextCookie); ck != nil {
				t.Errorf("arenet_oidc_next set for ?next=%q: %+v", next, ck)
			}
		})
	}
}

// A cookie left by an abandoned attempt must not steer a later sign-in
// that asked for no page.
func TestOIDCLogin_ClearsStaleNext(t *testing.T) {
	c := newCallbackEnv(t)
	rec := startLogin(t, c, "", &http.Cookie{Name: oidcNextCookie, Value: encodeNext("/certs")})
	ck := responseCookie(rec, oidcNextCookie)
	if ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("stale arenet_oidc_next not cleared: %+v", ck)
	}
}

func TestOIDCCallback_LandsOnStoredNext(t *testing.T) {
	c := newCallbackEnv(t)
	rec := c.fire(t, c.stdClaims(), withNextCookie(encodeNext("/certs?tab=acme")))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "/certs?tab=acme" {
		t.Errorf("Location = %q, want /certs?tab=acme", loc)
	}
	if !hasSession(rec) {
		t.Error("expected a session cookie")
	}
	if ck := responseCookie(rec, oidcNextCookie); ck == nil || ck.MaxAge >= 0 {
		t.Errorf("arenet_oidc_next not cleared after use: %+v", ck)
	}
}

// The cookie comes back from the browser, so it is validated again: a
// tampered value still signs in, but lands on /routes.
func TestOIDCCallback_TamperedNextLandsOnRoutes(t *testing.T) {
	cases := map[string]string{
		"protocol-relative": encodeNext("//evil.example"),
		"absolute URL":      encodeNext("https://evil.example/"),
		"backslash":         encodeNext(`/\evil.example`),
		"control char":      encodeNext("/\t/evil.example"),
		"entry page":        encodeNext("/login"),
		"not base64":        "%%%not-base64%%%",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			c := newCallbackEnv(t)
			rec := c.fire(t, c.stdClaims(), withNextCookie(value))
			if loc := rec.Header().Get("Location"); loc != defaultLandingPath {
				t.Errorf("Location = %q, want %s", loc, defaultLandingPath)
			}
			if !hasSession(rec) {
				t.Error("expected a session cookie: only the landing page falls back")
			}
		})
	}
}

func TestOIDCCallback_NoNextLandsOnRoutes(t *testing.T) {
	c := newCallbackEnv(t)
	rec := c.fire(t, c.stdClaims())
	if loc := rec.Header().Get("Location"); loc != defaultLandingPath {
		t.Errorf("Location = %q, want %s", loc, defaultLandingPath)
	}
}

// A failed sign-in keeps its /login?error= redirect: the stored page
// is only for a successful one.
func TestOIDCCallback_FailureIgnoresNext(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["nonce"] = "wrong-nonce-from-attacker"
	rec := c.fire(t, claims, withNextCookie(encodeNext("/certs")))
	assertNotAuthed(t, rec, "nonce_mismatch_with_next")
	if loc := rec.Header().Get("Location"); loc != "/login?error=invalid_state" {
		t.Errorf("Location = %q, want /login?error=invalid_state", loc)
	}
}

// Start then callback with the cookies the start handed out: the page
// asked for at the start is where the callback lands.
func TestOIDCNext_RoundTrip(t *testing.T) {
	c := newCallbackEnv(t)
	start := startLogin(t, c, "next="+url.QueryEscape("/certs"))
	state := responseCookie(start, oidcStateCookie)
	nonce := responseCookie(start, oidcNonceCookie)
	next := responseCookie(start, oidcNextCookie)
	if state == nil || nonce == nil || next == nil {
		t.Fatalf("login start cookies: state=%v nonce=%v next=%v", state, nonce, next)
	}
	c.state = state.Value
	c.nonce = nonce.Value

	rec := c.fire(t, c.stdClaims(), withNextCookie(next.Value))
	if loc := rec.Header().Get("Location"); loc != "/certs" {
		t.Errorf("Location = %q, want /certs", loc)
	}
	if !hasSession(rec) {
		t.Error("expected a session cookie")
	}
}
