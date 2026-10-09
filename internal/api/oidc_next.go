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
	"strings"
)

// The page an SSO sign-in comes back to. GET /auth/oidc/login takes
// it as ?next=, keeps it in the arenet_oidc_next cookie next to the
// state and nonce cookies, and the callback redirects there once the
// session is issued.
//
// ?next= is attacker-controlled (anyone can send a link to
// /api/v1/auth/oidc/login?next=https://evil.example), so it is checked
// with the rules of web/frontend/src/lib/utils/safe-next.ts on the way
// in AND again on the way out: the cookie is only as trustworthy as
// the browser that sends it back.

const (
	// oidcNextCookie carries the validated landing path from the
	// login redirect to the callback, base64url-encoded so every
	// byte is a valid cookie octet.
	oidcNextCookie = "arenet_oidc_next"

	// defaultLandingPath is where a sign-in lands without a usable
	// ?next= (DEFAULT_LANDING in safe-next.ts).
	defaultLandingPath = "/routes"

	// nextMaxLen bounds ?next= so its base64 form stays well inside
	// the 4096 bytes a browser keeps per cookie (RFC 6265 §6.1); a
	// longer value would be dropped by the browser and land on the
	// default anyway.
	nextMaxLen = 2048
)

// safeNextPath returns raw when it is a path on this origin and
// defaultLandingPath otherwise. Same rules as safeNext in
// web/frontend/src/lib/utils/safe-next.ts: it starts with exactly one
// "/" ("//host" is another host), has no backslash ("/\host" is read
// as "//host" by browsers) and no control character (the URL parser
// drops tabs and newlines, so "/\t/host" resolves as "//host"), and
// its path is not /login or /setup (trailing slashes ignored). On top
// of those, a value longer than nextMaxLen is refused. The control
// check is hasControlChar (waf_exclusions.go): a rune below 0x20 or
// DEL, the same set as the frontend's char-code scan.
func safeNextPath(raw string) string {
	if len(raw) > nextMaxLen || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return defaultLandingPath
	}
	if strings.Contains(raw, `\`) || hasControlChar(raw) {
		return defaultLandingPath
	}
	pathname := raw
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		pathname = raw[:i]
	}
	if isEntryPath(pathname) {
		return defaultLandingPath
	}
	return raw
}

// isEntryPath reports /login and /setup, the pages an anonymous
// visitor stays on ("/login/" included): landing on one after signing
// in would be a loop.
func isEntryPath(pathname string) bool {
	switch strings.TrimRight(pathname, "/") {
	case "/login", "/setup":
		return true
	}
	return false
}

// setOIDCNextCookie stores the landing path asked for by ?next= for
// the callback. A missing or unusable value clears the cookie, so a
// stale one left by an abandoned attempt cannot steer this one.
func setOIDCNextCookie(w http.ResponseWriter, r *http.Request, raw string) {
	next := safeNextPath(raw)
	if next == defaultLandingPath {
		if _, err := r.Cookie(oidcNextCookie); err == nil {
			clearOIDCFlowCookie(w, r, oidcNextCookie)
		}
		return
	}
	setOIDCFlowCookie(w, r, oidcNextCookie, base64.RawURLEncoding.EncodeToString([]byte(next)))
}

// takeOIDCNext returns the landing path stored by setOIDCNextCookie,
// validated again, and clears the cookie (single use, like the state
// cookie). defaultLandingPath when the cookie is absent, undecodable
// or unsafe.
func takeOIDCNext(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(oidcNextCookie)
	if err != nil {
		return defaultLandingPath
	}
	clearOIDCFlowCookie(w, r, oidcNextCookie)
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return defaultLandingPath
	}
	return safeNextPath(string(raw))
}
