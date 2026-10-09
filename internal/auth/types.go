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

// Package auth manages admin users, sessions, and the authentication
// primitives used by the API middleware (Chunk 2). Step D Phase 1 has
// a single-admin model; multi-user and SSO are deferred to Step D2/D3.
package auth

import "time"

// SECURITY: User is the internal storage shape and MUST NOT be exposed
// directly via HTTP. It contains PasswordHash and other fields that
// should never reach the wire. The API layer (Chunk 4) builds a
// separate wire shape that omits sensitive fields.
//
// User represents a single admin account.
//
// Phase 1: exactly one row. The setup flow creates it; the first login
// records LastLoginAt. Phase 2 will allow multiple rows with admin/editor
// roles (see docs/roadmap.md).
type User struct {
	ID                  string    `json:"id"`                // UUID v4
	Username            string    `json:"username"`          // lowercase, 3..32
	DisplayName         string    `json:"display_name"`      // free text, ≤64
	// Email is the user's primary contact address. Required on
	// new local accounts (setup flow + future invites — Phase 1
	// of the users-page refactor) and populated best-effort from
	// the OIDC `email` claim on every login. Pre-fix rows decode
	// to "" — omitempty keeps the on-disk JSON tight for
	// legacy users. Frontend displays "—" when empty.
	Email               string    `json:"email,omitempty"`
	PasswordHash        string    `json:"password_hash"`     // argon2id PHC string — never expose via HTTP
	HIBPCheckStatus     string    `json:"hibp_check_status"` // "pending" | "clean" | "compromised" | "skipped"
	HIBPCheckedAt       time.Time `json:"hibp_checked_at,omitempty"`
	PasswordCompromised bool      `json:"password_compromised"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
	LastLoginAt         time.Time `json:"last_login_at,omitempty"`
	// ThemePreference: "dark" | "light" | "" (empty = pre-Step-F user,
	// frontend treats "" as "dark" — see spec §4.2). Step F §3.1.
	// `omitempty` keeps legacy rows decoded by older binaries identical
	// to new rows that simply never had the field set.
	ThemePreference string `json:"theme_preference,omitempty"`
	// LanguagePreference (v2.9.11 i18n Phase 1): "en" | "fr" | ""
	// (empty = pre-v2.9.11 user, frontend treats "" as "en" — the
	// hardcoded default — see i18n spec §Edge cases). Same shape as
	// ThemePreference: settable via POST /api/v1/auth/me/language,
	// refreshed cookie arenet_language for the bootstrap script in
	// app.html, mirrored in /auth/me JSON for reconcile-from-server.
	// `omitempty` keeps legacy rows byte-identical to pre-i18n
	// binaries' on-disk shape.
	LanguagePreference string `json:"language_preference,omitempty"`
	// AuthSource (Step K.2) distinguishes locally-managed users
	// from OIDC-mapped users. "local" = bootstrapped via the
	// boot-time setup token + login flow (password / argon2id
	// PHC); "oidc" = canonicalised on first OIDC login from the
	// allowlist (PasswordHash empty by construction). Mutual
	// exclusion enforced at UserStore level: an OIDC user has no
	// PasswordHash; a local user has no OIDCSub.
	AuthSource string `json:"auth_source"`
	// OIDCSub (Step K.2) is the OIDC subject claim (IdP-stable
	// identifier) of an OIDC-source user. Empty for local users.
	// Set by the OIDC callback on first canonicalisation per
	// spec §1.3 decision 13.
	OIDCSub string `json:"oidc_sub,omitempty"`
	// Role (Step K.2 — §1.3 decision 12) gates business
	// endpoints. "viewer" = read-only access to /routes,
	// /audit, /topology (GET-only). "admin" = full CRUD on
	// routes / settings / users. Migrated pre-K users default
	// to "admin" (they were admin before the role model
	// existed). Newly auto-created OIDC users default to
	// "viewer" — elevation requires an explicit operator
	// gesture via POST /api/v1/admin/users/{id}/role.
	Role string `json:"role"`
	// MustChangePassword (v2.48) forces a password change before the
	// account can be used for anything else.
	//
	// Set on every account an admin creates, because that admin
	// necessarily knows the first password — they either typed it or
	// read it off the screen once. Without this flag they would know
	// it indefinitely; with it the exposure lasts one login.
	//
	// Cleared by UpdatePassword, which is the only way out. The setup
	// flow does NOT set it: the operator who bootstraps Arenet chose
	// their own password and there is nobody else to hide it from.
	//
	// omitempty keeps pre-v2.48 rows byte-identical on disk.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// AuthSource constants (Step K.2 + Phase 4).
const (
	UserAuthSourceLocal = "local" // username + PasswordHash, Step D
	UserAuthSourceOIDC  = "oidc"  // OIDC sub mapped to this user
	// UserAuthSourceService (Phase 4) is a machine-only
	// identity. No PasswordHash, no OIDCSub. Authenticates
	// exclusively via an Authorization: Bearer header carrying
	// an APIToken (see APITokenStore). Service users are
	// EXCLUDED from the last-admin guards — only human (local
	// or OIDC) admins count, so a service-admin can never
	// lock out humans by being the last admin in the system.
	UserAuthSourceService = "service"
)

// Role constants (Step K.2 — §1.3 decision 12).
const (
	UserRoleViewer = "viewer" // read-only admin UI access
	UserRoleAdmin  = "admin"  // full CRUD on routes / settings / users
)

// HIBP status constants. Matches the enum documented in spec §3.2 and §7.
const (
	HIBPStatusPending     = "pending"
	HIBPStatusClean       = "clean"
	HIBPStatusCompromised = "compromised"
	HIBPStatusSkipped     = "skipped"
)

// Theme preference values accepted by the API per Step F spec §3.1.
// The empty string "" is NOT in this list: it's a valid storage state
// (legacy pre-Step-F rows) but cannot be written back via the API.
const (
	ThemeDark  = "dark"
	ThemeLight = "light"
)

// Language preference values accepted by the API per v2.9.11 i18n
// Phase 1 spec. Same shape as the Theme* constants: "" is a valid
// storage state (legacy pre-v2.9.11 rows that never set the field)
// but cannot be written back via the API. The frontend normalises
// "" to LanguageEnglish at reconcile time — hardcoded default for
// determinism rather than reading navigator.language.
const (
	LanguageEnglish = "en"
	LanguageFrench  = "fr"
)

// Session represents a server-side authenticated session.
//
// The ID is the opaque 256-bit token also stored in the user's
// arenet_session cookie. ExpiresAt enforces the absolute upper bound
// (24h or 30d); LastActivity enforces the 15-minute idle lock window
// (the middleware check happens in Chunk 2).
type Session struct {
	ID           string    `json:"id"` // 256-bit base64 url-safe (43 chars)
	UserID       string    `json:"user_id"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"` // sliding TTL: 24h or 30d
	LastActivity time.Time `json:"last_activity"`
	RememberMe   bool      `json:"remember_me"`
	IP           string    `json:"ip"`         // captured at issue time
	UserAgent    string    `json:"user_agent"` // captured at issue time
}

// Session TTL constants per spec §3.3 and decision Q3.
const (
	SessionTTLDefault    = 24 * time.Hour      // sliding, non-remember-me
	SessionTTLRememberMe = 30 * 24 * time.Hour // sliding, remember-me
	SessionIdleTimeout   = 15 * time.Minute    // hard-auth lock window (enforced in Chunk 2)
)

// Argon2id parameters per spec §3.2 and decision Q4.
//
// These values are exposed so the userstore and tests can reference
// them without duplicating literals. The argon2id library expects the
// values directly in its Params struct.
const (
	Argon2idMemory      = 64 * 1024 // 64 MiB, in KiB as argon2id expects
	Argon2idIterations  = 3
	Argon2idParallelism = 4
	Argon2idSaltLength  = 16
	Argon2idKeyLength   = 32
)

// Username and password validation bounds per spec §3.2 and decision D5/D6.
const (
	UsernameMinLen    = 3
	UsernameMaxLen    = 32
	DisplayNameMaxLen = 64
	PasswordMinLen    = 15
	PasswordMaxLen    = 128
)

// SessionIDByteLen is the entropy used to generate session IDs:
// 32 bytes from crypto/rand, base64 url-safe encoded without padding.
// Encoded length is 43 characters.
const SessionIDByteLen = 32
