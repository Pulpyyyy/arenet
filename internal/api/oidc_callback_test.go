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
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.2 callback pipeline tests — the highest-risk handler in
// K.2 (external input → admin session). The fake IdP below runs
// inside the test process: discovery + JWKS + token endpoint,
// driven by a per-test claims/signer struct so each branch is
// exercisable in isolation.
//
// SCOPE — exercise oidcCallback END-TO-END:
//
//  Happy path (steady-state Sub match + bootstrap Email match +
//  canonicalisation patch).
//
//  Adversarial branches:
//   - state cookie missing
//   - state cookie / query mismatch (CSRF)
//   - nonce mismatch (replay)
//   - audience mismatch (token issued for a different client)
//   - issuer mismatch (token forged by a different IdP)
//   - signature invalid (signed by a different key)
//   - token expired
//   - allowlist miss (Sub not on the list, Email not on the list)
//   - unverified email cannot satisfy bootstrap pass (Δ7)
//
// These tests are pinned anti-regression: an auth bypass on K.2
// is the worst class of bug we can ship, and the smoke against
// a real IdP only covers the happy path.

// fakeIdP is a httptest.Server that speaks just enough OIDC for
// the go-oidc/v3 verifier + oauth2 Exchange to complete. The
// next signed token is set per test via setNextToken; the next
// signer can be overridden via setSigner (used for the
// bad-signature case).
type fakeIdP struct {
	srv       *httptest.Server
	mu        sync.Mutex
	signer    jose.Signer
	signerKey *rsa.PrivateKey
	jwks      jose.JSONWebKeySet
	nextToken string // raw id_token to return on the next /token call
	clientID  string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-kid-1"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{Key: priv.Public(), Use: "sig", Algorithm: "RS256", KeyID: "test-kid-1"},
		},
	}
	f := &fakeIdP{
		signer:    signer,
		signerKey: priv,
		jwks:      jwks,
	}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.jwks)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		tok := f.nextToken
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"id_token":     tok,
			"expires_in":   3600,
		})
	})
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) setNextToken(t *testing.T, claims map[string]any) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, err := jsonMarshalDeterministic(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signed, err := f.signer.Sign(raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialise: %v", err)
	}
	f.nextToken = compact
}

// signWithOtherKey forges a JWT signed by a key OUTSIDE the JWKS.
// Used by the bad-signature test — the verifier must reject this.
func (f *fakeIdP) signWithOtherKey(t *testing.T, claims map[string]any) string {
	t.Helper()
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("other rsa key: %v", err)
	}
	other, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: otherPriv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-kid-1"),
	)
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}
	raw, err := jsonMarshalDeterministic(claims)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := other.Sign(raw)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	c, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("serialise: %v", err)
	}
	return c
}

func jsonMarshalDeterministic(m map[string]any) ([]byte, error) {
	return json.Marshal(m)
}

// callbackEnv bundles per-test scaffolding: testEnv + fakeIdP +
// the state/nonce values seeded into request cookies.
type callbackEnv struct {
	env   *testEnv
	idp   *fakeIdP
	state string
	nonce string
}

func newCallbackEnv(t *testing.T) *callbackEnv {
	t.Helper()
	env := newTestEnv(t, false)
	idp := newFakeIdP(t)

	// Seed an OIDC config + allowlist on the test env.
	if err := env.store.PutOIDCConfig(context.Background(), storage.OIDCConfig{
		Enabled:      true,
		IssuerURL:    idp.srv.URL,
		ClientID:     "arenet-test",
		ClientSecret: "test-secret-1234567890",
		RedirectURL:  "http://localhost:8080/api/v1/auth/oidc/callback",
		Scopes:       []string{"openid", "profile", "email"},
		AllowedIdentities: []storage.OIDCAllowedIdentity{
			{Email: "alice@example.com", DisplayName: "Alice"},                      // pending bootstrap
			{Email: "bob@example.com", DisplayName: "Bob", Sub: "sub-bob-existing"}, // already canonicalised
		},
	}); err != nil {
		t.Fatalf("seed oidc config: %v", err)
	}
	idp.clientID = "arenet-test"
	return &callbackEnv{
		env:   env,
		idp:   idp,
		state: "test-state-token-32-bytes-padding-aa",
		nonce: "test-nonce-token-32-bytes-padding-bb",
	}
}

// fire mints the token with the given claims, then issues a
// GET /api/v1/auth/oidc/callback?state=...&code=... with the
// matching state + nonce cookies attached. Returns the recorder
// for inspection.
func (c *callbackEnv) fire(t *testing.T, claims map[string]any, opts ...fireOpt) *httptest.ResponseRecorder {
	t.Helper()
	fo := fireDefaults(c)
	for _, opt := range opts {
		opt(&fo)
	}
	if fo.token == "" {
		c.idp.setNextToken(t, claims)
	} else {
		c.idp.mu.Lock()
		c.idp.nextToken = fo.token
		c.idp.mu.Unlock()
	}
	url := fmt.Sprintf("/api/v1/auth/oidc/callback?state=%s&code=test-auth-code", fo.queryState)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if fo.attachStateCookie {
		req.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: fo.cookieState})
	}
	if fo.attachNonceCookie {
		req.AddCookie(&http.Cookie{Name: oidcNonceCookie, Value: fo.cookieNonce})
	}
	if fo.nextCookie != "" {
		req.AddCookie(&http.Cookie{Name: oidcNextCookie, Value: fo.nextCookie})
	}
	rec := httptest.NewRecorder()
	c.env.router.ServeHTTP(rec, req)
	return rec
}

type fireOpts struct {
	queryState        string
	cookieState       string
	cookieNonce       string
	attachStateCookie bool
	attachNonceCookie bool
	token             string // when set, used verbatim (bypasses claim-signing)
	nextCookie        string // when set, sent as the arenet_oidc_next cookie
}

func fireDefaults(c *callbackEnv) fireOpts {
	return fireOpts{
		queryState:        c.state,
		cookieState:       c.state,
		cookieNonce:       c.nonce,
		attachStateCookie: true,
		attachNonceCookie: true,
	}
}

type fireOpt func(*fireOpts)

func withoutStateCookie() fireOpt {
	return func(o *fireOpts) { o.attachStateCookie = false }
}
func withMismatchedState() fireOpt {
	return func(o *fireOpts) { o.queryState = "different-state-token-aaaaaaaaaaaa" }
}
func withRawToken(tok string) fireOpt {
	return func(o *fireOpts) { o.token = tok }
}

// stdClaims builds a base claims map with iss/aud/exp/iat/nonce
// matching the test env. Tests mutate the fields they want to
// pervert.
func (c *callbackEnv) stdClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            c.idp.srv.URL,
		"aud":            "arenet-test",
		"sub":            "sub-alice-canonical",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Unix(),
		"nonce":          c.nonce,
		"email":          "alice@example.com",
		"email_verified": true,
		"name":           "Alice",
	}
}

// hasSession asserts that the recorder carries the arenet
// session cookie (the canonical "user is signed in" signal).
func hasSession(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

// -------------------- HAPPY PATH --------------------

// TestOIDCCallback_HappyPath_BootstrapMatch_CreatesSession exercises
// the canonicalisation pipeline end-to-end : bootstrap (Email-pass)
// match on a pending invite, Sub stamped onto the allowlist entry,
// CreateOIDCUser, session cookie issued, 302 to /routes.
func TestOIDCCallback_HappyPath_BootstrapMatch_CreatesSession(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	// Email-pass entry "alice@example.com" with Sub="" → bootstrap.

	rec := c.fire(t, claims)

	if rec.Code != http.StatusFound {
		t.Fatalf("happy path expected 302, got %d body=%s", rec.Code, rec.Body)
	}
	if loc := rec.Header().Get("Location"); loc != "/routes" {
		t.Errorf("expected redirect to /routes, got %q", loc)
	}
	if !hasSession(rec) {
		t.Error("expected arenet session cookie on happy path")
	}

	// Canonicalisation patch was persisted.
	updated, err := c.env.store.GetOIDCConfig(context.Background())
	if err != nil {
		t.Fatalf("read post-callback config: %v", err)
	}
	var found bool
	for _, e := range updated.AllowedIdentities {
		if e.Email == "alice@example.com" && e.Sub == "sub-alice-canonical" {
			found = true
			if e.FirstLoginAt.IsZero() {
				t.Error("FirstLoginAt not set on canonicalisation")
			}
		}
	}
	if !found {
		t.Errorf("allowlist entry not canonicalised: %+v", updated.AllowedIdentities)
	}

	// Audit: login_success with auth_method=oidc.
	var sawOIDCLogin bool
	for _, e := range c.env.audit.Events() {
		if e.Action == audit.ActionLoginSuccess && strings.Contains(e.Message, "auth_method=oidc") {
			sawOIDCLogin = true
		}
	}
	if !sawOIDCLogin {
		t.Error("login_success with auth_method=oidc not audited")
	}
}

// TestOIDCCallback_HappyPath_SubMatch_NoBootstrap exercises the
// steady-state path : Sub already canonicalised on the allowlist,
// so the Email pass is not consulted at all.
func TestOIDCCallback_HappyPath_SubMatch_NoBootstrap(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["sub"] = "sub-bob-existing" // pre-canonicalised in newCallbackEnv
	claims["email"] = "bob@example.com"
	claims["email_verified"] = true
	claims["name"] = "Bob"

	rec := c.fire(t, claims)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/routes" {
		t.Fatalf("expected 302 to /routes, got %d %q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	if !hasSession(rec) {
		t.Error("expected session cookie on steady-state Sub match")
	}
}

// -------------------- ADVERSARIAL BRANCHES --------------------

// helper for the bypass-regression assertion : a rejected callback
// MUST NOT issue a session cookie AND MUST NOT redirect to /routes.
func assertNotAuthed(t *testing.T, rec *httptest.ResponseRecorder, label string) {
	t.Helper()
	if hasSession(rec) {
		t.Fatalf("AUTH BYPASS REGRESSION [%s]: session cookie issued on a rejected callback", label)
	}
	if loc := rec.Header().Get("Location"); loc == "/routes" {
		t.Fatalf("AUTH BYPASS REGRESSION [%s]: redirected to /routes on a rejected callback", label)
	}
}

func TestOIDCCallback_StateCookieMissing_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	rec := c.fire(t, c.stdClaims(), withoutStateCookie())
	assertNotAuthed(t, rec, "state_cookie_missing")
	// Should redirect to /login?error=invalid_state.
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "/login") {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "state_cookie_missing")
}

func TestOIDCCallback_StateMismatch_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	rec := c.fire(t, c.stdClaims(), withMismatchedState())
	assertNotAuthed(t, rec, "state_mismatch")
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "state_mismatch")
}

func TestOIDCCallback_NonceMismatch_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["nonce"] = "wrong-nonce-from-attacker" // ID token claims a different nonce
	rec := c.fire(t, claims)
	assertNotAuthed(t, rec, "nonce_mismatch")
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "nonce_mismatch")
}

func TestOIDCCallback_AudienceMismatch_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["aud"] = "some-other-client-id" // token issued for a different RP
	rec := c.fire(t, claims)
	assertNotAuthed(t, rec, "aud_mismatch")
	// Verifier rejects in id_token_invalid branch.
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "id_token_invalid")
}

func TestOIDCCallback_IssuerMismatch_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["iss"] = "https://evil.example.com" // forged by a different IdP
	rec := c.fire(t, claims)
	assertNotAuthed(t, rec, "iss_mismatch")
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "id_token_invalid")
}

func TestOIDCCallback_BadSignature_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	// Token signed by a key NOT in the IdP's JWKS — kid matches,
	// but the signature won't verify.
	tok := c.idp.signWithOtherKey(t, c.stdClaims())
	rec := c.fire(t, nil, withRawToken(tok))
	assertNotAuthed(t, rec, "bad_signature")
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "id_token_invalid")
}

func TestOIDCCallback_ExpiredToken_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["exp"] = time.Now().Add(-time.Hour).Unix() // expired an hour ago
	claims["iat"] = time.Now().Add(-2 * time.Hour).Unix()
	rec := c.fire(t, claims)
	assertNotAuthed(t, rec, "expired")
	expectAuditAction(t, c, audit.ActionOIDCCallbackInvalid, "id_token_invalid")
}

// TestOIDCCallback_AllowlistMiss_Rejected: signature OK, audience
// OK, nonce OK — but the Sub isn't on the list AND no pending
// Email entry matches. Most realistic post-deploy mistake.
func TestOIDCCallback_AllowlistMiss_Rejected(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["sub"] = "sub-not-on-list-12345"
	claims["email"] = "stranger@elsewhere.com"
	rec := c.fire(t, claims)
	assertNotAuthed(t, rec, "allowlist_miss")
	expectAuditAction(t, c, audit.ActionOIDCLoginRejected, "")
}

// TestOIDCCallback_EmailUnverified_BootstrapRefused exercises the
// Δ7 guard at the FULL pipeline level (not just the matcher unit
// test). An attacker controls a freshly-created IdP account that
// claims alice@example.com but with email_verified=false.
//
// The OIDC verifier accepts the token (signature + aud + iss +
// nonce all valid — the IdP signed it). The pipeline MUST stop
// AFTER verify, at the allowlist match, because matchAllowlist
// refuses the Email-pass without email_verified.
func TestOIDCCallback_EmailUnverified_BootstrapRefused(t *testing.T) {
	c := newCallbackEnv(t)
	claims := c.stdClaims()
	claims["sub"] = "sub-attacker-99"
	claims["email"] = "alice@example.com" // same email as the pending invite
	claims["email_verified"] = false      // ← the lie
	rec := c.fire(t, claims)
	assertNotAuthed(t, rec, "email_unverified_attacker")
	expectAuditAction(t, c, audit.ActionOIDCLoginRejected, "")
	// The pending Alice entry MUST still be pending — the attacker's
	// Sub MUST NOT have been written.
	cfg, _ := c.env.store.GetOIDCConfig(context.Background())
	for _, e := range cfg.AllowedIdentities {
		if e.Email == "alice@example.com" && e.Sub != "" {
			t.Fatalf("Δ7 REGRESSION: pending Alice entry was canonicalised by an unverified-email attacker (Sub=%q)", e.Sub)
		}
	}
}

func expectAuditAction(t *testing.T, c *callbackEnv, action string, msgSubstring string) {
	t.Helper()
	for _, e := range c.env.audit.Events() {
		if e.Action == action {
			if msgSubstring == "" || strings.Contains(e.Message, msgSubstring) {
				return
			}
		}
	}
	t.Errorf("expected audit action %q (msg contains %q); got events: %+v",
		action, msgSubstring, c.env.audit.Events())
}
