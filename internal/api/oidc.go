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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// Step K.2 — OIDC SSO admin login.
//
// Endpoints (gated under hard-auth EXCEPT the login + callback
// pair, which are no-auth — the login flow IS the auth):
//   - GET  /api/v1/auth/oidc/login        (no-auth, initiates flow)
//   - GET  /api/v1/auth/oidc/callback     (no-auth, IdP redirect target)
//   - GET  /api/v1/settings/oidc          (hard-auth admin)
//   - PUT  /api/v1/settings/oidc          (hard-auth admin)
//   - GET  /api/v1/settings/oidc/allowlist (hard-auth admin)
//   - POST /api/v1/settings/oidc/allowlist (hard-auth admin)
//   - DELETE /api/v1/settings/oidc/allowlist/{email} (hard-auth admin)
//
// BREAK-GLASS INVARIANT (§1.3 #4, #5): NONE of these endpoints
// gate or modify the local-credential login at /api/v1/auth/login.
// The local login NEVER calls any function in this file. The OIDC
// surface is purely additive — toggling it on enables the SSO
// route, never disables the local one.

const (
	// oidcStateCookie / oidcNonceCookie carry the random per-
	// request CSRF / replay tokens between the login redirect
	// and the callback. Short TTL (5 min) — long enough for an
	// IdP login dance, short enough to limit replay.
	oidcStateCookie   = "arenet_oidc_state"
	oidcNonceCookie   = "arenet_oidc_nonce"
	oidcCookieTTL     = 5 * time.Minute
	oidcStateNonceLen = 32 // bytes; base64url-encoded on the wire
	oidcSubMaxLen     = 256
	oidcEmailMaxLen   = 320 // RFC 5321 envelope-from upper bound
)

// OIDCStore is the subset of the storage layer the OIDC handlers
// depend on, declared at consumer side (decision D4) so tests
// can inject a fake without booting bbolt.
type OIDCStore interface {
	GetOIDCConfig(ctx context.Context) (storage.OIDCConfig, error)
	PutOIDCConfig(ctx context.Context, c storage.OIDCConfig) error
	OIDCConfigEverConfigured(ctx context.Context) (bool, error)
}

// OIDCManager owns the OIDC client state — the cached discovery
// document, the verifier, the oauth2 config. Built lazily on
// first PUT of an enabled config; refreshed on subsequent PUTs.
// Safe for concurrent use.
//
// The lazy build is intentional: many homelab deploys never turn
// OIDC on, and we don't want to hold a network round-trip on
// every Arenet boot just to fetch a discovery doc the operator
// hasn't configured.
type OIDCManager struct {
	mu       sync.RWMutex
	provider *oidc.Provider // nil until first successful build
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	cfgHash  string // detects config drift across reload
}

// NewOIDCManager constructs an empty manager. The handlers call
// EnsureBuilt before reading provider/verifier/oauth.
func NewOIDCManager() *OIDCManager {
	return &OIDCManager{}
}

// EnsureBuilt rebuilds the OIDC client state from the given
// config if it has changed since the last build (or if the
// manager has never been built). Returns an error if the IdP
// discovery doc cannot be fetched OR if the config is invalid;
// in either case the manager's state is left as it was so
// previously-good config keeps working through an IdP outage.
//
// Caller responsibility: cfg.Enabled MUST be true when calling
// this. EnsureBuilt is the lazy-build path for the active OIDC
// flow; disabled configs don't reach it.
func (m *OIDCManager) EnsureBuilt(ctx context.Context, cfg storage.OIDCConfig) error {
	if !cfg.Enabled {
		return errors.New("oidc: config is disabled")
	}
	h := configHash(cfg)
	m.mu.RLock()
	if m.cfgHash == h && m.provider != nil {
		m.mu.RUnlock()
		return nil
	}
	m.mu.RUnlock()

	// Discovery doc fetch with bounded timeout — the IdP shouldn't
	// hang the admin's PUT or the user's login redirect.
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(fetchCtx, cfg.IssuerURL)
	if err != nil {
		// Embed the issuer URL into the wrapped error so any
		// caller's log line is self-describing without needing
		// a parallel slog.String("issuer_url", ...) attribute.
		// Empirically motivated by Day 17 session diagnostic
		// where 2h were spent identifying which issuer URL was
		// failing because the wrapped error didn't carry it.
		return fmt.Errorf("oidc: discovery fetch failed for %q (timeout 10s): %w", cfg.IssuerURL, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	m.mu.Lock()
	m.provider = provider
	m.verifier = verifier
	m.oauth = oc
	m.cfgHash = h
	m.mu.Unlock()
	return nil
}

func (m *OIDCManager) snapshot() (*oidc.Provider, *oidc.IDTokenVerifier, *oauth2.Config) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.provider, m.verifier, m.oauth
}

// configHash fingerprints the discovery-relevant fields of an
// OIDCConfig. Changing IssuerURL / ClientID / ClientSecret /
// Scopes / RedirectURL triggers a rebuild; changing
// AllowedIdentities does not (the allowlist is consulted at
// callback time, not at build time).
func configHash(cfg storage.OIDCConfig) string {
	return strings.Join([]string{
		cfg.IssuerURL,
		cfg.ClientID,
		cfg.ClientSecret,
		strings.Join(cfg.Scopes, ","),
		cfg.RedirectURL,
		fmt.Sprintf("%t", cfg.Enabled),
	}, "|")
}

// --- Settings: OIDC config CRUD ------------------------------------------

// oidcConfigRequest is the wire shape on PUT.
// ClientSecret is write-only with preserve-on-edit (empty → keep
// the stored value). Mirrors Step J.4 + K.1 secret discipline.
type oidcConfigRequest struct {
	Enabled      bool     `json:"enabled"`
	IssuerURL    string   `json:"issuerUrl"`
	ClientID     string   `json:"clientId"`
	ClientSecret string   `json:"clientSecret"`
	Scopes       []string `json:"scopes"`
	RedirectURL  string   `json:"redirectUrl"`
	// AcceptUnverifiedEmail relaxes the §1.6 Δ7 guard on the
    // allowlist Email-pass bootstrap (Step #S-17). False by
    // default. Set true ONLY for self-hosted, operator-
    // controlled IdPs that don't emit email_verified=true by
    // default (Authentik admin-created users being the
    // motivating case). See storage.OIDCConfig.
    // AcceptUnverifiedEmail for the threat model.
    AcceptUnverifiedEmail bool `json:"acceptUnverifiedEmail"`	
	// Kind (optional) — provider kind for UI per-IdP hints
	// (login SSO button logo). One of "authentik" / "keycloak" /
	// "authelia" / "generic". Empty is accepted (treated as
	// "generic" downstream).
	Kind string `json:"kind,omitempty"`
}

// oidcConfigResponse is the wire shape on GET. ClientSecret is
// always empty (server-side redaction); ClientSecretSet flags
// the UI to render the "••• set" placeholder.
type oidcConfigResponse struct {
	Enabled           bool                          `json:"enabled"`
	IssuerURL         string                        `json:"issuerUrl"`
	ClientID          string                        `json:"clientId"`
	ClientSecret      string                        `json:"clientSecret"`
	ClientSecretSet   bool                          `json:"clientSecretSet"`
	Scopes            []string                      `json:"scopes"`
	RedirectURL       string                        `json:"redirectUrl"`
    // Step #S-17: surface the operator's opt-in for the Δ7
    // relaxation so the Settings → OIDC GUI can render the
    // current state of the checkbox.
    AcceptUnverifiedEmail bool                      `json:"acceptUnverifiedEmail"`
	Kind              string                        `json:"kind"`
	AllowedIdentities []oidcAllowedIdentityResponse `json:"allowedIdentities"`
	Configured        bool                          `json:"configured"`
}

type oidcAllowedIdentityResponse struct {
	Email        string `json:"email"`
	DisplayName  string `json:"displayName"`
	Sub          string `json:"sub"`
	AddedAt      string `json:"addedAt"`
	FirstLoginAt string `json:"firstLoginAt,omitempty"`
}

func oidcConfigToResponse(c storage.OIDCConfig, configured bool) oidcConfigResponse {
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	identities := make([]oidcAllowedIdentityResponse, 0, len(c.AllowedIdentities))
	for _, ai := range c.AllowedIdentities {
		entry := oidcAllowedIdentityResponse{
			Email:       ai.Email,
			DisplayName: ai.DisplayName,
			Sub:         ai.Sub,
			AddedAt:     ai.AddedAt.UTC().Format(timestampFormat),
		}
		if !ai.FirstLoginAt.IsZero() {
			entry.FirstLoginAt = ai.FirstLoginAt.UTC().Format(timestampFormat)
		}
		identities = append(identities, entry)
	}
	return oidcConfigResponse{
		Enabled:           c.Enabled,
		IssuerURL:         c.IssuerURL,
		ClientID:          c.ClientID,
		ClientSecret:      "",
		ClientSecretSet:   c.ClientSecret != "",
		Scopes:            scopes,
		RedirectURL:       c.RedirectURL,
		AcceptUnverifiedEmail: c.AcceptUnverifiedEmail,
		Kind:              c.Kind,
		AllowedIdentities: identities,
		Configured:        configured,
	}
}

// oidcConfigForAudit returns a copy of c with the ClientSecret
// blanked. Mirrors routeForAudit (I.5) / dnsProviderForAudit
// (J.4) / forwardAuthProviderForAudit (K.1).
func oidcConfigForAudit(c storage.OIDCConfig) storage.OIDCConfig {
	c.ClientSecret = ""
	return c
}

func (h *Handler) getOIDCConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetOIDCConfig(r.Context())
	configured := true
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			// Fresh install — render the not-configured shape.
			writeJSON(w, http.StatusOK, oidcConfigToResponse(storage.OIDCConfig{}, false))
			return
		}
		h.logger.Error("get oidc config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get oidc config")
		return
	}
	writeJSON(w, http.StatusOK, oidcConfigToResponse(cfg, configured))
}

func (h *Handler) putOIDCConfig(w http.ResponseWriter, r *http.Request) {
	var req oidcConfigRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	previous, prevErr := h.store.GetOIDCConfig(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("get oidc config (update)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load oidc config")
		return
	}

	// Preserve-on-edit secret semantics (Step J.4 / K.1 pattern):
	// empty ClientSecret on PUT keeps the previously stored value.
	clientSecret := req.ClientSecret
	if clientSecret == "" {
		clientSecret = previous.ClientSecret
	}
	// Preserve the existing allowlist across config edits — the
	// allowlist has its own dedicated endpoints. A bare PUT on
	// the config should NOT wipe the allowlist as a side effect.
	// Auto-strip the well-known suffix if the operator pasted the
	// discovery URL by mistake. The convention (RFC 8414) is that
	// the issuer is a stable PREFIX url, and go-oidc appends
	// `/.well-known/openid-configuration` itself; pasting it twice
	// produces a 404. The UI helptext warns about this, but
	// silently fixing the common slip is the right ergonomic call.
	issuer := strings.TrimSpace(req.IssuerURL)
	issuer = strings.TrimSuffix(issuer, "/.well-known/openid-configuration")
	issuer = strings.TrimSuffix(issuer, "/.well-known/openid-configuration/")

	merged := storage.OIDCConfig{
		Enabled:           req.Enabled,
		IssuerURL:         issuer,
		ClientID:          strings.TrimSpace(req.ClientID),
		ClientSecret:      clientSecret,
		Scopes:            req.Scopes,
		RedirectURL:       strings.TrimSpace(req.RedirectURL),
		AcceptUnverifiedEmail: req.AcceptUnverifiedEmail,
		Kind:              strings.TrimSpace(req.Kind),
		AllowedIdentities: previous.AllowedIdentities,
		CreatedAt:         previous.CreatedAt,
	}

	// When Enabled is true, attempt to validate the IdP discovery
	// doc BEFORE persisting. A misconfigured IdP would otherwise
	// produce a stored row that subsequent login flows can't use;
	// fail-loud at PUT time so the operator sees the IdP error
	// immediately, not on the first login attempt.
	if merged.Enabled {
		// The storage.validate() runs inside PutOIDCConfig; we
		// rely on it for the basic shape (issuer parseable,
		// scopes non-empty, etc.). Then EnsureBuilt verifies the
		// IdP is actually reachable + the discovery doc parses.
		if err := h.oidc.EnsureBuilt(r.Context(), merged); err != nil {
			// Log server-side too — the operator-facing 400 carries
			// the message but journalctl is where the on-call
			// engineer looks first when an admin's PUT is rejected.
			h.logger.Warn("oidc: config rejected at PUT validation",
				"err", err,
				"issuer_url", merged.IssuerURL,
				"client_id", merged.ClientID,
				"timeout_seconds", 10,
			)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("oidc config rejected: %s", err.Error()))
			return
		}
	}

	if err := h.store.PutOIDCConfig(r.Context(), merged); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Audit: oidc_configured on the first write, oidc_updated on
	// subsequent writes. Both with secrets scrubbed.
	action := audit.ActionOIDCUpdated
	if errors.Is(prevErr, storage.ErrNotFound) {
		action = audit.ActionOIDCConfigured
	}
	evt := audit.Event{
		Action:     action,
		TargetType: "oidc_config",
		TargetID:   "default",
		AfterJSON:  mustMarshalForAudit(oidcConfigForAudit(merged)),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		evt.BeforeJSON = mustMarshalForAudit(oidcConfigForAudit(previous))
	}
	h.appendAudit(r, evt)

	writeJSON(w, http.StatusOK, oidcConfigToResponse(merged, true))
}

// --- Settings: OIDC allowlist CRUD ---------------------------------------

type oidcAllowlistAddRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"displayName"`
	// Sub (Spec-1, optional) — pre-fill the IdP-stable subject
	// identifier directly. When non-empty, the entry skips the
	// email-bootstrap path (no Pass 2, Δ7 guard not invoked) and
	// the first login matches via Pass 1 (steady-state by Sub).
	// Required when the operator's IdP doesn't emit
	// `email_verified=true` (e.g. Authentik admin-created
	// accounts), making the bootstrap path unreachable.
	//
	// Empty value: legacy behaviour preserved — entry created
	// with Sub="" (pending) → first login goes through the
	// email-bootstrap Pass 2 with the Δ7 email_verified guard.
	Sub string `json:"sub,omitempty"`
}

func (h *Handler) listOIDCAllowlist(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Error("get oidc config for allowlist", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load oidc config")
		return
	}
	identities := make([]oidcAllowedIdentityResponse, 0, len(cfg.AllowedIdentities))
	for _, ai := range cfg.AllowedIdentities {
		entry := oidcAllowedIdentityResponse{
			Email:       ai.Email,
			DisplayName: ai.DisplayName,
			Sub:         ai.Sub,
			AddedAt:     ai.AddedAt.UTC().Format(timestampFormat),
		}
		if !ai.FirstLoginAt.IsZero() {
			entry.FirstLoginAt = ai.FirstLoginAt.UTC().Format(timestampFormat)
		}
		identities = append(identities, entry)
	}
	writeJSON(w, http.StatusOK, identities)
}

func (h *Handler) addOIDCAllowlist(w http.ResponseWriter, r *http.Request) {
	var req oidcAllowlistAddRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		writeError(w, http.StatusBadRequest, "email must not be empty")
		return
	}
	if len(email) > oidcEmailMaxLen {
		writeError(w, http.StatusBadRequest, "email exceeds 320 characters")
		return
	}
	if !strings.Contains(email, "@") {
		writeError(w, http.StatusBadRequest, "email must contain @")
		return
	}

	// Spec-1 — optional pre-filled Sub. Empty (after trim) keeps
	// the legacy pending-bootstrap path; non-empty installs the
	// entry as already-canonicalised, suitable for IdPs that
	// don't emit email_verified.
	sub := strings.TrimSpace(req.Sub)
	if sub != "" && len(sub) > oidcSubMaxLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("sub exceeds %d characters", oidcSubMaxLen))
		return
	}

	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Error("get oidc config for allowlist add", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load oidc config")
		return
	}
	// Case-insensitive uniqueness on email.
	for _, existing := range cfg.AllowedIdentities {
		if strings.EqualFold(strings.TrimSpace(existing.Email), email) {
			writeError(w, http.StatusConflict, fmt.Sprintf("allowlist already contains email %q", email))
			return
		}
	}
	// Spec-1 — Sub collision check: a pre-filled sub MUST NOT
	// duplicate any existing entry's sub (whether canonicalised
	// or pre-filled). Two entries sharing a sub would create
	// ambiguous Pass-1 matches at callback time.
	if sub != "" {
		for _, existing := range cfg.AllowedIdentities {
			if existing.Sub != "" && existing.Sub == sub {
				writeError(w, http.StatusConflict, fmt.Sprintf("allowlist already contains an entry with this sub (email %q)", existing.Email))
				return
			}
		}
	}
	now := time.Now().UTC()
	newEntry := storage.OIDCAllowedIdentity{
		Email:       email,
		DisplayName: req.DisplayName,
		Sub:         sub,
		AddedAt:     now,
	}
	cfg.AllowedIdentities = append(cfg.AllowedIdentities, newEntry)
	if err := h.store.PutOIDCConfig(r.Context(), cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, oidcAllowedIdentityResponse{
		Email:       email,
		DisplayName: req.DisplayName,
		Sub:         sub,
		AddedAt:     now.Format(timestampFormat),
	})
}

func (h *Handler) deleteOIDCAllowlist(w http.ResponseWriter, r *http.Request) {
	rawEmail := chi.URLParam(r, "email")
	email, err := url.PathUnescape(rawEmail)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid email parameter")
		return
	}
	email = strings.TrimSpace(email)
	if email == "" {
		writeError(w, http.StatusBadRequest, "email must not be empty")
		return
	}

	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "oidc not configured")
			return
		}
		h.logger.Error("get oidc config for allowlist delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load oidc config")
		return
	}

	found := false
	out := make([]storage.OIDCAllowedIdentity, 0, len(cfg.AllowedIdentities))
	for _, ai := range cfg.AllowedIdentities {
		if strings.EqualFold(strings.TrimSpace(ai.Email), email) {
			found = true
			continue
		}
		out = append(out, ai)
	}
	if !found {
		writeError(w, http.StatusNotFound, fmt.Sprintf("allowlist does not contain email %q", email))
		return
	}
	cfg.AllowedIdentities = out
	if err := h.store.PutOIDCConfig(r.Context(), cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- OIDC login flow: initiate + callback --------------------------------

// oidcStatusResponse is the anonymous status payload. `enabled`
// tells the login page whether to render the SSO button.
// `kind` (optional, may be empty) tells it which provider logo
// to use — exposed anonymously because the click on the SSO
// button immediately reveals the IdP via the 302 chain, so this
// is metadata not a secret. Empty kind → frontend falls back to
// the generic logo.
//
// IssuerURL / ClientID / allowlist are still NEVER echoed here —
// they would leak operational details that no anonymous probe
// needs.
type oidcStatusResponse struct {
	Enabled bool   `json:"enabled"`
	Kind    string `json:"kind,omitempty"`
}

// oidcStatus (GET /api/v1/auth/oidc/status) — anonymous hint
// endpoint. A read failure is treated as `enabled: false` (fail-
// closed for the UI hint; the local login path is unaffected by
// the read regardless — see the break-glass invariant).
//
// No-auth endpoint by design — the login page reads it before
// the user is authenticated.
func (h *Handler) oidcStatus(w http.ResponseWriter, r *http.Request) {
	resp := oidcStatusResponse{Enabled: false}
	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err == nil && cfg.Enabled {
		resp.Enabled = true
		resp.Kind = cfg.Kind
	}
	writeJSON(w, http.StatusOK, resp)
}

// oidcInitiateLogin (GET /api/v1/auth/oidc/login) starts the
// OIDC dance: generates a per-request state + nonce, sets them
// in short-TTL cookies, and 302s to the IdP's authorization
// endpoint with the matching parameters. An optional ?next= (a
// same-origin path, see safeNextPath) is kept in a third flow
// cookie for the callback's final redirect.
//
// SECURITY-CRITICAL: state + nonce MUST be cryptographically
// random per request. The state is the CSRF defence (the
// callback rejects a mismatch); the nonce is the replay defence
// (the ID token must echo it). Failure to generate strong
// randomness aborts the flow.
//
// No-auth endpoint by design — this IS the auth.
func (h *Handler) oidcInitiateLogin(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil || !cfg.Enabled {
		// Either no config or explicitly disabled — render a
		// clear 503 so the UI can fall back to local login.
		// Distinct from "configured but IdP down" which surfaces
		// further down the flow.
		writeError(w, http.StatusServiceUnavailable, "oidc sso is not enabled on this instance")
		return
	}
	if err := h.oidc.EnsureBuilt(r.Context(), cfg); err != nil {
		h.logger.Warn("oidc: discovery fetch failed at login initiate",
			"err", err,
			"issuer_url", cfg.IssuerURL,
			"client_id", cfg.ClientID,
			"timeout_seconds", 10,
		)
		writeError(w, http.StatusServiceUnavailable, "oidc identity provider unreachable")
		return
	}
	_, _, oauthCfg := h.oidc.snapshot()
	if oauthCfg == nil {
		// Defence: snapshot races with config edit. Recoverable
		// on retry; tell the user.
		writeError(w, http.StatusServiceUnavailable, "oidc client not ready, retry shortly")
		return
	}

	state, err := randomToken(oidcStateNonceLen)
	if err != nil {
		h.logger.Error("oidc: state generation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	nonce, err := randomToken(oidcStateNonceLen)
	if err != nil {
		h.logger.Error("oidc: nonce generation failed", "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setOIDCFlowCookie(w, r, oidcStateCookie, state)
	setOIDCFlowCookie(w, r, oidcNonceCookie, nonce)
	// The page to come back to (?next=, optional), kept beside the
	// state; never sent to the IdP.
	setOIDCNextCookie(w, r, r.URL.Query().Get("next"))

	authURL := oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcCallback (GET /api/v1/auth/oidc/callback) is the redirect
// target the IdP sends the user to after authentication. It:
//  1. Validates state (CSRF) against the cookie.
//  2. Exchanges the code for tokens.
//  3. Validates the ID token (signature, issuer, audience,
//     expiry, nonce).
//  4. Matches the validated identity against the allowlist
//     (Sub-pass first, Email-pass as bootstrap with the
//     mandatory email_verified == true guard per §1.6 Δ7).
//  5. Canonicalises Sub on the matching allowlist entry if it
//     was bootstrap-pending.
//  6. Resolves / auto-creates the Arenet user row (default
//     Role: viewer per §1.3 #12).
//  7. Issues an arenet_session cookie (same shape as local
//     login).
//  8. Redirects to the page asked for at login (?next=, kept in
//     the arenet_oidc_next cookie, see oidc_next.go), else /routes.
//
// No-auth endpoint by design. The break-glass invariant is
// preserved: this function never modifies the local-login
// behaviour.
func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// IdP-side error (user cancelled, IdP rejected, etc.).
	if errParam := q.Get("error"); errParam != "" {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: fmt.Sprintf("idp_error=%s", errParam),
		})
		http.Redirect(w, r, h.uiURL("/login?error=idp_error"), http.StatusFound)
		return
	}

	// State validation.
	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "state_cookie_missing",
		})
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}
	stateParam := q.Get("state")
	// Constant-time compare to avoid timing oracle on the state.
	if !constantTimeStringEqual(stateParam, stateCookie.Value) {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "state_mismatch",
		})
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}
	// Single-use: clear the state cookie now that we've consumed it.
	clearOIDCFlowCookie(w, r, oidcStateCookie)
	// Same for the landing page; only used if the sign-in succeeds.
	next := takeOIDCNext(w, r)

	// Nonce cookie — kept until ID-token verification reads it.
	nonceCookie, err := r.Cookie(oidcNonceCookie)
	if err != nil {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "nonce_cookie_missing",
		})
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}
	clearOIDCFlowCookie(w, r, oidcNonceCookie)

	cfg, err := h.store.GetOIDCConfig(r.Context())
	if err != nil || !cfg.Enabled {
		http.Redirect(w, r, h.uiURL("/login?error=idp_unreachable"), http.StatusFound)
		return
	}
	if err := h.oidc.EnsureBuilt(r.Context(), cfg); err != nil {
		h.logger.Warn("oidc: discovery fetch failed at callback",
			"err", err,
			"issuer_url", cfg.IssuerURL,
			"client_id", cfg.ClientID,
			"timeout_seconds", 10,
		)
		http.Redirect(w, r, h.uiURL("/login?error=idp_unreachable"), http.StatusFound)
		return
	}
	_, verifier, oauthCfg := h.oidc.snapshot()
	if oauthCfg == nil || verifier == nil {
		http.Redirect(w, r, h.uiURL("/login?error=idp_unreachable"), http.StatusFound)
		return
	}

	// Code exchange.
	code := q.Get("code")
	if code == "" {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "code_missing",
		})
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}
	tok, err := oauthCfg.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Warn("oidc: code exchange failed",
			"err", err,
			"issuer_url", cfg.IssuerURL,
			"client_id", cfg.ClientID,
		)
		http.Redirect(w, r, h.uiURL("/login?error=idp_unreachable"), http.StatusFound)
		return
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "id_token_missing",
		})
		http.Redirect(w, r, h.uiURL("/login?error=idp_unreachable"), http.StatusFound)
		return
	}

	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		h.logger.Warn("oidc: id token verification failed",
			"err", err,
			"issuer_url", cfg.IssuerURL,
			"client_id", cfg.ClientID,
		)
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "id_token_invalid",
		})
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}
	if idToken.Nonce != nonceCookie.Value {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCCallbackInvalid,
			Message: "nonce_mismatch",
		})
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}

	// Extract claims.
	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		h.logger.Warn("oidc: claims parse failed", "err", err)
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}
	if claims.Sub == "" || len(claims.Sub) > oidcSubMaxLen {
		http.Redirect(w, r, h.uiURL("/login?error=invalid_state"), http.StatusFound)
		return
	}

	// Allowlist match: Sub-pass first (steady-state),
	// Email-pass second (bootstrap, with email_verified guard).
	match, matchIdx, isBootstrap := matchAllowlist(cfg.AllowedIdentities, claims.Sub, claims.Email, claims.EmailVerified, cfg.AcceptUnverifiedEmail)
	if matchIdx < 0 {
		h.appendAudit(r, audit.Event{
			Action:  audit.ActionOIDCLoginRejected,
			Message: fmt.Sprintf("sub=%s email=%s verified=%t", truncate(claims.Sub, 64), truncate(claims.Email, 64), claims.EmailVerified),
		})
		http.Redirect(w, r, h.uiURL("/login?error=not_authorized"), http.StatusFound)
		return
	}

	// Bootstrap → canonicalise Sub + record FirstLoginAt.
	if isBootstrap {
		cfg.AllowedIdentities[matchIdx].Sub = claims.Sub
		cfg.AllowedIdentities[matchIdx].FirstLoginAt = time.Now().UTC()
		if err := h.store.PutOIDCConfig(r.Context(), cfg); err != nil {
			h.logger.Error("oidc: canonicalise failed", "err", err)
			http.Redirect(w, r, h.uiURL("/login?error=internal"), http.StatusFound)
			return
		}
		match = cfg.AllowedIdentities[matchIdx]
	}

	// Resolve / auto-create Arenet user.
	user, err := h.users.GetByOIDCSub(r.Context(), claims.Sub)
	if err != nil {
		if !errors.Is(err, auth.ErrUserNotFound) {
			h.logger.Error("oidc: lookup user by sub failed", "err", err)
			http.Redirect(w, r, h.uiURL("/login?error=internal"), http.StatusFound)
			return
		}
		// Auto-create — default Role viewer per §1.3 #12.
		username := pickOIDCUsername(claims.PreferredUsername, claims.Email, claims.Sub)
		displayName := claims.Name
		if displayName == "" {
			displayName = match.DisplayName
		}
		// Username uniqueness: if the derived value collides, append
		// a short suffix from the sub. Acceptable — operator can
		// rename later if they want.
		if existing, _ := h.users.GetByUsername(r.Context(), username); existing.ID != "" {
			username = uniqueSuffix(username, claims.Sub)
		}
		user, err = h.users.CreateOIDCUser(r.Context(), username, displayName, claims.Email, claims.Sub)
		if err != nil {
			h.logger.Error("oidc: auto-create user failed", "err", err)
			http.Redirect(w, r, h.uiURL("/login?error=internal"), http.StatusFound)
			return
		}
	}

	// Issue Arenet session — same cookie as local login.
	ip := auth.ClientIPFromContext(r.Context())
	sess, err := h.sessions.Create(r.Context(), user.ID, false, ip, r.UserAgent())
	if err != nil {
		h.logger.Error("oidc: session create failed", "err", err)
		http.Redirect(w, r, h.uiURL("/login?error=internal"), http.StatusFound)
		return
	}
	setSessionCookie(w, r, sess.ID, false)
	setThemeCookie(w, r, normalizeThemeForCookie(user.ThemePreference))
	// v2.9.11 i18n Phase 1 — same FOUC-bootstrap cookie for the
	// language preference. OIDC-mapped users default to "en" until
	// they pick a language in Settings.
	setLanguageCookie(w, r, normalizeLanguageForCookie(user.LanguagePreference))

	// Best-effort LastLoginAt + Email sync. Email-sync mirrors
	// the LastLoginAt pattern: if the IdP's email_verified=true
	// claim drifts (operator changes their primary email on the
	// IdP), the next login refreshes the local row so the users-
	// page reflects current state. UpdateEmail is a no-op when
	// the stored value already matches.
	emailClaim := claims.Email
	go func(uid, email string) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.users.RecordLogin(ctx, uid)
		if email != "" {
			_ = h.users.UpdateEmail(ctx, uid, email)
		}
	}(user.ID, emailClaim)

	h.appendAudit(r, audit.Event{
		Action:                audit.ActionLoginSuccess,
		ActorUserID:           user.ID,
		ActorUsernameSnapshot: user.Username,
		Message:               "auth_method=oidc",
	})

	// The page asked for at login (validated twice), /routes otherwise.
	http.Redirect(w, r, h.uiURL(next), http.StatusFound)
}

// matchAllowlist returns the matching entry + its index +
// whether the match was bootstrap (Email-pass). The order is
// (1) match by Sub, (2) match by Email with the mandatory
// email_verified == true guard.
//
// SECURITY (§1.6 Δ7): by default the Email-pass REQUIRES
// emailVerified == true. An IdP-side malicious account claiming
// someone else's unverified email never canonicalises into a
// pending invite. Pinned by
// TestOIDCMatchAllowlist_EmailUnverifiedRejected.
//
// Step #S-17 escape hatch: when acceptUnverifiedEmail is true,
// the Δ7 guard is relaxed. The operator MUST have explicitly
// opted in via OIDCConfig.AcceptUnverifiedEmail — this targets
// IdPs that don't emit email_verified by default (Authentik
// admin-created users) on instances where the operator
// controls account creation IdP-side. See OIDCConfig.
// AcceptUnverifiedEmail for the full threat model.
func matchAllowlist(entries []storage.OIDCAllowedIdentity, sub, email string, emailVerified, acceptUnverifiedEmail bool) (storage.OIDCAllowedIdentity, int, bool) {
	// First pass — match by Sub (steady state).
	for i, e := range entries {
		if e.Sub != "" && e.Sub == sub {
			return e, i, false
		}
	}
	// Second pass — match by Email, BUT only if the IdP
 	// asserted email_verified (§1.6 Δ7), unless the operator
	// canonicalises an invite (§1.6 Δ7).
	// opted in via OIDCConfig.AcceptUnverifiedEmail (Step
	// #S-17). An unverified email never canonicalises an
	// invite in the default secure mode.
	if !emailVerified && !acceptUnverifiedEmail {
		return storage.OIDCAllowedIdentity{}, -1, false
	}
	emailLower := strings.ToLower(strings.TrimSpace(email))
	if emailLower == "" {
		return storage.OIDCAllowedIdentity{}, -1, false
	}
	for i, e := range entries {
		if e.Sub != "" {
			continue // skip already-canonicalised entries
		}
		if strings.ToLower(strings.TrimSpace(e.Email)) == emailLower {
			return e, i, true
		}
	}
	return storage.OIDCAllowedIdentity{}, -1, false
}

// pickOIDCUsername chooses a username for an auto-created OIDC
// user. Order of preference:
//  1. preferred_username (when valid per usernameRegex)
//  2. email local part (lowercased + sanitised)
//  3. sub fallback (truncated to fit)
//
// All candidates are run through the same validation
// (lowercase alnum + dash/underscore, length bounds).
func pickOIDCUsername(preferred, email, sub string) string {
	if u := sanitizeUsername(preferred); u != "" {
		return u
	}
	if i := strings.Index(email, "@"); i > 0 {
		if u := sanitizeUsername(email[:i]); u != "" {
			return u
		}
	}
	// Sub fallback — sub may be a UUID-ish string; sanitize.
	if u := sanitizeUsername(sub); u != "" {
		return u
	}
	// Last resort — base64-encode a hash of the sub. Very rare;
	// we just need a non-empty username that passes the regex.
	return "oidc-user"
}

func sanitizeUsername(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) < auth.UsernameMinLen {
		return ""
	}
	if len(out) > auth.UsernameMaxLen {
		out = out[:auth.UsernameMaxLen]
	}
	return out
}

func uniqueSuffix(base, sub string) string {
	// Append a 6-char hex suffix derived from the sub. Stable
	// for repeated retries (the IdP's sub doesn't change).
	suffix := ""
	for _, r := range sub {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			suffix += string(r)
		}
		if len(suffix) == 6 {
			break
		}
	}
	if suffix == "" {
		suffix = "oidc"
	}
	combined := base + "-" + suffix
	if len(combined) > auth.UsernameMaxLen {
		combined = combined[:auth.UsernameMaxLen]
	}
	return combined
}

// --- Helpers ---------------------------------------------------------------

func randomToken(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
func setOIDCFlowCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(oidcCookieTTL),
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode, // Lax: cookie travels on the IdP→callback redirect
	})
}
func clearOIDCFlowCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
