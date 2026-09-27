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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Step CS.1 — CrowdSec bouncer admin settings.
//
// Endpoints (hard-auth admin):
//   - GET  /api/v1/settings/crowdsec        — current row (secrets redacted)
//   - PUT  /api/v1/settings/crowdsec        — persist + hot-reload Caddy
//   - POST /api/v1/settings/crowdsec/test   — probe LAPI with current creds
//
// Secret redaction (mirror of dnsProviderForAudit + oidc):
// APIKey is NEVER echoed by GET — the response carries an
// `apiKey: ""` field plus a `configured: bool` flag. The UI
// uses `configured` to render a "•••• already saved" placeholder
// in the password input and treats an empty submission on PUT
// as "keep the previously-stored value".

// CrowdSecApplier is the consumer-side seam the CrowdSec
// settings handler depends on for hot-reload. *caddymgr.
// CaddyManager satisfies it via ApplyCrowdSecConfig. Declared
// as an interface so tests can stub without booting Caddy
// (same pattern as CaddyReloader). The shape is intentionally
// narrow: only the "swap creds + reload" operation, no other
// manager surface area.
type CrowdSecApplier interface {
	ApplyCrowdSecConfig(ctx context.Context, apiURL, apiKey string) error
}

// crowdSecRequest is the wire shape accepted by PUT
// /api/v1/settings/crowdsec. APIKey="" on PUT keeps the
// previously stored value (preserve-on-edit; same pattern as
// dnsProviderRequest.ApplicationSecret).
type crowdSecRequest struct {
	LAPIURL        string `json:"lapiUrl"`
	APIKey         string `json:"apiKey"`
	BouncerName    string `json:"bouncerName"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

// crowdSecResponse is the wire shape returned by GET
// /api/v1/settings/crowdsec. APIKey is ALWAYS emitted as "" —
// the UI binds `configured` to render the "secret already
// saved" affordance.
type crowdSecResponse struct {
	LAPIURL        string `json:"lapiUrl"`
	APIKey         string `json:"apiKey"`
	BouncerName    string `json:"bouncerName"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	Configured     bool   `json:"configured"`
	UpdatedAt      string `json:"updatedAt,omitempty"`
	// RestartRequired (v2.51) is set on a PUT that MOVED the LAPI
	// address. Arenet reloads Caddy, and the bouncer is re-provisioned
	// with the new URL — but its streaming client keeps dialling the
	// previous one until the PROCESS restarts.
	//
	// Observed 2026-09-27 moving a LAPI from 127.0.0.1 to a WireGuard
	// address: the bouncer logged `address: http://10.66.0.1:8080` while
	// every request went to `http://127.0.0.1:8080`, so the log asserted
	// the new address and the traffic used the old one. A restart fixed
	// it immediately.
	//
	// This matters more than a cosmetic delay: the bouncer fails OPEN, so
	// for as long as it cannot reach LAPI it blocks nothing at all, with
	// no error anywhere in the UI. An operator who believes the change
	// took effect is unprotected and has no way to tell.
	RestartRequired bool `json:"restartRequired,omitempty"`
}

// crowdSecConfigForAudit returns a copy of c with the APIKey
// blanked. Mirror of oidcConfigForAudit + dnsProviderForAudit:
// the audit row holds the URL + bouncer name + the fact a
// change happened, never the secret payload.
func crowdSecConfigForAudit(c storage.CrowdSecConfig) storage.CrowdSecConfig {
	c.APIKey = ""
	return c
}

// crowdSecResponseFor builds the GET response shape from a
// stored row + an `everConfigured` boolean (true when a row
// exists; false for the fresh-install + AC #13 not-configured
// case). When the row is absent we still emit the canonical
// defaults so the UI has something coherent to bind to.
func crowdSecResponseFor(c storage.CrowdSecConfig, everConfigured bool) crowdSecResponse {
	if !everConfigured {
		d := storage.CrowdSecConfigDefaults()
		return crowdSecResponse{
			LAPIURL:        d.LAPIURL,
			APIKey:         "",
			BouncerName:    d.BouncerName,
			TimeoutSeconds: d.TimeoutSeconds,
			Configured:     false,
		}
	}
	resp := crowdSecResponse{
		LAPIURL:        c.LAPIURL,
		APIKey:         "",
		BouncerName:    c.BouncerName,
		TimeoutSeconds: c.TimeoutSeconds,
		Configured:     c.APIKey != "",
	}
	if !c.UpdatedAt.IsZero() {
		resp.UpdatedAt = c.UpdatedAt.UTC().Format(timestampFormat)
	}
	return resp
}

// getCrowdSecSettings serves GET /api/v1/settings/crowdsec.
// Returns 200 + defaults+configured=false on ErrNotFound
// (mirror of getDNSProviderOVH's no-row behaviour) — the
// lifecycle convention is "no 404 for absent settings; the
// operator PUTs to create".
func (h *Handler) getCrowdSecSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetCrowdSecConfig(r.Context())
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeJSON(w, http.StatusOK, crowdSecResponseFor(storage.CrowdSecConfig{}, false))
			return
		}
		h.logger.Error("get crowdsec config", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get crowdsec config")
		return
	}
	writeJSON(w, http.StatusOK, crowdSecResponseFor(cfg, true))
}

// putCrowdSecSettings serves PUT /api/v1/settings/crowdsec.
// Persists the row, then calls the CrowdSecApplier to swap
// the embedded Caddy's bouncer creds + reload. Rollback on
// reload failure mirrors putDNSProviderOVH (Step J.4) — the
// previous row is restored if Caddy rejects the new config.
//
// Preserve-on-edit: empty APIKey on the wire keeps the
// previously stored value (same convention as the OVH
// secrets). An explicit "wipe" requires PUT with ALL fields
// blank — that's the documented "Disable" path; the storage
// validate accepts the all-empty shape (not-configured state).
func (h *Handler) putCrowdSecSettings(w http.ResponseWriter, r *http.Request) {
	var req crowdSecRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	previous, prevErr := h.store.GetCrowdSecConfig(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("get crowdsec config (update)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load crowdsec config")
		return
	}

	// Preserve-on-edit merge for the secret.
	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" {
		apiKey = previous.APIKey
	}

	merged := storage.CrowdSecConfig{
		LAPIURL:        strings.TrimSpace(req.LAPIURL),
		APIKey:         apiKey,
		BouncerName:    strings.TrimSpace(req.BouncerName),
		TimeoutSeconds: req.TimeoutSeconds,
		CreatedAt:      previous.CreatedAt,
	}

	if err := h.store.PutCrowdSecConfig(r.Context(), merged); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// #R-CROWDSEC-audit-updated-at-zero — re-fetch the row
	// from storage so the audit AfterJSON snapshot carries
	// the storage-assigned UpdatedAt (PutCrowdSecConfig at
	// internal/storage/crowdsec_config.go:262 sets it to
	// time.Now() during the bbolt Update). Pre-fix the
	// audit captured `merged` directly, which left UpdatedAt
	// at the Go zero time (0001-01-01T00:00:00Z) in the
	// audit log — operator-confusing for a "just-updated"
	// event. Re-fetching is the cheap way to surface the
	// canonical persisted state without changing the
	// storage API. The response below also uses the
	// re-fetched value so the wire response reflects
	// what was actually persisted.
	persisted, refetchErr := h.store.GetCrowdSecConfig(r.Context())
	if refetchErr != nil {
		// The Put just succeeded so this should not happen
		// in practice; degrade gracefully by falling back to
		// `merged` rather than aborting the operation.
		h.logger.Warn("re-fetch crowdsec config after put failed; audit + response will report client-side merge state",
			"err", refetchErr)
		persisted = merged
	}

	// Hot-reload Caddy. The applier is nil-tolerant: tests
	// that don't exercise the manager leave SetCrowdSecApplier
	// unset, and we treat that as "no live bouncer to swap"
	// (a fresh storage row is still persisted, audit still
	// emits). Same pattern as the optional sink readers on
	// the Handler struct.
	if h.crowdsecApplier != nil {
		if err := h.crowdsecApplier.ApplyCrowdSecConfig(r.Context(), persisted.LAPIURL, persisted.APIKey); err != nil {
			h.logger.Error("caddy reload after crowdsec settings update — rolling back", "err", err)
			if errors.Is(prevErr, storage.ErrNotFound) {
				// No previous row to restore — leave the new
				// write in place. The operator gets the 500;
				// they can re-PUT.
			} else {
				if rbErr := h.store.PutCrowdSecConfig(r.Context(), previous); rbErr != nil {
					h.logger.Error("rollback crowdsec config failed", "err", rbErr)
				}
			}
			writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
			return
		}
	}

	// Audit AFTER the reload succeeds. Both before/after
	// JSON have APIKey blanked (SECRET).
	action := audit.ActionCrowdSecUpdated
	if errors.Is(prevErr, storage.ErrNotFound) {
		action = audit.ActionCrowdSecConfigured
	}
	evt := audit.Event{
		Action:     action,
		TargetType: "crowdsec_config",
		TargetID:   "default",
		AfterJSON:  mustMarshalForAudit(crowdSecConfigForAudit(persisted)),
	}
	if !errors.Is(prevErr, storage.ErrNotFound) {
		evt.BeforeJSON = mustMarshalForAudit(crowdSecConfigForAudit(previous))
	}
	h.appendAudit(r, evt)

	resp := crowdSecResponseFor(persisted, persisted.APIKey != "")
	// Only when the ADDRESS moved. Rotating the key alone re-provisions
	// cleanly, so demanding a restart for it would train the operator to
	// ignore the warning.
	resp.RestartRequired = !errors.Is(prevErr, storage.ErrNotFound) &&
		previous.LAPIURL != persisted.LAPIURL &&
		persisted.APIKey != ""
	if resp.RestartRequired {
		h.logger.Warn("crowdsec: the LAPI address changed; the bouncer keeps the previous one until Arenet restarts, and blocks nothing until then (fail-open)",
			"from", previous.LAPIURL, "to", persisted.LAPIURL)
	}
	writeJSON(w, http.StatusOK, resp)
}

// crowdSecTestRequest is the wire shape accepted by POST
// /api/v1/settings/crowdsec/test. Empty fields fall back to
// the currently persisted row (the UI sends the form values
// even before Save, so the operator can probe a candidate
// config without committing it). An explicit `useStored:
// true` field on the request skips wire fields and uses the
// stored row verbatim — handy for the "test the saved
// config" button on a re-visit.
type crowdSecTestRequest struct {
	LAPIURL        string `json:"lapiUrl"`
	APIKey         string `json:"apiKey"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
	UseStored      bool   `json:"useStored"`
}

// crowdSecTestResponse is the wire shape returned by POST
// /api/v1/settings/crowdsec/test. `ok` is the single
// boolean the UI flips a green / red badge on; the optional
// fields carry diagnostic detail for the operator's
// troubleshooting flow.
type crowdSecTestResponse struct {
	OK         bool   `json:"ok"`
	StatusCode int    `json:"statusCode,omitempty"`
	Version    string `json:"version,omitempty"`
	// Error is a short, operator-friendly string when ok=false.
	// Examples: "connection refused", "timeout", "auth failed",
	// "unexpected status 500". MUST NOT contain the API key
	// or any header that could leak it (we strip the auth
	// header from the underlying http.Client errors before
	// surfacing).
	Error string `json:"error,omitempty"`
	// EffectiveURL echoes the LAPI URL the probe actually
	// hit (after fallback to the stored row + default
	// resolution). Helps the operator confirm precedence
	// when they're debugging "why is my new URL not being
	// tried?".
	EffectiveURL string `json:"effectiveUrl,omitempty"`
}

// deleteCrowdSecSettings serves DELETE
// /api/v1/settings/crowdsec — Step CS.2 follow-up.
//
// Wipes the persisted CrowdSec config row AND hot-reloads
// Caddy so the bouncer module drops out of the running data
// plane within the request lifetime. AC #13 fail-open
// contract preserved: after the reload, requests no longer
// pass through the IP-reputation gate; WAF + rate-limiter
// still active.
//
// Idempotent: a fresh-install DELETE (no row to wipe) still
// runs the applier so any straggler bouncer state on a
// hot-reload boundary clears cleanly. Returns 200 with the
// "not configured" response shape so the UI's badge flips to
// amber without needing a separate GET round-trip.
//
// Audit: emits crowdsec_reset (distinct from crowdsec_updated)
// with BeforeJSON carrying the wiped row (APIKey scrubbed)
// and AfterJSON omitted (the row no longer exists).
//
// Rollback on reload failure: same shape as putCrowdSecSettings
// — if the Caddy reload fails after the storage delete, the
// previous row is restored. The audit row is NOT emitted on
// failure (the reset didn't take effect).
func (h *Handler) deleteCrowdSecSettings(w http.ResponseWriter, r *http.Request) {
	previous, prevErr := h.store.GetCrowdSecConfig(r.Context())
	if prevErr != nil && !errors.Is(prevErr, storage.ErrNotFound) {
		h.logger.Error("get crowdsec config (delete)", "err", prevErr)
		writeError(w, http.StatusInternalServerError, "failed to load crowdsec config")
		return
	}

	if !errors.Is(prevErr, storage.ErrNotFound) {
		if err := h.store.DeleteCrowdSecConfig(r.Context()); err != nil {
			h.logger.Error("delete crowdsec config", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to delete crowdsec config")
			return
		}
	}

	// Hot-reload Caddy with cleared creds. Pass empty URL +
	// empty key so the manager's buildConfigJSON omits the
	// apps.crowdsec block entirely (AC #13).
	if h.crowdsecApplier != nil {
		if err := h.crowdsecApplier.ApplyCrowdSecConfig(r.Context(), "", ""); err != nil {
			h.logger.Error("caddy reload after crowdsec delete — rolling back", "err", err)
			if !errors.Is(prevErr, storage.ErrNotFound) {
				if rbErr := h.store.PutCrowdSecConfig(r.Context(), previous); rbErr != nil {
					h.logger.Error("rollback crowdsec config failed", "err", rbErr)
				}
			}
			writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
			return
		}
	}

	// Audit AFTER the reload succeeds. Skip if there was no
	// row to begin with — a DELETE on a fresh install is a
	// no-op from the operator's perspective, no need for a
	// noisy audit row.
	if !errors.Is(prevErr, storage.ErrNotFound) {
		h.appendAudit(r, audit.Event{
			Action:     audit.ActionCrowdSecReset,
			TargetType: "crowdsec_config",
			TargetID:   "default",
			BeforeJSON: mustMarshalForAudit(crowdSecConfigForAudit(previous)),
			// AfterJSON intentionally nil — the row no longer
			// exists; the audit diff carries "was X, now gone".
		})
	}

	// Return the "not configured" response shape so the UI
	// can update its badge + form state without a separate
	// GET. configured=false ⇒ UI re-renders with defaults.
	writeJSON(w, http.StatusOK, crowdSecResponseFor(storage.CrowdSecConfig{}, false))
}

// testCrowdSecConnection serves POST
// /api/v1/settings/crowdsec/test. Probes LAPI's
// /v1/decisions endpoint with the operator-supplied (or
// stored) creds. CrowdSec's bouncer auth model is a single
// `X-Api-Key` header; success looks like 200 + a JSON array
// (possibly empty). The Test endpoint MAY accept 200/204 —
// 204 No Content is what LAPI returns when there are no
// active decisions.
//
// This handler does NOT mutate any state; it's purely an
// observability probe. No audit entry (the value is the
// real-time signal, not a config change). The handler runs
// under the same admin-auth guard as the PUT — only an
// admin can probe the bouncer.
func (h *Handler) testCrowdSecConnection(w http.ResponseWriter, r *http.Request) {
	var req crowdSecTestRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	// Resolve effective LAPI URL + API key:
	//   - UseStored:true → ignore wire fields entirely
	//   - else → wire fields, falling back to stored row
	//     on a per-field basis (a partial form should be
	//     possible: operator changes URL only and probes
	//     against the existing stored key, etc.)
	stored, storedErr := h.store.GetCrowdSecConfig(r.Context())
	if storedErr != nil && !errors.Is(storedErr, storage.ErrNotFound) {
		h.logger.Error("get crowdsec config (test)", "err", storedErr)
		writeError(w, http.StatusInternalServerError, "failed to load crowdsec config")
		return
	}

	var effURL, effKey string
	var effTimeout int
	if req.UseStored {
		effURL = stored.LAPIURL
		effKey = stored.APIKey
		effTimeout = stored.TimeoutSeconds
	} else {
		effURL = strings.TrimSpace(req.LAPIURL)
		if effURL == "" {
			effURL = stored.LAPIURL
		}
		effKey = strings.TrimSpace(req.APIKey)
		if effKey == "" {
			effKey = stored.APIKey
		}
		effTimeout = req.TimeoutSeconds
		if effTimeout == 0 {
			effTimeout = stored.TimeoutSeconds
		}
	}
	if effURL == "" {
		effURL = storage.CrowdSecConfigDefaults().LAPIURL
	}
	if effTimeout == 0 {
		effTimeout = storage.CrowdSecConfigDefaults().TimeoutSeconds
	}

	// Empty key is a config error, not a probe failure —
	// return 400 with a friendly message rather than the
	// generic ok=false (which would otherwise be
	// indistinguishable from a wrong key from the UI's
	// perspective).
	if effKey == "" {
		writeError(w, http.StatusBadRequest, "api key required to test connection")
		return
	}

	resp := h.probeCrowdSecLAPI(r.Context(), effURL, effKey, effTimeout)
	resp.EffectiveURL = effURL
	writeJSON(w, http.StatusOK, resp)
}

// probeCrowdSecLAPI performs the actual HTTP probe against
// LAPI. Factored out so unit tests can call it directly
// against an httptest.Server. Caller responsibility: don't
// pass an empty effKey (the testCrowdSecConnection handler
// guards that path).
func (h *Handler) probeCrowdSecLAPI(ctx context.Context, lapiURL, apiKey string, timeoutSec int) crowdSecTestResponse {
	probeURL := strings.TrimRight(lapiURL, "/") + "/v1/decisions"

	timeout := time.Duration(timeoutSec) * time.Second
	if timeout <= 0 || timeout > 60*time.Second {
		timeout = 5 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		// http.NewRequestWithContext only errors on malformed
		// URL — surface as a friendly config error.
		return crowdSecTestResponse{OK: false, Error: fmt.Sprintf("invalid LAPI URL: %s", redactKey(err.Error(), apiKey))}
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("User-Agent", "arenet/crowdsec-test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return crowdSecTestResponse{OK: false, Error: classifyProbeError(err, apiKey)}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	out := crowdSecTestResponse{StatusCode: resp.StatusCode}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		out.OK = true
		// LAPI emits its version in the X-Crowdsec-Version
		// header on responses; surface it so the UI can
		// render the "connected to LAPI v1.6.x" affordance.
		out.Version = resp.Header.Get("X-Crowdsec-Version")
	case http.StatusUnauthorized, http.StatusForbidden:
		out.OK = false
		out.Error = "authentication failed (invalid bouncer API key)"
	default:
		out.OK = false
		out.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
	return out
}

// classifyProbeError turns a low-level http.Client error into
// a short, operator-friendly explanation. Strips the API key
// from the error string defensively (Go's http stack doesn't
// normally include headers in error messages, but a custom
// Transport / proxy chain could; better safe).
func classifyProbeError(err error, apiKey string) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline exceeded"),
		strings.Contains(msg, "Client.Timeout"):
		return "timeout (LAPI did not respond in time)"
	case strings.Contains(msg, "connection refused"):
		return "connection refused (LAPI not running or unreachable on this port)"
	case strings.Contains(msg, "no such host"):
		return "DNS resolution failed (check the LAPI hostname)"
	case strings.Contains(msg, "tls"),
		strings.Contains(msg, "x509"):
		return "TLS handshake failed (LAPI is HTTPS — check certificate)"
	default:
		return redactKey(msg, apiKey)
	}
}

// redactKey scrubs the API key from any error string before
// it's returned to the operator. The defensive intent is to
// guarantee the UI doesn't accidentally render the secret
// inside an error toast (which could be screenshot-shared by
// the operator in a help thread).
func redactKey(msg, apiKey string) string {
	if apiKey == "" {
		return msg
	}
	return strings.ReplaceAll(msg, apiKey, "[REDACTED]")
}
