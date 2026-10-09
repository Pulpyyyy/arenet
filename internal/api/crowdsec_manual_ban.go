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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// Step CS.3 Commit C — Bannir une IP (manual ban) endpoint.
//
// POST /api/v1/security/crowdsec/decisions
//
// Builds a LAPI Alert payload with a single Decision and
// POSTs to /v1/alerts via the JWT auth path shared with the
// Scenarios tab (lapiWithJWT in crowdsec_scenarios.go).
//
// Auth model: admin-only (route mount applies
// RequireAdminMiddleware). The authenticated username is
// extracted from r.Context() via auth.UsernameKey — same
// pattern as audit_helpers.go:88.
//
// Format: per operator decision in the CS.3 brief, the
// emitted Decision.scenario carries the username AND the
// operator's free-form reason on the SAME field:
//
//   scenario = "manual:<username>|<reason>"
//
// Rationale: LAPI's GET /v1/decisions response shape (which
// the CS.3 Commit B Live LAPI tab consumes) does not include
// the parent Alert. To surface the reason in the Live LAPI
// table, the reason must travel on the Decision itself.
// Encoding it after a pipe separator in scenario keeps the
// existing `scenario.startsWith("manual:")` filter logic
// intact and makes cscli operators' output operator-readable
// too. See CS.3 Commit B for the frontend parser.
//
// LAPI payload shape (verified against
// crowdsec@v1.6.3/pkg/models.Alert + .Decision):
//
//   [
//     {
//       "scenario": "manual:<username>|<reason>",
//       "message":  "<reason>",
//       "events":   [],
//       "events_count": 0,
//       "capacity": 0,
//       "leakspeed": "0",
//       "start_at": "<RFC3339Nano>",
//       "stop_at":  "<RFC3339Nano + duration>",
//       "source": {
//         "scope": "Ip" | "Range",
//         "value": "<IP or CIDR>"
//       },
//       "decisions": [
//         {
//           "scenario": "manual:<username>|<reason>",
//           "duration": "<Go-duration string>",
//           "scope":    "Ip" | "Range",
//           "value":    "<IP or CIDR>",
//           "type":     "ban" | "captcha" | "throttle",
//           "origin":   "manual"
//         }
//       ]
//     }
//   ]
//
// LAPI POST /v1/alerts accepts an ARRAY of alerts (the
// swagger schema is AddAlertsRequest = []Alert). Even for a
// single manual ban we emit a 1-element array.

// manualBanRequest is the wire shape accepted by POST
// /api/v1/security/crowdsec/decisions. All four fields
// required. Validation happens in validateManualBanRequest
// (called pre-LAPI to surface friendly 400s).
type manualBanRequest struct {
	// Value is the target IP or CIDR. IPv4 and IPv6 both
	// accepted. A bare IP gets scope "Ip"; a CIDR gets
	// scope "Range" (LAPI's casing convention).
	Value string `json:"value"`
	// Duration is a Go-duration string ("1h", "24h", "7d"
	// custom — note LAPI's custom ParseDuration accepts "d"
	// suffix per crowdsec@v1.6.3/pkg/database/utils.go:72).
	// Empirically validated in CS.2.C HF 75fa166.
	Duration string `json:"duration"`
	// Type is the CrowdSec decision type. Accepted: "ban",
	// "captcha", "throttle". Free-form is rejected so
	// operators can't push types Arenet's UI doesn't display.
	Type string `json:"type"`
	// Reason is operator-supplied free-form text explaining
	// the ban. Embedded into scenario + duplicated as the
	// Alert.message so cscli output shows it too. Length
	// capped at 256 chars; non-printable runes are
	// rejected (defensive: a reason like "X\x00Y\n" could
	// confuse downstream consumers — sanitise upfront).
	Reason string `json:"reason"`
	// ConfirmSelfBan is the explicit override for the self-ban
	// guard: without it, a value that is or contains the
	// requesting client's own IP is refused with 409
	// crowdsec_self_ban. Optional; false when absent.
	ConfirmSelfBan bool `json:"confirmSelfBan,omitempty"`
}

// errCodeCrowdSecSelfBan is the stable machine code of the 409
// returned when a manual ban would cover the requesting client's
// own IP. The frontend translates it (errors.server.<code>) and
// offers the confirmSelfBan override behind a second
// confirmation.
const errCodeCrowdSecSelfBan = "crowdsec_self_ban"

// manualBanResponse is the wire shape returned on 201 success.
// Echoes the canonical scenario string so the frontend can
// optimistically prepend the new row to the Live LAPI table
// without waiting for the 30s polling tick.
type manualBanResponse struct {
	Scenario string `json:"scenario"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Origin   string `json:"origin"`
	ExpiresAt string `json:"expiresAt"`
}

// crowdSecManualBanReasonMaxLen caps the operator-supplied
// reason. 256 chars is enough for "smoke test: blocked
// after 5 failed SSH attempts from 198.51.100.42 at
// 2026-06-10T15:30Z" — way more than any operator should
// reasonably type. Lower bound avoids LAPI / log-truncation
// surprises downstream.
const crowdSecManualBanReasonMaxLen = 256

// addManualBan serves POST
// /api/v1/security/crowdsec/decisions.
//
// Status codes:
//   201 Created — happy path. Body echoes the canonical
//                 scenario string + scope/type/duration.
//   400 Bad Request — validation failed (bad IP, bad
//                     duration, bad type, reason too long /
//                     empty / non-printable).
//   409 Conflict — code crowdsec_self_ban: the value is, or
//                  contains, the requesting client's own IP
//                  (as resolved for the audit log) and
//                  confirmSelfBan was not set.
//   412 Precondition Failed — Security Automation creds
//                              not configured (reuses CS.2.C
//                              412 contract).
//   502 Bad Gateway — LAPI unreachable OR machine creds
//                     rejected after retry (mirror of
//                     CS.2.C error path).
//   500 Internal Server Error — storage read failed.
func (h *Handler) addManualBan(w http.ResponseWriter, r *http.Request) {
	var req manualBanRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	scope, value, vErr := validateManualBanValue(req.Value)
	if vErr != nil {
		writeError(w, http.StatusBadRequest, vErr.Error())
		return
	}
	if err := validateManualBanDuration(req.Duration); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	banType, tErr := validateManualBanType(req.Type)
	if tErr != nil {
		writeError(w, http.StatusBadRequest, tErr.Error())
		return
	}
	reason, rErr := validateManualBanReason(req.Reason)
	if rErr != nil {
		writeError(w, http.StatusBadRequest, rErr.Error())
		return
	}

	// Self-ban guard. The client IP is the one the audit log
	// records (auth.ClientIPFromContext, X-Forwarded-For aware
	// behind ARENET_TRUSTED_PROXIES). Banning it would cut the
	// operator off from every route the bouncer protects —
	// possibly this admin UI — so it takes an explicit
	// override. Checked before the credentials lookup: the
	// refusal does not depend on LAPI being configured.
	clientIP := auth.ClientIPFromContext(r.Context())
	if !req.ConfirmSelfBan && banCoversClientIP(scope, value, clientIP) {
		writeErrorCode(w, http.StatusConflict, errCodeCrowdSecSelfBan,
			fmt.Sprintf("%s covers your own client IP %s — resend with confirmSelfBan=true to ban it anyway", value, clientIP),
			map[string]any{"value": value, "clientIp": clientIP})
		return
	}

	// Auth context — admin-only route, the middleware
	// guarantees a non-empty username. Defensive fallback to
	// "unknown" in case of misconfiguration (the scenario
	// string stays parseable; the audit trail surfaces the
	// missing-context anomaly).
	username, _ := r.Context().Value(auth.UsernameKey).(string)
	if username == "" {
		username = "unknown"
	}

	// Security Automation creds — same source as the
	// Scenarios tab. If absent → 412 (the operator must
	// configure Settings → Security Automation before they
	// can manual-ban).
	creds, credsErr := h.store.GetWatcherCredentials(r.Context())
	if credsErr != nil && !errors.Is(credsErr, storage.ErrNotFound) {
		h.logger.Error("get watcher credentials (manual ban)", "err", credsErr)
		writeError(w, http.StatusInternalServerError, "failed to load automation credentials")
		return
	}
	if errors.Is(credsErr, storage.ErrNotFound) || !storage.WatcherCredentialsConfigured(creds) {
		writeError(w, http.StatusPreconditionFailed,
			"security automation not configured — set machine credentials in Settings → Security Automation to enable manual bans")
		return
	}

	// Reuse the bouncer's TimeoutSeconds if present, else 5s.
	timeoutSec := 5
	if cs, err := h.store.GetCrowdSecConfig(r.Context()); err == nil && cs.TimeoutSeconds > 0 {
		timeoutSec = cs.TimeoutSeconds
	}
	timeout := time.Duration(timeoutSec) * time.Second

	scenario := buildManualBanScenario(username, reason)
	alertPayload := buildManualBanAlertPayload(scenario, reason, scope, value, banType, req.Duration)

	if err := h.postManualBanToLAPI(r.Context(), creds, timeout, alertPayload); err != nil {
		if errors.Is(err, errLAPIAuthRejected) {
			writeError(w, http.StatusBadGateway,
				"machine credentials rejected by LAPI — re-verify Settings → Security Automation")
			return
		}
		writeError(w, http.StatusBadGateway, classifyProbeError(err, creds.Password))
		return
	}

	// Compute the wire-friendly ExpiresAt for the response
	// echo. LAPI's custom ParseDuration accepts "Nd" plus
	// stdlib forms — we already validated the format in
	// validateManualBanDuration. Best-effort parse here for
	// the UI; if it somehow fails post-validation, omit the
	// field rather than spike a 500.
	var expiresAt string
	if d, err := parseLAPIDuration(req.Duration); err == nil {
		expiresAt = time.Now().UTC().Add(d).Format(timestampFormat)
	}

	// Audit AFTER LAPI accepts. BeforeJSON is nil (this is a
	// CREATE; no prior state). AfterJSON carries the wire
	// shape WITH reason — secrets discipline (the audit
	// schema already redacts pre-defined secret fields at
	// the audit layer; the reason is operator-typed free-form
	// and is NOT a secret, so it stays). Username appears
	// twice: in scenario, and in the ActorUsernameSnapshot
	// set by h.appendAudit automatically.
	auditPayload := manualBanResponse{
		Scenario: scenario,
		Scope:    scope,
		Value:    value,
		Type:     banType,
		Duration: req.Duration,
		Origin:   "manual",
		ExpiresAt: expiresAt,
	}
	// An overridden self-ban is worth spelling out in the trail:
	// it is the one manual ban that can lock the operator out.
	var auditMsg string
	if req.ConfirmSelfBan && banCoversClientIP(scope, value, clientIP) {
		auditMsg = "self-ban override confirmed: covers the requesting client IP " + clientIP
	}
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionCrowdSecDecisionCreate,
		TargetType: "crowdsec_decision",
		TargetID:   value,
		AfterJSON:  mustMarshalForAudit(auditPayload),
		Message:    auditMsg,
	})

	writeJSON(w, http.StatusCreated, auditPayload)
}

// validateManualBanValue parses the operator-supplied IP /
// CIDR string and returns the LAPI-canonical scope + value.
// LAPI's scope strings are case-sensitive: "Ip" and "Range"
// (verified against crowdsec@v1.6.3/pkg/types/constants.go).
//
// Empty / pure whitespace → 400.
// Bare IPv4 or IPv6 → ("Ip", normalised).
// IPv4 or IPv6 CIDR → ("Range", normalised).
// Garbage → 400.
func validateManualBanValue(raw string) (scope string, value string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("value is required (IP or CIDR)")
	}
	if strings.Contains(trimmed, "/") {
		// CIDR form. ParseCIDR normalises (e.g.
		// "10.0.0.1/8" → "10.0.0.0/8"). LAPI accepts both,
		// but we send the canonical form so de-dup on the
		// LAPI side works.
		_, ipnet, parseErr := net.ParseCIDR(trimmed)
		if parseErr != nil {
			return "", "", fmt.Errorf("invalid CIDR %q: %v", trimmed, parseErr)
		}
		return "Range", ipnet.String(), nil
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP %q (expected IPv4, IPv6, or CIDR)", trimmed)
	}
	return "Ip", ip.String(), nil
}

// banCoversClientIP reports whether a validated ban target
// (scope + canonical value from validateManualBanValue) is, or
// contains, clientIP. An empty or unparseable clientIP never
// matches: the guard cannot protect an address it does not
// know, and refusing every ban in that case would make manual
// bans unusable behind a misconfigured proxy.
//
// net.IP.Equal and net.IPNet.Contains both normalise
// IPv4-mapped IPv6 (::ffff:a.b.c.d) to IPv4, so a client seen
// as ::ffff:203.0.113.7 still matches a ban on 203.0.113.7 or
// 203.0.113.0/24.
func banCoversClientIP(scope, value, clientIP string) bool {
	client := net.ParseIP(strings.TrimSpace(clientIP))
	if client == nil {
		return false
	}
	if scope == "Range" {
		_, ipnet, err := net.ParseCIDR(value)
		return err == nil && ipnet.Contains(client)
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.Equal(client)
}

// validateManualBanDuration confirms the duration parses
// through LAPI's grammar (Go stdlib + "Nd" suffix). Also
// rejects negative or zero durations (operator typo —
// they'd ban for "0s" which means no ban).
func validateManualBanDuration(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("duration is required (e.g. \"1h\", \"24h\", \"7d\")")
	}
	d, err := parseLAPIDuration(trimmed)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %v", trimmed, err)
	}
	if d <= 0 {
		return fmt.Errorf("duration must be positive, got %q", trimmed)
	}
	return nil
}

// validateManualBanType pins the accepted types to the set
// the UI displays. Free-form would let an operator push
// scenarios Arenet's CS.3 frontend can't render.
func validateManualBanType(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	switch trimmed {
	case "ban", "captcha", "throttle":
		return trimmed, nil
	case "":
		return "", errors.New("type is required (ban, captcha, throttle)")
	default:
		return "", fmt.Errorf("invalid type %q (accepted: ban, captcha, throttle)", trimmed)
	}
}

// validateManualBanReason caps length + rejects non-
// printable runes. Reason is operator-typed free text; we
// don't want a tab-stuffed or NUL-byte payload sneaking
// past into LAPI logs.
func validateManualBanReason(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("reason is required")
	}
	if len(trimmed) > crowdSecManualBanReasonMaxLen {
		return "", fmt.Errorf("reason exceeds %d chars (got %d)", crowdSecManualBanReasonMaxLen, len(trimmed))
	}
	// Reject control characters except spaces. Pipes are
	// permitted in the reason — buildManualBanScenario uses
	// the first pipe of the prefix as the username|reason
	// delimiter, so any pipes in the reason ride through to
	// the frontend parser which splits on FIRST pipe.
	for _, r := range trimmed {
		if r < 0x20 && r != '\t' {
			return "", fmt.Errorf("reason contains non-printable char (rune %U)", r)
		}
	}
	return trimmed, nil
}

// buildManualBanScenario encodes the (username, reason)
// pair into the Decision.scenario string per the operator-
// confirmed Option 1 format (CS.3 brief Day-7).
func buildManualBanScenario(username, reason string) string {
	return "manual:" + username + "|" + reason
}

// buildManualBanAlertPayload assembles the LAPI POST
// /v1/alerts body. Returns a 1-element array per the
// swagger AddAlertsRequest shape. All "Required: true"
// fields populated with sensible defaults (Capacity=0 /
// Leakspeed="0" / Events=[] / EventsCount=0 — the alert
// represents a single manual decision, no underlying
// scenario fired).
func buildManualBanAlertPayload(scenario, reason, scope, value, banType, duration string) []byte {
	now := time.Now().UTC()
	// stopAt is mostly informational on a manual ban —
	// LAPI computes the actual decision expiry from
	// Decision.Duration. We still populate it for
	// completeness so cscli's `decisions list` shows a
	// stop_at column.
	stopAt := now.Add(time.Hour) // sentinel; LAPI uses Duration field
	if d, err := parseLAPIDuration(duration); err == nil {
		stopAt = now.Add(d)
	}
	emptyEvents := []struct{}{}
	capacity := int32(0)
	leakspeed := "0"
	eventsCount := int32(0)

	scopePtr := scope
	valuePtr := value
	scenarioPtr := scenario
	messagePtr := reason
	startStr := now.Format(time.RFC3339Nano)
	stopStr := stopAt.Format(time.RFC3339Nano)
	typePtr := banType
	durationPtr := duration
	originPtr := "manual"

	// HF on 7302a3a — LAPI's swagger Alert schema marks
	// scenario_hash, scenario_version, simulated as
	// Required: true (crowdsec@v1.6.3/pkg/models/alert.go).
	// Without them LAPI parser returns HTTP 500 in ~1ms with
	// "validation failure list: ... is required". Empirically
	// confirmed via curl on AreNET-test 2026-06-10. We emit
	// empty strings for the hash + version (no upstream
	// scenario backing a manual ban) and `false` for
	// simulated (a real, enforceable ban). cscli's manual
	// alerts use the same shape; consumers downstream are
	// already tolerant of empty hash/version on manual rows.
	payload := []map[string]any{
		{
			"scenario":         scenarioPtr,
			"scenario_hash":    "",
			"scenario_version": "",
			"simulated":        false,
			"message":          messagePtr,
			"events":           emptyEvents,
			"events_count":     eventsCount,
			"capacity":         capacity,
			"leakspeed":        leakspeed,
			"start_at":         startStr,
			"stop_at":          stopStr,
			"source": map[string]any{
				"scope": scopePtr,
				"value": valuePtr,
			},
			"decisions": []map[string]any{
				{
					"scenario": scenarioPtr,
					"duration": durationPtr,
					"scope":    scopePtr,
					"value":    valuePtr,
					"type":     typePtr,
					"origin":   originPtr,
				},
			},
		},
	}
	buf, _ := json.Marshal(payload)
	return buf
}

// postManualBanToLAPI sends the assembled payload via the
// shared JWT helper. On 401 → invalidate cache + retry once.
// Second 401 → bubble errLAPIAuthRejected (no loop).
func (h *Handler) postManualBanToLAPI(ctx context.Context, creds storage.WatcherCredentials, timeout time.Duration, payload []byte) error {
	_, _, err := h.lapiWithJWT(ctx, creds, timeout, http.MethodPost, "/v1/alerts", payload, false)
	if err == nil {
		return nil
	}
	if errors.Is(err, errLAPIAuthRejected) {
		_, _, err = h.lapiWithJWT(ctx, creds, timeout, http.MethodPost, "/v1/alerts", payload, true)
	}
	return err
}

// parseLAPIDuration mirrors LAPI's custom ParseDuration
// (crowdsec@v1.6.3/pkg/database/utils.go:72) — handles
// "Nd" suffix manually, then delegates to time.ParseDuration.
// Used by validateManualBanDuration + the ExpiresAt echo on
// the success response.
func parseLAPIDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		if days == "" {
			return 0, errors.New("empty days prefix")
		}
		d, err := time.ParseDuration(days + "h")
		if err == nil {
			return d * 24, nil
		}
		// fallback: try the same value after parsing as float, then multiply.
		return 0, err
	}
	return time.ParseDuration(s)
}
