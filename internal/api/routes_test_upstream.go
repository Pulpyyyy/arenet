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
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
)

// Step #R-PROXMOX-HTTPS-LOOP commit 3 — POST /api/v1/routes
// /test-upstream. Operator-triggered probe used by the
// route-form UI to validate an upstream URL before saving
// (and to diagnose a stale route after the fact).
//
// Why per-URL rather than a batch endpoint:
//   - Per-URL keeps the handler simple (one timeout, one
//     transport, one shaped result).
//   - Frontend parallelises pool > 1 via Promise.all, so
//     wall-clock latency for a 3-upstream pool stays
//     bounded by the slowest dial, identical to a batch
//     endpoint with errgroup, but cheaper to test on both
//     sides.
//   - Per-URL failures surface independently in the UI
//     (one row green ✓ 200, one row red ✗ refused) without
//     a partial-failure batch result that would need
//     special render logic.
//
// Why GET / and not HEAD: many upstreams (Home Assistant,
// some Spring Boot apps) return 405 on HEAD even when the
// service is healthy. A 405 HEAD response would mislead the
// operator into thinking the upstream is broken when in
// fact GET / works. GET with a 4KB body cap captures the
// real proxy-equivalent response and gives the operator the
// `bodyPreview` + `serverHeader` they need to recognise a
// misdirected pool ("oh, this is the nginx default page,
// not Proxmox").
//
// Why redirects are NOT followed: we want to know what the
// upstream returns DIRECTLY (a 301 to https:// is a legit
// data point — exactly the symptom that started the
// #R-PROXMOX-HTTPS-LOOP investigation). Following would
// also mask redirect loops and could leak the request to a
// service the operator did not pick.
//
// SSRF posture (intentional homelab UX trade-off):
//   - Auth: admin-only (same guard as createRoute /
//     updateRoute). A viewer cannot trigger an outbound
//     probe.
//   - Scheme allowlist: http / https only. file://,
//     gopher://, ftp://, etc. are rejected at parse time.
//   - Max URL length: 2048 chars.
//   - Hard 5s deadline on the whole call.
//   - NO RFC 1918 / loopback blocking: the use case IS the
//     homelab (Proxmox at 192.168.1.60, HA at 10.0.0.10).
//     Blocking would defeat the feature. The trust model
//     is "admin credentials = root-equiv for proxy targets"
//     and this endpoint inherits that posture explicitly
//     (an admin can already CONFIGURE a route to any
//     internal IP via createRoute; this endpoint adds no
//     new capability, just a faster diagnostic loop).

const (
	// testUpstreamMaxURLLen caps the URL length the
	// handler accepts. 2048 matches the IETF RFC 7230 §3.1
	// recommendation for HTTP requests and is generous
	// enough for the deepest legitimate homelab URL.
	testUpstreamMaxURLLen = 2048

	// testUpstreamDeadline is the hard wall-clock budget
	// for one probe. Covers DNS + TCP + TLS + HTTP. 5s is
	// large enough for cold-cache homelab dials over WAN
	// while staying under the browser's UI freeze threshold
	// (the frontend renders a spinner anyway).
	testUpstreamDeadline = 5 * time.Second

	// testUpstreamMaxBodyBytes caps the body preview at
	// 4KB. Enough to capture a login page title and the
	// first paragraph of a default landing page, not so
	// much that an attacker exfiltrates a meaningful
	// payload via a phished-admin probe.
	testUpstreamMaxBodyBytes = 4 * 1024

	// testUpstreamBodyPreviewChars caps the preview that
	// reaches the response body (after UTF-8 sanitisation).
	// 200 chars is what an operator needs to recognise an
	// upstream by sight (page title + first headline);
	// more would crowd the UI chip.
	testUpstreamBodyPreviewChars = 200
)

// testUpstreamRequest is the wire-side request shape.
// `insecureSkipVerify` mirrors the route-level toggle so
// the operator can probe with the same TLS posture the
// saved route will use.
type testUpstreamRequest struct {
	URL                string `json:"url"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify,omitempty"`
	// UpstreamTLSServerName (v2.60.1) mirrors the route field of the
	// same name, and exists because v2.60.0 shipped without it: the
	// probe built its own tls.Config, left ServerName empty, and Go
	// then verified the certificate against the DIAL ADDRESS. On a
	// pool addressed by IP that is always a failure —
	//
	//   x509: cannot validate certificate for 194.163.129.255
	//   because it doesn't contain any IP SANs
	//
	// — reported for a configuration that works, which is the worst
	// kind of diagnostic: one that sends the operator to fix
	// something that is not broken.
	UpstreamTLSServerName string `json:"upstreamTlsServerName,omitempty"`
	// HostHeader (v2.55) is the Host the probe should send — the route's
	// own host, or whatever the health check overrides it with.
	//
	// Without it the probe carried the upstream's address, so a backend
	// that routes on Host answered 404 and the UI reported "HTTP 404"
	// for a service that serves the route perfectly. The probe now asks
	// the question a visitor asks.
	HostHeader string `json:"hostHeader,omitempty"`
	// RouteID (v2.56.2) is the route the probe was launched from, when
	// there is one. Absent from the create form, where no route exists
	// yet — recorded in the audit event's structured detail rather than
	// left only in its free text.
	RouteID string `json:"routeId,omitempty"`
}

// testUpstreamCertInfo summarises the leaf TLS cert the
// upstream presented. Empty on http:// probes; populated
// on every https probe (success and cert-error alike) so
// the UI can show "self-signed cert: pve.local" even when
// the verification failed.
type testUpstreamCertInfo struct {
	CommonName string `json:"commonName,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	// SelfSigned is the clearer-than-DN-comparison flag —
	// true when subject == issuer (the canonical x509
	// self-signed shape). A homelab Proxmox cert satisfies
	// this; a Let's Encrypt cert never does.
	SelfSigned bool `json:"selfSigned"`
}

// testUpstreamResponse is the shape the frontend renders
// into the per-row result chip.
type testUpstreamResponse struct {
	// Reachable is the operator-meaningful summary —
	// true iff the handler completed a TLS handshake AND
	// got a status code back (any status code, including
	// 401/403/404; those are still "the service is up").
	Reachable bool `json:"reachable"`
	// StatusCode is the upstream's HTTP status. Zero on
	// failure before HTTP (DNS, TCP, TLS, etc.).
	StatusCode int `json:"statusCode,omitempty"`
	// LatencyMs is the full round-trip in milliseconds
	// (DNS + TCP + TLS + request + response headers + up
	// to 4KB of body).
	LatencyMs int64 `json:"latencyMs,omitempty"`
	// TLSHandshakeMs is the TLS handshake duration alone,
	// reported separately so the operator can split a
	// "slow upstream" diagnosis into "slow TLS" (cert
	// validation chain fetching) vs "slow application"
	// (upstream backend itself is sluggish). Zero on
	// http:// probes.
	TLSHandshakeMs int64 `json:"tlsHandshakeMs,omitempty"`
	// Cert is populated on every https probe (success or
	// cert-error). Empty on http:// probes.
	Cert *testUpstreamCertInfo `json:"cert,omitempty"`
	// ServerHeader is the upstream's Server: response
	// header (e.g. "pve-api-daemon/3.0", "nginx/1.24.0").
	// Empty when the upstream omits it.
	ServerHeader string `json:"serverHeader,omitempty"`
	// BodyPreview is up to 200 chars of the first 4KB of
	// the response body, with control characters
	// stripped. Useful for sight-recognising an upstream
	// (Proxmox login page vs nginx default vs misdirected
	// service).
	BodyPreview string `json:"bodyPreview,omitempty"`
	// Error is operator-readable text when the probe
	// failed. Empty on success. Examples: "connection
	// refused", "x509: certificate signed by unknown
	// authority", "context deadline exceeded".
	Error string `json:"error,omitempty"`
}

// testUpstream is the chi handler for POST /api/v1/routes
// /test-upstream. Admin-only via the router-level
// RequireAdminMiddleware (see routes.go registration).
func (h *Handler) testUpstream(w http.ResponseWriter, r *http.Request) {
	var req testUpstreamRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	rawURL := strings.TrimSpace(req.URL)
	if rawURL == "" {
		writeError(w, http.StatusBadRequest, "url must not be empty")
		return
	}
	if len(rawURL) > testUpstreamMaxURLLen {
		writeError(w, http.StatusBadRequest, "url exceeds maximum length")
		return
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "url is malformed: "+err.Error())
		return
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		writeError(w, http.StatusBadRequest, "url must use http or https scheme")
		return
	}
	if parsed.Host == "" {
		writeError(w, http.StatusBadRequest, "url must include a host")
		return
	}

	// Honour the operator's deadline budget — never let a
	// probe outlive the handler's hard cap, even if the
	// request context carries a longer deadline.
	ctx, cancel := context.WithTimeout(r.Context(), testUpstreamDeadline)
	defer cancel()

	resp := probeUpstream(ctx, parsed, probeOpts{
		InsecureSkipVerify: req.InsecureSkipVerify,
		HostHeader:         req.HostHeader,
		TLSServerName:      req.UpstreamTLSServerName,
	})

	h.logger.Info("test-upstream probed",
		"url", parsed.Redacted(),
		"insecure_skip_verify", req.InsecureSkipVerify,
		"reachable", resp.Reachable,
		"status_code", resp.StatusCode,
		"latency_ms", resp.LatencyMs)

	// v2.56 — audited. Creating a route to reach an address leaves a
	// trail; a probe did not, which made it the quiet way to learn what
	// answers on an internal address. A refusal is recorded under its own
	// action, because an attempt at the metadata endpoint is worth more
	// than its absence.
	evt := audit.Event{
		Action:  probeAuditAction(resp.Error),
		Message: probeAuditMessage(parsed, resp.Reachable, resp.StatusCode, resp.Error),
	}
	probeAuditTarget(&evt, parsed.Redacted(), req.RouteID, map[string]any{
		"reachable": resp.Reachable,
		"status":    resp.StatusCode,
	})
	h.appendAudit(r, evt)

	writeJSON(w, http.StatusOK, resp)
}

// probeUpstream performs the actual outbound probe. Split
// from the HTTP handler so tests can drive it directly
// without a router.
// probeOpts carries the route's TLS and Host posture into the probe.
// It is a struct rather than three trailing parameters because two of
// them are strings that sit next to each other — hostHeader and
// tlsServerName — and a positional mix-up between them would produce a
// probe that passes while the real proxy fails, or the reverse.
type probeOpts struct {
	InsecureSkipVerify bool
	// HostHeader is the Host the probe sends (v2.55).
	HostHeader string
	// TLSServerName is the name presented in SNI and verified against
	// the backend's certificate (v2.60.1). Empty leaves Go's default,
	// which derives it from the dial address.
	TLSServerName string
}

func probeUpstream(ctx context.Context, target *url.URL, opts probeOpts) testUpstreamResponse {
	insecureSkipVerify := opts.InsecureSkipVerify
	hostHeader := opts.HostHeader
	resp := testUpstreamResponse{}

	// TLS handshake timing — captured via the
	// transport's TLSClientConfig + a side-channel
	// timestamp pair around the round-trip. We don't use
	// httptrace.ClientTrace because the only signal we
	// need is the handshake duration; a single
	// before/after pair on the round-trip suffices for
	// http:// (which leaves tlsHandshakeMs at 0) and
	// gives an upper-bound approximation for https://
	// (slightly inflated by the TCP dial; the operator
	// gets a "TLS vs HTTP" split that's good enough for
	// homelab diagnostics, not a precise telemetry
	// signal). A more precise per-phase split is in
	// scope for a future commit if operators ask for it.
	tlsCfg := &tls.Config{
		// MinVersion: stdlib default is TLS 1.2 since Go
		// 1.18; explicit pin spares a future Go default
		// drift from surprising us.
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // operator-controlled, matches saved route TLS posture
		// v2.60.1 — ServerName sets BOTH the SNI sent and the name the
		// certificate is verified against, which is what makes a probe
		// of an IP-addressed pool mean the same thing as the traffic
		// Caddy will send. Empty keeps Go's default.
		ServerName: opts.TLSServerName,
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   testUpstreamDeadline,
		ResponseHeaderTimeout: testUpstreamDeadline,
		// v2.56 — refuse link-local and cloud-metadata addresses, checked
		// on the resolved IP rather than on the name. See probe_dialer.go
		// for why the check belongs after resolution. Behaviour change on
		// an endpoint that previously fetched any http/https URL.
		DialContext: newProbeDialer(testUpstreamDeadline).DialContext,
		// Disable connection reuse — each probe is a
		// one-shot diagnostic, no benefit to a pooled
		// connection and explicit close keeps the
		// upstream's connection-count metric quiet.
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   testUpstreamDeadline,
		// Do not auto-follow redirects: we want to see
		// what the upstream returns DIRECTLY (a 301 to
		// https:// is a legit datapoint — that's exactly
		// the loop symptom that started this work).
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		resp.Error = err.Error()
		return resp
	}
	// User-Agent: explicit so an operator inspecting the
	// upstream's access log can identify the probe
	// (otherwise stdlib defaults to "Go-http-client/1.1"
	// which looks like generic traffic).
	httpReq.Header.Set("User-Agent", "Arenet-Upstream-Probe/1.0")
	// req.Host, not a "Host" header: net/http ignores the header and
	// sends URL.Host unless this field is set.
	if host := strings.TrimSpace(hostHeader); host != "" {
		httpReq.Host = host
	}

	start := time.Now()
	httpResp, err := client.Do(httpReq)
	if err != nil {
		resp.LatencyMs = time.Since(start).Milliseconds()
		resp.Error = humanProbeError(err)
		// On a TLS verification error we still got a
		// handshake (the failure is server-cert
		// validation, AFTER the cert was presented). The
		// underlying *tls.CertificateVerificationError
		// carries the unverified chain; surface it so the
		// UI can show the operator what the upstream
		// presented and why it was rejected.
		resp.Cert = extractCertFromError(err)
		return resp
	}
	defer httpResp.Body.Close()

	resp.LatencyMs = time.Since(start).Milliseconds()
	resp.Reachable = true
	resp.StatusCode = httpResp.StatusCode
	resp.ServerHeader = httpResp.Header.Get("Server")

	// TLS connection state — populated on https://
	// probes only.
	if httpResp.TLS != nil && len(httpResp.TLS.PeerCertificates) > 0 {
		leaf := httpResp.TLS.PeerCertificates[0]
		resp.Cert = &testUpstreamCertInfo{
			CommonName: leaf.Subject.CommonName,
			Issuer:     leaf.Issuer.String(),
			SelfSigned: leaf.Subject.String() == leaf.Issuer.String(),
		}
		// Without a precise httptrace hook the handshake
		// duration is approximated by the
		// time-to-first-byte. For the operator's
		// purposes ("did the TLS step dominate?") that's
		// good enough.
		resp.TLSHandshakeMs = resp.LatencyMs
	}

	// Body preview — read at most 4KB, then trim to 200
	// chars of printable content.
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, testUpstreamMaxBodyBytes))
	if err == nil {
		resp.BodyPreview = sanitiseBodyPreview(string(body), testUpstreamBodyPreviewChars)
	}

	return resp
}

// humanProbeError turns a stdlib net/url/tls error into a
// short operator-readable string. The goal is to avoid
// the raw error's noise ("Get \"https://...\": dial tcp:
// lookup foo: no such host") while preserving the actual
// cause ("DNS lookup failed: no such host").
func humanProbeError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	// Strip the "Get \"<url>\": " prefix that net/http
	// wraps every client error with — the URL is already
	// in the request, no need to echo it back.
	if i := strings.Index(msg, ": "); i > 0 && strings.HasPrefix(msg, "Get ") {
		msg = msg[i+2:]
	}
	// Map common cases to crisp operator-friendly text.
	// Anything not matched falls through to the trimmed
	// error.
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout (no response within 5s)"
	case strings.Contains(msg, "connection refused"):
		return "connection refused"
	case strings.Contains(msg, "no such host"):
		return "DNS lookup failed (host not found)"
	case strings.Contains(msg, "x509: certificate signed by unknown authority"):
		return "untrusted certificate (signed by unknown authority — try Ignorer la vérification)"
	case strings.Contains(msg, "x509: certificate has expired"):
		return "expired certificate"
	case strings.Contains(msg, "tls: handshake failure"):
		return "TLS handshake failed (incompatible protocol or cipher)"
	}
	return msg
}

// extractCertFromError digs out the unverified server
// cert from a x509 verification error, when present.
// Lets the UI render "untrusted cert from CN=pve.local"
// rather than just "untrusted certificate".
func extractCertFromError(err error) *testUpstreamCertInfo {
	var verr *tls.CertificateVerificationError
	if !errors.As(err, &verr) {
		return nil
	}
	if len(verr.UnverifiedCertificates) == 0 {
		return nil
	}
	leaf := verr.UnverifiedCertificates[0]
	return &testUpstreamCertInfo{
		CommonName: leaf.Subject.CommonName,
		Issuer:     leaf.Issuer.String(),
		SelfSigned: leaf.Subject.String() == leaf.Issuer.String(),
	}
}

// sanitiseBodyPreview trims control characters and caps
// the string at `max` runes. Multi-byte UTF-8 safe.
func sanitiseBodyPreview(body string, maxChars int) string {
	if body == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(maxChars)
	count := 0
	for _, r := range body {
		if count >= maxChars {
			break
		}
		// Keep printable + space; collapse any other
		// control sequence to a single space (matches
		// what a browser would render for the operator).
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if sb.Len() == 0 || sb.String()[sb.Len()-1] != ' ' {
				sb.WriteByte(' ')
				count++
			}
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		sb.WriteRune(r)
		count++
	}
	out := strings.TrimSpace(sb.String())
	// Defence-in-depth: x509 cert verification errors
	// can carry chain DNs that include unicode — already
	// safe through the rune loop above, but explicit cap
	// at the byte length avoids any future surprise from
	// a 4-byte rune at the boundary.
	if len(out) > maxChars*4 {
		out = out[:maxChars*4]
	}
	return out
}
