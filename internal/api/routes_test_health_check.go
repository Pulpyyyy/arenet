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
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.56 — run the active health check before saving it.
//
// A misconfigured check used to surface only on save: the post-change
// verification saw the upstream go down, got a 503 and undid the change
// ("Change undone…"), which protected the site and explained nothing.
//
// The reported case: a probe against Ghost with no X-Forwarded-Proto, so
// Ghost answered 301 to its https URL, the expected 200 never arrived, the
// upstream was removed from the pool and the route served 503.
//
// This endpoint runs ONE probe per upstream with the settings currently in
// the form, and reports what was sent and what came back. It writes
// nothing and reloads nothing — the point is to find out before committing.

const (
	// healthProbeDeadline caps one probe regardless of the timeout typed
	// in the form. A diagnostic that can hang for the operator's 60s
	// budget is a diagnostic nobody presses twice.
	healthProbeDeadline = 10 * time.Second
	// healthProbeBodyLimit is how much body is read back for the excerpt
	// and the regex. Caddy reads the whole body when max_size is 0, which
	// is what Arenet emits; a test does not need megabytes to tell the
	// operator what came back.
	healthProbeBodyLimit = 4096
	// healthProbeMaxUpstreams bounds one request. A pool larger than this
	// is not a health-check problem.
	healthProbeMaxUpstreams = 20
)

// healthProbeRequest carries the UNSAVED form state.
//
// The two nested shapes are the API's own wire types, NOT the storage
// structs. That distinction is the whole bug this shape was fixed for:
// storage.HealthCheck tags its fields snake_case (expect_status,
// expect_body, host_header) while every route endpoint — and therefore the
// form — speaks camelCase. Decoding the storage struct with
// DisallowUnknownFields made the button answer `unknown field
// "expectStatus"` on its first real click.
//
// Reusing healthCheckReq means the test endpoint cannot drift from the
// shape createRoute and updateRoute accept, because it is the same type.
type healthProbeRequest struct {
	// Upstreams is the pool as currently typed. The probe targets these,
	// not what is stored — testing a changed upstream is half the reason
	// the button exists.
	Upstreams []upstreamReq `json:"upstreams"`
	// HealthCheck is the check as currently typed, including its probe
	// Host and headers.
	HealthCheck healthCheckReq `json:"healthCheck"`
	// RouteHost is the route's primary host, used as the probe's Host
	// unless the check overrides it — the same resolution the emitted
	// config uses.
	RouteHost string `json:"routeHost"`
	// InsecureSkipVerify mirrors the route's TLS posture so an https
	// upstream with a self-signed certificate is testable.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
	// UpstreamTLSServerName (v2.60.1) mirrors the route field, for the
	// same reason as on the upstream probe: without it Go verifies the
	// certificate against the dial address, so a pool addressed by IP
	// always failed the probe while the emitted config worked.
	UpstreamTLSServerName string `json:"upstreamTlsServerName,omitempty"`
	// RouteID (v2.56.2) is the route the probe was launched from, when
	// there is one. Absent from the create form, where no route exists
	// yet.
	RouteID string `json:"routeId,omitempty"`
}

// healthProbeSentInfo is what went out, so the operator can see the
// request rather than infer it.
type healthProbeSentInfo struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers,omitempty"`
}

// healthProbeGotInfo is what came back.
type healthProbeGotInfo struct {
	StatusCode int   `json:"statusCode"`
	DurationMs int64 `json:"durationMs"`
	// Location is the redirect target, when there is one. Surfaced on its
	// own because a 3xx is the failure this endpoint exists to explain.
	Location string `json:"location,omitempty"`
	// BodyExcerpt is the first healthProbeBodyLimit bytes.
	BodyExcerpt   string `json:"bodyExcerpt,omitempty"`
	BodyTruncated bool   `json:"bodyTruncated"`
	// BodyMatched is nil when no expect_body was configured, so the UI can
	// tell "no regex" from "regex did not match".
	BodyMatched *bool `json:"bodyMatched,omitempty"`
}

// healthProbeResult is one upstream's verdict.
type healthProbeResult struct {
	// Upstream is the dial address probed, as the emitted config would
	// write it.
	Upstream string `json:"upstream"`
	Healthy  bool   `json:"healthy"`
	// Reason names the precise cause when Healthy is false: an unexpected
	// status, a body that did not match, a timeout, a refused connection,
	// a DNS or TLS failure.
	Reason string              `json:"reason,omitempty"`
	Sent   healthProbeSentInfo `json:"sent"`
	Got    *healthProbeGotInfo `json:"got,omitempty"`
	// Hint is attached only to an observed redirect that points at the
	// same URL over https, which is what an application expecting
	// X-Forwarded-Proto does.
	Hint string `json:"hint,omitempty"`
}

type healthProbeResponse struct {
	Results []healthProbeResult `json:"results"`
}

// testHealthCheck (POST /routes/test-health-check) runs the active check
// against every upstream in the submitted pool.
//
// Admin-only through the router's sub-group, same posture as createRoute:
// this reaches out to an address the request names. The probe dialer
// refuses link-local and cloud-metadata addresses (probe_dialer.go), and
// every probe is audited.
func (h *Handler) testHealthCheck(w http.ResponseWriter, r *http.Request) {
	var req healthProbeRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	if len(req.Upstreams) == 0 {
		writeError(w, http.StatusBadRequest, "at least one upstream is required")
		return
	}
	if len(req.Upstreams) > healthProbeMaxUpstreams {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("at most %d upstreams can be probed at once", healthProbeMaxUpstreams))
		return
	}

	hc := storage.HealthCheck{
		Enabled:      req.HealthCheck.Enabled,
		URI:          req.HealthCheck.URI,
		Method:       req.HealthCheck.Method,
		Interval:     req.HealthCheck.Interval,
		Timeout:      req.HealthCheck.Timeout,
		ExpectStatus: req.HealthCheck.ExpectStatus,
		ExpectBody:   req.HealthCheck.ExpectBody,
		Passes:       req.HealthCheck.Passes,
		Fails:        req.HealthCheck.Fails,
		HostHeader:   req.HealthCheck.HostHeader,
		Headers:      req.HealthCheck.Headers,
	}
	if !hc.Enabled {
		writeError(w, http.StatusBadRequest, "the health check must be enabled to test it")
		return
	}
	if strings.TrimSpace(hc.URI) == "" {
		writeError(w, http.StatusBadRequest, "healthCheck.uri is required")
		return
	}
	if err := storage.ValidateExpectStatus("healthCheck.expectStatus", hc.ExpectStatus); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The regex is compiled BEFORE any probe goes out: a typo in it is the
	// operator's mistake to hear about immediately, not after ten seconds
	// of waiting on an upstream that was never the problem.
	var bodyRe *regexp.Regexp
	if hc.ExpectBody != "" {
		var err error
		bodyRe, err = regexp.Compile(hc.ExpectBody)
		if err != nil {
			writeError(w, http.StatusBadRequest,
				"healthCheck.expectBody is not a valid regular expression: "+err.Error())
			return
		}
	}

	timeout := healthProbeTimeout(hc.Timeout)
	results := make([]healthProbeResult, 0, len(req.Upstreams))
	for _, up := range req.Upstreams {
		results = append(results, probeHealthCheck(
			r, storage.Upstream{URL: up.URL, Weight: up.Weight}, req, hc, bodyRe, timeout))
	}

	refused := 0
	for _, res := range results {
		if strings.Contains(res.Reason, blockedProbeAuditMarker) {
			refused++
		}
	}
	action := audit.ActionProbeHealthCheck
	if refused > 0 {
		action = audit.ActionProbeRefused
	}
	evt := audit.Event{
		Action:  action,
		Message: healthProbeAuditMessage(results),
	}
	probed := make([]string, 0, len(results))
	healthy := 0
	for _, res := range results {
		probed = append(probed, res.Upstream)
		if res.Healthy {
			healthy++
		}
	}
	probeAuditTarget(&evt, strings.Join(probed, ","), req.RouteID, map[string]any{
		"probed":  len(results),
		"healthy": healthy,
	})
	h.appendAudit(r, evt)

	writeJSON(w, http.StatusOK, healthProbeResponse{Results: results})
}

// healthProbeTimeout parses the form's timeout and caps it.
//
// A value the emitted config would accept can still be longer than anyone
// wants to wait on a button, so the cap applies even when the entered
// value is legal.
func healthProbeTimeout(raw string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d <= 0 {
		return healthProbeDeadline
	}
	if d > healthProbeDeadline {
		return healthProbeDeadline
	}
	return d
}

// probeHealthCheck runs one probe, built the way Caddy builds its own.
//
// Fidelity, each point read in caddy v2.11.3
// modules/caddyhttp/reverseproxy:
//
//   - the URL is the DIAL address plus the check's URI, not the upstream's
//     path (healthchecks.go:393-422);
//   - the scheme is http unless the transport speaks TLS, in which case
//     https (httptransport.go:608-612);
//   - req.Host comes from a configured Host header and nothing else
//     (healthchecks.go:452-455) — Arenet now always configures one;
//   - expect_status 0 means "any 2xx", otherwise StatusCodeMatches, which
//     accepts a class shorthand (healthchecks.go:531-542);
//   - expect_body is a regexp over the body (healthchecks.go:553-573).
//
// Redirects are deliberately not followed: Caddy's FollowRedirects
// defaults to false and Arenet emits no override, so a check that meets a
// 301 fails — which is exactly the case being diagnosed.
func probeHealthCheck(
	r *http.Request,
	up storage.Upstream,
	req healthProbeRequest,
	hc storage.HealthCheck,
	bodyRe *regexp.Regexp,
	timeout time.Duration,
) healthProbeResult {
	dial, err := upstreamDialForProbe(up)
	if err != nil {
		return healthProbeResult{
			Upstream: up.URL,
			Reason:   "the upstream URL could not be read: " + err.Error(),
		}
	}

	scheme := "http"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(up.URL)), "https://") {
		scheme = "https"
	}
	uri := hc.URI
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	target := scheme + "://" + dial + uri

	probeHost := hc.ProbeHost(req.RouteHost)
	res := healthProbeResult{
		Upstream: dial,
		Sent: healthProbeSentInfo{
			Method:  probeMethod(hc.Method),
			URL:     target,
			Host:    probeHost,
			Headers: hc.Headers,
		},
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, res.Sent.Method, target, nil)
	if err != nil {
		res.Reason = "the probe request could not be built: " + err.Error()
		return res
	}
	if probeHost != "" {
		httpReq.Host = probeHost
	}
	for name, value := range hc.Headers {
		httpReq.Header.Set(name, value)
	}

	transport := &http.Transport{
		DialContext: newProbeDialer(timeout).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: req.InsecureSkipVerify, //nolint:gosec // mirrors the route's saved TLS posture
			// v2.60.1 — the name the certificate is verified against,
			// so the probe asks the question the emitted config asks.
			ServerName: req.UpstreamTLSServerName,
		},
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// Not followed, because the real check does not follow either.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	elapsed := time.Since(start)
	if err != nil {
		res.Reason = humanProbeFailure(err)
		return res
	}
	defer resp.Body.Close()

	body, truncated := readBodyExcerpt(resp.Body)
	got := &healthProbeGotInfo{
		StatusCode:    resp.StatusCode,
		DurationMs:    elapsed.Milliseconds(),
		Location:      resp.Header.Get("Location"),
		BodyExcerpt:   string(body),
		BodyTruncated: truncated,
	}
	res.Got = got

	if !statusAccepted(resp.StatusCode, hc.ExpectStatus) {
		res.Reason = describeStatusMismatch(resp.StatusCode, hc.ExpectStatus)
		res.Hint = redirectHint(target, got.Location, resp.StatusCode)
		return res
	}
	if bodyRe != nil {
		matched := bodyRe.Match(body)
		got.BodyMatched = &matched
		if !matched {
			res.Reason = fmt.Sprintf(
				"the response body does not match %q — the excerpt below is what was tested", hc.ExpectBody)
			return res
		}
	}
	res.Healthy = true
	res.Hint = redirectHint(target, got.Location, resp.StatusCode)
	return res
}

// upstreamDialForProbe derives the dial address the emitted config would
// use, so the probe targets exactly what the real check targets.
//
// Mirrors caddymgr.upstreamDial (manager.go:3860-3881), including the
// default port per scheme. Duplicated rather than exported because the
// emitter's copy is the contract for the running config and this one only
// has to agree with it; a shared helper would put a diagnostic and the
// data plane on the same code path for no gain.
func upstreamDialForProbe(up storage.Upstream) (string, error) {
	raw := strings.TrimSpace(up.URL)
	if raw == "" {
		return "", errors.New("the upstream URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q has no host", raw)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		switch strings.ToLower(u.Scheme) {
		case "https":
			host += ":443"
		default:
			host += ":80"
		}
	}
	return host, nil
}

// probeMethod defaults the method the way the emitted config does.
func probeMethod(method string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		return http.MethodGet
	}
	return m
}

// statusAccepted mirrors Caddy's own comparison: 0 means any 2xx, and a
// value below 100 is a class shorthand.
func statusAccepted(got, expect int) bool {
	if expect == 0 {
		return got >= 200 && got < 300
	}
	if got == expect {
		return true
	}
	if expect < 100 && got >= expect*100 && got < (expect+1)*100 {
		return true
	}
	return false
}

func describeStatusMismatch(got, expect int) string {
	switch {
	case expect == 0:
		return fmt.Sprintf("the upstream answered %d; the check accepts any 2xx", got)
	case expect < 100:
		return fmt.Sprintf("the upstream answered %d; the check accepts any %dxx", got, expect)
	default:
		return fmt.Sprintf("the upstream answered %d; the check expects %d", got, expect)
	}
}

// redirectHint explains a redirect that points back at the same URL over
// https, which is what an application deciding it was reached insecurely
// does. Empty for every other case, including a redirect elsewhere.
func redirectHint(target, location string, status int) string {
	if status < 300 || status > 399 || location == "" {
		return ""
	}
	sent, err := url.Parse(target)
	if err != nil {
		return ""
	}
	to, err := url.Parse(location)
	if err != nil {
		return ""
	}
	// A relative Location cannot be an http→https upgrade.
	if to.Scheme != "https" || sent.Scheme != "http" {
		return fmt.Sprintf("the upstream redirected to %s, and the check does not follow redirects", location)
	}
	sameTarget := to.Path == sent.Path && (to.Host == sent.Host || to.Host == sent.Hostname())
	if !sameTarget {
		return fmt.Sprintf("the upstream redirected to %s, and the check does not follow redirects", location)
	}
	return "the upstream redirected to the same URL over https, which an application does when it " +
		"decides the request arrived insecurely — such an application usually wants the " +
		"X-Forwarded-Proto: https header"
}

// readBodyExcerpt reads at most healthProbeBodyLimit bytes and reports
// whether more was there.
func readBodyExcerpt(body io.Reader) ([]byte, bool) {
	buf, err := io.ReadAll(io.LimitReader(body, healthProbeBodyLimit+1))
	if err != nil && len(buf) == 0 {
		return nil, false
	}
	if len(buf) > healthProbeBodyLimit {
		return buf[:healthProbeBodyLimit], true
	}
	return buf, false
}

// humanProbeFailure turns a transport error into the precise cause the
// operator needs, keeping the refusal marker recognisable so the audit
// action can be chosen from it.
func humanProbeFailure(err error) string {
	if errors.Is(err, errBlockedProbeTarget) {
		return err.Error()
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "the probe timed out before the upstream answered"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "the upstream's name could not be resolved: " + dnsErr.Err
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, errBlockedProbeTarget) {
			return opErr.Err.Error()
		}
		return "the connection failed: " + opErr.Err.Error()
	}
	if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls:") {
		return "the TLS handshake failed: " + err.Error()
	}
	return err.Error()
}

// healthProbeAuditMessage records what was probed and how it went.
func healthProbeAuditMessage(results []healthProbeResult) string {
	parts := make([]string, 0, len(results))
	for _, res := range results {
		status := 0
		if res.Got != nil {
			status = res.Got.StatusCode
		}
		parts = append(parts, fmt.Sprintf("%s healthy=%t status=%d", res.Upstream, res.Healthy, status))
	}
	return truncate(strings.Join(parts, "; "), 400)
}
