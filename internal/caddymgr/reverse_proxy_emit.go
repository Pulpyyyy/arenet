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

package caddymgr

import (
	"fmt"

	"github.com/barto95100/arenet/internal/storage"
)

// proxyPoolParams carries the PER-POOL inputs (a route's pool, or later a
// per-path pool) to the reverse_proxy builder. Route-invariant concerns
// (the error-branding handle_response, the flush_interval toggle) are
// supplied by the caller as explicit arguments so the same builder emits
// byte-identical JSON regardless of which pool it renders.
type proxyPoolParams struct {
	// Upstreams is the dial pool in declaration order. Each URL is
	// resolved via upstreamDial; a malformed URL fails the whole build.
	Upstreams []storage.Upstream
	// LBPolicy is the load_balancing.selection_policy.policy value. For
	// weighted_round_robin the pool's weights are emitted in order.
	LBPolicy string
	// HealthCheck, when non-nil AND Enabled, emits health_checks.active.
	// nil (or a disabled check) omits the whole health_checks key.
	HealthCheck *storage.HealthCheck
	// ProbeHost is the route's primary host, used as the probe's Host
	// header unless the check overrides it (v2.55).
	//
	// Caddy builds the probe URL from the DIAL address, so without this
	// the request carries `Host: 10.0.0.2:80`. Any backend that routes
	// on Host — a second reverse proxy, a vhost, a container router —
	// answers 404 and every upstream is marked down while being
	// perfectly healthy.
	ProbeHost string
	// UsesHTTPS drives the transport.tls emission (Caddy speaks TLS to
	// the upstream). Mirrors Route.PoolUsesHTTPS().
	UsesHTTPS bool
	// InsecureSkipVerify sets transport.tls.insecure_skip_verify. Only
	// consulted when UsesHTTPS is true.
	InsecureSkipVerify bool
}

// probeHeaders builds health_checks.active.headers.
//
// The Host comes first in intent though not in the map: the operator's
// override if there is one, otherwise the route's own host, so the probe
// carries what the real traffic carries. An empty host (no route host
// and no override) emits nothing for it, leaving Caddy's dial-address
// behaviour exactly as it was.
func probeHeaders(hc *storage.HealthCheck, routeHost string) map[string][]string {
	out := make(map[string][]string, len(hc.Headers)+1)
	if host := hc.ProbeHost(routeHost); host != "" {
		out["Host"] = []string{host}
	}
	for name, value := range hc.Headers {
		// Host is refused by storage validation, so it cannot land here
		// and quietly outrank the field that owns it.
		out[name] = []string{value}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// errorBrandingStatusCodes is the shared status-code list consumed by
// both handle_response blocks. 401 + 407 are deliberately absent so
// their upstream Www-Authenticate / Proxy-Authenticate challenge headers
// reach the client verbatim (the 2026-06-24 Harbor / Docker registry
// fix). Declared once (DRY) and referenced by both blocks.
//
// It returns a fresh slice on each call so callers may not accidentally
// share (and mutate) a package-level backing array.
func errorBrandingStatusCodes() []int {
	return []int{
		// 4xx (except 401 + 407)
		400, 402, 403, 404, 405, 406, 408, 409, 410,
		411, 412, 413, 414, 415, 416, 417, 418, 421,
		422, 423, 424, 425, 426, 428, 429, 431, 451,
		// 5xx (full range)
		500, 501, 502, 503, 504, 505, 506, 507, 508,
		510, 511,
	}
}

// buildErrorBrandingHandleResponse builds the two-block handle_response
// structure that intercepts upstream 4xx/5xx responses and either passes
// them through verbatim (JSON errors, /api/* responses) or serves the
// branded Arenet error page.
//
// Step R Phase 1.1 — upstream 4xx/5xx catch. Without this, an upstream
// returning 404 or 502 (Proxmox 404 on a missing API path; Jellyfin 502
// on a media-server restart) streams the upstream's raw body straight to
// the client. The server's apps.http.servers.<*>.errors.routes chain
// only fires on Caddy-generated HandlerErrors (verified empirically
// against caddy v2.11.3 modules/caddyhttp/server.go:421-423 — the err
// arg is the return of s.serveHTTP, not the upstream status;
// reverseproxy.go:1229 writes res.StatusCode silently in
// finalizeResponse). A handle_response with a ResponseMatcher on the
// status list re-emits the upstream status as an http.handlers.error,
// which propagates as the wrapped roundtripSucceededError
// (reverseproxy.go:1165) — that one IS a HandlerError, so it triggers
// the server's errors chain like a native Caddy error. The
// {http.reverse_proxy.status_code} placeholder is set at
// reverseproxy.go:1081 BEFORE handle_response evaluates, so it carries
// the upstream's literal status into the error handler. No buffering is
// needed: handle_response evaluates on headers, and the upstream body is
// closed unconsumed if the route doesn't read it — critical for
// streaming routes (Jellyfin video, large downloads).
//
// 2026-06-24 Harbor / Docker registry fix — a wildcard [4,5] intercept
// converted EVERY upstream 4xx/5xx into a Caddy HandlerError, whose
// branded HTML body REPLACED the upstream's response headers, including
// Www-Authenticate (401) and Proxy-Authenticate (407) that transport the
// auth challenge the client needs to retry. So errorBrandingStatusCodes
// enumerates the include list (Caddy v2's ResponseMatcher has no `not`
// block — verified against responsematchers.go) and omits 401 + 407. The
// branded 401 body remains available for Arenet's OWN auth handlers
// (BasicAuth / ForwardAuth gates that reject BEFORE reverse_proxy);
// those 401s dispatch via apps.http.servers.<srv>.errors directly and
// never traverse this block.
//
// Preserve-JSON contract (fix/error-template-preserve-json): the branded
// HTML error page must NOT replace a proxied upstream's JSON / API error
// responses. Caddy evaluates handle_response entries in order and stops
// at the FIRST whose OUTER match passes, then runs THAT block's inner
// routes to completion (reverseproxy.go:1113-1173). A status-only outer
// block "wins" for every error, so its inner routes must handle EVERY
// case — an inner route that matches nothing drops the response (200,
// empty body). The /api decision and the branding fallback therefore
// live in the SAME block's inner routes with fall-through, not two
// separate status-only outer blocks.
//
// The two blocks:
//
//	B (first) — outer match = status AND Content-Type application/json*
//	  → copy_response. A JSON error of ANY path is sent verbatim.
//	  ("*" covers "; charset=utf-8".)
//	A/C (second) — outer match = status only; inner routes, in order:
//	  [path /api/* → copy_response] then [→ error]. A non-JSON /api
//	  response is copied verbatim; everything else falls through to the
//	  branded error handler.
func buildErrorBrandingHandleResponse(errorStatusCodes []int) []map[string]any {
	return []map[string]any{
		{ // B — application/json* response pass-through (any path)
			"match": map[string]any{
				"status_code": errorStatusCodes,
				"headers":     map[string]any{"Content-Type": []string{"application/json*"}},
			},
			"routes": []map[string]any{
				{
					"handle": []map[string]any{{"handler": "copy_response"}},
				},
			},
		},
		{ // A/C — /api/* pass-through, else branding (fall-through)
			"match": map[string]any{"status_code": errorStatusCodes},
			"routes": []map[string]any{
				{ // A: non-JSON /api response → verbatim
					"match":  []map[string]any{{"path": []string{"/api/*"}}},
					"handle": []map[string]any{{"handler": "copy_response"}},
				},
				{ // C: everything else → branded error page
					"handle": []map[string]any{
						{
							"handler":     "error",
							"status_code": "{http.reverse_proxy.status_code}",
						},
					},
				},
			},
		},
	}
}

// buildReverseProxyHandler assembles the full reverse_proxy handler map
// for one upstream pool: upstreams + load_balancing (+ weights for
// weighted_round_robin) + the Host-preserving request header +
// transport.tls-if-https + flush_interval-if-set + health_checks-if-
// enabled + the shared error-branding handle_response.
//
// It is the single source of truth for the reverse_proxy JSON shape.
// buildConfigJSON calls it once per route; the per-path-upstream feature
// (Task 4) calls it per path with a different pool, guaranteeing the two
// surfaces never drift. The emission is behaviour-preserving: a route
// without per-path upstreams emits byte-identical JSON to the previous
// inline construction (guarded by TestBuildReverseProxyHandler_
// RouteEmissionByteIdentical).
func buildReverseProxyHandler(p proxyPoolParams, sharedHandleResponse []map[string]any, flushInterval bool) (map[string]any, error) {
	// Build the upstream pool by dialing each Upstream in declaration
	// order. A one-element pool collapses to the same shape Step I
	// emitted, plus a load_balancing block (selection moot but valid).
	// Reject the whole build if any single upstream URL is malformed.
	upstreamsJSON := make([]map[string]any, 0, len(p.Upstreams))
	for i, u := range p.Upstreams {
		dial, err := upstreamDial(u.URL)
		if err != nil {
			return nil, fmt.Errorf("upstreams[%d]: %w", i, err)
		}
		upstreamsJSON = append(upstreamsJSON, map[string]any{"dial": dial})
	}

	// Emit load_balancing.selection_policy unconditionally when at least
	// one upstream is present. The policy is harmless on a one-element
	// pool ("selection is moot but valid"). For weighted_round_robin we
	// also emit the `weights` array in pool order; other policies need
	// no extra fields.
	selectionPolicy := map[string]any{"policy": p.LBPolicy}
	if p.LBPolicy == storage.LBPolicyWeightedRoundRobin {
		weights := make([]int, 0, len(p.Upstreams))
		for _, u := range p.Upstreams {
			weights = append(weights, u.Weight)
		}
		selectionPolicy["weights"] = weights
	}

	proxyHandler := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": upstreamsJSON,
		"load_balancing": map[string]any{
			"selection_policy": selectionPolicy,
		},
		// Preserve the original client Host header on the upstream
		// request. Caddy's default replaces it with the upstream URL's
		// host, which breaks every backend that builds absolute URLs
		// from Host (IdPs like authentik / Keycloak / Authelia
		// constructing their OIDC discovery doc, multi-tenant SaaS
		// dispatching by Host, single-page apps generating canonical
		// URLs, ...). Traefik and nginx both preserve Host by default —
		// Arenet aligns with the industry convention here.
		//
		// {http.request.host} is the Caddy placeholder for the
		// request's Host header (after the listener's matcher binding
		// but before any rewrites). The X-Forwarded-* trio is already
		// injected by Caddy's reverse_proxy (verified empirically
		// against caddyserver/caddy/v2@v2.11.3 reverseproxy.go:835) so
		// they don't need explicit wiring here.
		"headers": map[string]any{
			"request": map[string]any{
				"set": map[string][]string{
					"Host": {"{http.request.host}"},
				},
			},
		},
	}

	// #R-PROXMOX-HTTPS-LOOP (2026-06-10) — emit transport.tls when the
	// upstream pool is HTTPS. Caddy's reverse_proxy transport is
	// per-handler, not per-upstream, so the pool-level UsesHTTPS
	// predicate is the right discriminant (the storage validator
	// guarantees a same-scheme pool). When InsecureSkipVerify is true,
	// the tls block carries "insecure_skip_verify": true. Empty {} (the
	// default) uses Caddy's strict cert validation against the system
	// trust store.
	if p.UsesHTTPS {
		tlsCfg := map[string]any{}
		if p.InsecureSkipVerify {
			tlsCfg["insecure_skip_verify"] = true
		}
		proxyHandler["transport"] = map[string]any{
			"protocol": "http",
			"tls":      tlsCfg,
		}
	}

	// Phase 4.5 (#R-WAF-BUFFER-OOM-ON-LARGE-UPLOADS) — when the route is
	// in upload-streaming mode, tell Caddy to flush bytes through as
	// they arrive instead of buffering the whole request body in RAM.
	// The -1 sentinel maps to httputil.ReverseProxy.FlushInterval = -1
	// ("flush immediately after every write").
	if flushInterval {
		proxyHandler["flush_interval"] = -1
	}

	// Step J.2: active health checks. When enabled, emit
	// `health_checks.active` as a sibling of upstreams and
	// load_balancing. When disabled (or the pointer is nil), the whole
	// health_checks key is omitted — Caddy treats absence as "no probe
	// runs".
	//
	// Emission rules (§5.2):
	//   - uri, method, interval, timeout, passes, fails always emitted
	//     when Enabled (the API layer materialised the five defaults).
	//   - expect_status only when non-zero (zero = "any 2xx").
	//   - expect_body only when non-empty (empty regex = "no body check").
	if p.HealthCheck != nil && p.HealthCheck.Enabled {
		hc := p.HealthCheck
		active := map[string]any{
			"uri":      hc.URI,
			"method":   hc.Method,
			"interval": hc.Interval,
			"timeout":  hc.Timeout,
			"passes":   hc.Passes,
			"fails":    hc.Fails,
		}
		if hc.ExpectStatus != 0 {
			active["expect_status"] = hc.ExpectStatus
		}
		if hc.ExpectBody != "" {
			active["expect_body"] = hc.ExpectBody
		}
		// v2.55 — the probe's headers, Host first.
		//
		// Caddy's own special case: a `Host` key in this map sets
		// req.Host rather than adding a header
		// (caddy healthchecks.go:452-455). Everything else is added
		// verbatim. Emitted as lists because that is Caddy's http.Header
		// shape; json.Marshal sorts the keys, so the output stays stable.
		if headers := probeHeaders(hc, p.ProbeHost); len(headers) > 0 {
			active["headers"] = headers
		}
		proxyHandler["health_checks"] = map[string]any{
			"active": active,
		}
	}

	proxyHandler["handle_response"] = sharedHandleResponse

	return proxyHandler, nil
}
