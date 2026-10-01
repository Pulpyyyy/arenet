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
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// pathMatchers returns Caddy path matchers for a prefix: the prefix
// itself + everything under it. "/docs" → ["/docs","/docs/*"].
func pathMatchers(pr storage.PathRule) []string {
	// v2.44 — MatchExact emits the bare pattern. Verified in Caddy
	// v2.11.4 (caddyhttp/matchers.go): a pattern with no wildcard
	// falls through to path.Match, which the source itself calls
	// "exact matching if there are no glob/wildcard chars". So "/"
	// alone matches "/" and nothing else — which is the whole point,
	// since the prefix form would also match the redirect's target.
	if pr.MatchExact {
		return []string{pr.PathPrefix}
	}
	return []string{pr.PathPrefix, pr.PathPrefix + "/*"}
}

// poolUsesHTTPS reports whether a bare upstream pool (a route's or a
// per-path rule's) requires Caddy to negotiate TLS toward the upstreams.
// It mirrors storage.Route.PoolUsesHTTPS() for a pool that is not attached
// to a Route value (the per-path-upstream feature owns pools on
// storage.PathRule, not on Route). storage.upstreamScheme is package-
// private to storage, so caddymgr cannot call it; this helper reproduces
// the same-scheme invariant instead: the storage validator guarantees a
// same-scheme pool, so inspecting the first upstream is enough. Returns
// true iff the first upstream URL uses the https:// scheme.
func poolUsesHTTPS(pool []storage.Upstream) bool {
	if len(pool) == 0 {
		return false
	}
	url := pool[0].URL
	return len(url) >= 8 && (url[:8] == "https://" || url[:8] == "HTTPS://")
}

// buildPathRulesSubroute wraps the proxy in a subroute whose inner
// routes are the path-rules (sorted longest-prefix first, Q4) each
// applying its override handlers (path IP filter block, then basic
// auth) before proxying, followed by a match-less catch-all proxy.
//
// Ordering inside a matched path route is IP filter BEFORE basic
// auth BEFORE proxy: a blocked client gets its 403 without ever
// reaching the auth prompt (avoids leaking that the path exists /
// wasting a credential round-trip on traffic that would be denied
// anyway).
//
// The catch-all (no `match`) is REQUIRED: without it, a request
// whose path doesn't fall under any PathRule prefix would have no
// route to fall through to inside this subroute and would be
// dropped instead of reaching the plain proxy.
//
// Per-path upstream (v2.23.0): the TERMINAL proxy of each matched
// path route is resolved by pathProxyBuilder(pr), not by the shared
// routeProxy. A rule with its own upstream pool proxies to THAT pool
// (own load-balancing / health-check / transport, sharing the route's
// error-branding handle_response — supplied by the caller's closure);
// a rule with no pool returns the routeProxy verbatim (inherit). The
// catch-all still appends routeProxy, so any path outside every rule
// prefix reaches the route's own pool. pathProxyBuilder may fail (a
// malformed per-path upstream URL) — the error is propagated so the
// whole config build fails closed rather than emitting a half-built
// subroute.
//
// Ordering is UNCHANGED — [IP-block?] → [basic-auth?] → [proxy] — so
// a fail-closed IP filter still gates BEFORE the path's own upstream:
// a blocked client gets its 403 without the request ever reaching the
// per-path pool.
func buildPathRulesSubroute(
	routeID string,
	rules []storage.PathRule,
	routeProxy map[string]any,
	basicAuthBuilder func(storage.BasicAuthRouteConfig) map[string]any,
	// forwardAuthBuilder resolves a provider name to its gate, or to the
	// fail-closed 503 when the provider is gone. It returns the handler and
	// whether the chain may continue: a missing provider must NOT fall
	// through to the proxy, because the failure mode of an auth control
	// that quietly stops gating is a path served to anyone.
	forwardAuthBuilder func(providerName string) (handler map[string]any, ok bool),
	pathProxyBuilder func(storage.PathRule) (map[string]any, error),
) (map[string]any, error) {
	sorted := storage.SortPathRulesByPrefixLenDesc(rules)
	inner := make([]map[string]any, 0, len(sorted)+1)
	for _, pr := range sorted {
		handle := make([]map[string]any, 0, 3)
		if pr.IPFilter != nil && pr.IPFilter.IsActive() {
			// A path IP block inside the matched route: emit the block
			// route's matcher+handler as a nested subroute so a blocked
			// client gets the 403 before the proxy (and before auth).
			if ipRoute := buildIPFilterRoute(*pr.IPFilter); ipRoute != nil {
				handle = append(handle, map[string]any{
					"handler": "subroute",
					"routes":  []map[string]any{ipRoute},
				})
			}
		}
		// v2.56 — the per-path limit, BEFORE auth.
		//
		// The reason this feature exists is a login or session endpoint,
		// and the requests worth throttling there are the ones that have
		// not authenticated yet. Placed after basic auth it would count
		// only the attempts that already succeeded, which is the opposite
		// of a brute-force gate.
		//
		// Its own zone, so this limit and the route's are two separate
		// budgets and both apply.
		if rlHandler := buildPathRateLimitHandler(routeID, pr.PathPrefix, pr.RateLimit); rlHandler != nil {
			handle = append(handle, rlHandler)
		}
		if pr.BasicAuth != nil {
			handle = append(handle, basicAuthBuilder(*pr.BasicAuth))
		}
		// v2.57 — the per-path IdP gate, where basic auth sits: after the
		// cheap gates, before the proxy. Storage refuses both on one rule,
		// so these two are never emitted together.
		//
		// A missing provider emits the 503 and stops: the rest of this
		// rule's chain is skipped so the request cannot reach the backend
		// through a gate that is not there. Same posture as the route
		// level, for the same reason — an auth control that fails open is
		// the worst class of failure.
		if pr.ForwardAuth != nil {
			gate, ok := forwardAuthBuilder(pr.ForwardAuth.ProviderName)
			handle = append(handle, gate)
			if !ok {
				inner = append(inner, map[string]any{
					"match":  []map[string]any{{"path": pathMatchers(pr)}},
					"handle": handle,
				})
				continue
			}
		}
		// v2.44 — a path redirect replaces the proxy for THIS path
		// only; everything else on the route keeps being proxied. The
		// IP filter and basic auth above still run first, so a
		// protected path that also redirects stays protected.
		if pr.Redirect != nil {
			handle = append(handle, map[string]any{
				"handler":     "static_response",
				"status_code": pr.Redirect.Code(),
				"headers": map[string]any{
					"Location": []string{strings.TrimSpace(pr.Redirect.Target)},
				},
			})
		} else {
			proxy, err := pathProxyBuilder(pr)
			if err != nil {
				return nil, err
			}
			handle = append(handle, proxy)
		}
		inner = append(inner, map[string]any{
			"match":  []map[string]any{{"path": pathMatchers(pr)}},
			"handle": handle,
		})
	}
	// catch-all: no path match → the route's own proxy (paths with no rule).
	inner = append(inner, map[string]any{
		"handle": []map[string]any{routeProxy},
	})
	return map[string]any{"handler": "subroute", "routes": inner}, nil
}
