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

import "github.com/barto95100/arenet/internal/storage"

// buildIPFilterRoute emits a Caddy route that blocks the traffic an
// IPFilter forbids, using the native client_ip matcher. Returns nil when
// inactive.
//
// IP source: Arenet does NOT emit `trusted_proxies` in the Caddy server
// config, so `client_ip` resolves to the DIRECT TCP peer address, NOT a
// forwarded X-Forwarded-For value. This is the more secure default for an
// access gate — a client cannot spoof past an allow-list via XFF — but it
// means that behind a fronting L7 proxy/LB the matcher sees the LB's IP,
// not the real client's. Operators wanting XFF-based filtering behind a
// trusted LB would need `trusted_proxies` plumbed into the server config
// (v-next). (`ARENET_TRUSTED_PROXIES` is consumed only by Arenet's own
// admin IP logging in cmd/arenet/main.go, not by this Caddy matcher.)
//
// allow mode → block everything NOT in the list: match {not:{client_ip}}.
//
//	This is the FAIL-CLOSED shape: an unknown client hits the 403.
//
// deny mode → block the listed: match {client_ip}.
// Caddy has no ResponseMatcher `not` but MatchNot (http.matchers.not,
// matchers.go:1379) IS a request matcher — valid here.
func buildIPFilterRoute(f storage.IPFilter) map[string]any {
	if !f.IsActive() {
		return nil
	}
	status := f.StatusCode
	if status == 0 {
		status = 403
	}
	clientIP := map[string]any{"ranges": f.NormalizedCIDRs()}
	var match map[string]any
	if f.Mode == storage.IPFilterModeAllow {
		match = map[string]any{"not": []map[string]any{{"client_ip": clientIP}}}
	} else { // deny
		match = map[string]any{"client_ip": clientIP}
	}
	return map[string]any{
		"match": []map[string]any{match},
		"handle": []map[string]any{
			// Emit an `error` handler, NOT a static_response. static_response
			// returns a bare status body directly and BYPASSES the server's
			// `errors` chain, so a blocked client got an unstyled 403. The
			// `error` handler raises a Caddy HandlerError with this status,
			// which propagates to apps.http.servers.<srv>.errors and renders
			// the branded error page / the route's selected error template —
			// same path as a 404/502 and as Arenet's other pre-proxy gates
			// (BasicAuth/ForwardAuth 401/403 dispatch via the errors chain
			// too; see reverse_proxy_emit.go). fix/ip-filter-branded-error.
			{"handler": "error", "status_code": status},
		},
	}
}
