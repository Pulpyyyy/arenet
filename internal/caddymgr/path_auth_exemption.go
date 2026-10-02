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
	"sort"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// conventionalIdentityHeaders are the request headers a forward-auth setup
// conventionally carries, and therefore the ones an upstream is most likely
// to trust without checking anything else.
//
// They are stripped on an exempted path even when the provider does not copy
// them, because the risk is the upstream's credulity, not the provider's
// configuration: n8n, Grafana or a homemade admin page told to trust
// Remote-User will trust it whether or not Arenet's provider lists it. The
// set is deliberately visible — it is shown in the UI and documented in the
// wiki, so no header disappears in secret.
//
// X-Authentik-* uses Caddy's wildcard deletion, which matches on a
// lowercased field name (caddy v2.11.4 modules/caddyhttp/headers/headers.go
// :256-280), so the spelling here is for the operator's benefit only.
var conventionalIdentityHeaders = []string{
	"Remote-User",
	"Remote-Email",
	"Remote-Groups",
	"Remote-Name",
	"X-Authentik-*",
	"X-Forwarded-User",
}

// exemptPathMatchers returns the Caddy path patterns for every rule that
// exempts itself from the route's authentication, or nil when none does.
//
// Each rule contributes the same patterns it uses for its own matching, so
// an exemption covers exactly the paths the rule covers — including the
// MatchExact case, where "/" must not swallow the whole site. Patterns are
// sorted so the emitted config is byte-stable across reloads regardless of
// the order the rules happen to be stored in; an unstable config would make
// Caddy log a change on every apply and make diffing useless.
func exemptPathMatchers(rules []storage.PathRule) []string {
	var out []string
	for _, pr := range rules {
		if !pr.DisableRouteAuth {
			continue
		}
		out = append(out, pathMatchers(pr)...)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// identityHeadersToStrip returns the request headers to delete on an
// exempted path: the conventional set, plus whatever the route's provider is
// configured to copy, deduplicated and sorted for a stable config.
//
// provider is nil when the route's gate is basic auth rather than an IdP. The
// conventional set still applies: basic auth does not set identity headers,
// so anything arriving under those names on an exempted path came from the
// client.
func identityHeadersToStrip(provider *storage.ForwardAuthProvider) []string {
	seen := make(map[string]struct{}, len(conventionalIdentityHeaders)+4)
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" {
			return
		}
		key := strings.ToLower(h)
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		out = append(out, h)
	}
	for _, h := range conventionalIdentityHeaders {
		add(h)
	}
	if provider != nil {
		for _, h := range provider.CopyHeaders {
			add(h)
		}
	}
	sort.Strings(out)
	return out
}

// buildPathAuthExemption wraps a route's authentication handler so the
// exempted paths skip it, and strips the identity headers on those paths.
//
// Returns the handlers to append in place of authHandler. With no exempted
// path it returns exactly []{authHandler}, so a route without this feature
// emits a byte-identical config to before v2.58 — the non-regression the
// tests assert.
//
// Why this shape. The route's authentication runs BEFORE the path-rules
// subroute (manager.go: the auth append sits well above the
// buildPathRulesSubroute call), so by the time a path rule executes the
// decision has already been made and a rule cannot undo it. The exemption
// therefore has to be expressed where the auth is emitted, as a negated path
// matcher around it.
//
// Verified in Caddy v2.11.4: a subroute compiles its routes with the OUTER
// next as their terminal handler (modules/caddyhttp/subroute.go:73), so when
// no inner route matches — an exempted path — control continues down the
// outer chain with the auth simply skipped, rather than ending there. And
// the "not" matcher takes an ARRAY of matcher sets, each OR'ed
// (modules/caddyhttp/matchers.go:196-219, MarshalJSON at :1405), so one set
// holding one path matcher reads as "none of these paths".
func buildPathAuthExemption(
	authHandler map[string]any,
	rules []storage.PathRule,
	provider *storage.ForwardAuthProvider,
) []map[string]any {
	exempt := exemptPathMatchers(rules)
	if len(exempt) == 0 {
		return []map[string]any{authHandler}
	}

	// Strip first, unconditionally for the exempted paths, so a forged
	// header is gone before anything downstream can read it — including the
	// backend when the auth is skipped.
	strip := map[string]any{
		"handler": "subroute",
		"routes": []map[string]any{{
			"match": []map[string]any{{"path": exempt}},
			"handle": []map[string]any{{
				"handler": "headers",
				"request": map[string]any{
					"delete": identityHeadersToStrip(provider),
				},
			}},
		}},
	}

	// Then the auth, for every path EXCEPT the exempted ones.
	gated := map[string]any{
		"handler": "subroute",
		"routes": []map[string]any{{
			"match": []map[string]any{{
				"not": []map[string]any{{"path": exempt}},
			}},
			"handle": []map[string]any{authHandler},
		}},
	}

	return []map[string]any{strip, gated}
}
