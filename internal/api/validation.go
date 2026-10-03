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

// Package api exposes the REST admin API for Arenet.
package api

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/barto95100/arenet/internal/storage"
)

// hostnameRE is a pragmatic RFC 1123 hostname check: dot-separated labels,
// each label 1-63 chars of alnum + dash, must start and end with alnum.
var hostnameRE = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`,
)

// wildcardHostRE matches a single-label wildcard hostname of the
// shape `*.<rest>` where `<rest>` is itself a valid hostname per
// hostnameRE. Only one leading `*` is allowed (no `*.*.foo`) — ACME
// wildcard certs cover exactly one label. Used by validateHost +
// validateACMEChallenge to enforce "wildcard ⇒ dns-01" (§5.4).
var wildcardHostRE = regexp.MustCompile(
	`^\*\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`,
)

// isWildcardHost reports whether h is a single-label wildcard
// (e.g. "*.example.com"). Plain hosts ("example.com") and double-
// wildcards ("*.*.example.com") both return false. Used as the
// trigger for the "wildcard ⇒ dns-01" rule.
func isWildcardHost(h string) bool {
	return wildcardHostRE.MatchString(h)
}

// validateHost checks that s is non-empty, contains no whitespace, and matches
// a basic hostname grammar. Returns the first failure with a user-facing
// English message.
//
// Step J.4: single-label wildcards (`*.example.com`) are accepted as
// valid hosts so the operator can configure a route that issues a
// wildcard cert via DNS-01. The cross-rule "wildcard ⇒ dns-01" lives
// in validateACMEChallenge / createRoute / updateRoute — kept out of
// validateHost so the host-shape rule and the ACME-policy rule each
// have a single responsibility.
func validateHost(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("host must not be empty")
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return errors.New("host must not contain whitespace")
	}
	if len(s) > 253 {
		return errors.New("host must be a valid hostname")
	}
	if hostnameRE.MatchString(s) || wildcardHostRE.MatchString(s) {
		return nil
	}
	return errors.New("host must be a valid hostname")
}

// validateUpstreamURL checks that s is a parsable absolute URL using the http
// or https scheme and that it carries a host component.
func validateUpstreamURL(s string) error {
	if s == "" {
		return errors.New("upstreamUrl must not be empty")
	}
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return errors.New("upstreamUrl is not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return errors.New("upstreamUrl must use http or https scheme")
	}
	if u.Host == "" {
		return errors.New("upstreamUrl must include a host")
	}
	return nil
}

// validateUpstreamPool checks the Step J.1 upstream pool: at least
// one entry, each entry's URL parsable per validateUpstreamURL.
// Per-element Weight is NOT checked here — the API materialises
// Weight=0 → 1 before this function runs, so a weight that reaches
// the validator is, by construction, the API's chosen default or an
// explicit user value (which must be >= 1, asserted below).
//
// The friendly per-element error wraps validateUpstreamURL's
// existing message with the row index so operators can locate the
// offending pool element in a multi-upstream payload.
func validateUpstreamPool(pool []upstreamReq) error {
	return validateUpstreamPoolAllowingEmpty(pool, false)
}

// validateUpstreamPoolAllowingEmpty is validateUpstreamPool with the
// "at least one entry" rule made conditional.
//
// v2.58.4 — a redirecting route proxies nothing, so demanding a backend for
// it asks the operator to invent an address that will never be dialled.
// v2.45.2 established that and fixed it in two of the three places that
// enforce it: storage (routes.go, `len(r.Upstreams) == 0 && r.RedirectConfig
// == nil`) and the form (+page.svelte, `needsUpstream = stateChoice !==
// 'redirect'`). This layer, sitting between them, kept refusing — so the form
// let the operator save and the API answered 400 "upstreams must contain at
// least one entry", a message they could not act on because the field is
// deliberately hidden for a redirect.
//
// An empty pool is still the ONLY thing the exemption covers: entries that
// are present are validated exactly as before, so a redirecting route with a
// malformed upstream is still rejected.
func validateUpstreamPoolAllowingEmpty(pool []upstreamReq, allowEmpty bool) error {
	if len(pool) == 0 {
		if allowEmpty {
			return nil
		}
		return errors.New("upstreams must contain at least one entry")
	}
	for i, u := range pool {
		if err := validateUpstreamURL(u.URL); err != nil {
			return fmt.Errorf("upstreams[%d]: %s", i, err.Error())
		}
		if u.Weight < 1 {
			return fmt.Errorf("upstreams[%d].weight must be >= 1", i)
		}
	}
	return nil
}

// validateACMEChallenge enforces the Step J.4 §5.4 rules on a
// route's per-route ACME challenge selection. The caller has
// already normalised the empty string to "http-01" (POST / PUT
// default), so a value reaching this function is one of the
// enum values — anything else is rejected.
//
// Cross-rules enforced here:
//   - The challenge must be exactly "http-01" / "dns-01" /
//     "inherited" (the Step O.1 sentinel for routes covered by
//     a managed-domain wildcard).
//   - If ANY host in the route's hostname set (primary Host +
//     Aliases) is a wildcard, the challenge MUST be "dns-01".
//     HTTP-01 cannot issue wildcards (proving control of
//     "*.example.com" is impossible via an HTTP request to any
//     concrete host).
//
// "inherited" intentionally skips the wildcard check: a covered
// route delegates cert issuance to the managed-domain wildcard
// policy, which is itself emitted with the DNS-01 challenge
// (caddymgr §3.3). The wildcard-coverage cross-rule (must EXIST
// a managed domain that covers the host) lives in createRoute /
// updateRoute because it needs the store handle.
//
// The DNS-01-requires-a-configured-provider rule also lives in
// createRoute / updateRoute (same reason: needs the store
// handle). This pure function stays handle-free and testable.
func validateACMEChallenge(challenge, host string, aliases []string) error {
	switch challenge {
	case storage.ACMEChallengeHTTP01, storage.ACMEChallengeDNS01, storage.ACMEChallengeInherited:
	default:
		return fmt.Errorf("acmeChallenge %q must be %q, %q, or %q",
			challenge,
			storage.ACMEChallengeHTTP01,
			storage.ACMEChallengeDNS01,
			storage.ACMEChallengeInherited)
	}
	if challenge == storage.ACMEChallengeHTTP01 {
		if isWildcardHost(host) {
			return fmt.Errorf("acmeChallenge must be %q for wildcard host %q",
				storage.ACMEChallengeDNS01, host)
		}
		for _, a := range aliases {
			if isWildcardHost(a) {
				return fmt.Errorf("acmeChallenge must be %q for wildcard alias %q",
					storage.ACMEChallengeDNS01, a)
			}
		}
	}
	return nil
}

// validateAuthMode (Step K.1) checks that s is one of the three
// enum values. Empty string is rejected — the API materialises the
// default (createRoute: "none", updateRoute: preserve previous
// then "none") before this function runs.
func validateAuthMode(s string) error {
	switch s {
	case storage.RouteAuthNone, storage.RouteAuthBasic, storage.RouteAuthForwardAuth:
		return nil
	}
	return fmt.Errorf("authMode %q must be one of %q, %q, %q",
		s,
		storage.RouteAuthNone, storage.RouteAuthBasic, storage.RouteAuthForwardAuth)
}

// validateAuthFieldsMutex (Step K.1) enforces the mutual
// exclusivity of basic / forward_auth at the wire level — even if
// the operator hand-crafts a JSON body that picks AuthMode "basic"
// but ALSO sets ForwardAuth.ProviderName (or vice versa), the API
// rejects it. The form's radio-group UI prevents this state in the
// happy path; this is the AC #5 defence-in-depth guard.
func validateAuthFieldsMutex(req routeRequest) error {
	switch req.AuthMode {
	case storage.RouteAuthBasic:
		if req.ForwardAuth.ProviderName != "" {
			return errors.New("authMode is \"basic\" but forwardAuth.providerName is set — pick one auth method")
		}
	case storage.RouteAuthForwardAuth:
		if req.BasicAuth.Username != "" || req.BasicAuth.Password != "" {
			return errors.New("authMode is \"forward_auth\" but basicAuth.{username,password} is set — pick one auth method")
		}
	case storage.RouteAuthNone:
		if req.ForwardAuth.ProviderName != "" {
			return errors.New("authMode is \"none\" but forwardAuth.providerName is set — clear the field or change authMode")
		}
		if req.BasicAuth.Username != "" || req.BasicAuth.Password != "" {
			return errors.New("authMode is \"none\" but basicAuth.{username,password} is set — clear the fields or change authMode")
		}
	}
	return nil
}

// validateLBPolicy checks that s is one of the six storage.LBPolicy*
// values. Empty string is rejected — the API is expected to have
// materialised the default ("round_robin") before this function
// runs, so an empty value here is a programming error.
func validateLBPolicy(s string) error {
	for _, p := range storage.LBPolicies {
		if s == p {
			return nil
		}
	}
	return fmt.Errorf("lbPolicy %q is not a valid policy", s)
}

// Step J.2 — five default values the API layer materialises into
// HealthCheck sub-fields before validation runs. uri is NOT in
// this set: there is no sensible default health-check path; the
// operator must always supply it when Enabled is true (§5.2). The
// constants live next to the validator so a single edit keeps the
// materialise-then-validate pipeline consistent.
const (
	defaultHCMethod   = "GET"
	defaultHCInterval = "30s"
	defaultHCTimeout  = "5s"
	defaultHCPasses   = 1
	defaultHCFails    = 1
)

// validateHealthCheck runs the eight Step J.2 API-layer rules on a
// healthCheckReq that has been through the defaults injection
// (Method/Interval/Timeout/Passes/Fails) + Method uppercase
// normalisation. Only called when h.Enabled is true; callers MUST
// guard.
//
// The validation messages use camelCase field names ("healthCheck.
// uri", "healthCheck.method", ...) because they surface to the API
// caller verbatim — friendlier 400 than the snake_case storage
// errors. The storage HealthCheck.validate() runs after, as the
// strict last line of defence against direct CreateRoute /
// UpdateRoute calls that bypass the API.
func validateHealthCheck(h healthCheckReq) error {
	if h.URI == "" {
		return errors.New("healthCheck.uri must not be empty when enabled")
	}
	if !strings.HasPrefix(h.URI, "/") {
		return fmt.Errorf("healthCheck.uri %q must start with /", h.URI)
	}
	if h.Method != "GET" && h.Method != "HEAD" {
		return fmt.Errorf("healthCheck.method %q must be GET or HEAD", h.Method)
	}
	interval, err := time.ParseDuration(h.Interval)
	if err != nil {
		return fmt.Errorf("healthCheck.interval %q is not a valid duration", h.Interval)
	}
	if interval <= 0 {
		return errors.New("healthCheck.interval must be strictly positive")
	}
	timeout, err := time.ParseDuration(h.Timeout)
	if err != nil {
		return fmt.Errorf("healthCheck.timeout %q is not a valid duration", h.Timeout)
	}
	if timeout <= 0 {
		return errors.New("healthCheck.timeout must be strictly positive")
	}
	if timeout >= interval {
		return errors.New("healthCheck.timeout must be strictly less than interval")
	}
	// v2.55 — 1-5 is Caddy's status-class shorthand, so an app that
	// answers 302 on / can be matched as "any 3xx" instead of being
	// pinned to one code it may stop using.
	if err := storage.ValidateExpectStatus("healthCheck.expectStatus", h.ExpectStatus); err != nil {
		return err
	}
	if h.HostHeader != "" && strings.TrimSpace(h.HostHeader) == "" {
		return errors.New("healthCheck.hostHeader must not be blank")
	}
	if h.ExpectBody != "" {
		if _, err := regexp.Compile(h.ExpectBody); err != nil {
			return fmt.Errorf("healthCheck.expectBody is not a valid regex: %v", err)
		}
	}
	if h.Passes < 1 {
		return errors.New("healthCheck.passes must be >= 1")
	}
	if h.Fails < 1 {
		return errors.New("healthCheck.fails must be >= 1")
	}
	return nil
}

// materialiseHealthCheck applies the five default values (and the
// Method uppercase normalisation) to an Enabled health check
// before validation runs. URI is NOT defaulted — it must come
// from the caller. The function returns a new healthCheckReq with
// the defaults filled in; the caller swaps the original with the
// returned one before passing it to validateHealthCheck and to
// the storage mapping.
//
// Called only when the caller has determined Enabled is true.
func materialiseHealthCheck(h healthCheckReq) healthCheckReq {
	if h.Method == "" {
		h.Method = defaultHCMethod
	}
	h.Method = strings.ToUpper(h.Method)
	if h.Interval == "" {
		h.Interval = defaultHCInterval
	}
	if h.Timeout == "" {
		h.Timeout = defaultHCTimeout
	}
	if h.Passes == 0 {
		h.Passes = defaultHCPasses
	}
	if h.Fails == 0 {
		h.Fails = defaultHCFails
	}
	return h
}

// validatePathRuleUpstreams runs the same API-layer validation the
// route-level upstream pool gets (validateUpstreamPool / validateLBPolicy /
// validateHealthCheck) over each path-rule's OWN upstream pool, before the
// route write reaches storage.
//
// This exists because storage.PathRule.Validate() deliberately does NOT
// check upstream URL *syntax* (validateUpstreamURL lives only at the API
// layer — see storage/routes.go PathRule.Validate doc-comment) nor does it
// validate HealthCheck sub-fields at all. Without this pass, a
// syntactically broken path-rule upstream URL (e.g. "://broken") or an
// enabled path-rule health check missing its URI would sail past
// createRoute/updateRoute and only surface later at Caddy config emission
// — mirrors the route-level defence-in-depth pattern (routes.go
// validateUpstreamPool / validateHealthCheck calls).
//
// Only path rules carrying a non-empty Upstreams pool are checked — an
// empty pool means "inherit the route's pool" and has no LB/HC of its own
// to validate (mirrors mapPathRuleReqs' own "len(r.Upstreams) > 0" gate).
// Errors are wrapped with the offending PathPrefix so operators can locate
// the failing rule in a multi-path-rule payload.
func validatePathRuleUpstreams(reqs []pathRuleReq) error {
	for _, r := range reqs {
		if len(r.Upstreams) == 0 {
			continue
		}
		// Materialise Weight defaults before validation, mirroring the
		// route-level createRoute/updateRoute pre-validation step —
		// otherwise an omitted weight (validly defaulted to 1 later by
		// mapPathRuleReqs) would be rejected here as "< 1".
		pool := make([]upstreamReq, len(r.Upstreams))
		copy(pool, r.Upstreams)
		for i := range pool {
			if pool[i].Weight == 0 {
				pool[i].Weight = 1
			}
		}
		if err := validateUpstreamPool(pool); err != nil {
			return fmt.Errorf("path_rule %q: %s", r.PathPrefix, err.Error())
		}
		lb := r.LBPolicy
		if lb == "" {
			lb = storage.LBPolicyRoundRobin
		}
		if err := validateLBPolicy(lb); err != nil {
			return fmt.Errorf("path_rule %q: %s", r.PathPrefix, err.Error())
		}
		if r.HealthCheck != nil && r.HealthCheck.Enabled {
			hc := materialiseHealthCheck(*r.HealthCheck)
			if err := validateHealthCheck(hc); err != nil {
				return fmt.Errorf("path_rule %q: %s", r.PathPrefix, err.Error())
			}
		}
	}
	return nil
}
