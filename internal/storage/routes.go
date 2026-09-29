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

package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/apierr"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"

	"github.com/barto95100/arenet/internal/countryblock"
)

// Step J.1 load-balancing policies. Exposed as constants so the API
// validation layer and the Caddy generator share a single source of
// truth (no string typos drift). The order mirrors §1.3 decision 2.
const (
	LBPolicyRoundRobin         = "round_robin"
	LBPolicyWeightedRoundRobin = "weighted_round_robin"
	LBPolicyLeastConn          = "least_conn"
	LBPolicyIPHash             = "ip_hash"
	LBPolicyRandom             = "random"
	LBPolicyFirst              = "first"
)

// Step J.4 ACME challenge enum (§5.4), extended by Step O.1 with
// the "inherited" sentinel.
//
// Empty string is NOT in the enum but is treated by the API and the
// generator as equivalent to ACMEChallengeHTTP01 (default + the
// no-migration zero-value for pre-J.4 rows). Storage.validate
// accepts the empty string explicitly so the boot zero-value path
// works without a migration.
//
// Step O.1: ACMEChallengeInherited marks a route whose certificate
// is provisioned by a managed domain's wildcard policy (spec D8.A).
// The value is set by the managed-domain create handler when a
// covered route's previous value (http-01 / dns-01) becomes
// meaningless, and reverted back to "" on managed-domain delete.
// Operators do not set this directly via the route-edit UI; the
// frontend hides the ACMEChallenge selector when a managed domain
// covers the host.
const (
	ACMEChallengeHTTP01    = "http-01"
	ACMEChallengeDNS01     = "dns-01"
	ACMEChallengeInherited = "inherited"
)

// Step K.1 per-route authentication mode (§5.1). One of three
// mutually-exclusive values, materialised at the API layer
// (empty string → "none" on POST, preserve previous on PUT).
const (
	RouteAuthNone        = "none"
	RouteAuthBasic       = "basic"
	RouteAuthForwardAuth = "forward_auth"
)

// BasicAuthRouteConfig is the per-route Basic Auth configuration
// (Step K.1 — refactored from the flat BasicAuthEnabled / Username /
// PasswordHash fields shipped in Step I.5). The shape is unchanged
// at the bytes level; it lives in a nested struct so the radio-
// group auth model (none / basic / forward_auth) reads cleanly.
//
// Validation rules: when Route.AuthMode == RouteAuthBasic, both
// Username and PasswordHash must be non-empty. The PasswordHash
// is an argon2id PHC string — NEVER exposed over the API (the
// response surface uses a derived BasicAuthPasswordSet bool
// instead) and NEVER embedded in audit events.
type BasicAuthRouteConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // SECRET — never echoed
}

// PathRule applies additive protections to a URL sub-tree of a route.
// PathPrefix "/docs" matches "/docs" and everything under "/docs/*"
// (emission concern). At least one of BasicAuth / IPFilter / Upstreams
// must be set.
type PathRule struct {
	PathPrefix string                `json:"path_prefix"`
	BasicAuth  *BasicAuthRouteConfig `json:"basic_auth,omitempty"` // PasswordHash is a SECRET
	IPFilter   *IPFilter             `json:"ip_filter,omitempty"`
	// Per-path upstream routing (v2.23.0). When Upstreams is non-empty the
	// matched sub-path proxies to THIS pool instead of the route's. All
	// omitempty → a rule with no per-path pool stores byte-identically to
	// the pre-v2.23.0 shape (migration-free).
	Upstreams   []Upstream   `json:"upstreams,omitempty"`    // own pool; empty = inherit the route's
	LBPolicy    string       `json:"lb_policy,omitempty"`    // defaults to round_robin when pool non-empty
	HealthCheck *HealthCheck `json:"health_check,omitempty"` // own active HC for this path pool
	// InsecureSkipVerify (v2.23.1) applies ONLY to this path's own pool.
	// Autonomous: a path pool does NOT inherit the route's skip-verify
	// posture (Q1). Default false = strict TLS validation. Only consulted
	// when the pool is https (transport.tls is emitted). omitempty →
	// migration-free.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// MatchExact (v2.44) matches PathPrefix as the WHOLE path instead
	// of a sub-tree. Without it, "/" is a prefix that matches every
	// request — including the redirect's own target — so this is what
	// makes "/ goes to /admin/login" expressible at all.
	MatchExact bool `json:"match_exact,omitempty"`
	// Redirect (v2.44), when non-nil, answers a redirect for this path
	// instead of proxying it. The rest of the route keeps proxying
	// normally: unlike the route-level redirect state, this replaces
	// the proxy for ONE path.
	Redirect *PathRedirect `json:"redirect,omitempty"`
}

// PathRedirect answers a redirect for one path of a route.
//
// v2.44 — the second scope of
// docs/superpowers/specs/2026-09-24-route-redirects-design.md. Its
// reason to exist is the application that serves nothing at its root:
// a mail server's webadmin under /admin, an API under /api. Visiting
// the bare hostname gives a 404 that looks like Arenet's fault.
type PathRedirect struct {
	// Target is either a path on this same host ("/admin/login") or an
	// absolute URL ("https://elsewhere.example.com/docs").
	Target string `json:"target"`
	// StatusCode is 301 or 302; zero means 302.
	//
	// The default differs from the route-level redirect on purpose. A
	// domain move is permanent; a landing path is a convenience that
	// an application update can change, and a 301 cached by every
	// visitor's browser is remarkably hard to take back.
	StatusCode int `json:"status_code,omitempty"`
}

// Code returns the status code to emit, resolving the zero value.
func (pr *PathRedirect) Code() int {
	if pr == nil || pr.StatusCode == 0 {
		return 302
	}
	return pr.StatusCode
}

// Validate checks that the PathRule is well-formed: PathPrefix is a
// non-empty, whitespace-free, leading-slash path under 256 characters,
// and at least one ACTIVE protection (basic auth, an IP filter with
// Mode != "off", or a non-empty upstream pool) is declared and
// internally valid. An IP filter present but set to Mode "off" does
// not count — it emits zero protection, so a rule relying on it alone
// would be a silent passthrough.
func (p PathRule) Validate() error {
	if p.PathPrefix == "" || p.PathPrefix[0] != '/' {
		return fmt.Errorf("path_rule: path_prefix %q must start with /", p.PathPrefix)
	}
	if len(p.PathPrefix) > 256 {
		return fmt.Errorf("path_rule: path_prefix exceeds 256 characters")
	}
	for _, r := range p.PathPrefix {
		if r == ' ' || r == '\t' || r == '\n' {
			return fmt.Errorf("path_rule: path_prefix %q must not contain whitespace", p.PathPrefix)
		}
	}
	// v2.44 — Caddy lowercases the REQUEST path before matching but
	// never the pattern (caddyhttp/matchers.go MatchPath.MatchWithError).
	// A pattern carrying an uppercase letter can therefore never match
	// anything: Caddy accepts the config, the rule loads, and it
	// silently does nothing forever. Refusing it here is the only
	// place an operator can be told.
	if p.PathPrefix != strings.ToLower(p.PathPrefix) {
		return apierr.New("path_rule_uppercase",
			map[string]string{"path": p.PathPrefix, "lower": strings.ToLower(p.PathPrefix)},
			"path_rule: path_prefix %q contains an uppercase letter — Caddy lowercases the "+
				"request path but not the pattern, so this rule could never match anything; "+
				"use %q", p.PathPrefix, strings.ToLower(p.PathPrefix))
	}
	hasUpstreams := len(p.Upstreams) > 0
	if p.BasicAuth == nil && (p.IPFilter == nil || !p.IPFilter.IsActive()) && !hasUpstreams && p.Redirect == nil {
		return apierr.New("path_rule_empty", map[string]string{"path": p.PathPrefix},
			"path_rule %q: must declare at least one of basic auth, IP filter, an upstream, or a redirect",
			p.PathPrefix)
	}
	if err := p.validateRedirect(); err != nil {
		return err
	}
	if p.BasicAuth != nil && p.BasicAuth.Username == "" {
		return fmt.Errorf("path_rule %q: basic auth requires a username", p.PathPrefix)
	}
	if p.BasicAuth != nil && p.BasicAuth.PasswordHash == "" {
		return fmt.Errorf("path_rule %q: basic auth requires a password hash", p.PathPrefix)
	}
	if p.IPFilter != nil {
		if err := p.IPFilter.Validate(); err != nil {
			return fmt.Errorf("path_rule %q: %w", p.PathPrefix, err)
		}
	}
	if hasUpstreams {
		// Per-URL syntax validation (validateUpstreamURL) lives only at the
		// API layer today, not in package storage — see Task 1 brief §Step 4
		// ambiguity note. Here we enforce what storage CAN check: a positive
		// weight per upstream, and a same-scheme pool.
		for i, u := range p.Upstreams {
			if u.URL == "" {
				return fmt.Errorf("path_rule %q: upstreams[%d].url must not be empty", p.PathPrefix, i)
			}
			if u.Weight < 1 {
				return fmt.Errorf("path_rule %q: upstreams[%d].weight must be >= 1", p.PathPrefix, i)
			}
		}
		if err := validateSameSchemePool(p.Upstreams); err != nil {
			return fmt.Errorf("path_rule %q: %w", p.PathPrefix, err)
		}
		// LBPolicy must be one of the six enum values, mirroring the
		// route-level validate() check. Only enforced when a pool is
		// present: an empty pool leaves LBPolicy unused/ignored, so a
		// blank LBPolicy on a protection-only rule (no upstreams) must
		// not be rejected.
		ok := false
		for _, lp := range LBPolicies {
			if p.LBPolicy == lp {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("path_rule %q: lb_policy %q is not a valid policy", p.PathPrefix, p.LBPolicy)
		}
	}
	return nil
}

// validateRedirect checks a path rule's redirect, including the loop
// the operator cannot see coming.
//
// A redirect whose target is matched by the rule that produced it
// bounces the browser until it gives up. For an exact rule that means
// a target equal to the path; for a prefix rule it means anything
// under it. Both are refused here, while the form is still open,
// rather than discovered from a browser.
func (p PathRule) validateRedirect() error {
	if p.Redirect == nil {
		return nil
	}
	target := strings.TrimSpace(p.Redirect.Target)
	if target == "" {
		return apierr.New("path_rule_redirect_target_required",
			map[string]string{"path": p.PathPrefix},
			"path_rule %q: the redirect needs a target", p.PathPrefix)
	}
	if p.Redirect.StatusCode != 0 && p.Redirect.StatusCode != 301 && p.Redirect.StatusCode != 302 {
		return apierr.New("path_rule_redirect_status",
			map[string]string{"path": p.PathPrefix, "status": strconv.Itoa(p.Redirect.StatusCode)},
			"path_rule %q: redirect status must be 301 or 302, got %d",
			p.PathPrefix, p.Redirect.StatusCode)
	}

	// An absolute URL leaves this host, so no local loop is possible;
	// only its shape is checked.
	if !strings.HasPrefix(target, "/") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return apierr.New("path_rule_redirect_target_invalid",
				map[string]string{"path": p.PathPrefix, "target": p.Redirect.Target},
				"path_rule %q: the redirect target must be a path starting with / or an "+
					"absolute http(s) URL, got %q", p.PathPrefix, p.Redirect.Target)
		}
		return nil
	}

	// A local target: would this very rule match it back?
	if p.matches(target) {
		return apierr.New("path_rule_redirect_loop",
			map[string]string{"path": p.PathPrefix, "target": p.Redirect.Target},
			"path_rule %q: the redirect target %q is matched by this same rule, so every "+
				"visitor would be redirected to it forever; point it outside the rule's own "+
				"path", p.PathPrefix, p.Redirect.Target)
	}
	return nil
}

// matches reports whether this rule would match the given path, using
// the same semantics the emitted Caddy matcher uses: the whole path
// when MatchExact, otherwise the prefix and everything under it.
func (p PathRule) matches(path string) bool {
	// Caddy compares against a lowercased request path.
	path = strings.ToLower(path)
	prefix := strings.ToLower(p.PathPrefix)
	if p.MatchExact {
		return path == prefix
	}
	return path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")
}

// SortPathRulesByPrefixLenDesc returns the rules ordered longest-prefix
// first (Q4). Stable so equal-length prefixes keep declaration order.
func SortPathRulesByPrefixLenDesc(rules []PathRule) []PathRule {
	out := make([]PathRule, len(rules))
	copy(out, rules)
	sort.SliceStable(out, func(i, j int) bool {
		return len(out[i].PathPrefix) > len(out[j].PathPrefix)
	})
	return out
}

// ForwardAuthRouteConfig is the per-route reference to one of the
// instance-level forward-auth providers (Step K.1, §5.1). The
// provider configuration itself lives in the
// `forward_auth_providers` bucket, indexed by name. Per-route
// data is the reference only — keeps the route row small and
// lets one provider serve N routes.
//
// Validation rules: when Route.AuthMode == RouteAuthForwardAuth,
// ProviderName must be non-empty AND must reference an existing
// provider in the forward_auth_providers bucket. The API layer
// looks up the provider at edit time and rejects the route
// create / update if no such provider exists (same pattern as
// J.4 DNS-01 provider check).
type ForwardAuthRouteConfig struct {
	ProviderName string `json:"provider_name"`
}

// LBPolicies is the canonical ordered list of allowed LBPolicy values.
// Used by validate() and by the API enum check. Order matches the
// constants above and §1.3 decision 2.
var LBPolicies = []string{
	LBPolicyRoundRobin,
	LBPolicyWeightedRoundRobin,
	LBPolicyLeastConn,
	LBPolicyIPHash,
	LBPolicyRandom,
	LBPolicyFirst,
}

// Upstream is one backend in a Route's upstream pool (Step J.1).
//
// The pool replaces the pre-J.1 single Route.UpstreamURL string. Each
// Upstream carries the dial URL and a Weight; Weight defaults to 1 and
// is consulted only by the weighted_round_robin LB policy — other
// policies ignore it (§1.3 decision 1, §5.1).
type Upstream struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// HealthCheck is the per-route active health-check configuration
// (Step J.2). Caddy applies these settings to every Upstream in the
// pool — a single HealthCheck per route, not per upstream (§1.3,
// §5.2).
//
// Wire shape mirrors Caddy v2.11.3's ActiveHealthChecks struct for the
// eight fields Arenet exposes. Interval and Timeout are kept as Go
// strings ("30s") rather than int nanoseconds because Caddy parses
// the string form at unmarshal time and the human-readable form is
// preserved end-to-end. None of the fields use `omitempty` —
// consistent with the existing Route pattern (Aliases, RequestHeaders,
// etc.).
//
// Defaults for Method / Interval / Timeout / Passes / Fails are
// materialised by the API layer BEFORE storage validation (§5.2).
// URI is the one field the operator must always supply when Enabled
// is true — there is no sensible default health-check path that fits
// every backend.
type HealthCheck struct {
	Enabled  bool   `json:"enabled"`
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Interval string `json:"interval"`
	Timeout  string `json:"timeout"`
	// ExpectStatus is the status the probe accepts. Zero means "any
	// 2xx". A value of 1-5 is Caddy's class shorthand — 3 accepts every
	// 3xx (caddyhttp.StatusCodeMatches, caddyhttp.go:230-240), which is
	// what an app that answers 302 on / needs.
	ExpectStatus int    `json:"expect_status"`
	ExpectBody   string `json:"expect_body"`
	Passes       int    `json:"passes"`
	Fails        int    `json:"fails"`
	// HostHeader overrides the Host the probe sends (v2.55). Empty means
	// the route's own host, which is what the real traffic carries.
	//
	// Caddy builds the probe from the DIAL address, so before v2.55 it
	// sent `Host: 10.0.0.2:80` — and a reverse proxy behind Arenet that
	// routes on Host answered 404 and every upstream was marked down
	// (caddy healthchecks.go:393-396; the header is only overridden when
	// one is configured, :452-455).
	HostHeader string `json:"host_header,omitempty"`
	// Headers are extra probe headers, e.g. an Authorization a health
	// endpoint requires. Host is NOT accepted here — it has its own
	// field, so there is one place to look for it.
	Headers map[string]string `json:"headers,omitempty"`
}

// ProbeHost returns the Host the active health check should send for a
// route whose primary host is routeHost.
//
// The operator's override wins; otherwise the probe carries the route's
// own host, so it looks to the backend like the traffic it is standing
// in for. An empty result means "send nothing", which leaves Caddy's
// dial-address behaviour untouched.
func (h HealthCheck) ProbeHost(routeHost string) string {
	if h.HostHeader != "" {
		return h.HostHeader
	}
	return routeHost
}

// MaintenanceConfig, when non-nil (and Disabled=false), puts the route
// in maintenance mode: Caddy serves 503 + the global maintenance page +
// Retry-After, except BypassIPs which reach the real upstream. Nil =
// not in maintenance (zero value, migration-free). Exiting maintenance
// sets this back to nil (clear-on-off).
type MaintenanceConfig struct {
	// RetryAfterSeconds is sent as the 503 Retry-After header and
	// substituted into the maintenance page. 0 = omit the header.
	RetryAfterSeconds int `json:"retryAfterSeconds,omitempty"`
	// BypassIPs is an IP/CIDR allow-list; matching clients reach the
	// real upstream instead of the 503.
	BypassIPs []string `json:"bypassIps,omitempty"`
	// Message is the per-route maintenance message rendered via the
	// {arenet.maintenance.message} placeholder (v2.18.1). When empty,
	// the emission falls back to the GLOBAL message
	// (MaintenancePageConfig.Message). Stored verbatim (plain text) —
	// HTML-escaped + {env.*}/{file.*}-neutralized at emission, not
	// here. omitempty keeps pre-v2.18.1 rows migration-free.
	Message string `json:"message,omitempty"`
}

// RedirectConfig, when non-nil (and Disabled=false,
// MaintenanceConfig=nil), makes the route answer a redirect instead of
// proxying anything. Nil = not redirecting (zero value,
// migration-free), and turning the state off sets it back to nil,
// exactly like MaintenanceConfig.
//
// v2.44 — see docs/superpowers/specs/2026-09-24-route-redirects-design.md.
// This is the whole-host scope: moving a domain. It cannot express "/
// goes to /admin/login" — the target would be on the same host and the
// redirect would match its own target. That need is the path-rule
// scope, and the loop is why Validate refuses a same-host target.
type RedirectConfig struct {
	// Target is an absolute URL: scheme (http or https) plus host.
	// With PreservePath it must carry no path of its own — see the
	// field below for why.
	Target string `json:"target"`
	// StatusCode is 301 or 302. Zero means 301, the permanent move
	// that a domain change almost always is.
	StatusCode int `json:"statusCode,omitempty"`
	// PreservePath appends the original path AND query to the target,
	// so old.example.com/a/b?c reaches new.example.com/a/b?c. That is
	// what a domain move wants, so the API and the UI default it on;
	// the zero value is false only for hand-written JSON.
	//
	// It is also why Validate refuses a target that already has a
	// path: appending to https://host/app would produce /app/a/b,
	// which is silently not what anyone asked for.
	PreservePath bool `json:"preservePath,omitempty"`
}

// RedirectStatusCodes are the two this feature offers. 307 and 308
// preserve the request method, which is a different decision with
// different consequences (a browser re-POSTing to another host); they
// are a documented non-goal rather than an oversight.
var RedirectStatusCodes = []int{301, 302}

// Validate checks the target is a usable absolute URL and the status
// code is one we offer. The same-host loop guard is NOT here: it needs
// the route's host and aliases, so it lives in Route.Validate.
func (rc *RedirectConfig) Validate() error {
	if rc == nil {
		return nil
	}
	target := strings.TrimSpace(rc.Target)
	if target == "" {
		return apierr.New("redirect_target_required", nil,
			"redirect: a target URL is required")
	}
	u, err := url.Parse(target)
	if err != nil {
		return apierr.New("redirect_target_invalid", map[string]string{"target": rc.Target},
			"redirect: target %q is not a valid URL: %v", rc.Target, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return apierr.New("redirect_target_scheme", map[string]string{"target": rc.Target},
			"redirect: target %q must start with http:// or https://", rc.Target)
	}
	if u.Host == "" {
		return apierr.New("redirect_target_no_host", map[string]string{"target": rc.Target},
			"redirect: target %q has no host", rc.Target)
	}
	if rc.PreservePath && u.Path != "" && u.Path != "/" {
		return apierr.New("redirect_target_has_path",
			map[string]string{"target": rc.Target, "path": u.Path, "host": u.Host},
			"redirect: target %q already has a path (%q) — with \"keep the path\" on, the "+
				"visitor's own path is appended, which would produce %s%s/...; either drop the "+
				"path from the target or turn \"keep the path\" off",
			rc.Target, u.Path, u.Host, u.Path)
	}
	if rc.StatusCode != 0 && rc.StatusCode != 301 && rc.StatusCode != 302 {
		return apierr.New("redirect_status_unsupported",
			map[string]string{"status": strconv.Itoa(rc.StatusCode)},
			"redirect: statusCode must be 301 or 302, got %d", rc.StatusCode)
	}
	return nil
}

// Code returns the status code to emit, resolving the zero value.
func (rc *RedirectConfig) Code() int {
	if rc == nil || rc.StatusCode == 0 {
		return 301
	}
	return rc.StatusCode
}

// TargetHost returns the target's host without its port, lowercased,
// for the same-host comparison. Empty when the target is unparseable —
// Validate reports that separately.
func (rc *RedirectConfig) TargetHost() string {
	if rc == nil {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(rc.Target))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Validate rejects a negative Retry-After and any bypass entry that is
// neither a bare IP nor a CIDR.
func (m *MaintenanceConfig) Validate() error {
	if m == nil {
		return nil
	}
	if m.RetryAfterSeconds < 0 {
		return fmt.Errorf("maintenance: retryAfterSeconds must be >= 0, got %d", m.RetryAfterSeconds)
	}
	for _, e := range m.BypassIPs {
		if _, _, err := net.ParseCIDR(e); err == nil {
			continue
		}
		if net.ParseIP(e) != nil {
			continue
		}
		return fmt.Errorf("maintenance: bypass entry %q is not an IP or CIDR", e)
	}
	return nil
}

// Route is a proxied virtual host served by Arenet.
type Route struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	// Upstreams (Step J.1) is the pool of backends this route fans
	// traffic to. At least one element; created with one element by
	// the migrateUpstreamURLToPool boot migration for pre-J.1 rows.
	// The pre-J.1 UpstreamURL string field is gone — its value lives
	// at Upstreams[0].URL after migration. See spec §5.1, §6.1.
	Upstreams []Upstream `json:"upstreams"`
	// LBPolicy (Step J.1) is the load-balancing selection policy
	// Caddy applies across Upstreams. One of: round_robin (default),
	// weighted_round_robin, least_conn, ip_hash, random, first.
	// Materialised at create time and by the boot migration; never
	// empty post-J.1 (§5.1, §1.3 decision 2).
	LBPolicy   string `json:"lb_policy"`
	TLSEnabled bool   `json:"tls_enabled"`
	// RedirectToHTTPS (Step I.1, used by I.2) requests Caddy to
	// emit a 301 from http://<host>/* to https://<host>/* when the
	// matching route has TLSEnabled=true. Zero value is false: pre-
	// Step-I.1 routes silently keep the no-redirect behavior. The
	// wire JSON below this struct uses camelCase to match the API
	// shape; storage tags use snake_case for legacy reasons.
	RedirectToHTTPS bool `json:"redirect_to_https"`
	// Aliases (Step I.3) are additional hostnames served by the
	// SAME upstream. Caddy matches any of (Host ∪ Aliases) for this
	// route, and ACME issues a single multi-SAN cert covering them
	// all. Stored as a JSON array; pre-Step-I.3 routes decode with
	// a nil slice (zero value), which is treated identically to an
	// empty slice everywhere downstream.
	Aliases []string `json:"aliases"`
	// AuthMode (Step K.1) picks the per-route authentication
	// strategy: "none" / "basic" / "forward_auth". Mutually
	// exclusive (§1.3 decision 2). Step I.5 BasicAuth fields
	// previously lived flat on Route; they are now nested in
	// BasicAuth below, gated by AuthMode == RouteAuthBasic.
	// Empty string decodes for pre-K rows and is rewritten by
	// migrateBasicAuthToAuthMode at boot to "basic" (if the
	// pre-K BasicAuthEnabled was true) or "none" (otherwise).
	AuthMode string `json:"auth_mode"`
	// BasicAuth (Step K.1, replaces the flat Step I.5 fields).
	// Active when AuthMode == RouteAuthBasic. Empty when not.
	// The PasswordHash is an argon2id PHC string — NEVER
	// exposed over the API (the response surface uses a
	// derived BasicAuthPasswordSet bool instead) and NEVER
	// embedded in audit events.
	BasicAuth BasicAuthRouteConfig `json:"basic_auth"`
	// ForwardAuth (Step K.1) — per-route reference to an
	// instance-level forward-auth provider. Active when
	// AuthMode == RouteAuthForwardAuth.
	ForwardAuth ForwardAuthRouteConfig `json:"forward_auth"`
	// RequestHeaders (Step I.6) are key/value pairs set on the
	// proxied request before it reaches the upstream; ResponseHeaders
	// are set on the response before it reaches the client. Both
	// default nil; the API layer normalizes nil → {} on the wire so
	// frontend callers can iterate without a null check. Validation
	// (RFC 7230 token name, CR/LF-free value, hop-by-hop blacklist)
	// lives in internal/api/routes.go — storage trusts the API.
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	// WAFMode (Step I.4) replaces the pre-I.4 WAFEnabled bool with a
	// three-valued enum: "off" / "detect" / "block".
	//   - off    : no WAF inspection, no Caddy handler emitted.
	//   - detect : Coraza inspects, logs matches, lets traffic pass
	//              (SecRuleEngine DetectionOnly — FortiWeb-style
	//              safe shadow mode; recommended starting point).
	//   - block  : Coraza inspects and returns 403 on match
	//              (SecRuleEngine On).
	// Pre-I.4 routes with WAFEnabled=true are migrated to "block"
	// (semantic equivalent of "block on every detection"); WAFEnabled=
	// false routes are migrated to "off". See migrateWAFEnabledToWAFMode.
	WAFMode string `json:"waf_mode"`
	// ACMEChallenge (Step J.4) is the ACME challenge type used to
	// issue / renew the certificate for this route's hostnames when
	// TLSEnabled is true. One of: "http-01" (default), "dns-01".
	// Empty string decodes for pre-J.4 rows and is treated by the
	// API + generator as equivalent to "http-01" — no migration
	// needed. Only "dns-01" can issue wildcard certificates (the
	// API rejects a wildcard host with http-01). DNS-01 requires
	// the instance-level DNSProviderConfig to be configured; the
	// API enforces that at edit time (§5.4).
	ACMEChallenge string `json:"acme_challenge"`
	// UseDedicatedCert (Step O.1, spec D1.B) opts a covered route
	// OUT of the managed-domain wildcard cert and into per-route
	// ACME issuance. Default false: routes whose host is covered by
	// a managed domain inherit the wildcard cert. When true, the
	// route emits its own ACME challenge (HTTP-01 or DNS-01 per
	// ACMEChallenge) regardless of any covering managed domain. The
	// validator rejects UseDedicatedCert=true alongside
	// ACMEChallenge="inherited" (inconsistent — pick one path).
	UseDedicatedCert bool `json:"use_dedicated_cert,omitempty"`
	// HealthCheck (Step J.2) is the active health-check configuration
	// Caddy applies to every Upstream in the pool. Zero-value
	// (Enabled: false) means no probe runs — the generator omits the
	// `health_checks` Caddy block entirely. When Enabled is true the
	// remaining eight fields carry the probe parameters (see the
	// HealthCheck type above this Route struct). Materialisation of
	// the five defaultable fields (Method, Interval, Timeout, Passes,
	// Fails) happens at the API layer BEFORE the storage write —
	// storage.validate() is the last line of defence, strict (e.g.
	// Passes < 1 rejected) without blank-or-positive branching.
	HealthCheck HealthCheck `json:"health_check"`
	// CountryBlock (Step W) — per-route geo allow/deny gate. Active
	// when Mode is one of {ModeAllow, ModeDeny}. Empty / ModeOff
	// means the country-block handler is not even emitted in the
	// per-route Caddy chain (W.3 caddymgr skip-emission). Pre-W
	// rows decode with zero-value CountryBlock{Mode: ""} which
	// validates as "off" — no boot migration needed (the JSON
	// decoder zero-fills missing keys).
	//
	// Wire shape uses snake_case here per the storage convention;
	// the API layer (W.2 internal/api/routes.go) maps to/from a
	// camelCase routeRequest.CountryBlock mirror.
	CountryBlock countryblock.Config `json:"country_block"`
	// v1 path-based-rules. Empty on pre-v1 routes (migration-free).
	IPFilter  *IPFilter  `json:"ip_filter,omitempty"`  // whole-domain source-IP gate
	PathRules []PathRule `json:"path_rules,omitempty"` // per-sub-path overrides (additive)
	// InsecureSkipVerify (Step #R-PROXMOX-HTTPS-LOOP, 2026-06-10)
	// opts the route's upstream pool out of TLS certificate
	// verification when at least one Upstream URL uses the
	// `https://` scheme. Default false (strict: validate the
	// upstream's cert against the system trust store).
	//
	// Route-level not per-upstream because Caddy's reverse_proxy
	// `transport.tls` block is per-handler, not per-upstream
	// (verified against caddyserver/caddy@v2/modules/caddyhttp/
	// reverseproxy/httptransport.go). Per-upstream TLS configs
	// would require a different proxy plugin; deferred as a
	// future enhancement if a real need surfaces.
	//
	// Storage validate enforces a same-scheme pool: if any
	// Upstream is `https://`, ALL must be `https://`. Mixed
	// pools are rejected at create/update time with a clear
	// error so an operator can't accidentally point an
	// http-only Caddy transport at an https upstream.
	//
	// Pre-#R-PROXMOX rows decode with zero-value
	// InsecureSkipVerify=false — strict by default, matches
	// the operator-safer "verify everything" baseline. No
	// boot migration needed (the JSON decoder zero-fills
	// missing keys). See docs/superpowers/decisions/
	// 2026-06-10-https-upstream-tls-transport.md.
	//
	// JSON omitempty so the field is silently absent on
	// http-only routes — keeps the on-wire / on-disk shape
	// byte-equal with pre-fix snapshots for HTTP routes,
	// minimising diff noise during backup/restore.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
	// UploadStreamingMode (Phase 4.5, #R-WAF-BUFFER-OOM-ON-
	// LARGE-UPLOADS, 2026-06-14) is a per-route toggle that
	// neutralises the two RAM-buffering surfaces hit by big
	// request bodies (Docker registry pushes, file servers,
	// backups):
	//
	//   1. WAF body inspection — when this flag is true, the
	//      Coraza transaction skips ReadRequestBodyFrom so
	//      the upload is not staged in memory for rule
	//      scanning. Headers, URI, method, and the upstream
	//      response are still inspected; only the request
	//      body is left unscanned.
	//
	//   2. Caddy reverse_proxy buffering — when true,
	//      caddymgr emits `flush_interval: -1` on the
	//      reverse_proxy handler, which sets
	//      httputil.ReverseProxy.FlushInterval to -1 and
	//      tells Caddy to forward bytes as they arrive
	//      instead of staging them.
	//
	// Empirical evidence: VM 4 GB RAM, WAF=detect on a
	// registry route + Docker push → 3.5 GB RSS → OOM kill.
	// Same VM, WAF=off → 257 MB RSS, push succeeds. The 14x
	// gap is the Coraza body buffer combined with Caddy's
	// default buffered proxy. UploadStreamingMode neutralises
	// both without forcing the operator to disable the WAF
	// entirely — headers/URI rules still fire.
	//
	// Default false. WAFMode and UploadStreamingMode are
	// independent: any combination is valid. The combo
	// {WAFMode=block, UploadStreamingMode=true} keeps the
	// header/URI block surface live while leaving body bytes
	// alone — exactly the right posture for routes that
	// proxy large opaque payloads (binary uploads, encrypted
	// archives) where body inspection has near-zero security
	// signal and a high OOM cost.
	//
	// JSON omitempty so HTTP/non-streaming routes stay
	// byte-equal with pre-fix snapshots on disk and in
	// backup/restore exports.
	UploadStreamingMode bool `json:"upload_streaming_mode,omitempty"`
	// WAFDisableCRS (Step X.1, 2026-06-17) is the per-route opt-
	// out from the OWASP Core Rule Set load. When true, the
	// route's arenet_waf handler runs with @coraza.conf-recommended
	// only — the WAF engine is wired (events still emit if a rule
	// happens to fire) but NO CRS rule families are loaded, so
	// the per-request cost drops to a Coraza dispatch with zero
	// rules to evaluate. When false (the default for every
	// pre-X.1 route + every fresh-create route), the handler
	// keeps the pre-X.1 directives chain
	// (`Include @coraza.conf-recommended` + `@crs-setup.conf.example`
	// + `@owasp_crs/*.conf`) and loads the full CRS via the
	// embedded FS.
	//
	// Polarity rationale: the inverted shape ("disable" defaults
	// to false ⇒ CRS loaded) means pre-X.1 stored routes decode
	// with WAFDisableCRS=false ⇒ byte-equivalent runtime to the
	// pre-X.1 behaviour. No boot migration needed (the
	// migrateWAFEnabledToWAFMode / migrate.go pattern is reserved
	// for shape changes where the zero-value would mean something
	// wrong; here zero ⇒ "current behaviour", so the JSON decoder's
	// zero-fill is the migration). See ADR D2 + D5 in
	// docs/superpowers/decisions/2026-06-17-step-owasp-per-route-
	// decisions.md.
	//
	// Use case: trusted internal API ("nas.lan", "prometheus.local")
	// where the operator wants the WAF infrastructure wired
	// (mode-aware sink, event audit, dashboard counter all still
	// fire if a rule were loaded) but doesn't want the ~10 ms
	// per-request cost or the ~50 MB warm-pool RAM of the full
	// CRS load. WAFMode and WAFDisableCRS are independent: any
	// combination is valid. The natural combo
	// {WAFMode=detect, WAFDisableCRS=true} keeps the handler
	// observing but loads zero rules, so the operator can flip
	// the disable bit off when they want to actually inspect.
	//
	// JSON omitempty so pre-X.1 routes (and routes that keep
	// the default) stay byte-equal with pre-X.1 snapshots on disk
	// + in backup/restore exports.
	WAFDisableCRS bool `json:"waf_disable_crs,omitempty"`
	// WAFExcludeRules (Step X Option (c), 2026-06-18) is the
	// per-route list of CRS rule IDs the operator wants
	// SILENCED on this route while keeping the rest of the CRS
	// active. Empty (nil or zero-length) = no exclusions = the
	// arenet_waf handler runs with the full CRS chain (or
	// whatever WAFDisableCRS / WAFMode let through), so pre-
	// Y stored routes decode to byte-equivalent runtime
	// behaviour. No boot migration needed.
	//
	// Use case : the operator hits a false-positive on a
	// single rule (e.g. CRS 942100 triggering on a legitimate
	// SQL-heavy POST). Adding the rule ID to this list disables
	// it on this route ONLY, without nuking the whole SQLi
	// family (Option (b)) or the entire CRS (Option (a)).
	// Surgical fix.
	//
	// Interaction with WAFDisableCRS : when WAFDisableCRS is
	// true the entire CRS isn't loaded, so per-rule exclusions
	// are meaningless. The frontend greys the input ; the
	// caddymgr emit still ships the SecAction directive (it's
	// a no-op when there are no CRS rules to ctl-remove) so
	// flipping WAFDisableCRS back to false re-engages the
	// rules + the operator's exclusion list in one step.
	//
	// Validation : every ID must be a positive integer. The
	// CRS rule-id space is 100000-999999 (6-digit), with
	// Arenet reserving 100000-199999 for its own internal
	// directives (admin-API exclusion, future generated
	// SecRules). The API layer rejects IDs in the reserved
	// range with a 400.
	//
	// JSON omitempty so pre-Y routes (and routes that keep the
	// default empty list) stay byte-equal with pre-Y snapshots
	// on disk + in backup/restore exports.
	WAFExcludeRules []int `json:"waf_exclude_rules,omitempty"`
	// WAFExcludeTags (Step X Option (e), 2026-06-22) is the
	// per-route list of OWASP CRS tag strings the operator
	// wants SILENCED. Tag-based exclusion is the operator-
	// friendly sibling of WAFExcludeRules : instead of
	// enumerating N cryptic rule IDs that share a tag
	// (e.g. excluding 911100, 911011, 911012, ... all tagged
	// "attack-protocol"), the operator can supply the single
	// tag string and the whole family bypasses for this route.
	//
	// Use case : a route hosting a legacy client that sends
	// non-RFC HTTP requests triggers the entire
	// "attack-protocol" tag family. One entry here kills the
	// family without the operator having to enumerate the
	// 15+ rule IDs. A future CRS upgrade that adds new rules
	// to the same tag automatically inherits the exclusion.
	//
	// Tag matching semantics (verified empirically against
	// Coraza v3.7.0 rulegroup.go:136-144 + strings.go:118-125) :
	// EXACT BYTE EQUALITY, case-sensitive, no wildcards, no
	// regex. The API layer canonicalises operator input to
	// lowercase + dedupes + sorts at normalizeExcludeTags
	// time so the emit pool-key + the on-wire shape stay
	// stable.
	//
	// Interaction with WAFDisableCRS : same as WAFExcludeRules.
	// When the CRS is disabled the tag exclusions become no-ops
	// but the caddymgr emit still ships them in the SecAction
	// so toggling DisableCRS back to false re-engages
	// everything atomically.
	//
	// JSON omitempty so pre-X(e) routes stay byte-equal with
	// pre-X(e) snapshots on disk + in backup/restore exports.
	WAFExcludeTags []string `json:"waf_exclude_tags,omitempty"`
	// WAFTargetedExclusions (v2.36) narrows a CRS rule instead of
	// removing it: the rule stops inspecting one field, optionally
	// on one path only. Created from a WAF event ("Exclude…") or
	// by hand in the route form. Empty = no extra directives, so
	// routes without it keep byte-identical Caddy config.
	WAFTargetedExclusions []WAFTargetedExclusion `json:"waf_targeted_exclusions,omitempty"`
	// WAFCustomRules (v2.37) are the route's guided WAF rules (block
	// when every condition matches). Empty = no extra directives.
	WAFCustomRules []WAFCustomRule `json:"waf_custom_rules,omitempty"`
	// WAFSecLang (v2.38) is the route's expert SecLang, checked by
	// waf.CheckSecLang (allowlist, rule IDs 130000-139999) and emitted
	// before the CRS. Empty = no extra directives.
	WAFSecLang string `json:"waf_seclang,omitempty"`
	// RateLimit (Step Q, 2026-06-18) is the per-route rate
	// limiting configuration that gates inbound requests
	// BEFORE the WAF / country-block / CrowdSec chain runs.
	// Nil pointer = no rate limit on this route ; non-nil
	// = mholt/caddy-ratelimit zone with the operator-
	// supplied (Events, Window, Key) tuple.
	//
	// Polarity rationale : positive opt-in (nil = no limit
	// = pre-Q byte-equivalent runtime). No boot migration
	// needed ; pre-Q stored rows decode WAFExcludeRules
	// fine alongside a nil RateLimit and Caddy emits no
	// rate_limit handler for them — chain shape unchanged.
	//
	// Use cases :
	//  - login routes : 5 / 1 m on {http.request.remote.host}
	//    blunts credential-stuffing without locking out a
	//    NAT'd household.
	//  - public API routes : 100 / 1 m caps a single client
	//    from monopolising the upstream.
	//  - trusted internal API : leave nil ; full throttle
	//    only happens via the global system throttle.
	//
	// Key field accepts any Caddy placeholder. Defaults to
	// {http.request.remote.host} (raw socket peer IP, no
	// X-Forwarded-For trust). Operators on a trusted-proxy
	// deployment can override to {http.request.header.X-
	// Forwarded-For} or similar.
	RateLimit *RouteRateLimit `json:"rate_limit,omitempty"`
	// ErrorPageTemplateID (Step R) is the UUID of an
	// ErrorPageTemplate this route applies for the supported
	// 4xx/5xx status codes. Empty string means "fall back to the
	// built-in Arenet default templates". A dangling reference
	// (template deleted after the route was created) also falls
	// back to the default — the caddymgr emit logs a warning
	// when it can't resolve the ID.
	ErrorPageTemplateID string `json:"error_page_template_id,omitempty"`
	// ErrorPageOverrides (Step R) layers per-route HTML body
	// overrides on top of the chosen template. Keys MUST be in
	// SupportedErrorStatusCodes ; values are raw HTML expanded
	// at Caddy serve time via the standard runtime placeholders
	// ({http.error.status_code}, {http.request.uri}, ...).
	//
	// Resolution order at emit time :
	//   1. Route.ErrorPageOverrides[code]  (per-route override)
	//   2. Template.Pages[code]            (template the route opted into)
	//   3. arenetDefaultErrorPages[code]   (built-in caddymgr default)
	// The first non-empty hit wins.
	ErrorPageOverrides map[int]string `json:"error_page_overrides,omitempty"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"updated_at"`
	// Disabled (v2.14.3) takes a route out of service WITHOUT
	// deleting its config. When true, the route is filtered out
	// before the Caddy config is built (caddymgr applyLocked), so
	// it is not routed AND no cert is requested for its host —
	// requests fall to the branded catch-all 404. Zero value is
	// false = enabled: pre-v2.14.3 routes and old backups decode
	// as enabled (backward-safe, no migration). Polarity mirrors
	// WAFDisableCRS / InsecureSkipVerify — the JSON zero-value must
	// equal legacy behavior. omitempty keeps enabled routes'
	// wire bytes identical to pre-feature routes.
	Disabled bool `json:"disabled,omitempty"`
	// MaintenanceConfig, when non-nil, puts the route in maintenance
	// mode (see the MaintenanceConfig type doc above). Nil is the
	// zero value — pre-feature routes and fresh creates decode with
	// no maintenance active, no migration needed.
	MaintenanceConfig *MaintenanceConfig `json:"maintenanceConfig,omitempty"`
	// RedirectConfig (v2.44), when non-nil, makes the route answer a
	// redirect instead of proxying (see the RedirectConfig type doc).
	// Nil is the zero value and keeps pre-v2.44 rows migration-free.
	// Mutually exclusive with MaintenanceConfig — Validate enforces it.
	RedirectConfig *RedirectConfig `json:"redirectConfig,omitempty"`
	// CertSource (v2.19.0) selects the cert provider: "" or "acme"
	// (ACME, default), "internal" (self-signed), "manual" (external
	// uploaded cert referenced by CertID). Zero value = acme
	// (migration-free).
	CertSource string `json:"cert_source,omitempty"`
	// CertID references an ExternalCertificate.ID; required when
	// CertSource == "manual".
	CertID string `json:"cert_id,omitempty"`
}

// RouteCertSourceManual is the CertSource value selecting an
// operator-uploaded external certificate (referenced by CertID).
const RouteCertSourceManual = "manual"

// HostMatchesSAN reports whether host is covered by any SAN, with
// RFC 6125 single-label wildcard semantics ("*.example.com" covers
// "app.example.com" but not "sub.app.example.com" nor "example.com").
// Case-insensitive.
func HostMatchesSAN(host string, sans []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSuffix(san, "."))
		if san == host {
			return true
		}
		if strings.HasPrefix(san, "*.") {
			suffix := san[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) {
				label := host[:len(host)-len(suffix)]
				if label != "" && !strings.Contains(label, ".") {
					return true
				}
			}
		}
	}
	return false
}

// RouteRateLimit (Step Q, 2026-06-18) — per-route rate limit
// config emitted as an mholt/caddy-ratelimit zone.
//
// Validation contract (applied at the API layer + a
// belt-and-suspenders boot-time decode check) :
//   - Events >= 1 (zero would block every request and is
//     almost certainly a typo).
//   - Window parses cleanly via time.ParseDuration.
//   - Key default-initialised to "{http.request.remote.host}"
//     when empty at decode/emit time so the operator can
//     leave it blank in the UI for the common case.
type RouteRateLimit struct {
	// Events is the maximum number of requests allowed
	// within Window. mholt/caddy-ratelimit uses a sliding-
	// window algorithm so the limit is rolling, not a hard
	// per-minute reset.
	Events int `json:"events"`
	// Window is the sliding window duration. Stored as a
	// Go-time-parseable string ("30s", "1m", "5m", "1h").
	// caddy.Duration accepts the same shape so the wire
	// format passes through without parse work.
	Window string `json:"window"`
	// Key is the Caddy placeholder string the rate-limit
	// zone uses to partition counters. Empty at decode
	// time → defaulted to "{http.request.remote.host}" by
	// the caddymgr emit.
	Key string `json:"key,omitempty"`
}

// AllHosts returns the full ordered list of hostnames this route
// answers to: [Host, Aliases...]. The primary Host always comes
// first so callers that need a deterministic ordering (Caddy
// match.host, ACME subjects, audit log) get a stable shape.
func (r Route) AllHosts() []string {
	out := make([]string, 0, 1+len(r.Aliases))
	out = append(out, r.Host)
	out = append(out, r.Aliases...)
	return out
}

// ValidateRoute is the exported shim around the package-private
// validate(). The internal/backup package calls it during the
// import pipeline to re-validate business invariants before
// committing the snapshot. Existing internal callers stay on the
// private form (one less import on the hot path).
//
// Step K.3: the derogation for AllowIncompleteRestore is NOT
// embedded here — the caller (internal/backup) knows which fields
// it cleared on purpose and substitutes a non-empty placeholder
// before calling ValidateRoute, or skips ValidateRoute for that
// field specifically. Keeping the validator pure-grid stays true
// to the J.1 contract.
func ValidateRoute(r Route) error {
	return r.validate()
}

// upstreamScheme returns the lowercased scheme of an
// Upstream URL, or "" when the URL doesn't parse cleanly /
// has no scheme. Used by validateSameSchemePool to enforce
// the same-scheme invariant across a route's pool.
func upstreamScheme(raw string) string {
	// Lightweight prefix check first — most URLs are
	// well-formed and parsing them via net/url adds a real
	// allocation per check. Fast path: catch the two valid
	// forms; fall through to net/url only on edge cases.
	switch {
	case len(raw) >= 7 && (raw[:7] == "http://" || raw[:7] == "HTTP://"):
		return "http"
	case len(raw) >= 8 && (raw[:8] == "https://" || raw[:8] == "HTTPS://"):
		return "https"
	}
	return ""
}

// validateSameSchemePool enforces that all Upstreams in a
// pool share the same scheme. See the call-site comment in
// Route.validate for the rationale.
func validateSameSchemePool(pool []Upstream) error {
	var first string
	for i, u := range pool {
		s := upstreamScheme(u.URL)
		if i == 0 {
			first = s
			continue
		}
		if s != first {
			return fmt.Errorf(
				"route: upstreams must share the same scheme "+
					"(upstreams[0]=%q, upstreams[%d]=%q) — mixed http/https pools are not supported",
				first, i, s,
			)
		}
	}
	return nil
}

// PoolUsesHTTPS reports whether the route's upstream pool
// requires Caddy to negotiate TLS toward the upstreams.
// Returns true iff every Upstream URL uses the https://
// scheme. Used by:
//   - The caddymgr config builder to decide whether to
//     emit transport.tls in the reverse_proxy block.
//   - The API + frontend to decide whether to surface the
//     InsecureSkipVerify toggle.
//
// Same-scheme invariant means we only need to inspect
// upstreams[0] for the answer — the storage validator
// guarantees the rest agree.
func (r Route) PoolUsesHTTPS() bool {
	if len(r.Upstreams) == 0 {
		return false
	}
	return upstreamScheme(r.Upstreams[0].URL) == "https"
}

// validate checks the user-supplied fields of a Route.
func (r *Route) validate() error {
	if r.Host == "" {
		return errors.New("route: host must not be empty")
	}
	// Step J.1: upstream pool must contain at least one element, each
	// with a non-empty URL and a strictly positive weight. The API
	// layer validates the URL shape (http/https scheme, non-empty
	// host) earlier with friendlier messages; storage's job is to
	// reject obviously inconsistent rows that bypass the API.
	// v2.45.2 — a redirecting route proxies nothing, so demanding a
	// backend for it is asking the operator to invent an address that
	// will never be dialled. The operator hit this creating a route
	// whose only job was to forward a retired name.
	//
	// Every other route still needs a pool: without one there is
	// nothing to serve.
	if len(r.Upstreams) == 0 && r.RedirectConfig == nil {
		return errors.New("route: upstreams must contain at least one entry")
	}
	for i, u := range r.Upstreams {
		if u.URL == "" {
			return fmt.Errorf("route: upstreams[%d].url must not be empty", i)
		}
		if u.Weight < 1 {
			return fmt.Errorf("route: upstreams[%d].weight must be >= 1", i)
		}
	}
	// Step #R-PROXMOX-HTTPS-LOOP (2026-06-10): same-scheme pool
	// invariant. All Upstreams in the pool must share the same
	// scheme (all http:// or all https://). Mixed pools are
	// rejected because Caddy's reverse_proxy `transport.tls` is
	// per-handler — a pool of [http://a, https://b] would force
	// b's TLS context to apply to a's connection too, and
	// although Caddy ignores it for a (it only negotiates TLS
	// when the upstream is actually HTTPS-shaped), the
	// configuration intent is incoherent: an operator banning a
	// mixed pool is signalling something they probably didn't
	// mean.
	//
	// Empty-scheme tolerated for forward-compat (a pre-fix row
	// that somehow ended up with a scheme-less URL won't fail
	// boot; the upstreamDial path defaults to http). The API
	// layer validates scheme presence at create/update time
	// with a friendlier error.
	if err := validateSameSchemePool(r.Upstreams); err != nil {
		return err
	}
	// Step J.1: LBPolicy must be one of the six enum values. Empty is
	// rejected here because the API layer is responsible for
	// materialising the default (round_robin) before validation runs;
	// a row reaching storage with an empty LBPolicy is a programming
	// error, not a user-input case.
	{
		ok := false
		for _, p := range LBPolicies {
			if r.LBPolicy == p {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("route: lb_policy %q is not a valid policy", r.LBPolicy)
		}
	}
	// Step I.3: intra-route alias rules. Storage is the last line
	// of defense; the API layer also enforces these so the user
	// gets a 400 with a friendlier message. Keeping the check here
	// guarantees that any direct CreateRoute / UpdateRoute call
	// (tests, future internal callers) cannot smuggle a malformed
	// alias set into BoltDB.
	seen := make(map[string]struct{}, len(r.Aliases))
	for _, a := range r.Aliases {
		if a == "" {
			return errors.New("route: alias must not be empty")
		}
		if a == r.Host {
			return fmt.Errorf("route: alias %q duplicates the primary host", a)
		}
		if _, dup := seen[a]; dup {
			return fmt.Errorf("route: alias %q duplicates within the same route", a)
		}
		seen[a] = struct{}{}
	}
	// Step K.1: AuthMode enum check + per-mode sub-rules. The
	// empty string is accepted at the storage layer (a pre-K
	// row reads back zero-value before the boot migration runs;
	// not strictly possible because migrateBasicAuthToAuthMode
	// runs at NewStore time, but storage stays defensive).
	// The API layer materialises empty → "none" on POST and
	// preserve-previous on PUT before validate is invoked.
	switch r.AuthMode {
	case "", RouteAuthNone:
		// No auth; the BasicAuth and ForwardAuth structs are
		// inert. Storage trusts the API to not have populated
		// secret fields here, but a stray hash would just be
		// ignored at generation time (no handler emitted).
	case RouteAuthBasic:
		if r.BasicAuth.Username == "" {
			return errors.New("route: basic_auth.username must not be empty when auth_mode is \"basic\"")
		}
		if r.BasicAuth.PasswordHash == "" {
			return errors.New("route: basic_auth.password_hash must not be empty when auth_mode is \"basic\"")
		}
	case RouteAuthForwardAuth:
		if r.ForwardAuth.ProviderName == "" {
			return errors.New("route: forward_auth.provider_name must not be empty when auth_mode is \"forward_auth\"")
		}
		// Cross-rule "provider must exist" lives at the API
		// layer (it needs the store handle); storage's role is
		// the local-shape check.
	default:
		return fmt.Errorf("route: auth_mode %q must be one of \"none\", \"basic\", \"forward_auth\"", r.AuthMode)
	}
	// Step J.4 + O.1: ACMEChallenge enum check. The empty string is
	// accepted explicitly — a pre-J.4 row reads back with no
	// `acme_challenge` key (zero value ""), and the API + generator
	// both treat that as equivalent to "http-01". Step O.1 adds the
	// "inherited" sentinel for routes covered by a managed-domain
	// wildcard (spec D8.A). Any other value is a programming error
	// (the API rejects unknown values with a friendlier message
	// before reaching here). The cross-rules (wildcard host requires
	// dns-01, dns-01 requires a configured DNSProviderConfig,
	// "inherited" requires a covering managed domain) belong at the
	// API layer — storage stays a pure grid (same separation as J.1
	// / J.2).
	switch r.ACMEChallenge {
	case "", ACMEChallengeHTTP01, ACMEChallengeDNS01, ACMEChallengeInherited:
	default:
		return fmt.Errorf("route: acme_challenge %q must be http-01, dns-01, or inherited", r.ACMEChallenge)
	}
	// Step O.1 spec D1.B: UseDedicatedCert=true alongside
	// ACMEChallenge="inherited" is inconsistent — the route either
	// inherits the wildcard (inherited) OR opts out into a dedicated
	// per-route cert (useDedicatedCert) but not both.
	if r.UseDedicatedCert && r.ACMEChallenge == ACMEChallengeInherited {
		return errors.New(`route: use_dedicated_cert cannot be true while acme_challenge is "inherited" (pick one)`)
	}
	// Step W: per-route country-block validation. Delegates to
	// countryblock.Config.Validate so the §D2 footgun (allow + empty
	// list) is caught even when a hand-crafted JSON bypasses the
	// API layer. Pre-W rows decode with zero-value Mode == "" which
	// is accepted as a synonym for "off" (no migration needed).
	if err := r.CountryBlock.Validate(); err != nil {
		return err
	}
	// v1 path-based-rules: whole-domain IPFilter (nil is a no-op) and
	// each PathRule, plus a duplicate-PathPrefix guard so a hand-
	// crafted JSON can't declare two overlapping rules for the same
	// sub-tree (ambiguous emission order).
	if r.IPFilter != nil {
		if err := r.IPFilter.Validate(); err != nil {
			return err
		}
	}
	seenPrefix := make(map[string]struct{}, len(r.PathRules))
	for _, pr := range r.PathRules {
		if err := pr.Validate(); err != nil {
			return err
		}
		if _, dup := seenPrefix[pr.PathPrefix]; dup {
			return fmt.Errorf("path_rules: duplicate path_prefix %q", pr.PathPrefix)
		}
		seenPrefix[pr.PathPrefix] = struct{}{}
	}
	// Step J.2: active health-check validation, gated by Enabled.
	// When Enabled is false the sub-fields are inert; storage does
	// not touch them. When true the API layer has already
	// materialised the five defaultable fields (Method, Interval,
	// Timeout, Passes, Fails) before validate() runs, so the
	// checks below are uniformly strict — no "blank or positive"
	// branching. URI is the one field operators must always supply
	// (§5.2): there is no sensible default health-check path.
	if r.HealthCheck.Enabled {
		if err := r.HealthCheck.validate(); err != nil {
			return err
		}
	}
	// Step R: per-route ErrorPageOverrides must only target the
	// supported status codes ; an out-of-set key would silently
	// never render, which is operator-confusing. The template ref
	// is NOT validated for existence here — storage stays a pure
	// grid and the dangling-ref path falls back to the built-in
	// default cleanly at caddymgr emit time. Body size cap mirrors
	// the template-side validator (1 MiB) so a hand-crafted JSON
	// bypassing the API layer can't bloat the bolt value past sane.
	for code, body := range r.ErrorPageOverrides {
		if !IsSupportedErrorStatusCode(code) {
			return fmt.Errorf("route: error_page_overrides has unsupported status code %d (allowed: %v)",
				code, SupportedErrorStatusCodes)
		}
		if len(body) > 1<<20 {
			return fmt.Errorf("route: error_page_overrides[%d] exceeds 1 MiB (%d bytes)", code, len(body))
		}
	}
	// MaintenanceConfig: nil is inert (route not in maintenance); a
	// non-nil config is validated so a bad bypass IP/CIDR or a
	// negative Retry-After is rejected at the storage layer, the
	// same last-line-of-defence pattern as CountryBlock / HealthCheck
	// above.
	if err := r.MaintenanceConfig.Validate(); err != nil {
		return err
	}
	// RedirectConfig (v2.44): same last-line-of-defence posture as
	// maintenance above, plus the two checks that need the route
	// itself — exclusivity and the same-host loop.
	if err := r.RedirectConfig.Validate(); err != nil {
		return err
	}
	if r.RedirectConfig != nil {
		if r.MaintenanceConfig != nil {
			return apierr.New("route_maintenance_and_redirect", nil,
				"route: a route cannot be in maintenance and redirecting at the same time")
		}
		// The loop guard. A target on this route's own host — or on
		// one of its aliases — matches the redirect that produced it,
		// so the browser bounces until it gives up. Refuse it here,
		// while the operator is still looking at the form.
		//
		// This is also why "/ goes to /admin/login" is NOT expressible
		// at this scope: it is the same host by construction. That
		// need belongs to a path rule.
		target := r.RedirectConfig.TargetHost()
		for _, h := range r.AllHosts() {
			if target != "" && target == strings.ToLower(h) {
				return apierr.New("redirect_self_loop", map[string]string{"host": h},
					"redirect: the target points back at %s, which this route answers for — "+
						"every visitor would be redirected to the same place forever; "+
						"redirect to a different host, or use a path rule to send one path elsewhere",
					h)
			}
		}
	}
	return nil
}

// validate runs the strict last-line-of-defence checks on an
// Enabled HealthCheck. Called only when HealthCheck.Enabled is
// true — callers must guard. The API layer is expected to have
// materialised the five default fields (Method/Interval/Timeout/
// Passes/Fails) AND uppercased Method before storage's CreateRoute /
// UpdateRoute is invoked; a HealthCheck reaching this method with
// any of those fields blank, or with a non-uppercase Method, is a
// programming error and gets rejected here.
//
// This method is a PURE GRID — it does not mutate the receiver.
// Storage validators in Arenet follow the J.1 contract: the API
// normalises, storage checks. The pointer receiver only avoids a
// receiver copy on the hot path; nothing here writes back.
func (h *HealthCheck) validate() error {
	if h.URI == "" {
		return errors.New("route: health_check.uri must not be empty when enabled")
	}
	if !strings.HasPrefix(h.URI, "/") {
		return fmt.Errorf("route: health_check.uri %q must start with /", h.URI)
	}
	// Method enum check, no mutation. The API layer is responsible
	// for normalising "head" → "HEAD" before reaching storage; a
	// non-canonical value here is a programming error.
	if h.Method != "GET" && h.Method != "HEAD" {
		return fmt.Errorf("route: health_check.method %q must be GET or HEAD", h.Method)
	}
	interval, err := time.ParseDuration(h.Interval)
	if err != nil {
		return fmt.Errorf("route: health_check.interval %q is not a valid duration", h.Interval)
	}
	if interval <= 0 {
		return errors.New("route: health_check.interval must be strictly positive")
	}
	timeout, err := time.ParseDuration(h.Timeout)
	if err != nil {
		return fmt.Errorf("route: health_check.timeout %q is not a valid duration", h.Timeout)
	}
	if timeout <= 0 {
		return errors.New("route: health_check.timeout must be strictly positive")
	}
	if timeout >= interval {
		return errors.New("route: health_check.timeout must be strictly less than interval")
	}
	if err := ValidateExpectStatus("health_check.expect_status", h.ExpectStatus); err != nil {
		return fmt.Errorf("route: %w", err)
	}
	if h.ExpectBody != "" {
		if _, err := regexp.Compile(h.ExpectBody); err != nil {
			return fmt.Errorf("route: health_check.expect_body is not a valid regex: %v", err)
		}
	}
	if err := validateProbeHeaders(h.Headers); err != nil {
		return fmt.Errorf("route: health_check.%w", err)
	}
	if h.Passes < 1 {
		return errors.New("route: health_check.passes must be >= 1")
	}
	if h.Fails < 1 {
		return errors.New("route: health_check.fails must be >= 1")
	}
	return nil
}

// expectStatusClassMax is the largest of Caddy's status-class
// shorthands: 1 means "any 1xx" through 5 meaning "any 5xx"
// (caddyhttp.StatusCodeMatches, caddyhttp.go:234-238).
const expectStatusClassMax = 5

// ValidateExpectStatus accepts 0 (any 2xx), a status class 1-5, or a
// full status code.
//
// v2.55 — the class shorthand used to be refused, so an app that
// answers 302 on / had to be pinned to that exact code and silently
// went unhealthy the day it answered 301 instead.
// field is the caller's own name for the setting, because the two layers
// spell it differently — expect_status in storage, expectStatus on the
// wire — and an error should name the field the reader typed.
func ValidateExpectStatus(field string, code int) error {
	if code == 0 {
		return nil
	}
	if code >= 1 && code <= expectStatusClassMax {
		return nil
	}
	if code >= 100 && code <= 599 {
		return nil
	}
	return fmt.Errorf("%s %d must be 0 (any 2xx), a class 1-%d, or a status in 100..599",
		field, code, expectStatusClassMax)
}

// validateProbeHeaders checks the free-form probe headers.
//
// Host is refused on purpose: it has its own field, and accepting it in
// both places would mean two sources of truth for the one header that
// decides whether the probe reaches the right virtual host at all.
func validateProbeHeaders(headers map[string]string) error {
	for name := range headers {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			return errors.New("headers: a header name must not be empty")
		}
		if strings.EqualFold(trimmed, "Host") {
			return errors.New("headers: set the Host through host_header, not as a free-form header")
		}
		if textproto.CanonicalMIMEHeaderKey(trimmed) != trimmed {
			return fmt.Errorf("headers: %q is not a canonical header name (try %q)",
				name, textproto.CanonicalMIMEHeaderKey(trimmed))
		}
	}
	return nil
}

// CreateRoute persists a new Route. The ID, CreatedAt and UpdatedAt fields
// are assigned by the store and the populated Route is returned.
func (s *Store) CreateRoute(ctx context.Context, r Route) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := r.validate(); err != nil {
		return Route{}, err
	}

	now := time.Now().UTC()
	r.ID = uuid.NewString()
	r.CreatedAt = now
	r.UpdatedAt = now

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		buf, err := s.encodeRow(bucketRoutes, r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	}); err != nil {
		return Route{}, err
	}
	return r, nil
}

// GetRoute returns the Route identified by id, or ErrNotFound.
func (s *Store) GetRoute(ctx context.Context, id string) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return Route{}, errors.New("route: id must not be empty")
	}

	var out Route
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketRoutes)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return s.decodeRow(bucketRoutes, raw, &out)
	})
	if err != nil {
		return Route{}, err
	}
	return out, nil
}

// ListRoutes returns all stored routes, sorted by CreatedAt ascending.
func (s *Store) ListRoutes(ctx context.Context) ([]Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []Route
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketRoutes)).ForEach(func(_, v []byte) error {
			var r Route
			if err := s.decodeRow(bucketRoutes, v, &r); err != nil {
				return fmt.Errorf("unmarshal route: %w", err)
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// UpdateRoute replaces an existing Route. The CreatedAt timestamp is preserved
// from the stored record and UpdatedAt is refreshed.
func (s *Store) UpdateRoute(ctx context.Context, r Route) (Route, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return Route{}, errors.New("route: id must not be empty")
	}
	if err := r.validate(); err != nil {
		return Route{}, err
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		raw := b.Get([]byte(r.ID))
		if raw == nil {
			return ErrNotFound
		}
		var existing Route
		if err := s.decodeRow(bucketRoutes, raw, &existing); err != nil {
			return fmt.Errorf("unmarshal existing route: %w", err)
		}
		r.CreatedAt = existing.CreatedAt
		r.UpdatedAt = time.Now().UTC()
		buf, err := s.encodeRow(bucketRoutes, r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	})
	if err != nil {
		return Route{}, err
	}
	return r, nil
}

// DeleteRoute removes the Route identified by id. Returns ErrNotFound if it
// does not exist.
func (s *Store) DeleteRoute(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketRoutes))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

// RestoreRoute re-inserts an existing Route exactly as supplied, preserving
// the provided ID, CreatedAt and UpdatedAt timestamps.
//
// This method exists ONLY for the rollback path of internal/api when a Caddy
// reload fails after a DELETE. It bypasses the normal CreateRoute lifecycle
// (no UUID generation, no timestamp refresh) precisely to make rollback
// fidelity possible. Do NOT use it for business logic — use CreateRoute or
// UpdateRoute.
//
// RestoreRoute is an unconditional upsert: if the key already exists it is
// overwritten without error. By design, the rollback always wins the
// conflict — this is safe under the current single-writer flow (bbolt
// serialises writes and the HTTP handler processes mutations sequentially).
// Revisit if real concurrency on routes is introduced later.
func (s *Store) RestoreRoute(ctx context.Context, r Route) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if r.ID == "" {
		return errors.New("route: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := s.encodeRow(bucketRoutes, r)
		if err != nil {
			return fmt.Errorf("marshal route: %w", err)
		}
		return tx.Bucket([]byte(bucketRoutes)).Put([]byte(r.ID), buf)
	})
}
