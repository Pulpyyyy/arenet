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
	"strings"
	"testing"
)

// v2.44 — the route-level redirect state.
//
// What is pinned here is mostly what gets REFUSED. A redirect is one
// line of config that, wrong, produces a loop the operator discovers
// from their browser rather than from Arenet — so every refusal below
// is a message delivered while the form is still open.

func routeWithRedirect(rc *RedirectConfig) Route {
	return Route{
		ID: "r1", Host: "old.example.com",
		Upstreams:      []Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:       LBPolicyRoundRobin,
		RedirectConfig: rc,
	}
}

func TestRedirectConfig_AcceptsAUsableTarget(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://new.example.com", PreservePath: true})
	if err := r.validate(); err != nil {
		t.Fatalf("a plain host target must be accepted: %v", err)
	}
}

func TestRedirectConfig_RefusesWhatCannotWork(t *testing.T) {
	cases := []struct {
		name string
		rc   *RedirectConfig
		want string
	}{
		{"empty target", &RedirectConfig{}, "target URL is required"},
		{"no scheme", &RedirectConfig{Target: "new.example.com"}, "http:// or https://"},
		{"wrong scheme", &RedirectConfig{Target: "ftp://new.example.com"}, "http:// or https://"},
		{"no host", &RedirectConfig{Target: "https://"}, "no host"},
		{"unsupported code", &RedirectConfig{Target: "https://new.example.com", StatusCode: 307}, "301 or 302"},
		// The silent-corruption case: appending the visitor's path to
		// a target that already has one produces /app/a/b, which
		// nobody asked for and nothing reports.
		{
			"path on target while preserving the path",
			&RedirectConfig{Target: "https://new.example.com/app", PreservePath: true},
			"already has a path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := routeWithRedirect(c.rc)
			err := r.validate()
			if err == nil {
				t.Fatalf("%s must be refused", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("message must say why (%q): %v", c.want, err)
			}
		})
	}
}

// A target on the route's own host redirects to itself. The browser
// bounces until it gives up, and nothing in Arenet says so — which is
// exactly why this is refused at save.
func TestRedirectConfig_RefusesTheSelfLoop(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://old.example.com/admin/login"})
	err := r.validate()
	if err == nil {
		t.Fatal("a target on the route's own host must be refused")
	}
	if !strings.Contains(err.Error(), "old.example.com") {
		t.Errorf("the message must name the host: %v", err)
	}
	// And it must point at the way out rather than just refusing.
	if !strings.Contains(err.Error(), "path rule") {
		t.Errorf("the message must offer the alternative: %v", err)
	}
}

// Aliases answer for the same route, so a target on an alias loops too
// — less obviously, which makes it more worth catching.
func TestRedirectConfig_RefusesALoopThroughAnAlias(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://www.old.example.com"})
	r.Aliases = []string{"www.old.example.com"}
	if err := r.validate(); err == nil {
		t.Fatal("a target on an alias of this route must be refused")
	}
}

// Case and port must not let a loop through: Caddy matches hosts
// case-insensitively, and https://HOST:443 is the same place.
func TestRedirectConfig_LoopGuardIgnoresCaseAndPort(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://OLD.example.com:443"})
	if err := r.validate(); err == nil {
		t.Fatal("the loop guard must not be defeated by case or an explicit port")
	}
}

// The two states replace the proxy chain; both at once has no meaning.
func TestRedirectConfig_RefusesMaintenanceAtTheSameTime(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://new.example.com"})
	r.MaintenanceConfig = &MaintenanceConfig{RetryAfterSeconds: 300}
	err := r.validate()
	if err == nil {
		t.Fatal("maintenance and redirect together must be refused")
	}
	if !strings.Contains(err.Error(), "maintenance") {
		t.Errorf("message: %v", err)
	}
}

func TestRedirectConfig_CodeDefaultsToPermanent(t *testing.T) {
	if got := (&RedirectConfig{}).Code(); got != 301 {
		t.Errorf("zero must resolve to 301, got %d", got)
	}
	if got := (&RedirectConfig{StatusCode: 302}).Code(); got != 302 {
		t.Errorf("explicit 302 must survive, got %d", got)
	}
	var nilCfg *RedirectConfig
	if got := nilCfg.Code(); got != 301 {
		t.Errorf("nil must be usable, got %d", got)
	}
}

// A route that does not redirect must validate exactly as before.
func TestRedirectConfig_NilIsInert(t *testing.T) {
	r := routeWithRedirect(nil)
	if err := r.validate(); err != nil {
		t.Fatalf("no redirect configured must stay valid: %v", err)
	}
}

// --- v2.44 — the path-rule redirect ------------------------------

func routeWithPathRule(pr PathRule) Route {
	return Route{
		ID: "r1", Host: "app.example.com",
		Upstreams: []Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		PathRules: []PathRule{pr},
	}
}

func TestPathRedirect_AcceptsTheStalwartShape(t *testing.T) {
	r := routeWithPathRule(PathRule{
		PathPrefix: "/",
		MatchExact: true,
		Redirect:   &PathRedirect{Target: "/admin/login"},
	})
	if err := r.validate(); err != nil {
		t.Fatalf("the case this feature exists for must be accepted: %v", err)
	}
}

// The loop, in its two shapes. An exact rule on "/" pointing at "/",
// and a prefix rule pointing anywhere under itself.
func TestPathRedirect_RefusesTheLoop(t *testing.T) {
	cases := []struct {
		name string
		rule PathRule
	}{
		{"exact rule pointing at itself", PathRule{
			PathPrefix: "/", MatchExact: true,
			Redirect: &PathRedirect{Target: "/"},
		}},
		{"prefix rule pointing under itself", PathRule{
			PathPrefix: "/app",
			Redirect:   &PathRedirect{Target: "/app/login"},
		}},
		{"prefix rule pointing at itself", PathRule{
			PathPrefix: "/app",
			Redirect:   &PathRedirect{Target: "/app"},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := routeWithPathRule(c.rule)
			err := r.validate()
			if err == nil {
				t.Fatal("must be refused")
			}
			if !strings.Contains(err.Error(), "forever") {
				t.Errorf("the message must say what would happen: %v", err)
			}
		})
	}
}

// Without MatchExact, a "/" rule matches everything, so the very
// target the operator wants is inside the rule. This is the mistake
// the exact mode exists to let them avoid — and it must be refused
// rather than silently looping.
func TestPathRedirect_RefusesARootPrefixRule(t *testing.T) {
	r := routeWithPathRule(PathRule{
		PathPrefix: "/",
		Redirect:   &PathRedirect{Target: "/admin/login"},
	})
	if err := r.validate(); err == nil {
		t.Fatal("a prefix rule on / matches its own target: must be refused")
	}
}

// An absolute URL leaves this host, so no local loop is possible.
func TestPathRedirect_AcceptsAnAbsoluteTarget(t *testing.T) {
	r := routeWithPathRule(PathRule{
		PathPrefix: "/docs", MatchExact: true,
		Redirect: &PathRedirect{Target: "https://docs.example.com/"},
	})
	if err := r.validate(); err != nil {
		t.Fatalf("an off-host target must be accepted: %v", err)
	}
}

func TestPathRedirect_RefusesAMalformedTarget(t *testing.T) {
	for _, target := range []string{"", "admin/login", "ftp://x.example.com"} {
		r := routeWithPathRule(PathRule{
			PathPrefix: "/", MatchExact: true,
			Redirect: &PathRedirect{Target: target},
		})
		if err := r.validate(); err == nil {
			t.Errorf("target %q must be refused", target)
		}
	}
}

// Caddy lowercases the request path but never the pattern, so an
// uppercase rule loads fine and then never matches anything. Silence
// is the worst failure mode, so it is refused at save.
func TestPathRule_RefusesAnUppercasePath(t *testing.T) {
	r := routeWithPathRule(PathRule{
		PathPrefix: "/Admin",
		IPFilter:   &IPFilter{Mode: "allow", CIDRs: []string{"10.0.0.0/8"}},
	})
	err := r.validate()
	if err == nil {
		t.Fatal("an uppercase path prefix must be refused, so what is stored reads the way it matches")
	}
	// And the message must hand over the fix, not just the diagnosis.
	if !strings.Contains(err.Error(), "/admin") {
		t.Errorf("the message must offer the lowercase form: %v", err)
	}
}

// A redirect alone is enough to justify a path rule — before v2.44 a
// rule had to carry auth, a filter or a pool.
func TestPathRule_ARedirectIsEnoughOnItsOwn(t *testing.T) {
	r := routeWithPathRule(PathRule{
		PathPrefix: "/", MatchExact: true,
		Redirect: &PathRedirect{Target: "/admin/login"},
	})
	if err := r.validate(); err != nil {
		t.Fatalf("a redirect-only rule must be valid: %v", err)
	}
}

func TestPathRedirect_CodeDefaultsToTemporary(t *testing.T) {
	if got := (&PathRedirect{}).Code(); got != 302 {
		t.Errorf("a landing path must default to 302, got %d", got)
	}
	var nilCfg *PathRedirect
	if got := nilCfg.Code(); got != 302 {
		t.Errorf("nil must be usable, got %d", got)
	}
}
