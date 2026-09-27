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
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.51 — a template can be the default for routes that chose none.
//
// The operator flagged a template as the CATCH-ALL default and expected
// their routes to use it. They never did: a route with no template gets
// Arenet's built-in pages, and the catch-all flag only governs the body
// for a host matching no route. This is the missing layer, kept as a
// SEPARATE flag so the two decisions stay independent.

func routeDefaultTemplates() map[string]storage.ErrorPageTemplate {
	return map[string]storage.ErrorPageTemplate{
		"brand": {
			ID: "brand", Name: "brand", IsRouteDefault: true,
			Pages: map[int]string{404: "<html>BRAND 404</html>", 502: "<html>BRAND 502</html>"},
		},
	}
}

func TestResolveErrorPage_RouteDefaultApplies(t *testing.T) {
	route := storage.Route{ID: "r1", Host: "app.local"} // no template chosen
	got := resolveErrorPage(route, 404, routeDefaultTemplates())
	if !strings.Contains(got, "BRAND 404") {
		t.Fatalf("a route with no template must take the flagged default, got:\n%s", got)
	}
}

// A code the flagged template leaves blank must fall through rather than
// blanking the page: a template customising 404 and 502 should not wipe
// out the other six.
func TestResolveErrorPage_RouteDefaultFallsThroughOnMissingCode(t *testing.T) {
	route := storage.Route{ID: "r1", Host: "app.local"}
	got := resolveErrorPage(route, 503, routeDefaultTemplates())
	if got == "" {
		t.Fatal("a code the default leaves blank must fall back to Arenet's own page")
	}
	if strings.Contains(got, "BRAND") {
		t.Fatalf("503 is not in the template; got its body anyway:\n%s", got)
	}
}

// An explicit per-route choice still wins over the global default.
func TestResolveErrorPage_RouteTemplateBeatsRouteDefault(t *testing.T) {
	templates := routeDefaultTemplates()
	templates["own"] = storage.ErrorPageTemplate{
		ID: "own", Name: "own",
		Pages: map[int]string{404: "<html>OWN 404</html>"},
	}
	route := storage.Route{ID: "r1", Host: "app.local", ErrorPageTemplateID: "own"}

	got := resolveErrorPage(route, 404, templates)
	if !strings.Contains(got, "OWN 404") {
		t.Fatalf("the route's own template must win, got:\n%s", got)
	}
}

// And a per-route override still beats both.
func TestResolveErrorPage_OverrideBeatsEverything(t *testing.T) {
	route := storage.Route{
		ID: "r1", Host: "app.local",
		ErrorPageOverrides: map[int]string{404: "<html>OVERRIDE</html>"},
	}
	got := resolveErrorPage(route, 404, routeDefaultTemplates())
	if !strings.Contains(got, "OVERRIDE") {
		t.Fatalf("a per-route override must win, got:\n%s", got)
	}
}

// The two flags are independent. A template flagged ONLY as catch-all
// must not leak into routes — that is the exact surprise this change
// exists to remove, and reversing it would reintroduce it.
func TestResolveErrorPage_CatchallFlagDoesNotAffectRoutes(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{
		"c": {
			ID: "c", Name: "c", IsCatchallDefault: true,
			Pages: map[int]string{404: "<html>CATCHALL ONLY</html>"},
		},
	}
	route := storage.Route{ID: "r1", Host: "app.local"}
	got := resolveErrorPage(route, 404, templates)
	if strings.Contains(got, "CATCHALL ONLY") {
		t.Fatal("the catch-all flag must not apply to routes; that is what isRouteDefault is for")
	}
	if got == "" {
		t.Fatal("the route must still get Arenet's built-in 404")
	}
}

// And conversely: a route default must not become the catch-all body.
func TestResolveCatchallBody_RouteDefaultFlagIsNotEnough(t *testing.T) {
	body := resolveCatchallBody(routeDefaultTemplates())
	if strings.Contains(body, "BRAND 404") {
		t.Fatal("isRouteDefault must not make a template the catch-all body")
	}
	if body == "" {
		t.Fatal("the catch-all must still carry Arenet's built-in 404")
	}
}
