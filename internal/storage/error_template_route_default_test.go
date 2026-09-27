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
	"testing"
)

// v2.51 — isRouteDefault is exclusive, and independent of the catch-all
// flag.
//
// Exclusivity matters more than tidiness here: resolveErrorPage walks
// the template map, whose iteration order is random, so two flagged
// templates would serve different error pages from one reload to the
// next.

func tmplWith(name string, routeDefault, catchall bool) ErrorPageTemplate {
	return ErrorPageTemplate{
		Name:              name,
		Pages:             map[int]string{404: "<html>" + name + "</html>"},
		IsRouteDefault:    routeDefault,
		IsCatchallDefault: catchall,
	}
}

func TestErrorTemplate_RouteDefaultIsExclusive(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	first, err := store.CreateErrorPageTemplate(ctx, tmplWith("first", true, false))
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	second, err := store.CreateErrorPageTemplate(ctx, tmplWith("second", true, false))
	if err != nil {
		t.Fatalf("create second: %v", err)
	}

	all, err := store.ListErrorPageTemplates(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var flagged []string
	for _, tm := range all {
		if tm.IsRouteDefault {
			flagged = append(flagged, tm.ID)
		}
	}
	if len(flagged) != 1 {
		t.Fatalf("want exactly one route default, got %v", flagged)
	}
	if flagged[0] != second.ID {
		t.Errorf("the most recent claim must win: got %s, want %s", flagged[0], second.ID)
	}
	if flagged[0] == first.ID {
		t.Error("the first template kept the flag")
	}
}

// The two flags do not clear each other: one template may hold both, and
// claiming one must leave the other's holder alone.
func TestErrorTemplate_FlagsAreIndependent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	catchall, err := store.CreateErrorPageTemplate(ctx, tmplWith("catchall", false, true))
	if err != nil {
		t.Fatalf("create catchall: %v", err)
	}
	// A different template claims the ROUTE default. The catch-all
	// holder must keep its own flag.
	if _, err := store.CreateErrorPageTemplate(ctx, tmplWith("routes", true, false)); err != nil {
		t.Fatalf("create routes: %v", err)
	}

	got, err := store.GetErrorPageTemplate(ctx, catchall.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.IsCatchallDefault {
		t.Error("claiming the route default cleared the catch-all flag on another template")
	}
	if got.IsRouteDefault {
		t.Error("the catch-all template gained the route flag")
	}
}

// One template may legitimately hold both roles.
func TestErrorTemplate_BothFlagsOnOneTemplate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	created, err := store.CreateErrorPageTemplate(ctx, tmplWith("both", true, true))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := store.GetErrorPageTemplate(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.IsRouteDefault || !got.IsCatchallDefault {
		t.Fatalf("a template must be able to hold both roles, got route=%v catchall=%v",
			got.IsRouteDefault, got.IsCatchallDefault)
	}
}
