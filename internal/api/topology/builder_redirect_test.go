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

package topology

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.61 — the topology knew nothing of route-level redirects, and the
// canvas said something false as a result: a redirecting route has no
// upstream, so it drew an EMPTY backend cluster carrying the red
// "no upstream configured" warning — indistinguishable from a broken
// route. The operator met it on 2026-10-03 and asked whether that was
// normal. It was not.
//
// These pin the wire half: the target travels, and it travels under a
// name that cannot be confused with the :80 → :443 bounce that already
// lived here as `httpRedirect`.

func TestBuildRoute_RedirectTarget_OnTheWire(t *testing.T) {
	r := storage.Route{
		ID:       "r-redirect",
		Host:     "old.example.com",
		LBPolicy: storage.LBPolicyRoundRobin,
		RedirectConfig: &storage.RedirectConfig{
			Target:     "https://new.example.com",
			StatusCode: 301,
		},
	}
	out := buildRoute(&r, nil, nil)

	if out.RedirectTarget != "https://new.example.com" {
		t.Errorf("RedirectTarget = %q; want the configured target", out.RedirectTarget)
	}
	// A redirecting route legally carries no pool. The empty slice is
	// what the frontend reads to decide it has nothing to draw as a
	// backend — it must stay empty, not become a phantom upstream.
	if len(out.Upstreams) != 0 {
		t.Errorf("Upstreams = %d; want 0 on a redirecting route", len(out.Upstreams))
	}
}

func TestBuildRoute_ProxyingRoute_HasNoRedirectTarget(t *testing.T) {
	r := storage.Route{
		ID:        "r-proxy",
		Host:      "app.example.com",
		LBPolicy:  storage.LBPolicyRoundRobin,
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.5:8080", Weight: 1}},
	}
	out := buildRoute(&r, nil, nil)

	if out.RedirectTarget != "" {
		t.Errorf("RedirectTarget = %q on a proxying route; want empty", out.RedirectTarget)
	}
	// omitempty must keep the key off the wire entirely, so every
	// existing snapshot stays byte-identical for proxying routes.
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got := string(raw); strings.Contains(got, "redirectTarget") {
		t.Errorf("snapshot carries a redirectTarget key for a proxying route:\n%s", got)
	}
}

func TestBuildRoute_RedirectTarget_IsNotHTTPRedirect(t *testing.T) {
	// The two fields sit next to each other and mean different things:
	// httpRedirect is the :80 → :443 bounce, redirectTarget is "this
	// host answers a 301/302 to somewhere else". A route can have one,
	// the other, both, or neither — and conflating them would make the
	// canvas draw a redirect for every TLS route in the instance.
	r := storage.Route{
		ID:              "r-both",
		Host:            "old.example.com",
		LBPolicy:        storage.LBPolicyRoundRobin,
		TLSEnabled:      true,
		RedirectToHTTPS: true,
		RedirectConfig: &storage.RedirectConfig{
			Target:     "https://new.example.com",
			StatusCode: 302,
		},
	}
	out := buildRoute(&r, nil, nil)

	if !out.HTTPRedirect {
		t.Error("HTTPRedirect = false; want true (the route forces HTTPS)")
	}
	if out.RedirectTarget != "https://new.example.com" {
		t.Errorf("RedirectTarget = %q; want the configured target", out.RedirectTarget)
	}

	// And the converse: force-HTTPS alone must not look like a redirect.
	plain := storage.Route{
		ID:              "r-tls-only",
		Host:            "app.example.com",
		LBPolicy:        storage.LBPolicyRoundRobin,
		TLSEnabled:      true,
		RedirectToHTTPS: true,
		Upstreams:       []storage.Upstream{{URL: "http://10.0.0.5:8080", Weight: 1}},
	}
	if got := buildRoute(&plain, nil, nil); got.RedirectTarget != "" {
		t.Errorf("a force-HTTPS proxying route reported RedirectTarget = %q; want empty — "+
			"this is the confusion that would draw every TLS route as a redirect", got.RedirectTarget)
	}
}
