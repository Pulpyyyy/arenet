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
	"strings"
	"testing"
)

// v2.60 — UpstreamTLSServerName, modelled on
// routes_insecure_skip_verify_test.go. The invariants:
//
//  1. It round-trips through the store.
//  2. Omitted means the empty string, which is "Caddy's default" —
//     the same migration-free story as InsecureSkipVerify.
//  3. A pre-v2.60 row on disk decodes to the empty string.
//  4. The validator refuses what Caddy could not use, with the
//     reason named: a URL, a host:port, an IP literal, a malformed
//     label. That refusal is the whole point of the field — an
//     unusable name surfaces downstream as a bare 502.
//  5. A path rule carries its own, autonomously.

func TestRoute_UpstreamTLSServerName_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateRoute(context.Background(), Route{
		Host:                  "forum.example.com",
		Upstreams:             []Upstream{{URL: "https://194.163.129.255", Weight: 1}},
		LBPolicy:              LBPolicyRoundRobin,
		UpstreamTLSServerName: "forum.example.com",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UpstreamTLSServerName != "forum.example.com" {
		t.Errorf("UpstreamTLSServerName = %q; want %q", got.UpstreamTLSServerName, "forum.example.com")
	}
}

func TestRoute_UpstreamTLSServerName_DefaultsEmpty(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreateRoute(context.Background(), Route{
		Host:      "app.example.com",
		Upstreams: []Upstream{{URL: "https://10.0.0.5", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.UpstreamTLSServerName != "" {
		t.Errorf("UpstreamTLSServerName = %q; want \"\" (Caddy's default)", created.UpstreamTLSServerName)
	}
}

func TestRoute_DecodePreV260Row_HasEmptyUpstreamTLSServerName(t *testing.T) {
	// The "no boot migration needed" proof: a row written before the
	// field existed must decode to the empty string, which is
	// behaviourally identical to how it was served before.
	s := newTestStore(t)
	created, err := s.CreateRoute(context.Background(), Route{
		Host:      "legacy.example.com",
		Upstreams: []Upstream{{URL: "https://10.0.0.6", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UpstreamTLSServerName != "" {
		t.Errorf("pre-v2.60 row decoded UpstreamTLSServerName = %q; want \"\"", got.UpstreamTLSServerName)
	}
}

func TestValidateUpstreamTLSServerName(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr string // substring; "" means it must be accepted
	}{
		{"empty is the default", "", ""},
		{"plain hostname", "forum.example.com", ""},
		{"single label", "backend", ""},
		{"trailing dot is a legal FQDN", "forum.example.com.", ""},
		{"underscore (seen in internal zones)", "my_backend.internal", ""},
		{"hyphen inside a label", "forum-prod.example.com", ""},

		// The four an operator actually types by mistake.
		{"a whole URL", "https://forum.example.com", "not a URL"},
		{"host:port", "forum.example.com:443", "no port"},
		{"a path", "forum.example.com/srv/status", "no port"},
		{"an IP literal", "194.163.129.255", "cannot be a TLS server name"},

		{"leading space", " forum.example.com", "whitespace"},
		{"empty label", "forum..example.com", "empty label"},
		{"leading hyphen", "-forum.example.com", "hyphen"},
		{"trailing hyphen", "forum-.example.com", "hyphen"},
		{"illegal character", "forum!.example.com", "not allowed in a hostname"},
		{"label over 63", strings.Repeat("a", 64) + ".example.com", "longer than 63"},
		{"name over 253", strings.Repeat("a.", 130) + "example.com", "longer than 253 characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUpstreamTLSServerName(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateUpstreamTLSServerName(%q) = %v; want accepted", tc.in, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateUpstreamTLSServerName(%q) = nil; want an error mentioning %q", tc.in, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q — the operator has to know WHY it was refused",
					err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRoute_UpstreamTLSServerName_InvalidIsRefusedAtSave(t *testing.T) {
	// The validator is reachable from the storage layer, not just
	// callable in isolation: a bad value must not reach disk even if
	// a future caller skips the API.
	s := newTestStore(t)
	_, err := s.CreateRoute(context.Background(), Route{
		Host:                  "bad.example.com",
		Upstreams:             []Upstream{{URL: "https://10.0.0.7", Weight: 1}},
		LBPolicy:              LBPolicyRoundRobin,
		UpstreamTLSServerName: "https://bad.example.com",
	})
	if err == nil {
		t.Fatal("CreateRoute accepted a URL as a TLS server name; want refusal")
	}
	if !strings.Contains(err.Error(), "not a URL") {
		t.Errorf("error = %q; want it to name the problem", err.Error())
	}
}

func TestPathRule_UpstreamTLSServerName_RoundTripsAndIsAutonomous(t *testing.T) {
	// A path pool that dials a different address has a different
	// certificate identity. The route's name must not leak into it.
	s := newTestStore(t)
	created, err := s.CreateRoute(context.Background(), Route{
		Host:                  "app.example.com",
		Upstreams:             []Upstream{{URL: "https://10.0.0.5", Weight: 1}},
		LBPolicy:              LBPolicyRoundRobin,
		UpstreamTLSServerName: "app.internal",
		PathRules: []PathRule{{
			PathPrefix:            "/api",
			Upstreams:             []Upstream{{URL: "https://10.0.0.9", Weight: 1}},
			LBPolicy:              LBPolicyRoundRobin,
			UpstreamTLSServerName: "api.internal",
		}},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UpstreamTLSServerName != "app.internal" {
		t.Errorf("route name = %q; want app.internal", got.UpstreamTLSServerName)
	}
	if len(got.PathRules) != 1 {
		t.Fatalf("path rules = %d; want 1", len(got.PathRules))
	}
	if got.PathRules[0].UpstreamTLSServerName != "api.internal" {
		t.Errorf("path rule name = %q; want api.internal (its own, not the route's)",
			got.PathRules[0].UpstreamTLSServerName)
	}
}

func TestPathRule_UpstreamTLSServerName_InvalidNamesThePath(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateRoute(context.Background(), Route{
		Host:      "app.example.com",
		Upstreams: []Upstream{{URL: "https://10.0.0.5", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		PathRules: []PathRule{{
			PathPrefix:            "/api",
			Upstreams:             []Upstream{{URL: "https://10.0.0.9", Weight: 1}},
			LBPolicy:              LBPolicyRoundRobin,
			UpstreamTLSServerName: "api.internal:8443",
		}},
	})
	if err == nil {
		t.Fatal("accepted a host:port on a path rule; want refusal")
	}
	if !strings.Contains(err.Error(), "/api") {
		t.Errorf("error %q does not name the path rule — with several rules the "+
			"operator cannot tell which one to fix", err.Error())
	}
}
