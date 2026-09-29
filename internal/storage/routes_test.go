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

// v2.55 — expect_status classes and probe headers.
func TestValidateExpectStatus_AcceptsClasses(t *testing.T) {
	tests := []struct {
		code int
		ok   bool
		why  string
	}{
		{0, true, "any 2xx"},
		{3, true, "Caddy's class shorthand: any 3xx, which is what an app redirecting to login needs"},
		{1, true, "lowest class"},
		{5, true, "highest class"},
		{6, false, "no 6xx class exists"},
		{99, false, "neither a class nor a status"},
		{200, true, "a plain status"},
		{599, true, "top of the status range"},
		{600, false, "above the status range"},
		{-1, false, "negative"},
	}
	for _, tt := range tests {
		err := ValidateExpectStatus("expect_status", tt.code)
		if tt.ok && err != nil {
			t.Errorf("ValidateExpectStatus(%d) = %v; want nil (%s)", tt.code, err, tt.why)
		}
		if !tt.ok && err == nil {
			t.Errorf("ValidateExpectStatus(%d) = nil; want an error (%s)", tt.code, tt.why)
		}
	}
}

// Host has its own field. Accepting it here too would mean two places to
// look for the one header that decides whether the probe even reaches
// the right virtual host.
func TestValidateProbeHeaders_RefusesHostAndSaysWhere(t *testing.T) {
	err := validateProbeHeaders(map[string]string{"Host": "app.example.com"})
	if err == nil {
		t.Fatal("a Host in the free-form headers was accepted; it would silently outrank host_header")
	}
	if !strings.Contains(err.Error(), "host_header") {
		t.Errorf("error %q does not name the field to use instead", err)
	}
	// Case must not be a way around it.
	if validateProbeHeaders(map[string]string{"host": "x"}) == nil {
		t.Error("lowercase host slipped through")
	}
}

func TestValidateProbeHeaders_RejectsNonCanonicalNames(t *testing.T) {
	if err := validateProbeHeaders(map[string]string{"Authorization": "Bearer t"}); err != nil {
		t.Errorf("a canonical header was refused: %v", err)
	}
	if validateProbeHeaders(map[string]string{"": "v"}) == nil {
		t.Error("an empty header name was accepted")
	}
	err := validateProbeHeaders(map[string]string{"x-probe": "v"})
	if err == nil {
		t.Fatal("a non-canonical name was accepted; Caddy would send it as typed")
	}
	if !strings.Contains(err.Error(), "X-Probe") {
		t.Errorf("error %q does not suggest the canonical spelling", err)
	}
}

func TestHealthCheck_ProbeHost_OverrideWinsOverRouteHost(t *testing.T) {
	hc := HealthCheck{}
	if got := hc.ProbeHost("route.example.com"); got != "route.example.com" {
		t.Errorf("ProbeHost = %q; with no override the route's host is what real traffic carries", got)
	}
	hc.HostHeader = "internal.example.com"
	if got := hc.ProbeHost("route.example.com"); got != "internal.example.com" {
		t.Errorf("ProbeHost = %q; the override must win", got)
	}
	if got := (HealthCheck{}).ProbeHost(""); got != "" {
		t.Errorf("ProbeHost = %q; nothing to send means send nothing", got)
	}
}
