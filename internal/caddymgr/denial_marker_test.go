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
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/waf"
)

// v2.62 — Arenet's own refusals are named in the access log.
//
// Born from a production incident: two members were banned by CrowdSec
// and establishing why took an afternoon, because a 403 served by
// Arenet's WAF is byte-indistinguishable in the access log from a 403
// served by the backend. Two diagnostic queries written that day
// reached the wrong conclusion for precisely that reason.

// The constants are duplicated in the gate packages on purpose — they
// must not import caddymgr, since the dependency runs the other way.
// This is the test that keeps the copies honest. Without it, renaming
// one side leaves the marker silently absent from the log: the handler
// would read a var nobody sets, and write an empty field forever.
func TestDenialMarker_GateConstantsAgreeWithTheEmitter(t *testing.T) {
	if countryblock.DeniedVarKey != DeniedVarKey {
		t.Errorf("countryblock.DeniedVarKey = %q; caddymgr expects %q — the gate would "+
			"write a var the log_append handler never reads",
			countryblock.DeniedVarKey, DeniedVarKey)
	}
	if waf.DeniedVarKey != DeniedVarKey {
		t.Errorf("waf.DeniedVarKey = %q; caddymgr expects %q", waf.DeniedVarKey, DeniedVarKey)
	}
	// metrics is the READER — if its key drifts, every gate writes a
	// var nobody reads and the log field silently disappears.
	if metrics.DeniedVarKey != DeniedVarKey {
		t.Errorf("metrics.DeniedVarKey = %q (the reader); caddymgr expects %q",
			metrics.DeniedVarKey, DeniedVarKey)
	}
	if metrics.DeniedLogField != DeniedLogField {
		t.Errorf("metrics.DeniedLogField = %q; caddymgr expects %q",
			metrics.DeniedLogField, DeniedLogField)
	}
	if countryblock.DeniedReason != DeniedByCountryBlock {
		t.Errorf("countryblock.DeniedReason = %q; want %q",
			countryblock.DeniedReason, DeniedByCountryBlock)
	}
	if waf.DeniedReason != DeniedByWAF {
		t.Errorf("waf.DeniedReason = %q; want %q", waf.DeniedReason, DeniedByWAF)
	}
}

// The reason strings are a published contract: an operator's CrowdSec
// whitelist or log query is written against them, so a rename is a
// breaking change for configuration that lives outside this repo.
func TestDenialMarker_ReasonStringsAreStable(t *testing.T) {
	if DeniedByWAF != "waf" {
		t.Errorf("DeniedByWAF = %q; operators' log queries expect \"waf\"", DeniedByWAF)
	}
	if DeniedByCountryBlock != "country" {
		t.Errorf("DeniedByCountryBlock = %q; operators' log queries expect \"country\"",
			DeniedByCountryBlock)
	}
	if DeniedLogField != "arenet_denied" {
		t.Errorf("DeniedLogField = %q; operators' log queries expect \"arenet_denied\"",
			DeniedLogField)
	}
}

func TestBuildConfigJSON_DenialMarker_LoadsCleanly(t *testing.T) {
	// The project's rule for anything Caddy-facing: the emitted JSON
	// must survive caddy.Validate, which is what proves the
	// log_append module ID and its fields are real rather than
	// plausible.
	metrics.SetRegistry(metrics.NewRegistry())
	routes := []storage.Route{{
		ID:        "r-validate",
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate rejected the log_append denial marker: %v", err)
	}
}
