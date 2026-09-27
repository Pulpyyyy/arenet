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

package alerting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/systemhealth"
)

// v2.52 — the rule editor offered "boltdb"; the check registers "db".
//
// A database rule therefore failed on every evaluation with
// `component "boltdb" not found in report`, and that error only reached
// the rule's LastError — nothing on screen said the alert would never
// fire. The editor is fixed; rules already stored keep the old name, so
// the source aliases it rather than leaving them broken.

type stubHealthReporter struct{ report systemhealth.Report }

func (s stubHealthReporter) Run(_ context.Context) systemhealth.Report { return s.report }

func healthReportWithDB(status systemhealth.Status) systemhealth.Report {
	return systemhealth.Report{
		Status: status,
		Components: []systemhealth.NamedReport{
			{Name: "caddy", ComponentStatus: systemhealth.ComponentStatus{Status: systemhealth.StatusHealthy}},
			{Name: "db", ComponentStatus: systemhealth.ComponentStatus{Status: status, Message: "read timed out"}},
		},
	}
}

func TestSystemHealthSource_CanonicalComponentName(t *testing.T) {
	src := NewSystemHealthSource(stubHealthReporter{report: healthReportWithDB(systemhealth.StatusUnhealthy)})

	got, err := src.Read(context.Background(), json.RawMessage(`{"component":"db"}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.String == nil || *got.String != string(systemhealth.StatusUnhealthy) {
		t.Fatalf("value = %v, want unhealthy", got.String)
	}
}

// A rule stored before the fix must start working, not keep failing.
func TestSystemHealthSource_LegacyBoltdbNameStillResolves(t *testing.T) {
	src := NewSystemHealthSource(stubHealthReporter{report: healthReportWithDB(systemhealth.StatusUnhealthy)})

	got, err := src.Read(context.Background(), json.RawMessage(`{"component":"boltdb"}`))
	if err != nil {
		t.Fatalf("a rule created with the old name must still resolve: %v", err)
	}
	if got.String == nil || *got.String != string(systemhealth.StatusUnhealthy) {
		t.Fatalf("value = %v, want unhealthy", got.String)
	}
}

// And a genuinely unknown component must still be an error — the alias
// must not turn every typo into a silent pass.
func TestSystemHealthSource_UnknownComponentStillErrors(t *testing.T) {
	src := NewSystemHealthSource(stubHealthReporter{report: healthReportWithDB(systemhealth.StatusHealthy)})

	if _, err := src.Read(context.Background(), json.RawMessage(`{"component":"postgres"}`)); err == nil {
		t.Fatal("an unknown component must report an error")
	}
}
