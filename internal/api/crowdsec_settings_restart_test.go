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

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// v2.51 — a MOVED LAPI address needs a process restart, and the response
// has to say so.
//
// Observed on 2026-09-27: moving a LAPI from 127.0.0.1 to a WireGuard
// address reloaded Caddy, re-provisioned the bouncer with the new URL,
// and the bouncer then logged `address: http://10.66.0.1:8080` while
// every request still went to `http://127.0.0.1:8080`. Something under
// the bouncer retains the previous address until the process restarts.
//
// The reason this needs surfacing rather than documenting: the bouncer
// fails OPEN. For as long as it cannot reach LAPI it blocks nothing at
// all, and no other screen says so. An operator who believes the save
// took effect is unprotected and cannot tell.

func putCrowdSecBody(t *testing.T, h *Handler, body string) crowdSecResponse {
	t.Helper()
	req := reqWithAuth(http.MethodPut, "/api/v1/settings/crowdsec", "user", "admin", "1.2.3.4", "test")
	req.Body = httpBody(body)
	rec := httptest.NewRecorder()
	h.putCrowdSecSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var out crowdSecResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v\n%s", err, rec.Body.String())
	}
	return out
}

func TestPutCrowdSecSettings_MovedURL_SignalsRestart(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	h.SetCrowdSecApplier(&fakeCrowdSecApplier{})

	// First PUT configures; there is nothing to move from, so no
	// restart is claimed.
	first := putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k1","bouncerName":"arenet","timeoutSeconds":5}`)
	if first.RestartRequired {
		t.Error("the first configuration must not demand a restart — there is no previous address")
	}

	// Now move the address.
	moved := putCrowdSecBody(t, h,
		`{"lapiUrl":"http://10.66.0.1:8080","apiKey":"","bouncerName":"arenet","timeoutSeconds":5}`)
	if !moved.RestartRequired {
		t.Fatal("moving the LAPI address must signal that a restart is needed")
	}
	// And the operator is warned in the log too, since they may be
	// driving this from the API rather than the UI.
	if !bytes.Contains(logBuf.Bytes(), []byte("LAPI address changed")) {
		t.Errorf("no warning logged when the address moved:\n%s", logBuf.String())
	}
}

// Rotating only the key re-provisions cleanly. Demanding a restart for
// it would teach the operator to ignore the signal.
func TestPutCrowdSecSettings_KeyOnly_NoRestart(t *testing.T) {
	var logBuf bytes.Buffer
	h := newTestHandler(t, &fakeAuditAppender{}, &logBuf)
	h.SetCrowdSecApplier(&fakeCrowdSecApplier{})

	putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k1","bouncerName":"arenet","timeoutSeconds":5}`)
	rotated := putCrowdSecBody(t, h,
		`{"lapiUrl":"http://127.0.0.1:8080","apiKey":"k2","bouncerName":"arenet","timeoutSeconds":5}`)

	if rotated.RestartRequired {
		t.Error("rotating the key alone must not demand a restart")
	}
	if bytes.Contains(logBuf.Bytes(), []byte("LAPI address changed")) {
		t.Error("a key rotation must not log an address change")
	}
}
