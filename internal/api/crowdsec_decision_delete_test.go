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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeLAPIForDelete is a focused fake LAPI exposing
// /v1/watchers/login + /v1/decisions/{id}. Its default answer
// mirrors crowdsec@v1.6.3 DeleteDecisionById
// (pkg/apiserver/controllers/v1/decisions.go:84-113): 200 with
// nbDeleted as a STRING.
type fakeLAPIForDelete struct {
	loginCalls    atomic.Int32
	deleteCalls   atomic.Int32
	deleteHandler http.HandlerFunc
	lastMethod    atomic.Value // string
	lastPath      atomic.Value // string
	lastAuth      atomic.Value // string
}

func newFakeLAPIForDelete() *fakeLAPIForDelete {
	f := &fakeLAPIForDelete{}
	f.lastMethod.Store("")
	f.lastPath.Store("")
	f.lastAuth.Store("")
	return f
}

func (f *fakeLAPIForDelete) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", func(w http.ResponseWriter, r *http.Request) {
		f.loginCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"token":"jwt-ok","expire":"` +
			time.Now().Add(1*time.Hour).UTC().Format(time.RFC3339) + `"}`))
	})
	mux.HandleFunc("/v1/decisions/", func(w http.ResponseWriter, r *http.Request) {
		f.deleteCalls.Add(1)
		f.lastMethod.Store(r.Method)
		f.lastPath.Store(r.URL.Path)
		f.lastAuth.Store(r.Header.Get("Authorization"))
		if f.deleteHandler != nil {
			f.deleteHandler(w, r)
			return
		}
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nbDeleted":"1"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func seedWatcherCredsForDelete(t *testing.T, env *testEnv, lapiURL string) {
	t.Helper()
	if err := env.store.PutWatcherCredentials(context.Background(), storage.WatcherCredentials{
		LAPIURL:   lapiURL,
		MachineID: "arenet-test",
		Password:  "watcher-secret",
	}); err != nil {
		t.Fatalf("seed creds: %v", err)
	}
}

// deleteDecisionEvents keeps only the unban audit rows (the
// test env may record unrelated events).
func deleteDecisionEvents(env *testEnv) []audit.Event {
	var out []audit.Event
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionCrowdSecDecisionDelete {
			out = append(out, e)
		}
	}
	return out
}

func doDeleteDecision(env *testEnv, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/security/crowdsec/decisions/"+id, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestDeleteCrowdSecDecision_HappyPath(t *testing.T) {
	fake := newFakeLAPIForDelete()
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	rec := doDeleteDecision(env, "42")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp crowdSecDecisionDeleteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if resp.ID != 42 || resp.NbDeleted != 1 {
		t.Errorf("resp = %+v, want {ID:42 NbDeleted:1}", resp)
	}

	// LAPI saw a JWT-authenticated DELETE on the decision.
	if got := fake.lastMethod.Load().(string); got != http.MethodDelete {
		t.Errorf("LAPI method = %q, want DELETE", got)
	}
	if got := fake.lastPath.Load().(string); got != "/v1/decisions/42" {
		t.Errorf("LAPI path = %q, want /v1/decisions/42", got)
	}
	if got := fake.lastAuth.Load().(string); got != "Bearer jwt-ok" {
		t.Errorf("LAPI Authorization = %q, want the machine JWT", got)
	}

	events := deleteDecisionEvents(env)
	if len(events) != 1 {
		t.Fatalf("unban audit count = %d, want 1", len(events))
	}
	if events[0].TargetType != "crowdsec_decision" || events[0].TargetID != "42" {
		t.Errorf("audit target = (%q, %q), want (crowdsec_decision, 42)", events[0].TargetType, events[0].TargetID)
	}
	if !strings.Contains(string(events[0].AfterJSON), `"nbDeleted":1`) {
		t.Errorf("audit after_json = %s, want nbDeleted", events[0].AfterJSON)
	}
	if events[0].ActorUsernameSnapshot == "" {
		t.Error("audit row has no actor")
	}
}

func TestDeleteCrowdSecDecision_NotConfigured_Returns412(t *testing.T) {
	env := newTestEnv(t, false)
	// No watcher credentials: the bouncer key alone cannot
	// unban (LAPI mounts the route in its JWT group).
	rec := doDeleteDecision(env, "42")

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Security Automation") {
		t.Errorf("body lacks Security Automation hint: %s", rec.Body.String())
	}
	if got := len(deleteDecisionEvents(env)); got != 0 {
		t.Errorf("audit count = %d, want 0", got)
	}
}

func TestDeleteCrowdSecDecision_BadID_Returns400(t *testing.T) {
	fake := newFakeLAPIForDelete()
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	for _, id := range []string{"abc", "0", "-3", "1.5", "99999999999999999999"} {
		t.Run(id, func(t *testing.T) {
			rec := doDeleteDecision(env, id)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	if got := fake.deleteCalls.Load(); got != 0 {
		t.Errorf("LAPI hit %d times for invalid ids", got)
	}
}

func TestDeleteCrowdSecDecision_LAPIUnknownID500_Returns502_NoAudit(t *testing.T) {
	// crowdsec@v1.6.3 answers an unknown id with a 500 (DeleteFail
	// falls through HandleDBErrors' default branch).
	fake := newFakeLAPIForDelete()
	fake.deleteHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"decision with id '7' doesn't exist: cannot delete"}`))
	}
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	rec := doDeleteDecision(env, "7")

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "500") {
		t.Errorf("body should carry LAPI's status: %s", rec.Body.String())
	}
	if got := len(deleteDecisionEvents(env)); got != 0 {
		t.Errorf("audit count = %d, want 0 (nothing was removed)", got)
	}
}

func TestDeleteCrowdSecDecision_LAPI404_Returns404(t *testing.T) {
	fake := newFakeLAPIForDelete()
	fake.deleteHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	rec := doDeleteDecision(env, "7")

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

func TestDeleteCrowdSecDecision_LAPI401_RetriesOnce_Success(t *testing.T) {
	fake := newFakeLAPIForDelete()
	var hits atomic.Int32
	fake.deleteHandler = func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"nbDeleted":"1"}`))
	}
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	rec := doDeleteDecision(env, "42")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after retry, body=%s", rec.Code, rec.Body.String())
	}
	if got := fake.loginCalls.Load(); got != 2 {
		t.Errorf("login calls = %d, want 2 (initial + forced re-login)", got)
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("delete attempts = %d, want 2", got)
	}
}

func TestDeleteCrowdSecDecision_LAPI401Twice_Returns502_NoLoop(t *testing.T) {
	fake := newFakeLAPIForDelete()
	fake.deleteHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	rec := doDeleteDecision(env, "42")

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "machine credentials rejected") {
		t.Errorf("body lacks credential-rejected msg: %s", rec.Body.String())
	}
	if got := fake.deleteCalls.Load(); got != 2 {
		t.Errorf("delete attempts = %d, want exactly 2 (no loop)", got)
	}
}

func TestDeleteCrowdSecDecision_OddLAPIBody_StillOK(t *testing.T) {
	// LAPI accepted the delete; an unexpected body must not
	// turn that into an error (nbDeleted just reads 0).
	fake := newFakeLAPIForDelete()
	fake.deleteHandler = func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}
	srv := fake.server(t)
	env := newTestEnv(t, false)
	seedWatcherCredsForDelete(t, env, srv.URL)

	rec := doDeleteDecision(env, "42")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"nbDeleted":0`) {
		t.Errorf("body = %s, want nbDeleted 0", rec.Body.String())
	}
}
