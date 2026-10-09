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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/barto95100/arenet/internal/auth"
)

// The last-admin refusals carry a code the UI translates, and keep the
// 400 the break-glass refusal has always had.

func errorCodeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, rec.Body.String())
	}
	return body.Code
}

func TestWriteAdminRemovalError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"last human admin", fmt.Errorf("wrapped: %w", auth.ErrLastAdmin), http.StatusBadRequest, "user_last_admin"},
		{"last local admin", auth.ErrLastLocalAdmin, http.StatusBadRequest, "user_last_local_admin"},
		{"not found", auth.ErrUserNotFound, http.StatusNotFound, ""},
		{"anything else", errors.New("boom"), http.StatusBadRequest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writeAdminRemovalError(rec, tc.err)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if got := errorCodeOf(t, rec); got != tc.wantCode {
				t.Errorf("code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestUpdateUserRole_LastLocalAdmin_Coded(t *testing.T) {
	env, token := setupTestEnv(t)
	soleID, sessCookie := adminBootstrap(t, env, token, "admin", testAdminPassword)

	rec := postJSONWithSession(t, env, "/api/v1/admin/users/"+soleID+"/role", sessCookie,
		map[string]any{"role": "viewer"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if got := errorCodeOf(t, rec); got != "user_last_local_admin" {
		t.Errorf("code = %q, want user_last_local_admin", got)
	}
}

// forceUserRole rewrites a user's role straight in BoltDB. The guards
// forbid reaching a state with no local admin, which is exactly the
// state this file needs, so the fixture goes around them — the way a
// pre-guard database or a hand edit would.
func forceUserRole(t *testing.T, env *testEnv, id, role string) {
	t.Helper()
	u, err := auth.NewUserStore(env.store.DB()).GetByID(t.Context(), id)
	if err != nil {
		t.Fatalf("load user %s: %v", id, err)
	}
	u.Role = role
	raw, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal user %s: %v", id, err)
	}
	if err := env.store.DB().Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("users")).Put([]byte(id), raw)
	}); err != nil {
		t.Fatalf("rewrite user %s: %v", id, err)
	}
}

// With no local admin left, the only admin signs in through OIDC.
// The local-only guard used to let them demote or delete themselves,
// leaving the instance with no admin at all.
func TestAdminUsers_LastHumanAdminIsOIDC_Refused(t *testing.T) {
	env, token := setupTestEnv(t)
	localID, _ := adminBootstrap(t, env, token, "admin", testAdminPassword)

	users := auth.NewUserStore(env.store.DB())
	carol, err := users.CreateOIDCUser(t.Context(), "carol", "Carol", "carol@example.test", "sub-carol")
	if err != nil {
		t.Fatalf("seed OIDC user: %v", err)
	}
	if err := users.UpdateRole(t.Context(), carol.ID, auth.UserRoleAdmin); err != nil {
		t.Fatalf("elevate OIDC user: %v", err)
	}
	forceUserRole(t, env, localID, auth.UserRoleViewer)

	sess, err := auth.NewSessionStore(env.store.DB()).Create(t.Context(), carol.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}

	cases := []struct {
		name, method, path, body string
	}{
		{"demote", http.MethodPost, "/api/v1/admin/users/" + carol.ID + "/role", `{"role":"viewer"}`},
		{"delete", http.MethodDelete, "/api/v1/admin/users/" + carol.ID, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			withSessionCookie(req, sess.ID)
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if got := errorCodeOf(t, rec); got != "user_last_admin" {
				t.Errorf("code = %q, want user_last_admin", got)
			}
		})
	}

	got, err := users.GetByID(t.Context(), carol.ID)
	if err != nil {
		t.Fatalf("OIDC admin gone despite the refusal: %v", err)
	}
	if got.Role != auth.UserRoleAdmin {
		t.Errorf("role = %q, want admin", got.Role)
	}
}
