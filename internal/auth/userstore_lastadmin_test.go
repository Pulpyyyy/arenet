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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// The last-admin guards used to count local admins only. An instance
// whose last local admin was already gone could then demote — or
// delete — its only OIDC admin and be left with no admin at all.
// These tests pin both guards: the break-glass one (last LOCAL admin)
// and the human one (last admin of any source, service accounts
// excluded).

// seedUsers writes rows straight into the users bucket. The public
// constructors cannot build every state these tests need — a store
// with no local admin is exactly what the guards prevent — so the
// fixtures bypass them, the way a pre-guard database or a hand edit
// would.
func seedUsers(t *testing.T, db *bolt.DB, users ...User) {
	t.Helper()
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		for _, u := range users {
			raw, err := json.Marshal(u)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(u.ID), raw); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed users: %v", err)
	}
}

func fixtureUser(id, source, role string) User {
	u := User{ID: id, Username: id, AuthSource: source, Role: role}
	switch source {
	case UserAuthSourceLocal:
		u.PasswordHash = "not-a-real-hash"
	case UserAuthSourceOIDC:
		u.OIDCSub = "sub-" + id
	}
	return u
}

func localAdmin(id string) User   { return fixtureUser(id, UserAuthSourceLocal, UserRoleAdmin) }
func localViewer(id string) User  { return fixtureUser(id, UserAuthSourceLocal, UserRoleViewer) }
func oidcAdmin(id string) User    { return fixtureUser(id, UserAuthSourceOIDC, UserRoleAdmin) }
func serviceAdmin(id string) User { return fixtureUser(id, UserAuthSourceService, UserRoleAdmin) }

func TestUserStore_LastAdminGuards(t *testing.T) {
	cases := []struct {
		name    string
		users   []User
		target  string
		wantErr error // nil = the removal goes through
	}{
		{
			name:    "only OIDC admin is refused",
			users:   []User{oidcAdmin("carol"), localViewer("vic")},
			target:  "carol",
			wantErr: ErrLastAdmin,
		},
		{
			name:    "service admin does not count as a human admin",
			users:   []User{oidcAdmin("carol"), serviceAdmin("ci-bot")},
			target:  "carol",
			wantErr: ErrLastAdmin,
		},
		{
			name:   "OIDC admin with another OIDC admin",
			users:  []User{oidcAdmin("carol"), oidcAdmin("dave")},
			target: "carol",
		},
		{
			name:   "OIDC admin with a local admin",
			users:  []User{oidcAdmin("carol"), localAdmin("alice")},
			target: "carol",
		},
		{
			name:    "only local admin is refused (break-glass)",
			users:   []User{localAdmin("alice")},
			target:  "alice",
			wantErr: ErrLastLocalAdmin,
		},
		{
			name:    "last local admin is refused even with an OIDC admin",
			users:   []User{localAdmin("alice"), oidcAdmin("carol")},
			target:  "alice",
			wantErr: ErrLastLocalAdmin,
		},
		{
			name:    "last local admin is refused even with a service admin",
			users:   []User{localAdmin("alice"), serviceAdmin("ci-bot")},
			target:  "alice",
			wantErr: ErrLastLocalAdmin,
		},
		{
			name:   "local admin with another local admin",
			users:  []User{localAdmin("alice"), localAdmin("bob")},
			target: "alice",
		},
		{
			name:   "service admin is never guarded",
			users:  []User{serviceAdmin("ci-bot")},
			target: "ci-bot",
		},
		{
			name:   "viewer is never guarded",
			users:  []User{localViewer("vic")},
			target: "vic",
		},
	}

	for _, tc := range cases {
		t.Run("demote/"+tc.name, func(t *testing.T) {
			db := newTestDB(t)
			seedUsers(t, db, tc.users...)
			s := NewUserStore(db)
			ctx := context.Background()
			before, err := s.GetByID(ctx, tc.target)
			if err != nil {
				t.Fatalf("GetByID before: %v", err)
			}

			err = s.UpdateRole(ctx, tc.target, UserRoleViewer)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("UpdateRole error = %v, want %v", err, tc.wantErr)
			}

			after, err := s.GetByID(ctx, tc.target)
			if err != nil {
				t.Fatalf("GetByID after: %v", err)
			}
			want := UserRoleViewer
			if tc.wantErr != nil {
				want = before.Role
			}
			if after.Role != want {
				t.Errorf("role after = %q, want %q", after.Role, want)
			}
		})

		t.Run("delete/"+tc.name, func(t *testing.T) {
			db := newTestDB(t)
			seedUsers(t, db, tc.users...)
			s := NewUserStore(db)
			ctx := context.Background()

			err := s.Delete(ctx, tc.target)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Delete error = %v, want %v", err, tc.wantErr)
			}

			_, err = s.GetByID(ctx, tc.target)
			if tc.wantErr != nil && err != nil {
				t.Errorf("user gone despite the refusal: %v", err)
			}
			if tc.wantErr == nil && !errors.Is(err, ErrUserNotFound) {
				t.Errorf("GetByID after delete = %v, want ErrUserNotFound", err)
			}
		})
	}
}

// The guard counts and writes in one bbolt write transaction, so two
// admins demoting each other at the same moment cannot both see the
// other one as still there: exactly one demotion lands.
func TestUserStore_LastAdminGuard_ConcurrentDemotions(t *testing.T) {
	db := newTestDB(t)
	seedUsers(t, db, oidcAdmin("carol"), oidcAdmin("dave"))
	s := NewUserStore(db)
	ctx := context.Background()

	ids := []string{"carol", "dave"}
	errs := make([]error, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			errs[i] = s.UpdateRole(ctx, id, UserRoleViewer)
		}(i, id)
	}
	wg.Wait()

	refused := 0
	for i, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, ErrLastAdmin):
			refused++
		default:
			t.Fatalf("demote %s: unexpected error %v", ids[i], err)
		}
	}
	if refused != 1 {
		t.Fatalf("refused demotions = %d, want exactly 1 (errs=%v)", refused, errs)
	}

	admins := 0
	for _, id := range ids {
		u, err := s.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("GetByID %s: %v", id, err)
		}
		if u.Role == UserRoleAdmin {
			admins++
		}
	}
	if admins != 1 {
		t.Errorf("admins left = %d, want 1", admins)
	}
}
