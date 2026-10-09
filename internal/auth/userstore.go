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
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// usersBucketName is the BoltDB bucket where users live.
const usersBucketName = "users"

// usernameRegex enforces decision D5: lowercase letters, digits,
// underscore, and hyphen only.
var usernameRegex = regexp.MustCompile(`^[a-z0-9_-]+$`)

// argon2idParams is the configuration used by UserStore.Create and
// UpdatePassword. Values come from spec §3.2 / decision Q4.
var argon2idParams = &argon2id.Params{
	Memory:      Argon2idMemory,
	Iterations:  Argon2idIterations,
	Parallelism: Argon2idParallelism,
	SaltLength:  Argon2idSaltLength,
	KeyLength:   Argon2idKeyLength,
}

// ValidateUserForRestore is the Step K.3 shim used by
// internal/backup to re-validate a user row read from a snapshot
// before commit. The function checks the same invariants that
// UserStore.Create / UpdateRole enforce on the live path:
//   - username: regex + length bounds
//   - displayName: length bound
//   - id: non-empty
//   - auth_source ∈ {local, oidc}
//   - role ∈ {viewer, admin}
//   - password_hash non-empty when auth_source == "local" UNLESS
//     allowEmptyPasswordHash is true (the dérogation invoked by
//     internal/backup for fields legitimately cleared under
//     AllowIncompleteRestore — only for that user's
//     password_hash, only when the restore engine asked for it).
//
// The dérogation is intentionally narrow: ValidateUserForRestore
// stays a pure-grid check. The backup engine, which knows which
// fields it cleared and why, is the only legitimate caller of the
// allowEmptyPasswordHash form.
func ValidateUserForRestore(u User, allowEmptyPasswordHash bool) error {
	username := strings.TrimSpace(u.Username)
	if !usernameRegex.MatchString(username) || len(username) < UsernameMinLen || len(username) > UsernameMaxLen {
		return fmt.Errorf("auth: user %q: %w", u.ID, ErrUsernameInvalid)
	}
	if len(u.DisplayName) > DisplayNameMaxLen {
		return fmt.Errorf("auth: user %q: %w", u.ID, ErrDisplayNameTooLong)
	}
	if u.ID == "" {
		return fmt.Errorf("auth: user with empty ID")
	}
	switch u.AuthSource {
	case UserAuthSourceLocal, UserAuthSourceOIDC, UserAuthSourceService:
	default:
		return fmt.Errorf("auth: user %q: auth_source %q must be %q, %q, or %q",
			u.ID, u.AuthSource, UserAuthSourceLocal, UserAuthSourceOIDC, UserAuthSourceService)
	}
	switch u.Role {
	case UserRoleViewer, UserRoleAdmin:
	default:
		return fmt.Errorf("auth: user %q: role %q must be %q or %q", u.ID, u.Role, UserRoleViewer, UserRoleAdmin)
	}
	if u.AuthSource == UserAuthSourceLocal && u.PasswordHash == "" && !allowEmptyPasswordHash {
		return fmt.Errorf("auth: user %q: password_hash must not be empty when auth_source is %q", u.ID, UserAuthSourceLocal)
	}
	return nil
}

// UserStore persists admin users into the BoltDB "users" bucket.
//
// UserStore is safe for concurrent use: bbolt serializes writes
// through a single-writer transaction model. Reads use MVCC snapshots.
type UserStore struct {
	db *bolt.DB
}

// NewUserStore returns a user store backed by the given bbolt handle.
// The handle is shared with the rest of the application; the caller
// retains ownership.
func NewUserStore(db *bolt.DB) *UserStore {
	if db == nil {
		panic("auth.NewUserStore: db is nil")
	}
	return &UserStore{db: db}
}

// Create persists a new user. The username is normalized (trimmed)
// and validated against the D5 regex. The password is validated for
// length (D6) and hashed with argon2id (Q4). Returns ErrUsernameTaken
// if the username already exists.
//
// Phase 1 does not check the password against the top-10k list or
// HIBP here; those checks happen in Chunk 2's password validation
// layer that wraps this method.
//
// The hash is computed BEFORE the bbolt transaction starts, so the
// ~100 ms argon2id cost does not hold the single-writer lock. A
// theoretical race where two concurrent Create calls both pass the
// pre-transaction validation is resolved inside the transaction: the
// second caller observes the first's insertion and gets ErrUsernameTaken.
// Create persists a new local user. `email` is the user's
// contact address (now required for new local accounts —
// users-page Phase 1 refactor; callers validate the wire-
// level shape before calling). Pre-fix call sites that pass
// "" will produce a user with Email="" — bbolt JSON tolerates
// the absent field on read; the wire response renders "—".
func (s *UserStore) Create(ctx context.Context, username, displayName, email, password string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	username = strings.TrimSpace(username)
	if !usernameRegex.MatchString(username) || len(username) < UsernameMinLen || len(username) > UsernameMaxLen {
		return User{}, ErrUsernameInvalid
	}
	if len(displayName) > DisplayNameMaxLen {
		return User{}, ErrDisplayNameTooLong
	}
	if len(password) < PasswordMinLen {
		return User{}, ErrPasswordTooShort
	}
	if len(password) > PasswordMaxLen {
		return User{}, ErrPasswordTooLong
	}

	hash, err := argon2id.CreateHash(password, argon2idParams)
	if err != nil {
		return User{}, fmt.Errorf("auth: hash password: %w", err)
	}

	now := time.Now().UTC()
	user := User{
		ID:              uuid.NewString(),
		Username:        username,
		DisplayName:     displayName,
		Email:           strings.TrimSpace(email),
		PasswordHash:    hash,
		HIBPCheckStatus: HIBPStatusPending,
		HIBPCheckedAt:   now,
		CreatedAt:       now,
		UpdatedAt:       now,
		// Step K.2: locally-managed admin (created via the boot-
		// time setup-token flow). Default role is admin — the
		// setup flow is trusted by definition (the operator
		// knows the boot token), and a homelab with zero admin
		// is locked out.
		AuthSource: UserAuthSourceLocal,
		Role:       UserRoleAdmin,
	}

	if err := s.insertUnique(user); err != nil {
		return User{}, err
	}
	return user, nil
}

// insertUnique persists a brand-new user, refusing a username another
// row already holds.
//
// v2.48 — extracted from Create so CreateManaged shares the exact same
// uniqueness check rather than carrying a second copy of it. The
// check has to live inside the transaction: two concurrent creations
// would otherwise both read "free" and both insert.
//
// A corrupted row is logged and skipped rather than blocking every
// future creation — one unreadable record should not lock the
// operator out of adding users.
func (s *UserStore) insertUnique(user User) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		var taken bool
		_ = b.ForEach(func(k, v []byte) error {
			var existing User
			if err := json.Unmarshal(v, &existing); err != nil {
				slog.Default().Warn("auth: corrupted user row in bucket, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if existing.Username == user.Username {
				taken = true
			}
			return nil
		})
		if taken {
			return ErrUsernameTaken
		}
		value, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(user.ID), value)
	})
}

// ManagedUserSpec is a user an administrator creates from the Users
// page, as opposed to the single account the setup flow bootstraps.
type ManagedUserSpec struct {
	Username    string
	DisplayName string
	Email       string
	// Password is the first password. Already generated or typed by
	// the caller; this layer only validates and hashes it.
	Password string
	// Role is "viewer" or "admin". The caller decides; there is no
	// default here, so forgetting it is a refusal rather than a
	// silent privilege grant.
	Role string
}

// CreateManaged persists a user an administrator created.
//
// v2.48 — distinct from Create, which hardcodes Role=admin because the
// setup flow is trusted by definition and a homelab with zero admins
// is locked out. Neither assumption holds here: an admin creating an
// account picks the role, and the account starts out having to change
// its password, because whoever created it knows the first one.
func (s *UserStore) CreateManaged(ctx context.Context, spec ManagedUserSpec) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	username := strings.TrimSpace(spec.Username)
	if !usernameRegex.MatchString(username) || len(username) < UsernameMinLen || len(username) > UsernameMaxLen {
		return User{}, ErrUsernameInvalid
	}
	if len(spec.DisplayName) > DisplayNameMaxLen {
		return User{}, ErrDisplayNameTooLong
	}
	if spec.Role != UserRoleViewer && spec.Role != UserRoleAdmin {
		return User{}, ErrRoleInvalid
	}
	if len(spec.Password) < PasswordMinLen {
		return User{}, ErrPasswordTooShort
	}
	if len(spec.Password) > PasswordMaxLen {
		return User{}, ErrPasswordTooLong
	}

	hash, err := argon2id.CreateHash(spec.Password, argon2idParams)
	if err != nil {
		return User{}, fmt.Errorf("auth: hash password: %w", err)
	}

	now := time.Now().UTC()
	user := User{
		ID:              uuid.NewString(),
		Username:        username,
		DisplayName:     spec.DisplayName,
		Email:           strings.TrimSpace(spec.Email),
		PasswordHash:    hash,
		HIBPCheckStatus: HIBPStatusPending,
		HIBPCheckedAt:   now,
		CreatedAt:       now,
		UpdatedAt:       now,
		AuthSource:      UserAuthSourceLocal,
		Role:            spec.Role,
		// The whole point: the creator knows this password.
		MustChangePassword: true,
	}
	if err := s.insertUnique(user); err != nil {
		return User{}, err
	}
	return user, nil
}

// CreateServiceAccount persists a new service-account user
// (machine identity, Phase 4). The name is validated against
// the same regex as human usernames (D5) so display in the
// /utilisateurs table is consistent. Service accounts have NO
// PasswordHash and NO OIDCSub by construction; they
// authenticate exclusively via APIToken (see APITokenStore).
//
// Role is the caller's choice (admin OR viewer). Service
// admins are excluded from the last-admin guards (only human
// admins count, see checkAdminRemoval), so a service-admin
// can never be the "last admin standing".
//
// Returns ErrUsernameTaken if name collides with any
// existing user (human or service).
func (s *UserStore) CreateServiceAccount(ctx context.Context, name, role string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	name = strings.TrimSpace(name)
	if !usernameRegex.MatchString(name) || len(name) < UsernameMinLen || len(name) > UsernameMaxLen {
		return User{}, ErrUsernameInvalid
	}
	switch role {
	case UserRoleViewer, UserRoleAdmin:
	default:
		return User{}, fmt.Errorf("auth: service account role %q must be %q or %q",
			role, UserRoleViewer, UserRoleAdmin)
	}

	now := time.Now().UTC()
	user := User{
		ID:              uuid.NewString(),
		Username:        name,
		DisplayName:     name,
		AuthSource:      UserAuthSourceService,
		Role:            role,
		HIBPCheckStatus: HIBPStatusSkipped,
		HIBPCheckedAt:   now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		var taken bool
		_ = b.ForEach(func(k, v []byte) error {
			var existing User
			if err := json.Unmarshal(v, &existing); err != nil {
				slog.Default().Warn("auth: corrupted user row in bucket, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if existing.Username == name {
				taken = true
			}
			return nil
		})
		if taken {
			return ErrUsernameTaken
		}
		value, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("auth: marshal service-account user: %w", err)
		}
		return b.Put([]byte(user.ID), value)
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// GetByID returns the user with the given ID, or ErrUserNotFound.
func (s *UserStore) GetByID(ctx context.Context, id string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return User{}, ErrUserNotFound
	}

	var user User
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		return json.Unmarshal(v, &user)
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// GetByUsername returns the user with the given username, or
// ErrUserNotFound. O(n) scan; acceptable for Phase 1 single-admin
// per spec §3.6.
func (s *UserStore) GetByUsername(ctx context.Context, username string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, ErrUserNotFound
	}

	var user User
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			if found {
				return nil
			}
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				slog.Default().Warn("auth: corrupted user row in bucket, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if u.Username == username {
				user = u
				found = true
			}
			return nil
		})
	})
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

// Count returns the number of users currently in the bucket. Used by
// the bootstrap flow (count == 0 → setup mode).
func (s *UserStore) Count(ctx context.Context) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	var n int
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		n = b.Stats().KeyN
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// UpdatePassword re-hashes and stores a new password, updates
// UpdatedAt, and resets HIBPCheckStatus to "pending" so the new
// password gets re-verified at next login.
//
// Validates length only at this layer; top-10k and HIBP checks
// belong to Chunk 2.
func (s *UserStore) UpdatePassword(ctx context.Context, id, newPassword string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	if len(newPassword) < PasswordMinLen {
		return ErrPasswordTooShort
	}
	if len(newPassword) > PasswordMaxLen {
		return ErrPasswordTooLong
	}

	hash, err := argon2id.CreateHash(newPassword, argon2idParams)
	if err != nil {
		return fmt.Errorf("auth: hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.PasswordHash = hash
		u.HIBPCheckStatus = HIBPStatusPending
		u.HIBPCheckedAt = time.Time{} // re-verified at next login
		u.PasswordCompromised = false
		// v2.48 — changing the password is the only way out of the
		// forced-change state, and it is unconditional: a user who
		// arrives here already free of the flag simply stays free.
		u.MustChangePassword = false
		u.UpdatedAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// UpdateHIBPStatus updates the HIBP fields after a deferred re-check
// at login. Best-effort: callers should log and continue rather than
// propagating the error to the user-facing response.
func (s *UserStore) UpdateHIBPStatus(ctx context.Context, id string, status string, compromised bool) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.HIBPCheckStatus = status
		u.HIBPCheckedAt = time.Now().UTC()
		u.PasswordCompromised = compromised
		u.UpdatedAt = u.HIBPCheckedAt
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// UpdateThemePreference persists the user's UI theme preference. The
// value MUST be one of `ThemeDark` or `ThemeLight` exactly — any other
// input (including the empty string, which is a valid *storage* value
// for legacy rows but a forbidden *input* value) returns ErrThemeInvalid.
//
// Pattern: read, mutate, marshal, write — identical to UpdateHIBPStatus.
// Touches UpdatedAt because the user-visible profile changed.
//
// Step F spec §3.2.
func (s *UserStore) UpdateThemePreference(ctx context.Context, id, theme string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	if theme != ThemeDark && theme != ThemeLight {
		return ErrThemeInvalid
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.ThemePreference = theme
		u.UpdatedAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// UpdateLanguagePreference persists the user's UI language preference.
// The value MUST be one of `LanguageEnglish` or `LanguageFrench`
// exactly — any other input (including the empty string, which is a
// valid *storage* value for legacy rows but a forbidden *input* value)
// returns ErrLanguageInvalid.
//
// Pattern: read, mutate, marshal, write — byte-for-byte mirror of
// UpdateThemePreference. Touches UpdatedAt because the user-visible
// profile changed.
//
// v2.9.11 i18n Phase 1 spec.
func (s *UserStore) UpdateLanguagePreference(ctx context.Context, id, language string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	if language != LanguageEnglish && language != LanguageFrench {
		return ErrLanguageInvalid
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.LanguagePreference = language
		u.UpdatedAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// RecordLogin updates LastLoginAt only. UpdatedAt is intentionally NOT
// touched: LastLoginAt is observability metadata, not a profile mutation.
// Frequent logins should not signal "profile changed".
//
// Best-effort: callers should log and continue rather than propagating
// the error to the user-facing response.
func (s *UserStore) RecordLogin(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrUserNotFound
		}
		var u User
		if err := json.Unmarshal(v, &u); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		u.LastLoginAt = time.Now().UTC()
		out, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// CreateOIDCUser persists a new user mapped to an OIDC subject
// (Step K.2 §5.2 allowlist auto-create flow). The new user has
// no PasswordHash (the IdP is the auth source) and a default
// role of "viewer" — elevation to "admin" is an explicit later
// operator action via UpdateRole (§1.3 decision 12 — guards
// against over-permissive OIDC allowlist mistakes).
//
// Caller responsibilities:
//   - Validate the OIDC sub (non-empty, IdP-provided).
//   - Derive a unique Username from the IdP claims (preferred
//     username / email local part / sub fallback).
//   - Re-check uniqueness — the in-transaction check below
//     defends against concurrent Create races but the caller's
//     pre-check produces a friendlier error.
//
// `email` is the OIDC `email` claim — best-effort capture
// so the users-page can display contact info. Empty when
// the IdP didn't emit the claim; UpdateEmail can backfill on
// a subsequent login.
func (s *UserStore) CreateOIDCUser(ctx context.Context, username, displayName, email, oidcSub string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	username = strings.TrimSpace(username)
	if !usernameRegex.MatchString(username) || len(username) < UsernameMinLen || len(username) > UsernameMaxLen {
		return User{}, ErrUsernameInvalid
	}
	if len(displayName) > DisplayNameMaxLen {
		return User{}, ErrDisplayNameTooLong
	}
	if oidcSub == "" {
		return User{}, fmt.Errorf("auth: oidc_sub must not be empty")
	}

	now := time.Now().UTC()
	user := User{
		ID:              uuid.NewString(),
		Username:        username,
		DisplayName:     displayName,
		Email:           strings.TrimSpace(email),
		PasswordHash:    "", // OIDC user — no local password
		HIBPCheckStatus: HIBPStatusSkipped,
		CreatedAt:       now,
		UpdatedAt:       now,
		AuthSource:      UserAuthSourceOIDC,
		OIDCSub:         oidcSub,
		Role:            UserRoleViewer, // §1.3 decision 12 default
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		// Uniqueness in-transaction across BOTH Username AND OIDCSub.
		// Corrupted rows are logged and skipped.
		var usernameTaken, subTaken bool
		_ = b.ForEach(func(k, v []byte) error {
			var existing User
			if err := json.Unmarshal(v, &existing); err != nil {
				slog.Default().Warn("auth: corrupted user row in bucket, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if existing.Username == username {
				usernameTaken = true
			}
			if existing.OIDCSub != "" && existing.OIDCSub == oidcSub {
				subTaken = true
			}
			return nil
		})
		if usernameTaken {
			return ErrUsernameTaken
		}
		if subTaken {
			return fmt.Errorf("auth: oidc_sub %q already mapped to a user", oidcSub)
		}
		value, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(user.ID), value)
	})
	if err != nil {
		return User{}, err
	}
	return user, nil
}

// GetByOIDCSub returns the user mapped to the given OIDC subject,
// or ErrUserNotFound. Step K.2 §5.2 steady-state lookup path
// (post-canonicalisation).
func (s *UserStore) GetByOIDCSub(ctx context.Context, sub string) (User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if sub == "" {
		return User{}, ErrUserNotFound
	}

	var user User
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return nil // skip corrupted row
			}
			if u.OIDCSub != "" && u.OIDCSub == sub {
				user = u
				found = true
			}
			return nil
		})
	})
	if err != nil {
		return User{}, err
	}
	if !found {
		return User{}, ErrUserNotFound
	}
	return user, nil
}

// UpdateRole sets the user's Role field (Step K.2 §3.1).
// Validates the enum + enforces the §1.3 decision 12 last-admin
// guards (see checkAdminRemoval): demoting the last local admin
// (the break-glass channel) or the last human admin of any
// source is rejected to prevent locking the instance out of
// admin access.
//
// Returns ErrUserNotFound when no row matches id,
// ErrLastLocalAdmin / ErrLastAdmin when a guard fires, and the
// standard storage errors otherwise.
func (s *UserStore) UpdateRole(ctx context.Context, id, newRole string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	if newRole != UserRoleViewer && newRole != UserRoleAdmin {
		return fmt.Errorf("auth: invalid role %q (must be %q or %q)", newRole, UserRoleViewer, UserRoleAdmin)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrUserNotFound
		}
		var user User
		if err := json.Unmarshal(raw, &user); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}

		// Last-admin guards on the demote path "admin → viewer".
		// Checked inside this write transaction so two
		// concurrent demotions cannot both see the other admin
		// as still present.
		if newRole == UserRoleViewer {
			if err := checkAdminRemoval(b, id, user); err != nil {
				return err
			}
		}

		// No change → no write (avoids touching UpdatedAt on a no-op).
		if user.Role == newRole {
			return nil
		}

		user.Role = newRole
		user.UpdatedAt = time.Now().UTC()
		value, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), value)
	})
}

// CountLocalAdmins returns the number of users with
// AuthSource=local AND Role=admin. Used for the break-glass
// invariant check at boot and by UpdateRole's last-admin guard
// (see above). A pure count: returns 0 + nil if the bucket is
// empty.
func (s *UserStore) CountLocalAdmins(ctx context.Context) (int, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	count := 0
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		return b.ForEach(func(_, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return nil
			}
			if u.AuthSource == UserAuthSourceLocal && u.Role == UserRoleAdmin {
				count++
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return count, nil
}

// List returns every user, sorted by CreatedAt ascending. Used
// by the admin Users management UI (GET /api/v1/admin/users).
// PasswordHash + OIDCSub are NOT scrubbed here — the API layer
// builds a separate wire shape that omits them.
func (s *UserStore) List(ctx context.Context) ([]User, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	var out []User
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		return b.ForEach(func(_, v []byte) error {
			var u User
			if err := json.Unmarshal(v, &u); err != nil {
				return nil // skip corrupted
			}
			out = append(out, u)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// Delete removes the user identified by id. Returns
// ErrUserNotFound if no such user exists.
//
// Last-admin guards (same as UpdateRole, see
// checkAdminRemoval): refuses to delete the last local admin
// — the break-glass channel must always have at least one
// local admin (§1.3 decisions 4-6) — and the last human admin
// of any source. Returns ErrLastLocalAdmin / ErrLastAdmin
// when a guard fires.
//
// Session cleanup is performed by the API handler that
// wraps this call (SessionStore.DeleteAllForUser), not
// here — the storage layer stays single-bucket.
func (s *UserStore) Delete(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrUserNotFound
		}
		var target User
		if err := json.Unmarshal(raw, &target); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}

		// Last-admin guards. Same logic as UpdateRole's demote
		// path, scanning this transaction's bucket rather than
		// reusing CountLocalAdmins to avoid a second bbolt
		// transaction inside this Update.
		if err := checkAdminRemoval(b, id, target); err != nil {
			return err
		}

		return b.Delete([]byte(id))
	})
}

// isHumanAdmin reports whether u is an admin a person signs in as:
// local or OIDC. Service accounts are machine identities and never
// count toward the last-admin guards.
func isHumanAdmin(u User) bool {
	if u.Role != UserRoleAdmin {
		return false
	}
	return u.AuthSource == UserAuthSourceLocal || u.AuthSource == UserAuthSourceOIDC
}

// checkAdminRemoval refuses to take admin rights away from target
// (stored under key id) by demotion or deletion when that would
// leave the instance without:
//   - a local admin — ErrLastLocalAdmin. The break-glass channel:
//     only a local admin can sign in when the IdP is down (§1.3
//     decisions 4-6);
//   - a human admin of any source — ErrLastAdmin. Without this,
//     an instance whose last local admin is gone (pre-guard data,
//     a hand-edited database) could demote its only OIDC admin
//     and be left with no admin at all.
//
// It scans b, the bucket of the caller's write transaction, so the
// count and the write are atomic. A target that is not a human
// admin (viewer, service account) is always allowed: removing it
// does not change either count. Corrupted rows are skipped, the
// same as everywhere else in this store.
func checkAdminRemoval(b *bolt.Bucket, id string, target User) error {
	if !isHumanAdmin(target) {
		return nil
	}
	otherHumans, otherLocals := 0, 0
	_ = b.ForEach(func(k, v []byte) error {
		if string(k) == id {
			return nil
		}
		var other User
		if err := json.Unmarshal(v, &other); err != nil {
			return nil
		}
		if isHumanAdmin(other) {
			otherHumans++
			if other.AuthSource == UserAuthSourceLocal {
				otherLocals++
			}
		}
		return nil
	})
	if target.AuthSource == UserAuthSourceLocal && otherLocals == 0 {
		return ErrLastLocalAdmin
	}
	if otherHumans == 0 {
		return ErrLastAdmin
	}
	return nil
}

// UpdateEmail sets the user's Email field. Used by the OIDC
// callback to keep an existing user's email in sync with
// the IdP's `email` claim on every login (best-effort:
// callers ignore the error to avoid breaking the login
// path). A no-op when the stored email already matches
// — skips touching UpdatedAt.
func (s *UserStore) UpdateEmail(ctx context.Context, id, email string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return ErrUserNotFound
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(usersBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", usersBucketName)
		}
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrUserNotFound
		}
		var user User
		if err := json.Unmarshal(raw, &user); err != nil {
			return fmt.Errorf("auth: unmarshal user: %w", err)
		}
		if user.Email == email {
			return nil
		}
		user.Email = email
		user.UpdatedAt = time.Now().UTC()
		value, err := json.Marshal(user)
		if err != nil {
			return fmt.Errorf("auth: marshal user: %w", err)
		}
		return b.Put([]byte(id), value)
	})
}
