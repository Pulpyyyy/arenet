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
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/google/uuid"
)

// Step R — operator-defined HTML error pages.
//
// An ErrorPageTemplate is a named collection of HTML bodies keyed
// by HTTP status code. Routes opt into a template via
// Route.ErrorPageTemplateID ; the per-route Route.ErrorPageOverrides
// map can layer code-specific exceptions on top (mirror of how
// per-route waf rule exclusions layer on top of the global CRS).
//
// The template body is a raw HTML string. Caddy runtime placeholders
// (e.g. {http.error.status_code}, {http.request.uri}) are expanded
// by the upstream `http.handlers.static_response` handler at serve
// time — Arenet does NO server-side template rendering. Verified
// against caddy v2.11.3 modules/caddyhttp/staticresp.go:208
// (ReplaceKnown on Body before Fprint).
//
// Validation : Pages keys must lie in the spec-locked set
// {401, 403, 404, 429, 500, 502, 503, 504}. Codes outside the set
// would silently never render — the validator rejects them at
// storage and API boundary so the operator gets immediate feedback
// instead of mysterious empty-body responses in prod.
//
// HTML sanitization is NOT done at storage time : the raw body is
// what the operator typed. Sanitization (bluemonday UGCPolicy) lives
// at caddymgr emit time so the operator can keep iterating in the
// editor without losing characters to an over-eager filter.

// SupportedErrorStatusCodes enumerates the 8 HTTP status codes
// operators may customize. Locked at Step R for V1 ; extension
// (e.g. 405, 413) belongs to a focused follow-up so we don't grow
// the enum casually and break the per-tab UI assumptions.
var SupportedErrorStatusCodes = []int{401, 403, 404, 429, 500, 502, 503, 504}

// ErrorPageTemplate is the storage shape for one operator-defined
// collection of error pages.
//
// Pages maps status code → raw HTML body. Codes absent from the map
// fall back at caddymgr emit time to the per-route Override (if
// present) or to the Arenet built-in default (caddymgr-side const).
// Empty string in the map is treated as "explicitly use default"
// — distinct semantic from "code absent" only at the
// per-route-override level (handled in caddymgr, not storage).
type ErrorPageTemplate struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Pages       map[int]string `json:"pages"`
	// IsCatchallDefault (v2.9.10 Bug 1) marks this template as the
	// global default body for the catch-all route (a request for a
	// host not configured on any route). At most one template
	// carries the flag at any time — Create/Update enforce mutual
	// exclusion by clearing the flag on every OTHER template in the
	// same bbolt write transaction before persisting this one.
	//
	// When no template is flagged, the catch-all body falls back to
	// caddymgr's arenetDefaultErrorPages[404] builtin — i.e. the
	// Arenet branded 404 page operators already see on configured
	// routes that hit an upstream 404. The flag is opt-in.
	//
	// JSON tag is camelCase to match the rest of the type's wire
	// format; omitempty keeps the field out of GET responses for
	// templates that don't have it set (the common case).
	IsCatchallDefault bool `json:"isCatchallDefault,omitempty"`
	// IsRouteDefault (v2.51) marks this template as the default for
	// every ROUTE that has not chosen one of its own. At most one
	// template carries it, enforced the same way as the flag above.
	//
	// Deliberately SEPARATE from IsCatchallDefault, which an operator
	// reasonably read as meaning this. They are different decisions: an
	// unknown host arguably deserves a neutral 404 that reveals no
	// branding to a scanner, while real routes deserve the branded set —
	// and an operator may want the reverse. Folding them into one flag
	// would also have silently changed behaviour for every installation
	// that had already flagged a catch-all template.
	//
	// It sits between the route's own template and Arenet's built-in
	// pages in the resolution order (caddymgr.resolveErrorPage), so a
	// route that picked a template still wins, and nothing changes for an
	// installation that never sets this.
	IsRouteDefault bool      `json:"isRouteDefault,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// ValidateErrorPageTemplate is a public shim around the private
// validate() method. Same pattern as ValidateRoute — gives the API
// layer a way to dry-run a payload without going through the storage
// write path.
func ValidateErrorPageTemplate(t ErrorPageTemplate) error {
	return t.validate()
}

// validate runs the same checks every storage write goes through.
// Last line of defence : the API layer normalises + pre-validates
// first, but storage rejects malformed rows so a corrupted bucket
// state can't sneak in via a future call site that forgets the API
// hop.
func (t *ErrorPageTemplate) validate() error {
	if t.Name == "" {
		return errors.New("error_template: name must not be empty")
	}
	if len(t.Name) > 100 {
		return errors.New("error_template: name must be 100 chars or less")
	}
	if len(t.Description) > 500 {
		return errors.New("error_template: description must be 500 chars or less")
	}
	if t.Pages == nil {
		// nil map is legal (means "use defaults for everything") but
		// validate() normalises to an empty map so callers don't have
		// to nil-check downstream.
		t.Pages = map[int]string{}
	}
	for code, body := range t.Pages {
		if !IsSupportedErrorStatusCode(code) {
			return fmt.Errorf("error_template: unsupported status code %d (allowed: %v)",
				code, SupportedErrorStatusCodes)
		}
		// Sanity cap : a 1 MiB HTML body is already absurd for an
		// error page. Reject obvious abuse so the BoltDB value
		// size + caddy reload payload stay sane.
		if len(body) > 1<<20 {
			return fmt.Errorf("error_template: body for code %d exceeds 1 MiB (%d bytes)", code, len(body))
		}
	}
	return nil
}

// IsSupportedErrorStatusCode reports whether the given code is in
// the operator-customisable enum. Exposed because the per-route
// Route.ErrorPageOverrides validation uses the same gate.
func IsSupportedErrorStatusCode(code int) bool {
	for _, c := range SupportedErrorStatusCodes {
		if c == code {
			return true
		}
	}
	return false
}

// CreateErrorPageTemplate persists a new template. Assigns a fresh
// UUID + sets CreatedAt + UpdatedAt to the same UTC instant. Mirror
// of CreateRoute (routes.go:789).
func (s *Store) CreateErrorPageTemplate(ctx context.Context, t ErrorPageTemplate) (ErrorPageTemplate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := t.validate(); err != nil {
		return ErrorPageTemplate{}, err
	}

	now := time.Now().UTC()
	t.ID = uuid.NewString()
	t.CreatedAt = now
	t.UpdatedAt = now

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketErrorTemplates))
		if err := applyExclusiveFlags(b, t); err != nil {
			return err
		}
		buf, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("marshal error_template: %w", err)
		}
		return b.Put([]byte(t.ID), buf)
	}); err != nil {
		return ErrorPageTemplate{}, err
	}
	return t, nil
}

// exclusiveFlags are the template flags of which at most one template
// may carry each. v2.51 generalised this from a single hard-coded flag
// to a pair, rather than copying the walker below.
var exclusiveFlags = []struct {
	name string
	ptr  func(*ErrorPageTemplate) *bool
}{
	{"isCatchallDefault", func(t *ErrorPageTemplate) *bool { return &t.IsCatchallDefault }},
	{"isRouteDefault", func(t *ErrorPageTemplate) *bool { return &t.IsRouteDefault }},
}

// applyExclusiveFlags clears every exclusive flag that `t` claims from
// all OTHER templates, inside the caller's write transaction.
func applyExclusiveFlags(b *bolt.Bucket, t ErrorPageTemplate) error {
	for _, f := range exclusiveFlags {
		local := t
		if !*f.ptr(&local) {
			continue
		}
		if err := clearExclusiveFlagExcept(b, t.ID, f.name, f.ptr); err != nil {
			return err
		}
	}
	return nil
}

// clearExclusiveFlagExcept (v2.9.10 Bug 1, generalised v2.51) walks
// every template in the bucket and clears the named flag on any whose
// ID is NOT `keepID`. Called from inside Create/Update bbolt write
// transactions when the incoming payload claims that flag, to enforce
// the "at most one" invariant atomically.
//
// keepID may be empty when called from a write that wants to clear
// the flag globally without preserving any winner (not currently
// used; future ops endpoint could call this directly).
//
// Mutates rows in-place: read → flip flag → write back. The bbolt
// txn serialises the whole sequence, so a concurrent reader either
// sees the pre-clear state or the post-clear state — never a
// half-cleared map.
func clearExclusiveFlagExcept(b *bolt.Bucket, keepID, flagName string, flag func(*ErrorPageTemplate) *bool) error {
	type rewrite struct {
		key []byte
		t   ErrorPageTemplate
	}
	var pending []rewrite
	if err := b.ForEach(func(k, v []byte) error {
		var t ErrorPageTemplate
		if err := json.Unmarshal(v, &t); err != nil {
			return fmt.Errorf("clearExclusiveFlagExcept(%s): unmarshal: %w", flagName, err)
		}
		if t.ID == keepID || !*flag(&t) {
			return nil
		}
		*flag(&t) = false
		t.UpdatedAt = time.Now().UTC()
		pending = append(pending, rewrite{key: append([]byte(nil), k...), t: t})
		return nil
	}); err != nil {
		return err
	}
	for _, r := range pending {
		buf, err := json.Marshal(r.t)
		if err != nil {
			return fmt.Errorf("clearExclusiveFlagExcept(%s): marshal: %w", flagName, err)
		}
		if err := b.Put(r.key, buf); err != nil {
			return err
		}
	}
	return nil
}

// GetErrorPageTemplate returns the template identified by id, or
// ErrNotFound. Mirror of GetRoute.
func (s *Store) GetErrorPageTemplate(ctx context.Context, id string) (ErrorPageTemplate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return ErrorPageTemplate{}, errors.New("error_template: id must not be empty")
	}

	var out ErrorPageTemplate
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketErrorTemplates)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return ErrorPageTemplate{}, err
	}
	return out, nil
}

// ListErrorPageTemplates returns every template sorted by CreatedAt
// ascending. Mirror of ListRoutes.
func (s *Store) ListErrorPageTemplates(ctx context.Context) ([]ErrorPageTemplate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []ErrorPageTemplate
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketErrorTemplates)).ForEach(func(_, v []byte) error {
			var t ErrorPageTemplate
			if err := json.Unmarshal(v, &t); err != nil {
				return fmt.Errorf("unmarshal error_template: %w", err)
			}
			out = append(out, t)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// UpdateErrorPageTemplate replaces an existing template. CreatedAt
// is preserved from the stored record ; UpdatedAt is refreshed.
// Mirror of UpdateRoute.
func (s *Store) UpdateErrorPageTemplate(ctx context.Context, t ErrorPageTemplate) (ErrorPageTemplate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if t.ID == "" {
		return ErrorPageTemplate{}, errors.New("error_template: id must not be empty")
	}
	if err := t.validate(); err != nil {
		return ErrorPageTemplate{}, err
	}

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketErrorTemplates))
		raw := b.Get([]byte(t.ID))
		if raw == nil {
			return ErrNotFound
		}
		var existing ErrorPageTemplate
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal existing error_template: %w", err)
		}
		t.CreatedAt = existing.CreatedAt
		t.UpdatedAt = time.Now().UTC()
		if err := applyExclusiveFlags(b, t); err != nil {
			return err
		}
		buf, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("marshal error_template: %w", err)
		}
		return b.Put([]byte(t.ID), buf)
	})
	if err != nil {
		return ErrorPageTemplate{}, err
	}
	return t, nil
}

// GetCatchallDefaultErrorPageTemplate (v2.9.10 Bug 1) returns the
// template currently flagged as the catch-all default, or
// (ErrorPageTemplate{}, ErrNotFound) if no template carries the
// flag. Used by caddymgr when building the catch-all route body —
// a found template's Pages[404] is preferred over the builtin
// arenetDefaultErrorPages[404].
//
// The mutual-exclusion invariant (Create/Update) means at most one
// template can satisfy this query, but the implementation tolerates
// a corrupted bucket with multiple flagged templates by returning
// the first one encountered in the iteration order (deterministic
// per-boot via bbolt's key-order iteration). A future repair tool
// could detect and fix the duplicates; surfacing the corruption as
// an error here would just hide the catch-all from the operator.
func (s *Store) GetCatchallDefaultErrorPageTemplate(ctx context.Context) (ErrorPageTemplate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out ErrorPageTemplate
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketErrorTemplates)).ForEach(func(_, v []byte) error {
			if found {
				return nil
			}
			var t ErrorPageTemplate
			if err := json.Unmarshal(v, &t); err != nil {
				return fmt.Errorf("unmarshal error_template: %w", err)
			}
			if t.IsCatchallDefault {
				out = t
				found = true
			}
			return nil
		})
	})
	if err != nil {
		return ErrorPageTemplate{}, err
	}
	if !found {
		return ErrorPageTemplate{}, ErrNotFound
	}
	return out, nil
}

// DeleteErrorPageTemplate removes a template. Returns ErrNotFound
// if it does not exist.
//
// Note : routes referencing the deleted template will fall back to
// the built-in Arenet default at caddymgr emit time — the ref
// dangles but doesn't break the route. The API layer logs a warning
// when listing routes whose ErrorPageTemplateID points at a missing
// template ; the operator-facing UI can flag them for cleanup.
// Mirror of DeleteRoute.
func (s *Store) DeleteErrorPageTemplate(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("error_template: id must not be empty")
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketErrorTemplates))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}
