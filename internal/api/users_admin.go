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
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/apierr"
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
)

// Step K.2 — admin Users management.
//
// Endpoints (hard-auth + admin role required):
//   - GET  /api/v1/admin/users               — list users
//   - POST /api/v1/admin/users/{id}/role     — elevate/demote
//
// PasswordHash + OIDCSub are NEVER on the wire: the response
// surface omits PasswordHash and surfaces OIDCSub only as a
// boolean indicator ("oidcLinked") rather than the raw value
// (the sub is operational metadata for the storage layer; the
// admin UI doesn't need it).

type adminUserResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	// Email surfaced for the users-page Phase 1 contact
	// column. Empty for legacy local users (pre-Phase-1)
	// or OIDC users whose IdP didn't emit the claim. The
	// frontend renders "—" in the empty case.
	Email       string `json:"email,omitempty"`
	AuthSource  string `json:"authSource"`
	OIDCLinked  bool   `json:"oidcLinked"`
	Role        string `json:"role"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
	LastLoginAt string `json:"lastLoginAt,omitempty"`
	// LastActivityAt + ActiveSessionCount power the users-
	// page "online / active / offline" indicator. Sourced
	// from SessionStore.ListAllActive — LastActivityAt is
	// the freshest Touch across the user's live sessions;
	// ActiveSessionCount counts non-expired sessions.
	// Absent when the user has no live sessions (they are
	// "offline").
	LastActivityAt     string `json:"lastActivityAt,omitempty"`
	ActiveSessionCount int    `json:"activeSessionCount"`
}

// adminUserToResponse builds the wire response. `activity`
// is the user's entry from SessionStore.ListAllActive
// (zero-value when the user has no live sessions, which
// the frontend renders as "offline").
func adminUserToResponse(u auth.User, activity auth.UserActivity) adminUserResponse {
	out := adminUserResponse{
		ID:                 u.ID,
		Username:           u.Username,
		DisplayName:        u.DisplayName,
		Email:              u.Email,
		AuthSource:         u.AuthSource,
		OIDCLinked:         u.OIDCSub != "",
		Role:               u.Role,
		CreatedAt:          u.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:          u.UpdatedAt.UTC().Format(timestampFormat),
		ActiveSessionCount: activity.ActiveCount,
	}
	if !u.LastLoginAt.IsZero() {
		out.LastLoginAt = u.LastLoginAt.UTC().Format(timestampFormat)
	}
	if !activity.LastActivity.IsZero() {
		out.LastActivityAt = activity.LastActivity.UTC().Format(timestampFormat)
	}
	return out
}

func (h *Handler) listAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.users.List(r.Context())
	if err != nil {
		h.logger.Error("admin: list users", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list users")
		return
	}
	// Best-effort: a failure to enumerate live sessions
	// degrades the per-row activity indicator to "no live
	// session" rather than 5xx-ing the whole list. The
	// users-page reads the field as advisory only — actual
	// auth still goes through the session cookie.
	activity, actErr := h.sessions.ListAllActive(r.Context())
	if actErr != nil {
		h.logger.Warn("admin: list active sessions failed; users page activity indicator degraded",
			"err", actErr)
		activity = nil
	}
	out := make([]adminUserResponse, 0, len(users))
	for _, u := range users {
		out = append(out, adminUserToResponse(u, activity[u.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

type updateUserRoleRequest struct {
	Role string `json:"role"`
}

// updateUserRole is POST /api/v1/admin/users/{id}/role. Elevates
// or demotes another user's role (Step K.2 §1.3 #12). Last-admin
// guards fire when demoting the last LOCAL admin (the break-
// glass channel) or the last human admin of any source. The
// acting user can demote themselves IF another local admin
// exists.
func (h *Handler) updateUserRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req updateUserRoleRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	req.Role = strings.TrimSpace(req.Role)
	if req.Role != auth.UserRoleViewer && req.Role != auth.UserRoleAdmin {
		writeError(w, http.StatusBadRequest, "role must be \"viewer\" or \"admin\"")
		return
	}

	previous, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("admin: get user for role update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	if err := h.users.UpdateRole(r.Context(), id, req.Role); err != nil {
		// Last-admin guards fire here.
		writeAdminRemovalError(w, err)
		return
	}

	updated, _ := h.users.GetByID(r.Context(), id)

	// Activity snapshot for the response + audit. Mirrors
	// listAdminUsers — read once, fall back to zero-value
	// if the session store is degraded (audit row still
	// captures the user delta; only the activity counters
	// stay zero).
	activity, _ := h.sessions.ListAllActive(r.Context())

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionUserRoleChanged,
		TargetType: "user",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(adminUserToResponse(previous, activity[previous.ID])),
		AfterJSON:  mustMarshalForAudit(adminUserToResponse(updated, activity[updated.ID])),
	})

	writeJSON(w, http.StatusOK, adminUserToResponse(updated, activity[updated.ID]))
}

// deleteAdminUser handles DELETE /api/v1/admin/users/{id}.
//
// Users-page Phase 1: removes a user account. Last-admin
// guard fires inside UserStore.Delete — the only LOCAL admin
// cannot be deleted (the break-glass channel must remain
// reachable per §1.3 decisions 4-6).
//
// Cascade: every live session for the deleted user is
// purged via SessionStore.DeleteAllForUser. The deleted
// user's cookie immediately resolves to "not authenticated"
// on the next request — they're logged out across all
// devices.
//
// Self-delete: NOT enforced at the handler level. The
// frontend hides the Delete button on the acting user's
// own row as a UX guard, but the backend last-admin guard
// is the authoritative protection. An admin who deletes
// themselves while another local admin exists is a legal
// (if surprising) operation — they immediately become
// "not authenticated" and the other local admin keeps
// admin access.
//
// Audit: emits ActionUserDeleted with BeforeJSON containing
// the deleted user's wire response. AfterJSON is empty
// (the row no longer exists).
func (h *Handler) deleteAdminUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	previous, err := h.users.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "user not found")
			return
		}
		h.logger.Error("admin: get user for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	// Snapshot activity BEFORE delete so the audit row
	// captures the user's live state at the moment of
	// removal (informational — useful when investigating
	// "did this user have an active session when they were
	// deleted?").
	activity, _ := h.sessions.ListAllActive(r.Context())

	if err := h.users.Delete(r.Context(), id); err != nil {
		// Last-admin guards fire here. Same shape as
		// updateUserRole's demote path.
		writeAdminRemovalError(w, err)
		return
	}

	// Purge live sessions. Best-effort: a failure here
	// means the deleted user's existing cookie may resolve
	// for up to the session's idle window before being
	// invalidated by the next bucket scan — but the user
	// record is gone, so the middleware's user lookup
	// fails on the next hit anyway. Log the failure and
	// continue.
	if _, sessErr := h.sessions.DeleteAllForUser(r.Context(), id); sessErr != nil {
		h.logger.Warn("admin: failed to purge sessions for deleted user; cookies will lazily fail middleware lookup",
			"err", sessErr, "user_id", id)
	}

	h.appendAudit(r, audit.Event{
		Action:     audit.ActionUserDeleted,
		TargetType: "user",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(adminUserToResponse(previous, activity[id])),
	})

	w.WriteHeader(http.StatusNoContent)
}

// writeAdminRemovalError maps a refusal from UserStore.UpdateRole or
// UserStore.Delete to its HTTP response. The two last-admin guards
// carry a code so the UI can say them in the operator's language;
// both stay 400, the status the break-glass refusal has always had.
// Anything else keeps the pre-existing 400 + raw message shape.
func writeAdminRemovalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrUserNotFound):
		writeError(w, http.StatusNotFound, "user not found")
	case errors.Is(err, auth.ErrLastLocalAdmin):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_last_local_admin", nil, "%s", err))
	case errors.Is(err, auth.ErrLastAdmin):
		writeErrorFrom(w, http.StatusBadRequest,
			apierr.New("user_last_admin", nil, "%s", err))
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}
