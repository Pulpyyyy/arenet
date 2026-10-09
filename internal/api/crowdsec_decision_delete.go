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
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// Unban — DELETE /api/v1/security/crowdsec/decisions/{id}
//
// The counterpart of the manual ban (crowdsec_manual_ban.go):
// expires one LAPI decision by its id, the id the Live LAPI
// table already carries (GET /v1/decisions selects the ent
// decision id, crowdsec@v1.6.3 pkg/database/decisions.go:211).
//
// LAPI contract (verified against crowdsec@v1.6.3):
//
//   - Route: DELETE /v1/decisions/:decision_id is mounted in the
//     JWT (machine) group, not the bouncer API-key group —
//     pkg/apiserver/controllers/controller.go:127 (the API-key
//     group, :131-137, only has GET/HEAD on /v1/decisions). So the
//     bouncer key cannot unban; the Security Automation machine
//     credentials can, through the same lapiWithJWT helper as the
//     manual ban.
//   - Handler: pkg/apiserver/controllers/v1/decisions.go:84-113.
//     A non-integer id is a 400 (:87-91); success is 200 with
//     {"nbDeleted":"<n>"} — a STRING (:108-112).
//   - The decision is not removed but expired (until = now):
//     ExpireDecisionByID → ExpireDecisions, pkg/database/
//     decisions.go:648-664 and :585-591. GET /v1/decisions only
//     returns until >= now (:202-203), and the bouncer stream
//     reports decisions expired since its last pull as "deleted"
//     (controllers/v1/decisions.go:286, :357).
//   - An unknown id is NOT a 404 in v1.6.3: ExpireDecisionByID
//     wraps DeleteFail (decisions.go:652-654), which
//     HandleDBErrors maps to its default 500 (controllers/v1/
//     errors.go:36-37). We therefore cannot tell "already gone"
//     from a LAPI failure and answer 502 with LAPI's status; a
//     LAPI that does answer 404 is passed through as 404.

// crowdSecDecisionDeleteResponse is the 200 body of the unban
// endpoint. NbDeleted is LAPI's count, converted to a number.
type crowdSecDecisionDeleteResponse struct {
	ID        int64 `json:"id"`
	NbDeleted int   `json:"nbDeleted"`
}

// deleteCrowdSecDecision serves DELETE
// /api/v1/security/crowdsec/decisions/{id}.
//
// Status codes:
//
//	200 OK — LAPI expired the decision. Body echoes the id and
//	         LAPI's nbDeleted count.
//	400 Bad Request — id is not a positive integer.
//	404 Not Found — LAPI answered 404 for that id.
//	412 Precondition Failed — Security Automation machine
//	                          credentials not configured (same
//	                          contract as the manual ban).
//	502 Bad Gateway — LAPI unreachable, credentials rejected
//	                  after retry, or any other LAPI status
//	                  (v1.6.3 answers 500 for an unknown id).
//	500 Internal Server Error — storage read failed.
func (h *Handler) deleteCrowdSecDecision(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "decision id must be a positive integer")
		return
	}

	creds, credsErr := h.store.GetWatcherCredentials(r.Context())
	if credsErr != nil && !errors.Is(credsErr, storage.ErrNotFound) {
		h.logger.Error("get watcher credentials (decision delete)", "err", credsErr)
		writeError(w, http.StatusInternalServerError, "failed to load automation credentials")
		return
	}
	if errors.Is(credsErr, storage.ErrNotFound) || !storage.WatcherCredentialsConfigured(creds) {
		writeError(w, http.StatusPreconditionFailed,
			"security automation not configured — set machine credentials in Settings → Security Automation to remove decisions (the bouncer key is read-only)")
		return
	}

	timeoutSec := 5
	if cs, err := h.store.GetCrowdSecConfig(r.Context()); err == nil && cs.TimeoutSeconds > 0 {
		timeoutSec = cs.TimeoutSeconds
	}
	timeout := time.Duration(timeoutSec) * time.Second

	body, status, delErr := h.deleteDecisionFromLAPI(r.Context(), creds, timeout, id)
	if delErr != nil {
		switch {
		case errors.Is(delErr, errLAPIAuthRejected):
			writeError(w, http.StatusBadGateway,
				"machine credentials rejected by LAPI — re-verify Settings → Security Automation")
		case status == http.StatusNotFound:
			writeError(w, http.StatusNotFound, "LAPI has no decision with this id (it may have expired already)")
		default:
			writeError(w, http.StatusBadGateway, classifyProbeError(delErr, creds.Password))
		}
		return
	}

	out := crowdSecDecisionDeleteResponse{ID: id}
	var lapiResp struct {
		NbDeleted string `json:"nbDeleted"`
	}
	if len(body) > 0 && json.Unmarshal(body, &lapiResp) == nil {
		// Best effort: LAPI accepted the delete, a missing or
		// odd count must not turn that into an error.
		if n, convErr := strconv.Atoi(lapiResp.NbDeleted); convErr == nil {
			out.NbDeleted = n
		}
	}

	// Audit AFTER LAPI accepts, like the manual ban. The
	// decision's value is not known here (LAPI's delete answer
	// carries only a count), so the target is the LAPI id.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionCrowdSecDecisionDelete,
		TargetType: "crowdsec_decision",
		TargetID:   strconv.FormatInt(id, 10),
		AfterJSON:  mustMarshalForAudit(out),
	})

	writeJSON(w, http.StatusOK, out)
}

// deleteDecisionFromLAPI sends DELETE /v1/decisions/{id} through
// the shared JWT helper, with the manual ban's retry contract: a
// 401 invalidates the cached JWT and retries once; a second 401
// bubbles errLAPIAuthRejected. The returned status is LAPI's
// (0 on a transport error).
func (h *Handler) deleteDecisionFromLAPI(ctx context.Context, creds storage.WatcherCredentials, timeout time.Duration, id int64) ([]byte, int, error) {
	path := "/v1/decisions/" + strconv.FormatInt(id, 10)
	body, status, err := h.lapiWithJWT(ctx, creds, timeout, http.MethodDelete, path, nil, false)
	if errors.Is(err, errLAPIAuthRejected) {
		body, status, err = h.lapiWithJWT(ctx, creds, timeout, http.MethodDelete, path, nil, true)
	}
	return body, status, err
}
