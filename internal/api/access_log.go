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
	"io"
	"net/http"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.50 — GET/PUT /settings/access-log.
//
// The setting exists so CrowdSec has something to parse: Arenet emitted
// no access log at all, so an agent beside it enforced the community
// blocklist and detected nothing about this host. See
// docs/superpowers/specs/2026-09-27-access-log-for-crowdsec-design.md.

// accessLogResponse carries the stored config plus what the operator
// cannot work out for themselves.
type accessLogResponse struct {
	storage.AccessLogConfig
	// ResolvedPath is the file that will actually be written, with the
	// per-install default already applied. The operator needs the real
	// path to point CrowdSec at, and it differs between a systemd
	// install (/var/log/arenet) and a container (inside the data
	// volume) — leaving them to guess is how this feature silently
	// never fires.
	ResolvedPath string `json:"resolvedPath"`
	// CeilingMB is the worst case on disk before compression. Returned
	// rather than computed in the UI so one definition of "how big can
	// this get" exists.
	CeilingMB int `json:"ceilingMB"`
}

// AccessLogPathResolver reports where the log would be written for a
// given operator choice, applying the process-level defaults.
//
// An interface so the API does not reach into the Caddy manager's
// configuration: main wires the resolver, exactly as it wires the
// manager's own defaults.
type AccessLogPathResolver interface {
	ResolveAccessLogPath(operatorChoice string) string
}

// SetAccessLogPathResolver wires path resolution; nil answers the stored
// path verbatim, which is what a test without the wiring should see.
func (h *Handler) SetAccessLogPathResolver(r AccessLogPathResolver) { h.accessLogPaths = r }

func (h *Handler) resolveAccessLogPath(cfg storage.AccessLogConfig) string {
	if h.accessLogPaths == nil {
		return cfg.Path
	}
	return h.accessLogPaths.ResolveAccessLogPath(cfg.Path)
}

func (h *Handler) getAccessLogConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetAccessLogConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the access log setting")
		return
	}
	writeJSON(w, http.StatusOK, accessLogResponse{
		AccessLogConfig: cfg,
		ResolvedPath:    h.resolveAccessLogPath(cfg),
		CeilingMB:       cfg.CeilingMB(),
	})
}

func (h *Handler) putAccessLogConfig(w http.ResponseWriter, r *http.Request) {
	var req storage.AccessLogConfig
	dec := json.NewDecoder(io.LimitReader(r.Body, 4096))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}

	previous, _ := h.store.GetAccessLogConfig(r.Context())
	if err := h.store.PutAccessLogConfig(r.Context(), req); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// The log is part of the emitted Caddy config, so it only starts or
	// stops on a reload. A setting saved without one would leave the
	// operator watching a file that never appears.
	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		// Put the previous value back: a stored setting the running
		// config does not reflect is the worst of both.
		if rbErr := h.store.PutAccessLogConfig(r.Context(), previous); rbErr != nil {
			h.logger.Error("access log: could not restore the previous setting after a failed reload", "err", rbErr)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	stored, err := h.store.GetAccessLogConfig(r.Context())
	if err != nil {
		stored = req
	}

	h.appendAudit(r, audit.Event{
		Action: audit.ActionAccessLogUpdated, TargetType: "access_log", TargetID: "config",
		BeforeJSON: mustMarshalForAudit(previous), AfterJSON: mustMarshalForAudit(stored),
	})

	writeJSON(w, http.StatusOK, accessLogResponse{
		AccessLogConfig: stored,
		ResolvedPath:    h.resolveAccessLogPath(stored),
		CeilingMB:       stored.CeilingMB(),
	})
}
