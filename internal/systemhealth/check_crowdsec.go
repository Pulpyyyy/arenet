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

package systemhealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CrowdSecConfigReader is the minimal surface CrowdSecCheck
// needs. The wiring file adapts *storage.Store via a thin
// wrapper around GetCrowdSecSettings (returns the bouncer
// LAPI URL + API key, both empty when CrowdSec is
// unconfigured).
type CrowdSecConfigReader interface {
	GetCrowdSecConfig(ctx context.Context) (lapiURL, apiKey string, configured bool, err error)
}

// CrowdSecCheck probes the configured LAPI endpoint at
// /v1/decisions using the bouncer API key. The endpoint +
// auth shape mirror the existing probeCrowdSecLAPI in
// internal/api/crowdsec_settings.go:450-494 (verified
// against live LAPI v1.6.x — accepts X-Api-Key header
// + responds 200/204 on success, 401/403 on bad auth).
//
// Classification per ADR D2:
//   - healthy: LAPI configured + reachable + 2xx response
//   - degraded: LAPI configured but unreachable / auth
//     failed / non-2xx. The bouncer fails open (Caddy data
//     plane keeps serving without the LAPI feed), so the
//     route stays workable — just without fresh decisions.
//   - degraded: LAPI not configured (fresh install / opt-out)
//   - unhealthy: NOT used. CrowdSec is optional in arenet's
//     posture; an unreachable LAPI is a degraded security
//     posture, not an unhealthy system.
type CrowdSecCheck struct {
	Config     CrowdSecConfigReader
	HTTPClient *http.Client
}

// errBadProbeURL marks a LAPI URL that cannot be turned into a request at
// all. Separated from a transport failure because it is not transient:
// retrying a malformed URL just spends the budget twice.
var errBadProbeURL = errors.New("invalid LAPI URL")

// Name implements ComponentCheck.
func (c *CrowdSecCheck) Name() string { return "crowdsec" }

// attempt performs one probe. The caller decides whether to repeat it.
func (c *CrowdSecCheck) attempt(
	ctx context.Context,
	client *http.Client,
	probeURL, apiKey string,
) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return nil, errBadProbeURL
	}
	req.Header.Set("X-Api-Key", apiKey)
	// The operator sees this in `cscli bouncers list`. It is deliberately
	// distinct from the enforcement bouncer's and from the decisions feed's
	// (see internal/crowdsec.LiveSourceConfig.UserAgent) — though all three
	// share one API key, so they share one row there and the most frequent
	// caller wins its Version column. That is a reporting limitation of
	// CrowdSec, not something this check can fix; it is why "Last API pull"
	// on that row says nothing about whether the enforcement bouncer is
	// alive.
	req.Header.Set("User-Agent", "arenet/system-health")
	return client.Do(req)
}

// Check implements ComponentCheck.
func (c *CrowdSecCheck) Check(ctx context.Context) ComponentStatus {
	if c.Config == nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "crowdsec config not wired (degraded mode)",
		}
	}

	lapiURL, apiKey, configured, err := c.Config.GetCrowdSecConfig(ctx)
	if err != nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "crowdsec config read failed",
		}
	}
	if !configured {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "crowdsec not configured (bouncer disabled)",
		}
	}

	probeURL := strings.TrimRight(lapiURL, "/") + "/v1/decisions"

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	// v2.58.3 — try twice before calling the LAPI down.
	//
	// One sample used to decide, with PerCheckTimeout at 2s and no retry,
	// and the alerting rule fires on a single degraded reading. So one slow
	// response — a WireGuard rekey, a packet lost, a LAPI busy syncing
	// decisions — woke the operator with "the LAPI is unreachable, Arenet is
	// fail-open" while the enforcement bouncer was streaming happily. Their
	// logs showed it: the bouncer started at 14:09 and logged nothing, and
	// the alert fired at 15:06.
	//
	// That matters more than the inconvenience. An alert that cries wolf on
	// a security control teaches the operator to ignore it, and then the
	// outage that is real says nothing new.
	//
	// Only a transport failure is retried: an auth rejection or an unexpected
	// status is an answer, and answers are not transient. The retry shares
	// the caller's context, so PerCheckTimeout still bounds the whole check
	// and a genuinely dead LAPI is still reported within it.
	resp, err := c.attempt(ctx, client, probeURL, apiKey)
	if err != nil && !errors.Is(err, context.Canceled) {
		resp, err = c.attempt(ctx, client, probeURL, apiKey)
	}
	if err != nil {
		if errors.Is(err, errBadProbeURL) {
			return ComponentStatus{
				Status:  StatusDegraded,
				Message: "invalid LAPI URL",
			}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return ComponentStatus{
				Status:  StatusDegraded,
				Message: "lapi check timed out twice",
			}
		}
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "lapi unreachable (two attempts)",
		}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusNoContent:
		return ComponentStatus{
			Status:  StatusHealthy,
			Message: "lapi reachable",
		}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "lapi auth failed (invalid bouncer API key)",
		}
	default:
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("lapi unexpected status %d", resp.StatusCode),
		}
	}
}
