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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// defaultAdminAllowedCIDRs is the admin source allowlist applied when
// ARENET_ADMIN_ALLOWED_CIDRS is unset or empty: every non-Internet range.
// It closes the worst case — an admin port reachable from the Internet
// through a forgotten port forward or a VPS — without locking out any
// homelab path: LAN, SSH tunnel, Docker bridge (traffic from the host to
// a port published on 127.0.0.1 arrives from the network gateway, a
// private address — measured on Docker 29.9 rootful, see
// docs/operations/env-vars.md), Tailscale (CGNAT 100.64.0.0/10) and
// IPv6 ULA / link-local.
//
// It does NOT separate one LAN device from another, nor the host from
// the other containers of a Docker network: they are all private. An
// operator who wants that narrows the list explicitly.
var defaultAdminAllowedCIDRs = []string{
	"127.0.0.0/8",    // IPv4 loopback (SSH tunnel, in-container probe)
	"::1/128",        // IPv6 loopback
	"10.0.0.0/8",     // RFC 1918
	"172.16.0.0/12",  // RFC 1918 (Docker bridge networks live here)
	"192.168.0.0/16", // RFC 1918
	"100.64.0.0/10",  // RFC 6598 shared address space (Tailscale)
	"169.254.0.0/16", // IPv4 link-local
	"fc00::/7",       // IPv6 unique local
	"fe80::/10",      // IPv6 link-local
}

// SourceAllowlist decides which client IPs may reach the admin
// interface. It is read-only after construction, so it is safe for
// concurrent use without locking.
type SourceAllowlist struct {
	cidrs     []*net.IPNet
	defaulted bool
}

// NewSourceAllowlist parses a comma-separated list of CIDRs and bare IPs
// (a bare IP means that single address). An empty or blank list yields
// defaultAdminAllowedCIDRs. "0.0.0.0/0,::/0" opens the admin to every
// source. A malformed entry is an error: the server must refuse to start
// rather than run with an admin surface wider than the operator meant.
func NewSourceAllowlist(list string) (*SourceAllowlist, error) {
	if strings.TrimSpace(list) == "" {
		al, err := parseSourceAllowlist(defaultAdminAllowedCIDRs)
		if err != nil {
			return nil, err
		}
		al.defaulted = true
		return al, nil
	}
	return parseSourceAllowlist(strings.Split(list, ","))
}

func parseSourceAllowlist(entries []string) (*SourceAllowlist, error) {
	al := &SourceAllowlist{}
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ipNet, err := parseCIDROrIP(raw)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid entry in ARENET_ADMIN_ALLOWED_CIDRS: %q", raw)
		}
		al.cidrs = append(al.cidrs, ipNet)
	}
	if len(al.cidrs) == 0 {
		return nil, errors.New("auth: ARENET_ADMIN_ALLOWED_CIDRS has no usable entry")
	}
	return al, nil
}

// parseCIDROrIP accepts "10.0.0.0/8" as well as a bare "192.168.1.50",
// which becomes a /32 (or /128 for IPv6).
func parseCIDROrIP(raw string) (*net.IPNet, error) {
	if _, ipNet, err := net.ParseCIDR(raw); err == nil {
		return ipNet, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("not a CIDR or IP: %q", raw)
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// Allows reports whether ip (a textual address, as produced by
// IPExtractor.ClientIP) is inside the allowlist. An empty or unparsable
// address is refused: fail closed.
func (a *SourceAllowlist) Allows(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range a.cidrs {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// CIDRs returns the effective list in canonical form, for startup logging.
func (a *SourceAllowlist) CIDRs() []string {
	out := make([]string, 0, len(a.cidrs))
	for _, n := range a.cidrs {
		out = append(out, n.String())
	}
	return out
}

// Defaulted reports whether the list is defaultAdminAllowedCIDRs because
// the operator configured nothing.
func (a *SourceAllowlist) Defaulted() bool {
	return a.defaulted
}

// SourceAllowlistMiddleware refuses with 403 any request whose client IP
// is outside the allowlist. It must run AFTER IPExtractMiddleware: it
// judges the resolved client IP, so a request proxied by Arenet's own
// route (loopback, always a trusted proxy) is judged on the real client
// carried in X-Forwarded-For, not on 127.0.0.1.
//
// Paths in exempt bypass the check. /healthz is the one that matters: the
// container healthcheck probes it over loopback, and an operator who
// narrows the list to a single workstation must not turn the container
// unhealthy. It reveals nothing beyond liveness.
//
// Trust caveat: every CIDR in ARENET_TRUSTED_PROXIES may choose the IP
// this middleware sees, by setting X-Forwarded-For. Trusting a whole
// Docker network therefore lets any container on it pass the allowlist.
//
// al must be non-nil; callers that have no allowlist skip the middleware.
func SourceAllowlistMiddleware(al *SourceAllowlist, logger *slog.Logger, exempt ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, p := range exempt {
				if r.URL.Path == p {
					next.ServeHTTP(w, r)
					return
				}
			}
			ip := ClientIPFromContext(r.Context())
			if !al.Allows(ip) {
				logger.Warn("admin: request refused, source not in ARENET_ADMIN_ALLOWED_CIDRS",
					"client_ip", ip,
					"path", r.URL.Path,
				)
				writeForbidden(w, "source address not allowed to reach the admin interface")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
