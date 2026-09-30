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
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/barto95100/arenet/internal/audit"
)

// v2.56 — where a diagnostic probe may not go.
//
// Arenet's admin API has two endpoints that fetch a URL on the operator's
// behalf: the upstream Test button, and the health-check Test button. Both
// take their target from the request, which is correct — the operator is
// testing an address they are about to save — and it makes the admin API a
// way to reach anything the Arenet host can reach.
//
// A homelab reverse proxy must keep reaching private space: 10/8, 172.16/12,
// 192.168/16 and loopback are where the upstreams actually are. What it has
// no business fetching is the link-local range, because that is where cloud
// instance metadata lives (169.254.169.254 on every major provider, and
// fd00:ec2::254 on AWS over IPv6). Those endpoints hand out instance
// credentials to whoever asks from the instance.
//
// The check runs AFTER name resolution, on the IP actually being dialled,
// and it runs per connection attempt. A pre-flight lookup would be a
// different thing: the name could resolve to a harmless address for the
// check and to 169.254.169.254 for the connection that follows (DNS
// rebinding), and a name with several A records would only have its first
// one inspected. net.Dialer.Control is called once per candidate address
// with the resolved host:port, which is exactly the right seam — it also
// covers any redirect a probe follows, since each hop dials again.

// errBlockedProbeTarget is returned when a probe resolves to an address it
// may not reach. Wrapped rather than formatted so a caller can recognise
// it with errors.Is and say something better than "dial failed".
var errBlockedProbeTarget = errors.New("probe target is not allowed")

// blockedProbeAuditMarker is the substring a humanised probe error keeps
// from errBlockedProbeTarget, used to tell a refusal apart from an
// ordinary dial failure when choosing the audit action.
const blockedProbeAuditMarker = "not allowed"

// metadataIPv6 is AWS's IMDS address over IPv6. The IPv4 one
// (169.254.169.254) needs no entry of its own: it already sits inside the
// link-local range below.
var metadataIPv6 = net.ParseIP("fd00:ec2::254")

// probeTargetBlocked reports whether an IP is one a diagnostic probe must
// not connect to, and why.
//
// Private ranges and loopback are deliberately allowed: refusing them
// would break the feature for every homelab, where the upstream IS a
// private address.
func probeTargetBlocked(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "address could not be parsed"
	}
	// Covers 169.254.0.0/16 and fe80::/10, so the IPv4 metadata address
	// is already refused here.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, "link-local address (cloud instance metadata lives there)"
	}
	if ip.Equal(metadataIPv6) {
		return true, "cloud instance metadata address"
	}
	return false, ""
}

// newProbeDialer returns a dialer that refuses the addresses above.
//
// Control is called after resolution with the address about to be dialled,
// once per candidate, so a name resolving to several addresses has each of
// them checked and a rebound name cannot slip a second lookup past us.
func newProbeDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				// Control always receives host:port; a parse failure here
				// means something changed underneath us, so refuse rather
				// than connect to an address we did not inspect.
				return fmt.Errorf("%w: %q could not be read", errBlockedProbeTarget, address)
			}
			if blocked, why := probeTargetBlocked(net.ParseIP(host)); blocked {
				return fmt.Errorf("%w: %s is a %s", errBlockedProbeTarget, host, why)
			}
			return nil
		},
	}
}

// probeAuditAction picks the audit action for a finished probe: the
// refusal gets its own, so an attempt at a blocked address is searchable
// rather than buried among ordinary failures.
func probeAuditAction(probeErr string) string {
	if strings.Contains(probeErr, blockedProbeAuditMarker) {
		return audit.ActionProbeRefused
	}
	return audit.ActionProbeUpstream
}

// probeAuditMessage records what was asked and what came back. The URL is
// Redacted() so a userinfo-bearing upstream does not put a password in the
// trail.
func probeAuditMessage(target *url.URL, reachable bool, status int, probeErr string) string {
	if probeErr != "" {
		return fmt.Sprintf("target=%s refused=%s", target.Redacted(), truncate(probeErr, 200))
	}
	return fmt.Sprintf("target=%s reachable=%t status=%d", target.Redacted(), reachable, status)
}
