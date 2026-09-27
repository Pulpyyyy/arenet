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
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// v2.42 — TCP services (layer 4). A service relays raw TCP from a
// listening port to one or more backends, without reading the bytes:
// Arenet never terminates TLS here, so the client and the backend
// negotiate end to end. See
// docs/superpowers/specs/2026-09-23-l4-services-design.md.
//
// The type is deliberately NOT a field of Route: a route is an HTTP
// host with a WAF, path rules and error pages, none of which exist at
// layer 4.
//
// Field set follows what caddy-l4 actually accepts, checked against
// the module rather than assumed:
//   - selection policies are round_robin / least_conn / ip_hash /
//     first / random (modules/l4proxy/loadbalancing.go) — there is no
//     weighted policy, and an upstream carries no weight, so neither
//     does TCPUpstream;
//   - an upstream carries dial, tls and max_connections
//     (modules/l4proxy/upstream.go);
//   - the proxy handler accepts proxy_protocol "v1" or "v2" and
//     rejects anything else (modules/l4proxy/proxy.go:82).

// bucketTCPServices holds one row per service, keyed by id. The
// bucket is created empty: an installation without a TCP service
// emits exactly the Caddy config it emitted before.
const bucketTCPServices = "tcp_services"

// TCP service load-balancing policies, mirroring caddy-l4's
// layer4.proxy.selection_policies.* module IDs.
const (
	TCPLBRoundRobin = "round_robin"
	TCPLBLeastConn  = "least_conn"
	TCPLBIPHash     = "ip_hash"
	TCPLBFirst      = "first"
	TCPLBRandom     = "random"
)

// Transport protocols a service can relay. caddy-l4 addresses carry
// the network as a prefix ("tcp/host:port", "udp/host:port"), which
// is how this reaches the emitted config.
const (
	TCPServiceProtocolTCP = "tcp"
	TCPServiceProtocolUDP = "udp"
)

// PROXY protocol versions a service may prepend to the backend
// connection. Empty means the header is not sent at all.
const (
	ProxyProtocolOff = ""
	ProxyProtocolV1  = "v1"
	ProxyProtocolV2  = "v2"
)

// Application protocols a relay can be told to accept (v2.49). Each
// value is a caddy-l4 matcher module name, so it goes into the emitted
// config verbatim — the set was taken from the module IDs registered by
// caddy-l4 v0.1.1, not from the protocols one might expect.
const (
	AcceptProtocolAny       = ""
	AcceptProtocolTLS       = "tls"
	AcceptProtocolSSH       = "ssh"
	AcceptProtocolHTTP      = "http"
	AcceptProtocolPostgres  = "postgres"
	AcceptProtocolRDP       = "rdp"
	AcceptProtocolXMPP      = "xmpp"
	AcceptProtocolWinbox    = "winbox"
	AcceptProtocolDNS       = "dns"
	AcceptProtocolWireGuard = "wireguard"
	AcceptProtocolOpenVPN   = "openvpn"
)

// acceptProtocolTransports says which transports each protocol may be
// offered on. Read the two kinds of claim here separately, because they
// rest on different evidence.
//
// What the CODE proves (caddy-l4 v0.1.1, read 2026-09-27):
//   - only `quic` gates on transport at all, refusing any non-UDP local
//     address outright (modules/l4quic/matcher.go:84);
//   - `dns` and `openvpn` are genuinely dual, with explicit branches
//     keyed on *net.TCPAddr (modules/l4dns/matcher.go:74,
//     modules/l4openvpn/matcher.go:201) — the TCP wire format carries a
//     2-byte length prefix the UDP one does not;
//   - every other matcher has NO transport check whatsoever and runs
//     identically on either. So the source does NOT establish that they
//     are TCP-only.
//
// What the PROTOCOLS decide: SSH, PostgreSQL, RDP, XMPP, SOCKS, Winbox
// and cleartext HTTP/1.x are TCP protocols, and the TLS matcher parses
// TLS-over-TCP record framing rather than DTLS. WireGuard is UDP. There
// is no point offering a combination whose matcher can run but can
// never see the traffic it is looking for — that is not advice to the
// operator, it is not offering something broken.
//
// Why this matters more than a cosmetic UI restriction: a refusal is
// emitted as not(<matcher>), so a matcher that can never match refuses
// EVERY connection. A wrong entry here does not degrade a relay, it
// kills it.
//
// `socks4` and `socks5` are absent for a different reason: the matcher
// is trivial, but its Go package cannot be imported without pulling in a
// full SOCKS5 server library that Arenet would never run. The project is
// conservative with dependencies, and a homelab reverse proxy rarely
// relays SOCKS.
//
// `quic` is deliberately absent. It is UDP-only and correctly gated,
// but in its bare form it sets no ALPN, and quic-go documents that the
// TLS config must define an application protocol — its upstream tests
// only pass under a fake packet conn. An unverified matcher, combined
// with the not() inversion above, risks a relay that refuses
// everything. It goes in when a live probe says it works.
var acceptProtocolTransports = map[string][]string{
	AcceptProtocolTLS:       {TCPServiceProtocolTCP},
	AcceptProtocolSSH:       {TCPServiceProtocolTCP},
	AcceptProtocolHTTP:      {TCPServiceProtocolTCP},
	AcceptProtocolPostgres:  {TCPServiceProtocolTCP},
	AcceptProtocolRDP:       {TCPServiceProtocolTCP},
	AcceptProtocolXMPP:      {TCPServiceProtocolTCP},
	AcceptProtocolWinbox:    {TCPServiceProtocolTCP},
	AcceptProtocolWireGuard: {TCPServiceProtocolUDP},
	AcceptProtocolDNS:       {TCPServiceProtocolTCP, TCPServiceProtocolUDP},
	AcceptProtocolOpenVPN:   {TCPServiceProtocolTCP, TCPServiceProtocolUDP},
}

// AcceptProtocolsFor lists the protocols a relay on this transport may
// be told to accept, so the UI offers exactly what can work. Sorted, so
// the order is the same on every call and in every test.
func AcceptProtocolsFor(transport string) []string {
	if transport != TCPServiceProtocolUDP {
		transport = TCPServiceProtocolTCP
	}
	out := make([]string, 0, len(acceptProtocolTransports))
	for proto, transports := range acceptProtocolTransports {
		if slices.Contains(transports, transport) {
			out = append(out, proto)
		}
	}
	slices.Sort(out)
	return out
}

// tcpLBPolicies is the set accepted by Validate.
var tcpLBPolicies = map[string]struct{}{
	TCPLBRoundRobin: {},
	TCPLBLeastConn:  {},
	TCPLBIPHash:     {},
	TCPLBFirst:      {},
	TCPLBRandom:     {},
}

// TCPUpstream is one backend of a TCP service.
type TCPUpstream struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// MaxConnections caps simultaneous connections to THIS backend.
	// 0 = unlimited.
	MaxConnections int `json:"maxConnections,omitempty"`
}

// Dial renders the upstream as caddy-l4 expects it in `dial`.
func (u TCPUpstream) Dial() string {
	return net.JoinHostPort(u.Host, fmt.Sprint(u.Port))
}

// TCPHealthCheck is the active health check: caddy-l4 dials the
// backend on the service's port and marks it down when the dial
// fails. There is no request to send at layer 4 — connecting IS the
// check.
type TCPHealthCheck struct {
	Enabled  bool   `json:"enabled"`
	Interval string `json:"interval,omitempty"` // Go duration, default 30s
	Timeout  string `json:"timeout,omitempty"`  // Go duration, default 5s
}

// TCPService is a layer-4 relay: one listening port, one or more
// backends, and the gates that apply before the bytes flow.
type TCPService struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	// ListenAddr is the interface to listen on. Empty means every
	// interface; it is stored explicitly rather than defaulted at
	// emission time so the operator sees what they exposed.
	ListenAddr string `json:"listenAddr,omitempty"`
	ListenPort int    `json:"listenPort"`

	// Protocol is "tcp" (the default, and what an empty value means)
	// or "udp". UDP is what WireGuard, DNS, syslog and most game
	// servers need; a layer-4 relay that only did TCP would not be
	// one.
	Protocol string `json:"protocol,omitempty"`

	Upstreams []TCPUpstream `json:"upstreams"`
	LBPolicy  string        `json:"lbPolicy,omitempty"`

	HealthCheck *TCPHealthCheck `json:"healthCheck,omitempty"`

	// ProxyProtocol prepends the PROXY header so the backend sees the
	// real client IP. The backend must be configured to expect it —
	// a mismatch breaks connections silently, which is why the UI
	// pairs the two.
	ProxyProtocol string `json:"proxyProtocol,omitempty"`

	// AcceptProtocol (v2.49) is the application protocol the relay
	// accepts at the handshake — a layer4.matchers.<name> module.
	// Empty accepts anything, which is the pre-v2.49 behaviour; a
	// connection whose handshake is not that protocol is closed and
	// counted under cause "protocol".
	//
	// Named AcceptProtocol and not Protocol because Protocol above is
	// the TRANSPORT (tcp / udp). Two different axes, and names that
	// would otherwise be one letter apart.
	//
	// This is hardening, not a hole being closed: a correct backend
	// already rejects garbage. What it buys is that garbage never
	// reaches the backend, and that a repeated mismatch is countable.
	AcceptProtocol string `json:"acceptProtocol,omitempty"`

	// IPFilter is the same source-IP gate the HTTP routes use; at
	// layer 4 it is enforced by layer4.matchers.remote_ip — the
	// emitter's l4MatcherRemoteIP. (It said `layer4.matchers.ip`
	// until v2.49; no such module exists in caddy-l4.)
	IPFilter *IPFilter `json:"ipFilter,omitempty"`

	// CrowdSecEnabled applies the instance's CrowdSec decisions to
	// this service (layer4.matchers.crowdsec). Meaningless when the
	// bouncer is not configured; emission skips it in that case.
	CrowdSecEnabled bool `json:"crowdSecEnabled,omitempty"`

	Disabled bool `json:"disabled,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Network returns the transport to use, resolving the empty default.
func (s TCPService) Network() string {
	if s.Protocol == TCPServiceProtocolUDP {
		return TCPServiceProtocolUDP
	}
	return TCPServiceProtocolTCP
}

// ListenHostPort renders the listen address without its network.
func (s TCPService) ListenHostPort() string {
	addr := s.ListenAddr
	if addr == "" {
		addr = "0.0.0.0"
	}
	return net.JoinHostPort(addr, fmt.Sprint(s.ListenPort))
}

// ListenAddress renders the listen address as caddy-l4 expects it,
// network prefix included.
func (s TCPService) ListenAddress() string {
	return s.Network() + "/" + s.ListenHostPort()
}

// DialAddress renders a backend as caddy-l4 expects it: the relay's
// network followed by the address.
func (s TCPService) DialAddress(u TCPUpstream) string {
	return s.Network() + "/" + u.Dial()
}

// Validate enforces the invariants of a TCP service. Returns the
// first violation found.
func (s *TCPService) Validate() error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return errors.New("tcp service: name must not be empty")
	}
	if len(s.Name) > 64 {
		return errors.New("tcp service: name must be 64 characters or fewer")
	}

	s.ListenAddr = strings.TrimSpace(s.ListenAddr)
	if s.ListenAddr != "" && net.ParseIP(s.ListenAddr) == nil {
		return fmt.Errorf("tcp service: listen_addr %q is not an IP address", s.ListenAddr)
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return fmt.Errorf("tcp service: listen_port %d out of range 1-65535", s.ListenPort)
	}

	switch s.Protocol {
	case "", TCPServiceProtocolTCP, TCPServiceProtocolUDP:
	default:
		return fmt.Errorf("tcp service: protocol %q must be %q or %q",
			s.Protocol, TCPServiceProtocolTCP, TCPServiceProtocolUDP)
	}

	if s.AcceptProtocol != AcceptProtocolAny {
		transports, known := acceptProtocolTransports[s.AcceptProtocol]
		if !known {
			return fmt.Errorf("tcp service: accept_protocol %q is not supported", s.AcceptProtocol)
		}
		// Refused rather than silently ignored: the gate is emitted as
		// not(<matcher>), so a protocol whose matcher cannot see this
		// transport's traffic would refuse every connection.
		if !slices.Contains(transports, s.Network()) {
			return fmt.Errorf("tcp service: accept_protocol %q does not apply to %s",
				s.AcceptProtocol, s.Network())
		}
	}

	if len(s.Upstreams) == 0 {
		return errors.New("tcp service: at least one backend is required")
	}
	seen := make(map[string]struct{}, len(s.Upstreams))
	for i := range s.Upstreams {
		u := &s.Upstreams[i]
		u.Host = strings.TrimSpace(u.Host)
		if u.Host == "" {
			return fmt.Errorf("tcp service: backend %d: host must not be empty", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("tcp service: backend %d: port %d out of range 1-65535", i+1, u.Port)
		}
		if u.MaxConnections < 0 {
			return fmt.Errorf("tcp service: backend %d: max_connections must be >= 0", i+1)
		}
		dial := u.Dial()
		if _, dup := seen[dial]; dup {
			return fmt.Errorf("tcp service: backend %s listed twice", dial)
		}
		seen[dial] = struct{}{}
	}

	if s.LBPolicy != "" {
		if _, ok := tcpLBPolicies[s.LBPolicy]; !ok {
			return fmt.Errorf("tcp service: lb_policy %q is not supported", s.LBPolicy)
		}
	}

	switch s.ProxyProtocol {
	case ProxyProtocolOff, ProxyProtocolV1, ProxyProtocolV2:
	default:
		return fmt.Errorf("tcp service: proxy_protocol %q must be empty, %q or %q",
			s.ProxyProtocol, ProxyProtocolV1, ProxyProtocolV2)
	}
	// Version 1 of the PROXY protocol has no UDP address family
	// (modules/l4proxy/proxy.go:318 — "only v2 supports UDP
	// addresses"), so the pair is refused here rather than producing
	// a relay whose header the backend cannot read.
	if s.Network() == TCPServiceProtocolUDP && s.ProxyProtocol == ProxyProtocolV1 {
		return errors.New("tcp service: the PROXY protocol v1 carries no UDP address; use v2 or none")
	}

	if hc := s.HealthCheck; hc != nil && hc.Enabled {
		// A UDP "connection" is a local socket: dialing one always
		// succeeds, so an active check would report every backend
		// healthy for ever. Refusing is more honest than emitting a
		// check that cannot fail.
		if s.Network() == TCPServiceProtocolUDP {
			return errors.New("tcp service: an active health check needs a real connection; UDP has none")
		}
		if err := validateOptionalDuration("health_check.interval", hc.Interval); err != nil {
			return err
		}
		if err := validateOptionalDuration("health_check.timeout", hc.Timeout); err != nil {
			return err
		}
	}

	if s.IPFilter != nil {
		if err := s.IPFilter.Validate(); err != nil {
			return fmt.Errorf("tcp service: %w", err)
		}
	}
	return nil
}

// validateOptionalDuration accepts an empty string (the emitter's
// default applies) or a positive Go duration.
func validateOptionalDuration(field, value string) error {
	if value == "" {
		return nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("tcp service: %s %q is not a duration", field, value)
	}
	if d <= 0 {
		return fmt.Errorf("tcp service: %s must be > 0", field)
	}
	return nil
}

// CreateTCPService persists a new service. ID, CreatedAt and UpdatedAt
// are assigned by the store and the populated service is returned.
func (s *Store) CreateTCPService(ctx context.Context, svc TCPService) (TCPService, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := svc.Validate(); err != nil {
		return TCPService{}, err
	}

	now := time.Now().UTC()
	svc.ID = uuid.NewString()
	svc.CreatedAt = now
	svc.UpdatedAt = now

	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		buf, err := s.encodeRow(bucketTCPServices, svc)
		if err != nil {
			return fmt.Errorf("marshal tcp service: %w", err)
		}
		return tx.Bucket([]byte(bucketTCPServices)).Put([]byte(svc.ID), buf)
	}); err != nil {
		return TCPService{}, err
	}
	return svc, nil
}

// GetTCPService returns the service identified by id, or ErrNotFound.
func (s *Store) GetTCPService(ctx context.Context, id string) (TCPService, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return TCPService{}, errors.New("tcp service: id must not be empty")
	}

	var out TCPService
	if err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketTCPServices)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return s.decodeRow(bucketTCPServices, raw, &out)
	}); err != nil {
		return TCPService{}, err
	}
	return out, nil
}

// ListTCPServices returns every stored service, ordered by name so the
// UI and the emitted Caddy config are stable across calls.
func (s *Store) ListTCPServices(ctx context.Context) ([]TCPService, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	out := make([]TCPService, 0)
	if err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketTCPServices)).ForEach(func(_, v []byte) error {
			var svc TCPService
			if err := s.decodeRow(bucketTCPServices, v, &svc); err != nil {
				return fmt.Errorf("unmarshal tcp service: %w", err)
			}
			out = append(out, svc)
			return nil
		})
	}); err != nil {
		return nil, err
	}
	sortTCPServices(out)
	return out, nil
}

// UpdateTCPService replaces an existing service, preserving CreatedAt.
func (s *Store) UpdateTCPService(ctx context.Context, svc TCPService) (TCPService, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if svc.ID == "" {
		return TCPService{}, errors.New("tcp service: id must not be empty")
	}
	if err := svc.Validate(); err != nil {
		return TCPService{}, err
	}

	svc.UpdatedAt = time.Now().UTC()
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketTCPServices))
		raw := b.Get([]byte(svc.ID))
		if raw == nil {
			return ErrNotFound
		}
		var existing TCPService
		if err := s.decodeRow(bucketTCPServices, raw, &existing); err != nil {
			return fmt.Errorf("unmarshal tcp service: %w", err)
		}
		svc.CreatedAt = existing.CreatedAt
		buf, err := s.encodeRow(bucketTCPServices, svc)
		if err != nil {
			return fmt.Errorf("marshal tcp service: %w", err)
		}
		return b.Put([]byte(svc.ID), buf)
	}); err != nil {
		return TCPService{}, err
	}
	return svc, nil
}

// DeleteTCPService removes a service, or returns ErrNotFound.
func (s *Store) DeleteTCPService(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("tcp service: id must not be empty")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketTCPServices))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

// sortTCPServices orders by name, then by id to break ties — the
// emitted config must not depend on BoltDB's iteration order.
func sortTCPServices(list []TCPService) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}
