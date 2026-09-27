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

package caddymgr

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/barto95100/arenet/internal/apierr"
	"github.com/barto95100/arenet/internal/l4metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.42 — emission of the Caddy `layer4` app for TCP services.
//
// Shape (verified against caddy-l4 v0.1.1, not assumed):
//
//	"layer4": {"servers": {"svc_<id>": {
//	    "listen": ["tcp/0.0.0.0:993"],
//	    "routes": [{"match": [...], "handle": [...]}]
//	}}}
//
// Module IDs used, all present in v0.1.1:
//   - layer4.matchers.remote_ip   (field "ranges", CIDR or bare IP)
//   - layer4.matchers.crowdsec    (from the bouncer we already embed)
//   - layer4.handlers.proxy       ("upstreams[].dial" is a LIST)
//   - layer4.handlers.close       (refuse without lingering)
//
// The 2023 snapshot that used to be pulled indirectly had neither
// `close` nor `not`, which is why the dependency is now pinned
// explicitly at v0.1.1 — and at v0.1.1 rather than v0.1.2, because
// v0.1.2 drags quic-go from 0.59.1 to 0.60.0 and we are not changing
// the HTTP/3 stack to add a TCP relay.
//
// Ordering matters and is deliberate: within a server the first route
// whose matchers accept the connection handles it, and a connection
// that matches nothing is dropped by caddy-l4's terminal nop handler.
// We never rely on that implicit drop for a refusal we decided — a
// refusal is an explicit `close` route, so the emitted config reads
// the way the operator's intent reads.

const (
	l4MatcherRemoteIP = "remote_ip"
	l4MatcherCrowdSec = "crowdsec"
	// l4MatcherNot negates the matcher sets it carries. Its JSON is a
	// LIST of matcher sets, not an object — it unmarshals straight into
	// []caddy.ModuleMap (layer4/matchers.go:320-323).
	l4MatcherNot   = "not"
	l4HandlerProxy = "proxy"
	l4HandlerClose = "close"
)

// buildLayer4App returns the `layer4` app block, or nil when there is
// nothing to serve. Returning nil is what keeps a config emitted by an
// installation without TCP services byte-identical to the pre-v2.42
// one: the caller only inserts the key when this is non-nil.
//
// crowdSecAvailable mirrors the HTTP side: the per-service CrowdSec
// flag is only honoured when the instance actually has a bouncer
// configured, otherwise the matcher would reference an app that is
// not in the config.
func buildLayer4App(services []storage.TCPService, crowdSecAvailable bool) map[string]any {
	servers := make(map[string]any)
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		servers[l4ServerName(svc)] = map[string]any{
			// The network is part of the address in caddy-l4, which
			// is how a UDP relay is expressed.
			"listen": []string{svc.ListenAddress()},
			"routes": buildLayer4Routes(svc, crowdSecAvailable),
		}
	}
	if len(servers) == 0 {
		return nil
	}
	return map[string]any{"servers": servers}
}

// l4ServerName gives each service its own layer4 server (spec L10):
// one bad service fails to provision on its own instead of taking the
// whole app — and with it every other service — down.
func l4ServerName(svc storage.TCPService) string {
	return "svc_" + svc.ID
}

// buildLayer4Routes renders one refusal route per gate, then the relay.
//
// v2.49 — the gates used to be expressed the other way round: the
// conditions a connection had to SATISFY were collected into the relay
// route's single match object, and anything that failed any of them fell
// through to one shared `close`. That config was correct and told the
// operator nothing. A refused connection never reaches the relay chain,
// so it never reached the metrics handler either, and CrowdSec, the IP
// filter and now the protocol check were indistinguishable from each
// other — and from a relay whose protection was simply switched off.
//
// Each gate now owns a route that matches what it REJECTS, counts the
// refusal under its own cause, and closes. The relay is then
// unconditional: everything that survived the gates above belongs to it.
// Behaviour is unchanged — the same connections are refused — but the
// operator can finally see which gate did it.
//
// Ordering is the order a connection meets them, cheapest first: the
// address gates decide from the socket alone, CrowdSec needs a store
// lookup, and the protocol matcher has to read the handshake.
func buildLayer4Routes(svc storage.TCPService, crowdSecAvailable bool) []map[string]any {
	routes := make([]map[string]any, 0, 5)

	if f := svc.IPFilter; f != nil && len(f.CIDRs) > 0 {
		switch f.Mode {
		case storage.IPFilterModeDeny:
			// Listed sources are refused.
			routes = append(routes, l4RefusalRoute(svc.ID, l4metrics.CauseIPFilter,
				map[string]any{l4MatcherRemoteIP: map[string]any{"ranges": f.CIDRs}}))
		case storage.IPFilterModeAllow:
			// Everything NOT listed is refused. Fail-closed, as before.
			routes = append(routes, l4RefusalRoute(svc.ID, l4metrics.CauseIPFilter,
				l4Not(map[string]any{l4MatcherRemoteIP: map[string]any{"ranges": f.CIDRs}})))
		}
	}

	if crowdSecAvailable && svc.CrowdSecEnabled {
		// The matcher takes no options; an empty object is how a Caddy
		// matcher with no configuration is written. Negated, it matches
		// exactly the connections the bouncer refuses.
		//
		// Fail-open is preserved and comes from the bouncer, not from
		// here: with enable_hard_fails false its core returns "no
		// decision" when LAPI is unreachable, so the matcher says
		// allowed, the negation does not match, and the connection
		// reaches the relay.
		routes = append(routes, l4RefusalRoute(svc.ID, l4metrics.CauseCrowdSec,
			l4Not(map[string]any{l4MatcherCrowdSec: map[string]any{}})))
	}

	if p := svc.AcceptProtocol; p != storage.AcceptProtocolAny {
		// Anything whose handshake is not that protocol is refused.
		routes = append(routes, l4RefusalRoute(svc.ID, l4metrics.CauseProtocol,
			l4Not(l4ProtocolMatcher(p))))
	}

	// The relay, for everything the gates above let through. The metrics
	// handler goes FIRST in the chain: it wraps the connection so
	// everything the proxy then reads and writes is counted. It never
	// refuses a connection — a relay that stopped relaying because of a
	// counter would be a poor trade.
	routes = append(routes, map[string]any{"handle": []map[string]any{
		{"handler": l4metrics.HandlerName, "service_id": svc.ID},
		buildLayer4Proxy(svc),
	}})
	return routes
}

// l4Not wraps matchers so the route matches when they do NOT. The value
// is a list of matcher sets (see l4MatcherNot).
func l4Not(matchers map[string]any) map[string]any {
	return map[string]any{l4MatcherNot: []map[string]any{matchers}}
}

// l4ProtocolMatcher renders a protocol matcher with no sub-matchers,
// which is "match any connection speaking it".
//
// The empty value is NOT the same shape for every matcher, and getting
// it wrong fails config load rather than misbehaving quietly:
//
//   - `http` unmarshals straight into caddyhttp.RawMatcherSets, i.e.
//     []caddy.ModuleMap (modules/l4http/httpmatcher.go:57-59), so its
//     value must be a JSON ARRAY. `"http": {}` cannot decode at all.
//   - `tls` and the rest hold a caddy.ModuleMap or a plain struct whose
//     fields are all optional (modules/l4tls/matcher.go:37), so an
//     OBJECT is right for them.
//
// Verified by reading each matcher in caddy-l4 v0.1.1 on 2026-09-27.
func l4ProtocolMatcher(protocol string) map[string]any {
	if protocol == storage.AcceptProtocolHTTP {
		return map[string]any{protocol: []map[string]any{}}
	}
	return map[string]any{protocol: map[string]any{}}
}

// l4RefusalRoute closes a connection and records why.
//
// The metrics handler precedes `close` so the refusal is counted; on
// this route it is in cause mode, which deliberately leaves the traffic
// counters alone (l4metrics.Handler.Cause).
func l4RefusalRoute(serviceID, cause string, match map[string]any) map[string]any {
	return map[string]any{
		"match": []map[string]any{match},
		"handle": []map[string]any{
			{"handler": l4metrics.HandlerName, "service_id": serviceID, "cause": cause},
			{"handler": l4HandlerClose},
		},
	}
}

// buildLayer4Proxy renders the proxy handler. `dial` is a list in
// caddy-l4 (modules/l4proxy/upstream.go), not a string.
func buildLayer4Proxy(svc storage.TCPService) map[string]any {
	upstreams := make([]map[string]any, 0, len(svc.Upstreams))
	for _, u := range svc.Upstreams {
		up := map[string]any{"dial": []string{svc.DialAddress(u)}}
		if u.MaxConnections > 0 {
			up["max_connections"] = u.MaxConnections
		}
		upstreams = append(upstreams, up)
	}

	proxy := map[string]any{
		"handler":   l4HandlerProxy,
		"upstreams": upstreams,
	}
	if svc.ProxyProtocol != storage.ProxyProtocolOff {
		proxy["proxy_protocol"] = svc.ProxyProtocol
	}
	if svc.LBPolicy != "" && svc.LBPolicy != storage.TCPLBRoundRobin {
		// round_robin is caddy-l4's default; omitting it keeps the
		// emitted config free of noise.
		// The field is "selection" with an inline "policy" key
		// (modules/l4proxy/loadbalancing.go:37) — not
		// "selection_policy", which caddy.Validate rejected outright
		// when this was written from memory.
		proxy["load_balancing"] = map[string]any{
			"selection": map[string]any{"policy": svc.LBPolicy},
		}
	}
	if hc := svc.HealthCheck; hc != nil && hc.Enabled {
		active := map[string]any{}
		if hc.Interval != "" {
			active["interval"] = hc.Interval
		}
		if hc.Timeout != "" {
			active["timeout"] = hc.Timeout
		}
		proxy["health_checks"] = map[string]any{"active": active}
	}
	return proxy
}

// ReservedTCPPorts returns the ports Arenet needs for itself, mapped
// to what uses them, so a refusal can name the culprit. Callers pass
// the admin port they were configured with.
//
// 2019 is Caddy's own admin endpoint: it is bound to 127.0.0.1 and
// disabled in our config, but a service listening there would be a
// foot-gun the day it is re-enabled.
func ReservedTCPPorts(httpPort, httpsPort, adminPort int) map[int]string {
	return map[int]string{
		httpPort:  "Arenet HTTP routes",
		httpsPort: "Arenet HTTPS routes",
		adminPort: "the Arenet admin interface",
		2019:      "Caddy's admin endpoint",
	}
}

// ReservedTCPPortsFor resolves the reserved set from the running
// mode and the admin listen address as configured ("127.0.0.1:8001",
// ":8001"…). An unparseable admin address only costs that one entry:
// the HTTP, HTTPS and Caddy-admin guards still stand.
func ReservedTCPPortsFor(devMode bool, adminListen string) map[int]string {
	adminPort := 0
	if _, portStr, err := net.SplitHostPort(adminListen); err == nil {
		if p, convErr := strconv.Atoi(portStr); convErr == nil {
			adminPort = p
		}
	}
	return ReservedTCPPorts(httpPortFor(devMode), httpsPortFor(devMode), adminPort)
}

// ValidateTCPListen refuses, BEFORE anything is stored or applied, a
// service that would fight over a socket: a port Arenet needs for
// itself, or one another service already listens on. Emission would
// otherwise fail at reload time, which leaves the operator with a
// config that did not apply and no clear reason why.
func ValidateTCPListen(services []storage.TCPService, reserved map[int]string) error {
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		// The reserved set is checked on the port NUMBER, whatever
		// the network: Caddy serves HTTP/3 over UDP on the HTTPS
		// port, so a UDP relay on 443 would fight with it even
		// though the TCP socket is a different one.
		if what, taken := reserved[svc.ListenPort]; taken {
			return fmt.Errorf("tcp service %q: port %d is used by %s", svc.Name, svc.ListenPort, what)
		}
	}
	return l4ListenConflicts(services)
}

// CanBindTCP reports whether this process can actually listen on addr,
// and turns the privileged-port refusal into the sentence the operator
// needs. Called at validation time: a port below 1024 that the process
// cannot bind must be refused while the operator is looking at the
// form, not discovered at the next reload.
func CanBindTCP(addr string) error {
	return CanBind(storage.TCPServiceProtocolTCP, addr)
}

// CanBind probes the address on the service's OWN network.
//
// v2.44.1 — this used to open a TCP socket whatever the service said,
// so a UDP relay had its port checked on the wrong protocol: a free
// TCP/51820 proved nothing about UDP/51820, and something holding
// TCP/51820 refused a WireGuard relay that would have bound fine.
func CanBind(network, addr string) error {
	var closer interface{ Close() error }
	var err error
	if network == storage.TCPServiceProtocolUDP {
		var pc net.PacketConn
		pc, err = net.ListenPacket("udp", addr)
		closer = pc
	} else {
		var ln net.Listener
		ln, err = net.Listen("tcp", addr)
		closer = ln
	}
	if err == nil {
		_ = closer.Close()
		return nil
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return apierr.New("listen_needs_capability", map[string]string{"addr": addr},
			"cannot listen on %s: ports below 1024 need the capability. "+
				"Add `AmbientCapabilities=CAP_NET_BIND_SERVICE` to the arenet systemd unit "+
				"(or publish the port in docker-compose.yml when running in a container), "+
				"then restart Arenet: %v", addr, err)
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return apierr.New("listen_port_taken", map[string]string{"addr": addr},
			"cannot listen on %s: something else on this host already uses it: %v", addr, err)
	}
	return fmt.Errorf("cannot listen on %s: %w", addr, err)
}

// l4ListenConflicts reports services that would fight over the same
// listening socket. Returned as a plain error so both the API (before
// storing) and the manager (before emitting) can refuse with the same
// message.
func l4ListenConflicts(services []storage.TCPService) error {
	seen := make(map[string]string, len(services))
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		// Keyed by network too: a TCP and a UDP service can share a
		// port number without fighting — that is one socket each.
		addr := svc.ListenAddress()
		if other, dup := seen[addr]; dup {
			return fmt.Errorf("tcp services %q and %q both listen on %s", other, svc.Name, addr)
		}
		seen[addr] = svc.Name
	}
	return nil
}
