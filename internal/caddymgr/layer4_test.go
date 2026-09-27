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
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/l4metrics"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"

	// v2.42 — the layer-4 modules, blank-imported here for the same
	// reason as caddy-dns/ovh above: caddy.Validate provisions the
	// emitted JSON, so `layer4.handlers.proxy` and friends must be in
	// the test binary's module registry exactly as they are in the
	// production binary (cmd/arenet/main.go).
	_ "github.com/mholt/caddy-l4/modules/l4close"
	// v2.49 — the protocol matchers a service can be told to accept
	// (storage.AcceptProtocol*). These MUST be blank-imported here: a
	// matcher named in the emitted JSON but absent from this binary's
	// registry fails the reload outright with
	// "unknown module: layer4.matchers.ssh", which is exactly how
	// layer4.matchers.crowdsec escaped to production in v2.42.
	// TestBuildConfigJSON_LoadsCleanly_EveryAcceptProtocol walks
	// storage.AcceptProtocolsFor and provisions each one, so a protocol
	// offered without its import fails in CI instead of on the host.
	//
	// l4quic and l4socks are deliberately NOT here, and Arenet offers
	// neither protocol — see storage.acceptProtocolTransports for quic,
	// and for socks: importing l4socks drags in a whole SOCKS5 SERVER
	// implementation (github.com/things-go/go-socks5, via that package's
	// socks5_handler.go) to obtain a matcher that reads eight bytes.
	// Not a trade this project makes for a protocol a homelab reverse
	// proxy rarely relays.
	_ "github.com/mholt/caddy-l4/modules/l4dns"
	_ "github.com/mholt/caddy-l4/modules/l4http"
	_ "github.com/mholt/caddy-l4/modules/l4openvpn"
	_ "github.com/mholt/caddy-l4/modules/l4postgres"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/mholt/caddy-l4/modules/l4rdp"
	_ "github.com/mholt/caddy-l4/modules/l4ssh"
	_ "github.com/mholt/caddy-l4/modules/l4subroute"
	_ "github.com/mholt/caddy-l4/modules/l4tls"
	_ "github.com/mholt/caddy-l4/modules/l4winbox"
	_ "github.com/mholt/caddy-l4/modules/l4wireguard"
	_ "github.com/mholt/caddy-l4/modules/l4xmpp"
)

// proxyOf returns the proxy handler of a route, skipping the metrics
// handler the emitter puts in front of it.
func proxyOf(t *testing.T, route map[string]any) map[string]any {
	t.Helper()
	handle, _ := route["handle"].([]map[string]any)
	for _, h := range handle {
		if h["handler"] == l4HandlerProxy {
			return h
		}
	}
	t.Fatalf("no proxy handler in %v", handle)
	return nil
}

func imapsService() storage.TCPService {
	return storage.TCPService{
		ID:         "svc1",
		Name:       "stalwart-imaps",
		ListenPort: 9993,
		Upstreams:  []storage.TCPUpstream{{Host: "10.20.0.5", Port: 993}},
	}
}

// layer4Of unmarshals the emitted config and returns the layer4 app,
// or nil when the key is absent.
func layer4Of(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps, _ := cfg["apps"].(map[string]any)
	if apps == nil {
		t.Fatal("no apps block")
	}
	l4, _ := apps["layer4"].(map[string]any)
	return l4
}

// The contract every existing installation depends on: no TCP
// service, no change whatsoever in the emitted config.
func TestBuildConfigJSON_NoTCPServices_ByteIdentical(t *testing.T) {
	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	before, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Same call, but going through the v2.42 field with nothing in it
	// and with a disabled service, which must not surface either.
	after, err := buildConfigJSON(routes, buildOpts{
		DevMode: true,
		TCPServices: []storage.TCPService{
			func() storage.TCPService { s := imapsService(); s.Disabled = true; return s }(),
		},
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("emitted config changed with no active TCP service:\n--- before\n%s\n--- after\n%s", before, after)
	}
	if l4 := layer4Of(t, after); l4 != nil {
		t.Fatalf("layer4 app emitted with no active service: %v", l4)
	}
}

func TestBuildLayer4App_BareService(t *testing.T) {
	app := buildLayer4App([]storage.TCPService{imapsService()}, false)
	if app == nil {
		t.Fatal("buildLayer4App: want an app, got nil")
	}
	servers, _ := app["servers"].(map[string]any)
	srv, _ := servers["svc_svc1"].(map[string]any)
	if srv == nil {
		t.Fatalf("want one server per service, got %v", servers)
	}

	listen, _ := srv["listen"].([]string)
	if len(listen) != 1 || listen[0] != "tcp/0.0.0.0:9993" {
		t.Fatalf("listen: got %v", listen)
	}

	routes, _ := srv["routes"].([]map[string]any)
	if len(routes) != 1 {
		t.Fatalf("a service with no gate needs exactly one route, got %d: %v", len(routes), routes)
	}
	if _, hasMatch := routes[0]["match"]; hasMatch {
		t.Fatal("a service with no gate must not emit a matcher")
	}
	handle, _ := routes[0]["handle"].([]map[string]any)
	// v2.42 — metrics first, then the relay.
	if len(handle) != 2 || handle[0]["handler"] != "arenet_l4metrics" || handle[0]["service_id"] != "svc1" {
		t.Fatalf("handle: want the metrics handler then the proxy, got %v", handle)
	}
	proxy := proxyOf(t, routes[0])
	// dial is a LIST in caddy-l4, not a string.
	ups, _ := proxy["upstreams"].([]map[string]any)
	dial, _ := ups[0]["dial"].([]string)
	if len(dial) != 1 || dial[0] != "tcp/10.20.0.5:993" {
		t.Fatalf("dial: got %v", ups[0]["dial"])
	}
	if _, hasPP := proxy["proxy_protocol"]; hasPP {
		t.Fatal("proxy_protocol must be absent when the service does not send it")
	}
	if _, hasLB := proxy["load_balancing"]; hasLB {
		t.Fatal("round_robin is the default; it must not be emitted")
	}
}

func TestBuildLayer4App_ProxyProtocolAndHealthCheck(t *testing.T) {
	svc := imapsService()
	svc.ProxyProtocol = storage.ProxyProtocolV2
	svc.LBPolicy = storage.TCPLBLeastConn
	svc.HealthCheck = &storage.TCPHealthCheck{Enabled: true, Interval: "30s", Timeout: "5s"}
	svc.Upstreams[0].MaxConnections = 50

	app := buildLayer4App([]storage.TCPService{svc}, false)
	srv := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)
	proxy := proxyOf(t, srv["routes"].([]map[string]any)[0])

	if proxy["proxy_protocol"] != storage.ProxyProtocolV2 {
		t.Fatalf("proxy_protocol: got %v", proxy["proxy_protocol"])
	}
	lb, _ := proxy["load_balancing"].(map[string]any)
	sel, _ := lb["selection"].(map[string]any)
	if sel["policy"] != storage.TCPLBLeastConn {
		t.Fatalf("selection policy: got %v", lb)
	}
	hc, _ := proxy["health_checks"].(map[string]any)
	active, _ := hc["active"].(map[string]any)
	if active["interval"] != "30s" || active["timeout"] != "5s" {
		t.Fatalf("health check: got %v", hc)
	}
	ups := proxy["upstreams"].([]map[string]any)
	if ups[0]["max_connections"] != 50 {
		t.Fatalf("max_connections: got %v", ups[0])
	}
}

// refusalOf reads a refusal route: the cause it records and the
// matcher set that selects the connections it closes.
//
// Shape asserted here rather than inline everywhere, because it is the
// contract the counters depend on: metrics handler with a cause FIRST,
// then close. Reversed, the connection would be gone before it was
// counted.
func refusalOf(t *testing.T, route map[string]any) (cause string, match map[string]any) {
	t.Helper()
	handle, _ := route["handle"].([]map[string]any)
	if len(handle) != 2 {
		t.Fatalf("refusal route: want [metrics, close], got %v", handle)
	}
	if handle[0]["handler"] != l4metrics.HandlerName {
		t.Fatalf("refusal route: want the metrics handler first, got %v", handle[0])
	}
	if handle[1]["handler"] != l4HandlerClose {
		t.Fatalf("refusal route: want close last, got %v", handle[1])
	}
	cause, _ = handle[0]["cause"].(string)
	if cause == "" {
		t.Fatalf("refusal route: the metrics handler carries no cause: %v", handle[0])
	}
	ms, _ := route["match"].([]map[string]any)
	if len(ms) != 1 {
		t.Fatalf("refusal route: want exactly one matcher set, got %v", ms)
	}
	return cause, ms[0]
}

// negated returns the matcher set inside a `not`, failing when the
// route is not a negation.
func negated(t *testing.T, match map[string]any) map[string]any {
	t.Helper()
	inner, ok := match[l4MatcherNot].([]map[string]any)
	if !ok || len(inner) != 1 {
		t.Fatalf("want a single negated matcher set, got %v", match)
	}
	return inner[0]
}

// assertRelay checks the last route is the ungated relay: after v2.49
// every refusal owns a route, so the relay carries no matcher and no
// cause.
func assertRelay(t *testing.T, route map[string]any) {
	t.Helper()
	if _, gated := route["match"]; gated {
		t.Fatalf("the relay must not be gated once refusals own their routes: %v", route)
	}
	handle, _ := route["handle"].([]map[string]any)
	if handle[0]["handler"] != l4metrics.HandlerName {
		t.Fatalf("the relay must be counted: %v", handle)
	}
	if _, hasCause := handle[0]["cause"]; hasCause {
		t.Fatalf("the relay handler must carry no cause — it counts traffic, not refusals: %v", handle[0])
	}
	if proxyOf(t, route)["handler"] != l4HandlerProxy {
		t.Fatalf("the relay must relay: %v", route)
	}
}

// An allow filter refuses everything it does not list, and says so:
// the refusal is counted under its own cause instead of vanishing into
// a shared close.
func TestBuildLayer4App_IPFilterAllow(t *testing.T) {
	svc := imapsService()
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"192.168.1.0/24"}}

	app := buildLayer4App([]storage.TCPService{svc}, false)
	routes := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 2 {
		t.Fatalf("want refusal + relay, got %d routes: %v", len(routes), routes)
	}

	cause, match := refusalOf(t, routes[0])
	if cause != l4metrics.CauseIPFilter {
		t.Fatalf("cause: got %q", cause)
	}
	ip, _ := negated(t, match)[l4MatcherRemoteIP].(map[string]any)
	ranges, _ := ip["ranges"].([]string)
	if len(ranges) != 1 || ranges[0] != "192.168.1.0/24" {
		t.Fatalf("remote_ip ranges: got %v", match)
	}
	assertRelay(t, routes[1])
}

// A deny filter refuses the sources it lists — no negation needed.
func TestBuildLayer4App_IPFilterDeny(t *testing.T) {
	svc := imapsService()
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeDeny, CIDRs: []string{"203.0.113.0/24"}}

	app := buildLayer4App([]storage.TCPService{svc}, false)
	routes := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 2 {
		t.Fatalf("want refusal + relay, got %d routes: %v", len(routes), routes)
	}

	cause, match := refusalOf(t, routes[0])
	if cause != l4metrics.CauseIPFilter {
		t.Fatalf("cause: got %q", cause)
	}
	if _, negatedFilter := match[l4MatcherNot]; negatedFilter {
		t.Fatalf("a deny list matches what it refuses; no negation: %v", match)
	}
	ip, _ := match[l4MatcherRemoteIP].(map[string]any)
	if ranges, _ := ip["ranges"].([]string); len(ranges) != 1 || ranges[0] != "203.0.113.0/24" {
		t.Fatalf("remote_ip ranges: got %v", match)
	}
	assertRelay(t, routes[1])
}

// The CrowdSec matcher is only wired when the bouncer app is in the
// same config — referencing an absent app fails provisioning.
func TestBuildLayer4App_CrowdSecOnlyWhenAvailable(t *testing.T) {
	svc := imapsService()
	svc.CrowdSecEnabled = true

	without := buildLayer4App([]storage.TCPService{svc}, false)
	routes := without["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 1 {
		t.Fatalf("no bouncer configured: want the relay alone, got %v", routes)
	}
	assertRelay(t, routes[0])

	with := buildLayer4App([]storage.TCPService{svc}, true)
	routes = with["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 2 {
		t.Fatalf("want refusal + relay, got %v", routes)
	}
	cause, match := refusalOf(t, routes[0])
	if cause != l4metrics.CauseCrowdSec {
		t.Fatalf("cause: got %q", cause)
	}
	if _, ok := negated(t, match)[l4MatcherCrowdSec]; !ok {
		t.Fatalf("crowdsec matcher missing: %v", match)
	}
}

// The protocol gate refuses whatever does not speak it (v2.49).
func TestBuildLayer4App_AcceptProtocol(t *testing.T) {
	svc := imapsService()
	svc.AcceptProtocol = storage.AcceptProtocolTLS

	app := buildLayer4App([]storage.TCPService{svc}, false)
	routes := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 2 {
		t.Fatalf("want refusal + relay, got %v", routes)
	}
	cause, match := refusalOf(t, routes[0])
	if cause != l4metrics.CauseProtocol {
		t.Fatalf("cause: got %q", cause)
	}
	if _, ok := negated(t, match)[storage.AcceptProtocolTLS]; !ok {
		t.Fatalf("want a negated tls matcher, got %v", match)
	}
}

// Every gate keeps its own route and its own cause, in the order a
// connection meets them: the address gates decide from the socket, then
// CrowdSec looks a decision up, then the protocol matcher has to read
// the handshake. A single shared close could not attribute any of them,
// which is the defect this ordering exists to fix.
func TestBuildLayer4App_EachGateOwnsItsCause(t *testing.T) {
	svc := imapsService()
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeDeny, CIDRs: []string{"203.0.113.0/24"}}
	svc.CrowdSecEnabled = true
	svc.AcceptProtocol = storage.AcceptProtocolTLS

	app := buildLayer4App([]storage.TCPService{svc}, true)
	routes := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)["routes"].([]map[string]any)
	if len(routes) != 4 {
		t.Fatalf("want three refusals + relay, got %d: %v", len(routes), routes)
	}

	want := []string{l4metrics.CauseIPFilter, l4metrics.CauseCrowdSec, l4metrics.CauseProtocol}
	for i, wantCause := range want {
		cause, _ := refusalOf(t, routes[i])
		if cause != wantCause {
			t.Errorf("route %d: cause = %q, want %q", i, cause, wantCause)
		}
	}
	assertRelay(t, routes[3])

	// No two refusals may share a cause, or the counter would blur two
	// different reasons into one number.
	seen := map[string]int{}
	for i := range want {
		cause, _ := refusalOf(t, routes[i])
		seen[cause]++
	}
	for cause, n := range seen {
		if n != 1 {
			t.Errorf("cause %q emitted %d times", cause, n)
		}
	}
}

func TestBuildLayer4App_OneServerPerService(t *testing.T) {
	a := imapsService()
	b := imapsService()
	b.ID, b.Name, b.ListenPort = "svc2", "stalwart-smtp", 9025

	app := buildLayer4App([]storage.TCPService{a, b}, false)
	servers := app["servers"].(map[string]any)
	if len(servers) != 2 {
		t.Fatalf("want one server per service, got %v", servers)
	}
	if _, ok := servers["svc_svc2"]; !ok {
		t.Fatalf("server svc_svc2 missing: %v", servers)
	}
}

func TestL4ListenConflicts(t *testing.T) {
	a := imapsService()
	b := imapsService()
	b.ID, b.Name = "svc2", "other"

	if err := l4ListenConflicts([]storage.TCPService{a, b}); err == nil {
		t.Fatal("two services on the same address must conflict")
	} else if !strings.Contains(err.Error(), "9993") {
		t.Fatalf("the error must name the address, got %v", err)
	}

	b.ListenPort = 9025
	if err := l4ListenConflicts([]storage.TCPService{a, b}); err != nil {
		t.Fatalf("distinct addresses must not conflict: %v", err)
	}

	// A disabled service listens on nothing.
	b.ListenPort = 9993
	b.Disabled = true
	if err := l4ListenConflicts([]storage.TCPService{a, b}); err != nil {
		t.Fatalf("a disabled service must not conflict: %v", err)
	}
}

// The Step I.7 lesson applied to layer 4: emitting JSON that looks
// right proves nothing until Caddy provisions it. Ports are high so
// the test needs no privilege.
func TestBuildConfigJSON_LoadsCleanly_WithTCPService(t *testing.T) {
	svc := imapsService()
	svc.ProxyProtocol = storage.ProxyProtocolV2
	svc.LBPolicy = storage.TCPLBLeastConn
	svc.HealthCheck = &storage.TCPHealthCheck{Enabled: true, Interval: "30s", Timeout: "5s"}
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"192.168.1.0/24"}}

	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	// The arenet_routemetrics module's Provision needs the registry
	// cmd/arenet installs at boot; without it Validate fails on the
	// HTTP app for a reason that has nothing to do with layer 4.
	//
	// The singleton is process-wide, so it is reset afterwards:
	// leaving it installed changed the outcome of
	// TestSyncRegistry_NotCalledOnReloadFailure, which turns out to
	// depend on the reload failing for lack of a registry.
	metrics.SetRegistry(metrics.NewRegistry())
	t.Cleanup(metrics.ResetForTest)

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true, TCPServices: []storage.TCPService{svc}})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if l4 := layer4Of(t, raw); l4 == nil {
		t.Fatal("layer4 app missing from the emitted config")
	}
	var cfg caddy.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("caddy.Validate on a config carrying a TCP service: %v\n%s", err, raw)
	}
}

// Every protocol Arenet offers must actually LOAD.
//
// This is the gate that matters most for v2.49, because the empty form
// of a matcher is not one shape: `http` unmarshals into a slice and
// `"http": {}` cannot decode at all, while `tls` and the others want an
// object. Both produce a config Caddy refuses — so the failure mode is
// a relay that will not come up, not one that misbehaves subtly.
//
// It runs the real caddy.Validate, which provisions each matcher module,
// and it walks the offer rather than a hand-written list: a protocol
// added to storage without being loadable fails here.
func TestBuildConfigJSON_LoadsCleanly_EveryAcceptProtocol(t *testing.T) {
	metrics.SetRegistry(metrics.NewRegistry())
	t.Cleanup(metrics.ResetForTest)

	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	seen := 0
	for _, transport := range []string{storage.TCPServiceProtocolTCP, storage.TCPServiceProtocolUDP} {
		offered := storage.AcceptProtocolsFor(transport)
		if len(offered) == 0 {
			t.Fatalf("%s: nothing offered — the walk would assert nothing", transport)
		}
		for _, proto := range offered {
			seen++
			t.Run(transport+"/"+proto, func(t *testing.T) {
				svc := imapsService()
				svc.Protocol = transport
				svc.AcceptProtocol = proto
				// An active check needs a real connection, which UDP
				// has not; the fixture must stay valid on both.
				svc.HealthCheck = nil

				if err := svc.Validate(); err != nil {
					t.Fatalf("the offer contains a service storage refuses: %v", err)
				}

				raw, err := buildConfigJSON(routes, buildOpts{
					DevMode:     true,
					TCPServices: []storage.TCPService{svc},
				})
				if err != nil {
					t.Fatalf("buildConfigJSON: %v", err)
				}
				var cfg caddy.Config
				if err := json.Unmarshal(raw, &cfg); err != nil {
					t.Fatalf("unmarshal config: %v\n%s", err, raw)
				}
				if err := caddy.Validate(&cfg); err != nil {
					t.Fatalf("caddy.Validate with accept_protocol %q on %s: %v\n%s",
						proto, transport, err, raw)
				}
			})
		}
	}
	// 9 on TCP + 3 on UDP with the current offer. A floor, not an
	// equality, so adding a protocol does not fail this for the wrong
	// reason — but a truncated offer does.
	if seen < 12 {
		t.Errorf("only %d (transport, protocol) pairs exercised; the offer looks truncated", seen)
	}
}

// The offer is transport-aware, and storage refuses what it does not
// offer. Those two must not drift: a UI that offers wireguard on TCP
// would produce a service the API rejects, and — worse — a matcher that
// can never match refuses every connection, since the gate is emitted
// as not(<matcher>).
func TestAcceptProtocol_OfferMatchesValidation(t *testing.T) {
	for _, transport := range []string{storage.TCPServiceProtocolTCP, storage.TCPServiceProtocolUDP} {
		offered := map[string]bool{}
		for _, p := range storage.AcceptProtocolsFor(transport) {
			offered[p] = true
		}
		for _, p := range []string{
			storage.AcceptProtocolTLS, storage.AcceptProtocolSSH, storage.AcceptProtocolHTTP,
			storage.AcceptProtocolPostgres, storage.AcceptProtocolRDP, storage.AcceptProtocolXMPP,
			storage.AcceptProtocolWinbox, storage.AcceptProtocolDNS,
			storage.AcceptProtocolWireGuard, storage.AcceptProtocolOpenVPN,
		} {
			svc := imapsService()
			svc.Protocol = transport
			svc.AcceptProtocol = p
			svc.HealthCheck = nil
			err := svc.Validate()
			if offered[p] && err != nil {
				t.Errorf("%s/%s is offered but refused: %v", transport, p, err)
			}
			if !offered[p] && err == nil {
				t.Errorf("%s/%s is not offered yet accepted", transport, p)
			}
		}
	}

	// wireguard is the one that must flip between the two transports,
	// so the test cannot pass by offering everything everywhere.
	if slicesHas(storage.AcceptProtocolsFor(storage.TCPServiceProtocolTCP), storage.AcceptProtocolWireGuard) {
		t.Error("wireguard must not be offered on TCP")
	}
	if !slicesHas(storage.AcceptProtocolsFor(storage.TCPServiceProtocolUDP), storage.AcceptProtocolWireGuard) {
		t.Error("wireguard must be offered on UDP")
	}
	// quic is deliberately absent everywhere until a live probe settles
	// it: bare, it sets no ALPN, and not(quic) that never matches would
	// refuse every connection.
	for _, transport := range []string{storage.TCPServiceProtocolTCP, storage.TCPServiceProtocolUDP} {
		if slicesHas(storage.AcceptProtocolsFor(transport), "quic") {
			t.Errorf("%s: quic is offered but was not verified", transport)
		}
	}
}

func slicesHas(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func TestValidateTCPListen_ReservedPorts(t *testing.T) {
	reserved := ReservedTCPPorts(80, 443, 8001)

	for port, what := range map[int]string{80: "HTTP", 443: "HTTPS", 8001: "admin", 2019: "Caddy admin"} {
		svc := imapsService()
		svc.ListenPort = port
		err := ValidateTCPListen([]storage.TCPService{svc}, reserved)
		if err == nil {
			t.Fatalf("port %d (%s) must be refused", port, what)
		}
		if !strings.Contains(err.Error(), svc.Name) {
			t.Fatalf("the refusal must name the service, got %v", err)
		}
	}

	ok := imapsService()
	if err := ValidateTCPListen([]storage.TCPService{ok}, reserved); err != nil {
		t.Fatalf("a free port must be accepted: %v", err)
	}

	// A disabled service listens on nothing, so it cannot clash.
	clash := imapsService()
	clash.ListenPort = 443
	clash.Disabled = true
	if err := ValidateTCPListen([]storage.TCPService{clash}, reserved); err != nil {
		t.Fatalf("a disabled service must not be refused: %v", err)
	}
}

// The bind test is what turns "port 25 without the capability" into a
// sentence at validation time instead of a failed reload. Binding a
// high port must succeed on any host running the suite; the privileged
// branch is not exercised here because the test may well run as root.
func TestCanBindTCP(t *testing.T) {
	if err := CanBindTCP("127.0.0.1:0"); err != nil {
		t.Fatalf("binding an ephemeral port must work: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	err = CanBindTCP(ln.Addr().String())
	if err == nil {
		t.Fatal("an address already in use must be refused")
	}
	if !strings.Contains(err.Error(), "already uses it") {
		t.Fatalf("the refusal must say the address is taken, got %v", err)
	}
}

// v2.42 — UDP. A layer-4 relay that could not do UDP would be no use
// for WireGuard, DNS, syslog or a game server, which is most of what
// people put behind one.
func TestBuildLayer4App_UDPService(t *testing.T) {
	svc := imapsService()
	svc.Name, svc.ListenPort = "wireguard", 51820
	svc.Protocol = storage.TCPServiceProtocolUDP
	svc.Upstreams = []storage.TCPUpstream{{Host: "10.20.0.9", Port: 51820}}
	svc.ProxyProtocol = storage.ProxyProtocolV2

	app := buildLayer4App([]storage.TCPService{svc}, false)
	srv := app["servers"].(map[string]any)["svc_svc1"].(map[string]any)

	listen, _ := srv["listen"].([]string)
	if len(listen) != 1 || listen[0] != "udp/0.0.0.0:51820" {
		t.Fatalf("listen: got %v", listen)
	}
	proxy := proxyOf(t, srv["routes"].([]map[string]any)[0])
	dial, _ := proxy["upstreams"].([]map[string]any)[0]["dial"].([]string)
	if len(dial) != 1 || dial[0] != "udp/10.20.0.9:51820" {
		t.Fatalf("dial: got %v", dial)
	}
}

// Same port number on both networks is two sockets, not a conflict.
func TestL4ListenConflicts_TCPAndUDPCoexist(t *testing.T) {
	tcpSvc := imapsService()
	udpSvc := imapsService()
	udpSvc.ID, udpSvc.Name = "svc2", "same-port-udp"
	udpSvc.Protocol = storage.TCPServiceProtocolUDP

	if err := l4ListenConflicts([]storage.TCPService{tcpSvc, udpSvc}); err != nil {
		t.Fatalf("tcp and udp on the same port must coexist: %v", err)
	}
}

// --- v2.42.3 — every emitted module ID must exist ----------------
//
// The regression this pins: `layer4.matchers.crowdsec` lives in the
// bouncer's `layer4` subpackage, which registers only its own module
// in its own init(). Importing the bouncer's `crowdsec` and `http`
// packages left the matcher unregistered, so a service with CrowdSec
// armed emitted valid-looking JSON that Caddy refused at load time
// with "unknown module: layer4.matchers.crowdsec" — in front of the
// operator, at the first save.
//
// It escaped the suite because CrowdSec is the one family kept away
// from caddy.Validate on purpose (provisioning dials LAPI, see
// crowdsec_test.go:301). A registry lookup needs no LAPI, so this
// covers the gap: walk what the emitter can actually produce and ask
// Caddy whether each ID resolves.
func TestLayer4ModuleIDs_AllRegistered(t *testing.T) {
	// One service armed with everything the emitter knows how to
	// emit: a source filter (remote_ip + close), CrowdSec, and the
	// proxy itself.
	svc := imapsService()
	svc.CrowdSecEnabled = true
	svc.IPFilter = &storage.IPFilter{Mode: storage.IPFilterModeDeny, CIDRs: []string{"203.0.113.0/24"}}

	app := buildLayer4App([]storage.TCPService{svc}, true)
	if app == nil {
		t.Fatal("buildLayer4App returned nil")
	}

	ids := map[string]bool{}
	// collectMatchers RECURSES through `not`.
	//
	// v2.49 — the refusal routes wrap their matchers in
	// layer4.matchers.not, so a flat walk over the top level of each
	// match object stops seeing `crowdsec` and `remote_ip` entirely.
	// This guard exists precisely because a matcher name that is not a
	// registered module fails at reload time with
	// "unknown module: layer4.matchers.crowdsec" and no test caught it
	// once already. A walk that quietly looks at nothing is worse than
	// no walk, so it descends.
	var collectMatchers func(m map[string]any)
	collectMatchers = func(m map[string]any) {
		for name, raw := range m {
			ids["layer4.matchers."+name] = true
			if name != l4MatcherNot {
				continue
			}
			nested, _ := raw.([]map[string]any)
			for _, inner := range nested {
				collectMatchers(inner)
			}
		}
	}

	for _, srv := range app["servers"].(map[string]any) {
		for _, route := range srv.(map[string]any)["routes"].([]map[string]any) {
			// A route without matchers is the relay; only the handlers
			// of such a route carry an ID.
			match, _ := route["match"].([]map[string]any)
			for _, m := range match {
				collectMatchers(m)
			}
			handle, _ := route["handle"].([]map[string]any)
			for _, h := range handle {
				name, _ := h["handler"].(string)
				if name != "" {
					ids["layer4.handlers."+name] = true
				}
			}
		}
	}

	// Sanity: the walk must have seen the matcher that regressed AND
	// the wrapper it now hides behind, otherwise this test would pass
	// by looking at nothing.
	for _, want := range []string{"layer4.matchers.crowdsec", "layer4.matchers.not"} {
		if !ids[want] {
			t.Fatalf("test fixture emitted no %s: %v", want, ids)
		}
	}

	for id := range ids {
		if _, err := caddy.GetModule(id); err != nil {
			t.Errorf("module %q is emitted but not registered: %v", id, err)
		}
	}
}
