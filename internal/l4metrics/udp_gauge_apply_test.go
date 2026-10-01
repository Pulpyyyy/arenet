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

package l4metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
)

// Operator report, 2026-10-02: a LiveKit RTC service on udp/7882 showed
// "105 conn. · 38 open" more than an hour after the meeting ended, frozen.
// The idle timeout is 30s, so nothing should have been open.
//
// The cause is upstream and this test reproduces it against the real
// caddy-l4: when an apply replaces the layer-4 server, its run loop exits
// (server.go:154) while UDP pseudo-sessions are live. Each then reaches
// its idle timeout and tries to announce its closure on a channel buffered
// at 10 whose only reader was that loop (server.go:135, :138, :367). The
// ones that do not fit block forever, so their handler never returns and
// the deferred Closed() in module.go never runs.
//
// Arenet cannot unblock those goroutines. What it can do is stop believing
// the gauge across an apply, which is what Sync now does for a datagram
// service — and what this test pins.
//
// This drives layer4.App directly rather than a whole Caddy instance: a
// caddy.Validate-level fixture was tried in internal/caddymgr and left
// global state (admin endpoint, tls cache) that poisoned the next test in
// that package, as the note in manager_https_upstream_test.go records.
// Provisioning one app touches none of that.

// udpEchoBackend answers every datagram, standing in for the relay target.
func udpEchoBackend(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo backend: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// freeUDPPort returns a port nothing is listening on. Racy in principle,
// fine in practice, and the alternative (listen on :0 then read the port)
// is not available through the layer4 Listen string.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	return port
}

// startUDPRelay mounts one UDP service named serviceID, counted by this
// package's handler and relayed to an echo backend. The idle timeout is
// short so the test does not wait out caddy-l4's 30s default.
func startUDPRelay(t *testing.T, serviceID string, idle time.Duration) (listenPort int, stop func()) {
	t.Helper()
	backendPort := udpEchoBackend(t)
	listenPort = freeUDPPort(t)

	handlers := fmt.Sprintf(`[
	  {"handler":"arenet_l4metrics","service_id":%q},
	  {"handler":"proxy","upstreams":[{"dial":["udp/127.0.0.1:%d"]}]}
	]`, serviceID, backendPort)
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(handlers), &raw); err != nil {
		t.Fatalf("handler json: %v", err)
	}

	app := &layer4.App{
		Servers: map[string]*layer4.Server{
			"probe": {
				Listen:      []string{fmt.Sprintf("udp/127.0.0.1:%d", listenPort)},
				IdleTimeout: caddy.Duration(idle),
				Routes:      layer4.RouteList{&layer4.Route{HandlersRaw: raw}},
			},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	if err := app.Provision(ctx); err != nil {
		cancel()
		t.Fatalf("provision layer4: %v", err)
	}
	if err := app.Start(); err != nil {
		cancel()
		t.Fatalf("start layer4: %v", err)
	}
	return listenPort, func() {
		_ = app.Stop()
		cancel()
	}
}

// openUDPSessions sends one datagram from n distinct source ports, which
// is what makes caddy-l4 create n pseudo-sessions.
func openUDPSessions(t *testing.T, port, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatalf("dial session %d: %v", i, err)
		}
		if _, err := c.Write([]byte("probe")); err != nil {
			t.Fatalf("write session %d: %v", i, err)
		}
		t.Cleanup(func() { _ = c.Close() })
	}
}

// waitForActive polls until the gauge reaches want, and reports what it
// last saw. Polling because the sessions are created by the server's own
// goroutines, not by our writes returning.
func waitForActive(t *testing.T, reg *Registry, serviceID string, want int64, timeout time.Duration) int64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got int64
	for time.Now().Before(deadline) {
		got = reg.Snapshot()[serviceID].Active
		if got >= want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return got
}

func TestUDPGauge_LeaksAcrossAnApply(t *testing.T) {
	const (
		serviceID = "udp-svc"
		sessions  = 15
		idle      = 150 * time.Millisecond
	)
	ResetForTest()
	t.Cleanup(ResetForTest)
	reg := NewRegistry()
	SetRegistry(reg)
	reg.Sync([]SyncSpec{{ID: serviceID, Datagram: true}})

	port, stop := startUDPRelay(t, serviceID, idle)
	openUDPSessions(t, port, sessions)

	if live := waitForActive(t, reg, serviceID, sessions, 5*time.Second); live != sessions {
		t.Fatalf("active while live = %d; want %d — the relay never counted the sessions, "+
			"so this test is not exercising what it claims", live, sessions)
	}

	// The apply: the old layer-4 server goes away under live sessions.
	stop()
	// Well past the idle timeout: every session has had its chance to
	// report its own closure.
	time.Sleep(10 * idle)

	leaked := reg.Snapshot()[serviceID].Active
	if leaked == 0 {
		t.Skip("no sessions leaked across the stop: caddy-l4 appears to have been " +
			"fixed upstream, so the reset below guards nothing and this test should go")
	}
	t.Logf("confirmed: %d of %d sessions still counted as open after the server stopped",
		leaked, sessions)

	// THE FIX: the apply-time Sync must not carry those increments
	// forward. Without it they stay for the life of the process, which is
	// what the operator saw an hour after a meeting.
	reg.Sync([]SyncSpec{{ID: serviceID, Datagram: true}})
	if after := reg.Snapshot()[serviceID].Active; after != 0 {
		t.Errorf("active after the apply = %d; want 0 — a datagram service's gauge must "+
			"restart at zero, or leaked sessions are counted as open forever", after)
	}

	// The past is not erased: an apply does not undo traffic that happened.
	if got := reg.Snapshot()[serviceID].Connections; got != sessions {
		t.Errorf("connections after the apply = %d; want %d — resetting the gauge must "+
			"not touch the cumulative counters", got, sessions)
	}
}

// A stream service keeps its gauge across an apply: Stop() closes the
// listener, not the accepted connections, so a long-lived relay is still
// running and will report its own close. Zeroing it would read 0 for a
// service that is busy, then go negative when the session ends.
func TestStreamGauge_SurvivesAnApply(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	reg := NewRegistry()
	SetRegistry(reg)
	reg.Sync([]SyncSpec{{ID: "tcp-svc"}})

	reg.Opened("tcp-svc")
	reg.Opened("tcp-svc")
	reg.Sync([]SyncSpec{{ID: "tcp-svc"}})
	if got := reg.Snapshot()["tcp-svc"].Active; got != 2 {
		t.Fatalf("active after the apply = %d; want 2 (the sessions are still relaying)", got)
	}
	// They end afterwards, as they do across a real reload.
	reg.Closed("tcp-svc")
	reg.Closed("tcp-svc")
	if got := reg.Snapshot()["tcp-svc"].Active; got != 0 {
		t.Errorf("active after both closed = %d; want 0", got)
	}
}

// A close arriving after its increment was dropped must not take the
// gauge below zero: Active is a signed int64 the API serialises as-is, so
// a negative would reach the UI as "-3 open".
func TestGauge_NeverGoesNegative(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)
	reg := NewRegistry()
	SetRegistry(reg)

	// A datagram service whose gauge was just reset under a live session.
	reg.Sync([]SyncSpec{{ID: "udp-svc", Datagram: true}})
	reg.Opened("udp-svc")
	reg.Sync([]SyncSpec{{ID: "udp-svc", Datagram: true}})
	reg.Closed("udp-svc") // the pre-apply session finally ends
	if got := reg.Snapshot()["udp-svc"].Active; got != 0 {
		t.Errorf("active = %d; want 0, never below", got)
	}

	// And a service dropped then recreated, which is disable/re-enable.
	reg.Sync([]SyncSpec{{ID: "tcp-svc"}})
	reg.Opened("tcp-svc")
	reg.Sync(nil)                         // service removed, cell dropped
	reg.Sync([]SyncSpec{{ID: "tcp-svc"}}) // back, cell recreated at zero
	reg.Closed("tcp-svc")                 // the old generation's session ends
	if got := reg.Snapshot()["tcp-svc"].Active; got != 0 {
		t.Errorf("active after disable/re-enable = %d; want 0, never below", got)
	}
}
