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
	"testing"

	"github.com/barto95100/arenet/internal/l4metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.57.1 — the registry resets a datagram service's open-session gauge on
// every apply, but only if it is TOLD the service is a datagram one. The
// reset living in l4metrics and the transport being decided here is
// exactly the shape of defect this project keeps paying for: the fix works
// in its own package and does nothing in production because the caller
// never passes the flag. These tests pin the wiring, through the real
// registry rather than a double.
func TestSyncL4Registry_PassesTheTransport(t *testing.T) {
	l4metrics.ResetForTest()
	t.Cleanup(l4metrics.ResetForTest)
	reg := l4metrics.NewRegistry()
	l4metrics.SetRegistry(reg)

	services := []storage.TCPService{
		{ID: "udp-svc", Protocol: storage.TCPServiceProtocolUDP},
		{ID: "tcp-svc", Protocol: storage.TCPServiceProtocolTCP},
		// Empty protocol is TCP by default (TCPService.Network).
		{ID: "default-svc"},
	}
	syncL4Registry(services)

	// One session open on each.
	for _, id := range []string{"udp-svc", "tcp-svc", "default-svc"} {
		reg.Opened(id)
	}

	// A second apply, as any config change performs.
	syncL4Registry(services)

	snap := reg.Snapshot()
	if got := snap["udp-svc"].Active; got != 0 {
		t.Errorf("udp service active after an apply = %d; want 0 — the UDP gauge cannot "+
			"survive an apply (l4metrics.SyncSpec.Datagram), so Datagram must be set here", got)
	}
	if got := snap["tcp-svc"].Active; got != 1 {
		t.Errorf("tcp service active after an apply = %d; want 1 — a stream session keeps "+
			"relaying across an apply and reports its own close", got)
	}
	if got := snap["default-svc"].Active; got != 1 {
		t.Errorf("default-protocol service active after an apply = %d; want 1 — an empty "+
			"Protocol means TCP (TCPService.Network)", got)
	}
	// The cumulative count is untouched by either path.
	for _, id := range []string{"udp-svc", "tcp-svc", "default-svc"} {
		if got := snap[id].Connections; got != 1 {
			t.Errorf("%s connections = %d; want 1 — an apply must not erase the past", id, got)
		}
	}
}

// Disabled services are excluded, as before this change.
func TestSyncL4Registry_SkipsDisabled(t *testing.T) {
	l4metrics.ResetForTest()
	t.Cleanup(l4metrics.ResetForTest)
	reg := l4metrics.NewRegistry()
	l4metrics.SetRegistry(reg)

	syncL4Registry([]storage.TCPService{
		{ID: "live", Protocol: storage.TCPServiceProtocolUDP},
		{ID: "off", Protocol: storage.TCPServiceProtocolUDP, Disabled: true},
	})
	snap := reg.Snapshot()
	if _, present := snap["live"]; !present {
		t.Error("the enabled service has no cell")
	}
	if _, present := snap["off"]; present {
		t.Error("a disabled service got a cell; it serves nothing, so reporting it is noise")
	}
}

// A nil registry is the unit-test and pre-boot case: it must not panic.
func TestSyncL4Registry_NoRegistryIsSafe(t *testing.T) {
	l4metrics.ResetForTest()
	t.Cleanup(l4metrics.ResetForTest)
	syncL4Registry([]storage.TCPService{{ID: "svc"}})
}
