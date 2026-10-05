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

package metrics

import (
	"sync"
	"testing"
)

// Topology Plan B Phase 1 — IncByHost / SnapshotHosts /
// Sync host-cell drop tests.

func TestIncByHost_BumpsBothRouteAndHost(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.IncByHost("r1", "api.example.com", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r1", "api.example.com", Observation{Status: 200, DurMs: 0})

	// Route cell must have 2 reqs (per-host bump did NOT
	// double-count).
	got := r.Snapshot()
	if got["r1"].Reqs != 2 {
		t.Errorf("route reqs=%d want 2", got["r1"].Reqs)
	}

	// After the route Snapshot, the host cell still holds 2
	// (independent drain state). The two snapshots don't share
	// counters per the spec — they read independent cells.
	hosts := r.SnapshotHosts()
	if len(hosts) != 1 {
		t.Fatalf("host deltas len=%d want 1", len(hosts))
	}
	hd := hosts[0]
	if hd.RouteID != "r1" || hd.Host != "api.example.com" {
		t.Errorf("got (%s, %s) want (r1, api.example.com)", hd.RouteID, hd.Host)
	}
	if hd.Reqs != 2 {
		t.Errorf("host reqs=%d want 2", hd.Reqs)
	}
}

func TestIncByHost_EmptyHost_BumpsRouteOnly(t *testing.T) {
	// Middleware passes host="" when r.Host failed the
	// KnownHosts membership check. The route counter MUST
	// still tick (route counter is authoritative) but no host
	// cell is created.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.IncByHost("r1", "", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r1", "", Observation{Status: 500, DurMs: 0})

	got := r.Snapshot()
	if got["r1"].Reqs != 2 {
		t.Errorf("route reqs=%d want 2", got["r1"].Reqs)
	}
	if got["r1"].Errs != 1 {
		t.Errorf("route errs=%d want 1 (one 5xx)", got["r1"].Errs)
	}

	hosts := r.SnapshotHosts()
	if len(hosts) != 0 {
		t.Errorf("host deltas len=%d want 0 (host='' never creates a cell)", len(hosts))
	}

	// hostCells inner map for r1 must not exist.
	r.mu.RLock()
	_, hasInner := r.hostCells["r1"]
	r.mu.RUnlock()
	if hasInner {
		t.Errorf("hostCells[r1] inner map created on host='' bump; want absent")
	}
}

func TestIncByHost_UnknownRoute_NoOp(t *testing.T) {
	// No Sync → no route cell → IncByHost must silently no-op
	// AND must not create a host cell either.
	r := NewRegistry()

	r.IncByHost("ghost-route", "api.example.com", Observation{Status: 200, DurMs: 0})

	if len(r.cells) != 0 {
		t.Errorf("route cells map grew: %d", len(r.cells))
	}
	r.mu.RLock()
	innerCount := len(r.hostCells)
	r.mu.RUnlock()
	if innerCount != 0 {
		t.Errorf("hostCells map grew: %d", innerCount)
	}
}

func TestIncByHost_MultipleHostsPerRoute(t *testing.T) {
	// Two aliases of the same route fire independently. The
	// route counter agglomerates; the host counters partition.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	r.IncByHost("r1", "primary.example.com", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r1", "primary.example.com", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r1", "primary.example.com", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r1", "alias1.example.com", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r1", "alias2.example.com", Observation{Status: 404, DurMs: 0})

	got := r.Snapshot()
	if got["r1"].Reqs != 5 {
		t.Errorf("route reqs=%d want 5", got["r1"].Reqs)
	}
	if got["r1"].Errs4xx != 1 {
		t.Errorf("route errs4xx=%d want 1", got["r1"].Errs4xx)
	}

	hosts := r.SnapshotHosts()
	if len(hosts) != 3 {
		t.Fatalf("host deltas len=%d want 3", len(hosts))
	}
	// Build a lookup by host to assert specific counts.
	byHost := make(map[string]HostDelta, len(hosts))
	for _, hd := range hosts {
		if hd.RouteID != "r1" {
			t.Errorf("HostDelta.RouteID=%q want r1", hd.RouteID)
		}
		byHost[hd.Host] = hd
	}
	if byHost["primary.example.com"].Reqs != 3 {
		t.Errorf("primary reqs=%d want 3", byHost["primary.example.com"].Reqs)
	}
	if byHost["alias1.example.com"].Reqs != 1 {
		t.Errorf("alias1 reqs=%d want 1", byHost["alias1.example.com"].Reqs)
	}
	if byHost["alias2.example.com"].Reqs != 1 || byHost["alias2.example.com"].Errs4xx != 1 {
		t.Errorf("alias2 wrong: reqs=%d errs4xx=%d want 1/1",
			byHost["alias2.example.com"].Reqs, byHost["alias2.example.com"].Errs4xx)
	}
}

func TestIncByHost_SyncRemoval_DropsHostCells(t *testing.T) {
	// When Sync drops a routeID, the hostCells outer entry must
	// also disappear so memory doesn't leak for renamed /
	// deleted routes.
	r := NewRegistry()
	r.Sync([]string{"r1", "r2"})

	r.IncByHost("r1", "a.example.com", Observation{Status: 200, DurMs: 0})
	r.IncByHost("r2", "b.example.com", Observation{Status: 200, DurMs: 0})

	// Drop r1, keep r2.
	r.Sync([]string{"r2"})

	r.mu.RLock()
	_, hasR1 := r.hostCells["r1"]
	_, hasR2 := r.hostCells["r2"]
	r.mu.RUnlock()
	if hasR1 {
		t.Errorf("hostCells[r1] still present after Sync dropped r1")
	}
	if !hasR2 {
		t.Errorf("hostCells[r2] missing after Sync preserved r2")
	}

	hosts := r.SnapshotHosts()
	if len(hosts) != 1 || hosts[0].RouteID != "r2" {
		t.Errorf("SnapshotHosts = %+v; want only r2", hosts)
	}
}

func TestIncByHost_ConcurrentSafe(t *testing.T) {
	// Concurrent IncByHost on the same (routeID, host) must
	// not race. The first-hit cell-creation path is the most
	// race-prone area (lazy map insertion under the write
	// lock with double-check); this test pounds it.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	const goroutines = 16
	const perGoroutine = 250
	const totalExpected = goroutines * perGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				// Alternate between two hosts so both inner-
				// map insertion paths and steady-state cached
				// bumps execute concurrently.
				host := "primary.example.com"
				if i%2 == 1 {
					host = "alias.example.com"
				}
				r.IncByHost("r1", host, Observation{Status: 200, DurMs: 0})
			}
		}()
	}
	wg.Wait()

	got := r.Snapshot()
	if got["r1"].Reqs != uint64(totalExpected) {
		t.Errorf("route reqs=%d want %d (lost count under race)",
			got["r1"].Reqs, totalExpected)
	}

	hosts := r.SnapshotHosts()
	var hostSum uint64
	for _, hd := range hosts {
		hostSum += hd.Reqs
	}
	if hostSum != uint64(totalExpected) {
		t.Errorf("host reqs sum=%d want %d (lost count under race)",
			hostSum, totalExpected)
	}
	if len(hosts) != 2 {
		t.Errorf("host cell count=%d want exactly 2 (no duplicate cells under race)", len(hosts))
	}
}
