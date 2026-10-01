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

// Package l4metrics counts what a layer-4 relay carries.
//
// v2.42 — without this, a TCP or UDP service is a part of the
// installation nobody can watch: its traffic never crosses the HTTP
// chain, so the dashboard, the logs and the per-route counters see
// nothing of it. An operator would configure a database relay and
// have no way to know whether anyone ever connected.
//
// The shape is deliberately not the HTTP one. There are no status
// codes and no request latency at layer 4; what an operator asks is
// how many connections came, how many are open right now, how much
// went each way, and how many failed to reach the backend.
//
// Counters are cumulative since the process started, plus a live
// gauge for open connections. The registry is process-wide and
// installed once at boot, exactly like internal/metrics.
package l4metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Causes a connection can be refused for, in the JSON shape the API
// speaks (camelCase, like the counter names beside them).
//
// A gate's refusal is otherwise invisible: the relay chain — and with
// it every counter below — never runs, so an operator cannot tell a
// relay that is protecting them from one whose protection is off. That
// was true of every layer-4 refusal up to v2.48.
const (
	CauseProtocol = "protocol"
	CauseIPFilter = "ipFilter"
	CauseCrowdSec = "crowdsec"
)

// knownCauses is the fixed set every cell carries a counter for.
//
// Fixed on purpose: a cell can then be built once and read with plain
// atomics, no lock and no allocation on the refusal path. A cause the
// emitter does not know counts nothing, exactly like an unknown
// service — metrics never cost a relay a connection.
var knownCauses = [...]string{CauseProtocol, CauseIPFilter, CauseCrowdSec}

// Causes returns the refusal causes a cell counts, in a stable order.
//
// Exported so the API documentation and the UI can be checked against
// the set the registry actually emits, instead of repeating it and
// drifting.
func Causes() []string { return knownCauses[:] }

// ServiceCounters is one service's live view.
type ServiceCounters struct {
	// Connections accepted since start.
	Connections uint64 `json:"connections"`
	// Active is how many are open right now.
	Active int64 `json:"active"`
	// BytesIn is what clients sent, BytesOut what they received.
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
	// Errors counts connections the relay could not complete —
	// almost always a backend that refused or timed out.
	Errors uint64 `json:"errors"`
	// Refused counts connections a gate closed before they reached the
	// backend, keyed by cause. Absent when nothing was refused, and
	// causes that never fired are left out rather than reported as 0 —
	// a map so a later gate (country, rate) adds a key instead of a
	// field, and an older UI ignores what it does not know.
	//
	// These are NOT a subset of Connections: a refused connection never
	// reaches the relay chain, so it is counted here and nowhere else.
	Refused map[string]uint64 `json:"refused,omitempty"`
	// LastConnectionAt is empty until the first connection.
	LastConnectionAt string `json:"lastConnectionAt,omitempty"`
}

type cell struct {
	connections atomic.Uint64
	active      atomic.Int64
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64
	errors      atomic.Uint64
	lastNanos   atomic.Int64
	// refused is populated for every known cause at construction and
	// never written to afterwards, so it needs no lock.
	refused map[string]*atomic.Uint64
}

// newCell builds a cell with its refusal counters in place. Every cell
// must come from here: a bare &cell{} has a nil refused map and would
// silently drop refusals.
func newCell() *cell {
	c := &cell{refused: make(map[string]*atomic.Uint64, len(knownCauses))}
	for _, cause := range knownCauses {
		c.refused[cause] = new(atomic.Uint64)
	}
	return c
}

// Registry holds one cell per known service.
type Registry struct {
	mu    sync.RWMutex
	cells map[string]*cell
}

func NewRegistry() *Registry {
	return &Registry{cells: make(map[string]*cell)}
}

// SyncSpec is one mounted service, as the registry needs to know it at
// apply time.
type SyncSpec struct {
	ID string
	// Datagram marks a UDP service, whose open-session gauge cannot
	// survive an apply.
	//
	// v2.57.1 — a UDP "connection" is a pseudo-session caddy-l4 keeps per
	// downstream address. When an apply replaces the layer-4 server, the
	// old server's run loop exits (caddy-l4 v0.1.1 layer4/server.go:154)
	// while those sessions are still live. Each then reaches its idle
	// timeout and tries to report its own closure on a channel buffered
	// at 10 whose only reader was that loop (server.go:135, :138, :367),
	// so the ones that do not fit block forever — their handler never
	// returns, and the deferred decrement in module.go never runs. The
	// gauge keeps those increments for the life of the process.
	//
	// Measured, not inferred: 15 live sessions, server stopped, 8 still
	// counted as open afterwards (TestUDPGauge_LeaksAcrossAnApply).
	//
	// So for a datagram service the gauge restarts at zero on every
	// apply. Nothing of value is lost: a client still sending refills it
	// within the idle timeout, and sessions from before the apply are
	// gone whatever the counter says.
	//
	// A stream (TCP) service is left alone on purpose. Stop() closes the
	// listener, not the accepted connections (caddy-l4 layer4/app.go:111),
	// so a long-lived relay — IMAP from a phone — keeps running across an
	// apply and does report its own close. Zeroing it would make the
	// gauge read 0 for a service that is busy, then go negative when the
	// session finally ends.
	Datagram bool
}

// Sync makes the registry hold exactly these services: cells for
// services that disappeared are dropped, new ones start at zero, and a
// datagram service's open-session gauge is reset (see SyncSpec.Datagram).
// Called on every successful apply, like the HTTP registry's Sync.
func (r *Registry) Sync(specs []SyncSpec) {
	wanted := make(map[string]SyncSpec, len(specs))
	for _, s := range specs {
		wanted[s.ID] = s
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.cells {
		if _, keep := wanted[id]; !keep {
			delete(r.cells, id)
		}
	}
	for id, spec := range wanted {
		existing, exists := r.cells[id]
		if !exists {
			r.cells[id] = newCell()
			continue
		}
		// Cumulative counters (connections, bytes, errors, refusals) are
		// kept: they describe the past and an apply does not undo it.
		// Only the "right now" gauge is unreliable across an apply.
		if spec.Datagram {
			existing.active.Store(0)
		}
	}
}

// cellFor returns the cell, or nil when the service is unknown —
// which happens between an apply and the Sync that follows it. A
// missing cell must never cost a connection, so every caller treats
// nil as "do not count" rather than as an error.
func (r *Registry) cellFor(serviceID string) *cell {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cells[serviceID]
}

// Opened records an accepted connection.
func (r *Registry) Opened(serviceID string) {
	if c := r.cellFor(serviceID); c != nil {
		c.connections.Add(1)
		c.active.Add(1)
		c.lastNanos.Store(time.Now().UnixNano())
	}
}

// Closed records a finished connection.
//
// v2.43 — the bytes used to be reported here, accumulated in the
// connection wrapper and handed over in one lump at close. That read
// correctly for a short relay and wrongly for everything else: an
// IMAP session from a phone stays open for hours, so the traffic
// column showed 0 B for a service that was busy the whole time. Bytes
// now go straight into the cell as they cross (see Recorder), and
// this only closes the gauge.
func (r *Registry) Closed(serviceID string) {
	c := r.cellFor(serviceID)
	if c == nil {
		return
	}
	// v2.57.1 — never below zero. A session can open before an apply and
	// close after it, against a cell whose gauge was reset (a datagram
	// service) or which was dropped and recreated (disable then
	// re-enable). The decrement then has no increment to cancel, and
	// Active is a signed int64 that the API serialises as-is: the UI
	// would show a negative number of open sessions, which is worse than
	// a gauge that is briefly low.
	for {
		cur := c.active.Load()
		if cur <= 0 {
			return
		}
		if c.active.CompareAndSwap(cur, cur-1) {
			return
		}
	}
}

// Recorder is a direct handle to one service's byte counters, taken
// once when a connection opens.
//
// Going through the registry on every read and write would mean a map
// lookup under a lock per syscall; the cell pointer costs two atomic
// adds instead. A nil Recorder counts nothing, which is what an
// unknown service — or no registry at all — must cost a relay.
type Recorder struct{ c *cell }

// RecorderFor returns a handle for the service, nil when unknown.
func (r *Registry) RecorderFor(serviceID string) *Recorder {
	if c := r.cellFor(serviceID); c != nil {
		return &Recorder{c: c}
	}
	return nil
}

// AddIn counts bytes the client sent.
func (rec *Recorder) AddIn(n uint64) {
	if rec != nil && rec.c != nil {
		rec.c.bytesIn.Add(n)
	}
}

// AddOut counts bytes the client received.
func (rec *Recorder) AddOut(n uint64) {
	if rec != nil && rec.c != nil {
		rec.c.bytesOut.Add(n)
	}
}

// Refused records a connection a gate closed before the relay.
//
// An unknown cause is ignored rather than added: the set is fixed so
// the cell needs no lock, and a typo in a hand-written config must not
// grow a map that connections are reading.
func (r *Registry) Refused(serviceID, cause string) {
	c := r.cellFor(serviceID)
	if c == nil {
		return
	}
	if n := c.refused[cause]; n != nil {
		n.Add(1)
	}
}

// Failed records a connection the relay could not complete.
func (r *Registry) Failed(serviceID string) {
	if c := r.cellFor(serviceID); c != nil {
		c.errors.Add(1)
	}
}

// Snapshot returns a copy of every known service's counters.
func (r *Registry) Snapshot() map[string]ServiceCounters {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]ServiceCounters, len(r.cells))
	for id, c := range r.cells {
		sc := ServiceCounters{
			Connections: c.connections.Load(),
			Active:      c.active.Load(),
			BytesIn:     c.bytesIn.Load(),
			BytesOut:    c.bytesOut.Load(),
			Errors:      c.errors.Load(),
		}
		for cause, n := range c.refused {
			if v := n.Load(); v > 0 {
				if sc.Refused == nil {
					sc.Refused = make(map[string]uint64, len(knownCauses))
				}
				sc.Refused[cause] = v
			}
		}
		if nanos := c.lastNanos.Load(); nanos > 0 {
			sc.LastConnectionAt = time.Unix(0, nanos).UTC().Format(time.RFC3339)
		}
		out[id] = sc
	}
	return out
}
