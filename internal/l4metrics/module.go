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
	"net"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
)

// Module IDs, in both forms Caddy needs: the dotted identifier for
// its registry, and the bare name that goes in the JSON `handler`
// field. Mixing the two fails config load with "unknown handler",
// which is exactly the class of bug caddy.Validate catches for us.
const (
	ModuleID    = "layer4.handlers.arenet_l4metrics"
	HandlerName = "arenet_l4metrics"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler counts a service's connections and bytes, then hands over.
//
// It is deliberately forgiving: when no registry is installed, or
// the service is unknown to it, the handler counts nothing and lets
// the connection through. Metrics must never be the reason a relay
// stops relaying.
type Handler struct {
	// ServiceID is the row this connection belongs to. The emitter
	// fills it; an empty value means "count nothing", which is what
	// a hand-written config without it would deserve.
	ServiceID string `json:"service_id,omitempty"`

	// Cause, when set, makes this handler count a REFUSAL instead of a
	// connection: the route it sits on has already decided to close,
	// and the next handler is `close`.
	//
	// It deliberately touches none of the traffic counters. A refused
	// connection never reaches the backend, so counting it as a
	// connection — or wrapping it to count its bytes — would inflate
	// the figures the operator uses to judge whether the relay is
	// working. See Registry.Refused.
	Cause string `json:"cause,omitempty"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(Handler) },
	}
}

// Handle counts, then hands over.
//
// On a refusal route (Cause set) it records the refusal and hands the
// connection to `close` untouched. Otherwise it wraps the connection so
// reads and writes are counted, then calls the next handler — the proxy,
// in every config Arenet emits.
func (h Handler) Handle(cx *layer4.Connection, next layer4.Handler) error {
	reg := GlobalRegistry()
	if reg == nil || h.ServiceID == "" {
		return next.Handle(cx)
	}

	if h.Cause != "" {
		reg.Refused(h.ServiceID, h.Cause)
		// No Opened, no wrapping: this connection is being closed, and
		// the traffic counters must keep meaning "traffic that reached
		// the backend".
		return next.Handle(cx)
	}

	reg.Opened(h.ServiceID)
	counted := &countingConn{Conn: cx.Conn, rec: reg.RecorderFor(h.ServiceID)}
	// Close the gauge once, whatever happens below — a handler that
	// panicked or returned early must not leave it climbing. The
	// bytes are already in: countingConn records them as they cross,
	// so a session that stays open for hours is visible while it is
	// open rather than only once it ends.
	defer reg.Closed(h.ServiceID)

	err := next.Handle(cx.Wrap(counted))
	if err != nil {
		reg.Failed(h.ServiceID)
	}
	return err
}

// countingConn counts what crosses it, into the registry as it goes.
// Reads are what the client sent, writes are what it received.
type countingConn struct {
	net.Conn
	rec *Recorder
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.AddIn(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.rec.AddOut(uint64(n))
	}
	return n, err
}

// --- process-wide registry -------------------------------------
//
// Same contract as internal/metrics: main installs one at boot,
// before Caddy is started, and the module reads it at connection
// time. A missing registry is survivable here by design.

var (
	globalRegistry *Registry
	globalOnce     sync.Once
	globalMu       sync.RWMutex
)

// SetRegistry installs the process-wide registry. Only the first
// call wins, so a stray second call cannot orphan the counters the
// running config is already writing to.
func SetRegistry(r *Registry) {
	globalOnce.Do(func() {
		globalMu.Lock()
		globalRegistry = r
		globalMu.Unlock()
	})
}

// GlobalRegistry returns the installed registry, or nil.
func GlobalRegistry() *Registry {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalRegistry
}

// ResetForTest clears the singleton. Tests only.
func ResetForTest() {
	globalMu.Lock()
	globalRegistry = nil
	globalMu.Unlock()
	globalOnce = sync.Once{}
}

// Interface guard: the layer4 chain calls NextHandler.
var _ layer4.NextHandler = (*Handler)(nil)
