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
	"errors"
	"net"
	"testing"

	"github.com/mholt/caddy-l4/layer4"
)

func TestRegistry_CountsAConnection(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]SyncSpec{{ID: "svc1"}})

	reg.Opened("svc1")
	snap := reg.Snapshot()
	if snap["svc1"].Connections != 1 || snap["svc1"].Active != 1 {
		t.Fatalf("after Opened: %+v", snap["svc1"])
	}
	if snap["svc1"].LastConnectionAt == "" {
		t.Fatal("the first connection must set lastConnectionAt")
	}

	// v2.43 — bytes land as they cross, not in a lump at close.
	rec := reg.RecorderFor("svc1")
	rec.AddIn(120)
	rec.AddOut(4096)

	reg.Closed("svc1")
	snap = reg.Snapshot()
	got := snap["svc1"]
	if got.Active != 0 {
		t.Fatalf("a closed connection must leave the gauge at zero: %+v", got)
	}
	if got.Connections != 1 || got.BytesIn != 120 || got.BytesOut != 4096 {
		t.Fatalf("counters: %+v", got)
	}

	reg.Failed("svc1")
	if reg.Snapshot()["svc1"].Errors != 1 {
		t.Fatalf("errors: %+v", reg.Snapshot()["svc1"])
	}
}

// An unknown service must cost nothing — that happens between an
// apply and the Sync that follows it, and a connection must never
// pay for a missing cell.
func TestRegistry_UnknownServiceIsIgnored(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]SyncSpec{{ID: "svc1"}})

	reg.Opened("ghost")
	reg.Closed("ghost")
	reg.Failed("ghost")
	// A nil Recorder must be usable, not a panic: that is the path a
	// connection takes between an apply and the Sync that follows it.
	ghost := reg.RecorderFor("ghost")
	ghost.AddIn(10)
	ghost.AddOut(10)

	if _, exists := reg.Snapshot()["ghost"]; exists {
		t.Fatal("an unknown service must not create a cell")
	}
}

func TestRegistry_SyncDropsAndCreates(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]SyncSpec{{ID: "a"}, {ID: "b"}})
	reg.Opened("a")

	reg.Sync([]SyncSpec{{ID: "b"}, {ID: "c"}})
	snap := reg.Snapshot()
	if _, gone := snap["a"]; gone {
		t.Fatal("a deleted service must stop being reported")
	}
	if _, ok := snap["c"]; !ok {
		t.Fatal("a new service must get a cell")
	}
	if snap["b"].Connections != 0 {
		t.Fatalf("an existing service must keep its counters: %+v", snap["b"])
	}
}

// fakeConn is a net.Conn whose reads return a fixed payload once.
type fakeConn struct {
	net.Conn
	toRead  []byte
	written int
}

func (f *fakeConn) Read(p []byte) (int, error) {
	if len(f.toRead) == 0 {
		return 0, errors.New("eof")
	}
	n := copy(p, f.toRead)
	f.toRead = f.toRead[n:]
	return n, nil
}

func (f *fakeConn) Write(p []byte) (int, error) {
	f.written += len(p)
	return len(p), nil
}

func (f *fakeConn) Close() error         { return nil }
func (f *fakeConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero, Port: 1} }
func (f *fakeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 2} }

// The handler counts what crosses the connection and always hands
// over: a relay must not stop relaying because of a counter.
func TestHandler_CountsBytesAndAlwaysCallsNext(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	reg := NewRegistry()
	reg.Sync([]SyncSpec{{ID: "svc1"}})
	SetRegistry(reg)

	conn := &fakeConn{toRead: []byte("hello backend")}
	cx := layer4.WrapConnection(conn, []byte{}, nil)

	called := false
	next := layer4.HandlerFunc(func(c *layer4.Connection) error {
		called = true
		buf := make([]byte, 32)
		if _, err := c.Read(buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if _, err := c.Write([]byte("hi")); err != nil {
			t.Fatalf("write: %v", err)
		}
		return nil
	})

	h := Handler{ServiceID: "svc1"}
	if err := h.Handle(cx, next); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !called {
		t.Fatal("the next handler must always run")
	}

	got := reg.Snapshot()["svc1"]
	if got.Connections != 1 || got.Active != 0 {
		t.Fatalf("connection accounting: %+v", got)
	}
	if got.BytesIn == 0 || got.BytesOut == 0 {
		t.Fatalf("bytes must be counted both ways: %+v", got)
	}
}

// No registry installed: the handler must be transparent rather than
// refuse the connection.
func TestHandler_NoRegistryIsTransparent(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	cx := layer4.WrapConnection(&fakeConn{}, []byte{}, nil)
	called := false
	next := layer4.HandlerFunc(func(*layer4.Connection) error {
		called = true
		return nil
	})

	if err := (Handler{ServiceID: "svc1"}).Handle(cx, next); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !called {
		t.Fatal("without a registry the connection must still be relayed")
	}
}

// A handler that fails records the failure, and the gauge still
// comes back down.
func TestHandler_FailureIsRecorded(t *testing.T) {
	ResetForTest()
	t.Cleanup(ResetForTest)

	reg := NewRegistry()
	reg.Sync([]SyncSpec{{ID: "svc1"}})
	SetRegistry(reg)

	cx := layer4.WrapConnection(&fakeConn{}, []byte{}, nil)
	next := layer4.HandlerFunc(func(*layer4.Connection) error {
		return errors.New("backend refused")
	})

	if err := (Handler{ServiceID: "svc1"}).Handle(cx, next); err == nil {
		t.Fatal("the handler must not swallow the error")
	}
	got := reg.Snapshot()["svc1"]
	if got.Errors != 1 {
		t.Fatalf("errors: %+v", got)
	}
	if got.Active != 0 {
		t.Fatalf("the gauge must come back down after a failure: %+v", got)
	}
}

// --- v2.43 — bytes are visible while the connection is open ------
//
// The regression this pins: the counters used to be accumulated in
// the connection wrapper and reported once, at close. A phone's IMAP
// session stays open for hours, so the traffic column read 0 B for a
// relay that was busy the whole time — the operator saw an idle
// service and a working one as the same thing.
func TestRecorder_BytesVisibleBeforeClose(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]SyncSpec{{ID: "svc1"}})
	reg.Opened("svc1")

	rec := reg.RecorderFor("svc1")
	rec.AddIn(64)
	rec.AddOut(1024)

	// Still open: the gauge says so, and the bytes are already there.
	snap := reg.Snapshot()["svc1"]
	if snap.Active != 1 {
		t.Fatalf("the connection must still count as open: %+v", snap)
	}
	if snap.BytesIn != 64 || snap.BytesOut != 1024 {
		t.Fatalf("bytes must be visible before close: %+v", snap)
	}

	// More traffic on the same live connection keeps accumulating.
	rec.AddIn(36)
	if got := reg.Snapshot()["svc1"].BytesIn; got != 100 {
		t.Fatalf("bytesIn after a second read: got %d, want 100", got)
	}

	reg.Closed("svc1")
	if got := reg.Snapshot()["svc1"]; got.Active != 0 || got.BytesIn != 100 {
		t.Fatalf("close must only move the gauge: %+v", got)
	}
}
