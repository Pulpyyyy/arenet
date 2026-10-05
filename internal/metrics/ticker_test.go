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
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

// staticLister is a deterministic RouteLister for tests.
type staticLister struct {
	routes []RouteMetadata
	err    error
}

func (l *staticLister) ListRoutesForMetrics(_ context.Context) ([]RouteMetadata, error) {
	return l.routes, l.err
}

func TestNewTicker_NilRegistry_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil registry")
		}
	}()
	NewTicker(nil, NewBroadcaster(quietLogger()), &staticLister{})
}

func TestNewTicker_NilBroadcaster_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil broadcaster")
		}
	}()
	NewTicker(NewRegistry(), nil, &staticLister{})
}

func TestNewTicker_NilLister_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on nil lister")
		}
	}()
	NewTicker(NewRegistry(), NewBroadcaster(quietLogger()), nil)
}

func TestTicker_MakeSnapshot_JoinsDeltasWithRoutes(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1", "r2"})
	r.Inc("r1", Observation{Status: 200, DurMs: 0})
	r.Inc("r1", Observation{Status: 200, DurMs: 0})
	r.Inc("r2", Observation{Status: 503, DurMs: 0})

	lister := &staticLister{
		routes: []RouteMetadata{
			{ID: "r1", Host: "app.example", Upstream: "http://10.0.0.1:80"},
			{ID: "r2", Host: "api.example", Upstream: "http://10.0.0.2:80"},
		},
	}
	tk := NewTicker(r, NewBroadcaster(quietLogger()), lister)

	snap := tk.makeSnapshot(context.Background(), time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC))

	if len(snap.Routes) != 2 {
		t.Fatalf("Routes len=%d want 2", len(snap.Routes))
	}
	byID := map[string]RouteSnapshot{}
	for _, rt := range snap.Routes {
		byID[rt.ID] = rt
	}
	if byID["r1"].Reqs != 2 || byID["r1"].Errs != 0 {
		t.Errorf("r1=%+v", byID["r1"])
	}
	if byID["r1"].Host != "app.example" {
		t.Errorf("r1 metadata not joined: host=%q", byID["r1"].Host)
	}
	if byID["r2"].Reqs != 1 || byID["r2"].Errs != 1 {
		t.Errorf("r2=%+v", byID["r2"])
	}
	if byID["r2"].ErrRate5xx != 1.0 {
		t.Errorf("r2.ErrRate5xx=%v want 1.0", byID["r2"].ErrRate5xx)
	}
}

func TestTicker_MakeSnapshot_IdleRoutesIncluded(t *testing.T) {
	// Spec §5.2: routes with zero traffic still appear with zero
	// counters.
	r := NewRegistry()
	r.Sync([]string{"r1"})
	// No Inc — r1 is idle.

	lister := &staticLister{
		routes: []RouteMetadata{
			{ID: "r1", Host: "idle.example", Upstream: "http://10.0.0.1:80"},
		},
	}
	tk := NewTicker(r, NewBroadcaster(quietLogger()), lister)
	snap := tk.makeSnapshot(context.Background(), time.Now())

	if len(snap.Routes) != 1 {
		t.Fatalf("idle route missing from snapshot")
	}
	if snap.Routes[0].Reqs != 0 || snap.Routes[0].Errs != 0 {
		t.Errorf("idle counters non-zero: %+v", snap.Routes[0])
	}
}

func TestTicker_MakeSnapshot_ListerError_EmptyRoutes(t *testing.T) {
	r := NewRegistry()
	r.Sync([]string{"r1"})
	r.Inc("r1", Observation{Status: 200, DurMs: 0})

	lister := &staticLister{err: errors.New("storage down")}
	tk := NewTicker(r, NewBroadcaster(quietLogger()), lister)

	snap := tk.makeSnapshot(context.Background(), time.Now())
	if snap.Routes == nil {
		t.Fatal("Routes is nil; want empty non-nil")
	}
	if len(snap.Routes) != 0 {
		t.Errorf("Routes len=%d want 0 (lister error)", len(snap.Routes))
	}
}

func TestTicker_MakeSnapshot_ClampsErrRate(t *testing.T) {
	// Spec §11.8: if errs > reqs (rare swap race), errRate5xx
	// MUST be clamped to 1.0.
	r := NewRegistry()
	r.Sync([]string{"r1"})

	// Directly manipulate counters to simulate the rare race condition
	// where errs > reqs. (In production, atomic ops would produce this
	// transiently between the two SwapUint64 calls.)
	r.cells["r1"].reqs = 10
	r.cells["r1"].errs = 99 // pathological

	lister := &staticLister{
		routes: []RouteMetadata{{ID: "r1", Host: "h", Upstream: "u"}},
	}
	tk := NewTicker(r, NewBroadcaster(quietLogger()), lister)

	snap := tk.makeSnapshot(context.Background(), time.Now())
	if snap.Routes[0].ErrRate5xx != 1.0 {
		t.Errorf("errRate=%v want 1.0 (clamped)", snap.Routes[0].ErrRate5xx)
	}
}

func TestTicker_MakeSnapshot_TimestampUTC(t *testing.T) {
	// Spec snapshot.go contract: T must be UTC.
	r := NewRegistry()
	tk := NewTicker(r, NewBroadcaster(quietLogger()), &staticLister{})

	loc, _ := time.LoadLocation("America/New_York")
	nyc := time.Date(2026, 5, 18, 12, 0, 0, 0, loc)

	snap := tk.makeSnapshot(context.Background(), nyc)
	if snap.T.Location() != time.UTC {
		t.Errorf("snap.T location=%v want UTC (input was NYC)", snap.T.Location())
	}
}

func TestTicker_Run_PublishesAtTickInterval(t *testing.T) {
	// synctest gives a virtual clock so we can advance simulated time
	// without sleeping for real wall-clock seconds. Available since
	// Go 1.25 (testing/synctest, GA).
	synctest.Test(t, func(t *testing.T) {
		r := NewRegistry()
		r.Sync([]string{"r1"})
		r.Inc("r1", Observation{Status: 200, DurMs: 0})

		br := NewBroadcaster(quietLogger())
		s := br.Subscribe()

		lister := &staticLister{
			routes: []RouteMetadata{{ID: "r1", Host: "h", Upstream: "u"}},
		}
		tk := NewTicker(r, br, lister)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go tk.Run(ctx)

		// Advance the virtual clock by exactly TickInterval. The
		// Ticker fires once.
		time.Sleep(TickInterval)
		synctest.Wait()

		select {
		case snap := <-s.Ch:
			if len(snap.Routes) != 1 || snap.Routes[0].Reqs != 1 {
				t.Errorf("snapshot wrong: %+v", snap)
			}
		default:
			t.Error("no snapshot received after TickInterval elapsed")
		}
	})
}

func TestTicker_Run_StopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := NewRegistry()
		br := NewBroadcaster(quietLogger())
		lister := &staticLister{}
		tk := NewTicker(r, br, lister)

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			tk.Run(ctx)
			close(done)
		}()

		cancel()
		synctest.Wait()

		select {
		case <-done:
			// expected
		default:
			t.Error("Run did not exit promptly on cancel")
		}
	})
}
