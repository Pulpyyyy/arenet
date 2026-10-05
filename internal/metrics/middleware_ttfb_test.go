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

// Gates G3, G4, G6 and G8 of the 2026-10-05 latency-truth design.
//
// The question these answer is the one an operator asked after reading
// "p95 6701 ms" on a blog that loads instantly: what exactly is being
// measured? The answer was "everything, including the visitor's
// download", and the proof was in their own access log — the same asset
// at 0.108 s TTFB / 0.326 s total for a fast client, and 24 s for a slow
// one. Same server, same file, same path.

package metrics

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// slowWriter is a ResponseWriter whose Write blocks, standing in for a
// client reading the body over a weak connection. Nothing about the
// server is slow here; only the transfer is.
type slowWriter struct {
	http.ResponseWriter
	delayPerWrite time.Duration
	shortBy       int // bytes to pretend were not accepted
	hijackErr     error
	hijacked      bool
}

func (w *slowWriter) Write(b []byte) (int, error) {
	time.Sleep(w.delayPerWrite)
	n := len(b) - w.shortBy
	if n < 0 {
		n = 0
	}
	return w.ResponseWriter.Write(b[:n])
}

func (w *slowWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijackErr != nil {
		return nil, nil, w.hijackErr
	}
	w.hijacked = true
	return nil, nil, nil
}

// TestTTFB_SlowClientDoesNotMoveTTFB is gate G3, and it is the one that
// cannot be faked: it needs a writer that genuinely blocks.
//
// The server commits its response immediately and then spends 300 ms
// pushing the body to a slow reader. Total duration must reflect that;
// TTFB must not. Conflating the two is what made a 0.1 s server look
// like a 24 s one.
func TestTTFB_SlowClientDoesNotMoveTTFB(t *testing.T) {
	start := time.Now()
	w := &slowWriter{ResponseWriter: httptest.NewRecorder(), delayPerWrite: 150 * time.Millisecond}
	rec := newStatusRecorder(w, start)

	rec.WriteHeader(http.StatusOK)
	ttfbAtCommit := rec.ttfbMs

	// Two slow writes: 300 ms of transfer on a response that was ready
	// at once.
	if _, err := rec.Write([]byte("first chunk")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := rec.Write([]byte("second chunk")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	totalMs := float64(time.Since(start).Microseconds()) / 1000.0

	if totalMs < 250 {
		t.Fatalf("total = %.1f ms, want >= 250 — the slow writer did not block, so this test proves nothing", totalMs)
	}
	if rec.ttfbMs > 50 {
		t.Errorf("TTFB = %.1f ms after %.1f ms of transfer; a slow client must not inflate it", rec.ttfbMs, totalMs)
	}
	if rec.ttfbMs != ttfbAtCommit {
		t.Errorf("TTFB changed after the response committed: %.3f -> %.3f ms", ttfbAtCommit, rec.ttfbMs)
	}
	t.Logf("server committed in %.3f ms, transfer took %.1f ms total — the gap this gate exists to expose", rec.ttfbMs, totalMs)
}

// TestTTFB_StampedByWriteWhenHeaderImplicit — a handler may never call
// WriteHeader. Write implies 200, and it is just as much the moment the
// response committed, so both paths have to stamp.
func TestTTFB_StampedByWriteWhenHeaderImplicit(t *testing.T) {
	rec := newStatusRecorder(httptest.NewRecorder(), time.Now())
	if rec.ttfbCommitted {
		t.Fatalf("committed before any write")
	}
	if _, err := rec.Write([]byte("body")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Asserted on the FLAG, not on the value: an implicit-200 Write
	// this fast legitimately measures 0.000 ms, so checking the value
	// would be checking the wrong thing — and is how the sentinel bug
	// got written in the first place.
	if !rec.ttfbCommitted {
		t.Error("not committed after an implicit-200 Write — only the WriteHeader path is stamping")
	}
}

// TestTTFB_SubMicrosecondResponseIsStillCommitted — zero is a real
// measurement here, not an absent one. Conflating them re-opens the
// bug where a slow client's transfer time overwrote a TTFB that had
// already been taken.
func TestTTFB_SubMicrosecondResponseIsStillCommitted(t *testing.T) {
	rec := newStatusRecorder(httptest.NewRecorder(), time.Now())
	rec.WriteHeader(http.StatusOK)
	if !rec.ttfbCommitted {
		t.Fatal("not committed after WriteHeader")
	}
	before := rec.ttfbMs
	time.Sleep(40 * time.Millisecond)
	_, _ = rec.Write([]byte("body sent much later"))
	if rec.ttfbMs != before {
		t.Errorf("TTFB moved from %.3f to %.3f ms; a 0.000 ms commit was mistaken for no commit at all", before, rec.ttfbMs)
	}
}

// TestTTFB_NotOverwrittenBySecondWrite — TTFB is time to the FIRST
// byte. A long streaming response must not keep pushing it later.
func TestTTFB_NotOverwrittenBySecondWrite(t *testing.T) {
	rec := newStatusRecorder(httptest.NewRecorder(), time.Now())
	_, _ = rec.Write([]byte("a"))
	first := rec.ttfbMs
	time.Sleep(30 * time.Millisecond)
	_, _ = rec.Write([]byte("b"))
	if rec.ttfbMs != first {
		t.Errorf("TTFB moved from %.3f to %.3f ms on a later write", first, rec.ttfbMs)
	}
}

// TestTTFB_NeverExceedsTotal is gate G4. Reported together, a TTFB
// above the total duration would be visibly impossible and would
// discredit both numbers.
func TestTTFB_NeverExceedsTotal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		drive func(rec *statusRecorder)
	}{
		{"explicit 204, no body", func(rec *statusRecorder) { rec.WriteHeader(http.StatusNoContent) }},
		{"implicit 200 with body", func(rec *statusRecorder) { _, _ = rec.Write([]byte("hello")) }},
		{"error status then body", func(rec *statusRecorder) {
			rec.WriteHeader(http.StatusBadGateway)
			_, _ = rec.Write([]byte("upstream is gone"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			rec := newStatusRecorder(httptest.NewRecorder(), start)
			tc.drive(rec)
			totalMs := float64(time.Since(start).Microseconds()) / 1000.0
			if rec.ttfbMs > totalMs {
				t.Errorf("TTFB %.3f ms exceeds total %.3f ms", rec.ttfbMs, totalMs)
			}
		})
	}
}

// TestTTFB_NothingWrittenIsNotCommitted — a handler that returns an
// error without writing produced no response, so there is no
// time-to-first-byte at all.
//
// The distinction the caller needs is "never committed", read off the
// flag. Not "zero", which is also what a sub-microsecond response
// measures — the conflation that put a slow client's 151 ms into a
// TTFB already taken.
func TestTTFB_NothingWrittenIsNotCommitted(t *testing.T) {
	rec := newStatusRecorder(httptest.NewRecorder(), time.Now())
	time.Sleep(5 * time.Millisecond)
	if rec.ttfbCommitted {
		t.Error("committed with nothing written — there is no first byte to time")
	}
	if rec.bytesOut != 0 {
		t.Errorf("bytesOut = %d with nothing written, want 0", rec.bytesOut)
	}
}

// TestBytesOut_CountsWhatReachedTheWire is gate G6.
func TestBytesOut_CountsWhatReachedTheWire(t *testing.T) {
	rec := newStatusRecorder(httptest.NewRecorder(), time.Now())
	_, _ = rec.Write(make([]byte, 1000))
	_, _ = rec.Write(make([]byte, 24))
	if rec.bytesOut != 1024 {
		t.Errorf("bytesOut = %d, want 1024", rec.bytesOut)
	}
}

// TestBytesOut_ShortWriteCountsOnlyWhatWasAccepted — a client that
// hangs up mid-body accepted fewer bytes than were offered. Counting
// the offer would overstate egress on exactly the requests most likely
// to be investigated.
func TestBytesOut_ShortWriteCountsOnlyWhatWasAccepted(t *testing.T) {
	w := &slowWriter{ResponseWriter: httptest.NewRecorder(), shortBy: 400}
	rec := newStatusRecorder(w, time.Now())
	n, err := rec.Write(make([]byte, 1000))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 600 {
		t.Fatalf("Write returned %d, want 600 (fixture assumption broken)", n)
	}
	if rec.bytesOut != 600 {
		t.Errorf("bytesOut = %d, want 600 — the offered length was counted instead of the accepted one", rec.bytesOut)
	}
}

// TestHijack_IsRecordedNotZeroed is gate G8.
//
// A WebSocket upgrade takes the connection over, after which neither
// WriteHeader nor Write is reached. TTFB and bytesOut are then
// unobservable BY CONSTRUCTION, and reporting their zero values as
// measurements would be the same silent-zero failure this whole change
// exists to stop.
func TestHijack_IsRecordedNotZeroed(t *testing.T) {
	w := &slowWriter{ResponseWriter: httptest.NewRecorder()}
	rec := newStatusRecorder(w, time.Now())

	if _, _, err := rec.Hijack(); err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if !rec.hijacked {
		t.Error("hijacked = false after a successful Hijack; the request would read as a 0 ms response of 0 bytes")
	}
	if rec.ttfbMs != 0 || rec.bytesOut != 0 {
		t.Errorf("ttfb=%v bytes=%d after Hijack; both are unobservable on this path and must stay zero so the hijacked flag is the only signal",
			rec.ttfbMs, rec.bytesOut)
	}
}

// TestHijack_FailureIsNotRecordedAsHijacked — a writer that cannot
// hijack leaves the response observable, so flagging it would discard
// measurements that do exist.
func TestHijack_FailureIsNotRecordedAsHijacked(t *testing.T) {
	rec := newStatusRecorder(httptest.NewRecorder(), time.Now())
	if _, _, err := rec.Hijack(); err == nil {
		t.Fatal("Hijack succeeded on a plain recorder; fixture assumption broken")
	}
	if rec.hijacked {
		t.Error("hijacked = true after a FAILED Hijack — the response is still observable on this path")
	}
}
