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
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Per spec §3.1 and §3.5: dotted module ID for Caddy's internal
// module system, plain handler name for the JSON config.
const (
	// ModuleID is the full dotted module identifier registered with
	// Caddy. Spec §3.1.
	ModuleID = "http.handlers.arenet_routemetrics"

	// HandlerName is the last segment of ModuleID, used as the
	// "handler" string in Caddy JSON config (spec §3.5). Mixing forms
	// (passing ModuleID instead of HandlerName in JSON) silently
	// fails Caddy config load with an "unknown handler" error.
	HandlerName = "arenet_routemetrics"
)

// ErrRegistryNotInstalled is returned by Provision when no Registry
// has been installed via SetRegistry. Indicates a programmer error
// in main(): the wiring order must be NewRegistry → SetRegistry →
// caddymgr.Start. Exported so tests can match with errors.Is.
var ErrRegistryNotInstalled = errors.New(
	"metrics: registry not installed; call SetRegistry before caddymgr.Start",
)

// NormalSubmitter is the seam V.1.2 calls on every eligible
// successful request. Declared in this package (not as
// internal/geo.NormalSink) so the metrics module has zero
// import-time dependency on internal/geo. The production
// type *geo.DefaultNormalSink satisfies this interface
// structurally; V.1.3 installs it via SetNormalSubmitter
// in cmd/arenet/main.go.
//
// Tests substitute a stub without needing the geo package
// (no MMDB, no LRU, no Bus).
//
// The signature is (status, srcIP, routeID) — 3 args, no
// method. The D1 method gate (HEAD/OPTIONS rejected) runs
// in eligibleForNormal BEFORE Submit is called, so the
// sink doesn't need to re-check it.
type NormalSubmitter interface {
	Submit(status int, srcIP, routeID string)
}

// ClientIPFunc is the seam for extracting the trusted-proxy-
// aware client IP from a request. cmd/arenet wires the real
// implementation (backed by auth.IPExtractor honoring
// ARENET_TRUSTED_PROXIES); the package default
// RemoteAddrClientIPFn is a degraded fallback that strips
// the port from r.RemoteAddr — correct for direct-deployed
// homelabs, wrong when arenet sits behind another proxy.
type ClientIPFunc func(r *http.Request) string

// RemoteAddrClientIPFn is the default ClientIPFunc used when
// SetClientIPFn was never called. Strips the port from
// r.RemoteAddr; returns the raw string if it can't be
// parsed (e.g. AF_UNIX socket — shouldn't happen for
// arenet's HTTP listeners but kept defensive).
func RemoteAddrClientIPFn(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// hardcodedExcludePaths is the spec §D3 "non-overridable"
// path-prefix blocklist. Operator's
// ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS extends, doesn't
// replace, this list.
//
//   - /healthz: orchestrator probes, not user traffic.
//   - /metrics: Prometheus scrape, not user traffic.
//   - /api/v1/ws/topology: the live topology WS stream;
//     the operator's own dashboard tab opens this on every
//     /topology page mount.
//   - /api/v1/ws/geo-events: the V.3 WS stream that
//     delivers the very arcs we're about to emit. Without
//     this exclusion, opening /map triggers a WS upgrade
//     → arenet emits a "normal" event for the upgrade →
//     enricher publishes the event back over the same WS
//     → operator sees their own connection arc on the
//     map. Pre-empted per the V.1 spec freeze §7 finding
//     (commit e87269f).
var hardcodedExcludePaths = []string{
	"/healthz",
	"/metrics",
	"/api/v1/ws/topology",
	"/api/v1/ws/geo-events",
}

// HardcodedExcludePaths returns a defensive copy of the V.1
// non-overridable path-prefix list. Exported for the V.1.3
// boot signal (cmd/arenet logs the count alongside the
// operator-configured list count) + future docs / admin-
// UI surfaces. The returned slice is safe to mutate.
func HardcodedExcludePaths() []string {
	out := make([]string, len(hardcodedExcludePaths))
	copy(out, hardcodedExcludePaths)
	return out
}

func init() {
	caddy.RegisterModule(RouteMetricsHandler{})
}

// RouteMetricsHandler is the Caddy middleware module that counts
// requests per route (spec §3). Caddy provisions one instance per
// route from the JSON config produced by internal/caddymgr; each
// instance carries its own RouteID. Provision fetches the
// process-wide *Registry via the package-level singleton (spec §3.4).
type RouteMetricsHandler struct {
	// RouteID is the storage UUID of the route this handler is
	// attached to. Set from JSON config. Required (Validate rejects
	// empty).
	RouteID string `json:"route_id,omitempty"`

	// ExcludePaths is the operator-configurable path-prefix
	// blocklist for V.1 normal-traffic emission (spec §D3).
	// Extends (does NOT replace) hardcodedExcludePaths. Each
	// entry is matched as a prefix against r.URL.Path. Set
	// from JSON config — caddymgr threads the env-var
	// extension into the route-handler emit.
	//
	// Empty (default) means only the hardcoded list applies.
	ExcludePaths []string `json:"exclude_paths,omitempty"`

	// KnownHosts is the lowercase set of hostnames this route
	// authoritatively serves (primary Host + every alias).
	// Topology Plan B Phase 1 addition.
	//
	// Used by ServeHTTP to gate the per-host counter bump in
	// Registry.IncByHost — a request whose r.Host (lowercased,
	// port-stripped) is NOT in this set still bumps the route
	// counter but is dropped from the host counter, defending
	// against DNS-rebinding probes / direct-IP requests / bad
	// routing configs from polluting the per-alias histogram
	// with garbage hostnames.
	//
	// Empty / absent (pre-Plan-B Caddy config) makes the
	// middleware fall back to the legacy Inc path (route counter
	// only, no host bump). This preserves byte-equality with
	// pre-Plan-B configs for routes the caller hasn't yet
	// extended.
	//
	// Caddymgr is responsible for lowercasing every entry at
	// emit time; the middleware does NOT re-normalise to keep
	// the hot path lookup O(1) via a map cached in Provision.
	KnownHosts []string `json:"known_hosts,omitempty"`

	// registry is resolved at Provision time. Not serialized: Caddy
	// instantiates modules from JSON and cannot inject Go pointers
	// (spec §3.4).
	registry *Registry

	// knownHostSet is the O(1) lookup view of KnownHosts, built
	// once at Provision. nil when KnownHosts is empty / absent
	// (legacy path: no per-host bump). Topology Plan B Phase 1.
	knownHostSet map[string]struct{}

	// V.1.3 install-order constraint: the geo bus +
	// enricher + DefaultNormalSink are constructed in
	// cmd/arenet/main.go AFTER mgr.Start, so at Provision
	// time the globals are still nil. To make late
	// installation visible to already-provisioned
	// handlers, normalSink + clientIP are read LIVE from
	// the global atomic pointers on every eligible
	// request (see ServeHTTP defer). Per-request reads
	// are lock-free atomic.Load — nanoseconds. The branch
	// is short-circuited anyway when the value is nil,
	// so the V.1-disabled path stays effectively zero-cost.
}

// CaddyModule returns the module info. Required by the Caddy module
// interface. Value receiver because Caddy calls this on a zero
// value to discover the type.
func (RouteMetricsHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(RouteMetricsHandler) },
	}
}

// Provision is called once per handler instance after the JSON
// config is loaded and before Validate. Resolves the process-wide
// Registry or returns ErrRegistryNotInstalled.
//
// V.1.2 + V.1.3: the optional NormalSubmitter + ClientIPFn
// are NOT cached at Provision — they're resolved live on
// every request via atomic.Pointer reads. See the
// install-order rationale on the struct comment above.
func (h *RouteMetricsHandler) Provision(_ caddy.Context) error {
	r := GlobalRegistry()
	if r == nil {
		return ErrRegistryNotInstalled
	}
	h.registry = r
	// Phase 1 — build the O(1) host lookup. Caddymgr is
	// expected to emit lowercased entries; we tolerate mixed
	// case defensively (strings.ToLower is a no-op on already-
	// lowercase input, so the cost is negligible). nil-keep
	// when no entries so ServeHTTP can short-circuit cheaply.
	if len(h.KnownHosts) > 0 {
		h.knownHostSet = make(map[string]struct{}, len(h.KnownHosts))
		for _, k := range h.KnownHosts {
			h.knownHostSet[strings.ToLower(k)] = struct{}{}
		}
	}
	return nil
}

// Validate checks the resolved configuration. Rejects empty RouteID
// (spec §3.1): a handler with no RouteID would silently miscount
// every request as belonging to "" in the registry map.
func (h *RouteMetricsHandler) Validate() error {
	if h.RouteID == "" {
		return errors.New(
			"metrics: route_id is required on arenet_routemetrics handler",
		)
	}
	return nil
}

// ServeHTTP wraps the response writer in a statusRecorder, defers
// the counter increment so it observes the final status code, then
// dispatches to the next handler in the chain (typically
// reverse_proxy). Spec §3.3.
//
// The defer uses a closure rather than a direct call so the status
// code is read AFTER next.ServeHTTP has returned. A direct
// `defer h.registry.Inc(h.RouteID, rec.status)` would capture the
// default 200 at defer time, losing every non-200 status.
//
// The recorded status comes from metricsStatus: when next returns
// an error before writing (reverse_proxy 502 on a dead upstream,
// IP filter / basic auth / rate limit / CrowdSec blocks), it is the
// status Caddy will send for that error — NOT the recorder's
// default 200 (v2.26 fix; this supersedes Step E spec §11.6, whose
// "implicit 200" premise does not hold once Caddy serves the error).
func (h *RouteMetricsHandler) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
) (err error) {
	start := time.Now()
	rec := newStatusRecorder(w, start)
	// Phase 1 — capture r.Host now (before next.ServeHTTP
	// runs). Some downstream handlers may mutate the request
	// header set; reading at entry pins the value the matcher
	// originally dispatched on. The host is also resolved
	// against the route's KnownHosts BEFORE the defer fires so
	// the per-host bump only happens for recognised hosts.
	matchedHost := h.resolveHost(r)
	defer func() {
		status := metricsStatus(rec, err)
		durMs := float64(time.Since(start).Microseconds()) / 1000.0
		// Phase 1 — IncByHost replaces Inc. When matchedHost
		// is "" (legacy KnownHosts-empty path OR host header
		// failed membership check), IncByHost bumps the route
		// counter only — identical to the pre-Phase-1 Inc
		// behavior. So this swap is wire-compatible for every
		// route that doesn't yet have KnownHosts emitted.
		h.registry.IncByHost(h.RouteID, matchedHost, status, durMs)

		// V.1.2 / V.1.3 — normal-traffic geo emission. Read
		// the sink LIVE from the global atomic pointer; a
		// nil result means V.1 is disabled (operator never
		// set ARENET_NORMAL_TRAFFIC_SAMPLE_PCT, or set it
		// to 0). The atomic.Load is lock-free; the
		// short-circuit on nil keeps the V.1-disabled path
		// effectively zero-cost. Gates here are SHORT-
		// CIRCUITS (status / method / path); the sink owns
		// the D2 LAN + D9 sampling/cooldown decisions.
		if sink := GlobalNormalSubmitter(); sink != nil && h.eligibleForNormal(r, status) {
			sink.Submit(status, GlobalClientIPFn()(r), h.RouteID)
		}
	}()
	err = next.ServeHTTP(rec, r)
	// v2.62 — copy the denying gate's verdict into the access log.
	//
	// This handler is already first in every route's chain and already
	// wraps the response, so it is the natural place: no extra handler,
	// no shift of the chain every other test pins, and one fewer
	// middleware per route.
	//
	// It replaces a first attempt that emitted Caddy's own
	// http.handlers.log_append. That worked, but it inserted a handler
	// at position 1 and broke fifteen chain-order tests — and it wrote
	// the field as an EMPTY value on every allowed request, because
	// log_append adds the field unconditionally (logappend.go:158).
	// Doing it here lets the field be absent when nothing denied,
	// which is what an operator grepping their log actually wants.
	_ = appendDenialLogField(r)
	return err
}

// appendDenialLogField writes the arenet_denied field into the access
// log when a gate set DeniedVarKey on this request, and writes nothing
// otherwise.
//
// A LOG FIELD and not a response header, deliberately: a header would
// be trivial but would tell a prober which gate stopped them, which is
// information that helps them tune. Caddy installs the extra-log-field
// holder on every request context (caddy/v2@v2.11.4
// modules/caddyhttp/server.go:998) and the access log encoder reads it,
// so nothing reaches the client.
//
// The need came from a production incident on 2026-10-04: two members
// were banned by CrowdSec and establishing why took an afternoon,
// because a 403 served by Arenet's WAF is byte-indistinguishable in the
// access log from a 403 served by the backend.
// It returns the reason it wrote, or "" when it wrote nothing, so the
// decision is testable: caddyhttp.ExtraLogFields keeps its field slice
// unexported, so a test cannot read back what Add received. The branches
// are where the bugs would live anyway — var unset, wrong type, holder
// missing — and Add itself is Caddy's, already covered upstream.
func appendDenialLogField(r *http.Request) string {
	ctx := r.Context()
	reason, ok := caddyhttp.GetVar(ctx, DeniedVarKey).(string)
	if !ok || reason == "" {
		return ""
	}
	extra, ok := ctx.Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields)
	if !ok || extra == nil {
		// Defensive: only absent if something upstream replaced the
		// request context. Losing a log field must never cost a
		// request.
		return ""
	}
	extra.Add(zap.String(DeniedLogField, reason))
	return reason
}

// DeniedVarKey is the Caddy var an Arenet gate sets when it refuses a
// request; DeniedLogField is the key it appears under in the access
// log. Mirrored in internal/waf and internal/countryblock, which must
// not import this package either — a test in caddymgr pins that every
// copy agrees.
const (
	DeniedVarKey   = "arenet_denied"
	DeniedLogField = "arenet_denied"
)

// statusSecurityBlock is the status recorded for a request ended by a
// security block that owns its own counter (WAF): it counts in reqs
// but in neither the 4xx nor the 5xx class (IncByHost classifies
// only >= 400), and fails the normal-traffic gate (< 200).
const statusSecurityBlock = 0

// securityBlock is implemented by errors of security gates whose
// blocks are counted by their own pipeline and must stay out of the
// 4xx/5xx classes — the WAF (Step M spec AC #4: a WAF block
// increments waf_block_count and req_count only). Matched by
// behaviour so this package imports none of those gates.
type securityBlock interface {
	SecurityBlock() bool
}

// metricsStatus returns the status to record for a request, given
// what the recorder saw and the error next returned.
//
//   - A securityBlock error → statusSecurityBlock, even when the
//     block status was already written (WAF response-phase blocks).
//   - Any other error before anything was written → the status Caddy
//     sends for it: HandlerError.StatusCode, 500 otherwise (caddy
//     v2.11.4 modules/caddyhttp/server.go:448-451, and errors.go
//     Error() for the StatusCode default). Caddy serves the error
//     response AFTER this middleware returns (server.go:421), so the
//     recorder never sees that status itself.
//   - Otherwise → the recorded status (implicit 200 when the handler
//     wrote a body without WriteHeader, or wrote nothing and
//     returned nil).
func metricsStatus(rec *statusRecorder, err error) int {
	if err == nil {
		return rec.status
	}
	var sb securityBlock
	if errors.As(err, &sb) && sb.SecurityBlock() {
		return statusSecurityBlock
	}
	if rec.headerWritten {
		return rec.status
	}
	var he caddyhttp.HandlerError
	if errors.As(err, &he) && he.StatusCode != 0 {
		return he.StatusCode
	}
	return http.StatusInternalServerError
}

// eligibleForNormal applies the spec §D1 + §D3 gates that
// run UPSTREAM of the sink. Pure function (method on
// handler only for the ExcludePaths field access);
// testable in isolation.
//
// Reject rules (in order):
//   - status outside [200, 399]                       (D1)
//   - status == 304                                   (D1)
//   - status < 200 (1xx — e.g. 101 Switching Protocols WS upgrade) (D1)
//   - method == HEAD                                  (D1)
//   - method == OPTIONS                               (D1)
//   - r.URL.Path has a prefix in hardcodedExcludePaths (D3)
//   - r.URL.Path has a prefix in h.ExcludePaths        (D3)
//
// All other status/method/path combinations are eligible;
// the sink's gates (D2 LAN, D9 sampling/cooldown) decide
// whether to emit.
func (h *RouteMetricsHandler) eligibleForNormal(r *http.Request, status int) bool {
	// D1 — status class. Reject 1xx, 4xx, 5xx (and the
	// 304-NotModified asset-cache hit per spec §D1).
	if status < 200 || status >= 400 || status == http.StatusNotModified {
		return false
	}
	// D1 — method. Reject probes / preflights.
	if r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	// D3 — hardcoded path exclusion (non-overridable).
	path := r.URL.Path
	for _, p := range hardcodedExcludePaths {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	// D3 — operator-configured path exclusion (extension).
	for _, p := range h.ExcludePaths {
		if strings.HasPrefix(path, p) {
			return false
		}
	}
	return true
}

// resolveHost extracts the lowercased + port-stripped host from
// r.Host and validates it against the route's KnownHosts set.
// Returns the canonical host on a successful match, or "" when:
//   - the route has no KnownHosts emitted (legacy / pre-Phase-1
//     Caddy config — the middleware then bumps the route counter
//     only via IncByHost("", ...))
//   - r.Host is empty (HTTP/0.9 or malformed request)
//   - the lowercased host is not in the KnownHosts set
//     (DNS-rebinding probe, direct-IP request, bad routing config)
//
// Topology Plan B Phase 1. Pure function on the handler's cached
// knownHostSet; no allocation in the steady state when the host
// is already lowercase and has no port suffix (the strings.Index
// + ToLower compare are cheap fast-path checks).
func (h *RouteMetricsHandler) resolveHost(r *http.Request) string {
	if h.knownHostSet == nil || r.Host == "" {
		return ""
	}
	raw := r.Host
	// Strip port if present. net.SplitHostPort errors when the
	// input has no colon (the common case for HTTPS where Caddy
	// strips the port before the handler), so fall through to
	// the raw value when split fails.
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	// IPv6 literals arrive as "[::1]:443" which SplitHostPort
	// returns as "::1" with no brackets — already correct.
	// Bare IPv6 in r.Host (rare, but RFC-permitted) like "[::1]"
	// stays bracketed; we lowercase + lookup as-is.
	host := strings.ToLower(raw)
	if _, ok := h.knownHostSet[host]; !ok {
		return ""
	}
	return host
}

// Interface guards: compile-time assertions of the Caddy interfaces
// we implement. If Caddy's API changes incompatibly, this breaks at
// compile time rather than at first request.
var (
	_ caddy.Provisioner           = (*RouteMetricsHandler)(nil)
	_ caddy.Validator             = (*RouteMetricsHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*RouteMetricsHandler)(nil)
)

// --- statusRecorder --------------------------------------------------------

// statusRecorder wraps an http.ResponseWriter to remember the status
// code written by an inner handler. Forwards Hijacker / Flusher /
// Pusher to the wrapped writer when supported; degrades gracefully
// (ErrNotSupported / no-op) otherwise — spec §3.3.
//
// Default status is http.StatusOK to match Caddy's implicit-OK
// behavior when the inner handler returns without explicitly setting
// a status code (spec §11.6).
type statusRecorder struct {
	http.ResponseWriter
	status        int
	headerWritten bool

	// start is the instant the middleware took the request, used to
	// stamp ttfbMs below.
	start time.Time

	// ttfbMs is the time to the response's FIRST byte — strictly, to
	// the moment the response commits, which is the first WriteHeader
	// or the first Write, whichever an inner handler reaches first.
	//
	// It exists because the total duration this middleware already
	// records includes the whole response body transfer, so it answers
	// a different question than operators think it does. Measured on a
	// real instance: the same asset served in 0.108 s TTFB and 0.326 s
	// total to a fast client appeared in the access log at 24 s for a
	// slow one. The server was never slow; nothing in the metric could
	// say so.
	//
	// TTFB is the upstream-responsiveness number. Total duration stays
	// too, because "what are my visitors actually experiencing" is a
	// real question — it is just not the same question.
	//
	// Read it with ttfbCommitted, never by testing for zero. A
	// response that commits in under a microsecond measures 0.000 ms
	// after the integer-microsecond division, so zero is a legitimate
	// value AND would be the obvious sentinel — exactly the
	// absent-versus-zero conflation this whole change exists to
	// remove. The gate caught it on the first run: WriteHeader stamped
	// 0.000, the guard read that as "not stamped", and the next Write
	// re-stamped at 151 ms, putting a slow client's transfer time
	// straight into the number built to exclude it.
	ttfbMs        float64
	ttfbCommitted bool

	// bytesOut counts response body bytes that passed through Write.
	// Volume was recorded nowhere, so the cause of a slow transfer —
	// on the instance above, a 2.9 MB file — was reachable only by
	// running jq over a raw access log. A reverse proxy that cannot
	// report its own egress cannot explain its own latency.
	//
	// Excludes response headers, and excludes anything written after a
	// Hijack: see hijacked.
	bytesOut uint64

	// hijacked records that the connection was taken over, which is
	// what a WebSocket upgrade does.
	//
	// After Hijack there is no WriteHeader and no Write, so TTFB and
	// bytesOut are unobservable here BY CONSTRUCTION — not merely
	// missing. The count is surfaced rather than letting those
	// requests read as a 0 ms response of 0 bytes, which is the kind
	// of silent zero this whole change exists to stop.
	hijacked bool
}

func newStatusRecorder(w http.ResponseWriter, start time.Time) *statusRecorder {
	return &statusRecorder{
		ResponseWriter: w,
		status:         http.StatusOK,
		start:          start,
	}
}

// commit stamps the time-to-first-byte on the first response write.
// Called from both WriteHeader and Write, because only one of them
// fires first and either one means the response has begun.
func (s *statusRecorder) commit() {
	if s.ttfbCommitted {
		return
	}
	s.ttfbCommitted = true
	s.ttfbMs = float64(time.Since(s.start).Microseconds()) / 1000.0
}

// WriteHeader captures the status code on the first call. Subsequent
// calls follow the http.ResponseWriter contract (Go stdlib emits a
// "superfluous WriteHeader" log on double calls); we mirror that by
// keeping the first status and forwarding only the first call.
func (s *statusRecorder) WriteHeader(code int) {
	if s.headerWritten {
		// Per Go contract, subsequent WriteHeader calls are no-ops on
		// the wire. Forward anyway so the underlying writer can log
		// "superfluous" if it wishes.
		s.ResponseWriter.WriteHeader(code)
		return
	}
	s.status = code
	s.headerWritten = true
	s.commit()
	s.ResponseWriter.WriteHeader(code)
}

// Write implies WriteHeader(200) if WriteHeader has not been called
// (per net/http contract). We mark headerWritten so a later explicit
// WriteHeader is treated as superfluous, matching stdlib behavior.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.headerWritten {
		s.headerWritten = true
		// status already 200 from newStatusRecorder.
	}
	s.commit()
	n, err := s.ResponseWriter.Write(b)
	// Count what actually reached the wire, not what was offered: a
	// short write on a client that hung up mid-body must not be
	// reported as bytes delivered.
	if n > 0 {
		s.bytesOut += uint64(n)
	}
	return n, err
}

// Hijack forwards to the wrapped writer if it supports Hijacker, else
// returns http.ErrNotSupported. WebSocket upgrades through proxied
// routes need this path; without it, gorilla/websocket Upgrade
// would error out at our handler.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := h.Hijack()
		if err == nil {
			// Everything after this point bypasses Write, so TTFB and
			// bytesOut stop being observable. Record that fact instead
			// of reporting their zero values as measurements.
			s.hijacked = true
		}
		return conn, rw, err
	}
	return nil, nil, http.ErrNotSupported
}

// Flush forwards if supported, else no-op. SSE handlers under a
// proxied route would call Flush; we must not panic on a writer that
// does not support it.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Push forwards if supported (HTTP/2 server push), else returns
// http.ErrNotSupported. Caddy passes through writers that may or may
// not implement Pusher depending on the request's protocol.
func (s *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := s.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// Status returns the recorded status code. After ServeHTTP returns,
// this is the final status the client will see (or http.StatusOK if
// the handler emitted no explicit code).
func (s *statusRecorder) Status() int {
	return s.status
}
