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

package countryblock

import (
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Per spec §D10 + §3.6: dotted module ID for Caddy's internal
// resolver, plain handler name for the JSON config. Mixing
// forms (passing ModuleID in the JSON "handler" field) silently
// fails Caddy config load with "unknown handler".
const (
	// ModuleID is the full dotted module identifier registered
	// with Caddy.
	ModuleID = "http.handlers.arenet_country_block"

	// HandlerName is the last segment of ModuleID, used as the
	// "handler" string in the caddymgr-emitted JSON config (W.3).
	HandlerName = "arenet_country_block"
)

// CountryLookup is the seam Handler uses to resolve a source
// IP to an ISO 3166-1 alpha-2 country code. The production
// implementation in W.3+ adapts internal/geo.Lookup via a
// thin wrapper that calls .LookupIP(net.ParseIP(srcIP)) and
// returns the .Country field (with the "LAN" sentinel mapped
// to "" so the matcher's RFC1918 bypass owns LAN detection).
//
// Tests substitute a stub without spinning up the MMDB. The
// seam keeps internal/countryblock free of the
// oschwald/geoip2-golang dependency.
type CountryLookup interface {
	// Lookup returns the ISO 3166-1 alpha-2 country code for
	// srcIP, or "" if the lookup failed or the IP is not in
	// the MMDB. Implementations MUST be safe for concurrent
	// use and MUST be non-blocking (called on the request
	// goroutine).
	Lookup(srcIP string) string
}

// GeoLookup is optionally implemented by a CountryLookup that can
// also resolve the continent (v2.27). Checked by type assertion so
// existing CountryLookup implementations keep working.
type GeoLookup interface {
	LookupGeo(srcIP string) GeoInfo
}

// BlockMatch is the value type the Handler passes to the
// BlockSink on every blocked request. W.1 originally
// shipped a 4-argument Submit; W.4 widened it to a struct
// so the sink can persist + enrich the full operator-
// meaningful context (Mode, Reason) without a 7-argument
// function call. Fields:
//
//   - Timestamp: when the block decision was reached.
//     Sink defaults to time.Now().UTC() when zero (defense
//     in depth — Handler stamps it explicitly).
//   - RouteID: the storage UUID of the route that gated.
//   - SourceIP: trusted-proxy-resolved client IP (see
//     GlobalClientIPFn).
//   - Country: ISO 3166-1 alpha-2 code from the MMDB
//     lookup. May be "" when the §D5 fail-open path
//     declined to block (not currently reachable —
//     fail-open accepts — but the field accommodates a
//     future ModeStrict).
//   - Mode: "allow" or "deny" — the route's enforcement
//     mode at the moment the block fired. Read from
//     Handler.Config.Mode; persisted so the activity-log
//     row can render "blocked by ALLOW list (country not
//     in FR,DE)" vs "blocked by DENY list (country is RU)".
//   - StatusCode: the HTTP status the Handler returned
//     (403/451/444 per spec §D3).
//   - Reason: the W.1 matcher reason enum (kebab-case —
//     "allow-miss" / "deny-match" / etc.). Surfaced
//     verbatim in the persisted row so the W.5 activity
//     log can render a tooltip without parsing free text.
//
// Host and ASN are intentionally NOT in this struct:
//   - Host: the Handler doesn't carry it (W.3 elided it
//     from the JSON config per its deviation #2). The W.5
//     frontend cross-references RouteID → host via the
//     existing routes API.
//   - ASN: V.1's MMDB is City-only; ASN would require the
//     separate GeoLite2-ASN.mmdb. Deferred to a future
//     step if operator feedback requires it.
type BlockMatch struct {
	Timestamp  time.Time
	RouteID    string
	SourceIP   string
	Country    string
	Mode       string
	StatusCode int
	Reason     string
}

// BlockSink is the seam Handler calls on every blocked request.
// The W.1 module ships only the call site; W.4 wires the real
// DefaultCountryBlockSink with sampling + cooldown + bus
// publish + country_block_event persistence.
//
// nil-safe: Handler short-circuits on a nil sink. A typical
// W.1-only deployment (sink not yet installed) sees blocks
// fire correctly but emits no observability events — operators
// gain the AC #2 / AC #3 enforcement immediately, AC #8 / AC #9
// arrive with W.4.
type BlockSink interface {
	// Submit is fire-and-forget: the sink owns sampling +
	// per-IP cooldown internally so the request goroutine never
	// stalls on event emission. The BlockMatch value carries
	// every field the sink needs for persistence + enrichment;
	// see the type doc-comment for field semantics.
	Submit(m BlockMatch)
}

// ErrLookupNotInstalled is returned by Provision when no
// CountryLookup has been installed via SetGlobalLookup.
// Indicates a programmer error in main(): the wiring order
// must be SetGlobalLookup → caddymgr.Start, mirroring the
// V.1.2 metrics SetRegistry contract.
//
// Exported so tests can match with errors.Is.
var ErrLookupNotInstalled = errors.New(
	"countryblock: lookup not installed; call SetGlobalLookup before caddymgr.Start",
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler is the Caddy middleware module that enforces the
// country-block gate. Caddy instantiates one per route from
// the JSON config produced by caddymgr (W.3); each instance
// carries its own embedded Config.
//
// Cross-route dependencies (CountryLookup, trustedIPs, sink,
// defaultStatusCode) are resolved LIVE on every request via
// atomic.Pointer reads against package-level globals — the V.1.3
// late-install pattern. Rationale: cmd/arenet constructs the
// geo Lookup and the sink AFTER mgr.Start (the boot order
// gates the storage layer first); a Handler instance
// Provisioned during mgr.Start sees nil globals at Provision
// time. Atomic.Pointer makes a later SetGlobalLookup call
// immediately visible on the next request.
//
// Per-request reads are lock-free atomic loads — nanoseconds —
// and a nil result short-circuits the gate (fail-open mirror
// of the V.1.2 RouteMetricsHandler's behavior).
type Handler struct {
	// Config is the per-route gate config (Mode + CountryList +
	// StatusCode). Set from JSON by Caddy; Provision calls
	// Validate to reject malformed config at load time.
	Config Config `json:"config"`

	// RouteID is the storage UUID of the route this handler
	// instance guards. Threaded by caddymgr (W.3) so the W.4
	// sink can attribute blocks per-route. Not strictly
	// required for W.1's gate logic, but Validate rejects an
	// empty RouteID to match the V.1.2 / WAF invariant
	// (silent miscount would surface only at the dashboard).
	RouteID string `json:"routeID,omitempty"`
}

// CaddyModule returns the module info. Required by the Caddy
// module interface. Value receiver because Caddy calls this
// on a zero value to discover the type (mirror of
// RouteMetricsHandler.CaddyModule).
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision validates the embedded Config and confirms a
// CountryLookup has been installed. The sink and trustedIPs
// globals are NOT checked here — both have nil-safe defaults
// (no sink = no events; no trustedIPs = only RFC1918 bypass).
//
// Provision runs once per Handler instance at Caddy config
// load time (every mgr.Apply triggers a fresh Provision pass).
// Re-validating on every reload guards against a hot-edit that
// landed an invalid config past the API layer.
func (h *Handler) Provision(_ caddy.Context) error {
	if err := h.Config.Validate(); err != nil {
		return err
	}
	if GlobalLookup() == nil {
		return ErrLookupNotInstalled
	}
	return nil
}

// Validate is the Caddy module Validate hook. Provision
// already calls Config.Validate; we re-run the RouteID check
// here so a future direct-validate path (a Caddy adapter test
// that calls Validate without Provision) still catches the
// invariant.
func (h *Handler) Validate() error {
	if h.RouteID == "" {
		return errors.New(
			"countryblock: routeID is required on arenet_country_block handler",
		)
	}
	return nil
}

// ServeHTTP is the gate. Flow:
//
//  1. Resolve src IP via the V.1.3 metrics.ClientIPFunc seam —
//     extracted out-of-band via GlobalClientIPFn (set by
//     cmd/arenet at boot). On nil, fall back to r.RemoteAddr
//     port-stripped — the same degraded behavior the metrics
//     middleware uses.
//
//  2. Resolve country via GlobalLookup. A nil lookup or empty
//     result feeds Evaluate as country=="" → fail-open per
//     AC #18.
//
//  3. Evaluate the gate. On Accepted=true, pass to next.
//     On Accepted=false, fire the sink (nil-safe) + write
//     the configured status code + return nil (handled).
//
// Status code precedence: Config.StatusCode (per-route
// override) > GlobalDefaultStatusCode (env default) > 403
// (hardcoded baseline). The defensive 403 ensures a block
// never silently 200s on a misconfigured deployment.
func (h *Handler) ServeHTTP(
	w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
) error {
	// Source IP resolution.
	srcIP := resolveSrcIP(r)

	// Geo resolution — nil-safe. A lookup that also resolves the
	// continent (GeoLookup, v2.27) is preferred; a country-only
	// CountryLookup still works for country rules.
	var geo GeoInfo
	if lookup := GlobalLookup(); lookup != nil {
		if gl, ok := lookup.(GeoLookup); ok {
			geo = gl.LookupGeo(srcIP)
		} else {
			geo.Country = lookup.Lookup(srcIP)
		}
	}

	// Gate evaluation.
	decision := EvaluateGeo(h.Config, geo, srcIP, GlobalTrustedIPs())
	if decision.Accepted {
		return next.ServeHTTP(w, r)
	}

	// Block path.
	status := h.Config.StatusCode
	if status == 0 {
		status = GlobalDefaultStatusCode()
	}
	if status == 0 {
		status = http.StatusForbidden
	}

	if sink := GlobalBlockSink(); sink != nil {
		sink.Submit(BlockMatch{
			Timestamp:  time.Now().UTC(),
			RouteID:    h.RouteID,
			SourceIP:   srcIP,
			Country:    decision.Country,
			Mode:       string(h.Config.Mode),
			StatusCode: status,
			Reason:     decision.Reason,
		})
	}

	// v2.62 — name the refusal in the access log. Without this a
	// country-block 403 is byte-indistinguishable from a backend's own
	// 403, which is how an afternoon went on 2026-10-04. The value is
	// read back by the log_append handler at the top of the chain; it
	// is a Caddy var and not a response header deliberately, so a
	// prober is not told which gate stopped them.
	caddyhttp.SetVar(r.Context(), DeniedVarKey, DeniedReason)

	w.WriteHeader(status)
	return nil
}

// DeniedVarKey / DeniedReason mirror caddymgr's constants of the same
// name. Duplicated rather than imported because countryblock must not
// depend on caddymgr — the dependency runs the other way (caddymgr
// emits the JSON that references this module). A test in caddymgr pins
// that the two agree.
const (
	DeniedVarKey = "arenet_denied"
	DeniedReason = "country"
)

// resolveSrcIP returns the trusted-proxy-aware client IP via
// the GlobalClientIPFn seam, falling back to r.RemoteAddr
// (port-stripped) when no seam has been installed. Mirrors
// the V.1.3 metrics resolution path so a single
// SetClientIPFn call in cmd/arenet covers both V.1 and W.
//
// The clientIPFn seam is a function pointer rather than the
// metrics package interface to avoid a circular import
// (metrics already exposes RemoteAddrClientIPFn for its own
// fallback; countryblock cannot import metrics without
// metrics importing countryblock for cross-wiring tests).
func resolveSrcIP(r *http.Request) string {
	if fn := GlobalClientIPFn(); fn != nil {
		return fn(r)
	}
	// Degraded fallback — port-stripped r.RemoteAddr.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// --- Globals (V.1.3 atomic.Pointer late-install pattern) ------------------

// Globals are deliberately package-level rather than passed
// through the Handler struct: Caddy instantiates Handler from
// JSON config and cannot inject Go pointers into struct fields.
// The metrics package solved the same problem with
// GlobalRegistry; we mirror the pattern for Lookup + sink +
// trustedIPs + statusCode + clientIPFn.
//
// atomic.Pointer (not sync.Once + bare pointer) because cmd/arenet
// may re-call SetGlobalTrustedIPs / SetGlobalDefaultStatusCode
// on every mgr.Apply (env-var reload via SIGHUP, planned for
// W+1). atomic.Pointer makes the swap visible on the next
// request without rebuilding the Caddy config.
var (
	globalLookup            atomic.Pointer[CountryLookup]
	globalBlockSink         atomic.Pointer[BlockSink]
	globalTrustedIPs        atomic.Pointer[[]*net.IPNet]
	globalDefaultStatusCode atomic.Int64
	globalClientIPFn        atomic.Pointer[ClientIPFunc]
)

// ClientIPFunc is the seam for resolving the trusted-proxy-aware
// client IP from a request. cmd/arenet (W.3) wires the real
// implementation (backed by auth.IPExtractor honoring
// ARENET_TRUSTED_PROXIES); leaving it unset means the
// resolveSrcIP fallback (port-stripped r.RemoteAddr) applies.
type ClientIPFunc func(r *http.Request) string

// SetGlobalLookup installs the process-wide country-resolution
// seam. Safe to call from any goroutine. Re-callable — a later
// call swaps the seam atomically; in-flight requests may see
// the old seam, subsequent requests see the new one.
//
// Pass nil to clear the seam (Provision will then fail with
// ErrLookupNotInstalled until a non-nil value is installed).
func SetGlobalLookup(l CountryLookup) {
	if l == nil {
		globalLookup.Store(nil)
		return
	}
	globalLookup.Store(&l)
}

// GlobalLookup returns the currently-installed lookup seam, or
// nil when unset. Lock-free atomic load; safe on the per-request
// hot path.
func GlobalLookup() CountryLookup {
	p := globalLookup.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetGlobalBlockSink installs the process-wide sink (W.4 wires
// the real DefaultCountryBlockSink). nil disables event
// emission entirely — gate enforcement still works, only the
// observability surface goes dark.
func SetGlobalBlockSink(s BlockSink) {
	if s == nil {
		globalBlockSink.Store(nil)
		return
	}
	globalBlockSink.Store(&s)
}

// GlobalBlockSink returns the currently-installed sink, or
// nil when unset.
func GlobalBlockSink() BlockSink {
	p := globalBlockSink.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetGlobalTrustedIPs installs the operator-supplied trusted-IP
// allowlist. Pass nil or an empty slice to clear it (only RFC1918
// bypass remains active).
//
// The slice is shared by reference, NOT copied — callers MUST
// NOT mutate it after the call. cmd/arenet parses the env var
// once at boot and never re-mutates; future SIGHUP support
// (W+1) would pass a freshly-allocated slice rather than
// editing in place.
func SetGlobalTrustedIPs(ips []*net.IPNet) {
	if ips == nil {
		globalTrustedIPs.Store(nil)
		return
	}
	globalTrustedIPs.Store(&ips)
}

// GlobalTrustedIPs returns the currently-installed trusted-IP
// list, or nil when unset.
func GlobalTrustedIPs() []*net.IPNet {
	p := globalTrustedIPs.Load()
	if p == nil {
		return nil
	}
	return *p
}

// SetGlobalDefaultStatusCode installs the process-wide default
// status code used when Config.StatusCode == 0. Pass 0 to
// reset to the hardcoded 403 fallback.
//
// Uses atomic.Int64 (cheaper than atomic.Pointer for an int).
// cmd/arenet (W.3) parses ARENET_COUNTRY_BLOCK_STATUS and
// installs the value at boot; the env-var parser validates
// against {403, 451, 444} before installing so a bad value
// never reaches this setter.
func SetGlobalDefaultStatusCode(code int) {
	globalDefaultStatusCode.Store(int64(code))
}

// GlobalDefaultStatusCode returns the installed default status,
// or 0 when unset (ServeHTTP applies the 403 hardcoded
// fallback in that case).
func GlobalDefaultStatusCode() int {
	return int(globalDefaultStatusCode.Load())
}

// SetGlobalClientIPFn installs the client-IP resolution seam.
// nil clears the seam (resolveSrcIP falls back to
// port-stripped r.RemoteAddr).
func SetGlobalClientIPFn(fn ClientIPFunc) {
	if fn == nil {
		globalClientIPFn.Store(nil)
		return
	}
	globalClientIPFn.Store(&fn)
}

// GlobalClientIPFn returns the installed resolver, or nil
// when unset.
func GlobalClientIPFn() ClientIPFunc {
	p := globalClientIPFn.Load()
	if p == nil {
		return nil
	}
	return *p
}

// ResetGlobalsForTest clears every package-level global. Tests
// that mutate the globals MUST call this in t.Cleanup to avoid
// cross-test pollution (test order is non-deterministic under
// `go test -count=N`).
//
// Mirrors metrics.ResetForTest.
func ResetGlobalsForTest() {
	globalLookup.Store(nil)
	globalBlockSink.Store(nil)
	globalTrustedIPs.Store(nil)
	globalDefaultStatusCode.Store(0)
	globalClientIPFn.Store(nil)
}

// Interface guards — compile-time assertions of the Caddy
// interfaces Handler implements. Mirrors the V.1.2 metrics
// pattern: if Caddy's API changes incompatibly, this breaks
// at compile time rather than at first request.
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.Validator             = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)
