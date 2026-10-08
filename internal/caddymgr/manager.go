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

// Package caddymgr embeds Caddy v2 as a library and translates Arenet's
// stored routes into Caddy JSON configuration applied via caddy.Load.
package caddymgr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"net/url"
	"os"
	"runtime/pprof"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"

	// Side-effect import: registers every standard Caddy module
	// (reverse_proxy, host matcher, internal TLS issuer, ...).
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Side-effect import: registers the arenet_routemetrics module so
	// the JSON config produced by buildConfigJSON (referencing it as
	// a handler) is accepted by caddy.Load. Step E spec §3.
	"github.com/barto95100/arenet/internal/l4metrics"
	"github.com/barto95100/arenet/internal/metrics"

	// Step M.1 — side-effect import: registers the arenet_waf
	// Caddy module (internal/waf/module.go init()) so the
	// `arenet_waf` handler ID buildWAFHandler now emits is
	// resolvable at caddy.Load time. Replaces the legacy
	// coraza-caddy/v2 import that previously registered the
	// `waf` handler.
	_ "github.com/barto95100/arenet/internal/waf"

	// Step W.3 — side-effect import: registers the
	// arenet_country_block Caddy module (internal/countryblock
	// module.go init()) so the handler ID buildCountryBlockHandler
	// emits is resolvable at caddy.Load time. Mirror of the WAF
	// import pattern above. Globals (lookup, trustedIPs, sink,
	// defaultStatusCode, clientIPFn) are installed by
	// cmd/arenet/main.go via the package's atomic.Pointer setters
	// — caddymgr does NOT touch them, just emits the JSON config
	// that references the module.
	"github.com/barto95100/arenet/internal/countryblock"

	// #R-TOPO-real-health-probe (Stage B, 2026-06-04) — registers
	// the arenet_topology_hc events handler so the apps.events.
	// subscriptions block buildConfigJSON emits is resolvable at
	// caddy.Load time. The tracker singleton is installed by
	// cmd/arenet before this manager calls caddy.Load; the
	// handler module's Provision pulls it then.
	//
	// v2.9.8 Bug B fix: now also imported by name so the manager
	// can hold a typed *HCStatusTracker reference and call Reset()
	// before each caddy.Load (defeats Caddy's transition-only emit
	// semantics that leave stale "unhealthy" entries after reload —
	// see caddyhc/tracker.go Reset() docstring for the empirical
	// Caddy v2.11.3 citations).
	"github.com/barto95100/arenet/internal/caddyhc"

	// Step T T.1 (2026-06-05) — side-effect import: registers the
	// arenet_cert_info events handler so the apps.events.subscriptions
	// entry buildConfigJSON emits for "tls" origin events is
	// resolvable at caddy.Load time. Same singleton-injection shape
	// as caddyhc above: cmd/arenet installs the cert tracker before
	// mgr.Start, the handler module's Provision pulls it.
	_ "github.com/barto95100/arenet/internal/certinfo"

	// Step Z.1 (2026-06-18) — side-effect import: registers the
	// arenet_ratelimit_sink events handler so the
	// apps.events.subscriptions entry buildConfigJSON emits for
	// "rate_limit_exceeded" events (origin: http.handlers.
	// rate_limit) is resolvable at caddy.Load time. Same singleton
	// pattern: cmd/arenet installs the global sink before
	// mgr.Start, the handler module pulls it on every Handle.
	_ "github.com/barto95100/arenet/internal/ratelimit"

	"github.com/barto95100/arenet/internal/storage"
)

// Listen ports by mode (Step I.1, refactored to ints in Step I.7
// hotfix Finding #8 so we can declare apps.http.http_port /
// https_port to Caddy and stop its auto_https logic from mis-
// identifying our HTTP listener as TLS-capable).
//
// Dev keeps the high ports so a non-root developer can bind without
// CAP_NET_BIND_SERVICE. Prod uses the standard reverse-proxy ports —
// ACME HTTP-01 challenges arrive on :80 and Let's Encrypt-issued
// certs serve on :443. Operators that cannot bind :80 / :443 must
// either run the binary as root or `setcap cap_net_bind_service+ep`
// on it; documented in the Step I.1 commit message.
const (
	httpPortDev   = 8080
	httpsPortDev  = 8443
	httpPortProd  = 80
	httpsPortProd = 443
)

// Listen address forms are derived from the int port constants
// above at the call site via fmt.Sprintf(":%d", port) — this
// keeps the string form mechanically consistent with the int
// port returned by httpPortFor / httpsPortFor, including any
// ARENET_HTTP_PORT / ARENET_HTTPS_PORT override (Step L.5
// prereq). The old standalone string consts (httpListenDev,
// httpsListenDev, httpListenProd, httpsListenProd) were
// removed because they would have silently shadowed the
// override.

// ACME directory URLs (Step I.1).
//
// `--dev` mode targets Let's Encrypt **staging** so iteration on the
// reverse-proxy config doesn't burn the production rate limit
// (50 certs / week / domain). Prod mode targets the real directory.
const (
	acmeProdURL    = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// CaddyManager owns the lifecycle of the embedded Caddy instance and
// reloads it from the persisted routes.
//
// The optional registry, when non-nil, is reconciled with the canonical
// route IDs after each successful caddy.Load (spec §11.5 + §4.1). When
// nil (typical for unit tests that only exercise buildConfigJSON or
// catch-all behavior), the metrics layer is fully bypassed.
//
// devMode (Step I.1) selects the listen ports (:8080/:8443 vs :80/:443)
// and the ACME directory (staging vs production). acmeEmail is the
// contact email passed to the ACME issuer; empty is accepted by
// Let's Encrypt but discouraged (no expiry reminders).
type CaddyManager struct {
	store     *storage.Store
	logger    *slog.Logger
	registry  *metrics.Registry
	devMode   bool
	acmeEmail string

	// adminListen (v2.42) is the admin interface's bind address, set
	// at boot via SetAdminListen. The TCP-service port guard reads it
	// so a relay can never take the port the operator manages Arenet
	// through. Empty only costs that one guard.
	adminListen string

	// crowdsec (Step N.1) holds the LAPI connection config. Both
	// fields are read from env vars at boot by main.go and pushed
	// via SetCrowdSecConfig BEFORE Start; once set they are
	// embedded in every emitted Caddy config (AC #14 invariant:
	// route mutations must NOT silently drop the bouncer). Empty
	// APIKey is the degraded-mode signal — buildConfigJSON omits
	// the apps.crowdsec block entirely AND skips the per-route
	// handler prepend (AC #13 fail-open at boot).
	crowdsec crowdsecConfig

	// normalTrafficExcludePaths (Step V.1.3) is the operator-
	// supplied path-prefix extension to the V.1.2 hardcoded
	// exclude list, parsed from
	// ARENET_NORMAL_TRAFFIC_EXCLUDE_PATHS by main.go and
	// pushed via SetNormalTrafficExcludePaths BEFORE Start.
	// Threaded into every per-route metricsHandler JSON
	// emit so a route reload preserves the operator's
	// exclusions. Empty slice (default) means only the
	// hardcoded list applies; the JSON field is omitted
	// via omitempty in that case.
	normalTrafficExcludePaths []string

	// accessLogConfiguredPath / accessLogDataDir (v2.50) are what the
	// access-log file path is derived from when the operator has not
	// typed one: ARENET_ACCESS_LOG_PATH (which the systemd installer
	// sets to /var/log/arenet/access.log) and the data dir. Pushed by
	// main.go before Start, same invariant as the exclude paths above.
	accessLogConfiguredPath string
	accessLogDataDir        string

	// previousWAFModes (W.bugfix Fix #3) is the WAF mode per
	// route observed at the END of the most recent successful
	// applyLocked. Used to compute a diff against the routes
	// being applied this pass and emit a "waf config diff
	// applied" log line summarizing added / removed / mode-
	// changed counts. Empty at boot — first applyLocked
	// reports every route-with-WAF as "added". Guarded by mu
	// like every other applyLocked-touched field.
	previousWAFModes map[string]string

	// previousCountryBlockModes (Step W.3) is the per-route
	// "country-block fingerprint" (mode + sorted country list
	// + status code) observed at the end of the most recent
	// successful applyLocked. The diff log mirrors the WAF
	// pattern: a change between two applies fires the
	// "country block config diff applied" summary; routine
	// non-country-block edits stay silent. Empty at boot —
	// first applyLocked reports every gated route as "added".
	previousCountryBlockModes map[string]string

	// hcTracker (v2.9.8, Bug B fix) is the process-wide active-
	// health-check status tracker installed by cmd/arenet before
	// Start. Held here so applyLocked can call Reset() before each
	// caddy.Load. Without the reset, stale "unhealthy" entries
	// persist across reloads forever — empirical Caddy v2.11.3
	// reverseproxy/healthchecks.go:478,498 + hosts.go:251-264
	// emits events only on state TRANSITIONS via atomic CAS, and
	// new Upstream objects default to healthy, so the first probe
	// success on a fresh reload silently CASes 0→0 and never
	// emits the recovery event our tracker needs to clear the
	// stale state.
	//
	// May be nil — unit tests instantiate the manager without a
	// tracker; the applyLocked call site nil-guards before Reset.
	hcTracker *caddyhc.HCStatusTracker

	mu      sync.Mutex
	started bool

	// Reload health (v2.26 — replaces the systemhealth probe of
	// Caddy's admin API, which is now disabled). reloadStartedAt is
	// the unix-nano start of the apply in flight (0 = none; a hung
	// caddy.Load keeps it set). reloadTimedOut is set by a
	// ReloadFromStore timeout and cleared by the next apply that
	// completes.
	reloadStartedAt atomic.Int64
	// startedFlag mirrors started for lock-free reads (ReloadHealth).
	startedFlag    atomic.Bool
	reloadTimedOut atomic.Bool

	// applyFn is the seam ReloadFromStore invokes inside its
	// goroutine + timeout wrapper. Default points to
	// applyLocked (the real Caddy reload path); tests override
	// to a stub that blocks indefinitely or returns a chosen
	// error so the wrapper's timeout / error-propagation paths
	// can be exercised without spinning up an embedded Caddy.
	// Set in New(); kept as a field so the timeout-wrapper
	// test seam stays type-safe (no global function pointer).
	applyFn func(context.Context) error
}

// crowdsecConfig is the manager-side mirror of the bouncer's
// connection settings. Step N.1 only exposes the two
// operator-facing fields (api_url + api_key); the rest of the
// bouncer's tuning (ticker_interval, enable_streaming,
// enable_hard_fails) is fixed per the Step N spec D1/D2/D7
// arbitrage and emitted as literals in buildCrowdSecApp.
//
// A future Step N revision could expose the tuning fields via
// admin Settings; v1.0 keeps the surface narrow.
type crowdsecConfig struct {
	apiURL string
	apiKey string
}

// New constructs a CaddyManager. The store and logger must be non-nil.
// The registry may be nil; passing a non-nil registry enables the
// per-reload Sync call that keeps the metrics counter map in step
// with the current set of routes.
//
// devMode and acmeEmail were added in Step I.1:
//   - devMode=true selects high listen ports (:8080/:8443) and the
//     Let's Encrypt staging directory; devMode=false picks :80/:443
//     and the production directory.
//   - acmeEmail is the contact passed to the ACME issuer when a route
//     has TLSEnabled=true. Empty is accepted but Let's Encrypt won't
//     send expiry reminders; caller is responsible for logging a
//     WARN at boot if appropriate.
func New(store *storage.Store, logger *slog.Logger, registry *metrics.Registry, devMode bool, acmeEmail string) (*CaddyManager, error) {
	if store == nil {
		return nil, errors.New("caddymgr: store must not be nil")
	}
	if logger == nil {
		return nil, errors.New("caddymgr: logger must not be nil")
	}
	m := &CaddyManager{
		store:     store,
		logger:    logger,
		registry:  registry,
		devMode:   devMode,
		acmeEmail: acmeEmail,
	}
	m.applyFn = m.applyLocked
	return m, nil
}

// SetNormalTrafficExcludePaths (Step V.1.3) installs the
// operator's path-prefix extension to the hardcoded V.1.2
// exclude list. Threaded into every per-route metricsHandler
// JSON emit so subsequent route reloads preserve the
// exclusions. Empty slice (or nil) means "only the hardcoded
// list applies" — the per-route emit omits the field
// entirely via omitempty.
//
// MUST be called BEFORE Start so the initial Caddy config
// emits the exclusions from the first applyLocked. Same
// invariant as SetCrowdSecConfig.
// SetAccessLogDefaults supplies what the access-log path falls back to
// when the operator has not chosen one: the configured path and the data
// directory.
//
// The emitter does not read process configuration, so this is how the
// per-topology default reaches it — /var/log/arenet under systemd, the
// data dir (and so the Docker volume) everywhere else.
//
// MUST be called BEFORE Start, so the first applyLocked already writes
// the log the operator enabled on a previous run.
func (m *CaddyManager) SetAccessLogDefaults(configuredPath, dataDir string) {
	m.mu.Lock()
	m.accessLogConfiguredPath = configuredPath
	m.accessLogDataDir = dataDir
	m.mu.Unlock()
}

func (m *CaddyManager) SetNormalTrafficExcludePaths(paths []string) {
	m.mu.Lock()
	// Defensive copy so the caller can't mutate the slice
	// underneath us across a reload.
	if len(paths) == 0 {
		m.normalTrafficExcludePaths = nil
	} else {
		m.normalTrafficExcludePaths = append([]string(nil), paths...)
	}
	m.mu.Unlock()
}

// SetHCTracker (v2.9.8, Bug B fix) installs the process-wide
// active-health-check status tracker so applyLocked can call
// Reset() on it before each caddy.Load. Without this wiring, the
// applyLocked Reset call is a no-op (nil-guard skips it) and the
// stale-after-reload symptom described in
// internal/caddyhc/tracker.go Reset() docstring reappears.
//
// MUST be called BEFORE Start so the very first applyLocked
// already benefits from the reset semantics. Passing nil is
// accepted and equivalent to not calling the setter (useful for
// unit tests that don't care about tracker behaviour).
func (m *CaddyManager) SetHCTracker(t *caddyhc.HCStatusTracker) {
	m.mu.Lock()
	m.hcTracker = t
	m.mu.Unlock()
}

// SetCrowdSecConfig (Step N.1) installs the LAPI connection
// settings consumed by the embedded caddy-crowdsec-bouncer.
// MUST be called BEFORE Start when the operator wants the
// reputation gate; calling it after Start has no effect on
// already-running Caddy until the next reload (any route
// mutation will trigger an applyLocked that picks up the new
// config).
//
// Both fields trimmed; an empty apiKey is the degraded-mode
// signal (AC #13): buildConfigJSON omits the apps.crowdsec
// block AND the per-route handler prepend. The data plane keeps
// running with WAF + rate-limiter active, just without
// IP-reputation enforcement.
func (m *CaddyManager) SetCrowdSecConfig(apiURL, apiKey string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crowdsec.apiURL = strings.TrimSpace(apiURL)
	m.crowdsec.apiKey = strings.TrimSpace(apiKey)
}

// SetAdminListen records the admin interface's bind address for the
// TCP-service port guard. Called at boot, before Start.
func (m *CaddyManager) SetAdminListen(addr string) {
	m.adminListen = addr
}

// ApplyCrowdSecConfig (Step CS.1) atomically swaps the LAPI
// connection settings AND triggers an applyLocked so the
// embedded Caddy picks up the new creds. Used by the
// /api/v1/settings/crowdsec PUT handler: the audit-config
// admin UI saves a row, then this method ensures the running
// Caddy reflects the change within the request lifetime (no
// process restart, no "Restart required" UX).
//
// The (Set + applyLocked) pair runs under a SINGLE m.mu.Lock
// acquisition so a concurrent /routes PUT or another settings
// PUT can't observe a half-written crowdsec config nor race the
// apply against a stale read. The cost is that this method
// holds m.mu across the full Caddy reload (~50-200ms typical);
// admin-API write contention is low enough that this is the
// right trade-off vs the alternative of a buildOpts-level
// snapshot indirection (extra surface, more places to forget
// to use it).
//
// AC #13 fail-open contract preserved: passing an empty apiKey
// clears the configured state — buildConfigJSON omits the
// apps.crowdsec block AND the per-route handler prepend,
// matching the env-driven boot path's degraded mode.
func (m *CaddyManager) ApplyCrowdSecConfig(ctx context.Context, apiURL, apiKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crowdsec.apiURL = strings.TrimSpace(apiURL)
	m.crowdsec.apiKey = strings.TrimSpace(apiKey)
	// If Start hasn't been called yet (e.g. test harness or
	// boot-time precedence wiring), skip the reload — the
	// initial applyLocked at Start will pick up the values
	// we just wrote.
	if !m.started {
		return nil
	}
	return m.applyLocked(ctx)
}

// crowdSecEnabled reports whether the manager has the LAPI key
// configured. Used by buildOpts plumbing + by the boot log
// line in main.go. Reads under the mutex to stay race-free
// against an admin-side SetCrowdSecConfig from a settings
// handler (no such handler exists yet at N.1 — env-driven
// only — but the API surface stays correct for future use).
func (m *CaddyManager) crowdSecEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.crowdsec.apiKey != ""
}

// Start launches the embedded Caddy with the config derived from the store.
// It is safe to call Start exactly once per CaddyManager instance.
func (m *CaddyManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return errors.New("caddymgr: already started")
	}

	if err := m.applyLocked(ctx); err != nil {
		return fmt.Errorf("initial caddy load: %w", err)
	}
	m.started = true
	m.startedFlag.Store(true)
	m.logger.Info("Caddy started", "http", m.httpListen(), "https", m.httpsListen(), "dev", m.devMode)
	return nil
}

// httpListen returns the HTTP listen address based on devMode
// and the optional env-var override (Step L.5 prereq). Step
// I.1: dev picks :8080, prod picks :80 (for ACME HTTP-01 + the
// I.2 redirect). The string form is derived from the int port
// returned by httpPortFor so the boot-time log line ALWAYS
// matches the listener's actual port even when the operator
// overrides via ARENET_HTTP_PORT.
func (m *CaddyManager) httpListen() string {
	return fmt.Sprintf(":%d", httpPortFor(m.devMode))
}

// httpsListen returns the HTTPS listen address based on devMode
// and the optional ARENET_HTTPS_PORT override.
func (m *CaddyManager) httpsListen() string {
	return fmt.Sprintf(":%d", httpsPortFor(m.devMode))
}

// HTTPListen exposes the effective HTTP listen address for the
// caller's log line. Mirrors m.httpListen with the override
// applied, so cmd/arenet/main.go prints the same port Caddy
// actually bound. Added in the M.0 sweep to fix Finding #L.5-1.
func (m *CaddyManager) HTTPListen() string {
	return m.httpListen()
}

// HTTPSListen mirrors HTTPListen for the TLS side.
func (m *CaddyManager) HTTPSListen() string {
	return m.httpsListen()
}

// Stop halts the embedded Caddy. Safe to call when Start was never invoked.
func (m *CaddyManager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.started {
		return nil
	}
	m.started = false
	m.startedFlag.Store(false)
	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("caddy stop: %w", err)
	}
	m.logger.Info("Caddy stopped")
	return nil
}

// reloadFromStoreTimeout bounds the wait inside ReloadFromStore so a
// stuck Caddy applyLocked (typically caddy.Load → unsyncedDecodeAndRun
// hanging on ACME / DNS provisioning while Caddy's internal rawCfgMu
// is held) does not stall the calling handler indefinitely. 25s sits
// between the frontend timeout (30s via client.ts REQUEST_TIMEOUT_MS,
// commit a234dbc) so the backend can return its 500 BEFORE the
// frontend AbortController fires — operators see a clean "caddy
// reload failed" message instead of a generic client-side
// "request timed out".
//
// Caveat (#R-CADDY-ADMIN-DEADLOCK): when this timeout fires the
// applyLocked goroutine continues running with Caddy's rawCfgMu
// still held. The current ReloadFromStore call returns promptly,
// but subsequent calls will each re-incur the 25s wait until
// the upstream ACME / DNS call eventually times out OR the
// operator restarts arenet. V1 trades "hang silently forever"
// for "fail fast in 25s with degraded throughput". The root
// cause (no arenet-controllable timeout on the certmagic /
// Caddy TLS app provisioning path) is upstream, out of V1
// scope.
const reloadFromStoreTimeout = 25 * time.Second

// reloadFromStoreTimeoutForTest is the runtime knob the timeout
// wrapper reads. Defaults to the package-level const above;
// tests override via withShortTimeout to a sub-second budget so
// the suite stays fast. NEVER mutate outside tests — the
// production code path takes its value once per call and a
// concurrent write here would race with running reloads.
var reloadFromStoreTimeoutForTest = reloadFromStoreTimeout

// ReloadFromStore rebuilds the Caddy config from the persisted routes and
// hot-reloads the running server.
//
// Bounded by reloadFromStoreTimeout. On expiry the function returns a
// wrapped context.DeadlineExceeded and dumps every goroutine stack to
// stderr via runtime/pprof so the operator (or post-mortem analyst)
// can identify the blocked goroutine without waiting for a SIGTERM
// timeout dump. The dump is the actionable signal — the timeout error
// alone tells the operator "Caddy is stuck" but not "where".
func (m *CaddyManager) ReloadFromStore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	reloadCtx, cancel := context.WithTimeout(ctx, reloadFromStoreTimeoutForTest)
	defer cancel()

	// Run the actual reload in a goroutine so the select below
	// can preempt it on timeout. applyFn defaults to
	// applyLocked; tests override to drive the timeout branch
	// without booting Caddy. The goroutine continues running
	// after a timeout — see reloadFromStoreTimeout caveat — so
	// caddy.Load eventually completes (or fails) in the
	// background even though we've returned to the caller.
	done := make(chan error, 1)
	go func() {
		m.reloadStartedAt.Store(time.Now().UnixNano())
		err := m.applyFn(reloadCtx)
		m.reloadStartedAt.Store(0)
		m.reloadTimedOut.Store(false)
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-reloadCtx.Done():
		// Dump goroutines BEFORE returning so the operator
		// reading the log sees the stack snapshot adjacent to
		// the error line. pprof.Lookup("goroutine").WriteTo
		// with debug=2 emits human-readable stacks (same shape
		// as a SIGQUIT dump). Best-effort: the WriteTo error
		// is logged but does not change the returned error
		// semantics — the caller's recourse is identical.
		m.logger.Error("caddy reload timeout — goroutine dump emitted to stderr",
			"timeout", reloadFromStoreTimeoutForTest,
		)
		if dumpErr := pprof.Lookup("goroutine").WriteTo(os.Stderr, 2); dumpErr != nil {
			m.logger.Warn("caddy reload timeout — goroutine dump write failed",
				"err", dumpErr,
			)
		}
		m.reloadTimedOut.Store(true)
		return fmt.Errorf("caddy reload timed out after %s: %w",
			reloadFromStoreTimeoutForTest, reloadCtx.Err())
	}
}

// ReloadHealth reports whether Caddy config reloads are healthy:
// started is false before Start; inFlight is how long the current
// reload has been running (0 when none); timedOut is true while the
// last ReloadFromStore timed out and no reload has completed since.
// A reload stuck inside caddy.Load (Caddy's config mutex held by a
// blocking provisioning call, #R-CADDY-ADMIN-DEADLOCK) shows up as a
// growing inFlight.
func (m *CaddyManager) ReloadHealth() (started bool, inFlight time.Duration, timedOut bool) {
	// Lock-free on purpose: ReloadFromStore holds m.mu for the whole
	// reload, and a health probe must not queue behind it.
	started = m.startedFlag.Load()
	if at := m.reloadStartedAt.Load(); at != 0 {
		inFlight = time.Since(time.Unix(0, at))
	}
	return started, inFlight, m.reloadTimedOut.Load()
}

// applyLocked must be called with m.mu held. It reads routes from the store,
// renders the Caddy JSON config and applies it.
//
// After a successful caddy.Load, syncs the metrics registry (if any)
// with the canonical route IDs so the per-route counters are aligned
// with the live config (spec §11.5). The Sync happens AFTER the
// reload succeeds — same pattern as audit emission for /routes
// mutations (Step D Bug 1 / D2): on reload failure the storage is
// rolled back by the caller (handlers in internal/api/routes.go),
// so the registry already reflects the pre-attempt state, and we
// must not re-sync against a state that was rejected.

// filterDisabledRoutes returns the routes that must be emitted into
// Caddy — i.e. the ones with Disabled=false. Filtering the slice ONCE
// here removes disabled routes from every downstream emission at once:
// routing, TLS connection policies, ACME issuance (subjects accumulate
// inside buildConfigJSON's route loop), buildSkipList, error routes,
// and the HC re-prime loop below — because they all consume this slice.
func filterDisabledRoutes(routes []storage.Route) []storage.Route {
	live := routes[:0:0]
	for _, r := range routes {
		if r.Disabled {
			continue
		}
		live = append(live, r)
	}
	return live
}

func (m *CaddyManager) applyLocked(ctx context.Context) error {
	routes, err := m.store.ListRoutes(ctx)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}

	// v2.14.3: drop disabled routes before anything consumes the slice.
	// One filter point covers routing + TLS policies + ACME issuance +
	// skip_certificates + error routes + the HC re-prime loop.
	for _, r := range routes {
		if r.Disabled {
			m.logger.Info("route skipped: disabled", "route_id", r.ID, "host", r.Host)
		}
	}
	routes = filterDisabledRoutes(routes)

	// Task 1d: read the UUID-keyed DNS provider collection into a map
	// keyed by config ID. Used by buildManagedDomainPolicies to emit a
	// DNS-01 ACME policy per managed domain, each sourced from ITS OWN
	// provider (md.ProviderID → config), and by buildTLSPolicies for
	// per-route (non-wildcard) DNS-01. Empty map on a fresh install is
	// the normal, silent path. The API layer rejects a route create /
	// update that would activate DNS-01 without a configured provider,
	// so reaching the emit paths with a DNS-01 subject and an empty map
	// is a programming error the generator handles defensively (no
	// DNS-01 policy emitted; route falls back to the internal issuer)
	// rather than failing the whole reload.
	provList, err := m.store.ListDNSProviders(ctx)
	if err != nil {
		return fmt.Errorf("read dns providers: %w", err)
	}
	dnsProviders := make(map[string]storage.DNSProviderConfig, len(provList))
	for _, p := range provList {
		dnsProviders[p.ID] = p
	}

	// Step K.1: read the instance-level forward-auth provider
	// catalogue so buildConfigJSON can resolve each route's
	// referenced provider into the emitted Caddy handler shape.
	// Empty list is the normal state on a fresh install; routes
	// with AuthMode == "forward_auth" are rejected at edit time
	// when no matching provider exists (§5.1 cross-rule).
	fwdAuthList, err := m.store.ListForwardAuthProviders(ctx)
	if err != nil {
		return fmt.Errorf("list forward_auth providers: %w", err)
	}
	fwdAuthMap := make(map[string]storage.ForwardAuthProvider, len(fwdAuthList))
	for _, p := range fwdAuthList {
		fwdAuthMap[p.Name] = p
	}

	// Step O.2: read the instance-level managed domains so
	// buildConfigJSON can emit ONE wildcard TLS policy per
	// declared apex and skip per-route ACME partition for
	// covered hosts. Empty list is the normal state on a fresh
	// install — D5.A byte-equality short-circuit then applies.
	// AC #14 invariant: this read runs on EVERY applyLocked,
	// guaranteeing the wildcard policies survive every reload.
	managedDomains, err := m.store.ListManagedDomains(ctx)
	if err != nil {
		return fmt.Errorf("list managed domains: %w", err)
	}

	// Step R — read every ErrorPageTemplate before each apply
	// so dangling refs (template deleted between two reloads)
	// resolve cleanly to nil in the lookup map and the
	// caddymgr emit falls back to the built-in default. Empty
	// bucket → empty map → operators on a fresh install get
	// the built-in default for every route automatically.
	errorTemplates, err := m.store.ListErrorPageTemplates(ctx)
	if err != nil {
		return fmt.Errorf("list error templates: %w", err)
	}
	errorTemplatesMap := make(map[string]storage.ErrorPageTemplate, len(errorTemplates))
	for _, t := range errorTemplates {
		errorTemplatesMap[t.ID] = t
	}

	// Task 4 — read the global maintenance page singleton before
	// each apply, same plumbing as ErrorTemplates above. A fresh
	// install / never-customized page returns a zero value (empty
	// HTML) with nil error; buildConfigJSON's maintenance branch
	// falls back to the branded default in that case.
	// v2.50 — the access-log setting, read before each apply like the
	// error templates above. A read failure must not take the whole
	// reload down over a log: treat it as off and say so.
	accessLog, err := m.store.GetAccessLogConfig(ctx)
	if err != nil {
		m.logger.Warn("access log: read setting; leaving the log off for this apply", "err", err)
		accessLog = storage.AccessLogConfig{}
	}
	accessLogPath := ResolveAccessLogPath(m.accessLogConfiguredPath, m.accessLogDataDir, accessLog.Path)

	maintenancePage, err := m.store.GetMaintenancePageConfig(ctx)
	if err != nil {
		return fmt.Errorf("get maintenance page config: %w", err)
	}

	// v2.19.0 (external-certificates SOCLE) — read every
	// operator-uploaded external certificate before each apply, same
	// plumbing as ErrorTemplates / maintenance above. Keyed by ID so
	// buildConfigJSON can resolve a manual-cert route's Route.CertID to
	// its PEM material for load_pem emission. A dangling CertID (cert
	// deleted between two reloads) resolves to a missing map entry and
	// buildLoadPemList skips it defensively. Empty bucket → empty map →
	// no load_pem block (the common case, no manual-cert routes).
	extCerts, err := m.store.ListExternalCertificates(ctx)
	if err != nil {
		return fmt.Errorf("list external certificates: %w", err)
	}
	extCertsMap := make(map[string]storage.ExternalCertificate, len(extCerts))
	for _, c := range extCerts {
		extCertsMap[c.ID] = c
	}

	// v2.42 — TCP (layer 4) services. A store that cannot be read is
	// a hard failure like the routes above; an individual service
	// that would fight over a socket is refused HERE rather than
	// after Caddy has already been handed the config, so the HTTP
	// routes keep reloading and the operator gets the reason.
	tcpServices, err := m.store.ListTCPServices(ctx)
	if err != nil {
		return fmt.Errorf("list tcp services: %w", err)
	}
	if err := ValidateTCPListen(tcpServices, ReservedTCPPortsFor(m.devMode, m.adminListen)); err != nil {
		return fmt.Errorf("tcp services: %w", err)
	}
	activeTCP := 0
	for _, svc := range tcpServices {
		if svc.Disabled {
			m.logger.Info("tcp service skipped: disabled", "service_id", svc.ID, "name", svc.Name)
			continue
		}
		activeTCP++
		m.logger.Info("tcp service mounted",
			"service_id", svc.ID, "name", svc.Name,
			"listen", svc.ListenHostPort(), "backends", len(svc.Upstreams),
			"proxy_protocol", svc.ProxyProtocol)
	}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{
		DevMode:                   m.devMode,
		ACMEEmail:                 m.acmeEmail,
		DNSProviders:              dnsProviders,
		ForwardAuthProviders:      fwdAuthMap,
		CrowdSec:                  m.crowdsec,
		ManagedDomains:            managedDomains,
		NormalTrafficExcludePaths: m.normalTrafficExcludePaths,
		ErrorTemplates:            errorTemplatesMap,
		MaintenancePageHTML:       maintenancePage.HTML,
		MaintenanceMessage:        maintenancePage.Message,
		ExternalCerts:             extCertsMap,
		TCPServices:               tcpServices,
		AccessLog:                 accessLog,
		AccessLogPath:             accessLogPath,
	})
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}

	m.logger.Debug("applying caddy config",
		"routes", len(routes), "tcp_services", activeTCP, "bytes", len(cfgJSON))

	// W.bugfix Fix #3 — emit a "waf config diff applied"
	// summary when this pass adds / removes / changes the
	// WAF mode of any route relative to the previous
	// successful apply. Helps operators verify that a UI
	// edit to wafMode actually triggered the reload (the
	// Probe #2 confirmation in the discovery doc was harder
	// than necessary because no log surfaced the
	// propagation). Silent when no WAF mode changed, so
	// routine non-WAF edits don't fill the log.
	currentWAFModes := make(map[string]string, len(routes))
	for _, r := range routes {
		currentWAFModes[r.ID] = r.WAFMode
	}
	var (
		added         []string
		removed       []string
		changed       []string
		changeDetails []string
	)
	for id, curMode := range currentWAFModes {
		prev, existed := m.previousWAFModes[id]
		switch {
		case !existed:
			// New route OR first-ever applyLocked. Only
			// surface in the diff log if the route has WAF on
			// — operators care about WAF coverage, not about
			// every freshly-created off-route.
			if curMode != "" && curMode != "off" {
				added = append(added, id)
			}
		case prev != curMode:
			changed = append(changed, id)
			changeDetails = append(changeDetails, id+":"+prev+"→"+curMode)
		}
	}
	for id, prevMode := range m.previousWAFModes {
		if _, stillThere := currentWAFModes[id]; !stillThere {
			if prevMode != "" && prevMode != "off" {
				removed = append(removed, id)
			}
		}
	}
	if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
		m.logger.Info("waf config diff applied",
			"added_count", len(added),
			"removed_count", len(removed),
			"changed_count", len(changed),
			"changes", changeDetails,
		)
	}
	m.previousWAFModes = currentWAFModes

	// W.bugfix Fix #2 — emit a per-route skip log for every
	// route whose WAF is off. The provisioned-side log lives
	// in internal/waf module.Provision (which only fires
	// when the handler is actually emitted in the chain);
	// caddymgr is the only place that knows about routes
	// whose WAF handler was deliberately omitted because
	// mode is empty / "off". Symmetric coverage so an
	// operator scanning journalctl after a reload sees every
	// route's WAF status (on with mode + skipped with
	// reason). Runs on EVERY applyLocked — same cadence as
	// the provisioned-side log, so the operator's mental
	// model stays consistent across hot-reloads.
	for _, r := range routes {
		if r.WAFMode == "" || r.WAFMode == "off" {
			m.logger.Info("waf handler skipped",
				"route_id", r.ID,
				"host", r.Host,
				"reason", "mode_off",
			)
		}
	}

	// Step W.3 — country-block diff + per-route provisioned /
	// skipped logs. Mirror of the WAF Fix #2 + Fix #3 patterns
	// directly above. The diff log fires when any route
	// gained / lost / changed country-block config relative
	// to the previous successful apply; the per-route
	// provisioned + skipped logs run on every apply so the
	// operator sees full country-block coverage in journalctl
	// regardless of whether anything changed.
	currentCountryBlockModes := make(map[string]string, len(routes))
	for _, r := range routes {
		currentCountryBlockModes[r.ID] = countryBlockFingerprint(r.CountryBlock)
	}
	{
		var (
			cbAdded         []string
			cbRemoved       []string
			cbChanged       []string
			cbChangeDetails []string
		)
		offFingerprint := countryBlockFingerprint(countryblock.Config{})
		for id, curFp := range currentCountryBlockModes {
			prev, existed := m.previousCountryBlockModes[id]
			switch {
			case !existed:
				// New route OR first-ever applyLocked. Only
				// surface in the diff log if the route has the
				// gate ON — operators care about country-block
				// coverage changes, not about every fresh off-
				// route. Symmetric to the WAF diff carve-out.
				if curFp != offFingerprint {
					cbAdded = append(cbAdded, id)
				}
			case prev != curFp:
				cbChanged = append(cbChanged, id)
				cbChangeDetails = append(cbChangeDetails, id+":"+prev+"→"+curFp)
			}
		}
		for id, prevFp := range m.previousCountryBlockModes {
			if _, stillThere := currentCountryBlockModes[id]; !stillThere {
				if prevFp != offFingerprint {
					cbRemoved = append(cbRemoved, id)
				}
			}
		}
		if len(cbAdded) > 0 || len(cbRemoved) > 0 || len(cbChanged) > 0 {
			m.logger.Info("country block config diff applied",
				"added_count", len(cbAdded),
				"removed_count", len(cbRemoved),
				"changed_count", len(cbChanged),
				"changes", cbChangeDetails,
			)
		}
	}
	m.previousCountryBlockModes = currentCountryBlockModes

	// Per-route provisioned + skipped logs (mirror WAF Fix #2).
	// Operators reading journalctl after a reload see one line
	// per route's country-block state — gated routes show the
	// mode + list count + status_code; off routes show the
	// reason. Together with the diff log above, this gives
	// full per-reload visibility without flooding the log on
	// routine non-country-block edits.
	for _, r := range routes {
		if r.CountryBlock.Mode == "" || r.CountryBlock.Mode == countryblock.ModeOff {
			m.logger.Info("country block handler skipped",
				"route_id", r.ID,
				"host", r.Host,
				"reason", "mode_off",
			)
			continue
		}
		m.logger.Info("country block handler provisioned",
			"route_id", r.ID,
			"host", r.Host,
			"mode", string(r.CountryBlock.Mode),
			"country_list_count", len(r.CountryBlock.CountryList),
			"continents", r.CountryBlock.Continents,
			"asn_count", len(r.CountryBlock.ASNs),
			"exception_count", exceptionCount(r.CountryBlock),
			"status_code", r.CountryBlock.StatusCode,
		)
	}

	// 2026-06-24 — forceReload switched from true → false.
	//
	// Pre-switch behaviour (forceReload=true) : every PUT /routes/X
	// triggered a FULL Caddy restart cycle visible in journalctl as :
	//   - "servers shutting down; grace period initiated", duration:5
	//   - "server shutdown", error: "context canceled", addresses [":443"]
	//   - "stopping ..." crowdsec instance + reconnection round-trip
	//   - WAF pool rebuild (every Coraza instance re-provisioned)
	//   - Per-upstream HC tracker state reset (in-process memory wiped)
	// Operator-observed symptom : route health badge stuck at "unknown"
	// or "healthy" even when journalctl showed "connection refused"
	// probes ; the tracker never accumulated enough consecutive
	// failures between reloads to trip Caddy's setHealthy(false)
	// transition AND emit the "unhealthy" event our tracker
	// subscribes to.
	//
	// caddy.Load(cfgJSON, false) (forceReload=false) per Caddy
	// v2.11.3 caddy.go:112-115 doc : "runs it only if it is
	// different from the current config or forceReload is true".
	// With the second arg false, Caddy hashes the new vs current
	// config and :
	//   - no-op when identical (saves a full reload cycle on
	//     idempotent puts, e.g. operator clicks Save without
	//     changing anything)
	//   - graceful incremental reload when different : the new
	//     config provisions in parallel, atomic swap, the OLD
	//     server keeps serving in-flight requests until grace
	//     completes, NO restart of subsystems that didn't change
	//     (CrowdSec stays connected, WAF pool keys that didn't
	//     change keep their Coraza instances, HC tracker state
	//     survives)
	//
	// Side effect win : the route health badge bug (Bug #1 in the
	// 2026-06-24 operator report) becomes immediately observable
	// in the live UI because the HC tracker now accumulates
	// across PUTs instead of resetting.
	// v2.9.8 Bug B fix — reset the HC tracker BEFORE caddy.Load.
	// Empirical Caddy v2.11.3 reverseproxy/healthchecks.go:478,498
	// + hosts.go:251-264: "healthy"/"unhealthy" events fire only on
	// state TRANSITIONS via Upstream.setHealthy atomic CAS. New
	// Upstream objects created by the upcoming Load default to
	// healthy (unhealthy = 0); the first probe success silently
	// CASes 0→0 and never emits the recovery event our tracker
	// would need to clear a pre-reload "unhealthy" entry. Without
	// this reset the badge stays stuck DOWN forever even when the
	// upstream is answering 2xx on the new config.
	//
	// Nil-guard for unit tests / boot orderings that don't install
	// a tracker. Reset acquires its own lock; the caller's
	// manager-mu is unrelated (covers store/registry/started, not
	// the tracker's internal map).
	if m.hcTracker != nil {
		m.hcTracker.Reset()
	}

	if err := caddy.Load(cfgJSON, false); err != nil {
		// v2.26: DNS provider modules may echo a credential in their
		// Provision error (caddy-dns/cloudflare does). The error is
		// logged by every ReloadFromStore caller, so it is rebuilt
		// from its redacted text — deliberately NOT wrapped, which
		// would keep the raw secret reachable via errors.Unwrap.
		return fmt.Errorf("caddy.Load: %s", storage.RedactDNSSecrets(err.Error(), provList...))
	}

	// v2.9.9 Bug B follow-up — re-prime healthy after every reload.
	// Symmetric to the cmd/arenet boot-time prime: Caddy's active
	// health checker only emits state-TRANSITION events; new
	// Upstream objects default to healthy (Caddy v2.11.3 hosts.go:251
	// — u.unhealthy.Load() == 0). After the v2.9.8 Reset() above
	// the tracker is empty, so an upstream whose probes succeed
	// silently leaves the badge gray forever (no event ever fires
	// to flip it green).
	//
	// Priming-as-healthy matches Caddy's optimistic default. The
	// window of risk: ≤1 probe interval (~30s default). If the
	// upstream is actually DOWN, Caddy's first probe (fired
	// IMMEDIATELY at goroutine start per healthchecks.go:283) will
	// fail, accumulate to Fails threshold, transition the Upstream
	// state to false, and emit "unhealthy" — at which point our
	// tracker flips to DOWN and the badge turns red. Worst case
	// the operator sees a green-then-red sequence within 30s after
	// a Save on a route whose upstream is genuinely broken.
	if m.hcTracker != nil {
		for _, r := range routes {
			if !r.HealthCheck.Enabled {
				continue
			}
			for _, u := range r.Upstreams {
				m.hcTracker.RecordHealthy(u.URL)
			}
		}
	}

	// Reload succeeded — sync the metrics registry with the live
	// route IDs. Nil registry (typical for unit tests) skips the
	// sync. Extracted into syncRegistry so the no-Caddy unit test
	// (TestApplyLocked_SyncCalledAfterSuccess) can exercise the
	// Sync path directly without spinning up an embedded Caddy.
	m.syncRegistry(routes)
	// v2.42 — same for the layer-4 counters, so a service that was
	// deleted stops being reported and a new one starts from zero.
	syncL4Registry(tcpServices)
	return nil
}

// syncL4Registry reconciles the layer-4 counters with the services
// that are actually mounted. Disabled services are excluded: they
// serve nothing, so reporting a cell for them would be noise.
func syncL4Registry(services []storage.TCPService) {
	reg := l4metrics.GlobalRegistry()
	if reg == nil {
		return
	}
	specs := make([]l4metrics.SyncSpec, 0, len(services))
	for _, svc := range services {
		if svc.Disabled {
			continue
		}
		// v2.57.1 — the transport decides whether the open-session gauge
		// can survive this apply. See l4metrics.SyncSpec.Datagram.
		specs = append(specs, l4metrics.SyncSpec{
			ID:       svc.ID,
			Datagram: svc.Network() == storage.TCPServiceProtocolUDP,
		})
	}
	reg.Sync(specs)
}

// syncRegistry reconciles the metrics registry's cells with the
// canonical route IDs. No-op when m.registry is nil. Pulled out of
// applyLocked so tests can exercise it without going through
// caddy.Load.
func (m *CaddyManager) syncRegistry(routes []storage.Route) {
	if m.registry == nil {
		return
	}
	ids := make([]string, len(routes))
	for i, r := range routes {
		ids[i] = r.ID
	}
	m.registry.Sync(ids)
}

// caddyConfig models the subset of Caddy JSON we need.
type caddyConfig struct {
	Admin *adminConfig   `json:"admin,omitempty"`
	Apps  appsConfig     `json:"apps"`
	Logs  *loggingConfig `json:"logging,omitempty"`
}

type adminConfig struct {
	Disabled bool `json:"disabled"`
}

// adminBlock returns the top-level Caddy "admin" config (v2.26).
//
// Arenet drives Caddy in-process through caddy.Load and never uses
// Caddy's admin HTTP API, yet with no admin block Caddy starts it on
// localhost:2019 — unauthenticated, serving the full config (DNS
// credentials, private keys, CrowdSec key) and accepting POST /load
// from any local process or SSRF. And with persist unset, every
// caddy.Load writes the full config in plaintext to autosave.json
// (caddy@v2.11.4/caddy.go:377-392). Both are turned off.
func adminBlock() map[string]any {
	return map[string]any{
		"disabled": true,
		"config":   map[string]any{"persist": false},
	}
}

type loggingConfig struct {
	// Empty for now — keep room for explicit log routing in a later step.
}

type appsConfig struct {
	HTTP httpApp `json:"http"`
	// Step N.1 — embedded CrowdSec bouncer Caddy app. Pointer
	// with omitempty so the JSON shape is byte-identical to
	// pre-N when the operator hasn't configured a LAPI key
	// (AC #13 degraded mode). Populated by buildCrowdSecApp
	// when buildOpts.CrowdSec.apiKey != "".
	CrowdSec *crowdsecApp `json:"crowdsec,omitempty"`
}

// crowdsecApp is the Caddy "crowdsec" app config block. JSON
// tags mirror github.com/hslatman/caddy-crowdsec-bouncer
// v0.12.1 crowdsec/crowdsec.go:59-89 verbatim. Only the
// operator-facing fields are exposed at N.1; the remaining
// tuning (appsec_*, metrics_interval, enable_caddy_metrics)
// stays at the upstream default per Step N spec §3.4 (scope
// constrained to IP-reputation gate; AppSec is explicitly
// out-of-scope per §8).
type crowdsecApp struct {
	APIURL          string `json:"api_url"`
	APIKey          string `json:"api_key"`
	TickerInterval  string `json:"ticker_interval"`
	EnableStreaming bool   `json:"enable_streaming"`
	EnableHardFails bool   `json:"enable_hard_fails"`
	// EnableCaddyError (bouncer v0.13.0+) makes a ban / throttle
	// return a Caddy HandlerError instead of writing a bare
	// status, so the server's errors chain serves the branded 403
	// / 429 page (same path as the IP filter's `error` handler).
	// The bouncer README asks for static error routes (DoS):
	// Arenet's are static_response handlers (error_pages.go).
	EnableCaddyError bool `json:"enable_caddy_error,omitempty"`
}

type httpApp struct {
	Servers map[string]httpServer `json:"servers"`
}

type httpServer struct {
	Listen []string    `json:"listen"`
	Routes []httpRoute `json:"routes,omitempty"`
	// Logs (v2.50) points this server's requests at the access-log
	// sink. Caddy only enables access logging at all when this is
	// non-nil (caddyhttp/app.go:234), so omitting it is how the log
	// stays off — and how the emitted config stays byte-identical for
	// an installation that never turns it on.
	Logs            map[string]any        `json:"logs,omitempty"`
	Errors          *httpErrors           `json:"errors,omitempty"`
	AutomaticHTTPS  *automaticHTTPSConfig `json:"automatic_https,omitempty"`
	TLSConnPolicies []tlsConnectionPolicy `json:"tls_connection_policies,omitempty"`
}

// Step R — mirror of caddy modules/caddyhttp/server.go:758
// HTTPErrorConfig { Routes RouteList }. The "errors" subroute
// runs whenever a primary-route handler returns a HandlerError
// (server.go:421-423). Caddy does NOT auto-dispatch by status
// code — each route under Errors.Routes carries its own matcher
// (we use the CEL `expression` matcher on
// {http.error.status_code}).
type httpErrors struct {
	Routes []httpRoute `json:"routes,omitempty"`
}

type automaticHTTPSConfig struct {
	Disable             bool `json:"disable"`
	DisableRedirects    bool `json:"disable_redirects,omitempty"`
	DisableCertificates bool `json:"disable_certificates,omitempty"`
	// Skip lists hostnames EXCLUDED from auto-HTTPS entirely — no cert
	// management AND no redirect handling, and removed from the
	// server's domain set (caddy v2.11.3 autohttps.go:53-54, 161-162).
	// Arenet does not currently need this full exclusion; left here for
	// completeness / future use. Kept empty in normal operation.
	Skip []string `json:"skip,omitempty"`
	// SkipCerts lists hostnames that STAY in auto-HTTPS but for which
	// Caddy must NOT provision a per-host cert (autohttps.go:57-60,
	// 204). This is the correct field for Step #S-20's intent: routes
	// covered by a managed-domain wildcard get the wildcard cert
	// (pre-acquired via apps.tls.certificates.automate) served at
	// handshake via SNI, so per-host acquisition must be suppressed —
	// WITHOUT dropping the host from redirect/auto-HTTPS processing.
	// Prior code emitted these into Skip, which also silently removed
	// redirect handling for the host (latent bug); skip_certificates
	// keeps that behaviour intact.
	SkipCerts []string `json:"skip_certificates,omitempty"`
}

type tlsConnectionPolicy struct {
	// Empty policy = use Caddy defaults; relies on the tls app to issue certs.
}

type httpRoute struct {
	Match  []matcherSet     `json:"match,omitempty"`
	Handle []map[string]any `json:"handle"`
	// Terminal (Step K.4 parity fix) — when true, Caddy stops
	// route dispatching after this route matches. Mirrors the
	// canonical forward_auth Caddyfile expansion (every emitted
	// route there is terminal). Defence-in-depth: prevents a
	// future request from matching BOTH this route and another
	// one on the same host (e.g. passthrough-prefix + main
	// route sharing the Host).
	Terminal bool `json:"terminal,omitempty"`
}

type matcherSet struct {
	Host []string `json:"host,omitempty"`
	// Step K.4 — Path matcher. Caddy v2 takes a slice of glob
	// patterns; a request matches if ANY pattern matches.
	// Omitempty so the legacy host-only routes stay byte-
	// identical in the emitted JSON.
	Path []string `json:"path,omitempty"`
	// Step R — CEL expression matcher. Single string
	// evaluated as a CEL expression with access to all
	// request/error placeholders (verified caddy v2.11.3
	// modules/caddyhttp/celmatcher.go:82, module ID
	// http.matchers.expression). Used by the per-server
	// errors block to dispatch by {http.error.status_code}.
	// omitempty preserves byte-identical JSON for the
	// pre-R routes.
	Expression string `json:"expression,omitempty"`
	// ClientIP (v2.70.0) — Caddy's client_ip matcher as a SET member,
	// so it ANDs with Host: "this host, and only from these ranges".
	// That is what lets a maintenance route hand its bypass list the
	// real route while a sibling catch-all serves everyone else the
	// 503 (see the maintenance window in maintenance.go).
	//
	// A pointer with omitempty, for the same reason Path and
	// Expression above carry it: every route that does not set this
	// serialises exactly as it did before the field existed, which is
	// what the two golden fixtures in this package assert.
	//
	// client_ip rather than remote_ip, deliberately. remote_ip reads
	// the TCP peer, so behind any upstream proxy every request would
	// appear to come from that proxy and the bypass would either match
	// nobody or match everybody. client_ip resolves the chain through
	// Caddy's trusted_proxies. The pre-v2.70.0 bypass subroute chose the
	// same matcher when it only guarded a static 503; the choice matters
	// more now that it guards the backend.
	ClientIP *clientIPMatcher `json:"client_ip,omitempty"`
}

// clientIPMatcher is Caddy's http.matchers.client_ip config shape.
// Ranges accepts CIDRs and bare addresses (storage.MaintenanceConfig
// validates them before they reach here).
type clientIPMatcher struct {
	Ranges []string `json:"ranges"`
}

// wrapInSubroute (Step K.4 parity fix) packages a flat handler
// chain into the canonical "subroute" handler shape that Caddy's
// own Caddyfile-to-JSON adapter produces for the forward_auth
// directive. Mirrors forward_auth_authelia.caddyfiletest verbatim:
// every chain handler becomes a single-handler entry in
// subroute.routes, wrapped by exactly one subroute handler at the
// outer level.
//
// Why: K.1 originally emitted handlers flat in httpRoute.Handle.
// That works for simple cases but diverges from the canonical
// expansion of the forward_auth directive. The K.4 smoke surfaced
// the structural divergence as the cause of latent risks (e.g.
// passthrough-path × main-route double-match without a `terminal`
// flag). Emitting the canonical shape removes those classes by
// construction.
//
// Single-handler input: returns a one-entry subroute. Zero-
// handler input: returns an empty subroute (defensive — caller
// should ensure non-empty).
func wrapInSubroute(handlers []map[string]any) map[string]any {
	subRoutes := make([]map[string]any, 0, len(handlers))
	for _, h := range handlers {
		subRoutes = append(subRoutes, map[string]any{
			"handle": []map[string]any{h},
		})
	}
	return map[string]any{
		"handler": "subroute",
		"routes":  subRoutes,
	}
}

// buildOpts configures buildConfigJSON's environment-dependent
// behaviors. Step I.1 introduced it so the manager can pass devMode
// + acmeEmail down without buildConfigJSON growing a long parameter
// list. Tests pass a value-typed default (zero values) when they
// only exercise the catch-all + internal-issuer path.
type buildOpts struct {
	// DevMode selects listen ports (:8080/:8443 vs :80/:443) and
	// the ACME directory URL (staging vs production).
	DevMode bool
	// ACMEEmail is forwarded to the ACME issuer when at least one
	// route has TLSEnabled=true. Empty is accepted (Let's Encrypt
	// won't send expiry reminders).
	ACMEEmail string
	// DNSProviders (Task 1d) maps DNSProviderConfig.ID -> config,
	// read by the manager from BoltDB before each apply. It replaces
	// the pre-v2.11 single DNSProvider and is the per-managed-domain
	// DNS-01 dispatch source: each managed domain looks up its own
	// credentials by md.ProviderID (multi-account). An empty / nil
	// map means "no provider configured"; buildManagedDomainPolicies
	// then emits the internal issuer (D4.A loud unconfigured state)
	// and buildTLSPolicies emits no per-route DNS-01 policy. The API
	// rejects route create / update that would activate DNS-01
	// without a configured provider, so reaching those code paths
	// with DNS-01 subjects and an empty map is a programming error
	// caught defensively at apply time.
	DNSProviders map[string]storage.DNSProviderConfig
	// ForwardAuthProviders (Step K.1) is the map of configured
	// forward-auth provider rows, keyed by Name, read by the
	// manager from BoltDB before each apply. Routes with
	// AuthMode == "forward_auth" look up their provider by name
	// in this map; a missing key is the programming-error path
	// (API rejects route create / update referencing a non-
	// existent provider, §5.1 cross-rule). buildConfigJSON falls
	// back to NO auth handler in that defensive case rather than
	// failing the reload — same posture as the J.4 DNS-01
	// fall-back.
	ForwardAuthProviders map[string]storage.ForwardAuthProvider
	// CrowdSec (Step N.1) is the LAPI connection config. Zero-
	// value APIKey means "not configured" — buildConfigJSON
	// silently omits both the apps.crowdsec block and the
	// per-route handler prepend (AC #13 fail-open: data plane
	// keeps running without the reputation gate).
	CrowdSec crowdsecConfig
	// ManagedDomains (Step O.2) is the list of operator-declared
	// wildcard managed domains. Empty slice means "no managed
	// domains" — the D5.A invariant requires that buildConfigJSON
	// emits byte-equal output to Step J in that state. Each
	// managed domain produces ONE TLS policy covering `*.<apex>`
	// (+ `<apex>` when IncludeApex). Routes whose host is covered
	// by a managed domain AND which do NOT opt out via
	// UseDedicatedCert skip the per-route HTTP-01 / DNS-01
	// partition — the wildcard policy serves them at handshake
	// time. Read from BoltDB on every applyLocked (AC #14:
	// preserved on every Caddy reload).
	ManagedDomains []storage.ManagedDomain

	// NormalTrafficExcludePaths (Step V.1.3) is the
	// operator-supplied path-prefix extension to the V.1.2
	// hardcoded exclude list inside RouteMetricsHandler.
	// Threaded into every per-route metricsHandler emit
	// below as the `exclude_paths` JSON field. Empty (nil
	// or empty slice) → field omitted via omitempty; the
	// V.1.2 middleware then only applies its hardcoded
	// list. Operator changes between reloads take effect
	// immediately (next applyLocked re-renders the JSON).
	NormalTrafficExcludePaths []string

	// ErrorTemplates (Step R) is the map of operator-defined
	// ErrorPageTemplate rows keyed by template ID, read by
	// the manager from BoltDB before each applyLocked.
	// Routes opt into a template via
	// Route.ErrorPageTemplateID ; per-route overrides layer
	// on top via Route.ErrorPageOverrides. A nil map (no
	// templates configured) is the common case — the
	// caddymgr emit falls back to the built-in Arenet
	// default for every route.
	ErrorTemplates map[string]storage.ErrorPageTemplate
	// MaintenancePageHTML (Task 4) is the operator's stored global
	// maintenance page body (Task 2, storage.MaintenancePageConfig
	// singleton), read by the manager from BoltDB before each
	// applyLocked — same plumbing as ErrorTemplates above. Empty
	// string (fresh install / operator never customized it) means
	// "use the branded default" — resolveMaintenancePage in
	// maintenance.go implements that fallback.
	MaintenancePageHTML string
	// AccessLog (v2.50) is the operator's access-log setting, and
	// AccessLogPath the already-resolved absolute file. Resolution
	// happens in the caller because it needs the process config (data
	// dir, ARENET_ACCESS_LOG_PATH), which the emitter has no business
	// reading.
	AccessLog     storage.AccessLogConfig
	AccessLogPath string
	// MaintenanceMessage (v2.18.0) is the operator's global
	// maintenance message (storage.MaintenancePageConfig.Message),
	// read from BoltDB before each applyLocked alongside
	// MaintenancePageHTML. It is substituted — HTML-escaped, with
	// newlines rendered as <br> — into the maintenance 503 body via
	// the {arenet.maintenance.message} placeholder (both in the
	// built-in default page and in any custom page that references
	// it). Empty string (default) renders nothing.
	MaintenanceMessage string
	// ExternalCerts (v2.19.0, external-certificates SOCLE) maps
	// ExternalCertificate.ID → the operator-uploaded cert, read by
	// the manager from BoltDB before each applyLocked. A route with
	// CertSource=="manual" references one via Route.CertID; the
	// caddymgr emit then (a) serves the cert through
	// apps.tls.certificates.load_pem, (b) adds the host to
	// automatic_https.skip_certificates, and (c) EXCLUDES the host
	// from every ACME subject partition — so Caddy never tries to
	// ACME-issue a host it already serves a manual cert for. A nil /
	// empty map is the common case (no manual-cert routes).
	ExternalCerts map[string]storage.ExternalCertificate
	// TCPServices (v2.42) are the layer-4 relays to emit alongside the
	// HTTP app. Empty — the case of every installation that has not
	// created one — emits no `layer4` key at all, so the config stays
	// byte-identical to the pre-v2.42 one.
	TCPServices []storage.TCPService
}

// acmePartition splits a TLS-enabled route's public subjects into
// two slices based on the route's ACMEChallenge (Step J.4 §5.4).
// The caller (buildConfigJSON) accumulates one acmePartition over
// the route iteration; buildTLSPolicies consumes it to decide
// which of HTTP-01 and DNS-01 policies to emit. Two-element split
// keeps the partition local to caddymgr — no new public type.
type acmePartition struct {
	HTTP01 []string
	DNS01  []string
}

// buildConfigJSON renders the full Caddy config for the given routes.
//
// Step I.1 wires real ACME: routes with TLSEnabled=true produce a
// dedicated tls.automation.policies entry pointing at Let's Encrypt
// (staging in dev mode, prod otherwise). The historical catch-all
// "internal" policy stays as the LAST policy so any host not bound
// to an ACME policy (localhost, .local, IP literals) still receives
// a self-signed cert and Caddy can answer HTTPS at all.
//
// AutomaticHTTPS remains disabled at the server level: Caddy's
// built-in port-80 redirect logic and the implicit cert magic are
// replaced by Arenet's own explicit translation (per-route opt-in,
// I.2 redirect handler). Keeps the JSON deterministic and testable.
func buildConfigJSON(routes []storage.Route, opts buildOpts) ([]byte, error) {
	httpRoutes := make([]httpRoute, 0, len(routes)+1)
	httpsRoutes := make([]httpRoute, 0, len(routes)+1)
	// Step J.4: publicly-validatable TLS hosts, partitioned by ACME
	// challenge. Pre-J.4 (and any route persisted without an
	// explicit ACMEChallenge) feeds HTTP01 — the same behaviour
	// Step I.1 shipped. A route with ACMEChallenge=="dns-01" feeds
	// DNS01 instead. The partition is consumed by buildTLSPolicies
	// to emit up to two ACME policies (one per non-empty side).
	acme := acmePartition{
		HTTP01: make([]string, 0, len(routes)),
		DNS01:  make([]string, 0, len(routes)),
	}

	// openWindow is the maintenance window of the iteration in flight.
	// Declared outside the loop so the check after it can tell whether
	// some exit path forgot to close one — see the error below the loop.
	var openWindow *maintenanceWindow

	for _, r := range routes {
		// Handler chain order (spec §11.5) — the metrics handler MUST
		// run before reverse_proxy so it observes the upstream's status
		// code via the deferred Inc. Reversing this order makes the
		// metric record 200 for every request.
		//
		// The "handler" string is exactly metrics.HandlerName
		// ("arenet_routemetrics", no dot, no http.handlers. prefix).
		// Caddy's JSON config convention uses the last-segment form;
		// passing the dotted ModuleID silently fails config load
		// (spec §3.5). Tests in this package guard both invariants.
		metricsHandler := map[string]any{
			"handler":  metrics.HandlerName,
			"route_id": r.ID,
		}
		// Step V.1.3 — thread the operator's
		// NormalTrafficExcludePaths into each per-route
		// metricsHandler emit. Field is omitted when the
		// slice is empty so byte-equality with pre-V.1.3
		// configs is preserved on default installs.
		if len(opts.NormalTrafficExcludePaths) > 0 {
			metricsHandler["exclude_paths"] = opts.NormalTrafficExcludePaths
		}
		// Topology Plan B Phase 2.1 — thread the route's
		// lowercased + port-stripped + deduped known-host set
		// into the per-route metricsHandler emit. The Phase 1
		// middleware (commit af48ad6) consumes this via
		// RouteMetricsHandler.KnownHosts to gate the per-host
		// counter bump. Field is omitted when the set is
		// empty (storage-layer impossible since validate()
		// rejects empty Host, but defensively kept omitempty
		// so any future degraded path stays wire-compatible
		// with pre-Phase-2.1 configs).
		if known := buildKnownHosts(r); len(known) > 0 {
			metricsHandler["known_hosts"] = known
		}
		// Step R Phase 1.1 — upstream 4xx/5xx catch + the preserve-JSON
		// contract. The shared status-code list (401 + 407 deliberately
		// absent so their upstream Www-Authenticate / Proxy-Authenticate
		// challenge headers reach the client verbatim — the 2026-06-24
		// Harbor / Docker registry fix) and the two-block handle_response
		// structure (JSON pass-through, /api pass-through, else branded
		// error page) both live in reverse_proxy_emit.go. See
		// errorBrandingStatusCodes and buildErrorBrandingHandleResponse
		// there for the full empirical rationale + Caddy source citations.
		errorStatusCodes := errorBrandingStatusCodes()
		sharedHandleResponse := buildErrorBrandingHandleResponse(errorStatusCodes)

		// Assemble the reverse_proxy handler for this route's pool via the
		// single shared builder (reverse_proxy_emit.go). It emits
		// upstreams + load_balancing (+ weights) + the Host-preserving
		// request header + transport.tls-if-https + flush_interval-if-set
		// + health_checks-if-enabled + the shared handle_response. The
		// extraction is byte-identity-guarded by
		// TestBuildReverseProxyHandler_RouteEmissionByteIdentical: a route
		// without per-path upstreams emits exactly the JSON the previous
		// inline construction did.
		//
		// Step J.2: the HealthCheck pointer is passed only when Enabled,
		// so a disabled check omits the whole health_checks key (Caddy
		// treats absence as "no probe runs").
		var hcPtr *storage.HealthCheck
		if r.HealthCheck.Enabled {
			hc := r.HealthCheck
			hcPtr = &hc
		}
		proxyHandler, err := buildReverseProxyHandler(proxyPoolParams{
			Upstreams:          r.Upstreams,
			LBPolicy:           r.LBPolicy,
			HealthCheck:        hcPtr,
			ProbeHost:          r.Host,
			UsesHTTPS:          r.PoolUsesHTTPS(),
			InsecureSkipVerify: r.InsecureSkipVerify,
			// v2.60 — the route's TLS identity for its own pool.
			UpstreamTLSServerName: r.UpstreamTLSServerName,
		}, sharedHandleResponse, r.UploadStreamingMode)
		if err != nil {
			return nil, fmt.Errorf("route %s (%s): %w", r.ID, r.Host, err)
		}

		// Task 4 — maintenance mode. When the route carries a
		// MaintenanceConfig, it is served EXCLUSIVELY by the
		// maintenance subroute: everyone gets a static_response
		// 503 (+ Retry-After + branded/operator body) except the
		// client_ip bypass allow-list, which reaches the normal
		// proxy handler chain unmodified. This branch REPLACES
		// the whole normal gate/proxy assembly below (auth, WAF,
		// headers) — a maintenance route is not simultaneously
		// gated by those, mirroring the forward-auth deny path's
		// "STOP appending to the chain" posture (manager.go
		// buildForwardAuthDenyHandler precedent) but with a
		// DISTINCT two-inner-route subroute shape instead of a
		// single terminal static_response.
		//
		// Note: Route.Disabled routes never reach buildConfigJSON
		// at all (filterDisabledRoutes runs once in applyLocked
		// before this loop, manager.go:542-573), so a maintenance
		// route reaching this point is implicitly enabled. The
		// r.Disabled check below is defensive belt-and-braces for
		// direct buildConfigJSON callers (e.g. tests) that don't
		// pre-filter.
		// Open the maintenance window BEFORE anything in this iteration
		// can append a route, so httpFrom/httpsFrom really are "the
		// state before this route". Nothing between the top of the loop
		// and here appends; checked, not assumed.
		//
		// openMaintenanceWindow returns nil for every route that is not
		// in maintenance, so the cost on the normal path is one nil and
		// not one byte of emitted JSON can move.
		openWindow = openMaintenanceWindow(
			r, metricsHandler, opts.MaintenancePageHTML, opts.MaintenanceMessage,
			len(httpRoutes), len(httpsRoutes),
		)

		// v2.70.0 — maintenance no longer shares this branch.
		//
		// It used to, and that was the defect: short-circuiting here
		// skipped every remaining line of the body, so a bypassed client
		// reached a route with no path rules, no headers and no gates.
		// A maintenance route now runs through the normal assembly like
		// any other and is gated afterwards by its window, opened just
		// above and closed on every exit below.
		//
		// The redirect state keeps the branch. It has nothing to
		// preview and no bypass list, and separating the two is what
		// let the maintenance half move without touching this one.
		if r.RedirectConfig != nil && !r.Disabled {
			replacement := buildRedirectStateHandler(metricsHandler, r.RedirectConfig)

			allHosts := r.AllHosts()
			route := httpRoute{
				Match:    []matcherSet{{Host: allHosts}},
				Handle:   []map[string]any{replacement},
				Terminal: true,
			}

			// Same TLS-redirect / cert-registration tail as the
			// normal path below (Step I.2 + Step I.3/J.4): a
			// maintenance route still needs its host reachable
			// on both listeners and its cert issued/kept alive,
			// only the served content differs.
			if r.TLSEnabled && r.RedirectToHTTPS {
				httpRoutes = append(httpRoutes, buildRedirectRoute(r.ID, r.Host, r.CountryBlock, allHosts))
			} else {
				httpRoutes = append(httpRoutes, route)
			}
			if r.TLSEnabled {
				httpsRoutes = append(httpsRoutes, route)
				// v2.19.0 — a manual-cert route serves its uploaded
				// cert via load_pem; it must NEVER be added to the ACME
				// subject partition (Caddy would then ACME-issue the
				// host IN ADDITION to serving the manual cert — the
				// exact rate-limit / duplication bug the SOCLE prevents).
				// The httpsRoutes append above is kept: the route still
				// serves on :443 (that's how the manual cert is used at
				// handshake, and how a maintenance manual route 503s).
				if r.CertSource != storage.RouteCertSourceManual {
					for _, h := range allHosts {
						if !certmagic.SubjectQualifiesForPublicCert(h) {
							continue
						}
						if !r.UseDedicatedCert {
							if _, covered := IsHostCoveredByManagedDomain(h, opts.ManagedDomains); covered {
								continue
							}
						}
						switch r.ACMEChallenge {
						case storage.ACMEChallengeDNS01:
							acme.DNS01 = append(acme.DNS01, h)
						default:
							acme.HTTP01 = append(acme.HTTP01, h)
						}
					}
				}
			}
			continue
		}

		// Step K.1 — per-route auth (refactored from Step I.5's flat
		// BasicAuthEnabled toggle into the AuthMode enum: "none",
		// "basic", "forward_auth"). The three modes are mutually
		// exclusive (§1.3 decision 2). The handler emitted (or not)
		// here is the auth gate; it sits BEFORE the WAF and the
		// reverse_proxy in the chain so a failed auth short-circuits
		// the rest (Finding #9 chain order preserved).
		//
		// Step I.6 — custom request/response headers (`headers`
		// handler) slot between auth and the proxy. Modifying
		// headers on a request that's about to be 401'd is wasted
		// work, hence ordering AFTER auth; modifying them BEFORE
		// the proxy is required so request changes reach the
		// upstream and response changes are applied on the way back.
		//
		// Handler chain order (spec §3.2 + K.1 §5.1):
		//   [metrics, auth?, waf?, headers?, reverse_proxy]
		// Metrics MUST stay first to observe the final status code
		// (§11.5 invariant).
		handlers := []map[string]any{metricsHandler}

		// Step Q (2026-06-18) — per-route rate limit gate.
		// Slot RIGHT AFTER metrics (so the routemetrics defer
		// observes the 429 status and surfaces the throttling
		// in the per-route counter tile) and BEFORE every other
		// gate (country-block, CrowdSec, auth, WAF). Counter
		// comparison is the cheapest wall : a brute-force IP
		// hits the rate limiter and bounces with 429 without
		// ever exercising the CIDR / LAPI / Coraza checks
		// downstream. The emit is omitted entirely when the
		// route has no RateLimit configured — pre-Q routes
		// stay byte-equal to their pre-Q handler chain.
		if rlHandler := buildRateLimitHandler(r.ID, r.RateLimit); rlHandler != nil {
			handlers = append(handlers, rlHandler)
		}

		// Step W.3 — country-block gate. Chain position #2 per
		// spec §D10: AFTER routemetrics (so the V.1.2 defer
		// observes the 403 status and surfaces the block in
		// the per-route error-rate tile with no new plumbing)
		// and BEFORE crowdsec/auth/waf (operator-declared
		// static policy is cheaper than dynamic LAPI lookups
		// and more permanent than rate-limit decisions). The
		// emit is omitted entirely when Mode == "" || "off"
		// — zero per-request cost for routes that don't use
		// the feature. Mirror of the WAF cheap-skip at
		// buildWAFHandler.
		if cbHandler := buildCountryBlockHandler(r.ID, r.Host, r.CountryBlock); cbHandler != nil {
			handlers = append(handlers, cbHandler)
		}

		// v1 path-based-rules: whole-domain source-IP gate. Sibling of
		// country-block — cheap static policy before crowdsec/auth/waf.
		// Emitted as a route (matcher + static_response) so it can be an
		// inner route of the subroute; wrap accordingly to match the
		// existing handler-slice shape.
		if r.IPFilter != nil {
			if ipRoute := buildIPFilterRoute(*r.IPFilter); ipRoute != nil {
				// The chain is a handler slice; a matcher+handler pair is
				// expressed as a `subroute` with one inner route so it
				// slots into `handlers`. (Matches wrapInSubroute usage.)
				handlers = append(handlers, map[string]any{
					"handler": "subroute",
					"routes":  []map[string]any{ipRoute},
				})
			}
		}

		// Step N.1 — CrowdSec reputation gate. Slot RIGHT AFTER
		// metrics and BEFORE every other gate (auth, WAF,
		// headers): the IP-reputation check is the first wall.
		// A blocked IP returns 403 without exposing any of the
		// downstream gates to forged traffic.
		//
		// DIVERGENCE FROM STEP M (acknowledged & forced):
		// CrowdSec 403s ARE counted in fourxx_count. This is
		// OPPOSITE to WAF behaviour (M's AC #4, verified live
		// at M.5 with 212 WAF blocks + 3 real backend 404s
		// that "never collide"), not consistent with it.
		//
		// Mechanism for the WAF (v2.26): internal/waf returns
		// its block as a HandlerError whose error implements
		// SecurityBlock(); the metrics middleware
		// (internal/metrics metricsStatus) records it outside the
		// 4xx/5xx classes. (Earlier comments described a
		// context "wafBlocked" flag that was never implemented;
		// AC #4 only held because every Caddy error used to be
		// recorded as 200 — fixed in v2.26.)
		// hslatman/caddy-crowdsec-bouncer v0.12.1 exposes NO
		// callback hook of any shape (confirmed by source
		// read of internal/core/core.go and
		// internal/bouncer/stream.go — there is no listener
		// registration API nor a context flag we can read
		// after the handler returns). The 403 therefore
		// reaches the metrics middleware as a GENERIC 4xx.
		//
		// Operator interpretation on the M+Q+N dashboard:
		//   - bucket.fourxx_count  = real backend 4xx + CrowdSec 403s
		//   - bucket.waf_block_count = pure WAF signal (M's AC #4
		//     guarantees no contamination)
		//   - bucket.crowdsec_decision_count (N.2) = pure
		//     CrowdSec signal via the sentinel "_crowdsec"
		//     route + the BumpCrowdSecDecisions hook.
		// Pinned by N spec AC #N1-divergence-vs-M.
		//
		// Only emitted when the LAPI key is configured (same
		// flag controls the apps.crowdsec block emission).
		// Empty-key path keeps the chain byte-identical to
		// pre-N for the AC #16/#17 anti-regression guarantee.
		if opts.CrowdSec.apiKey != "" {
			handlers = append(handlers, map[string]any{"handler": "crowdsec"})
		}
		// Step K.4 — captured here so the passthrough-route block
		// below (post-handler-chain construction) can read the
		// resolved provider without re-doing the map lookup. nil
		// when AuthMode != "forward_auth" OR provider is missing
		// (the FAIL-CLOSED deny path).
		var fwdAuthProviderForPassthrough *storage.ForwardAuthProvider
		switch r.AuthMode {
		case storage.RouteAuthBasic:
			// Step I.5 — Basic Auth, preserved verbatim through K.1.
			// Step Q5 — extracted into buildBasicAuthHandlerFromConfig
			// so path-rules (Q5, per-path basic auth override) can
			// reuse the SAME shape, in particular the hash_cache
			// field (see that function's doc comment for the
			// RAM-exhaustion rationale). Reusing here guarantees the
			// route-level and path-level handlers never drift.
			// Realm is per-vhost ("Arenet route <host>") — restores
			// the pre-extraction behaviour (fix for a Task 5 review
			// regression where the extraction dropped r.Host access
			// and fell back to a fixed "Arenet" realm).
			// v2.58 — a path rule may exempt itself from the route's
			// authentication; with none doing so this appends exactly the
			// same single handler as before. See buildPathAuthExemption.
			handlers = append(handlers, buildPathAuthExemption(
				buildBasicAuthHandlerFromConfig(r.BasicAuth, fmt.Sprintf("Arenet route %s", r.Host)),
				r.PathRules, nil)...)
		case storage.RouteAuthForwardAuth:
			// Step K.1 — forward_auth. Look up the referenced
			// provider in opts.ForwardAuthProviders (passed in by
			// applyLocked from the storage layer). The provider's
			// existence is enforced at the API layer (a route
			// referencing an unknown provider is rejected at
			// edit-time per §5.1; DELETE on a referenced provider
			// is rejected with 409 per §1.3 decision 14), so the
			// happy path always finds a match here.
			//
			// FAIL-CLOSED CONTRACT — security-critical. If we ever
			// reach this code with an unknown provider (e.g. a
			// storage corruption, a future migration drift, a
			// direct BoltDB edit, or any class of bug we haven't
			// imagined), the route MUST NOT serve traffic to the
			// upstream without authentication. The previous
			// implementation fell back to no-auth, which silently
			// exposed an operator's intended-protected route as
			// public — the worst class of failure for an auth
			// control. Fail-closed via a static_response 503
			// short-circuits the chain BEFORE the reverse_proxy:
			// the route becomes loudly unavailable (Caddy logs,
			// browser-visible 503) instead of silently exposed.
			// Recovery is operator action: configure the missing
			// provider, Caddy reloads, the route comes back up.
			provider, ok := opts.ForwardAuthProviders[r.ForwardAuth.ProviderName]
			if ok {
				// v2.58 — same exemption wrapper as basic auth above. The
				// provider is passed so the headers it copies are stripped
				// on the exempted paths, on top of the conventional set.
				handlers = append(handlers, buildPathAuthExemption(
					buildForwardAuthHandler(provider), r.PathRules, &provider)...)
				// Capture for the passthrough-route block below.
				// Local-variable copy — the loop iteration reuses
				// the same map key on the next route, so we take a
				// pointer to a per-iteration copy rather than the
				// map's value (would alias across iterations).
				p := provider
				fwdAuthProviderForPassthrough = &p
			} else {
				// Build the deny handler + STOP appending to the
				// chain — no waf, no headers, no reverse_proxy.
				// The static_response is the terminal handler.
				handlers = append(handlers, buildForwardAuthDenyHandler(r.ForwardAuth.ProviderName))
				denyHosts := r.AllHosts()
				denyRoute := httpRoute{
					Match:    []matcherSet{{Host: denyHosts}},
					Handle:   []map[string]any{wrapInSubroute(handlers)},
					Terminal: true,
				}
				httpRoutes = append(httpRoutes, denyRoute)
				if r.TLSEnabled {
					httpsRoutes = append(httpsRoutes, denyRoute)
					// Still register TLS subjects so the cert is
					// issued (the operator can fix the provider
					// without losing the cert when reload runs).
					// v2.19.0 — but NOT for a manual-cert route: it
					// serves the uploaded cert via load_pem, so adding
					// its host to the ACME partition here would
					// double-issue (see the maintenance-path note
					// above). httpsRoutes stays appended — the deny
					// route still serves on :443.
					if r.CertSource != storage.RouteCertSourceManual {
						for _, h := range denyHosts {
							if !certmagic.SubjectQualifiesForPublicCert(h) {
								continue
							}
							if r.ACMEChallenge == storage.ACMEChallengeDNS01 {
								acme.DNS01 = append(acme.DNS01, h)
							} else {
								acme.HTTP01 = append(acme.HTTP01, h)
							}
						}
					}
				}
				// Exit path #1 of 2 for a maintenance route. The deny
				// route is in the window, so it gets gated behind the
				// bypass list and the 503 follows it: with maintenance
				// off an unresolvable provider denies, so a bypassed
				// client is denied too and everyone else meets the 503.
				httpRoutes, httpsRoutes = closeMaintenanceWindow(openWindow, httpRoutes, httpsRoutes)
				openWindow = nil
				continue
			}
		}
		// Step I.4 — WAF (Coraza). Slot between basicauth and the
		// headers handler:
		//   - AFTER basicauth, so a 401 short-circuits before
		//     wasting Coraza analysis on anonymous traffic;
		//   - BEFORE headers, so Coraza analyses the original
		//     request as the client sent it (headers cosmetic
		//     mutations would otherwise confuse the rules);
		//   - BEFORE proxy, so a block-mode rejection (403) never
		//     reaches the upstream.
		if wafHandler := buildWAFHandler(r.ID, r.Host, r.WAFMode, r.UploadStreamingMode, r.WAFDisableCRS, r.WAFExcludeRules, r.WAFExcludeTags, r.WAFTargetedExclusions, r.WAFCustomRules, r.WAFSecLang); wafHandler != nil {
			handlers = append(handlers, wafHandler)
		}
		if headersHandler := buildHeadersHandler(r.RequestHeaders, r.ResponseHeaders); headersHandler != nil {
			handlers = append(handlers, headersHandler)
		}
		// Step Q5 — per-path rules (additive overrides on top of the
		// route-level chain above). When PathRules is empty this is
		// byte-identical to pre-Q5 (plain proxyHandler append), so
		// every route without path rules is unaffected.
		if len(r.PathRules) > 0 {
			// Per-path basic auth reuses the route's vhost realm too
			// (per-host, not per-path) — keeps credential scoping
			// tied to the vhost, consistent with the route-level site
			// above.
			pathRealm := fmt.Sprintf("Arenet route %s", r.Host)
			// v2.23.0 — per-path upstream. A rule with its own upstream
			// pool proxies to THAT pool via the shared reverse_proxy
			// builder (own load-balancing / health-check / transport,
			// reusing THIS route's sharedHandleResponse so the error
			// branding is identical across the route pool and every path
			// pool). A rule with no pool inherits the route's proxyHandler.
			// DECISION: a path pool is autonomous (v2.23.1): its
			// InsecureSkipVerify is the path rule's OWN field, NOT the
			// route's — so a self-signed https backend on one path doesn't
			// force the whole route insecure (Q1). UploadStreamingMode is
			// still inherited from the route (no per-path toggle — YAGNI).
			// A rule with no pool inherits the route's whole proxyHandler.
			pathProxy := func(pr storage.PathRule) (map[string]any, error) {
				if len(pr.Upstreams) == 0 {
					return proxyHandler, nil // inherit the route pool
				}
				return buildReverseProxyHandler(proxyPoolParams{
					Upstreams:          pr.Upstreams,
					LBPolicy:           pr.LBPolicy,
					HealthCheck:        pr.HealthCheck, // already a pointer
					ProbeHost:          r.Host,
					UsesHTTPS:          poolUsesHTTPS(pr.Upstreams),
					InsecureSkipVerify: pr.InsecureSkipVerify,
					// v2.60 — the path pool's OWN TLS identity, never the
					// route's: a pool that dials a different address has a
					// different certificate, so inheriting would verify the
					// wrong backend. Same autonomy as InsecureSkipVerify.
					UpstreamTLSServerName: pr.UpstreamTLSServerName,
				}, sharedHandleResponse, r.UploadStreamingMode)
			}
			sub, err := buildPathRulesSubroute(r.ID, r.PathRules, proxyHandler, func(c storage.BasicAuthRouteConfig) map[string]any {
				return buildBasicAuthHandlerFromConfig(c, pathRealm)
			}, func(providerName string) (map[string]any, bool) {
				// v2.57 — resolve against the same provider map the route
				// level uses, with the same fail-closed answer when the
				// name no longer exists.
				provider, found := opts.ForwardAuthProviders[providerName]
				if !found {
					return buildForwardAuthDenyHandler(providerName), false
				}
				return buildForwardAuthHandler(provider), true
			}, pathProxy)
			if err != nil {
				return nil, fmt.Errorf("route %s (%s) path rules: %w", r.ID, r.Host, err)
			}
			handlers = append(handlers, sub)
		} else {
			handlers = append(handlers, proxyHandler)
		}

		// Step I.3: Match.Host carries the full hostname set
		// (primary + aliases) so Caddy dispatches the same route to
		// any of them. acmeSubjects collects every TLS-enabled host
		// individually so a single multi-SAN cert covers them all.
		//
		// Step K.4 parity fix — the handler chain is wrapped in a
		// canonical `subroute` (mirror forward_auth_authelia
		// .caddyfiletest) and the route is marked terminal. Empty
		// chain (theoretically possible) yields an empty subroute,
		// but in practice handlers always carries at least the
		// metrics handler.
		allHosts := r.AllHosts()
		route := httpRoute{
			Match:    []matcherSet{{Host: allHosts}},
			Handle:   []map[string]any{wrapInSubroute(handlers)},
			Terminal: true,
		}

		// Step K.4 — auth passthrough. When the resolved
		// forward-auth provider declares an AuthPassthroughPrefix,
		// emit an additional route BEFORE the main one matching
		// that path prefix on the same Host(s). It reverse-proxies
		// straight to the provider's verify-URL host, no
		// forward_auth gate. Caddy dispatches routes in
		// declaration order — the prefixed route MUST land first
		// so it claims the matching requests before the catch-all
		// (the main `route`) sees them.
		//
		// Use case: Authentik embedded outpost serves its UI /
		// OAuth start endpoints under
		// `/outpost.goauthentik.io/*` on the application's own
		// External Host. Without the passthrough, those URIs
		// would go through forward_auth → loop or 404. Pattern is
		// generic: oauth2-proxy uses `/oauth2/*` the same way.
		var passthroughRoute *httpRoute
		if fwdAuthProviderForPassthrough != nil && fwdAuthProviderForPassthrough.AuthPassthroughPrefix != "" {
			pr := buildAuthPassthroughRoute(*fwdAuthProviderForPassthrough, allHosts)
			passthroughRoute = &pr
		}

		// Step I.2: when TLS is on AND the operator asked for an
		// automatic HTTP→HTTPS upgrade, the HTTP-side route serves
		// a 301 instead of the proxy. The HTTPS-side keeps the
		// normal proxy chain. RedirectToHTTPS is a NO-OP when TLS
		// is off (the field is meaningless without a target HTTPS
		// listener) — L3 in the Step I spec.
		//
		// Caddy injects the ACME HTTP-01 challenge handler ABOVE
		// these user routes at load time (apps.tls.automation owns
		// that side), so /.well-known/acme-challenge/* is never
		// shadowed by the 301 — verified by the smoke pass on
		// staging at I.7.
		if r.TLSEnabled && r.RedirectToHTTPS {
			// Passthrough route also serves under HTTPS-only
			// when the operator opted into the redirect; on the
			// HTTP side the 301 wins (Caddy matches the most
			// specific Host route — here both share the same
			// Host, so the order matters: 301 first, passthrough
			// never reached on :80). That's intentional — the
			// passthrough endpoint is OIDC + must be served over
			// HTTPS too.
			httpRoutes = append(httpRoutes, buildRedirectRoute(r.ID, r.Host, r.CountryBlock, allHosts))
		} else {
			if passthroughRoute != nil {
				httpRoutes = append(httpRoutes, *passthroughRoute)
			}
			httpRoutes = append(httpRoutes, route)
		}
		if r.TLSEnabled {
			if passthroughRoute != nil {
				httpsRoutes = append(httpsRoutes, *passthroughRoute)
			}
			httpsRoutes = append(httpsRoutes, route)
			// Step I.7 hotfix (Finding #6): only PUBLICLY validatable
			// hostnames go into the ACME policy subjects list. A
			// .local / .lan / localhost / IP-literal subject in an
			// ACME policy makes Caddy try HTTP-01 against Let's
			// Encrypt, which can't reach those names — so no cert
			// is ever acquired and the handshake fails with an
			// "internal error" alert at Client Hello time.
			//
			// Private hosts fall through to the catch-all `internal`
			// policy below and get a self-signed cert from Caddy's
			// embedded local CA. certmagic.SubjectQualifiesForPublicCert
			// implements the RFC 6761 / 2606 classification (IPs,
			// loopback, .local, .home.arpa, etc.) and is the same
			// function Caddy uses internally for its own auto-HTTPS.
			// Step J.4: route a public host into HTTP01 or DNS01 based
			// on the route's ACMEChallenge. The empty string and
			// "http-01" both land in HTTP01 (default + pre-J.4 rows);
			// "dns-01" lands in DNS01. A wildcard host (`*.foo.bar`)
			// is rejected by certmagic.SubjectQualifiesForPublicCert
			// only if it fails the IP/loopback/.local classification;
			// wildcards DO qualify and reach the partition, where the
			// API guarantees they sit on a dns-01 route.
			//
			// v2.19.0 — a manual-cert route is EXCLUDED from the ACME
			// partition entirely: it serves its operator-uploaded cert
			// via load_pem, so adding its host here would make Caddy
			// ACME-issue the host IN ADDITION (the rate-limit /
			// duplication bug the SOCLE prevents). httpsRoutes above is
			// kept — the route still serves on :443, which is how the
			// manual cert is presented at handshake.
			if r.CertSource != storage.RouteCertSourceManual {
				for _, h := range allHosts {
					if !certmagic.SubjectQualifiesForPublicCert(h) {
						continue
					}
					// Step O.2 (D5.A short-circuit on empty managed
					// domains): when the route's host is covered by
					// a managed domain AND the route does NOT opt
					// out via UseDedicatedCert, skip the per-route
					// partition — the wildcard policy at
					// `*.<apex>` will serve the cert at handshake
					// time via certmagic's wildcard expansion. The
					// covered+opt-out path (UseDedicatedCert=true)
					// emits its own per-route policy ALONGSIDE the
					// wildcard, sharing the apex but with a
					// dedicated key (D1.B).
					if !r.UseDedicatedCert {
						if _, covered := IsHostCoveredByManagedDomain(h, opts.ManagedDomains); covered {
							continue
						}
					}
					switch r.ACMEChallenge {
					case storage.ACMEChallengeDNS01:
						acme.DNS01 = append(acme.DNS01, h)
					case storage.ACMEChallengeInherited:
						// Defensive: a route persisted as
						// "inherited" should always be covered by
						// some managed domain (the storage layer
						// only sets "inherited" inside the managed-
						// domain create handler). Reaching this
						// fallback means the operator deleted the
						// managing apex without invoking the
						// reverse migration — programming-error
						// path. Same posture as J.4's "dns-01 with
						// no provider" defensive fall-back: route
						// to HTTP-01 so the host still gets a cert
						// rather than silently dropping it from
						// every policy. The dashboard will show
						// the route as "per-route ACME" instead
						// of "inherited"; the operator notices.
						acme.HTTP01 = append(acme.HTTP01, h)
					default:
						acme.HTTP01 = append(acme.HTTP01, h)
					}
				}
			}
		}

		// Exit path #2 of 2 for a maintenance route: the normal end of
		// the body. Everything this iteration emitted is now in the
		// window, so gate it behind the bypass list and append the 503.
		// A no-op for every route that is not in maintenance.
		httpRoutes, httpsRoutes = closeMaintenanceWindow(openWindow, httpRoutes, httpsRoutes)
		openWindow = nil
	}

	// A window left open means some exit path out of the loop body did
	// not close it, which would emit a maintenance route serving its
	// real content to the world. Loud by design: this is the guard that
	// makes two explicit call sites acceptable instead of wrapping the
	// whole body in a closure.
	if openWindow != nil {
		return nil, fmt.Errorf(
			"internal: maintenance window for route %s left open — a new exit path "+
				"from the route loop must call closeMaintenanceWindow", openWindow.routeID)
	}

	// Final catch-all: must be the LAST route. No match block = matches every
	// request that none of the prior host-matched routes handled.
	// v2.9.10 Bug 1: body resolved from opts.ErrorTemplates (operator-flagged
	// IsCatchallDefault template's Pages[404], else builtin Arenet 404 HTML).
	httpRoutes = append(httpRoutes, catchAllRoute(opts.ErrorTemplates, opts.CrowdSec.apiKey != ""))

	httpListen, httpsListen := listenPortsFor(opts.DevMode)

	// Step I.7 hotfix (Finding #7): Caddy's automatic_https struct
	// has three orthogonal flags with VERY different semantics
	// (per modules/caddyhttp/autohttps.go in caddy/v2 v2.11.3):
	//
	//   - `disable: true`              kills EVERYTHING: cert
	//                                  management AND auto-redirects
	//                                  AND every other auto-HTTPS
	//                                  side effect. This is the
	//                                  nuclear option.
	//   - `disable_certificates: true` kills ONLY automatic cert
	//                                  acquisition; auto-redirects
	//                                  remain.
	//   - `disable_redirects: true`    kills ONLY the implicit
	//                                  HTTP→HTTPS 301 routes Caddy
	//                                  would add on every TLS host;
	//                                  cert management stays active.
	//
	// Pre-Finding-#7 Arenet (since Step B / Step E, latent until
	// smoke I.7 §2.3 finally exercised a real TLS handshake on
	// :8443) emitted `disable: true` on BOTH servers, which killed
	// cert management on `arenet_https`. The :8443 listener came
	// up but had nothing to present at Client Hello, so every
	// handshake failed with `tlsv1 alert internal error`.
	//
	// The correct intent — and what we emit now — is
	// `disable_redirects: true` ONLY: Arenet provides its own
	// HTTP→HTTPS 301 routes per-route via buildRedirectRoute
	// (Step I.2), so Caddy's blanket auto-redirect would step on
	// our explicit per-route control. Cert management stays
	// active and consumes the tls.automation.policies we emit
	// (public hosts → ACME, private hosts → internal CA via the
	// catch-all policy added in Finding #6).
	// Step R — error-page routes per server. Routes WITHOUT TLS
	// land on arenet_http, routes WITH TLS land on arenet_https.
	// The split mirrors how primary routes are dispatched.
	//
	// Phase 1.1 fix : the Errors block is emitted for EVERY
	// route, not gated on operator opt-in. Phase 1 wrongly
	// added a gate "only emit if at least one route has a
	// template/override" with the rationale "preserve byte-
	// identical JSON for pre-R rollout". That concern was a
	// one-time rollout safety net — post-Phase-1 the operator
	// expectation (and the original Step R spec) is "every
	// route always gets the Arenet branded default page for
	// 401/403/404/429/500/502/503/504 with zero config".
	// Empirical smoke caught this : a freshly-created route
	// returning a Caddy-generated 404 served the bare
	// "404 page not found" plain-text body instead of the
	// branded default.
	//
	// buildErrorRoutesForServer returns nil when no route is
	// on this server's TLS scope ; the Errors field is then
	// omitted via omitempty, which keeps the JSON tight for
	// the http-only-or-https-only deployment cases.
	servers := map[string]httpServer{
		"arenet_http": {
			Listen: []string{httpListen},
			AutomaticHTTPS: &automaticHTTPSConfig{
				DisableRedirects: true,
			},
			Routes: httpRoutes,
		},
	}
	if errRoutes := buildErrorRoutesForServer(routes, opts.ErrorTemplates, false, nil); len(errRoutes) > 0 {
		srv := servers["arenet_http"]
		srv.Errors = &httpErrors{Routes: errRoutes}
		servers["arenet_http"] = srv
	}

	// v2.50 — point both servers at the access-log sink. Caddy enables
	// access logging only when a server carries `logs`
	// (caddyhttp/app.go:234), so a sink with no server attached to it
	// creates the file and receives nothing — which loads cleanly and
	// looks entirely correct.
	if logs := accessLogServerConfig(opts.AccessLog, opts.AccessLogPath); logs != nil {
		srv := servers["arenet_http"]
		srv.Logs = logs
		servers["arenet_http"] = srv
	}

	if len(httpsRoutes) > 0 {
		// v2.9.10 Bug 1: same branded-body resolution as the HTTP server.
		httpsRoutes = append(httpsRoutes, catchAllRoute(opts.ErrorTemplates, opts.CrowdSec.apiKey != ""))
		httpsServer := httpServer{
			Listen: []string{httpsListen},
			AutomaticHTTPS: &automaticHTTPSConfig{
				DisableRedirects: true,
				// Step #S-20: routes covered by a managed-domain
				// wildcard (ACMEChallenge == "inherited") must be
				// skipped from Caddy's per-host auto-cert flow, so
				// Caddy serves the wildcard cert (pre-acquired via
				// apps.tls.certificates.automate) for them at TLS
				// handshake via SNI matching instead of obtaining
				// a separate cert per route. This uses
				// skip_certificates (NOT skip): the host stays in
				// auto-HTTPS (routing + redirect handling intact),
				// only per-host cert provisioning is suppressed.
				SkipCerts: buildSkipList(routes),
			},
			TLSConnPolicies: []tlsConnectionPolicy{{}},
			Routes:          httpsRoutes,
		}
		if errRoutes := buildErrorRoutesForServer(routes, opts.ErrorTemplates, true, nil); len(errRoutes) > 0 {
			httpsServer.Errors = &httpErrors{Routes: errRoutes}
		}
		if logs := accessLogServerConfig(opts.AccessLog, opts.AccessLogPath); logs != nil {
			httpsServer.Logs = logs
		}
		servers["arenet_https"] = httpsServer
	}

	cfg := caddyConfig{
		Apps: appsConfig{
			HTTP: httpApp{Servers: servers},
		},
	}

	// Step I.7 hotfix (Finding #8): declare our HTTP / HTTPS ports
	// at the http app level. Without this, Caddy defaults to 80 /
	// 443 and mis-identifies our :8080 (dev) or non-:80 prod port
	// as a "non-HTTP-port" listener that might be TLS-capable. Its
	// auto_https logic (caddyhttp/autohttps.go L125-131) then
	// SKIPS the "listening-only-on-HTTP-port → Disabled=true"
	// guard, walks the routes' host matchers, finds hosts that
	// qualify for cert management (because every host matches our
	// catch-all internal policy), and INJECTS TLS connection
	// policies into the server at runtime — turning the HTTP
	// listener into a TLS listener. Clear HTTP requests then hit
	// Go std net/http's TLS handshake path, which writes back the
	// canonical 400 "Client sent an HTTP request to an HTTPS
	// server" before any of our handlers ever run.
	//
	// Declaring the ports explicitly here fixes Finding #8 by
	// making the autohttps guard trigger correctly: arenet_http
	// is recognized as listening on THE HTTP port, auto_https is
	// disabled on it, no TLS policies are injected. arenet_https
	// listens on THE HTTPS port and keeps its cert management.
	apps := map[string]any{
		"http": map[string]any{
			"http_port":  httpPortFor(opts.DevMode),
			"https_port": httpsPortFor(opts.DevMode),
			// No grace_period (Caddy default 0 = eternal) — v2.35.1.
			// A finite value (5s since #R-CADDY-graceful-shutdown-
			// too-long) killed every in-flight HTTP/3 request on
			// each config reload: App.Stop builds the grace context
			// with a deferred cancel and returns at once when the
			// process is not exiting (caddyhttp/app.go:655-800), so
			// quic-go's http3 Server.Shutdown sees it done and
			// closes all open HTTP/3 connections (http3/
			// server.go:632-643). An admin UI reached through
			// Arenet over HTTP/3 lost the response of every save.
			// With the eternal default the old server drains:
			// measured on a real binary, a 3 s HTTP/3 request
			// across a reload now completes (200) instead of
			// failing at 0.64 s. SIGTERM is unaffected — Arenet
			// stops Caddy with caddy.Stop (not caddy's exit path),
			// so App.Stop never waits for the grace period:
			// measured exit 0.02-0.03 s with an HTTP/1.1 or
			// HTTP/3 request in flight.
			"servers": cfg.Apps.HTTP.Servers,
		},
		"tls": buildTLSApp(acme, opts, routes),
	}
	// Step #S-19v2: suppress Caddy's default local-CA root install
	// attempt. v1.0.2 (now reverted) tried to set this via the typed
	// cfg.Apps.PKI struct field, but the JSON marshal path here
	// builds the apps map manually and only pulled HTTP.Servers from
	// cfg — silently dropping PKI. Adding the block directly to the
	// map (same pattern as CrowdSec below) so it actually lands in
	// the emitted JSON. install_trust:false keeps the local CA
	// functional for the catch-all SNI fallback but skips the
	// hostile sudo + certutil install attempt at boot.
	apps["pki"] = map[string]any{
		"certificate_authorities": map[string]any{
			"local": map[string]any{
				"install_trust": false,
			},
		},
	}
	// Step N.1 — apps.crowdsec block. Inject ONLY when the
	// operator has provided a LAPI key; empty key is the
	// degraded-mode signal (AC #13). The handler prepend on
	// every route is conditioned on the same flag (see the
	// per-route loop above).
	//
	// AC #14 invariant: this code path runs on EVERY reload
	// (every route mutation goes through buildConfigJSON); the
	// apps.crowdsec block must therefore reappear in every
	// emitted config or the bouncer is silently removed from
	// the running Caddy instance. Pinned by
	// TestBuildConfigJSON_WithCrowdSec_ReloadPreserves.
	crowdSecApp := buildCrowdSecApp(opts.CrowdSec)
	if crowdSecApp != nil {
		apps["crowdsec"] = crowdSecApp
	}

	// v2.42 — layer-4 services. Absent when there is none to serve,
	// which is what keeps the emitted config unchanged for every
	// installation that does not use them. The CrowdSec matcher is
	// only wired when the bouncer app is actually in this config:
	// referencing an app that is not there fails provisioning.
	if l4 := buildLayer4App(opts.TCPServices, crowdSecApp != nil); l4 != nil {
		apps["layer4"] = l4
	}

	// #R-TOPO-real-health-probe (Stage B, 2026-06-04): subscribe
	// to Caddy's active-health-checker events ("healthy" /
	// "unhealthy") and route them into the AreNET-side
	// HCStatusTracker so the topology snapshot can surface real
	// per-upstream probe outcomes. The handler module is
	// implemented in internal/caddyhc (registered into Caddy's
	// global module registry by that package's init); its
	// Provision pulls the process-wide tracker singleton set by
	// cmd/arenet before this config is loaded.
	//
	// This block must be re-emitted on EVERY reload — same
	// invariant as the crowdsec block above — or the subscription
	// is silently torn down on the next caddy.Load call.
	// "modules" filter targets the ORIGIN module ID — the module
	// instance whose ctx called Emit. For active-health-checker
	// events that's the reverse_proxy handler itself
	// ("http.handlers.reverse_proxy"), not a fictitious
	// ".health_checker" submodule. The events App's dispatch walks
	// UP the module tree from the origin (caddyevents/app.go:269-
	// 313), so a more-specific filter would never match: an
	// origin "http.handlers.reverse_proxy" never reaches a
	// subscription filtered on "http.handlers.reverse_proxy.x".
	// First-debug-round of #R-TOPO-real-health-probe Stage B
	// caught this when the operator saw all-unknown statuses
	// despite probes firing — no events were reaching our handler.
	//
	// Step T T.1 adds a SECOND subscription for certmagic events.
	// Origin module for cert_obtaining / cert_obtained / cert_failed
	// is "tls" — the top-level caddytls.TLS app (declared at
	// modules/caddytls/tls.go:156). The certmagic.Config's emit
	// callback flows through (*caddytls.TLS).onEvent which calls
	// t.events.Emit(t.ctx, ...) — t.ctx is the TLS app's own
	// caddy.Context, so the origin module ID dispatch sees is "tls".
	// Filter MUST be "tls" or empty; "tls.issuance.acme" is a
	// descendant and would never match (same trap as Stage B Bug 1).
	// Verified empirically during T.1 recon against certmagic v0.25.3
	// + caddy v2.11.3 — citations in internal/certinfo/types.go.
	//
	// Satisfies AC #1 + AC #4 cert-event ingestion path
	// (Step T spec v1.2.0-step-t-spec).
	// Implemented by 1350777 (T.1).
	apps["events"] = map[string]any{
		"subscriptions": []map[string]any{
			{
				"events":  []string{"healthy", "unhealthy"},
				"modules": []string{"http.handlers.reverse_proxy"},
				"handlers": []map[string]any{
					{
						"handler": "arenet_topology_hc",
					},
				},
			},
			{
				// Step U.2 added cert_ocsp_revoked to this list
				// (verified emit site: certmagic v0.25.3
				// maintain.go:375). Single subscription block per
				// T.1's AC #18 pattern — adding to the events
				// array, NOT a parallel block, so the same
				// arenet_cert_info handler dispatches all four
				// cert lifecycle signals.
				"events":  []string{"cert_obtaining", "cert_obtained", "cert_failed", "cert_ocsp_revoked"},
				"modules": []string{"tls"},
				"handlers": []map[string]any{
					{
						"handler": "arenet_cert_info",
					},
				},
			},
			{
				// Step Z.1 — rate_limit_exceeded ingestion.
				// Emit site verified empirically against
				// mholt/caddy-ratelimit@v0.1.0 handler.go:232
				// (h.events.Emit(h.ctx, "rate_limit_exceeded",
				// map[string]any{"zone", "wait", "remote_ip"})).
				// The handler's module origin is
				// http.handlers.rate_limit — the events app
				// walks UP the module tree, so the modules
				// filter accepts the parent http.handlers.
				// rate_limit module ID.
				"events":  []string{"rate_limit_exceeded"},
				"modules": []string{"http.handlers.rate_limit"},
				"handlers": []map[string]any{
					{
						"handler": "arenet_ratelimit_sink",
					},
				},
			},
		},
	}

	full := map[string]any{"apps": apps, "admin": adminBlock()}
	// `logging` is a TOP-LEVEL Caddy key, sibling of apps — not part of
	// the http app. Absent when the access log is off.
	if logging := buildAccessLogging(opts.AccessLog, opts.AccessLogPath); logging != nil {
		full["logging"] = logging
	}
	return json.MarshalIndent(full, "", "  ")
}

// buildCrowdSecApp renders the apps.crowdsec JSON block from
// the manager's stored config. Returns nil when no key is set
// (degraded mode — caller skips the apps map injection AND
// the per-route handler prepend).
//
// Field values reflect Step N spec arbitrage:
//   - D1.A enable_streaming=true (streaming mode, sub-ms hot path).
//   - D2.A enable_hard_fails=false (fail-open on LAPI down).
//   - D7.A ticker_interval=60s (match Caddy bouncer default,
//     same cadence as the parallel go-cs-bouncer consumer in N.2).
func buildCrowdSecApp(cfg crowdsecConfig) *crowdsecApp {
	if cfg.apiKey == "" {
		return nil
	}
	apiURL := cfg.apiURL
	if apiURL == "" {
		apiURL = "http://127.0.0.1:8080/"
	}
	return &crowdsecApp{
		APIURL:           apiURL,
		APIKey:           cfg.apiKey,
		TickerInterval:   "60s",
		EnableStreaming:  true,
		EnableHardFails:  false,
		EnableCaddyError: true,
	}
}

// buildTLSPolicies returns the tls.automation.policies array.
//
// Order matters for Caddy: the FIRST policy whose subjects list
// matches a host wins, and matching is STRICT (no automatic
// fallback to a later policy if the matched issuer fails). We
// emit subject-bound ACME policies first (HTTP-01 then DNS-01,
// arbitrary stable order — they are partitioned and don't share
// subjects) and the internal catch-all last, so:
//
//   - hosts in `partition.HTTP01` get an HTTP-01 ACME cert,
//   - hosts in `partition.DNS01`  get a DNS-01  ACME cert,
//   - any other host falls back to Caddy's internal CA (self-signed).
//
// CRITICAL contract on the partition (Step I.7 hotfix Finding #6,
// preserved through Step J.4): the caller MUST only include hosts
// that are publicly validatable by an ACME CA. Including a private
// host (localhost, .local, IP literal, ...) would route it to the
// ACME issuer; Let's Encrypt could not validate the HTTP-01
// challenge for that name and Caddy would never acquire a cert —
// the TLS handshake then fails with "internal error" at Client
// Hello. The peuplement site in buildConfigJSON uses
// certmagic.SubjectQualifiesForPublicCert to enforce this; do NOT
// bypass it on a future refactor.
//
// Step J.4 DNS-01 specifics (§5.4):
//   - The per-route DNS-01 policy is emitted ONLY when both
//     `partition.DNS01` is non-empty AND at least one fully-configured
//     provider exists in opts.DNSProviders (every registry-required
//     credential non-empty, see storage.ProviderConfigured). The default
//     provider is chosen by defaultDNSProvider. The API validates
//     provider presence at edit time, so reaching this code with
//     DNS-01 hosts and no configured provider is a programming error —
//     we defensively skip the DNS-01 policy emission rather than emit
//     a malformed Caddy config that would fail Validate.
//   - The provider sub-block always carries `name: <provider type>` so
//     Caddy's `caddy:"namespace=dns.providers inline_key=name"` tag
//     on DNSChallengeConfig.ProviderRaw resolves correctly
//     (empirically verified during J.4 recon).
//   - A single issuer per ACME policy (Let's Encrypt only). No
//     ZeroSSL fallback — consistent with Step I's single-issuer
//     shape.
//
// If no route has TLSEnabled=true (or all TLS hosts are private),
// both partition slices are empty and we emit only the catch-all
// internal policy, preserving the exact pre-Step-I.1 wire shape
// so existing tests of that path keep passing.
func buildTLSPolicies(partition acmePartition, opts buildOpts) []map[string]any {
	internalPolicy := map[string]any{
		"issuers": []map[string]any{
			{"module": "internal"},
		},
	}
	// Step O.2 — managed-domain wildcard policies. Computed up
	// front so the empty-managed-domains case stays a strict
	// no-op and the no-TLS short-circuit below preserves D5.A
	// byte-equality. Order in the final array: per-route
	// policies (HTTP-01 + DNS-01) FIRST, then wildcard
	// policies, then internal catch-all. This ordering is
	// load-bearing for the D1.B per-route opt-out: Caddy's
	// getAutomationPolicyForName (modules/caddytls/tls.go:862-
	// 878 in v2.11.3) walks the policies slice and returns
	// the FIRST match via certmagic.MatchWildcard — so a
	// per-route policy listing `payments.example.com` MUST
	// precede the wildcard `*.example.com` policy to win for
	// the opt-out host. Empirically validated by the J-era
	// behaviour the byte-equality test pins.
	managedPolicies := buildManagedDomainPolicies(opts)

	if len(partition.HTTP01) == 0 && len(partition.DNS01) == 0 && len(managedPolicies) == 0 {
		return []map[string]any{internalPolicy}
	}
	policies := make([]map[string]any, 0, 3+len(managedPolicies))
	if len(partition.HTTP01) > 0 {
		policies = append(policies, buildACMEPolicy(partition.HTTP01, opts, nil))
	}
	// Per-route (non-wildcard) DNS-01: there is NO per-route provider
	// selection in the data model (only managed domains carry a
	// ProviderID), so we pick a single default provider from the
	// collection. See defaultDNSProvider for the deterministic choice.
	if len(partition.DNS01) > 0 {
		if prov, ok := defaultDNSProvider(opts.DNSProviders); ok {
			policies = append(policies, buildACMEPolicy(partition.DNS01, opts, &prov))
		} else {
			// Fix #2 (v2.12.2): no configured DNS provider for these
			// dns-01 hosts. They get NO ACME policy and fall through to
			// the internal CA (self-signed). Before v2.12.2 this was
			// silent; log it loudly so the drop is visible in the
			// journal. The API delete-guard (Fix #3) prevents this via
			// the normal flow, but import / manual-DB paths can still
			// reach here.
			slog.Warn("per-route DNS-01 hosts have no configured DNS provider; "+
				"they will NOT get an ACME cert and fall back to the internal CA (self-signed) — "+
				"configure a DNS provider in Settings",
				"hosts", partition.DNS01)
		}
	}
	policies = append(policies, managedPolicies...)
	policies = append(policies, internalPolicy)
	return policies
}

// buildManagedDomainPolicies returns one TLS policy per managed
// domain in opts.ManagedDomains. Empty input → nil (the D5.A
// short-circuit invariant: buildTLSPolicies treats nil and an
// empty slice identically, the per-route partition logic above
// is unchanged when no managed domains are declared, and the
// emitted Caddy JSON is byte-equal to Step J).
//
// For each managed domain `<apex>`:
//   - subjects = ["*.<apex>"] if IncludeApex == false
//   - subjects = ["*.<apex>", "<apex>"] if IncludeApex == true (D2.C)
//
// Issuer selection (D4.A "loud unconfigured state"):
//   - When the DNS provider that this managed domain references by
//     md.ProviderID is present in opts.DNSProviders AND fully
//     configured, emit the acme issuer with the dns-01 challenge
//     sub-block sourced from THAT provider's credentials.
//   - When the referenced provider is missing or NOT configured,
//     emit the internal issuer — the wildcard policy stays in the
//     JSON (a subsequent reload doesn't drop it), routes serve
//     internal-CA self-signed certs, no ACME traffic. The Settings
//     UI surfaces the unconfigured state separately (AC #8). This
//     avoids the infinite-ACME-retry risk called out in §5 risks.
//
// Multi-managed-domain (D6.A) + Task 1d multi-provider: the slice is
// iterated verbatim — N managed domains produce N policies — and each
// domain dispatches to its OWN provider config via md.ProviderID, so
// two domains under different OVH accounts each get their own
// credentials in their own policy.
func buildManagedDomainPolicies(opts buildOpts) []map[string]any {
	if len(opts.ManagedDomains) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(opts.ManagedDomains))
	for _, md := range opts.ManagedDomains {
		var subjects []string
		if md.IncludeApex {
			subjects = []string{"*." + md.Apex, md.Apex}
		} else {
			subjects = []string{"*." + md.Apex}
		}
		// D4.A + Task 1d: look up THIS domain's provider by id.
		// Configured → DNS-01 ACME with that provider's creds;
		// missing/unconfigured → internal CA (loud unconfigured
		// state, no silent HTTP-01 fallback because wildcards
		// require DNS-01).
		prov, ok := opts.DNSProviders[md.ProviderID]
		if ok && dnsProviderConfigured(prov) {
			out = append(out, buildACMEPolicy(subjects, opts, &prov))
		} else {
			out = append(out, map[string]any{
				"subjects": subjects,
				"issuers": []map[string]any{
					{"module": "internal"},
				},
			})
		}
	}
	return out
}

// defaultDNSProvider picks the single provider used for per-route
// (non-wildcard) DNS-01 challenges. Unlike managed domains, a
// per-route DNS-01 route carries no ProviderID in the data model, so
// there is no per-route provider selection — the collection must
// designate one default.
//
// Behaviour (documented, deterministic):
//   - 0 configured providers → (zero, false): the caller skips the
//     DNS-01 policy (fail-open, same as the pre-Task-1d unconfigured
//     path). A route requesting DNS-01 with no provider is a
//     programming error rejected at the API layer.
//   - exactly 1 configured provider → that provider. The unambiguous,
//     overwhelmingly common homelab case.
//   - >1 configured providers → the configured provider with the
//     lexicographically smallest ID (stable across reloads because the
//     input is a map with no inherent order). This is inherently
//     ambiguous — the data model cannot express which OVH account a
//     bare per-route DNS-01 route should use — so we log a WARN once
//     per apply and keep the choice deterministic. Operators who need
//     per-account control should use managed domains, which DO dispatch
//     per ProviderID.
func defaultDNSProvider(providers map[string]storage.DNSProviderConfig) (storage.DNSProviderConfig, bool) {
	ids := make([]string, 0, len(providers))
	for id, p := range providers {
		if dnsProviderConfigured(p) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return storage.DNSProviderConfig{}, false
	}
	sort.Strings(ids)
	if len(ids) > 1 {
		slog.Warn("per-route DNS-01 with multiple configured DNS providers is ambiguous; "+
			"defaulting to the provider with the smallest id — use managed domains for per-account control",
			"chosen_id", ids[0], "configured_count", len(ids))
	}
	return providers[ids[0]], true
}

// buildTLSApp returns the full apps.tls section, combining the
// automation policies (per-route ACME + managed-domain wildcards
// + internal catch-all) with the certificates.automate list when
// managed domains are declared.
//
// When opts.ManagedDomains is empty, the returned map contains
// only the "automation" key — byte-equal to the pre-S-20 emission.
// This preserves the D5.A short-circuit invariant pinned by
// TestBuildConfigJSON_NoManagedDomains_PreservesShape (or
// equivalent test name).
func buildTLSApp(acme acmePartition, opts buildOpts, routes []storage.Route) map[string]any {
	tls := map[string]any{
		"automation": map[string]any{
			"policies": buildTLSPolicies(acme, opts),
		},
	}
	if automate := buildAutomateList(opts.ManagedDomains); len(automate) > 0 {
		tls["certificates"] = map[string]any{
			"automate": automate,
		}
	}
	// v2.19.0 (external-certificates SOCLE) — serve each manual-cert
	// route's operator-uploaded cert via apps.tls.certificates.load_pem.
	// Merge with any existing "automate" key (managed domains) rather
	// than clobbering it: both sub-keys can coexist under
	// tls["certificates"].
	if loadPem := buildLoadPemList(routes, opts.ExternalCerts); len(loadPem) > 0 {
		certs, _ := tls["certificates"].(map[string]any)
		if certs == nil {
			certs = map[string]any{}
		}
		certs["load_pem"] = loadPem
		tls["certificates"] = certs
	}
	return tls
}

// buildLoadPemList returns the apps.tls.certificates.load_pem entries
// for every route whose CertSource=="manual", resolving Route.CertID
// against the operator-uploaded certs map (ext). Each entry is
// {"certificate": <leaf PEM (+ "\n" + chain PEM when present)>, "key":
// <key PEM>} — the Caddy v2 CertKeyFilePair shape for inline PEM.
//
// Dedup by CertID: a certificate shared by several routes (e.g. a SAN
// cert covering multiple hostnames) emits ONCE. A route whose CertID is
// absent from ext (dangling reference — cert deleted between reloads) is
// skipped defensively rather than emitting a broken half-entry. A row
// with an empty leaf CertPEM (e.g. a pending_csr row awaiting issuance)
// is likewise skipped — see the guard below.
func buildLoadPemList(routes []storage.Route, ext map[string]storage.ExternalCertificate) []map[string]any {
	out := make([]map[string]any, 0)
	seen := make(map[string]struct{})
	for _, route := range routes {
		// A manual-cert route only serves the cert when TLS is enabled;
		// a non-TLS route has no :443 listener to present it on, so emit
		// no load_pem for it (mirrors the delete-guard condition).
		if route.CertSource != storage.RouteCertSourceManual || !route.TLSEnabled {
			continue
		}
		if _, dup := seen[route.CertID]; dup {
			continue
		}
		cert, ok := ext[route.CertID]
		if !ok {
			// Dangling CertID — skip rather than emit a broken entry.
			continue
		}
		if cert.CertPEM == "" {
			// A pending_csr row (or any cert missing its leaf) is not
			// servable — emitting {"certificate":"", ...} yields invalid
			// Caddy JSON. Skip it defensively; emission is NOT otherwise
			// guarded on an empty leaf (verified manager.go:2591, v2.20.0).
			continue
		}
		seen[route.CertID] = struct{}{}
		pem := cert.CertPEM
		if cert.ChainPEM != "" {
			pem = cert.CertPEM + "\n" + cert.ChainPEM
		}
		out = append(out, map[string]any{
			"certificate": pem,
			"key":         cert.KeyPEM,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildAutomateList returns the subjects Caddy should proactively
// pre-acquire via ACME at config-load time, computed from declared
// managed domains.
//
// Without this list, Caddy lazily acquires per-host certs ON-DEMAND
// when each route's hostname is first hit — defeating the
// "one wildcard cert covers all sub-domains under <apex>" intent
// the managed-domain feature promises in its GUI.
//
// With this list, Caddy proactively obtains `*.<apex>` (and `<apex>`
// when IncludeApex is true) at boot, then serves it for any matching
// sub-domain at TLS handshake via SNI wildcard matching.
//
// Step #S-20 fix. Companion of buildSkipList (which prevents the
// per-host fallback by removing covered hostnames from Caddy's
// automatic_https eligible list).
func buildAutomateList(managedDomains []storage.ManagedDomain) []string {
	if len(managedDomains) == 0 {
		return nil
	}
	out := make([]string, 0, 2*len(managedDomains))
	for _, md := range managedDomains {
		out = append(out, "*."+md.Apex)
		if md.IncludeApex {
			out = append(out, md.Apex)
		}
	}
	return out
}

// buildSkipList returns the route hostnames (Host + every Alias) of
// routes whose ACMEChallenge == "inherited" — i.e., routes covered
// by a managed-domain wildcard. These names go into
// apps.http.servers.arenet_https.automatic_https.skip_certificates
// so Caddy does NOT add them to its auto-managed cert acquisition
// list, while keeping them in auto-HTTPS (routing + redirect handling
// intact — the plain "skip" field would drop both).
//
// Without this skip, Caddy would obtain a separate per-host cert
// for each route via the wildcard policy's DNS-01 challenge config
// (the policy matches via wildcard but Caddy obtains the *specific*
// hostname, not the policy's subjects). With the skip, the wildcard
// cert from buildAutomateList is served for all matching routes via
// SNI matching at TLS handshake.
//
// Routes with explicit ACMEChallenge ("http-01" or "dns-01") are
// NOT skipped — they get their own cert as the operator intended.
//
// Step #S-20 fix. Companion of buildAutomateList.
func buildSkipList(routes []storage.Route) []string {
	out := make([]string, 0, len(routes))
	for _, route := range routes {
		if route.ACMEChallenge == storage.ACMEChallengeInherited {
			out = append(out, route.Host)
			out = append(out, route.Aliases...)
		}
		// v2.19.0 (external-certificates SOCLE) — a manual-cert route
		// serves its operator-uploaded cert via load_pem. Its host must
		// be skipped from auto-HTTPS cert management (same mechanism as
		// the managed-domain wildcard above: kept in auto-HTTPS routing
		// / redirect handling, but never auto-issued), so Caddy does not
		// try to ACME-acquire a host it already has a cert for. The ACME
		// subject partition is excluded at the three per-route sites in
		// buildConfigJSON; this skip is the auto-HTTPS-side companion.
		if route.CertSource == storage.RouteCertSourceManual && route.TLSEnabled {
			out = append(out, route.Host)
			out = append(out, route.Aliases...)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildACMEPolicy returns a single tls.automation.policies entry
// shaped as Caddy v2.11.3 expects. When `dnsProvider` is nil the
// policy uses HTTP-01 (Caddy's implicit default for the ACME
// issuer — no `challenges` block needed); when non-nil it adds the
// DNS-01 `challenges.dns.provider` sub-block sourced from the
// provider's registry credentials. Pulled out of buildTLSPolicies so the HTTP-01
// and DNS-01 emission paths share the same issuer-shape code —
// any future addition (challenge timeouts, alt-name list, ...)
// lands in one place. Step J.4 §5.4.
func buildACMEPolicy(subjects []string, opts buildOpts, dnsProvider *storage.DNSProviderConfig) map[string]any {
	acmeIssuer := map[string]any{
		"module": "acme",
		"ca":     acmeDirectoryURL(opts.DevMode),
	}
	if opts.ACMEEmail != "" {
		acmeIssuer["email"] = opts.ACMEEmail
	}
	if dnsProvider != nil {
		// `name` is REQUIRED — without it Caddy's
		// DNSChallengeConfig.ProviderRaw cannot resolve which
		// dns.providers.* module to instantiate (empirically observed
		// failure: `module not registered: dns.providers.ovh`). The
		// credential keys are the module's own JSON keys (registry,
		// storage/dns_provider_types.go); Caddy decodes them strictly.
		provider := map[string]any{"name": dnsProvider.Type}
		for k, v := range dnsProvider.Credentials {
			if v != "" {
				provider[k] = v
			}
		}
		acmeIssuer["challenges"] = map[string]any{
			"dns": map[string]any{
				"provider": provider,
			},
		}
	}
	return map[string]any{
		"subjects": subjects,
		"issuers":  []map[string]any{acmeIssuer},
	}
}

// dnsProviderConfigured reports whether a DNS provider has every
// registry-required credential — the bar for emitting a DNS-01 ACME
// policy that won't fail Caddy's Provision. The API rejects a route
// create / update that would activate DNS-01 without a configured
// provider, but the generator double-checks here so a programming
// error doesn't slip through to caddy.Load. Step J.4 §5.4, v2.26.
func dnsProviderConfigured(c storage.DNSProviderConfig) bool {
	return storage.ProviderConfigured(c)
}

// acmeDirectoryURL returns the Let's Encrypt directory URL for the
// current mode. Dev mode uses staging (no rate limit on cert
// issuance for iteration); prod uses the real directory.
func acmeDirectoryURL(devMode bool) string {
	if devMode {
		return acmeStagingURL
	}
	return acmeProdURL
}

// Env-var names for the optional data-plane port override (Step
// L.5 prereq). Absent or invalid values fall back EXACTLY to the
// devMode-based defaults — production deployments that do not
// set these vars see the same :80/:443 behaviour they always
// had.
//
// Both vars must be set together when overriding (an HTTP
// override without HTTPS would leave the HTTPS side on the
// default, which is rarely what an operator wants but is
// supported; the validator only rejects unparseable / out-of-
// range integers, not partial overrides).
const (
	envHTTPPort  = "ARENET_HTTP_PORT"
	envHTTPSPort = "ARENET_HTTPS_PORT"
)

// portOverrideFromEnv reads name from the environment and parses
// it as a port. Returns fallback on any failure (unset, empty,
// non-numeric, out of [1, 65535]). The fallback path is the only
// path that preserves the existing behaviour, so prod deployments
// without the var set get exactly httpPortProd / httpsPortProd as
// before this change.
//
// Errors are silent on the fallback path: the operator already
// gets the boot-time "Caddy started" log line which surfaces the
// effective ports, so a typo'd ARENET_HTTP_PORT is visible from
// the log (the listener will be on the default, not the typo).
func portOverrideFromEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return fallback
	}
	return n
}

// listenPortsFor returns the (HTTP, HTTPS) listen addresses based
// on mode. Step I.1: dev keeps :8080/:8443, prod uses :80/:443.
// Step L.5 prereq: ARENET_HTTP_PORT / ARENET_HTTPS_PORT override
// either default when set to a valid port; invalid / absent
// falls back to the devMode-based default (NEVER touches prod
// :80/:443 unless the env var is explicitly set).
func listenPortsFor(devMode bool) (string, string) {
	return fmt.Sprintf(":%d", httpPortFor(devMode)),
		fmt.Sprintf(":%d", httpsPortFor(devMode))
}

// httpPortFor returns the HTTP port number (int) used by this
// mode. Same source of truth as listenPortsFor — the string
// listen address `:8080` and the int port 8080 are mechanically
// linked through this function (Step L.5 prereq centralised that
// linkage). Step I.7 hotfix Finding #8: this int value is what
// Caddy expects in apps.http.http_port to recognize our HTTP
// listener.
func httpPortFor(devMode bool) int {
	fallback := httpPortProd
	if devMode {
		fallback = httpPortDev
	}
	return portOverrideFromEnv(envHTTPPort, fallback)
}

// httpsPortFor mirrors httpPortFor for the HTTPS side.
func httpsPortFor(devMode bool) int {
	fallback := httpsPortProd
	if devMode {
		fallback = httpsPortDev
	}
	return portOverrideFromEnv(envHTTPSPort, fallback)
}

// buildRedirectRoute returns the HTTP-side route entry that serves
// a 301 redirect to the HTTPS scheme for the given hostname set
// (Step I.2, extended to multi-host in I.3).
//
// Caddy's `{http.request.host}` and `{http.request.uri}` placeholders
// are resolved at request time:
//   - {http.request.host} preserves the actual Host header the
//     client used — so a hit on an alias is redirected to that same
//     alias on HTTPS, not to the primary host. The match.host array
//     here covers every alias; the placeholder echoes whichever one
//     hit.
//   - {http.request.uri} preserves both path and query string, so
//     a hit on http://x/foo?bar=1 redirects to https://x/foo?bar=1
//     (AC #2 verification).
//
// `close: true` is not set: HTTP/1.1 keep-alive is fine for a 301
// (the client retries on TLS regardless, no connection reuse for
// the redirected request).
//
// Step W follow-up — the route's CountryBlock gate is prepended
// when active (Mode != "off"), so a non-allowed source country
// receives 403 directly on port 80 instead of a 301 that would
// confirm the host exists and let the client retry against the
// HTTPS chain (where the gate also fires). Without this, the
// HTTP chain leaks "host present" information to operator-blocked
// sources — exactly the symptom check-host.net flagged on
// http://ha.example.com returning 301 from 58 worldwide
// probes even with mode=allow countryList=["FR","PT"].
//
// The country-block handler runs FIRST in the redirect-route
// chain. On block it returns the configured status (403/451/444
// per spec §D3) and stops; on pass-through it falls through to
// the static_response 301 — same behaviour the operator gets
// when there's no country gate at all. RFC1918 / loopback /
// trusted-IP bypass is owned by the W.1 matcher (Layers 1-2)
// so LAN clients always reach the redirect regardless of mode.
//
// The sink emission path is scheme-agnostic — country_block_event
// rows carry no scheme/protocol column (prescribed by the W-
// httpgate brief §D: "scheme-agnostic, keep current schema"),
// so an HTTP-side block and an HTTPS-side block produce
// identically-shaped rows. The operator sees the block
// regardless of port.
func buildRedirectRoute(routeID, host string, cb countryblock.Config, hosts []string) httpRoute {
	handlers := make([]map[string]any, 0, 2)
	if cbHandler := buildCountryBlockHandler(routeID, host, cb); cbHandler != nil {
		handlers = append(handlers, cbHandler)
	}
	handlers = append(handlers, map[string]any{
		"handler":     "static_response",
		"status_code": 301,
		"headers": map[string]any{
			"Location": []string{"https://{http.request.host}{http.request.uri}"},
		},
	})
	return httpRoute{
		Match:  []matcherSet{{Host: hosts}},
		Handle: handlers,
	}
}

// buildWAFHandler returns the Caddy WAF handler config for the
// given route + mode, or nil when WAF is disabled (mode "off"
// or empty) so the caller skips appending anything to the
// handler chain.
//
// Step M.1: emits the new `arenet_waf` handler (custom Caddy
// module wrapping coraza/v3 directly, internal/waf/module.go)
// in place of the legacy `waf` (coraza-caddy/v2) handler.
// Spec §3.2 — full replacement, no per-route opt-in toggle.
// The new module exposes per-rule events via a global
// EventSink, which is what the Step M dashboard mocks
// require (rule_id, OWASP category, severity, src_ip,
// payload sample).
//
// Mode mapping (spec L5, unchanged from I.4):
//   - "detect": the module appends SecRuleEngine
//     DetectionOnly to the directives + filters its
//     per-match emission by severity (≤ Warning) so the
//     dashboard sees real-attack signatures, not anomaly-
//     scoring noise.
//   - "block": SecRuleEngine On + per-Disruptive emission.
//     Coraza interrupts; the module translates that into a
//     403 (or whatever status the rule declared).
//
// Config shape (unchanged from I.4 — same three Includes,
// same load_owasp_crs requirement):
//
//  1. `load_owasp_crs: true` is REQUIRED. Without this flag
//     the embedded coreruleset FS is not mounted and the
//     `@owasp_crs` Include alias resolves to zero rules.
//  2. THREE Includes needed: @coraza.conf-recommended,
//     @crs-setup.conf.example, @owasp_crs/*.conf. Loading
//     only @owasp_crs/*.conf silently degrades coverage
//     because CRS rules reference undefined tx.* variables
//     from @crs-setup.
//  3. Directives are HARDCODED here on purpose (F2 in the
//     I.4 audit): no API path lets an admin inject arbitrary
//     Coraza directives.
//
// Step M closes the `audit_waf_match` PARTIAL from I.4 + the
// Step J §1.4 deferred item by emitting per-rule events
// directly to internal/observability storage. The
// route_id field is REQUIRED by the arenet_waf module's
// Validate (it's how each event is attributed on the
// dashboard).
//
// Note: SecRuleEngine is NOT in the directives string here.
// The arenet_waf module appends it itself based on its Mode
// field so the module owns the policy decision (we don't
// want two sources of truth disagreeing).
// buildKnownHosts assembles the lowercased + port-stripped +
// deduplicated host set the per-route arenet_routemetrics handler
// uses to validate r.Host before bumping its per-host counter
// (Topology Plan B Phase 2.1).
//
// Input: storage.Route.AllHosts() → [Host, ...Aliases] in
// declared order. The primary host is always first.
//
// Output rules:
//   - lowercase every entry (case-insensitive DNS matching, RFC
//     1035; the Phase 1 middleware does ToLower on r.Host before
//     the map lookup, so the cached set must be lowercase too).
//   - strip a :port suffix if present (defensive — storage's
//     validate() doesn't reject port-bearing hostnames today, so
//     an operator who typed "example.com:443" in the API would
//     otherwise produce a hostname the middleware's
//     net.SplitHostPort path strips at request time, causing a
//     silent miss).
//   - drop empty entries (post-normalisation).
//   - preserve first-seen order (primary first, then aliases in
//     declared order) so a future API surface that echoes
//     known_hosts back has a stable shape.
//   - de-duplicate (e.g., "Example.com" + "example.com" reduce
//     to one entry; the deterministic-order test pins this).
//
// Returns nil when every entry normalises to empty — keeps the
// metricsHandler emit byte-equal to the pre-Phase-2.1 shape when
// the storage layer has a degraded row (Host == "" can only
// happen via direct BoltDB write bypass; validate() rejects it).
func buildKnownHosts(r storage.Route) []string {
	hosts := r.AllHosts()
	if len(hosts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		norm := normalizeKnownHost(h)
		if norm == "" {
			continue
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeKnownHost lowercases + strips :port from one entry.
// Split out so the per-entry semantics are unit-testable
// independently of the dedupe / order logic.
func normalizeKnownHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	// Strip port if present. net.SplitHostPort errors when there's
	// no colon, so fall through to the raw value on error.
	if hostOnly, _, err := net.SplitHostPort(h); err == nil {
		h = hostOnly
	}
	return strings.ToLower(h)
}

func buildWAFHandler(routeID, host, mode string, skipBody, disableCRS bool, excludeRules []int, excludeTags []string, targeted []storage.WAFTargetedExclusion, custom []storage.WAFCustomRule, secLang string) map[string]any {
	if mode == "" || mode == "off" {
		return nil
	}
	// Step X.1 (2026-06-17) — per-route CRS load opt-out. When
	// disableCRS is true, the handler is wired but :
	//   - the embedded coreruleset FS is NOT mounted by the
	//     arenet_waf module at Provision time
	//     (load_owasp_crs:false).
	//   - EVERY `@`-Include directive is stripped from the
	//     directives string. The Coraza-style `@<name>` Include
	//     aliases (including @coraza.conf-recommended,
	//     @crs-setup.conf.example, @owasp_crs/*.conf) are ALL
	//     served by the same coreruleset FS — empirically
	//     verified at /Users/.../coraza-coreruleset/rules/
	//     contains the three of them. So if the FS isn't
	//     mounted, NONE of the @-Includes can resolve, and
	//     Coraza fails at Provision time with "failed to
	//     readfile: open @coraza.conf-recommended: no such
	//     file or directory" (smoke-caught regression while
	//     drafting X.1).
	//
	// The "WAF wired, loads nothing" posture is exactly what
	// the operator wants for a trusted internal API : the
	// arenet_waf handler still slots into the chain, the
	// mode-aware event sink + audit log + dashboard counter
	// remain wired (no rule trips because no rules loaded, but
	// the surface is in place if the operator ever flips the
	// disable bit off). Coraza's engine constructs cleanly with
	// zero directives beyond SecRuleEngine itself.
	loadCRS := !disableCRS

	// Step X Option (c) (2026-06-18) — per-route per-rule
	// exclusion list. Emits a SecAction directive that fires
	// unconditionally at phase:1 and chains a
	// ctl:ruleRemoveById=<id> action per excluded rule. The
	// SecAction primitive is preferred over a SecRule with
	// REQUEST_URI "@rx ^.*$" because it carries no operator
	// (Coraza nilOperator path, /coraza/v3/internal/corazawaf/
	// rule.go:212) — zero matcher work per request.
	//
	// Canonical sort (ADR D3) : ascending int order is the
	// canonical form so two routes with the same exclusion set
	// in different operator-input order ([942100, 920280] vs
	// [920280, 942100]) produce the same directives string ⇒
	// the same WAF pool key ⇒ pool dedup.
	//
	// SecAction ID space — empirical findings :
	//  - The design spec §2 nominated the 200000-range as
	//    "Arenet-reserved". Empirical smoke caught a
	//    collision : @coraza.conf-recommended itself ships a
	//    SecAction with id:200001 (the JSON requestBodyProcessor
	//    setup). Coraza errors at WAF construction with
	//    "duplicated rule id 200001".
	//  - Bumped to id:999001. The 999xxx range is the
	//    operator-convention high-end-user space ; the CRS
	//    project ID space stays under 999000 by convention,
	//    Coraza's built-in directives use ≤ 900000. 999001
	//    is collision-free against everything bundled with
	//    Arenet today.
	//  - The Arenet-reserved validation range stays
	//    [100000, 199999] on the API side (mirror of
	//    adminAPIExclusionDirective's id:100001 + future
	//    growth headroom) — the 999001 ID is for OUR own
	//    generated SecAction, not for operator-supplied
	//    exclusions.
	//
	// Interaction with disableCRS : when disableCRS is true the
	// CRS Includes are stripped, so there are no rules to
	// ctl-remove. We STILL emit the SecAction (it's a no-op
	// against an empty rule set) so flipping disableCRS back
	// to false re-engages BOTH the CRS AND the operator's
	// exclusion list in one step, with no pool-key churn caused
	// by the directives string changing shape on toggle.
	//
	// Skip when len(excludeRules) == 0 AND len(excludeTags) == 0
	// so routes that don't opt-in stay byte-equal with the
	// pre-X directives string (pool dedup with pre-X routes
	// preserved). Routes that opt into EITHER mechanism get a
	// single SecAction carrying every ctl: action — single
	// rule = single rule = stable pool key.
	//
	// Step X Option (e) — tag-based exclusion. Coraza v3.7.0
	// exposes ctl:ruleRemoveByTag=<tag> at ctl.go:302-308 with
	// exact-match case-sensitive semantics (verified
	// empirically pre-code at audit time). The API normalises
	// operator input to lowercase ; here we trust the API
	// canonicalisation and sort-by-string for stable emit order.
	//
	// Ordering — CRITICAL : the SecAction MUST be emitted
	// BEFORE the CRS Includes, not after. Coraza evaluates
	// phase:1 rules in file load order ; a ctl:ruleRemove*
	// action that runs after its target rule has already
	// fired is a no-op for the current transaction (the
	// match event is already emitted, the request is already
	// blocked in block mode). Empirically discovered Step X
	// (e) smoke test 2026-06-22 against rule 920170 (GET-
	// with-body, tag attack-protocol) : ctl:ruleRemoveByTag
	// AND ctl:ruleRemoveById both failed to bypass it when
	// the SecAction was appended ; both pass when prepended.
	// Same root-cause pattern as adminAPIExclusionDirective
	// (module.go:283-291). Pre-fix Step X (c) shipped in
	// v2.3.0 (commit a133a53) carried this latent bug —
	// operators believed their per-rule exclusions worked,
	// they did not until this commit.
	var preCRSDirectives string
	if len(excludeRules) > 0 || len(excludeTags) > 0 {
		secAction := "SecAction \"id:999001,phase:1,pass,nolog,"
		// Canonical sort + de-alias the operator-supplied slices
		// locally to keep the public arguments untouched (callers
		// may rely on their slice order elsewhere).
		sortedRules := make([]int, len(excludeRules))
		copy(sortedRules, excludeRules)
		sort.Ints(sortedRules)
		sortedTags := make([]string, len(excludeTags))
		copy(sortedTags, excludeTags)
		sort.Strings(sortedTags)
		parts := make([]string, 0, len(sortedRules)+len(sortedTags))
		for _, id := range sortedRules {
			parts = append(parts, fmt.Sprintf("ctl:ruleRemoveById=%d", id))
		}
		for _, tag := range sortedTags {
			parts = append(parts, fmt.Sprintf("ctl:ruleRemoveByTag=%s", tag))
		}
		secAction += strings.Join(parts, ",") + "\""
		preCRSDirectives = secAction
	}
	// v2.36 — targeted exclusions (one rule stops inspecting one
	// field, optionally on one path). Same placement constraint as
	// the SecAction above: before the CRS Includes.
	for _, d := range targetedExclusionDirectives(targeted) {
		if preCRSDirectives != "" {
			preCRSDirectives += "\n"
		}
		preCRSDirectives += d
	}
	// v2.37 — guided rules (block when every condition matches),
	// after the exclusions and before the CRS so they decide early.
	for _, d := range customRuleDirectives(custom) {
		if preCRSDirectives != "" {
			preCRSDirectives += "\n"
		}
		preCRSDirectives += d
	}
	// v2.38 — the route's expert SecLang (validated by the API with
	// waf.CheckSecLang), last before the CRS.
	if strings.TrimSpace(secLang) != "" {
		if preCRSDirectives != "" {
			preCRSDirectives += "\n"
		}
		preCRSDirectives += strings.TrimSpace(secLang)
	}

	directives := preCRSDirectives
	if loadCRS {
		if directives != "" {
			directives += "\n"
		}
		directives += "Include @coraza.conf-recommended\n" +
			"Include @crs-setup.conf.example\n" +
			"Include @owasp_crs/*.conf"
	}

	out := map[string]any{
		"handler":        "arenet_waf",
		"route_id":       routeID,
		"host":           host,
		"mode":           mode,
		"load_owasp_crs": loadCRS,
		"directives":     directives,
	}
	// Phase 4.5 — when the route opts into upload streaming
	// mode, tell the arenet_waf handler to skip the request-
	// body inspection branch in processRequest. Omitted on
	// the wire when false so existing snapshots stay byte-
	// equal for routes that don't use this feature.
	if skipBody {
		out["skip_body_inspection"] = true
	}
	return out
}

// buildCountryBlockHandler returns the Caddy JSON for the
// arenet_country_block per-route handler (Step W.3), or nil
// when the route's CountryBlock is off / unset. Per spec §D10
// the handler slots at chain position #2 (between
// arenet_routemetrics and crowdsec_handler); per spec §3.6
// the emit is omitted entirely for off-mode routes so the
// per-request cost stays at zero.
//
// Cross-route dependencies (the geo lookup, the operator's
// trusted-IP allowlist, the env-default status code, the
// client-IP resolver) are NOT threaded through the per-route
// JSON. They live as process-wide globals installed by
// cmd/arenet/main.go via countryblock.SetGlobal* setters —
// the handler reads them at Provision + ServeHTTP via lock-
// free atomic.Pointer loads (V.1.3 late-install pattern).
// This keeps the JSON shape minimal + identical regardless
// of operator env-var configuration.
//
// Symmetric to buildWAFHandler above.
//
// The host parameter is consumed by the caller (applyLocked
// log lines) but NOT threaded into the handler JSON — the
// W.1 Handler struct intentionally carries only RouteID +
// Config, so caddymgr's boot/diff log is the single
// surface where the host is correlated with the route ID.
func buildCountryBlockHandler(routeID, _ string, cb countryblock.Config) map[string]any {
	if cb.Mode == "" || cb.Mode == countryblock.ModeOff {
		return nil
	}
	config := map[string]any{
		"mode":        string(cb.Mode),
		"countryList": cb.CountryList,
		"statusCode":  cb.StatusCode,
	}
	// v2.27 — emitted only when set, so a country-only route keeps a
	// byte-identical handler block. Without these keys the module
	// would silently ignore continents and exceptions.
	if len(cb.Continents) > 0 {
		config["continents"] = cb.Continents
	}
	if len(cb.ASNs) > 0 {
		config["asns"] = cb.ASNs
	}
	if exc := buildCountryBlockExceptions(cb.Exceptions); exc != nil {
		config["exceptions"] = exc
	}
	return map[string]any{
		"handler": countryblock.HandlerName,
		"routeID": routeID,
		"config":  config,
	}
}

// Default Caddy placeholder for the rate-limit zone key when
// the operator leaves the Key field empty. {http.request.
// remote.host} resolves to the raw socket peer IP — no
// X-Forwarded-For trust by default, which is the safe choice
// for routes facing the public internet without a verified
// trusted-proxy chain. Operators on a tested reverse-proxy
// deployment can override to a header-derived placeholder
// via the form's "custom key" path (Phase Q.2 UI).
const defaultRateLimitKey = "{http.request.remote.host}"

// buildRateLimitHandler returns the Caddy mholt/caddy-
// ratelimit handler config for the given route's RateLimit
// declaration, or nil when the route has no rate-limit
// configured (rl == nil OR validation fails).
//
// JSON shape ships ONE zone per route, keyed by the route's
// UUID so two routes can have orthogonal limits without
// counter-bleed even when their config bytes are otherwise
// identical (the upstream README's "MUST be globally
// unique" warning applies here). The zone name is
// "route-<routeID>" — operator-readable for the
// {http.rate_limit.exceeded.name} placeholder if a future
// custom-429-page feature wants to surface it.
//
// Validation : operator-supplied (Events, Window) are
// gated at the API layer (storage.RouteRateLimit
// validation contract). The handler here defends in depth :
// invalid window parse OR Events <= 0 returns nil + a
// warn-level log so a corrupt stored row doesn't crash the
// reload — the route just runs without the rate limit
// instead of failing the whole config build.
func buildRateLimitHandler(routeID string, rl *storage.RouteRateLimit) map[string]any {
	if rl == nil {
		return nil
	}
	if rl.Events <= 0 {
		slog.Warn("rate-limit emit: skipping route with non-positive Events",
			"route_id", routeID, "events", rl.Events)
		return nil
	}
	dur, err := time.ParseDuration(rl.Window)
	if err != nil || dur <= 0 {
		slog.Warn("rate-limit emit: skipping route with invalid Window",
			"route_id", routeID, "window", rl.Window, "err", err)
		return nil
	}
	key := rl.Key
	if key == "" {
		key = defaultRateLimitKey
	}
	zoneName := "route-" + routeID
	return map[string]any{
		"handler": "rate_limit",
		"rate_limits": map[string]any{
			zoneName: map[string]any{
				"key":        key,
				"window":     dur, // caddy.Duration marshalled as nanoseconds
				"max_events": rl.Events,
			},
		},
	}
}

// buildPathRateLimitHandler returns the rate_limit handler for ONE path
// rule, in its own zone.
//
// Why the zone name encodes the prefix rather than the rule's position:
// caddy-ratelimit keeps its zones in a caddy.NewUsagePool keyed by NAME
// (handler.go:279), reference-counted, and Cleanup deletes by name
// (handler.go:245-250). A zone whose name is still in use by the next
// config therefore survives the reload WITH ITS COUNTERS. Naming zones
// path0, path1, … would mean reordering two rules hands each the other's
// counters — a client throttled on /admin would arrive pre-throttled on
// /api after an unrelated edit.
//
// So the name carries a sanitised prefix for readability (it surfaces
// through {http.rate_limit.exceeded.name}) plus a hash of the exact
// prefix for uniqueness: sanitising alone would collide "/a/b" with
// "/a-b" and bleed counters between two different rules.
func buildPathRateLimitHandler(routeID, prefix string, rl *storage.RouteRateLimit) map[string]any {
	if rl == nil {
		return nil
	}
	if rl.Events <= 0 {
		slog.Warn("rate-limit emit: skipping path rule with non-positive Events",
			"route_id", routeID, "path", prefix, "events", rl.Events)
		return nil
	}
	dur, err := time.ParseDuration(rl.Window)
	if err != nil || dur <= 0 {
		slog.Warn("rate-limit emit: skipping path rule with invalid Window",
			"route_id", routeID, "path", prefix, "window", rl.Window, "err", err)
		return nil
	}
	key := rl.Key
	if key == "" {
		key = defaultRateLimitKey
	}
	return map[string]any{
		"handler": "rate_limit",
		"rate_limits": map[string]any{
			pathRateLimitZoneName(routeID, prefix): map[string]any{
				"key":        key,
				"window":     dur,
				"max_events": rl.Events,
			},
		},
	}
}

// pathRateLimitZoneName builds a zone name that is unique per (route,
// prefix) and stable across reloads and rule reordering.
func pathRateLimitZoneName(routeID, prefix string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(prefix))
	return fmt.Sprintf("route-%s-path-%s-%08x", routeID, sanitiseZoneLabel(prefix), h.Sum32())
}

// sanitiseZoneLabel keeps the readable part of a prefix: lowercase
// alphanumerics, everything else collapsed to a single dash, bounded so a
// 256-character prefix does not produce a 256-character zone name. The
// hash beside it is what guarantees uniqueness, so losing detail here is
// only a loss of readability.
func sanitiseZoneLabel(prefix string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(prefix) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastDash = false
		case !lastDash && b.Len() > 0:
			b.WriteByte('-')
			lastDash = true
		}
		if b.Len() >= 32 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// countryBlockFingerprint serialises the operator-meaningful
// fields of a Route.CountryBlock into a stable string used as
// the diff key in previousCountryBlockModes. The format is
// "<mode>|<sorted country list comma-separated>|<statusCode>"
// — sorting the country list defends against operator UI
// reorders that don't change the actual gate semantic. Pre-W
// rows (Mode == "") hash to "off|<empty list>|<0>" same as a
// fresh off route, so a zero-value decode doesn't get
// reported as a spurious "added" entry.
func countryBlockFingerprint(cb countryblock.Config) string {
	mode := cb.Mode
	if mode == "" {
		mode = countryblock.ModeOff
	}
	// Stable order so [FR, DE] and [DE, FR] don't generate a
	// false diff. Operator's input order isn't load-bearing
	// for the gate decision (containsCountry is a linear
	// scan), so the canonicalisation is safe here.
	fp := fmt.Sprintf("%s|%s|%d", string(mode), sortedJoin(cb.CountryList), cb.StatusCode)
	// v2.27 — appended only when set so pre-v2.27 fingerprints are
	// unchanged (no spurious "changed" log after an upgrade).
	if len(cb.Continents) > 0 {
		fp += "|continents=" + sortedJoin(cb.Continents)
	}
	if len(cb.ASNs) > 0 {
		fp += "|asns=" + sortedJoinASN(cb.ASNs)
	}
	if cb.Exceptions != nil && len(cb.Exceptions.Countries) > 0 {
		fp += "|except=" + sortedJoin(cb.Exceptions.Countries)
	}
	if cb.Exceptions != nil && len(cb.Exceptions.ASNs) > 0 {
		fp += "|except-asns=" + sortedJoinASN(cb.Exceptions.ASNs)
	}
	return fp
}

// buildCountryBlockExceptions returns the handler's "exceptions"
// object with only the non-empty lists, or nil when there are none.
func buildCountryBlockExceptions(e *countryblock.Exceptions) map[string]any {
	if e == nil {
		return nil
	}
	out := map[string]any{}
	if len(e.Countries) > 0 {
		out["countries"] = e.Countries
	}
	if len(e.ASNs) > 0 {
		out["asns"] = e.ASNs
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sortedJoinASN returns the AS numbers sorted and comma-joined,
// without mutating the input.
func sortedJoinASN(asns []uint32) string {
	list := slices.Clone(asns)
	slices.Sort(list)
	parts := make([]string, len(list))
	for i, n := range list {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, ",")
}

// exceptionCount returns the number of deny-mode exceptions.
func exceptionCount(cb countryblock.Config) int {
	if cb.Exceptions == nil {
		return 0
	}
	return len(cb.Exceptions.Countries) + len(cb.Exceptions.ASNs)
}

// sortedJoin returns the codes sorted and comma-joined, without
// mutating the input.
func sortedJoin(codes []string) string {
	list := slices.Clone(codes)
	slices.Sort(list)
	return strings.Join(list, ",")
}

// buildHeadersHandler returns the Caddy `headers` handler config for
// the given (request, response) header maps, or nil when BOTH maps
// are empty (so the caller skips appending anything to the handler
// chain). Step I.6.
//
// Caddy's headers handler expects `request.set` and `response.set`
// to be `http.Header` shaped — i.e. map[string][]string. Arenet's
// schema carries single-valued map[string]string entries; the
// conversion wraps each value in a one-element slice. Multi-value
// headers are not exposed in v1.0 (acceptable trade-off; cookies
// and CORS lists are usually single-value in homelab proxying).
//
// Each side (`request` / `response`) is OMITTED from the emitted
// JSON when its source map is empty (Caddy treats both as
// `omitempty`); this keeps the wire config minimal and the smoke
// diff readable.
func buildHeadersHandler(reqHeaders, respHeaders map[string]string) map[string]any {
	if len(reqHeaders) == 0 && len(respHeaders) == 0 {
		return nil
	}
	handler := map[string]any{"handler": "headers"}
	if len(reqHeaders) > 0 {
		handler["request"] = map[string]any{
			"set": wrapHeaderValues(reqHeaders),
		}
	}
	if len(respHeaders) > 0 {
		handler["response"] = map[string]any{
			"set": wrapHeaderValues(respHeaders),
		}
	}
	return handler
}

// wrapHeaderValues turns a map[string]string into the
// map[string][]string shape Caddy's headers handler consumes.
// Each value becomes a one-element slice.
func wrapHeaderValues(m map[string]string) map[string][]string {
	out := make(map[string][]string, len(m))
	for k, v := range m {
		out[k] = []string{v}
	}
	return out
}

// buildBasicAuthHandlerFromConfig returns the Caddy `authentication`
// handler config for a Basic Auth gate — Step I.5, extracted in Step
// Q5 so both the route-level AuthMode==basic case AND the per-path
// PathRule.BasicAuth override (Q5 path-rules subroute) emit the
// IDENTICAL shape from one place instead of risking drift between
// two hand-written copies.
//
// hash_cache is REQUIRED here — do not drop it. It enables Caddy's
// per-credential verification cache (caddyauth.Cache). Without it,
// Caddy re-runs the full 64 MiB argon2id derivation on EVERY
// request; an SSE-heavy upstream that opens many reconnecting
// streams then exhausts RAM+swap (the regression this fixed,
// memory: route_basic_auth_hash_cache). The cache collapses
// repeated identical verifications to one hash (singleflight
// coalesces concurrent ones). Empty object = enabled; the cache has
// no tunable fields (internal random eviction). Tradeoff: plaintext
// passwords stay in memory a bit longer — acceptable, since Basic
// Auth receives them per request over the wire regardless.
//
// Realm is caller-supplied (per-vhost, e.g. "Arenet route
// app.example.com") rather than fixed — the realm scopes the
// browser's Basic-Auth credential cache, so a single global realm
// across every route/path would make the browser auto-send or
// suppress re-prompts across unrelated vhosts. This mirrors the
// pre-Q5-extraction inline behaviour. Both the route-level call site
// and the per-path call site pass "Arenet route "+r.Host so
// credential scoping stays tied to the vhost either way.
func buildBasicAuthHandlerFromConfig(c storage.BasicAuthRouteConfig, realm string) map[string]any {
	return map[string]any{
		"handler": "authentication",
		"providers": map[string]any{
			"http_basic": map[string]any{
				"hash":       map[string]any{"algorithm": "argon2id"},
				"realm":      realm,
				"hash_cache": map[string]any{},
				"accounts": []map[string]any{
					{
						"username": c.Username,
						"password": c.PasswordHash,
					},
				},
			},
		},
	}
}

// buildForwardAuthHandler returns the Caddy handler config for the
// per-route forward-auth (Step K.1, §5.1). Shape verified against
// the Caddy v2.11.3 Caddyfile-adapt reference samples
// (caddy/caddytest/integration/caddyfile_adapt/forward_auth_*.
// caddyfiletest):
//
//   - The handler is a `reverse_proxy` that targets the IdP's
//     verify URL (provider.VerifyURL), rewrites the method to GET
//     and the URI to provider.AuthRequestURI (the standard
//     `forward_auth` Caddyfile expansion), and sets the two
//     forwarded-request headers (X-Forwarded-Method,
//     X-Forwarded-Uri) so the IdP knows what the original request
//     looked like.
//   - On a 2xx response from the IdP, `handle_response` fires:
//     each header in provider.CopyHeaders is read from the IdP
//     response and copied onto the original request (so the
//     downstream chain — WAF, custom headers, real proxy — sees
//     the IdP-injected identity headers like Remote-User /
//     Remote-Email).
//   - On a non-2xx response (the IdP redirected the user to its
//     login page, returned 401, etc.), the reverse_proxy returns
//     that response to the client and the downstream chain is
//     short-circuited. This is the standard forward_auth gate.
//
// The "vars" handler inside each handle_response route is the
// Caddyfile expansion's idiomatic no-op slot — it's where a
// future "request_header overrides" feature would land. We keep
// it for shape-fidelity with caddy adapt.
//
// Notes:
//   - provider.ClientSecret is not emitted in the JSON here. The
//     standard Authelia / Authentik / Keycloak forward_auth flow
//     uses cookies / session for the IdP-side authentication,
//     not a static RP credential. ClientSecret is plumbed at the
//     storage / API level to support the future case where a
//     provider needs an explicit credential (e.g. as an HTTP
//     Authorization header on the sub-request); a follow-up
//     refinement can read it here. v1.0 of K.1 ships the cookie-
//     based pattern that covers Authelia / Authentik / Keycloak.
//   - The provider must have at least one entry in CopyHeaders
//     for the `handle_response` block to be meaningful; an empty
//     CopyHeaders list still produces a valid forward_auth gate
//     (auth check happens, but no claims are forwarded to the
//     upstream).
func buildForwardAuthHandler(p storage.ForwardAuthProvider) map[string]any {
	// Build the per-header copy routes. For each header, two
	// routes mirror the Caddyfile expansion: (1) delete the
	// header from the original request (so any client-supplied
	// value is wiped), (2) set it from the IdP response —
	// conditionally on the IdP response actually containing a
	// value (the {http.reverse_proxy.header.X} placeholder, if
	// the IdP omitted the header, would otherwise inject the
	// literal placeholder text into the upstream request).
	copyRoutes := []map[string]any{
		{"handle": []map[string]any{{"handler": "vars"}}},
	}
	for _, h := range p.CopyHeaders {
		// Delete the original-request value first.
		copyRoutes = append(copyRoutes, map[string]any{
			"handle": []map[string]any{
				{
					"handler": "headers",
					"request": map[string]any{
						"delete": []string{h},
					},
				},
			},
		})
		// Conditionally set it from the IdP response (skip if
		// the IdP didn't return a value).
		copyRoutes = append(copyRoutes, map[string]any{
			"handle": []map[string]any{
				{
					"handler": "headers",
					"request": map[string]any{
						"set": map[string][]string{
							h: {fmt.Sprintf("{http.reverse_proxy.header.%s}", h)},
						},
					},
				},
			},
			"match": []map[string]any{
				{
					"not": []map[string]any{
						{
							"vars": map[string][]string{
								fmt.Sprintf("{http.reverse_proxy.header.%s}", h): {""},
							},
						},
					},
				},
			},
		})
	}

	// Step K.4 — header set for the sub-request. X-Forwarded-Method/
	// Uri are canonical (forward_auth_authelia.caddyfiletest line
	// 211-218). The Host header is OPTIONALLY rewritten to the
	// verify URL's hostport when the provider opts in via
	// RewriteVerifyHost — required for Authentik embedded outpost
	// which routes apps by Host. Default behaviour (RewriteVerifyHost
	// false) is the canonical Caddy expansion: Host header
	// propagated from the client request to the upstream, which
	// Authelia / Keycloak / oauth2-proxy / Authentik external
	// outpost all accept.
	headerSet := map[string][]string{
		"X-Forwarded-Method": {"{http.request.method}"},
		"X-Forwarded-Uri":    {"{http.request.uri}"},
	}
	if p.RewriteVerifyHost {
		if u, err := url.Parse(p.VerifyURL); err == nil && u.Host != "" {
			headerSet["Host"] = []string{u.Host}
		}
	}

	rp := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]any{{"dial": forwardAuthDial(p.VerifyURL)}},
		"rewrite": map[string]any{
			"method": "GET",
			"uri":    p.AuthRequestURI,
		},
		"headers": map[string]any{
			"request": map[string]any{
				"set": headerSet,
			},
		},
		"handle_response": []map[string]any{
			{
				"match": map[string]any{
					"status_code": []int{2}, // 2xx family
				},
				"routes": copyRoutes,
			},
		},
	}
	// Step K.4 fix (found at smoke time): when the verify URL is
	// HTTPS the forward_auth sub-request MUST be sent over TLS;
	// reverse_proxy defaults to plain HTTP otherwise. Without
	// this, the IdP returns 400 "Client sent an HTTP request to
	// an HTTPS server" on every sub-request and the gate refuses
	// every requester — same outcome as fail-closed but for the
	// wrong reason. Mirror of the transport-flip the K.4
	// passthrough emits.
	if u, err := url.Parse(p.VerifyURL); err == nil && strings.EqualFold(u.Scheme, "https") {
		rp["transport"] = map[string]any{
			"protocol": "http",
			"tls":      map[string]any{},
		}
	}
	return rp
}

// buildForwardAuthDenyHandler returns the fail-closed
// short-circuit handler emitted when a route's forward_auth
// provider reference is unresolvable at generator time. Critical
// security-control: a route configured for forward_auth MUST
// NOT serve unauthenticated traffic when its gate is missing.
// The handler is a `static_response` with status 503 + a body
// pointing the operator to the Settings page; the chain stops
// here (the caller is responsible for NOT appending the
// reverse_proxy after this handler — see the AuthMode switch
// in buildConfigJSON).
//
// 503 is the right code for the operator-fixable, recoverable
// state: route configured, dependency missing, recovery is to
// configure the dependency. Retry-After: 0 because the recovery
// is operator action, not a "client should retry in N seconds".
// The body is text/plain so a curl shows it immediately; a
// browser will render it as well.
func buildForwardAuthDenyHandler(providerName string) map[string]any {
	body := fmt.Sprintf(
		"Service Unavailable: forward-auth provider %q is not configured.\n"+
			"This route requires an authenticated identity but its auth "+
			"gate is missing. An administrator must configure the "+
			"forward-auth provider under Arenet Settings → Forward-auth "+
			"providers, then reload.\n",
		providerName,
	)
	return map[string]any{
		"handler":     "static_response",
		"status_code": 503,
		"headers": map[string]any{
			"Content-Type": []string{"text/plain; charset=utf-8"},
			"Retry-After":  []string{"0"},
		},
		"body": body,
	}
}

// buildAuthPassthroughRoute returns the httpRoute that
// reverse-proxies a single path prefix on the route's Host(s)
// straight to the forward-auth provider's verify-URL host,
// bypassing the forward_auth gate. Caddy v2 path matchers treat
// "/prefix/*" as "any URI starting with /prefix/" — exact match
// on "/prefix" alone is NOT covered (the spec wants the prefix
// branch to claim its own subtree; the bare prefix would
// normally not have meaning either way). The dial uses TLS when
// the verify URL is https; this matches the verify-URL Dial
// behaviour at forwardAuthDial.
//
// Step K.4. SECURITY note: this route does NOT include the
// metrics handler, since the requests it serves are IdP-side UI
// / OAuth endpoints — instrumenting them as if they were
// regular upstream traffic would distort the per-route counters
// (they're internal-to-auth, not application). Same posture as
// the forward_auth sub-request itself (which doesn't go through
// metrics either).
func buildAuthPassthroughRoute(provider storage.ForwardAuthProvider, hosts []string) httpRoute {
	// Path matcher: "<prefix>/*" matches the prefix subtree.
	// Caddy's path matcher uses a glob with "*" matching anything
	// including "/", so a single trailing /* is the right shape
	// for "everything under /prefix/".
	pathPattern := strings.TrimSuffix(provider.AuthPassthroughPrefix, "/") + "/*"
	dial := forwardAuthDial(provider.VerifyURL)

	rp := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": []map[string]any{{"dial": dial}},
	}
	// v2.58.1 — honour RewriteVerifyHost here too.
	//
	// This route and the forward-auth sub-request both go to the verify
	// host, so they must agree about the Host header or only one of them
	// arrives. They did not: buildForwardAuthHandler applied the rewrite
	// and this route did not, so with an IdP behind a third-party reverse
	// proxy that routes by Host — Authentik behind Traefik, which is the
	// common deployment — the auth check reached the IdP while every
	// browser request to the IdP's own endpoint got that proxy's 404. The
	// gate worked and the sign-in round trip could not complete.
	//
	// Both topologies now work from one setting:
	//   - Arenet talks to the IdP directly: leave it off, both halves send
	//     the visitor's Host, and the IdP resolves the application from it.
	//   - A reverse proxy fronts the IdP: turn it on, both halves send the
	//     IdP's own host so that proxy routes them, and the IdP still
	//     resolves the application from X-Forwarded-Host, which Caddy sets
	//     from the original request before these header ops apply
	//     (caddy v2.11.4 reverseproxy.go:489 prepareRequest, then the user
	//     ops at ~:695).
	if provider.RewriteVerifyHost {
		if u, err := url.Parse(provider.VerifyURL); err == nil && u.Host != "" {
			rp["headers"] = map[string]any{
				"request": map[string]any{
					"set": map[string][]string{"Host": {u.Host}},
				},
			}
		}
	}
	// When the verify URL is HTTPS the upstream must be reached
	// over TLS; reverse_proxy's transport defaults to plain HTTP
	// unless we tell it otherwise.
	if u, err := url.Parse(provider.VerifyURL); err == nil && strings.EqualFold(u.Scheme, "https") {
		rp["transport"] = map[string]any{
			"protocol": "http",
			"tls":      map[string]any{},
		}
	}

	return httpRoute{
		Match: []matcherSet{{
			Host: hosts,
			Path: []string{pathPattern},
		}},
		Handle:   []map[string]any{wrapInSubroute([]map[string]any{rp})},
		Terminal: true,
	}
}

// forwardAuthDial converts a provider's VerifyURL (e.g.
// "http://authelia:9091") into the host:port form Caddy's
// reverse_proxy expects in the "dial" field. Same shape as
// upstreamDial but specific to forward_auth providers (the
// VerifyURL is validated at the API layer to be a parseable
// http/https URL with a host component).
func forwardAuthDial(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// API validation should prevent this; defensive return.
		return raw
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		switch strings.ToLower(u.Scheme) {
		case "https":
			host += ":443"
		default:
			host += ":80"
		}
	}
	return host
}

// catchAllRoute builds the final 404 catch-all route: no match block
// (matches every remaining request) with a static_response handler.
//
// v2.9.10 Bug 1 — the body is now branded HTML resolved by
// resolveCatchallBody: the operator-flagged template's Pages[404]
// if any, else arenetDefaultErrorPages[404] (the same Arenet
// branded HTML configured routes serve on an upstream 404).
// Pre-v2.9.10 this returned plain text "Not Found - no route
// configured for this host" with no Content-Type, breaking
// visual consistency.
// catchAllRoute answers everything no host-matched route claimed.
//
// crowdSec prepends the bouncer so a banned source is refused here too
// (v2.49). Until then the catch-all answered a bare 404 before CrowdSec
// was ever consulted, because the bouncer lives in each route's own
// handler chain — so an operator who had banned an IP watched it get a
// 404 from an unknown host and could not tell whether the ban worked.
// That is the confusion reported on 2026-09-26.
//
// It is worth saying plainly that this buys very little security: a
// banned IP got a 404 before and gets a 403 now, and no attack is
// prevented either way. It is here for predictability — a ban should
// mean refused everywhere — and because under a flood a short refusal
// beats a rendered 404 page.
//
// The cost is one in-memory lookup: Arenet runs the bouncer in
// streaming mode (crowdsecApp.EnableStreaming), where a decision is
// resolved from the local store rather than by asking LAPI
// (caddy-crowdsec-bouncer internal/core/decisions.go:105-106). And
// enable_hard_fails stays false, so a LAPI outage still cannot turn
// this into a wall: unresolvable means allowed, and the 404 comes back.
func catchAllRoute(templates map[string]storage.ErrorPageTemplate, crowdSec bool) httpRoute {
	body := resolveCatchallBody(templates)
	handle := make([]map[string]any, 0, 2)
	if crowdSec {
		handle = append(handle, map[string]any{"handler": "crowdsec"})
	}
	handle = append(handle, map[string]any{
		"handler":     "static_response",
		"status_code": 404,
		"headers": map[string]any{
			"Content-Type": []string{"text/html; charset=utf-8"},
		},
		"body": body,
	})
	return httpRoute{Handle: handle}
}

// HasHTTPSServer reports whether the current store contents would produce an
// HTTPS server in the Caddy config (i.e. at least one route has TLSEnabled).
func (m *CaddyManager) HasHTTPSServer(ctx context.Context) (bool, error) {
	routes, err := m.store.ListRoutes(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range routes {
		if r.TLSEnabled && !r.Disabled {
			return true, nil
		}
	}
	return false, nil
}

// upstreamDial converts an Upstream URL ("http://127.0.0.1:9999") into the
// host:port form Caddy's reverse_proxy expects in the "dial" field.
// Called once per Upstream in the pool by buildConfigJSON.
func upstreamDial(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("upstream_url is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse upstream_url %q: %w", raw, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("upstream_url %q has no host", raw)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		switch strings.ToLower(u.Scheme) {
		case "https":
			host += ":443"
		default:
			host += ":80"
		}
	}
	return host, nil
}
