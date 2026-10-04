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

package waf

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
)

// Caddy module identifiers. Mirrors the Step E
// metrics module's split between full dotted ID (Caddy
// internals) and the handler-name segment (JSON config).
const (
	ModuleID    = "http.handlers.arenet_waf"
	HandlerName = "arenet_waf"
)

// wafPool reuses coraza.WAF instances across Caddy reloads.
// Two routes with identical config + mode share one WAF
// (saves the ~50 ms CRS parse on every reload). Mirrors the
// coraza-caddy/v2 pattern.
var wafPool = caddy.NewUsagePool()

type pooledWAF struct {
	waf coraza.WAF
}

func (p *pooledWAF) Destruct() error {
	if c, ok := p.waf.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func init() {
	caddy.RegisterModule(ArenetWafHandler{})
}

// ArenetWafHandler is the Step M custom Caddy WAF module. It
// wraps coraza/v3 directly (rather than coraza-caddy/v2)
// so the per-rule match callback exposes per-block events
// that the dashboard requires (rule_id, OWASP category,
// severity, src_ip, payload sample). See spec
// docs/superpowers/specs/2026-05-28-step-m-security.md §3.2
// for the rationale and §1.3 D1 for the rejected alternative
// (status-code-derived).
//
// Configuration fields are populated by caddymgr's
// buildArenetWafHandler emit:
//   - RouteID: the storage route UUID this handler instance
//     guards. Carried into every emitted Event so the
//     dashboard can attribute blocks per-route.
//   - Mode: "block" or "detect". block returns the
//     interruption status (typically 403); detect emits the
//     event but lets the request continue. Distinct from
//     the Coraza-level SecRuleEngine directive — Mode is
//     OUR policy, baked into the appended directive at
//     Provision.
//   - Directives: the user's coraza directive string
//     (Include @coraza.conf-recommended, Include
//     @owasp_crs/*.conf, etc.). Step M caddymgr emit hardcodes
//     the recommended CRS setup, same as Step I.4.
//   - LoadOWASPCRS: when true, the CRS-embedded FS is mounted
//     so the @owasp_crs Include directives resolve.
type ArenetWafHandler struct {
	RouteID      string `json:"route_id,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Directives   string `json:"directives,omitempty"`
	LoadOWASPCRS bool   `json:"load_owasp_crs,omitempty"`
	// Host is the primary hostname this handler guards. Used
	// only for the W.bugfix Fix #2 boot log line so operators
	// reading journalctl don't have to cross-reference
	// route_id back to a host. Optional on the wire — a
	// pre-Fix-#2 emit decodes with Host="" and the log line
	// just shows the route_id.
	Host string `json:"host,omitempty"`
	// SkipBodyInspection (Phase 4.5, #R-WAF-BUFFER-OOM-ON-
	// LARGE-UPLOADS) tells processRequest to skip the
	// ReadRequestBodyFrom path so the upload is not staged in
	// RAM for rule scanning. Headers / URI / response phases
	// stay live; only the request body bytes are not fed to
	// Coraza. Paired in the route config with Caddy's
	// flush_interval=-1 — the two effects together preserve
	// the per-route WAF posture (headers blocked, URL rules
	// active) while making bulk uploads safe on small-RAM
	// homelab hosts. NOT included in computePoolKey: it's a
	// per-call decision that doesn't change the underlying
	// WAF instance, so routes with matching directives+mode
	// can still share a pooled Coraza WAF.
	SkipBodyInspection bool `json:"skip_body_inspection,omitempty"`

	waf     coraza.WAF
	poolKey string
}

// wafTxBuffers stages onMatch-fired Events between match time
// and handler exit. Keyed by tx.ID() string (NOT tx pointer —
// Coraza v3 recycles *Transaction via sync.Pool at internal/
// corazawaf/waf.go:53, so a pointer key could collide
// silently with a recycled allocation; tx.ID() is a
// per-NewTransaction 19-char random string, collision-safe at
// homelab scale).
//
// Step Z (2026-06-18) — PROMOTED to package-level.
//
// Pre-Z this map was per-ArenetWafHandler (h.txBuffers).
// With Step I.4 pool dedup, several handlers share the
// underlying coraza.WAF instance ; the error callback closure
// captured by buildWAF (line 274) bound to whichever handler
// won the LoadOrNew race. Subsequent handlers' transactions
// fired through the first handler's closure, which then
// looked up the buffer in its OWN h.txBuffers — miss — and
// fell through to fallbackEmit(h.RouteID = first-handler-
// route, ...). Every other route's events were attributed to
// the first-provisioned route. Audit recorded the empirical
// repro and the design pivot.
//
// Promoting wafTxBuffers to package scope solves it : every
// handler stages its tx buffer in the SAME map ; the callback-
// owner handler finds buffers staged by pool-shared peers ;
// the per-buffer RouteID field (txEventBuffer.RouteID below)
// carries the runtime-correct attribution.
//
// Lifecycle (per request) :
//  1. ServeHTTP creates a buffer with h.RouteID and stores
//     it under tx.ID() in wafTxBuffers BEFORE calling
//     processRequest.
//  2. onMatch looks up the buffer via mr.TransactionID() in
//     wafTxBuffers and appends the Event with the buffer's
//     RouteID (NOT the closure-captured h.RouteID) +
//     placeholder Action / StatusCode.
//  3. The flush defer walks the buffer, sets the correct
//     (Action, StatusCode) tuple based on mode +
//     tx.Interruption(), and sink.Emits each event.
//  4. A nested defer Deletes the entry from the map even
//     if the flush body panics — guarantees no buffer
//     leak across the tx pool recycle window.
//
// Memory : entry count is bounded by the number of in-flight
// transactions. Coraza closes the tx synchronously in
// ServeHTTP's defer chain, so the steady-state count is the
// concurrent request count on routes with WAF on. No
// long-lived accumulation.
var wafTxBuffers sync.Map

// txEventBuffer collects events fired by onMatch during a
// single transaction. No mutex : the Coraza error callback
// runs synchronously on the request goroutine, so onMatch
// and the flush defer are the only writers and they're
// sequential.
//
// Step Z : RouteID carries the runtime-correct route
// attribution across the pool-dedup boundary. Populated by
// the handler in ServeHTTP from its OWN h.RouteID at buffer
// staging time. onMatch reads buf.RouteID instead of the
// (potentially-wrong) closure-captured h.RouteID so events
// land on the right route regardless of which handler owns
// the Coraza WAF instance.
type txEventBuffer struct {
	RouteID string
	events  []Event
}

// CaddyModule satisfies caddy.Module.
func (ArenetWafHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  ModuleID,
		New: func() caddy.Module { return new(ArenetWafHandler) },
	}
}

// Validate enforces the small set of fields the handler
// requires before Provision can build the WAF. RouteID and
// Mode are caddymgr-supplied; an empty RouteID would attribute
// every event to the "" route, which would silently corrupt
// the dashboard.
func (h *ArenetWafHandler) Validate() error {
	if h.RouteID == "" {
		return errors.New("arenet_waf: route_id is required")
	}
	switch h.Mode {
	case "block", "detect":
	case "":
		return errors.New("arenet_waf: mode is required (\"block\" or \"detect\")")
	default:
		return fmt.Errorf("arenet_waf: mode %q must be \"block\" or \"detect\"", h.Mode)
	}
	return nil
}

// Provision builds (or reuses from the pool) the coraza.WAF
// instance for this handler. The error callback registered
// here is the secret sauce of D1=B: Coraza calls it per
// matched rule, we translate each call into a sink.Emit.
func (h *ArenetWafHandler) Provision(_ caddy.Context) error {
	h.poolKey = h.computePoolKey()
	// Step Z (2026-06-18) — tx event buffer map moved to
	// package level (wafTxBuffers). Pre-Z this was per-
	// handler ; the audit caught the cross-handler
	// misattribution that move fixes (see wafTxBuffers
	// docstring).

	val, loaded, err := wafPool.LoadOrNew(h.poolKey, func() (caddy.Destructor, error) {
		waf, err := h.buildWAF()
		if err != nil {
			return nil, err
		}
		return &pooledWAF{waf: waf}, nil
	})
	if err != nil {
		return fmt.Errorf("arenet_waf: build waf: %w", err)
	}
	h.waf = val.(*pooledWAF).waf

	// W.bugfix Fix #2 — per-route boot signal. Emits one log
	// line every time Caddy instantiates a WAF handler (i.e.
	// once per route-with-WAF-on per reload). The `pooled`
	// field tells operators whether this provision reused an
	// existing Coraza WAF instance from wafPool (true == reused
	// — saves the ~50 ms CRS parse cost) or built a fresh one.
	// Two routes with identical (mode, directives, crs) share
	// a pool_key — that's intentional (computePoolKey design)
	// and visible in the log for verification.
	//
	// Pre-Fix-#2 boot logs showed only one sink-level
	// "waf event sink wired" line, leaving operators blind
	// to which routes actually had WAF on and at what mode.
	slog.Default().Info("waf handler provisioned",
		"route_id", h.RouteID,
		"host", h.Host,
		"mode", h.Mode,
		"pool_key", h.poolKey,
		"pooled", loaded,
		"load_owasp_crs", h.LoadOWASPCRS,
	)
	return nil
}

// buildWAF constructs the coraza.WAF, with the error callback
// hooking each rule match into the global EventSink. The
// callback closure captures h.RouteID + h.Mode so each event
// carries the right attribution.
func (h *ArenetWafHandler) buildWAF() (coraza.WAF, error) {
	// In block mode we need SecRuleEngine On; in detect mode
	// DetectionOnly. Append AFTER the user's directives so
	// our policy wins on conflict — the dashboard's notion
	// of "this route is in block mode" is the contract we
	// expose to the operator, and Coraza must agree.
	mode := "On"
	if h.Mode == "detect" {
		mode = "DetectionOnly"
	}
	// Exclusion rules must PREPEND the CRS Includes, not
	// append: Coraza processes phase:1 rules in file load
	// order, so an exclusion that fires after rule 911100
	// (PROTOCOL_ENFORCEMENT method check) never gets to
	// remove it from the transaction's scope — 911100
	// already blocked. By placing the SecRule + ctl action
	// BEFORE the CRS Includes, the ctl runs first and the
	// CRS rules added afterward are removed before they
	// evaluate.
	//
	// SecRuleEngine still appends (terminal directive
	// wins) so block/detect mode behaviour is unchanged.
	directives := adminAPIExclusionDirective + h.Directives + "\nSecRuleEngine " + mode

	cfg := coraza.NewWAFConfig().
		WithErrorCallback(h.onMatch).
		WithDirectives(directives)
	if h.LoadOWASPCRS {
		cfg = cfg.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
	}
	return coraza.NewWAF(cfg)
}

// adminAPIExclusionDirective is a CRS false-positive guard
// for the Arenet management plane.
//
// History:
//   - Item 1 (#R-WAF-FP-uuid-paths, commit a6276a8, 2026-06-08):
//     guard added with a narrow regex covering ONLY UUID-shaped
//     paths /api/v1/(routes|settings)/<UUID> after DETECT-mode
//     observation caught rules 930120 (LFI), 931100 (RFI),
//     949110 (anomaly), 911100 (PROTOCOL method) triggering on
//     the hex+hyphen UUID string.
//   - #R-WAF-BLOCKS-MUTATING-METHODS (this change, 2026-06-10):
//     widened to cover the WHOLE `/api/v1/` subtree. Operator-
//     reproduced bug: a self-route admin (host=arenet.* →
//     127.0.0.1:adminPort) with WAFMode=block + OWASP CRS
//     loaded was returning 403 on every PUT/DELETE/PATCH to
//     literal-named admin paths (e.g. /api/v1/settings/crowdsec,
//     /api/v1/settings/automation/credentials). The UUID-only
//     regex didn't cover the literal-named subtree.
//     CRS 911100 (PROTOCOL_ENFORCEMENT method check) fires on
//     PUT/DELETE/PATCH because the default tx.allowed_methods
//     is "GET HEAD POST OPTIONS". See
//     docs/superpowers/decisions/2026-06-10-waf-excludes-
//     management-plane.md for the architecture rationale.
//
// Mechanism (unchanged from Item 1):
// SecRule on REQUEST_FILENAME at phase:1 (request headers,
// runs BEFORE the CRS phase:2 evaluation rules). When the
// path matches the admin API pattern, ctl:ruleRemoveById
// removes the four FP-prone rule families from this
// transaction's scope. The rule itself uses pass + nolog so
// it neither blocks nor emits an event — the legitimate
// request reaches the inner handlers unchanged.
//
// Pattern: ^/api/v1(/.*)?$
//   - Anchored start so it can't be widened by leading
//     path components.
//   - Optional trailing path captures every endpoint
//     (settings/<uuid>, settings/crowdsec, security/*,
//     audit, routes, observability/*, automation/*, etc.).
//   - No trailing $ so query strings + fragments still match
//     (REQUEST_FILENAME is path-only per Coraza's
//     transaction.go:864, so this is effectively anchored
//     end-of-path anyway).
//
// Variable choice (unchanged): REQUEST_FILENAME (path-only)
// rather than REQUEST_URI. Coraza's ProcessURI populates
// REQUEST_URI with the full input string passed by the
// caller — in arenet's case `req.URL.String()` which retains
// scheme+host when present (e.g.
// "http://localhost/api/v1/settings/crowdsec"). REQUEST_FILENAME
// is set to `parsedURL.Path`, always starting at "/"
// regardless of caller URL composition. Matching the
// path-only variable keeps the regex compact and works
// identically across test + production code paths.
//
// Rule families removed (unchanged from Item 1):
//   - 911100-911199: PROTOCOL_ENFORCEMENT method checks
//     (PUT/DELETE/PATCH not in default allowed_methods —
//     would 403 every legitimate operator API write).
//     THIS IS THE PRIMARY DRIVER of the widening.
//   - 930000-930999: LFI rules (UUID hex+hyphen pattern
//     triggers 930120 restricted-file-access; widening
//     keeps the original Item 1 coverage for UUID paths
//     as a strict superset).
//   - 931000-931999: RFI rules (same FP shape as LFI).
//   - 949000-949999: anomaly score aggregator. Removing
//     this means OTHER families (942xxx SQLi, 941xxx XSS,
//     etc.) still EMIT events but don't trigger blocking
//     on management plane URIs — they only contribute to
//     the anomaly score, and without 949* nothing reads
//     that score to make the block decision.
//
// Rule ID 100001: arenet-reserved ID block (CRS reserves
// 900000..999999 for OWASP, leaves 100000+ free for custom).
//
// Trade-off (unchanged shape, wider scope):
// The management plane IS the operator's own authenticated
// admin surface. Every /api/v1/ endpoint is HardAuth-gated
// (chi middleware at routes.go:143) and admin writes have a
// further RequireAdminMiddleware (routes.go:284). Auth +
// RBAC are the real gates; the WAF was producing false
// positives here without protecting against real threats
// the operator-only-authenticated path could face. Non-FP
// rule families (SQLi, XSS, scanner) still EMIT events so
// the activity log records attempted attack shapes for
// forensic review.
//
// User proxy routes are UNAFFECTED — the pattern is path-
// based, not host-based, and user routes proxy to upstreams
// whose path space is entirely operator-controlled. A user
// app that happens to expose its API under "/api/v1/" (e.g.
// a Home Assistant instance) WOULD have these CRS families
// stripped on that path; this collision is narrow, accepted,
// and documented in the decision doc as a known limitation.
const adminAPIExclusionDirective = `

# Arenet — CRS false-positive guard for the management plane.
# Skip CRS rule families 911*, 930*, 931*, 949* when the
# request URI is under /api/v1/. Documented in
# internal/waf/module.go's adminAPIExclusionDirective.
SecRule REQUEST_FILENAME "@rx ^/api/v1(/.*)?$" \
    "id:100001,phase:1,nolog,pass,\
    ctl:ruleRemoveById=911100-911199,\
    ctl:ruleRemoveById=930000-930999,\
    ctl:ruleRemoveById=931000-931999,\
    ctl:ruleRemoveById=949000-949999"
`

// computePoolKey makes pool reuse hash-sensitive to the
// fields that influence WAF construction. Two handler
// instances with the same (mode, directives, load_owasp_crs)
// share a WAF; differing instances build their own.
func (h *ArenetWafHandler) computePoolKey() string {
	hash := sha256.New()
	hash.Write([]byte(h.Mode))
	hash.Write([]byte{0})
	hash.Write([]byte(h.Directives))
	hash.Write([]byte{0})
	if h.LoadOWASPCRS {
		hash.Write([]byte("crs"))
	}
	return fmt.Sprintf("arenet-waf-%x", hash.Sum(nil))
}

// Cleanup releases the pooled WAF reference. The pool's
// UsagePool destructs the underlying coraza.WAF when the last
// reference drops.
func (h *ArenetWafHandler) Cleanup() error {
	_, err := wafPool.Delete(h.poolKey)
	return err
}

// onMatch is Coraza's per-matched-rule callback. Fires once
// per rule the request tripped (a single bad request can
// trip several). Builds + emits an Event for the matches
// that should reach the operator; the sink's LRU rate-limit
// handles deduplication beyond that. The sink also bumps
// the per-minute block counter on every Emit (AC #3
// invariant), so the dashboard timeline reflects attack
// volume even when the LRU suppresses event-table rows.
//
// Filtering policy depends on the handler's mode:
//
//   - **block**: emit only Disruptive() matches. In
//     SecRuleEngine On, the disruptive match is the
//     determinative one (the rule that crossed the anomaly
//     threshold and got the request denied). Non-disruptive
//     warn-level CRS rules contribute to the score but are
//     noise on their own — emitting them would flood the
//     event log.
//
//   - **detect** (SecRuleEngine DetectionOnly): every match
//     is non-disruptive by Coraza's definition, so the
//     block-mode filter would emit nothing. Instead filter
//     by severity: Warning (4) or higher means a CRS rule
//     designed to indicate a real attack signature. Notice/
//     Info/Debug matches stay suppressed (CRS uses them for
//     scoring + tracing).
//
// Coraza severity scale is inverted: 0=Emergency, 1=Alert,
// 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug.
// Lower = more severe; we want sev ≤ 4 in detect mode.
const detectModeMaxSeverity = 4

func (h *ArenetWafHandler) onMatch(mr types.MatchedRule) {
	rule := mr.Rule()
	switch h.Mode {
	case "block":
		if !mr.Disruptive() {
			return
		}
	case "detect":
		if int(rule.Severity()) > detectModeMaxSeverity {
			return
		}
	default:
		// Validate caught this at Provision-time; defensive
		// belt-and-braces.
		return
	}

	// #R-WAF-EVENT-LABEL-BLOCK-VS-200 — Action + StatusCode
	// are now decided at handler exit, NOT here. Pre-fix the
	// W.bugfix Fix #1 set Action=ActionBlock+StatusCode=403
	// unconditionally when h.Mode==block AND mr.Disruptive()
	// — but Disruptive_ at this point only means "this rule
	// has a disruptive action declared AND SecRuleEngine is
	// On". On admin paths the 949* aggregator is excluded
	// (manager-plane FP guard), so a disruptive 942 match
	// FIRES onMatch with Disruptive=true but never actually
	// interrupts the transaction — the request reaches the
	// upstream and returns 200. Emitting BLOCK/403 here
	// produced waf_event rows that contradicted the real
	// HTTP status.
	//
	// New shape: append the event to the per-tx buffer with
	// Action=ActionDetect + StatusCode=0 as placeholder. The
	// flush defer at ServeHTTP exit walks the buffer and
	// rewrites (Action, StatusCode) to the correct pair
	// based on (h.Mode, tx.Interruption()).
	bufRaw, ok := wafTxBuffers.Load(mr.TransactionID())
	if !ok {
		// No buffer for this tx — happens on the rule-engine-
		// off short-circuit path (ServeHTTP returns before
		// Store fires) and on tests that hand-roll a tx
		// without going through ServeHTTP. Fall back to the
		// pre-fix emit shape (best-effort: the operator
		// still sees the event in the activity log) so we
		// don't silently drop the match.
		//
		// Step Z caveat : the closure-captured h.RouteID may
		// be the wrong route when pool dedup is active (the
		// first-provisioned handler owns the closure). This
		// fallback path is reachable in production only for
		// rule-engine-off requests, which by construction
		// don't produce rule matches ; the path is therefore
		// effectively unreachable in steady-state and the
		// h.RouteID staleness is a documented best-effort
		// degradation for the hand-rolled-tx test edge case.
		fallbackEmit(h.RouteID, h.Mode, mr, rule)
		return
	}
	buf := bufRaw.(*txEventBuffer)

	ruleID := strconv.Itoa(rule.ID())
	method, path, payload, matchedVar := requestSnippetFromMatch(mr)
	buf.events = append(buf.events, Event{
		Ts: time.Now().UTC(),
		// Step Z — read the buffer's RouteID (runtime-correct,
		// staged by the handler that actually owns this
		// request) instead of h.RouteID (closure-captured at
		// buildWAF time, attributes to the first-provisioned
		// route when pool dedup is active).
		RouteID:       buf.RouteID,
		RuleID:        ruleID,
		Category:      CategoryForRule(ruleID),
		Severity:      int(rule.Severity()),
		SrcIP:         mr.ClientIPAddress(),
		RequestMethod: method,
		RequestPath:   Truncate(Redact(path), MaxRequestPathBytes),
		PayloadSample: Truncate(Redact(payload), MaxPayloadSampleBytes),
		MatchedVar:    Truncate(matchedVar, MaxMatchedVarBytes),
		// Action + StatusCode left as zero values — set by
		// flushTxBuffer based on the final tx verdict.
	})
}

// fallbackEmit is the pre-#R-WAF-EVENT-LABEL emit path,
// preserved for the rule-engine-off short-circuit branch and
// for hand-rolled-tx test paths that don't set up the per-tx
// buffer. Block-mode emits BLOCK/403, detect-mode emits
// DETECT/0 — the original (slightly buggy on admin paths)
// label policy. Production traffic always goes through the
// buffered path because ServeHTTP unconditionally Stores a
// buffer post-NewTransaction.
func fallbackEmit(routeID, mode string, mr types.MatchedRule, rule types.RuleMetadata) {
	sink := getGlobalSink()
	if sink == nil {
		return
	}
	ruleID := strconv.Itoa(rule.ID())
	method, path, payload, matchedVar := requestSnippetFromMatch(mr)
	action := ActionDetect
	statusCode := 0
	if mode == "block" {
		action = ActionBlock
		statusCode = http.StatusForbidden
	}
	sink.Emit(Event{
		Ts:            time.Now().UTC(),
		RouteID:       routeID,
		RuleID:        ruleID,
		Category:      CategoryForRule(ruleID),
		Severity:      int(rule.Severity()),
		SrcIP:         mr.ClientIPAddress(),
		RequestMethod: method,
		RequestPath:   Truncate(Redact(path), MaxRequestPathBytes),
		PayloadSample: Truncate(Redact(payload), MaxPayloadSampleBytes),
		MatchedVar:    Truncate(matchedVar, MaxMatchedVarBytes),
		Action:        action,
		StatusCode:    statusCode,
	})
}

// flushTxBuffer walks the buffered events for a transaction
// and Emits each with the correct (Action, StatusCode) tuple
// computed from the handler mode + the transaction's final
// interruption state. Called from ServeHTTP's defer chain
// BEFORE tx.Close (which would recycle the *Transaction into
// Coraza's sync.Pool).
//
// Decision matrix:
//
//	block mode + interrupted → BLOCK + interruption.Status
//	                           (typically 403 from CRS 949110)
//	block mode + NOT interrupted → DETECT + 200 (event fired
//	                                but transaction continued;
//	                                the admin-path FP guard
//	                                scenario)
//	detect mode → DETECT + 0 (sentinel: "request reached
//	                           upstream; status not captured
//	                           at WAF layer" — frontend
//	                           renders "—" for that case)
func (h *ArenetWafHandler) flushTxBuffer(buf *txEventBuffer, interruption *types.Interruption) {
	if len(buf.events) == 0 {
		return
	}
	sink := getGlobalSink()
	if sink == nil {
		return
	}

	action := ActionDetect
	statusCode := 0
	if h.Mode == "block" {
		if interruption != nil {
			action = ActionBlock
			statusCode = interruption.Status
			if statusCode == 0 {
				statusCode = http.StatusForbidden
			}
		} else {
			// Block-mode + no actual interruption: this is
			// the admin-path FP scenario. Operator sees the
			// match in the activity log but the row
			// truthfully says DETECT + 200 to match the
			// HTTP outcome.
			action = ActionDetect
			statusCode = http.StatusOK
		}
	}

	for i := range buf.events {
		buf.events[i].Action = action
		buf.events[i].StatusCode = statusCode
		sink.Emit(buf.events[i])
	}
}

// requestSnippetFromMatch extracts the method, path, and a
// payload sample from a MatchedRule. The coraza/v3 types
// surface the URI on the rule (it's the full request URI
// unparsed). Method is not directly exposed on the rule, so
// we fall back to an empty string — the dashboard's recent-
// events widget shows "—" when method is unknown.
//
// Payload sample: built from the matched-variable Data() of
// the first MatchData (the variable that triggered the rule).
// CRS rules typically populate Data with the offending bytes;
// for non-CRS rules it may be empty.
//
// matchedVar (v2.36) is "VARIABLE:key" of that same MatchData (the
// rule's own variable, see coraza transaction.go GetField), or "" when
// the variable has no key.
func requestSnippetFromMatch(mr types.MatchedRule) (method, path, payload, matchedVar string) {
	path = mr.URI()
	// Method isn't on the rule; the request lives in the
	// transaction. Coraza doesn't expose it through the
	// MatchedRule interface, so we use the (empty) default.
	// caddymgr could pass it via a context-bound replacer
	// in a future refinement; for M.1 it's tolerable.
	method = ""
	for _, md := range mr.MatchedDatas() {
		if v := md.Value(); v != "" {
			payload = v
			if k := md.Key(); k != "" {
				matchedVar = md.Variable().Name() + ":" + k
			}
			break
		}
	}
	return
}

// isWebSocketUpgrade reports whether r is an HTTP 1.1
// WebSocket upgrade handshake (RFC 6455 §4.1). Two header
// invariants — both required, case-insensitive (HTTP headers
// are case-insensitive per RFC 7230 §3.2):
//
//   - Upgrade: websocket
//   - Connection: upgrade (may carry additional tokens,
//     e.g. "keep-alive, Upgrade" — the comma-separated list
//     is RFC 7230 §6.1 compliant and present in some clients;
//     substring-match the lowercased value rather than
//     EqualFold the whole header).
//
// We intentionally do NOT check Sec-WebSocket-Key /
// Sec-WebSocket-Version: a client missing those is malformed
// but still trying to upgrade, and bypassing the WAF is the
// safest behaviour (Coraza can't handle it either way; the
// upstream gets the malformed handshake and replies 400).
//
// Pure function; called once per request on the hot path.
// Two map lookups + a strings.Contains; nanoseconds.
func isWebSocketUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// ServeHTTP wraps the next handler with Coraza's request +
// response inspection. The shape mirrors coraza-caddy/v2's
// ServeHTTP exactly — the security path is too risky to
// reinvent. Differences from upstream:
//   - We use our package-local processRequest / wrap.
//   - Logging on interruption uses slog.Default rather than
//     a zap logger embedded in the handler (caddymgr emits
//     don't carry one).
//   - On interruption: in BLOCK mode we return HandlerError
//     so Caddy emits the configured status (typically 403);
//     in DETECT mode we let the request through (the
//     callback already emitted the event).
//   - WebSocket upgrade requests bypass the WAF entirely
//     (see isWebSocketUpgrade doc-comment below). The
//     bypass runs BEFORE tx.NewTransaction so we don't
//     allocate Coraza state for a request we're going to
//     pass through anyway.
func (h *ArenetWafHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// WAF bypass for WebSocket upgrades. Coraza wraps the
	// response writer for phase 4-5 (response body) rule
	// evaluation, but the wrapper does NOT implement
	// http.Hijacker — required for HTTP 101 Switching
	// Protocols. Activating the WAF (even in detect mode)
	// on a route that proxies a WebSocket app (Home
	// Assistant /api/websocket, Jellyfin, n8n, TeslaMate,
	// Outline) breaks the WebSocket handshake. Coraza
	// maintainer confirmed this is intentional / out of
	// scope upstream:
	// https://github.com/corazawaf/coraza/discussions/1399
	//
	// The bypass is unconditional: detect + block modes
	// both pass WebSocket upgrade requests through to the
	// upstream untouched. Operators wanting per-route WAF
	// coverage on the HTTP side of a WebSocket app keep
	// that protection — only the upgrade handshake itself
	// (one request per session) is exempt.
	//
	// DEBUG (not INFO) log because chatty heartbeat-heavy
	// apps would otherwise spam journalctl: an active
	// dashboard with 5 routes could emit hundreds of
	// upgrade attempts per minute under reconnect storms.
	// Operators flipping arenet to DEBUG see the bypass
	// signal without paying the steady-state cost.
	if isWebSocketUpgrade(r) {
		slog.Default().Debug("waf: bypassing websocket upgrade",
			"route_id", h.RouteID,
			"path", r.URL.Path,
		)
		return next.ServeHTTP(w, r)
	}

	tx := h.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	if tx.IsRuleEngineOff() {
		return next.ServeHTTP(w, r)
	}

	// #R-WAF-EVENT-LABEL-BLOCK-VS-200 — stage per-tx event
	// buffer BEFORE any rule evaluation so onMatch can find
	// it via mr.TransactionID() lookup. Flush defer runs
	// FIRST in LIFO order (added AFTER the tx.Close defer
	// above) — critical so tx.Interruption() is still
	// readable when flushTxBuffer fires; tx.Close pools the
	// transaction and would clear the interruption state
	// underneath us.
	//
	// Nested defer for Delete (D5 defensive): guarantees
	// the buffer entry is removed from txBuffers even if
	// flushTxBuffer panics. Without this, a panic would
	// leak the entry; Coraza's tx.ID() generator
	// (RandomString(19)) makes collision practically
	// impossible, but a stale entry still costs memory and
	// triggers a never-cleared sink Emit retry on the
	// next eviction.
	txID := tx.ID()
	// Step Z — RouteID seeded from THIS handler's RouteID at
	// staging time so the runtime route attribution survives
	// the pool-shared callback closure. See wafTxBuffers
	// docstring for the full audit trail.
	buf := &txEventBuffer{RouteID: h.RouteID}
	wafTxBuffers.Store(txID, buf)
	defer func() {
		defer wafTxBuffers.Delete(txID)
		h.flushTxBuffer(buf, tx.Interruption())
	}()

	if h.SkipBodyInspection {
		// Phase 4.5 — surfaced at DEBUG so operators tracing
		// a large-upload route can verify the skip is in
		// effect without a per-request INFO line at steady
		// state. The route_id ties the skip back to storage
		// so cross-referencing with the /utilisateurs view
		// stays trivial.
		slog.Default().Debug("waf: skipping request body inspection per route config",
			"route_id", h.RouteID,
			"path", r.URL.Path,
		)
	}
	if it, err := processRequest(tx, r, h.SkipBodyInspection); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		// In block mode the Coraza transaction is in
		// SecRuleEngine On so it returns a real interruption.
		// In detect mode it's DetectionOnly so we should NOT
		// see an interruption — but if the user's directives
		// include a disruptive rule that bypasses
		// DetectionOnly, fall through gracefully (don't
		// block the request, since the operator declared
		// detect intent on this route).
		if h.Mode == "block" {
			// v2.62 — name the refusal in the access log. A WAF 403
			// was byte-indistinguishable from a backend's own 403,
			// which cost an afternoon on 2026-10-04 when two members
			// were banned by CrowdSec and nothing in the log said who
			// had refused them. Read back by the log_append handler at
			// the top of the chain. A Caddy var, not a response
			// header: a prober should not be told which gate stopped
			// them.
			//
			// Set BEFORE returning the HandlerError, because the error
			// path unwinds through log_append just as the normal path
			// does.
			caddyhttp.SetVar(r.Context(), DeniedVarKey, DeniedReason)
			return caddyhttp.HandlerError{
				StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
				ID:         tx.ID(),
				Err:        errInterruptionTriggered,
			}
		}
		// detect mode + interruption: log and continue.
		return next.ServeHTTP(w, r)
	}

	ww, processResponse := wrap(w, r, tx)
	if err := next.ServeHTTP(ww, r); err != nil {
		return err
	}
	return processResponse(tx, r)
}

// DeniedVarKey / DeniedReason mirror caddymgr's constants of the same
// name. Duplicated rather than imported because waf must not depend on
// caddymgr — the dependency runs the other way. A test in caddymgr
// pins that the two agree.
const (
	DeniedVarKey = "arenet_denied"
	DeniedReason = "waf"
)

// Interface guards.
var (
	_ caddy.Provisioner           = (*ArenetWafHandler)(nil)
	_ caddy.Validator             = (*ArenetWafHandler)(nil)
	_ caddy.CleanerUpper          = (*ArenetWafHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ArenetWafHandler)(nil)
)
