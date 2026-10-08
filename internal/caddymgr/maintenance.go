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

package caddymgr

import (
	"fmt"
	"html"
	"strconv"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.69.0 removed {arenet.maintenance.retry_after}, the bare-integer
// sentinel this file carried since v2.18.0. It existed to put the delay
// in the page body, and "Retry in 86400s" is not a delay a visitor can
// read — which is what retry_after_human below is for.
//
// Removing a sentinel is normally a silent public break, because
// static_response expands its body with repl.ReplaceKnown (Caddy
// v2.11.4 staticresp.go:208) and ReplaceKnown is documented as
// "Unrecognized placeholders will remain in the output"
// (replacer.go:151-157): an unsubstituted token is PRINTED on the 503,
// not dropped. It was safe here only because the operator confirmed the
// installed base is two instances, both theirs. That reasoning does not
// transfer to the next sentinel someone wants to retire.
//
// The guard that keeps this from rotting lives in
// maintenance_example_page_test.go, whose mustNotContain still lists
// the dead token: a shipped example that reaches for it now fails the
// suite instead of printing it to the public.

// maintenanceMessageSentinel is replaced at emission time with the
// global operator-authored maintenance message
// (storage.MaintenancePageConfig.Message, v2.18.0). Unlike the
// retry_after value (a trusted int), the message is untrusted free
// text, so buildMaintenanceBody HTML-escapes it before substitution
// and renders its newlines as <br>. Empty message → substituted with
// the empty string, so the built-in default's generic sentence stands
// alone and a custom page referencing the placeholder renders nothing
// there.
const maintenanceMessageSentinel = "{arenet.maintenance.message}"

// maintenanceRefreshMetaSentinel is replaced at emission time with a
// <meta http-equiv="refresh" content="N"> tag (N = the route's
// Retry-After seconds) so the built-in default page auto-reloads the
// browser when the maintenance window is expected to end (v2.18.1).
// When Retry-After is 0 the sentinel is replaced with the empty string
// — content="0" would reload instantly, hammering the server in a loop.
// The built-in default page carries this sentinel; a custom page does
// not, but it can opt in simply by putting the sentinel in its own
// <head> — the substitution below runs over the whole body, not just
// the default page, and it brings the Retry-After 0 guard with it. The
// older advice here was to hand-write content="N" from the raw
// retry_after sentinel, which reimplemented that guard badly and is
// moot now that the raw sentinel is gone.
const maintenanceRefreshMetaSentinel = "{arenet.maintenance.refresh_meta}"

// maintenanceRetryAfterHumanSentinel is replaced at emission time with
// the route's Retry-After rendered in words — "1 day", "5 minutes",
// "1 hour 30 minutes" — and with the empty string when Retry-After is 0
// (v2.69.0).
//
// This is now the ONLY way to state the delay in a page body. The
// operator asked for exactly that — "pourquoi avoir les deux …?" — and
// accepted the one consequence: the words are English, so the shipped
// French example reads "1 day" inside French prose. A page in another
// language either lives with that or writes its own fixed wording,
// which is the operator's stated design (English default, customise the
// page for anything else).
//
// The words are English because there is nothing to localise against:
// the value is baked into a static body at config-build time and
// nothing in the data model says what language the page is in. Giving
// it a locale is a feature with storage and UI, not a formatter change.
const maintenanceRetryAfterHumanSentinel = "{arenet.maintenance.retry_after_human}"

// maintenanceRetryAfterLineSentinel is replaced at emission time with
// the default page's whole "Retry in …" paragraph, or with the empty
// string when Retry-After is 0.
//
// It exists because the paragraph has to disappear entirely at 0, not
// just lose its value: today the page says "Retry in 0s", and with a
// humanised value alone it would say "Retry in " with a dangling space.
// A CSS :empty rule cannot reach it either — the <p> still holds the
// literal words "Retry in". So the whole line is the substituted unit.
//
// Default-page-only, exactly like refresh_meta: a custom page carries
// no such sentinel and composes its own prose around
// {arenet.maintenance.retry_after_human}.
const maintenanceRetryAfterLineSentinel = "{arenet.maintenance.retry_after_line}"

// Seconds per unit, spelled as arithmetic so each is self-evidently
// right rather than a number to be trusted.
const (
	secondsPerMinute = 60
	secondsPerHour   = 60 * secondsPerMinute
	secondsPerDay    = 24 * secondsPerHour
)

// retryAfterUnits are the units formatRetryAfterHuman decomposes into,
// largest first. Days is the ceiling deliberately, on two grounds: a
// maintenance window measured in weeks is not a maintenance window, and
// a "month" is not a fixed number of seconds, so rendering one would be
// a guess. It also matches the unit list the operator picks from in the
// route form exactly (web/frontend/src/lib/utils/duration.ts:
// 'seconds' | 'minutes' | 'hours' | 'days'), so a window entered as
// "1 day" is read back by the visitor as "1 day".
var retryAfterUnits = []struct {
	seconds  int
	singular string
}{
	{secondsPerDay, "day"},
	{secondsPerHour, "hour"},
	{secondsPerMinute, "minute"},
	{1, "second"},
}

// formatRetryAfterHuman renders a Retry-After seconds count as English
// words: 86400 → "1 day", 300 → "5 minutes", 5400 → "1 hour 30
// minutes", 90 → "1 minute 30 seconds".
//
// Every non-zero component is emitted, so the text is always EXACTLY
// the stored value and never a rounded approximation. That can produce
// a long string for an odd input ("1 day 1 hour 1 minute 1 second"),
// which is the honest rendering of an odd input; every value the route
// form can produce with its number+unit selector is one component.
//
// Returns the empty string for 0 and for negatives. 0 is reachable —
// storage validates >= 0 (storage/routes.go:651) and the field is
// omitempty — and it means "no Retry-After header, no auto-refresh",
// i.e. no duration to state. Negatives cannot reach here through
// validation; the guard keeps the function total rather than trusting
// that.
//
// English only, matching the rest of the default page (lang="en").
func formatRetryAfterHuman(seconds int) string {
	if seconds <= 0 {
		return ""
	}
	parts := make([]string, 0, len(retryAfterUnits))
	rest := seconds
	for _, u := range retryAfterUnits {
		n := rest / u.seconds
		if n == 0 {
			continue
		}
		rest -= n * u.seconds
		word := u.singular
		if n > 1 {
			word += "s"
		}
		parts = append(parts, strconv.Itoa(n)+" "+word)
	}
	return strings.Join(parts, " ")
}

// buildMaintenanceBody returns the maintenance HTML with the per-route
// Retry-After and the global message substituted in. `pageHTML` is the
// operator's stored page (already sanitized via SanitizeErrorPageBody
// upstream) or the branded default (arenetDefaultMaintenancePage).
// retryAfter is seconds, rendered as a plain integer (e.g. "300").
//
// message is untrusted operator free text. It is HTML-escaped (so it
// cannot inject markup into every 503 body) and its newlines rendered
// as <br> (so a multi-line message from the Settings textarea displays
// across lines instead of collapsing). Escape-then-<br> ordering is
// deliberate: any <br> typed into the message is escaped to &lt;br&gt;
// first, so only the newline-derived <br> tags are real markup. An
// empty message substitutes to the empty string.
func buildMaintenanceBody(pageHTML string, retryAfter int, message string) string {
	// Escape HTML markup, then defang dangerous Caddy placeholders
	// ({env.*}/{file.*}) the operator may have typed — the message
	// has no legitimate placeholders of its own and is substituted
	// into a placeholder-expanded static_response body, so an
	// unneutralized {env.SECRET} would leak into the public 503.
	// Newlines last so multi-line messages render as <br>.
	renderedMsg := html.EscapeString(message)
	renderedMsg = neutralizeDangerousPlaceholders(renderedMsg)
	renderedMsg = strings.ReplaceAll(renderedMsg, "\n", "<br>")

	// Auto-refresh meta (default page only): a positive Retry-After
	// yields a <meta http-equiv="refresh">; 0 yields nothing (an
	// instant-reload loop guard). Custom pages carry no sentinel, so
	// this ReplaceAll is a no-op there.
	refreshMeta := ""
	if retryAfter > 0 {
		refreshMeta = `<meta http-equiv="refresh" content="` + strconv.Itoa(retryAfter) + `">`
	}

	// The humanised duration and the default page's retry line. Both
	// collapse to "" at 0, for the same reason refreshMeta does: there
	// is no duration to state. The line carries the prose so the
	// paragraph can vanish whole — see the sentinel's doc comment.
	//
	// The meta refresh above and the Retry-After header on the 503 route
	// (buildMaintenance503Route) keep the RAW seconds. The humanised form is
	// for the reader only; a meta refresh needs an integer and
	// Retry-After is delta-seconds per RFC 9110 §10.2.3.
	retryHuman := formatRetryAfterHuman(retryAfter)
	retryLine := ""
	if retryHuman != "" {
		retryLine = `<p class="retry">Retry in ` + retryHuman + `</p>`
	}

	// Substitution order is free here, and I checked rather than
	// assumed: both retry-after sentinels close with '}', so
	// "…retry_after_human}" is not a substring of "…retry_after_line}"
	// or the reverse, and neither pass can eat the other's token. That
	// stops being true the moment one is renamed to drop or move the
	// brace, which is what
	// TestBuildMaintenanceBody_SentinelsDoNotShadowEachOther pins.
	out := strings.ReplaceAll(pageHTML, maintenanceRetryAfterHumanSentinel, retryHuman)
	out = strings.ReplaceAll(out, maintenanceRetryAfterLineSentinel, retryLine)
	out = strings.ReplaceAll(out, maintenanceRefreshMetaSentinel, refreshMeta)
	return strings.ReplaceAll(out, maintenanceMessageSentinel, renderedMsg)
}

// resolveMaintenancePage returns the HTML body to use for a
// maintenance route: the operator's stored global page (Task 2,
// MaintenancePageConfig singleton) if non-empty, sanitized through
// the same pipeline as error-page bodies, else the branded default.
// Mirrors resolveErrorPage's override-then-default precedence
// (error_pages.go:404), collapsed to two tiers since there is only
// one global maintenance page (no per-route override, no template
// catalogue) per the Task 2 storage shape.
func resolveMaintenancePage(storedHTML string) string {
	if storedHTML != "" {
		return SanitizeErrorPageBody(storedHTML)
	}
	return arenetDefaultMaintenancePage
}

// arenetDefaultMaintenancePage is the branded default served when the
// operator has not customized the global maintenance page (Task 2,
// MaintenancePageConfig.HTML empty). Mirrors the structure/branding
// of arenetDefaultPage (error_pages.go:259) — same dark theme, same
// card layout, same "powered by Arenet" footer — with a blue "Back
// soon" framing appropriate for a planned outage rather than an
// error, plus the retry-after line.
//
// v2.69.0: that line used to read "Retry in {arenet.maintenance.
// retry_after}s", which put "Retry in 86400s" in front of a visitor who
// has no way to know that is a day. It is now the retry_after_line
// sentinel, which carries the duration in words and vanishes whole when
// Retry-After is 0 (where the old line said "Retry in 0s").
var arenetDefaultMaintenancePage = fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{arenet.maintenance.refresh_meta}
<title>503 Maintenance</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { max-width:520px; text-align:center; }
  .code { font-family:"SF Mono",Menlo,Consolas,monospace; font-size:96px; font-weight:600; color:#58a6ff; margin:0; line-height:1; letter-spacing:-2px; }
  h1 { font-size:24px; font-weight:500; margin:16px 0 8px; color:#f0f6fc; }
  p { color:#8b949e; line-height:1.5; margin:8px 0; }
  .retry { color:#58a6ff; font-family:"SF Mono",Menlo,Consolas,monospace; font-size:13px; }
  /* .msg holds the operator's global message ({arenet.maintenance.message}).
     :empty collapses it to zero height so an unset message leaves no gap. */
  .msg { color:#c9d1d9; line-height:1.6; margin:16px 0 0; }
  .msg:empty { display:none; }
  .meta { margin-top:32px; padding-top:16px; border-top:1px solid #21262d; color:#6e7681; font-size:12px; font-family:"SF Mono",Menlo,Consolas,monospace; }
  a { color:#58a6ff; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <p class="code">503</p>
  <h1>Back soon</h1>
  <p>This service is undergoing scheduled maintenance. Please check back shortly.</p>
  <p class="msg">%s</p>
  %s
  <div class="meta">
    {http.request.method} {http.request.uri_escaped} · request id: {http.request.uuid}<br>
    <a href="https://github.com/barto95100/arenet">powered by Arenet</a>
  </div>
</div>
</body>
</html>`, maintenanceMessageSentinel, maintenanceRetryAfterLineSentinel)

// DefaultMaintenancePageHTML returns the branded default maintenance
// page HTML served when the operator has not customized the global
// maintenance page (storage.MaintenancePageConfig.HTML empty). It is
// the exported accessor for arenetDefaultMaintenancePage, added
// (v2.17.1 Item E) so internal/api's GET /settings/maintenance-page
// handler can surface the built-in default to the frontend — mirrors
// how the error-templates surface exposes its own built-in default
// (Step R Phase 2.1's virtual "arenet-default" template entry).
func DefaultMaintenancePageHTML() string {
	return arenetDefaultMaintenancePage
}

// ---------------------------------------------------------------------
// The maintenance window (v2.70.0)
//
// Spec: docs/superpowers/specs/2026-10-08-maintenance-bypass-serves-
// the-real-route-design.md. Plan: the sibling file under plans/.
//
// Until v2.69.0 a maintenance route short-circuited the whole emitter:
// the branch in buildConfigJSON built a subroute with two inner routes —
// bypass IPs to a bare reverse_proxy over the route's root pool,
// everyone else to the 503 — and skipped every remaining line of the
// per-route body. The bypassed client therefore reached a DIFFERENT
// route than the one that would go live: no path rules (so no per-path
// pools, forward auth, basic auth, IP filters, redirects or rate
// limits), no request/response headers, no gates.
//
// The operator found it the way the feature is meant to be used:
// "depuis mon ip l'accès a la route avec mon ip en bypass c'est ok mais
// une prefix/header qui match une URI avec forward auth elle tombe en
// 404 depuis mon ip". A bypass exists to verify a route before
// reopening it, and it cannot do that while it serves something else.
//
// So the emitter no longer branches. A maintenance route runs through
// the normal assembly and produces exactly the routes it always would;
// afterwards, those routes are gated behind the bypass allow-list and a
// catch-all 503 is appended beside them. Caddy ANDs the members of a
// matcher set and dispatches routes in declaration order, so
// {host, client_ip} followed by {host} is precisely "bypassed clients
// get the real route, everyone else gets the 503".
//
// The window is what makes that safe for every OTHER route: it is
// opened only when MaintenanceConfig is non-nil, so a route without one
// pays a single nil check and not one byte of its emitted JSON can
// move. That is asserted, not argued — testdata/gated_emission_golden
// .json was captured from the code as it stood before this change.
// ---------------------------------------------------------------------

// maintenanceWindow records the span of emitted routes belonging to one
// route in maintenance, so the span can be gated once the loop has
// finished producing it.
type maintenanceWindow struct {
	routeID string

	// hosts is the route's full hostname set (primary + aliases), the
	// same slice the gated routes match on, so the 503 catches exactly
	// what they do not.
	hosts []string

	// httpFrom / httpsFrom are the lengths of the two route slices as
	// they stood BEFORE this iteration appended anything, so the window
	// is everything from that index to the end.
	httpFrom  int
	httpsFrom int

	// bypassIPs empty means nobody bypasses: the window is dropped
	// rather than emitted behind a matcher nothing can satisfy.
	bypassIPs []string

	tlsEnabled bool

	// httpCarriesRedirectOnly records that the HTTP listener received a
	// 301-to-https hop rather than the route (TLSEnabled &&
	// RedirectToHTTPS). Gating a hop is meaningless, and appending a
	// 503 beside it would turn today's "301 then 503 over TLS" into a
	// 503 over plain HTTP — a change on a path that is not the bug.
	// Taken from the same expression the emitter branches on, so the two
	// cannot drift apart.
	httpCarriesRedirectOnly bool

	// The 503 itself, resolved at open time while the route and the
	// options are both in scope.
	body              string
	retryAfterSeconds int
	metricsHandler    map[string]any
}

// openMaintenanceWindow returns nil for every route that is not in
// maintenance, which is the whole non-regression argument: the caller's
// only cost on the normal path is this nil.
func openMaintenanceWindow(
	r storage.Route,
	metricsHandler map[string]any,
	globalPageHTML, globalMessage string,
	httpLen, httpsLen int,
) *maintenanceWindow {
	if r.MaintenanceConfig == nil || r.Disabled {
		return nil
	}
	// Per-route message wins, global is the fallback, both empty
	// substitutes to nothing (v2.18.1).
	msg := r.MaintenanceConfig.Message
	if msg == "" {
		msg = globalMessage
	}
	return &maintenanceWindow{
		routeID:                 r.ID,
		hosts:                   r.AllHosts(),
		httpFrom:                httpLen,
		httpsFrom:               httpsLen,
		bypassIPs:               r.MaintenanceConfig.BypassIPs,
		tlsEnabled:              r.TLSEnabled,
		httpCarriesRedirectOnly: r.TLSEnabled && r.RedirectToHTTPS,
		body: buildMaintenanceBody(
			resolveMaintenancePage(globalPageHTML),
			r.MaintenanceConfig.RetryAfterSeconds,
			msg,
		),
		retryAfterSeconds: r.MaintenanceConfig.RetryAfterSeconds,
		metricsHandler:    metricsHandler,
	}
}

// closeMaintenanceWindow gates the routes this iteration emitted behind
// the bypass allow-list and appends the catch-all 503.
//
// It must be called on EVERY path out of the per-route loop body, not
// just the last one — the forward-auth deny branch continues early. A
// window left open is caught after the loop and returned as an error
// rather than silently producing a maintenance route that serves its
// real content to the world.
func closeMaintenanceWindow(w *maintenanceWindow, httpRoutes, httpsRoutes []httpRoute) ([]httpRoute, []httpRoute) {
	if w == nil {
		return httpRoutes, httpsRoutes
	}

	resp := buildMaintenance503Route(w)

	// HTTP listener. Under RedirectToHTTPS it holds a 301 hop, which is
	// left exactly as it is today (see httpCarriesRedirectOnly).
	if !w.httpCarriesRedirectOnly {
		httpRoutes = gateRoutesBehindBypass(httpRoutes, w.httpFrom, w.bypassIPs)
		httpRoutes = append(httpRoutes, resp)
	}

	if w.tlsEnabled {
		httpsRoutes = gateRoutesBehindBypass(httpsRoutes, w.httpsFrom, w.bypassIPs)
		httpsRoutes = append(httpsRoutes, resp)
	}

	return httpRoutes, httpsRoutes
}

// gateRoutesBehindBypass adds the client_ip matcher to every route from
// `from` onwards, or truncates them away when nobody bypasses.
func gateRoutesBehindBypass(routes []httpRoute, from int, bypassIPs []string) []httpRoute {
	if len(bypassIPs) == 0 {
		// Nobody bypasses, so the real routes must not be reachable at
		// all. Dropped rather than emitted behind an unsatisfiable
		// matcher: a route Caddy can never dispatch to is dead config,
		// and "unsatisfiable" is a property of the matcher that a future
		// edit could accidentally relax.
		return routes[:from]
	}
	for i := from; i < len(routes); i++ {
		if len(routes[i].Match) == 0 {
			// A route with no matcher set matches EVERY request, so it
			// cannot be left alone here — client_ip on its own is the
			// correct gate. No emitted route currently takes this path;
			// the branch exists so that one appearing later is gated
			// rather than silently exposed.
			routes[i].Match = []matcherSet{{ClientIP: &clientIPMatcher{Ranges: bypassIPs}}}
			continue
		}
		for j := range routes[i].Match {
			routes[i].Match[j].ClientIP = &clientIPMatcher{Ranges: bypassIPs}
		}
	}
	return routes
}

// buildMaintenance503Route is a host-only catch-all serving the 503.
//
// It is what survived buildMaintenanceRoute, removed in v2.70.0: that
// function wrapped two inner routes in a subroute — bypass IPs to a
// bare proxy, everyone else to the 503 — and the bypass half is now the
// real route, gated by the window above. `git log -S buildMaintenanceRoute`
// has the old shape.
//
// metricsHandler stays first, per the invariant that every emitted
// chain begins with it. The bypassed route already starts its own chain
// with the same handler, and the two routes are mutually exclusive by
// matcher, so a request is counted exactly once.
func buildMaintenance503Route(w *maintenanceWindow) httpRoute {
	headers := map[string]any{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}
	if w.retryAfterSeconds > 0 {
		headers["Retry-After"] = []string{strconv.Itoa(w.retryAfterSeconds)}
	}
	return httpRoute{
		Match: []matcherSet{{Host: w.hosts}},
		Handle: []map[string]any{
			w.metricsHandler,
			{
				"handler":     "static_response",
				"status_code": 503,
				"body":        w.body,
				"headers":     headers,
			},
		},
		Terminal: true,
	}
}
