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
)

// maintenanceRetryAfterSentinel is replaced at emission time with the
// route's Retry-After value inside the maintenance page body. Kept as
// a distinct placeholder (rather than reusing an error-page runtime
// placeholder) because the retry-after value is a per-route STATIC
// int baked in at config-build time, not a Caddy runtime expression —
// there is no {http....} equivalent for "this route's configured
// Retry-After seconds".
const maintenanceRetryAfterSentinel = "{arenet.maintenance.retry_after}"

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
// Only the built-in default page carries this sentinel; custom pages
// don't (auto-refresh is default-page-only), but they can add their own
// meta refresh using {arenet.maintenance.retry_after}.
const maintenanceRefreshMetaSentinel = "{arenet.maintenance.refresh_meta}"

// maintenanceRetryAfterHumanSentinel is replaced at emission time with
// the route's Retry-After rendered in words — "1 day", "5 minutes",
// "1 hour 30 minutes" — and with the empty string when Retry-After is 0
// (v2.69.0).
//
// The raw sentinel above stays raw, and the operator pushed back on
// that: "retire donc le retry_after et garde seulement le bon non ?
// pourquoi avoir les deux". Two reasons, one decisive.
//
// Decisive: removing a sentinel does not hide it, it REVEALS it.
// static_response expands its body with repl.ReplaceKnown (Caddy
// v2.11.4 staticresp.go:208), and ReplaceKnown is documented as
// "Unrecognized placeholders will remain in the output"
// (replacer.go:151-157). Stop substituting the token and every custom
// maintenance page already deployed that uses it starts printing the
// literal text "{arenet.maintenance.retry_after}" on a public 503.
// Silent, public, and in every installation but ours.
//
// The other: it is the only language-neutral form. A page written in
// anything but English composes its own sentence around the number,
// because formatRetryAfterHuman emits English words and the served
// page has no locale to key off. The shipped French example is exactly
// that case.
//
// What the raw sentinel is NOT for, and I had this wrong in the first
// draft of this comment: building your own <meta refresh>.
// {arenet.maintenance.refresh_meta} does that in a custom page too —
// the substitution runs over the whole body, not just the default page
// — and it carries the Retry-After 0 guard that a hand-written
// content="0" would reload-loop without.
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
	// The meta refresh above and the Retry-After header in
	// buildMaintenanceRoute keep the RAW seconds. The humanised form is
	// for the reader only; a meta refresh needs an integer and
	// Retry-After is delta-seconds per RFC 9110 §10.2.3.
	retryHuman := formatRetryAfterHuman(retryAfter)
	retryLine := ""
	if retryHuman != "" {
		retryLine = `<p class="retry">Retry in ` + retryHuman + `</p>`
	}

	// Substitution order is free here, and I checked rather than
	// assumed: the three retry-after sentinels all close with '}', so
	// "{arenet.maintenance.retry_after}" is NOT a substring of
	// "…retry_after_human}" or "…retry_after_line}" and no pass can eat
	// another's token. That stops being true the moment one of them is
	// renamed to drop or move the brace, which is what
	// TestBuildMaintenanceBody_SentinelsDoNotShadowEachOther pins.
	out := strings.ReplaceAll(pageHTML, maintenanceRetryAfterHumanSentinel, retryHuman)
	out = strings.ReplaceAll(out, maintenanceRetryAfterLineSentinel, retryLine)
	out = strings.ReplaceAll(out, maintenanceRetryAfterSentinel, strconv.Itoa(retryAfter))
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

// buildMaintenanceRoute builds the terminal subroute handler for a
// route in maintenance mode: an OPTIONAL first inner route matching
// the operator's client_ip bypass allow-list (terminal, dispatches to
// the normal proxy handler chain), followed by a catch-all inner
// route serving a static_response 503 (with Retry-After + the
// maintenance body). metricsHandler is placed first in the 503 inner
// route so the 503 is counted in the per-route metrics (mirrors the
// invariant that metrics stays first in every emitted chain,
// manager.go handlers := []map[string]any{metricsHandler}).
//
// When bypassIPs is empty, the bypass inner route is omitted
// entirely rather than emitted with an empty ranges list: Caddy's
// client_ip matcher with a zero-length ranges slice is documented as
// "matches nothing meaningfully" territory we don't want to rely on
// — omitting the route entirely is the unambiguous "all traffic hits
// the 503" shape.
//
// message is the global operator maintenance message (v2.18.0),
// substituted (escaped, newlines→<br>) into the body via
// buildMaintenanceBody. Empty message renders nothing.
func buildMaintenanceRoute(metricsHandler, proxyHandler map[string]any, bypassIPs []string, retryAfterSeconds int, maintenanceHTML, message string) map[string]any {
	innerRoutes := make([]map[string]any, 0, 2)

	if len(bypassIPs) > 0 {
		innerRoutes = append(innerRoutes, map[string]any{
			"match": []map[string]any{
				{"client_ip": map[string]any{"ranges": bypassIPs}},
			},
			"handle":   []map[string]any{metricsHandler, proxyHandler},
			"terminal": true,
		})
	}

	body := buildMaintenanceBody(maintenanceHTML, retryAfterSeconds, message)
	headers := map[string]any{
		"Content-Type": []string{"text/html; charset=utf-8"},
	}
	if retryAfterSeconds > 0 {
		headers["Retry-After"] = []string{strconv.Itoa(retryAfterSeconds)}
	}
	staticResp := map[string]any{
		"handler":     "static_response",
		"status_code": 503,
		"body":        body,
		"headers":     headers,
	}
	innerRoutes = append(innerRoutes, map[string]any{
		"handle": []map[string]any{metricsHandler, staticResp},
	})

	return map[string]any{
		"handler": "subroute",
		"routes":  innerRoutes,
	}
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
