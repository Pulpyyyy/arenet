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
	"log/slog"
	"regexp"
	"strings"

	"github.com/microcosm-cc/bluemonday"

	"github.com/barto95100/arenet/internal/storage"
)

// Step R — caddymgr-side emit of per-route custom error pages.
//
// SUPPORTED PLACEHOLDERS (Phase 1.1 docs)
//
// Operators write Caddy runtime placeholders inside their template
// body — NOT Go template syntax. The static_response handler
// expands them at serve time via repl.ReplaceKnown
// (staticresp.go:208). Go template syntax {{.X}} is passed through
// literally and renders as visible text — V2 backlog if there's
// real demand (would need a Caddy templates handler wrap).
//
// Inside an errors-block route (set by HTTPErrorConfig.WithError
// at server.go:765-787 BEFORE the error route runs) :
//
//   {http.error.status_code}    HTTP status code (e.g. 403)
//   {http.error.status_text}    Status text (e.g. "Forbidden")
//   {http.error.id}             Per-error Caddy-generated UUID
//   {http.error.message}        Error message string
//   {http.error.trace}          Handler trace (debug-only ; tends to leak internals)
//
// Inside a reverse_proxy handle_response error path (Phase 1.1
// FIX 3 ; upstream returns 4xx/5xx) :
//
//   {http.reverse_proxy.status_code}    Upstream's literal status
//                                        (verified reverseproxy.go:1081)
//
// Standard request placeholders survive into the error pipeline
// because WithError uses a shallow copy of *Request with the same
// Replacer (server.go:765-772) :
//
//   {http.request.method}       GET / POST / etc.
//   {http.request.host}         Host header (route's primary host)
//   {http.request.uri}          Full URI including query
//   {http.request.uri.path}     Path only (no query)
//   {http.request.uuid}         Per-request Caddy-generated UUID
//                                (useful for "show this ID when you contact support")
//   {http.request.remote.host}  Client IP (or proxy's IP if behind LB)
//
// Reference : https://caddyserver.com/docs/json/apps/http/#errors
//
// Wire shape verified against caddy v2.11.3 :
//   - modules/caddyhttp/server.go:745 (HTTPErrorConfig { Routes RouteList })
//   - modules/caddyhttp/staticresp.go:127 (static_response handler)
//   - modules/caddyhttp/celmatcher.go:82 (http.matchers.expression module)
//
// Resolution order at emit time, in this priority :
//   1. Route.ErrorPageOverrides[code]      (per-route override)
//   2. Template.Pages[code]                (template the route opted into)
//   3. arenetDefaultErrorPages[code]       (built-in default)
//
// First non-empty hit wins. Empty body at any layer falls through.
//
// HTML sanitization : every emitted body passes through the
// bluemonday policy below. Defense-in-depth against a compromised-
// admin reflected-XSS scenario even though the CRUD endpoint is
// RequireAdmin-gated. See Phase R.0 audit.

// errorPageSanitizer is the process-global bluemonday policy
// applied to every emitted body. Allocated once via UGCPolicy()
// then loosened to permit branded error pages (inline + external
// CSS, common <meta> tags) while keeping <script> / <iframe> /
// <object> / event handlers blocked.
//
// bluemonday.Policy is documented as goroutine-safe after the
// AllowXxx wiring completes ; we call those wirings only here.
//
// Phase 2.2 — AllowUnsafe(true) is set explicitly so that the
// CSS rules inside operator-typed <style> blocks survive the
// sanitize pass. Without it, bluemonday strips the inner text
// of any <style> token (sanitize.go:431-440 only emits the
// inner text when AllowUnsafe is true). Pre-2.2 the builtin
// Arenet branded page (which uses a <style> block in <head>
// for the dark theme rules) rendered in prod as bare HTML
// with no styling — matching neither the operator's preview
// nor any reasonable "branded" expectation.
//
// Safety analysis (verified empirically by the 6 test cases
// in error_pages_test.go's "AllowUnsafe safety probe"
// section) :
//
//   - <script> is NOT in AllowElements, so it's stripped by
//     the element policy BEFORE the AllowUnsafe gate matters
//     at the TextToken switch.
//   - <iframe>, <object>, <embed> same : not declared, stripped.
//   - Inline event handlers (onclick, onerror, ...) are
//     stripped by UGCPolicy's attribute allowlist regardless
//     of AllowUnsafe.
//   - The ONLY effect of AllowUnsafe here is preserving the
//     textual content of <style> elements (which are explicitly
//     allowed by our AllowElements call above).
//
// One remaining risk : CSS at-rules that load external
// resources (@import / @charset) can exfil to a tracking
// server via the stylesheet network fetch. stripDangerousAtRules
// (post-sanitize pass) handles that. Operator-supplied url()
// references (background-image, @font-face, ...) are left
// untouched so legitimate branding assets (logos, brand fonts)
// still load — the operator is a trusted admin role.
var errorPageSanitizer = func() *bluemonday.Policy {
	p := bluemonday.UGCPolicy()
	p.AllowStyling()
	p.AllowElements("style", "head", "html", "body", "meta", "title", "link")
	p.AllowAttrs("rel", "href", "media", "type", "crossorigin").OnElements("link")
	p.AllowAttrs("name", "content", "charset", "http-equiv").OnElements("meta")
	p.AllowAttrs("lang").OnElements("html")
	p.AllowUnsafe(true)
	return p
}()

// dangerousAtRulesRE matches CSS at-rules that load external
// resources : @import (loads another stylesheet ; classic
// CSS-based exfil pivot) + @charset (lower-severity but
// still operator-side noise). Both are stripped from <style>
// content via stripDangerousAtRules.
//
// Intentionally NOT stripping url(...) references — legitimate
// branding assets (logos, custom fonts via @font-face) use them.
// The operator role is admin-only, so we trust the operator's
// intent for url() ; @import is the asymmetric risk because
// it cascades into another stylesheet that the operator
// may not have authored.
//
// Pattern : (?i) case-insensitive ; (?s) dot matches newline
// so multi-line @import declarations are caught.
var dangerousAtRulesRE = regexp.MustCompile(`(?is)@(?:import|charset)\b[^;]*;?`)

// styleBlockRE matches the entire <style>...</style> element
// including the tags. The capture group isolates the inner
// CSS text so stripDangerousAtRules can operate on it without
// risk of mangling adjacent HTML.
var styleBlockRE = regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style>`)

// stripDangerousAtRules removes @import / @charset declarations
// from every <style> block in the input. Returns the modified
// HTML. Non-<style> content (inline style="" attributes, body
// text) is untouched.
//
// Defence in depth : even though the operator typed the @import
// themselves (admin role), a compromised admin account /
// reflected XSS via template content / future "import template
// from URL" feature could plant a tracking @import without
// triggering visible browser dev-tools fetches.
func stripDangerousAtRules(html string) string {
	return styleBlockRE.ReplaceAllStringFunc(html, func(match string) string {
		// Extract inner CSS, strip at-rules, re-wrap.
		inner := styleBlockRE.FindStringSubmatch(match)[1]
		cleanInner := dangerousAtRulesRE.ReplaceAllString(inner, "")
		// Preserve the original <style> opening tag (with any
		// attributes like media="print") by substring-replacing
		// the inner text inside the match.
		return strings.Replace(match, inner, cleanInner, 1)
	})
}

// SanitizeErrorPageBody is the exported sanitize pipeline used
// by both the caddymgr emit path AND the API preview endpoint
// (Phase 2.2 — preview now mirrors prod sanitize for visual
// parity in the operator's editor iframe). Single source of
// truth ; any future tightening lands here.
//
// Steps :
//  1. bluemonday Sanitize (elements + attrs allowlist, with
//     AllowUnsafe to preserve <style> content)
//  2. stripDangerousAtRules (remove @import / @charset from
//     <style> blocks)
//  3. postSanitize (re-prepend <!doctype html> that bluemonday
//     strips by design)
//
// Returns the sanitized body ready to write into either a
// Caddy static_response.body field (prod) or an HTTP response
// (preview).
func SanitizeErrorPageBody(body string) string {
	return neutralizeDangerousPlaceholders(postSanitize(stripDangerousAtRules(errorPageSanitizer.Sanitize(body))))
}

// dangerousPlaceholderPrefixes are the Caddy replacer namespaces that
// resolve process/host state independent of the request, so they would
// leak into a PUBLIC static_response body regardless of who triggers
// the 5xx. Verified against Caddy v2.11.3 replacer.go:
//   - {env.*}  → os.Getenv (replacer.go:382-384) — process secrets
//   - {file.*} → readFileIntoBuffer (replacer.go:350-361) — arbitrary
//     on-disk file contents
//
// The documented-safe {http.request.*} (offered in the error-page
// editor's variable palette) and our own {arenet.*} sentinels are
// deliberately NOT in this list — they stay expandable.
var dangerousPlaceholderPrefixes = []string{"{env.", "{file."}

// neutralizeDangerousPlaceholders defangs {env.*} / {file.*} in
// operator-supplied page bodies by replacing the opening brace with its
// HTML entity (&#123;). The text still RENDERS as "{env.FOO}" in the
// browser, but Caddy's placeholder replacer scans for a literal '{' and
// no longer matches, so the value is never expanded at serve time.
// Applied AFTER bluemonday (bluemonday passes {…} through as ordinary
// text, so it must run here, on the final operator content). Our own
// {arenet.maintenance.*} sentinels are substituted in Go before Caddy
// ever sees the body, and {http.request.*} is a documented-safe,
// request-scoped namespace — neither is touched.
func neutralizeDangerousPlaceholders(s string) string {
	for _, prefix := range dangerousPlaceholderPrefixes {
		if strings.Contains(s, prefix) {
			s = strings.ReplaceAll(s, prefix, "&#123;"+prefix[1:])
		}
	}
	return s
}

// ArenetDefaultErrorPages returns the built-in default body
// for the given supported status code, plus a present flag.
// The internal map is unexported (immutability defence — a
// shared exported map would let callers mutate the global)
// but the accessor lets other packages (internal/api Phase
// 2.1 surface) materialise the builtin into a virtual
// template visible in the operator UI.
//
// Returns ("", false) for unsupported codes.
func ArenetDefaultErrorPages(code int) (string, bool) {
	body, ok := arenetDefaultErrorPages[code]
	return body, ok
}

// ArenetDefaultErrorPagesMap returns a shallow copy of the
// full builtin map. Used by the /api/v1/error-templates list
// handler to synthesise the virtual "arenet-default" entry.
// Copy semantics : the caller may not mutate the returned
// map's strings (Go strings are immutable) but the map
// itself is a fresh allocation, so adding/removing keys on
// the returned value does NOT touch the global.
func ArenetDefaultErrorPagesMap() map[int]string {
	out := make(map[int]string, len(arenetDefaultErrorPages))
	for k, v := range arenetDefaultErrorPages {
		out[k] = v
	}
	return out
}

// arenetDefaultErrorPages is the built-in fallback used when no
// template / override matches. Slate dark theme matching the
// Arenet brand. Operators get a recognisable Arenet-branded page
// for free without configuring anything ; opt-in for custom
// branding starts here.
//
// Body strings carry Caddy runtime placeholders
// ({http.error.status_code}, {http.request.uri}, ...) which the
// static_response handler expands at serve time.
var arenetDefaultErrorPages = map[int]string{
	401: arenetDefaultPage(401, "Unauthorized", "Authentication is required to access this resource."),
	403: arenetDefaultPage(403, "Forbidden", "Access to this resource has been denied."),
	404: arenetDefaultPage(404, "Not Found", "The requested resource could not be located on this server."),
	429: arenetDefaultPage(429, "Too Many Requests", "Rate limit exceeded. Please retry after a short wait."),
	500: arenetDefaultPage(500, "Internal Server Error", "An unexpected condition was encountered."),
	502: arenetDefaultPage(502, "Bad Gateway", "The upstream service returned an invalid response."),
	503: arenetDefaultPage(503, "Service Unavailable", "The service is temporarily unable to handle the request."),
	504: arenetDefaultPage(504, "Gateway Timeout", "The upstream service did not respond in time."),
}

// arenetDefaultPage produces a minimal, brand-aligned HTML body
// for one status code. ~1.5 KiB per body — well under the 1 MiB
// cap. The duplicate %d/%s vs format args is intentional ; the
// status code appears twice in the rendered HTML (large hero +
// the <title> tag).
func arenetDefaultPage(code int, title, msg string) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%d %s</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { max-width:520px; text-align:center; }
  .code { font-family:"SF Mono",Menlo,Consolas,monospace; font-size:96px; font-weight:600; color:#58a6ff; margin:0; line-height:1; letter-spacing:-2px; }
  h1 { font-size:24px; font-weight:500; margin:16px 0 8px; color:#f0f6fc; }
  p { color:#8b949e; line-height:1.5; margin:8px 0; }
  .meta { margin-top:32px; padding-top:16px; border-top:1px solid #21262d; color:#6e7681; font-size:12px; font-family:"SF Mono",Menlo,Consolas,monospace; }
  a { color:#58a6ff; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <p class="code">%d</p>
  <h1>%s</h1>
  <p>%s</p>
  <div class="meta">
    {http.request.method} {http.request.uri_escaped} · request id: {http.request.uuid}<br>
    <a href="https://github.com/barto95100/arenet">powered by Arenet</a>
  </div>
</div>
</body>
</html>`, code, title, code, title, msg)
}

// arenetGenericErrorPage is the branded body served by the
// per-host generic fallback error route (buildErrorRoutesForRoute).
// Unlike arenetDefaultPage it hard-codes NO status code: the
// {http.error.status_code} placeholder renders whatever status the
// errors subroute is dispatching, so a SINGLE body covers every
// intercepted code that has no dedicated per-code page.
//
// Why this exists: the reverse_proxy handle_response block intercepts
// ~40 upstream 4xx/5xx codes, but only the 8 SupportedErrorStatusCodes
// have a per-code branded page. Before this fallback, any other
// intercepted code (400, 402, 405, 406, 409, 501, 505, ...) was
// re-raised into the errors chain, matched no route, and finalized as
// a bare empty-body response — the exact symptom that made an upstream
// 400 (e.g. Home Assistant rejecting an untrusted X-Forwarded-For
// proxy) undiagnosable. The generic page guarantees a legible branded
// body for every intercepted status.
//
// The body carries the same Caddy runtime placeholders the
// static_response handler expands at serve time.
var arenetGenericErrorPage = fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{http.error.status_code} · Arenet</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }
  .card { max-width:520px; text-align:center; }
  .code { font-family:"SF Mono",Menlo,Consolas,monospace; font-size:96px; font-weight:600; color:#58a6ff; margin:0; line-height:1; letter-spacing:-2px; }
  h1 { font-size:24px; font-weight:500; margin:16px 0 8px; color:#f0f6fc; }
  p { color:#8b949e; line-height:1.5; margin:8px 0; }
  .meta { margin-top:32px; padding-top:16px; border-top:1px solid #21262d; color:#6e7681; font-size:12px; font-family:"SF Mono",Menlo,Consolas,monospace; }
  a { color:#58a6ff; text-decoration:none; }
</style>
</head>
<body>
<div class="card">
  <p class="code">{http.error.status_code}</p>
  <h1>%s</h1>
  <p>%s</p>
  <div class="meta">
    {http.request.method} {http.request.uri_escaped} · request id: {http.request.uuid}<br>
    <a href="https://github.com/barto95100/arenet">powered by Arenet</a>
  </div>
</div>
</body>
</html>`, "Request could not be completed", "The server or an upstream service returned an error for this request.")

// postSanitize re-prepends the `<!doctype html>` declaration
// that bluemonday strips by design (sanitize.go:241 — "DocType
// is not handled as there is no safe parsing mechanism"). The
// DOCTYPE is a static, parameter-less string ; re-adding it
// is safe because it doesn't carry user content. Without it,
// browsers fall into quirks mode and rendering of the
// operator's CSS becomes unpredictable.
//
// The check skips bodies that don't look like a full HTML
// document (operator wrote just `<h1>403</h1>`) — those don't
// benefit from a DOCTYPE prefix and browsers will quirks-render
// the fragment anyway.
func postSanitize(s string) string {
	trimmed := strings.TrimLeft(s, " \t\n\r")
	// Only re-prepend if the output starts with <html ...> — that's
	// the marker that the operator intended a full document.
	if strings.HasPrefix(strings.ToLower(trimmed), "<html") {
		return "<!doctype html>\n" + s
	}
	return s
}

// resolveCatchallBody (v2.9.10 Bug 1) picks the HTML body for the
// catch-all route emitted by catchAllRoute. Resolution order:
//
//  1. The first template in `templates` whose IsCatchallDefault is
//     true and whose Pages[404] is a non-empty string — returned
//     sanitised with the same bluemonday policy applied to per-
//     route templates.
//  2. Else arenetDefaultErrorPages[404] (the builtin branded body
//     shared with per-route 404 responses).
//
// Empty-body protection: a flagged template whose Pages[404] is
// missing or empty falls through to the builtin. The catch-all
// always serves SOMETHING — never a blank response.
//
// The templates map is the same one buildConfigJSON already builds
// from storage.ListErrorPageTemplates; resolveCatchallBody just
// re-uses it to keep the storage read count at one per reload.
func resolveCatchallBody(templates map[string]storage.ErrorPageTemplate) string {
	for _, t := range templates {
		if !t.IsCatchallDefault {
			continue
		}
		if body, ok := t.Pages[404]; ok && body != "" {
			return SanitizeErrorPageBody(body)
		}
		break
	}
	if body, ok := arenetDefaultErrorPages[404]; ok && body != "" {
		return body
	}
	return ""
}

// resolveErrorPage returns the HTML body to emit for the given
// (route, statusCode) tuple after applying the 3-layer resolution
// order. Empty result means no body is configured — caller skips
// the error route for this code (Caddy falls back to its bare
// status-line response with no body).
//
// templates is the lookup map keyed by template ID, built from
// store.ListErrorPageTemplates(). A dangling
// Route.ErrorPageTemplateID (template deleted) is treated as if
// the route had no template ref : layer 2 falls through to
// layer 3 (built-in default).
func resolveErrorPage(route storage.Route, code int, templates map[string]storage.ErrorPageTemplate) string {
	if body, ok := route.ErrorPageOverrides[code]; ok && body != "" {
		return body
	}
	if route.ErrorPageTemplateID != "" {
		if tmpl, ok := templates[route.ErrorPageTemplateID]; ok {
			if body, ok := tmpl.Pages[code]; ok && body != "" {
				return body
			}
		}
	}
	// v2.51 — the operator's default for routes that chose nothing.
	//
	// Sits BELOW the route's own template on purpose: an explicit choice
	// must keep winning. And it is a separate flag from the catch-all
	// one, because an operator read "default catch-all page" as meaning
	// this and was surprised — the two are different decisions (an
	// unknown host may deserve a neutral 404 while real routes get the
	// branded set), and merging them would have changed behaviour under
	// existing installations without anyone asking.
	if body := routeDefaultErrorPage(templates, code); body != "" {
		return body
	}
	if body, ok := arenetDefaultErrorPages[code]; ok && body != "" {
		return body
	}
	return ""
}

// routeDefaultErrorPage returns the body for code from the template the
// operator flagged as the route default, or "" when none is flagged or
// it defines nothing for that code.
//
// Falling through on a code the template leaves blank is deliberate: a
// template that only customises 404 and 502 should not blank out the
// other six, it should let Arenet's own pages serve them.
func routeDefaultErrorPage(templates map[string]storage.ErrorPageTemplate, code int) string {
	for _, t := range templates {
		if !t.IsRouteDefault {
			continue
		}
		if body, ok := t.Pages[code]; ok && body != "" {
			return SanitizeErrorPageBody(body)
		}
		// At most one template carries the flag (storage enforces it),
		// so there is nothing further to look at.
		break
	}
	return ""
}

// buildErrorRoutesForRoute returns the httpRoute entries that
// should appear under apps.http.servers.<srv>.errors.routes for
// ONE upstream route's host set. One httpRoute per supported
// status code that has a resolvable body.
//
// Each emitted entry carries a matcher set with :
//   - Host : the route's primary host + aliases (scopes the
//     error page to THIS route's traffic ; api.example.com 403
//     doesn't fire the admin.example.com 403 template)
//   - Expression : CEL `{http.error.status_code} == <code>`
//     (dispatches by the in-flight error's status)
//
// The two fields AND-combine inside one matcherSet per Caddy
// docs. One code per route = trivial expressions + the operator
// can disable a single code without affecting the others.
func buildErrorRoutesForRoute(route storage.Route, templates map[string]storage.ErrorPageTemplate, logger *slog.Logger) []httpRoute {
	// AllHosts always returns at least [Host] (possibly "") so we
	// check Host explicitly. A route without a Host shouldn't have
	// made it past storage validation, but defence-in-depth keeps
	// the error route emission tight when an obscure code path
	// calls in with a half-initialised Route.
	if route.Host == "" {
		return nil
	}
	hosts := route.AllHosts()

	if route.ErrorPageTemplateID != "" {
		if _, ok := templates[route.ErrorPageTemplateID]; !ok && logger != nil {
			logger.Warn("error_pages: template ref dangling ; route falls back to built-in defaults",
				"route_id", route.ID,
				"host", route.Host,
				"missing_template_id", route.ErrorPageTemplateID,
			)
		}
	}

	out := make([]httpRoute, 0, len(storage.SupportedErrorStatusCodes)+1)
	for _, code := range storage.SupportedErrorStatusCodes {
		body := resolveErrorPage(route, code, templates)
		if body == "" {
			continue
		}
		clean := SanitizeErrorPageBody(body)
		out = append(out, httpRoute{
			Match: []matcherSet{{
				Host:       hosts,
				Expression: fmt.Sprintf("{http.error.status_code} == %d", code),
			}},
			Handle: []map[string]any{
				{
					"handler":     "static_response",
					"status_code": fmt.Sprintf("%d", code),
					"headers": map[string]any{
						"Content-Type": []string{"text/html; charset=utf-8"},
					},
					"body": clean,
				},
			},
		})
	}
	// Generic fallback (empty-body-400 class fix). MUST be last: Caddy
	// evaluates errors subroutes in order, so the per-code routes above
	// win for the 8 customizable codes, and any OTHER intercepted status
	// (400, 402, 405, 409, 501, ...) falls through to this catch-all
	// instead of finalizing as a bare empty-body response. No per-code
	// Expression → matches every error status for this host; the body
	// renders the live {http.error.status_code} placeholder so one page
	// serves them all. status_code echoes the dispatched error status so
	// the client still receives the upstream's real code, not a rewrite.
	out = append(out, httpRoute{
		Match: []matcherSet{{Host: hosts}},
		Handle: []map[string]any{
			{
				"handler":     "static_response",
				"status_code": "{http.error.status_code}",
				"headers": map[string]any{
					"Content-Type": []string{"text/html; charset=utf-8"},
				},
				"body": arenetGenericErrorPage,
			},
		},
	})
	return out
}

// buildErrorRoutesForServer aggregates the per-route error routes
// for every route in `routes` whose hosts belong on this server
// (HTTP vs HTTPS — TLS-enabled routes land on the HTTPS server).
// Returns the slice ready to plug into httpServer.Errors.Routes,
// or nil if no route has any error config (the caller omits the
// Errors field entirely to keep the emitted JSON tight for the
// no-feature case).
//
// tlsScope picks which routes contribute :
//   - true  → only routes with TLSEnabled (HTTPS server)
//   - false → only routes WITHOUT TLSEnabled (plain-HTTP server)
//
// The split mirrors how the primary routes are dispatched between
// servers (httpRoutes vs httpsRoutes) in buildConfigJSON.
func buildErrorRoutesForServer(routes []storage.Route, templates map[string]storage.ErrorPageTemplate, tlsScope bool, logger *slog.Logger) []httpRoute {
	var out []httpRoute
	for _, r := range routes {
		if r.TLSEnabled != tlsScope {
			continue
		}
		out = append(out, buildErrorRoutesForRoute(r, templates, logger)...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
