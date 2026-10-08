<!-- Arenet — implementation plan. AGPL-3.0-or-later. See LICENSE. -->

# Plan — maintenance bypass serves the real route

Spec: `docs/superpowers/specs/2026-10-08-maintenance-bypass-serves-the-real-route-design.md`
Target: **v2.70.0**

## The control-flow decision the spec left open

The spec's D3 says "post-process the window of routes this iteration
appended". Writing it revealed that `buildConfigJSON`'s per-route loop
body has **more than one exit**, so a post-processing step placed at the
end of the body would be skipped on the others.

Exits a maintenance route can take, read off the code:

| Exit | Site | Reached when |
| --- | --- | --- |
| forward-auth deny `continue` | `manager.go:1834` | `AuthMode == forward_auth` and the named provider no longer resolves |
| end of body | after the cert-registration tail | everything else |

(The `continue`s at `manager.go:1826`/`:1830` belong to the inner
`for _, h := range denyHosts` loop, not the route loop. Checked, not
assumed — they are indented one level deeper.)

**Decision: open the window at the top of the iteration, close it
explicitly at both exits, and fail loudly if one is ever left open.**

Rejected alternatives, and why:

- *Wrap the body in a closure so one `defer` covers every exit.* A
  mechanical `continue` → `return nil` transformation over a ~400-line
  body, where several `return nil, fmt.Errorf(...)` must still
  propagate out of `buildConfigJSON`. The blast radius is the whole
  function, against a constraint that says do not break anything.
- *Match routes by host set after the loop instead of by index.*
  Indirect: it infers which routes belong to a route instead of knowing.
  Host uniqueness is enforced elsewhere, so it would probably work,
  which is exactly the property that makes it a bad guard.
- *Process windows after the loop.* The window's END index is only
  knowable at the exit, so this does not remove the two call sites, it
  just moves the bookkeeping further from them.

The loud failure is the part that makes two call sites acceptable: a
third exit added in two years' time becomes a build-time-visible error
rather than a maintenance route that silently stops serving its 503.

## A second decision writing T4 forced — D10

Under `TLSEnabled && RedirectToHTTPS`, the two listeners do not receive
the same thing. The emitter puts `buildRedirectRoute` (a 301 to https)
on the HTTP listener and the real route on the HTTPS one, for a
maintenance route exactly as for any other.

So on the HTTP listener the window contains a **hop**, not the route.
Gating a hop behind the bypass list is meaningless, and appending a 503
beside it would change what a non-bypassed HTTP visitor sees today:
currently a 301 to https and then the 503 there, which would become a
503 straight over plain HTTP.

That second shape is arguably nicer — one round trip, and a maintenance
notice needs no TLS to be read — but it is a behaviour change on a path
that is not the bug, against a constraint that says do not break
anything.

**D10: when `TLSEnabled && RedirectToHTTPS`, the HTTP listener is left
exactly as it is today — window ungated, no 503 appended. All gating
happens on the HTTPS listener, where the real route actually lives.**
The window records the condition (`httpCarriesRedirectOnly`) from the
same expression the emitter branches on, so the two cannot drift.

## Tasks

### T1 — the non-regression instrument *(done, commit `4f4ec3f`)*

`gatedRoutes()` + `testdata/gated_emission_golden.json`, captured from
unmodified code. Covers every shape the maintenance branch skips.
Nothing below may change these bytes.

### T2 — `matcherSet.ClientIP`

Add to the struct in `manager.go`:

```go
// ClientIP (v2.70.0) — Caddy's client_ip matcher, as a matcher SET
// member so it ANDs with Host. omitempty keeps every route that does
// not set it byte-identical, same contract as Path and Expression.
ClientIP *clientIPMatcher `json:"client_ip,omitempty"`
```

with `type clientIPMatcher struct { Ranges []string `json:"ranges"` }`.

Gate: `go test ./internal/caddymgr/` — both goldens still pass. A new
pointer field with `omitempty` must move zero bytes.

### T3 — split the maintenance half out of the shared branch

`manager.go:1551` currently reads
`if (r.MaintenanceConfig != nil || r.RedirectConfig != nil) && !r.Disabled`.
Narrow it to `RedirectConfig` only (spec D9). The maintenance route then
falls through into the normal assembly.

At this point the build is deliberately WRONG — a maintenance route
serves its real content to everyone. T4 makes it right. Do not ship T3
alone; squash T3+T4+T5 or keep them on one branch.

Gate: both goldens pass (neither fixture has a redirect or a
maintenance route, so this must be a no-op for them).

### T4 — open, close and apply the window

A small struct and three helpers next to `buildMaintenanceRoute`'s
remains in `maintenance.go`:

- `openMaintenanceWindow(r, httpLen, httpsLen) *maintenanceWindow` —
  nil when `r.MaintenanceConfig == nil`, so every other route pays one
  nil check.
- `closeMaintenanceWindow(w, httpRoutes, httpsRoutes, …) (http, https
  []httpRoute)` — adds the `client_ip` matcher to every route in the
  window, or **drops** them when `BypassIPs` is empty (spec D5), then
  appends the catch-all 503 route.
- the 503 route itself, which is what is left of
  `buildMaintenanceRoute` once the subroute shape goes: metrics handler
  first (spec D7), then the `static_response`.

Call `closeMaintenanceWindow` at `manager.go:1834` (before the
`continue`) and at the end of the body. After the loop:

```go
if openWindow != nil {
    return nil, fmt.Errorf("internal: maintenance window for route %s "+
        "left open — a new exit path from the route loop must close it", openWindow.routeID)
}
```

Gate: both goldens pass. Then G3–G6.

### T5 — delete `buildMaintenanceRoute` and its subroute shape

Its two inner routes become two sibling top-level routes, so the
function has no caller. Its tests move to the new shape:
`TestBuildConfigJSON_MaintenanceRoute` and `..._NoBypass`
(`maintenance_test.go:44`, `:97`) assert `static_response` 503,
`Retry-After` and `client_ip` vs `remote_ip` — all still true, at a
different nesting depth.

`buildMaintenanceBody`, `resolveMaintenancePage`,
`formatRetryAfterHuman` and all four sentinels are untouched: the body
is identical, only where the route carrying it sits changes.

### T6 — the gates

| Gate | Assertion |
| --- | --- |
| G3 | maintenance + bypass + a `PathRule` with its own pool → that pool is emitted, inside the route carrying the `client_ip` matcher. The operator's 404, asserted. |
| G4 | same fixture with `RequestHeaders`/`ResponseHeaders` → the `headers` handler is in the bypassed chain. |
| G5 | a host-only catch-all route serving 503 + `Retry-After`, declared AFTER the bypassed route. Order matters: Caddy dispatches in declaration order, so a 503 declared first would swallow the bypass. |
| G6 | `BypassIPs` empty → **no** emitted route proxies this host. Security, not cosmetics: a leak here exposes a backend the operator believes is closed. |
| G7 | extend `TestBuildConfigJSON_LoadsCleanly`'s fixture with a maintenance route carrying a bypass, path rules and headers, and keep `..._HandlersAllResolvable` green. A `client_ip` nested in a matcher set beside `host` is a shape this codebase has never emitted — validate it against real Caddy rather than reasoning about it. |
| G8 | each of G3–G6 run with its own fix reverted, and seen to fail. |

### T7 — docs

`docs/wiki-seed/Routes.md` + `-FR.md` describe the bypass. They must say
what it now serves, because the old behaviour was the surprise the
operator hit. No tombstone: describe what it does, not what it used to
do.

## Review checklist

- `git diff --stat` shows **no** change under `testdata/`.
- `go test -race -count=1 ./...` green.
- `caddy.Validate` passes on the new shape (G7).
- Every G3–G6 guard seen to fail with its fix reverted (G8).
