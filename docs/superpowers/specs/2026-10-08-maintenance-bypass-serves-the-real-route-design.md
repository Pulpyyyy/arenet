<!-- Arenet — design spec. AGPL-3.0-or-later. See LICENSE. -->

# Maintenance bypass serves the real route

**Target version:** v2.70.0
**Status:** design locked, plan not written
**Reported:** 2026-10-08, operator dogfooding

## The report

> "depuis mon ip l'accès a la route avec mon ip en bypass c'est ok mais
> une prefix/header qui match une URI avec forward auth elle tombe en 404
> depuis mon ip"

A route in maintenance with the operator's IP in `BypassIPs`. The root
path works. A path rule with its own upstream pool and a forward-auth
gate answers 404 — and the 404 comes from the backend, not from Arenet.

## What is actually emitted today

`buildConfigJSON`'s per-route loop opens a branch at `manager.go:1551`
and `continue`s at `manager.go:1620`. Everything the loop assembles
after line 1620 therefore does not exist for a maintenance route. The
bypass inner route receives exactly `[]map[string]any{metricsHandler,
proxyHandler}` (`maintenance.go:274`), where `proxyHandler` was built
from `r.Upstreams` alone.

Dropped for the bypassed client:

| Config | Emission site | Consequence |
| --- | --- | --- |
| `PathRules` (whole slice) | `manager.go:1857`, `:1893` → `buildPathRulesSubroute` | no path matchers, no per-path pools, no per-path forward auth / basic auth / IP filter / redirect / rate limit |
| `RequestHeaders`, `ResponseHeaders` | `manager.go:1850` → `buildHeadersHandler` | custom headers absent, including on the root path |
| `IPFilter` (whole-domain) | `manager.go:1679` | gate absent |
| `RateLimit` | `manager.go:1656` | gate absent |
| `CountryBlock` | `manager.go:1671` | gate absent |
| CrowdSec | `manager.go:1733` | gate absent |
| `AuthMode` / `BasicAuth` / `ForwardAuth` | `manager.go:1740`–`:1805` | gate absent |
| WAF family | `manager.go:1848` | gate absent |

Kept, because they are built before line 1551 and travel inside
`proxyHandler`: the health check with its probe headers
(`reverse_proxy_emit.go:337`), and the hard-coded `Host:
{http.request.host}` preservation (`reverse_proxy_emit.go:257`).

The route's own matcher is host-only — `Match: []matcherSet{{Host:
allHosts}}` (`manager.go:1574`) — so every path on the host enters the
maintenance subroute regardless of its path rules.

## Why this is a defect and not a trade-off

The branch's comment justifies what it discards as "the whole normal
gate/proxy assembly below (auth, WAF, headers)". That enumerates
**gates**, and for gates the argument holds: an operator listing a
trusted IP to check their own site should not have to clear the WAF or
re-authenticate.

Path rules are not a gate. They are the route's routing topology, and
they are mentioned nowhere in that comment — which reads as collateral
rather than a decision. `RequestHeaders` / `ResponseHeaders` are named
in the comment, but they are not a gate either.

The feature's purpose decides it. A bypass IP exists so the operator can
verify a route **before reopening it**. It cannot do that job while it
serves a different route than the one that will go live. The operator hit
exactly that: it "worked" from their IP and proved nothing.

## Locked decisions

| # | Decision | Why |
| --- | --- | --- |
| D1 | **Semantics: "as if maintenance were off, for these IPs."** A bypassed client gets the route the loop would have emitted with no `MaintenanceConfig` — path rules, headers AND gates. | The only semantics an operator can predict. If the WAF or the IdP blocks them, that is information about the route they are about to reopen, not noise. "My route minus its protections" is a thing nobody asks for. |
| D2 | **Shape: two sibling top-level routes, not one subroute with two inner routes.** The route the normal assembly produced gains a `client_ip` matcher; a catch-all 503 route for the same hosts is appended after it. | Caddy ANDs matchers within a set and dispatches routes in declaration order, so `{host, client_ip}` then `{host}` is exactly "bypassed clients get the real route, everyone else gets the 503". It needs no change inside the assembly. |
| D3 | **Implementation: post-process the window of routes this iteration appended.** Record `len(httpRoutes)` / `len(httpsRoutes)` before the per-route body, then after it add the `client_ip` matcher to the routes in that window and append the 503. | Non-regression becomes true **by construction**: for a route with no `MaintenanceConfig` the post-processing is a no-op, so not one byte of its emitted JSON can move. A reviewer verifies a guard condition, not a 280-line chain. |
| D4 | **`matcherSet` gains `ClientIP *clientIPMatcher` with `omitempty`.** | Every route that does not set it serialises exactly as today. Same reasoning the `Path` and `Expression` fields already carry in that struct. |
| D5 | **Empty `BypassIPs` emits only the 503 route.** The real route is dropped from the window rather than emitted with an unsatisfiable matcher. | Today's behaviour is "everyone gets the 503", and an emitted-but-unreachable route is dead config Caddy still has to dispatch against. Byte-identity is NOT claimed for this case — the shape changes from a subroute to a single route — only the behaviour is. |
| D6 | **The forward-auth deny path needs no special case.** If the loop short-circuits to a deny route (`manager.go:~1803`), that route is in the window: it gets the `client_ip` matcher and the 503 follows it. | Falls out of D1. With maintenance off, an unresolvable provider denies; so a bypassed client is denied and everyone else gets the 503. A dedicated branch here is how the two paths drift. |
| D7 | **Metrics are counted exactly once per request.** The 503 route keeps `metricsHandler` first; the real route already starts its chain with it. `buildMaintenanceRoute`'s own prepending of `metricsHandler` disappears with the function. | The invariant that metrics stays first in every emitted chain (`manager.go` `handlers := []map[string]any{metricsHandler}`) is preserved, and a bypassed request must not be double-counted. |
| D8 | **The TLS-redirect tail keeps its current behaviour.** `TLSEnabled && RedirectToHTTPS` still puts `buildRedirectRoute` on the HTTP listener; the HTTPS listener carries the window plus the 503. | Unchanged from both the normal and the maintenance path today. A route in maintenance still has to be reachable on both listeners and still needs its certificate. |
| D9 | **Redirect state is untouched.** `RedirectConfig` keeps the existing early branch. | A redirect has no bypass and nothing to preview. Splitting the two states is also what lets the maintenance half move without touching the redirect half. |

## Non-goals

- **Changing what an unbypassed visitor sees.** The 503, its
  `Retry-After` header, its body and its auto-refresh stay exactly as
  v2.69.0 ships them.
- **A per-path or per-gate bypass granularity.** One allow-list per
  route, as today.
- **Making the bypass skip the gates.** Explicitly rejected in D1.
- **Touching `buildPathRulesSubroute`, `buildHeadersHandler` or any
  gate builder.** The whole point of D3 is that they are not involved.
- **Byte-identity for a maintenance route with no bypass.** See D5.

## Empirical validation gates

The operator's constraint is the first-class requirement: *"il ne faut
pas que tu casse le fonctionnement de arenet avec ou sans le mode
maintenance"*. These gates are how that gets proven rather than
promised.

1. **G1 — the existing golden fixture does not move.**
   `testdata/route_emission_golden.json` must match byte for byte;
   already asserted by
   `TestBuildReverseProxyHandler_RouteEmissionByteIdentical`
   (`reverse_proxy_emit_test.go:128`), which fails with "route emission
   changed — refactor is NOT byte-identical".

   **Its scope is much narrower than its size suggests, and the plan
   must not mistake it for coverage.** `representativeRoutes()` emits
   six routes: single upstream, weighted pool, https pool, skip-verify,
   health check, upload streaming. Every one carries `WAFMode: "off"`
   and **no** `PathRules`, **no** `RequestHeaders` / `ResponseHeaders`,
   **no** `IPFilter`, `RateLimit`, `CountryBlock`, auth or WAF. Verified
   by reading the fixture, and the file contains zero occurrences of
   `maintenance`, `Retry-After` or `client_ip`.

   So G1 proves the proxy-emission shapes are stable and says nothing
   about anything this change is near.

2. **G2 — a second golden covering what G1 does not.** This is the
   load-bearing gate for the operator's constraint, not a supplement to
   G1. Build a fixture that exercises path rules (with and without their
   own pool), `RequestHeaders` / `ResponseHeaders`, each gate, the auth
   passthrough route and the forward-auth deny path; capture
   `buildConfigJSON`'s output on `main` BEFORE any code change; commit
   it; assert byte equality after.

   Capturing it before the change is what makes it evidence. A golden
   written from the new code proves only that the new code agrees with
   itself.

   **Hazard: `go test -update` rewrites every golden in the package.**
   The flag is declared once (`reverse_proxy_emit_test.go:34`) and read
   by each golden test, so one invocation re-blesses all of them.
   Running it to make a red test go green would bless the regression as
   the new expectation, silently and permanently. The plan must state
   that neither golden is regenerated during this work, and a diff of
   `testdata/` is part of the review.

3. **G3 — the bypassed client reaches the path rule.** A route with
   `MaintenanceConfig{BypassIPs: [...]}` plus a `PathRule` carrying its
   own upstream pool must emit that pool, reachable behind the
   `client_ip` matcher. This is the operator's 404, asserted.

4. **G4 — the bypassed client gets the headers.** Same fixture with
   `RequestHeaders` / `ResponseHeaders`: the `headers` handler must
   appear in the bypassed route's chain.

5. **G5 — an unbypassed client still gets the 503.** Same fixture: a
   catch-all host-only route serving `static_response` 503 with
   `Retry-After`, declared AFTER the bypassed route.

6. **G6 — no bypass means no reachable proxy.** `BypassIPs` empty must
   emit no route that proxies this host. Guards the D5 drop against
   leaving the real route exposed during maintenance, which would be a
   security regression, not a cosmetic one.

7. **G7 — `caddy.Validate` on the emitted JSON.** Extend the existing
   `TestBuildConfigJSON_LoadsCleanly*` fixture with a maintenance route
   that has a bypass, path rules and headers, and keep
   `TestBuildConfigJSON_HandlersAllResolvable` passing. A `client_ip`
   matcher nested in a matcher set alongside `host` is a shape this
   codebase has not emitted before, so it gets validated against a real
   Caddy rather than assumed.

8. **G8 — fault injection on every new guard.** Each of G3–G6 is run
   with its own fix reverted, and must fail. Per
   `docs/ENGINEERING-PRACTICES.md`: a guard that has never failed has
   not been shown to guard anything.

## What the current tests cover

Nothing in either direction. The two maintenance emission tests
(`maintenance_test.go:44`, `:97`) assert only `static_response`,
`status_code: 503`, `Retry-After`, and `client_ip` vs `remote_ip`. The
path-rule emission tests (`path_rules_emit_test.go`,
`path_rules_upstream_emit_test.go`, `path_auth_exemption_test.go`,
`path_rate_limit_test.go`) contain no occurrence of "maintenance". The
canonical `TestBuildConfigJSON_LoadsCleanly` fixture includes a
maintenance route with a bypass CIDR and deliberately no path rules and
no headers.

So the behaviour this spec changes is currently unasserted, and so is
the behaviour it must preserve. G2 exists because of that second half.

## Open question for the plan

Whether the `client_ip` matcher should use Caddy's `client_ip` (which
honours trusted proxies) or `remote_ip`. `buildMaintenanceRoute` chose
`client_ip` and a test pins it against `remote_ip`
(`maintenance_test.go:87`). Keeping `client_ip` is the default; the plan
should state why in one line rather than inherit it silently, since the
matcher now gates access to the real backend rather than to a static
503.
