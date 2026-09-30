# Routes

A **route** in Arenet maps an inbound `host` (FQDN) to one or more `upstreams` (backends). Every route also carries TLS, WAF, auth, rate-limit, country-block, and health-check configuration.

This page covers the route lifecycle : create, configure, alias, debug.

---

## Create your first route

1. Open the admin UI : `http://<your-host>:8001`
2. Sidebar → **Routes**
3. Click **+ Add route**
4. Fill in :
   - **Host** : the public hostname, e.g. `vault.example.com`
   - **Upstreams** : one or more backends. Click **+ Add upstream** to add. Format : `http://<lan-ip>:<port>` or `https://<host>:<port>` for HTTPS backends. Each upstream has a `weight` (used when LB policy is weighted-round-robin).
   - **LB Policy** : `round_robin` (default) or `weighted_round_robin`
   - **TLS** : check ✅ to enable HTTPS + auto-cert via ACME. Pick the **ACME challenge** : `http-01` (default, works for any domain pointing at your host) or `dns-01` (required for wildcard certs, needs DNS provider creds in Settings).
5. Click **Save**

Within ~5 seconds, Caddy reloads and the route is live :
- HTTP requests to `http://vault.example.com` redirect to `https://`
- HTTPS requests get an auto-issued Let's Encrypt cert (first request may take 5-15s while ACME completes)
- The request is reverse-proxied to your upstream

---

## The route form (v2.41)

A route carries a lot of settings, so the form groups them into **collapsible sections**. Only **Essentials** (host, aliases, upstreams, LB policy) is open when the panel opens; everything else is folded.

You do not have to open a section to know what is inside: each closed row shows a **one-line summary** of its current state — `WAF — OWASP CRS · 2 exclusions` with a `block` badge, `Country & IP filtering — 3 country/ASN blocked`, `Rate limit — no limit`. Sections that decide what happens to traffic also carry a **badge and a coloured left rail**, with the same code as the country-block sentence:

| Colour | Meaning |
|---|---|
| green | lets traffic through on a criterion (allow-list, authentication required) |
| red | blocks traffic (WAF in block mode, country block, IP deny-list) |
| amber | watches without blocking (WAF in detect mode) |
| grey | configured but inactive |

Sections that do not decide (TLS, health check, headers, error pages) stay neutral, so the colour keeps its meaning.

Inside a section, a setting with a few exclusive modes — WAF inspection, authentication, country filtering — is a **segmented control**: every mode stays visible, wears its colour, and the selected one prints what it does underneath (`Requests are inspected and logged, never blocked.`). On/off settings are switches carrying their own helper line, and one that removes a protection (**Disable the OWASP CRS**) is framed in red. Where several fields add up to one rule, the form states the rule: the rate limit reads `Beyond 60 requests per 1m from the same client IP, requests are refused with a 429.`

The panel header stays visible while you scroll and shows an **unsaved changes** marker as soon as you touch a field. Leaving with changes pending — Cancel, a click outside the panel, or picking another route — asks first; **Keep editing** puts you back where you were.

In the routes list, the **Security** column now shows everything that guards a route, not just the WAF: the WAF mode, a `Geo` chip when country filtering is on, an `IP` chip for the source-IP filter, and the rate limit as `60/1m`. Green lets through on a criterion, red blocks; hover a chip for the counts.

---

## Import a Caddyfile (v2.40)

Coming from plain Caddy? **Routes → Import a Caddyfile** reads your file with Caddy's own parser and turns each site block into a route.

1. Paste the Caddyfile (or drop the file) and click **Analyse**. Nothing is written yet.
2. The preview lists one line per site block: the host and its aliases, the upstreams, badges (HTTP, path rules, **already exists**) and, folded, everything that could not be translated — each with its line number.
3. Tick what you want and click **Import**. Caddy is reloaded once; if it refuses the result, every imported route is removed and the call fails, so you never end up half-imported.

What is imported:

| Caddyfile | Route |
|---|---|
| the block's addresses | host + aliases; `http://` → TLS off |
| `reverse_proxy` | upstreams, `lb_policy`, `health_uri` / `health_interval` / `health_timeout` / `health_status`, `header_up` / `header_down`, `transport http { tls_insecure_skip_verify }` |
| `reverse_proxy /path/*`, `handle_path`, `handle`, `route` with a `reverse_proxy` | a path rule with its own upstreams |
| `tls <email>` or nothing | ACME HTTP-01 |
| `tls { dns … }` | ACME DNS-01 (configure the provider in Arenet — credentials are never imported) |
| `encode`, `log` | ignored silently (Arenet handles them) |

What is reported instead of guessed: `basic_auth` (Caddy stores a bcrypt hash, set the password again), `tls internal` and explicit certificates (upload them in Certificates), `file_server`, `php_fastcgi`, `redir`, `respond`, `rewrite`, named matchers, unix-socket and placeholder upstreams, ports other than 80/443, global options and named routes.

A block with no `reverse_proxy` cannot be imported; it is listed with the reason.

Two safety rules: a host already served by a route is **skipped** unless you tick **replace** (which overwrites that route — its WAF, geo and rate-limit settings are lost), and imported routes start with **WAF in detect mode** so you see what the CRS would block before enforcing.

---

## Anatomy of a route

Every route stores the following fields (BoltDB `routes` bucket) :

| Field | Default | Purpose |
| ----- | ------- | ------- |
| `host` | — (required) | Primary FQDN matcher |
| `aliases` | `[]` | Additional FQDNs that match the same route |
| `upstreams[]` | — (required) | Backend pool (`url` + `weight`) |
| `lbPolicy` | `round_robin` | Load balancing policy |
| `tlsEnabled` | `false` | Auto-HTTPS via ACME |
| `redirectToHttps` | `false` | If TLS, force HTTP→HTTPS redirect |
| `acmeChallenge` | `http-01` | `http-01` / `dns-01` / `inherited` (from managed apex) |
| `useDedicatedCert` | `false` | Force a per-route cert vs the wildcard apex cert |
| `insecureSkipVerify` | `false` | Trust self-signed upstream certs |
| `uploadStreamingMode` | `false` | Don't buffer upload bodies (large file PUT, registry push) |
| `requestHeaders` | `{}` | Extra headers forwarded to upstream |
| `responseHeaders` | `{}` | Extra headers added to client response |
| `wafMode` | `off` | `off` / `detect` / `block` ([see WAF](WAF)) |
| `wafDisableCRS` | `false` | Don't load OWASP CRS on this route |
| `wafExcludeRules[]` | `[]` | CRS rule IDs to exclude |
| `wafExcludeTags[]` | `[]` | CRS tag families to exclude |
| `authMode` | `none` | `none` / `basic` / `forward` ([see OIDC-SSO](OIDC-SSO)) |
| `countryBlock` | `{mode:off}` | GeoIP allow/deny list |
| `rateLimit` | `null` | Per-route throttle |
| `healthCheck` | `{enabled:false}` | Active health checks (URI + status + body regex) |
| `errorPageTemplateId` | `""` | Custom error pages template |
| `errorPageOverrides` | `{}` | Per-status-code HTML overrides |

The full schema lives in `internal/storage/routes.go`.

---

## Aliases : one route, multiple hostnames

Use aliases when you have several FQDNs that should hit the same backend with the same config (WAF, auth, TLS).

Example : a single Traefik backend behind Arenet that serves 20 *arr-stack apps :
- **Host** : `traefik.example.com`
- **Aliases** : `sonarr.example.com`, `radarr.example.com`, `prowlarr.example.com`, ...

Caddy auto-acquires SAN certs covering all aliases. The `/topology` dashboard groups them visually as one container with N alias nodes.

---

## Wildcard certificates

For a route like `*.example.com`, you need a **managed apex** :

1. Sidebar → **Certificates** (`/certs`)
2. **Wildcard policies per apex** section → **+ Wildcard apex**
3. Apex : `example.com`
4. DNS provider : OVH (more providers planned) — paste your API keys
5. Save

Routes whose host falls under `*.example.com` (e.g. `vault.example.com`, `cloud.example.com`) will inherit the wildcard cert automatically. Set their `acmeChallenge` to `inherited` for explicit declaration, or leave default and Caddy will pick the wildcard cert via SNI matching at handshake.

---

## Cert Source (ACME / Internal / Manual)

When TLS is enabled, the route's **Cert Source** picker decides where its certificate comes from:

- **ACME** (default) — Caddy auto-issues and auto-renews a Let's Encrypt cert via the `http-01` or `dns-01` challenge. This is the behaviour described above; a route created before v2.19.0 keeps it with no migration.
- **Internal** — Caddy serves a self-signed cert from its internal CA (handy for a purely-internal host where you don't want ACME).
- **Manual (v2.19.0)** — the route serves an **external certificate you uploaded** (from a non-ACME CA, corporate PKI, etc.), with **no** ACME issuance for that host. Pick **Cert Source = Manual**, then choose the uploaded cert; only certs whose SAN covers the route host are offered (exact or one-label wildcard, RFC 6125). Renewal is **manual** — see [Certificates → External / uploaded certificates](Certificates#external--uploaded-certificates-v2190).

---

## Health checks

Active health checks monitor each upstream and remove unhealthy ones from the pool. To enable :

1. Edit a route → **Health check** section
2. **Enabled** ✅
3. **URI** : the path Caddy will GET on the upstream, e.g. `/healthz` or `/api/health`
4. **Method** : default `GET`
5. **Interval** : default `30s`
6. **Timeout** : default `5s` (must be `<` interval)
7. **Expected status** : default `0` = "any 2xx is OK". Since **v2.55** you may also give a **class**, `1` to `5` — `3` accepts every 3xx, which is what an app that redirects to a login page needs. Any other value is a single code, e.g. `200`.
8. **Expected body** (regex) : optional, e.g. `^\\{"status":"ok"\\}` for JSON healthz
9. **Passes** : consecutive checks needed to mark healthy (default `1`)
10. **Fails** : consecutive checks needed to mark unhealthy (default `1`)
11. **Probe Host** (optional, v2.55) : the `Host` the probe sends. Empty means the route's own host.
12. **Probe headers** (optional, v2.55) : extra headers, e.g. an `Authorization` the health endpoint requires. `Host` is not accepted here — it has its own field.

Unhealthy upstreams are skipped by the load balancer ; the `/topology` dashboard shows them in dimmed state.

### The Host the probe sends (changed in v2.55)

Caddy builds the health-check request from the upstream's **dial address**, so before v2.55 the probe asked for `Host: 10.0.0.2:80`. A backend that dispatches on `Host` — a second reverse proxy, a vhost, a container router — has no such virtual host, answers **404**, and every upstream is marked down while serving its route perfectly.

From v2.55 the probe carries the **route's own host** by default, so it looks to the backend like the traffic it stands in for. Set **Probe Host** when the backend expects a different name.

> **This changes behaviour for health checks configured before v2.55.** Their probe now sends the route host instead of the dial address. A backend that was answering the old probe on its IP and does *not* serve the route's hostname would start failing — set **Probe Host** to the name it does serve.

The **Test** button beside each upstream uses the same Host, so what it reports is what the health check will see. It marks a 2xx or 3xx answer with `✓` and a 4xx or 5xx with `⚠` : the probe reaching the upstream and the upstream answering usefully are two different facts.

Since **v2.56** the probe refuses two kinds of address, checked on the IP it resolves to rather than on the name: the **link-local** range (`169.254.0.0/16`, `fe80::/10`) and AWS's IPv6 metadata address (`fd00:ec2::254`). That is where a cloud provider's instance metadata answers, handing out instance credentials to anything asking from the instance, and a Test button is no business of it. Private space and loopback stay allowed, because that is where a homelab's upstreams actually are: `10/8`, `172.16/12`, `192.168/16`, `127.0.0.1`. Every probe is now recorded in the audit log, refusals included.

---

## Source IP filter (v2.21.0)

Restrict a whole route to — or block it from — specific source IPs, in the route's **Source IP filter** section:

| Mode | Effect |
| ---- | ------ |
| **Off** | No filtering (default) |
| **Allow-list** | Only the listed IPs / CIDRs get through ; everyone else gets **403** |
| **Deny-list** | The listed IPs / CIDRs get **403** ; everyone else passes |

One IP or CIDR per line (`192.168.1.10`, `10.0.0.0/8`, IPv6 too). Blocked visitors get the route's branded **403** error page.

> **Which IP is checked?** The **direct TCP peer** — `X-Forwarded-For` is ignored, so a client can't spoof its way past an allow-list. The flip side: if Arenet sits behind another proxy / CDN / load balancer, the filter sees that proxy's IP, not the visitor's.

---

## Path rules (v2.21.0 → v2.23.0)

**Path rules** apply extra protection — and optionally a different backend — to a URL sub-path of a route, without creating a second route. Typical: basic-auth on `/docs` (Swagger), `/metrics` reachable from one monitoring IP only, `/api/v1` sent to another backend, the rest of the site unchanged.

In the route form → **Path rules** → **Add path rule**:

| Field | Meaning |
| ----- | ------- |
| **Path prefix** | `/docs` matches `/docs` **and everything under it** (`/docs/…`). Prefix only — no regex. |
| **Basic auth override** | Username + password required for this path only. |
| **Scoped IP filter** | Allow-list / deny-list for this path only (same rules as the route-level filter above). |
| **Specific upstream (optional)** | Send this path to its own backend pool instead of the route's : URLs + weights, load-balancing policy, active health-check, and *Skip TLS verification* for a self-signed HTTPS backend (v2.23.0 / v2.23.1). Leave empty to follow the route's upstream. |

A rule needs at least one of: basic auth, an active IP filter, or a specific upstream (a rule with only an upstream is pure routing).

**How rules combine**

- **Additive**: a path keeps every protection of the route (WAF, country block, CrowdSec, route-level auth…) and **adds** its own. A path rule can never switch off a protection of the route.
- **Longest prefix wins**: with `/api` and `/api/admin`, a request to `/api/admin/users` uses the `/api/admin` rule. You never order rules by hand.
- **Transport per pool**: a path's pool may be HTTP while the route's is HTTPS (or the reverse); all backends inside one pool must share the same scheme.

The **Topology** page shows a route's path pools as sections inside its backend cluster (see [Topology](Topology)).

Not available per path yet: forward-auth, WAF on/off, rate limit, country block, headers.

---

## Route states (Active / Maintenance / Redirect / Disabled)

Every route has a **3-state lifecycle control**, shown as an icon-only segmented control on the `/routes` list — play (▶, green) = **Active**, wrench (🔧, amber) = **Maintenance**, power (⏻, red) = **Disabled**. Hover any segment for a tooltip with its name ; click a segment to switch state.

| State | Traffic | TLS / `:443` | Config |
| ----- | ------- | ------------- | ------ |
| **Active** | Normal reverse-proxy to the upstream pool | Kept if `tlsEnabled` | — |
| **Maintenance** | 503 + branded maintenance page + `Retry-After` header to everyone, except bypass IPs which reach the real upstream | **Kept** — host/TLS stay served | Upstreams/WAF/etc. untouched, just wrapped |
| **Disabled** | Route removed from Caddy entirely ; the host falls through to the catch-all (404) | Dropped ; disabling the **last** active HTTPS route removes the `:443` listener (a confirm dialog warns you first) | **Preserved** for one-click re-enable |

If a route somehow carries both a `disabled` flag and a `maintenanceConfig` at once, **Disabled wins** — it's the stronger "serves no traffic at all" state. Priority : **Disabled → 404** (wins) > **Maintenance → 503** > **Active**.

### Disabled (v2.15.0)

Disabling a route is for **maintenance windows where you don't want the app reachable at all**, or for parking a route you don't want to delete (its host/upstreams/TLS/WAF/aliases config is preserved in BoltDB — nothing is lost). A disabled route is filtered out before the Caddy config is built, so:

- The host stops resolving through Arenet — a request for it hits the **catch-all** (404, see [Custom Error Pages](Custom-Error-Pages#catch-all-host-not-configured)).
- If it was the **last route with `tlsEnabled` + active**, disabling it also removes the `:443` HTTPS listener — any other HTTPS URL served by Arenet will fail with connection refused until you re-enable a route or add a new HTTPS one. The UI detects this case and shows a dedicated warning dialog ("Disable the last HTTPS route?") before you confirm.
- Re-enabling is one click (or `POST /routes/{id}/enable`) — same upstreams, TLS, WAF, everything comes back exactly as configured.

### Maintenance (v2.17.0)

Maintenance mode is for **"I need to take the app down for a bit, but I still want to hit it myself to verify"**. Unlike Disabled, the route **stays served** — Caddy keeps the host + TLS cert alive — but every request gets:

- **HTTP 503**
- The **global maintenance page** (customized in Settings → Error Pages → Maintenance tab, see [Custom Error Pages](Custom-Error-Pages#maintenance-page))
- A **`Retry-After`** header (seconds, configurable per route)

...**except** requests from IPs/CIDRs on the route's **bypass allow-list**, which are forwarded straight to the real upstream as if the route were Active. This lets you validate the app is actually back up before flipping everyone else over.

Configure maintenance in the route's **edit form**, in the **Maintenance** section (shown for every route, not just ones currently in maintenance, so you can pre-fill it before switching the state control):

- **Retry-After** — pick a **number + unit** (seconds / minutes / hours / days) instead of hand-converting to seconds. The value is sent as the `Retry-After` response header (always in seconds, per RFC 9110 — browsers and bots read seconds) and substituted into the maintenance page via the `{arenet.maintenance.retry_after}` placeholder. A `0` value omits the header. Defaults to `5 minutes` (300 s) the first time a route enters maintenance. _(The unit selector is UI sugar only — the stored/wire value is always seconds.)_
- **Bypass IPs / CIDRs** — a repeater of bare IPs (`10.0.0.5`) or CIDR ranges (`192.168.1.0/24`). Add as many as you need.

The bypass check matches the **real client IP** (Caddy's `client_ip` matcher), not the `X-Forwarded-For` header — so it can't be spoofed by a request header the way an `X-Forwarded-For` check could.

- **Maintenance message (v2.18.1)** — a **per-route** message, shown on this route's maintenance page via the `{arenet.maintenance.message}` placeholder. Leave it empty to fall back to the **global** message (**Settings → Error Pages → Maintenance tab**, above the HTML editor), which is the shared default for routes that don't set their own. The message is plain text: HTML-escaped, line breaks → `<br>` at serve time (no markup injection), and `{env.*}` / `{file.*}` Caddy placeholders are neutralized so they can't leak secrets or file contents into the public 503.

**Resolution:** per-route message if set, else the global message, else nothing (the built-in default then shows its generic sentence).

**Auto-refresh (v2.18.1).** The built-in default maintenance page includes a `<meta http-equiv="refresh">` built from the route's Retry-After, so a visitor's browser reloads itself once the window is expected to end. When Retry-After is `0` no meta is emitted (a `content="0"` would reload instantly in a loop). This applies to the **built-in default page only** — a custom page can opt in by adding its own `<meta http-equiv="refresh" content="{arenet.maintenance.retry_after}">`. Note this is a *browser convenience* — the `Retry-After` **header** itself is advisory (bots/crawlers respect it; browsers do not auto-reload on it).

Toggling the state control to/from Maintenance is idempotent and immediate — entering maintenance again on an already-in-maintenance route keeps your existing Retry-After/bypass config (it doesn't reset to defaults) ; exiting clears the maintenance config back to nil, so the next time you enter maintenance it starts fresh from the default `300`s.

### API reference (state control)

```bash
# Disable / re-enable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/disable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/enable

# Enter / exit maintenance (config — retryAfter/bypassIps — is set via the normal PUT route update)
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance/off
```

All four endpoints are idempotent : disabling an already-disabled route, or entering maintenance on a route already in maintenance, returns `200` without error.

---

## Redirect one path (v2.44)

The case this exists for: an application that serves **nothing at its
root**. A mail server's webadmin under `/admin`, an API under `/api`.
Visiting the bare hostname gives a 404 that looks like Arenet's fault.

In **Path rules**, add a rule on `/`, turn on **Match this exact path
only**, turn on **Redirect this path**, and give it `/admin/login`.
Everything else on the route keeps being proxied.

**Why the exact mode is not optional here.** Path rules match a
sub-tree by default: a rule on `/` also covers `/admin/login`, so the
redirect would match its own target and the browser would bounce until
it gave up. Exact matching makes the rule cover `/` and nothing else.
Arenet refuses a target that its own rule would match, whichever mode
you picked.

**301 or 302.** 302 is the default and usually the right one: a
landing path is a convenience that an application update can change,
and a 301 is remembered by every visitor's browser — remarkably hard
to take back. Use 301 only for something you will not revisit.

**The target** can be a path on this host (`/admin/login`) or a full
URL elsewhere (`https://docs.example.com/`). A rule that only
redirects is a complete rule: it needs no authentication, no filter
and no upstream pool.

> **Paths are lowercase.** Caddy lowercases the request path before
> matching but never the pattern, so a rule written `/Admin` could
> never match anything — it would load without error and silently do
> nothing. Arenet refuses an uppercase path at save and tells you the
> lowercase form to use.

## Redirect a whole domain (v2.44)

A route in the **Redirect** state stops proxying and answers a 301 or a
302. This is the "I moved a domain" state: `old.example.com` sends
every visitor to `new.example.com`.

**Keep the visitor's path** (on by default) appends the original path
*and* query, so `/a/b?c=1` lands on the same `/a/b?c=1` at the target.
With it on, the target must carry no path of its own — appending to
`https://example.com/app` would silently produce `/app/a/b`, so Arenet
refuses it at save instead of emitting it.

**301 or 302.** 301 is permanent and is remembered by browsers and
search engines — right for a move you will not undo. 302 is temporary
and is not cached; use it while you are still unsure. 307 and 308,
which preserve the request method, are deliberately not offered: a
browser re-POSTing to another host is a different decision.

**The target must be a different host.** A target on this route's own
name — or on one of its aliases — matches the redirect that produced
it, so the browser bounces until it gives up. Arenet refuses it while
the form is still open rather than letting you find out from a browser.

> **To send one path elsewhere on the same host** — `/` to
> `/admin/login`, the shape a mail server's webadmin needs — a
> whole-host redirect cannot work, for exactly that reason. That is a
> path rule's job.

**What still applies:** TLS. A redirecting route terminates TLS to
answer at all, so it keeps its certificate and its renewals. **What
does not:** the WAF, authentication, the rate limit and country
blocking — the state replaces the proxy chain, exactly like
maintenance.

**On the list**, a redirecting route shows its state as a badge rather
than the three-way control: switching to a redirect needs a target, so
it happens in the form.

## Per-route security knobs (cheat sheet)

The most common configuration combinations :

### Public read-only website

```
TLS: ✅ enabled, http-01
WAF: detect mode (observe attacks, don't block legit users)
Rate limit: 60 req/min per remote IP
Country block: off
Auth: none
```

### Internal admin tool (Vault, Proxmox, Grafana)

```
TLS: ✅ enabled, dns-01 wildcard
WAF: off (or detect with attack-protocol excluded if backend is REST-noisy)
Rate limit: off
Country block: allow [FR, BE, CH] (your home countries)
Auth: forward (Authelia / Authentik) OR OIDC SSO at the route level
```

### Public API endpoint

```
TLS: ✅ enabled
WAF: block mode
Rate limit: 100 req/min per API key
Country block: deny [CN, RU, ...] or allow [your-customer-countries]
Auth: forward (your API gateway) or basic
```

### Webhook receiver (low-trust source)

```
TLS: ✅ enabled
WAF: block mode + paranoia level 2
Rate limit: 10 req/min per remote IP
Country block: allow only the webhook source's country
upload streaming mode: ✅ (large payloads ; skip WAF body buffering)
```

---

## Upstream error interception

When an upstream returns a 4xx or 5xx response, Arenet automatically replaces the upstream's raw body with the route's configured error page (see [Custom Error Pages](Custom-Error-Pages)). This keeps the visual experience consistent — operators see the Arenet-branded 404 instead of e.g. nginx's default 404.

### Auto-passthrough on auth challenges

Two status codes are **intentionally NOT intercepted** : **401 Unauthorized** and **407 Proxy Authentication Required**. The upstream's full response — including the `WWW-Authenticate` / `Proxy-Authenticate` header carrying the challenge — flows through to the client untouched.

This is required for any auth flow where the client retries with credentials after reading the challenge header. Replacing the body with a generic HTML 401 would strip the challenge header and break the negotiation entirely.

If you want a branded 401 page for one of YOUR auth gates (BasicAuth, ForwardAuth, OIDC at the Arenet layer), those still serve the branded body — they raise their 401 BEFORE the request reaches the upstream, so the auto-passthrough isn't on the path. Only upstream-originated 401/407 traverse the passthrough.

### Codes intercepted

`400, 402, 403, 404, 405, 406, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451` (4xx without 401+407) and `500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511` (full 5xx range).

For each intercepted code, Arenet returns its own response built from the route's error-page template, the per-route override, or the Arenet built-in default (in that priority order).

---

## Check after save (v2.35)

After every save, Arenet sends **one real request to the route through its own proxy** (to `127.0.0.1` with the route's host name, like a visitor):

| Result | Meaning | What happens |
| --- | --- | --- |
| **ok** | Caddy routed the request (any answer except 502 / 503 / 504 — a 401 or 404 from the app is fine) | nothing |
| **does not answer** | 502 / 503 / 504 (backend unreachable, timeout, no healthy upstream) | see below |
| **certificate being issued** | a new HTTPS route whose Let's Encrypt certificate is not ready yet | info message — not a failure |

When a route **does not answer**:

- **Modification** — Arenet puts the **previous version back** and checks it. If the previous version answered, **your change is undone** and the form explains why (typically a wrong upstream address or port). If the previous version did not answer either (the backend is simply down), your change is **kept** with a warning — undoing it would fix nothing.
- **Creation and re-activation** are **never undone** (you often create the route before starting the service): you get a warning only.
- Disabling, maintenance and deletion are not checked.

The check makes up to 3 attempts 2 s apart, so a save can take ~10 s when the route does not answer. Wildcard-only routes are not checked. Turn it off in **Settings → Route check after save**. Undone changes appear in the audit log as `route_update_rolled_back`.

---

## Hot-reload

Every route change applies in **< 5 seconds** without dropping in-flight connections. Caddy keeps the old config serving until the new one is fully provisioned, then swaps atomically.

If a config emit fails (e.g. malformed regex in `wafExcludeRules`), the API call returns 400 with the error, the route is NOT saved, and the live Caddy config is unchanged. Loud-fail.

---

## API reference

For automation (Ansible, Terraform, scripts), the same operations are available via REST :

```bash
# List
curl -b /tmp/jar http://localhost:8001/api/v1/routes

# Create
curl -b /tmp/jar -X POST -H "Content-Type: application/json" \
  -d '{"host":"vault.example.com","upstreams":[{"url":"http://192.168.1.50:8200","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true}' \
  http://localhost:8001/api/v1/routes

# Update
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{...}' http://localhost:8001/api/v1/routes/<route-id>

# Delete
curl -b /tmp/jar -X DELETE http://localhost:8001/api/v1/routes/<route-id>
```

Auth : the cookie jar (`/tmp/jar`) must hold a session from `/api/v1/auth/login` (Content-Type `application/json`, body `{"username","password"}`).

---

## See also

- [Topology](Topology) — visualize your routes as a live graph
- [WAF](WAF) — protect your routes against OWASP attacks
- [Custom Error Pages](Custom-Error-Pages) — brand the 4xx/5xx pages per route ; also covers the global [Maintenance page](Custom-Error-Pages#maintenance-page)
- [Rate Limit](Rate-Limit) — throttle abusive clients
- [Country Block](Country-Block) — geo-fence per route
- [OIDC SSO](OIDC-SSO) — single sign-on for admin tools
