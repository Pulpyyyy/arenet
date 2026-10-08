# Custom Error Pages

Out of the box, Arenet serves **branded error pages** for the 8 standard HTTP error codes : 401, 403, 404, 429, 500, 502, 503, 504. The default templates are minimal dark-themed pages with the request method/URI/UUID + a "powered by Arenet" footer.

You can override these with your own HTML per-template or per-route. Step R (Phase 2).

---

## Three layers of resolution

When Caddy needs to serve an error page for a status code, it walks the resolution stack in order :

1. **Route override** — if the route has a per-status-code override (Route.ErrorPageOverrides), use that
2. **Template** — if the route has a template attached (Route.ErrorPageTemplateID), use the template's body for this status code
3. **Built-in default** — Arenet branded fallback

The first non-empty match wins.

---

## Built-in default

The built-in default lives in `internal/caddymgr/error_pages.go` as `arenetDefaultErrorPages` — a Go-level map of `int → HTML string`. To "modify the default" you'd edit the Go source and rebuild the binary. Most operators won't need to ; **prefer the template path below** for any customization.

---

## Templates (operator-friendly path)

A **template** is a named collection of HTML bodies, one per status code. You create N templates, attach each to N routes.

### Create a template

1. Sidebar → **Settings** → **Pages d'erreur** (`/settings/error-pages`)
2. Click **+ Nouveau template**
3. **Nom** : e.g. `homelab-branded`
4. **Description** (optional)
5. For each of the 8 status code tabs (401/403/404/429/500/502/503/504), fill the HTML body in the CodeMirror editor on the left
6. The **Preview** iframe on the right shows the rendered output with mock data
7. The **Variables Caddy disponibles** section lists every placeholder you can use ; click to insert at cursor
8. Click **Enregistrer**

### Attach a template to a route

1. Sidebar → **Routes** → edit the route → **Pages d'erreur** section
2. **Template** dropdown : pick `homelab-branded`
3. Optionally, fill **per-status overrides** for any code you want to override the template's body
4. Save

Within 5s the route serves your template's HTML on the matched status codes.

---

## Caddy placeholders

Inside the HTML body, you can use Caddy placeholders that expand at serve time :

| Placeholder | Expands to |
| ----------- | ---------- |
| `{http.request.method}` | GET / POST / etc. |
| `{http.request.uri}` | The requested URI |
| `{http.request.host}` | The Host header value |
| `{http.request.uuid}` | A per-request UUID (useful for support tickets) |
| `{http.error.status_code}` | The status code being served |
| `{http.error.status_text}` | "Not Found" / "Internal Server Error" / etc. |
| `{http.error.message}` | Error message from the upstream handler if any |
| `{time.now.iso8601}` | Current ISO 8601 timestamp |
| `{time.now.year}` | Current year (for copyright lines) |

Example template body for 404 :

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>404 — homelab.example.com</title>
  <style>
    body { background:#0d1117; color:#c9d1d9; font-family:system-ui,sans-serif;
           min-height:100vh; display:flex; align-items:center; justify-content:center;
           margin:0; padding:24px; }
    .card { max-width:540px; text-align:center; }
    .code { font-size:96px; font-weight:600; color:#58a6ff; margin:0; }
    .meta { margin-top:32px; font-size:12px; color:#6e7681; }
  </style>
</head>
<body>
  <div class="card">
    <p class="code">404</p>
    <h1>This page doesn't exist on homelab.example.com</h1>
    <p>If you got here by following a link, please report it.</p>
    <div class="meta">
      Request ID : <code>{http.request.uuid}</code><br>
      Method+URI : <code>{http.request.method} {http.request.uri}</code><br>
      Timestamp : <code>{time.now.iso8601}</code>
    </div>
  </div>
</body>
</html>
```

The placeholders inside `<code>` blocks will render the live values per-request — useful for support : the user can paste the request UUID and you can grep `/logs` to find their exact request.

---

## HTML sanitization

Templates are passed through a sanitizer before persistence to prevent stored XSS in case multiple admins share the template editor :

- `<script>` tags stripped
- `on*` event handlers stripped
- Inline `style` attributes preserved (we need them for styling)
- Caddy placeholders preserved verbatim

The sanitizer is bluemonday with a custom policy ; see `internal/storage/error_template.go`.

---

## Per-route override (advanced)

If a single route needs a different body for one specific code (e.g. the registry route needs a 502 with Docker-specific guidance), use the per-status override :

1. Edit route → **Pages d'erreur**
2. **Template** : `homelab-branded` (or none)
3. **Status code overrides** : add `502` → paste the Docker-specific 502 body
4. Save

The override takes precedence over the template's 502 ; other codes still use the template.

---

## 1 MiB body cap

Each HTML body (template page OR per-route override) is capped at 1 MiB pre-sanitization. Sufficient for any reasonable HTML page (the built-in default is ~1.5 KiB). Inline images base64-encoded would push you near the cap ; prefer linking to images served by the route itself.

---

## Catch-all (host not configured)

When a request hits Arenet for a hostname that is **NOT** declared as primary or alias on any route, Arenet serves a 404 — the *catch-all* response.

By default that catch-all body is the Arenet built-in branded 404 page (same look as `arenetDefaultErrorPages[404]`, the one configured routes see on an upstream 404). Operators who want their own branding everywhere — including on unmatched hosts — can promote one of their templates as the catch-all default.

### Promote a template as the catch-all default

1. Sidebar → **Settings** → **Pages d'erreur**
2. Edit (or create) the template whose 404 body should be served on unmatched hosts
3. Tick the **Utiliser comme page catch-all par défaut** checkbox above the status-code tabs
4. **Enregistrer**

From that point the catch-all serves the **404 body of that template** (the other status codes of the template are ignored — the catch-all only ever responds with 404).

### Mutual exclusion

At most **one template** can carry the catch-all-default flag at any time. The storage layer enforces this in the same write transaction : ticking the box on Template B automatically clears it on Template A. No risk of two templates fighting for the catch-all slot ; the most recent Save wins.

### Behaviour matrix

| State | Catch-all body served |
| ----- | --------------------- |
| No template is flagged | Arenet built-in 404 (same as `arenetDefaultErrorPages[404]`) |
| One template is flagged + its `Pages[404]` is set | Operator-defined 404 body from that template |
| One template is flagged BUT its `Pages[404]` is empty | Falls back to Arenet built-in (catch-all never serves an empty body) |
| The flagged template is deleted | Flag goes with it ; catch-all reverts to built-in next reload |

### Why this matters

Without the flag the catch-all served plain text "Not Found - no route configured for this host" (pre-v2.9.10), which was inconsistent with the branded pages on configured routes. With the flag operators get end-to-end branding even on typo'd / scan / DNS-leak requests.

---

## "Inspect built-in default"

In the templates list page, the built-in default appears as a row marked **Built-in** (read-only). Click **Aperçu** to open the editor in read-only mode and inspect the default templates side-by-side ; click **Dupliquer** to create an editable copy as a starting point for your own template.

---

## Maintenance page

The **maintenance page** is a separate concept from the templates above : it's the **one global HTML page** served on `503` responses for any route an operator switches into [Maintenance state](Routes#route-states-active-maintenance-disabled) (v2.17.0). Unlike error-page templates (many, attachable per-route), there is only **one** maintenance page for the whole Arenet instance — every route in maintenance serves the same body.

### Customize it

1. Sidebar → **Settings** → **Error Pages** (`/settings/error-pages`)
2. Click the **Maintenance** tab (next to the templates list)
3. The editor opens with **Arenet Default (built-in)** — a branded "Back soon" dark-themed page — pre-loaded as a starting point. A **Built-in** badge marks it as such until you save a change.
4. Edit the HTML in the CodeMirror pane ; the **Preview** pane on the right renders it live
5. Click **Save**

An **empty** body is equivalent to not customizing it — Arenet serves the branded built-in default in that case.

### Maintenance message (per-route, with global fallback — v2.18.1)

The message shown on a maintenance page is **per-route** (set in each route's edit form, Maintenance section) with the **global message** as a shared fallback. Above the HTML editor here is the **global Maintenance message** field — the default shown on any route that doesn't set its own. Type "Database migration in progress, back around 14:00" once and it applies to every route without a specific message ; a route that needs a different notice sets its own in its edit form.

Resolution : **per-route message if set → else the global message → else nothing** (the built-in default then shows its generic sentence). The message is plain text : HTML-escaped and its line breaks turned into `<br>` at serve time, so it can't inject markup. **Reset to default** clears the global message too.

### Auto-refresh (v2.18.1)

The built-in default page carries a `<meta http-equiv="refresh">` built from the route's Retry-After (via the `{arenet.maintenance.refresh_meta}` placeholder), so a visitor's browser reloads itself when the window is expected to end. Retry-After `0` emits no meta (a `content="0"` would loop). Custom pages don't get it automatically: drop `{arenet.maintenance.refresh_meta}` in your own `<head>` and you get the same tag, with the same `0` guard.

### Maintenance placeholders

Unlike the `{http.request.*}` / `{time.*}` Caddy placeholders used in error-page templates, the maintenance page has these dedicated Arenet placeholders :

| Placeholder | Expands to |
| ----------- | ---------- |
| `{arenet.maintenance.retry_after_human}` | The **triggering route's** Retry-After **in words**: `1 day`, `30 minutes`, `1 hour 30 minutes`. Exact, never rounded. Empty when Retry-After is `0` — collapse the block that holds it with a `:has(:empty)` rule, as the shipped examples do. **English only**: the served page has no locale for Arenet to key off, so a page in another language either accepts that or writes its own fixed wording |
| `{arenet.maintenance.message}` | The route's message, or the global message as fallback (HTML-escaped, line breaks → `<br>`). Empty when neither is set |
| `{arenet.maintenance.refresh_meta}` | A `<meta http-equiv="refresh" content="N">` tag (N = Retry-After) ; empty when Retry-After is `0`. Present in the built-in default page's `<head>` — add it to a custom page if you want auto-refresh |

None is a Caddy runtime expression — all are baked into the response body at config-build time. `retry_after_human` and `refresh_meta` are per-route (each route shows *its own* value inside the otherwise-identical shared HTML) ; `message` resolves per-route-then-global. The `{http.request.*}` / `{time.*}` Caddy placeholders documented above also still work inside the maintenance page body (method, URI, request UUID, timestamp).

> **Note (security).** `{env.*}` and `{file.*}` Caddy placeholders are **neutralized** inside operator-supplied maintenance/error page bodies and the global message — they render as literal text instead of expanding — so an admin can't accidentally (or a compromised admin can't deliberately) leak a process-environment secret or an on-disk file into the public response.

### Example page to start from

A polished, ready-to-copy example maintenance page ships in the repo at [`docs/examples/maintenance-page-example-en.html`](https://github.com/barto95100/arenet/blob/main/docs/examples/maintenance-page-example-en.html) (a French version is at [`maintenance-page-example-fr.html`](https://github.com/barto95100/arenet/blob/main/docs/examples/maintenance-page-example-fr.html)). It's a dark, animated page that uses **only** the placeholders Arenet actually substitutes — `{arenet.maintenance.refresh_meta}` in `<head>` (auto-refresh), `{arenet.maintenance.message}` (collapses cleanly when empty, via a `.message:empty` rule), `{arenet.maintenance.retry_after_human}`, and the `{http.request.*}` / `{time.now.year}` request vars. Copy its contents into the Maintenance editor and adapt the wording/branding. A regression test keeps it valid against sanitizer changes, so what you copy is always what Arenet will actually serve.

### Reset to default

Click **Reset to default** to clear the stored page back to empty — the next Save serves the branded built-in default again. This is the maintenance-page equivalent of deleting a custom template.

### Where it fits

- The maintenance page is **not** part of the 3-layer error-page resolution stack above — it only applies to routes in maintenance (`503` from the maintenance handler), not to upstream-originated errors or the catch-all.
- It goes through the same [HTML sanitization](#html-sanitization) pipeline as templates and per-route overrides before being persisted.
- See [Routes](Routes#maintenance-v2170) for how a route enters/exits maintenance and configures its Retry-After + bypass IP allow-list.

---

## Ready-made example templates

Arenet ships a set of **branded, drop-in example pages** — one polished dark-themed HTML page per supported status code (401, 403, 404, 429, 500, 502, 503, 504). They use only the placeholders Caddy substitutes at serve time, contain no JavaScript, and pass the sanitizer unchanged (verified). Use them as a starting point instead of writing a template from scratch.

### 📁 Get the files

All templates live in the repo, in both languages:

**➡️ [`docs/mocks/error-pages/`](https://github.com/barto95100/arenet/tree/main/docs/mocks/error-pages)** — browse the folder

| Status | English | French |
| ------ | ------- | ------ |
| 401 Unauthorized | [en/401.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/401.html) | [fr/401.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/401.html) |
| 403 Forbidden | [en/403.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/403.html) | [fr/403.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/403.html) |
| 404 Not Found | [en/404.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/404.html) | [fr/404.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/404.html) |
| 429 Too Many Requests | [en/429.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/429.html) | [fr/429.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/429.html) |
| 500 Internal Server Error | [en/500.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/500.html) | [fr/500.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/500.html) |
| 502 Bad Gateway | [en/502.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/502.html) | [fr/502.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/502.html) |
| 503 Service Unavailable | [en/503.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/503.html) | [fr/503.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/503.html) |
| 504 Gateway Timeout | [en/504.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/504.html) | [fr/504.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/504.html) |

There's also a visual catalog of all 8 pages: [en/error-pages-overview.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/error-pages-overview.html) · [fr/error-pages-overview.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/error-pages-overview.html) (open the raw file in a browser to preview it).

> Tip: on a file page, click the **Raw** button (or **Copy raw file**) to grab the full HTML, or **Download raw file** to save it.

### How to use one

1. Open the file for the status code you want (e.g. [en/404.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/404.html)) and copy its full HTML (use the **Raw** view).
2. Sidebar → **Settings** → **Error Pages** → **+ New template** (or edit an existing one).
3. Paste the HTML into the tab for that status code (the `404` tab for `404.html`, etc.).
4. Repeat for each code you want branded, then **Save**.
5. Attach the template to a route (see [Routes](Routes)), or tick **catch-all default** to brand un-routed hosts too.

The placeholders inside these pages (`{http.error.id}`, `{http.request.uuid}`, `{http.request.method}`, `{http.request.uri.path}`, `{http.request.host}`, `{http.request.remote.host}`, `{http.reverse_proxy.status_code}` on 502/503/504, and `{time.now.year}` in the footer) are filled in by Caddy at serve time — no extra configuration needed.

> These are **examples**, not the built-in defaults. Arenet's own built-in fallback pages (served when no template is configured) are the minimal ones defined in `internal/caddymgr/error_pages.go`. Copy an example into a template to opt into the richer branding.

---

## See also

- [Routes](Routes) — where to attach a template to a route ; [Route states](Routes#route-states-active-maintenance-disabled) for how a route enters Maintenance
- `internal/caddymgr/error_pages.go` — the built-in default + 3-layer resolution at serve time
- `internal/caddymgr/maintenance.go` — maintenance 503 handler, `client_ip` bypass, `{arenet.maintenance.*}` substitution
- `internal/storage/error_template.go` — sanitizer + storage layer
- `web/frontend/src/routes/settings/error-pages/+page.svelte` — the template editor UI + the Maintenance tab
- [Caddy placeholder reference](https://caddyserver.com/docs/conventions#placeholders) — full list of `{http.request.*}` and `{time.*}` placeholders
