<!-- Arenet wiki — Forward auth (protecting backend apps with an IdP). AGPL-3.0. -->

# Forward auth

**🌐 English** · [Français](Forward-Auth-FR)

Forward auth puts your **identity provider in front of a backend application**, so visitors sign in before the app ever sees them. The app itself needs no OIDC support, no plugin, no change: Arenet asks the IdP about every request and only proxies the ones it approves.

> **Not the same thing as [OIDC SSO](OIDC-SSO).** That page is about signing in to *Arenet's own admin UI*. This page is about protecting *the applications behind Arenet*. They are independent — you can use either, both, or neither.

## When you need it

An application with no authentication of its own, or whose own login you would rather not expose: a metrics endpoint, a debug console, Sonarr, an internal dashboard, the editor half of n8n. Anything you would otherwise leave open and hope nobody finds.

## Step 1 — create the provider

**Settings → Forward auth → Add provider.** One provider is reusable across any number of routes.

| Field | What it is |
| ----- | ---------- |
| **Name** | Your label for it, lowercase letters, digits and dashes, up to 32 characters. **Immutable after creation** — to rename, delete and recreate. |
| **Kind** | `authelia`, `authentik`, `keycloak` or `generic`. It selects nothing magic; it records what you are talking to. |
| **Verify URL** | Where Arenet asks. The IdP's address *as Arenet reaches it*, so usually a private address or a container name — `http://authelia:9091`, `http://10.0.0.50:9000`. Not your public domain. |
| **Auth request URI** | The path on that host that answers the question. Must start with `/`. Per provider, see the table below. |
| **Copy headers** | Which headers the IdP's answer carries forward to your application — the identity it will read. Comma-separated. The form's default `Remote-User, Remote-Email` is **Authelia's** convention; Authentik sends `X-authentik-username`, `X-authentik-email`, `X-authentik-groups`, `X-authentik-name`, `X-authentik-uid` instead. Copy the names your application actually reads. |
| **Client secret** | Only if your provider requires one. Leave blank on edit to keep the stored value; it is never echoed back, by the API or the audit log. |
| **Auth passthrough prefix** | A path served by the IdP itself, under your application's domain, that must **skip** the gate. Without it the IdP's redirect to its own UI feeds back into the gate — an infinite loop or a 404. See Authentik below. |
| **Rewrite verify host** | Send the IdP's own hostname instead of your visitor's. Turn it on **when something between Arenet and the IdP routes by `Host`** — typically a reverse proxy in front of the IdP, such as Authentik behind Traefik or nginx. Leave it off when Arenet reaches the IdP directly. The IdP still identifies the application either way, from `X-Forwarded-Host`, which Arenet sends from the original request. |

### Values per provider

| Kind | Auth request URI | Passthrough prefix | Copy headers |
| ---- | ---------------- | ------------------ | ------------ |
| **Authelia** | `/api/authz/forward-auth` | — | `Remote-User, Remote-Email, Remote-Groups` |
| **Authentik** | `/outpost.goauthentik.io/auth/caddy` | `/outpost.goauthentik.io` | `X-authentik-username, X-authentik-email, X-authentik-groups` |
| **oauth2-proxy** (`generic`) | `/oauth2/auth` | `/oauth2` | `X-Auth-Request-User, X-Auth-Request-Email` |
| **Keycloak** | depends on your adapter | — | depends on your adapter |

**Rewrite verify host** is not in this table on purpose: it depends on your network, not on which IdP you run. Turn it on only when a reverse proxy sits between Arenet and the IdP and routes by `Host`.

**Authentik needs one more step that is easy to miss.** The `/outpost.goauthentik.io/...` endpoint is served by an **outpost**, not by the Authentik server on its own, so the provider has to be assigned to one: *Applications → Outposts → authentik Embedded Outpost → Edit*, and your provider must appear under **Selected**. Until it is, every request to that path answers **404** whatever else you configure — and the Authentik log says nothing, because as far as it is concerned the route does not exist.

## Step 2 — point a route at it

Open the route → **Authentication** → **Forward auth** → pick the provider.

That is the whole wiring. Every request to the route now goes through the IdP.

## Step 3 — check it

In a private window, open the route. You should land on your IdP's login page, and come back to the application after signing in. If you do not, see the pitfalls below.

## Narrower than a whole route

Two things you can do per path, in the route's **Paths & headers** section:

- **[Protect one path only](Routes#an-identity-provider-for-one-path-v257)** (v2.57) — leave the route itself open and gate `/metrics` alone.
- **[Exempt one path](Routes#exempting-one-path-from-the-routes-authentication-v258)** (v2.58) — gate the route, but let `/webhook/` through for services that will never hold a session. This is the only path rule that *removes* a protection, and it strips the identity headers so a caller cannot forge one.

Together they cover the n8n case: the editor behind the IdP, `/webhook/`, `/form/` and the OAuth callback exempted.

## Common pitfalls

### Infinite redirect loop, or a 404 on the IdP's own path

The IdP serves part of itself under your application's domain and that part is being gated too. Fill in **Auth passthrough prefix** (`/outpost.goauthentik.io` for Authentik, `/oauth2` for oauth2-proxy). Arenet then proxies that subtree straight to the Verify URL's host, with no gate — carrying the same `Host` as the auth check, so a reverse proxy fronting the IdP routes both the same way (v2.58.1; before that the passthrough ignored **Rewrite verify host**, and such a setup had a working gate and a broken sign-in).

### Authentik answers 404 to the check

If the reply is **404**: the provider is probably not assigned to an outpost — see the Authentik note above. If it is **500** with `failed to detect a forward URL` in the Authentik log, the outpost did not receive the `X-Forwarded-*` headers; Arenet sends them, so suspect something between Arenet and the IdP stripping them. If a reverse proxy in front of the IdP answers 404 instead, turn **Rewrite verify host** on.

### The application does not know who the visitor is

It reads a header you are not copying. Add it to **Copy headers** — and check which name your application actually expects; `Remote-User` is a convention, not a standard.

### A login form inside the application stops working

Forward auth answers the browser's background requests with a redirect to the IdP, which an application expecting JSON cannot follow. Do not put an IdP in front of a path whose application authenticates its own users; protect what has no gate of its own.

### The route answers 503 after you delete a provider

Deliberate. A route whose provider is gone becomes unavailable rather than being served unprotected, and the 503 names the missing provider. Recreate it, or change the route's authentication.

## API reference

```
GET    /api/v1/settings/forward-auth/providers
POST   /api/v1/settings/forward-auth/providers
GET    /api/v1/settings/forward-auth/providers/{name}
PUT    /api/v1/settings/forward-auth/providers/{name}
DELETE /api/v1/settings/forward-auth/providers/{name}
```

`DELETE` is refused with **409** while a route still references the provider, and the response body names the routes to fix — the reference is checked, not assumed. The client secret is never returned by any of these.

## See also

- [Routes](Routes) — per-path rules, including protecting and exempting single paths
- [OIDC SSO](OIDC-SSO) — signing in to Arenet's own admin UI, a different thing
