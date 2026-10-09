# OIDC SSO

**🌐 English** · [Français](OIDC-SSO-FR)

Arenet supports **OpenID Connect** single sign-on for admin login : delegate the authentication flow to your existing IdP (authentik, Keycloak, Authelia, Dex, Auth0, ...) instead of managing local username/password accounts in Arenet's BoltDB.

After OIDC is wired :
- Local admin accounts still work (break-glass, see below)
- The login page exposes a **"Sign in with SSO"** button
- Successful SSO matches the IdP identity against an allowlist → grants Arenet role (admin or viewer)
- All admin/viewer access flows through the IdP (centralize MFA, audit, account lifecycle)

---

## Prerequisites

- An OIDC IdP reachable from Arenet's outbound network
- An OAuth client registered on the IdP with :
  - **Client type** : confidential (Arenet has a client secret)
  - **Redirect URI** : `https://<your-arenet-host>/api/v1/auth/oidc/callback`
  - **Scopes** : `openid`, `email`, `profile`
  - **Response type** : `code` (authorization code flow)

The IdP must publish a valid OIDC discovery doc at `{issuer}/.well-known/openid-configuration` that returns the right `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`.

---

## Quick start

### 1. Get IdP details

From your IdP admin UI, note :
- **Issuer URL** — e.g. `https://auth.example.com/application/o/arenet/` (authentik) or `https://keycloak.example.com/realms/master` (Keycloak)
- **Client ID** — typically a UUID or a slug
- **Client Secret** — paste-once, store securely

### 2. Configure Arenet

1. Sidebar → **Settings** → **OIDC** section
2. **Enabled** ✅
3. **Issuer URL** : paste from step 1 (Arenet auto-strips `/.well-known/openid-configuration` if you paste the full discovery URL by accident)
4. **Client ID** + **Client Secret** : paste
5. **Scopes** : default `openid email profile` is fine
6. **Redirect URL** : `https://<your-arenet-host>/api/v1/auth/oidc/callback` (must match the IdP-side config)
7. **Kind** : pick `authentik` / `keycloak` / `authelia` / `generic` (just for UI label customization)
8. **Save**

On Save, Arenet immediately fetches the discovery doc to validate the config. If the fetch fails (unreachable IdP, wrong URL), the Save returns 400 with the error message — your config is NOT persisted.

### 3. Add identities to the allowlist

Once OIDC is wired, you need to tell Arenet which IdP identities can log in. Sidebar → **Users** → **+ Add OIDC identity** :

- **Email** : the identity's email as the IdP will send it in the `email` claim
- **Display name** : human-readable (optional)
- **Role** : `viewer` or `admin`

Save. The first time this user signs in via SSO, Arenet matches the email → creates a User row → grants the role.

### 4. Test the flow

1. Open `/login` in a private browser window
2. Click **Sign in with SSO**
3. You're redirected to the IdP login page
4. Authenticate
5. IdP redirects back to `/api/v1/auth/oidc/callback?state=...&code=...`
6. Arenet exchanges the code for tokens, validates the ID token signature + issuer + nonce + audience + email_verified
7. Allowlist match → session cookie set → you land on `/dashboard`

---

## RBAC : viewer vs admin

Two roles :

| Role | Can do |
| ---- | ------ |
| `viewer` | Read everything : dashboard, routes list, security events, audit log, cert events, alerts. Cannot mutate. |
| `admin` | Everything viewer can + create / edit / delete routes, users, OIDC config, alerting rules, backups, restore. |

The role is set per-allowlist-entry (Users page). Changing an entry's role requires a re-login (the role is baked into the session at login time).

**Last-admin safeguard** : Arenet prevents you from demoting the last local admin account (the break-glass). The API returns 400 ; the UI greys out the demote action. Always keep at least one local admin even when OIDC is wired. A second guard refuses to demote or delete the last human admin, local or OIDC (service accounts never count), so an instance can never be left with no admin at all.

---

## Accept-unverified-email opt-in

By default Arenet rejects logins where the IdP's `email_verified` claim is `false` — typical when a user signed up but never confirmed their email.

For some IdP setups (Keycloak with auto-confirm disabled, internal LDAP-sourced identities that don't have email validation), you may want to accept unverified emails.

1. Settings → OIDC → **Accept unverified email** ✅
2. Save

⚠️ This **relaxes a security check**. Only enable if your IdP's identity model doesn't need email verification (e.g. IdP-side identity is authoritative regardless).

---

## Common pitfalls

### Discovery fetch timeout (`context deadline exceeded`)

The IdP isn't reachable from the Arenet host. Common causes :

- **DNS** : Arenet host can't resolve the IdP FQDN. Fix : add to `/etc/hosts` or fix the resolver.
- **Hairpin NAT** : if the IdP FQDN points at your public IP and your router doesn't support NAT loopback, Arenet (sitting behind the same NAT) can't reach it. Fix : `/etc/hosts` override pointing at the IdP's LAN IP.
- **TLS handshake stall** : IdP cert expired, IdP server overloaded, MITM. Fix : `curl -v https://<idp>/.well-known/openid-configuration` from the Arenet host to confirm.
- **Outbound firewall** : Arenet daemon user can't egress :443. Fix : check `systemd` hardening, nftables.

Arenet enriches the log line with the issuer URL since v2.8.3 — `journalctl -u arenet | grep "discovery fetch failed"` shows exactly which URL timed out.

### `invalid_state` error in browser

The state cookie didn't survive the IdP round-trip. Common causes :

- **Different domains for Arenet UI and the callback** : the state cookie is set on Arenet's domain ; if the redirect_uri is on a different subdomain, the cookie isn't sent. Fix : ensure the redirect_uri matches the domain you're logging in from.
- **Cookie SameSite issue** : the IdP doesn't 302 back ; instead it form-POSTs (unusual). Fix : use a IdP-side setting to force GET-based redirect.
- **Long IdP login time exceeded cookie max-age** : Arenet's state cookie has a short lifetime. Fix : the operator just needs to retry the SSO flow.

### Authentik specifically : wrong issuer URL in discovery doc

If authentik is behind another proxy that doesn't preserve the Host header, authentik builds the discovery doc's `issuer` field from the upstream's host. Arenet then tries to validate the JWT's `iss` claim against the discovery doc's `issuer` → mismatch → token validation fails.

Fix : in authentik, **Applications → Providers → your provider → Issuer mode** :
- Each provider has a different issuer (recommended) — uses the application slug
- AND make sure the front proxy preserves the Host header (Arenet does this by default since v2.8.4 ; if your stack is `client → other RP → Arenet → authentik`, check the other RP)

---

## Sessions and the idle lock

- A session lasts **24 h** (30 days with *Remember me*), extended by activity.
- After **15 minutes without activity** the session is **locked**: the lock screen asks for your password again — or, for an OIDC account, to sign in again through your identity provider.
- **Activity = something you did** (a click or keystroke that reaches the server). Since **v2.32**, the requests the UI sends on its own — notification bell every minute, heartbeat, auto-refresh of Logs / Certificates / CrowdSec live — **no longer count**: an Arenet tab left open on an unattended computer locks after 15 minutes. Before v2.32 those requests kept the session awake indefinitely.

---

## Operational : the break-glass account

The first admin you created during the setup wizard is a **local account** (username + password stored in BoltDB, Argon2id-hashed). This account survives any OIDC-side breakage :

- IdP down for maintenance → log in with the local admin → diagnose
- IdP cert expired → log in with the local admin → reconfigure / disable OIDC temporarily
- IdP irrecoverably lost (you decommissioned authentik without exporting allowlist) → log in with the local admin → re-wire to a new IdP

**Keep the local admin password somewhere safe** (password manager, sealed envelope, vault). Don't delete it.

---

## API reference

```bash
# Configure OIDC
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" -d '{
  "enabled": true,
  "issuerUrl": "https://auth.example.com/application/o/arenet/",
  "clientId": "abc123",
  "clientSecret": "secret",
  "scopes": ["openid","email","profile"],
  "redirectUrl": "https://arenet.example.com/api/v1/auth/oidc/callback",
  "kind": "authentik"
}' http://localhost:8001/api/v1/settings/oidc

# Add an OIDC identity to the allowlist
curl -b /tmp/jar -X POST -H "Content-Type: application/json" -d '{
  "email": "alice@example.com",
  "displayName": "Alice",
  "role": "admin"
}' http://localhost:8001/api/v1/oidc/allowlist
```

The OIDC config GET endpoint **redacts the client secret** (returns `"[REDACTED]"`) so it can be displayed in the UI safely.

---

## See also

- [Routes](Routes) — wire `forward_auth` per-route if you want IdP-protected backend apps (different from admin UI SSO)
- [Backup & Restore](Backup-Restore) — OIDC config + allowlist are included in backup snapshots
- [Troubleshooting](Troubleshooting) — OIDC failure diagnosis
- `internal/api/oidc.go` — full OIDC implementation
- [OIDC Discovery spec](https://openid.net/specs/openid-connect-discovery-1_0.html)
