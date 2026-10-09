# OIDC SSO

[English](OIDC-SSO) · **🌐 Français**

Arenet supporte le single sign-on **OpenID Connect** pour le login admin : délègue le flow d'authentification à ton IdP existant (authentik, Keycloak, Authelia, Dex, Auth0, ...) au lieu de gérer des comptes username/password locaux dans le BoltDB d'Arenet.

Une fois OIDC câblé :
- Les comptes admin locaux fonctionnent toujours (break-glass, voir plus bas)
- La page de login expose un bouton **"Sign in with SSO"**
- Un SSO réussi match l'identité IdP contre une allowlist → grant un rôle Arenet (admin ou viewer)
- Tous les accès admin/viewer flow à travers l'IdP (centralise MFA, audit, cycle de vie des comptes)

---

## Prérequis

- Un IdP OIDC reachable depuis le réseau outbound d'Arenet
- Un client OAuth enregistré sur l'IdP avec :
  - **Client type** : confidential (Arenet a un client secret)
  - **Redirect URI** : `https://<your-arenet-host>/api/v1/auth/oidc/callback`
  - **Scopes** : `openid`, `email`, `profile`
  - **Response type** : `code` (authorization code flow)

L'IdP doit publier un doc de discovery OIDC valide à `{issuer}/.well-known/openid-configuration` qui retourne les bons `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`.

---

## Quick start

### 1. Récupère les détails de l'IdP

Depuis l'UI d'admin de ton IdP, note :
- **Issuer URL** — ex. `https://auth.example.com/application/o/arenet/` (authentik) ou `https://keycloak.example.com/realms/master` (Keycloak)
- **Client ID** — typiquement un UUID ou un slug
- **Client Secret** — paste-once, stocke en sécurité

### 2. Configure Arenet

1. Sidebar → **Settings** → section **OIDC**
2. **Enabled** ✅
3. **Issuer URL** : colle depuis l'étape 1 (Arenet auto-strip `/.well-known/openid-configuration` si tu colles l'URL discovery complète par accident)
4. **Client ID** + **Client Secret** : colle
5. **Scopes** : le défaut `openid email profile` est fine
6. **Redirect URL** : `https://<your-arenet-host>/api/v1/auth/oidc/callback` (doit matcher la config côté IdP)
7. **Kind** : choisis `authentik` / `keycloak` / `authelia` / `generic` (juste pour la customization du label UI)
8. **Save**

Au Save, Arenet fetch immédiatement le doc de discovery pour valider la config. Si le fetch échoue (IdP unreachable, mauvaise URL), le Save retourne 400 avec le message d'erreur — ta config n'est PAS persistée.

### 3. Ajoute des identités à l'allowlist

Une fois OIDC câblé, tu dois dire à Arenet quelles identités IdP peuvent log in. Sidebar → **Users** → **+ Add OIDC identity** :

- **Email** : l'email de l'identité tel que l'IdP l'enverra dans le claim `email`
- **Display name** : human-readable (optionnel)
- **Role** : `viewer` ou `admin`

Save. La première fois que cet utilisateur sign in via SSO, Arenet match l'email → crée une ligne User → grant le rôle.

### 4. Test le flow

1. Ouvre `/login` dans une fenêtre privée
2. Clique **Sign in with SSO**
3. Tu es redirigé vers la page de login de l'IdP
4. Authentifie-toi
5. L'IdP redirige back vers `/api/v1/auth/oidc/callback?state=...&code=...`
6. Arenet exchange le code contre des tokens, valide la signature de l'ID token + issuer + nonce + audience + email_verified
7. Match allowlist → cookie de session set → tu atterris sur `/dashboard`

---

## RBAC : viewer vs admin

Deux rôles :

| Rôle | Peut faire |
| ---- | ---------- |
| `viewer` | Lire tout : dashboard, liste des routes, événements sécurité, audit log, événements cert, alertes. Ne peut pas muter. |
| `admin` | Tout ce que viewer peut + create / edit / delete routes, users, config OIDC, règles d'alerting, backups, restore. |

Le rôle est set par entrée d'allowlist (page Users). Changer le rôle d'une entrée nécessite un re-login (le rôle est baké dans la session au moment du login).

**Safeguard last-admin** : Arenet t'empêche de demote le dernier compte admin local (le break-glass). L'API retourne 400 ; l'UI greys out l'action demote. Garde toujours au moins un admin local même quand OIDC est câblé. Un second garde-fou refuse de rétrograder ou supprimer le dernier admin humain, local ou OIDC (les comptes de service ne comptent jamais), pour qu'une instance ne se retrouve jamais sans aucun admin.

---

## Opt-in accept-unverified-email

Par défaut Arenet rejette les logins où le claim `email_verified` de l'IdP est `false` — typique quand un user s'est sign up mais n'a jamais confirmé son email.

Pour certains setups IdP (Keycloak avec auto-confirm désactivé, identités sourced LDAP internes qui n'ont pas de validation email), tu peux vouloir accepter les emails non vérifiés.

1. Settings → OIDC → **Accept unverified email** ✅
2. Save

⚠️ Ça **relâche un check de sécurité**. À activer uniquement si le modèle d'identité de ton IdP n'a pas besoin de vérification email (ex. l'identité côté IdP est autoritative quoi qu'il arrive).

---

## Pièges communs

### Timeout du fetch de discovery (`context deadline exceeded`)

L'IdP n'est pas reachable depuis l'host Arenet. Causes communes :

- **DNS** : l'host Arenet ne peut pas résoudre le FQDN de l'IdP. Fix : ajoute à `/etc/hosts` ou fixe le resolver.
- **NAT hairpin** : si le FQDN de l'IdP pointe sur ton IP publique et que ton router ne supporte pas le NAT loopback, Arenet (qui sit derrière le même NAT) ne peut pas le reach. Fix : override `/etc/hosts` pointant vers l'IP LAN de l'IdP.
- **Stall du handshake TLS** : cert IdP expiré, serveur IdP surchargé, MITM. Fix : `curl -v https://<idp>/.well-known/openid-configuration` depuis l'host Arenet pour confirmer.
- **Firewall outbound** : le user daemon Arenet ne peut pas egress :443. Fix : check le hardening `systemd`, nftables.

Arenet enrichit la ligne de log avec l'URL issuer depuis v2.8.3 — `journalctl -u arenet | grep "discovery fetch failed"` montre exactement quelle URL a timed out.

### Erreur `invalid_state` dans le navigateur

Le cookie state n'a pas survécu au round-trip IdP. Causes communes :

- **Domaines différents pour l'UI Arenet et le callback** : le cookie state est set sur le domaine d'Arenet ; si le redirect_uri est sur un subdomain différent, le cookie n'est pas envoyé. Fix : assure-toi que le redirect_uri match le domaine depuis lequel tu logge.
- **Problème SameSite cookie** : l'IdP ne 302 pas back ; à la place il form-POST (inhabituel). Fix : utilise un setting côté IdP pour forcer le redirect GET-based.
- **Login IdP trop long dépassé max-age cookie** : le cookie state d'Arenet a une lifetime courte. Fix : l'opérateur a juste besoin de retry le flow SSO.

### Authentik spécifiquement : mauvaise URL issuer dans le doc de discovery

Si authentik est derrière un autre proxy qui ne préserve pas le header Host, authentik build le champ `issuer` du doc de discovery depuis le host upstream. Arenet essaie alors de valider le claim `iss` du JWT contre l'`issuer` du doc de discovery → mismatch → la validation du token échoue.

Fix : dans authentik, **Applications → Providers → ton provider → Issuer mode** :
- Each provider has a different issuer (recommandé) — utilise le slug de l'application
- ET assure-toi que le front proxy préserve le header Host (Arenet fait ça par défaut depuis v2.8.4 ; si ta stack est `client → other RP → Arenet → authentik`, check l'autre RP)

---

## Sessions et verrouillage

- Une session dure **24 h** (30 jours avec *Se souvenir de moi*), prolongée par l'activité.
- Après **15 minutes sans activité**, la session est **verrouillée** : l'écran de verrouillage redemande le mot de passe — ou, pour un compte OIDC, de se reconnecter via le fournisseur d'identité.
- **Activité = une action de ta part** (clic ou frappe qui atteint le serveur). Depuis la **v2.32**, les requêtes que l'interface envoie seule — cloche de notifications chaque minute, heartbeat, rafraîchissement automatique des pages Logs / Certificats / CrowdSec en direct — **ne comptent plus** : un onglet Arenet resté ouvert sur un poste sans surveillance se verrouille au bout de 15 minutes. Avant la v2.32, ces requêtes maintenaient la session éveillée indéfiniment.

---

## Opérationnel : le compte break-glass

Le premier admin que tu as créé pendant le wizard de setup est un **compte local** (username + password stocké dans BoltDB, hashé Argon2id). Ce compte survit à toute breakage côté OIDC :

- IdP down pour maintenance → log in avec l'admin local → diagnose
- Cert IdP expiré → log in avec l'admin local → reconfigure / disable OIDC temporairement
- IdP irrecoverable perdu (tu as decommissioned authentik sans exporter l'allowlist) → log in avec l'admin local → re-câble à un nouvel IdP

**Garde le password de l'admin local quelque part safe** (password manager, enveloppe scellée, vault). Ne le delete pas.

---

## Référence API

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

L'endpoint GET de config OIDC **redacte le client secret** (retourne `"[REDACTED]"`) pour qu'il puisse être affiché dans l'UI en sécurité.

---

## See also

- [Routes](Routes-FR) — câble `forward_auth` par route si tu veux des backend apps protégés par IdP (différent du SSO de l'UI d'admin)
- [Backup & Restore](Backup-Restore-FR) — la config OIDC + allowlist sont incluses dans les snapshots backup
- [Troubleshooting](Troubleshooting) — diagnostic d'échec OIDC
- `internal/api/oidc.go` — implémentation OIDC complète
- [Spec OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
