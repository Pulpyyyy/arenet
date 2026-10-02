<!-- Arenet wiki — Forward auth (protéger une application avec un IdP). AGPL-3.0. -->

# Forward auth

[English](Forward-Auth) · **🌐 Français**

Le forward auth place **votre fournisseur d'identité devant une application**, pour que les visiteurs s'authentifient avant même que l'application les voie. L'application n'a besoin de rien : ni support OIDC, ni greffon, ni modification. Arenet interroge l'IdP pour chaque requête et ne relaie que celles qu'il approuve.

> **À ne pas confondre avec le [SSO OIDC](OIDC-SSO-FR).** Cette page-là concerne la connexion à *l'interface d'administration d'Arenet*. Celle-ci concerne la protection des *applications derrière Arenet*. Les deux sont indépendants : vous pouvez utiliser l'un, l'autre, les deux ou aucun.

## Quand en avoir besoin

Une application sans authentification propre, ou dont vous préférez ne pas exposer la page de connexion : un endpoint de métriques, une console de débogage, Sonarr, un tableau de bord interne, la partie éditeur de n8n. Tout ce que vous laisseriez sinon ouvert en espérant que personne ne le trouve.

## Étape 1 — créer le fournisseur

**Réglages → Forward auth → Ajouter un fournisseur.** Un fournisseur est réutilisable sur autant de routes que vous voulez.

| Champ | Ce que c'est |
| ----- | ------------ |
| **Name** | Votre étiquette : minuscules, chiffres et tirets, 32 caractères maximum. **Non modifiable après création** — pour renommer, supprimez et recréez. |
| **Kind** | `authelia`, `authentik`, `keycloak` ou `generic`. Cela ne déclenche aucune magie ; cela consigne à quoi vous parlez. |
| **Verify URL** | Où Arenet interroge. L'adresse de l'IdP *telle qu'Arenet l'atteint*, donc en général une adresse privée ou un nom de conteneur — `http://authelia:9091`, `http://10.0.0.50:9000`. Pas votre domaine public. |
| **Auth request URI** | Le chemin, sur cet hôte, qui répond à la question. Doit commencer par `/`. Variable selon le fournisseur, voir le tableau ci-dessous. |
| **Copy headers** | Les en-têtes que la réponse de l'IdP transmet à votre application — l'identité qu'elle lira. Séparés par des virgules. Par défaut `Remote-User, Remote-Email`. |
| **Client secret** | Seulement si votre fournisseur l'exige. Laissez vide à la modification pour conserver la valeur enregistrée ; elle n'est jamais renvoyée, ni par l'API ni par le journal d'audit. |
| **Auth passthrough prefix** | Un chemin servi par l'IdP lui-même, sous le domaine de votre application, qui doit **échapper** au contrôle. Sans cela, la redirection de l'IdP vers sa propre interface repasse dans le contrôle : boucle infinie ou 404. Voir Authentik ci-dessous. |
| **Rewrite verify host** | Envoyer le nom d'hôte de l'IdP dans la question, au lieu de celui de votre visiteur. Nécessaire quand l'IdP aiguille par `Host` — c'est le cas de l'outpost embarqué d'Authentik. |

### Valeurs selon le fournisseur

| Kind | Auth request URI | Passthrough prefix | Rewrite verify host |
| ---- | ---------------- | ------------------ | ------------------- |
| **Authelia** | `/api/authz/forward-auth` | — | non |
| **Authentik**, outpost embarqué | `/outpost.goauthentik.io/auth/caddy` | `/outpost.goauthentik.io` | **oui** |
| **Authentik**, outpost séparé | `/outpost.goauthentik.io/auth/caddy` | `/outpost.goauthentik.io` | non |
| **oauth2-proxy** (`generic`) | `/oauth2/auth` | `/oauth2` | non |
| **Keycloak** | selon votre adaptateur | — | non |

Les deux lignes Authentik ne diffèrent que par **Rewrite verify host**. L'outpost embarqué vit dans le serveur Authentik, qui aiguille les applications par `Host` ; une question portant le `Host` de votre visiteur reçoit un 404 du routeur d'applications d'Authentik. Un outpost déployé séparément a son propre écouteur et n'a pas besoin de cette réécriture.

## Étape 2 — y rattacher une route

Ouvrez la route → **Authentification** → **Forward auth** → choisissez le fournisseur.

C'est tout le câblage. Chaque requête vers la route passe désormais par l'IdP.

## Étape 3 — vérifier

En navigation privée, ouvrez la route. Vous devez arriver sur la page de connexion de votre IdP, puis revenir sur l'application après authentification. Si ce n'est pas le cas, voyez les pièges ci-dessous.

## Plus fin qu'une route entière

Deux possibilités par chemin, dans la section **Paths & headers** de la route :

- **[Protéger un seul chemin](Routes-FR#un-fournisseur-didentité-pour-un-chemin-v257)** (v2.57) — laisser la route ouverte et ne contrôler que `/metrics`.
- **[Exempter un chemin](Routes-FR#exempter-un-chemin-de-lauthentification-de-la-route-v258)** (v2.58) — contrôler la route, mais laisser passer `/webhook/` pour des services qui n'auront jamais de session. C'est la seule règle par chemin qui *retire* une protection, et elle retire les en-têtes d'identité pour qu'un appelant ne puisse pas en forger un.

Ensemble, elles couvrent le cas n8n : l'éditeur derrière l'IdP, `/webhook/`, `/form/` et le rappel OAuth exemptés.

## Pièges courants

### Boucle de redirection infinie, ou 404 sur un chemin de l'IdP

L'IdP sert une partie de lui-même sous le domaine de votre application, et cette partie est contrôlée elle aussi. Renseignez **Auth passthrough prefix** (`/outpost.goauthentik.io` pour Authentik, `/oauth2` pour oauth2-proxy). Arenet relaie alors ce sous-arbre directement vers l'hôte du Verify URL, sans contrôle.

### Authentik répond 404 à la vérification

**Rewrite verify host** est désactivé alors que vous utilisez l'outpost embarqué. Activez-le.

### L'application ne sait pas qui est le visiteur

Elle lit un en-tête que vous ne recopiez pas. Ajoutez-le dans **Copy headers** — et vérifiez le nom que votre application attend réellement : `Remote-User` est une convention, pas un standard.

### Un formulaire de connexion dans l'application cesse de fonctionner

Le forward auth répond aux requêtes d'arrière-plan du navigateur par une redirection vers l'IdP, qu'une application attendant du JSON ne peut pas suivre. Ne placez pas d'IdP devant un chemin dont l'application authentifie ses propres utilisateurs ; protégez ce qui n'a aucun contrôle propre.

### La route répond 503 après la suppression d'un fournisseur

C'est volontaire. Une route dont le fournisseur a disparu devient indisponible au lieu d'être servie sans protection, et le 503 nomme le fournisseur manquant. Recréez-le, ou changez l'authentification de la route.

## Référence API

```
GET    /api/v1/settings/forward-auth/providers
POST   /api/v1/settings/forward-auth/providers
GET    /api/v1/settings/forward-auth/providers/{name}
PUT    /api/v1/settings/forward-auth/providers/{name}
DELETE /api/v1/settings/forward-auth/providers/{name}
```

Le `DELETE` est refusé par un **409** tant qu'une route référence encore le fournisseur, et le corps de la réponse nomme les routes à corriger — la référence est vérifiée, pas supposée. Le client secret n'est renvoyé par aucun de ces appels.

## Voir aussi

- [Routes](Routes-FR) — les règles par chemin, dont la protection et l'exemption d'un chemin isolé
- [SSO OIDC](OIDC-SSO-FR) — la connexion à l'interface d'administration d'Arenet, qui est autre chose
