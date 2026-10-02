# Arenet Wiki

[English](Home) · **🌐 Français**

Bienvenue. Ce wiki est le compagnon **how-to** du [README](https://github.com/barto95100/arenet/blob/main/README.fr.md) — guides task-oriented pour chaque fonctionnalité, écrits pour l'opérateur qui fait tourner Arenet sur son homelab.

Si tu débutes : commence par [Installation](Installation-FR), puis suis [Routes](Routes-FR) pour mettre live ton premier host proxifié. Tout le reste est une référence feature-by-feature.

---

## Navigation rapide

### Démarrer
- **[Installation](Installation-FR)** — Docker, systemd natif, wizard de premier boot
- **[Routes](Routes-FR)** — ta première route de reverse proxy, TLS, upstreams, alias, filtrage IP source, règles par chemin, import d'un Caddyfile
- **[Services TCP / UDP](TCP-Services-FR)** — relayer du TCP ou de l'UDP brut (messagerie, bases de données, SSH, WireGuard) en préservant l'IP réelle du client
- **[DNS Providers](DNS-Providers-FR)** — 9 fournisseurs DNS (OVHcloud, Cloudflare, Hetzner, Route 53…) pour les certificats wildcard (DNS-01), avec test de connexion
- **[Topology](Topology-FR)** — dashboard live avec visualisation de trafic en temps réel

### Stack sécurité
- **[WAF](WAF-FR)** — Coraza + OWASP CRS, opt-out par route, exclusions ciblées depuis un événement, règles guidées, éditeur SecLang avec testeur
- **[CrowdSec](CrowdSec-FR)** — réputation IP communautaire, setup bouncer LAPI
- **[Country Block](Country-Block-FR)** — listes allow/deny basées GeoIP par route
- **[Rate Limit](Rate-Limit-FR)** — throttling événements/fenêtre par route
- **[SSO OIDC](OIDC-SSO-FR)** — intégration authentik / Keycloak / Authelia + RBAC, pour se connecter à Arenet lui-même
- **[Forward auth](Forward-Auth-FR)** — placer votre IdP devant une application qui n'a pas de connexion propre

### Opérations
- **[Mettre à jour Arenet](Updates-FR)** — workflow de mise à niveau manuelle (Docker + binaire), rollback, notes de sécurité
- **[Backup & Restore](Backup-Restore-FR)** — export config complète, import avec résolution sentinel, disaster recovery
- **[Alerting](Alerting-FR)** — channels, règles threshold + state, Discord/email/webhook
- **[Custom Error Pages](Custom-Error-Pages-FR)** — templates HTML par route avec placeholders Caddy
- **[API (OpenAPI)](API-FR)** — l'API d'administration, les jetons de compte de service, la page de doc intégrée
- **[Troubleshooting](Troubleshooting-FR)** — diagnostic des symptômes, pièges communs, décodage des logs

---

## Qu'est-ce qu'Arenet ?

Arenet est un **reverse proxy single-binary** qui combine [Caddy v2](https://caddyserver.com) (le moteur HTTP, auto-HTTPS + HTTP/3 + ACME) avec :

- Une **UI d'admin** pour configurer routes, certificats, paramètres de sécurité
- Une **stack sécurité intégrée** : WAF (Coraza + OWASP CRS), réputation IP (CrowdSec), blocage par pays, rate limiting
- Une **surface d'observabilité live** : dashboard topologie avec particules en temps réel, métriques par route, log d'activité unifié, audit trail
- Un **sous-système d'alerting natif** avec routing multi-canal (Discord, email, webhook)
- **Backup/restore** de toute la config via l'UI

Le tout en **un seul binaire Go** (~100 Mo) backé par BoltDB + SQLite — pas de sidecars, pas de dépendances externes au-delà de l'infra propre de l'opérateur (DNS, instance CrowdSec optionnelle, serveur SMTP optionnel, IdP optionnel).

## Pour qui ?

Conçu pour l'opérateur qui fait tourner **5 à 50 routes sur un seul host** (homelab, petite entreprise, freelance). Pas conçu pour des déploiements cloud multi-tenant, pas conçu pour des scénarios d'ingress controller k8s. Si tu veux une posture production sans la complexité production, Arenet est l'audience cible.

## Comment ce wiki est-il organisé ?

- Les **pages get-started** sont des tutoriels avec des commandes copy-paste que tu peux suivre top-to-bottom.
- Les **pages feature** expliquent une seule capacité en profondeur : ce qu'elle fait, quand l'utiliser, comment la configurer, pièges communs.
- Les **pages opérations** couvrent les tâches de cycle de vie (backup, recovery, câblage d'alerting).
- Chaque page se termine par une section "**See also**" liant les sujets connexes et les fichiers pertinents dans le dossier `docs/` du repo principal (pour les opérateurs qui veulent creuser l'architecture).

Si tu trouves un trou ou veux contribuer à une page, [ouvre une issue](https://github.com/barto95100/arenet/issues).

## Couverture des versions

Ce wiki suit **Arenet v2.40.x** (la ligne de release stable courante). Les versions plus anciennes peuvent différer en surface de feature ; consulte les [release notes](https://github.com/barto95100/arenet/releases) en cas de doute.

## Où vivent les choses (cheat sheet)

| Concept | Chemin UI | Chemin API | Stockage |
| ------- | --------- | ---------- | -------- |
| Routes | `/routes` | `/api/v1/routes` | BoltDB bucket `routes` |
| Services TCP / UDP | `/tcp-services` | `/api/v1/tcp-services` | BoltDB bucket `tcp_services` |
| Certificats | `/certs` | `/api/v1/certificates` | Caddy storage + cert tracker |
| DNS providers | `/settings` (DNS Providers) | `/api/v1/settings/dns-providers` | BoltDB `dns_providers` bucket |
| Événements WAF | `/security` | `/api/v1/security/events` | SQLite table `waf_event` |
| Événements cert | `/logs` (badge CERT) | `/api/v1/observability/cert-events` | SQLite table `cert_event` |
| Audit log | `/audit` | `/api/v1/audit/events` | BoltDB bucket `audit` |
| Règles d'alerting | `/alerting` (onglet Rules) | `/api/v1/alerting/rules` | BoltDB bucket `alert_rules` |
| Config OIDC | `/settings` | `/api/v1/settings/oidc` | BoltDB key `oidc_config` |
| Users | `/users` | `/api/v1/users` | BoltDB bucket `users` |
| Snapshot backup | `/settings` (section Backup) | `/api/v1/admin/backup` + `/admin/restore` | Tous les buckets sérialisés en JSON |

Port admin par défaut : `:8001` (loopback par défaut ; set `ARENET_ADMIN_BIND=0.0.0.0:8001` pour accès LAN).

---

## Variables d'environnement (cheat sheet)

Toutes optionnelles — chaque variable a un défaut safe. Définis-les de la même façon dans **les deux** modes de déploiement :

- **Docker** — un bloc `environment:` dans `docker-compose.yml` (ou `-e VAR=value` sur `docker run`).
- **systemd / binaire** — des lignes dans `/etc/arenet/arenet.env` (sourcé par l'unit via `EnvironmentFile=`), ou `Environment="VAR=value"` dans l'unit.

| Variable | Défaut | Rôle |
| -------- | ------ | ---- |
| `ARENET_ADMIN_BIND` | `127.0.0.1:8001` | Adresse de bind de l'UI/API d'admin (`0.0.0.0:8001` pour le LAN). |
| `ARENET_DATA_DIR` | `/var/lib/arenet` | Dossier d'état (BoltDB + SQLite). |
| `ARENET_HTTP_PORT` / `ARENET_HTTPS_PORT` | `:80` / `:443` | Ports d'écoute du data-plane public. |
| `ARENET_ACME_EMAIL` | _(aucun)_ | Email de contact pour l'émetteur ACME (notices Let's Encrypt). |
| `ARENET_UPDATE_CHECK_INTERVAL` | `24h` | Cadence du vérificateur de mises à jour (durée Go, min `1h` ; le check s'active dans *Réglages → Mises à jour*, pas par env). |
| `ARENET_TRUSTED_PROXIES` | _(aucun)_ | CIDRs dont le `X-Forwarded-For` est de confiance (derrière un proxy/LB frontal). |
| `ARENET_UI_ORIGIN` | _(aucun)_ | Origin du SPA pour les redirects de callback OIDC quand l'UI est servie séparément. |
| `ARENET_CROWDSEC_API_URL` / `ARENET_CROWDSEC_API_KEY` | _(aucun)_ | Câblage LAPI CrowdSec — voir [CrowdSec](CrowdSec-FR). |
| `ARENET_GEOIP_MMDB` | `/var/lib/arenet/GeoLite2-City.mmdb` | Chemin vers la base GeoLite2-City fournie par l'opérateur (ou téléchargée automatiquement via *Réglages → GeoIP*). |
| `ARENET_GEOIP_ASN_MMDB` | `GeoLite2-ASN.mmdb` à côté de la base City | Chemin vers la base GeoLite2-ASN utilisée par les [règles ASN](Country-Block-FR#réseaux-asn-v2280) (téléchargée automatiquement avec la base City). |
| `ARENET_PUBLIC_IP` | _(auto)_ | Force l'IP publique détectée du serveur (topology / carte geo). |
| `ARENET_TOPOLOGY_TICK_MS` | `2000` | Intervalle de push WebSocket de la topology, en ms (arrondi à un multiple de 1000). |

> **Lors d'une mise à niveau :** les variables d'environnement sont **fournies par toi** — Arenet n'écrit jamais dans ton `.env` ni ton compose (un service exposé au réseau ne doit pas éditer sa propre config système ; même raisonnement que [pourquoi il n'y a pas d'auto-update](Updates-FR#notes-de-sécurité)). Les nouvelles variables d'une release sont listées dans les notes de cette release ; ajoute celles que tu veux à ton `.env` / compose. Chaque variable a un défaut safe, donc une mise à niveau ne *nécessite* jamais d'éditer ta config — non définie = « utilise le défaut ».
