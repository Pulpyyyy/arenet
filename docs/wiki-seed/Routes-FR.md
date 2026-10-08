# Routes

[English](Routes) · **🌐 Français**

Une **route** dans Arenet fait correspondre un `host` (FQDN) entrant à un ou plusieurs `upstreams` (backends). Chaque route porte aussi sa config TLS, WAF, auth, rate-limit, country-block et health-check.

Cette page couvre le cycle de vie d'une route : créer, configurer, aliaser, débugger.

---

## Créer ta première route

1. Ouvre l'UI d'admin : `http://<ton-host>:8001`
2. Barre latérale → **Routes**
3. Clique sur **+ Add route**
4. Remplis :
   - **Host** : le hostname public, ex. `vault.example.com`
   - **Upstreams** : un ou plusieurs backends. Clique sur **+ Add upstream** pour en ajouter. Format : `http://<ip-lan>:<port>` ou `https://<host>:<port>` pour les backends HTTPS. Chaque upstream a un `weight` (utilisé quand la policy LB est weighted-round-robin).
   - **LB Policy** : `round_robin` (défaut) ou `weighted_round_robin`
   - **TLS** : coche ✅ pour activer HTTPS + auto-cert via ACME. Choisis le **challenge ACME** : `http-01` (défaut, marche pour n'importe quel domaine qui pointe vers ton host) ou `dns-01` (requis pour les certs wildcard, nécessite des creds DNS provider dans Settings).
5. Clique sur **Save**

En ~5 secondes, Caddy recharge et la route est live :
- Les requêtes HTTP vers `http://vault.example.com` redirigent vers `https://`
- Les requêtes HTTPS reçoivent un cert Let's Encrypt auto-émis (la première requête peut prendre 5-15s le temps qu'ACME termine)
- La requête est reverse-proxifiée vers ton upstream

---

## Le formulaire de route (v2.41)

Une route porte beaucoup de réglages : le formulaire les regroupe donc en **sections repliables**. Seule la section **Essentiel** (hôte, alias, backends, policy LB) est ouverte à l'ouverture du panneau ; tout le reste est replié.

Pas besoin d'ouvrir une section pour savoir ce qu'elle contient : chaque ligne repliée affiche un **résumé d'état sur une ligne** — `WAF — OWASP CRS · 2 exclusions` avec une pastille `block`, `Filtrage géo & IP — 3 pays/ASN bloqués`, `Limitation de débit — aucune limite`. Les sections qui décident du sort du trafic portent en plus une **pastille et un liseré coloré à gauche**, avec le même code que la phrase du blocage par pays :

| Couleur | Sens |
|---|---|
| vert | laisse passer le trafic sur un critère (liste d'autorisation, authentification exigée) |
| rouge | bloque le trafic (WAF en mode block, blocage par pays, liste de refus d'IP) |
| ambre | observe sans bloquer (WAF en mode detect) |
| gris | configuré mais inactif |

Les sections qui ne décident de rien (TLS, health check, en-têtes, pages d'erreur) restent neutres, pour que la couleur garde son sens.

À l'intérieur d'une section, un réglage à quelques modes exclusifs — inspection WAF, authentification, filtrage par pays — est un **contrôle segmenté** : tous les modes restent visibles, portent leur couleur, et le mode sélectionné affiche en dessous ce qu'il fait (`Les requêtes sont inspectées et journalisées, jamais bloquées.`). Les réglages oui/non sont des interrupteurs avec leur ligne d'aide, et celui qui retire une protection (**Désactiver le CRS OWASP**) est encadré en rouge. Quand plusieurs champs forment une seule règle, le formulaire énonce la règle : la limitation de débit affiche `Au-delà de 60 requêtes par 1m depuis la même IP du client, les requêtes sont refusées avec un 429.`

L'en-tête du panneau reste visible pendant le défilement et affiche un marqueur **modifications non enregistrées** dès que tu touches un champ. Partir avec des modifications en attente — Annuler, un clic hors du panneau, ou sélectionner une autre route — demande confirmation ; **Continuer à modifier** te remet où tu étais.

Dans la liste des routes, la colonne **Sécurité** montre désormais tout ce qui garde une route, pas seulement le WAF : le mode WAF, une pastille `Géo` quand le filtrage par pays est actif, une pastille `IP` pour le filtrage par IP source, et la limitation de débit sous la forme `60/1m`. Vert = laisse passer sur un critère, rouge = bloque ; survole une pastille pour les compteurs.

---

## Importer un Caddyfile (v2.40)

Tu viens de Caddy « nu » ? **Routes → Importer un Caddyfile** lit ton fichier avec le parseur de Caddy et transforme chaque bloc de site en route.

1. Colle le Caddyfile (ou dépose le fichier) et clique sur **Analyser**. Rien n'est encore écrit.
2. L'aperçu affiche une ligne par bloc : l'hôte et ses alias, les backends, des badges (HTTP, règles par chemin, **déjà présente**) et, repliés, tous les éléments non repris — chacun avec son numéro de ligne.
3. Coche ce que tu veux et clique sur **Importer**. Caddy est rechargé une seule fois ; s'il refuse le résultat, toutes les routes importées sont retirées et l'appel échoue, donc jamais d'import à moitié fait.

Ce qui est importé :

| Caddyfile | Route |
|---|---|
| les adresses du bloc | hôte + alias ; `http://` → TLS désactivé |
| `reverse_proxy` | backends, `lb_policy`, `health_uri` / `health_interval` / `health_timeout` / `health_status`, `header_up` / `header_down`, `transport http { tls_insecure_skip_verify }` |
| `reverse_proxy /chemin/*`, `handle_path`, `handle`, `route` contenant un `reverse_proxy` | une règle par chemin avec ses propres backends |
| `tls <email>` ou rien | ACME HTTP-01 |
| `tls { dns … }` | ACME DNS-01 (configure le fournisseur dans Arenet — les identifiants ne sont jamais importés) |
| `encode`, `log` | ignorés en silence (Arenet s'en charge) |

Ce qui est signalé plutôt que deviné : `basic_auth` (Caddy stocke un hachage bcrypt, ressaisis le mot de passe), `tls internal` et les certificats explicites (téléverse-les dans Certificats), `file_server`, `php_fastcgi`, `redir`, `respond`, `rewrite`, les matchers nommés, les backends en socket unix ou avec des variables, les ports autres que 80/443, les options globales et les routes nommées.

Un bloc sans `reverse_proxy` n'est pas importable : il est listé avec la raison.

Deux garde-fous : un hôte déjà servi par une route est **ignoré**, sauf si tu coches **remplacer** (ce qui écrase cette route : ses réglages WAF, géo et limites sont perdus), et les routes importées démarrent avec le **WAF en mode detect**, pour que tu voies ce que le CRS bloquerait avant de l'appliquer.

---

## Anatomie d'une route

Chaque route stocke les champs suivants (bucket BoltDB `routes`) :

| Champ | Défaut | Usage |
| ----- | ------- | ------- |
| `host` | — (requis) | Matcher FQDN principal |
| `aliases` | `[]` | FQDNs additionnels qui matchent la même route |
| `upstreams[]` | — (requis) | Pool de backends (`url` + `weight`) |
| `lbPolicy` | `round_robin` | Policy de load balancing |
| `tlsEnabled` | `false` | Auto-HTTPS via ACME |
| `redirectToHttps` | `false` | Si TLS, force la redirection HTTP→HTTPS |
| `acmeChallenge` | `http-01` | `http-01` / `dns-01` / `inherited` (depuis un apex managé) |
| `useDedicatedCert` | `false` | Forcer un cert par-route plutôt que le cert apex wildcard |
| `insecureSkipVerify` | `false` | Faire confiance aux certs self-signed de l'upstream |
| `uploadStreamingMode` | `false` | Ne pas bufferiser les corps d'upload (gros PUT de fichier, push registry) |
| `requestHeaders` | `{}` | Headers additionnels transmis à l'upstream |
| `responseHeaders` | `{}` | Headers additionnels ajoutés à la réponse client |
| `wafMode` | `off` | `off` / `detect` / `block` ([voir WAF](WAF)) |
| `wafDisableCRS` | `false` | Ne pas charger l'OWASP CRS sur cette route |
| `wafExcludeRules[]` | `[]` | IDs de règles CRS à exclure |
| `wafExcludeTags[]` | `[]` | Familles de tags CRS à exclure |
| `authMode` | `none` | `none` / `basic` / `forward` ([voir OIDC-SSO](OIDC-SSO)) |
| `countryBlock` | `{mode:off}` | Liste allow/deny GeoIP |
| `rateLimit` | `null` | Throttle par route |
| `healthCheck` | `{enabled:false}` | Health checks actifs (URI + status + regex sur le body) |
| `errorPageTemplateId` | `""` | Template de pages d'erreur personnalisées |
| `errorPageOverrides` | `{}` | Surcharges HTML par code de statut |

Le schéma complet vit dans `internal/storage/routes.go`.

---

## Aliases : une route, plusieurs hostnames

Utilise les aliases quand tu as plusieurs FQDNs qui doivent taper sur le même backend avec la même config (WAF, auth, TLS).

Exemple : un seul backend Traefik derrière Arenet qui sert 20 apps *arr-stack* :
- **Host** : `traefik.example.com`
- **Aliases** : `sonarr.example.com`, `radarr.example.com`, `prowlarr.example.com`, ...

Caddy acquiert automatiquement un cert SAN couvrant tous les aliases. Le dashboard `/topology` les groupe visuellement comme un seul conteneur avec N nodes alias.

---

## Certificats wildcard

Pour une route comme `*.example.com`, il te faut un **apex managé** :

1. Barre latérale → **Certificates** (`/certs`)
2. Section **Wildcard policies per apex** → **+ Wildcard apex**
3. Apex : `example.com`
4. DNS provider : OVH (d'autres providers sont prévus) — colle tes clés API
5. Save

Les routes dont le host tombe sous `*.example.com` (ex. `vault.example.com`, `cloud.example.com`) hériteront automatiquement du cert wildcard. Mets leur `acmeChallenge` sur `inherited` pour une déclaration explicite, ou laisse le défaut et Caddy choisira le cert wildcard via SNI matching au handshake.

---

## Cert Source (ACME / Internal / Manual)

Quand TLS est activé, le sélecteur **Cert Source** de la route décide d'où vient son certificat :

- **ACME** (défaut) — Caddy émet et renouvelle automatiquement un cert Let's Encrypt via le challenge `http-01` ou `dns-01`. C'est le comportement décrit ci-dessus ; une route créée avant la v2.19.0 le conserve sans migration.
- **Internal** — Caddy sert un cert self-signed depuis son CA interne (pratique pour un host purement interne où tu ne veux pas d'ACME).
- **Manual (v2.19.0)** — la route sert un **certificat externe que tu as uploadé** (depuis un CA non-ACME, une PKI d'entreprise, etc.), **sans aucune** émission ACME pour ce host. Choisis **Cert Source = Manual**, puis sélectionne le cert uploadé ; seuls les certs dont le SAN couvre le host de la route sont proposés (exact ou wildcard à un label, RFC 6125). Le renouvellement est **manuel** — voir [Certificates → Certificats externes / uploadés](Certificates-FR#certificats-externes--uploadés-v2190).

---

## Health checks

Les health checks actifs surveillent chaque upstream et retirent les mauvais du pool. Pour activer :

1. Édite une route → section **Health check**
2. **Enabled** ✅
3. **URI** : le path que Caddy va GET sur l'upstream, ex. `/healthz` ou `/api/health`
4. **Method** : défaut `GET`
5. **Interval** : défaut `30s`
6. **Timeout** : défaut `5s` (doit être `<` interval)
7. **Expected status** : défaut `0` = « n'importe quel 2xx convient ». Depuis la **v2.55**, vous pouvez aussi donner une **classe**, de `1` à `5` — `3` accepte tous les 3xx, ce qu'il faut pour une application qui redirige vers une page de connexion. Toute autre valeur est un code unique, par exemple `200`.
8. **Expected body** (regex) : optionnel, ex. `^\\{"status":"ok"\\}` pour un healthz JSON
9. **Passes** : checks consécutifs requis pour marquer healthy (défaut `1`)
10. **Fails** : checks consécutifs requis pour marquer unhealthy (défaut `1`)
11. **Host de la sonde** (facultatif, v2.55) : le `Host` qu'envoie la sonde. Vide, elle utilise l'hôte de la route.
12. **En-têtes de la sonde** (facultatif, v2.55) : des en-têtes supplémentaires, par exemple l'`Authorization` qu'exige un point de santé. Le `Host` n'est pas accepté ici — il a son propre champ.

Les upstreams unhealthy sont skippés par le load balancer ; le dashboard `/topology` les montre en état dimmed.

### Tester le contrôle avant de l'enregistrer (v2.56)

**Tester le contrôle**, à côté des champs du health check, lance une sonde par upstream avec les réglages actuellement à l'écran, avant tout enregistrement. Rien n'est écrit, rien n'est rechargé.

Le rapport donne, pour chaque upstream : le verdict et la cause précise de l'échec (code inattendu, corps ne correspondant pas, délai dépassé, connexion refusée, erreur DNS ou TLS), la requête réellement envoyée (méthode, URL, `Host`, en-têtes), et ce qui est revenu (code, durée, `Location` en cas de redirection, et les 4 premiers Kio du corps).

Les redirections ne sont **pas** suivies, parce que le contrôle actif ne les suit pas non plus — un contrôle qui rencontre un 301 échoue, et c'est précisément ce qu'il faut voir. Quand la redirection pointe vers la même URL en `https`, le résultat le dit et nomme `X-Forwarded-Proto: https`, ce qu'attend généralement une application qui estime avoir été jointe sans chiffrement.

Pourquoi c'est là : un contrôle mal réglé ne se manifestait qu'à l'enregistrement. La vérification post-modification voyait l'upstream quitter le pool, obtenait un 503 et annulait le changement — ce qui protège le site et n'explique rien. Le cas qui l'a motivé : une sonde sur Ghost sans `X-Forwarded-Proto`, Ghost répondant 301, le 200 attendu jamais atteint, l'upstream retiré et la route en 503.

Le délai est plafonné à 10 s quelle que soit la valeur du formulaire, une expression de corps invalide est refusée avant tout envoi, et la sonde ne peut atteindre ni le lien-local ni les adresses de métadonnées cloud. Chaque exécution est enregistrée dans le journal d'audit.

### Le Host que la sonde envoie (changement en v2.55)

Caddy construit la requête de health check à partir de l'**adresse de dial** de l'upstream. Avant la v2.55, la sonde demandait donc `Host: 10.0.0.2:80`. Un backend qui aiguille sur le `Host` — un second reverse proxy, un vhost, un routeur de conteneurs — n'a aucun hôte virtuel à ce nom : il répond **404**, et tous les upstreams sont marqués down alors qu'ils servent parfaitement leur route.

Depuis la v2.55, la sonde porte par défaut **l'hôte de la route**, pour ressembler au trafic qu'elle représente. Renseignez **Host de la sonde** si le backend attend un autre nom.

> **Ceci change le comportement des health checks configurés avant la v2.55.** Leur sonde envoie désormais l'hôte de la route au lieu de l'adresse de dial. Un backend qui répondait à l'ancienne sonde sur son IP et qui ne sert **pas** le nom d'hôte de la route se mettrait à échouer — renseignez alors **Host de la sonde** avec le nom qu'il sert.

Le bouton **Test** à côté de chaque upstream utilise le même Host : ce qu'il affiche est donc ce que verra le health check. Il marque une réponse 2xx ou 3xx d'un `✓` et une 4xx ou 5xx d'un `⚠` — joindre l'upstream et obtenir une réponse utile sont deux faits distincts.

Depuis la **v2.56**, la sonde refuse deux familles d'adresses, contrôlées sur l'IP effectivement résolue et non sur le nom : la plage **lien-local** (`169.254.0.0/16`, `fe80::/10`) et l'adresse de métadonnées IPv6 d'AWS (`fd00:ec2::254`). C'est là que répondent les métadonnées d'instance d'un fournisseur cloud, qui livrent des identifiants à quiconque les demande depuis l'instance : un bouton Test n'y a rien à faire. Les adresses privées et le loopback restent autorisés, parce que c'est là que vivent réellement les upstreams d'un homelab : `10/8`, `172.16/12`, `192.168/16`, `127.0.0.1`. Chaque sonde est désormais enregistrée dans le journal d'audit, refus compris.

---

## Filtrage IP source (v2.21.0)

Réserve une route entière à certaines IP sources — ou bloque-les — dans la section **Filtrage IP source** de la route :

| Mode | Effet |
| ---- | ----- |
| **Désactivé** | Aucun filtrage (défaut) |
| **Liste blanche** | Seules les IP / CIDR listées passent ; les autres reçoivent **403** |
| **Liste noire** | Les IP / CIDR listées reçoivent **403** ; les autres passent |

Une IP ou un CIDR par ligne (`192.168.1.10`, `10.0.0.0/8`, IPv6 aussi). Les visiteurs bloqués reçoivent la page d'erreur **403** brandée de la route.

> **Quelle IP est vérifiée ?** Celle du **pair TCP direct** — `X-Forwarded-For` est ignoré, donc un client ne peut pas contourner une liste blanche en le falsifiant. Contrepartie : si Arenet est derrière un autre proxy / CDN / load balancer, le filtre voit l'IP de ce proxy, pas celle du visiteur.

---

### Une limite plus stricte pour un seul chemin (v2.56)

La limite de débit de la route gouverne tout le site. Un point d'entrée de connexion ou de session en veut généralement une bien plus serrée — et relever celle de la route pour protéger un chemin serait le mauvais instrument : cela ralentirait chaque ressource de la page pour freiner un seul formulaire.

Cochez **Limite de débit pour ce chemin** sur une règle et donnez-lui ses propres requêtes-par-durée. Ce qui compte :

- elle s'ajoute à celle de la route, elle ne la remplace pas. Les deux s'appliquent, et les compteurs sont des zones distinctes — une limite stricte sur `/api/v1/auth` ne consomme pas le budget de la route, et la limite de la route ne la dilue pas ;
- elle s'applique **avant** l'authentification basique de ce chemin : les requêtes comptées sont donc celles qui ne se sont pas encore authentifiées. C'est tout l'intérêt sur un point de connexion — ne compter que les connexions réussies ne serait aucune protection ;
- au-delà, la requête reçoit un `429` ;
- la clé vaut par défaut l'IP du client (`{http.request.remote.host}`), comme pour la route. Arenet n'émet aucun `trusted_proxies` : c'est donc le véritable pair de la socket, non falsifiable via `X-Forwarded-For`.

Exemple — le point de session admin de Ghost à 3 tentatives par 5 minutes, tandis que le blog reste aux 200 par minute de la route : ajoutez une règle sur `/ghost/api/admin/session`, cochez la limite, mettez 3 et `5m`.

### Un fournisseur d'identité pour un chemin (v2.57)

Certains chemins n'ont aucune authentification propre : un `/metrics` exposé, une console de débogage, une interface d'administration qui n'était pas censée être accessible depuis l'extérieur. Jusqu'ici le seul contrôle d'identité par chemin était l'authentification basique, et un mot de passe partagé est une réponse médiocre quand on exploite déjà un IdP.

Cochez **Fournisseur d'identité pour ce chemin** sur une règle et choisissez l'un de vos fournisseurs configurés (Réglages → Forward auth). Ce qui compte :

- il s'ajoute à l'authentification de la route, qui s'exécute toujours en premier. Une règle par chemin ne désactive jamais une protection de la route ;
- il **remplace l'authentification basique de cette règle** : un seul contrôle d'identité par chemin, pas deux. Activer l'un désactive l'autre, la combinaison invalide est donc impossible à construire ;
- si le fournisseur est supprimé par la suite, le chemin répond **`503`** au lieu d'être servi sans protection. Un contrôle qui cesse de contrôler en silence est pire qu'un contrôle indisponible : la panne est rendue visible ;
- le contrôle se place au même endroit dans la chaîne que l'authentification basique du chemin : après le filtre IP et la limite de débit du chemin, avant le relais vers le backend.

**Ce à quoi cela ne sert pas.** Un chemin dont l'application authentifie elle-même ses utilisateurs. Un IdP placé devant une page de connexion répond aux requêtes d'arrière-plan du navigateur par une redirection vers l'IdP, qu'une application attendant du JSON ne peut pas suivre : le formulaire de connexion cesse silencieusement de fonctionner. Protégez ce qui n'a aucun contrôle propre, et laissez le reste à l'application.

**Avec Authentik**, l'outpost sert aussi `/outpost.goauthentik.io` sous le domaine de votre application, et ce sous-arbre doit échapper au contrôle, sinon l'aller-retour de connexion ne peut pas aboutir. Renseignez-le dans le champ **Auth passthrough prefix** du fournisseur plutôt qu'en règle par chemin — voir [Forward auth](Forward-Auth-FR). Une version antérieure de cette page conseillait la règle par chemin ; le champ du fournisseur est la voie prévue et ne demande aucune règle.

---

### Exempter un chemin de l'authentification de la route (v2.58)

Toutes les autres règles par chemin **ajoutent** à ce que fait déjà la route. Celle-ci retire, et c'est la seule.

Le cas qui la justifie : une application qui a besoin des deux postures en même temps. n8n derrière un IdP veut son éditeur protégé, et `/webhook/`, `/form/` ainsi que `/rest/oauth2-credential/callback` joignables par des services — HelloAsso, Ghost, l'aller-retour OAuth de Google — qui n'auront jamais de session. Sans cela, la seule option est une seconde route sur le même hôte, qui duplique tous les autres réglages et divergera de la première dès qu'on en modifiera une.

Cela suppose que la route porte une authentification — voyez [Forward auth](Forward-Auth-FR) pour configurer un fournisseur.

Cochez **Exempter ce chemin de l'authentification de la route** sur une règle. Ce que cela fait, exactement :

- l'authentification de la route — Basic ou le fournisseur d'identité — **ne s'exécute pas** sur ce chemin. Elle continue de s'exécuter partout ailleurs ;
- **tout le reste de la route continue de s'appliquer** : WAF, CrowdSec, filtrage par pays, filtrage d'IP source et limite de débit. Le chemin est exempté de la connexion, pas des défenses ;
- les en-têtes d'identité sont **retirés des requêtes entrantes** sur ce chemin : `Remote-User`, `Remote-Email`, `Remote-Groups`, `Remote-Name`, `X-Authentik-*`, `X-Forwarded-User`, plus ceux que votre fournisseur est configuré à recopier. Sans cela, un appelant pourrait envoyer `Remote-User: admin` et votre application — qui fait confiance à cet en-tête précisément parce que l'IdP le pose d'ordinaire — le croirait. C'est ce point qui rend l'exemption utilisable sans danger ;
- elle ne se combine pas avec un fournisseur d'identité sur la même règle, ce qui serait deux instructions opposées. Elle **se combine** avec l'authentification Basic de cette règle, ce qui remplace le contrôle d'identité de la route par un secret partagé sur un seul chemin ;
- la modification est inscrite au journal d'audit, dans les deux sens : quand l'exemption est ajoutée, et quand elle est retirée.

**Attention aux préfixes.** `/webhook` couvre `/webhook` et tout ce qui est en dessous, et ne couvre **pas** `/webhook-test` : ce sont deux préfixes distincts, chacun a besoin de sa règle. Pour une URL unique sans rien en dessous, comme un rappel OAuth, cochez **correspondance exacte** pour que l'exemption couvre ce seul chemin.

**n8n, concrètement.** Quatre règles sur la route : `/webhook` exempté, `/webhook-test` exempté, `/form` exempté, et `/rest/oauth2-credential/callback` exempté en correspondance exacte. L'éditeur et tout le reste restent derrière l'IdP.

---

## Règles par chemin (v2.21.0 → v2.23.0)

Les **règles par chemin** ajoutent une protection — et au besoin un autre backend — à un sous-chemin d'une route, sans créer de seconde route. Cas typiques : basic auth sur `/docs` (Swagger), `/metrics` accessible depuis une seule IP de supervision, `/api/v1` envoyé vers un autre backend, le reste du site inchangé.

Dans le formulaire de la route → **Règles par chemin** → **Ajouter une règle** :

| Champ | Signification |
| ----- | ------------- |
| **Préfixe de chemin** | `/docs` couvre `/docs` **et tout ce qui est en dessous** (`/docs/…`). Préfixe uniquement — pas de regex. |
| **Authentification Basic spécifique** | Utilisateur + mot de passe exigés pour ce chemin seulement. |
| **Filtrage IP dédié** | Liste blanche / liste noire pour ce chemin seulement (mêmes règles que le filtrage de la route ci-dessus). |
| **Limite de débit pour ce chemin** (v2.56) | Une limite plus stricte pour ce seul chemin. **En plus** de celle de la route, et non à sa place — les deux sont des zones de compteurs distinctes. Au-delà : `429`. |
| **Exempter de l'authentification de la route** (v2.58) | L'authentification de la route ne s'exécute pas sur ce chemin. Tout le reste s'applique, et les en-têtes d'identité sont retirés pour qu'un appelant ne puisse pas en forger un. |
| **Fournisseur d'identité pour ce chemin** (v2.57) | Fait passer ce chemin par l'un de vos fournisseurs forward-auth. **En plus** de l'authentification de la route. Remplace l'authentification basique de cette règle — un seul contrôle d'identité par chemin, pas deux. |
| **Upstream spécifique (optionnel)** | Envoie ce chemin vers son propre pool de backends au lieu de celui de la route : URL + poids, répartition de charge, health-check actif, et *Ignorer la vérification TLS* pour un backend HTTPS auto-signé (v2.23.0 / v2.23.1). Laisser vide pour suivre l'upstream de la route. |

Une règle doit contenir au moins : une basic auth, un fournisseur d'identité, une exemption d'authentification, un filtrage IP actif, une limite de débit, une redirection ou un upstream spécifique (une règle avec seulement un upstream sert à router).

**Comment les règles se combinent**

- **Additif** : un chemin garde toutes les protections de la route (WAF, blocage pays, CrowdSec, auth de la route…) et **ajoute** les siennes. Une règle par chemin ne peut jamais désactiver une protection de la route.
- **Le préfixe le plus long gagne** : avec `/api` et `/api/admin`, une requête vers `/api/admin/users` utilise la règle `/api/admin`. Aucun ordre à régler à la main.
- **Transport par pool** : le pool d'un chemin peut être en HTTP alors que celui de la route est en HTTPS (ou l'inverse) ; tous les backends d'un même pool doivent partager le même schéma.

La page **Topologie** affiche les pools par chemin comme des sections dans le cluster de backends de la route (voir [Topology](Topology-FR)).

Pas encore disponible par chemin : WAF on/off, blocage pays, en-têtes.

---

## Route states (Active / Maintenance / Redirect / Disabled)

Chaque route a un **contrôle de cycle de vie à 3 états**, affiché comme un segmented control icon-only sur la liste `/routes` — play (▶, vert) = **Active**, wrench (🔧, ambre) = **Maintenance**, power (⏻, rouge) = **Disabled**. Survole un segment pour son tooltip ; clique dessus pour changer d'état.

| État | Trafic | TLS / `:443` | Config |
| ----- | ------- | ------------- | ------ |
| **Active** | Reverse-proxy normal vers le pool d'upstreams | Conservé si `tlsEnabled` | — |
| **Maintenance** | 503 + page de maintenance brandée + header `Retry-After` pour tout le monde, sauf les IPs bypass qui obtiennent toute la route — règles de chemin, en-têtes, gates | **Conservé** — host/TLS restent servis | Config intacte ; la route est protégée derrière la liste bypass, pas remplacée |
| **Disabled** | Route totalement retirée de Caddy ; le host tombe sur le catch-all (404) | Supprimé ; désactiver la **dernière** route HTTPS active supprime le listener `:443` (un dialogue de confirmation t'avertit avant) | **Préservée** pour une ré-activation en un clic |

Si une route porte à la fois un flag `disabled` et un `maintenanceConfig`, **Disabled gagne** — c'est l'état "ne sert aucun trafic du tout" le plus fort. Priorité : **Disabled → 404** (gagne) > **Maintenance → 503** > **Active**.

### Disabled (v2.15.0)

Désactiver une route sert pour les **fenêtres de maintenance où tu ne veux pas du tout que l'app soit joignable**, ou pour mettre de côté une route que tu ne veux pas supprimer (sa config host/upstreams/TLS/WAF/aliases est préservée dans BoltDB — rien n'est perdu). Une route désactivée est filtrée avant la construction de la config Caddy, donc :

- Le host arrête de résoudre via Arenet — une requête dessus tombe sur le **catch-all** (404, voir [Custom Error Pages](Custom-Error-Pages-FR#catch-all-hôte-non-configuré)).
- Si c'était la **dernière route avec `tlsEnabled` + active**, la désactiver supprime aussi le listener HTTPS `:443` — toute autre URL HTTPS servie par Arenet échouera en connection refused jusqu'à ce que tu ré-actives une route ou en ajoutes une nouvelle en HTTPS. L'UI détecte ce cas et affiche un dialogue de confirmation dédié ("Disable the last HTTPS route?") avant que tu confirmes.
- Ré-activer c'est un clic (ou `POST /routes/{id}/enable`) — mêmes upstreams, TLS, WAF, tout revient exactement comme configuré.

### Maintenance (v2.17.0)

Le mode maintenance sert pour le cas « je dois couper l'app un moment, mais je veux quand même pouvoir la taper moi-même pour vérifier ». Contrairement à Disabled, la route **reste servie** — Caddy garde le host + le cert TLS actifs — mais chaque requête reçoit :

- **HTTP 503**
- La **page de maintenance globale** (personnalisable dans Settings → Error Pages → onglet Maintenance, voir [Custom Error Pages](Custom-Error-Pages-FR#page-de-maintenance))
- Un header **`Retry-After`** (secondes, configurable par route)

... **sauf** les requêtes venant des IPs/CIDRs sur la **liste bypass** de la route, qui obtiennent la route exactement telle qu'elle sera une fois l'état rebasculé : **comme si la route était Active**. Les règles de chemin avec leurs propres pools d'upstreams, les forward auth / basic auth / filtres IP / redirections / limites de débit par chemin, tes en-têtes de requête et de réponse, l'auth de la route, le WAF, la limite de débit, le blocage par pays et CrowdSec — tout s'applique à une requête bypassée, parce que c'est la même route émise.

C'est tout l'intérêt de la liste : une vérification qui n'exerce pas la vraie route ne prouve rien sur elle. Si ton IdP ou le WAF te bloque en bypass, c'est un fait sur la route que tu es à un clic de rouvrir.

Une exception volontaire : sur une route avec **HTTP→HTTPS automatique**, le listener HTTP en clair répond toujours un `301` à tout le monde, bypassé ou non. La redirection est un saut, pas la route, donc la liste s'applique là où la route se trouve réellement — en HTTPS.

Configure la maintenance dans le **formulaire d'édition** de la route, section **Maintenance** (affichée pour toute route, pas seulement celles actuellement en maintenance, pour que tu puisses pré-remplir avant de basculer le contrôle d'état) :

- **Retry-After** — choisis un **nombre + une unité** (secondes / minutes / heures / jours) au lieu de convertir à la main en secondes. La valeur est envoyée dans le header de réponse `Retry-After` (toujours en secondes, conformément à la RFC 9110 — les navigateurs et robots lisent des secondes) et affichée en mots sur la page de maintenance via le placeholder `{arenet.maintenance.retry_after_human}` (`86400` devient `1 day`). La valeur `0` omet le header. Défaut `5 minutes` (300 s) la première fois qu'une route entre en maintenance. _(Le sélecteur d'unité n'est qu'un confort d'UI — la valeur stockée/wire est toujours en secondes.)_
- **Bypass IPs / CIDRs** — un répéteur d'IPs nues (`10.0.0.5`) ou de plages CIDR (`192.168.1.0/24`). Ajoutes-en autant que nécessaire.

Le check de bypass matche l'**IP réelle du client** (le matcher `client_ip` de Caddy), pas le header `X-Forwarded-For` — donc il ne peut pas être spoofé par un header de requête comme le serait un check `X-Forwarded-For`.

- **Message de maintenance (v2.18.1)** — un message **par route**, affiché sur la page de maintenance de cette route via le placeholder `{arenet.maintenance.message}`. Laisse-le vide pour retomber sur le message **global** (**Settings → Error Pages → onglet Maintenance**, au-dessus de l'éditeur HTML), qui est le défaut partagé pour les routes qui n'ont pas le leur. Le message est du texte brut : échappé en HTML, retours à la ligne → `<br>` au rendu (pas d'injection de markup), et les placeholders Caddy `{env.*}` / `{file.*}` sont neutralisés pour ne pas fuiter de secrets/fichiers dans le 503 public.

**Résolution :** message de la route si défini, sinon le message global, sinon rien (la page par défaut affiche alors sa phrase générique).

**Auto-refresh (v2.18.1).** La page de maintenance par défaut intégrée inclut une balise `<meta http-equiv="refresh">` construite depuis le Retry-After de la route, pour que le navigateur du visiteur se recharge une fois la fenêtre censée terminée. Quand Retry-After vaut `0`, aucune balise n'est émise (un `content="0"` rechargerait en boucle instantanément). Ça ne concerne que la **page par défaut intégrée** — une page personnalisée peut l'activer en mettant `{arenet.maintenance.refresh_meta}` dans son propre `<head>`, ce qui apporte la protection à `0` avec elle. Note : c'est un *confort navigateur* — l'en-tête `Retry-After` lui-même est indicatif (bots/crawlers le respectent ; les navigateurs ne rechargent pas automatiquement dessus).

Basculer le contrôle d'état vers/depuis Maintenance est idempotent et immédiat — ré-entrer en maintenance sur une route déjà en maintenance garde ta config Retry-After/bypass existante (ça ne reset pas aux défauts) ; en sortir efface la config de maintenance à nil, donc la prochaine fois que tu entres en maintenance ça repart des défauts (`300`s).

### Référence API (contrôle d'état)

```bash
# Disable / re-enable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/disable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/enable

# Entrer / sortir de maintenance (la config — retryAfter/bypassIps — se règle via l'update PUT normal de la route)
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance/off
```

Les quatre endpoints sont idempotents : désactiver une route déjà désactivée, ou entrer en maintenance sur une route déjà en maintenance, renvoie `200` sans erreur.

---

## Rediriger un seul chemin (v2.44)

Le cas pour lequel ça existe : une application qui **ne sert rien à sa
racine**. L'interface d'administration d'un serveur de messagerie sous
`/admin`, une API sous `/api`. Visiter le nom d'hôte nu donne un 404
qui a tout l'air d'être la faute d'Arenet.

Dans **Règles par chemin**, ajoute une règle sur `/`, active **Ne
correspondre qu'à ce chemin exact**, active **Rediriger ce chemin**,
et donne `/admin/login`. Tout le reste de la route continue d'être
relayé normalement.

**Pourquoi le mode exact n'est pas optionnel ici.** Les règles par
chemin couvrent un sous-arbre par défaut : une règle sur `/` couvre
donc aussi `/admin/login`, la redirection correspondrait à sa propre
destination, et le navigateur rebondirait jusqu'à abandonner. La
correspondance exacte fait que la règle ne couvre que `/`. Arenet
refuse une destination que sa propre règle attraperait, quel que soit
le mode choisi.

**301 ou 302.** Le 302 est la valeur par défaut, et généralement la
bonne : un chemin d'accueil est un confort qu'une mise à jour de
l'application peut changer, et un 301 est retenu par le navigateur de
chaque visiteur — très difficile à reprendre. Le 301 ne se justifie
que pour quelque chose sur quoi tu ne reviendras pas.

**La destination** peut être un chemin sur cet hôte (`/admin/login`)
ou une URL complète ailleurs (`https://docs.example.com/`). Une règle
qui ne fait que rediriger est une règle complète : elle n'a besoin ni
d'authentification, ni de filtre, ni de backend.

> **Les chemins sont en minuscules.** Caddy minuscule le chemin de la
> requête avant de comparer, mais jamais le motif : une règle écrite
> `/Admin` ne pourrait donc jamais correspondre à quoi que ce soit —
> elle se chargerait sans erreur et ne ferait rien, en silence. Arenet
> refuse un chemin comportant une majuscule à l'enregistrement et
> t'indique la forme en minuscules.

## Rediriger tout un domaine (v2.44)

Une route dans l'état **Redirection** cesse de relayer et répond un 301
ou un 302. C'est l'état « j'ai déménagé un domaine » :
`old.example.com` envoie tous ses visiteurs vers `new.example.com`.

**Conserver le chemin du visiteur** (activé par défaut) ajoute le
chemin *et* la requête d'origine, donc `/a/b?c=1` arrive sur le même
`/a/b?c=1` à destination. Avec cette option, la destination ne doit
porter aucun chemin : l'ajouter à `https://example.com/app`
produirait silencieusement `/app/a/b`, donc Arenet le refuse à
l'enregistrement plutôt que de l'émettre.

**301 ou 302.** Le 301 est permanent et retenu par les navigateurs et
les moteurs de recherche — c'est celui d'un déménagement sur lequel tu
ne reviendras pas. Le 302 est temporaire et n'est pas mémorisé ; il
convient tant que tu hésites. Les codes 307 et 308, qui préservent la
méthode de la requête, ne sont volontairement pas proposés : un
navigateur qui re-POSTe vers un autre hôte est une autre décision.

**La destination doit être un autre hôte.** Une destination sur le nom
de cette route — ou sur l'un de ses alias — correspond à la
redirection qui l'a produite, et le navigateur rebondit jusqu'à
abandonner. Arenet le refuse pendant que le formulaire est encore
ouvert, plutôt que de te le laisser découvrir depuis un navigateur.

> **Pour envoyer un seul chemin ailleurs sur le même hôte** — `/` vers
> `/admin/login`, ce dont a besoin l'interface d'administration d'un
> serveur de messagerie — une redirection d'hôte entier ne peut pas
> fonctionner, précisément pour cette raison. C'est le travail d'une
> règle par chemin.

**Ce qui s'applique encore :** le TLS. Une route en redirection termine
le TLS pour pouvoir répondre, donc elle garde son certificat et ses
renouvellements. **Ce qui ne s'applique plus :** le WAF,
l'authentification, la limitation de débit et le blocage par pays —
l'état remplace la chaîne de relais, exactement comme la maintenance.

**Dans la liste**, une route en redirection affiche son état sous forme
de pastille plutôt que le sélecteur à trois positions : passer en
redirection exige une destination, donc cela se fait dans le
formulaire.

## Per-route security knobs (antisèche)

Les combinaisons de configuration les plus courantes :

### Site public en lecture seule

```
TLS: ✅ enabled, http-01
WAF: detect mode (observer les attaques, ne pas bloquer les utilisateurs légitimes)
Rate limit: 60 req/min par IP distante
Country block: off
Auth: none
```

### Outil d'admin interne (Vault, Proxmox, Grafana)

```
TLS: ✅ enabled, dns-01 wildcard
WAF: off (ou detect avec attack-protocol exclu si le backend est REST-bruyant)
Rate limit: off
Country block: allow [FR, BE, CH] (tes pays "maison")
Auth: forward (Authelia / Authentik) OU OIDC SSO au niveau de la route
```

### Endpoint API public

```
TLS: ✅ enabled
WAF: block mode
Rate limit: 100 req/min par clé API
Country block: deny [CN, RU, ...] ou allow [pays-de-tes-clients]
Auth: forward (ta gateway API) ou basic
```

### Récepteur de webhook (source à faible confiance)

```
TLS: ✅ enabled
WAF: block mode + paranoia level 2
Rate limit: 10 req/min par IP distante
Country block: allow seulement le pays de la source du webhook
upload streaming mode: ✅ (gros payloads ; skip le buffering body du WAF)
```

---

## Interception des erreurs upstream

Quand un upstream renvoie une réponse 4xx ou 5xx, Arenet remplace automatiquement le body brut de l'upstream par la page d'erreur configurée sur la route (voir [Custom Error Pages](Custom-Error-Pages-FR)). Ça garde une expérience visuelle cohérente — les opérateurs voient le 404 brandé Arenet plutôt que, par exemple, le 404 par défaut de nginx.

### Auto-passthrough sur les challenges d'auth

Deux codes de statut sont **intentionnellement PAS interceptés** : **401 Unauthorized** et **407 Proxy Authentication Required**. La réponse complète de l'upstream — y compris le header `WWW-Authenticate` / `Proxy-Authenticate` portant le challenge — passe jusqu'au client sans y toucher.

C'est nécessaire pour tout flow d'auth où le client retente avec des credentials après avoir lu le header de challenge. Remplacer le body par un 401 HTML générique retirerait le header de challenge et casserait complètement la négociation.

Si tu veux une page 401 brandée pour un de TES propres gates d'auth (BasicAuth, ForwardAuth, OIDC au niveau Arenet), ceux-là servent quand même le body brandé — ils lèvent leur 401 AVANT que la requête n'atteigne l'upstream, donc l'auto-passthrough n'est pas sur le chemin. Seuls les 401/407 originaires de l'upstream traversent le passthrough.

### Codes interceptés

`400, 402, 403, 404, 405, 406, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451` (4xx sans 401+407) et `500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511` (plage 5xx complète).

Pour chaque code intercepté, Arenet renvoie sa propre réponse construite depuis le template de page d'erreur de la route, la surcharge par route, ou le défaut intégré Arenet (dans cet ordre de priorité).

---

## Vérification après enregistrement (v2.35)

Après chaque enregistrement, Arenet envoie **une vraie requête à la route à travers son propre proxy** (vers `127.0.0.1` avec le nom d'hôte de la route, comme un visiteur) :

| Résultat | Signification | Ce qui se passe |
| --- | --- | --- |
| **ok** | Caddy a routé la requête (toute réponse sauf 502 / 503 / 504 — un 401 ou 404 de l'application convient) | rien |
| **ne répond pas** | 502 / 503 / 504 (backend injoignable, délai dépassé, aucun upstream sain) | voir ci-dessous |
| **certificat en cours d'émission** | une nouvelle route HTTPS dont le certificat Let's Encrypt n'est pas encore prêt | message d'information — pas un échec |

Quand une route **ne répond pas** :

- **Modification** — Arenet **remet l'ancienne version** et la vérifie. Si l'ancienne répondait, **ta modification est annulée** et le formulaire explique pourquoi (typiquement une mauvaise adresse ou un mauvais port d'upstream). Si l'ancienne ne répondait pas non plus (le backend est simplement arrêté), ta modification est **gardée** avec un avertissement — l'annuler ne réparerait rien.
- **Création et réactivation** ne sont **jamais annulées** (on crée souvent la route avant de démarrer le service) : avertissement seulement.
- Désactivation, maintenance et suppression ne sont pas vérifiées.

La vérification fait jusqu'à 3 essais espacés de 2 s : un enregistrement peut prendre ~10 s quand la route ne répond pas. Les routes uniquement en wildcard ne sont pas vérifiées. Désactivable dans **Réglages → Vérification des routes**. Les modifications annulées apparaissent dans l'audit sous `route_update_rolled_back`.

---

## Hot-reload

Chaque changement de route s'applique en **< 5 secondes** sans couper les connexions en cours. Caddy garde l'ancienne config active jusqu'à ce que la nouvelle soit entièrement provisionnée, puis bascule de façon atomique.

Si l'émission de la config échoue (ex. regex malformée dans `wafExcludeRules`), l'appel API renvoie 400 avec l'erreur, la route N'EST PAS sauvegardée, et la config Caddy live reste inchangée. Loud-fail.

---

## Référence API

Pour l'automatisation (Ansible, Terraform, scripts), les mêmes opérations sont disponibles via REST :

```bash
# Liste
curl -b /tmp/jar http://localhost:8001/api/v1/routes

# Création
curl -b /tmp/jar -X POST -H "Content-Type: application/json" \
  -d '{"host":"vault.example.com","upstreams":[{"url":"http://192.168.1.50:8200","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true}' \
  http://localhost:8001/api/v1/routes

# Mise à jour
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{...}' http://localhost:8001/api/v1/routes/<route-id>

# Suppression
curl -b /tmp/jar -X DELETE http://localhost:8001/api/v1/routes/<route-id>
```

Auth : le cookie jar (`/tmp/jar`) doit porter une session obtenue via `/api/v1/auth/login` (Content-Type `application/json`, body `{"username","password"}`).

---

## Voir aussi

- [Topology](Topology) — visualiser tes routes comme un graphe live (page EN — pas encore de traduction FR)
- [WAF](WAF) — protéger tes routes contre les attaques OWASP (page EN — pas encore de traduction FR)
- [Custom Error Pages](Custom-Error-Pages-FR) — brander les pages 4xx/5xx par route ; couvre aussi la [page de maintenance](Custom-Error-Pages-FR#page-de-maintenance) globale
- [Rate Limit](Rate-Limit) — throttler les clients abusifs (page EN — pas encore de traduction FR)
- [Country Block](Country-Block) — geo-fencing par route (page EN — pas encore de traduction FR)
- [OIDC SSO](OIDC-SSO) — single sign-on pour les outils d'admin (page EN — pas encore de traduction FR)
