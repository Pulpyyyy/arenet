# Pages d'erreur personnalisées

Par défaut, Arenet sert des **pages d'erreur brandées** pour les 8 codes d'erreur HTTP standard : 401, 403, 404, 429, 500, 502, 503, 504. Les templates par défaut sont des pages minimalistes en thème sombre avec la méthode/URI/UUID de la requête + un pied de page « powered by Arenet ».

Tu peux les surcharger avec ton propre HTML, par template ou par route. Step R (Phase 2).

---

## Trois niveaux de résolution

Quand Caddy doit servir une page d'erreur pour un code de statut, il parcourt la pile de résolution dans l'ordre :

1. **Surcharge de route** — si la route a une surcharge par code de statut (Route.ErrorPageOverrides), elle est utilisée
2. **Template** — si la route a un template attaché (Route.ErrorPageTemplateID), le corps du template pour ce code de statut est utilisé
3. **Défaut intégré** — le repli brandé Arenet

Le premier résultat non vide l'emporte.

---

## Défaut intégré

Le défaut intégré vit dans `internal/caddymgr/error_pages.go` sous la forme `arenetDefaultErrorPages` — une map côté Go de `int → chaîne HTML`. Pour « modifier le défaut », il faut éditer le source Go et reconstruire le binaire. La plupart des opérateurs n'en auront pas besoin ; **préférez le chemin des templates ci-dessous** pour toute personnalisation.

---

## Templates (chemin adapté aux opérateurs)

Un **template** est une collection nommée de corps HTML, un par code de statut. Tu crées N templates, puis tu en attaches chacun à N routes.

### Créer un template

1. Barre latérale → **Réglages** → **Pages d'erreur** (`/settings/error-pages`)
2. Clique sur **+ Nouveau template**
3. **Nom** : par ex. `homelab-branded`
4. **Description** (optionnel)
5. Pour chacun des 8 onglets de code de statut (401/403/404/429/500/502/503/504), remplis le corps HTML dans l'éditeur CodeMirror à gauche
6. L'iframe **Aperçu** à droite affiche le rendu avec des données factices
7. La section **Variables Caddy disponibles** liste chaque placeholder utilisable ; clique pour l'insérer au curseur
8. Clique sur **Enregistrer**

### Attacher un template à une route

1. Barre latérale → **Routes** → édite la route → section **Pages d'erreur**
2. Menu déroulant **Template** : choisis `homelab-branded`
3. Optionnellement, remplis les **surcharges par statut** pour tout code dont tu veux surcharger le corps du template
4. Enregistre

Dans les 5 secondes, la route sert le HTML de ton template sur les codes de statut concernés.

---

## Placeholders Caddy

À l'intérieur du corps HTML, tu peux utiliser des placeholders Caddy qui s'étendent au moment de servir la réponse :

| Placeholder | S'étend en |
| ----------- | ---------- |
| `{http.request.method}` | GET / POST / etc. |
| `{http.request.uri}` | L'URI demandée |
| `{http.request.host}` | La valeur de l'en-tête Host |
| `{http.request.uuid}` | Un UUID par requête (utile pour les tickets support) |
| `{http.error.status_code}` | Le code de statut servi |
| `{http.error.status_text}` | « Not Found » / « Internal Server Error » / etc. |
| `{http.error.message}` | Message d'erreur du handler upstream, le cas échéant |
| `{time.now.iso8601}` | Horodatage ISO 8601 courant |
| `{time.now.year}` | Année courante (pour les mentions de copyright) |

Exemple de corps de template pour 404 :

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

Les placeholders à l'intérieur des blocs `<code>` afficheront les valeurs réelles par requête — utile pour le support : l'utilisateur peut coller l'UUID de la requête et tu peux grepper `/logs` pour retrouver sa requête exacte.

---

## Assainissement HTML

Les templates passent par un assainisseur (sanitizer) avant persistance, pour prévenir le XSS stocké si plusieurs admins partagent l'éditeur de templates :

- Les balises `<script>` sont supprimées
- Les gestionnaires d'événements `on*` sont supprimés
- Les attributs `style` inline sont conservés (nécessaires pour le style)
- Les placeholders Caddy sont conservés tels quels

L'assainisseur est bluemonday avec une politique personnalisée ; voir `internal/storage/error_template.go`.

---

## Surcharge par route (avancé)

Si une seule route a besoin d'un corps différent pour un code spécifique (par ex. la route registry a besoin d'un 502 avec des instructions spécifiques à Docker), utilise la surcharge par statut :

1. Édite la route → **Pages d'erreur**
2. **Template** : `homelab-branded` (ou aucun)
3. **Surcharges par code de statut** : ajoute `502` → colle le corps 502 spécifique à Docker
4. Enregistre

La surcharge prend le pas sur le 502 du template ; les autres codes continuent d'utiliser le template.

---

## Plafond de 1 Mio par corps

Chaque corps HTML (page de template OU surcharge par route) est plafonné à 1 Mio avant assainissement. Suffisant pour toute page HTML raisonnable (le défaut intégré fait environ 1,5 Kio). Des images inline encodées en base64 te rapprocheraient vite du plafond ; préfère lier vers des images servies par la route elle-même.

---

## Catch-all (hôte non configuré)

Quand une requête arrive sur Arenet pour un nom d'hôte qui n'est **PAS** déclaré comme primaire ou alias sur une route, Arenet sert un 404 — la réponse *catch-all*.

Par défaut, ce corps catch-all est la page 404 brandée intégrée d'Arenet (même apparence que `arenetDefaultErrorPages[404]`, celle que voient les routes configurées sur un 404 upstream). Les opérateurs qui veulent leur propre branding partout — y compris sur les hôtes non appariés — peuvent promouvoir un de leurs templates comme défaut catch-all.

### Promouvoir un template comme défaut catch-all

1. Barre latérale → **Réglages** → **Pages d'erreur**
2. Édite (ou crée) le template dont le corps 404 doit être servi sur les hôtes non appariés
3. Coche la case **Utiliser comme page catch-all par défaut** au-dessus des onglets de code de statut
4. **Enregistrer**

À partir de là, le catch-all sert le **corps 404 de ce template** (les autres codes de statut du template sont ignorés — le catch-all ne répond jamais qu'en 404).

### Exclusion mutuelle

Au maximum **un seul template** peut porter le flag catch-all-default à un instant donné. La couche de stockage l'impose dans la même transaction d'écriture : cocher la case sur le Template B l'efface automatiquement sur le Template A. Aucun risque que deux templates se disputent la place de catch-all ; le Save le plus récent l'emporte.

### Matrice de comportement

| État | Corps catch-all servi |
| ----- | --------------------- |
| Aucun template n'est marqué | 404 intégré d'Arenet (identique à `arenetDefaultErrorPages[404]`) |
| Un template est marqué + son `Pages[404]` est renseigné | Corps 404 défini par l'opérateur, issu de ce template |
| Un template est marqué MAIS son `Pages[404]` est vide | Repli sur l'intégré d'Arenet (le catch-all ne sert jamais un corps vide) |
| Le template marqué est supprimé | Le flag disparaît avec lui ; le catch-all revient à l'intégré au prochain rechargement |

### Pourquoi c'est important

Sans le flag, le catch-all servait du texte brut « Not Found - no route configured for this host » (avant v2.9.10), ce qui n'était pas cohérent avec les pages brandées des routes configurées. Avec le flag, les opérateurs obtiennent un branding de bout en bout, même sur les requêtes fautes de frappe / scans / fuites DNS.

---

## « Inspecter le défaut intégré »

Dans la page liste des templates, le défaut intégré apparaît comme une ligne marquée **Built-in** (lecture seule). Clique sur **Aperçu** pour ouvrir l'éditeur en mode lecture seule et inspecter les templates par défaut côte à côte ; clique sur **Dupliquer** pour créer une copie éditable comme point de départ pour ton propre template.

---

## Page de maintenance

La **page de maintenance** est un concept séparé des templates ci-dessus : c'est la **seule page HTML globale** servie sur les réponses `503` pour toute route qu'un opérateur bascule en [état Maintenance](Routes-FR#maintenance-v2170) (v2.17.0). Contrairement aux templates de pages d'erreur (plusieurs, attachables par route), il n'y a qu'**une seule** page de maintenance pour toute l'instance Arenet — chaque route en maintenance sert le même corps.

### La personnaliser

1. Barre latérale → **Réglages** → **Pages d'erreur** (`/settings/error-pages`)
2. Clique sur l'onglet **Maintenance** (à côté de la liste des templates)
3. L'éditeur s'ouvre avec **Arenet Default (built-in)** — une page brandée « Back soon » en thème sombre — préchargée comme point de départ. Un badge **Built-in** la marque comme telle jusqu'à ce que tu enregistres une modification.
4. Édite le HTML dans le panneau CodeMirror ; le panneau **Aperçu** à droite le rend en direct
5. Clique sur **Enregistrer**

Un corps **vide** équivaut à ne pas la personnaliser — Arenet sert le défaut intégré brandé dans ce cas.

### Message de maintenance (par route, avec repli global — v2.18.1)

Le message affiché sur une page de maintenance est **par route** (défini dans le formulaire d'édition de chaque route, section Maintenance) avec le **message global** comme repli partagé. Au-dessus de l'éditeur HTML ici se trouve le champ **Message de maintenance global** — le défaut affiché sur toute route qui n'a pas le sien. Tape « Migration de la base en cours, retour vers 14h00 » une fois et il s'applique à toutes les routes sans message spécifique ; une route qui a besoin d'un autre avis définit le sien dans son formulaire d'édition.

Résolution : **message de la route si défini → sinon le message global → sinon rien** (la page par défaut affiche alors sa phrase générique). Le message est du texte brut : échappé en HTML et ses retours à la ligne transformés en `<br>` au moment de servir, donc il ne peut pas injecter de markup. **Réinitialiser au défaut** efface aussi le message global.

### Auto-refresh (v2.18.1)

La page par défaut intégrée porte une balise `<meta http-equiv="refresh">` construite depuis le Retry-After de la route (via le placeholder `{arenet.maintenance.refresh_meta}`), pour que le navigateur du visiteur se recharge quand la fenêtre est censée finir. Retry-After `0` n'émet aucune balise (un `content="0"` boucherait). Les pages personnalisées ne l'ont pas automatiquement — ajoute ton propre `<meta http-equiv="refresh" content="{arenet.maintenance.retry_after}">` si tu le veux.

### Placeholders de maintenance

Contrairement aux placeholders Caddy `{http.request.*}` / `{time.*}` utilisés dans les templates de pages d'erreur, la page de maintenance a ces placeholders Arenet dédiés :

| Placeholder | S'étend en |
| ----------- | ---------- |
| `{arenet.maintenance.retry_after}` | La valeur Retry-After configurée sur la **route déclenchante**, entier brut en secondes (`86400`), substituée au moment de servir la réponse. À utiliser là où une machine lit la valeur — ton propre `<meta refresh>`, un attribut `data-` |
| `{arenet.maintenance.retry_after_human}` | Le même délai **en mots** : `1 day`, `30 minutes`, `1 hour 30 minutes`. Exact, jamais arrondi. Vide quand Retry-After vaut `0`. **En anglais uniquement** — la page servie n'a aucune locale sur laquelle Arenet pourrait s'appuyer, donc une page non anglophone garde plutôt la forme entière |
| `{arenet.maintenance.message}` | Le message de la route, ou le message global en repli (échappé en HTML, retours à la ligne → `<br>`). Vide si aucun des deux n'est défini |
| `{arenet.maintenance.refresh_meta}` | Une balise `<meta http-equiv="refresh" content="N">` (N = Retry-After) ; vide quand Retry-After vaut `0`. Présente dans le `<head>` de la page par défaut — ajoute-la à une page personnalisée pour l'auto-refresh |

Aucun n'est une expression runtime Caddy — tous sont intégrés dans le corps de la réponse au moment de la construction de la config. `retry_after`, `retry_after_human` et `refresh_meta` sont par route (chaque route affiche *sa propre* valeur dans le HTML partagé par ailleurs identique) ; `message` se résout par-route-puis-global. Les placeholders Caddy `{http.request.*}` / `{time.*}` documentés plus haut fonctionnent aussi toujours dans le corps de la page de maintenance (méthode, URI, UUID de requête, timestamp).

> **Note (sécurité).** Les placeholders Caddy `{env.*}` et `{file.*}` sont **neutralisés** dans les corps de pages de maintenance/erreur fournis par l'opérateur et dans le message global — ils s'affichent en texte littéral au lieu de s'étendre — pour qu'un admin ne puisse pas (accidentellement, ou délibérément si le compte est compromis) faire fuiter un secret d'environnement ou un fichier disque dans la réponse publique.

### Page d'exemple pour démarrer

Une page de maintenance d'exemple soignée et prête à copier est fournie dans le repo : [`docs/examples/maintenance-page-example-fr.html`](https://github.com/barto95100/arenet/blob/main/docs/examples/maintenance-page-example-fr.html) (une version anglaise est disponible dans [`maintenance-page-example-en.html`](https://github.com/barto95100/arenet/blob/main/docs/examples/maintenance-page-example-en.html)). C'est une page sombre animée qui utilise **uniquement** les placeholders qu'Arenet substitue réellement — `{arenet.maintenance.refresh_meta}` dans le `<head>` (auto-refresh), `{arenet.maintenance.message}` (se réduit proprement quand vide, via une règle `.message:empty`), `{arenet.maintenance.retry_after}`, et les variables de requête `{http.request.*}` / `{time.now.year}`. Copie son contenu dans l'éditeur Maintenance et adapte le texte/branding. Un test de non-régression la maintient valide face aux évolutions du sanitizer, donc ce que tu copies est toujours ce qu'Arenet servira réellement.

### Réinitialiser au défaut

Clique sur **Réinitialiser au défaut** pour effacer la page stockée et revenir à vide — le prochain Enregistrer servira à nouveau le défaut intégré brandé. C'est l'équivalent, pour la page de maintenance, de supprimer un template personnalisé.

### Où ça se situe

- La page de maintenance ne fait **pas** partie de la pile de résolution à 3 niveaux des pages d'erreur ci-dessus — elle s'applique uniquement aux routes en maintenance (`503` depuis le handler de maintenance), pas aux erreurs d'origine upstream ni au catch-all.
- Elle passe par le même pipeline d'[assainissement HTML](#assainissement-html) que les templates et les surcharges par route avant d'être persistée.
- Voir [Routes](Routes-FR#maintenance-v2170) pour comment une route entre/sort de maintenance et configure son Retry-After + sa liste d'IPs bypass.

---

## Modèles d'exemple prêts à l'emploi

Arenet fournit un ensemble de **pages d'exemple brandées, prêtes à l'emploi** — une page HTML soignée en thème sombre par code de statut supporté (401, 403, 404, 429, 500, 502, 503, 504). Elles n'utilisent que les placeholders que Caddy substitue au moment de servir la réponse, ne contiennent aucun JavaScript, et passent l'assainisseur sans modification (vérifié). Utilise-les comme point de départ plutôt que d'écrire un template depuis zéro.

### 📁 Récupérer les fichiers

Tous les templates vivent dans le dépôt, dans les deux langues :

**➡️ [`docs/mocks/error-pages/`](https://github.com/barto95100/arenet/tree/main/docs/mocks/error-pages)** — parcourir le dossier

| Statut | Anglais | Français |
| ------ | ------- | -------- |
| 401 Unauthorized | [en/401.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/401.html) | [fr/401.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/401.html) |
| 403 Forbidden | [en/403.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/403.html) | [fr/403.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/403.html) |
| 404 Not Found | [en/404.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/404.html) | [fr/404.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/404.html) |
| 429 Too Many Requests | [en/429.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/429.html) | [fr/429.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/429.html) |
| 500 Internal Server Error | [en/500.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/500.html) | [fr/500.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/500.html) |
| 502 Bad Gateway | [en/502.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/502.html) | [fr/502.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/502.html) |
| 503 Service Unavailable | [en/503.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/503.html) | [fr/503.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/503.html) |
| 504 Gateway Timeout | [en/504.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/504.html) | [fr/504.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/504.html) |

Il y a aussi un catalogue visuel des 8 pages : [en/error-pages-overview.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/en/error-pages-overview.html) · [fr/error-pages-overview.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/error-pages-overview.html) (ouvre le fichier brut dans un navigateur pour le prévisualiser).

> Astuce : sur la page d'un fichier, clique sur le bouton **Raw** (ou **Copy raw file**) pour récupérer tout le HTML, ou **Download raw file** pour le télécharger.

### Comment en utiliser une

1. Ouvre le fichier correspondant au code de statut voulu (par ex. [fr/404.html](https://github.com/barto95100/arenet/blob/main/docs/mocks/error-pages/fr/404.html)) et copie tout le HTML (utilise la vue **Raw**).
2. Barre latérale → **Réglages** → **Pages d'erreur** → **+ Nouveau template** (ou édite un template existant).
3. Colle le HTML dans l'onglet correspondant à ce code de statut (l'onglet `404` pour `404.html`, etc.).
4. Répète pour chaque code que tu veux brander, puis **Enregistre**.
5. Attache le template à une route (voir [Routes](Routes-FR)), ou coche **défaut catch-all** pour brander aussi les hôtes non routés.

Les placeholders à l'intérieur de ces pages (`{http.error.id}`, `{http.request.uuid}`, `{http.request.method}`, `{http.request.uri.path}`, `{http.request.host}`, `{http.request.remote.host}`, `{http.reverse_proxy.status_code}` sur 502/503/504, et `{time.now.year}` dans le pied de page) sont remplis par Caddy au moment de servir la réponse — aucune configuration supplémentaire nécessaire.

> Ce sont des **exemples**, pas les défauts intégrés. Les pages de repli intégrées propres à Arenet (servies quand aucun template n'est configuré) sont les pages minimalistes définies dans `internal/caddymgr/error_pages.go`. Copie un exemple dans un template pour bénéficier de ce branding plus riche.

---

## Voir aussi

- [Routes](Routes-FR) — où attacher un template à une route ; [Route states](Routes-FR#route-states-active-maintenance-disabled) pour comment une route passe en Maintenance
- `internal/caddymgr/error_pages.go` — le défaut intégré + la résolution à 3 niveaux au moment de servir la réponse
- `internal/caddymgr/maintenance.go` — handler 503 de maintenance, bypass `client_ip`, substitution `{arenet.maintenance.retry_after}`
- `internal/storage/error_template.go` — assainisseur + couche de stockage
- `web/frontend/src/routes/settings/error-pages/+page.svelte` — l'UI de l'éditeur de templates + l'onglet Maintenance
- [Référence des placeholders Caddy](https://caddyserver.com/docs/conventions#placeholders) — liste complète des placeholders `{http.request.*}` et `{time.*}`
