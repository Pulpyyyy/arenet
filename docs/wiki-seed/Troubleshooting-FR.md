# Troubleshooting

[English](Troubleshooting) · **🌐 Français**

Playbook de diagnostic pour les symptômes communs d'Arenet. Chaque section nomme le symptôme, la ou les causes probables, et les commandes empiriques pour confirmer + fixer.

Pour les diagnostics spécifiques aux messages de boot, voir [`docs/operations/troubleshooting.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/troubleshooting.md) qui couvre les lignes de log "attendues-mais-surprenantes".

---

## Est-ce l'hôte, ou est-ce Arenet ? (v2.45)

**Réglages → Système** rapporte désormais la machine sur laquelle
Arenet tourne, rafraîchie toutes les cinq secondes : utilisation et
charge du processeur, mémoire, espace libre sur le **répertoire de
données**, plus la mémoire d'Arenet, ses goroutines et son temps de
fonctionnement. C'est le premier endroit à regarder quand les relais
ralentissent ou qu'un rechargement échoue sans raison visible : ça
sépare « l'hôte manque de quelque chose » de « Arenet se comporte
mal » avant d'aller fouiller.

Le chiffre du disque porte volontairement sur le **répertoire de
données**, pas sur `/`. La base, les sauvegardes et les journaux y
vivent tous, et sur une installation qui lui donne son propre volume,
une racine en bonne santé ne dit rien de la place qui restera pour la
prochaine sauvegarde.

**En conteneur, lis l'étiquette de provenance.** `/proc` rapporte
l'*hôte* : un conteneur limité à 512 Mio afficherait sinon les 64 Gio
de la machine — littéralement exact, et inutile quand on cherche
pourquoi Arenet se fait tuer par l'OOM killer. Quand une limite cgroup
existe, Arenet affiche cette limite et le dit ; un quota de processeur
est montré à côté du nombre réel de cœurs de la machine, pour qu'il se
lise comme une restriction et non comme une machine plus petite.

**L'utilisation du processeur affiche un tiret les premières secondes
après un redémarrage.** C'est un taux, et un taux exige deux mesures ;
le panneau préfère ne rien montrer plutôt qu'inventer un chiffre.

---

## UI d'admin pas reachable

### Symptôme
`http://<host>:8001` time out ou refuse la connexion.

### Diagnostic
```bash
# Le binaire tourne-t-il seulement ?
sudo systemctl status arenet      # natif
docker compose ps                  # docker

# Le port est-il bound ?
sudo ss -tlnp | grep 8001

# Depuis l'intérieur de l'host
curl http://127.0.0.1:8001/healthz
```

### Causes probables
- **Bind loopback par défaut** : l'UI d'admin bind `127.0.0.1:8001` par défaut. Depuis le LAN tu as besoin de `ARENET_ADMIN_BIND=0.0.0.0:8001` (systemd) ou le port publié `8001:8001` (docker)
- **Service pas démarré** : `sudo systemctl start arenet` (natif) ou `docker compose up -d` (docker)
- **Firewall** : `sudo ufw status` ou `sudo nft list ruleset | grep 8001`

---

## Les routes retournent 502 Bad Gateway

### Symptôme
Une route retourne 502 même si Arenet lui-même est healthy.

### Diagnostic
```bash
# Test l'upstream directement depuis l'host Arenet
sudo -u arenet curl -v --max-time 5 <upstream-url-from-route-config>

# Compare l'URL upstream dans la config de la route
curl -b /tmp/jar http://127.0.0.1:8001/api/v1/routes | jq '.[] | select(.host=="<your-host>") | .upstreams'

# Check que Caddy atteint l'upstream
docker logs arenet 2>&1 | grep "<upstream-host>" | tail -10
```

### Causes probables
- **Upstream down** : le service backend est offline. Check `systemctl status <backend>` ou le status du container
- **Mauvais port upstream** : l'URL upstream de la route a le mauvais port. Ex. authentik est sur `:9000` HTTP ou `:9443` HTTPS, pas `:80`
- **HTTPS-to-HTTPS sans TLS skip** : l'upstream est HTTPS mais utilise un cert auto-signé. Active **Insecure skip verify** dans la section TLS de la route
- **Health check actif l'a marqué down** : check `/topology` — si le node upstream est rouge, le HC a échoué N fois. Vérifie que l'URI HC + status attendu sont sensibles pour ce backend
- **Network unreachable** : `ping <upstream-ip>` depuis l'host Arenet. Firewall entre les deux ?

---

## Le cert HTTPS ne s'émet pas

### Symptôme
Une nouvelle route avec TLS activée ne sert jamais HTTPS ; le navigateur montre "no cert" ou warning auto-signé.

### Diagnostic
```bash
# Que dit Caddy sur le process ACME ?
docker logs arenet 2>&1 | grep -iE "acme|certificate|tls" | tail -20

# Le port 80 est-il reachable depuis l'extérieur (challenge HTTP-01 en a besoin) ?
curl http://<your-public-ip>/.well-known/acme-challenge/test
# Devrait retourner 404 (Arenet handle le path mais pas de challenge actif right now)
# Si time out, port forwarding cassé
```

### Causes probables
- **Port 80 pas forwarded** : le challenge HTTP-01 nécessite TCP/80 inbound. Ouvre le firewall + la règle NAT du router
- **DNS ne pointe pas sur ton host** : `dig <your-route-host> +short` devrait retourner ton IP publique. Sinon, ACME ne peut pas valider
- **Rate limit Let's Encrypt hit** : l'environnement staging existe pour tester ; les limites production sont 50 certs/semaine/domaine. Check `docker logs arenet | grep "rateLimited"`. Attends, ou utilise DNS-01 avec un apex wildcard
- **DNS-01 sans creds provider** : `acmeChallenge` de la route est `dns-01` mais aucun provider configuré. Settings → DNS Providers → câble OVH
- **Héritage wildcard cassé** : la route est sous un managed apex mais `acmeChallenge` est `http-01` au lieu de `inherited` (ou cert wildcard pas encore émis)

---

## Le login SSO OIDC échoue

### Symptôme
Click "Sign in with SSO" → soit une page d'erreur de l'IdP, soit retour sur `/login?error=invalid_state` / `idp_unreachable`.

### Diagnostic
```bash
# Check le fetch de discovery depuis le côté Arenet
sudo -u arenet curl -v --max-time 10 \
  "https://<your-idp>/<path>/.well-known/openid-configuration" 2>&1 | tail -20

# Check les logs Arenet
sudo journalctl -u arenet --since "5 min ago" | grep -i oidc
```

### Causes probables
- **Timeout du fetch de discovery** : IdP unreachable. Voir les pièges communs de [OIDC SSO](OIDC-SSO-FR)
- **`invalid_state`** : le cookie state n'a pas survécu au round-trip IdP. Généralement un mismatch de domaine (le redirect_uri doit être sur le même domaine que l'UI Arenet depuis laquelle tu as initié le login)
- **`idp_unreachable`** : same as timeout du fetch de discovery, ou l'IdP a retourné une erreur sur l'échange du code
- **Identité pas dans l'allowlist** : check la page Users. Ajoute l'email + rôle

Les lignes de log OIDC depuis v2.8.3 enrichissent chaque échec avec `issuer_url=...` + `client_id=...` pour que tu saches exactement quelle config échoue.

---

## Le WAF bloque des requêtes légitimes (faux positifs)

### Symptôme
Une requête spécifique qui devrait passer reçoit 403 avec la page d'erreur brandée Arenet.

### Diagnostic
1. Identifie quelle règle CRS a fired : `/security` → filter par route + temps récent → regarde les événements
2. Note le `rule_id` (ex. `942100`, `920170`)
3. Note la `category` (SQLi, attack-protocol, ...) et regarde le payload qui a matché

### Fix
Trois portes de sortie, scope croissant (voir [WAF](WAF-FR) pour les détails) :

- **Exclure un ID de règle** : Route → WAF → Excluded rule IDs → ajoute l'ID
- **Exclure une famille de tags entière** : Route → WAF → Excluded tags → choisis le tag depuis autocomplete
- **Désactiver CRS entièrement** : Route → WAF → Disable OWASP CRS ✅ (dernier recours, réduit la sécurité)

Si ta route est genuinely public-facing, préfère le scope le plus serré (rule ID > tag > full disable).

---

## L'alerte ne fire jamais malgré la condition qui trip

### Symptôme
La condition d'une rule est true (vérifiée via l'évaluation manuelle de la source) mais aucune alerte ne land dans Discord / email.

### Diagnostic
1. `/alerting` → onglet Rules → clique ta rule → **Test rule** → le message de test land-t-il ?
2. Si le test fonctionne : check l'onglet **History** → la rule a-t-elle été évaluée récemment ? Quelle valeur ?
3. Check le cooldown : la rule a peut-être fired plus tôt et est en cooldown
4. `journalctl -u arenet --since "10 min ago" | grep -i alerting`

### Causes probables
- **Cooldown actif** : le défaut est 300s. Attends, ou baisse temporairement le cooldown pour tester
- **Source retourne une valeur inattendue** : les source params peuvent ne pas matcher le state courant. Ex. `cert_renewal_failed` avec `domain=specific.example.com` filtre strictement — assure-toi que la string domain est exacte
- **Channel désactivé** : onglet Channels → check le toggle Enabled du channel
- **Watcher pas en train de tourner** : extrêmement rare ; signifierait qu'Arenet n'a pas boot le watcher d'alerting (check les logs pour `alerting: watcher started`)
- **Rule désactivée** : onglet Rules → check le toggle Enabled de la rule

---

## Usage CPU / RAM élevé

### Symptôme
Arenet utilise plus de ressources qu'attendu.

### Diagnostic
```bash
# CPU + RAM par process
top -p $(pgrep -f arenet)

# Métriques par route : laquelle est hot ?
curl -b /tmp/jar "http://127.0.0.1:8001/api/v1/metrics/per-host?windowSecs=300" | jq

# Profile goroutine + heap (si pprof exposé)
curl http://127.0.0.1:8001/debug/pprof/goroutine?debug=1
```

### Causes probables
- **WAF sur chaque route** : Coraza est le plus gros consommateur (~10-30 MB par config WAF unique). N routes avec N configs WAF distinctes = N × 30 MB. Le WAF pool dedup par SHA de directives-string — les routes avec config identique partagent une instance Coraza. Réduis en settant le même profile WAF à travers des routes similaires
- **Gros upload sans streaming mode** : un push Docker registry de 4GB sans `uploadStreamingMode=true` va balloon la RAM à 3.5GB. Active upload streaming sur les routes registry / serveur de fichiers
- **Decision list CrowdSec très large** : si tu as des millions de décisions communauté cachées, le bouncer peut utiliser 100+ MB. Tune la rétention de décisions de l'agent
- **Croissance de la table d'événements SQLite** : `du -sh /var/lib/arenet/observability.db` — si énorme, la loop de rétention peut avoir stallé. Check `journalctl | grep -i prune`

---

## Restore échoue avec des erreurs `sentinel:...`

### Symptôme
Le restore retourne 400 avec un message comme : "Restore rejected: sentinel `oidc-config:default:client_secret` could not be resolved from the live store..."

### Cause
Tu as exporté un snapshot **redacted** (Export without secrets) et tu essaies de restore sur une instance fresh OU sur une instance qui n'a pas les valeurs live originales à hériter.

### Fix
Two paths forward :

1. **Tick "Allow incomplete restore"** avant de cliquer Restore. Les sentinels qui ne peuvent pas hériter seront CLEARED ; le prochain boot print un WARN listant les champs cleared. Tu re-save ensuite manuellement ces secrets via l'UI.

2. **Re-export depuis l'instance source avec secrets included** (Export with secrets…) et utilise ce fichier. Restores anywhere, pas besoin d'héritage.

Voir [Backup & Restore](Backup-Restore-FR) pour l'explainer complet de résolution sentinel.

---

## Le bouncer CrowdSec bloque ta propre IP

### Symptôme
Tu ne peux pas atteindre l'UI Arenet depuis ta connexion maison.

### Diagnostic
```bash
# Check si ton IP est dans la decision list
docker exec crowdsec cscli decisions list | grep $(curl -s ifconfig.me)
```

### Fix
```bash
# Delete la décision
docker exec crowdsec cscli decisions delete --ip $(curl -s ifconfig.me)

# Whitelist en permanent (recommandé pour tes IPs maison)
docker exec crowdsec cscli postoverflows install crowdsecurity/whitelists
# Puis édite /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
```

Si tu t'es complètement lockout, tu peux temporairement désactiver l'intégration CrowdSec dans Arenet (Settings → CrowdSec → Disable + Save) ce qui laisse le bouncer off jusqu'à ce que tu re-actives.

---

## Changer l'adresse LAPI arrête silencieusement tout blocage

### Symptôme
Vous avez modifié l'URL de la LAPI dans Réglages → CrowdSec, enregistré, et CrowdSec ne bloque plus rien. Le journal affiche la nouvelle adresse mais les erreurs nomment l'ancienne :

```
"address":"http://10.66.0.1:8080"
"error":"... Get \"http://127.0.0.1:8080/v1/decisions/stream?...\": connection refused"
```

### Cause
L'enregistrement recharge Caddy et le bouncer est reconstruit avec la nouvelle URL, mais son client de flux continue d'appeler la précédente jusqu'au redémarrage du **processus**. Il annonce la nouvelle adresse tout en utilisant l'ancienne.

Le bouncer **laisse passer par conception**, donc pendant tout ce temps le trafic circule sans aucune protection et rien d'autre dans l'interface ne le signale.

### Fix
```bash
sudo systemctl restart arenet          # systemd
docker compose restart arenet          # Docker
```

Depuis la v2.51, le panneau de réglages affiche un avertissement disant exactement cela après un enregistrement qui déplace l'adresse. Sur une version antérieure, redémarrez systématiquement après tout changement d'URL de LAPI.

Vérifiez ensuite que le bouncer a réellement suivi — et lisez le **journal**, pas `cscli bouncers list` :

```bash
journalctl -u arenet --since "2 min ago" | grep -i crowdsec
```

Aucun `connection refused` et une ligne `using API key auth` portant la nouvelle adresse : c'est réussi.

`cscli bouncers list` est trompeur ici : CrowdSec indexe un bouncer par nom **et par IP**, donc après le déplacement les pulls alimentent une seconde ligne (`arenet@<nouvelle-ip>`) tandis que la ligne d'origine reste figée à son dernier pull, définitivement. Un horodatage périmé sur l'ancienne ligne n'est pas un échec : c'est une ligne que plus rien n'écrit.

---

## CrowdSec ne bannit rien qui vienne de chez vous

### Symptôme
CrowdSec est configuré, le bouncer est connecté, mais aucune décision n'apparaît jamais en dehors de celles importées de la liste communautaire. Rien de local n'est jamais détecté.

### Diagnostic
```bash
# 1. Arenet écrit-il un journal d'accès ? (désactivé par défaut)
#    Réglages → Sécurité → Journal d'accès HTTP — lisez le chemin affiché.
sudo ls -l /var/log/arenet/access.log

# 2. Grossit-il ? Chargez une de vos routes pendant que ceci tourne.
sudo tail -f /var/log/arenet/access.log

# 3. L'agent le lit-il ?
sudo cscli metrics | grep -A 5 Acquisition

# 4. L'agent peut-il le lire ? Caddy écrit le fichier en 0600.
systemctl show crowdsec -p User
sudo cscli explain --file /var/log/arenet/access.log --type caddy | head -20
```

### Fix
Les quatre vérifications ci-dessus échouent de quatre façons différentes, chacune avec sa réponse.

1. **Aucun fichier.** Le journal d'accès est désactivé par défaut — il enregistre l'IP et les URL de chaque visiteur, Arenet ne l'active donc pas à votre place. Activez-le dans Réglages → Sécurité, et notez que le chemin affiché là est celui à utiliser : il diffère entre une installation systemd (`/var/log/arenet/access.log`) et un conteneur (dans le volume de données).
2. **Le fichier existe mais reste vide.** Les requêtes n'atteignent pas la destination. Vérifiez que l'enregistrement a bien rechargé Caddy — le journal fait partie de la configuration émise. Signalez ce cas : c'est un bug, pas un réglage.
3. **Le compteur d'acquisition reste à zéro.** L'agent ne lit pas. Vérifiez que le chemin dans `/etc/crowdsec/acquis.d/` correspond exactement, et que `labels: type: caddy` est présent. Sous Docker, l'agent a besoin du volume monté en lecture seule (`arenet-data:/var/lib/arenet:ro`).
4. **`cscli explain` signale un échec d'analyse.** Installez la collection : `sudo cscli collections install crowdsecurity/caddy`.

La cause la plus fréquente de loin est celle des **permissions** : Caddy crée le fichier en `0600` appartenant à l'utilisateur Arenet, donc l'agent doit être root. Il l'est par défaut avec une installation par paquet, mais pas si vous l'avez changé.

À savoir : les échecs de connexion à l'**administration d'Arenet** ne sont jamais dans ce journal — le plan d'administration est servi séparément et n'atteint jamais Caddy. Ils sont couverts par Security Automation, dont toutes les règles sont **désactivées par défaut**, ce qui est l'autre raison pour laquelle un opérateur ne voit aucune décision `arenet/…`. Voir [CrowdSec](CrowdSec-FR).

---

## Le fichier de backup est énorme (> 10 MB)

### Symptôme
Ton backup de config est beaucoup plus large qu'attendu.

### Cause
L'export inclut chaque user + chaque métadata d'événement cert + chaque body de template de page d'erreur. Les plus gros contributeurs :
- Templates de pages d'erreur custom (cap 1 MiB par body × 8 codes × N templates)
- Beaucoup d'users avec display names + emails custom

### Fix
- Trim les templates de pages d'erreur unused : `/settings/error-pages` → delete les templates qu'aucune route n'utilise
- Trim les users stales : `/users` → retire les ex-collaborateurs

Les fichiers cert + tables d'événements SQLite ne sont PAS dans le backup donc ils ne contribuent pas.

---

## "Regarder ça depuis l'extérieur d'Arenet"

Si rien de ce qui précède ne match ton symptôme :

1. **Reproduis empiriquement** — request exacte + response exacte + lignes de log exactes
2. **Inspecte l'audit log** à `/audit` — chaque changement de config est là avec acteur + before/after
3. **Check le `/logs` unifié** — événements WAF / rate-limit / auth / cert pour la route affectée, filter par temps + IP source
4. **Ouvre une issue** à https://github.com/barto95100/arenet/issues avec :
   - Version Arenet (`docker exec arenet arenet --version` ou `arenet --version`)
   - Recette de reproduction
   - Snippet de log pertinent (`journalctl -u arenet --since "10 min ago" | grep <route-host>`)
   - Snapshot sanitized si ça aide (export → redact tes secrets manuellement avant de partager)

---

## See also

- [`docs/operations/troubleshooting.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/troubleshooting.md) — warnings de boot + lignes de log attendues qui ont l'air scary mais ne le sont pas
- [`docs/operations/http3.md`](https://github.com/barto95100/arenet/blob/main/docs/operations/http3.md) — debug spécifique HTTP/3
- [Installation](Installation-FR) — issues côté install
- [WAF](WAF-FR) — triage des faux positifs WAF
- [OIDC SSO](OIDC-SSO-FR) — pièges communs spécifiques OIDC
- [Backup & Restore](Backup-Restore-FR) — modes d'échec de restore
