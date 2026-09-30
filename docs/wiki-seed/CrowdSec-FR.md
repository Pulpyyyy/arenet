# CrowdSec

[English](CrowdSec) · **🌐 Français**

[CrowdSec](https://www.crowdsec.net) est un service de réputation IP community-powered : un IDS collaboratif qui laisse tes hosts partager du threat intelligence. Arenet ship un [bouncer CrowdSec](https://github.com/hslatman/caddy-crowdsec-bouncer) natif qui bloque les requêtes depuis les IPs que la communauté CrowdSec a flaguées.

**L'agent CrowdSec lui-même tourne séparément** — en service Linux installé depuis le dépôt CrowdSec, ou en conteneur Docker. Les deux sont couverts ci-dessous. Arenet n'embarque que le *bouncer* : le composant qui interroge l'API locale (LAPI) de l'agent et applique ses décisions.

---

## Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│  Arenet         │ ────▶ │  CrowdSec       │ ◀──── │  CrowdSec Hub    │
│  (bouncer)      │ LAPI  │  agent          │       │  (blocklists     │
│                 │ LAPI  │  (votre hôte)   │       │   communauté)    │
└─────────────────┘       └─────────────────┘       └──────────────────┘
   │                          │
   │ si IP dans decision      │ scenarios triggerent
   │ → reject avec 403        │ sur les lignes de log parsées
   ▼                          ▼
   Client                     Décisions locales
                              (IPs bannies)
```

L'agent analyse vos journaux locaux (authentification, serveur web…), se déclenche sur des scénarios (force brute, balayage, exploitation) et crée des **décisions** : bannir telle IP pendant tel temps. Le bouncer interroge l'agent toutes les N secondes et applique ces décisions.

Tu reçois aussi des **décisions communauté** gratuitement : l'agent fetch la blocklist curated du hub CrowdSec, des IPs actuellement abusives dans la communauté globale. Effectivement une blocklist temps réel maintenue par des milliers d'opérateurs dans le monde.

---

## Quick start

### 1. Installer et démarrer l'agent CrowdSec

L'agent tourne sur la même machine qu'Arenet, ou sur n'importe quelle
machine qu'Arenet peut joindre. Choisissez la voie qui correspond à la
façon dont Arenet lui-même est installé.

#### Paquet Linux — Arenet en service systemd ou en binaire

```bash
curl -s https://install.crowdsec.net | sudo sh   # ajoute le dépôt CrowdSec
sudo apt install crowdsec                        # Debian / Ubuntu
# sudo yum install crowdsec                      # RHEL / CentOS / Fedora
sudo systemctl enable --now crowdsec
```

Le paquet démarre l'agent et son API locale. Vérifiez qu'elle écoute :

```bash
ss -tlnp | grep 8080
# tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("crowdsec",pid=…))
```

La configuration se trouve dans `/etc/crowdsec/`, la base dans
`/var/lib/crowdsec/data/`. Journaux de l'agent :
`sudo journalctl -u crowdsec -f`.

Voir le [guide d'installation Linux officiel](https://docs.crowdsec.net/u/getting_started/installation/linux/)
pour les autres distributions.

#### Docker — Arenet en conteneur

```bash
docker run -d --name crowdsec \
  -e GID="$(getent group docker | cut -d: -f3)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/log:/var/log:ro \
  -v crowdsec-db:/var/lib/crowdsec/data \
  -v crowdsec-config:/etc/crowdsec \
  -p 127.0.0.1:8080:8080 \
  crowdsecurity/crowdsec
```

Dans les deux cas, l'API locale de l'agent est maintenant sur
`http://127.0.0.1:8080`.

> **Toutes les commandes `cscli` de cette page sont écrites pour
> l'installation par paquet.** Avec l'agent en Docker, préfixez-les par
> `docker exec crowdsec` : `sudo cscli decisions list` devient
> `docker exec crowdsec cscli decisions list`.

### 2. Déclarer le bouncer Arenet

```bash
sudo cscli bouncers add arenet
```

La commande affiche une clé d'API — copiez-la.

### 3. Configure Arenet

1. Sidebar → **Settings** → section **CrowdSec**
2. **LAPI URL** : `http://127.0.0.1:8080` (ou l'adresse de ton agent)
3. **Clé d'API** : collez la clé obtenue à l'étape 2
4. **Bouncer name** : `arenet` (correspond à la registration cscli)
5. **Timeout** : `5s` (défaut ; combien de temps le bouncer attend la réponse LAPI)
6. **Test connection** → devrait retourner ✅
7. **Save**

Le bouncer est actif en une trentaine de secondes. Toute requête entrante dont l'IP source figure dans les décisions courantes de CrowdSec reçoit un **403 Forbidden** avant même d'atteindre le WAF ou les gestionnaires de route.

Depuis la **v2.26.0**, un visiteur bloqué reçoit la **page d'erreur personnalisée** d'Arenet au lieu d'une réponse vide : une décision `ban` sert la page **403** de la route, une décision `throttle` sa page **429** (avec un en-tête `Retry-After` égal à la durée de la décision). C'est la page choisie pour la route dans ses réglages de pages d'erreur, ou celle d'Arenet par défaut — les mêmes pages que pour le filtre IP et les erreurs d'upstream (voir [Pages d'erreur personnalisées](Custom-Error-Pages-FR)).

---

## Trois briques, et laquelle vous avez

C'est la question à laquelle l'écran de réglages ne répond pas seul, parce que CrowdSec apparaît à **trois** endroits dans Arenet, qui ne font pas la même chose.

| Brique | Sens | Identifiants | Rôle |
|---|---|---|---|
| **Bouncer** (Réglages → CrowdSec) | Arenet **lit** | `cscli bouncers add arenet` | Refuse les IP que LAPI désigne. C'est l'application. |
| **Journal d'accès** (Réglages → Sécurité) | Arenet **écrit un fichier** | aucun | Donne à CrowdSec des requêtes à analyser, pour qu'*il* détecte. |
| **Security Automation** (Réglages → Sécurité) | Arenet **écrit dans LAPI** | `cscli machines add arenet-writer` | Arenet décide lui-même et pousse des bannissements. |

**Pourquoi deux jeux d'identifiants pour la même LAPI.** C'est le modèle d'authentification de CrowdSec, pas une bizarrerie d'Arenet : un *bouncer* ne peut que lire des décisions, une *machine* (watcher) peut créer des alertes. Une clé de bouncer ne permet pas d'écrire, donc pousser un bannissement exige la seconde.

**Avec le bouncer seul**, vous avez la liste communautaire. C'est une vraie couche — des milliers d'opérateurs signalant les IP actuellement malveillantes — mais rien de ce qui concerne *votre* machine n'est jamais détecté.

### Après une mise à jour en v2.56 — les journaux déjà écrits

Le masquage s'applique à partir du rechargement. Tout ce qui a été écrit avant reste en clair sur le disque, et Arenet ne peut pas le réécrire : ces fichiers appartiennent au système de fichiers, pas à la base.

**Les stores d'Arenet ne demandent rien.** Le store d'événements WAF est re-masqué par une migration au premier démarrage, et un secret déjà enregistré y est masqué sur place.

**Les fichiers de journal sont à votre charge.** Les copies tournées comptent, y compris compressées :

```bash
# Vérifiez d'abord s'il y a eu fuite, avant de supprimer quoi que ce soit.
sudo zgrep -lE '(access_token|id_token|refresh_token)=' /var/log/arenet/access.log*

# Puis, si oui : videz le fichier courant et supprimez les fichiers tournés.
sudo truncate -s 0 /var/log/arenet/access.log
sudo rm -f /var/log/arenet/access.log.*
```

Videz le fichier courant plutôt que de le supprimer : Caddy le tient ouvert, et le supprimer laisse le processus écrire dans un inode que plus rien ne peut lire.

**Ce que CrowdSec a déjà ingéré est un store distinct.** L'acquisition lit le fichier, et la ligne brute est conservée avec toute alerte déclenchée par les scénarios : un jeton peut donc survivre dans la base de CrowdSec après que vous avez nettoyé le journal. Vérifiez avec `sudo cscli alerts list`, examinez une alerte avec `sudo cscli alerts inspect <id> -d`, et supprimez celles qui portent un identifiant avec `sudo cscli alerts delete --id <id>`. Arenet n'a aucun accès à cette base — elle est à l'agent.

Si la fenêtre a été courte et que le journal n'a pas quitté la machine, juger que cela ne vaut pas l'effort est un choix défendable. Faire tourner le jeton dans l'application concernée est le choix rigoureux : un identifiant qui a atteint un fichier que vous ne maîtrisez pas entièrement vaut mieux être remplacé que poursuivi.

**Le journal d'accès** est ce qui permet aux scénarios de CrowdSec de voir votre trafic : balayages, force brute contre les applications derrière Arenet, tentatives d'exploitation connues. Arenet n'émettait aucun journal d'accès avant la **v2.50**, ce qui explique qu'un agent pouvait rester en place des mois sans jamais déclencher un scénario.

**Security Automation** est l'autre détecteur, et il travaille à partir de ce qu'Arenet comprend déjà plutôt que des requêtes brutes : événements WAF, événements de limitation de débit, et échecs de connexion à l'administration d'Arenet. Quand une IP source franchit un seuil dans une fenêtre, Arenet pousse un bannissement dans LAPI avec `origin=arenet` et un scénario nommé `arenet/…`. Il déduplique, et si vous levez un bannissement à la main il se retient au lieu de le repousser aussitôt.

> **Toutes les règles d'automation sont désactivées par défaut.** Si vous avez renseigné les identifiants du watcher sans jamais voir de décision `arenet/…`, c'est presque certainement la raison : les identifiants seuls ne font rien.

Les deux détecteurs ne se recouvrent pas : Security Automation voit ce qu'Arenet a déjà qualifié, CrowdSec voit ce qu'Arenet se contente de transmettre.

### Un mot sur « watcher »

Le terme désigne deux choses sans rapport dans Arenet. Un **watcher** CrowdSec est une machine autorisée à écrire dans LAPI. Le **watcher** de la page [Alerting](Alerting-FR) est la boucle qui évalue vos règles d'alerte toutes les 30 secondes. Même mot, aucun lien.

---

## Activer la détection

1. **Réglages → Sécurité → Journal d'accès HTTP** → cochez *Écrire un journal d'accès*.
2. Lisez le **chemin affiché par la carte**. Ne le devinez pas : le défaut est `/var/log/arenet/access.log` sur une installation systemd et `/var/lib/arenet/logs/access.log` dans le conteneur sous Docker, et seul le processus en cours sait lequel s'applique.
3. Vérifiez **Paramètres d'URL masqués**. La valeur de chaque paramètre listé est remplacée par `REDACTED` dans l'URI journalisée. La liste est pré-remplie, parce que certaines applications transportent un secret dans l'URL : Vaultwarden envoie le jeton de session de l'utilisateur sous la forme `/notifications/hub?access_token=eyJ...`, et sans masquage le journal enregistre un identifiant vivant dans un fichier que CrowdSec lit aussi. La requête transmise au backend n'est pas modifiée — la substitution a lieu dans l'encodeur du journal.
4. Enregistrez. Arenet recharge Caddy — le journal fait partie de la configuration émise, donc rien n'apparaît avant ce rechargement.
5. Sur la machine CrowdSec :

```bash
sudo cscli collections install crowdsecurity/caddy
```

```yaml
# /etc/crowdsec/acquis.d/arenet.yaml
filenames:
  - /var/log/arenet/access.log      # le chemin de l'étape 2
labels:
  type: caddy
```

```bash
sudo systemctl restart crowdsec
```

5. Vérifiez que l'agent lit réellement :

```bash
sudo cscli metrics | grep -A 5 Acquisition
```

Le fichier doit apparaître avec un compteur de lignes qui **augmente**. Zéro signifie que l'agent n'arrive pas à le lire — voir [Troubleshooting](Troubleshooting-FR).

**Le journal est désactivé par défaut, volontairement.** Il enregistre l'adresse IP de chaque visiteur et les URL demandées. C'est ce dont un moteur de détection a besoin, et ce sont aussi des données personnelles sur votre disque ; lequel des deux compte le plus vous appartient, ce n'est pas à un défaut d'en décider. La rotation n'est pas optionnelle — 10 Mo sur 5 fichiers compressés par défaut, et le formulaire affiche le plafond correspondant.

**Docker** : montez le volume en lecture seule dans l'agent plutôt que d'utiliser un chemin de l'hôte —

```yaml
crowdsec:
  volumes:
    - arenet-data:/var/lib/arenet:ro
```

**Ce qui n'est pas dans ce journal** : l'interface d'administration d'Arenet, servie séparément et qui n'atteint jamais Caddy. Les échecs de connexion à l'administration sont couverts par Security Automation.

---

## Plusieurs machines, une seule liste de décisions

Arenet est le reverse proxy : toutes les requêtes arrivent par lui. C'est donc l'endroit naturel pour **appliquer** — et cela signifie que la détection peut se faire n'importe où, puisque quoi que trouve une machine, c'est chez Arenet que le blocage évite réellement du travail.

Concrètement : une autre machine, avec Traefik et des conteneurs, détecte une attaque, écrit la décision dans la LAPI que lit Arenet, et **Arenet refuse cette IP à la réception**. La requête n'atteint jamais l'autre machine.

C'est le modèle multi-serveurs de CrowdSec lui-même : plusieurs agents peuvent alimenter une LAPI, et plusieurs bouncers peuvent la lire. Rien là-dedans n'est spécifique à Arenet.

> **Arenet ne lit qu'une seule LAPI.** Il ne peut pas en agréger deux. Les agents des autres machines doivent donc écrire *dans* celle que lit Arenet, et non l'inverse.

### Brancher une autre machine

Sur l'autre machine, un agent **sans LAPI locale** :

```bash
sudo cscli lapi register -u http://<machine-arenet>:8080
# puis dans /etc/crowdsec/config.yaml, sous api.server :
#   enable: false
sudo systemctl restart crowdsec
```

Les identifiants atterrissent dans `/etc/crowdsec/local_api_credentials.yaml`. Sur la machine Arenet, validez la machine et faites écouter la LAPI au-delà de la boucle locale :

```bash
sudo cscli machines list
sudo cscli machines validate <nom-de-la-machine>
# /etc/crowdsec/config.yaml — api.server.listen_uri
```

**N'exposez pas la LAPI sur l'internet.** Elle accepte des écritures et distribue votre politique de blocage. Établissez un tunnel WireGuard entre les machines et faites écouter la LAPI sur l'adresse du tunnel uniquement ; à défaut, TLS plus un pare-feu restreint à l'adresse de l'autre machine.

### ⚠️ L'erreur qui coupe tout

Si tout le trafic atteint l'autre machine **à travers Arenet**, alors son serveur web ne voit plus vos visiteurs : il voit **Arenet**. Son agent CrowdSec analyse des journaux où chaque attaque semble venir d'Arenet, bannit Arenet, écrit ce bannissement dans la LAPI partagée, et le bouncer d'Arenet l'applique contre lui-même.

Tous les conteneurs derrière deviennent injoignables, et la cause n'a l'air de rien.

Trois choses, dans cet ordre d'importance :

1. **Mettez Arenet en liste blanche d'abord, comme filet.** Faites-le *avant* de brancher le second agent, pour que rien ne puisse bannir votre point d'entrée même si le reste est mal réglé.

   ```bash
   sudo cscli postoverflows install crowdsecurity/whitelists
   # puis ajoutez l'adresse d'Arenet dans
   # /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
   ```

2. **Faites consigner la vraie IP du client par l'autre serveur**, en lui faisant reconnaître Arenet comme proxy amont — `forwardedHeaders.trustedIPs` chez Traefik, `set_real_ip_from` chez nginx. Arenet envoie toujours `X-Forwarded-For` : l'information est là, c'est au backend de l'utiliser au lieu de l'adresse de connexion.

3. **Vérifiez que son parseur lit bien ce champ**, et non l'adresse de socket :

   ```bash
   sudo cscli explain --file /var/log/traefik/access.log --type traefik | head -20
   ```

   Si l'IP source extraite est celle d'Arenet, arrêtez-vous et corrigez l'étape 2 avant d'aller plus loin.

### Pourquoi s'embêter, si tout passe déjà par Arenet

Parce que les deux étages ne voient pas la même chose. Arenet voit la **forme** du trafic HTTP : balayages, rafales de 404, mauvais protocole sur un relai de niveau 4. Les applications derrière voient le **sens** : un échec de connexion WordPress, un 401 applicatif, une API maltraitée d'une façon parfaitement bien formée vue de l'extérieur.

La détection appartient à l'endroit où se trouve l'information. L'application appartient à la porte d'entrée.

---

## Ce qui se fait bloquer

Le bouncer applique **les décisions dont l'agent dispose**. Les scénarios installés par défaut (après `cscli scenarios install crowdsecurity/http-cve`, par exemple) couvrent :

- Brute-force sur SSH / pages d'auth web
- Scanning (nmap, masscan, scanners web vuln)
- Tentatives d'exploit connues (scenarios tagués CVE)
- Blocklist communauté : IPs actuellement abusives à travers le réseau CrowdSec

Tu peux étendre avec des scenarios custom — voir [docs CrowdSec](https://docs.crowdsec.net/docs/scenarios/intro).

---

## Observabilité

Chaque block CrowdSec émet une ligne `decision_event` dans la table SQLite `decision_event` :

- `ts` — timestamp
- `src_ip` — IP bannie
- `reason` — nom du scenario (ex. `crowdsecurity/http-bf`)
- `duration` — longueur du ban
- `origin` — `local` (scenarios de ton agent) ou `crowdsec` (blocklist communauté)

La page `/security/decisions` rend ces événements avec filtre par origin + scenario + temps. Le `/logs` unifié les montre à côté des événements WAF / auth / rate-limit.

---

## Vérifier que l'intégration fonctionne

Bannissez votre propre IP une minute et regardez une route vous refuser.

**1. Trouvez votre adresse — depuis la machine avec laquelle vous allez
naviguer, pas depuis le serveur.**

`curl -s ifconfig.me` lancé *sur l'hôte Arenet* retourne l'adresse
publique **du serveur**, pas celle avec laquelle votre navigateur arrive.
La bannir revient à bannir le serveur. Lancez la commande là où vous
êtes assis :

```bash
curl -s https://ifconfig.me        # sur votre poste, PAS sur le serveur
curl -4 -s https://ifconfig.me     # votre IPv4, précisément
curl -6 -s https://ifconfig.me     # votre IPv6, précisément
```

Si votre navigateur atteint le site en IPv6, bannissez l'adresse IPv6 :
un bannissement sur la mauvaise famille d'adresses ne fait absolument
rien, et c'est la raison la plus fréquente pour laquelle ce test semble
échouer.

**2. Bannissez-la, sur l'hôte Arenet :**

```bash
sudo cscli decisions add --ip <l-adresse-de-l-etape-1> --duration 60s
sudo cscli decisions list          # vérifiez que Scope:Value est bien celle attendue
```

**3. Chargez une de vos routes configurées** depuis cette machine →
**403**. Au bout de 60 s le bannissement expire et la route répond de
nouveau normalement.

> **Un 404 au lieu d'un 403 n'est pas un échec.** Le bouncer s'exécute
> dans la chaîne de chaque route, il ne voit donc que les requêtes qui
> correspondent à une route que vous avez configurée. Tout le reste — un
> hôte inconnu, un chemin qui n'appartient à aucune route — est traité
> par le 404 attrape-tout d'Arenet avant que CrowdSec ne soit consulté.
> Testez sur une route qui existe.

---

## Réglage : que faire quand CrowdSec bloque des utilisateurs légitimes

CrowdSec est communautaire — il arrive qu'une IP soit bannie globalement
pour un comportement que vos propres utilisateurs n'ont pas. Vous avez
deux soupapes.

### Mettre une IP en liste blanche

```bash
sudo cscli decisions delete --ip <ip-de-l-utilisateur>
sudo cscli postoverflows install crowdsecurity/whitelists
# Puis éditer /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
# pour y ajouter l'IP ou le CIDR de l'utilisateur.
# En Docker, ce fichier est dans le volume crowdsec-config :
#   docker exec -it crowdsec vi /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
```

### Désactiver le bouncer sur une route

CrowdSec est aujourd'hui **global** dans Arenet : toutes les routes ou
aucune. Pour l'écarter sur une route précise, il faut soit placer cette
route sur une autre instance d'Arenet, soit mettre les IP source en liste
blanche au niveau de l'agent CrowdSec.

Un toggle CrowdSec par route est dans le backlog V3 ; ouvre une issue si tu trouverais ça utile.

---

## Comportement fallback (LAPI down)

Quand l'agent est injoignable — coupure réseau, plantage, redémarrage — le bouncer **laisse passer par défaut** : les requêtes circulent comme si CrowdSec était désactivé. C'est délibéré (`enable_hard_fails: false`) : le trafic légitime ne doit pas tomber parce que l'agent a une mauvaise journée.

La carte CrowdSec du tableau de bord indique l'état de l'agent (✅ joignable / ⚠️ injoignable, avec l'horodatage du dernier succès). Ajoutez une règle d'[alerte](Alerting) sur `system_health == degraded` pour être prévenu par Discord ou courriel quand l'agent décroche.

---

## See also

- [WAF](WAF-FR) — defense en couches ; le WAF catche ce que CrowdSec ne catche pas
- [Country Block](Country-Block-FR) — couche geo-fence au-dessus de CrowdSec
- [Alerting](Alerting) — pager quand l'agent est down
- [Docs officielles CrowdSec](https://docs.crowdsec.net) — install agent, scenarios, hub
- [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) — le module Caddy qu'Arenet utilise
- `internal/crowdsec/` — wrapping d'Arenet (sink, adaptateur d'observabilité)
