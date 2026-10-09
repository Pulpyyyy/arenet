# Mettre à jour Arenet

[English](Updates) · **🌐 Français**

Arenet est livré comme un binaire / image de conteneur unique. **La mise à jour est une action manuelle, pilotée par l'opérateur** — Arenet ne télécharge ni n'installe jamais une mise à jour tout seul. Le [vérificateur de mises à jour opt-in](DNS-Providers-FR#rester-à-jour) (v2.12.3) ne fait que te *notifier* qu'une version stable plus récente existe ; cette page explique comment effectuer la mise à niveau, en toute sécurité.

> **Pourquoi pas d'auto-update ?** Voir [Notes de sécurité](#notes-de-sécurité) ci-dessous. En bref : auto-mettre à jour un reverse proxy revient à donner à un service exposé au réseau le privilège d'écraser son propre binaire et de se redémarrer — une grande surface d'attaque et un risque supply-chain. Comme nginx, Traefik, Caddy et Postgres, Arenet te laisse la décision (et le timing) de la mise à niveau.

---

## 0. Avant de commencer : vérifie ta version actuelle

Il n'y a **pas de flag `--version`**. Lis la version en cours via l'un de :

- **UI** — *Réglages → Mises à jour* affiche la version actuelle (et la dernière disponible, si le checker est activé).
- **API** — `GET /api/v1/system/version` (session admin) → `{"current": "vX.Y.Z", ...}`.
- **Logs** — `journalctl -u arenet | grep "Arenet starting" | tail -1` (systemd) ou `docker logs arenet 2>&1 | grep "Arenet starting" | tail -1` (Docker). La dernière ligne montre la version en cours (`version=vX.Y.Z`).

Compare avec la [dernière release](https://github.com/barto95100/arenet/releases/latest).

**Règle d'or :** fais un backup avant chaque mise à niveau. UI : *Backup → Exporter*. Voir [Backup & Restore](Backup-Restore-FR).

---

## 1. Docker Compose (recommandé)

Si tu déploies avec le `docker-compose.yml` de référence (image `ghcr.io/barto95100/arenet:latest`) :

```bash
cd ~/arenet            # là où vit ton docker-compose.yml
docker compose pull    # récupère la nouvelle image :latest
docker compose up -d   # recrée le conteneur sur la nouvelle image
docker compose logs -f arenet | grep "Arenet starting"   # confirme la nouvelle version
```

Ton état vit dans le volume nommé `arenet-data` (monté sur `/var/lib/arenet`), il survit donc à la recréation du conteneur. Rien d'autre à faire.

> **⚠️ Vérifie `ARENET_ADMIN_BIND` dans ton compose.** Les anciennes versions du `docker-compose.yml` de référence définissaient `ARENET_ADMIN_BIND: 127.0.0.1:8001`. Les anciennes images l'ignoraient silencieusement ; les nouvelles le respectent, ce qui bind l'admin sur le loopback *du conteneur* — injoignable via le port publié, alors que le healthcheck reste vert. **Supprime cette ligne** avant de mettre à jour : dans le conteneur l'admin doit rester sur `:8001`, et la restriction au loopback est assurée par le mapping de port `"127.0.0.1:8001:8001"`. Arenet logue un warning `admin bound to loopback inside a container` au démarrage si la ligne est toujours là. Au passage, ajoute `- "443:443/udp"` sous `ports:` pour HTTP/3.

**Épingle une version précise** au lieu de `:latest` pour des mises à niveau reproductibles :

```yaml
# docker-compose.yml
services:
  arenet:
    image: ghcr.io/barto95100/arenet:vX.Y.Z   # choisis un tag sur la page des releases
```
Remplace `vX.Y.Z` par un tag de la [page des releases](https://github.com/barto95100/arenet/releases), puis `docker compose pull`, `docker compose up -d`. Pour passer à une version plus récente ensuite, bump le tag et recommence.

---

## 2. Image Docker (`docker run` standalone)

```bash
docker pull ghcr.io/barto95100/arenet:latest
docker stop arenet && docker rm arenet
docker run -d --name arenet \
  --cap-add=NET_BIND_SERVICE \
  -p 80:80 -p 443:443 -p 443:443/udp -p 127.0.0.1:8001:8001 \
  -v arenet-data:/var/lib/arenet \
  ghcr.io/barto95100/arenet:latest
```

Le volume `arenet-data` porte tes données à travers le remplacement. Garde le **même nom de volume `-v`** et la **cible de montage `/var/lib/arenet`** — c'est là que le binaire lit son état.

---

## 3. Binaire natif + systemd

Télécharge le nouveau binaire de release, vérifie son checksum, remplace-le, redémarre :

```bash
ARCH=linux-amd64        # ou linux-arm64

cd /tmp

# Télécharge le DERNIER binaire stable + son manifeste de checksums.
# L'URL /releases/latest/download/ redirige toujours vers la release
# stable la plus récente — aucun numéro de version à maintenir. Le
# fichier est enregistré sous son nom de release (arenet-linux-amd64)
# pour correspondre à l'entrée dans checksums.txt et que `sha256sum -c`
# le retrouve.
curl -L -o "arenet-${ARCH}" "https://github.com/barto95100/arenet/releases/latest/download/arenet-${ARCH}"
curl -L -o checksums.txt "https://github.com/barto95100/arenet/releases/latest/download/checksums.txt"

# Vérifie l'intégrité (la release publie un manifeste sha256). À lancer
# dans le même dossier que le fichier téléchargé.
grep "arenet-${ARCH}\$" checksums.txt | sha256sum -c -
#   → "arenet-linux-amd64: OK"

# Remplace le binaire (renomme vers le chemin d'install) et redémarre
sudo systemctl stop arenet
sudo mv "arenet-${ARCH}" /usr/local/bin/arenet
sudo chmod +x /usr/local/bin/arenet
sudo chown root:root /usr/local/bin/arenet
sudo systemctl start arenet
sudo systemctl status arenet          # Active: active (running)
sudo journalctl -u arenet | grep "Arenet starting" | tail -1
```

Le dossier de données (`/var/lib/arenet` par défaut) n'est pas touché par un remplacement de binaire.

---

## 4. Rollback

Une mise à niveau est réversible tant que tu n'as pas franchi un bump MAJOR de schéma (voir [§5](#5-sûreté-de-migration)).

**Docker Compose / run** — ré-épingle le tag d'image précédent et recrée. Remplace `vPREV` par la version où tu étais avant la mise à niveau (dans ton historique shell, ou sur la [page des releases](https://github.com/barto95100/arenet/releases)) :
```bash
docker pull ghcr.io/barto95100/arenet:vPREV
# remets le tag d'image du compose à :vPREV, ou relance docker run avec :vPREV
docker compose up -d
```

**Binaire** — garde l'ancien binaire avant d'écraser (`sudo cp /usr/local/bin/arenet /usr/local/bin/arenet.prev` avant l'étape 3), puis :
```bash
sudo systemctl stop arenet
sudo mv /usr/local/bin/arenet.prev /usr/local/bin/arenet
sudo systemctl start arenet
```

Si l'état a été touché et ne charge plus, restaure le backup que tu as pris : [Backup & Restore → Restaurer](Backup-Restore-FR).

---

## 5. Sûreté de migration

- Arenet exécute des **migrations de boot idempotentes** au démarrage (ex. la migration DNS-provider de v2.12.0). Elles sont sûres à ré-exécuter et ne demandent aucune action.
- **Les backups portent une version de schéma** (`SchemaVersion`, MAJOR `1` aujourd'hui). La restauration impose **MAJOR-égal** : un backup d'une génération de schéma différente est rejeté avec un message clair plutôt que de corrompre l'état. À l'intérieur du même MAJOR, restaurer entre versions minor/patch est OK.
- **Règle pratique :** les mises à niveau patch/minor sont drop-in. Avant une mise à niveau **MAJOR**, lis les notes de cette release, prends un backup, et sois prêt à revenir au binaire/image précédent (un backup ne peut être restauré que sur un binaire de même MAJOR).
- **Mise à niveau vers v2.15.1+ (permissions du répertoire de données) :** v2.15.1 resserre le répertoire de données en `0700` (owner-only) car il contient des secrets et des clés privées TLS. Les installs neuves et les mises à niveau standard l'ont automatiquement — le binaire chmod le dir en `0700` au boot. **Aucune action nécessaire** dans le cas courant ; pour confirmer : `stat -c '%a' /var/lib/arenet` → `700`. Si tu tournes Arenet sous un bind mount et que le boot échoue sur le répertoire de données, vois [Installation → Setup du répertoire de données](Installation-FR#setup-du-répertoire-de-données-volume-nommé-vs-bind-mount).
- **Mise à niveau vers v2.30.0+ (secrets chiffrés au repos) :** au premier démarrage, Arenet génère `arenet.key` dans le répertoire de données (mode `0600`) et chiffre tous les secrets stockés dans `arenet.db` — identifiants DNS, clés privées des certificats importés, secrets CrowdSec / MaxMind / OIDC / forward-auth, identifiants des canaux d'alerte, en-têtes de route sensibles — puis réécrit le fichier pour qu'aucune copie en clair ne subsiste. Deux effets visibles : **tout le monde se reconnecte une fois** (les identifiants de session sont désormais stockés hachés), et un WARN demande de **sauvegarder `arenet.key` à part**. Sans la clé les secrets sont irrécupérables, et Arenet refuse de démarrer sur une base chiffrée dont la clé manque ou diffère. **Revenir sous v2.30 exige la sauvegarde du répertoire de données faite *avant* la mise à niveau** — un binaire plus ancien ne sait pas lire les secrets chiffrés.

---

## 6. Automatisation (CLI-only)

Si tu veux des mises à niveau non-attendues, garde-les **en dehors** d'Arenet — sur ton propre planning, avec tes propres garde-fous :

- **Docker — Watchtower** (ou un cron `docker compose pull && up -d`) : auto-pull des nouvelles images. Préfère un **tag épinglé + bump manuel** en production pour qu'une mise à niveau n'arrive que quand tu le décides.
- **Binaire — timer systemd / cron** : un script qui télécharge la dernière release, **vérifie le checksum**, remplace le binaire et redémarre. Toujours backup d'abord dans le script.
- **Flotte — Ansible** : un rôle templatant la version binaire/image, derrière une revue des notes de release.

Tout ceci tourne sous *ton* contrôle et tes privilèges — pas ceux du reverse proxy.

---

## Notes de sécurité

- **Ne câble PAS un bouton « mettre à jour maintenant », plugin ou hack qui laisserait le process Arenet remplacer son propre binaire.** Cela nécessiterait de donner à un service exposé au réseau un accès en écriture à `/usr/local/bin` (ou à l'image du conteneur) plus la capacité de se redémarrer — un amplificateur d'escalade de privilèges et de RCE si un chemin de download/parse est un jour exploité.
- **Vérifie l'intégrité.** Les releases binaires livrent un `checksums.txt` (sha256). Vérifie-le (§3) avant d'installer. Les releases ne sont **pas** signées GPG/cosign aujourd'hui, donc le checksum + HTTPS depuis GitHub est ton contrôle d'intégrité.
- **Supply chain.** Épingle des versions explicites en production ; relis les notes de release avant de bumper. Un `:latest` aveugle sur chaque host signifie qu'une seule mauvaise release atteint tout le monde d'un coup.
- **Backup avant chaque mise à niveau.** C'est le rollback le moins cher que tu aies. Voir [Backup & Restore](Backup-Restore-FR).
- **Pattern industriel.** nginx, Traefik, Caddy, Postgres — aucun ne s'auto-met à jour via sa propre surface d'admin. Notification + mise à niveau manuelle et contrôlée est la norme pour de l'infrastructure qui termine ton trafic.

---

_Voir aussi : [DNS Providers → Rester à jour](DNS-Providers-FR#rester-à-jour) · [Backup & Restore](Backup-Restore-FR) · [Installation](Installation-FR)_
