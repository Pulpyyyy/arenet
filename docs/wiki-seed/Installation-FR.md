# Installation

[English](Installation) · **🌐 Français**

Deux chemins d'installation supportés : **Docker** (recommandé pour la plupart des homelabs) et **systemd natif** sur Linux. Choisis-en un — les deux finissent au même endroit : une instance Arenet qui tourne avec l'UI d'admin accessible sur `:8001` et le listener public sur `:80` + `:443`.

Cette page est le guide condensé. Pour les détails par OS, voir le dossier [docs/install/](https://github.com/barto95100/arenet/tree/main/docs/install) dans le repo principal.

---

## Prérequis

| Requirement | Pourquoi |
| ----------- | -------- |
| Host Linux (amd64 ou arm64) | Cible binaire native ; l'image Docker est multi-arch |
| DNS public pointant sur le host | Pour que le challenge ACME HTTP-01 fonctionne pour l'auto-HTTPS |
| TCP/80 + TCP/443 ouverts en inbound | Redirect HTTP-to-HTTPS + serving HTTPS |
| **UDP/443 ouvert en inbound** | HTTP/3 sur QUIC ([voir doc HTTP/3](https://github.com/barto95100/arenet/blob/main/docs/operations/http3.md)) |
| Optionnel : creds API DNS provider | Challenge DNS-01 pour les certs wildcard — configure un ou plusieurs comptes OVH, voir [DNS Providers](DNS-Providers-FR) |

Cible hardware : 2 vCPU + 1 Go RAM est confortable pour 50 routes. Le WAF Coraza est le plus gros consommateur — désactive-le par route sur les hosts low-resource si nécessaire (voir [WAF](WAF-FR)).

---

## Chemin 1 : Docker (recommandé)

### 1. Récupère le fichier compose

```bash
mkdir -p ~/arenet && cd ~/arenet
curl -O https://raw.githubusercontent.com/barto95100/arenet/main/docker-compose.yml
```

### 2. Pull + start

```bash
docker compose pull
docker compose up -d
```

Un volume nommé `arenet-data` contient l'état BoltDB + SQLite + les certs Caddy. Backup tout le volume (ou utilise l'[UI Backup](Backup-Restore-FR)) pour la disaster recovery.

### 3. Récupère le setup token

Au premier boot, Arenet génère un setup token one-time pour bootstrapper le compte admin. Trouve-le dans les logs :

```bash
docker compose logs arenet | grep "setup token"
```

Tu verras une ligne comme : `setup token : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### 4. Ouvre le wizard

Ouvre `http://<your-host>:8001` dans un navigateur. Le wizard de setup demande :
- Le setup token (de l'étape 3)
- Un username + password admin (hashé en Argon2id)
- Un email admin (pour alerting + recovery)

Clique **Submit** → tu es dedans. Le setup token est consommé (usage one-time), le compte admin est créé avec le rôle `admin`, et le wizard de setup disparaît aux visites suivantes.

### Setup du répertoire de données (volume nommé vs bind mount)

Le répertoire de données contient `arenet.db` (routes, users, audit, et **secrets** — client secrets OIDC, clés API DNS, le hash du password admin) plus les clés privées TLS sous `certmagic/`. Depuis la v2.30 ces secrets sont **chiffrés** avec `arenet.key`, généré à côté de la base au premier démarrage — sauvegarde-le à part (voir [Updates → Sûreté de migration](Updates-FR#5-sûreté-de-migration) ; `ARENET_SECRET_KEY_FILE` le déplace, par exemple vers un secret Docker). Arenet le garde **owner-only (`0700`)**, appartenant à l'utilisateur distroless `nonroot` (UID **65532**).

**Volume nommé (le défaut) — rien à faire.** Docker seed l'ownership et les permissions d'un volume nommé neuf depuis le `/var/lib/arenet` de l'image, qui ship en `65532:65532` mode `0700`. Ça marche direct, et les secrets sont owner-only dès le premier boot.

**Bind mount (`./data:/var/lib/arenet`) — nécessite un fix d'ownership une fois.** Un directory host appartient à qui l'a créé (souvent root ou ton user de login), **pas** à l'UID 65532. Le container distroless n'a pas de shell et ne peut pas `chown` son propre mount, donc il crash-loop avec `permission denied`. Choisis :

**Option A — manuel (le plus simple) :** crée le dir avec le bon owner et mode avant `docker compose up` :

```bash
mkdir -p ./data
sudo chown -R 65532:65532 ./data   # UID distroless 'nonroot'
sudo chmod 700 ./data              # owner-only : secrets + clés TLS
```

Puis édite `docker-compose.yml` pour monter `./data:/var/lib/arenet` au lieu du volume nommé.

**Option B — init container (automatique, idempotent) :** ajoute un service one-shot qui fixe l'ownership avant qu'Arenet démarre. Il **resserre aussi un directory laissé en `0755` par une install pré-v2.15.1**. Ajoute à `docker-compose.yml` :

```yaml
services:
  arenet:
    # ... config existante ...
    volumes:
      - ./data:/var/lib/arenet     # bind mount au lieu du volume nommé
    depends_on:
      arenet-init:
        condition: service_completed_successfully

  arenet-init:
    image: busybox:1.37
    user: "0:0"                    # tourne en root juste pour chown le mount
    command: ["sh", "-c", "chown -R 65532:65532 /data && chmod 700 /data"]
    volumes:
      - ./data:/data               # MÊME dir host que le bind mount d'arenet
    restart: "no"
    security_opt:
      - no-new-privileges:true
```

`arenet-init` tourne une fois, fixe le mount, et sort ; `depends_on … service_completed_successfully` fait attendre Arenet. On peut le laisser en place — le relancer est un no-op.

> **Pourquoi 65532 / 0700 ?** `65532` est l'utilisateur distroless `nonroot` sous lequel Arenet tourne. `0700` veut dire que seul cet utilisateur peut lire ou écrire le directory — donc les secrets dans `arenet.db` et les clés privées TLS ne sont pas exposés aux autres users ou containers qui partagent le host. Vois [Updates → Sûreté de migration](Updates-FR#5-sûreté-de-migration) si tu upgrades une install plus ancienne, et [Troubleshooting → permission denied](Troubleshooting) si un boot échoue sur le répertoire de données (page EN pour l'instant).

---

## Chemin 2 : Linux natif + systemd

Pour les opérateurs qui ne veulent pas Docker, ou qui veulent intégrer Arenet avec le graphe d'unit systemd existant du host (ex. `WantedBy` ta stack de monitoring).

### 1. Exécute le script d'install

```bash
curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh \
  | sudo bash
```

Le script :
- Télécharge le dernier binaire release (multi-arch) depuis les GitHub releases
- Crée l'utilisateur système `arenet` (pas de shell, password locké)
- Installe le binaire à `/usr/local/bin/arenet`
- Installe l'unit systemd à `/etc/systemd/system/arenet.service`
- Crée `/var/lib/arenet/` pour l'état BoltDB + SQLite
- Reload systemd (`systemctl daemon-reload`)

Arenet crée et garde `/var/lib/arenet` en mode **`0700`** (owner-only) — il contient des secrets et des clés privées TLS. Les installs neuves l'ont automatiquement ; si tu **upgrades depuis avant v2.15.1**, le binaire resserre le dir en `0700` à son prochain boot. Pour confirmer : `stat -c '%a' /var/lib/arenet` → `700`.

### 2. Démarre le service

```bash
sudo systemctl enable --now arenet
```

### 3. Récupère le setup token

```bash
sudo journalctl -u arenet --since "1 min ago" | grep "setup token"
```

### 4. Ouvre le wizard

Pareil que l'étape 4 du chemin Docker — `http://<your-host>:8001`, colle le token, crée le compte admin.

---

## Post-install : exposer l'UI d'admin

Par défaut l'UI d'admin bind sur `127.0.0.1:8001` (loopback uniquement) par sécurité. Pour y accéder depuis ton LAN :

**Docker** : le `docker-compose.yml` de référence publie `127.0.0.1:8001:8001`. Remplace cette ligne par `8001:8001` pour joindre `http://<docker-host>:8001` depuis ton LAN — ne touche pas à `ARENET_ADMIN_BIND`, dans le conteneur l'admin doit rester sur `:8001`. Restreins via des policies Docker network ou ton firewall.

**systemd** : édite `/etc/systemd/system/arenet.service` et set la variable d'env :

```ini
[Service]
Environment="ARENET_ADMIN_BIND=0.0.0.0:8001"
```

Puis `systemctl daemon-reload && systemctl restart arenet`.

⚠️ **N'expose pas l'UI d'admin publiquement**. Utilise [SSO OIDC](OIDC-SSO-FR) + une route qui cible `127.0.0.1:8001` pour que l'admin soit derrière ta chaîne d'auth.

---

## Variables d'environnement (optionnel)

Toutes optionnelles — définis-les via `environment:` dans `docker-compose.yml` ou `Environment="..."` dans l'unit systemd.

| Variable | Défaut | Rôle |
| -------- | ------ | ---- |
| `ARENET_ADMIN_BIND` | `127.0.0.1:8001` | Adresse de bind de l'UI/API d'admin. Mets `0.0.0.0:8001` pour un accès LAN (voir ci-dessus). |
| `ARENET_DATA_DIR` | `/var/lib/arenet` | Où le binaire stocke son état BoltDB/SQLite. |
| `ARENET_UPDATE_CHECK_INTERVAL` | `24h` | Cadence du vérificateur de mises à jour opt-in (durée Go, min `1h`). Le check doit tout de même être **activé dans Réglages → Mises à jour** — pas de toggle env pour ça. Voir [DNS Providers → Rester à jour](DNS-Providers-FR#rester-à-jour). |
| `ARENET_ACME_EMAIL` | _(aucun)_ | Email de contact passé à l'émetteur ACME pour les notices Let's Encrypt. |

D'autres variables opérationnelles (`ARENET_CROWDSEC_*`, `ARENET_UI_ORIGIN`, …) sont documentées dans les pages de feature correspondantes.

---

## Vérifier l'install

```bash
# Endpoint Healthz
curl http://localhost:8001/healthz

# Output attendu : {"status":"ok"}
```

Si tu vois `{"status":"ok"}`, Arenet tourne et le Caddy embarqué + BoltDB + Coraza + bouncer CrowdSec ont tous booté proprement. Sinon, voir [Troubleshooting](Troubleshooting-FR).

---

## See also

- [Routes](Routes-FR) — câble ton premier host proxifié
- [Backup & Restore](Backup-Restore-FR) — sauve ta config avant/après les upgrades
- [Troubleshooting](Troubleshooting-FR) — pièges communs d'install + décodage des logs
- [`docs/install/docker-quickstart.md`](https://github.com/barto95100/arenet/blob/main/docs/install/docker-quickstart.md) — guide Docker étendu avec troubleshooting
- [`docs/install/systemd-native.md`](https://github.com/barto95100/arenet/blob/main/docs/install/systemd-native.md) — guide systemd étendu
