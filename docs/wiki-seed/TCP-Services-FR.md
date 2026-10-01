<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Services TCP / UDP (niveau 4)

[English](TCP-Services) · **🌐 Français**

Une **route** relaie du HTTP : Arenet termine le TLS, lit la requête, applique le WAF, choisit un backend. Un **service TCP / UDP** fait tout autre chose — il transfère des octets sans les lire. Arenet ne déchiffre jamais ce trafic : le chiffrement est négocié de bout en bout entre le client et le backend.

C'est ce qui le rend utile pour tout ce que le HTTP ne sait pas porter : un serveur de messagerie, une base de données, SSH, RDP, WireGuard, DNS, syslog, un serveur de jeu.

---

## Ce qui s'applique et ce qui ne s'applique pas

| | Route (HTTP) | Service TCP / UDP |
|---|---|---|
| WAF, règles guidées, SecLang | ✅ | ❌ |
| Pages d'erreur, page de maintenance | ✅ | ❌ |
| Blocage par pays | ✅ | ❌ |
| Règles par chemin, en-têtes | ✅ | ❌ |
| Filtrage d'IP source | ✅ | ✅ |
| Décisions CrowdSec | ✅ | ✅ |
| Contrôle de santé | requête HTTP | connexion TCP (pas en UDP) |
| Certificats | portés par Arenet | portés par le **backend** |

Le formulaire le dit aussi. Un relais n'est pas une route avec moins d'options : c'est autre chose.

---

## En créer un

**Services TCP / UDP → + Nouveau service**. Nomme-le, choisis le transport, donne le port d'écoute et le backend vers lequel il relaie.

Le formulaire te prend au mot. **Rien n'est restreint tant que tu ne le restreins pas** — si le relais porte une base de données, un protocole d'administration ou quoi que ce soit qui n'a pas à être joignable depuis Internet, le filtrage d'IP source est à toi de le poser. Arenet ne devine pas ce qu'un numéro de port signifie.

Renseigne ensuite le backend (`hôte:port`) et enregistre. L'adresse d'écoute est vérifiée **avant** tout enregistrement : un port dont Arenet a besoin est refusé nommément, un port déjà pris par un autre service est refusé en nommant les deux, et un port sous 1024 que le processus ne peut pas ouvrir est refusé avec la ligne exacte à ajouter à l'unité systemd.

---

## Le PROXY protocol — à lire

Sans lui, **ton backend voit l'adresse d'Arenet à la place de celle du client**. Sur un serveur de messagerie, ça casse les vérifications SPF, rend l'antispam aveugle et vide de sens les limites par IP. Ailleurs, ça ruine tes journaux et tes propres bannissements.

Arenet envoie l'en-tête quand tu choisis **v2** (ou v1, en TCP seulement — la v1 ne transporte pas d'adresse UDP).

**Le backend doit être configuré pour l'attendre**, et c'est là le piège : si un seul des deux côtés est réglé, **les connexions échouent en silence**. Aucun des deux ne signale d'erreur ; ça ne marche simplement pas.

| Backend | Ce qu'il faut régler |
|---|---|
| Stalwart | `proxyTrustedNetworks` = l'IP d'Arenet (Settings → Network) |
| HAProxy | `accept-proxy` sur la ligne `bind` |
| NGINX | `proxy_protocol` sur la ligne `listen`, plus `set_real_ip_from` |
| Postfix | `postscreen_upstream_proxy_protocol = haproxy` |
| Dovecot | `haproxy_trusted_networks` + `haproxy = yes` sur l'écouteur |

Le formulaire affiche l'adresse à déclarer, et le bouton **Tester les backends** vérifie l'autre bout avant que tu fasses confiance au relais.

Depuis la v2.43, le test envoie un **vrai en-tête PROXY** — le même que celui du relais — puis observe ce que le backend en fait. Ce qui marque un refus, c'est la fermeture, pas le silence ni les octets : un backend qui n'est pas configuré pour cet en-tête le lit comme son propre protocole, n'y comprend rien et raccroche, parfois après avoir répondu quelque chose. Un backend qui l'attend, lui, le consomme et attend que le client parle — ce qui, sur un port en TLS implicite, revient à ne rien dire du tout. Le verdict est donc **en-tête non refusé** ou **en-tête refusé**, jamais « accepté » : une seule connexion ne peut pas prouver que l'autre bout l'a analysé, seulement qu'il ne l'a pas rejeté.

Un relais **UDP** est signalé comme *non testable*. Il n'y a aucune connexion à ouvrir, donc la réponse honnête est que la question n'a pas de réponse ; avant la v2.43 le test ouvrait une connexion TCP quel que soit le protocole, et déclarait en panne tout relais UDP parfaitement sain.

---

## Publier le port

**Installation native.** L'unité systemd embarque `AmbientCapabilities=CAP_NET_BIND_SERVICE`, donc les ports sous 1024 fonctionnent d'emblée. Si tu as écrit ta propre unité, ajoute cette ligne — Arenet te le dira au moment où tu essaieras.

**Docker.** Un relais écoute **à l'intérieur** du conteneur : le port doit donc aussi être publié dans `docker-compose.yml`. Sans ça, le service s'affiche en vert dans l'interface et rien ne l'atteint jamais :

```yaml
ports:
  - "993:993"          # IMAPS
  - "51820:51820/udp"  # WireGuard — noter le /udp
```

---

## Le surveiller

Le trafic de niveau 4 ne traverse aucune chaîne HTTP : il n'apparaît dans aucune métrique de route, aucune ligne de journal, aucune tuile du tableau de bord. La colonne **Trafic** de la liste est la vue : connexions acceptées, connexions ouvertes en ce moment, octets dans chaque sens, et connexions que le relais n'a pas pu mener à bien — presque toujours un backend qui refuse ou qui ne répond pas.

Depuis la v2.43, cette colonne **se rafraîchit toute seule**, toutes les cinq secondes, et les octets avancent **pendant qu'une connexion est ouverte**. Auparavant ils n'étaient ajoutés qu'à la fermeture : une session IMAP de téléphone, qui reste ouverte des heures, affichait 0 o pour un relais occupé en permanence.

**Ce que « ouvertes » compte sur un relais UDP (v2.57.1).** UDP n'a pas de
connexions : caddy-l4 maintient une pseudo-session par adresse cliente et
l'abandonne 30 secondes après le dernier paquet de ce client. « Ouvertes »
sur un service UDP signifie donc *adresses clientes distinctes vues dans les
30 dernières secondes* — un nombre qui retombe de lui-même à zéro quand le
trafic cesse, et qui compte plusieurs fois un même client média s'il change
d'adresse.

Ce compteur **repart aussi de zéro à chaque application de configuration**,
pour les services UDP uniquement. Lorsqu'une application remplace le moteur
de niveau 4, les sessions vivantes à cet instant sont abandonnées sans jamais
signaler leur fermeture : leur décompte serait sinon traîné pendant toute la
durée de vie du processus. Un opérateur a ainsi vu `38 ouvertes` sur un relais
LiveKit, figé, plus d'une heure après la fin de la réunion. Le trafic réel
regarnit le nombre en moins d'une fenêtre d'inactivité, et les compteurs
cumulés — connexions et octets — ne sont jamais remis à zéro. Un service
**TCP** conserve son compteur au travers d'une application, parce qu'un
relais établi y survit et signale bien sa fermeture.

Les mêmes compteurs sont disponibles sur `GET /api/v1/tcp-services/metrics`.

---

## Cas concret : un serveur de messagerie sur une autre machine

Stalwart (ou Postfix + Dovecot) sur une VM d'un autre réseau, Arenet devant.

**Les ports.** Le 25 pour le courrier qui arrive des autres serveurs — ce n'est jamais un port client. Le 465 et le 993 pour les téléphones et Outlook, en TLS implicite. Le 587 pour les clients qui font encore du STARTTLS. Le 4190 pour ManageSieve, restreint à ton LAN ou à ton VPN.

**Les certificats restent sur le serveur de messagerie**, puisque Arenet ne déchiffre pas. Mais Arenet occupe le port 80, donc un renouvellement HTTP-01 depuis le serveur de messagerie ne peut pas aboutir seul. Deux sorties : du DNS-01 côté serveur de messagerie, ou une **route** Arenet pour le nom d'hôte du mail, avec une règle par chemin qui lui envoie `/.well-known/acme-challenge/*`.

**Le courrier sortant ne passe pas par Arenet.** Un relais de niveau 4 ne porte que l'entrant. Ton enregistrement MX pointe sur l'IP d'Arenet, mais **le SPF et le reverse DNS doivent couvrir l'adresse par laquelle le serveur de messagerie sort**. Se tromper là-dessus envoie ton courrier en indésirable pendant des semaines sans cause évidente.

---

## Cas concret : une base de données joignable depuis le LAN

PostgreSQL sur une autre machine, atteignable depuis ton poste à travers Arenet.

Arme le filtrage d'IP source et mets-y ta plage LAN (`192.168.1.0/24`). Rien ne le fait à ta place, et un relais PostgreSQL sans filtre est joignable depuis Internet. Laisse le PROXY protocol désactivé, sauf si ton PostgreSQL est configuré pour — contrairement au mail, rien ici ne dépend de voir l'IP du client.

Active le contrôle de santé : au niveau 4 c'est une connexion TCP, et c'est exactement comme ça que tu apprendras que la base ne répond plus.

Et garde en tête ce que dit le formulaire : **aucun WAF ne protège ceci**. La barrière, c'est le filtrage d'IP source et CrowdSec, rien d'autre.
