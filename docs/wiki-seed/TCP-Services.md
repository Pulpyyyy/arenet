<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# TCP / UDP services (layer 4)

**🌐 English** · [Français](TCP-Services-FR)

A **route** proxies HTTP: Arenet terminates TLS, reads the request, applies the WAF, picks a backend. A **TCP / UDP service** does something else entirely — it forwards bytes without reading them. Arenet never decrypts this traffic: the client and the backend negotiate TLS end to end.

That is what makes it useful for everything HTTP cannot carry: a mail server, a database, SSH, RDP, WireGuard, DNS, syslog, a game server.

---

## What applies and what does not

| | Route (HTTP) | TCP / UDP service |
|---|---|---|
| WAF, custom rules, SecLang | ✅ | ❌ |
| Error pages, maintenance page | ✅ | ❌ |
| Country blocking | ✅ | ❌ |
| Per-path rules, headers | ✅ | ❌ |
| Source-IP filter | ✅ | ✅ |
| CrowdSec decisions | ✅ | ✅ |
| Health check | HTTP request | TCP connection (not UDP) |
| Certificates | Arenet holds them | the **backend** holds them |

The form says this too. A relay is not a route with fewer options — it is a different thing.

---

## Creating one

**Services TCP / UDP → + New service**. Name it, pick the transport, give the port it listens on and the backend it forwards to.

The form takes you at your word. **Nothing is restricted unless you restrict it** — if the relay carries a database, an admin protocol or anything else that should not be reachable from the internet, the source-IP filter is yours to set. Arenet does not guess what a port number means.

Then fill the backend (`host:port`) and save. The listen address is checked *before* anything is stored: a port Arenet needs for itself is refused by name, a port another service holds is refused with both names, and a port below 1024 the process cannot bind is refused with the exact line to add to the systemd unit.

---

## The PROXY protocol — read this one

Without it, **your backend sees Arenet's address instead of the client's**. On a mail server that breaks SPF checks, blinds the spam filter and makes per-IP limits meaningless. On anything else it ruins your logs and your own bans.

Arenet sends the header when you pick **v2** (or v1, TCP only — v1 carries no UDP address).

**The backend must be configured to expect it**, and this is the trap: if only one side is configured, **connections fail silently**. Neither end reports an error; things just do not work.

| Backend | What to set |
|---|---|
| Stalwart | `proxyTrustedNetworks` = Arenet's IP (Settings → Network) |
| HAProxy | `accept-proxy` on the `bind` line |
| NGINX | `proxy_protocol` on the `listen` line, plus `set_real_ip_from` |
| Postfix | `postscreen_upstream_proxy_protocol = haproxy` |
| Dovecot | `haproxy_trusted_networks` + `haproxy = yes` on the listener |

The form prints the address to trust, and the **Test the backends** button checks the far side before you trust the relay.

Since v2.43 the test sends a **real PROXY header** — the same one the relay sends — and then watches what the backend does with it. What marks a refusal is the close, not the silence and not the bytes: a backend that is not configured for the header reads it as its own protocol, fails to parse it and hangs up, sometimes after answering something first. A backend that *is* configured consumes the header and waits for the client to speak, which on an implicit-TLS port means saying nothing at all. So the verdict is **header not refused** or **header refused**, never "accepted" — one connection cannot prove the far side parsed it, only that it did not reject it.

A **UDP** relay is reported as *not testable*. There is no connection to open, so the honest answer is that the question cannot be answered; before v2.43 the test dialled TCP regardless and reported every healthy UDP relay as broken.

---

## Publishing the port

**Native install.** The systemd unit ships `AmbientCapabilities=CAP_NET_BIND_SERVICE`, so ports below 1024 work out of the box. If you rolled your own unit, add that line — Arenet will tell you so when you try.

**Docker.** A relay listens *inside* the container, so the port must also be published in `docker-compose.yml`. Without it the service shows green in the UI and nothing ever reaches it:

```yaml
ports:
  - "993:993"          # IMAPS
  - "51820:51820/udp"  # WireGuard — note the /udp
```

---

## Watching it

Layer-4 traffic crosses no HTTP chain, so it appears in no route metric, no log line and no dashboard tile. The **Traffic** column of the services list is the view: connections accepted, how many are open right now, bytes each way, and connections the relay could not complete — almost always a backend that refused or timed out.

Since v2.43 the column **refreshes on its own**, every five seconds, and the bytes move **while a connection is open**. Before that they were only added when a connection closed, so a phone's IMAP session — which stays open for hours — showed 0 B for a relay that was busy the whole time.

**What "open" counts on a UDP relay (v2.57.1).** UDP has no connections, so
caddy-l4 keeps one pseudo-session per client address and drops it 30 seconds
after that client's last packet. "Open" on a UDP service therefore means
*distinct client addresses seen in the last 30 seconds* — a number that falls
back to zero on its own once traffic stops, and that counts one media client
several times if it roams between addresses.

That gauge also **restarts at zero whenever you apply a configuration
change**, for UDP services only. When an apply replaces the layer-4 engine,
the sessions alive at that instant are abandoned without ever reporting their
own closure, so their count would otherwise be carried for the lifetime of
the process: one operator saw `38 open` on a LiveKit relay, frozen, more than
an hour after the meeting had ended. Real traffic refills the number within
the idle window, and the cumulative counters — connections and bytes — are
never reset. A **TCP** service keeps its gauge across an apply, because an
established relay survives it and does report its own close.

The same counters are available at `GET /api/v1/tcp-services/metrics`.

---

## Worked example: a mail server on another machine

Stalwart (or Postfix + Dovecot) on a VM in another network, Arenet in front.

**The ports.** 25 for mail arriving from other servers — never a client port. 465 and 993 for phones and Outlook, over implicit TLS. 587 for clients that still do STARTTLS. 4190 for ManageSieve, restricted to your LAN or VPN.

**The certificates stay on the mail server**, since Arenet does not decrypt. But Arenet occupies port 80, so an HTTP-01 renewal from the mail server cannot work on its own. Two ways out: DNS-01 on the mail server, or an Arenet **route** for the mail hostname with a path rule sending `/.well-known/acme-challenge/*` to it.

**Outbound mail does not pass through Arenet.** A layer-4 relay only carries what comes in. Your MX record points at Arenet's IP, but **SPF and reverse DNS must cover the address the mail server sends from**. Getting this wrong lands your mail in spam folders for weeks without an obvious cause.

---

## Worked example: a database you reach from the LAN

PostgreSQL on another host, reachable from your workstation through Arenet.

Arm the source-IP filter and put your LAN range in it (`192.168.1.0/24`). Nothing does this for you, and a PostgreSQL relay without it is reachable from the internet. Leave the PROXY protocol off unless your PostgreSQL is configured for it; unlike mail, nothing here depends on seeing the client IP.

Turn the health check on: at layer 4 it is a TCP connection, which is exactly how you learn the database stopped answering.

And keep in mind what the form says: **no WAF protects this**. The gate is the source filter and CrowdSec, nothing else.
