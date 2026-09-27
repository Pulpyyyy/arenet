<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Layer-4 protocol filtering, and counting refusals — design

**Target version**: v2.49.0
**Date**: 2026-09-26
**Origin**: operator request, "filtrage / sécurité L4", explicitly kept
last of five improvements.

---

## Why these two together

The operator asked for protocol filtering. Shipping it alone would make
it the **third invisible filter** on a layer-4 relay.

Verified in the code, not assumed:

- the `arenet_l4metrics` handler is placed **inside the relay route's**
  `handle` chain (`internal/caddymgr/layer4.go:129-136`), so it only
  ever sees connections that **passed** the matchers;
- the refusal routes carry `{"handler": "close"}` and nothing else — the
  IP-filter deny route (`layer4.go:107-112`) and the terminal fallback
  (`layer4.go:141-145`);
- `ServiceCounters` has no refused/blocked field at all
  (`internal/l4metrics/registry.go:42-55`), and `Errors` is incremented
  only when `next.Handle` fails (`module.go:77-80`), i.e. after the
  matchers already passed.

**A connection refused by CrowdSec or by the IP filter on a layer-4
relay increments nothing, logs nothing and stores nothing.** The
operator cannot distinguish a relay that is protecting them from one
whose protection is switched off. That is the defect this feature would
otherwise triple down on, so the counters ship in the same wave.

It is also the same failure mode that cost two smoke-test findings this
month: the stale health pill (v2.45) and the path redirect dropped
without a message (v2.46). A refusal nobody can see is a bug, not a
feature working quietly.

---

## What layer 4 can and cannot do

Stated up front because it bounds every decision below.

Arenet sees, per connection: the **source IP**, the **service** it
reached, the **bytes** and **duration**, whether it was **refused and by
what**, and the **shape of the protocol** at the handshake. It does not
see inside the stream: TLS is end-to-end to the backend.

So **Coraza / SecLang at layer 4 is impossible**, and not because of a
gap in Arenet — there is no HTTP request to inspect and no plaintext to
match. Any security at this layer is connection-level: who is
connecting, from where, speaking what, how often.

Protocol filtering is therefore **hardening, not a hole being closed**: a
correct backend already rejects garbage. Its value is that garbage never
reaches the backend, and — once refusals are counted (D5) — that
repeated protocol mismatches become a signal a later wave can act on.

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Expose the caddy-l4 matcher set as-is**: `tls`, `ssh`, `postgres`, `dns`, `rdp`, `wireguard`, `openvpn`, `socks4`, `socks5`, `xmpp`, `winbox`, `quic`, `http`. No presets, no "known services" wizard, no advice in the UI | The operator was explicit: *"c'est à l'utilisateur de savoir quoi faire … pas à Arenet de lui dire"*. Arenet offers the control and stays quiet about how to use it. Verified available in caddy-l4 v0.1.1 by module-ID enumeration |
| D2 | **At most one protocol per service**, empty = accept anything (today's behaviour) | A relay forwards one port to one backend speaking one protocol. A multi-select invites `tls OR ssh` configurations whose only effect is to weaken the check |
| D3 | **A mismatch closes the connection**, like the IP filter — no error, no banner | There is no protocol to answer in. `layer4.handlers.close` is what the IP filter already uses |
| D4 | **Transport-aware offer**: the UI only offers matchers that make sense for the service's transport | `tls` on UDP is meaningless outside QUIC; `wireguard` and `dns` are UDP-native. Which matcher works on which transport is an **empirical gate**, not an assumption — see G2 |
| D5 | **Count refusals per service and per cause**: `protocol`, `ip_filter`, `crowdsec` | Without this the feature is invisible. Per cause because "42 refusals" does not tell the operator whether to fix a CIDR, a protocol choice, or nothing at all |
| D6 | **Implemented by giving each refusal its own close route**, each prefixed with the metrics handler carrying a `cause` | The single shared terminal close cannot attribute a cause. Verified feasible: the CrowdSec matcher returns `(false, nil)` and does **not** close the connection itself (`caddy-crowdsec-bouncer/layer4/l4.go:92`), so the refusal does reach Arenet's route |
| D7 | **Do not enable the bouncer's own Prometheus counters** | The bouncer does count blocks, labelled by `server`/`origin`/`remediation` (`internal/metrics/metrics.go:544`), and its `layer4-<local addr>` label is even attributable since Arenet gives each service its own port. But it covers **only** CrowdSec, so Arenet would need its own counting anyway for the other two causes — and then two mechanisms disagree. One source, ours, for all three causes. `enable_caddy_metrics` stays at the upstream default |
| D8 | **The HTTP catch-all consults CrowdSec** | Folded in because it is the same defect: an operator who bans an IP expects it refused everywhere, and today an unmatched host is answered by a bare 404 (`manager.go:3733`) before CrowdSec is consulted — which is exactly what confused the operator on 2026-09-26. Cost is one in-memory map lookup: Arenet sets `EnableStreaming: true` (`manager.go:2296`) and streaming mode resolves from the local store (`caddy-crowdsec-bouncer/internal/core/decisions.go:105-106`). `enable_hard_fails: false` is unchanged, so a LAPI outage still cannot take the site down |
| D9 | **Counters stay process-lifetime and in-memory**, like the existing six | Consistency with `l4metrics` today. Persisting layer-4 history is its own decision, and a bigger one |

### On D8, honestly

This buys very little **security**. A banned IP gets a 404 today and a
403 tomorrow; no attack is prevented either way. It is worth doing for
predictability, for serving a short refusal instead of a rendered 404
page under a flood, and for consistency with the layer-4 relays. It is
in this spec because it is cheap and removes a surprise — not because
more controls are safer.

---

## Non-goals

**Per-source-IP visibility and Arenet as a detector.** The information is
there — the bouncer's own matcher reads `cx.Conn.RemoteAddr()`
(`layer4/l4.go:110-122`) and Arenet's handler simply never does, keying
its counters by `service_id` alone. Reading it would let the existing
auto-classify engine take a layer-4 source and push bans to LAPI through
machinery that already works (rules, thresholds, dedupe, operator
cooldown, audit). That is the payoff wave, and it is a wave of its own.

**Connection-rate limiting.** caddy-l4's `throttle` handler limits
**bandwidth**, not connections (`read_bytes_per_second`,
`total_read_bytes_per_second` — `modules/l4throttle/throttle.go:38-52`).
There is no upstream connection-rate limiter, so this means writing a
module with shared cross-connection state and an expiry policy.

**Country gating at layer 4.** Useful and blunt; needs a new
`layer4.ConnMatcher` reusing `internal/geo`. No upstream equivalent
exists (enumerated: the 24 caddy-l4 matchers are protocol or IP/CIDR).
Deferred to keep this wave to one subject.

**Anything inside the stream.** See §What layer 4 can and cannot do.

---

## Empirical validation gates

1. **G1 — the emitted config loads.** `caddy.Validate()` on the JSON for
   a service with each offered protocol, and handler-ID resolvability,
   extending `TestBuildConfigJSON_LoadsCleanly*` /
   `TestBuildConfigJSON_HandlersAllResolvable`. CrowdSec stays out of
   `caddy.Validate` (provisioning dials LAPI) and keeps its
   registry-lookup guard instead — the lesson of the
   `unknown module: layer4.matchers.crowdsec` escape.
2. **G2 — which matchers actually work on UDP.** caddy-l4 reads packet
   conns within frame boundaries (`layer4/connection.go:99-133`), so
   matching is possible — but per-matcher behaviour is not assumed. A
   harness drives a real relay per (matcher, transport) pair and records
   match / no-match. D4's offer is derived from the **result**, not from
   the matcher names.
3. **G3 — a refusal increments its own cause, exactly once.** Three
   probes against a live relay: a wrong-protocol connection, a
   source outside an allow CIDR, and a banned IP. Each bumps one
   counter, the others stay at zero, and `connections` does **not** move.
4. **G4 — non-regression.** A service with no protocol set emits
   byte-identical Caddy JSON to v2.48. Asserted, per the project rule.
5. **G5 — D8 does not break the unmatched path.** With CrowdSec
   configured, an unbanned request to an unknown host still gets the
   catch-all 404; a banned one gets 403; with LAPI down, both get the
   404 (fail-open).

---

## Shape

`storage.TCPService` gains one field. Per the both-axes rule
(ENGINEERING-PRACTICES Lesson 8) this lands on storage **and** API/UI in
the same change: JSON tag, migration if needed, backup/restore, wire
shape, validation, frontend types.

```go
// Protocol the relay accepts at the handshake; empty accepts anything,
// which is the pre-v2.49 behaviour. A connection that does not match is
// closed, and counted under cause "protocol".
Protocol string `json:"acceptProtocol,omitempty"`
```

`TCPServiceCounters` gains refusals by cause:

```json
{"connections": 128, "active": 2, "bytesIn": 40960, "bytesOut": 81920,
 "errors": 0, "refused": {"protocol": 3, "ipFilter": 17, "crowdsec": 42},
 "lastConnectionAt": "2026-09-26T18:02:11Z"}
```

`refused` is a map so a later cause — country, rate — adds a key rather
than a field, and an older UI reading an unknown key ignores it.

---

## Open question for the operator

`acceptProtocol` is a new `storage.TCPService` field, so it needs a name
that will still read correctly when a second protocol-ish control
appears. `acceptProtocol` says what it does; `protocol` would collide
with the existing transport field (`tcp` / `udp`), which is a different
axis and already confusingly close.
