// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Topology view domain types.
 *
 * Frontend-only shapes describing what the topology canvas needs
 * to render. Decoupled from the backend storage.Route to keep the
 * canvas hackable in isolation while the live data feed is being
 * wired up.
 *
 * Important: Svelte Flow constrains `Node<T>` and `Edge<T>` data
 * payloads to extend `Record<string, unknown>`. Each *NodeData /
 * FlowEdgeData type alias is therefore declared as the intersection
 * of the strict shape with Record<string, unknown> — object
 * literals carrying the strict fields then satisfy the intersection
 * directly (no `as` cast needed at the call site).
 */

import type { Node, Edge } from '@xyflow/svelte';

// ---------------------------------------------------------------------------
// Domain enums
// ---------------------------------------------------------------------------

export type LBPolicy =
        | 'round_robin'
        | 'weighted_round_robin'
        | 'least_conn'
        | 'ip_hash'
        | 'random'
        | 'first';

export type HealthStatus = 'healthy' | 'unhealthy' | 'draining' | 'unknown';

export type FlowTier = 'dead' | 'idle' | 'low' | 'mid' | 'high' | 'warn' | 'bad';

// ---------------------------------------------------------------------------
// Domain types — input
// ---------------------------------------------------------------------------

export interface TopologyRoute {
        id: string;
        host: string;
        aliases?: string[];
        /** Per-alias windowed metrics, populated by the backend's
         *  Phase 2.2 builder. Sorted descending by `reqPerSec`
         *  server-side (operator-visible "top consumers" first);
         *  the frontend preserves order so the layout doesn't need
         *  to re-sort.
         *
         *  ALWAYS present (non-omitempty server-side, see
         *  `internal/api/topology/types.go` Route docstring) — when
         *  the route has zero aliases the field is `[]`, NOT
         *  absent. Optional in the type definition so legacy
         *  snapshots (pre-Phase-2.2) deserialise cleanly during
         *  the rolling redeploy window. Once every running arenet
         *  emits the field, the optional `?` can be dropped.
         */
        aliasMetrics?: TopologyAlias[];

        upstreams: TopologyUpstream[];
        lbPolicy: LBPolicy;

        /** Per-path routing branches (v2.24.0). Absent/empty = no per-path
         *  pool. Each entry with its own pool renders as a separate backend
         *  cluster labelled by pathPrefix. Optional so pre-v2.24.0 snapshots
         *  deserialise cleanly during the rolling redeploy window. */
        pathPools?: TopologyPathPool[];

        reqPerSec: number;
        p99LatencyMs: number;
        errorRate5xx: number;            // 0-100

        tlsEnabled: boolean;
        wafLevel?: 'off' | 'detect' | 'block';
        rateLimited?: boolean;
        mtlsRequired?: boolean;

        // True when storage.Route.RedirectToHTTPS is true. Drives
        // the "HTTP → HTTPS" protocols label variant on the FQDN
        // node (C18, 2026-06-04). The backend always emits the
        // field; tlsEnabled === false implies httpRedirect === false.
        httpRedirect: boolean;
        /**
         * v2.61 — the destination of a ROUTE-LEVEL redirect, absent on a
         * proxying route. Not to be confused with `httpRedirect` above,
         * which is the :80 → :443 bounce; the names are close and the
         * meanings are not.
         *
         * Before this, a redirecting route drew an empty backend cluster
         * wearing the red "no upstream configured" warning — the canvas
         * claiming a working route was broken.
         */
        redirectTarget?: string;

        // True when storage.Route.HealthCheck.Enabled is true on
        // the backend. Drives the per-upstream shield indicator
        // (#R-TOPO-health-coherence v1.1.0). NOT optional — the
        // backend always emits the field.
        hasHealthCheck: boolean;

        // v2.14.3 route disable/enable. Mirrors storage.Route.Disabled
        // via internal/api/topology/types.go Route.Disabled. A disabled
        // route is not emitted into Caddy (serves nothing) but the
        // topology reads storage directly, so it still appears here —
        // this flag is what lets the FQDN node render dimmed instead of
        // looking like a mysterious zero-traffic phantom. The backend
        // always emits the field (non-omitempty); NOT optional.
        disabled: boolean;

        clusterLabel?: string;
}

/** One alias of a route — the wire shape of backend
 *  `internal/api/topology/types.go` `Alias` (Phase 2.2).
 *
 *  `host` preserves the operator's original casing as
 *  declared in storage (lowercase normalisation only
 *  happens at the registry/lookup layer). `reqPerSec` is
 *  the windowed mean over the 60s sliding window
 *  populated by the per-host Snapshot drain. */
export interface TopologyAlias {
        host: string;
        reqPerSec: number;
        p99LatencyMs: number;
        errorRate5xx: number;            // 0-100
}

/** One per-path routing branch (v2.24.0): a path-rule with its own upstream
 *  pool, the wire shape of backend `internal/api/topology/types.go`
 *  `PathPool`. Rendered as a separate backend cluster labelled by
 *  `pathPrefix`. Structure only — no live-traffic fields in v1. */
export interface TopologyPathPool {
        pathPrefix: string;
        upstreams: TopologyUpstream[];
        lbPolicy: LBPolicy;
        insecureSkipVerify?: boolean;
}

export interface TopologyUpstream {
        id: string;
        url: string;
        runtime?: string;
        status: HealthStatus;

        // Mirrors the parent route's hasHealthCheck — denormalised
        // by the backend so the UpstreamNode component doesn't have
        // to thread the route in. True ⇒ render a small "monitored"
        // shield next to the URL.
        healthCheckConfigured: boolean;

        reqPerSec: number;
        p99LatencyMs: number;
        fairnessRatio: number;           // 0-1
}

// ---------------------------------------------------------------------------
// Node data payloads — `& Record<string, unknown>` to satisfy
// Svelte Flow's Node<T> constraint.
// ---------------------------------------------------------------------------

/** Col 0 — primary host serving a route.
 *
 *  C16 (2026-06-03): `wafLevel` carries route-level WAF state —
 *  rendered as a Lucide Shield/ShieldCheck glyph next to the host.
 *
 *  C17 (2026-06-04): `aliases` is the additional-hosts list for
 *  the route, used to populate the "X hosts" subline tooltip with
 *  real hostnames. `protocols` is now derived strictly from
 *  TLS-enabled (HTTPS / HTTP) until the backend exposes the real
 *  ALPN list — the previous "HTTPS · h2 · h3" was mock leakage.
 *  See `#R-TOPO-alpn` in docs/backlog-step-r.md. */
export type FQDNNodeData = {
        kind: 'fqdn';
        host: string;
        protocols: string;
        meta: string;
        aliases?: string[];
        wafLevel: 'off' | 'detect' | 'block';
        /** Sujet 1 Phase 3.e (2026-06-17). Carry the route ID
         *  back to the FQDN node so its chevron click handler
         *  can call collapsedRoutes.toggle(routeId) without
         *  duplicating the layout's routing. */
        routeId: string;
        /** Total alias count for this route. Drives chevron
         *  visibility on the FQDN card: zero ⇒ no chevron, no
         *  collapse / expand toggle. Counts ALL aliases (active
         *  + idle), not just the ones currently rendering — the
         *  toggle exists regardless of traffic. */
        aliasCount: number;
        /** Sum of every alias's reqPerSec. Surfaced on the FQDN
         *  meta line ONLY when the route is collapsed (replaces
         *  the per-alias breakdown that's now hidden). Includes
         *  idle aliases which contribute zero — keeping the
         *  policy "sum all aliases" identical regardless of
         *  active / idle bucket so the number doesn't jump as
         *  aliases cross the threshold. */
        aliasTotalRps: number;
        /** True when this route is currently collapsed in the
         *  topology view. Drives the chevron glyph (▶ collapsed,
         *  ▼ expanded) and which meta line variant renders. */
        collapsed: boolean;
        /** v2.14.3 route disable/enable — mirrors TopologyRoute.disabled.
         *  Drives the dimmed/dashed "deliberately off" card state and
         *  the `topology.disabled.tooltip` title on the FQDN node. */
        disabled: boolean;
} & Record<string, unknown>;

/** The single central Caddy hub.
 *
 *  C21 (2026-06-04) trimmed the visible content to "Caddy" label +
 *  aggregate req/s only. `version` and `instanceId` are still on
 *  the payload but the component surfaces them only via a hover
 *  tooltip — they're identity, not focal content. `chips` was
 *  removed entirely: L7-LB / WAF / RATE / mTLS all moved out (WAF
 *  is now on the FQDN node via Critique 16; L7-LB was redundant
 *  with what Caddy is; RATE / mTLS removed for a clean round
 *  focal point). */
export type CaddyHubNodeData = {
        kind: 'caddy';
        version: string;
        instanceId: string;
        aggregateReqPerSec: number;
} & Record<string, unknown>;

/** Vue B col 3 — group container for a route's upstream pool.
 *
 *  Sub-flow restructure (2026-06-03): the cluster used to render
 *  one card with N upstream rows AND a single inbound edge from
 *  caddy-hub. The N edges critique called this out — the operator
 *  couldn't see per-upstream flow shape. We now emit:
 *    - one BackendClusterNode group (this payload, no upstreams[])
 *    - N UpstreamNode children with parentId + extent: 'parent'
 *    - N edges from caddy-hub to each child
 *
 *  The cluster node itself only carries header metadata; the
 *  per-upstream rendering moved to UpstreamNode. `lbPolicy` is
 *  still surfaced in the header but hidden by the component when
 *  totalCount === 1 (round_robin over 1 target is meaningless). */
export type BackendClusterNodeData = {
        kind: 'backend-cluster';
        clusterLabel: string;
        runtime?: string;
        lbPolicy: LBPolicy;
        healthyCount: number;
        // Strictly status === 'unhealthy'. Distinct from
        // `totalCount - healthyCount` because 'unknown' is its own
        // third state in v1.1.0 — see Critique 9 / Regression A.
        unhealthyCount: number;
        totalCount: number;
        // Mirrors the parent route's hasHealthCheck. Drives the
        // header's "monitored" framing: when false we can't talk
        // about "sains" because nothing is being probed.
        hasHealthCheck: boolean;
        warning?: string;
        /**
         * v2.61 — set when the route redirects instead of proxying. The
         * cluster then renders its destination rather than an empty pool,
         * and carries no warning: a redirect is not a route missing its
         * backend, it is a route whose destination is not a backend.
         */
        redirectTarget?: string;
        /**
         * Hosts of every route that redirects to `redirectTarget`, in
         * canvas order. Set only on a redirect cluster.
         *
         * A redirect cluster is keyed by its DESTINATION, not by a
         * route: several routes sending traffic to one place are one
         * node with several inbound edges, not N identical nodes side
         * by side. The list is what lets the node name who arrives —
         * without it, a grouped node would silently stand for an
         * unknown number of routes.
         */
        redirectSourceHosts?: string[];
} & Record<string, unknown>;

/** A per-path section header rendered INSIDE a route's single backend
 *  cluster (v2.25.0). A light child node showing the path prefix, placed
 *  above that path-pool's upstream rows. */
export type PathSectionHeaderNodeData = {
        kind: 'path-section-header';
        pathPrefix: string;
} & Record<string, unknown>;

/** Vue B col 3 child — one upstream inside a cluster group.
 *
 *  Rendered as a sibling of the cluster header in Svelte Flow's
 *  sub-flow layout (parentId points at `cluster-${routeId}` on
 *  the Node, NOT on this data payload). Carries everything the
 *  presentation needs from the source TopologyUpstream plus a
 *  pre-computed flow tier — the parent's data no longer holds an
 *  upstreams[] array, so each child must be self-sufficient. */
export type UpstreamNodeData = {
        kind: 'upstream';
        upstreamId: string;
        url: string;
        runtime?: string;
        status: HealthStatus;
        healthCheckConfigured: boolean;
        // Whether the original url started with https/h2 (or any
        // TLS-bearing scheme). Surfaced as a tiny lock glyph next to
        // the displayDisplayed URL so we don't lose the TLS info when
        // stripping the scheme.
        wasHttps: boolean;
        // Url with scheme stripped for display (http://, https://,
        // h2://, h2c:// removed). The original is preserved on `url`
        // for tooltips and any future copy-to-clipboard action.
        displayUrl: string;
        reqPerSec: number;
        p99LatencyMs: number;
        // Load ratio relative to the busiest upstream across the
        // whole canvas (C14b, 2026-06-04). Pre-computed at layout
        // time so the bar width is a simple `loadRatio * 100%`.
        // Single source of comparison — all upstream bars share the
        // same scale, the eye spots hot upstreams regardless of
        // which cluster they belong to. globalMax === 0 yields 0
        // here (clean empty bars at idle).
        //
        // Replaces the previous `fairnessRatio` which was a
        // per-cluster weight share — meaningless on single-upstream
        // clusters (always 1.0) and not comparable across clusters.
        loadRatio: number;               // 0-1
} & Record<string, unknown>;

/** Col 0 sub-node — one alias of a route (Sujet 1 Phase 3.a).
 *
 *  Rendered below the primary FQDN node in the col-0 stack,
 *  visually scaled to ~70% of the FQDN width so the hierarchy
 *  reads correctly. Carries only what the AliasNode component
 *  surfaces:
 *    - `host`: the operator-declared hostname (original casing
 *      preserved).
 *    - `reqPerSec`: windowed mean from the per-host SlidingWindow.
 *      Drives the meta line + the idle-state visual when zero.
 *    - `p99LatencyMs`: surfaced on hover only (no header
 *      slot — col 0's compact size doesn't accommodate a
 *      latency badge).
 *    - `errorRate5xx`: same hover-only treatment.
 *    - `parentRouteId`: backref to the FQDN node's route id.
 *      Used by the layout to position the alias under its
 *      primary FQDN (Phase 3.b) and by the AliasOfEdge to
 *      target the right FQDN node.
 *    - `isIdle`: pre-computed at layout time (`reqPerSec === 0`)
 *      so the component renders a grayed state without re-
 *      computing the threshold. The future "idle" tier could
 *      be extended to "very low traffic" with a different
 *      threshold; keeping the boolean here gives the layout
 *      that policy hook. */
export type AliasNodeData = {
        kind: 'alias';
        host: string;
        reqPerSec: number;
        p99LatencyMs: number;
        errorRate5xx: number;
        parentRouteId: string;
        isIdle: boolean;
} & Record<string, unknown>;

/** Col 0 visual container wrapping [primary FQDN + its aliases]
 *  (Sujet 1 Phase 3.c).
 *
 *  Pure visual binding — carries no metrics, has no handles. The
 *  container's only job is to make the route↔aliases relationship
 *  read at a glance: a subtle background rectangle behind the
 *  primary FQDN and all its alias nodes, with a slight border, so
 *  the operator's eye groups them as one logical entity instead
 *  of N floating cards.
 *
 *  Why a node rather than a Background pattern? Background is
 *  global (the canvas grid). A per-route container has variable
 *  bounds that follow the route's alias count — easier to emit
 *  as a node whose width/height we already compute server-side
 *  via routeCol0Height().
 *
 *  z-order: the route-group node must be emitted FIRST in the
 *  nodes array so it renders BEHIND the FQDN + alias cards
 *  (SvelteFlow paints nodes in array order). The layout enforces
 *  this. */
export type RouteGroupNodeData = {
        kind: 'route-group';
        routeId: string;
        /** Operator-facing host name of the primary FQDN inside
         *  the group. Used by accessibility tooling only — the
         *  node renders no visible label. */
        primaryHost: string;
} & Record<string, unknown>;

export type TopologyNodeData =
        | FQDNNodeData
        | CaddyHubNodeData
        | BackendClusterNodeData
        | PathSectionHeaderNodeData
        | UpstreamNodeData
        | AliasNodeData
        | RouteGroupNodeData;

// ---------------------------------------------------------------------------
// Edge data
// ---------------------------------------------------------------------------

export type FlowEdgeData = {
        kind: 'flow';
        reqPerSec: number;
        p99LatencyMs: number;
        errorRate5xx: number;
        /** v2.24.1 — a structural routing branch (a path-pool cluster edge):
         *  no measured traffic in v1, rendered as a dashed visible line rather
         *  than the near-invisible dead-tier stroke. When per-branch metrics
         *  land, this flag is dropped and the edge animates like any flow. */
        structural?: boolean;
} & Record<string, unknown>;

/** Phase 3.c (2026-06-17): AliasOfEdgeData removed. The Phase
 *  3.a dashed semantic edge between alias and primary FQDN became
 *  visually redundant once Phase 3.c shipped the RouteGroupNode
 *  container background — the operator now reads "this alias
 *  belongs to this route" from the shared container, not from a
 *  line. Aliases that carry traffic get their own
 *  AnimatedFlowEdge straight to the Caddy hub instead, mirroring
 *  the primary FQDN's edge so the visual sum of particles on
 *  col-1 equals the route's total flow. */

export type TopologyEdgeData = FlowEdgeData;

// ---------------------------------------------------------------------------
// Output shape
// ---------------------------------------------------------------------------

export type TopologyNode = Node<TopologyNodeData>;
export type TopologyEdge = Edge<TopologyEdgeData>;

export interface TopologyGraph {
        nodes: TopologyNode[];
        edges: TopologyEdge[];
}

// ---------------------------------------------------------------------------
// Tier resolution — single source of truth for AnimatedFlowEdge
// and the legend in the right sidebar.
//
// v2.61.1 — RESCALED. The brackets were taken from the original design
// mock (≥400 / 150 / 20 req/s) and were never checked against a real
// instance. On the operator's, which peaks around 24 req/s on its
// busiest route, EVERY edge fell under 20 and rendered the same pale
// grey. A colour scale that reports one colour is a decoration.
//
// The new brackets are roughly ×5 apart, because traffic is
// log-distributed and a linear scale wastes its whole range on volumes
// a homelab never reaches. Arenet calls itself a homelab-friendly
// reverse proxy; 400 req/s per edge is a datacentre number.
//
// Deliberately NOT operator-configurable. It is a default that was
// wrong, not a preference — and a threshold form field would ask every
// operator to solve a problem the default should have solved.
//
// Precedence:
//   1. errorRate5xx ≥ 1%   → 'bad'  (red, dashed)
//   2. errorRate5xx > 0     → 'warn' (amber) — something, not an outage
//   3. p99LatencyMs > 300   → 'warn' (amber)
//   4. reqPerSec brackets:
//        ≥ 25 req/s  → 'high'
//        5–25        → 'mid'
//        1–5         → 'low'
//        (0, 1)      → 'idle' (pale particles)
//        exactly 0   → 'dead' (no particles, line only)
//
// The 1% floor on 'bad' is the second half of the same lesson. It used
// to be `> 0`, so a SINGLE 5xx painted an edge red permanently — and
// a reverse proxy in front of a real site always has a background rate
// of them (clients vanishing mid-response, a backend worker recycling).
// The operator's forum sits at 0.8%: red for ever, which says no more
// than grey for ever did. Anything non-zero still shows as amber, so
// nothing is hidden; only the alarm colour now requires an alarm.
//
// The 'dead' tier (added 2026-06-03) carves out exactly-zero
// traffic from 'idle'. Browser smoke surfaced the confusion:
// 'idle' rendered two pale particles even when the route was
// truly silent (reqPerSec === 0), reading as "a trickle of
// traffic where there is none". 'dead' keeps the edge line
// drawn so the operator still sees the route exists, but skips
// the particle animation so silent routes look silent.

/** Flow-tier thresholds. Exported so the sidebar legend and the tests
 *  read the same numbers the resolver does — the legend used to restate
 *  them as hardcoded strings in two locales, which is how a rescale
 *  leaves the legend lying. */
export const FLOW_TIER = {
        /** errorRate5xx at or above this is an outage, not background noise. */
        badErrorRate: 0.01,
        /** p99 above this is slow enough to say so. */
        warnLatencyMs: 300,
        highReqPerSec: 25,
        midReqPerSec: 5,
        lowReqPerSec: 1,
} as const;

// ---------------------------------------------------------------------------

export function resolveFlowTier(data: FlowEdgeData): FlowTier {
        if (data.errorRate5xx >= FLOW_TIER.badErrorRate) return 'bad';
        if (data.errorRate5xx > 0) return 'warn';
        if (data.p99LatencyMs > FLOW_TIER.warnLatencyMs) return 'warn';
        if (data.reqPerSec >= FLOW_TIER.highReqPerSec) return 'high';
        if (data.reqPerSec >= FLOW_TIER.midReqPerSec) return 'mid';
        if (data.reqPerSec >= FLOW_TIER.lowReqPerSec) return 'low';
        // Exactly-zero traffic gets its own tier so AnimatedFlowEdge
        // can suppress the particle render. Any positive sub-1 value
        // still falls into 'idle' (pale particles).
        if (data.reqPerSec > 0) return 'idle';
        return 'dead';
}
