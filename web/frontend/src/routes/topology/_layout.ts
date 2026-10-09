// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Layout builder for the topology canvas.
 *
 * Single pure function `buildTopologyGraph(routes)` that emits a
 * three-column graph:
 *
 *   col 0 (FQDN)        primary host per route
 *   col 1 (Caddy hub)   single central hub node
 *   col 2 (backends)    one BackendCluster group per route with N
 *                       UpstreamNode children inside (sub-flow);
 *                       caddy-hub fans out to one edge per upstream
 *
 * C6b-i (2026-06-04) simplified this module: the previous
 * "Vue protocole" entry-point layout and the consumer column on
 * the service view were Phase-1 mock leakage — entry-point and
 * consumer fixtures were hardcoded constants, the view toggle
 * exposed a second canvas that carried no real data. Dropping
 * both views collapses the layout to a single source-of-truth
 * builder reading only from the live route list.
 */

import type {
        AliasNodeData,
        BackendClusterNodeData,
        CaddyHubNodeData,
        FlowEdgeData,
        FQDNNodeData,
        LBPolicy,
        PathSectionHeaderNodeData,
        RouteGroupNodeData,
        TopologyEdge,
        TopologyGraph,
        TopologyNode,
        TopologyRoute,
        TopologyUpstream,
        UpstreamNodeData,
} from './_types';
import { t } from '$lib/i18n';

// ---------------------------------------------------------------------------
// Layout constants
// ---------------------------------------------------------------------------

/** Three-column layout: FQDN → Caddy hub → BackendCluster. The
 *  cluster column was 900px in the four-column service view; with
 *  the consumer column removed (C6b-i) everything shifted left.
 *
 *  The columns were 400 px apart until the operator pointed out how
 *  much empty canvas sat between them: an FQDN card is FQDN_WIDTH
 *  (200 px) wide, so a 400 px pitch left 200 px of nothing before
 *  the hub. 280 keeps 80 px of breathing room on each side of the
 *  hub card — which is CSS-sized, NOT laid out from a constant here
 *  (buildCaddyNode sets x/y only), so this pitch is the one layout
 *  number that cannot be checked by arithmetic alone. */
export const COL_X = {
        FQDN: 0,
        CADDY: 280,
        BACKEND: 560,
} as const;

/** Vertical gap inserted between two stacked rows, on top of each
 *  row's own height (see computeStackYsForHeights).
 *
 *  Was 150 px from the first three-column layout through v2.58, when
 *  rows were taller. Against a 70 px FQDN_HEIGHT card that is more
 *  than twice as much air as content, which is exactly what the
 *  operator saw on a canvas of a dozen routes. 56 px still reads as
 *  "a different route" — it is ~9× UPSTREAM_GAP_Y, the gap between
 *  two cards INSIDE one cluster — while fitting ~2.7× more rows on
 *  screen. Safe to shrink because no edge carries a mid-span label:
 *  AnimatedFlowEdge draws the stroke and its animation, nothing
 *  else, so tighter rows cannot collide with edge text. */
export const ROW_SPACING_Y = 56;

// Col-0 height model (Sujet 1 Phase 3.b). The FQDN node height
// is empirically ~70 px (3 text rows at 12-13 px font + 10 px
// padding × 2 + ~6 px line-spacing); the AliasNode is ~44 px
// (2 text rows at 10-11 px + 6 px padding × 2). Both numbers are
// approximate measurements of the rendered card, not exact —
// Svelte Flow uses these only for layout positioning (not for
// SVG clipping), so a few px of slack at the bottom of the
// route's col-0 block is invisible to the operator.
//
// The gap between primary FQDN and the first AliasNode is
// generous (16 px) so the visual hierarchy "this is the primary
// host; these are its aliases" reads at a glance. Gaps between
// successive AliasNodes are tighter (8 px) so a long stack
// (the operator's 21-alias traefik route) packs vertically
// without dominating the canvas.
// Paint order, made EXPLICIT (2026-09-27).
//
// It used to rely purely on the order nodes appear in the array — the
// route-group container was pushed before its cards so SvelteFlow would
// paint it behind. That holds on a first render, when every node is
// created in one pass, and breaks on an update: SvelteFlow leaves already
// mounted nodes where they are and appends new ones, so a card created
// later lands on top of containers mounted earlier.
//
// Which is exactly what folding aliases by default (v2.48) turned from a
// latent fragility into a visible bug: expanding a route creates its
// alias cards at that moment, and they painted over the route-group
// chrome, hiding the R/s figures underneath. Before the fold default,
// routes started expanded and the cards were created on first mount.
//
// An explicit zIndex does not care when a node was created.
const Z_ROUTE_GROUP = 0; // chrome, behind everything it surrounds
const Z_CARD = 1; // FQDN + alias cards

export const FQDN_HEIGHT = 70;
const ALIAS_HEIGHT = 44;
const FQDN_TO_ALIAS_GAP = 16;
const ALIAS_TO_ALIAS_GAP = 8;

// FQDN node renders at ~200 px wide (mock-derived; see
// FQDNNode.svelte). AliasNode is 140 px wide, indented +30 px
// from the col-0 left edge — so its right edge sits at 30 + 140
// = 170 px (4 px shy of the FQDN right edge). The container
// (Phase 3.c) wraps both with a small lateral inset so it
// frames the cards without crowding them.
const FQDN_WIDTH = 200;
const ALIAS_WIDTH = 170;
const ROUTE_GROUP_PADDING = 10;
const ROUTE_GROUP_WIDTH = FQDN_WIDTH + ROUTE_GROUP_PADDING * 2;

/** Right edge of col 0, in canvas coordinates. The route-group
 *  container is the widest thing in that column and it starts one
 *  padding to the LEFT of COL_X.FQDN, so its right edge is one
 *  padding to the right of the FQDN card's. */
const COL0_RIGHT_EDGE = COL_X.FQDN + FQDN_WIDTH + ROUTE_GROUP_PADDING;

/** Clear canvas between col 0 and the destination column in the
 *  Redirects view — the span the dashed stroke and its status-code
 *  label have to themselves.
 *
 *  Equal to the width of the card the edge leaves, which is the one
 *  proportion on this canvas an operator can check by eye. */
const REDIRECT_EDGE_SPAN = FQDN_WIDTH;

/** x of the destination cluster in the Redirects view.
 *
 *  v2.67.0 reclaimed the vacated hub column, which put the 300 px
 *  destination card at COL_X.CADDY — 70 px from col 0's right edge.
 *  The operator read two cards that close as a single block: "on
 *  dirait qu'ils sont les uns sur les autres au niveau horizontale".
 *
 *  70 px is the same pitch the Proxy view uses between col 0 and the
 *  hub, where it reads fine — the hub is a small junction card, not a
 *  second column of text. Here the gap has to separate two wide cards
 *  AND carry the only thing joining them, so it gets a span of its
 *  own. Still well left of COL_X.BACKEND, so the Redirects canvas
 *  stays narrower than the Proxy one. */
export const REDIRECT_COL_X = COL0_RIGHT_EDGE + REDIRECT_EDGE_SPAN;

// Sujet 1 Phase 3.e (2026-06-17). Alias x-offset is the
// horizontal centring delta so each AliasNode shares the same
// vertical axis of symmetry as the primary FQDN above. With
// FQDN 200 px and Alias 170 px the half-delta is 15 px; the
// pre-3.e layout pushed aliases 30 px right (left-leaning
// indent) which the operator read as "broken alignment". The
// symmetric offset makes the col-0 stack read as one centred
// column, container-bound, with the primary as the visual
// anchor at the top.
const ALIAS_X_OFFSET = (FQDN_WIDTH - ALIAS_WIDTH) / 2;

// Active-alias threshold (Phase 3.c). reqPerSec strictly > 0
// is "active" — the alias gets its own AnimatedFlowEdge to
// Caddy. Strictly === 0 is "idle" — the alias renders in the
// container but no edge is emitted (keeps idle routes
// visually quiet on a 21-alias canvas).
const ALIAS_ACTIVE_THRESHOLD_RPS = 0;

/** Sub-flow cluster geometry (Vue B col 3). Children are positioned
 *  relative to the cluster group node — so x/y here is local. The
 *  group's width/height must accommodate header + N stacked upstream
 *  cards with the configured padding. Children stack vertically. */
// Cluster sized to fit "host.example.local:8443" (~22 chars at the
// upstream card's monospaced font) without truncation, plus the
// fairness bar + r/s readout below. Bumped from 260 → 300 in C6
// after the operator flagged mid-IP truncation of "http://192.168…"
// (Critique 7). Both views' col 3 is rightmost so the widening
// only pushes the canvas a bit further right — no other column
// needs to move.
const CLUSTER_WIDTH = 300;
const CLUSTER_HEADER_HEIGHT = 56;
const CLUSTER_PADDING_TOP = CLUSTER_HEADER_HEIGHT + 4;
const CLUSTER_PADDING_BOTTOM = 8;
const CLUSTER_WARNING_FOOTER_HEIGHT = 34;
const UPSTREAM_HEIGHT = 56;
const UPSTREAM_GAP_Y = 6;
const UPSTREAM_X_INSET = 8;          // inset from cluster left edge
const UPSTREAM_INNER_WIDTH = CLUSTER_WIDTH - UPSTREAM_X_INSET * 2;

// v2.25.0 Task 2 — a route's path-pools render as sections INSIDE
// its single backend cluster instead of as separate clusters
// (replaces the v2.24.0 separate-clusters-per-path and v2.24.1
// dashed-stacked-clusters models). SECTION_HEADER_HEIGHT is the
// PathSectionHeaderNode's fixed height (a one-line "── /v1 ──"
// divider); SECTION_GAP_Y is the breathing room before and after
// that header, mirroring UPSTREAM_GAP_Y's role between cards.
const SECTION_HEADER_HEIGHT = 22;
const SECTION_GAP_Y = 8;

/** Vertical extent occupied by N upstream cards (no padding). */
function upstreamsBlockHeight(n: number): number {
        if (n === 0) return 0;
        return n * UPSTREAM_HEIGHT + (n - 1) * UPSTREAM_GAP_Y;
}

/** One line of the source list inside a grouped redirect cluster.
 *  Matches `.redirect-source` in BackendClusterNode. */
const REDIRECT_SOURCE_LINE_HEIGHT = 17;

/** Extra height a redirect cluster needs for the routes that arrive
 *  at it.
 *
 *  Zero for a single source, so a one-route redirect keeps EXACTLY
 *  the height it had before grouping existed — the destination line
 *  alone has always fitted in the padding, and changing that would
 *  move every other cluster on the canvas for no reason.
 *
 *  Grouped nodes pay for the lines beyond the first. */
function redirectSourcesBlockHeight(sourceCount: number): number {
        if (sourceCount <= 1) return 0;
        return (sourceCount - 1) * REDIRECT_SOURCE_LINE_HEIGHT;
}

/** Total cluster group height for N upstream children. When a warning
 *  is present, reserve extra bottom space so the absolute-positioned
 *  warning footer in BackendClusterNode doesn't overlap the last
 *  upstream card. */
function clusterTotalHeight(n: number, hasWarning: boolean): number {
        const base = CLUSTER_PADDING_TOP + upstreamsBlockHeight(n) + CLUSTER_PADDING_BOTTOM;
        return hasWarning ? base + CLUSTER_WARNING_FOOTER_HEIGHT : base;
}

/** v2.25.0 Task 2 — total height of a route's SINGLE backend
 *  cluster: root upstreams block, then for each path-pool a
 *  section header (with its leading + trailing gap) followed by
 *  that section's own upstreams block. A route with zero path
 *  pools reduces to exactly `clusterTotalHeight(rootN, hasWarning)`
 *  — the non-regression contract for paths-less routes. */
function singleClusterHeight(
        rootN: number,
        pathSections: { upstreams: unknown[] }[],
        hasWarning: boolean,
): number {
        let h = CLUSTER_PADDING_TOP + upstreamsBlockHeight(rootN);
        for (const s of pathSections) {
                h += SECTION_GAP_Y + SECTION_HEADER_HEIGHT + SECTION_GAP_Y + upstreamsBlockHeight(s.upstreams.length);
        }
        h += CLUSTER_PADDING_BOTTOM;
        return hasWarning ? h + CLUSTER_WARNING_FOOTER_HEIGHT : h;
}

/** Total vertical height of a route's col-0 block, accounting
 *  for the primary FQDN + N alias sub-nodes (Sujet 1 Phase
 *  3.b). When the route has zero aliases this returns the
 *  bare FQDN_HEIGHT so the layout for non-alias routes stays
 *  byte-equal to the pre-Phase-3.b shape (modulo the per-route
 *  stacker migration, which is symmetric for the zero-alias
 *  case).
 *
 *  Formula:
 *    FQDN_HEIGHT
 *    + (aliasCount > 0 ? FQDN_TO_ALIAS_GAP : 0)
 *    + aliasCount × ALIAS_HEIGHT
 *    + (aliasCount > 0 ? (aliasCount - 1) × ALIAS_TO_ALIAS_GAP : 0)
 */
function routeCol0Height(aliasCount: number): number {
        if (aliasCount === 0) return FQDN_HEIGHT;
        return (
                FQDN_HEIGHT
                + FQDN_TO_ALIAS_GAP
                + aliasCount * ALIAS_HEIGHT
                + (aliasCount - 1) * ALIAS_TO_ALIAS_GAP
        );
}

/** v2.25.0 (Task 2): back to ONE backend cluster per route.
 *  Per-path routing branches (route.pathPools) no longer render
 *  as their own separate clusters (v2.24.0) nor as dashed-stacked
 *  sibling clusters (v2.24.1) — each renders as a `path-section-
 *  header` + its own upstream children INSIDE the route's single
 *  cluster. ClusterSpec is therefore one entry per ROUTE again;
 *  `pathSections` carries the ordered per-prefix child groups the
 *  child-cursor walk (below) lays out after the root upstreams. */
type ClusterPathSection = {
        prefix: string;
        upstreams: TopologyUpstream[];
};

type ClusterSpec = {
        route: TopologyRoute;
        clusterId: string;
        rootUpstreams: TopologyUpstream[];
        pathSections: ClusterPathSection[];
        lbPolicy: LBPolicy;
        hasHealthCheck: boolean;
        warning?: string;
        /** v2.61 — set on a redirecting route; the cluster draws the
         *  destination instead of an empty pool. */
        redirectTarget?: string;
        /** Every route that redirects to `redirectTarget`, in canvas
         *  order. Set only on a redirect spec, where ONE node stands
         *  for a destination rather than for a route. `route` above is
         *  then the first of these — kept so the existing per-route
         *  plumbing (ids, flow data) still has a representative. */
        redirectSources?: TopologyRoute[];
};

// ===========================================================================
// Public API — buildTopologyGraph
// ===========================================================================

/**
 * Build the topology graph from the live route list. Single source
 * of truth — no fixtures, no view variants.
 *
 *   col 0 (FQDN)        primary host per route
 *   col 1 (Caddy hub)   single central hub node
 *   col 2 (backends)    one BackendCluster group per route with N
 *                       UpstreamNode children inside (sub-flow);
 *                       caddy-hub fans out to one edge per upstream
 *
 * Sujet 1 Phase 3.e (2026-06-17). `collapsedRouteIds` is the set
 * of routes whose alias sub-stack is currently FOLDED. A route in
 * this set:
 *   - still emits its primary FQDN node + its container (so the
 *     visual signature "this route is one of the ones with aliases"
 *     persists even when folded);
 *   - skips every AliasNode + per-alias AnimatedFlowEdge;
 *   - keeps its FQDN→Caddy edge at the FULL route.reqPerSec (no
 *     primary-vs-alias rebalance, since aliases aren't drawing
 *     any particles of their own).
 *
 * Default behaviour (empty set, omitted parameter) is full
 * expansion — matches the pre-3.e shape so callers that don't pass
 * the set get the Phase 3.d layout byte-equal.
 */
/** Build-time options. */
export type TopologyGraphOptions = {
        /**
         * Drop the Caddy hub and wire each host straight to its
         * redirect destination. Set by the Redirects view.
         *
         * The hub is the literal truth for a proxied route — traffic
         * really does pass through Arenet to reach the upstream. For a
         * redirect Arenet answers the client and the client goes on by
         * itself, so in a view where every route is a redirect the hub
         * is a hop that carries nothing, identical on every row. The
         * operator described what that looks like: "cette notion de
         * noeud a gauche avec rond au milieu et rien vers les noeuds a
         * droite est bizarre".
         *
         * They chose keeping it when shown three mockups, then asked
         * for it gone after living with it. Both reads were
         * defensible; the one that survived contact with the screen
         * wins.
         */
        hideHub?: boolean;
};

export function buildTopologyGraph(
        routes: TopologyRoute[],
        collapsedRouteIds: ReadonlySet<string> = new Set<string>(),
        opts: TopologyGraphOptions = {},
): TopologyGraph {
        const hideHub = opts.hideHub === true;
        // routeID -> destination cluster id, for the hub-less wiring.
        // Filled by the clusterSpecs loop, read by the edge loop after
        // it.
        const redirectClusterByRoute = new Map<string, string>();
        const nodes: TopologyNode[] = [];
        const edges: TopologyEdge[] = [];

        // C14b (2026-06-04): UpstreamNode bar width is a
        // global-relative ratio reqPerSec / globalMax. Compute once
        // up front so every upstream's data carries its own
        // pre-divided loadRatio. Falls back to 0 across the board
        // when nothing has traffic — avoids divide-by-zero and keeps
        // all bars empty at idle for a clean baseline.
        let globalMaxReqPerSec = 0;
        for (const r of routes) {
                for (const u of r.upstreams) {
                        if (u.reqPerSec > globalMaxReqPerSec) globalMaxReqPerSec = u.reqPerSec;
                }
        }

        // Col 0 — FQDN + per-route AliasNodes (Sujet 1 Phase 3.b).
        //
        // Pre-3.b shape: one FQDN per route, evenly spaced via
        // computeStackYs(routes.length). With aliases shipping
        // as first-class sub-nodes underneath the primary FQDN,
        // each route's col-0 block can grow vertically to fit
        // N alias cards. We migrate to computeStackYsForHeights
        // (already proven on backend clusters) so a route with
        // 21 aliases doesn't overlap its neighbours' FQDN cards
        // while a route without aliases keeps the same
        // single-card footprint as before.
        //
        // Sort: aliasMetrics arrives pre-sorted desc by
        // reqPerSec from the backend (Phase 2.2 buildAliasMetrics
        // applies the sort). The layout preserves that order
        // verbatim — top consumer first, idle aliases at the
        // bottom.
        // Phase 3.e: col-0 block height depends on whether the
        // route is collapsed. A collapsed route always sizes its
        // block to bare FQDN_HEIGHT — the alias sub-stack is
        // hidden so the block must shrink, otherwise neighbours
        // would stay artificially pushed apart and the canvas
        // would look like the aliases are still there but
        // invisible.
        const col0Heights = routes.map((r) => {
                if (collapsedRouteIds.has(r.id)) return FQDN_HEIGHT;
                return routeCol0Height(r.aliasMetrics?.length ?? 0);
        });
        const col0BlockTops = computeStackYsForHeights(col0Heights);
        routes.forEach((route, i) => {
                const blockTop = col0BlockTops[i];
                const aliasMetrics = route.aliasMetrics ?? [];
                const hasAliases = aliasMetrics.length > 0;
                const collapsed = collapsedRouteIds.has(route.id);
                // Sum every alias rate — active + idle. Idle
                // aliases contribute zero so the result equals
                // sum(active aliases) but the policy "sum all
                // aliases" is stable as aliases cross the active
                // threshold; the number doesn't twitch when an
                // alias flips between idle and low-traffic in the
                // collapsed-meta display.
                const aliasTotalRps = aliasMetrics.reduce((sum, a) => sum + a.reqPerSec, 0);

                // Phase 3.c: emit the RouteGroupNode FIRST (when the
                // route has aliases) so SvelteFlow paints it BEHIND
                // the FQDN + alias cards. The container is pure
                // visual chrome (no handles, no metrics) — it binds
                // the operator's eye to "primary + its aliases =
                // one route". A route without aliases gets no
                // container; the bare FQDN card stands on its own
                // exactly as it did pre-3.c (backward compat).
                //
                // Phase 3.e: still emit the container when the
                // route is collapsed AND has aliases. The
                // container's height shrinks to fit the FQDN
                // alone, but its presence preserves the visual
                // signature "this route has more behind the
                // chevron" even when folded.
                // HOTFIX (2026-06-17 #4, post-3.e ship) — revert
                // the parent/child wire shipped in HF3. The wire
                // solved the visual desync (container stayed put
                // when the FQDN dragged) BUT regressed the drag
                // affordance : with draggable:false on the FQDN
                // child, the operator could no longer drag the
                // primary card directly — only the surrounding
                // blue chrome was draggable, which is unnatural
                // for the route-row's focal element.
                //
                // The new wire :
                //  - Container : standalone node, ABSOLUTE position,
                //    draggable: false (it's pure visual chrome —
                //    operator never needed to drag it directly,
                //    they wanted to drag the FQDN and have the
                //    container follow).
                //  - FQDN : standalone node, ABSOLUTE position,
                //    draggable: true (the natural affordance).
                //  - Alias children : standalone, ABSOLUTE
                //    position, draggable: false (the operator
                //    drags the primary, aliases follow as a
                //    group — they're not individually draggable
                //    by design).
                //
                // The group-follows-primary behaviour is wired in
                // +page.svelte via SvelteFlow's onnodedrag event :
                // when an FQDN node moves, compute the delta and
                // apply it to the matching route-group + every
                // alias of the same route. The delta is small
                // (single drag event), so the side-effect of
                // updating ~22 nodes for the traefik scenario is
                // cheap (sub-ms in jsdom + SvelteFlow's diff is
                // O(N) per node).
                //
                // Routes WITHOUT aliases : no container, FQDN
                // standalone (unchanged backward-compat path).
                if (hasAliases) {
                        const groupHeight = col0Heights[i] + ROUTE_GROUP_PADDING * 2;
                        const groupData: RouteGroupNodeData = {
                                kind: 'route-group',
                                routeId: route.id,
                                primaryHost: route.host,
                        };
                        nodes.push({
                                id: `route-group-${route.id}`,
                                type: 'route-group',
                                position: {
                                        x: COL_X.FQDN - ROUTE_GROUP_PADDING,
                                        y: blockTop - ROUTE_GROUP_PADDING,
                                },
                                width: ROUTE_GROUP_WIDTH,
                                height: groupHeight,
                                data: groupData,
                                draggable: false,
                                selectable: false,
                                zIndex: Z_ROUTE_GROUP,
                        });
                }

                const fqdnData: FQDNNodeData = {
                        kind: 'fqdn',
                        host: route.host,
                        protocols: formatProtocols(route),
                        meta: formatFQDNMeta(route),
                        aliases: route.aliases,
                        wafLevel: route.wafLevel ?? 'off',
                        routeId: route.id,
                        aliasCount: aliasMetrics.length,
                        aliasTotalRps,
                        collapsed,
                        disabled: route.disabled,
                };
                // Standalone FQDN — absolute position, default
                // drag affordance. Whether the route has aliases
                // or not, the FQDN is the operator's drag handle
                // for the row.
                nodes.push({
                        id: `fqdn-${route.id}`,
                        type: 'fqdn',
                        position: { x: COL_X.FQDN, y: blockTop },
                        data: fqdnData,
                        zIndex: Z_CARD,
                });

                // Phase 3.e: skip the entire alias sub-node loop
                // when the route is collapsed. The chevron-driven
                // collapsed state means the operator wants the row
                // condensed; emitting the cards anyway would
                // either render them hidden (wasted SvelteFlow
                // bookkeeping) or render them visible (defeats
                // the toggle).
                if (collapsed) return;

                // Alias sub-nodes (Phase 3.b shape preserved). The
                // aliasMetrics slice from the backend is already
                // sorted desc by reqPerSec with alphabetical tie-
                // break for idles; render in that order so the top
                // consumer sits directly under the primary FQDN.
                //
                // Phase 3.e (2026-06-17): x-offset switched from
                // the indent-leaning +30 px to a true horizontal
                // centring (+15 px = (FQDN_WIDTH - ALIAS_WIDTH) / 2)
                // so aliases share the same vertical axis of
                // symmetry as the primary FQDN. The container's
                // background hugs both — the eye reads col 0 as
                // one centred column rather than a left-leaning
                // stair.
                aliasMetrics.forEach((alias, aIdx) => {
                        // HOTFIX (2026-06-17 #4) : absolute
                        // positions restored (parent / child wire
                        // reverted). Aliases are draggable:false —
                        // the operator drags the primary FQDN
                        // and the +page.svelte onnodedrag handler
                        // applies the same delta to every alias
                        // of the same route, keeping the visual
                        // group cohesive without making each
                        // alias an independent drag target.
                        const aliasY =
                                blockTop
                                + FQDN_HEIGHT
                                + FQDN_TO_ALIAS_GAP
                                + aIdx * (ALIAS_HEIGHT + ALIAS_TO_ALIAS_GAP);
                        const aliasData: AliasNodeData = {
                                kind: 'alias',
                                host: alias.host,
                                reqPerSec: alias.reqPerSec,
                                p99LatencyMs: alias.p99LatencyMs,
                                errorRate5xx: alias.errorRate5xx,
                                parentRouteId: route.id,
                                isIdle: alias.reqPerSec === 0,
                        };
                        nodes.push({
                                id: `alias-${route.id}-${aIdx}`,
                                type: 'alias',
                                position: {
                                        x: COL_X.FQDN + ALIAS_X_OFFSET,
                                        y: aliasY,
                                },
                                draggable: false,
                                selectable: false,
                                data: aliasData,
                                zIndex: Z_CARD,
                        });
                });
        });

        // Col 1 — Caddy hub
        if (!hideHub) {
                nodes.push(buildCaddyNode(routes, COL_X.CADDY));
        }

        // Col 2 — Backend clusters as sub-flow groups + N upstream children
        // (+ per-path-pool section headers).
        //
        // Each cluster is a group node sized to fit its upstream pool.
        // Cluster Ys are computed so the *centers* of variable-height
        // groups remain evenly spaced and prevent overlap when one
        // route has many upstreams. Children carry parentId +
        // extent: 'parent' so Svelte Flow keeps them inside the group
        // when the user drags either the parent or a child.
        //
        // v2.25.0 (Task 2): back to ONE cluster per route (replaces
        // v2.24.0's one-cluster-per-path-pool and v2.24.1's dashed-
        // stacked-clusters models). Per-path routing branches
        // (route.pathPools) render INSIDE the route's single cluster
        // as a `path-section-header` child + that section's own
        // upstream children, laid out AFTER the root upstreams with
        // a running Y cursor. A route with zero pathPools contributes
        // zero sections — non-regression: identical to the pre-
        // v2.24.0 single-cluster shape.
        // One spec per PROXY route, as ever — and one spec per distinct
        // REDIRECT DESTINATION.
        //
        // The operator's words: "sinon ça fait trop de node". Before
        // this, three routes pointing at one Discord invite drew three
        // nodes carrying the same URL, side by side, which says
        // "three destinations" when there is one. Grouping makes the
        // convergence the thing you see: one node, three inbound
        // edges.
        //
        // Route ORDER is preserved rather than partitioned: a group
        // takes the slot of its first member. A proxy-only route list
        // therefore produces byte-identical specs to the pre-grouping
        // build, which is what the layout non-regression tests pin.
        const redirectGroups = groupRoutesByRedirectTarget(routes);
        const emittedGroups = new Set<string>();
        const clusterSpecs: ClusterSpec[] = [];
        routes.forEach((route) => {
                const groupKey = route.redirectTarget ? redirectTargetKey(route.redirectTarget) : undefined;
                if (groupKey !== undefined) {
                        // Only the first member of a group emits the node.
                        if (emittedGroups.has(groupKey)) return;
                        emittedGroups.add(groupKey);
                        const sources = redirectGroups.get(groupKey) ?? [route];
                        clusterSpecs.push({
                                route,
                                // Keyed by the destination, URL-encoded rather than
                                // slugified: a lossy slug could map two genuinely
                                // different destinations onto one id and merge them
                                // silently. Stable across rebuilds too, so Svelte
                                // Flow keeps the node's identity (and the position
                                // the operator dragged it to) when routes are added.
                                clusterId: `redirect-to-${encodeURIComponent(groupKey)}`,
                                rootUpstreams: [],
                                pathSections: [],
                                lbPolicy: route.lbPolicy,
                                hasHealthCheck: false,
                                warning: deriveClusterWarning(route),
                                // The first source's spelling wins as the label. The
                                // key normalises away a trailing slash and case, so
                                // the raw string is the honest thing to show.
                                redirectTarget: route.redirectTarget,
                                redirectSources: sources,
                        });
                        // Every source host points at this destination, so
                        // the hub-less wiring can find it from any of them.
                        const clusterId = `redirect-to-${encodeURIComponent(groupKey)}`;
                        sources.forEach((src) => redirectClusterByRoute.set(src.id, clusterId));
                        return;
                }
                clusterSpecs.push({
                        route,
                        clusterId: `cluster-${route.id}`,
                        rootUpstreams: route.upstreams,
                        pathSections: (route.pathPools ?? []).map((pp) => ({
                                prefix: pp.pathPrefix,
                                upstreams: pp.upstreams,
                        })),
                        lbPolicy: route.lbPolicy,
                        hasHealthCheck: route.hasHealthCheck,
                        warning: deriveClusterWarning(route),
                        redirectTarget: route.redirectTarget,
                });
        });

        const clusterHeights = clusterSpecs.map(
                (spec) =>
                        singleClusterHeight(spec.rootUpstreams.length, spec.pathSections, spec.warning !== undefined)
                        + redirectSourcesBlockHeight(spec.redirectSources?.length ?? 0),
        );
        const clusterYs = computeStackYsForHeights(clusterHeights);
        clusterSpecs.forEach((spec, i) => {
                const allUpstreams = spec.rootUpstreams.concat(
                        spec.pathSections.flatMap((s) => s.upstreams),
                );
                const healthyCount = allUpstreams.filter((u) => u.status === 'healthy').length;
                const unhealthyCount = allUpstreams.filter((u) => u.status === 'unhealthy').length;
                const totalCount = allUpstreams.length;
                const clusterData: BackendClusterNodeData = {
                        kind: 'backend-cluster',
                        // A redirect node IS the destination, so it is labelled
                        // by the destination's host. Labelling it with the first
                        // source's host — which is what happened before grouping
                        // — named the node after one of the things pointing AT
                        // it, and became plainly wrong as soon as two routes
                        // converged.
                        clusterLabel: spec.redirectSources
                                ? deriveRedirectLabel(spec.redirectTarget)
                                : (spec.route.clusterLabel ?? deriveClusterLabel(spec.route.host)),
                        runtime: dominantRuntime(allUpstreams),
                        lbPolicy: spec.lbPolicy,
                        healthyCount,
                        unhealthyCount,
                        totalCount,
                        hasHealthCheck: spec.hasHealthCheck,
                        warning: spec.warning,
                        redirectTarget: spec.redirectTarget,
                        redirectSourceHosts: spec.redirectSources?.map((r) => r.host),
                };
                nodes.push({
                        id: spec.clusterId,
                        type: 'backend-cluster',
                        position: { x: hideHub ? REDIRECT_COL_X : COL_X.BACKEND, y: clusterYs[i] },
                        width: CLUSTER_WIDTH,
                        height: clusterHeights[i],
                        data: clusterData,
                });

                // Children walk: root upstreams first (no header —
                // Q2=B), then per path-pool a section header + its
                // upstreams, tracked with a running local Y cursor.
                let cy = CLUSTER_PADDING_TOP;
                spec.rootUpstreams.forEach((upstream, ui) => {
                        pushUpstreamChild(nodes, upstream, spec.clusterId, spec.route.id, cy, globalMaxReqPerSec);
                        cy += UPSTREAM_HEIGHT + (ui < spec.rootUpstreams.length - 1 ? UPSTREAM_GAP_Y : 0);
                });
                spec.pathSections.forEach((section, si) => {
                        cy += SECTION_GAP_Y;
                        const headerId = `path-section-header-${spec.route.id}-${si}`;
                        const headerData: PathSectionHeaderNodeData = {
                                kind: 'path-section-header',
                                pathPrefix: section.prefix,
                        };
                        nodes.push({
                                id: headerId,
                                type: 'path-section-header',
                                position: { x: UPSTREAM_X_INSET, y: cy },
                                width: UPSTREAM_INNER_WIDTH,
                                height: SECTION_HEADER_HEIGHT,
                                parentId: spec.clusterId,
                                extent: 'parent',
                                draggable: false,
                                selectable: false,
                                data: headerData,
                        });
                        cy += SECTION_HEADER_HEIGHT + SECTION_GAP_Y;
                        section.upstreams.forEach((upstream, ui) => {
                                pushUpstreamChild(nodes, upstream, spec.clusterId, spec.route.id, cy, globalMaxReqPerSec);
                                cy += UPSTREAM_HEIGHT + (ui < section.upstreams.length - 1 ? UPSTREAM_GAP_Y : 0);
                        });
                });
        });

        // Edges: FQDN -> caddy + (per active alias) alias -> caddy,
        // then caddy -> upstream (fan-out per cluster).
        //
        // Phase 3.c (2026-06-17): two interleaved changes.
        //
        // 1. Per-active-alias edge to Caddy. For each alias with
        //    reqPerSec > ALIAS_ACTIVE_THRESHOLD_RPS, emit an
        //    AnimatedFlowEdge sourced from the alias node, target
        //    Caddy hub, carrying the alias's own reqPerSec / p99 /
        //    5xx. Idle aliases (reqPerSec === 0) skip — keeps a
        //    21-alias canvas with 3 active aliases visually quiet
        //    on col 1.
        //
        // 2. Primary FQDN edge intensity rebalanced. The route's
        //    total reqPerSec is split between the primary host and
        //    the aliases; the primary edge now carries ONLY the
        //    primary's own traffic (route.reqPerSec minus the sum
        //    of the active aliases' rates). The visual sum of all
        //    edges entering Caddy from a route still equals
        //    route.reqPerSec — the operator reads "this column of
        //    particles totals my route's load" intuitively.
        //
        //    Clamped at zero: rounding error in the windowed
        //    aggregator can produce a slightly-negative residue
        //    (sum of alias rates over a 60 s window can drift a
        //    fraction higher than the route's own rate over the
        //    same window). Clamping protects the AnimatedFlowEdge
        //    tier resolver from a negative reqPerSec sneaking
        //    through.
        // Where a host's traffic edge points.
        //
        // With the hub it is the hub. Without it, the host's own
        // destination — and that single edge then carries two honest
        // facts at once: the particles count the redirects actually
        // issued, and the dash plus the code say "answered here, not
        // forwarded". Nothing is lost by merging them, because the
        // thing the hub used to show (Arenet is what answers) is
        // exactly what the dash already says.
        const trafficTarget = (route: TopologyRoute): string =>
                hideHub ? (redirectClusterByRoute.get(route.id) ?? 'caddy-hub') : 'caddy-hub';

        // The redirect marker, applied to the merged edge so a
        // hub-less view still reads as a redirect rather than a proxy.
        const withRedirectMark = (route: TopologyRoute, data: FlowEdgeData): FlowEdgeData => {
                if (!hideHub || !redirectClusterByRoute.has(route.id)) return data;
                return { ...data, redirectStatusCode: route.redirectStatusCode ?? 301 };
        };

        routes.forEach((route) => {
                const aliasMetrics = route.aliasMetrics ?? [];
                const collapsed = collapsedRouteIds.has(route.id);

                // Phase 3.e: when the route is collapsed, the
                // alias sub-nodes are NOT in the graph, so they
                // can't be edge sources. The primary FQDN edge
                // absorbs the FULL route.reqPerSec — no rebalance
                // — so the operator still sees the total flow on
                // the canvas (just consolidated on one edge
                // instead of fanning out). Expand the route and
                // the rebalance + per-alias edges kick back in.
                if (collapsed) {
                        edges.push(
                                makeFlowEdge(`e-fqdn-${route.id}-caddy`, `fqdn-${route.id}`, trafficTarget(route), withRedirectMark(route, {
                                        kind: 'flow',
                                        reqPerSec: route.reqPerSec,
                                        p99LatencyMs: route.p99LatencyMs,
                                        errorRate5xx: route.errorRate5xx,
                                })),
                        );
                        return;
                }

                const activeAliasRpsSum = aliasMetrics.reduce(
                        (sum, a) => (a.reqPerSec > ALIAS_ACTIVE_THRESHOLD_RPS ? sum + a.reqPerSec : sum),
                        0,
                );
                const primaryRps = Math.max(0, route.reqPerSec - activeAliasRpsSum);
                edges.push(
                        makeFlowEdge(`e-fqdn-${route.id}-caddy`, `fqdn-${route.id}`, trafficTarget(route), withRedirectMark(route, {
                                kind: 'flow',
                                reqPerSec: primaryRps,
                                p99LatencyMs: route.p99LatencyMs,
                                errorRate5xx: route.errorRate5xx,
                        })),
                );

                aliasMetrics.forEach((alias, aIdx) => {
                        if (alias.reqPerSec <= ALIAS_ACTIVE_THRESHOLD_RPS) return;
                        edges.push(
                                makeFlowEdge(
                                        `e-alias-${route.id}-${aIdx}-caddy`,
                                        `alias-${route.id}-${aIdx}`,
                                        // Same target as the route's own edge: an alias
                                        // of a redirecting host redirects too, so it
                                        // must land on the destination rather than on a
                                        // hub that is not in this view.
                                        trafficTarget(route),
                                        withRedirectMark(route, {
                                                kind: 'flow',
                                                reqPerSec: alias.reqPerSec,
                                                p99LatencyMs: alias.p99LatencyMs,
                                                errorRate5xx: alias.errorRate5xx,
                                        }),
                                ),
                        );
                });
        });

        // Caddy hub -> each ROOT upstream child (N edges per cluster),
        // plus ONE structural edge per path-pool section.
        //
        // Pre-restructure (one edge per cluster) hid per-upstream flow
        // shape — the operator couldn't tell which replica was hot. We
        // emit one edge per ROOT upstream, carrying that upstream's
        // own reqPerSec / p99 / a synthesized 5xx (route-level — we
        // don't have per-upstream error rates yet, see Stage B).
        //
        // Falls back to a single edge to the cluster group when the
        // route has 0 root upstreams (degenerate route): the cluster
        // node still renders its empty-pool warning, and the edge
        // lets the operator see the route exists. This is the exact
        // pre-v2.24.0 root fan-out — byte-identical for a paths-less
        // route.
        //
        // v2.25.0 (Task 2): path-pools no longer get their own
        // cluster edge. Each path-pool section instead gets exactly
        // ONE structural edge caddy-hub -> <section-header node>,
        // carrying nominal/zero flow (pathPoolFlowData(), kept from
        // v2.24.1) — not fabricated, the backend hasn't wired
        // per-path metrics yet.
        clusterSpecs.forEach((spec) => {
                if (spec.rootUpstreams.length === 0) {
                        // ONE edge per source route, even when several share
                        // the destination node. The edge id still carries the
                        // route id, so nothing collides and a grouped node
                        // reads as "three routes arrive here" rather than
                        // flattening three flows into one.
                        //
                        // A degenerate proxy route (no upstream, no redirect)
                        // has no redirectSources, falls back to its own single
                        // edge, and is byte-identical to the pre-grouping
                        // build.
                        const sources = spec.redirectSources ?? [spec.route];
                        sources.forEach((src) => {
                                const data = routeFlowData(src);
                                if (spec.redirectSources) {
                                        // Nothing traverses this edge. Arenet answers
                                        // the client and the client goes on by itself,
                                        // so the edge states where it was sent rather
                                        // than drawing a flow. The real traffic is on
                                        // the FQDN-to-hub edge before it, which keeps
                                        // its particles.
                                        data.redirectStatusCode = src.redirectStatusCode ?? 301;
                                }
                                // With the hub gone there is no source for this
                                // edge: the host now points straight at the
                                // destination, and that single edge already carries
                                // both the traffic and the redirect mark.
                                if (hideHub && redirectClusterByRoute.has(src.id)) return;
                                edges.push(makeFlowEdge(
                                        `e-caddy-cluster-${src.id}`,
                                        'caddy-hub',
                                        spec.clusterId,
                                        data,
                                ));
                        });
                } else {
                        spec.rootUpstreams.forEach((upstream) => {
                                edges.push(makeFlowEdge(
                                        `e-caddy-upstream-${spec.route.id}-${upstream.id}`,
                                        'caddy-hub',
                                        `upstream-${spec.route.id}-${upstream.id}`,
                                        {
                                                kind: 'flow',
                                                reqPerSec: upstream.reqPerSec,
                                                p99LatencyMs: upstream.p99LatencyMs,
                                                // Per-upstream 5xx not yet instrumented (Stage B
                                                // — #R-TOPO-upstream-metrics). Route-level rate is
                                                // the closest signal: if the route is bleeding 5xx,
                                                // surfacing it on every upstream edge is honest about
                                                // the lack of per-replica visibility.
                                                errorRate5xx: spec.route.errorRate5xx,
                                        },
                                ));
                        });
                }

                spec.pathSections.forEach((_section, si) => {
                        edges.push(makeFlowEdge(
                                `e-caddy-section-${spec.route.id}-${si}`,
                                'caddy-hub',
                                `path-section-header-${spec.route.id}-${si}`,
                                pathPoolFlowData(),
                        ));
                });
        });

        return { nodes, edges };
}

// ===========================================================================
// Helpers
// ===========================================================================

function buildCaddyNode(routes: TopologyRoute[], x: number): TopologyNode {
        // C21 (2026-06-04) trimmed the visible content of the hub
        // to "Caddy" + aggregate req/s; version + instanceId now
        // surface only as a hover tooltip in the component.
        const data: CaddyHubNodeData = {
                kind: 'caddy',
                version: 'Caddy 2.8',
                instanceId: 'arenet-instance',
                aggregateReqPerSec: routes.reduce((sum, r) => sum + r.reqPerSec, 0),
        };
        return {
                id: 'caddy-hub',
                type: 'caddy',
                position: { x, y: 0 },
                data,
        };
}

function routeFlowData(route: TopologyRoute): FlowEdgeData {
        return {
                kind: 'flow',
                reqPerSec: route.reqPerSec,
                p99LatencyMs: route.p99LatencyMs,
                errorRate5xx: route.errorRate5xx,
        };
}

/** Flow data for a path-pool cluster's caddy->cluster edge.
 *  Path-pools are structure-only in v1 (no per-path traffic
 *  instrumentation yet) — every path-pool cluster gets exactly one
 *  such edge carrying nominal/zero flow, never fabricated numbers
 *  borrowed from the route total. */
function pathPoolFlowData(): FlowEdgeData {
        return { kind: 'flow', reqPerSec: 0, p99LatencyMs: 0, errorRate5xx: 0, structural: true };
}

function makeFlowEdge(
        id: string,
        source: string,
        target: string,
        data: FlowEdgeData,
): TopologyEdge {
        return { id, source, target, type: 'animated-flow', data };
}

/** Push one UpstreamNode child of a backend cluster at local Y
 *  `cy`, extracted (v2.25.0 Task 2) so both the root upstreams
 *  block and each path-pool section's upstreams block share the
 *  exact same child-construction logic (all UpstreamNodeData
 *  fields + loadRatio math + parentId/extent/draggable). Upstream
 *  node ids stay `upstream-${routeId}-${upstream.id}` — the
 *  backend already namespaces path-pool upstream ids as
 *  `${routeId}-path-${pi}-${j}`, so root and path upstream ids
 *  never collide within the same route. */
function pushUpstreamChild(
        nodes: TopologyNode[],
        upstream: TopologyUpstream,
        clusterId: string,
        routeId: string,
        cy: number,
        globalMaxReqPerSec: number,
): void {
        const { displayUrl, wasHttps } = formatUpstreamUrl(upstream.url);
        const loadRatio = globalMaxReqPerSec > 0 ? upstream.reqPerSec / globalMaxReqPerSec : 0;
        const childData: UpstreamNodeData = {
                kind: 'upstream',
                upstreamId: upstream.id,
                url: upstream.url,
                displayUrl,
                wasHttps,
                runtime: upstream.runtime,
                status: upstream.status,
                healthCheckConfigured: upstream.healthCheckConfigured,
                reqPerSec: upstream.reqPerSec,
                p99LatencyMs: upstream.p99LatencyMs,
                loadRatio,
        };
        nodes.push({
                id: `upstream-${routeId}-${upstream.id}`,
                type: 'upstream',
                position: { x: UPSTREAM_X_INSET, y: cy },
                width: UPSTREAM_INNER_WIDTH,
                height: UPSTREAM_HEIGHT,
                parentId: clusterId,
                extent: 'parent',
                draggable: false,
                selectable: false,
                data: childData,
        });
}

/** Stack variable-height blocks vertically with a constant gap
 *  between them, centered around y=0. Returns the TOP-Y of each
 *  block (Svelte Flow positions nodes by their top-left corner).
 *
 *  Used for backend clusters whose height grows with the number
 *  of upstreams — a fixed-row stacker would overlap a tall
 *  cluster with its neighbour. */
function computeStackYsForHeights(heights: number[]): number[] {
        if (heights.length === 0) return [];
        const totalHeight =
                heights.reduce((sum, h) => sum + h, 0) +
                (heights.length - 1) * ROW_SPACING_Y;
        const startTop = -totalHeight / 2;
        const ys: number[] = [];
        let cursor = startTop;
        for (const h of heights) {
                ys.push(cursor);
                cursor += h + ROW_SPACING_Y;
        }
        return ys;
}

function deriveClusterLabel(host: string): string {
        const parts = host.split('.');
        return parts[0] || host;
}

/**
 * Grouping key for a redirect destination.
 *
 * Normalises only what cannot change where traffic lands: the case of
 * the scheme and host (both case-insensitive per RFC 3986 §3.1 / §3.2.2)
 * and a single trailing slash on an otherwise-empty path, since
 * `https://x` and `https://x/` are the same resource.
 *
 * Deliberately conservative beyond that. The path, the query and the
 * fragment are compared verbatim: `/a` and `/A` are different paths on
 * most servers, and over-normalising would merge two destinations into
 * one node, which is a worse error than drawing two nodes for one
 * destination — the operator can see duplicates, they cannot see a
 * merge.
 *
 * A target the URL parser rejects is keyed by its trimmed raw string,
 * so a malformed redirect still groups with its identical twin instead
 * of throwing.
 */
function redirectTargetKey(target: string): string {
        const raw = target.trim();
        try {
                const u = new URL(raw);
                const path = u.pathname === '/' ? '' : u.pathname;
                return `${u.protocol.toLowerCase()}//${u.host.toLowerCase()}${path}${u.search}${u.hash}`;
        } catch {
                return raw;
        }
}

/**
 * Index every redirecting route by its destination key, preserving the
 * order routes arrive in so the canvas order is the route-list order.
 */
function groupRoutesByRedirectTarget(routes: TopologyRoute[]): Map<string, TopologyRoute[]> {
        const groups = new Map<string, TopologyRoute[]>();
        routes.forEach((route) => {
                if (!route.redirectTarget) return;
                const key = redirectTargetKey(route.redirectTarget);
                const existing = groups.get(key);
                if (existing) existing.push(route);
                else groups.set(key, [route]);
        });
        return groups;
}

/**
 * Header label for a redirect destination node: the destination's host,
 * which is what the node stands for.
 *
 * Unlike deriveClusterLabel this keeps the whole host rather than the
 * first label. `discord` tells the operator nothing; `discord.gg` is
 * the destination. Falls back to the raw string when the target does
 * not parse, and to 'redirection' when there is no target at all —
 * never an empty header.
 */
function deriveRedirectLabel(target: string | undefined): string {
        if (!target) return 'redirection';
        try {
                return new URL(target).host || target;
        } catch {
                return target;
        }
}

function dominantRuntime(upstreams: TopologyUpstream[]): string | undefined {
        if (upstreams.length === 0) return undefined;
        const counts = new Map<string, number>();
        upstreams.forEach((u) => {
                if (u.runtime) counts.set(u.runtime, (counts.get(u.runtime) ?? 0) + 1);
        });
        let best: { runtime: string; count: number } | undefined;
        counts.forEach((count, runtime) => {
                if (!best || count > best.count) best = { runtime, count };
        });
        return best?.runtime;
}

function deriveClusterWarning(route: TopologyRoute): string | undefined {
        const ups = route.upstreams;
        // v2.61 — a redirecting route has no upstream BY DESIGN, so the
        // empty-pool warning was the canvas calling a working route
        // broken. Checked BEFORE the length test, not after: the length
        // is zero in both cases and only the redirect explains it.
        if (route.redirectTarget) return undefined;
        // Translated at build time: the page rebuilds the graph on every
        // WebSocket frame (2 s by default), so a language switch shows
        // up on the next one.
        if (ups.length === 0) return t('topology.cluster.noUpstream');
        // Three-state aware (Regression A, 2026-06-03). v1.1.0 emits
        // 'unknown' for every upstream — "no probe data yet, not the
        // same as bad". The warning must fire ONLY for STRICTLY
        // unhealthy upstreams. Previously this fired whenever
        // healthyCount === 0, which is true in the all-unknown case
        // too → red "Tous les upstreams sont indisponibles" on every
        // route in the canvas.
        const unhealthy = ups.filter((u) => u.status === 'unhealthy').length;
        if (unhealthy === ups.length) return t('topology.cluster.allDown');
        if (unhealthy > 0) return t('topology.cluster.someDown', { count: unhealthy });
        // All upstreams unknown OR all healthy OR a mix without any
        // strictly-unhealthy → no warning. The header surfaces the
        // count breakdown for those cases.
        return undefined;
}

/** FQDN protocols label.
 *
 *  C18 (2026-06-04): renders "HTTP → HTTPS" when the route has
 *  TLS enabled AND http→https redirect configured, otherwise just
 *  "HTTPS" / "HTTP". The arrow communicates "plain-HTTP requests
 *  get bounced", which the operator can't otherwise see from the
 *  canvas. tlsEnabled === false short-circuits to "HTTP" (you
 *  can't redirect to a non-existent HTTPS endpoint).
 *
 *  C17a (2026-06-04 same commit): the previous "HTTPS · h2 · h3"
 *  mock suffix is gone — the backend doesn't expose real ALPN
 *  yet (#R-TOPO-alpn).
 */
function formatProtocols(route: TopologyRoute): string {
        if (!route.tlsEnabled) return 'HTTP';
        if (route.httpRedirect) return 'HTTP → HTTPS';
        return 'HTTPS';
}

/** FQDN meta line.
 *
 *  Always shows the current req/s. C17b + C19 (2026-06-04):
 *  appends an alias count ONLY when the route actually has
 *  aliases. The label uses "alias(es)" terminology so the
 *  primary FQDN (already shown above) isn't counted in the
 *  number — operator's mental model is "the FQDN plus how
 *  many additional hosts", and "1 host" for a route with no
 *  aliases was confusing noise.
 */
function formatFQDNMeta(route: TopologyRoute): string {
        const rate = formatRate(route.reqPerSec);
        const aliasCount = route.aliases?.length ?? 0;
        if (aliasCount === 0) return rate;
        if (aliasCount === 1) return `${rate} · 1 alias`;
        return `${rate} · ${aliasCount} aliases`;
}

function formatRate(rps: number): string {
        if (rps >= 1000) return `${(rps / 1000).toFixed(1)} k req/s`;
        return `${Math.round(rps)} req/s`;
}

/** Strip http://, https://, h2://, h2c:// from an upstream URL for
 *  display, and report whether the original used a TLS-bearing scheme.
 *
 *  The original full URL stays in TopologyUpstream.url for tooltips
 *  and future copy actions; this just produces the short label for
 *  the UpstreamNode card.
 *
 *  Why not surface scheme as a separate field from the backend? The
 *  Caddy reverse_proxy upstream string is what the operator typed —
 *  storage doesn't decompose it. Doing the split client-side avoids
 *  a backend types change and keeps the wire shape backwards
 *  compatible.
 */
const SCHEME_RX = /^(https?|h2c?):\/\//i;
function formatUpstreamUrl(rawUrl: string): { displayUrl: string; wasHttps: boolean } {
        const m = rawUrl.match(SCHEME_RX);
        if (!m) return { displayUrl: rawUrl, wasHttps: false };
        const scheme = m[1].toLowerCase();
        const wasHttps = scheme === 'https' || scheme === 'h2';
        return { displayUrl: rawUrl.slice(m[0].length), wasHttps };
}
