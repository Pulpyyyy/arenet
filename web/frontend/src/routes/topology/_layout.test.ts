// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.b + 3.c — _layout.ts alias integration tests.
//
// Pins the operator-visible contract for the col-0 stack:
//   - routes without aliases keep their single-FQDN footprint
//     (backward-compat: legacy traefik / arenet / ha layouts
//     don't shift when aliases ship — no container, no extra
//     edges, no visual change at all).
//   - routes with aliases emit a RouteGroupNode container
//     (Phase 3.c) wrapping the FQDN + alias cards visually.
//   - aliases stack vertically below the primary FQDN, in
//     backend order (sorted desc by reqPerSec).
//   - active aliases (reqPerSec > 0) get their own
//     AnimatedFlowEdge straight to the Caddy hub. Idle
//     aliases (reqPerSec === 0) get no edge — they stay
//     visible inside the container but don't carry particles.
//   - the primary FQDN edge intensity is rebalanced: it
//     carries route.reqPerSec MINUS the sum of active alias
//     rates (the visual sum of particles entering Caddy from
//     a route still equals route.reqPerSec).
//   - 21-alias realistic-load case (operator traefik route)
//     layouts cleanly: 21 alias nodes + 1 container, only the
//     active aliases emit edges, sort preserved end-to-end.

import { describe, it, expect } from 'vitest';
import { buildTopologyGraph, FQDN_HEIGHT, ROW_SPACING_Y } from './_layout';
import type {
	AliasNodeData,
	BackendClusterNodeData,
	FlowEdgeData,
	FQDNNodeData,
	RouteGroupNodeData,
	TopologyAlias,
	TopologyRoute
} from './_types';

function makeRoute(overrides: Partial<TopologyRoute> = {}): TopologyRoute {
	return {
		id: 'r-1',
		host: 'primary.local',
		upstreams: [
			{
				id: 'u-1',
				url: 'http://127.0.0.1:9000',
				status: 'unknown',
				healthCheckConfigured: false,
				reqPerSec: 0,
				p99LatencyMs: 0,
				fairnessRatio: 1
			}
		],
		lbPolicy: 'round_robin',
		reqPerSec: 0,
		p99LatencyMs: 0,
		errorRate5xx: 0,
		tlsEnabled: false,
		httpRedirect: false,
		hasHealthCheck: false,
		disabled: false,
		...overrides
	};
}

function alias(host: string, reqPerSec: number): TopologyAlias {
	return { host, reqPerSec, p99LatencyMs: 0, errorRate5xx: 0 };
}

describe('buildTopologyGraph — alias integration', () => {
	// -------------------------------------------------------
	// Phase 3.b shape — preserved through 3.c with the
	// AliasOfEdge expectations dropped (the dashed semantic
	// edge was removed in 3.c — RouteGroupNode replaces it).
	// -------------------------------------------------------

	it('route without aliases emits a single FQDN node — no container, no alias nodes', () => {
		const graph = buildTopologyGraph([makeRoute()]);
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(0);
		expect(graph.nodes.filter((n) => n.type === 'fqdn')).toHaveLength(1);
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
	});

	it('route with empty aliasMetrics array also stays single-FQDN with no container', () => {
		// aliasMetrics: [] (Phase 2.2's non-omitempty wire shape
		// for a route without aliases) must be treated identically
		// to "field absent" — no container, no alias nodes.
		const graph = buildTopologyGraph([makeRoute({ aliasMetrics: [] })]);
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(0);
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
	});

	it('route with aliases emits FQDN + AliasNodes in backend order', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [
					alias('sonarr.example.com', 0.94),
					alias('radarr.example.com', 0.47),
					alias('idle.example.com', 0)
				]
			})
		]);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliasNodes).toHaveLength(3);
		const hosts = aliasNodes.map((n) => (n.data as AliasNodeData).host);
		expect(hosts).toEqual([
			'sonarr.example.com',
			'radarr.example.com',
			'idle.example.com'
		]);
		expect((aliasNodes[0].data as AliasNodeData).reqPerSec).toBe(0.94);
		expect((aliasNodes[0].data as AliasNodeData).isIdle).toBe(false);
		expect((aliasNodes[2].data as AliasNodeData).isIdle).toBe(true);
	});

	it('AliasNodes positioned below the primary FQDN, top consumer closest', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [alias('top.example.com', 5), alias('mid.example.com', 1), alias('bot.example.com', 0)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1');
		const aliases = graph.nodes
			.filter((n) => n.type === 'alias')
			.sort((a, b) => a.position.y - b.position.y);
		expect(fqdn).toBeDefined();
		expect(aliases).toHaveLength(3);
		for (const a of aliases) {
			expect(a.position.y).toBeGreaterThan(fqdn!.position.y);
		}
		expect((aliases[0].data as AliasNodeData).host).toBe('top.example.com');
		expect((aliases[1].data as AliasNodeData).host).toBe('mid.example.com');
		expect((aliases[2].data as AliasNodeData).host).toBe('bot.example.com');
	});

	it('multi-route layout: alias-heavy route does not push neighbours into overlap', () => {
		const graph = buildTopologyGraph([
			makeRoute({ id: 'r-1', host: 'small.local' }),
			makeRoute({
				id: 'r-2',
				host: 'big.local',
				aliasMetrics: [alias('a.big.local', 1), alias('b.big.local', 0), alias('c.big.local', 0)]
			})
		]);
		// HF4 : all nodes carry ABSOLUTE positions, so the
		// overlap check is a direct comparison again.
		const fqdn1 = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		const fqdn2 = graph.nodes.find((n) => n.id === 'fqdn-r-2')!;
		expect(fqdn1.position.y).not.toBe(fqdn2.position.y);
		const top = fqdn1.position.y < fqdn2.position.y ? fqdn1 : fqdn2;
		const bot = fqdn1.position.y < fqdn2.position.y ? fqdn2 : fqdn1;
		const topRouteAliases = graph.nodes.filter(
			(n) => n.type === 'alias' && (n.data as AliasNodeData).parentRouteId === top.id
		);
		const topBlockBottom =
			topRouteAliases.length > 0
				? Math.max(...topRouteAliases.map((a) => a.position.y)) + 44 // ALIAS_HEIGHT
				: top.position.y + 70; // FQDN_HEIGHT
		expect(bot.position.y).toBeGreaterThan(topBlockBottom);
	});

	it('FQDNNodeData still carries the legacy aliases string array for backward-compat', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				aliases: ['foo.example.com', 'bar.example.com'],
				aliasMetrics: [alias('foo.example.com', 1), alias('bar.example.com', 0)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.type === 'fqdn')!;
		expect((fqdn.data as FQDNNodeData).aliases).toEqual(['foo.example.com', 'bar.example.com']);
	});

	// -------------------------------------------------------
	// Phase 3.c — RouteGroupNode container + per-alias edges
	// + primary FQDN edge rebalance.
	// -------------------------------------------------------

	it('route with aliases emits a RouteGroupNode container with FQDN + aliases inside its bounds', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [
					alias('sonarr.example.com', 1),
					alias('radarr.example.com', 0.5),
					alias('idle.example.com', 0)
				]
			})
		]);
		const containers = graph.nodes.filter((n) => n.type === 'route-group');
		expect(containers).toHaveLength(1);
		const container = containers[0];
		expect(container.id).toBe('route-group-r-1');
		expect((container.data as RouteGroupNodeData).routeId).toBe('r-1');
		expect((container.data as RouteGroupNodeData).primaryHost).toBe('primary.local');

		// Container bounds : every node uses ABSOLUTE positions
		// (HF4 reverted the parent/child wire). Container's
		// width/height define the bounding box from its (x, y)
		// origin.
		const cx = container.position.x;
		const cy = container.position.y;
		const cw = (container.width as number) ?? 0;
		const ch = (container.height as number) ?? 0;
		expect(cw).toBeGreaterThan(0);
		expect(ch).toBeGreaterThan(0);

		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		expect(fqdn.position.x).toBeGreaterThanOrEqual(cx);
		expect(fqdn.position.y).toBeGreaterThanOrEqual(cy);
		// FQDN right + bottom edges sit within the container.
		expect(fqdn.position.x + 200).toBeLessThanOrEqual(cx + cw);
		expect(fqdn.position.y + 70).toBeLessThanOrEqual(cy + ch);

		const aliases = graph.nodes.filter((n) => n.type === 'alias');
		for (const a of aliases) {
			expect(a.position.x).toBeGreaterThanOrEqual(cx);
			expect(a.position.y).toBeGreaterThanOrEqual(cy);
			expect(a.position.x + 170).toBeLessThanOrEqual(cx + cw);
			expect(a.position.y + 44).toBeLessThanOrEqual(cy + ch);
		}
	});

	it('container is emitted FIRST in the nodes array so it paints behind FQDN + alias cards', () => {
		// SvelteFlow paints nodes in array order. For the
		// container to act as a background it MUST precede every
		// node it visually wraps.
		const graph = buildTopologyGraph([
			makeRoute({ id: 'r-1', aliasMetrics: [alias('a.example.com', 1)] })
		]);
		const containerIdx = graph.nodes.findIndex((n) => n.type === 'route-group');
		const fqdnIdx = graph.nodes.findIndex((n) => n.id === 'fqdn-r-1');
		const aliasIdx = graph.nodes.findIndex((n) => n.type === 'alias');
		expect(containerIdx).toBeGreaterThanOrEqual(0);
		expect(containerIdx).toBeLessThan(fqdnIdx);
		expect(containerIdx).toBeLessThan(aliasIdx);
	});

	it('active alias (reqPerSec > 0) emits an AnimatedFlowEdge to Caddy with its own rate', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 10,
				aliasMetrics: [alias('sonarr.example.com', 4), alias('radarr.example.com', 2.5)]
			})
		]);
		const aliasEdges = graph.edges.filter((e) => e.source.startsWith('alias-r-1-'));
		expect(aliasEdges).toHaveLength(2);
		for (const edge of aliasEdges) {
			expect(edge.type).toBe('animated-flow');
			expect(edge.target).toBe('caddy-hub');
		}
		const sonarrEdge = aliasEdges.find((e) => e.source === 'alias-r-1-0')!;
		expect((sonarrEdge.data as FlowEdgeData).reqPerSec).toBe(4);
		const radarrEdge = aliasEdges.find((e) => e.source === 'alias-r-1-1')!;
		expect((radarrEdge.data as FlowEdgeData).reqPerSec).toBe(2.5);
	});

	it('idle alias (reqPerSec === 0) emits NO edge — alias node still rendered in container', () => {
		// The idle alias must be visible inside the container
		// (Phase 3.c keeps the visual presence) but NOT carry a
		// particle edge (which would imply traffic where there
		// is none).
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 5,
				aliasMetrics: [alias('hot.example.com', 5), alias('idle.example.com', 0)]
			})
		]);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliasNodes).toHaveLength(2);
		const aliasEdges = graph.edges.filter((e) => e.source.startsWith('alias-r-1-'));
		expect(aliasEdges).toHaveLength(1);
		expect(aliasEdges[0].source).toBe('alias-r-1-0');
	});

	it('primary FQDN edge reqPerSec = route.reqPerSec - sum(active alias rates)', () => {
		// Route total: 10 r/s, split 6/2.5 between two active
		// aliases. Primary's own share: 10 - (6 + 2.5) = 1.5 r/s.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 10,
				aliasMetrics: [alias('a.example.com', 6), alias('b.example.com', 2.5)]
			})
		]);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBeCloseTo(1.5, 5);
	});

	it('primary FQDN edge clamps at 0 when alias sum exceeds route rate (rounding drift)', () => {
		// Windowed aggregation can leave the alias sum a hair
		// above the route's own rate. The primary edge must clamp
		// at 0 — never negative — so tier resolution stays sane.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 5,
				aliasMetrics: [alias('a.example.com', 3), alias('b.example.com', 2.5)]
			})
		]);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBe(0);
	});

	it('primary FQDN edge keeps full route rate when route has no aliases', () => {
		// Backward-compat: without aliases there is no subtraction
		// to apply. The primary edge must carry route.reqPerSec
		// unchanged.
		const graph = buildTopologyGraph([makeRoute({ id: 'r-1', reqPerSec: 42 })]);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBe(42);
	});

	// -------------------------------------------------------
	// Phase 3.e — centering + collapse / expand toggle
	// -------------------------------------------------------

	it('aliases are horizontally centred relative to the primary FQDN (15 px offset)', () => {
		// FQDN width is 200 px, AliasNode width 170 px (Phase 3.d
		// bump). The horizontal centring delta is therefore
		// (200 - 170) / 2 = 15 px. Aliases must position at
		// COL_X.FQDN + 15 so the col-0 stack reads as one
		// vertical column of symmetry, not a left-leaning stair.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [alias('a.example.com', 1), alias('b.example.com', 0.5)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		const aliases = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliases.length).toBe(2);
		for (const a of aliases) {
			// Each alias sits 15 px to the right of the primary's
			// left edge — symmetric centring under the 200 px
			// FQDN.
			expect(a.position.x - fqdn.position.x).toBe(15);
		}
	});

	it('collapsed route: container + FQDN only, no alias nodes, no per-alias edges', () => {
		const collapsed = new Set(['r-1']);
		const graph = buildTopologyGraph(
			[
				makeRoute({
					id: 'r-1',
					reqPerSec: 8,
					aliasMetrics: [alias('a.example.com', 5), alias('b.example.com', 3)]
				})
			],
			collapsed
		);
		// Container still present — the visual signature for
		// "this route has aliases hiding behind the chevron"
		// must persist even when collapsed.
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(1);
		// FQDN still present.
		expect(graph.nodes.filter((n) => n.id === 'fqdn-r-1')).toHaveLength(1);
		// No alias nodes when collapsed.
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
		// No per-alias edges either.
		expect(graph.edges.filter((e) => e.source.startsWith('alias-'))).toHaveLength(0);
	});

	it('collapsed route: primary FQDN edge carries FULL route.reqPerSec (no rebalance)', () => {
		// When collapsed the aliases aren't drawing their own
		// edges, so the primary FQDN edge absorbs the full
		// route.reqPerSec — operator still sees the total flow
		// on the canvas, just consolidated on one edge instead
		// of fanning out. Expanded mode would subtract the alias
		// sum (Phase 3.c rebalance); collapsed mode skips that
		// subtraction.
		const collapsed = new Set(['r-1']);
		const graph = buildTopologyGraph(
			[
				makeRoute({
					id: 'r-1',
					reqPerSec: 8,
					aliasMetrics: [alias('a.example.com', 5), alias('b.example.com', 3)]
				})
			],
			collapsed
		);
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBe(8);
	});

	it('FQDNNodeData carries routeId + aliasCount + aliasTotalRps + collapsed', () => {
		// FQDN data must thread the route ID back (for the
		// chevron's toggle call), the alias count (drives
		// chevron visibility), the aliasTotalRps aggregate (for
		// the collapsed meta line "N aliases · X r/s total"),
		// and the current collapsed boolean.
		const collapsed = new Set(['r-1']);
		const graph = buildTopologyGraph(
			[
				makeRoute({
					id: 'r-1',
					reqPerSec: 8,
					aliasMetrics: [alias('a.example.com', 5), alias('b.example.com', 3), alias('idle.example.com', 0)]
				})
			],
			collapsed
		);
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		const data = fqdn.data as FQDNNodeData;
		expect(data.routeId).toBe('r-1');
		expect(data.aliasCount).toBe(3);
		// Sum every alias — active + idle. Idle aliases
		// contribute zero so the total equals sum(active) but
		// the policy is "all aliases" so the number is stable
		// when an alias crosses the active threshold.
		expect(data.aliasTotalRps).toBe(8);
		expect(data.collapsed).toBe(true);
	});

	it('expanded route (default — empty Set or omitted arg): full alias rendering', () => {
		// Backward-compat: when the collapsed set is empty (or
		// the argument is omitted entirely), every route renders
		// in expanded mode. Same shape as Phase 3.d.
		const graphOmitted = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				reqPerSec: 5,
				aliasMetrics: [alias('a.example.com', 3), alias('b.example.com', 2)]
			})
		]);
		const graphEmptySet = buildTopologyGraph(
			[
				makeRoute({
					id: 'r-1',
					reqPerSec: 5,
					aliasMetrics: [alias('a.example.com', 3), alias('b.example.com', 2)]
				})
			],
			new Set<string>()
		);
		// Both shapes must be identical: 2 alias nodes, 2
		// alias edges + 1 primary edge.
		for (const graph of [graphOmitted, graphEmptySet]) {
			expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(2);
			expect(graph.edges.filter((e) => e.source.startsWith('alias-'))).toHaveLength(2);
			const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
			expect((fqdn.data as FQDNNodeData).collapsed).toBe(false);
		}
	});

	// -------------------------------------------------------
	// Phase 3.e HOTFIX (2026-06-17 #4) — drag affordance + padding.
	//
	// HF3 (parent/child wire) shipped a fix for the container-
	// stays-put-on-primary-drag desync, but at the cost of the
	// natural drag affordance : the primary FQDN became
	// draggable:false, so the operator could only drag by the
	// surrounding blue chrome instead of the focal card.
	//
	// HF4 reverts the parent/child wire and replaces it with :
	//  - Container : standalone node, ABSOLUTE position,
	//    draggable: false (pure visual chrome).
	//  - FQDN : standalone node, ABSOLUTE position, draggable:
	//    true (default — the natural affordance).
	//  - Alias children : standalone node, ABSOLUTE position,
	//    draggable: false (operator drags via the primary;
	//    aliases follow as a group).
	// The follow-group behaviour is wired in +page.svelte via
	// SvelteFlow's onnodedrag callback (delta applied to
	// matching route-group + every alias of the same route).
	//
	// Routes WITHOUT aliases : no container, FQDN standalone
	// with default drag — backward compat unchanged.
	// -------------------------------------------------------

	it('drag affordance: FQDN is draggable (default, no explicit override)', () => {
		// `draggable` undefined on the node means SvelteFlow
		// applies its default `true`. The operator drags the
		// FQDN; the +page.svelte onnodedrag handler propagates
		// the delta to the container + aliases.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [alias('a.example.com', 1)]
			})
		]);
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		// Explicit assertion : no override at the node level.
		// SvelteFlow's default kicks in (draggable = true).
		expect(fqdn.draggable).toBeUndefined();
		// Also pin no parentId — HF3's wire is gone.
		expect(fqdn.parentId).toBeUndefined();
	});

	it('drag affordance: RouteGroup container is NOT draggable directly', () => {
		// HF4 : the container is pure visual chrome. The
		// operator's drag target is the FQDN; the container
		// follows via the onnodedrag handler. Making the
		// container directly draggable would create a second
		// drag target that the +page.svelte handler doesn't
		// know about (no delta sync) — a regression source.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [alias('a.example.com', 1)]
			})
		]);
		const container = graph.nodes.find((n) => n.id === 'route-group-r-1')!;
		expect(container.draggable).toBe(false);
		expect(container.selectable).toBe(false);
	});

	it('drag affordance: aliases are NOT individually draggable', () => {
		// HF4 : aliases follow the primary via the onnodedrag
		// handler. Making an alias directly draggable would let
		// the operator decouple it from the group — visual
		// chaos. Keep them locked.
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [
					alias('a.example.com', 1),
					alias('b.example.com', 0.5)
				]
			})
		]);
		const aliases = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliases.length).toBeGreaterThan(0);
		for (const a of aliases) {
			expect(a.draggable).toBe(false);
			expect(a.selectable).toBe(false);
			// No parentId either — HF4 reverted the parent /
			// child wire.
			expect(a.parentId).toBeUndefined();
		}
	});

	it('padding symmetry: container leaves equal padding on all four sides of the FQDN (collapsed)', () => {
		// Collapsed route : container hugs the FQDN alone. The
		// padding around the FQDN must be ROUTE_GROUP_PADDING
		// on every side (10 px) so the blue chrome looks
		// uniformly thick. Pre-HF4 the bottom padding drifted
		// because the FQDN rendered taller than the assumed
		// FQDN_HEIGHT (content-driven sizing). HF4 pins the
		// FQDN card height in CSS so the layout math matches
		// reality.
		const collapsed = new Set(['r-1']);
		const graph = buildTopologyGraph(
			[
				makeRoute({
					id: 'r-1',
					aliasMetrics: [alias('a.example.com', 1)]
				})
			],
			collapsed
		);
		const container = graph.nodes.find((n) => n.id === 'route-group-r-1')!;
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		const cw = (container.width as number) ?? 0;
		const ch = (container.height as number) ?? 0;
		const leftPad = fqdn.position.x - container.position.x;
		const topPad = fqdn.position.y - container.position.y;
		const rightPad = container.position.x + cw - (fqdn.position.x + 200);
		const bottomPad = container.position.y + ch - (fqdn.position.y + 70);
		expect(leftPad).toBe(10);
		expect(topPad).toBe(10);
		expect(rightPad).toBe(10);
		expect(bottomPad).toBe(10);
	});

	it('padding symmetry: container leaves equal lateral padding around the FQDN + alias stack (expanded)', () => {
		// Expanded route : container wraps FQDN + N aliases.
		// The lateral padding (left + right) around the FQDN
		// must stay equal to ROUTE_GROUP_PADDING. Vertical
		// padding : equal at top (above FQDN) and bottom
		// (below the last alias).
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r-1',
				aliasMetrics: [
					alias('a.example.com', 1),
					alias('b.example.com', 0.5),
					alias('c.example.com', 0)
				]
			})
		]);
		const container = graph.nodes.find((n) => n.id === 'route-group-r-1')!;
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		const aliases = graph.nodes.filter((n) => n.type === 'alias');
		const ch = (container.height as number) ?? 0;
		const lastAlias = aliases.reduce((acc, n) => (n.position.y > acc.position.y ? n : acc));
		const topPad = fqdn.position.y - container.position.y;
		const bottomPad = container.position.y + ch - (lastAlias.position.y + 44);
		expect(topPad).toBe(10);
		expect(bottomPad).toBe(10);
		expect(topPad).toBe(bottomPad);
	});

	it('drag affordance: collapsed route preserves the same affordance (FQDN draggable, container chrome)', () => {
		// Collapse / expand toggle must NOT regress the drag
		// affordance contract — the FQDN stays the drag
		// target in both modes.
		const collapsed = new Set(['r-1']);
		const graph = buildTopologyGraph(
			[
				makeRoute({
					id: 'r-1',
					aliasMetrics: [alias('a.example.com', 1), alias('b.example.com', 0)]
				})
			],
			collapsed
		);
		const container = graph.nodes.find((n) => n.id === 'route-group-r-1')!;
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		expect(container.draggable).toBe(false);
		expect(fqdn.draggable).toBeUndefined();
		expect(graph.nodes.filter((n) => n.type === 'alias')).toHaveLength(0);
	});

	it('drag affordance: standalone FQDN (route without aliases) keeps default drag', () => {
		// Backward compat : routes without aliases have no
		// container, no follow-group concern, just a vanilla
		// draggable FQDN.
		const graph = buildTopologyGraph([makeRoute({ id: 'r-1' })]);
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-r-1')!;
		expect(fqdn.draggable).toBeUndefined();
		expect(fqdn.parentId).toBeUndefined();
		// No container emitted.
		expect(graph.nodes.find((n) => n.type === 'route-group')).toBeUndefined();
	});

	// HOTFIX (2026-06-17) — effect_update_depth_exceeded.
	// Shipped Phase 3.e had a runtime infinite-loop bug : the
	// page-level $effect that called rebuildGraph on
	// collapsedRoutes.collapsed change was implicitly tracking
	// `nodes` / `edges` (read inside rebuildGraph for the diff
	// path) AND mutating them (written for the first-build /
	// mixed-id-set paths). The write retriggered the effect →
	// loop → Svelte's effect_update_depth_exceeded guard fired
	// after a few hundred iterations and the canvas froze.
	//
	// The runtime fix wraps the rebuildGraph call inside
	// untrack() (+page.svelte). The architectural guarantee that
	// makes the fix sound is THIS : buildTopologyGraph must be
	// deterministic AND pure on its inputs (no mutation of the
	// routes array nor the collapsedRouteIds Set). If a future
	// change mutated either, the untrack-wrapped effect would
	// still be correct but other consumers (currently none) would
	// observe a different invariant. The tests below pin the
	// purity contract so an accidental mutation surfaces as a
	// test failure rather than a runtime loop.

	it('buildTopologyGraph is deterministic — same inputs yield identical output', () => {
		// Pure-function contract : two successive calls with the
		// same arguments produce shape-equivalent output. The
		// effect path relies on this so that a "no-op" rebuild
		// (effect re-fires but inputs haven't changed) doesn't
		// observe spurious differences and re-trigger downstream
		// state writes.
		const routesIn = [
			makeRoute({
				id: 'r-1',
				reqPerSec: 5,
				aliasMetrics: [alias('a.example.com', 3), alias('b.example.com', 0)]
			})
		];
		const collapsed = new Set(['r-1']);
		const a = buildTopologyGraph(routesIn, collapsed);
		const b = buildTopologyGraph(routesIn, collapsed);
		expect(a.nodes.map((n) => n.id)).toEqual(b.nodes.map((n) => n.id));
		expect(a.edges.map((e) => e.id)).toEqual(b.edges.map((e) => e.id));
		expect(a.nodes.length).toBe(b.nodes.length);
		expect(a.edges.length).toBe(b.edges.length);
	});

	it('buildTopologyGraph does NOT mutate the collapsedRouteIds Set', () => {
		// HOTFIX regression : the effect passes its tracked
		// collapsedRoutes.collapsed Set straight in. A mutation
		// inside the layout would change the store's Set in
		// place, which Svelte 5 cannot observe (mutation doesn't
		// fire $state notifications) AND would corrupt the next
		// rebuild's input. Pin no-mutation.
		const collapsed = new Set(['r-1', 'r-2']);
		const snapshot = new Set(collapsed);
		buildTopologyGraph(
			[
				makeRoute({ id: 'r-1', aliasMetrics: [alias('a.example.com', 1)] }),
				makeRoute({ id: 'r-2', aliasMetrics: [alias('b.example.com', 0)] }),
				makeRoute({ id: 'r-3' })
			],
			collapsed
		);
		expect(collapsed.size).toBe(snapshot.size);
		for (const id of snapshot) {
			expect(collapsed.has(id)).toBe(true);
		}
	});

	it('buildTopologyGraph does NOT mutate the routes array nor per-route alias arrays', () => {
		// HOTFIX regression : a mutation of the input routes
		// array (or any of its nested aliasMetrics) would corrupt
		// the next live-tick rebuild's input snapshot. Pin no-
		// mutation on the input boundary.
		const aliasMetrics = [alias('a.example.com', 2), alias('b.example.com', 0)];
		const routesIn = [
			makeRoute({ id: 'r-1', reqPerSec: 3, aliasMetrics }),
			makeRoute({ id: 'r-2' })
		];
		const routesSnapshot = JSON.stringify(routesIn);
		const aliasSnapshot = JSON.stringify(aliasMetrics);
		buildTopologyGraph(routesIn, new Set(['r-1']));
		buildTopologyGraph(routesIn, new Set());
		expect(JSON.stringify(routesIn)).toBe(routesSnapshot);
		expect(JSON.stringify(aliasMetrics)).toBe(aliasSnapshot);
	});

	it('collapsed route shrinks col-0 height so neighbours close the gap', () => {
		// When a route with 5 aliases is collapsed, its col-0
		// block shrinks to bare FQDN height; the neighbouring
		// routes must close the visual gap (they were pushed
		// apart by the expanded alias stack).
		const heavyAliases = Array.from({ length: 5 }, (_, i) => alias(`a${i}.local`, 0));
		const expanded = buildTopologyGraph([
			makeRoute({ id: 'top', host: 'top.local' }),
			makeRoute({ id: 'mid', host: 'mid.local', aliasMetrics: heavyAliases }),
			makeRoute({ id: 'bot', host: 'bot.local' })
		]);
		const collapsed = buildTopologyGraph(
			[
				makeRoute({ id: 'top', host: 'top.local' }),
				makeRoute({ id: 'mid', host: 'mid.local', aliasMetrics: heavyAliases }),
				makeRoute({ id: 'bot', host: 'bot.local' })
			],
			new Set(['mid'])
		);
		const expandedTopBot =
			expanded.nodes.find((n) => n.id === 'fqdn-bot')!.position.y -
			expanded.nodes.find((n) => n.id === 'fqdn-top')!.position.y;
		const collapsedTopBot =
			collapsed.nodes.find((n) => n.id === 'fqdn-bot')!.position.y -
			collapsed.nodes.find((n) => n.id === 'fqdn-top')!.position.y;
		expect(collapsedTopBot).toBeLessThan(expandedTopBot);
	});

	it('21-alias realistic-load case (operator traefik scenario) layouts cleanly', () => {
		// Mirrors the operator's empirically-validated case from
		// the Phase 2.2 smoke: 21 aliases on a single route, top
		// 3 consumers carrying real traffic, rest idle. With
		// Phase 3.c: 1 container + 21 alias nodes; only 3 alias
		// edges to Caddy (the actives); sort preserved end-to-end.
		const heavyAliases: TopologyAlias[] = [
			alias('sonarr.traefik.local', 0.94),
			alias('radarr.traefik.local', 0.47),
			alias('logs.traefik.local', 0.07),
			...Array.from({ length: 18 }, (_, i) => alias(`idle${i}.traefik.local`, 0))
		];
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'traefik',
				host: 'traefik.local',
				reqPerSec: 1.48,
				aliasMetrics: heavyAliases
			})
		]);
		expect(graph.nodes.filter((n) => n.type === 'route-group')).toHaveLength(1);
		const aliasNodes = graph.nodes.filter((n) => n.type === 'alias');
		expect(aliasNodes).toHaveLength(21);

		// Only the 3 actives emit edges to Caddy.
		const aliasEdges = graph.edges.filter((e) => e.source.startsWith('alias-traefik-'));
		expect(aliasEdges).toHaveLength(3);

		// Sort preserved: backend-supplied order matches node
		// order when sorted by y position.
		const aliasNodesSorted = [...aliasNodes].sort((a, b) => a.position.y - b.position.y);
		const renderedHosts = aliasNodesSorted.map((n) => (n.data as AliasNodeData).host);
		const expectedHosts = heavyAliases.map((a) => a.host);
		expect(renderedHosts).toEqual(expectedHosts);

		// Top consumer (sonarr) is closest to the primary FQDN.
		const fqdn = graph.nodes.find((n) => n.id === 'fqdn-traefik')!;
		const closestAliasToFqdn = aliasNodesSorted.find((n) => n.position.y > fqdn.position.y)!;
		expect((closestAliasToFqdn.data as AliasNodeData).host).toBe('sonarr.traefik.local');

		// Primary edge clamped at zero: alias sum (1.48) ==
		// route rate (1.48), so primary's share is exactly 0.
		const primaryEdge = graph.edges.find((e) => e.id === 'e-fqdn-traefik-caddy')!;
		expect((primaryEdge.data as FlowEdgeData).reqPerSec).toBeCloseTo(0, 5);
	});

	// -------------------------------------------------------
	// v2.24.0 — per-path routing branches (pathPools).
	// v2.25.0 Task 2 REPLACES the v2.24.0 Task-3 "one cluster
	// per path-pool" model (and the v2.24.1 dashed-stacked-
	// clusters model) with a single cluster per route whose
	// children include per-prefix section headers. The tests
	// below are rewritten for that model; the old "3 clusters"
	// / "cluster-r1-path-0" assertions no longer apply — see
	// the dedicated v2.25.0 Task 2 block further below for the
	// full single-cluster/section-header coverage.
	// -------------------------------------------------------

	it('a route with a path-pool still emits exactly one cluster (path-pool renders as a section, not a cluster)', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r1',
				host: 'api.example.com',
				pathPools: [
					{
						pathPrefix: '/v1',
						lbPolicy: 'round_robin',
						upstreams: [
							{
								id: 'r1-path-0-0',
								url: 'http://v1:8080',
								status: 'unknown',
								healthCheckConfigured: false,
								reqPerSec: 0,
								p99LatencyMs: 0,
								fairnessRatio: 1
							}
						]
					},
					{
						pathPrefix: '/legacy',
						lbPolicy: 'round_robin',
						upstreams: [
							{
								id: 'r1-path-1-0',
								url: 'https://old:8443',
								status: 'unknown',
								healthCheckConfigured: false,
								reqPerSec: 0,
								p99LatencyMs: 0,
								fairnessRatio: 1
							}
						]
					}
				]
			})
		]);
		const clusters = graph.nodes.filter((n) => n.type === 'backend-cluster');
		expect(clusters.length).toBe(1);
		const headers = graph.nodes.filter((n) => n.type === 'path-section-header');
		expect(headers.map((h) => (h.data as any).pathPrefix).sort()).toEqual(['/legacy', '/v1']);
	});

	it('a route with no path-pools emits exactly one cluster (non-regression)', () => {
		const graph = buildTopologyGraph([makeRoute({ id: 'r2', host: 'plain.example.com' })]);
		expect(graph.nodes.filter((n) => n.type === 'backend-cluster').length).toBe(1);
	});

	it('a path-pool section has a parented upstream child inside the single cluster', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r1',
				host: 'api.example.com',
				pathPools: [
					{
						pathPrefix: '/v1',
						lbPolicy: 'round_robin',
						upstreams: [
							{
								id: 'r1-path-0-0',
								url: 'http://v1:8080',
								status: 'unknown',
								healthCheckConfigured: false,
								reqPerSec: 0,
								p99LatencyMs: 0,
								fairnessRatio: 1
							}
						]
					}
				]
			})
		]);
		const cluster = graph.nodes.find((n) => n.type === 'backend-cluster')!;
		const child = graph.nodes.find(
			(n) => n.type === 'upstream' && (n.data as any).upstreamId === 'r1-path-0-0'
		);
		expect(child).toBeDefined();
		expect(child!.parentId).toBe(cluster.id);
	});

	it('marks the hub->section edge as structural', () => {
		const graph = buildTopologyGraph([
			makeRoute({
				id: 'r1',
				host: 'api.example.com',
				pathPools: [
					{
						pathPrefix: '/v1',
						lbPolicy: 'round_robin',
						upstreams: [
							{
								id: 'r1-path-0-0',
								url: 'http://v1:8080',
								status: 'unknown',
								healthCheckConfigured: false,
								reqPerSec: 0,
								p99LatencyMs: 0,
								fairnessRatio: 1
							}
						]
					}
				]
			})
		]);
		const header = graph.nodes.find((n) => n.type === 'path-section-header')!;
		const sectionEdge = graph.edges.find((e) => e.target === header.id);
		expect(sectionEdge).toBeDefined();
		expect((sectionEdge!.data as FlowEdgeData).structural).toBe(true);
		// a route/root edge must NOT be structural
		const rootEdges = graph.edges.filter(
			(e) => e.source === 'caddy-hub' && e.target !== header.id
		);
		for (const e of rootEdges) {
			expect((e.data as FlowEdgeData).structural).not.toBe(true);
		}
	});

	// -------------------------------------------------------
	// v2.24.1 Task 2 — contiguous per-route cluster stacking.
	// A route's own clusters (root + its path pools) must stack
	// tight (INTRA_ROUTE_GAP); a new route's root cluster keeps
	// the full original spacing (INTER_ROUTE_GAP === 150, the
	// old ROW_SPACING_Y) so paths-less layouts are unchanged.
	// -------------------------------------------------------

	it('a paths-less multi-route set stacks with the uniform ROW_SPACING_Y gap', () => {
		// v2.25.0 Task 2: the gap-stacker (computeStackYsWithGaps,
		// INTER/INTRA_ROUTE_GAP) is gone — routes are back to ONE
		// cluster each, stacked with the restored uniform
		// computeStackYsForHeights (ROW_SPACING_Y === 150).
		const routes = [
			{ id: 'r1', host: 'a.example.com', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-0', url: 'http://a:8080', status: 'unknown', reqPerSec: 0 }], reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false },
			{ id: 'r2', host: 'b.example.com', lbPolicy: 'round_robin', upstreams: [{ id: 'r2-0', url: 'http://b:8080', status: 'unknown', reqPerSec: 0 }], reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false },
		];
		const { nodes } = buildTopologyGraph(routes as any);
		const c1 = nodes.find((n) => n.id === 'cluster-r1')!;
		const c2 = nodes.find((n) => n.id === 'cluster-r2')!;
		const gap = c2.position.y - (c1.position.y + (c1.height ?? 0));
		// v2.59 — asserted against the constant, not against 150. The
		// property under test is "the stacker is uniform"; the pitch
		// itself is a visual-density decision that moved once (150 →
		// 56) and may move again. A literal here failed the change
		// for no reason and told us nothing about the stacker.
		expect(gap).toBe(ROW_SPACING_Y);
	});

	it('the row pitch leaves less air than content — the canvas is not mostly empty', () => {
		// v2.59 — the decision the previous test can no longer hold,
		// now that it reads the constant: the gap BETWEEN two rows
		// must stay smaller than the card it separates. At 150 px
		// against a 70 px FQDN card the canvas was more than two
		// thirds empty vertically, which is what the operator saw
		// and reported. This assertion fails on any future bump
		// past FQDN_HEIGHT; it is the intent, not the number.
		expect(ROW_SPACING_Y).toBeLessThan(FQDN_HEIGHT);
	});

	// -------------------------------------------------------
	// v2.25.0 Task 2 — one cluster per route, per-prefix
	// sections rendered INSIDE that single cluster. Replaces
	// the v2.24.0 separate-clusters-per-path model and the
	// v2.24.1 dashed-stacked-clusters model above.
	// -------------------------------------------------------

	it('renders ONE cluster per route with a section header per path-pool', () => {
		const routes = [{
			id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
			upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
			pathPools: [
				{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] },
				{ pathPrefix: '/legacy', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-1-0', url: 'https://old:8443', status: 'unknown', reqPerSec: 0 }] },
			],
			reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
		}];
		const { nodes } = buildTopologyGraph(routes as any);
		// exactly ONE cluster
		expect(nodes.filter((n) => n.type === 'backend-cluster').length).toBe(1);
		// one section header per path-pool, carrying the prefix
		const headers = nodes.filter((n) => n.type === 'path-section-header');
		expect(headers.length).toBe(2);
		expect(headers.map((h) => (h.data as any).pathPrefix).sort()).toEqual(['/legacy', '/v1']);
		// all upstreams (root + paths) parented to the single cluster
		const cluster = nodes.find((n) => n.type === 'backend-cluster')!;
		const ups = nodes.filter((n) => n.type === 'upstream');
		expect(ups.length).toBe(3);
		for (const u of ups) expect(u.parentId).toBe(cluster.id);
		for (const h of headers) expect(h.parentId).toBe(cluster.id);
	});

	it('a paths-less route renders one cluster, zero section headers (non-regression)', () => {
		const routes = [{
			id: 'r2', host: 'plain.example.com', lbPolicy: 'round_robin',
			upstreams: [{ id: 'r2-0', url: 'http://a:8080', status: 'unknown', reqPerSec: 0 }],
			reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
		}];
		const { nodes } = buildTopologyGraph(routes as any);
		expect(nodes.filter((n) => n.type === 'backend-cluster').length).toBe(1);
		expect(nodes.filter((n) => n.type === 'path-section-header').length).toBe(0);
	});

	it('each path-pool gets one structural hub->section edge; root keeps its fan-out', () => {
		const routes = [{
			id: 'r1', host: 'api.example.com', lbPolicy: 'round_robin',
			upstreams: [{ id: 'r1-0', url: 'http://route:8080', status: 'unknown', reqPerSec: 0 }],
			pathPools: [{ pathPrefix: '/v1', lbPolicy: 'round_robin', upstreams: [{ id: 'r1-path-0-0', url: 'http://v1:8080', status: 'unknown', reqPerSec: 0 }] }],
			reqPerSec: 0, tlsEnabled: false, httpRedirect: false, hasHealthCheck: false, disabled: false,
		}];
		const { edges } = buildTopologyGraph(routes as any);
		const structural = edges.filter((e) => (e.data as any)?.structural === true);
		expect(structural.length).toBe(1); // one per path-pool
		// root edge(s) exist and are NOT structural
		const rootEdges = edges.filter((e) => e.source === 'caddy-hub' && (e.data as any)?.structural !== true);
		expect(rootEdges.length).toBeGreaterThanOrEqual(1);
	});
});

// -----------------------------------------------------------------
// v2.61 — a redirecting route on the canvas.
//
// It drew an EMPTY backend cluster carrying the red "Aucun upstream
// configuré" warning, visually identical to a genuinely broken route.
// The operator met it on 2026-10-03 and asked whether that was normal.
// A redirect is not a route missing its backend; it is a route whose
// destination is not a backend, and the graph now says so.
// -----------------------------------------------------------------
describe('buildTopologyGraph — redirecting routes', () => {
	function redirectRoute(overrides: Partial<TopologyRoute> = {}): TopologyRoute {
		return {
			id: 'r-redirect',
			host: 'old.example.com',
			upstreams: [],
			lbPolicy: 'round_robin',
			reqPerSec: 0,
			p99LatencyMs: 0,
			errorRate5xx: 0,
			tlsEnabled: true,
			httpRedirect: false,
			hasHealthCheck: false,
			disabled: false,
			redirectTarget: 'https://new.example.com',
			...overrides
		} as TopologyRoute;
	}

	// A redirect node is keyed by its DESTINATION, not by a route: the
	// id is `redirect-to-<encoded destination key>`, so several routes
	// pointing at one place are one node. Tests find it by its data
	// rather than by spelling the id out, which keeps them honest about
	// what the node is for.
	function redirectNodes(nodes: ReturnType<typeof buildTopologyGraph>['nodes']) {
		return nodes.filter((n) => n.id.startsWith('redirect-to-'));
	}

	it('carries no empty-pool warning', () => {
		const { nodes } = buildTopologyGraph([redirectRoute()]);
		const cluster = redirectNodes(nodes)[0]!;
		const data = cluster.data as BackendClusterNodeData;
		expect(data.warning).toBeUndefined();
	});

	it('carries its destination so the graph can draw where traffic goes', () => {
		const { nodes } = buildTopologyGraph([redirectRoute()]);
		const cluster = redirectNodes(nodes)[0]!;
		const data = cluster.data as BackendClusterNodeData;
		expect(data.redirectTarget).toBe('https://new.example.com');
	});

	// --- Grouping by destination -------------------------------------
	//
	// The operator: "sinon ça fait trop de node". Three routes pointing
	// at one Discord invite used to draw three nodes carrying the same
	// URL, which says "three destinations" when there is one.

	it('draws ONE node for several routes sharing a destination', () => {
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', host: 'a.example.com' }),
			redirectRoute({ id: 'r-2', host: 'b.example.com' }),
			redirectRoute({ id: 'r-3', host: 'c.example.com' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(1);
	});

	it('names every route that arrives at the destination', () => {
		// Without this the grouped node stands for an unknown number of
		// routes and reads exactly like a single one.
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', host: 'a.example.com' }),
			redirectRoute({ id: 'r-2', host: 'b.example.com' })
		]);
		const data = redirectNodes(nodes)[0]!.data as BackendClusterNodeData;
		expect(data.redirectSourceHosts).toEqual(['a.example.com', 'b.example.com']);
	});

	it('keeps one inbound edge per source route', () => {
		// Flattening three flows into one edge would lose which route
		// actually carries the traffic.
		const { edges } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', host: 'a.example.com' }),
			redirectRoute({ id: 'r-2', host: 'b.example.com' })
		]);
		const ids = edges.map((e) => e.id).filter((id) => id.startsWith('e-caddy-cluster-'));
		expect(ids).toEqual(['e-caddy-cluster-r-1', 'e-caddy-cluster-r-2']);
		const targets = new Set(edges.filter((e) => ids.includes(e.id)).map((e) => e.target));
		expect(targets.size).toBe(1);
	});

	it('still draws separate nodes for different destinations', () => {
		// The guard against over-grouping: the whole point is lost if
		// two destinations merge.
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectTarget: 'https://one.example.com' }),
			redirectRoute({ id: 'r-2', redirectTarget: 'https://two.example.com' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(2);
	});

	it('treats a trailing slash on an empty path as the same destination', () => {
		// https://x and https://x/ are the same resource.
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectTarget: 'https://new.example.com' }),
			redirectRoute({ id: 'r-2', redirectTarget: 'https://new.example.com/' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(1);
	});

	it('treats host case as the same destination', () => {
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectTarget: 'https://New.Example.com' }),
			redirectRoute({ id: 'r-2', redirectTarget: 'https://new.example.com' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(1);
	});

	it('does NOT merge destinations that differ only in path case', () => {
		// /a and /A are different paths on most servers. Merging them
		// would be an error the operator cannot see; drawing two nodes
		// for one destination is one they can.
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectTarget: 'https://x.example.com/a' }),
			redirectRoute({ id: 'r-2', redirectTarget: 'https://x.example.com/A' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(2);
	});

	it('does NOT merge destinations that differ only in query', () => {
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectTarget: 'https://x.example.com/?a=1' }),
			redirectRoute({ id: 'r-2', redirectTarget: 'https://x.example.com/?a=2' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(2);
	});

	it('groups identical malformed targets instead of throwing', () => {
		const { nodes } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectTarget: 'not a url' }),
			redirectRoute({ id: 'r-2', redirectTarget: 'not a url' })
		]);
		expect(redirectNodes(nodes)).toHaveLength(1);
	});

	it('labels the node by the destination, not by one of its sources', () => {
		// Before grouping the node was labelled with the first source's
		// host — naming it after one of the things pointing AT it, which
		// becomes plainly wrong as soon as two routes converge.
		const { nodes } = buildTopologyGraph([
			redirectRoute({
				id: 'r-1',
				host: 'join.example.com',
				redirectTarget: 'https://discord.gg/abc'
			})
		]);
		const data = redirectNodes(nodes)[0]!.data as BackendClusterNodeData;
		expect(data.clusterLabel).toBe('discord.gg');
		expect(data.clusterLabel).not.toBe('join');
	});

	it('gives a grouped node room for its extra source lines', () => {
		// The source list is real content; without the height the names
		// would render outside the node box.
		const one = buildTopologyGraph([redirectRoute({ id: 'r-1', host: 'a.example.com' })]);
		const three = buildTopologyGraph([
			redirectRoute({ id: 'r-1', host: 'a.example.com' }),
			redirectRoute({ id: 'r-2', host: 'b.example.com' }),
			redirectRoute({ id: 'r-3', host: 'c.example.com' })
		]);
		const h1 = redirectNodes(one.nodes)[0]!.height!;
		const h3 = redirectNodes(three.nodes)[0]!.height!;
		expect(h3).toBeGreaterThan(h1);
	});

	it('leaves a single-source redirect at the height it always had', () => {
		// Non-regression: a one-route redirect must not move every other
		// cluster on the canvas.
		const { nodes } = buildTopologyGraph([redirectRoute()]);
		const proxy = buildTopologyGraph([makeRoute({ id: 'r-empty', upstreams: [] })]);
		const redirectH = redirectNodes(nodes)[0]!.height!;
		const emptyProxyH = proxy.nodes.find((n) => n.id === 'cluster-r-empty')!.height!;
		// Same geometry: both are a header over an empty pool. The proxy
		// one additionally reserves its warning footer.
		expect(redirectH).toBeLessThan(emptyProxyH);
	});

	it('still warns a route that has no upstream AND no redirect', () => {
		// The guard must not swallow the real case it was written for.
		const broken = redirectRoute({ id: 'r-broken', redirectTarget: undefined });
		const { nodes } = buildTopologyGraph([broken]);
		const data = nodes.find((n) => n.id === 'cluster-r-broken')!
			.data as BackendClusterNodeData;
		expect(data.warning).toBe('No upstream configured');
	});

	it('leaves a proxying route untouched', () => {
		const { nodes } = buildTopologyGraph([makeRoute({ id: 'r-proxy' })]);
		const data = nodes.find((n) => n.id === 'cluster-r-proxy')!
			.data as BackendClusterNodeData;
		expect(data.warning).toBeUndefined();
		expect(data.redirectTarget).toBeUndefined();
	});

	// --- The redirect edge is a statement, not a path ----------------
	//
	// The operator's question, twice over: are the traffic dots on a
	// redirect real, and why does Arenet sit in the middle of a chain
	// it is not part of? For a proxied route the edge IS the path
	// traffic takes. For a redirect Arenet answers the client and the
	// client goes on by itself, so nothing traverses this edge and
	// animating it claims a flow that does not exist.

	it('marks the hub-to-destination edge with the redirect status code', () => {
		const { edges } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', redirectStatusCode: 302 })
		]);
		const edge = edges.find((e) => e.id === 'e-caddy-cluster-r-1')!;
		expect(edge).toBeDefined();
		const data = edge.data as FlowEdgeData;
		expect(data.redirectStatusCode).toBe(302);
	});

	it('defaults the code to 301 when the wire omits it', () => {
		// Storage stores zero to mean 301 and the builder resolves it,
		// but an older server will send nothing at all.
		const { edges } = buildTopologyGraph([redirectRoute({ id: 'r-1' })]);
		const data = edges.find((e) => e.id === 'e-caddy-cluster-r-1')!.data as FlowEdgeData;
		expect(data.redirectStatusCode).toBe(301);
	});

	it('leaves the FQDN-to-hub edge alone', () => {
		// That edge carries REAL traffic: requests arriving at the host
		// and being answered. Marking it too would erase the one honest
		// flow on the canvas.
		const { edges } = buildTopologyGraph([redirectRoute({ id: 'r-1' })]);
		const fqdn = edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect(fqdn).toBeDefined();
		expect((fqdn.data as FlowEdgeData).redirectStatusCode).toBeUndefined();
	});

	it('does NOT mark a proxied route’s cluster edge', () => {
		// The guard against over-reach: a degenerate proxy route with no
		// upstream takes the same single-edge branch, and its edge is a
		// real path.
		const { edges } = buildTopologyGraph([makeRoute({ id: 'r-empty', upstreams: [] })]);
		const edge = edges.find((e) => e.id === 'e-caddy-cluster-r-empty')!;
		expect(edge).toBeDefined();
		expect((edge.data as FlowEdgeData).redirectStatusCode).toBeUndefined();
	});

	// --- hideHub: the Redirects view wires hosts to destinations ------
	//
	// The operator chose keeping the hub when shown three mockups, then
	// asked for it gone after living with it: "cette notion de noeud a
	// gauche avec rond au milieu et rien vers les noeuds a droite est
	// bizarre". The hub is the literal truth for a proxied route, and a
	// hop that carries nothing in a view where every route redirects.

	it('drops the Caddy hub', () => {
		const { nodes } = buildTopologyGraph([redirectRoute()], new Set(), { hideHub: true });
		expect(nodes.find((n) => n.id === 'caddy-hub')).toBeUndefined();
	});

	it('keeps the hub by default, so the proxy view is untouched', () => {
		const { nodes } = buildTopologyGraph([makeRoute()]);
		expect(nodes.find((n) => n.id === 'caddy-hub')).toBeDefined();
	});

	it('points the host edge straight at the destination', () => {
		const { edges, nodes } = buildTopologyGraph([redirectRoute({ id: 'r-1' })], new Set(), {
			hideHub: true
		});
		const dest = nodes.find((n) => n.id.startsWith('redirect-to-'))!;
		const edge = edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!;
		expect(edge).toBeDefined();
		expect(edge.target).toBe(dest.id);
	});

	it('leaves no edge sourced from the hub it removed', () => {
		// An edge whose source node does not exist is an invisible
		// edge, and Svelte Flow will not warn about it.
		const { edges, nodes } = buildTopologyGraph(
			[redirectRoute({ id: 'r-1' }), redirectRoute({ id: 'r-2', host: 'b.example.com' })],
			new Set(),
			{ hideHub: true }
		);
		const ids = new Set(nodes.map((n) => n.id));
		for (const e of edges) {
			expect(ids.has(e.source)).toBe(true);
			expect(ids.has(e.target)).toBe(true);
		}
	});

	it('carries the traffic AND the redirect mark on the merged edge', () => {
		// One edge now says two true things: the particles count the
		// redirects actually issued, the dash and the code say
		// "answered here, not forwarded".
		const { edges } = buildTopologyGraph(
			[redirectRoute({ id: 'r-1', reqPerSec: 12, redirectStatusCode: 302 })],
			new Set(),
			{ hideHub: true }
		);
		const data = edges.find((e) => e.id === 'e-fqdn-r-1-caddy')!.data as FlowEdgeData;
		expect(data.reqPerSec).toBe(12);
		expect(data.redirectStatusCode).toBe(302);
	});

	it('moves the destination into the vacated column', () => {
		// Leaving the hub's column empty would waste a third of the
		// canvas, which is the opposite of what the operator asked for
		// when they said the nodes were too far apart.
		const withHub = buildTopologyGraph([redirectRoute()]);
		const without = buildTopologyGraph([redirectRoute()], new Set(), { hideHub: true });
		const x = (g: typeof withHub) =>
			g.nodes.find((n) => n.id.startsWith('redirect-to-'))!.position.x;
		expect(x(without)).toBeLessThan(x(withHub));
	});

	it('leaves the two columns far enough apart to read as two', () => {
		// v2.68 — reclaiming the hub's column put a 300 px destination
		// card 70 px from col 0: "on dirait qu'ils sont les uns sur les
		// autres au niveau horizontale". The span also has to carry the
		// dashed stroke and its status-code label.
		//
		// Measured off the GRAPH, not off REDIRECT_COL_X, so moving the
		// cluster back to the hub's x fails this — asserting the
		// constant against itself would not.
		const { nodes } = buildTopologyGraph([redirectRoute({ id: 'r-1' })], new Set(), {
			hideHub: true
		});
		const group = nodes.find((n) => n.id === 'route-group-r-1');
		const dest = nodes.find((n) => n.id.startsWith('redirect-to-'))!;
		// A route with no alias gets no container, so fall back to the
		// FQDN card — whose right edge is one padding further left,
		// which only makes the assertion stricter.
		const col0Right = group
			? group.position.x + (group.width as number)
			: nodes.find((n) => n.id === 'fqdn-r-1')!.position.x + 200;
		expect(dest.position.x - col0Right).toBeGreaterThanOrEqual(190);
	});

	it('marks every source edge when routes converge on one destination', () => {
		const { edges } = buildTopologyGraph([
			redirectRoute({ id: 'r-1', host: 'a.example.com' }),
			redirectRoute({ id: 'r-2', host: 'b.example.com' })
		]);
		for (const id of ['e-caddy-cluster-r-1', 'e-caddy-cluster-r-2']) {
			const data = edges.find((e) => e.id === id)!.data as FlowEdgeData;
			expect(data.redirectStatusCode).toBe(301);
		}
	});
});
