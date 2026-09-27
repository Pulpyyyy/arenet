// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Paint order in column 0 (2026-09-27).
//
// It used to rely purely on array order — the route-group container was
// pushed before its cards so SvelteFlow would paint it behind. That holds
// on a first render, when every node is created in one pass, and breaks on
// an update: SvelteFlow leaves mounted nodes in place and appends new
// ones, so a card created later lands on top of containers mounted
// earlier.
//
// Folding aliases by default (v2.48) turned that latent fragility into a
// reported bug: expanding a route created its alias cards at that moment
// and they painted over the route-group chrome, hiding the R/s figures.
//
// These assert the explicit zIndex, which does not care when a node was
// created. Array order is deliberately NOT asserted — relying on it is
// what caused this.

import { describe, it, expect } from 'vitest';
import { buildTopologyGraph } from './_layout';
import type { TopologyRoute } from './_types';

function routeWithAliases(): TopologyRoute {
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
		aliasMetrics: [
			{ host: 'a1.local', reqPerSec: 3 },
			{ host: 'a2.local', reqPerSec: 0 }
		]
	} as TopologyRoute;
}

function zOf(nodes: { id: string; zIndex?: number }[], prefix: string): number[] {
	return nodes.filter((n) => n.id.startsWith(prefix)).map((n) => n.zIndex ?? 0);
}

describe('topology column 0 — explicit paint order', () => {
	it('puts every card strictly above the route-group chrome', () => {
		const graph = buildTopologyGraph([routeWithAliases()]);

		const groupZ = zOf(graph.nodes, 'route-group-');
		const fqdnZ = zOf(graph.nodes, 'fqdn-');
		const aliasZ = zOf(graph.nodes, 'alias-');

		expect(groupZ).toHaveLength(1);
		expect(fqdnZ).toHaveLength(1);
		expect(aliasZ).toHaveLength(2);

		for (const cardZ of [...fqdnZ, ...aliasZ]) {
			expect(cardZ).toBeGreaterThan(groupZ[0]);
		}
	});

	// The reported case: the route starts folded, then the operator
	// expands it. The cards created at that moment must still be above
	// the chrome — which is what an explicit zIndex guarantees and array
	// order does not.
	it('holds when the route is expanded after being folded', () => {
		const route = routeWithAliases();

		const folded = buildTopologyGraph([route], new Set(['r-1']));
		expect(zOf(folded.nodes, 'alias-')).toHaveLength(0);
		// The chrome is still emitted while folded.
		expect(zOf(folded.nodes, 'route-group-')).toHaveLength(1);

		const expanded = buildTopologyGraph([route], new Set<string>());
		const groupZ = zOf(expanded.nodes, 'route-group-')[0];
		const aliasZ = zOf(expanded.nodes, 'alias-');
		expect(aliasZ).toHaveLength(2);
		for (const z of aliasZ) {
			expect(z).toBeGreaterThan(groupZ);
		}
	});

	// Every node in the column must carry one. A node left without gets
	// SvelteFlow's default and the guarantee above stops holding for it.
	it('leaves no column-0 node without a zIndex', () => {
		const graph = buildTopologyGraph([routeWithAliases()]);
		const col0 = graph.nodes.filter(
			(n) =>
				n.id.startsWith('route-group-') || n.id.startsWith('fqdn-') || n.id.startsWith('alias-')
		);
		expect(col0.length).toBeGreaterThan(0);
		for (const n of col0) {
			expect(n.zIndex, `${n.id} has no zIndex`).toBeTypeOf('number');
		}
	});
});
