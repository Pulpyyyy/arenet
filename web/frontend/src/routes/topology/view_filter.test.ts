// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.61.1 — the Proxy / Redirects selector split the graph by reading a
// $derived from inside untrack(). untrack suppresses the machinery that
// marks a derived dirty, so the effect could be handed the PREVIOUS
// view's route list: nodes vanished on a switch and came back ~2s later
// when the next WebSocket frame rebuilt with the correct set. The
// operator found it within minutes of the release.
//
// The fix makes the split a plain function of (routes, view). This test
// pins the partition itself — that it is total, disjoint, and keyed on
// redirectTarget and nothing else — so the behaviour survives whatever
// the reactive plumbing does around it.

import { describe, it, expect } from 'vitest';
import { FLOW_TIER, resolveFlowTier } from './_types';
import type { FlowEdgeData, TopologyRoute } from './_types';
// v2.62.1 — imported, no longer restated. The previous version of this
// file carried its own copy of filterForView with a comment saying so,
// which is why it stayed green through the bug it was written to
// prevent: the partition was right in both places while the page's
// live-tick path passed the UNFILTERED list, and the proxy view showed
// every node. A test that copies its subject cannot notice the subject
// going unused.
import { filterForView, type TopoView } from './_view';

function route(id: string, redirectTarget?: string): TopologyRoute {
	return {
		id,
		host: `${id}.example.com`,
		upstreams: redirectTarget ? [] : [{ id: `${id}-0`, url: 'http://10.0.0.5', status: 'unknown', reqPerSec: 0 }],
		lbPolicy: 'round_robin',
		reqPerSec: 0,
		p99LatencyMs: 0,
		errorRate5xx: 0,
		tlsEnabled: true,
		httpRedirect: false,
		hasHealthCheck: false,
		disabled: false,
		...(redirectTarget ? { redirectTarget } : {})
	} as unknown as TopologyRoute;
}

describe('topology view filter', () => {
	const all = [
		route('a'),
		route('b', 'https://new.example.com'),
		route('c'),
		route('d', 'https://discord.gg/xyz')
	];

	it('proxy shows only routes with a backend', () => {
		expect(filterForView(all, 'proxy').map((r) => r.id)).toEqual(['a', 'c']);
	});

	it('redirect shows only routes with a destination', () => {
		expect(filterForView(all, 'redirect').map((r) => r.id)).toEqual(['b', 'd']);
	});

	it('the partition is total and disjoint — no route is lost or shown twice', () => {
		// The property that matters on a canvas: switching views must
		// never hide a route from BOTH tabs. An operator who cannot
		// find a route anywhere has no way to tell a filter bug from a
		// missing route.
		const proxy = filterForView(all, 'proxy').map((r) => r.id);
		const redirect = filterForView(all, 'redirect').map((r) => r.id);
		expect([...proxy, ...redirect].sort()).toEqual(['a', 'b', 'c', 'd']);
		expect(proxy.filter((id) => redirect.includes(id))).toEqual([]);
	});

	it('an empty redirectTarget counts as a proxy route, not a redirect', () => {
		// The wire field is omitempty, so absent and "" both mean "not
		// a redirect". A truthiness check is the contract; === undefined
		// would put an empty-string route in the redirect tab with
		// nothing to draw.
		const odd = [route('e'), { ...route('f'), redirectTarget: '' } as TopologyRoute];
		expect(filterForView(odd, 'proxy').map((r) => r.id)).toEqual(['e', 'f']);
		expect(filterForView(odd, 'redirect')).toEqual([]);
	});
});

// -----------------------------------------------------------------
// v2.61.1 — the flow-tier scale.
//
// The brackets came from the original design mock (≥400 / 150 / 20
// req/s) and were never checked against a real instance. On the
// operator's, whose busiest route peaks around 24 req/s, every edge
// fell under 20 and rendered the same pale grey: "les points sont
// pratiquement tout le temps gris". A colour scale that reports one
// colour is a decoration.
//
// And the error tier had the mirror-image fault: `errorRate5xx > 0`
// meant a SINGLE 5xx painted an edge red for good. A proxy in front of
// a real site always has a background rate of them — the operator's
// forum sits at 0.8% — so the alarm colour was permanent, which says
// no more than grey-for-ever did.
// -----------------------------------------------------------------
describe('resolveFlowTier — scaled for the traffic a homelab actually has', () => {
	const edge = (over: Partial<FlowEdgeData> = {}): FlowEdgeData =>
		({ kind: 'flow', reqPerSec: 0, p99LatencyMs: 0, errorRate5xx: 0, ...over }) as FlowEdgeData;

	it('separates the operator\'s real traffic instead of collapsing it to one tier', () => {
		// The numbers from the live instance: a busiest route near 24,
		// a mid one, a trickle, and silence. Under the mock scale all
		// four were 'idle' or 'low'; they must now be distinguishable.
		const tiers = [24, 8, 2, 0.3, 0].map((reqPerSec) =>
			resolveFlowTier(edge({ reqPerSec }))
		);
		expect(tiers).toEqual(['mid', 'mid', 'low', 'idle', 'dead']);
		expect(new Set(tiers).size).toBeGreaterThan(3);
	});

	it('reaches the top tier at a volume a homelab can actually produce', () => {
		expect(resolveFlowTier(edge({ reqPerSec: 25 }))).toBe('high');
		expect(resolveFlowTier(edge({ reqPerSec: 400 }))).toBe('high');
	});

	it('exactly zero stays its own tier so silent routes look silent', () => {
		expect(resolveFlowTier(edge({ reqPerSec: 0 }))).toBe('dead');
		expect(resolveFlowTier(edge({ reqPerSec: 0.01 }))).toBe('idle');
	});

	it('a background error rate is amber, not red', () => {
		// 0.8% is what the operator's forum reports. Red there is a
		// permanent false alarm; amber still says "look".
		expect(resolveFlowTier(edge({ reqPerSec: 24, errorRate5xx: 0.008 }))).toBe('warn');
	});

	it('an error rate above one percent is red', () => {
		expect(resolveFlowTier(edge({ reqPerSec: 24, errorRate5xx: 0.01 }))).toBe('bad');
		expect(resolveFlowTier(edge({ reqPerSec: 24, errorRate5xx: 0.5 }))).toBe('bad');
	});

	it('errors outrank latency, and latency outranks volume', () => {
		expect(resolveFlowTier(edge({ reqPerSec: 400, p99LatencyMs: 900, errorRate5xx: 0.2 })))
			.toBe('bad');
		expect(resolveFlowTier(edge({ reqPerSec: 400, p99LatencyMs: 900 }))).toBe('warn');
	});

	it('the legend reads the same numbers the resolver does', () => {
		// The legend used to restate the thresholds as hardcoded
		// strings in two locales, which is how a rescale leaves the
		// legend lying. The constants are the shared source now.
		expect(FLOW_TIER.highReqPerSec).toBe(25);
		expect(FLOW_TIER.midReqPerSec).toBe(5);
		expect(FLOW_TIER.lowReqPerSec).toBe(1);
		expect(FLOW_TIER.badErrorRate).toBe(0.01);
	});
});
