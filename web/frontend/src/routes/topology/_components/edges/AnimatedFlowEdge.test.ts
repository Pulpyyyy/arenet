// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The redirect edge, which is a STATEMENT rather than a path.
//
// The operator asked the question twice: are the traffic dots on a
// redirect real, and why does Arenet sit in the middle of a chain it
// is not part of? For a proxied route the edge IS the route traffic
// takes and the particles are the truth. For a redirect Arenet answers
// the client and the client goes on by itself — nothing traverses this
// edge, so animating it claims a flow that does not exist.
//
// The layout side is covered in _layout.test.ts. This file covers the
// drawing: dashed, no particles, labelled with the code.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import type { ComponentProps } from 'svelte';
import Edge from './AnimatedFlowEdge.svelte';
import type { FlowEdgeData } from '../../_types';

/**
 * Minimal EdgeProps. The component reads only the geometry and the
 * data; the rest of Svelte Flow's edge contract is never touched, so
 * the cast is to the component's own prop type rather than to
 * something looser that would stop catching a real mismatch.
 */
function props(data: FlowEdgeData): ComponentProps<typeof Edge> {
	return {
		id: 'e-test',
		source: 'caddy-hub',
		target: 'redirect-to-x',
		sourceX: 0,
		sourceY: 0,
		targetX: 200,
		targetY: 0,
		sourcePosition: 'right',
		targetPosition: 'left',
		data
	} as unknown as ComponentProps<typeof Edge>;
}

function flow(over: Partial<FlowEdgeData> = {}): FlowEdgeData {
	return {
		kind: 'flow',
		reqPerSec: 30,
		p99LatencyMs: 50,
		errorRate5xx: 0,
		...over
	} as FlowEdgeData;
}

/** Particles the viewer can actually see. */
function visibleParticles(container: HTMLElement): number {
	return Array.from(container.querySelectorAll('circle.particle')).filter((c) => {
		const o = (c as SVGElement).style.opacity;
		return o !== '' && Number(o) > 0;
	}).length;
}

describe('AnimatedFlowEdge — redirect edges', () => {
	it('draws no particles on a redirect edge', () => {
		// The whole point. At 30 req/s a proxy edge is busy with them.
		const { container } = render(Edge, { props: props(flow({ redirectStatusCode: 301 })) });
		expect(visibleParticles(container)).toBe(0);
	});

	it('still draws particles on a proxy edge carrying the same traffic', () => {
		// The control. Without it the test above would pass on an edge
		// component that had simply stopped animating anything.
		const { container } = render(Edge, { props: props(flow()) });
		expect(visibleParticles(container)).toBeGreaterThan(0);
	});

	it('labels the edge with the status code', () => {
		const { container } = render(Edge, { props: props(flow({ redirectStatusCode: 302 })) });
		const label = container.querySelector('[data-testid="edge-redirect-label-e-test"]');
		expect(label).not.toBeNull();
		expect(label?.textContent?.trim()).toBe('302');
	});

	it('carries no label on a proxy edge', () => {
		const { container } = render(Edge, { props: props(flow()) });
		expect(container.querySelector('[data-testid^="edge-redirect-label-"]')).toBeNull();
	});

	it('dashes the redirect edge', () => {
		// Dashed says "answered here, not forwarded" the way a
		// structural branch says "routing branch" — the same visual
		// vocabulary, so an operator reads both without a legend.
		const { container } = render(Edge, { props: props(flow({ redirectStatusCode: 301 })) });
		const path = container.querySelector('path');
		expect(path?.getAttribute('style') ?? '').toContain('stroke-dasharray');
	});

	it('does not dash an ordinary proxy edge', () => {
		const { container } = render(Edge, { props: props(flow()) });
		const path = container.querySelector('path');
		expect(path?.getAttribute('style') ?? '').not.toContain('stroke-dasharray');
	});
});
