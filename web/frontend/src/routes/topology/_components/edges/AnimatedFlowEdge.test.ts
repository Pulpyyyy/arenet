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

import { describe, it, expect, afterEach } from 'vitest';
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

// --- legibility at zero traffic --------------------------------------------
//
// The bug that followed the hub removal. tierStrokeStyle sends the
// 'dead' tier (reqPerSec exactly 0) to stroke-opacity 0.2 in grey,
// which is close to invisible on a dark canvas. In the hub-less
// Redirects view the redirect edge is the ONLY thing joining a host to
// its destination, and a redirect nobody has used yet sits at exactly
// that tier — so the destination floated unconnected.
//
// The operator's words: "les noeud de gauche et de droite ne sont pas
// connecter en adequation par rapport a la configuration". The edge
// was there and correct; it could not be seen.

function strokeOpacity(container: HTMLElement): number {
	const style = container.querySelector('path')?.getAttribute('style') ?? '';
	const m = /stroke-opacity:\s*([\d.]+)/.exec(style);
	return m ? Number(m[1]) : NaN;
}

describe('AnimatedFlowEdge — a redirect stays visible without traffic', () => {
	it('lifts the dead tier out of near-invisibility', () => {
		// A configured redirect is a fact whether or not anyone visited.
		const dead = render(Edge, {
			props: props(flow({ reqPerSec: 0, redirectStatusCode: 301 }))
		});
		expect(strokeOpacity(dead.container)).toBeGreaterThanOrEqual(0.45);
	});

	it('leaves a proxy edge at the dead tier dim, as before', () => {
		// The control. A proxied cluster is still joined by one solid
		// edge per upstream, so a dim line recedes without orphaning
		// anything — and changing that would undo the v2.25.1 decision
		// that dashes must not over-stand-out.
		const { container } = render(Edge, { props: props(flow({ reqPerSec: 0 })) });
		expect(strokeOpacity(container)).toBeLessThan(0.45);
	});

	it('still brightens a busy redirect above the floor', () => {
		// The floor is a minimum, not a flattening: a redirect carrying
		// real traffic must read as busier than one carrying none.
		const quiet = render(Edge, {
			props: props(flow({ reqPerSec: 0, redirectStatusCode: 301 }))
		});
		const busy = render(Edge, {
			props: props(flow({ reqPerSec: 0, errorRate5xx: 0.05, redirectStatusCode: 301 }))
		});
		expect(strokeOpacity(busy.container)).toBeGreaterThan(strokeOpacity(quiet.container));
	});

	it('keeps the dash on a redirect whatever the opacity', () => {
		const { container } = render(Edge, {
			props: props(flow({ reqPerSec: 0, redirectStatusCode: 301 }))
		});
		const style = container.querySelector('path')?.getAttribute('style') ?? '';
		expect(style).toContain('stroke-dasharray');
	});

	it("does not override the bad tier's own dash pattern", () => {
		// tierStrokeStyle already emits `stroke-dasharray: 4 4` for
		// 'bad', so the redirect dash must not be appended on top of
		// it — the outage pattern is the one that should survive.
		//
		// Asserted on the PATTERN, not on the number of declarations.
		// The first version of this test counted occurrences of
		// "stroke-dasharray" and expected one, and it could not fail:
		// getAttribute('style') returns CSSOM-normalised text, which
		// deduplicates properties, so a doubled declaration is
		// invisible to the DOM and harmless in CSS (last wins). What IS
		// observable is which pattern won.
		const { container } = render(Edge, {
			props: props(flow({ errorRate5xx: 0.5, redirectStatusCode: 301 }))
		});
		const style = container.querySelector('path')?.getAttribute('style') ?? '';
		expect(style).toContain('stroke-dasharray: 4 4');
		expect(style).not.toContain('stroke-dasharray: 5 4');
	});
});

// --- prefers-reduced-motion -------------------------------------------------
//
// app.css stops CSS animation under the preference; the particles ride
// SMIL <animateMotion>, which no stylesheet reaches, so they kept
// travelling for people who had asked for stillness. Under the
// preference the edge draws no particle and carries the tier in the
// stroke instead.

/** Install a matchMedia that answers `matches` for the reduced-motion
 *  query. Undone by the returned function. */
function preferReducedMotion(matches: boolean): () => void {
	const original = window.matchMedia;
	window.matchMedia = ((query: string) => ({
		matches: query.includes('prefers-reduced-motion') ? matches : false,
		media: query,
		onchange: null,
		addListener: () => {},
		removeListener: () => {},
		addEventListener: () => {},
		removeEventListener: () => {},
		dispatchEvent: () => true
	})) as unknown as typeof window.matchMedia;
	return () => {
		window.matchMedia = original;
	};
}

function strokeWidth(container: HTMLElement): number {
	const style = container.querySelector('path')?.getAttribute('style') ?? '';
	const m = /stroke-width:\s*([\d.]+)/.exec(style);
	return m ? Number(m[1]) : NaN;
}

describe('AnimatedFlowEdge — reduced motion', () => {
	let restore: () => void = () => {};
	afterEach(() => {
		restore();
		restore = () => {};
	});

	it('renders no animateMotion and no particle when reduced motion is asked for', () => {
		restore = preferReducedMotion(true);
		const { container } = render(Edge, { props: props(flow({ reqPerSec: 30 })) });
		// getElementsByTagName, not querySelector: it matches the
		// camelCase SVG name whichever namespace the element lands in.
		expect(container.getElementsByTagName('animateMotion').length).toBe(0);
		expect(container.querySelectorAll('circle.particle').length).toBe(0);
	});

	it('keeps the particles when no preference is set', () => {
		// The control: the test above must not pass on an edge that
		// simply stopped drawing particles for everyone.
		restore = preferReducedMotion(false);
		const { container } = render(Edge, { props: props(flow({ reqPerSec: 30 })) });
		expect(container.getElementsByTagName('animateMotion').length).toBeGreaterThan(0);
	});

	it('shows the traffic tier through stroke width and opacity instead', () => {
		restore = preferReducedMotion(true);
		const quiet = render(Edge, { props: props(flow({ reqPerSec: 0.5 })) });
		const busy = render(Edge, { props: props(flow({ reqPerSec: 100 })) });
		expect(strokeWidth(busy.container)).toBeGreaterThan(strokeWidth(quiet.container));
		expect(strokeOpacity(busy.container)).toBeGreaterThan(strokeOpacity(quiet.container));
	});
});
