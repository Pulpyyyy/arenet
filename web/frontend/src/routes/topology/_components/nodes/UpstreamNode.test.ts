// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Upstream health is not carried by colour alone.
//
// The node's only health signal was a 3 px left stripe in green, red
// or amber — three hues a deuteranope cannot tell apart. A monitored
// upstream now also shows a glyph, the word for the states that need
// action ("down", "draining"), and its state in the accessible name.

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import type { UpstreamNodeData } from '../../_types';

vi.mock('@xyflow/svelte', async () => {
	const actual = await vi.importActual<typeof import('@xyflow/svelte')>('@xyflow/svelte');
	const HandleStub = (await import('./HandleStub.test.svelte')).default;
	return { ...actual, Handle: HandleStub };
});

const UpstreamNode = (await import('./UpstreamNode.svelte')).default;

function data(over: Partial<UpstreamNodeData> = {}): UpstreamNodeData {
	return {
		kind: 'upstream',
		upstreamId: 'u-0',
		url: 'http://10.0.0.5:8080',
		status: 'unknown',
		healthCheckConfigured: true,
		wasHttps: false,
		displayUrl: '10.0.0.5:8080',
		reqPerSec: 0,
		p99LatencyMs: 0,
		loadRatio: 0,
		...over
	} as UpstreamNodeData;
}

/** The NodeProps surface SvelteFlow hands a custom node; the
 *  component reads only `data`. Same shape as the sibling tests. */
function nodeProps(d: UpstreamNodeData): any {
	return {
		id: 'upstream-u-0',
		type: 'upstream',
		data: d,
		dragging: false,
		selected: false,
		isConnectable: false,
		positionAbsoluteX: 0,
		positionAbsoluteY: 0,
		width: 220,
		height: 48,
		zIndex: 0
	};
}

function node(): HTMLElement {
	return screen.getByRole('group');
}

describe('UpstreamNode — health without colour', () => {
	it('writes "down" on an unhealthy monitored upstream', () => {
		render(UpstreamNode, { props: nodeProps(data({ status: 'unhealthy' })) });
		const tag = screen.getByTestId('upstream-health');
		expect(tag.textContent ?? '').toMatch(/down/);
		// A glyph too, for a glance that does not read.
		expect(tag.querySelector('.up-health-glyph')?.textContent).toBe('✕');
	});

	it('names the state in the accessible name and tooltip of a down upstream', () => {
		render(UpstreamNode, { props: nodeProps(data({ status: 'unhealthy' })) });
		const label = node().getAttribute('aria-label') ?? '';
		expect(label).toContain('http://10.0.0.5:8080');
		expect(label).toMatch(/down/);
		expect(node().getAttribute('title')).toBe(label);
	});

	it('writes "draining" on a draining upstream', () => {
		render(UpstreamNode, { props: nodeProps(data({ status: 'draining' })) });
		expect(screen.getByTestId('upstream-health').textContent ?? '').toMatch(/draining/);
		expect(node().getAttribute('aria-label') ?? '').toMatch(/draining/);
	});

	it('shows a glyph but no word on a healthy upstream', () => {
		// Healthy needs no call to action; the word stays in the
		// accessible name so the state is still stated, not implied.
		render(UpstreamNode, { props: nodeProps(data({ status: 'healthy' })) });
		const tag = screen.getByTestId('upstream-health');
		expect(tag.querySelector('.up-health-glyph')?.textContent).toBe('✓');
		expect(tag.querySelector('.up-health-word')).toBeNull();
		// Anchored: "Upstream" itself contains "up".
		expect(node().getAttribute('aria-label') ?? '').toMatch(/:\s*up$/);
	});

	it('claims no health on an unmonitored upstream', () => {
		// No probe, no state: the node must not invent one.
		render(UpstreamNode, {
			props: nodeProps(data({ status: 'unhealthy', healthCheckConfigured: false }))
		});
		expect(screen.queryByTestId('upstream-health')).toBeNull();
		expect(node().getAttribute('aria-label')).toBe('http://10.0.0.5:8080');
	});
});
