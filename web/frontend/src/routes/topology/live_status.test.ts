// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The topology page must not look live when it is not.
//
// Two lies this file pins shut:
//   - every page load said "reconnecting" before the first frame,
//     because the indicator STARTED in that state — a claim that
//     something broke when nothing had connected yet;
//   - a dropped stream changed one toolbar dot and nothing else, so
//     the particles kept flowing at the last rates and the graph read
//     as live traffic.
//
// Driven through the real page with the API module mocked, as in
// live_tick_view.test.ts, so the onTick / onDisconnect callbacks are
// the ones the page actually registers.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import type { TopologyRoute } from './_types';
import type { OnTick, OnDisconnect, SnapshotPayload } from './_api';

const apiMock = vi.hoisted(() => ({
	fetchSnapshot: vi.fn(),
	connectLiveStream: vi.fn(),
	onTick: null as null | OnTick,
	onDisconnect: null as null | OnDisconnect
}));

vi.mock('./_api', async () => {
	const actual = await vi.importActual<typeof import('./_api')>('./_api');
	return {
		...actual,
		fetchSnapshot: (...a: unknown[]) => apiMock.fetchSnapshot(...a),
		connectLiveStream: (onTick: OnTick, onDisconnect?: OnDisconnect) => {
			apiMock.onTick = onTick;
			apiMock.onDisconnect = onDisconnect ?? null;
			return apiMock.connectLiveStream(onTick, onDisconnect) ?? (() => {});
		}
	};
});

import Page from './+page.svelte';

function proxyRoute(id: string): TopologyRoute {
	return {
		id,
		host: `${id}.example.com`,
		upstreams: [
			{ id: `${id}-0`, url: 'http://10.0.0.5', status: 'unknown', reqPerSec: 0, p99LatencyMs: 0 }
		],
		lbPolicy: 'round_robin',
		reqPerSec: 0,
		p99LatencyMs: 0,
		errorRate5xx: 0,
		tlsEnabled: true,
		httpRedirect: false,
		hasHealthCheck: false,
		disabled: false
	} as unknown as TopologyRoute;
}

const GENERATED_AT = '2026-10-05T09:00:00Z';

function snapshot(routes: TopologyRoute[]): SnapshotPayload {
	return { generatedAt: GENERATED_AT, routes };
}

beforeEach(() => {
	apiMock.fetchSnapshot.mockReset();
	apiMock.connectLiveStream.mockReset();
	apiMock.onTick = null;
	apiMock.onDisconnect = null;
	apiMock.fetchSnapshot.mockResolvedValue(snapshot([proxyRoute('p-1')]));
	apiMock.connectLiveStream.mockReturnValue(() => {});
});

afterEach(() => {
	vi.restoreAllMocks();
});

function indicator(): HTMLElement {
	return screen.getByTestId('topology-live-status');
}

function canvasFrame(container: HTMLElement): HTMLElement {
	const el = container.querySelector('.canvas-frame');
	if (!el) throw new Error('canvas-frame not found — did the page layout change?');
	return el as HTMLElement;
}

describe('topology: the live indicator tells the truth', () => {
	it('starts as connecting, not reconnecting', async () => {
		render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		expect(indicator().getAttribute('data-live-status')).toBe('connecting');
		expect(indicator().textContent ?? '').not.toMatch(/reconnect/i);
	});

	it('is announced as a status', async () => {
		render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		expect(indicator()).toHaveAttribute('role', 'status');
	});

	it('turns live on the first frame', async () => {
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		apiMock.onTick!([proxyRoute('p-1')], GENERATED_AT);
		await waitFor(() => expect(indicator().getAttribute('data-live-status')).toBe('live'));
		expect(canvasFrame(container).classList.contains('is-stale')).toBe(false);
	});

	it('marks the canvas stale and gives the last update time on disconnect', async () => {
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		apiMock.onTick!([proxyRoute('p-1')], GENERATED_AT);
		await waitFor(() => expect(indicator().getAttribute('data-live-status')).toBe('live'));

		expect(apiMock.onDisconnect).not.toBeNull();
		apiMock.onDisconnect!();

		await waitFor(() =>
			expect(indicator().getAttribute('data-live-status')).toBe('reconnecting')
		);
		// The canvas says it is not live: dimmed, particles hidden.
		expect(canvasFrame(container).classList.contains('is-stale')).toBe(true);
		expect(canvasFrame(container).getAttribute('data-stale')).toBe('true');
		// And the indicator says how old the picture is.
		expect(indicator().textContent ?? '').toMatch(/last update/i);
		expect(indicator().textContent ?? '').toMatch(/\d{1,2}:\d{2}:\d{2}/);
		expect(indicator()).toHaveAttribute('role', 'status');
	});

	it('comes back to live, undimmed, on the next frame', async () => {
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		apiMock.onDisconnect!();
		await waitFor(() => expect(canvasFrame(container).classList.contains('is-stale')).toBe(true));

		apiMock.onTick!([proxyRoute('p-1')], GENERATED_AT);
		await waitFor(() => expect(canvasFrame(container).classList.contains('is-stale')).toBe(false));
		expect(indicator().getAttribute('data-live-status')).toBe('live');
	});
});
