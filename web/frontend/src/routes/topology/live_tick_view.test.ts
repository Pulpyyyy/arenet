// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.62.1 — the Proxy view showed every node, redirects included.
//
// Not a filter bug. filterForView was correct, and view_filter.test.ts
// proved it at length — while carrying its own COPY of the function,
// so it could never notice that one caller had stopped using it. The
// page rebuilds the graph from four places; three passed the filtered
// list and the WebSocket tick passed the raw one. Every frame (2 s by
// default) therefore rebuilt the canvas with all routes and undid the
// operator's choice, which is why it looked like the selector did
// nothing rather than like it broke.
//
// This file tests the thing the unit test could not: that the graph
// the page renders only ever contains one view's routes, including
// after a live frame arrives. It drives the real page with the API
// module mocked, so a future fourth caller that forgets the filter
// fails here.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/svelte';
import type { TopologyRoute } from './_types';
import type { OnTick, SnapshotPayload } from './_api';

// The page's only I/O. fetchSnapshot resolves the initial canvas;
// connectLiveStream hands us its onTick callback so the test can push
// a frame on demand instead of waiting on a socket.
const apiMock = vi.hoisted(() => ({
	fetchSnapshot: vi.fn(),
	connectLiveStream: vi.fn(),
	// Typed as the module's own OnTick, so the test pushes frames in
	// exactly the shape the page receives them — including the
	// generatedAt second argument.
	onTick: null as null | OnTick
}));

vi.mock('./_api', async () => {
	const actual = await vi.importActual<typeof import('./_api')>('./_api');
	return {
		...actual,
		fetchSnapshot: (...a: unknown[]) => apiMock.fetchSnapshot(...a),
		connectLiveStream: (onTick: OnTick) => {
			apiMock.onTick = onTick;
			return apiMock.connectLiveStream(onTick) ?? (() => {});
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

function redirectRoute(id: string, target = 'https://elsewhere.example.com'): TopologyRoute {
	return {
		...proxyRoute(id),
		upstreams: [],
		redirectTarget: target
	} as unknown as TopologyRoute;
}

const SNAPSHOT_ROUTES = [proxyRoute('p-1'), redirectRoute('r-1')];

const GENERATED_AT = '2026-10-05T09:00:00Z';

function snapshot(routes: TopologyRoute[]): SnapshotPayload {
	return { generatedAt: GENERATED_AT, routes };
}

beforeEach(() => {
	apiMock.fetchSnapshot.mockReset();
	apiMock.connectLiveStream.mockReset();
	apiMock.onTick = null;
	apiMock.fetchSnapshot.mockResolvedValue(snapshot(SNAPSHOT_ROUTES));
	apiMock.connectLiveStream.mockReturnValue(() => {});
	// @xyflow/svelte measures its container.
	if (!globalThis.ResizeObserver) {
		globalThis.ResizeObserver = class {
			observe() {}
			unobserve() {}
			disconnect() {}
		} as unknown as typeof ResizeObserver;
	}
});

afterEach(() => {
	vi.restoreAllMocks();
});

/**
 * Assertions are scoped to the CANVAS, not the document.
 *
 * Scoping is kept even though the sidebar now follows the selector
 * too: a canvas assertion that silently also covered the sidebar would
 * pass if either one filtered, and the point of this file is the
 * canvas rebuild path. The sidebar gets its own test below.
 */
function canvas(container: HTMLElement): HTMLElement {
	const el = container.querySelector('.canvas-frame');
	if (!el) throw new Error('canvas-frame not found — did the page layout change?');
	return el as HTMLElement;
}

/** The redirect route's destination node, present only in the
 *  Redirects view. Found by the text it renders rather than by a node
 *  id, so it survives the layout internals changing. */
function redirectNodeVisible(container: HTMLElement): boolean {
	return within(canvas(container)).queryAllByText('elsewhere.example.com').length > 0;
}

/** The proxy route's upstream, present only in the Proxy view. */
function proxyNodeVisible(container: HTMLElement): boolean {
	return within(canvas(container)).queryAllByText(/10\.0\.0\.5/).length > 0;
}

describe('topology: the live tick respects the selected view', () => {
	it('does not show a redirect destination in the Proxy view', async () => {
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.fetchSnapshot).toHaveBeenCalled());
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		await waitFor(() => expect(proxyNodeVisible(container)).toBe(true));
		expect(redirectNodeVisible(container)).toBe(false);
	});

	it('keeps the Proxy view after a live frame arrives', async () => {
		// THE regression. Before the fix the tick rebuilt from the raw
		// list and the redirect node appeared ~2 s after load, with no
		// operator action at all.
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());
		await waitFor(() => expect(proxyNodeVisible(container)).toBe(true));

		apiMock.onTick!([proxyRoute('p-1'), redirectRoute('r-1')], GENERATED_AT);

		await waitFor(() => expect(proxyNodeVisible(container)).toBe(true));
		expect(redirectNodeVisible(container)).toBe(false);
	});

	it('sidebar Top flows follows the selector', async () => {
		// The operator asked for this: "il faudrait qu'il suive le
		// selecteur". A panel ranking proxy routes while the canvas
		// shows only redirects made the filter look half-applied.
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());

		const sidebar = () => {
			const el = container.querySelector('.topo-sidebar');
			if (!el) throw new Error('topo-sidebar not found');
			return el as HTMLElement;
		};
		const sidebarHosts = () =>
			Array.from(sidebar().querySelectorAll('.host')).map((e) => e.textContent);

		await waitFor(() => expect(sidebarHosts()).toContain('p-1.example.com'));
		expect(sidebarHosts()).not.toContain('r-1.example.com');

		await fireEvent.click(screen.getByTestId('topo-view-redirect'));
		await waitFor(() => expect(sidebarHosts()).toContain('r-1.example.com'));
		expect(sidebarHosts()).not.toContain('p-1.example.com');

		// And a live frame must not drag the other view's routes back,
		// exactly as on the canvas.
		apiMock.onTick!([proxyRoute('p-1'), redirectRoute('r-1')], GENERATED_AT);
		await waitFor(() => expect(sidebarHosts()).toContain('r-1.example.com'));
		expect(sidebarHosts()).not.toContain('p-1.example.com');
	});

	it('keeps the Redirects view after a live frame arrives', async () => {
		// The mirror case: a tick must not drag proxy nodes back into
		// the redirect view either. Asserting only one direction would
		// pass against a filter hard-coded to one branch.
		const { container } = render(Page);
		await waitFor(() => expect(apiMock.onTick).not.toBeNull());

		await fireEvent.click(screen.getByTestId('topo-view-redirect'));
		await waitFor(() => expect(redirectNodeVisible(container)).toBe(true));

		apiMock.onTick!([proxyRoute('p-1'), redirectRoute('r-1')], GENERATED_AT);

		await waitFor(() => expect(redirectNodeVisible(container)).toBe(true));
		expect(proxyNodeVisible(container)).toBe(false);
	});
});
