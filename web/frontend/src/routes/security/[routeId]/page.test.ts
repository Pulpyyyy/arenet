// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The per-route security page's way out to the activity log. The
// page shows 20 recent WAF events; the log holds more, and the
// rate-limit and country blocks for the same route.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';

// Inside vi.hoisted because the vi.mock factories below are hoisted
// above every top-level const.
const { ROUTE_ID, mocks } = vi.hoisted(() => ({
	ROUTE_ID: 'f2aa08ff-8c86-4ede-8bc1-96670b1342a5',
	mocks: {
		fetchTimeseries: vi.fn(),
		fetchEvents: vi.fn(),
		fetchEventsByRule: vi.fn(),
		getRoute: vi.fn()
	}
}));

vi.mock('$lib/api/metrics', () => ({
	fetchTimeseries: (...a: unknown[]) => mocks.fetchTimeseries(...a)
}));

vi.mock('$lib/api/security', () => ({
	fetchEvents: (...a: unknown[]) => mocks.fetchEvents(...a),
	fetchEventsByRule: (...a: unknown[]) => mocks.fetchEventsByRule(...a)
}));

vi.mock('$lib/api/client', () => ({
	getRoute: (...a: unknown[]) => mocks.getRoute(...a)
}));

vi.mock('$app/state', () => ({
	page: { params: { routeId: ROUTE_ID } }
}));

vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import Page from './+page.svelte';

beforeEach(() => {
	mocks.getRoute.mockReset();
	mocks.getRoute.mockResolvedValue({
		id: ROUTE_ID,
		host: 'blog.example.com',
		wafMode: 'block',
		upstreams: []
	});
	mocks.fetchTimeseries.mockReset();
	mocks.fetchTimeseries.mockResolvedValue({
		routeId: ROUTE_ID,
		metric: 'req_per_sec',
		window: '24h',
		bucketSizeSeconds: 60,
		points: []
	});
	mocks.fetchEvents.mockReset();
	mocks.fetchEvents.mockResolvedValue({ events: [] });
	mocks.fetchEventsByRule.mockReset();
	mocks.fetchEventsByRule.mockResolvedValue({ rows: [] });
});

describe('security route page: the way to the log', () => {
	it('links to the activity log filtered on this route', async () => {
		render(Page);
		const link = await screen.findByRole('link', { name: /View in logs/ });
		expect(link).toHaveAttribute('href', `/logs?route=${ROUTE_ID}`);
	});
});
