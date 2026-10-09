// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The quantile selector's wiring, which T12 shipped without.
//
// That omission is the same shape as the bug fixed in v2.62.1: there,
// a pure partition function was correct and well tested while one of
// the page's four callers had stopped using it, so the suite stayed
// green through the whole defect. Here the chart has tests, the API
// has tests, and the button-to-refetch path had none — verified only
// by reading. The operator asked what to check in v2.65.0 and this was
// the honest answer, so it is a test now instead of a devtools errand.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';

// Inside vi.hoisted because the vi.mock factories below are hoisted
// above every top-level const, and referencing one from there throws
// "Cannot access 'ROUTE_ID' before initialization".
const { ROUTE_ID, mocks } = vi.hoisted(() => ({
	ROUTE_ID: 'f2aa08ff-8c86-4ede-8bc1-96670b1342a5',
	mocks: {
		fetchTimeseries: vi.fn(),
		getRoute: vi.fn()
	}
}));

vi.mock('$lib/api/metrics', () => ({
	fetchTimeseries: (...a: unknown[]) => mocks.fetchTimeseries(...a)
}));

vi.mock('$lib/api/client', () => ({
	getRoute: (...a: unknown[]) => mocks.getRoute(...a)
}));

vi.mock('$app/state', () => ({
	page: { params: { routeId: ROUTE_ID } }
}));

vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import Page from './+page.svelte';

/** A dense, gap-free series so nothing is suppressed for thin data. */
function series(value: number | null) {
	return {
		routeId: ROUTE_ID,
		metric: 'total_ms',
		window: '24h',
		bucketSizeSeconds: 60,
		points: Array.from({ length: 10 }, (_, i) => ({
			ts: `2026-10-05T00:${String(i).padStart(2, '0')}:00Z`,
			value
		}))
	};
}

/** Every (metric, quantile) pair the page asked for. */
function callsFor(metric: string): (string | undefined)[] {
	return mocks.fetchTimeseries.mock.calls
		.filter((c) => c[1] === metric)
		.map((c) => c[3] as string | undefined);
}

beforeEach(() => {
	mocks.fetchTimeseries.mockReset();
	mocks.getRoute.mockReset();
	mocks.getRoute.mockResolvedValue({ id: ROUTE_ID, host: 'blog.example.com' });
	mocks.fetchTimeseries.mockImplementation((_r: string, metric: string) =>
		Promise.resolve({ ...series(100), metric })
	);
	if (!globalThis.ResizeObserver) {
		globalThis.ResizeObserver = class {
			observe() {}
			unobserve() {}
			disconnect() {}
		} as unknown as typeof ResizeObserver;
	}
});

describe('observability route page: the quantile selector', () => {
	it('states p95 explicitly on first load', async () => {
		// The page sends the parameter rather than leaning on the
		// server's default, and that is the better behaviour: an
		// operator reading their network tab sees exactly which
		// quantile produced the chart, with no need to know what the
		// default is. This test first asserted the opposite — the
		// omission my fetchTimeseries comment described — and caught
		// that the comment and the call site disagreed.
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBeGreaterThan(0));
		expect(callsFor('total_ms')).toEqual(['p95']);
		expect(callsFor('ttfb_ms')).toEqual(['p95']);
	});

	it('fetches BOTH latency series, not the legacy scalar', async () => {
		// p95_latency_ms is the legacy column: fixed at p95 and built as
		// a mean of per-bucket percentiles, which is not a percentile.
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBe(1));
		expect(callsFor('ttfb_ms').length).toBe(1);
		expect(callsFor('p95_latency_ms')).toEqual([]);
	});

	it('refetches both latency series with the chosen quantile', async () => {
		// THE untested path. The button has to reach the fetch; a
		// selector that only repaints would show p95 data under a p99
		// label, which is worse than not offering the choice.
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBe(1));

		await fireEvent.click(screen.getByTestId('quantile-p99'));

		await waitFor(() => expect(callsFor('total_ms')).toEqual(['p95', 'p99']));
		expect(callsFor('ttfb_ms')).toEqual(['p95', 'p99']);
	});

	it('passes p50 as well, so the parameter is not hard-coded to p99', async () => {
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBe(1));

		await fireEvent.click(screen.getByTestId('quantile-p50'));
		await waitFor(() => expect(callsFor('total_ms')).toEqual(['p95', 'p50']));
	});

	it('does not refetch when the selected quantile is clicked again', async () => {
		// Five requests per load; re-firing them on a no-op click is
		// the kind of waste the v2.62 work on background chatter was
		// about.
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBe(1));

		await fireEvent.click(screen.getByTestId('quantile-p95'));
		await new Promise((r) => setTimeout(r, 0));
		expect(callsFor('total_ms').length).toBe(1);
	});

	it('marks the active quantile for assistive tech, not only visually', async () => {
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBe(1));

		expect(screen.getByTestId('quantile-p95').getAttribute('aria-pressed')).toBe('true');
		expect(screen.getByTestId('quantile-p99').getAttribute('aria-pressed')).toBe('false');

		await fireEvent.click(screen.getByTestId('quantile-p99'));
		await waitFor(() =>
			expect(screen.getByTestId('quantile-p99').getAttribute('aria-pressed')).toBe('true')
		);
		expect(screen.getByTestId('quantile-p95').getAttribute('aria-pressed')).toBe('false');
	});

	it('keeps the counter series out of the quantile', async () => {
		// req_per_sec, four_xx_rate and five_xx_rate are counts. Sending
		// a quantile with them would be meaningless, and the operator
		// reading their network tab would reasonably conclude the
		// parameter applies to everything.
		render(Page);
		await waitFor(() => expect(callsFor('total_ms').length).toBe(1));
		await fireEvent.click(screen.getByTestId('quantile-p99'));
		await waitFor(() => expect(callsFor('total_ms').length).toBe(2));

		for (const metric of ['req_per_sec', 'four_xx_rate', 'five_xx_rate']) {
			expect(callsFor(metric).every((q) => q === undefined)).toBe(true);
		}
	});
});

// Each count point is one bucket's count: a minute on 24h, an hour
// on 30d. The titles read "/ minute" on both windows.
describe('observability route page: count units follow the bucket', () => {
	it('reads per minute on 24h and per hour on 30d', async () => {
		render(Page);
		await waitFor(() =>
			expect(screen.getByTestId('obs-title-req')).toHaveTextContent('Requests / min')
		);

		mocks.fetchTimeseries.mockImplementation((_r: string, metric: string) =>
			Promise.resolve({ ...series(100), metric, window: '30d', bucketSizeSeconds: 3600 })
		);
		await fireEvent.click(screen.getByRole('button', { name: '30d' }));

		await waitFor(() =>
			expect(screen.getByTestId('obs-title-req')).toHaveTextContent('Requests / h')
		);
	});
});

describe('observability route page: the way to the log', () => {
	it('links to the activity log filtered on this route', async () => {
		render(Page);
		const link = await screen.findByRole('link', { name: /View in logs/ });
		expect(link).toHaveAttribute('href', `/logs?route=${ROUTE_ID}`);
	});
});
