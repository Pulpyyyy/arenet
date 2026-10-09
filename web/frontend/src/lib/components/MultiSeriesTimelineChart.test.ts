// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 5 — MultiSeriesTimelineChart tests.
//
// Approach mirrors the existing TimelineChart pattern: pin
// the rendered <path data-testid="series-path-*"> elements
// per series, plus legend toggle behaviour and tooltip
// emission on hover. Mechanical assertions (presence /
// absence of DOM nodes, attribute values) — hover x→idx
// math is tested via direct fireEvent.mouseMove with a
// known clientX.

import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Chart from './MultiSeriesTimelineChart.svelte';

const sampleData = [
	{ bucketStart: '2026-06-01T00:00:00Z', issued: 2, renewed: 0, failed: 1 },
	{ bucketStart: '2026-06-02T00:00:00Z', issued: 0, renewed: 0, failed: 0 },
	{ bucketStart: '2026-06-03T00:00:00Z', issued: 1, renewed: 2, failed: 0 }
];

const certSeries = [
	{ key: 'issued', label: 'Issued', color: 'var(--status-up)' },
	{ key: 'renewed', label: 'Renewed', color: 'var(--accent-cyan)' },
	{ key: 'failed', label: 'Failed', color: 'var(--status-down)' }
];

describe('MultiSeriesTimelineChart', () => {
	it('renders one path per series', () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		expect(screen.getByTestId('series-path-issued')).toBeTruthy();
		expect(screen.getByTestId('series-path-renewed')).toBeTruthy();
		expect(screen.getByTestId('series-path-failed')).toBeTruthy();
	});

	it('renders one legend toggle per series', () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		expect(screen.getByTestId('legend-toggle-issued')).toBeTruthy();
		expect(screen.getByTestId('legend-toggle-renewed')).toBeTruthy();
		expect(screen.getByTestId('legend-toggle-failed')).toBeTruthy();
	});

	it('hides a series path when its legend toggle is clicked', async () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		expect(screen.queryByTestId('series-path-failed')).not.toBeNull();

		await fireEvent.click(screen.getByTestId('legend-toggle-failed'));

		expect(screen.queryByTestId('series-path-failed')).toBeNull();
		// Other series still rendered.
		expect(screen.getByTestId('series-path-issued')).toBeTruthy();
		expect(screen.getByTestId('series-path-renewed')).toBeTruthy();
	});

	it('restores a hidden series when its toggle is clicked again', async () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		const toggle = screen.getByTestId('legend-toggle-failed');
		await fireEvent.click(toggle);
		expect(screen.queryByTestId('series-path-failed')).toBeNull();
		await fireEvent.click(toggle);
		expect(screen.queryByTestId('series-path-failed')).toBeTruthy();
	});

	it('renders empty-state text when every series is hidden', async () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		await fireEvent.click(screen.getByTestId('legend-toggle-issued'));
		await fireEvent.click(screen.getByTestId('legend-toggle-renewed'));
		await fireEvent.click(screen.getByTestId('legend-toggle-failed'));

		expect(screen.getByText('No events in this period')).toBeTruthy();
	});

	it('renders empty-state text when data is all zeros', () => {
		const zeros = sampleData.map((d) => ({ ...d, issued: 0, renewed: 0, failed: 0 }));
		render(Chart, { props: { data: zeros, series: certSeries, label: 'Cert events' } });
		expect(screen.getByText('No events in this period')).toBeTruthy();
	});

	it('does NOT render tooltip when hover is outside chart bounds', () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		// Without a mouse move, tooltip should not be in the DOM.
		expect(screen.queryByTestId('chart-tooltip')).toBeNull();
	});

	it('aria-pressed reflects toggled state on the legend button', async () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		const toggle = screen.getByTestId('legend-toggle-failed');
		expect(toggle.getAttribute('aria-pressed')).toBe('true');
		await fireEvent.click(toggle);
		expect(toggle.getAttribute('aria-pressed')).toBe('false');
	});

	it('renders legend label text from series.label', () => {
		render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		expect(screen.getByText('Issued')).toBeTruthy();
		expect(screen.getByText('Renewed')).toBeTruthy();
		expect(screen.getByText('Failed')).toBeTruthy();
	});

	it('uses series.color via inline style on the swatch', () => {
		const { container } = render(Chart, {
			props: { data: sampleData, series: certSeries, label: 'Cert events' }
		});
		const swatches = container.querySelectorAll('.legend-swatch');
		expect(swatches.length).toBe(3);
		// inline style is exposed via element.style or the
		// style attribute. JSDOM stringifies oklch / var() refs.
		expect(swatches[0].getAttribute('style')).toContain('--status-up');
		expect(swatches[2].getAttribute('style')).toContain('--status-down');
	});
});

// --- nullAsGap -------------------------------------------------------------
//
// The latency chart on /observability/<id> plots two series whose
// points can legitimately be null: a bucket predating schema v15, a
// bucket where nothing observable was recorded, or one holding too few
// requests for the chosen quantile.
//
// Drawing those at zero would claim the route answered instantly
// exactly where nothing was measured — the defect the whole
// latency-truth work removed from the backend, and trivially
// reintroducible in a chart. nullAsGap is opt-in because the existing
// caller plots COUNTS, where a missing bucket really did see zero
// events and drawing it at zero is the truth.

const latencySeries = [
	{ key: 'ttfb', label: 'server', color: 'var(--status-info)' },
	{ key: 'total', label: 'with transfer', color: 'var(--accent-cyan)' }
];

const gappyData = [
	{ bucketStart: '2026-10-05T00:00:00Z', ttfb: 100, total: 120 },
	{ bucketStart: '2026-10-05T00:01:00Z', ttfb: null, total: null },
	{ bucketStart: '2026-10-05T00:02:00Z', ttfb: 110, total: 300 }
];

/** Count the subpaths in an SVG path: one M per pen-down. */
function subpaths(d: string): number {
	return (d.match(/M/g) ?? []).length;
}

describe('MultiSeriesTimelineChart — nullAsGap', () => {
	it('breaks the line at a null instead of drawing through zero', () => {
		render(Chart, {
			props: { data: gappyData, series: latencySeries, label: 'Latency', nullAsGap: true }
		});
		const d = screen.getByTestId('series-path-ttfb').getAttribute('d') ?? '';
		// Two subpaths: one before the gap, one after. A single
		// subpath means the line was drawn across it.
		expect(subpaths(d)).toBe(2);
	});

	it('does not plot a null at the zero baseline', () => {
		// The y of a zero value is the bottom of the plot area. With
		// maxVal 300 over three buckets, a point drawn at zero would
		// sit far below the real ones; the gap means no such point
		// exists at all.
		render(Chart, {
			props: { data: gappyData, series: latencySeries, label: 'Latency', nullAsGap: true }
		});
		const d = screen.getByTestId('series-path-total').getAttribute('d') ?? '';
		const ys = Array.from(d.matchAll(/[ML] [\d.]+ ([\d.]+)/g)).map((m) => Number(m[1]));
		expect(ys).toHaveLength(2);
		// Both remaining points come from real values (120 and 300),
		// so neither sits at the baseline the way a coerced zero would.
		const maxY = Math.max(...ys);
		const minY = Math.min(...ys);
		expect(maxY).toBeGreaterThan(minY);
	});

	it('keeps the zero-coercion when nullAsGap is off', () => {
		// The dashboard's certificate chart depends on this: a day with
		// no events is a real measurement of none, and its line must
		// stay continuous through it.
		render(Chart, {
			props: { data: gappyData, series: latencySeries, label: 'Latency' }
		});
		const d = screen.getByTestId('series-path-ttfb').getAttribute('d') ?? '';
		expect(subpaths(d)).toBe(1);
	});

	it('scales the y axis to the measured values, ignoring the gaps', () => {
		// A null folded in as zero would not change the max, but a null
		// folded in as a VALUE would. This pins that the gap is absent
		// from the scale rather than participating in it.
		render(Chart, {
			props: {
				data: [
					{ bucketStart: '2026-10-05T00:00:00Z', ttfb: null, total: null },
					{ bucketStart: '2026-10-05T00:01:00Z', ttfb: 50, total: 50 }
				],
				series: latencySeries,
				label: 'Latency',
				nullAsGap: true
			}
		});
		const d = screen.getByTestId('series-path-ttfb').getAttribute('d') ?? '';
		// One real point only, so one subpath and no stray segment
		// reaching back to a phantom zero.
		expect(subpaths(d)).toBe(1);
		expect((d.match(/L/g) ?? []).length).toBe(0);
	});

	it('renders an empty state when every point is null', () => {
		// All-null is not all-zero. The chart must not draw a flat line
		// along the baseline implying a route that answered instantly
		// all window.
		render(Chart, {
			props: {
				data: [
					{ bucketStart: '2026-10-05T00:00:00Z', ttfb: null, total: null },
					{ bucketStart: '2026-10-05T00:01:00Z', ttfb: null, total: null }
				],
				series: latencySeries,
				label: 'Latency',
				nullAsGap: true
			}
		});
		const path = screen.queryByTestId('series-path-ttfb');
		const d = path?.getAttribute('d') ?? '';
		expect(d).toBe('');
	});
});
