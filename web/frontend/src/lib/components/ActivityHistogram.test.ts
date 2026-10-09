// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Z.5.4 — unit tests for ActivityHistogram.
// Focused on the SVG output shape (one stacked bar per
// bucket, segmented by source) without exercising the
// hover tooltip which needs jsdom event plumbing not
// worth the test weight at V1.

import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import ActivityHistogram from './ActivityHistogram.svelte';

// Anchor inside each test via a helper to avoid the
// module-load-vs-test-run time skew that can push a
// short-window bucket outside the active window when
// the test suite warms up slowly.
function isoOffset(secondsBack: number): string {
	return new Date(Date.now() - secondsBack * 1000).toISOString();
}

const SERIES = [
	{ key: 'waf', label: 'WAF', color: 'red' },
	{ key: 'rate_limit', label: 'RATE-LIMIT', color: 'orange' },
	{ key: 'auth', label: 'AUTH', color: 'cyan' }
];

describe('ActivityHistogram', () => {
	it('renders the SVG with the aria-label', () => {
		const { container, getByLabelText } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Test histogram'
		});
		expect(getByLabelText('Test histogram')).toBeInTheDocument();
		expect(container.querySelector('svg')).toBeInTheDocument();
	});

	it('produces zero <rect class="bar-seg"> when cells are empty', () => {
		const { container } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Empty'
		});
		expect(container.querySelectorAll('rect.bar-seg').length).toBe(0);
	});

	it('renders one bar segment per non-empty (bucket × source) cell', () => {
		const { container } = render(ActivityHistogram, {
			cells: [
				{ ts: isoOffset(60), source: 'waf' },
				{ ts: isoOffset(60), source: 'waf' },
				{ ts: isoOffset(60), source: 'rate_limit' },
				{ ts: isoOffset(120), source: 'auth' }
			],
			series: SERIES,
			label: 'Three bars'
		});
		const segs = container.querySelectorAll('rect.bar-seg');
		// 60s ago: 2 sources → 2 segments
		// 120s ago: 1 source → 1 segment
		// Total = 3.
		expect(segs.length).toBe(3);
	});

	it('renders bar segments with the series color (verifies stack identity)', () => {
		const { container } = render(ActivityHistogram, {
			cells: [
				{ ts: isoOffset(60), source: 'waf' },
				{ ts: isoOffset(60), source: 'rate_limit' }
			],
			series: SERIES,
			label: 'Colors'
		});
		const fills = Array.from(container.querySelectorAll('rect.bar-seg')).map(
			(el) => el.getAttribute('fill')
		);
		expect(fills).toContain('red');
		expect(fills).toContain('orange');
	});

	it('drops cells older than the window', () => {
		// 25h ago > 24h window → cell must NOT produce a bar.
		const { container } = render(ActivityHistogram, {
			cells: [{ ts: isoOffset(25 * 3600), source: 'waf' }],
			series: SERIES,
			label: 'Old cell dropped',
			windowMs: 24 * 60 * 60 * 1000
		});
		expect(container.querySelectorAll('rect.bar-seg').length).toBe(0);
	});

	it('renders axis labels (start/middle/now)', () => {
		const { getByText } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Axes'
		});
		// "now" tick is the right edge label.
		expect(getByText('now')).toBeInTheDocument();
	});

	it('honors a custom bucketMs (1-minute granularity)', () => {
		// Two cells inside the SAME 1-minute bucket → exactly
		// one stacked bar segment.
		//
		// Pre-fix : the test used isoOffset(1) + isoOffset(3),
		// expecting "tight spread under 5s = same bucket". That
		// premise was wrong : the 1-minute bucket is aligned on
		// epoch boundaries (Math.floor(ts/60_000)*60_000), so
		// two timestamps 2s apart STRADDLE the boundary whenever
		// the test happens to run within 3s of a minute mark.
		// Fail rate ≈ 5% (3 seconds out of 60), and CI's slower
		// startup amplifies the chance the test lands on the
		// boundary. Locally observed pass ; CI observed fail
		// 2026-06-23 commit ef960b5 sweep.
		//
		// Fix : anchor both timestamps inside a single bucket by
		// snapping to the current bucket's floor + adding tiny
		// offsets that stay WITHIN the same 60s window. The
		// arithmetic is timezone-agnostic (epoch millis only).
		const bucketMs = 60 * 1000;
		// Pick a recent bucket floor ; aim for 90 s ago so we
		// land safely inside the 24h default window AND have a
		// full bucket of headroom away from the "now" boundary
		// (avoids the symmetric flake where Date.now() advances
		// past the bucket end between the test setup and the
		// component's render-time current-time read).
		const bucketFloor = Math.floor((Date.now() - 90 * 1000) / bucketMs) * bucketMs;
		const insideBucketA = new Date(bucketFloor + 5_000).toISOString();
		const insideBucketB = new Date(bucketFloor + 30_000).toISOString();
		const { container } = render(ActivityHistogram, {
			cells: [
				{ ts: insideBucketA, source: 'waf' },
				{ ts: insideBucketB, source: 'waf' }
			],
			series: SERIES,
			label: '1-min bucket',
			bucketMs
		});
		expect(container.querySelectorAll('rect.bar-seg').length).toBe(1);
	});

	// Phase Z.5.6 — height: 'fill' mode tests.
	it('numeric height renders the SVG with the literal pixel attribute', () => {
		const { container } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Numeric',
			height: 240
		});
		const svg = container.querySelector('svg');
		expect(svg).not.toBeNull();
		// Z.5.6 invariant : numeric path is unchanged from
		// pre-Z.5.6 behavior. The fill mode must NOT activate
		// for callers that pass a number.
		expect(svg?.getAttribute('height')).toBe('240');
		const wrap = container.querySelector('.activity-histogram');
		expect(wrap?.classList.contains('fill')).toBe(false);
	});

	it('height: "fill" renders SVG height="100%" + fill class on wrapper', () => {
		const { container } = render(ActivityHistogram, {
			cells: [],
			series: SERIES,
			label: 'Fill',
			height: 'fill'
		});
		const svg = container.querySelector('svg');
		expect(svg?.getAttribute('height')).toBe('100%');
		const wrap = container.querySelector('.activity-histogram');
		// .fill class is what unlocks the .fill { flex:1 }
		// CSS rule on the wrapper. Pinning the class lets a
		// future regression where the wire-up drops the
		// boolean surface as a class-missing assertion.
		expect(wrap?.classList.contains('fill')).toBe(true);
	});
});

// The tooltip was mouse-only (mouseenter). It now follows pointer
// events, which a finger fires too, and the keyboard.
describe('ActivityHistogram — tooltip', () => {
	// An hour apart, so the two land in different 5-minute buckets:
	// the older one holds AUTH, the newer one two WAF events.
	function twoBuckets() {
		return [
			{ ts: isoOffset(3600), source: 'auth' },
			{ ts: isoOffset(60), source: 'waf' },
			{ ts: isoOffset(60), source: 'waf' }
		];
	}

	/** A pointer event; jsdom may lack PointerEvent, so a MouseEvent
	 *  with pointerType attached stands in for it. */
	function pointer(type: string, pointerType: string): Event {
		const ev = new MouseEvent(type, { bubbles: false, clientX: 100, clientY: 20 });
		Object.defineProperty(ev, 'pointerType', { value: pointerType });
		return ev;
	}

	it('shows on pointerenter and hides on a mouse pointerleave', async () => {
		const { container } = render(ActivityHistogram, {
			cells: twoBuckets(),
			series: SERIES,
			label: 'Pointer'
		});
		const bars = container.querySelectorAll('[data-testid="histogram-bucket"]');
		expect(bars.length).toBe(2);

		await fireEvent(bars[1], pointer('pointerenter', 'mouse'));
		const tip = screen.getByTestId('histogram-tooltip');
		expect(tip.textContent).toContain('WAF · 2');

		await fireEvent(bars[1], pointer('pointerleave', 'mouse'));
		expect(screen.queryByTestId('histogram-tooltip')).toBeNull();
	});

	it('keeps a tapped tooltip after the finger lifts', async () => {
		const { container } = render(ActivityHistogram, {
			cells: twoBuckets(),
			series: SERIES,
			label: 'Touch'
		});
		const bars = container.querySelectorAll('[data-testid="histogram-bucket"]');
		await fireEvent(bars[0], pointer('pointerenter', 'touch'));
		await fireEvent(bars[0], pointer('pointerleave', 'touch'));
		expect(screen.getByTestId('histogram-tooltip').textContent).toContain('AUTH · 1');
	});

	it('steps through the buckets that hold events with the arrow keys', async () => {
		render(ActivityHistogram, { cells: twoBuckets(), series: SERIES, label: 'Keys' });
		const plot = screen.getByRole('slider', { name: 'Keys' });
		expect(plot.getAttribute('tabindex')).toBe('0');
		expect(plot.getAttribute('aria-valuemax')).toBe('1');

		await fireEvent.keyDown(plot, { key: 'ArrowRight' });
		expect(screen.getByTestId('histogram-tooltip').textContent).toContain('AUTH · 1');
		expect(plot.getAttribute('aria-valuetext')).toContain('AUTH 1');

		await fireEvent.keyDown(plot, { key: 'ArrowRight' });
		expect(screen.getByTestId('histogram-tooltip').textContent).toContain('WAF · 2');
		expect(plot.getAttribute('aria-valuenow')).toBe('1');

		await fireEvent.keyDown(plot, { key: 'Escape' });
		expect(screen.queryByTestId('histogram-tooltip')).toBeNull();
	});
});
