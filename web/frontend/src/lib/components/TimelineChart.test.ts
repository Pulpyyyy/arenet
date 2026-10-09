// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// TimelineChart tests: zero is data (an all-zero series draws a flat
// line, not the empty state), and the tooltip answers to pointers of
// any kind and to the keyboard.

import { afterEach, beforeEach, describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import { language } from '$lib/stores/language.svelte';
import Chart from './TimelineChart.svelte';

const WIDTH = 640;
const HEIGHT = 120;
// Mirrors the chart's left padding and its inner width at WIDTH
// (WIDTH - PAD_L - PAD_R), so a test can aim a pointer at a point.
const PAD_L = 36;
const INNER = WIDTH - 36 - 12;

function series(values: (number | null)[]) {
	return values.map((value, i) => ({
		ts: new Date(2026, 9, 5, 14, i).toISOString(),
		value
	}));
}

/** x in client pixels of point i out of n, given the stubbed rect. */
function xOf(i: number, n: number): number {
	return PAD_L + (i / (n - 1)) * INNER;
}

/** A pointer event of the given type. jsdom may lack PointerEvent, so
 *  build a MouseEvent (it carries clientX) and attach pointerType. */
function pointer(type: string, clientX: number, pointerType = 'mouse'): Event {
	const ev = new MouseEvent(type, { bubbles: true, clientX });
	Object.defineProperty(ev, 'pointerType', { value: pointerType });
	return ev;
}

function plot(): HTMLElement {
	return screen.getByRole('slider', { name: 'Errors' });
}

/** The value line of the tooltip, or null when no tooltip is shown. */
function tooltipText(): string | null {
	const tip = screen.queryByTestId('chart-tooltip');
	if (!tip) return null;
	return tip.querySelector('.tooltip-val')?.textContent ?? '';
}

describe('TimelineChart — zero is data', () => {
	it('draws an all-zero series as a line, not the empty state', () => {
		const { container } = render(Chart, {
			props: { points: series([0, 0, 0, 0]), color: 'red', label: 'Errors' }
		});
		expect(screen.queryByTestId('chart-empty')).toBeNull();
		expect(screen.queryByText('no data in this window')).toBeNull();
		const paths = container.querySelectorAll('path');
		expect(paths.length).toBe(1);
		const d = paths[0].getAttribute('d') ?? '';
		expect(d.startsWith('M')).toBe(true);
		// Flat: every vertex sits at the same y, the baseline.
		const ys = Array.from(d.matchAll(/[ML] [\d.]+ ([\d.]+)/g)).map((m) => m[1]);
		expect(ys).toHaveLength(4);
		expect(new Set(ys).size).toBe(1);
	});

	it('shows the empty state when no point was measured', () => {
		const { container } = render(Chart, {
			props: { points: series([null, null, null]), color: 'red', label: 'Errors' }
		});
		expect(screen.getByText('no data in this window')).toBeTruthy();
		expect(container.querySelectorAll('path').length).toBe(0);
	});

	it('says the empty state in the app language', () => {
		language.applyLocally('fr');
		try {
			render(Chart, {
				props: { points: series([null, null]), color: 'red', label: 'Errors' }
			});
			expect(screen.getByText('aucune donnée sur cette période')).toBeTruthy();
		} finally {
			language.applyLocally('en');
		}
	});
});

describe('TimelineChart — keyboard', () => {
	const points = series([11, 22, 33, 44, 55]);

	it('is a focusable slider named after the series', () => {
		render(Chart, { props: { points, color: 'red', label: 'Errors' } });
		const el = plot();
		expect(el.getAttribute('tabindex')).toBe('0');
		expect(el.getAttribute('aria-roledescription')).toBe('chart');
		expect(el.getAttribute('aria-valuemax')).toBe('4');
		// Nothing shown yet: the value text says how to read the chart.
		expect(el.getAttribute('aria-valuetext')).toBe(
			'Use the left and right arrow keys to read each point'
		);
	});

	it('steps the tooltip with the arrow keys', async () => {
		render(Chart, { props: { points, color: 'red', label: 'Errors' } });
		const el = plot();
		expect(tooltipText()).toBeNull();

		await fireEvent.keyDown(el, { key: 'ArrowRight' });
		expect(tooltipText()).toBe('11');
		expect(el.getAttribute('aria-valuenow')).toBe('0');
		expect(el.getAttribute('aria-valuetext')).toMatch(/: 11$/);

		await fireEvent.keyDown(el, { key: 'ArrowRight' });
		expect(tooltipText()).toBe('22');
		expect(el.getAttribute('aria-valuenow')).toBe('1');

		await fireEvent.keyDown(el, { key: 'ArrowLeft' });
		expect(tooltipText()).toBe('11');

		await fireEvent.keyDown(el, { key: 'End' });
		expect(tooltipText()).toBe('55');
	});

	it('starts Left on the most recent point', async () => {
		render(Chart, { props: { points, color: 'red', label: 'Errors' } });
		await fireEvent.keyDown(plot(), { key: 'ArrowLeft' });
		expect(tooltipText()).toBe('55');
	});

	it('hides the tooltip with Escape and on blur', async () => {
		render(Chart, { props: { points, color: 'red', label: 'Errors' } });
		const el = plot();
		await fireEvent.keyDown(el, { key: 'ArrowRight' });
		await fireEvent.keyDown(el, { key: 'Escape' });
		expect(tooltipText()).toBeNull();

		await fireEvent.keyDown(el, { key: 'ArrowRight' });
		expect(tooltipText()).not.toBeNull();
		await fireEvent.blur(el);
		expect(tooltipText()).toBeNull();
	});
});

describe('TimelineChart — pointer', () => {
	const points = series([11, 22, 33, 44, 55]);

	beforeEach(() => {
		// jsdom lays nothing out: give the chart a width and the plot a
		// rect so a clientX maps to a point.
		vi.spyOn(Element.prototype, 'clientWidth', 'get').mockReturnValue(WIDTH);
		vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
			left: 0,
			top: 0,
			right: WIDTH,
			bottom: HEIGHT,
			width: WIDTH,
			height: HEIGHT,
			x: 0,
			y: 0,
			toJSON: () => ({})
		} as DOMRect);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('shows the tooltip for the point under a moving pointer', async () => {
		render(Chart, { props: { points, color: 'red', label: 'Errors' } });
		const el = plot();
		await fireEvent(el, pointer('pointermove', xOf(2, points.length)));
		expect(tooltipText()).toBe('33');

		await fireEvent(el, pointer('pointerleave', 0));
		expect(tooltipText()).toBeNull();
	});

	it('keeps a tapped tooltip after the finger lifts', async () => {
		render(Chart, { props: { points, color: 'red', label: 'Errors' } });
		const el = plot();
		await fireEvent(el, pointer('pointerdown', xOf(1, points.length), 'touch'));
		expect(tooltipText()).toBe('22');

		// Touch fires pointerleave right after pointerup.
		await fireEvent(el, pointer('pointerleave', xOf(1, points.length), 'touch'));
		expect(tooltipText()).toBe('22');
	});
});
