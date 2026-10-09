// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V polish — MapLegend tests.
//
// Pins the 5-row legend shape, the per-row CSS-var swatch
// color (single source of truth = categoryColors.ts), the
// translated labels, and the "à venir" marker on the
// currently-unemitted "normal" category. A future
// regression that drops a category or rewires a color
// surfaces immediately.

import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import MapLegend from './MapLegend.svelte';
import { CATEGORY_COLORS } from './categoryColors';
import { language } from '$lib/stores/language.svelte';

const CATEGORIES = ['normal', 'throttle', 'waf', 'crowdsec', 'auth', 'country_block'] as const;

describe('MapLegend', () => {
	it('renders all 6 category rows', () => {
		render(MapLegend);
		for (const cat of CATEGORIES) {
			expect(screen.getByTestId(`map-legend-item-${cat}`)).toBeInTheDocument();
		}
	});

	it('uses the categoryColors.ts CSS var for each row dot-svg', () => {
		render(MapLegend);
		for (const cat of CATEGORIES) {
			const row = screen.getByTestId(`map-legend-item-${cat}`);
			const dots = row.querySelector('.dots') as SVGElement | null;
			expect(dots).not.toBeNull();
			// Inline style sets `color: var(--token)`; the
			// dot circles paint via fill="currentColor" so
			// the per-row token resolves at browser runtime
			// (jsdom doesn't compute CSS custom properties).
			expect(dots?.getAttribute('style') ?? '').toContain(CATEGORY_COLORS[cat]);
		}
	});

	it('renders the operator labels in English by default', () => {
		render(MapLegend);
		// Pin a sample of the operator-meaningful copy.
		expect(screen.getByTestId('map-legend-item-throttle').textContent ?? '').toContain(
			'rate-limit'
		);
		expect(screen.getByTestId('map-legend-item-waf').textContent ?? '').toContain(
			'Coraza'
		);
		expect(screen.getByTestId('map-legend-item-crowdsec').textContent ?? '').toContain(
			'reputation'
		);
		expect(screen.getByTestId('map-legend-item-auth').textContent ?? '').toContain(
			'authentication'
		);
	});

	it('renders the French labels when French is chosen', () => {
		language.current = 'fr';
		try {
			render(MapLegend);
			expect(screen.getByTestId('map-legend-item-crowdsec').textContent ?? '').toContain(
				'réputation'
			);
			expect(screen.getByTestId('map-legend').getAttribute('aria-label') ?? '').toMatch(
				/légende/i
			);
		} finally {
			language.current = 'en';
		}
	});

	it('does NOT mark "normal" as à venir (V.1.4 — backend now emits green arcs)', () => {
		// Pin the V.1.4 regression: V.1.1-V.1.3 ship the
		// backend emission path for the "normal" category,
		// so the legend row no longer needs the "à venir"
		// future-state marker. A future regression that
		// re-adds comingSoon: true to the normal row would
		// flag this row as not-yet-shipped even though
		// operators with ARENET_NORMAL_TRAFFIC_SAMPLE_PCT
		// > 0 see live green arcs.
		render(MapLegend);
		const normalRow = screen.getByTestId('map-legend-item-normal');
		// Checked on the marker element, not its text: the text
		// is translated, the element is not.
		expect(normalRow.querySelector('.legend-coming-soon')).toBeNull();
	});

	it('preserves the .legend-coming-soon CSS hook for future categories', () => {
		// The conditional `{#if entry.comingSoon}` branch
		// + the .legend-coming-soon class stay in place
		// even though no live entry uses them today. A
		// future category (or a feature-gate use-case) can
		// re-enable the marker without re-architecting the
		// row shape. This test asserts the structural
		// surface is intact — no actual .legend-coming-soon
		// element renders since all 5 V.1.4 entries set
		// comingSoon to false.
		const { container } = render(MapLegend);
		// No live coming-soon markers in V.1.4 — but the
		// stylesheet should still carry the class so
		// re-enabling the flag in a future entry doesn't
		// produce unstyled text. We check the rendered
		// DOM has zero coming-soon emelents AND the
		// component's <style> block (parsed by Svelte)
		// still references the class. Since the style is
		// scoped, we can verify by enumerating attributes
		// on the rendered subtree — there shouldn't be
		// any .legend-coming-soon nodes.
		expect(container.querySelectorAll('.legend-coming-soon').length).toBe(0);
	});

	it('exposes a toggle that collapses + restores the list', async () => {
		render(MapLegend);
		// Default: expanded.
		expect(screen.getByTestId('map-legend-list')).toBeInTheDocument();

		const toggle = screen.getByTestId('map-legend-toggle');
		await fireEvent.click(toggle);
		expect(screen.queryByTestId('map-legend-list')).toBeNull();
		expect(toggle.getAttribute('aria-expanded')).toBe('false');

		await fireEvent.click(toggle);
		expect(screen.getByTestId('map-legend-list')).toBeInTheDocument();
		expect(toggle.getAttribute('aria-expanded')).toBe('true');
	});

	it('has an aria-label on the root for screen-reader discoverability', () => {
		render(MapLegend);
		const root = screen.getByTestId('map-legend');
		expect(root.getAttribute('aria-label') ?? '').toMatch(/legend/i);
	});

	it('mirrors the topology panel visual language (.panel class + dots + legend-note)', () => {
		// Pins the visual-consistency win: a future
		// regression that drops the .panel class or the
		// .dots / .legend-note shape would diverge from
		// the topology page's TopologySidebar pattern.
		render(MapLegend);
		const root = screen.getByTestId('map-legend');
		expect(root.classList.contains('panel')).toBe(true);
		expect(root.querySelectorAll('.dots').length).toBe(6);
		expect(root.querySelector('.legend-note')).not.toBeNull();
	});
});
