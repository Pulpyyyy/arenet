// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The legend shows each category's dash rhythm, not only its colour.
//
// Hue alone does not separate the map's categories (normal vs waf for
// a deuteranope, crowdsec vs auth for everyone), so every arc also
// carries a dash pattern from CATEGORY_DASHES. A key drawn in colour
// only could not be matched to the map by someone who does not see
// the hue — it must draw the same pattern.
//
// Kept apart from MapLegend.test.ts, whose label assertions another
// change is translating, so the two can land in either order.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import MapLegend from './MapLegend.svelte';
import { CATEGORY_DASHES } from './categoryColors';

const CATEGORIES = ['normal', 'throttle', 'waf', 'crowdsec', 'auth', 'country_block'] as const;

describe('MapLegend — dash patterns', () => {
	it.each(CATEGORIES)('draws the %s row with the pattern its arcs use', (cat) => {
		render(MapLegend);
		const line = screen.getByTestId(`map-legend-item-${cat}`).querySelector('.dots line');
		expect(line).not.toBeNull();
		expect(line?.getAttribute('stroke-dasharray')).toBe(CATEGORY_DASHES[cat]);
	});

	it('draws six different patterns', () => {
		render(MapLegend);
		const patterns = CATEGORIES.map(
			(cat) =>
				screen
					.getByTestId(`map-legend-item-${cat}`)
					.querySelector('.dots line')
					?.getAttribute('stroke-dasharray') ?? ''
		);
		expect(new Set(patterns).size).toBe(CATEGORIES.length);
	});
});
