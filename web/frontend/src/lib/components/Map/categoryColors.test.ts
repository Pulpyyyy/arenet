// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.6 — pins the category → CSS var mapping so a
// future regression that drops or renames a token
// surfaces immediately. The tokens themselves resolve at
// browser runtime (jsdom doesn't compute CSS custom
// properties), so we only assert the var() reference
// shape, not the rendered color.

import { describe, it, expect } from 'vitest';
import { CATEGORY_COLORS, CATEGORY_DASHES, CATEGORY_LABELS_FR } from './categoryColors';
import type { GeoEventCategory } from '$lib/api/types';

const ALL_CATEGORIES: readonly GeoEventCategory[] = [
	'normal',
	'throttle',
	'waf',
	'crowdsec',
	'auth'
];

describe('CATEGORY_COLORS', () => {
	it.each(ALL_CATEGORIES)('declares a CSS var for category %s', (cat) => {
		expect(CATEGORY_COLORS[cat]).toMatch(/^var\(--[a-z-]+\)$/);
	});

	it('maps each category to a DISTINCT token', () => {
		// Spec §5.6 lists 5 categories; the V.6 brief asked
		// for 5 distinct colors. The V.5 file-header
		// comment proposed re-using --status-down for both
		// waf and crowdsec; V.6 split crowdsec onto
		// --accent-cyan to honor "5 distinct colors". This
		// test pins that decision.
		const values = ALL_CATEGORIES.map((c) => CATEGORY_COLORS[c]);
		expect(new Set(values).size).toBe(ALL_CATEGORIES.length);
	});

	it('uses --status-down for waf (red)', () => {
		expect(CATEGORY_COLORS.waf).toBe('var(--status-down)');
	});

	it('uses --accent-cyan for crowdsec (distinct from waf)', () => {
		expect(CATEGORY_COLORS.crowdsec).toBe('var(--accent-cyan)');
		expect(CATEGORY_COLORS.crowdsec).not.toBe(CATEGORY_COLORS.waf);
	});
});

// Hue alone does not separate the categories (normal vs waf for a
// deuteranope, crowdsec vs auth for everyone), so each one also has a
// line rhythm. All six, country_block included — it is the category
// most often read as "just another grey line".
const EVERY_CATEGORY: readonly GeoEventCategory[] = [...ALL_CATEGORIES, 'country_block'];

describe('CATEGORY_DASHES', () => {
	it.each(EVERY_CATEGORY)('declares a dash pattern for category %s', (cat) => {
		// 'none' (solid) or a list of non-negative numbers.
		expect(CATEGORY_DASHES[cat]).toMatch(/^(none|\d+(\.\d+)?( \d+(\.\d+)?)+)$/);
	});

	it('gives every category a DISTINCT pattern', () => {
		const values = EVERY_CATEGORY.map((c) => CATEGORY_DASHES[c]);
		expect(new Set(values).size).toBe(EVERY_CATEGORY.length);
	});

	it('separates the pairs that hue confuses', () => {
		expect(CATEGORY_DASHES.normal).not.toBe(CATEGORY_DASHES.waf);
		expect(CATEGORY_DASHES.crowdsec).not.toBe(CATEGORY_DASHES.auth);
	});
});

describe('CATEGORY_LABELS_FR', () => {
	it.each(ALL_CATEGORIES)('declares a non-empty French label for %s', (cat) => {
		expect(CATEGORY_LABELS_FR[cat]).toMatch(/.+/);
	});
});
