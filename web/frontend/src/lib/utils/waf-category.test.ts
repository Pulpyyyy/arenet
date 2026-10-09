// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Y (2026-06-18) — waf-category helper invariants.
//
// Pins the centralised metadata contract :
//   - every OwaspCategory has a label + description + colour
//     + family entry (no Record holes that would let a
//     consumer crash on a real category).
//   - categoryMeta(unknown) degrades to the fallback meta.
//   - categoriesByFamily preserves the input order and groups
//     by family without losing entries.

import { describe, it, expect } from 'vitest';
import { ALL_OWASP_CATEGORIES, type OwaspCategory } from '$lib/api/types';
import {
	categoryMeta,
	categoriesByFamily,
	CATEGORY_META,
	FAMILY_LABEL,
	type CategoryFamily
} from './waf-category';
import { language } from '$lib/stores/language.svelte';

describe('waf-category', () => {
	it('CATEGORY_META has an entry for every OwaspCategory in ALL_OWASP_CATEGORIES', () => {
		for (const c of ALL_OWASP_CATEGORIES) {
			expect(CATEGORY_META[c], `missing meta for ${c}`).toBeDefined();
			expect(CATEGORY_META[c].label.length).toBeGreaterThan(0);
			expect(CATEGORY_META[c].description.length).toBeGreaterThan(0);
		}
	});

	// The copy lives in the locale files: a missing key would make
	// t() hand back the raw key, which still passes the length checks
	// above. Check both languages resolve to real text, and that the
	// English one follows the language switch.
	it('resolves every label, description and family in both languages', () => {
		try {
			for (const lang of ['en', 'fr'] as const) {
				language.current = lang;
				for (const c of ALL_OWASP_CATEGORIES) {
					expect(CATEGORY_META[c].label).not.toContain('wafCategory.');
					expect(CATEGORY_META[c].description).not.toContain('wafCategory.');
				}
				for (const fam of Object.keys(FAMILY_LABEL) as CategoryFamily[]) {
					expect(FAMILY_LABEL[fam]).not.toContain('wafCategory.');
				}
				expect(categoryMeta('TOTALLY_FAKE_CATEGORY').label).not.toContain('wafCategory.');
			}
			language.current = 'en';
			expect(FAMILY_LABEL['request-attack']).toBe('Request attacks');
			expect(CATEGORY_META.CUSTOM.label).toBe('Custom rules');
			language.current = 'fr';
			expect(FAMILY_LABEL['request-attack']).toBe('Attaques sur la requête');
			expect(CATEGORY_META.CUSTOM.label).toBe('Règles personnalisées');
		} finally {
			language.current = 'en';
		}
	});

	it('every meta entry has a family in FAMILY_LABEL', () => {
		const known = new Set(Object.keys(FAMILY_LABEL));
		for (const c of ALL_OWASP_CATEGORIES) {
			expect(known.has(CATEGORY_META[c].family), `unknown family for ${c}`).toBe(true);
		}
	});

	it('categoryMeta falls back to a non-empty meta for an unknown string', () => {
		const m = categoryMeta('TOTALLY_FAKE_CATEGORY' as OwaspCategory);
		expect(m.label.length).toBeGreaterThan(0);
		expect(m.color.length).toBeGreaterThan(0);
		expect(m.family).toBeDefined();
	});

	it('categoriesByFamily covers every category exactly once', () => {
		const groups = categoriesByFamily(ALL_OWASP_CATEGORIES);
		const seen = new Set<OwaspCategory>();
		for (const g of groups) {
			for (const c of g.categories) {
				if (seen.has(c)) {
					throw new Error(`category ${c} appears in more than one family group`);
				}
				seen.add(c);
			}
		}
		for (const c of ALL_OWASP_CATEGORIES) {
			expect(seen.has(c), `category ${c} missing from family grouping`).toBe(true);
		}
	});

	it('categoriesByFamily yields families in FAMILY_LABEL order', () => {
		const groups = categoriesByFamily(ALL_OWASP_CATEGORIES);
		const expected = Object.keys(FAMILY_LABEL) as CategoryFamily[];
		const got = groups.map((g) => g.family);
		// got is a SUBSEQUENCE of expected (families with zero
		// categories are dropped). Pin the relative order.
		let idx = 0;
		for (const fam of got) {
			while (idx < expected.length && expected[idx] !== fam) idx++;
			if (idx === expected.length) {
				throw new Error(`family ${fam} appeared out of FAMILY_LABEL order`);
			}
			idx++;
		}
	});

	it('Phase Y request-attack family includes the previously-aggregated RCE family split', () => {
		// Pre-Y the operator saw a single RCE entry that
		// summed shell injection + PHP + Java + generic. Phase
		// Y splits them ; the request-attack family must list
		// each as its own entry.
		const reqAttack = categoriesByFamily(ALL_OWASP_CATEGORIES).find(
			(g) => g.family === 'request-attack'
		);
		expect(reqAttack).toBeDefined();
		expect(reqAttack!.categories).toEqual(
			expect.arrayContaining(['RCE', 'PHP', 'JAVA', 'GENERIC'])
		);
	});

	it('Phase Y data-leak family pulls together the 950-955 response-side rules', () => {
		const dataLeak = categoriesByFamily(ALL_OWASP_CATEGORIES).find(
			(g) => g.family === 'data-leak'
		);
		expect(dataLeak).toBeDefined();
		expect(dataLeak!.categories).toEqual(
			expect.arrayContaining([
				'DATA_LEAK',
				'DATA_LEAK_SQL',
				'DATA_LEAK_JAVA',
				'DATA_LEAK_PHP',
				'DATA_LEAK_IIS',
				'WEBSHELL'
			])
		);
	});
});
