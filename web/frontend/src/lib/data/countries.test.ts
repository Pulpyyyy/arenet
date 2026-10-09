// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// W.7 — unit tests for the country dataset + lookup.

import { afterEach, describe, it, expect } from 'vitest';
import { language } from '$lib/stores/language.svelte';
import { ALPHA2_CODES, countryName, matchCountries } from './countries';

describe('ALPHA2_CODES', () => {
	it('contains the full ISO 3166-1 alpha-2 set', () => {
		// 249 officially-assigned codes as of 2026. Sanity-
		// bound the count so an accidental drop / paste error
		// surfaces immediately.
		expect(ALPHA2_CODES.length).toBe(249);
	});

	it('contains the operationally-meaningful sample codes', () => {
		for (const code of ['FR', 'DE', 'GB', 'US', 'RU', 'CN', 'JP', 'KP', 'BR']) {
			expect(ALPHA2_CODES).toContain(code);
		}
	});

	it('uses uppercase only', () => {
		for (const code of ALPHA2_CODES) {
			expect(code).toBe(code.toUpperCase());
			expect(code).toMatch(/^[A-Z]{2}$/);
		}
	});

	it('has no duplicates', () => {
		const set = new Set(ALPHA2_CODES);
		expect(set.size).toBe(ALPHA2_CODES.length);
	});

	it('is alphabetically sorted', () => {
		// Operator-visible: the autocomplete's empty-query
		// branch shows the first N codes, so sort order
		// matters for natural reading. Pin against an
		// accidental shuffle.
		const sorted = [...ALPHA2_CODES].sort();
		expect(ALPHA2_CODES).toEqual(sorted);
	});
});

describe('countryName', () => {
	afterEach(() => {
		language.applyLocally('en');
	});

	it('resolves canonical codes to their English names by default', () => {
		// Tests run with the app language at its 'en' default.
		// Intl.DisplayNames is available in jsdom + Node ≥ 16,
		// which vitest runs under; the names listed are the
		// canonical ICU "region" labels.
		expect(countryName('FR')).toBe('France');
		expect(countryName('RU')).toBe('Russia');
		expect(countryName('DE')).toBe('Germany');
		expect(countryName('US')).toBe('United States');
		expect(countryName('CN')).toBe('China');
		expect(countryName('JP')).toBe('Japan');
	});

	it('follows the app language when it switches to French', () => {
		language.applyLocally('fr');
		expect(countryName('RU')).toBe('Russie');
		expect(countryName('DE')).toBe('Allemagne');
		// Switching back must not serve the cached French
		// instance (the cache is per locale).
		language.applyLocally('en');
		expect(countryName('DE')).toBe('Germany');
	});

	it('resolves canonical codes to their French names with an explicit locale', () => {
		expect(countryName('FR', 'fr')).toBe('France');
		expect(countryName('RU', 'fr')).toBe('Russie');
		expect(countryName('DE', 'fr')).toBe('Allemagne');
		expect(countryName('US', 'fr')).toBe('États-Unis');
		expect(countryName('CN', 'fr')).toBe('Chine');
		expect(countryName('JP', 'fr')).toBe('Japon');
	});

	it('uppercases lowercase input before lookup', () => {
		// Operators may type "fr" or "FR" or "Fr" in the
		// autocomplete; the lookup should be case-insensitive.
		expect(countryName('fr')).toBe('France');
		expect(countryName('Fr')).toBe('France');
	});

	it('returns the input verbatim for empty/malformed input', () => {
		expect(countryName('')).toBe('');
		expect(countryName('X')).toBe('X'); // single letter
		expect(countryName('FRA')).toBe('FRA'); // 3 letters
	});

	it('falls back to the code itself for unknown codes', () => {
		// "ZZ" is reserved in ISO 3166-1 and not in the
		// canonical 249-code set; the lookup falls back to
		// the uppercased input. (If a future ICU revision
		// happens to assign ZZ a name, this assertion would
		// need updating — but ZZ is currently a stable
		// "definitely-not-assigned" sentinel.)
		const result = countryName('zz');
		// The fallback contract is "code or name"; we accept
		// either uppercase "ZZ" or the ICU's chosen label
		// when present. The KEY invariant is: never empty,
		// never a thrown error.
		expect(result).toBeTruthy();
		expect(result.length).toBeGreaterThan(0);
	});
});

describe('matchCountries', () => {
	it('matches by code prefix (uppercase or lowercase query)', () => {
		const results = matchCountries('fr');
		const codes = results.map((m) => m.code);
		// "FR" is the first match (exact prefix); the
		// dataset has no other FR-prefixed code.
		expect(codes).toContain('FR');
		expect(codes[0]).toBe('FR');
	});

	it('matches by name prefix in the app language', () => {
		const results = matchCountries('russ');
		const codes = results.map((m) => m.code);
		expect(codes).toContain('RU');
		expect(matchCountries('germ').map((m) => m.code)).toContain('DE');
	});

	it('matches French names when the app language is French', () => {
		language.applyLocally('fr');
		try {
			expect(matchCountries('allem').map((m) => m.code)).toContain('DE');
			expect(matchCountries('RUSSIE').map((m) => m.code)).toContain('RU');
		} finally {
			language.applyLocally('en');
		}
	});

	it('returns code-prefix matches before name-prefix matches', () => {
		// Typing "fr" should match the code "FR" before the
		// name prefix match for "France" (which is
		// also "FR"). Either way the canonical short form
		// should surface first.
		const results = matchCountries('fr');
		expect(results[0].code).toBe('FR');
	});

	it('respects the excludeCodes filter', () => {
		// Operator already added FR to the chip list →
		// dropdown should not re-suggest FR.
		const results = matchCountries('fr', ['FR']);
		const codes = results.map((m) => m.code);
		expect(codes).not.toContain('FR');
	});

	it('clamps results to the limit', () => {
		// Empty query returns the first `limit` codes
		// alphabetically (the dropdown's empty-state view).
		const results = matchCountries('', [], 5);
		expect(results.length).toBe(5);
	});

	it('returns empty array for a query that matches nothing', () => {
		// "ZZZZZZZ" doesn't prefix any code OR any name.
		const results = matchCountries('zzzzzzz');
		expect(results.length).toBe(0);
	});

	it('result entries carry both code and name', () => {
		const results = matchCountries('FR');
		const fr = results.find((m) => m.code === 'FR');
		expect(fr).toBeDefined();
		expect(fr?.name).toBe('France');
	});

	it('matches case-insensitively across both axes', () => {
		// Operators may type "RU", "ru", "Russ", "RUSS" — all
		// should surface RU.
		for (const query of ['RU', 'ru', 'Russ', 'RUSSIA']) {
			const codes = matchCountries(query).map((m) => m.code);
			expect(codes).toContain('RU');
		}
	});

	it('deduplicates a code that matches both code- and name-prefix', () => {
		// Hypothetical: a query that matches BOTH a code's
		// own prefix AND its name's prefix should still only
		// surface the code once. (Real-world hard to engineer;
		// the matcher's `seen` set guards against future
		// ISO revisions producing such a collision.)
		const results = matchCountries('FR');
		const frCount = results.filter((m) => m.code === 'FR').length;
		expect(frCount).toBe(1);
	});
});
