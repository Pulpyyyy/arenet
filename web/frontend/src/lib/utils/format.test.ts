// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { afterEach, describe, expect, it } from 'vitest';
import { language } from '$lib/stores/language.svelte';
import { formatBytes, formatTime } from './format';

// Intl separates number and unit with a regular, no-break or narrow
// no-break space depending on locale and ICU version; `\s` matches
// all three, so the assertions pin the digits and labels only.

describe('formatBytes', () => {
	afterEach(() => {
		language.applyLocally('en');
	});

	it('uses decimal units in English', () => {
		expect(formatBytes(2_899_675, 'en')).toMatch(/^2\.9\sMB$/);
		expect(formatBytes(12_400_000, 'en')).toMatch(/^12\sMB$/);
		expect(formatBytes(2048, 'en')).toMatch(/^2\skB$/);
		expect(formatBytes(1_800_000_000, 'en')).toMatch(/^1\.8\sGB$/);
		expect(formatBytes(3_500_000_000_000, 'en')).toMatch(/^3\.5\sTB$/);
	});

	it('uses a decimal comma and French unit labels in French', () => {
		expect(formatBytes(2_899_675, 'fr')).toMatch(/^2,9\sMo$/);
		expect(formatBytes(12_400_000, 'fr')).toMatch(/^12\sMo$/);
		expect(formatBytes(1500, 'fr')).toMatch(/^1,5\sko$/);
		expect(formatBytes(1_800_000_000, 'fr')).toMatch(/^1,8\sGo$/);
	});

	it('names plain bytes in full, pluralised by the language', () => {
		expect(formatBytes(512, 'en')).toMatch(/^512\sbytes$/);
		expect(formatBytes(1, 'en')).toMatch(/^1\sbyte$/);
		expect(formatBytes(512, 'fr')).toMatch(/^512\soctets$/);
	});

	it('steps up a unit at 1000, not 1024', () => {
		expect(formatBytes(999, 'en')).toMatch(/^999\sbytes$/);
		expect(formatBytes(1000, 'en')).toMatch(/^1\skB$/);
		expect(formatBytes(1_000_000, 'en')).toMatch(/^1\sMB$/);
	});

	it('follows the app language when no locale is passed', () => {
		expect(formatBytes(1500)).toMatch(/^1\.5\skB$/);
		language.applyLocally('fr');
		expect(formatBytes(1500)).toMatch(/^1,5\sko$/);
	});
});

describe('formatTime', () => {
	afterEach(() => {
		language.applyLocally('en');
	});

	it('renders a zero-padded 24-hour clock in both languages', () => {
		const morning = new Date(2026, 0, 1, 9, 5);
		const evening = new Date(2026, 0, 1, 23, 59);
		const midnight = new Date(2026, 0, 1, 0, 0);
		expect(formatTime(morning, 'en')).toBe('09:05');
		expect(formatTime(evening, 'en')).toBe('23:59');
		expect(formatTime(midnight, 'en')).toBe('00:00');
		expect(formatTime(morning, 'fr')).toBe('09:05');
		expect(formatTime(evening, 'fr')).toBe('23:59');
	});

	it('follows the app language when no locale is passed', () => {
		const d = new Date(2026, 0, 1, 14, 30);
		expect(formatTime(d)).toBe('14:30');
		language.applyLocally('fr');
		expect(formatTime(d)).toBe('14:30');
	});
});
