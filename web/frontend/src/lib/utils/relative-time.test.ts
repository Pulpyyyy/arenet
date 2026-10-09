// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Expected strings come from Intl itself rather than literals, so a
// CLDR update to the short style ("5 min. ago" vs "5m ago") does not
// break the suite; the assertions pin the unit, the count, the
// direction and the language.

import { afterEach, describe, expect, it } from 'vitest';
import { language } from '$lib/stores/language.svelte';
import { recentTime, relativeTimeShort } from './relative-time';

const NOW = new Date('2026-10-05T12:00:00Z');

function at(offsetSec: number): string {
	return new Date(NOW.getTime() + offsetSec * 1000).toISOString();
}

function short(locale: string, value: number, unit: Intl.RelativeTimeFormatUnit): string {
	return new Intl.RelativeTimeFormat(locale, { style: 'short', numeric: 'always' }).format(value, unit);
}

describe('relativeTimeShort', () => {
	afterEach(() => {
		language.applyLocally('en');
	});

	it('picks the largest unit that fits and truncates the count', () => {
		expect(relativeTimeShort(at(-42), NOW, 'en')).toBe(short('en', -42, 'second'));
		expect(relativeTimeShort(at(-(5 * 60 + 59)), NOW, 'en')).toBe(short('en', -5, 'minute'));
		expect(relativeTimeShort(at(-(3600 - 1)), NOW, 'en')).toBe(short('en', -59, 'minute'));
		expect(relativeTimeShort(at(-3 * 3600), NOW, 'en')).toBe(short('en', -3, 'hour'));
		expect(relativeTimeShort(at(-2 * 86400), NOW, 'en')).toBe(short('en', -2, 'day'));
	});

	it('reads past as "ago" in English and "il y a" in French', () => {
		expect(relativeTimeShort(at(-300), NOW, 'en')).toContain('ago');
		const fr = relativeTimeShort(at(-300), NOW, 'fr');
		expect(fr).toBe(short('fr', -5, 'minute'));
		expect(fr).toContain('il y a');
		expect(fr).toContain('5');
	});

	it('reads future as "in" / "dans"', () => {
		expect(relativeTimeShort(at(2 * 3600 + 900), NOW, 'en')).toBe(short('en', 2, 'hour'));
		expect(relativeTimeShort(at(2 * 3600), NOW, 'fr')).toContain('dans');
	});

	it('puts "now" on the past side', () => {
		expect(relativeTimeShort(NOW.toISOString(), NOW, 'en')).toBe(short('en', -0, 'second'));
		expect(relativeTimeShort(NOW.toISOString(), NOW, 'en')).toContain('ago');
	});

	it('follows the app language by default', () => {
		language.applyLocally('fr');
		expect(relativeTimeShort(at(-300), NOW)).toBe(short('fr', -5, 'minute'));
		language.applyLocally('en');
		expect(relativeTimeShort(at(-300), NOW)).toBe(short('en', -5, 'minute'));
	});

	it('returns an unparseable timestamp unchanged', () => {
		expect(relativeTimeShort('not-a-date', NOW, 'en')).toBe('not-a-date');
	});
});

describe('recentTime', () => {
	it('is relative within the last hour', () => {
		expect(recentTime(at(-12), NOW, 'en')).toBe(short('en', -12, 'second'));
		expect(recentTime(at(-3 * 60), NOW, 'fr')).toBe(short('fr', -3, 'minute'));
	});

	it('switches to the local HH:MM clock after an hour', () => {
		const iso = at(-2 * 3600);
		const d = new Date(iso);
		const clock = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
		expect(recentTime(iso, NOW, 'en')).toBe(clock);
		expect(recentTime(iso, NOW, 'fr')).toBe(clock);
	});

	it('treats a timestamp slightly in the future as now', () => {
		expect(recentTime(at(30), NOW, 'en')).toBe(short('en', -0, 'second'));
	});
});
