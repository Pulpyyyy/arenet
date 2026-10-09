// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { absoluteDate } from './date-format';

// Noon UTC keeps the calendar day the same in every runner timezone.
const ISO = '2026-09-03T12:00:00Z';

describe('absoluteDate', () => {
	it('formats in the requested locale', () => {
		expect(absoluteDate(ISO, false, 'en')).toBe(
			new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(new Date(ISO))
		);
		expect(absoluteDate(ISO, false, 'fr')).toBe(
			new Intl.DateTimeFormat('fr', { dateStyle: 'medium' }).format(new Date(ISO))
		);
		expect(absoluteDate(ISO, false, 'en')).toMatch(/2026/);
	});

	it('defaults to the in-app language (en at test boot)', () => {
		expect(absoluteDate(ISO)).toBe(absoluteDate(ISO, false, 'en'));
	});

	it('adds the time when asked', () => {
		expect(absoluteDate(ISO, true, 'en')).toBe(
			new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(
				new Date(ISO)
			)
		);
	});

	it('returns an empty string for an unparseable timestamp', () => {
		expect(absoluteDate('not a date')).toBe('');
	});
});
