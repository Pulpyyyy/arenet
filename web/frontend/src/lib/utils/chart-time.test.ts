// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Dates are built from local components so the labels do not depend
// on the time zone the suite runs in.

import { afterEach, describe, expect, it } from 'vitest';
import { language } from '$lib/stores/language.svelte';
import { chartClock, chartDay, chartDayTime } from './chart-time';

// 5 October 2026, 09:07 local: day and month differ, so the order shows.
const OCT_5 = new Date(2026, 9, 5, 9, 7);

describe('chart-time', () => {
	afterEach(() => {
		language.applyLocally('en');
	});

	it('puts the day first in French and the month first in English', () => {
		expect(chartDay(OCT_5, 'fr')).toBe('05/10');
		expect(chartDay(OCT_5, 'en')).toBe('10/05');
	});

	it('keeps a 24-hour clock in both languages', () => {
		const evening = new Date(2026, 9, 5, 21, 30);
		expect(chartClock(evening, 'en')).toBe('21:30');
		expect(chartClock(evening, 'fr')).toBe('21:30');
		expect(chartClock(new Date(2026, 9, 5, 0, 5), 'en')).toBe('00:05');
	});

	it('joins day and clock', () => {
		expect(chartDayTime(OCT_5, 'fr')).toBe('05/10 09:07');
	});

	it('follows the app language by default', () => {
		language.applyLocally('fr');
		expect(chartDay(OCT_5)).toBe('05/10');
		language.applyLocally('en');
		expect(chartDay(OCT_5)).toBe('10/05');
	});
});
