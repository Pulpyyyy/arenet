// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

import { describe, it, expect } from 'vitest';
import {
	DURATION_UNIT_FACTORS,
	formatCountdown,
	secondsToParts,
	partsToSeconds
} from './duration';

describe('secondsToParts', () => {
	it('picks the largest whole unit that divides evenly', () => {
		expect(secondsToParts(300)).toEqual({ value: 5, unit: 'minutes' });
		expect(secondsToParts(3600)).toEqual({ value: 1, unit: 'hours' });
		expect(secondsToParts(86400)).toEqual({ value: 1, unit: 'days' });
		expect(secondsToParts(172800)).toEqual({ value: 2, unit: 'days' });
	});

	it('falls back to seconds when no larger unit divides evenly', () => {
		expect(secondsToParts(90)).toEqual({ value: 90, unit: 'seconds' });
		expect(secondsToParts(45)).toEqual({ value: 45, unit: 'seconds' });
		// 90000 = 25h exactly (not a whole day) → hours, not days
		expect(secondsToParts(90000)).toEqual({ value: 25, unit: 'hours' });
	});

	it('handles zero as zero seconds', () => {
		expect(secondsToParts(0)).toEqual({ value: 0, unit: 'seconds' });
	});

	it('clamps negatives to zero seconds', () => {
		expect(secondsToParts(-5)).toEqual({ value: 0, unit: 'seconds' });
	});
});

describe('partsToSeconds', () => {
	it('multiplies value by the unit factor', () => {
		expect(partsToSeconds(5, 'minutes')).toBe(300);
		expect(partsToSeconds(1, 'hours')).toBe(3600);
		expect(partsToSeconds(2, 'days')).toBe(172800);
		expect(partsToSeconds(90, 'seconds')).toBe(90);
	});

	it('clamps NaN / negative to zero', () => {
		expect(partsToSeconds(Number.NaN, 'minutes')).toBe(0);
		expect(partsToSeconds(-3, 'hours')).toBe(0);
	});

	it('round-trips through secondsToParts for round values', () => {
		for (const s of [0, 30, 60, 300, 3600, 7200, 86400]) {
			const { value, unit } = secondsToParts(s);
			expect(partsToSeconds(value, unit)).toBe(s);
		}
	});
});

describe('DURATION_UNIT_FACTORS', () => {
	it('exposes the canonical seconds-per-unit map', () => {
		expect(DURATION_UNIT_FACTORS).toEqual({
			seconds: 1,
			minutes: 60,
			hours: 3600,
			days: 86400
		});
	});
});

describe('formatCountdown', () => {
	it('renders minutes and zero-padded seconds', () => {
		expect(formatCountdown(900)).toBe('15:00');
		expect(formatCountdown(3600)).toBe('60:00');
		expect(formatCountdown(61)).toBe('1:01');
		expect(formatCountdown(45)).toBe('0:45');
	});

	it('rounds a fraction up and clamps nonsense to 0:00', () => {
		expect(formatCountdown(0.2)).toBe('0:01');
		expect(formatCountdown(0)).toBe('0:00');
		expect(formatCountdown(-5)).toBe('0:00');
		expect(formatCountdown(Number.NaN)).toBe('0:00');
	});
});
