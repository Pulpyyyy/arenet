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
import { humanToNs, nsToHuman } from './rule-duration';

const S = 1e9;

describe('humanToNs', () => {
	it('reads every documented unit', () => {
		expect(humanToNs('30s')).toBe(30 * S);
		expect(humanToNs('5m')).toBe(300 * S);
		expect(humanToNs('2h')).toBe(7200 * S);
		expect(humanToNs('1d')).toBe(86400 * S);
	});

	it('takes a bare number as seconds', () => {
		expect(humanToNs('90')).toBe(90 * S);
		expect(humanToNs('0')).toBe(0);
	});

	it('accepts "min", spaces and surrounding blanks', () => {
		expect(humanToNs('5min')).toBe(300 * S);
		expect(humanToNs(' 5 min ')).toBe(300 * S);
		expect(humanToNs('4 h')).toBe(4 * 3600 * S);
	});

	// These all used to come back as 0 and be saved as 0.
	it('refuses what it cannot read, rather than returning 0', () => {
		for (const bad of ['', '   ', 'abc', '1.5h', '-5m', '5 minutes', '5M', '1w', 'h', '5m30s']) {
			expect(humanToNs(bad), bad).toBeNull();
		}
	});

	it('refuses a value the backend cannot hold (int64 nanoseconds)', () => {
		expect(humanToNs('106751d')).toBe(106751 * 86400 * S);
		expect(humanToNs('106752d')).toBeNull();
		expect(humanToNs('9'.repeat(400))).toBeNull();
	});
});

describe('nsToHuman', () => {
	it('shows the largest whole unit', () => {
		expect(nsToHuman(60 * S)).toBe('1m');
		expect(nsToHuman(4 * 3600 * S)).toBe('4h');
		expect(nsToHuman(7 * 86400 * S)).toBe('7d');
		expect(nsToHuman(90 * S)).toBe('90s');
	});

	it('shows zero, negatives and garbage as 0s', () => {
		expect(nsToHuman(0)).toBe('0s');
		expect(nsToHuman(-5)).toBe('0s');
		expect(nsToHuman(Number.NaN)).toBe('0s');
	});

	it('round-trips through humanToNs', () => {
		for (const text of ['45s', '15m', '4h', '7d']) {
			expect(nsToHuman(humanToNs(text)!)).toBe(text);
		}
	});
});
