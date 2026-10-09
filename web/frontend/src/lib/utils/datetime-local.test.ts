// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { localInputToIso } from './datetime-local';

describe('localInputToIso', () => {
	it('returns an empty string for an empty input (no filter)', () => {
		expect(localInputToIso('')).toBe('');
		expect(localInputToIso('   ')).toBe('');
	});

	it('reads the value as local time and returns UTC ISO', () => {
		// Expected value built the same way, so the test holds in any
		// time zone the suite runs in.
		const expected = new Date(2026, 4, 1, 14, 30).toISOString();
		expect(localInputToIso('2026-05-01T14:30')).toBe(expected);
	});

	it('accepts seconds and milliseconds', () => {
		expect(localInputToIso('2026-05-01T14:30:15')).toBe(new Date(2026, 4, 1, 14, 30, 15).toISOString());
		expect(localInputToIso('2026-05-01T14:30:15.250')).toBe(
			new Date(2026, 4, 1, 14, 30, 15, 250).toISOString()
		);
	});

	it('rejects incomplete or malformed values', () => {
		for (const v of ['2026', '2026-05-0', '2026-05-01', '2026-05-01T1', '2026-05-01T14:3', 'yesterday']) {
			expect(localInputToIso(v), v).toBeNull();
		}
	});

	it('rejects a well-shaped value that is not a real date', () => {
		expect(localInputToIso('2026-13-01T00:00')).toBeNull();
	});
});
