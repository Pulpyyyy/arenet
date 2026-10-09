// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { bucketUnit } from './bucket-unit';

describe('bucketUnit', () => {
	it.each([
		[60, 'min'],
		[3600, 'h'],
		[300, '5 min'],
		[7200, '2 h'],
		[30, '30 s'],
		[90, '90 s']
	])('%i s → %s', (seconds, unit) => {
		expect(bucketUnit(seconds)).toBe(unit);
	});
});
