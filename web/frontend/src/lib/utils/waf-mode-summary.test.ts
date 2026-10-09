// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { countWafModes } from './waf-mode-summary';

describe('countWafModes', () => {
	it('counts proxying routes by their stored mode', () => {
		expect(
			countWafModes([
				{ wafMode: 'block' },
				{ wafMode: 'detect' },
				{ wafMode: 'detect' },
				{ wafMode: 'off' }
			])
		).toEqual({ block: 1, detect: 2, off: 1, skipped: 0 });
	});

	it('a route that proxies nothing is skipped, not counted under its stored mode', () => {
		// The WAF is not in the emitted chain for these, so a stored
		// 'block' must not show up as enforcement.
		expect(
			countWafModes([
				{ wafMode: 'block', disabled: true },
				{ wafMode: 'block', redirectConfig: { target: 'https://new.example.com' } },
				{ wafMode: 'detect', maintenanceConfig: { retryAfterSeconds: 300 } }
			])
		).toEqual({ block: 0, detect: 0, off: 0, skipped: 3 });
	});

	it('an unknown mode counts as off', () => {
		expect(countWafModes([{ wafMode: '' as never }])).toEqual({
			block: 0,
			detect: 0,
			off: 1,
			skipped: 0
		});
	});

	it('no routes, all zero', () => {
		expect(countWafModes([])).toEqual({ block: 0, detect: 0, off: 0, skipped: 0 });
	});
});
