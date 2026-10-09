// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { invalidSections, sectionForErrorKey } from './route-form-errors';

describe('sectionForErrorKey', () => {
	it.each([
		['host', 'essentials'],
		['lbPolicy', 'essentials'],
		['upstreams', 'essentials'],
		['upstreams[2].url', 'essentials'],
		['upstreams[0].weight', 'essentials'],
		['healthCheck.uri', 'healthCheck'],
		['healthCheck.expectBody', 'healthCheck'],
		['pathRules.3', 'pathsHeaders'],
		['wafExcludeRules', 'waf'],
		['wafExcludeTags', 'waf']
	])('%s lives in %s', (key, section) => {
		expect(sectionForErrorKey(key)).toBe(section);
	});

	it('an unknown key has no section', () => {
		expect(sectionForErrorKey('somethingElse')).toBeNull();
	});
});

describe('invalidSections', () => {
	it('collects each section once, ignoring empty messages', () => {
		const got = invalidSections({
			'healthCheck.uri': 'URI is required',
			'healthCheck.timeout': 'Timeout must be less than interval',
			'pathRules.0': 'rule /api has nothing in it',
			host: '',
			unknown: 'no section'
		});
		expect([...got].sort()).toEqual(['healthCheck', 'pathsHeaders']);
	});

	it('no errors, no sections', () => {
		expect(invalidSections({}).size).toBe(0);
	});
});
