// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { DEFAULT_LANDING, isEntryPath, safeNext, withNext } from './safe-next';

describe('safeNext', () => {
	it('keeps a same-origin path, with its query and fragment', () => {
		expect(safeNext('/certs')).toBe('/certs');
		expect(safeNext('/observability/r-1?range=24h')).toBe('/observability/r-1?range=24h');
		expect(safeNext('/routes#r-2')).toBe('/routes#r-2');
	});

	it('falls back to the default landing when there is nothing', () => {
		expect(safeNext(null)).toBe(DEFAULT_LANDING);
		expect(safeNext(undefined)).toBe(DEFAULT_LANDING);
		expect(safeNext('')).toBe(DEFAULT_LANDING);
	});

	it('refuses anything that is not a path', () => {
		expect(safeNext('https://evil.example/')).toBe(DEFAULT_LANDING);
		expect(safeNext('javascript:alert(1)')).toBe(DEFAULT_LANDING);
		expect(safeNext('certs')).toBe(DEFAULT_LANDING);
	});

	it('refuses paths a browser reads as another host', () => {
		expect(safeNext('//evil.example')).toBe(DEFAULT_LANDING);
		expect(safeNext('///evil.example')).toBe(DEFAULT_LANDING);
		expect(safeNext('/\\evil.example')).toBe(DEFAULT_LANDING);
		expect(safeNext('/\t/evil.example')).toBe(DEFAULT_LANDING);
		expect(safeNext('/\n/evil.example')).toBe(DEFAULT_LANDING);
	});

	it('refuses the entry pages, which would loop', () => {
		expect(safeNext('/login')).toBe(DEFAULT_LANDING);
		expect(safeNext('/login/')).toBe(DEFAULT_LANDING);
		expect(safeNext('/login?next=/certs')).toBe(DEFAULT_LANDING);
		expect(safeNext('/setup')).toBe(DEFAULT_LANDING);
	});

	it('keeps an encoded slash, which stays on this origin', () => {
		expect(safeNext('/%2F%2Fevil.example')).toBe('/%2F%2Fevil.example');
	});
});

describe('isEntryPath', () => {
	it('is true for /login and /setup only', () => {
		expect(isEntryPath('/login')).toBe(true);
		expect(isEntryPath('/setup')).toBe(true);
		expect(isEntryPath('/setup/')).toBe(true);
		expect(isEntryPath('/routes')).toBe(false);
		expect(isEntryPath('/')).toBe(false);
		expect(isEntryPath('/loginx')).toBe(false);
	});
});

describe('withNext', () => {
	it('carries a usable target, encoded', () => {
		expect(withNext('/login', '/certs?tab=acme')).toBe('/login?next=%2Fcerts%3Ftab%3Dacme');
		expect(withNext('/setup', '/certs')).toBe('/setup?next=%2Fcerts');
	});

	it('leaves the parameter out when it would change nothing', () => {
		expect(withNext('/login', '/')).toBe('/login');
		expect(withNext('/login', DEFAULT_LANDING)).toBe('/login');
		expect(withNext('/login', null)).toBe('/login');
	});

	it('drops an unsafe target instead of passing it on', () => {
		expect(withNext('/setup', '//evil.example')).toBe('/setup');
		expect(withNext('/login', 'https://evil.example')).toBe('/login');
	});
});
