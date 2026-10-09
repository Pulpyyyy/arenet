// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { formatSourceIP, isFullIP, maskIP } from './ipClass';

describe('isFullIP', () => {
	it('accepts complete IPv4 and IPv6 addresses', () => {
		expect(isFullIP('82.65.1.2')).toBe(true);
		expect(isFullIP('2001:db8::1')).toBe(true);
		expect(isFullIP('::ffff:192.0.2.1')).toBe(true);
	});

	it('rejects the /logs placeholders and malformed values', () => {
		expect(isFullIP('')).toBe(false);
		expect(isFullIP('?')).toBe(false);
		expect(isFullIP('(interne)')).toBe(false);
		expect(isFullIP('82.65.1.x')).toBe(false);
		expect(isFullIP('300.1.1.1')).toBe(false);
	});
});

describe('maskIP', () => {
	it('masks the trailing octet of an IPv4 address', () => {
		expect(maskIP('82.65.1.2')).toBe('82.65.1.x');
		expect(maskIP('192.168.1.5')).toBe('192.168.1.x');
		expect(maskIP('10.0.0.1')).toBe('10.0.0.x');
	});

	it('masks IPv6 by keeping first 4 groups + ::x suffix', () => {
		expect(maskIP('2001:db8:85a3:8d3:1319:8a2e:370:7348')).toBe(
			'2001:db8:85a3:8d3::x'
		);
	});

	it('returns unknown shapes verbatim so regressions surface', () => {
		// A 1-group "address" doesn't match either branch ;
		// returning verbatim makes the regression visible at
		// the column.
		expect(maskIP('garbage')).toBe('garbage');
		expect(maskIP('')).toBe('');
	});
});

describe('formatSourceIP', () => {
	it('renders "ip · country" for a public IP with a resolved code', () => {
		expect(formatSourceIP('82.65.1.2', 'FR')).toBe('82.65.1.x · FR');
		expect(formatSourceIP('203.0.113.7', 'US')).toBe('203.0.113.x · US');
	});

	it('renders "ip · LAN" for RFC1918 sentinels', () => {
		expect(formatSourceIP('192.168.1.5', 'LAN')).toBe('192.168.1.x · LAN');
	});

	it('renders "ip · ?" when the backend answered with empty country', () => {
		// MMDB miss or degraded path — operator-honest "we
		// asked, we don't know" rather than silently dropping
		// the suffix.
		expect(formatSourceIP('203.0.113.99', '')).toBe('203.0.113.x · ?');
	});

	it('renders plain (no suffix) when country is undefined (not yet resolved)', () => {
		// Lookup hasn't returned yet — row appears immediately
		// without a flashing placeholder.
		expect(formatSourceIP('82.65.1.2')).toBe('82.65.1.x');
	});

	it('returns the em-dash sentinel for an empty IP', () => {
		expect(formatSourceIP('')).toBe('—');
		expect(formatSourceIP('', 'FR')).toBe('—');
	});
});
