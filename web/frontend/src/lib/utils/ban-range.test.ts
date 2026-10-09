// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { classifyBanTarget } from './ban-range';

describe('classifyBanTarget — wide ranges', () => {
	it.each<[string, boolean]>([
		['10.0.0.0/16', true],
		['203.0.113.0/16', true],
		['0.0.0.0/0', true],
		['203.0.113.0/17', false],
		['203.0.113.0/24', false],
		['2001:db8::/48', true],
		['2001:db8::/32', true],
		['2001:db8::/49', false],
		['2001:db8::/64', false],
		['203.0.113.42', false],
		['2001:db8::1', false]
	])('%s → wide=%s', (raw, wide) => {
		expect(classifyBanTarget(raw).wide).toBe(wide);
	});

	it('gives a rough size for a wide range', () => {
		expect(classifyBanTarget('10.0.0.0/16').approxIPs).toBe('≈ 65.5 k');
		expect(classifyBanTarget('203.0.113.0/24').approxIPs).toBe('');
	});
});

describe('classifyBanTarget — private / loopback / link-local', () => {
	it.each<[string, string]>([
		['192.168.1.0/24', '192.168.0.0/16'],
		['10.20.0.0/16', '10.0.0.0/8'],
		['172.20.0.0/16', '172.16.0.0/12'],
		['100.100.0.0/16', '100.64.0.0/10'],
		['169.254.0.0/16', '169.254.0.0/16'],
		['127.0.0.1', '127.0.0.0/8'],
		['127.0.0.0/8', '127.0.0.0/8'],
		// A public range wide enough to swallow a private block.
		['0.0.0.0/0', '10.0.0.0/8'],
		['fd12:3456::/64', 'fc00::/7'],
		['fe80::/64', 'fe80::/10'],
		['::1', '::1/128']
	])('%s touches %s', (raw, block) => {
		expect(classifyBanTarget(raw).sensitiveBlock).toBe(block);
	});

	it.each<string>([
		// One LAN device: ordinary homelab work, not flagged.
		'192.168.1.50',
		'10.0.0.7',
		'fe80::1',
		'203.0.113.0/24',
		'198.51.100.7',
		'2001:db8::/48',
		'2001:db8::1'
	])('%s is not flagged', (raw) => {
		expect(classifyBanTarget(raw).sensitiveBlock).toBeNull();
	});
});

describe('classifyBanTarget — input it cannot parse', () => {
	it.each<string>([
		'',
		'not-an-ip',
		'10.0.0.0/33',
		'10.0.0.0/',
		'10.0.0/16',
		'1::2::3',
		'2001:db8::/129',
		'fe80::1%eth0'
	])('%s → no risk reported (the backend answers 400)', (raw) => {
		expect(classifyBanTarget(raw)).toEqual({ wide: false, approxIPs: '', sensitiveBlock: null });
	});

	it('trims surrounding spaces like the submit does', () => {
		expect(classifyBanTarget('  192.168.1.0/24  ').sensitiveBlock).toBe('192.168.0.0/16');
	});

	it('reads an embedded IPv4 tail', () => {
		expect(classifyBanTarget('::ffff:192.0.2.1').sensitiveBlock).toBeNull();
		expect(classifyBanTarget('::ffff:192.0.2.0/120').wide).toBe(false);
	});
});
