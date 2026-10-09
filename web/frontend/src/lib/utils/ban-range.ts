// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Manual-ban target risk (BanIPModal).
//
// Two independent reasons to make the operator confirm a ban
// before it is sent:
//   - wide: an IPv4 range of /16 or wider, or an IPv6 range of
//     /48 or wider. A /48 is the usual allocation for a whole
//     site — the IPv6 counterpart of "a whole /16 network".
//   - sensitive: the target overlaps a private, loopback,
//     link-local or CGNAT block — the operator's LAN, a VPN
//     (Tailscale lives in 100.64.0.0/10) or Arenet's own host.
//     A single private IP is not flagged (banning one
//     misbehaving LAN device is ordinary homelab work); a
//     loopback IP is.
//
// These are UX guards only. The backend's own guard is the
// self-ban refusal (409 crowdsec_self_ban), which knows the
// operator's real client IP; this module does not.

/** What makes a ban target worth a second confirmation. */
export interface BanTargetRisk {
	/** Range of /16 or wider (IPv4) or /48 or wider (IPv6). */
	wide: boolean;
	/** Rough size of a wide range ("≈ 65.5 k"); '' otherwise. */
	approxIPs: string;
	/** The private / loopback / link-local block the target touches, or null. */
	sensitiveBlock: string | null;
}

/** Widest IPv4 prefix length that still counts as "wide". */
const V4_WIDE_MAX_PREFIX = 16;
/** Widest IPv6 prefix length that still counts as "wide". */
const V6_WIDE_MAX_PREFIX = 48;

interface Prefix {
	bytes: number[];
	bits: number;
	isRange: boolean;
	v6: boolean;
}

function parseIPv4(s: string): number[] | null {
	const parts = s.split('.');
	if (parts.length !== 4) return null;
	const out: number[] = [];
	for (const p of parts) {
		if (!/^\d{1,3}$/.test(p)) return null;
		const n = Number(p);
		if (n > 255) return null;
		out.push(n);
	}
	return out;
}

function parseHextets(s: string): number[] | null {
	if (s === '') return [];
	const out: number[] = [];
	for (const g of s.split(':')) {
		if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
		out.push(parseInt(g, 16));
	}
	return out;
}

function parseIPv6(raw: string): number[] | null {
	let s = raw;
	// Embedded IPv4 tail (::ffff:192.0.2.1) → two hextets.
	if (s.includes('.')) {
		const cut = s.lastIndexOf(':');
		const v4 = parseIPv4(s.slice(cut + 1));
		if (v4 === null) return null;
		s =
			s.slice(0, cut + 1) +
			((v4[0] << 8) | v4[1]).toString(16) +
			':' +
			((v4[2] << 8) | v4[3]).toString(16);
	}
	const halves = s.split('::');
	if (halves.length > 2) return null;
	const head = parseHextets(halves[0]);
	const tail = halves.length === 2 ? parseHextets(halves[1]) : [];
	if (head === null || tail === null) return null;
	let groups: number[];
	if (halves.length === 2) {
		const fill = 8 - head.length - tail.length;
		if (fill < 1) return null;
		groups = [...head, ...new Array<number>(fill).fill(0), ...tail];
	} else {
		if (head.length !== 8) return null;
		groups = head;
	}
	const bytes: number[] = [];
	for (const g of groups) bytes.push(g >> 8, g & 0xff);
	return bytes;
}

function parsePrefix(raw: string): Prefix | null {
	const s = raw.trim();
	const slash = s.indexOf('/');
	const addr = slash < 0 ? s : s.slice(0, slash);
	const v6 = addr.includes(':');
	const bytes = v6 ? parseIPv6(addr) : parseIPv4(addr);
	if (bytes === null) return null;
	const total = bytes.length * 8;
	if (slash < 0) return { bytes, bits: total, isRange: false, v6 };
	const maskStr = s.slice(slash + 1);
	if (!/^\d{1,3}$/.test(maskStr)) return null;
	const bits = Number(maskStr);
	if (bits > total) return null;
	return { bytes, bits, isRange: true, v6 };
}

/** True when a and b agree on their first `bits` bits. */
function samePrefix(a: number[], b: number[], bits: number): boolean {
	let left = bits;
	for (let i = 0; i < a.length && left > 0; i++, left -= 8) {
		const mask = left >= 8 ? 0xff : (0xff << (8 - left)) & 0xff;
		if ((a[i] & mask) !== (b[i] & mask)) return false;
	}
	return true;
}

interface SensitiveBlock {
	cidr: string;
	/** Flag a single address inside it too (loopback), not only ranges. */
	single: boolean;
	bytes: number[];
	bits: number;
}

function block(cidr: string, single: boolean): SensitiveBlock {
	const p = parsePrefix(cidr);
	if (p === null) throw new Error(`ban-range: bad built-in block ${cidr}`);
	return { cidr, single, bytes: p.bytes, bits: p.bits };
}

const SENSITIVE_V4: ReadonlyArray<SensitiveBlock> = [
	block('10.0.0.0/8', false),
	block('172.16.0.0/12', false),
	block('192.168.0.0/16', false),
	block('100.64.0.0/10', false),
	block('169.254.0.0/16', false),
	block('127.0.0.0/8', true)
];

const SENSITIVE_V6: ReadonlyArray<SensitiveBlock> = [
	block('fc00::/7', false),
	block('fe80::/10', false),
	block('::1/128', true)
];

function approxCount(hostBits: number): string {
	// 2^hostBits fits easily in a Number for IPv4; IPv6 uses the
	// exponent form, friendlier than the raw integer.
	const count = Math.pow(2, hostBits);
	if (count >= 1e9) return `≈ 10^${Math.round(Math.log10(count))}`;
	if (count >= 1e6) return `≈ ${(count / 1e6).toFixed(1)} M`;
	if (count >= 1e3) return `≈ ${(count / 1e3).toFixed(1)} k`;
	return String(count);
}

/**
 * Classify a ban target as typed by the operator (IP or CIDR).
 * Anything that does not parse is reported as risk-free: syntax
 * errors are the backend's to report (400).
 */
export function classifyBanTarget(raw: string): BanTargetRisk {
	const p = parsePrefix(raw);
	if (p === null) return { wide: false, approxIPs: '', sensitiveBlock: null };

	const wide = p.isRange && p.bits <= (p.v6 ? V6_WIDE_MAX_PREFIX : V4_WIDE_MAX_PREFIX);
	const approxIPs = wide ? approxCount(p.bytes.length * 8 - p.bits) : '';

	let sensitiveBlock: string | null = null;
	for (const b of p.v6 ? SENSITIVE_V6 : SENSITIVE_V4) {
		if (!p.isRange && !b.single) continue;
		// Two prefixes overlap iff they agree on the shorter one.
		if (samePrefix(p.bytes, b.bytes, Math.min(p.bits, b.bits))) {
			sensitiveBlock = b.cidr;
			break;
		}
	}
	return { wide, approxIPs, sensitiveBlock };
}
