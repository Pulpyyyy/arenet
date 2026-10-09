// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unit tests for the Step T T.4 certificate-format helpers. The
// status → badge variant mapping is the AC #10 LOCKED contract;
// the labels are part of the spec vocabulary. Both pinned here.

import { describe, it, expect, afterEach } from 'vitest';
import type { Certificate } from '$lib/api/types';
import { language } from '$lib/stores/language.svelte';
import {
	certificateSourceLabel,
	certificateStatusLabel,
	certificateStatusToBadgeVariant,
	countByEffectiveSource,
	daysUntilExpiry,
	dominantIssuer,
	inferChallengeLabel,
	isExpired,
	isExpiringSoon,
	isZeroTimestamp,
	RENEWAL_WINDOW_DAYS,
	resolveSource,
} from './certificate-format';

const NOW = new Date('2026-06-05T12:00:00Z');

function mkCert(overrides: Partial<Certificate>): Certificate {
	return {
		domain: 'x.example.com',
		sanList: ['x.example.com'],
		issuer: "Let's Encrypt",
		notBefore: new Date(NOW.getTime() - 30 * 86400000).toISOString(),
		notAfter: new Date(NOW.getTime() + 60 * 86400000).toISOString(),
		status: 'VALID',
		source: 'specific',
		...overrides,
	};
}

describe('certificateStatusToBadgeVariant', () => {
	it('maps VALID to status-up', () => {
		expect(certificateStatusToBadgeVariant('VALID')).toBe('status-up');
	});
	it('maps RENEWAL_PENDING to status-warn', () => {
		expect(certificateStatusToBadgeVariant('RENEWAL_PENDING')).toBe('status-warn');
	});
	it('maps EXPIRED to status-down', () => {
		expect(certificateStatusToBadgeVariant('EXPIRED')).toBe('status-down');
	});
	it('maps OBTAIN_FAILED to status-down', () => {
		expect(certificateStatusToBadgeVariant('OBTAIN_FAILED')).toBe('status-down');
	});
	it('maps UNKNOWN to neutral', () => {
		expect(certificateStatusToBadgeVariant('UNKNOWN')).toBe('neutral');
	});
});

// The labels follow the active language: the English UI used to
// show the French badges because they were hardcoded here.
describe('certificateStatusLabel', () => {
	afterEach(() => {
		language.current = 'en';
	});

	it('maps each status to the English label by default', () => {
		language.current = 'en';
		expect(certificateStatusLabel('VALID')).toBe('VALID');
		expect(certificateStatusLabel('RENEWAL_PENDING')).toBe('RENEWING');
		expect(certificateStatusLabel('EXPIRED')).toBe('EXPIRED');
		expect(certificateStatusLabel('OBTAIN_FAILED')).toBe('FAILED');
		expect(certificateStatusLabel('UNKNOWN')).toBe('—');
	});

	it('keeps the spec French vocabulary when French is chosen', () => {
		language.current = 'fr';
		expect(certificateStatusLabel('VALID')).toBe('VALIDE');
		expect(certificateStatusLabel('RENEWAL_PENDING')).toBe('RENOUV. AUTO');
		expect(certificateStatusLabel('EXPIRED')).toBe('EXPIRÉ');
		expect(certificateStatusLabel('OBTAIN_FAILED')).toBe('ÉCHEC');
		expect(certificateStatusLabel('UNKNOWN')).toBe('—');
	});
});

describe('certificateSourceLabel', () => {
	afterEach(() => {
		language.current = 'en';
	});

	it('maps each source to its label in English', () => {
		language.current = 'en';
		expect(certificateSourceLabel('wildcard')).toBe('wildcard');
		expect(certificateSourceLabel('apex')).toBe('apex');
		expect(certificateSourceLabel('specific')).toBe('specific');
	});

	it('translates "specific" in French', () => {
		language.current = 'fr';
		expect(certificateSourceLabel('specific')).toBe('spécifique');
	});
});

describe('inferChallengeLabel', () => {
	it('returns DNS-01 for wildcards (the only path certmagic uses)', () => {
		expect(inferChallengeLabel('wildcard')).toBe('DNS-01');
	});
	it('returns HTTP-01 for specific and apex (the default)', () => {
		expect(inferChallengeLabel('specific')).toBe('HTTP-01');
		expect(inferChallengeLabel('apex')).toBe('HTTP-01');
	});
	it('returns — for OBTAIN_FAILED non-wildcards (no successful obtain to learn from)', () => {
		expect(inferChallengeLabel('specific', 'OBTAIN_FAILED')).toBe('—');
		expect(inferChallengeLabel('apex', 'OBTAIN_FAILED')).toBe('—');
	});
	it('still returns DNS-01 for OBTAIN_FAILED wildcards (only path certmagic can use)', () => {
		expect(inferChallengeLabel('wildcard', 'OBTAIN_FAILED')).toBe('DNS-01');
	});
});

describe('resolveSource', () => {
	it('passes through explicit sources verbatim', () => {
		expect(resolveSource(mkCert({ source: 'wildcard' }))).toBe('wildcard');
		expect(resolveSource(mkCert({ source: 'apex' }))).toBe('apex');
		expect(resolveSource(mkCert({ source: 'specific' }))).toBe('specific');
	});
	it('derives wildcard from a *.x domain when source is empty', () => {
		const c = mkCert({
			domain: '*.test.local',
			source: '' as unknown as Certificate['source'],
		});
		expect(resolveSource(c)).toBe('wildcard');
	});
	it('defaults to specific when source is empty and domain is not *.x', () => {
		const c = mkCert({
			domain: 'api.example.com',
			source: '' as unknown as Certificate['source'],
		});
		expect(resolveSource(c)).toBe('specific');
	});
});

describe('countByEffectiveSource', () => {
	it('breakdown sums to the total (no entries lost to empty-source filtering)', () => {
		const certs: Certificate[] = [
			mkCert({ domain: 'a.example.com', source: 'specific' }),
			mkCert({ domain: '*.b.example.com', source: 'wildcard' }),
			// OBTAIN_FAILED-shaped entries — empty source, wildcard
			// domain string. Pre-polish these fell out of both
			// wildcard and specific filters.
			mkCert({
				domain: '*.test.local',
				source: '' as unknown as Certificate['source'],
				status: 'OBTAIN_FAILED',
			}),
			mkCert({
				domain: 'broken.example.com',
				source: '' as unknown as Certificate['source'],
				status: 'OBTAIN_FAILED',
			}),
		];
		const { wildcard, specific } = countByEffectiveSource(certs);
		expect(wildcard).toBe(2);
		expect(specific).toBe(2);
		expect(wildcard + specific).toBe(certs.length);
	});
	it('returns zeros for an empty list', () => {
		expect(countByEffectiveSource([])).toEqual({ wildcard: 0, specific: 0 });
	});
});

describe('isZeroTimestamp', () => {
	it('detects Go zero time (0001-01-01T00:00:00Z)', () => {
		expect(isZeroTimestamp('0001-01-01T00:00:00Z')).toBe(true);
	});
	it('detects empty / null / undefined / malformed input', () => {
		expect(isZeroTimestamp('')).toBe(true);
		expect(isZeroTimestamp(null)).toBe(true);
		expect(isZeroTimestamp(undefined)).toBe(true);
		expect(isZeroTimestamp('not-a-date')).toBe(true);
	});
	it('returns false for real timestamps', () => {
		expect(isZeroTimestamp('2026-06-05T12:00:00Z')).toBe(false);
		expect(isZeroTimestamp('2020-01-01T00:00:00Z')).toBe(false);
	});
});

describe('daysUntilExpiry', () => {
	it('returns positive whole days for future expiries', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + 10 * 86400000).toISOString(),
		});
		expect(daysUntilExpiry(c, NOW)).toBe(10);
	});
	it('returns negative whole days for past expiries', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() - 5 * 86400000).toISOString(),
		});
		expect(daysUntilExpiry(c, NOW)).toBe(-5);
	});
	it('returns null when notAfter is malformed', () => {
		const c = mkCert({ notAfter: 'not-a-date' });
		expect(daysUntilExpiry(c, NOW)).toBeNull();
	});
	it('returns null when notAfter is Go zero-time (never obtained)', () => {
		const c = mkCert({ notAfter: '0001-01-01T00:00:00Z' });
		expect(daysUntilExpiry(c, NOW)).toBeNull();
	});
});

describe('isExpiringSoon', () => {
	it('flags certs inside the renewal window', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + 15 * 86400000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(true);
	});
	it('does NOT flag certs beyond the renewal window', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + (RENEWAL_WINDOW_DAYS + 5) * 86400000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(false);
	});
	it('does NOT flag already-expired certs (negative days)', () => {
		const c = mkCert({
			status: 'EXPIRED',
			notAfter: new Date(NOW.getTime() - 3 * 86400000).toISOString(),
		});
		expect(daysUntilExpiry(c, NOW)).toBe(-3);
		expect(isExpiringSoon(c, NOW)).toBe(false);
	});
	it('does NOT flag a cert that expired less than a day ago (days rounds to 0)', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() - 3600000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(false);
	});
	it('flags a cert that expires later today (days === 0, not yet expired)', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + 3600000).toISOString(),
		});
		expect(daysUntilExpiry(c, NOW)).toBe(0);
		expect(isExpiringSoon(c, NOW)).toBe(true);
	});
	it('flags a cert exactly at the edge of the renewal window', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + RENEWAL_WINDOW_DAYS * 86400000).toISOString(),
		});
		expect(isExpiringSoon(c, NOW)).toBe(true);
	});
	it('does NOT flag OBTAIN_FAILED entries (no obtained cert to renew)', () => {
		const c = mkCert({
			status: 'OBTAIN_FAILED',
			notAfter: '0001-01-01T00:00:00Z',
		});
		expect(isExpiringSoon(c, NOW)).toBe(false);
	});
	it('does NOT flag zero-time entries even when status is not OBTAIN_FAILED', () => {
		const c = mkCert({
			status: 'UNKNOWN',
			notAfter: '0001-01-01T00:00:00Z',
		});
		expect(isExpiringSoon(c, NOW)).toBe(false);
	});
});

describe('isExpired', () => {
	it('is true once notAfter has passed', () => {
		const c = mkCert({
			status: 'EXPIRED',
			notAfter: new Date(NOW.getTime() - 3 * 86400000).toISOString(),
		});
		expect(isExpired(c, NOW)).toBe(true);
	});
	it('is true less than a day after notAfter (days rounds to 0)', () => {
		const c = mkCert({
			notAfter: new Date(NOW.getTime() - 3600000).toISOString(),
		});
		expect(isExpired(c, NOW)).toBe(true);
	});
	it('is true at notAfter itself (backend: !now.Before(NotAfter))', () => {
		const c = mkCert({ notAfter: NOW.toISOString() });
		expect(isExpired(c, NOW)).toBe(true);
	});
	it('is false for a cert still valid, even inside the renewal window', () => {
		expect(isExpired(mkCert({}), NOW)).toBe(false);
		const c = mkCert({
			notAfter: new Date(NOW.getTime() + 3600000).toISOString(),
		});
		expect(isExpired(c, NOW)).toBe(false);
	});
	it('is false for zero-time or malformed notAfter (never obtained)', () => {
		expect(
			isExpired(mkCert({ status: 'OBTAIN_FAILED', notAfter: '0001-01-01T00:00:00Z' }), NOW)
		).toBe(false);
		expect(isExpired(mkCert({ notAfter: 'not-a-date' }), NOW)).toBe(false);
	});
});

describe('dominantIssuer', () => {
	it('returns the most common issuer string', () => {
		const certs: Certificate[] = [
			mkCert({ issuer: "Let's Encrypt" }),
			mkCert({ issuer: "Let's Encrypt" }),
			mkCert({ issuer: 'ZeroSSL' }),
		];
		expect(dominantIssuer(certs)).toBe("Let's Encrypt");
	});
	it('returns — for an empty list', () => {
		expect(dominantIssuer([])).toBe('—');
	});
	it('ties break alphabetically (deterministic)', () => {
		const certs: Certificate[] = [
			mkCert({ issuer: 'B-CA' }),
			mkCert({ issuer: 'A-CA' }),
		];
		expect(dominantIssuer(certs)).toBe('A-CA');
	});
});
