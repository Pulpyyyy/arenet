// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 2 (2026-06-17) — parser + copy helper unit tests.
//
// The parser is the only piece between the backend's stable
// wire string and the badge's structured display. If it ever
// drifts (e.g. a future "managed-domain:" parse mis-extracts the
// apex), every multi-MD operator immediately sees the wrong apex
// on the wrong route. Tests pin every variant + the defensive
// fallbacks.

import { describe, it, expect } from 'vitest';
import {
	parseEffectiveCertSource,
	certSourceLabel,
	certSourceTooltip,
} from './effective-cert-source';
import { language } from '$lib/stores/language.svelte';

describe('parseEffectiveCertSource', () => {
	it('returns kind "none" for undefined / null / empty', () => {
		expect(parseEffectiveCertSource(undefined)).toEqual({ kind: 'none' });
		expect(parseEffectiveCertSource(null)).toEqual({ kind: 'none' });
		expect(parseEffectiveCertSource('')).toEqual({ kind: 'none' });
	});

	it('parses a single-MD wildcard apex', () => {
		expect(parseEffectiveCertSource('managed-domain:example.com')).toEqual({
			kind: 'managed-domain',
			coveringApex: 'example.com',
		});
	});

	it('parses a multi-label apex (nested MD)', () => {
		// Operator scenario : MD `staging.example.com`. The apex
		// itself contains dots — the parser must preserve them
		// verbatim, not split at the first dot.
		expect(parseEffectiveCertSource('managed-domain:staging.example.com')).toEqual({
			kind: 'managed-domain',
			coveringApex: 'staging.example.com',
		});
	});

	it('preserves the apex case as-emitted by the backend (no case-folding)', () => {
		// Backend normalises to lowercase at storage time, but a
		// future change might surface a different casing. The
		// parser stays neutral — case is the backend's
		// responsibility.
		expect(parseEffectiveCertSource('managed-domain:Example.COM')).toEqual({
			kind: 'managed-domain',
			coveringApex: 'Example.COM',
		});
	});

	it('parses per-route ACME variants (dns-01 / http-01)', () => {
		expect(parseEffectiveCertSource('per-route-acme:dns-01')).toEqual({
			kind: 'per-route-acme',
			challenge: 'dns-01',
		});
		expect(parseEffectiveCertSource('per-route-acme:http-01')).toEqual({
			kind: 'per-route-acme',
			challenge: 'http-01',
		});
	});

	it('parses per-route-internal', () => {
		expect(parseEffectiveCertSource('per-route-internal')).toEqual({
			kind: 'per-route-internal',
		});
	});

	it('parses per-route-manual (v2.19.0 external cert)', () => {
		// Regression: the backend emits "per-route-manual" for a route
		// pinned to an operator-uploaded external cert
		// (computeEffectiveCertSource, handler.go). Before this fix the
		// parser degraded it to "none" → empty badge → the TLS column
		// showed a bare "TLS". The certName is resolved by the caller
		// (route.cert_id → externalCerts) and injected here.
		expect(parseEffectiveCertSource('per-route-manual')).toEqual({
			kind: 'manual',
		});
	});

	it('degrades to kind "none" on unknown wire shape', () => {
		// Forward compat : a future backend adding a fifth source
		// must not crash the route list. The dashboard quietly
		// omits the badge until the frontend is taught the new
		// variant.
		expect(parseEffectiveCertSource('quantum-quic:dns-99')).toEqual({ kind: 'none' });
		expect(parseEffectiveCertSource('managed-domain')).toEqual({ kind: 'none' });
		// Defensive : "managed-domain:" with empty apex must not
		// emit a badge with apex "" (would render "Couvert par
		// *." — broken text).
		expect(parseEffectiveCertSource('managed-domain:')).toEqual({ kind: 'none' });
		expect(parseEffectiveCertSource('managed-domain:   ')).toEqual({ kind: 'none' });
	});
});

describe('certSourceLabel', () => {
	it('emits "Covered by *.<apex>" for managed-domain', () => {
		expect(
			certSourceLabel({ kind: 'managed-domain', coveringApex: 'example.com' })
		).toBe('Covered by *.example.com');
	});

	it('emits "Dedicated cert (DNS-01)" / "Dedicated cert (HTTP-01)" for per-route', () => {
		expect(certSourceLabel({ kind: 'per-route-acme', challenge: 'dns-01' })).toBe(
			'Dedicated cert (DNS-01)'
		);
		expect(certSourceLabel({ kind: 'per-route-acme', challenge: 'http-01' })).toBe(
			'Dedicated cert (HTTP-01)'
		);
	});

	it('emits "Internal cert" for per-route-internal', () => {
		expect(certSourceLabel({ kind: 'per-route-internal' })).toBe('Internal cert');
	});

	it('emits "Manual cert: <name>" for a named manual cert', () => {
		expect(certSourceLabel({ kind: 'manual', certName: 'SCCNF' })).toBe('Manual cert: SCCNF');
	});

	it('emits "Manual cert: *.<apex>" when the manual cert is a wildcard', () => {
		// The caller detects a wildcard SAN and passes "*.example.com"
		// as certName so a manual wildcard reads like the ACME wildcard.
		expect(certSourceLabel({ kind: 'manual', certName: '*.example.com' })).toBe(
			'Manual cert: *.example.com'
		);
	});

	it('emits a bare "Manual cert" when the cert name is unresolved', () => {
		// Defensive: an orphaned cert_id (cert deleted) still gets a
		// meaningful badge instead of falling back to the empty string.
		expect(certSourceLabel({ kind: 'manual' })).toBe('Manual cert');
		expect(certSourceLabel({ kind: 'manual', certName: '' })).toBe('Manual cert');
	});

	it('emits empty string for kind "none"', () => {
		expect(certSourceLabel({ kind: 'none' })).toBe('');
	});

	it('follows the active language', () => {
		language.current = 'fr';
		try {
			expect(
				certSourceLabel({ kind: 'managed-domain', coveringApex: 'example.com' })
			).toBe('Couvert par *.example.com');
			expect(certSourceLabel({ kind: 'manual', certName: 'SCCNF' })).toBe('Cert manuel : SCCNF');
		} finally {
			language.current = 'en';
		}
	});
});

describe('certSourceTooltip', () => {
	it('mentions the RFC 6125 rule for managed-domain', () => {
		const tt = certSourceTooltip({
			kind: 'managed-domain',
			coveringApex: 'example.com',
		});
		expect(tt).toContain('*.example.com');
		expect(tt).toContain('RFC 6125');
	});

	it('distinguishes dns-01 vs http-01 in per-route tooltip', () => {
		expect(certSourceTooltip({ kind: 'per-route-acme', challenge: 'dns-01' })).toContain(
			'DNS-01'
		);
		expect(certSourceTooltip({ kind: 'per-route-acme', challenge: 'http-01' })).toContain(
			'HTTP-01'
		);
	});

	it('mentions auto-signed for per-route-internal', () => {
		expect(certSourceTooltip({ kind: 'per-route-internal' })).toContain('self-signed');
	});

	it('mentions the uploaded external cert for manual', () => {
		const tt = certSourceTooltip({ kind: 'manual', certName: 'SCCNF' });
		expect(tt).toContain('SCCNF');
		expect(tt.toLowerCase()).toContain('manual');
	});

	it('gives a generic manual tooltip when the name is unresolved', () => {
		expect(certSourceTooltip({ kind: 'manual' }).toLowerCase()).toContain('manual');
	});

	it('emits empty string for kind "none"', () => {
		expect(certSourceTooltip({ kind: 'none' })).toBe('');
	});
});
