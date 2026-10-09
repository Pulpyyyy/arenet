// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 2 (2026-06-17) — parser for the Route.effectiveCertSource
// wire string.
//
// The backend (internal/api/handler.go:1407 computeEffectiveCert-
// Source) encodes the (kind, coveringApex) pair as a single
// string with a colon-prefix scheme that pre-dates this helper :
//
//   "managed-domain:<apex>"   — covered by a wildcard / apex MD
//   "per-route-acme:dns-01"   — dedicated dns-01 cert
//   "per-route-acme:http-01"  — dedicated http-01 cert
//   "per-route-internal"      — Caddy internal CA (private host)
//   ""                        — no inference (omitted on wire)
//
// Pre-Sujet-2 the routes table parsed the prefix inline (see
// src/routes/routes/+page.svelte:1623) and surfaced only a
// "wildcard" badge with the apex hidden in the title attribute.
// Operators with multiple managed domains couldn't tell at a
// glance WHICH wildcard covered a route, which is the gap
// Sujet 2 closes.
//
// The parser stays purely in TypeScript : the wire shape is
// stable and the colon-prefix scheme is unambiguous so a
// frontend parse is byte-equal to a (hypothetical) explicit
// coveringApex field, with the upside of not breaking the
// existing 7 Go tests pinning the string shape (see
// internal/api/managed_domain_test.go).

import { t } from '$lib/i18n';

/** Discriminated union — every variant of effectiveCertSource. */
export type ParsedCertSource =
	| { kind: 'managed-domain'; coveringApex: string }
	| { kind: 'per-route-acme'; challenge: 'dns-01' | 'http-01' }
	| { kind: 'per-route-internal' }
	// v2.19.0 external cert — the route is pinned to an operator-uploaded
	// cert. The wire string is the bare "per-route-manual"; certName is
	// resolved by the caller (route.cert_id → externalCerts list) and
	// injected, since the backend string carries no name. It holds the
	// cert's display name, or "*.<apex>" when the cert is a wildcard.
	| { kind: 'manual'; certName?: string }
	| { kind: 'none' };

/**
 * Parse the wire string into its structured shape.
 *
 *   parse(undefined) === { kind: 'none' }
 *   parse("")        === { kind: 'none' }
 *   parse("managed-domain:example.com")
 *     === { kind: 'managed-domain', coveringApex: 'example.com' }
 *   parse("managed-domain:")   // defensive — empty apex
 *     === { kind: 'none' }
 *   parse("per-route-acme:dns-01")
 *     === { kind: 'per-route-acme', challenge: 'dns-01' }
 *   parse("per-route-acme:http-01")
 *     === { kind: 'per-route-acme', challenge: 'http-01' }
 *   parse("per-route-internal")
 *     === { kind: 'per-route-internal' }
 *   parse("unknown:value")
 *     === { kind: 'none' }
 */
export function parseEffectiveCertSource(raw: string | undefined | null): ParsedCertSource {
	if (!raw) return { kind: 'none' };
	if (raw.startsWith('managed-domain:')) {
		const apex = raw.slice('managed-domain:'.length).trim();
		if (apex === '') return { kind: 'none' };
		return { kind: 'managed-domain', coveringApex: apex };
	}
	if (raw === 'per-route-acme:dns-01') {
		return { kind: 'per-route-acme', challenge: 'dns-01' };
	}
	if (raw === 'per-route-acme:http-01') {
		return { kind: 'per-route-acme', challenge: 'http-01' };
	}
	if (raw === 'per-route-internal') {
		return { kind: 'per-route-internal' };
	}
	if (raw === 'per-route-manual') {
		// certName is filled in by the caller after resolving cert_id.
		return { kind: 'manual' };
	}
	// Unknown shape — degrade gracefully. A future backend that
	// adds a fifth source would not crash the route list; the
	// dashboard would simply omit the badge until the frontend is
	// taught the new variant.
	return { kind: 'none' };
}

/**
 * Operator-facing label for a parsed cert source, in the active
 * language. Used by the CertSourceBadge component and any other
 * surface that needs the same wording (e.g. a future details
 * panel rewrite).
 *
 * Single source of truth for the copy so the routes list and
 * other surfaces stay aligned.
 */
export function certSourceLabel(parsed: ParsedCertSource): string {
	switch (parsed.kind) {
		case 'managed-domain':
			return t('certSource.labelManagedDomain', { apex: parsed.coveringApex });
		case 'per-route-acme':
			return parsed.challenge === 'dns-01'
				? t('certSource.labelDedicatedDns')
				: t('certSource.labelDedicatedHttp');
		case 'per-route-internal':
			return t('certSource.labelInternal');
		case 'manual':
			// certName is the cert display name, or "*.<apex>" for a
			// wildcard cert (resolved by the caller). Fall back to a
			// bare label when the cert_id could not be resolved.
			return parsed.certName
				? t('certSource.labelManualNamed', { name: parsed.certName })
				: t('certSource.labelManual');
		case 'none':
			return '';
	}
}

/**
 * Long-form tooltip explaining the cert source. Surfaces the
 * RFC 6125 single-label rule on managed-domain matches so the
 * operator can debug "why isn't my deep.sub.example.com
 * covered" without leaving the page.
 */
export function certSourceTooltip(parsed: ParsedCertSource): string {
	switch (parsed.kind) {
		case 'managed-domain':
			return t('certSource.tooltipManagedDomain', { apex: parsed.coveringApex });
		case 'per-route-acme':
			return parsed.challenge === 'dns-01'
				? t('certSource.tooltipDedicatedDns')
				: t('certSource.tooltipDedicatedHttp');
		case 'per-route-internal':
			return t('certSource.tooltipInternal');
		case 'manual':
			return parsed.certName
				? t('certSource.tooltipManualNamed', { name: parsed.certName })
				: t('certSource.tooltipManual');
		case 'none':
			return '';
	}
}
