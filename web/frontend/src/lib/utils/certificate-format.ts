// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step T T.4 — helpers for rendering Certificate runtime metadata
// in the /certs Domaines table. The Badge variant mapping is the
// AC #10 LOCKED contract (spec §1.4 + AC #10); the renewal-window
// constant matches the backend's RenewalMargin in
// internal/certinfo/tracker.go (30 days).
//
// Satisfies AC #2 (status enum surface) + AC #10 (badge palette
// LOCKED) — Step T spec v1.2.0-step-t-spec.
// Implemented by e8e6311 (T.4); resolveSource + zero-time guards
// added by c6013f2 (polish HF2).

import type { Certificate, CertificateStatus, CertificateSource } from '$lib/api/types';
import { t } from '$lib/i18n';

/**
 * Days before notAfter at which the frontend treats a cert as
 * "Expirent bientôt" for the tab filter AND switches the EXPIRE
 * DANS column to the amber warning tone. Mirrors
 * certinfo.RenewalMargin (30 * 24h) on the backend; kept as a
 * named constant so the future change-window-policy step touches
 * one place per side.
 */
export const RENEWAL_WINDOW_DAYS = 30;

/**
 * Badge variant the AC #10 status → color table maps to. The
 * Badge component (web/frontend/src/lib/components/Badge.svelte)
 * has no dedicated cert variants — we reuse the existing
 * status-up / status-warn / status-down / neutral palette so the
 * Routes-page C11 badge precedent stays consistent.
 */
export type CertificateBadgeVariant =
	| 'status-up' // VALID
	| 'status-warn' // RENEWAL_PENDING
	| 'status-down' // EXPIRED, OBTAIN_FAILED
	| 'neutral'; // UNKNOWN

/**
 * Maps a CertificateStatus to the Badge variant the Domaines
 * table renders. Pure function — no I/O, no clock reads — so
 * the unit test doesn't need date stubbing.
 *
 * The mapping is the spec §1.4 + AC #10 locked vocabulary:
 *   VALID            → green   (status-up)
 *   RENEWAL_PENDING  → amber   (status-warn)
 *   EXPIRED          → red     (status-down)
 *   OBTAIN_FAILED    → red     (status-down)
 *   UNKNOWN          → grey    (neutral)
 */
export function certificateStatusToBadgeVariant(
	status: CertificateStatus
): CertificateBadgeVariant {
	switch (status) {
		case 'VALID':
			return 'status-up';
		case 'RENEWAL_PENDING':
			return 'status-warn';
		case 'EXPIRED':
		case 'OBTAIN_FAILED':
			return 'status-down';
		case 'UNKNOWN':
		default:
			return 'neutral';
	}
}

/**
 * Operator-facing label for the status badge, in the active
 * language. The French copy keeps the spec's "VALIDE / RENOUV.
 * AUTO / EXPIRÉ / ÉCHEC / —" vocabulary (AC #10).
 *
 * t() reads language.current, so a template calling this re-renders
 * on a language switch without any extra dependency trigger.
 */
export function certificateStatusLabel(status: CertificateStatus): string {
	switch (status) {
		case 'VALID':
			return t('certs.statusValid');
		case 'RENEWAL_PENDING':
			return t('certs.statusRenewalPending');
		case 'EXPIRED':
			return t('certs.statusExpired');
		case 'OBTAIN_FAILED':
			return t('certs.statusFailed');
		case 'UNKNOWN':
		default:
			return '—';
	}
}

/**
 * Operator-facing label for the source classifier (rendered under
 * the domain column). "wildcard" and "apex" read the same in both
 * languages; only "specific" is translated.
 */
export function certificateSourceLabel(source: CertificateSource): string {
	switch (source) {
		case 'wildcard':
			return 'wildcard';
		case 'apex':
			return 'apex';
		case 'specific':
		default:
			return t('certs.sourceSpecific');
	}
}

/**
 * Effective source classification for display. The backend leaves
 * Source as the Go zero-value empty string on OBTAIN_FAILED
 * placeholder entries that never reached cert_obtained (the
 * Source field isn't known until a cert is successfully parsed).
 * On the wire that surfaces as `"source": ""` which TypeScript
 * widens to a value outside the CertificateSource union.
 *
 * Fall-through heuristic: a domain starting with "*." is a
 * wildcard whatever the source field says. Otherwise the
 * empty source defaults to "specific" (the most-common path).
 *
 * Pure function — UX heuristic only, no I/O. Tested against
 * the empirically-captured wire shape from AreNET-test on
 * 2026-06-05.
 */
export function resolveSource(cert: Certificate): CertificateSource {
	if (cert.source === 'wildcard' || cert.source === 'apex' || cert.source === 'specific') {
		return cert.source;
	}
	if (cert.domain.startsWith('*.')) return 'wildcard';
	return 'specific';
}

/**
 * Best-guess ACME challenge label for the sub-line under DOMAINE.
 * Wildcard-source certs go through DNS-01 (the only way certmagic
 * can fulfill *.x). Specific / apex certs default to HTTP-01.
 *
 * For OBTAIN_FAILED entries we don't know the challenge yet —
 * there's no successful obtain to learn from. Return '—' so the
 * table doesn't claim "HTTP-01" for a cert that hasn't even
 * been attempted via that challenge type. The wildcard path is
 * the exception: certmagic CAN ONLY fulfill *.x via DNS-01, so
 * the label is accurate even before a successful obtain.
 *
 * This is a UX heuristic — the backend doesn't currently surface
 * the actual challenge used per cert (would require certmagic
 * Issuer introspection). A future Step T+N could promote this to
 * a real backend-supplied field; today the heuristic is operator-
 * correct in 100% of AreNET-configured paths.
 */
export function inferChallengeLabel(
	source: CertificateSource,
	status?: Certificate['status']
): string {
	if (source === 'wildcard') return 'DNS-01';
	if (status === 'OBTAIN_FAILED') return '—';
	return 'HTTP-01';
}

/**
 * True when the parsed ISO timestamp is Go's zero-time
 * ("0001-01-01T00:00:00Z") or an unparseable string. OBTAIN_FAILED
 * entries that never reached cert_obtained have zero-valued
 * NotBefore / NotAfter on the wire; rendering them as relative
 * times would surface "il y a 2 027 ans" / "expiré" which are
 * cosmetically wrong (the cert hasn't been obtained, not "expired").
 */
export function isZeroTimestamp(iso: string | null | undefined): boolean {
	if (!iso) return true;
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return true;
	return d.getUTCFullYear() <= 1;
}

/**
 * Whole-day count between now and the cert's notAfter. Returns
 * null for certs whose notAfter is zero-valued (never obtained) —
 * callers should treat null as "—" / "n/a", NOT as 0 or "expired".
 * Otherwise positive for future expiries, negative for past.
 *
 * Rounding: floor on positive, ceil on negative — so "in 0 days"
 * means "expires today" and "-1 days" means "expired yesterday".
 */
export function daysUntilExpiry(cert: Certificate, now: Date = new Date()): number | null {
	if (isZeroTimestamp(cert.notAfter)) return null;
	const notAfter = new Date(cert.notAfter);
	if (Number.isNaN(notAfter.getTime())) return null;
	const diffMs = notAfter.getTime() - now.getTime();
	const days = diffMs / (1000 * 60 * 60 * 24);
	return diffMs >= 0 ? Math.floor(days) : Math.ceil(days);
}

/**
 * Predicate: cert is "expiring soon" per the AC #6 tab filter
 * vocabulary. Defined as "notAfter <= now + RENEWAL_WINDOW_DAYS"
 * — matches the backend's RENEWAL_PENDING status derivation so
 * the tab surfaces the same set the badge highlights.
 *
 * Excludes:
 *   - OBTAIN_FAILED entries: their notAfter is the Go zero-value
 *     (0001-01-01) which trivially compares < now+30d; surfacing
 *     them in the "Expirent bientôt" bucket would be misleading
 *     (they haven't been obtained yet, so there's nothing to
 *     renew). The dedicated ÉCHEC badge already calls them out.
 *   - Zero-time entries from any other path (defensive — the
 *     daysUntilExpiry null return signals "no known expiry").
 *
 * Includes already-expired certs with valid timestamps (the
 * operator surely wants to see those in the bucket too).
 */
export function isExpiringSoon(cert: Certificate, now: Date = new Date()): boolean {
	if (cert.status === 'OBTAIN_FAILED') return false;
	const days = daysUntilExpiry(cert, now);
	if (days === null) return false;
	return days <= RENEWAL_WINDOW_DAYS;
}

/**
 * Wildcard-vs-specific breakdown for the "Certificats actifs"
 * KPI sub-label. Uses resolveSource so OBTAIN_FAILED entries
 * with empty source still get classified honestly — pre-polish
 * the breakdown didn't sum to the total because empty-source
 * entries fell out of both wildcard and specific filters.
 *
 * Apex-source certs count toward the "spécifique" bucket because
 * the KPI sub-label is wildcard-vs-non-wildcard (the apex policy
 * IS a "specific" cert in operator vocabulary, distinct from a
 * wildcard cert).
 */
export function countByEffectiveSource(certs: Certificate[]): {
	wildcard: number;
	specific: number;
} {
	let wildcard = 0;
	let specific = 0;
	for (const c of certs) {
		if (resolveSource(c) === 'wildcard') {
			wildcard++;
		} else {
			specific++;
		}
	}
	return { wildcard, specific };
}

/**
 * Most-common Issuer string across the cert list. Used for the
 * "Émetteur principal" KPI. Returns '—' for an empty list.
 *
 * Tie-breaker: alphabetical (deterministic for snapshot tests).
 * In practice every AreNET install uses a single issuer, so the
 * tiebreaker path is exercised only by fixtures.
 */
export function dominantIssuer(certs: Certificate[]): string {
	if (certs.length === 0) return '—';
	const counts = new Map<string, number>();
	for (const c of certs) {
		const k = c.issuer || '—';
		counts.set(k, (counts.get(k) ?? 0) + 1);
	}
	let best = '';
	let bestCount = -1;
	for (const [issuer, count] of counts) {
		if (count > bestCount || (count === bestCount && issuer < best)) {
			best = issuer;
			bestCount = count;
		}
	}
	return best;
}
