// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Absolute date rendering in the in-app language. Complements
// relativeTime() (audit-format.ts): a relative "in 3 months" says how
// urgent something is, the absolute date says exactly when.

import { language } from '$lib/stores/language.svelte';

/**
 * Formats an ISO timestamp as an absolute date ("Sep 3, 2026" /
 * "3 sept. 2026"), with the time too when `withTime` is set. The locale
 * defaults to the in-app language, not the browser's, so the date reads
 * in the same language as the rest of the page. Returns '' for an
 * unparseable timestamp.
 *
 * Callers wanting a re-render on language switch read language.current
 * at the call site (`{language.current && absoluteDate(iso)}`).
 */
export function absoluteDate(
	iso: string,
	withTime = false,
	locale: string = language.current
): string {
	const d = new Date(iso);
	if (Number.isNaN(d.getTime())) return '';
	const opts: Intl.DateTimeFormatOptions = withTime
		? { dateStyle: 'medium', timeStyle: 'short' }
		: { dateStyle: 'medium' };
	return new Intl.DateTimeFormat(locale, opts).format(d);
}
