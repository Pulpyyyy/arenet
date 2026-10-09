// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Compact relative times for dense table cells (WAF events, CrowdSec
// decisions). relativeTime() in audit-format.ts spells units out
// ("5 minutes ago"), which is too wide for a timestamp column; these
// use Intl's short style instead, in the app language rather than the
// browser's, for the same reason relativeTime() does.

import { language } from '$lib/stores/language.svelte';

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

/**
 * relativeTimeShort renders `isoTimestamp` relative to `now` in Intl's
 * short style: "5 min. ago" / "il y a 5 min", "in 2 hr." / "dans 2 h".
 *
 * Counts are truncated, not rounded, so 59 min 59 s still reads as
 * minutes. "Now" reads as past ("0 sec. ago"), never "in 0 sec.".
 * An unparseable timestamp is returned unchanged.
 */
export function relativeTimeShort(
	isoTimestamp: string,
	now: Date = new Date(),
	locale: string = language.current
): string {
	const then = new Date(isoTimestamp);
	if (Number.isNaN(then.getTime())) return isoTimestamp;
	const diffSec = (then.getTime() - now.getTime()) / 1000;
	const abs = Math.abs(diffSec);
	let unit: Intl.RelativeTimeFormatUnit = 'day';
	let size = DAY;
	if (abs < MINUTE) {
		unit = 'second';
		size = 1;
	} else if (abs < HOUR) {
		unit = 'minute';
		size = MINUTE;
	} else if (abs < DAY) {
		unit = 'hour';
		size = HOUR;
	}
	const count = Math.floor(abs / size);
	const rtf = new Intl.RelativeTimeFormat(locale, { style: 'short', numeric: 'always' });
	// Intl treats -0 as past, which is what puts "now" on the past side.
	return rtf.format(diffSec <= 0 ? -count : count, unit);
}

/**
 * recentTime is the event-table timestamp: a short relative time for
 * the last hour, then the local 24-hour HH:MM clock. A timestamp
 * slightly ahead of `now` (clock skew between hosts) reads as now.
 */
export function recentTime(
	isoTimestamp: string,
	now: Date = new Date(),
	locale: string = language.current
): string {
	const then = new Date(isoTimestamp);
	if (Number.isNaN(then.getTime())) return isoTimestamp;
	const ageMs = Math.max(0, now.getTime() - then.getTime());
	if (ageMs < HOUR * 1000) {
		return relativeTimeShort(new Date(now.getTime() - ageMs).toISOString(), now, locale);
	}
	const hh = String(then.getHours()).padStart(2, '0');
	const mm = String(then.getMinutes()).padStart(2, '0');
	return `${hh}:${mm}`;
}
