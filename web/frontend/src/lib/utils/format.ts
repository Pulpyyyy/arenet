// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Locale-aware display helpers. Every function takes its locale
// from the app language (`language.current`), never from the
// browser: an operator who picked English on a French OS must read
// "1.5 MB", and one who picked French must read "1,5 Mo".
//
// The locale is a default parameter so tests can pin it, and so a
// call from a Svelte template or $derived reads the store and
// re-renders when the operator switches language.

import { language } from '$lib/stores/language.svelte';

// Decimal (SI) units, 1 kB = 1000 B. Chosen over binary because:
//   - Intl.NumberFormat only knows the decimal byte units
//     (kilobyte, megabyte…); 'kibibyte' is rejected, so binary
//     would mean hand-writing KiB/Kio labels per language.
//   - Bandwidth and file sizes, which these figures get compared
//     against, are quoted in decimal units.
//   - The route metrics strip already rendered decimal kB/MB.
const BYTE_STEP = 1000;
const SCALED_UNITS = ['kilobyte', 'megabyte', 'gigabyte', 'terabyte', 'petabyte'] as const;

// Below this value a scaled figure keeps one decimal ("2.9 MB"),
// above it none ("12 MB"): roughly constant significant figures.
const ONE_DECIMAL_BELOW = 10;

/**
 * formatBytes renders a byte count at the scale an operator reads,
 * in the app language: "512 bytes", "2.9 MB", "12 MB" in English;
 * "512 octets", "2,9 Mo", "12 Mo" in French.
 *
 * Plain byte counts use the long unit name because CLDR's short
 * English label for a byte is the singular "byte" ("500 byte").
 */
export function formatBytes(n: number, locale: string = language.current): string {
	if (Math.abs(n) < BYTE_STEP) {
		return new Intl.NumberFormat(locale, {
			style: 'unit',
			unit: 'byte',
			unitDisplay: 'long'
		}).format(n);
	}
	let value = n / BYTE_STEP;
	let unit = 0;
	while (Math.abs(value) >= BYTE_STEP && unit < SCALED_UNITS.length - 1) {
		value /= BYTE_STEP;
		unit++;
	}
	return new Intl.NumberFormat(locale, {
		style: 'unit',
		unit: SCALED_UNITS[unit],
		unitDisplay: 'short',
		maximumFractionDigits: Math.abs(value) < ONE_DECIMAL_BELOW ? 1 : 0
	}).format(value);
}

/**
 * formatTime renders the local wall-clock hour and minute of `d`
 * ("09:05", "23:59") in the app language. The 24-hour cycle is
 * forced so English does not switch to "9:05 AM": the panels using
 * it are dense timelines where a fixed width reads better.
 */
export function formatTime(d: Date, locale: string = language.current): string {
	return new Intl.DateTimeFormat(locale, {
		hour: '2-digit',
		minute: '2-digit',
		hourCycle: 'h23'
	}).format(d);
}
