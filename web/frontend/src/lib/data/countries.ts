// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step W.7 — ISO 3166-1 alpha-2 country code dataset for
// the country-block autocomplete UI.
//
// Two pieces:
//   1. ALPHA2_CODES — the canonical list of 249 codes (the
//      ISO standard set as of 2026; we update on each ISO
//      revision). Static export so the typeahead has a
//      stable set to scan + match against; ~2 KB minified
//      gzip.
//   2. countryName(code) — resolves a code to its display
//      name in the app language (language.current) via the
//      runtime Intl.DisplayNames API
//      (zero-bundle cost — the browser ships the data).
//      Falls back to the code itself when DisplayNames is
//      unsupported OR the code isn't in the locale data.
//
// Why Intl.DisplayNames over a vendored static dictionary:
//   - 0 KB bundle cost (vs ~3-4 KB for an alpha-2 → name
//     map gzipped).
//   - Browser data stays in sync with ISO revisions
//     automatically.
//   - Supported by every browser Arenet targets (Chrome
//     81+ / Firefox 86+ / Safari 14.1+ — all ≥ 2021, well
//     under Arenet's "modern evergreen" floor).
//   - Locale switch is free: the resolver reads
//     language.current, so every label re-resolves when
//     the operator changes the app language.
//
// Fallback discipline: if Intl.DisplayNames is missing
// (very old browser) or returns undefined (newly-added
// ISO code the browser doesn't know yet), countryName
// returns the input code. The autocomplete UX degrades
// gracefully — operator types "FR", sees "FR" instead of
// "France", chip still works.

import { language } from '$lib/stores/language.svelte';

// ALPHA2_CODES is the static set of ISO 3166-1 alpha-2
// country codes. Includes the 249 officially-assigned
// codes; excludes user-assigned (AA, ZZ), reserved
// transitional, and the special "EU" code (not in ISO
// 3166-1 proper). Sorted alphabetically for the
// dropdown's natural reading order; the autocomplete's
// matcher does prefix matching on both the code and
// the resolved name, so sort order is presentational only.
export const ALPHA2_CODES: readonly string[] = [
	'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AO', 'AQ', 'AR',
	'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE',
	'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ',
	'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD',
	'CF', 'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR',
	'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM',
	'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI',
	'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF',
	'GG', 'GH', 'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS',
	'GT', 'GU', 'GW', 'GY', 'HK', 'HM', 'HN', 'HR', 'HT', 'HU',
	'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ', 'IR', 'IS', 'IT',
	'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI', 'KM', 'KN',
	'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK',
	'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME',
	'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ',
	'MR', 'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA',
	'NC', 'NE', 'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU',
	'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM',
	'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS',
	'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI',
	'SJ', 'SK', 'SL', 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV',
	'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG', 'TH', 'TJ', 'TK',
	'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW', 'TZ', 'UA',
	'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG', 'VI',
	'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW'
];

// Lazy per-locale cache — the DisplayNames constructor is
// cheap but not free (~50 µs in v8), and matchCountries
// resolves every code on each keystroke. One instance per
// locale, built on first use. A `null` entry records that
// the runtime cannot build one (no Intl.DisplayNames —
// possible under Node SSR with an older ICU build), so the
// resolver short-circuits to the code-as-name fallback.
const _displayNames = new Map<string, Intl.DisplayNames | null>();

function displayNames(locale: string): Intl.DisplayNames | null {
	const cached = _displayNames.get(locale);
	if (cached !== undefined) return cached;
	let dn: Intl.DisplayNames | null = null;
	try {
		// `Intl.DisplayNames` is a constructor on modern
		// runtimes; the type guard catches the
		// "no DisplayNames" environment (Node < 16, very
		// old iOS WebView).
		if (typeof Intl !== 'undefined' && typeof Intl.DisplayNames === 'function') {
			dn = new Intl.DisplayNames([locale], { type: 'region' });
		}
	} catch {
		dn = null;
	}
	_displayNames.set(locale, dn);
	return dn;
}

/**
 * Resolves an ISO 3166-1 alpha-2 country code to its
 * display name in `locale` (default: the app language,
 * `language.current`) via Intl.DisplayNames. Reading the
 * store inside the call lets Svelte templates and
 * $derived re-run on a language switch. Falls back to
 * the code itself when:
 *   - The runtime lacks Intl.DisplayNames.
 *   - The code is unknown to the browser's locale data.
 *   - The input is malformed (not exactly 2 ASCII letters).
 *
 * Safe to call from any render path; no I/O, no
 * allocations on the hot path.
 *
 * Example:
 *   countryName('FR')       // → "France"
 *   countryName('RU')       // → "Russia" (app language en)
 *   countryName('RU', 'fr') // → "Russie"
 *   countryName('XX')       // → "XX" (unknown — fallback)
 *   countryName('')         // → ""    (empty input)
 */
export function countryName(code: string, locale: string = language.current): string {
	if (!code || code.length !== 2) return code;
	const upper = code.toUpperCase();
	const dn = displayNames(locale);
	if (!dn) return upper;
	try {
		const name = dn.of(upper);
		return name && name !== upper ? name : upper;
	} catch {
		return upper;
	}
}

/**
 * Matches an autocomplete query against the alpha-2 code
 * set, returning at most `limit` results. The matcher:
 *   - Prefix-matches the UPPERCASED query against the
 *     alpha-2 code itself (typing "RU" matches RU/RW/...).
 *   - Prefix-matches the lowercased query against the
 *     LOWERCASED name resolved in the app language
 *     (typing "russ" or "RUSS" matches Russia / Russie).
 *   - De-duplicates: a code matching both bars surfaces once.
 *   - Sorts code-prefix matches before name-prefix matches
 *     (operator typing the canonical short form gets it first).
 *
 * Returns the matches as `{code, name}` tuples; consumers
 * decide whether to render the badge + name or the code
 * alone (the chip-list uses the code, the dropdown uses
 * both).
 *
 * `excludeCodes` lets the caller hide codes already added
 * to the country list — typing "FR" with FR already in
 * the chip set surfaces an empty dropdown rather than a
 * dead-end "FR is already here" entry.
 *
 * Empty query returns the first `limit` codes
 * alphabetically (so an empty-state dropdown shows the
 * Aaa-to-Aml prefix). The route-edit UI doesn't render
 * the dropdown until the operator types, so the empty
 * branch is documented for completeness; consumers can
 * filter further at the call site.
 */
export interface CountryMatch {
	code: string;
	name: string;
}

const MAX_AUTOCOMPLETE_RESULTS = 8;

export function matchCountries(
	query: string,
	excludeCodes: readonly string[] = [],
	limit: number = MAX_AUTOCOMPLETE_RESULTS
): CountryMatch[] {
	const exclude = new Set(excludeCodes.map((c) => c.toUpperCase()));
	const codePrefix = query.trim().toUpperCase();
	const namePrefix = query.trim().toLowerCase();

	if (codePrefix === '') {
		return ALPHA2_CODES
			.filter((c) => !exclude.has(c))
			.slice(0, limit)
			.map((c) => ({ code: c, name: countryName(c) }));
	}

	const codeMatches: CountryMatch[] = [];
	const nameMatches: CountryMatch[] = [];
	const seen = new Set<string>();

	for (const code of ALPHA2_CODES) {
		if (exclude.has(code) || seen.has(code)) continue;
		const name = countryName(code);
		if (code.startsWith(codePrefix)) {
			codeMatches.push({ code, name });
			seen.add(code);
		} else if (name.toLowerCase().startsWith(namePrefix)) {
			nameMatches.push({ code, name });
			seen.add(code);
		}
		// Early termination once both buckets exceed the
		// limit — sorting them at the end produces at most
		// `limit` entries anyway.
		if (codeMatches.length + nameMatches.length >= limit * 2) break;
	}

	return codeMatches.concat(nameMatches).slice(0, limit);
}
