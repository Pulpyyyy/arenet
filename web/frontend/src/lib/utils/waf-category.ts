// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Y (2026-06-18) — single source of truth for the
// operator-facing presentation of every OwaspCategory : the
// human label, the longer description, the colour token used
// across charts / tiles / event tables, and the family
// grouping used by the /waf page tiles.
//
// Why centralise : pre-Y every consumer (CategoryDistribution,
// WafEventList, MixedEventList, /waf, /security/[routeId])
// carried its own switch over the 6-category enum. With the
// Phase Y expansion to 25 categories, that pattern would
// duplicate the same 25-arm switch in 5+ files. Centralising
// here lets the consumers read CATEGORY_META[c].label etc.
// without each one needing to know about the full taxonomy.
//
// Source of truth for the ranges + purpose : the empirical
// audit pinned in internal/waf/category.go's switch and
// internal/waf/category_test.go's per-file mapping table.
// Updating the Go side without updating CATEGORY_META here
// will leave the dashboard rendering raw enum strings — the
// `unknown` fallback at the bottom catches that silently
// but the operator sees less friendly labels.

import type { OwaspCategory } from '$lib/api/types';
import { t } from '$lib/i18n';

/** The family bucket the /waf page renders together. */
export type CategoryFamily =
	| 'request-attack'
	| 'protocol-behaviour'
	| 'aggregator'
	| 'data-leak'
	| 'infrastructure';

export interface CategoryMeta {
	label: string;
	description: string;
	/** CSS var name (without `var()`) for the chart / pill colour. */
	color: string;
	family: CategoryFamily;
}

// Labels and descriptions live in the locale files under
// `wafCategory.*` and are read through getters, so every consumer
// keeps reading `meta.label` / `meta.description` and still gets
// the active language (t() reads language.current, which makes the
// read reactive inside a $derived or a template).
function meta(code: string, color: string, family: CategoryFamily): CategoryMeta {
	return {
		get label() {
			return t(`wafCategory.${code}.label`);
		},
		get description() {
			return t(`wafCategory.${code}.description`);
		},
		color,
		family
	};
}

/** Fallback for unknown categories (post-Y rows referencing a
 *  category the frontend hasn't been taught yet — keeps the
 *  UI rendering instead of crashing). */
const UNKNOWN_META: CategoryMeta = {
	get label() {
		return t('wafCategory.unknown.label');
	},
	get description() {
		return t('wafCategory.unknown.description');
	},
	color: 'var(--text-muted)',
	family: 'infrastructure'
};

export const CATEGORY_META: Record<OwaspCategory, CategoryMeta> = {
	// --- Request attacks (red / orange family) ---
	SQLi: meta('SQLi', 'var(--status-down)', 'request-attack'),
	XSS: meta('XSS', 'var(--status-warn)', 'request-attack'),
	RCE: meta('RCE', 'var(--status-down)', 'request-attack'),
	PHP: meta('PHP', 'var(--status-down)', 'request-attack'),
	JAVA: meta('JAVA', 'var(--status-down)', 'request-attack'),
	GENERIC: meta('GENERIC', 'var(--status-warn)', 'request-attack'),
	LFI: meta('LFI', 'var(--status-warn)', 'request-attack'),
	RFI: meta('RFI', 'var(--status-warn)', 'request-attack'),

	// --- Protocol / behaviour ---
	METHOD: meta('METHOD', 'var(--status-info)', 'protocol-behaviour'),
	PROTOCOL: meta('PROTOCOL', 'var(--status-info)', 'protocol-behaviour'),
	PROTOCOL_ATK: meta('PROTOCOL_ATK', 'var(--status-warn)', 'protocol-behaviour'),
	MULTIPART: meta('MULTIPART', 'var(--status-warn)', 'protocol-behaviour'),
	SCANNER: meta('SCANNER', 'var(--status-info)', 'protocol-behaviour'),
	SESSION: meta('SESSION', 'var(--status-warn)', 'protocol-behaviour'),

	// --- Aggregators ---
	ANOMALY_REQ: meta('ANOMALY_REQ', 'var(--text-muted)', 'aggregator'),
	ANOMALY_RESP: meta('ANOMALY_RESP', 'var(--text-muted)', 'aggregator'),
	CORRELATION: meta('CORRELATION', 'var(--text-muted)', 'aggregator'),

	// --- Response-side / data leak ---
	DATA_LEAK: meta('DATA_LEAK', 'var(--status-warn)', 'data-leak'),
	DATA_LEAK_SQL: meta('DATA_LEAK_SQL', 'var(--status-warn)', 'data-leak'),
	DATA_LEAK_JAVA: meta('DATA_LEAK_JAVA', 'var(--status-warn)', 'data-leak'),
	DATA_LEAK_PHP: meta('DATA_LEAK_PHP', 'var(--status-warn)', 'data-leak'),
	DATA_LEAK_IIS: meta('DATA_LEAK_IIS', 'var(--status-warn)', 'data-leak'),
	WEBSHELL: meta('WEBSHELL', 'var(--status-down)', 'data-leak'),

	// --- Infrastructure / catch-all ---
	INIT: meta('INIT', 'var(--text-muted)', 'infrastructure'),
	COMMON_EXCEPT: meta('COMMON_EXCEPT', 'var(--text-muted)', 'infrastructure'),
	CUSTOM: meta('CUSTOM', 'var(--accent-cyan)', 'infrastructure'),
	OTHER: meta('OTHER', 'var(--text-muted)', 'infrastructure')
};

/** Safe accessor — returns the fallback meta for unknown
 *  categories so the UI never crashes on a category string
 *  the frontend hasn't been taught yet. */
export function categoryMeta(c: OwaspCategory | string): CategoryMeta {
	return (CATEGORY_META as Record<string, CategoryMeta>)[c] ?? UNKNOWN_META;
}

/** Operator-facing family labels for the /waf page section
 *  headers. Order matches the visual flow : focal attacks
 *  first, then behaviour, then aggregators, response-side,
 *  infrastructure. */
export const FAMILY_LABEL: Record<CategoryFamily, string> = {
	get 'request-attack'() {
		return t('wafCategory.family.requestAttack');
	},
	get 'protocol-behaviour'() {
		return t('wafCategory.family.protocolBehaviour');
	},
	get aggregator() {
		return t('wafCategory.family.aggregator');
	},
	get 'data-leak'() {
		return t('wafCategory.family.dataLeak');
	},
	get infrastructure() {
		return t('wafCategory.family.infrastructure');
	}
};

/** Categories grouped by family in dashboard-display order.
 *  Computed from CATEGORY_META + ALL_OWASP_CATEGORIES so the
 *  /waf page can iterate families → categories without
 *  reasoning about the flat enum order. */
export function categoriesByFamily(
	all: readonly OwaspCategory[]
): Array<{ family: CategoryFamily; categories: OwaspCategory[] }> {
	const groups = new Map<CategoryFamily, OwaspCategory[]>();
	for (const c of all) {
		const fam = categoryMeta(c).family;
		const arr = groups.get(fam) ?? [];
		arr.push(c);
		groups.set(fam, arr);
	}
	// Stable order per FAMILY_LABEL keys.
	return (Object.keys(FAMILY_LABEL) as CategoryFamily[])
		.filter((fam) => groups.has(fam))
		.map((family) => ({ family, categories: groups.get(family)! }));
}
