// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// v2.36 — helpers for targeted WAF exclusions. They mirror the
// backend validation (internal/api/waf_exclusions.go) so the UI only
// offers what the server accepts; the server stays authoritative.

/** Collections a targeted exclusion may name. */
export const WAF_TARGET_VARIABLES = [
	'ARGS',
	'ARGS_GET',
	'ARGS_POST',
	'ARGS_NAMES',
	'REQUEST_COOKIES',
	'REQUEST_COOKIES_NAMES',
	'REQUEST_HEADERS',
	'REQUEST_HEADERS_NAMES',
	'FILES',
	'FILES_NAMES'
] as const;

/** CRS initialization / blocking-evaluation / correlation families. */
const PROTECTED_FAMILIES = [901, 949, 959, 980];
const MIN_EXCLUDABLE = 200000;
const MAX_EXCLUDABLE = 999999;
const TARGET_KEY_MAX = 128;
const PATH_MAX = 512;
const TARGET_FORBIDDEN = /[\s,;"'\\|]/;
const PATH_FORBIDDEN = /[\s"'\\]/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * Whether a rule can be excluded: a CRS rule (not an Arenet rule,
 * 1xxxxx) outside the families that drive the blocking itself.
 */
export function isExcludableRule(ruleId: string | number): boolean {
	const id = typeof ruleId === 'number' ? ruleId : Number(ruleId);
	if (!Number.isInteger(id) || id < MIN_EXCLUDABLE || id > MAX_EXCLUDABLE) return false;
	return !PROTECTED_FAMILIES.includes(Math.floor(id / 1000));
}

/** Splits and validates "VARIABLE:key"; null when not usable as a target. */
export function parseWafTarget(raw: string | undefined): { variable: string; key: string } | null {
	if (!raw) return null;
	const i = raw.indexOf(':');
	if (i <= 0) return null;
	const variable = raw.slice(0, i).trim().toUpperCase();
	const key = raw.slice(i + 1).trim();
	if (!(WAF_TARGET_VARIABLES as readonly string[]).includes(variable)) return null;
	if (!isValidTargetKey(key)) return null;
	return { variable, key };
}

/** Field-name rules of a target (see wafTargetForbiddenChars). */
export function isValidTargetKey(key: string): boolean {
	return (
		key !== '' &&
		key.length <= TARGET_KEY_MAX &&
		!key.startsWith('/') &&
		!TARGET_FORBIDDEN.test(key) &&
		!CONTROL.test(key)
	);
}

/** Path rules of an exclusion (see wafPathForbiddenChars). */
export function isValidExclusionPath(path: string): boolean {
	return (
		path.startsWith('/') && path.length <= PATH_MAX && !PATH_FORBIDDEN.test(path) && !CONTROL.test(path)
	);
}

/**
 * The path an exclusion should match for an event: the request URI
 * without its query string, percent-decoded — Coraza compares
 * REQUEST_FILENAME, the decoded path. "" when unusable.
 */
export function eventExclusionPath(requestPath: string): string {
	let path = requestPath.split('?')[0].split('#')[0];
	try {
		path = decodeURIComponent(path);
	} catch {
		return '';
	}
	return isValidExclusionPath(path) ? path : '';
}

/**
 * Who triggers a rule on a route, as the exclude dialog shows it.
 * `hits` comes from the server aggregate (exact over the window);
 * `distinctIps` is counted over the `sampled` recent events the UI
 * could load, so it is exact only when `sampled >= hits`.
 */
export interface RuleEvidence {
	hits: number;
	sampled: number;
	distinctIps: number;
}

/**
 * Builds a RuleEvidence from the window's hit count and a list of
 * recent events (any rule): keeps the events of `ruleId` at or after
 * `sinceMs`, and counts their distinct, non-empty source IPs.
 */
export function summariseRuleEvidence(
	ruleId: string,
	hits: number,
	events: readonly { ruleId: string; ts: string; srcIp: string }[],
	sinceMs: number
): RuleEvidence {
	const ips = new Set<string>();
	let sampled = 0;
	for (const ev of events) {
		if (ev.ruleId !== ruleId) continue;
		const ts = Date.parse(ev.ts);
		if (Number.isNaN(ts) || ts < sinceMs) continue;
		sampled++;
		if (ev.srcIp) ips.add(ev.srcIp);
	}
	return { hits, sampled, distinctIps: ips.size };
}
