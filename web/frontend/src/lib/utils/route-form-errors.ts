// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Which section of the route form holds a given field error.
//
// Only Essentials starts open, so an error rendered next to a field
// in a closed section — a health-check URI, a path rule, a WAF
// exclusion — was on the page but out of sight: Save did nothing
// visible beyond a toast naming the first error. The form uses this
// to open, and mark, every section that holds one.
//
// Keys are the ones validateBeforeSubmit and fieldFromMessage write
// into the form's `errors` map.

/** A route form section that can hold field errors. */
export type RouteFormSection = 'essentials' | 'healthCheck' | 'pathsHeaders' | 'waf';

/** The section rendering this error key, or null for a key with no section. */
export function sectionForErrorKey(key: string): RouteFormSection | null {
	if (key === 'host' || key === 'lbPolicy' || key.startsWith('upstreams')) return 'essentials';
	if (key.startsWith('healthCheck.')) return 'healthCheck';
	if (key.startsWith('pathRules.')) return 'pathsHeaders';
	if (key === 'wafExcludeRules' || key === 'wafExcludeTags') return 'waf';
	return null;
}

/** The sections holding at least one non-empty error. */
export function invalidSections(errors: Record<string, string>): Set<RouteFormSection> {
	const out = new Set<RouteFormSection>();
	for (const [key, msg] of Object.entries(errors)) {
		if ((msg ?? '').trim() === '') continue;
		const section = sectionForErrorKey(key);
		if (section) out.add(section);
	}
	return out;
}
