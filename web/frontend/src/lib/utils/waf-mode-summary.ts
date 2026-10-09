// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The /waf "Mode" tile used to read a hardcoded "Blocking" while the
// mode is set per route and detect is the recommended start. This
// counts what Coraza actually enforces, route by route. Whether the
// WAF runs at all is route-gates' question: a disabled, redirecting
// or maintenance route counts as `skipped` whatever its wafMode says.

import type { Route } from '$lib/api/types';
import { gateApplies, type GateRelevantRoute } from './route-gates';

/** Route counts by the WAF mode Coraza actually applies. */
export type WafModeCounts = {
	block: number;
	detect: number;
	off: number;
	/** Routes whose WAF is not in the emitted chain: disabled, maintenance, redirect. */
	skipped: number;
};

/** Counts routes by effective WAF mode. Unknown modes count as off. */
export function countWafModes(
	routes: readonly (GateRelevantRoute & Pick<Route, 'wafMode'>)[]
): WafModeCounts {
	const counts: WafModeCounts = { block: 0, detect: 0, off: 0, skipped: 0 };
	for (const r of routes) {
		if (!gateApplies(r, 'waf')) counts.skipped++;
		else if (r.wafMode === 'block') counts.block++;
		else if (r.wafMode === 'detect') counts.detect++;
		else counts.off++;
	}
	return counts;
}
