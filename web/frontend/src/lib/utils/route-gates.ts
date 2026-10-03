// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Which per-route gates Arenet actually emits into the Caddy config,
 * given the route's state.
 *
 * This exists because the list and the form read the STORED config
 * and drew conclusions from it: a redirecting route with wafMode
 * 'block' showed a red BLOCK chip, and a maintenance route showed its
 * geo and rate-limit chips, while neither handler was in the emitted
 * chain at all. The operator could set the WAF to block, see the
 * badge, save without error, and have no rule ever evaluated.
 *
 * The truth lives in internal/caddymgr/manager.go:1549 — a route with
 * a RedirectConfig or a MaintenanceConfig takes a branch that builds
 * ONE replacement handler, marks the route terminal, and `continue`s
 * at :1618, before the normal chain is assembled at :1640. So the
 * emitted chain for such a route is exactly [arenet_routemetrics,
 * static_response] (internal/caddymgr/redirect.go:43) — no rate
 * limit (:1653), no country block (:1668), no IP filter, no CrowdSec
 * (:1731), no basic auth (:1756), no forward auth (:1789), no WAF
 * (:1845), no header ops (:1848), no reverse proxy (:1903).
 *
 * A disabled route serves nothing whatsoever, so it gates nothing
 * either.
 *
 * Keep this function as the single place that answers the question.
 * The day a gate IS emitted on a redirect answer — the :443 side of
 * the country block is a known gap, since a redirecting route with
 * force-HTTPS carries the geo gate on :80 only (manager.go:1585) —
 * this is the one list to change, and every screen follows.
 */
export type RouteGate = 'waf' | 'auth' | 'geo' | 'ipFilter' | 'rateLimit' | 'healthCheck';

/** Every gate, in the order the emitted chain applies them. */
export const ALL_ROUTE_GATES: readonly RouteGate[] = [
	'rateLimit',
	'geo',
	'ipFilter',
	'auth',
	'waf',
	'healthCheck'
];

/** The subset of a route's config that decides whether gates apply. */
export interface GateRelevantRoute {
	disabled?: boolean;
	redirectConfig?: unknown;
	maintenanceConfig?: unknown;
}

/**
 * True when the route proxies nothing — so none of its stored gates
 * reach the emitted config. Redirect and maintenance both replace the
 * proxy chain; disabled removes the route from both listeners.
 */
export function proxiesNothing(route: GateRelevantRoute): boolean {
	return Boolean(route.disabled || route.redirectConfig || route.maintenanceConfig);
}

/** The gates Arenet emits for this route. Empty when it proxies nothing. */
export function emittedGates(route: GateRelevantRoute): readonly RouteGate[] {
	return proxiesNothing(route) ? [] : ALL_ROUTE_GATES;
}

/** True when this one gate reaches the emitted config for this route. */
export function gateApplies(route: GateRelevantRoute, gate: RouteGate): boolean {
	return emittedGates(route).includes(gate);
}
