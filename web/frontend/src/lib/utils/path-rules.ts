// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { PathRule } from '$lib/api/types';

// fix/path-rule-empty-500 — dogfooding bug: an operator edited a route,
// removed a path-rule's protection (left ipFilter.mode "off" with a
// residual CIDR, no basic auth), clicked Save, and got a 500. The
// backend correctly rejects a path-rule with zero active protection
// (`path_rule "...": must declare at least one protection (basic auth
// or IP filter)`) — that's a storage.Route.validate() invariant, not a
// bug. The bug was twofold: (1) the backend surfaced that rejection as
// a 500 instead of a 400 (fixed separately in updateRoute), and (2) the
// frontend had no business sending a rule with no active protection in
// the first place — "remove a rule's protection" reads to an operator
// as "remove the rule", not "send an invalid rule and hope the server
// tells me why".
//
// Product decision: a path-rule with no ACTIVE protection is silently
// dropped at submit time. "Active" means:
//   - basicAuth is configured with a non-empty username, OR
//   - ipFilter.mode is 'allow' or 'deny' (i.e. not 'off'/'').
// A kept rule whose ipFilter.mode is 'off' has its cidrs cleared on
// the wire — a residual CIDR list under mode "off" is meaningless and
// is exactly what triggered the operator's 500 (the log showed
// `mode:"off", cidrs:["8.8.8.8"]`).

/** Returns true when `rule.basicAuth` represents a configured (non-empty
 *  username) basic-auth override. */
function hasActiveBasicAuth(rule: PathRule): boolean {
	return !!rule.basicAuth && rule.basicAuth.username.trim().length > 0;
}

/** Returns true when `rule.ipFilter` is an active allow/deny gate
 *  (mode 'off' or '' is not active, regardless of any residual cidrs). */
function hasActiveIPFilter(rule: PathRule): boolean {
	const mode = rule.ipFilter?.mode;
	return mode === 'allow' || mode === 'deny';
}

/** Returns true when `rule.upstreams` is a non-empty pool (pure routing
 *  counts as active content — v2.23.0). */
function hasActiveUpstream(rule: PathRule): boolean {
	return !!rule.upstreams && rule.upstreams.length > 0;
}

/**
 * sanitizePathRules filters `rules` down to those that carry at least
 * one active protection (basic auth with a non-empty username, or an
 * ipFilter in allow/deny mode), or a non-empty upstream pool — a pure
 * routing rule with no auth/IP-filter is legitimate content and must
 * survive (v2.23.0). Also clears `cidrs` on any kept rule whose
 * ipFilter mode is 'off' (a residual CIDR list under mode "off" is
 * dead weight and confusing on the wire).
 *
 * Pure and side-effect-free — does not mutate the input array or its
 * elements — so it's callable directly from the submit payload
 * assembler and from unit tests.
 */
/** A rule that redirects: target filled in. */
function hasActiveRedirect(rule: PathRule): boolean {
	return (rule.redirect?.target ?? '').trim().length > 0;
}

/**
 * A rule that throttles: a limit with a positive request count.
 *
 * v2.56.3 — without this a rate-limit-only rule was filtered out here and
 * never reached the API, so saving it returned 200 and the rule was gone on
 * the next read. Protecting one path with a strict limit and nothing else
 * is the ordinary way to use the feature, not an edge case.
 */
function hasActiveRateLimit(rule: PathRule): boolean {
	return (rule.rateLimit?.events ?? 0) > 0;
}

/**
 * A rule gated by an identity provider: a provider is named.
 *
 * v2.57 — gating a path through an IdP and nothing else is the whole point
 * of the feature, so without this predicate every such rule would be
 * filtered out here and the path would stay open.
 */
function hasActiveForwardAuth(rule: PathRule): boolean {
	return (rule.forwardAuth?.providerName ?? '').trim().length > 0;
}

/**
 * A rule that exempts its path from the route's authentication.
 *
 * v2.58 — content, even though it protects nothing: it is a deliberate
 * instruction, and an exemption-only rule is the ordinary shape of the
 * feature. Without this predicate every such rule would be filtered out at
 * submit and the path would quietly keep demanding a login.
 */
function hasAuthExemption(rule: PathRule): boolean {
	return rule.disableRouteAuth === true;
}

/**
 * Every predicate that makes a rule worth keeping.
 *
 * Exported so a test can assert the list covers each content field of
 * PathRule: the failure mode is not a crash but a silent drop with a
 * success toast, which is invisible until an operator notices their rule
 * disappeared.
 */
export const pathRuleContentChecks: ((rule: PathRule) => boolean)[] = [
	hasActiveBasicAuth,
	hasActiveIPFilter,
	hasActiveUpstream,
	hasActiveRedirect,
	hasActiveRateLimit,
	hasActiveForwardAuth,
	hasAuthExemption
];

export function sanitizePathRules(rules: PathRule[]): PathRule[] {
	return rules
		// v2.44 — a redirect is on its own enough to justify a rule:
		// "/" going to "/admin/login" carries no auth, no filter and
		// no pool, and dropping it here would silently discard exactly
		// the rule the operator just wrote.
		// Every kind of content a rule can carry has to be listed here.
		// The filter exists to drop a row the operator added and never
		// filled, and anything missing from this list is silently treated
		// as such — which is how a redirect was lost in v2.44 and a rate
		// limit in v2.56.1. pathRuleContentChecks below is walked by a
		// test so a new field cannot be added without landing here.
		.filter((rule) => pathRuleContentChecks.some((has) => has(rule)))
		.map((rule) => {
			if (rule.ipFilter && rule.ipFilter.mode === 'off') {
				return { ...rule, ipFilter: { ...rule.ipFilter, cidrs: [] } };
			}
			return rule;
		});
}
