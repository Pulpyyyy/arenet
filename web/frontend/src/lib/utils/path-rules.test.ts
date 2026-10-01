// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { pathRuleContentChecks, sanitizePathRules } from './path-rules';
import type { PathRule } from '$lib/api/types';

describe('sanitizePathRules', () => {
	it('drops a rule with no active protection (ipFilter off, no basic auth)', () => {
		// This is the exact operator-reported shape: mode "off" with a
		// residual CIDR and no basicAuth block — the backend 500'd on
		// this before the fix; now it must never even be sent.
		const rules: PathRule[] = [
			{
				pathPrefix: '/metrics-zabbix',
				ipFilter: { mode: 'off', cidrs: ['8.8.8.8'] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([]);
	});

	it('drops a rule whose basicAuth is present but has an empty username', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/empty-toggle',
				basicAuth: { username: '', password: '' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([]);
	});

	it('keeps a rule with an active ipFilter (allow/deny) and clears nothing', () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/metrics', ipFilter: { mode: 'allow', cidrs: ['192.168.1.5'] } }
		];
		expect(sanitizePathRules(rules)).toEqual([
			{ pathPrefix: '/metrics', ipFilter: { mode: 'allow', cidrs: ['192.168.1.5'] } }
		]);
	});

	it('keeps a rule with configured basic auth (non-empty username)', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/docs',
				basicAuth: { username: 'doc', password: 'somePlainPassword' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([
			{
				pathPrefix: '/docs',
				basicAuth: { username: 'doc', password: 'somePlainPassword' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		]);
	});

	it('clears cidrs on a kept rule whose ipFilter mode is "off"', () => {
		// A rule kept because of active basic auth, but which also
		// carries a residual (meaningless) CIDR list under mode "off" —
		// must be cleared on the wire.
		const rules: PathRule[] = [
			{
				pathPrefix: '/admin',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'off', cidrs: ['10.0.0.0/8', '8.8.8.8'] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual([
			{
				pathPrefix: '/admin',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'off', cidrs: [] }
			}
		]);
	});

	it('keeps a rule with both active protections untouched', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/both',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'deny', cidrs: ['1.2.3.4'] }
			}
		];
		expect(sanitizePathRules(rules)).toEqual(rules);
	});

	it('does not mutate the input array or its elements', () => {
		const rules: PathRule[] = [
			{
				pathPrefix: '/admin',
				basicAuth: { username: 'admin', password: 'secret' },
				ipFilter: { mode: 'off', cidrs: ['8.8.8.8'] }
			}
		];
		const snapshot = JSON.parse(JSON.stringify(rules));
		sanitizePathRules(rules);
		expect(rules).toEqual(snapshot);
	});

	it('returns an empty array for an empty input', () => {
		expect(sanitizePathRules([])).toEqual([]);
	});

	it('drops dead rules while keeping active ones in a mixed list', () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/dead', ipFilter: { mode: 'off', cidrs: ['8.8.8.8'] } },
			{ pathPrefix: '/alive', ipFilter: { mode: 'deny', cidrs: ['1.2.3.4'] } }
		];
		expect(sanitizePathRules(rules)).toEqual([
			{ pathPrefix: '/alive', ipFilter: { mode: 'deny', cidrs: ['1.2.3.4'] } }
		]);
	});

	it('keeps a rule that has ONLY an upstream pool (pure routing)', () => {
		const rules = [
			{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], lbPolicy: 'round_robin' as const }
		];
		const out = sanitizePathRules(rules as any);
		expect(out).toHaveLength(1);
		expect(out[0].pathPrefix).toBe('/v1');
	});

	it('drops a rule with an EMPTY upstream pool and no protection', () => {
		const rules = [{ pathPrefix: '/v1', upstreams: [] }];
		const out = sanitizePathRules(rules as any);
		expect(out).toHaveLength(0);
	});

	it('keeps a rule with upstream + off-mode ipFilter and clears its residual cidrs', () => {
		const rules = [
			{ pathPrefix: '/v1', upstreams: [{ url: 'http://a:8080', weight: 1 }], ipFilter: { mode: 'off' as const, cidrs: ['8.8.8.8'] } }
		];
		const out = sanitizePathRules(rules as any);
		expect(out).toHaveLength(1);
		expect(out[0].ipFilter?.cidrs).toEqual([]);
	});
});

// --- v2.44 — a redirect justifies a rule on its own ---------------
//
// Before v2.44 a path rule had to carry auth, an IP filter or a pool,
// and anything else was dropped here as empty. The operator's live
// case carries none of the three: "/" going to "/admin/login" is a
// rule whose only content is the redirect, and silently discarding it
// on save would be the worst possible answer.

describe('sanitizePathRules — redirects', () => {
	it('keeps a rule whose only content is a redirect', () => {
		const rules = [
			{ pathPrefix: '/', matchExact: true, redirect: { target: '/admin/login', statusCode: 302 } }
		];
		expect(sanitizePathRules(rules)).toHaveLength(1);
	});

	it('still drops a rule that carries nothing at all', () => {
		expect(sanitizePathRules([{ pathPrefix: '/', redirect: { target: '   ' } }])).toEqual([]);
		expect(sanitizePathRules([{ pathPrefix: '/nothing' }])).toEqual([]);
	});
});

// v2.56.3 — a rule carrying ONLY a rate limit was filtered out here, so
// saving it returned 200 and the rule was gone on the next read.
//
// The same shape of loss happened in v2.44 with a path redirect. The filter
// enumerates what counts as content, and anything missing from the list is
// treated as a row the operator abandoned.
describe('sanitizePathRules — rate-limit-only rules', () => {
	it('keeps a rule whose only content is a rate limit', () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/rl-test', ipFilter: { mode: 'off' }, rateLimit: { events: 5, window: '1m' } }
		];
		const kept = sanitizePathRules(rules);
		expect(kept, 'a rate-limit-only rule was dropped before it could be saved').toHaveLength(1);
		expect(kept[0].rateLimit).toEqual({ events: 5, window: '1m' });
	});

	it('still drops a row that carries nothing at all', () => {
		const rules: PathRule[] = [{ pathPrefix: '/empty', ipFilter: { mode: 'off' } }];
		expect(sanitizePathRules(rules)).toHaveLength(0);
	});

	// A limit of zero requests is not a limit; it is a half-filled row.
	it('drops a rate limit with no request count', () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/x', ipFilter: { mode: 'off' }, rateLimit: { events: 0, window: '1m' } }
		];
		expect(sanitizePathRules(rules)).toHaveLength(0);
	});

	// The drift guard. Each content field of PathRule must be recognised by
	// at least one predicate, or a rule carrying only that field is silently
	// discarded with a success toast — invisible until an operator notices
	// their rule vanished.
	it('recognises every kind of content a rule can carry', () => {
		// v2.57 — this guard used to be a hand-written map typed
		// Record<string, PathRule>, so adding a field to PathRule did not
		// make it fail: it only tested the fields someone remembered to
		// list, which is the same weakness as the payload assembler it
		// exists to protect. ContentField is now derived from PathRule
		// itself, with the non-content fields named explicitly, so a new
		// field makes `npm run check` fail until it is classified as
		// content (with a sample below) or as a modifier (excluded here).
		//
		// pathPrefix is the rule's identity; matchExact changes how the
		// prefix matches; lbPolicy, healthCheck and insecureSkipVerify
		// only qualify an upstream pool and are meaningless alone.
		type NonContentField =
			| 'pathPrefix'
			| 'matchExact'
			| 'lbPolicy'
			| 'healthCheck'
			| 'insecureSkipVerify';
		type ContentField = Exclude<keyof PathRule, NonContentField>;

		const byField: Record<ContentField, PathRule> = {
			basicAuth: { pathPrefix: '/a', basicAuth: { username: 'ops', password: 'x' } },
			ipFilter: { pathPrefix: '/a', ipFilter: { mode: 'allow', cidrs: ['10.0.0.0/8'] } },
			upstreams: { pathPrefix: '/a', upstreams: [{ url: 'http://10.0.0.2:80', weight: 1 }] },
			redirect: { pathPrefix: '/a', redirect: { target: '/login' } },
			rateLimit: { pathPrefix: '/a', rateLimit: { events: 5, window: '1m' } },
			forwardAuth: { pathPrefix: '/a', forwardAuth: { providerName: 'authentik' } }
		};
		for (const [field, rule] of Object.entries(byField)) {
			expect(
				pathRuleContentChecks.some((has) => has(rule)),
				`a rule carrying only ${field} is treated as empty and dropped on save`
			).toBe(true);
		}
	});

	it('keeps a rule gated only by an identity provider', () => {
		// v2.57 — the ordinary way to use the feature: an exposed path with
		// nothing else on the rule. Dropped here, the path stays open.
		const rules: PathRule[] = [
			{ pathPrefix: '/metrics', forwardAuth: { providerName: 'authentik' } }
		];
		expect(sanitizePathRules(rules)).toEqual(rules);
	});

	it('drops a rule whose forwardAuth names no provider', () => {
		const rules: PathRule[] = [{ pathPrefix: '/metrics', forwardAuth: { providerName: '  ' } }];
		expect(sanitizePathRules(rules)).toEqual([]);
	});
});
