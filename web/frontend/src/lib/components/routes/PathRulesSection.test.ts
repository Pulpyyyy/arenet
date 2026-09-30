// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// PathRulesSection component tests (Task 8, path-based-rules). Behavior-based
// per the project's Toggle-neighbor test convention: render + simulate user
// interaction + assert observable outcome, no internal state peeking.

import { describe, it, expect } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte';
import { tick } from 'svelte';
import PathRulesSection from './PathRulesSection.svelte';
import type { PathRule } from '$lib/api/types';

describe('PathRulesSection', () => {
	it('is collapsed by default and adds a rule card on demand', async () => {
		const { getByTestId, queryAllByTestId } = render(PathRulesSection, { value: [] });
		expect(queryAllByTestId('path-rule-card').length).toBe(0);
		await fireEvent.click(getByTestId('path-rules-add'));
		expect(queryAllByTestId('path-rule-card').length).toBe(1);
	});

	it('renders one card per existing rule', () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }, { pathPrefix: '/api' }];
		const { queryAllByTestId } = render(PathRulesSection, { value });
		expect(queryAllByTestId('path-rule-card').length).toBe(2);
	});

	it('removes a rule card on demand', async () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }];
		const { getByTestId, queryAllByTestId } = render(PathRulesSection, { value });
		expect(queryAllByTestId('path-rule-card').length).toBe(1);
		await fireEvent.click(getByTestId('path-rule-remove-0'));
		expect(queryAllByTestId('path-rule-card').length).toBe(0);
	});

	// Task 8: path-rule basic auth takes a PLAIN password on the wire
	// (hashed server-side), matching route-level basicAuth. Typing into
	// the password field must land in `basicAuth.password` — binding it
	// to `passwordHash` was the bug this fix corrects (an operator's
	// plaintext password would've been stored verbatim as a "hash").
	// Rule starts with basicAuth already present (mirrors the existing
	// 'renders one card per existing rule' convention) so the test
	// exercises the input binding directly rather than the checkbox's
	// cross-render reactivity plumbing.
	it('binds the password field to basicAuth.password (plain), not passwordHash', async () => {
		const value: PathRule[] = [{ pathPrefix: '/admin', basicAuth: { username: 'admin' } }];
		const { getByTestId } = render(PathRulesSection, { value });

		const passwordInput = getByTestId('path-rule-basicauth-password-0') as HTMLInputElement;
		expect(passwordInput.type).toBe('password');

		await fireEvent.input(passwordInput, { target: { value: 'somePlainPassword' } });

		expect(value[0].basicAuth?.password).toBe('somePlainPassword');
		expect((value[0].basicAuth as unknown as Record<string, unknown>).passwordHash).toBeUndefined();
	});

	// Task 6 (path-based-rules, per-path upstream routing) — the
	// "Upstream spécifique" disclosure is collapsed by default: the
	// <details> exists per rule, but its inner fields (url repeater,
	// add-backend button) are not rendered/visible until the
	// disclosure is opened, mirroring the route-level health-check
	// <details> idiom (open={...}, collapsed unless there's already
	// content).
	it('renders a collapsed "Upstream spécifique" disclosure per rule', async () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		const disclosure = getByTestId('path-rule-upstream-disclosure-0') as HTMLDetailsElement;
		expect(disclosure).toBeTruthy();
		expect(disclosure.open).toBe(false);
		// No backends badge yet — pool is empty.
		expect(queryByTestId('path-rule-backends-badge-0')).toBeNull();
	});

	it('adding a backend materialises the pool and shows the "→ N backends" badge', async () => {
		const value: PathRule[] = [{ pathPrefix: '/docs' }];
		const { getByTestId } = render(PathRulesSection, { value });

		await fireEvent.click(getByTestId('path-rule-upstream-add-0'));
		expect(value[0].upstreams?.length).toBe(1);
		expect(getByTestId('path-rule-backends-badge-0').textContent).toContain('1');

		// Second interaction: asserted purely via the DOM. The bare
		// `value` array literal this test passes to render() is not a
		// reactive ($state) host — Svelte's $bindable only write-backs
		// to that exact outer reference on its first prop replacement
		// (empirically verified), so a second round-trip read of the
		// `value` variable here would be stale even though the
		// component's own internal state (and therefore the real app,
		// where the parent's pathRules IS $state) is correct.
		await fireEvent.click(getByTestId('path-rule-upstream-add-0'));
		expect(getByTestId('path-rule-backends-badge-0').textContent).toContain('2');
	});

	it('shows a "→ N backends" badge on mount when the rule already has a non-empty pool', () => {
		const value: PathRule[] = [
			{
				pathPrefix: '/api',
				upstreams: [
					{ url: 'http://a:8080', weight: 1 },
					{ url: 'http://b:8080', weight: 1 }
				]
			}
		];
		const { getByTestId } = render(PathRulesSection, { value });
		expect(getByTestId('path-rule-backends-badge-0').textContent).toContain('2');
	});

	it('removing a backend updates the pool and the input is gone', async () => {
		const value: PathRule[] = [
			{ pathPrefix: '/api', upstreams: [{ url: 'http://a:8080', weight: 1 }] }
		];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		expect(getByTestId('path-rule-upstream-url-0-0')).toBeTruthy();
		await fireEvent.click(getByTestId('path-rule-upstream-remove-0-0'));

		expect(value[0].upstreams?.length).toBe(0);
		expect(queryByTestId('path-rule-upstream-url-0-0')).toBeNull();
		expect(queryByTestId('path-rule-backends-badge-0')).toBeNull();
	});

	it('typing a backend url updates the bound rule', async () => {
		const value: PathRule[] = [
			{ pathPrefix: '/api', upstreams: [{ url: '', weight: 1 }] }
		];
		const { getByTestId } = render(PathRulesSection, { value });

		const urlInput = getByTestId('path-rule-upstream-url-0-0') as HTMLInputElement;
		await fireEvent.input(urlInput, { target: { value: 'http://backend:9090' } });
		expect(value[0].upstreams?.[0].url).toBe('http://backend:9090');
	});

	it('typing a backend weight updates the DOM value', async () => {
		// Second interaction on a freshly rendered instance, asserted
		// via the DOM element's own `.value` rather than the outer
		// `value` array — see the note in the "adding a backend..."
		// test above re: bare-array $bindable props in this harness.
		// lbPolicy is explicitly weighted_round_robin (v2.23.1) — the
		// weight input is now gated on that policy (see the
		// hides/shows-the-weight-input tests below), so this test must
		// opt in to keep exercising the weight input itself.
		const value: PathRule[] = [
			{
				pathPrefix: '/api',
				upstreams: [{ url: 'http://backend:9090', weight: 1 }],
				lbPolicy: 'weighted_round_robin'
			}
		];
		const { getByTestId } = render(PathRulesSection, { value });

		const weightInput = getByTestId('path-rule-upstream-weight-0-0') as HTMLInputElement;
		await fireEvent.input(weightInput, { target: { value: '5' } });
		expect(weightInput.value).toBe('5');
	});

	it('enabling the health-check materialises a full HealthCheck object with the uri field visible', async () => {
		const value: PathRule[] = [{ pathPrefix: '/api' }];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		expect(queryByTestId('path-rule-hc-uri-0')).toBeNull();
		await fireEvent.click(getByTestId('path-rule-hc-toggle-0'));

		expect(value[0].healthCheck?.enabled).toBe(true);
		expect(value[0].healthCheck?.method).toBe('GET');
		expect(getByTestId('path-rule-hc-uri-0')).toBeTruthy();
	});

	it('disabling the health-check hides the uri field', async () => {
		// Fresh instance starting already-enabled, so disabling it is
		// the FIRST interaction against this render — keeps the
		// assertion on the outer `value` reference valid (see note
		// above re: bare-array $bindable props only write-back once).
		const value: PathRule[] = [
			{
				pathPrefix: '/api',
				healthCheck: {
					enabled: true,
					uri: '/health',
					method: 'GET',
					interval: '10s',
					timeout: '5s',
					expectStatus: 0,
					expectBody: '',
					passes: 1,
					fails: 1
				}
			}
		];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		expect(getByTestId('path-rule-hc-uri-0')).toBeTruthy();
		await fireEvent.click(getByTestId('path-rule-hc-toggle-0'));

		expect(value[0].healthCheck).toBeUndefined();
		expect(queryByTestId('path-rule-hc-uri-0')).toBeNull();
	});

	// v2.23.1 — the weight input is only meaningful under
	// weighted_round_robin (mirrors the route-level weightVisible gate in
	// routes/+page.svelte); showing it unconditionally is inconsistent
	// with that pattern and misleading for round_robin/least_conn/etc.
	it('hides the weight input unless the path LB is weighted_round_robin', () => {
		const value: PathRule[] = [
			{
				pathPrefix: '/v1',
				upstreams: [{ url: 'http://a:8080', weight: 1 }],
				lbPolicy: 'round_robin'
			}
		];
		const { queryByTestId } = render(PathRulesSection, { value });
		expect(queryByTestId('path-rule-upstream-weight-0-0')).toBeNull();
	});

	it('shows the weight input when the path LB is weighted_round_robin', () => {
		const value: PathRule[] = [
			{
				pathPrefix: '/v1',
				upstreams: [{ url: 'http://a:8080', weight: 1 }],
				lbPolicy: 'weighted_round_robin'
			}
		];
		const { getByTestId } = render(PathRulesSection, { value });
		expect(getByTestId('path-rule-upstream-weight-0-0')).toBeInTheDocument();
	});

	// v2.23.1 — the skip-TLS-verify checkbox is only meaningful when the
	// path's own upstream pool has an https:// URL. Rendered as two
	// separate instances rather than relying on `rerender` — this
	// harness's $bindable write-back on a bare-array prop is only
	// reliable across the FIRST prop replacement (see the note in the
	// "adding a backend..." test above), so a rerender-based assertion
	// here would be flaky for the same underlying reason.
	it('hides the skip-TLS-verify checkbox for an http-only pool', () => {
		const value: PathRule[] = [
			{
				pathPrefix: '/v1',
				upstreams: [{ url: 'http://a:8080', weight: 1 }],
				lbPolicy: 'round_robin'
			}
		];
		const { queryByTestId } = render(PathRulesSection, { value });
		expect(queryByTestId('path-rule-skip-verify-0')).toBeNull();
	});

	it('shows the skip-TLS-verify checkbox when the pool has an https URL', () => {
		const value: PathRule[] = [
			{
				pathPrefix: '/v1',
				upstreams: [{ url: 'https://a:8443', weight: 1 }],
				lbPolicy: 'round_robin'
			}
		];
		const { getByTestId } = render(PathRulesSection, { value });
		expect(getByTestId('path-rule-skip-verify-0')).toBeInTheDocument();
	});
});

// --- v2.44 — exact match and the path redirect -------------------
//
// The case this exists for: an application that serves nothing at its
// root. A whole-host redirect cannot express "/ goes to /admin/login"
// — the target is on the same host, so it would match its own target
// — and a "/" prefix rule has the same problem. The exact mode is
// what makes the rule possible at all.

describe('PathRulesSection — exact match and redirect (v2.44)', () => {
	it('carries the exact-match choice into the rule', async () => {
		const value: PathRule[] = [{ pathPrefix: '/' }];
		const { getByTestId } = render(PathRulesSection, { value });

		await fireEvent.click(getByTestId('path-rule-exact-toggle-0'));
		expect(value[0].matchExact).toBe(true);
	});

	it('adds and removes the redirect, with a temporary default', async () => {
		const value: PathRule[] = [{ pathPrefix: '/', matchExact: true }];
		const { getByTestId, queryByTestId } = render(PathRulesSection, { value });

		// Nothing is rendered until the rule carries a redirect. (The
		// block's own rendering is covered below, on a rule that has
		// one at mount: this harness passes a plain array, so nested
		// mutation does not re-render — the same reason every other
		// toggle test in this file asserts the data.)
		expect(queryByTestId('path-rule-redirect-0')).toBeNull();

		await fireEvent.click(getByTestId('path-rule-redirect-toggle-0'));
		// 302 by default: a landing path is a convenience an application
		// update can change, and a 301 cached by every visitor's browser
		// is remarkably hard to take back.
		expect(value[0].redirect).toEqual({ target: '', statusCode: 302 });

		await fireEvent.click(getByTestId('path-rule-redirect-toggle-0'));
		expect(value[0].redirect).toBeUndefined();
	});

	it('types the target into the rule', async () => {
		const value: PathRule[] = [
			{ pathPrefix: '/', matchExact: true, redirect: { target: '', statusCode: 302 } }
		];
		const { getByTestId } = render(PathRulesSection, { value });

		const input = getByTestId('path-rule-redirect-target-0') as HTMLInputElement;
		await fireEvent.input(input, { target: { value: '/admin/login' } });
		expect(value[0].redirect?.target).toBe('/admin/login');
	});

	it('warns that the target must fall outside the rule', () => {
		const value: PathRule[] = [
			{ pathPrefix: '/', matchExact: true, redirect: { target: '', statusCode: 302 } }
		];
		const { getByTestId } = render(PathRulesSection, { value });
		expect(getByTestId('path-rule-redirect-0').textContent).toMatch(/forever/i);
	});
});

// v2.56 — a stricter limit for one path.
//
// Reason to exist: a login or session endpoint wants a much tighter limit
// than the site around it, and raising the route's limit to protect one
// path would throttle every asset on the page to slow down one form.
describe('PathRulesSection — per-path rate limit', () => {
	it('is off until asked for, and seeds a usable pair when turned on', async () => {
		const rules: PathRule[] = [{ pathPrefix: '/api/v1/auth', ipFilter: { mode: 'off' } }];
		render(PathRulesSection, { value: rules });

		expect(screen.queryByTestId('path-rule-rate-events-0')).toBeNull();

		await fireEvent.click(screen.getByTestId('path-rule-rate-limit-toggle-0'));
		await tick();

		const events = screen.getByTestId('path-rule-rate-events-0') as HTMLInputElement;
		const window_ = screen.getByTestId('path-rule-rate-window-0') as HTMLInputElement;
		expect(events.value).toBe('10');
		expect(window_.value).toBe('1m');
	});

	it('clears the limit when switched back off', async () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/api/v1/auth', rateLimit: { events: 5, window: '1m' } }
		];
		render(PathRulesSection, { value: rules });

		expect(screen.getByTestId('path-rule-rate-events-0')).toBeTruthy();
		await fireEvent.click(screen.getByTestId('path-rule-rate-limit-toggle-0'));
		await tick();

		expect(rules[0].rateLimit).toBeUndefined();
		expect(screen.queryByTestId('path-rule-rate-events-0')).toBeNull();
	});

	// The operator has to be told this is NOT the route's limit, or they
	// will set it thinking they replaced one.
	it('says the route limit still applies and that counters are separate', async () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/api/v1/auth', rateLimit: { events: 5, window: '1m' } }
		];
		render(PathRulesSection, { value: rules });

		const hint = screen.getByText(/Counted separately from the route/i);
		expect(hint.textContent).toMatch(/still applies/i);
	});

	it('keeps each rule limit to its own rule', async () => {
		const rules: PathRule[] = [
			{ pathPrefix: '/api/v1/auth', rateLimit: { events: 5, window: '1m' } },
			{ pathPrefix: '/admin', ipFilter: { mode: 'off' } }
		];
		render(PathRulesSection, { value: rules });

		expect(screen.getByTestId('path-rule-rate-events-0')).toBeTruthy();
		expect(screen.queryByTestId('path-rule-rate-events-1')).toBeNull();
	});
});
