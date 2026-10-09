// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step §5.3 — Extended frontend test suite for the Routes page.
// Promoted to BLOCKING BEFORE THE `v0.6.0-step-j` tag during J.7
// (see docs/backlog-step-j.md). The J.3 Routes-page rewrite
// shipped without these tests; this file is the catch-up.
//
// Test taxonomy (mirrors §5.3 bullets):
//   - Upstream-pool repeater add / remove / last-row guard
//   - LB-selector visibility flip — preserved across flips
//   - Weight-column visibility flip — preserved across flips
//   - Health-check sub-form gating + state preservation
//   - Client-side validation rules (§5.2 — each rule)
//   - Error map round-trip (server 400 → errors[<field>])
//   - openEdit → submit-unchanged round-trip pinning all 9
//     HealthCheck fields (the J.3 review's manual audit, now
//     automated)
//
// Harness notes:
//   - `@testing-library/svelte` v5.3.1 + jsdom (Step F infra).
//   - The page imports the API client wrappers, not raw `fetch`;
//     we mock `$lib/api/client` + `$lib/api/settings` so no HTTP
//     traffic leaves the test process.
//   - The page uses Svelte 5 runes ($state/$effect/$derived) —
//     `render(Page)` mounts it normally; reactivity ticks run
//     synchronously enough for click → assertion sequences.
//   - jsdom does not run a real layout engine, but the form's
//     visibility logic is rune-driven ({#if lbSelectorVisible})
//     so it's testable by `queryByLabelText` returning null /
//     non-null rather than by computed style.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

// --- Mocks. vi.mock + the supporting references both go through
// vi.hoisted so they end up above the page import the bundler
// hoists into place. See client.test.ts for the same pattern
// (it works because that file deferred its import; we use the
// vi.hoisted form so we can keep the static `import Page from`
// at the top of this file).

const { toastMock, apiMock, settingsMock, authMock, externalCertsMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	// v2.19.0 external-certs SOCLE (Task 8) — the route form loads
	// the uploaded external-cert list when the operator picks the
	// "manual" cert source. Default to an empty list; the manual-cert
	// tests rebind list() to return covering / non-covering certs.
	externalCertsMock: {
		list: vi.fn()
	},
	apiMock: {
		listRoutes: vi.fn(),
		createRoute: vi.fn(),
		updateRoute: vi.fn(),
		deleteRoute: vi.fn(),
		// Step #R-PROXMOX-HTTPS-LOOP commit 3 — operator-
		// triggered upstream probe. Per-test rebinds the
		// resolve / reject to drive the result chip states.
		testUpstream: vi.fn(),
		testHealthCheck: vi.fn(),
		// v2.14.3 — route disable/enable dedicated endpoints.
		disableRoute: vi.fn(),
		enableRoute: vi.fn(),
		// Task 8/9 — route maintenance mode dedicated endpoints.
		enterMaintenance: vi.fn(),
		exitMaintenance: vi.fn(),
		// v2.38 — SecLang live check / guided → SecLang / WAF tester.
		validateSecLang: vi.fn(),
		previewCaddyfileImport: vi.fn(),
		importCaddyfile: vi.fn(),
		secLangFromGuided: vi.fn(),
		testRouteWaf: vi.fn()
	},
	settingsMock: {
		listDNSProviders: vi.fn()
	},
	// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT layer B. submitForm
	// reads auth.state to decide whether to suppress the
	// danger toast on lock-screen overlap; tests flip
	// authMock.state to drive the branch.
	authMock: {
		user: null as null | { id: string; role: 'admin' | 'viewer' },
		state: 'authenticated' as 'authenticated' | 'anonymous' | 'locked' | 'unknown',
		clear: vi.fn(),
		setLocked: vi.fn()
	}
}));

// $app/navigation: only reached if the page redirects (it doesn't
// here). Stub to avoid the SvelteKit runtime dependency.
vi.mock('$app/navigation', () => ({
	goto: vi.fn(),
	beforeNavigate: vi.fn()
}));

// $lib/stores/toast: pushToast is called on success / failure
// paths. We capture invocations so success-path tests can assert
// "Route updated" / "Route created" reached the toast layer.
vi.mock('$lib/stores/toast', () => ({
	pushToast: toastMock.pushToast
}));

// $lib/api/client: the Routes page calls listRoutes on mount and
// {create,update,delete}Route from the form submit. Each test
// rebinds the impl via the exported references below.
vi.mock('$lib/api/client', () => ({
	listRoutes: (...args: unknown[]) => apiMock.listRoutes(...args),
	createRoute: (...args: unknown[]) => apiMock.createRoute(...args),
	updateRoute: (...args: unknown[]) => apiMock.updateRoute(...args),
	deleteRoute: (...args: unknown[]) => apiMock.deleteRoute(...args),
	testUpstream: (...args: unknown[]) => apiMock.testUpstream(...args),
	testHealthCheck: (...args: unknown[]) => apiMock.testHealthCheck(...args),
	disableRoute: (...args: unknown[]) => apiMock.disableRoute(...args),
	enableRoute: (...args: unknown[]) => apiMock.enableRoute(...args),
	enterMaintenance: (...args: unknown[]) => apiMock.enterMaintenance(...args),
	exitMaintenance: (...args: unknown[]) => apiMock.exitMaintenance(...args),
	validateSecLang: (...args: unknown[]) => apiMock.validateSecLang(...args),
	previewCaddyfileImport: (...args: unknown[]) => apiMock.previewCaddyfileImport(...args),
	importCaddyfile: (...args: unknown[]) => apiMock.importCaddyfile(...args),
	secLangFromGuided: (...args: unknown[]) => apiMock.secLangFromGuided(...args),
	testRouteWaf: (...args: unknown[]) => apiMock.testRouteWaf(...args)
}));

// $lib/api/settings: listDNSProviders is called in openCreate /
// openEdit and on mount (via the DNS provider snapshot). Default
// to an empty list ("not configured"); tests touching the DNS-01
// path rebind for that scenario.
vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		listDNSProviders: () => settingsMock.listDNSProviders()
	}
}));

// $lib/api/external-certs: the Routes page loads the uploaded
// external-cert list to populate the "manual" cert-source picker.
// Default (beforeEach) resolves an empty list; manual-cert tests
// rebind externalCertsMock.list per-scenario.
// v2.28 — ASNPicker (geo filtering) searches through $lib/api/security.
const asnMock = vi.hoisted(() => ({
	searchASN: vi.fn(),
	namesASN: vi.fn()
}));

// The panel header metrics strip reads GET /metrics/route-summary
// on every panel open. Unmocked, the real wrapper would reach for
// `request` from the mocked client module, which does not export
// it — the page would swallow the throw and the strip would simply
// never render, so every strip test would pass for the wrong
// reason. Default is a rejection: the common case in this file is
// a test that does not care about the strip, and a rejection is
// what "no metrics here" has to look like.
const metricsMock = vi.hoisted(() => ({
	fetchRouteSummary: vi.fn()
}));
vi.mock('$lib/api/metrics', () => metricsMock);
vi.mock('$lib/api/security', () => asnMock);
vi.mock('$lib/api/external-certs', () => ({
	externalCertsApi: {
		list: (...args: unknown[]) => externalCertsMock.list(...args)
	}
}));

// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT layer B. The page now
// reads auth.state to decide whether to suppress the danger
// toast on session-locked-during-save. Mock the store so tests
// can flip the state.
vi.mock('$lib/stores/auth.svelte', () => ({
	auth: authMock
}));

import { ApiError } from '$lib/api/types';
import Page from './+page.svelte';
import type { Route } from '$lib/api/types';

// Helper: build a server Route response in the wire shape the
// page consumes (camelCase, healthCheck non-optional, etc.).
function makeRoute(overrides: Partial<Route> = {}): Route {
	return {
		id: 'route-fixture-1',
		host: 'fixture.example.com',
		upstreams: [{ url: 'http://127.0.0.1:9000', weight: 1 }],
		lbPolicy: 'round_robin',
		tlsEnabled: false,
		redirectToHttps: false,
		aliases: [],
		authMode: 'none',
		basicAuth: { username: '', passwordSet: false },
		forwardAuth: { providerName: '' },
		requestHeaders: {},
		responseHeaders: {},
		wafMode: 'off',
		acmeChallenge: 'http-01',
		healthCheck: {
			enabled: false,
			uri: '',
			method: '',
			interval: '',
			timeout: '',
			expectStatus: 0,
			expectBody: '',
			passes: 0,
			fails: 0
		},
		createdAt: '2026-05-25T10:00:00.000Z',
		updatedAt: '2026-05-25T10:00:00.000Z',
		// Critique 11 Pack A defaults — match the no-HC-configured
		// path (the gate forces unknown with healthy=0).
		aggregateStatus: 'unknown',
		healthyUpstreamCount: 0,
		totalUpstreamCount: 1,
		// W.5 — country-block default to the disabled state.
		// toResponse normalises a storage zero-value to
		// {mode:"off", countryList:[], statusCode:0}; tests
		// that need the gate active override via the partial
		// Route overrides.
		countryBlock: { mode: 'off', countryList: [], continents: [], asns: [], exceptions: { countries: [], asns: [] }, statusCode: 0 },
		// Step #R-PROXMOX-HTTPS-LOOP — strict default. Tests
		// exercising the disclosure / toggle override via the
		// partial Route overrides.
		insecureSkipVerify: false,
		upstreamTlsServerName: '',
		// Phase 4.5 — strict default; tests that exercise the
		// streaming toggle override via the partial Route
		// overrides parameter.
		uploadStreamingMode: false,
		// Step X.2 — strict default ; tests exercising the
		// disable-CRS toggle override via the partial Route
		// overrides parameter (zero-value false = CRS loaded).
		wafDisableCRS: false,
		// Step X Option (c) — strict default empty exclusion
		// list ; tests exercising the per-rule exclusion input
		// override via the partial Route overrides parameter.
		wafExcludeRules: [],
		// Step X Option (e) — strict default empty tag exclusion
		// list ; tests exercising the per-tag input override via
		// the partial Route overrides parameter.
		wafExcludeTags: [],
		wafTargetedExclusions: [],
		wafCustomRules: [],
		wafSecLang: '',
		// Step Q — strict default no rate limit ; tests
		// exercising the rate-limit section override via the
		// partial Route overrides parameter set a non-null
		// value to populate the form.
		rateLimit: null,
		...overrides
	};
}

beforeEach(() => {
	toastMock.pushToast.mockReset();
	apiMock.listRoutes.mockReset();
	apiMock.createRoute.mockReset();
	apiMock.updateRoute.mockReset();
	apiMock.deleteRoute.mockReset();
	apiMock.testUpstream.mockReset();
	apiMock.testHealthCheck.mockReset();
	apiMock.disableRoute.mockReset();
	apiMock.enableRoute.mockReset();
	apiMock.enterMaintenance.mockReset();
	apiMock.exitMaintenance.mockReset();
	settingsMock.listDNSProviders.mockReset();
	externalCertsMock.list.mockReset();
	metricsMock.fetchRouteSummary.mockReset();
	// Day 13 — auth store defaults: every test starts in
	// authenticated state. Tests exercising the lock-screen-
	// during-save branch flip authMock.state = 'locked' before
	// the submit fires.
	authMock.state = 'authenticated';
	authMock.clear.mockReset();
	authMock.setLocked.mockReset();

	// Sensible defaults so tests that don't override see an empty
	// page (no routes) and a not-configured DNS provider (empty
	// collection → dnsProviderConfigured=false).
	apiMock.listRoutes.mockResolvedValue([]);
	settingsMock.listDNSProviders.mockResolvedValue([]);
	externalCertsMock.list.mockResolvedValue([]);
	metricsMock.fetchRouteSummary.mockRejectedValue(new Error('no metrics in this test'));
});

// Opens the create form (clicks "+ Add route") and returns after
// the modal is mounted. Tests that don't need the empty-state CTA
// path go through this helper.
async function openCreateForm(): Promise<void> {
	// Two "+ Add route" buttons exist in the markup: PageHeader's
	// actions snippet ("+ Add route") and the empty-state CTA
	// ("+ Add your first route"). When routes is empty (the
	// default in beforeEach), only the empty-state CTA renders the
	// "+ Add your first route" label; the header button reads
	// "+ Add route". Either opens the modal; pick the header one
	// so the test works whether the page has data or not.
	const btn = await screen.findByRole('button', { name: /^\+\s*Add route$/i });
	await userEvent.click(btn);
	await tick();
}

// Reaches into the modal: returns the "Host" Input (label match
// is the deterministic anchor — the input gets an id assigned at
// render so role=textbox + accessible name is the right query).
function hostInput(): HTMLInputElement {
	return screen.getByLabelText('Host') as HTMLInputElement;
}

// Returns the LB-policy <select>. Returns null when the selector
// is hidden (pool size 1 → {#if lbSelectorVisible} suppresses it).
function lbSelect(): HTMLSelectElement | null {
	return screen.queryByLabelText('Load balancing') as HTMLSelectElement | null;
}

// Returns all upstream URL inputs in repeater order. They share
// the placeholder text but no label; pick by placeholder.
function upstreamURLInputs(): HTMLInputElement[] {
	return screen.getAllByPlaceholderText('http://127.0.0.1:8080') as HTMLInputElement[];
}

// v2.41 — the WAF mode is a segmented control (ModeSelector), not a
// <select>: pick a mode by clicking its segment.
async function setWafMode(mode: 'off' | 'detect' | 'block'): Promise<void> {
	await userEvent.click(screen.getByTestId(`route-waf-mode-${mode}`));
	await tick();
}

// --- 1. Upstream-pool repeater ------------------------------------

describe('Routes page — upstream-pool repeater', () => {
	it('starts with one upstream row on a fresh create', async () => {
		render(Page);
		await openCreateForm();
		expect(upstreamURLInputs()).toHaveLength(1);
	});

	it('adds a row when "+ Add upstream" is clicked', async () => {
		render(Page);
		await openCreateForm();
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		expect(upstreamURLInputs()).toHaveLength(2);
		await userEvent.click(addBtn);
		await tick();
		expect(upstreamURLInputs()).toHaveLength(3);
	});

	it('removes a row when "×" is clicked on a non-last row', async () => {
		render(Page);
		await openCreateForm();
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		await userEvent.click(addBtn);
		await tick();
		expect(upstreamURLInputs()).toHaveLength(3);

		// Type identifying URLs so we can verify which row got removed.
		const inputs = upstreamURLInputs();
		await userEvent.type(inputs[0], 'http://a.test');
		await userEvent.type(inputs[1], 'http://b.test');
		await userEvent.type(inputs[2], 'http://c.test');

		// Remove the middle row. The × buttons in the upstream rows
		// are the ones in the same flex container as the URL Input;
		// by role name they all match /^×$/, so pick by index.
		const removeButtons = screen
			.getAllByRole('button', { name: '×' })
			// Aliases also render × buttons in this test — filter to
			// the upstream removers by their proximity to an upstream URL input.
			.filter((b) => {
				const row = b.closest('.flex.items-start');
				return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
			});
		expect(removeButtons).toHaveLength(3);
		await userEvent.click(removeButtons[1]);
		await tick();

		const remaining = upstreamURLInputs();
		expect(remaining).toHaveLength(2);
		expect(remaining[0].value).toBe('http://a.test');
		expect(remaining[1].value).toBe('http://c.test');
	});

	it('disables the remove "×" button when only one row remains (last-row guard)', async () => {
		render(Page);
		await openCreateForm();
		expect(upstreamURLInputs()).toHaveLength(1);
		// Pick the upstream's × — same proximity heuristic.
		const removeBtn = screen
			.getAllByRole('button', { name: '×' })
			.find((b) => {
				const row = b.closest('.flex.items-start');
				return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
			});
		expect(removeBtn).toBeDefined();
		// `disabled` attribute on the button (the page passes
		// disabled={formData.upstreams.length <= 1} to <Button>).
		expect(removeBtn).toBeDisabled();
	});
});

// --- 1b. Aliases layout -------------------------------------------

describe('Routes page — aliases layout', () => {
	it('lays alias inputs out in an auto-fit grid (not a vertical stack)', async () => {
		render(Page);
		await openCreateForm();
		const addAlias = screen.getByRole('button', { name: /\+\s*Add alias/i });
		await userEvent.click(addAlias);
		await userEvent.click(addAlias);
		await tick();
		// two alias inputs now present (by their placeholder)
		expect(screen.getAllByPlaceholderText('alt.example.com')).toHaveLength(2);
		// and they live inside the auto-fit grid container
		const grid = screen.getByTestId('alias-grid');
		expect(grid.className).toContain('grid-cols-[repeat(auto-fit,minmax(200px,1fr))]');
	});
});

// --- 2. LB-selector visibility flip -------------------------------

describe('Routes page — LB selector visibility', () => {
	it('is hidden with one upstream, shown with two, preserves state across flips', async () => {
		render(Page);
		await openCreateForm();
		// One upstream → hidden.
		expect(lbSelect()).toBeNull();

		// Add second upstream → shown, default round_robin.
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		let sel = lbSelect();
		expect(sel).not.toBeNull();
		expect(sel!.value).toBe('round_robin');

		// Change the LB policy.
		await userEvent.selectOptions(sel!, 'least_conn');
		await tick();
		expect(lbSelect()!.value).toBe('least_conn');

		// Remove the second upstream → selector hides again.
		const removeBtn = screen
			.getAllByRole('button', { name: '×' })
			.find((b) => {
				const row = b.closest('.flex.items-start');
				return (
					row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null &&
					!(b as HTMLButtonElement).disabled
				);
			});
		await userEvent.click(removeBtn!);
		await tick();
		expect(lbSelect()).toBeNull();

		// Re-add a second upstream → selector reappears with the
		// previously-chosen policy preserved (formData.lbPolicy
		// was never reset).
		await userEvent.click(addBtn);
		await tick();
		sel = lbSelect();
		expect(sel).not.toBeNull();
		expect(sel!.value).toBe('least_conn');
	});
});

// --- 3. Weight column visibility flip -----------------------------

describe('Routes page — weight column visibility', () => {
	// Returns only the upstream WEIGHT inputs (not the HC passes /
	// fails inputs, which also use placeholder="1"). Identifies
	// them by proximity to an upstream URL input inside the same
	// flex container.
	function weightInputs(): HTMLInputElement[] {
		return Array.from(
			document.querySelectorAll<HTMLInputElement>('input[type="number"][placeholder="1"]')
		).filter((el) => {
			const row = el.closest('.flex.items-start');
			return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
		});
	}

	it('is hidden for round_robin, shown for weighted_round_robin, preserves values across flips', async () => {
		render(Page);
		await openCreateForm();

		// Need a 2-upstream pool to see the LB selector.
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();

		// Weight column hidden for the default round_robin.
		expect(weightInputs().length).toBe(0);

		// Flip to weighted_round_robin.
		await userEvent.selectOptions(lbSelect()!, 'weighted_round_robin');
		await tick();

		// Two weight inputs now (one per upstream row).
		let weights = weightInputs();
		expect(weights.length).toBe(2);

		// Set distinct values.
		await userEvent.clear(weights[0]);
		await userEvent.type(weights[0], '5');
		await userEvent.clear(weights[1]);
		await userEvent.type(weights[1], '7');
		await tick();
		weights = weightInputs();
		expect(weights[0].value).toBe('5');
		expect(weights[1].value).toBe('7');

		// Flip back to round_robin → column hides.
		await userEvent.selectOptions(lbSelect()!, 'round_robin');
		await tick();
		expect(weightInputs().length).toBe(0);

		// Flip back to weighted_round_robin → column reappears
		// with the values preserved (formData.upstreams[i].weight
		// was never touched).
		await userEvent.selectOptions(lbSelect()!, 'weighted_round_robin');
		await tick();
		weights = weightInputs();
		expect(weights.length).toBe(2);
		expect(weights[0].value).toBe('5');
		expect(weights[1].value).toBe('7');
	});
});

// --- 4. Health-check sub-form gating + state preservation ---------

describe('Routes page — health-check gating', () => {
	it('sub-fields are disabled when enabled=false, enabled when true, state preserved across the toggle', async () => {
		render(Page);
		await openCreateForm();

		// HC URI input by id (the field is `<input id="hc-uri">`).
		const uri = document.getElementById('hc-uri') as HTMLInputElement;
		const method = document.getElementById('hc-method') as HTMLSelectElement;
		const passes = document.getElementById('hc-passes') as HTMLInputElement;
		const fails = document.getElementById('hc-fails') as HTMLInputElement;
		const expectStatus = document.getElementById('hc-expect-status') as HTMLInputElement;
		expect(uri).not.toBeNull();
		expect(method).not.toBeNull();

		// Initial: enabled=false → every sub-field disabled.
		expect(uri.disabled).toBe(true);
		expect(method.disabled).toBe(true);
		expect(passes.disabled).toBe(true);
		expect(fails.disabled).toBe(true);
		expect(expectStatus.disabled).toBe(true);

		// Flip the HC checkbox on. The Checkbox component hides the
		// native input visually; click the label text.
		const hcCheckbox = screen.getByLabelText('Enable active health checks') as HTMLInputElement;
		await userEvent.click(hcCheckbox);
		await tick();

		// Sub-fields now enabled.
		expect(uri.disabled).toBe(false);
		expect(method.disabled).toBe(false);
		expect(passes.disabled).toBe(false);

		// Type identifying values.
		await userEvent.type(uri, '/probe');
		await userEvent.selectOptions(method, 'HEAD');
		await tick();
		expect(uri.value).toBe('/probe');
		expect(method.value).toBe('HEAD');

		// Toggle OFF.
		await userEvent.click(hcCheckbox);
		await tick();
		expect(uri.disabled).toBe(true);
		expect(method.disabled).toBe(true);
		// State preserved (the page never clears the sub-fields).
		expect(uri.value).toBe('/probe');
		expect(method.value).toBe('HEAD');

		// Toggle ON again — values still there, fields editable.
		await userEvent.click(hcCheckbox);
		await tick();
		expect(uri.disabled).toBe(false);
		expect(uri.value).toBe('/probe');
		expect(method.value).toBe('HEAD');
	});
});

// --- 5. Client-side validation rules ------------------------------
//
// The submit path runs validateBeforeSubmit() which writes the
// `errors` map keyed by field path. Each failing rule below
// triggers a submit and asserts the matching error message
// surfaces. We never let the submit reach the API mocks — when
// validation rejects, no createRoute() call is made.

describe('Routes page — validation rules (§5.2)', () => {
	async function submitForm() {
		// The submit button is the only "Save" / "Create" button
		// inside the Modal; the form's onsubmit handler runs the
		// validation. fireEvent.submit on the form keeps the
		// preventDefault contract.
		const form = document.querySelector('form');
		expect(form).not.toBeNull();
		await fireEvent.submit(form!);
		await tick();
	}

	it('rejects empty host', async () => {
		render(Page);
		await openCreateForm();
		await submitForm();
		// The Input renders the error under the field as a <p>.
		// validateBeforeSubmit writes errors['host'] = "Host must
		// not be empty".
		expect(screen.getByText('Host must not be empty')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects malformed upstream URL (missing http:// scheme)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'just-a-host');
		await submitForm();
		// "URL must use http or https" comes from the URL parse +
		// protocol check in validateBeforeSubmit.
		expect(
			screen.getByText(/URL must use http or https|URL is malformed/i)
		).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects HC enabled with empty URI', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const hcCheckbox = screen.getByLabelText('Enable active health checks');
		await userEvent.click(hcCheckbox);
		await tick();
		await submitForm();
		expect(screen.getByText('URI is required')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	// A refused field inside a closed section used to stay out of
	// sight: Save produced a toast and nothing else on screen.
	describe('a refused save brings the error into view', () => {
		let scroll: ReturnType<typeof vi.fn>;
		beforeEach(() => {
			// jsdom has no scrollIntoView; the page calls it optionally.
			scroll = vi.fn();
			Element.prototype.scrollIntoView = scroll as unknown as Element['scrollIntoView'];
		});
		afterEach(() => {
			delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
		});

		it('opens and marks the section holding the error, and scrolls to it', async () => {
			render(Page);
			await openCreateForm();
			await userEvent.type(hostInput(), 'h.test');
			await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
			await userEvent.click(screen.getByLabelText('Enable active health checks'));
			const section = screen.getByTestId('section-health-check') as HTMLDetailsElement;
			section.open = false;
			await tick();

			await submitForm();

			await vi.waitFor(() => expect(scroll).toHaveBeenCalled());
			expect(section.open).toBe(true);
			expect(section.hasAttribute('data-invalid')).toBe(true);
			expect(screen.getByTestId('section-health-check-invalid')).toBeInTheDocument();
			expect(scroll.mock.contexts[0]).toHaveTextContent('URI is required');
			// Sections without an error carry no marker.
			expect(screen.queryByTestId('section-essentials-invalid')).toBeNull();
		});

		it('focuses the refused field when the error is on the field itself', async () => {
			render(Page);
			await openCreateForm();
			await submitForm();

			await vi.waitFor(() => expect(scroll).toHaveBeenCalled());
			expect(screen.getByTestId('section-essentials-invalid')).toBeInTheDocument();
			expect(document.activeElement).toBe(hostInput());
		});

		it('repeats a form-level refusal next to Save', async () => {
			apiMock.createRoute.mockRejectedValue(
				new ApiError('something the form cannot place', 400, 'validation')
			);
			render(Page);
			await openCreateForm();
			await userEvent.type(hostInput(), 'h.test');
			await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

			await submitForm();

			await vi.waitFor(() =>
				expect(screen.getByTestId('form-error-footer')).toHaveTextContent(
					'something the form cannot place'
				)
			);
		});
	});

	it('rejects HC URI that does not start with /', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, 'probe');
		await submitForm();
		expect(screen.getByText('URI must start with /')).toBeInTheDocument();
	});

	it('rejects HC interval with malformed duration shape', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		// Interval Input has label "Interval" so we can query by label.
		await userEvent.type(screen.getByLabelText('Interval'), 'nope');
		await submitForm();
		expect(
			screen.getByText('Interval must be a duration (e.g. 30s)')
		).toBeInTheDocument();
	});

	it('rejects HC timeout equal to interval (timeout < interval rule)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		await userEvent.type(screen.getByLabelText('Interval'), '30s');
		await userEvent.type(screen.getByLabelText('Timeout'), '30s');
		await submitForm();
		expect(
			screen.getByText('Timeout must be less than interval')
		).toBeInTheDocument();
	});

	it('rejects HC expectStatus that is neither a class nor a code', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const expectStatusInput = document.getElementById('hc-expect-status') as HTMLInputElement;
		await userEvent.clear(expectStatusInput);
		await userEvent.type(expectStatusInput, '700');
		await submitForm();
		expect(
			screen.getByText(/Expected status must be 0, a class from 1 to 5/)
		).toBeInTheDocument();
	});

	// v2.55 — Caddy accepts a status CLASS (caddyhttp.StatusCodeMatches),
	// and the form used to refuse it, so an app answering 302 on / had to
	// be pinned to that one code and went unhealthy the day it sent 301.
	it('accepts a status class in HC expectStatus', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const expectStatusInput = document.getElementById('hc-expect-status') as HTMLInputElement;
		await userEvent.clear(expectStatusInput);
		await userEvent.type(expectStatusInput, '3');
		await submitForm();
		expect(
			screen.queryByText(/Expected status must be/),
			'3 means "any 3xx" to Caddy and must not be refused'
		).toBeNull();
	});

	it('rejects HC expectBody that is not a valid regex', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		await userEvent.type(screen.getByLabelText('Expected body (regex)'), '(unbalanced');
		await submitForm();
		expect(
			screen.getByText('Expected body is not a valid regex')
		).toBeInTheDocument();
	});

	// §5.1 / J.1 weight rule. The client check is gated on
	// `weightVisible` (only fires when the weighted_round_robin
	// policy is selected) — so the test must arrange both a
	// 2-upstream pool AND that policy before typing a < 1 weight.
	// The HTML5 `min="1"` attribute is a soft hint that jsdom (and
	// most browsers prior to form-submit) do not enforce on input,
	// so a user typing "0" in the field still reaches the JS
	// validator, which is what we pin here.
	it('rejects upstream weight < 1 when weighted_round_robin is selected', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		// Add a second upstream so the LB selector + weight column
		// become reachable.
		await userEvent.click(screen.getByRole('button', { name: /\+\s*Add upstream/i }));
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://127.0.0.1:9001');
		await userEvent.selectOptions(
			screen.getByLabelText('Load balancing') as HTMLSelectElement,
			'weighted_round_robin'
		);
		await tick();

		// Reach the second weight input (the first carries the
		// default 1 — leave it valid so the rejection names the
		// row we deliberately broke).
		const weightInputs = Array.from(
			document.querySelectorAll<HTMLInputElement>('input[type="number"][placeholder="1"]')
		).filter((el) => {
			const row = el.closest('.flex.items-start');
			return row?.querySelector('input[placeholder="http://127.0.0.1:8080"]') != null;
		});
		expect(weightInputs.length).toBe(2);
		await userEvent.clear(weightInputs[1]);
		await userEvent.type(weightInputs[1], '0');
		await submitForm();
		expect(screen.getByText('Weight must be >= 1')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	// §5.2 #9 / J.2 passes rule. The client relaxes the server's
	// `>= 1` to `>= 0` (intentional — passes=0 means "use the
	// server default", per the inline comment in
	// validateBeforeSubmit). Only NEGATIVE values are rejected
	// client-side; the HTML5 min="1" hint is not enforced before
	// submit, so the test types a negative value to reach the JS
	// rule.
	it('rejects negative HC passes', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const passesInput = document.getElementById('hc-passes') as HTMLInputElement;
		await userEvent.clear(passesInput);
		// userEvent.type with a leading minus on a number input
		// produces a negative numeric value in the bound state.
		await userEvent.type(passesInput, '-2');
		await submitForm();
		expect(screen.getByText('Passes must be >= 1')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	// §5.2 #10 / J.2 fails rule. Same shape as the passes rule
	// above. Both negative-value tests share the same client-side
	// "0 ⇒ use default, < 0 ⇒ reject" semantic; the server enforces
	// the strict >= 1 boundary on top.
	it('rejects negative HC fails', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		const failsInput = document.getElementById('hc-fails') as HTMLInputElement;
		await userEvent.clear(failsInput);
		await userEvent.type(failsInput, '-3');
		await submitForm();
		expect(screen.getByText('Fails must be >= 1')).toBeInTheDocument();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});
});

// --- 6. Error map round-trip (server 400 → errors[<field>]) ------
//
// On a successful client-validate-pass but a server 400, the
// page's submitForm catches the ApiError, runs fieldFromMessage
// on the message, and writes the error onto errors[field]. We
// inject a controlled ApiError on createRoute and assert the
// right field renders the message.

describe('Routes page — server error map round-trip', () => {
	it('routes "upstreams[0].weight must be >= 1" to errors[upstreams[0].weight]', async () => {
		// Two-upstream pool with weighted_round_robin so the weight
		// inputs are visible AND the rejection message has a real
		// target field to render under.
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByRole('button', { name: /\+\s*Add upstream/i }));
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://127.0.0.1:9001');
		await userEvent.selectOptions(lbSelect()!, 'weighted_round_robin');
		await tick();

		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('upstreams[0].weight must be >= 1', 400, 'validation')
		);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick(); // submitForm awaits the API call resolution

		// fieldFromMessage maps the message to errors['upstreams[0].weight'];
		// the markup renders it under the second weight input.
		expect(
			screen.getByText('upstreams[0].weight must be >= 1')
		).toBeInTheDocument();
	});

	it('routes "host must be a valid hostname" to errors[host]', async () => {
		render(Page);
		await openCreateForm();
		// The client passes the empty-host gate first; supply a value
		// that the CLIENT accepts (non-empty) but trigger the server
		// rejection by mocking it.
		await userEvent.type(hostInput(), 'something');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('host must be a valid hostname', 400, 'validation')
		);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// Assert against the Input's <p> error element. By
		// fieldFromMessage's "host " prefix rule, the message is
		// keyed to errors['host'].
		expect(
			screen.getByText('host must be a valid hostname')
		).toBeInTheDocument();
	});

	it('routes "healthCheck.timeout must be strictly less than interval" to errors[healthCheck.timeout]', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'h.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/p');
		// Client-side rule would reject equal durations, so supply
		// values the CLIENT accepts (timeout < interval by string,
		// but the server semantics catches "1m vs 60s"). We're
		// asserting the server-rejection wiring, not the rule.
		await userEvent.type(screen.getByLabelText('Interval'), '60s');
		await userEvent.type(screen.getByLabelText('Timeout'), '5s');

		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError(
				'healthCheck.timeout must be strictly less than interval',
				400,
				'validation'
			)
		);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(
			screen.getByText('healthCheck.timeout must be strictly less than interval')
		).toBeInTheDocument();
	});
});

// --- 7. openEdit round-trip (THE pivot test) ----------------------
//
// Spec §5.3 / J.3 review: a route with a complete HealthCheck
// (all 9 fields in non-default values) must round-trip through
// openEdit → submit-unchanged → updateRoute payload without
// losing any field. Failure mode being guarded: a regression
// where openEdit forgets to copy one of the 9 fields would let
// the form keep the zero value, the user wouldn't notice (the
// form has been touched: healthCheckTouched=true so the block
// ships in the payload), and the storage would silently overwrite
// the field with the form's zero. This test pins the property.

describe('Routes page — openEdit round-trip preserves HealthCheck', () => {
	it('all 9 HealthCheck fields survive openEdit → submit-unchanged → updateRoute payload', async () => {
		// Distinct non-default values per field so a regression
		// that swaps two fields would also be caught.
		const seededHC = {
			enabled: true,
			uri: '/probe-path',
			method: 'HEAD' as const,
			interval: '12s',
			timeout: '3s',
			expectStatus: 204,
			expectBody: '^pong$',
			passes: 4,
			fails: 7
		};
		const seededRoute = makeRoute({
			id: 'edit-fixture',
			host: 'edit.example.com',
			upstreams: [{ url: 'http://127.0.0.1:9100', weight: 1 }],
			healthCheck: seededHC
		});
		apiMock.listRoutes.mockResolvedValue([seededRoute]);
		// updateRoute returns the (unchanged) route; the page only
		// reads it via toResponse-equivalent for the toast/redirect.
		apiMock.updateRoute.mockResolvedValue(seededRoute);

		render(Page);

		// Wait for listRoutes to settle and the table to render the
		// row. Polish round 2026-06-06 dropped the per-row "Edit"
		// button — the whole <tr> is the affordance now, so we
		// open the edit panel by clicking the row itself. Find by
		// the host cell text and walk up to the row.
		const hostCell = await screen.findByText('edit.example.com');
		const row = hostCell.closest('tr')!;

		// IMPORTANT: this test is meaningful only if the HC sub-form
		// is actually mounted by openEdit. We assert against the
		// payload sent to updateRoute, NOT against the DOM-typed
		// values — the test must catch a regression where openEdit
		// silently drops a field. If we re-read each field from the
		// DOM and used it to build the payload, a missing-field
		// regression would be invisible. We do NOT do that.
		await userEvent.click(row);
		await tick();

		// Mark HC touched (the wrapper onclick / oninput in the
		// sub-form does this when the user interacts; the test
		// simulates a no-edit save where the user opened the edit,
		// looked at the form, then clicked Save).
		//
		// The PUT path on the page omits the HC block if
		// healthCheckTouched is false. To pin the round-trip
		// property of openEdit→submit specifically, we MUST set
		// touched=true; otherwise we're testing the "preserve
		// previous on omit" path which is exercised server-side,
		// not the openEdit field-by-field copy.
		//
		// We trigger touched by re-typing the same URI value back
		// into itself — this fires oninput → markHealthCheckTouched
		// without changing any value. (A no-op click on the summary
		// also flips it, but we want the touched flag without
		// risking a checkbox toggle.)
		const uri = document.getElementById('hc-uri') as HTMLInputElement;
		expect(uri.value).toBe(seededHC.uri); // openEdit copied it
		// Trigger oninput by dispatching an input event that does
		// not change the value (avoids userEvent.clear() which would
		// blank the field before the round-trip is verified).
		uri.dispatchEvent(new Event('input', { bubbles: true }));
		await tick();

		// Submit.
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// updateRoute must have been called exactly once.
		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const [id, payload] = apiMock.updateRoute.mock.calls[0];
		expect(id).toBe('edit-fixture');

		// THE assertion: every HC field on the payload matches the
		// seeded value byte for byte. If openEdit drops a field, the
		// formData zero-value would land in the payload and one of
		// these assertions would fail with a clear "got 0 / '' /
		// false" diff.
		expect(payload.healthCheck).toBeDefined();
		expect(payload.healthCheck.enabled).toBe(seededHC.enabled);
		expect(payload.healthCheck.uri).toBe(seededHC.uri);
		expect(payload.healthCheck.method).toBe(seededHC.method);
		expect(payload.healthCheck.interval).toBe(seededHC.interval);
		expect(payload.healthCheck.timeout).toBe(seededHC.timeout);
		expect(payload.healthCheck.expectStatus).toBe(seededHC.expectStatus);
		expect(payload.healthCheck.expectBody).toBe(seededHC.expectBody);
		expect(payload.healthCheck.passes).toBe(seededHC.passes);
		expect(payload.healthCheck.fails).toBe(seededHC.fails);
	});
});

// --- 2026-06-25 — double-PUT guard (operator empirical report) -----
//
// Empirical observation : journalctl on the operator's homelab
// showed 2 PUT /api/v1/routes/X calls 47ms apart for a single
// Save click. The 2nd PUT carried "config is unchanged" in the
// Caddy reload log (idempotent) but still consumed a server
// round-trip + grace-period cycle on the 1st PUT.
//
// v2.9.6 added `disabled={submitting}` on the Save button but the
// double-PUT persisted post-deploy. Root cause analysis : Svelte
// 5 reactivity → DOM commit window has a microtask gap where a
// queued 2nd click event (OS-level double-click setting, mouse
// hardware bounce, accessibility tool) can pass through before
// the disabled attribute actually lands on the <button>.
//
// v2.9.7 adds a `if (submitting) return` guard at the start of
// submitForm() itself — bulletproof against any click event
// volume, regardless of DOM commit timing.
describe('Routes page — submitForm double-PUT guard', () => {
	it('fires updateRoute exactly once when the form is submitted twice in rapid succession', async () => {
		const seeded = makeRoute({
			id: 'guard-fixture',
			host: 'guard.example.com',
			upstreams: [{ url: 'http://10.0.0.1:80', weight: 1 }],
			healthCheck: {
				enabled: true,
				uri: '/healthz',
				method: 'GET',
				interval: '30s',
				timeout: '5s',
				expectStatus: 0,
				expectBody: '',
				passes: 1,
				fails: 1
			}
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);

		// Slow the updateRoute response so the 2nd submit fires
		// while the 1st is still in flight — mirrors the empirical
		// 47ms-apart double-PUT the operator captured.
		let resolveUpdate: (r: Route) => void;
		apiMock.updateRoute.mockReturnValue(
			new Promise<Route>((resolve) => {
				resolveUpdate = resolve;
			})
		);

		render(Page);

		// Open edit panel for the route.
		const row = await screen.findByText('guard.example.com');
		await userEvent.click(row.closest('tr')!);
		await tick();

		// Fire submit twice within the same microtask. tick() is
		// NOT called between them — that's the point. We mirror
		// the OS-level double-click event delivery where both
		// clicks land before Svelte's reactivity commits the
		// disabled attribute.
		const form = document.querySelector('form')!;
		fireEvent.submit(form);
		fireEvent.submit(form);
		await tick();
		await tick();

		// Now resolve the in-flight updateRoute so the test cleans up.
		resolveUpdate!(seeded);
		await tick();
		await tick();

		// THE assertion : exactly ONE updateRoute call, no matter
		// how many submit events fired before the resolve.
		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
	});
});

// --- C11 Pack A — aggregate health badge + filter tabs --------------
//
// Operator's Pack A smoke caught the original "static green dot"
// mendacity; the polish round (this commit, amended a8a4723)
// replaced the dot with an explicit uppercase Badge. These tests
// pin the badge → variant mapping AND the segmented-tab filter
// semantics so a future regression on either gets caught
// immediately.
describe('Routes page — aggregate health badges + filter tabs', () => {
	const mkRoute = (
		id: string,
		host: string,
		aggregateStatus: Route['aggregateStatus'],
		healthy: number,
		total: number,
	): Route =>
		makeRoute({
			id,
			host,
			aggregateStatus,
			healthyUpstreamCount: healthy,
			totalUpstreamCount: total,
			upstreams: Array.from({ length: total }, (_, i) => ({
				url: `http://10.0.0.${i + 1}:80`,
				weight: 1,
			})),
		});

	it('renders one badge per route with the label matching aggregateStatus', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-h', 'healthy.example', 'healthy', 1, 1),
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			mkRoute('r-down', 'down.example', 'down', 0, 1),
			mkRoute('r-u', 'unknown.example', 'unknown', 0, 1),
		]);
		render(Page);

		expect(await screen.findByText('HEALTHY')).toBeInTheDocument();
		expect(screen.getByText('DEGRADED')).toBeInTheDocument();
		expect(screen.getByText('DOWN')).toBeInTheDocument();
		expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
	});

	it('Healthy tab filters to aggregateStatus === healthy only', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-h', 'healthy.example', 'healthy', 1, 1),
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			mkRoute('r-u', 'unknown.example', 'unknown', 0, 1),
		]);
		render(Page);

		// Wait for the initial render — the Healthy badge being
		// in the DOM is a reliable readiness signal that listRoutes
		// resolved.
		await screen.findByText('HEALTHY');

		await userEvent.click(screen.getByRole('button', { name: 'Healthy' }));
		await tick();

		// Strict: unknown must NOT pass the Healthy filter. The
		// gray-≠-green contract from the C13 Topology gate.
		expect(screen.getByText('HEALTHY')).toBeInTheDocument();
		expect(screen.queryByText('DEGRADED')).not.toBeInTheDocument();
		expect(screen.queryByText('UNKNOWN')).not.toBeInTheDocument();
	});

	it('renders the inactive-HC badge for not_monitored aggregateStatus (2026-06-25 UX split)', async () => {
		// Pre-2026-06-25 : routes with HealthCheck.Enabled=false
		// rendered the same "UNKNOWN" badge as HC-enabled-but-warm-up
		// routes, making the operator unable to tell whether the
		// gray badge meant "I chose not to monitor" or "I monitor
		// but I don't know yet". The split adds 'not_monitored' as
		// a distinct aggregateStatus with its own label.
		//
		// v2.59 — the label was the hard-coded French "HC INACTIF",
		// and this test asserted it WHILE RUNNING IN ENGLISH, which
		// is how a French string in the English locale survived four
		// months with a test covering it. The label now goes through
		// i18n; this asserts the English one.
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-nm', 'unmonitored.example', 'not_monitored', 0, 1),
			mkRoute('r-u', 'warmup.example', 'unknown', 0, 1),
		]);
		render(Page);

		expect(await screen.findByText('HC INACTIVE')).toBeInTheDocument();
		expect(screen.getByText('UNKNOWN')).toBeInTheDocument();
	});

	it('Alerts tab filters to degraded OR down; unknown excluded', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mkRoute('r-h', 'healthy.example', 'healthy', 1, 1),
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			mkRoute('r-down', 'down.example', 'down', 0, 1),
			mkRoute('r-u', 'unknown.example', 'unknown', 0, 1),
		]);
		render(Page);

		await screen.findByText('HEALTHY');

		await userEvent.click(screen.getByRole('button', { name: 'Alerts' }));
		await tick();

		expect(screen.getByText('DEGRADED')).toBeInTheDocument();
		expect(screen.getByText('DOWN')).toBeInTheDocument();
		expect(screen.queryByText('HEALTHY')).not.toBeInTheDocument();
		// "Unknown ≠ alert" — operator can't get false-positive
		// noise from warm-up routes in the alerts list.
		expect(screen.queryByText('UNKNOWN')).not.toBeInTheDocument();
	});

	it('multi-upstream "N/M sains" appears only for routes with a verdict', async () => {
		apiMock.listRoutes.mockResolvedValue([
			// Two upstreams, degraded → counter visible.
			mkRoute('r-d', 'degraded.example', 'degraded', 1, 2),
			// Single upstream, healthy → counter hidden (noise).
			mkRoute('r-h1', 'single.example', 'healthy', 1, 1),
			// Two upstreams, unknown → counter hidden (no verdict).
			mkRoute('r-u2', 'warmup.example', 'unknown', 0, 2),
		]);
		render(Page);

		await screen.findByText('DEGRADED');

		// v2.9.14 i18n Phase 3 batch 1 — counter copy migrated
		// from hardcoded FR "N/M sains" to t('routes.list.healthyCounter')
		// which resolves to "N/M healthy" in EN (test default boot).
		expect(screen.getByText(/1\/2 healthy/)).toBeInTheDocument();
		expect(screen.queryByText(/0\/2 healthy/)).not.toBeInTheDocument();
		expect(screen.queryByText(/1\/1 healthy/)).not.toBeInTheDocument();
	});
});

// --- C11 Pack A polish — table-row affordance ---------------------
//
// Operator's smoke after the badge polish caught two more UX
// gaps: (1) the per-row "Edit" button was redundant noise next
// to the whole-row click target, and (2) the selected row had
// no visual indication, which is a real footgun when multiple
// routes share similar URLs (operator's test2 + arenet-test
// both point at 192.168.99.10:8080). This commit drops the
// button entirely and adds a route-row-selected class on the
// active row. These tests pin the new contract.
describe('Routes page — table row interaction affordance', () => {
	const mk = (id: string, host: string): Route =>
		makeRoute({ id, host, upstreams: [{ url: 'http://127.0.0.1:9000', weight: 1 }] });

	it('renders no per-row "Edit" button (whole-row affordance instead)', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mk('r-a', 'alpha.example'),
			mk('r-b', 'beta.example'),
		]);
		render(Page);

		// Wait for the rows to render.
		await screen.findByText('alpha.example');

		// No button anywhere in the document with the accessible
		// name "Edit" — the polish round explicitly removed it.
		expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
	});

	it('clicking a row opens the edit panel', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;

		// Before click: the edit-panel form is not mounted. The
		// most stable anchor is the host input — it's only in the
		// DOM when the form is open. (createForm path also mounts
		// it, but here we haven't opened the create form either.)
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();

		await userEvent.click(row);
		await tick();

		// After click: the edit form is mounted and pre-populated
		// with the clicked route's host.
		const hostInput = screen.getByLabelText('Host') as HTMLInputElement;
		expect(hostInput.value).toBe('alpha.example');
	});

	it('selected row gets the route-row-selected class; deselects when another row opens', async () => {
		apiMock.listRoutes.mockResolvedValue([
			mk('r-a', 'alpha.example'),
			mk('r-b', 'beta.example'),
		]);
		render(Page);

		const alphaCell = await screen.findByText('alpha.example');
		const betaCell = screen.getByText('beta.example');
		const alphaRow = alphaCell.closest('tr')!;
		const betaRow = betaCell.closest('tr')!;

		// Initial: no row selected.
		expect(alphaRow.classList.contains('route-row-selected')).toBe(false);
		expect(betaRow.classList.contains('route-row-selected')).toBe(false);

		// Click alpha → alpha gets the selected class.
		await userEvent.click(alphaRow);
		await tick();
		expect(alphaRow.classList.contains('route-row-selected')).toBe(true);
		expect(betaRow.classList.contains('route-row-selected')).toBe(false);

		// Click beta → beta selected, alpha deselected. The
		// highlight follows the active editing route — critical
		// for the operator-footgun scenario (similar URLs across
		// routes).
		await userEvent.click(betaRow);
		await tick();
		expect(alphaRow.classList.contains('route-row-selected')).toBe(false);
		expect(betaRow.classList.contains('route-row-selected')).toBe(true);
	});

	// --- Polish round 3 (2026-06-06) — close paths -------------
	// Operator caught two regressions in 5a07275: Save left the
	// row highlighted (phantom selection with no panel), and
	// click-outside did nothing. These tests pin the three
	// close paths (Save / Cancel / outside-click) and the
	// click-same-row toggle so the next refactor can't regress.

	it('Save closes the panel AND deselects the row', async () => {
		const route = mk('r-a', 'alpha.example');
		apiMock.listRoutes.mockResolvedValue([route]);
		apiMock.updateRoute.mockResolvedValue(route);

		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();

		// Sanity: row is selected before Save.
		expect(row.classList.contains('route-row-selected')).toBe(true);

		// Submit. Re-using the same pattern as the validation
		// suite — fireEvent.submit on the panel's form.
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick(); // closePanel + loadRoutes both schedule

		// After Save: row is deselected (Bug 1 fix). The route is
		// still rendered (loadRoutes ran), but no row carries the
		// route-row-selected class.
		const rowAfter = (await screen.findByText('alpha.example')).closest('tr')!;
		expect(rowAfter.classList.contains('route-row-selected')).toBe(false);
		// Form mount anchor is gone too — the panel closed.
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();
	});

	it('clicking outside the panel closes it and deselects the row', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();
		expect(row.classList.contains('route-row-selected')).toBe(true);

		// Click on the page <h1> heading — outside the panel
		// AND outside the table. The mousedown listener should
		// fire closePanel.
		const heading = screen.getByRole('heading', { name: /Routes/i });
		await fireEvent.mouseDown(heading);
		await tick();

		expect(row.classList.contains('route-row-selected')).toBe(false);
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();
	});

	it('clicking inside the panel does NOT close it', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();

		// Click on a form input inside the panel — must not
		// trigger closePanel. The host input is the most reliable
		// in-panel anchor.
		const hostInput = screen.getByLabelText('Host') as HTMLInputElement;
		await fireEvent.mouseDown(hostInput);
		await tick();

		// Panel still open, row still selected.
		expect(row.classList.contains('route-row-selected')).toBe(true);
		expect(screen.getByLabelText('Host')).toBeInTheDocument();
	});

	it('clicking the same selected row toggles the panel closed', async () => {
		apiMock.listRoutes.mockResolvedValue([mk('r-a', 'alpha.example')]);
		render(Page);

		const hostCell = await screen.findByText('alpha.example');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();
		expect(row.classList.contains('route-row-selected')).toBe(true);

		// Click the same row again — toggle close (macOS Finder
		// list inspector behaviour). The row's onclick calls
		// selectOrToggleRoute which detects editingId === r.id
		// and invokes closePanel instead of re-opening.
		await userEvent.click(row);
		await tick();

		expect(row.classList.contains('route-row-selected')).toBe(false);
		expect(screen.queryByLabelText('Host')).not.toBeInTheDocument();
	});
});

// W.5 — country-block form section. The section lives in
// the route create/edit modal between WAF mode and the
// HealthCheck details block. Mode="off" hides the country
// list + status-code sub-fields; mode="allow" with an
// empty list surfaces a reactive footgun error (the W.2 API
// rejects with 400; client-side message is the
// pre-submit UX nudge).
describe('Routes page — W.5 country-block form section', () => {
	it('shows the country-block details block in the create form', async () => {
		render(Page);
		await openCreateForm();
		// The <summary> for the country-block <details> is
		// the canonical anchor.
		// v2.9.17 i18n hotfix — "Pays bloqués" migrated to t();
		// v2.27 renamed the section → "Geo filtering" in the EN
		// bundle (test boot default).
		expect(screen.getByText('Geo filtering')).toBeInTheDocument();
	});

	it('mode=off hides the country-list + status-code sub-fields', async () => {
		render(Page);
		await openCreateForm();
		// Default mode is 'off' → the sub-fields don't render.
		expect(screen.queryByTestId('country-block-input')).not.toBeInTheDocument();
		expect(
			screen.queryByLabelText(/HTTP code \(0/i)
		).not.toBeInTheDocument();
	});

	it('mode=deny reveals the country-list + status-code sub-fields', async () => {
		render(Page);
		await openCreateForm();
		// W.7 — Mode is now a 3-button toggle, not a dropdown.
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('country-block-input')).toBeInTheDocument();
		expect(screen.getByLabelText(/HTTP code \(0/i)).toBeInTheDocument();
	});

	it('typing FR + Enter adds a chip to the country list', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();

		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();

		const chips = screen.getAllByTestId('country-block-chip');
		expect(chips).toHaveLength(1);
		// v2.22.0 — the raw ISO code was replaced by a flag
		// (Flag.svelte). The code now lives in the flag's
		// `fi-fr` class; the resolved French name still renders
		// in .cb-chip__name.
		expect(chips[0].querySelector('.fi-fr')).not.toBeNull();
		// "France" comes from Intl.DisplayNames(fr) which
		// jsdom + Node ICU both ship.
		expect(chips[0].textContent).toContain('France');
	});

	it('mode=allow + empty list shows the footgun error', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();

		// Reactive paragraph with testid country-block-allow-empty-error
		// renders immediately on mode change while the list is empty.
		expect(
			screen.getByTestId('country-block-allow-empty-error')
		).toBeInTheDocument();
	});

	it('mode=allow + non-empty list clears the footgun error', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		// Error visible.
		expect(
			screen.getByTestId('country-block-allow-empty-error')
		).toBeInTheDocument();
		// Add a country — error clears.
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		expect(
			screen.queryByTestId('country-block-allow-empty-error')
		).not.toBeInTheDocument();
	});
});

// W.7 polish — autocomplete + mode-color + counter +
// CTA tests. These layer on top of the W.5 tests above
// without replacing them; the W.5 contracts (mode → input
// visibility, footgun error, payload shape) all still hold.
describe('Routes page — W.7 country-block polish', () => {
	it('renders the 3-button mode toggle (Off / Allow / Deny)', async () => {
		render(Page);
		await openCreateForm();
		expect(screen.getByTestId('country-block-mode-off')).toBeInTheDocument();
		expect(screen.getByTestId('country-block-mode-allow')).toBeInTheDocument();
		expect(screen.getByTestId('country-block-mode-deny')).toBeInTheDocument();
	});

	it('mode=off shows the muted off-hint instead of the input', async () => {
		render(Page);
		await openCreateForm();
		// Default state is off → hint visible, no input.
		expect(screen.getByTestId('country-block-off-hint')).toBeInTheDocument();
		expect(
			screen.queryByTestId('country-block-input')
		).not.toBeInTheDocument();
	});

	it('clicking the Allow button activates it (aria-pressed=true)', async () => {
		render(Page);
		await openCreateForm();
		const allowBtn = screen.getByTestId('country-block-mode-allow');
		expect(allowBtn).toHaveAttribute('aria-pressed', 'false');
		await userEvent.click(allowBtn);
		await tick();
		expect(allowBtn).toHaveAttribute('aria-pressed', 'true');
		expect(allowBtn).toHaveClass('active');
	});

	it('section root gets the mode-allow class when allow is selected', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		// CSS hook for chip + section recoloring.
		expect(screen.getByTestId('country-block-section')).toHaveClass(
			'cb-mode-allow'
		);
	});

	it('section root gets the mode-deny class when deny is selected', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('country-block-section')).toHaveClass(
			'cb-mode-deny'
		);
	});

	it('typing into the input opens the dropdown with matching suggestions', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'ru');
		await tick();
		// Suggestion list opens.
		expect(screen.getByTestId('country-block-dropdown')).toBeInTheDocument();
		// "RU" is one of the suggestions (prefix-matched on
		// the alpha-2 code).
		const suggestions = screen.getAllByTestId('country-block-suggestion');
		// v2.22.0 — the code renders as a flag (Flag.svelte);
		// the alpha-2 lives in the flag's `fi-{code}` class.
		const hasRU = suggestions.some((el) => el.querySelector('.fi-ru'));
		expect(hasRU).toBe(true);
	});

	it('typing a French name prefix matches the country (russie → RU)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'russ');
		await tick();
		const suggestions = screen.getAllByTestId('country-block-suggestion');
		const hasRU = suggestions.some((el) => el.querySelector('.fi-ru'));
		expect(hasRU).toBe(true);
	});

	it('clicking a suggestion adds it as a chip with the French name', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'fr');
		await tick();
		const suggestion = screen
			.getAllByTestId('country-block-suggestion')
			.find((el) => el.querySelector('.fi-fr'));
		expect(suggestion).toBeDefined();
		// mousedown (not click) because that's what the
		// onmousedown handler fires on — picked over click
		// so it runs BEFORE the input's blur closes the
		// dropdown.
		await fireEvent.mouseDown(suggestion!);
		await tick();
		const chips = screen.getAllByTestId('country-block-chip');
		expect(chips).toHaveLength(1);
		expect(chips[0].querySelector('.fi-fr')).not.toBeNull();
		expect(chips[0].textContent).toContain('France');
	});

	it('counter shows "{N} country(ies) blocked" in deny mode + agrees with N', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		expect(screen.getByTestId('country-block-counter')).toHaveTextContent(
			'1 country(ies) blocked'
		);
		// Second country → plural.
		await userEvent.type(input, 'DE{enter}');
		await tick();
		expect(screen.getByTestId('country-block-counter')).toHaveTextContent(
			'2 country(ies) blocked'
		);
	});

	it('counter shows "{N} country(ies) allowed" in allow mode', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		expect(screen.getByTestId('country-block-counter')).toHaveTextContent(
			'1 country(ies) allowed'
		);
	});

	it('counter is hidden when N=0 (even in allow/deny mode)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(
			screen.queryByTestId('country-block-counter')
		).not.toBeInTheDocument();
	});

	it('"+ Ajouter" CTA button is present in allow/deny mode', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('country-block-add-cta')).toBeInTheDocument();
	});

	it('chip removes itself when the × button is clicked', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR{enter}');
		await tick();
		const removeBtn = screen
			.getByTestId('country-block-chip')
			.querySelector('.cb-chip__remove');
		expect(removeBtn).not.toBeNull();
		await fireEvent.click(removeBtn!);
		await tick();
		expect(
			screen.queryByTestId('country-block-chip')
		).not.toBeInTheDocument();
	});

	it('comma separator adds the buffered code (paste-chain UX)', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		const input = screen.getByTestId('country-block-input') as HTMLInputElement;
		await userEvent.type(input, 'FR,');
		await tick();
		const chips = screen.getAllByTestId('country-block-chip');
		expect(chips).toHaveLength(1);
		expect(chips[0].querySelector('.fi-fr')).not.toBeNull();
	});
});

// W.7 follow-up — pinning the collapse-on-off UX fix.
// Before the fix, the <details> element's `open`
// attribute was reactively bound to (mode !== 'off') —
// so clicking "Désactivé" collapsed the entire section
// out of view, hiding the muted hint operators needed
// to confirm their choice. Fix: cbSectionOpen $state
// holds the open/closed intent independently of mode;
// switching to off keeps the section open + reveals
// the muted hint where the input used to live.
describe('Routes page — W.7 follow-up: section visibility on mode=off', () => {
	async function openSection(): Promise<void> {
		// New create-form path: section starts closed
		// (matches the create-form discipline for other
		// detail blocks like HealthCheck). Operator opens
		// it by clicking the summary.
		await openCreateForm();
		const summary = screen
			.getByTestId('country-block-section')
			.querySelector('summary');
		expect(summary).not.toBeNull();
		await fireEvent.click(summary!);
		await tick();
	}

	it('section starts closed on a fresh create form', async () => {
		render(Page);
		await openCreateForm();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(false);
	});

	it('summary shows "(désactivé)" tag when collapsed in off-state', async () => {
		render(Page);
		await openCreateForm();
		// Summary visible (always rendered in jsdom — the
		// <summary> element isn't hidden by details.open=false).
		expect(
			screen.getByTestId('country-block-summary-off')
		).toBeInTheDocument();
	});

	it('clicking Allow opens the section AND reveals the input', async () => {
		render(Page);
		await openCreateForm();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(false);
		// Picking Allow auto-opens — operator's "I want to
		// configure this" intent unmistakable.
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		expect(section.open).toBe(true);
		expect(screen.getByTestId('country-block-input')).toBeInTheDocument();
	});

	it('clicking Désactivé from an open Allow state KEEPS section open + shows the muted hint', async () => {
		render(Page);
		await openSection();
		// Pick Allow first (configured state).
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(true);
		expect(screen.getByTestId('country-block-input')).toBeInTheDocument();

		// Now pick Off — the brief's UX-feedback regression.
		// Before the fix, this collapsed the whole section.
		// After the fix, section stays open + the muted
		// hint takes over where the input was.
		await userEvent.click(screen.getByTestId('country-block-mode-off'));
		await tick();
		expect(section.open).toBe(true);
		expect(screen.getByTestId('country-block-off-hint')).toBeInTheDocument();
		// Input + chips no longer rendered (the {#if mode
		// !== 'off'} branch evaporates), but the toggle
		// + the muted hint stay visible — operator can
		// see what they just picked.
		expect(
			screen.queryByTestId('country-block-input')
		).not.toBeInTheDocument();
		// All 3 mode buttons still on screen.
		expect(
			screen.getByTestId('country-block-mode-off')
		).toBeInTheDocument();
		expect(
			screen.getByTestId('country-block-mode-allow')
		).toBeInTheDocument();
		expect(
			screen.getByTestId('country-block-mode-deny')
		).toBeInTheDocument();
	});

	it('the off-state muted hint message reads the canonical Step W copy', async () => {
		render(Page);
		await openSection();
		// Verbatim string the brief specified — operator-
		// visible nudge "Choose Allow-list or Deny-list to
		// activate." Future copy changes should reach this
		// test before reaching production.
		const hint = screen.getByTestId('country-block-off-hint');
		expect(hint.textContent).toContain('Aucun gate par pays');
		expect(hint.textContent).toContain('Allow-list');
		expect(hint.textContent).toContain('Deny-list');
	});

	it('operator can still manually collapse the section via the summary', async () => {
		render(Page);
		await openSection();
		const section = screen.getByTestId(
			'country-block-section'
		) as HTMLDetailsElement;
		expect(section.open).toBe(true);
		// Manual summary click toggles open/closed — the
		// fix's "section.open is not mode-reactive" rule
		// must NOT lock the section into an always-open
		// state.
		const summary = section.querySelector('summary');
		await fireEvent.click(summary!);
		await tick();
		expect(section.open).toBe(false);
	});
});

// --- 9. #R-PROXMOX-HTTPS-LOOP commit 2 — TLS advanced disclosure +
// per-row hints + scheme-transition self-heal -----------------------

describe('Routes page — TLS advanced disclosure + UX hints (#R-PROXMOX-HTTPS-LOOP)', () => {
	// Reaches the first upstream URL input directly via the
	// placeholder selector (helper from §1 above).
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('hides the TLS advanced disclosure on an http-only pool', async () => {
		render(Page);
		await openCreateForm();
		// Initial state: row is empty → poolScheme === "empty" →
		// disclosure absent.
		expect(screen.queryByTestId('tls-advanced-disclosure')).toBeNull();
		// Type http URL — disclosure stays absent.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8123');
		await tick();
		expect(screen.queryByTestId('tls-advanced-disclosure')).toBeNull();
	});

	it('shows the TLS advanced disclosure on an https-only pool', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		expect(screen.queryByTestId('tls-advanced-disclosure')).not.toBeNull();
	});

	it('hides the disclosure AND clears the toggle on https→http scheme transition (self-heal)', async () => {
		render(Page);
		await openCreateForm();
		// 1. Type https — disclosure appears.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const disclosure = screen.getByTestId('tls-advanced-disclosure');
		// 2. Tick the toggle — would persist a true on submit.
		const toggle = screen.getByLabelText(
			'Skip upstream certificate verification'
		) as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		expect(toggle.checked).toBe(true);
		// 3. Flip the URL to http — disclosure must leave the DOM
		// AND the $effect must reset insecureSkipVerify to false.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8123');
		await tick();
		expect(screen.queryByTestId('tls-advanced-disclosure')).toBeNull();
		// 4. Re-flip to https — toggle must re-appear UNCHECKED
		// (the $effect cleared it on the transition, so the
		// operator's stale intent doesn't leak back).
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const reborn = screen.getByLabelText(
			'Skip upstream certificate verification'
		) as HTMLInputElement;
		expect(reborn.checked).toBe(false);
		// touch the disclosure so the previous binding is held
		// (no-op assertion to keep TS happy on the reference).
		expect(disclosure).toBeTruthy();
	});

	it('shows the path warning when the upstream URL carries a non-root path', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://1.2.3.4:8006/api2/json');
		await tick();
		const warning = screen.getByTestId('upstream-path-warning');
		expect(warning.textContent).toContain('/api2/json');
		expect(warning.textContent).toMatch(/ignoré/i);
		// And the value is preserved (no auto-strip — the operator
		// has to decide).
		expect(firstURL().value).toBe('https://1.2.3.4:8006/api2/json');
	});

	it('shows the private-IP hint on https + RFC 1918 host', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const hint = screen.getByTestId('upstream-private-ip-hint');
		// v2.9.17 i18n hotfix — "IP privée + https détectés…"
		// migrated to t() → "Private IP + https detected…" in EN.
		expect(hint.textContent).toMatch(/Private IP/i);
		// Negative case: http + RFC 1918 → hint absent.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://192.168.1.60:8006');
		await tick();
		expect(screen.queryByTestId('upstream-private-ip-hint')).toBeNull();
		// Negative case: https + public IP → hint absent.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://1.1.1.1');
		await tick();
		expect(screen.queryByTestId('upstream-private-ip-hint')).toBeNull();
	});

	it('blocks submit on a mixed-scheme pool with a pool-level error', async () => {
		render(Page);
		await openCreateForm();
		// Fill a usable host so the host validator doesn't shadow
		// the mixed-scheme error.
		await userEvent.type(hostInput(), 'mixed.example.com');
		// Row 0: http. Row 1: https.
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8000');
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		const row1 = upstreamURLInputs()[1];
		await userEvent.type(row1, 'https://10.0.0.11:8000');
		await tick();
		// Submit — backend should NOT be reached; the form's
		// validateBeforeSubmit short-circuits with the mixed-pool
		// error rendered under the pool header. Create-mode button
		// label is "Create" (Edit-mode would read "Save").
		const submitBtn = screen.getByRole('button', { name: /^Create$/i });
		await userEvent.click(submitBtn);
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
		// Error copy exact phrase pinned (a future copy change
		// should reach this test, not production).
		expect(
			screen.getByText(/All upstreams must share the same scheme/i)
		).not.toBeNull();
	});

	it('serialises insecureSkipVerify=true into the POST payload on an https pool', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({
			host: 'pve.example.com',
			upstreams: [{ url: 'https://192.168.1.60:8006', weight: 1 }],
			insecureSkipVerify: true
		}));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'pve.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		const toggle = screen.getByLabelText(
			'Skip upstream certificate verification'
		) as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		const submitBtn = screen.getByRole('button', { name: /^Create$/i });
		await userEvent.click(submitBtn);
		await tick();
		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0] as Record<string, unknown>;
		expect(payload.insecureSkipVerify).toBe(true);
	});

	it('OMITS insecureSkipVerify from the PUT payload on an http-only pool (preserve-on-omit)', async () => {
		// openEdit a route that's currently http+true (a stale
		// row from before a manual scheme switch). The form's
		// scheme-transition $effect already self-healed
		// formData.insecureSkipVerify to false in the
		// openEdit→render path; the submit pipeline OMITS the
		// field on an http pool so the backend's preserve-
		// previous path runs (the backend will then itself
		// self-heal the stored true → false with a warn-log on
		// the next PUT that DOES touch the flag).
		const fixture = makeRoute({
			id: 'route-http-stale',
			host: 'ha.example.com',
			upstreams: [{ url: 'http://10.0.0.10:8123', weight: 1 }],
			insecureSkipVerify: false
		});
		apiMock.listRoutes.mockResolvedValue([fixture]);
		apiMock.updateRoute.mockResolvedValue(fixture);
		render(Page);
		// Wait for the route row, then click it to enter edit.
		const row = await screen.findByText('ha.example.com');
		await userEvent.click(row);
		await tick();
		// Submit unchanged.
		const saveBtn = screen.getByRole('button', { name: /^Save$/i });
		await userEvent.click(saveBtn);
		await tick();
		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.updateRoute.mock.calls[0][1] as Record<string, unknown>;
		// Pin the OMISSION — preserve-on-omit path. The backend
		// will preserve whatever was stored (false here).
		expect('insecureSkipVerify' in payload).toBe(false);
	});
});

// --- 10. #R-PROXMOX-HTTPS-LOOP commit 3 — Test-upstream UI ---------

describe('Routes page — Test upstream button + chip (#R-PROXMOX-HTTPS-LOOP commit 3)', () => {
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('renders one "Tester" button per upstream row, disabled while URL empty', async () => {
		render(Page);
		await openCreateForm();
		const btn0 = screen.getByTestId('test-upstream-0') as HTMLButtonElement;
		expect(btn0.disabled).toBe(true);
		// Type a URL, disabled flips off.
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		expect(btn0.disabled).toBe(false);
	});

	// v2.56 — run the health check before saving it.
	//
	// A misconfigured check used to surface only as a post-save 503 and an
	// undone change ("Change undone…"), which protected the site and
	// explained nothing. The reported case: a probe against Ghost with no
	// X-Forwarded-Proto, so Ghost answered 301 and the expected 200 never
	// arrived.
	it('sends the unsaved settings to the probe endpoint', async () => {
		apiMock.testHealthCheck.mockResolvedValue({ results: [] });
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'blog.example.com');
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/alive');
		await tick();

		await userEvent.click(screen.getByText(/Test the check/i));
		await waitFor(() => expect(apiMock.testHealthCheck).toHaveBeenCalledTimes(1));

		const sent = apiMock.testHealthCheck.mock.calls[0][0] as {
			routeHost?: string;
			upstreams: { url: string }[];
			healthCheck: { uri: string; enabled: boolean };
		};
		// The form state, not what is stored — nothing has been saved.
		expect(sent.routeHost).toBe('blog.example.com');
		expect(sent.upstreams.map((u) => u.url)).toEqual(['http://10.66.0.2:80']);
		expect(sent.healthCheck.uri).toBe('/alive');
		expect(sent.healthCheck.enabled).toBe(true);
	});

	it('shows the reason and the redirect hint for a failed probe', async () => {
		apiMock.testHealthCheck.mockResolvedValue({
			results: [
				{
					upstream: '10.66.0.2:80',
					healthy: false,
					reason: 'the upstream answered 301; the check accepts any 2xx',
					sent: { method: 'GET', url: 'http://10.66.0.2:80/', host: 'blog.example.com' },
					got: {
						statusCode: 301,
						durationMs: 12,
						location: 'https://10.66.0.2:80/',
						bodyTruncated: false
					},
					hint: 'the upstream redirected to the same URL over https … X-Forwarded-Proto: https header'
				}
			]
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/');
		await userEvent.click(screen.getByText(/Test the check/i));

		await waitFor(() => expect(screen.getByTestId('hc-probe-result')).toBeInTheDocument());
		expect(screen.getByTestId('hc-probe-reason').textContent).toContain('301');
		// The one piece nobody guesses.
		expect(screen.getByTestId('hc-probe-hint').textContent).toContain('X-Forwarded-Proto');
		// And the request that went out is on screen, not inferred.
		expect(screen.getByTestId('hc-probe-result').textContent).toContain('Host: blog.example.com');
	});

	it('surfaces a refusal instead of claiming the probe ran', async () => {
		apiMock.testHealthCheck.mockRejectedValue(
			new ApiError('healthCheck.expectBody is not a valid regular expression', 400, 'validation')
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(document.getElementById('hc-uri') as HTMLInputElement, '/');
		await userEvent.click(screen.getByText(/Test the check/i));

		await waitFor(() => expect(screen.getByTestId('hc-probe-error')).toBeInTheDocument());
		expect(screen.getByTestId('hc-probe-error').textContent).toContain('regular expression');
		expect(screen.queryByTestId('hc-probe-result')).toBeNull();
	});

	// v2.55 — reported from a setup where every route proxies to one
	// backend that dispatches on Host. The probe carried the upstream's
	// address, so the backend had no such virtual host and answered 404 —
	// "✓ HTTP 404" for a service serving that route perfectly.
	it('probes with the route host, not the upstream address', async () => {
		apiMock.testUpstream.mockResolvedValue({ reachable: true, statusCode: 200, latencyMs: 5 });
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'vault.example.com');
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();

		const args = apiMock.testUpstream.mock.calls[0][0] as { hostHeader?: string };
		expect(args.hostHeader, 'the probe must ask the question a visitor asks').toBe(
			'vault.example.com'
		);
	});

	it('probes with the health check Host override when one is set', async () => {
		apiMock.testUpstream.mockResolvedValue({ reachable: true, statusCode: 200, latencyMs: 5 });
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'vault.example.com');
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await userEvent.click(screen.getByLabelText('Enable active health checks'));
		await tick();
		await userEvent.type(screen.getByTestId('hc-host-header'), 'internal.example.com');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();

		const args = apiMock.testUpstream.mock.calls[0][0] as { hostHeader?: string };
		expect(args.hostHeader, 'the test must agree with what the health check probes').toBe(
			'internal.example.com'
		);
	});

	// Reaching the upstream and the upstream answering usefully are two
	// different facts. A tick on a 404 said "all good" about a refusal.
	it('does not tick a 4xx answer', async () => {
		apiMock.testUpstream.mockResolvedValue({ reachable: true, statusCode: 404, latencyMs: 7 });
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();

		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toMatch(/HTTP 404/);
		expect(chip.textContent, 'a 404 marked with a tick reads as "all good"').not.toContain('✓');
		expect(chip.textContent).toContain('⚠');
	});

	it('still ticks a 3xx, which is a served answer', async () => {
		apiMock.testUpstream.mockResolvedValue({ reachable: true, statusCode: 302, latencyMs: 7 });
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.66.0.2:80');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();

		expect(screen.getByTestId('upstream-test-chip-0').textContent).toContain('✓');
	});

	it('sends the URL to the API and renders the reachable chip on success', async () => {
		apiMock.testUpstream.mockResolvedValue({
			reachable: true,
			statusCode: 200,
			latencyMs: 42,
			serverHeader: 'nginx/1.24.0'
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		const btn = screen.getByTestId('test-upstream-0');
		await userEvent.click(btn);
		await tick();
		expect(apiMock.testUpstream).toHaveBeenCalledTimes(1);
		const args = apiMock.testUpstream.mock.calls[0][0] as {
			url: string;
			insecureSkipVerify?: boolean;
		};
		expect(args.url).toBe('http://10.0.0.10:8080');
		// http pool → insecureSkipVerify must be false on
		// the wire, never the form's stale state.
		expect(args.insecureSkipVerify).toBe(false);
		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toMatch(/HTTP 200/);
		expect(chip.textContent).toMatch(/42ms/);
		expect(chip.textContent).toContain('nginx/1.24.0');
	});

	it('renders the error chip on a backend error result', async () => {
		apiMock.testUpstream.mockResolvedValue({
			reachable: false,
			error: 'connection refused'
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();
		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toMatch(/✗/);
		expect(chip.textContent).toMatch(/connection refused/i);
	});

	it('renders an error chip when the request itself throws (network down)', async () => {
		apiMock.testUpstream.mockRejectedValue(new Error('network down'));
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();
		const chip = screen.getByTestId('upstream-test-chip-0');
		expect(chip.textContent).toContain('network down');
	});

	it('forwards insecureSkipVerify on an https pool with the toggle checked', async () => {
		apiMock.testUpstream.mockResolvedValue({
			reachable: true,
			statusCode: 200,
			latencyMs: 50,
			cert: { commonName: 'pve.local', issuer: 'CN=pve.local', selfSigned: true }
		});
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://192.168.1.60:8006');
		await tick();
		// Tick the toggle so the request carries true.
		const toggle = screen.getByLabelText(
			'Skip upstream certificate verification'
		) as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		await userEvent.click(screen.getByTestId('test-upstream-0'));
		await tick();
		expect(apiMock.testUpstream).toHaveBeenCalledTimes(1);
		const args = apiMock.testUpstream.mock.calls[0][0] as {
			insecureSkipVerify?: boolean;
		};
		expect(args.insecureSkipVerify).toBe(true);
		const chip = screen.getByTestId('upstream-test-chip-0');
		// self-signed warning rendered on the chip.
		expect(chip.textContent).toMatch(/self-signed/i);
	});

	it('"Tester tous" parallelises the probe across every non-empty row', async () => {
		apiMock.testUpstream.mockImplementation(async (req: { url: string }) => ({
			reachable: true,
			statusCode: 200,
			latencyMs: 10,
			serverHeader: `fake-for-${req.url}`
		}));
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		await userEvent.click(addBtn);
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://10.0.0.11:8080');
		// Leave row 2 empty — "Tester tous" should skip it.
		const testAllBtn = screen.getByTestId('test-all-upstreams');
		await userEvent.click(testAllBtn);
		await tick();
		await tick();
		// Two probes fired: rows 0 and 1 (row 2 skipped).
		expect(apiMock.testUpstream).toHaveBeenCalledTimes(2);
		// Both chips rendered.
		expect(screen.getByTestId('upstream-test-chip-0').textContent).toMatch(
			/10\.0\.0\.10/
		);
		expect(screen.getByTestId('upstream-test-chip-1').textContent).toMatch(
			/10\.0\.0\.11/
		);
		expect(screen.queryByTestId('upstream-test-chip-2')).toBeNull();
	});

	it('removing a tested row shifts the surviving chip indices', async () => {
		// Pin the splice cleanup in removeUpstream — without
		// it, removing row 0 would leave chip-0 attached to
		// the old result, and the row that was at index 1
		// (now at 0) would have no chip.
		apiMock.testUpstream.mockResolvedValue({
			reachable: true,
			statusCode: 200,
			latencyMs: 7,
			serverHeader: 'row-1'
		});
		render(Page);
		await openCreateForm();
		await userEvent.type(firstURL(), 'http://10.0.0.10:8080');
		const addBtn = screen.getByRole('button', { name: /\+\s*Add upstream/i });
		await userEvent.click(addBtn);
		await tick();
		await userEvent.type(upstreamURLInputs()[1], 'http://10.0.0.11:8080');
		// Test row 1 only.
		await userEvent.click(screen.getByTestId('test-upstream-1'));
		await tick();
		expect(screen.getByTestId('upstream-test-chip-1').textContent).toContain('row-1');
		expect(screen.queryByTestId('upstream-test-chip-0')).toBeNull();
		// Remove row 0 — the tested row should now be at
		// index 0; chip-1 should be gone, chip-0 should
		// carry the old row-1 result.
		const removeButtons = screen
			.getAllByRole('button')
			.filter((b) => b.textContent?.trim() === '×');
		await userEvent.click(removeButtons[0]);
		await tick();
		expect(screen.queryByTestId('upstream-test-chip-1')).toBeNull();
		expect(screen.getByTestId('upstream-test-chip-0').textContent).toContain('row-1');
	});
});

// --- Phase 4.5 — uploadStreamingMode toggle ----------------------------
//
// The toggle lives inside the WAF settings block (modulates WAF body
// inspection + Caddy buffering — coupling it with the WAF knob it
// affects is the clearer mental model than burying it under
// "advanced TLS"). These tests pin:
//   1. Toggle is rendered + defaults to unchecked on create
//   2. Helper text is present and surfaces the operative invariants
//      (body skipped, headers still scanned)
//   3. Form ships uploadStreamingMode=false by default on POST
//   4. Form ships uploadStreamingMode=true when operator ticks the
//      toggle
//   5. openEdit loads the persisted value (true) onto the toggle
//   6. The toggle works independently of wafMode (no constraint
//      between the two)

describe('Routes page — Phase 4.5 uploadStreamingMode toggle', () => {
	it('renders the toggle unchecked by default on create', async () => {
		render(Page);
		await openCreateForm();

		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		expect(toggle).toBeInTheDocument();
		expect(toggle.checked).toBe(false);
	});

	it('renders helper text describing the body-skip / header-still-scanned invariants', async () => {
		render(Page);
		await openCreateForm();

		const label = screen.getByTestId('upload-streaming-toggle-label');
		// v2.9.17 i18n hotfix — "Mode upload streaming…" migrated
		// to t() → "Upload streaming mode…" in the EN bundle.
		expect(label.textContent).toMatch(/Upload streaming mode/);

		// The helper paragraph follows the label. Walk the parent
		// to find it without coupling to exact DOM structure.
		const wafSection = label.closest('div')!;
		const helperText = wafSection.textContent ?? '';
		expect(helperText).toMatch(/headers/);
		expect(helperText).toMatch(/URL/);
		expect(helperText).toMatch(/response/);
		expect(helperText).toMatch(/registry/i);
	});

	it('ships uploadStreamingMode=false by default in the create payload', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'plain.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.uploadStreamingMode).toBe(false);
	});

	it('ships uploadStreamingMode=true when operator ticks the toggle', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ uploadStreamingMode: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'registry.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:5000');

		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.uploadStreamingMode).toBe(true);
	});

	it('loads the persisted uploadStreamingMode=true value into the toggle on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-streaming',
			host: 'registry.edit.example.com',
			uploadStreamingMode: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);

		render(Page);
		const hostCell = await screen.findByText('registry.edit.example.com');
		const row = hostCell.closest('tr')!;
		await userEvent.click(row);
		await tick();

		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);
	});

	it('persists toggle state across wafMode changes (no cross-coupling)', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ uploadStreamingMode: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'files.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8081');

		// Operator ticks the toggle FIRST, then sets WAF=block.
		// Streaming-mode state must survive the wafMode change —
		// no coupling between the two.
		const toggle = screen.getByTestId('upload-streaming-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		expect(toggle.checked).toBe(true);

		await setWafMode('block');
		// Toggle still checked after the WAF mode change.
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.uploadStreamingMode).toBe(true);
		expect(payload.wafMode).toBe('block');
	});
});

// --- Day 13 #R-FRONTEND-PUT-NO-TIMEOUT — submitForm error
// handling. Two pins:
//   1. Timeout (system-kind ApiError) → spinner clears + danger
//      toast surfaces the actionable message.
//   2. Locked state after the await → spinner clears + NO
//      toast (LockScreen overlay already informs the operator).
//
// Both branches go through the same try/catch/finally —
// regressions would either leave the spinner running (worst
// case, the operator-reported symptom) or double-notify on
// lock (LockScreen + danger toast competing for focus).

describe('Routes page — submitForm error handling (#R-FRONTEND-PUT-NO-TIMEOUT)', () => {
	it('shows danger toast + closes spinner when backend stalls past the timeout', async () => {
		// updateRoute rejects with the exact ApiError shape the
		// request() helper throws on AbortController timeout.
		apiMock.updateRoute.mockRejectedValue(
			new ApiError('request timed out after 30s', 0, 'system')
		);
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-timeout', host: 'timeout.example.com' })
		]);

		render(Page);
		const hostCell = await screen.findByText('timeout.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// Toast surfaces the timeout message verbatim — operator
		// reads "request timed out after 30s" and knows the
		// backend was unresponsive, not that they did something
		// wrong.
		expect(toastMock.pushToast).toHaveBeenCalledWith(
			'request timed out after 30s',
			'danger'
		);
		// Spinner gone: the Save button is no longer in its
		// loading state. We assert via the overlay test-id
		// which only mounts while submitting=true.
		expect(screen.queryByTestId('route-save-overlay')).toBeNull();
	});

	it('suppresses the danger toast when auth.state is "locked" after the await', async () => {
		// The PUT returned a 403 session-locked; the client
		// interceptor called auth.setLocked() (which flipped the
		// store to 'locked') and threw ApiError(403, forbidden).
		// submitForm must see auth.state==='locked' in its catch
		// and skip the toast — the LockScreen overlay is the
		// authoritative operator signal.
		authMock.state = 'locked';
		apiMock.updateRoute.mockRejectedValue(
			new ApiError('session locked', 403, 'forbidden')
		);
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-lock', host: 'lock.example.com' })
		]);

		render(Page);
		const hostCell = await screen.findByText('lock.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		// No double-notify: pushToast not called for the lock
		// case. (The LockScreen overlay is layout-level, not
		// asserted here — its mounting is covered by
		// auth.test.ts + layout tests.)
		expect(toastMock.pushToast).not.toHaveBeenCalled();
		// Spinner still cleared — finally ran even on the
		// suppressed-toast branch.
		expect(screen.queryByTestId('route-save-overlay')).toBeNull();
	});
});

// --- Step X.2 — wafDisableCRS toggle + confirm dialog ----------------
//
// The toggle lives in the WAF settings block alongside wafMode +
// uploadStreamingMode. Two operator-visible contracts :
//   1. Enabling the toggle (false → true) opens an ADR-D4 confirm
//      dialog before the form state mutates. Cancelling leaves
//      the toggle unticked and the formData at false ; confirming
//      commits the true.
//   2. Disabling the toggle (true → false) flips immediately. No
//      dialog : re-enabling CRS is a security-improving action,
//      always safe.
//
// Wire contract :
//   3. Payload ships wafDisableCRS=false by default on POST
//      (zero-value byte-equivalent to pre-X.1 routes).
//   4. Payload ships wafDisableCRS=true after the operator
//      confirms via the dialog.
//   5. Edit loads the persisted value (true) so the toggle
//      reflects the stored state on re-open.
//   6. Toggle is independent of wafMode (same independence as
//      uploadStreamingMode, mirror of the Phase 4.5 invariant).

describe('Routes page — Step X.2 wafDisableCRS toggle + confirm dialog', () => {
	it('renders the toggle unchecked by default on create', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		expect(toggle).toBeInTheDocument();
		expect(toggle.checked).toBe(false);
	});

	it('ticking the toggle opens the ADR-D4 confirm dialog and DOES NOT mutate the toggle state', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		// v2.9.14 i18n Phase 3 batch 1 — dialog title resolves via
		// t('routes.wafCRSDialog.title'). Test boot has no cookie/
		// localStorage in jsdom → EN bundle wins.
		expect(screen.getByText('Disable the OWASP CRS rules?')).toBeInTheDocument();
		// Toggle visual state stays at false until the operator
		// confirms via the dialog.
		expect(toggle.checked).toBe(false);
	});

	it('cancelling the dialog keeps the toggle unchecked and the form value at false', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'cancel.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		// Cancel via the ConfirmDialog cancel button (EN: "Cancel").
		// v2.9.14 — multiple "Cancel" buttons exist now (form +
		// dialog); scope the lookup to a role+name match that
		// finds the dialog's cancel since the dialog is the only
		// currently-visible button-named "Cancel" in modal scope.
		const cancelBtns = screen.getAllByRole('button', { name: 'Cancel' });
		// The CRS confirm dialog cancel is the most-recently-mounted
		// "Cancel" button (Modal portals to body end). Click the last.
		await userEvent.click(cancelBtns[cancelBtns.length - 1]);
		await tick();

		expect(toggle.checked).toBe(false);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafDisableCRS).toBe(false);
	});

	it('confirming the dialog flips formData true and ships wafDisableCRS=true in the create payload', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ wafDisableCRS: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'nas.lan');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8080');

		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		// Confirm the dialog — the affirmative button reads
		// "Disable CRS" (EN bundle, test boot default).
		const confirmBtn = screen.getByText('Disable CRS');
		await userEvent.click(confirmBtn);
		await tick();
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafDisableCRS).toBe(true);
	});

	it('unticking an already-true toggle DOES NOT open the dialog (re-enable CRS is always safe)', async () => {
		// Seed a stored route with wafDisableCRS=true so the
		// edit form opens with the toggle checked. The operator
		// then unticks ; no dialog should appear, the formData
		// flips immediately, and the next save ships false.
		const seeded = makeRoute({
			id: 'edit-disable-crs',
			host: 'edit.nas.lan',
			wafDisableCRS: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue({ ...seeded, wafDisableCRS: false });

		render(Page);
		const hostCell = await screen.findByText('edit.nas.lan');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);

		await userEvent.click(toggle);
		// NO dialog on un-tick path. v2.9.14 i18n Phase 3 batch 1
		// flipped the title to t('routes.wafCRSDialog.title') →
		// "Disable the OWASP CRS rules?" in the EN bundle.
		expect(screen.queryByText('Disable the OWASP CRS rules?')).toBeNull();
		expect(toggle.checked).toBe(false);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.updateRoute.mock.calls[0][1];
		expect(payload.wafDisableCRS).toBe(false);
	});

	it('loads the persisted wafDisableCRS=true value into the toggle on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-disable-crs-load',
			host: 'load.nas.lan',
			wafDisableCRS: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('load.nas.lan');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);
	});

	it('toggle is independent of wafMode (no cross-coupling, mirror of streaming-mode invariant)', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ wafDisableCRS: true }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'independent.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8000');

		// Tick + confirm BEFORE changing wafMode.
		const toggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		await userEvent.click(screen.getByText('Disable CRS'));
		await tick();
		expect(toggle.checked).toBe(true);

		await setWafMode('block');
		// Toggle survives the mode change.
		expect(toggle.checked).toBe(true);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafDisableCRS).toBe(true);
		expect(payload.wafMode).toBe('block');
	});
});

// --- Step X Option (c) — wafExcludeRules textarea ----------------
//
// The textarea lives below the wafDisableCRS toggle in the WAF block.
// Operator types a comma-separated list of 6-digit CRS rule IDs ;
// frontend parses, validates (range + reserved-Arenet check),
// dedupes + sorts, and ships the canonical number[] in the payload.
//
// Operator-visible contracts pinned :
//   1. Empty input on create ships [] (no exclusions).
//   2. Valid 6-digit IDs parse into number[] payload.
//   3. Non-numeric input surfaces a frontend error and blocks
//      submit.
//   4. Out-of-range IDs (< 100000, > 999999) surface a frontend
//      error.
//   5. Arenet-reserved range [100000, 199999] surfaces a
//      frontend error.
//   6. Edit loads the persisted list back into the textarea.
//   7. Textarea is disabled when wafDisableCRS is true (the
//      stored list is preserved, just gated).
//   8. /security/{routeId} link is present in edit mode for rule
//      ID discovery.

describe('Routes page — Step X Option (c) wafExcludeRules textarea', () => {
	it('ships empty wafExcludeRules in the create payload when textarea is empty', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'empty.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeRules).toEqual([]);
	});

	it('parses comma-separated 6-digit IDs into the create payload', async () => {
		apiMock.createRoute.mockResolvedValue(
			makeRoute({ wafExcludeRules: [920280, 941390, 942100] })
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'parse.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		// Type out of order to verify the frontend canonicalises
		// (ascending sort + dedup) before sending.
		await userEvent.type(textarea, '942100, 941390, 920280');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeRules).toEqual([920280, 941390, 942100]);
	});

	it('surfaces a frontend error on non-numeric input and blocks submit', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'bad.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, 'abc, 942100');

		const errorNode = screen.getByTestId('waf-exclude-rules-error');
		expect(errorNode.textContent ?? '').toContain('abc');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects IDs in the Arenet-reserved range [100000, 199999]', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'reserved.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, '150000');

		const errorNode = screen.getByTestId('waf-exclude-rules-error');
		expect(errorNode.textContent ?? '').toMatch(/réservée|reserved/i);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('rejects IDs out of the 6-digit range', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'oor.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, '99999');

		const errorNode = screen.getByTestId('waf-exclude-rules-error');
		expect(errorNode.textContent ?? '').toMatch(/6 chiffres|range/i);
	});

	it('loads the persisted exclusion list into the textarea on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-exclude',
			host: 'edit.exclude.local',
			wafExcludeRules: [920280, 941390, 942100]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('edit.exclude.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		// Canonical comma-separated form ; openEdit calls
		// formatExcludeRulesInput on the stored slice.
		expect(textarea.value).toBe('920280, 941390, 942100');
	});

	it('disables the textarea when wafDisableCRS is true', async () => {
		const seeded = makeRoute({
			id: 'edit-disable',
			host: 'edit.disable.local',
			wafDisableCRS: true,
			wafExcludeRules: [942100]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('edit.disable.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement;
		// Disabled but NOT cleared — the operator may toggle CRS
		// back on later and expect the list to still apply.
		expect(textarea.disabled).toBe(true);
		expect(textarea.value).toBe('942100');
	});

	it('surfaces the /security/{routeId} discovery link in edit mode', async () => {
		const seeded = makeRoute({
			id: 'discover-link',
			host: 'discover.local'
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('discover.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const link = screen.getByTestId('waf-exclude-rules-security-link') as HTMLAnchorElement;
		expect(link.getAttribute('href')).toBe('/security/discover-link');
	});
});

// --- Step X Option (e) — wafExcludeTags textarea + datalist --------
//
// Sibling of (c). Same operator-visible contracts :
//   1. Empty input → ships [] (no exclusions).
//   2. Comma-separated tags parse + canonicalise (lowercase,
//      dedup, sort) into the payload.
//   3. Invalid characters (comma inside a tag, whitespace
//      inside a tag, double-quote) surface a frontend error
//      and block submit.
//   4. Edit loads the persisted list back into the textarea.
//   5. Datalist exposes the curated CRS tag catalog (24 entries).
//   6. Textarea is disabled when wafDisableCRS is true.

describe('Routes page — Step X Option (e) wafExcludeTags textarea', () => {
	it('ships empty wafExcludeTags in the create payload when textarea is empty', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'empty-tags.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeTags).toEqual([]);
	});

	it('parses comma-separated tags into the canonicalised create payload', async () => {
		apiMock.createRoute.mockResolvedValue(
			makeRoute({ wafExcludeTags: ['attack-protocol', 'attack-sqli', 'paranoia-level/3'] })
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'parse-tags.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		// Type out-of-order + mixed-case + duplicate to verify
		// the frontend canonicalises (lowercase, dedup, sort).
		await userEvent.type(textarea, 'Paranoia-Level/3, attack-sqli, ATTACK-PROTOCOL, attack-sqli');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.wafExcludeTags).toEqual(['attack-protocol', 'attack-sqli', 'paranoia-level/3']);
	});

	it('surfaces a frontend error on a comma-smuggling tag and blocks submit', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'bad-tag.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		// Note : the parser splits on `,`, so the way to land
		// a comma-inside-a-tag here is to use a token that the
		// split already produced and that still contains an
		// invalid character. Double-quote is the cleanest signal.
		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		await userEvent.type(textarea, 'attack-sqli"');

		const errorNode = screen.getByTestId('waf-exclude-tags-error');
		expect(errorNode.textContent ?? '').toContain('SecAction');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});

	it('reloads the persisted tag list into the textarea on edit', async () => {
		const seeded = makeRoute({
			id: 'tag-edit',
			host: 'tag-edit.local',
			wafExcludeTags: ['attack-protocol', 'paranoia-level/3']
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('tag-edit.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		expect(textarea.value).toBe('attack-protocol, paranoia-level/3');
	});

	it('exposes the curated CRS tag catalog via <datalist>', async () => {
		render(Page);
		await openCreateForm();
		const datalist = document.getElementById('waf-exclude-tags-catalog') as HTMLDataListElement;
		expect(datalist).not.toBeNull();
		// 24 curated tags — the catalog is hardcoded so this
		// is a stable assertion across CRS upstream updates.
		expect(datalist.options.length).toBe(24);
		// Spot-check a high-traffic tag is present.
		const values = Array.from(datalist.options).map((o) => o.value);
		expect(values).toContain('attack-protocol');
		expect(values).toContain('paranoia-level/3');
	});

	it('disables the textarea when wafDisableCRS is true', async () => {
		render(Page);
		await openCreateForm();
		const crsToggle = screen.getByTestId('waf-disable-crs-toggle') as HTMLInputElement;
		await userEvent.click(crsToggle);
		// The confirm dialog gates the flip ; click the confirm
		// button by label (the ConfirmDialog component doesn't
		// carry a stable testid on the action button — finding
		// the visible label is the operator-equivalent path).
		// v2.9.14 i18n Phase 3 batch 1 — EN default in test boot.
		const confirmBtn = await screen.findByRole('button', { name: 'Disable CRS' });
		await userEvent.click(confirmBtn);
		await tick();

		const textarea = screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement;
		expect(textarea.disabled).toBe(true);
	});
});

// --- Step Q — rate-limit section -------------------------------

describe('Routes page — Step Q rate-limit toggle + payload', () => {
	it('renders the toggle unchecked on create + hides the inputs when off', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('rate-limit-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(false);
		// Inputs only render when the toggle is on.
		expect(screen.queryByTestId('rate-limit-events-input')).toBeNull();
		expect(screen.queryByTestId('rate-limit-window-input')).toBeNull();
		expect(screen.queryByTestId('rate-limit-key-input')).toBeNull();
	});

	it('toggling on seeds the inputs with operator-meaningful defaults', async () => {
		render(Page);
		await openCreateForm();
		const toggle = screen.getByTestId('rate-limit-toggle') as HTMLInputElement;
		await userEvent.click(toggle);
		await tick();
		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		const window = screen.getByTestId('rate-limit-window-input') as HTMLInputElement;
		const key = screen.getByTestId('rate-limit-key-input') as HTMLInputElement;
		expect(events.value).toBe('60');
		expect(window.value).toBe('1m');
		expect(key.value).toBe('{http.request.remote.host}');
	});

	it('ships rateLimit object in the create payload when the toggle is on', async () => {
		apiMock.createRoute.mockResolvedValue(
			makeRoute({ rateLimit: { events: 5, window: '10s', key: '{http.request.remote.host}' } })
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'rate.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		await userEvent.click(screen.getByTestId('rate-limit-toggle'));
		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		const window = screen.getByTestId('rate-limit-window-input') as HTMLInputElement;
		await userEvent.clear(events);
		await userEvent.type(events, '5');
		await userEvent.clear(window);
		await userEvent.type(window, '10s');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.rateLimit).toMatchObject({ events: 5, window: '10s' });
		// v2.9.13 Phase Q.2 — when the toggle is ON, clearRateLimit
		// MUST stay absent (or false). Otherwise the sentinel would
		// wipe the rateLimit body the operator just typed.
		expect(payload.clearRateLimit).toBeFalsy();
	});

	it('omits rateLimit but sends clearRateLimit:true when toggle is off (v2.9.13 Phase Q.2)', async () => {
		// Pre-v2.9.13 the OFF case omitted both fields. The backend
		// treated that as preserve-on-omit, so the UI toggle OFF
		// appeared to succeed but a previously-stored rate-limit
		// stuck around (operator-reported 2026-06-26). The frontend
		// now signals the OFF intent via clearRateLimit:true so the
		// backend handler actively clears the stored value.
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'noRate.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.rateLimit).toBeUndefined();
		expect(payload.clearRateLimit).toBe(true);
	});

	it('loads the persisted rateLimit into the toggle + inputs on edit', async () => {
		const seeded = makeRoute({
			id: 'edit-rate',
			host: 'edit.rate.example.com',
			rateLimit: { events: 100, window: '5m', key: '{http.request.remote.host}' }
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		const hostCell = await screen.findByText('edit.rate.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();
		const toggle = screen.getByTestId('rate-limit-toggle') as HTMLInputElement;
		expect(toggle.checked).toBe(true);
		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		expect(events.value).toBe('100');
	});

	// v2.56.3 — the scenario the load test above stops short of.
	//
	// clearRateLimit is the sentinel that actively wipes the stored limit,
	// and it is sent whenever the form's rateLimit is null. Loading a route
	// that HAS a limit must populate that field, or every unrelated edit —
	// a header, a WAF mode — would silently delete the limit while
	// reporting success.
	it('does not wipe a stored rate limit on an edit that never touched it', async () => {
		const seeded = makeRoute({
			id: 'edit-rate-keep',
			host: 'keep.rate.example.com',
			rateLimit: { events: 100, window: '5m', key: '{http.request.remote.host}' }
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		const hostCell = await screen.findByText('keep.rate.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		// Save without going near the rate-limit section.
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.updateRoute.mock.calls[0][1] as {
			clearRateLimit?: boolean;
			rateLimit?: { events: number; window: string };
		};
		expect(
			payload.clearRateLimit,
			'clearRateLimit on an untouched limit would delete it on every save'
		).toBeFalsy();
		expect(payload.rateLimit).toMatchObject({ events: 100, window: '5m' });
	});
});

// --- v2.14.3 / Task 9 — route disable/enable/maintenance state control ---
//
// Task 7 (frontend UI). API client (disableRoute/enableRoute), the
// Route.disabled wire field, and the i18n keys were wired in Tasks
// 6/T6. Task 9 replaces the row-level Activer/Désactiver ghost
// button with the 3-state RouteStateControl (Task 8) and wires it
// to enterMaintenance/exitMaintenance in addition to
// disableRoute/enableRoute. This suite pins: the Disabled badge on
// a disabled row, the dim treatment, the 3-state control reflecting
// derived state, the onchange routing to the right endpoint, the
// confirm dialog (normal + special last-HTTPS-route copy) gated to
// the DISABLED transition only, and the RouteForm "Disabled"
// checkbox round-trip.

// Returns the RouteStateControl's radiogroup scoped to the row for
// the given route id — the row is located via the host text, and
// the radiogroup is the one descendant with role="radiogroup"
// inside that <tr>.
function stateControlFor(host: string): HTMLElement {
	const hostCell = screen.getByText(host);
	const row = hostCell.closest('tr')!;
	const group = row.querySelector('[role="radiogroup"]');
	expect(group).toBeTruthy();
	return group as HTMLElement;
}

function pickSegment(group: HTMLElement, state: 'active' | 'maintenance' | 'disabled'): void {
	const btn = group.querySelector(`[data-state="${state}"]`) as HTMLButtonElement;
	expect(btn).toBeTruthy();
	fireEvent.click(btn);
}

describe('/routes — disable/enable', () => {
	// v2.17.1 Item C — the redundant "Disabled" text badge near the
	// host cell was REMOVED (the RouteStateControl now carries the
	// state via its fill color + active segment; see the
	// '/routes — 3-state control + maintenance' suite below for the
	// aria-checked assertion on the control itself). This test now
	// pins the ABSENCE of the old badge markup instead.
	it('does not render a redundant Disabled badge near the host (state lives in RouteStateControl)', async () => {
		// Arrange: listRoutes returns one disabled route.
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r1',
				host: 'off.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: false,
				disabled: true
			})
		]);
		render(Page);
		await screen.findByText('off.example.com');
		expect(screen.queryByText('Disabled', { selector: '.badge' })).toBeNull();
	});

	it('dims the row (opacity class) for a disabled route', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r1',
				host: 'off.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: false,
				disabled: true
			})
		]);
		render(Page);
		const hostCell = await screen.findByText('off.example.com');
		const row = hostCell.closest('tr')!;
		expect(row.className).toContain('opacity-50');
	});

	it('clicking Disable on an active route opens the confirm dialog then calls disableRoute', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r2',
				host: 'live.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: false,
				disabled: false
			})
		]);
		apiMock.disableRoute.mockResolvedValue({ id: 'r2', disabled: true, lastHttpsRouteAffected: false });
		render(Page);
		await screen.findByText('live.example.com');
		pickSegment(stateControlFor('live.example.com'), 'disabled');
		// confirm dialog appears
		await fireEvent.click(screen.getByTestId('route-disable-confirm'));
		await waitFor(() => expect(apiMock.disableRoute).toHaveBeenCalledWith('r2'));
	});

	it('shows the normal confirm copy (not the last-HTTPS warning) for a non-TLS route', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r2',
				host: 'live.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: false,
				disabled: false
			})
		]);
		apiMock.disableRoute.mockResolvedValue({ id: 'r2', disabled: true, lastHttpsRouteAffected: false });
		render(Page);
		await screen.findByText('live.example.com');
		pickSegment(stateControlFor('live.example.com'), 'disabled');
		expect(await screen.findByText('Disable route?')).toBeInTheDocument();
		expect(screen.queryByText('Disable the last HTTPS route?')).not.toBeInTheDocument();
	});

	it('shows the special last-HTTPS-route confirm copy when disabling the only active TLS route', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r-tls',
				host: 'secure.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: true,
				disabled: false
			})
		]);
		apiMock.disableRoute.mockResolvedValue({ id: 'r-tls', disabled: true, lastHttpsRouteAffected: true });
		render(Page);
		await screen.findByText('secure.example.com');
		pickSegment(stateControlFor('secure.example.com'), 'disabled');
		expect(await screen.findByText('Disable the last HTTPS route?')).toBeInTheDocument();
		await fireEvent.click(screen.getByTestId('route-disable-confirm'));
		await waitFor(() => expect(apiMock.disableRoute).toHaveBeenCalledWith('r-tls'));
	});

	it('does NOT show the last-HTTPS warning when a second active TLS route exists', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r-tls-1',
				host: 'secure1.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: true,
				disabled: false
			}),
			makeRoute({
				id: 'r-tls-2',
				host: 'secure2.example.com',
				upstreams: [{ url: 'http://y', weight: 1 }],
				tlsEnabled: true,
				disabled: false
			})
		]);
		render(Page);
		await screen.findByText('secure1.example.com');
		pickSegment(stateControlFor('secure1.example.com'), 'disabled');
		expect(await screen.findByText('Disable route?')).toBeInTheDocument();
		expect(screen.queryByText('Disable the last HTTPS route?')).not.toBeInTheDocument();
	});

	it('clicking Enable on a disabled route calls enableRoute directly (no confirm dialog)', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r3',
				host: 'off.example.com',
				upstreams: [{ url: 'http://x', weight: 1 }],
				tlsEnabled: false,
				disabled: true
			})
		]);
		apiMock.enableRoute.mockResolvedValue({ id: 'r3', disabled: false });
		render(Page);
		await screen.findByText('off.example.com');
		pickSegment(stateControlFor('off.example.com'), 'active');
		await waitFor(() => expect(apiMock.enableRoute).toHaveBeenCalledWith('r3'));
		// No confirm dialog gating the enable path.
		expect(screen.queryByTestId('route-disable-confirm')).not.toBeInTheDocument();
	});

	// v2.41.2 — the state control is a form field: picking Disabled
	// changes nothing until Save, and then it ships in the PUT.
	it('RouteForm state control ships the picked state with the save', async () => {
		const seeded = makeRoute({
			id: 'edit-disable',
			host: 'edit-disable.example.com',
			upstreams: [{ url: 'http://127.0.0.1:9000', weight: 1 }],
			disabled: false
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue({ ...seeded, disabled: true });
		render(Page);

		const hostCell = await screen.findByText('edit-disable.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		const form = document.querySelector('form')!;
		expect(within(form).getByTestId('route-state-active').getAttribute('aria-checked')).toBe('true');

		await userEvent.click(within(form).getByTestId('route-state-disabled'));
		await tick();
		// Nothing committed yet — no endpoint, no PUT.
		expect(apiMock.disableRoute).not.toHaveBeenCalled();
		expect(apiMock.updateRoute).not.toHaveBeenCalled();
		// …and the form knows it has unsaved work.
		expect(screen.getByTestId('form-dirty')).toBeInTheDocument();

		await fireEvent.submit(form);
		await tick();
		await tick();
		expect(apiMock.disableRoute).not.toHaveBeenCalled();
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		expect(payload.disabled).toBe(true);
	});
});

// --- Task 9 — 3-state control + maintenance form section -----------------
//
// Wires RouteStateControl (Task 8) into the routes list, replacing
// the old Activer/Désactiver ghost button (see the suite above,
// which was updated in place to drive the control instead of the
// button). This suite covers what's new: state derivation from
// `disabled` + `maintenanceConfig`, the onchange routing to
// enterMaintenance/exitMaintenance, the disabled-only last-HTTPS
// warning gate, and the edit-form Maintenance section.

describe('/routes — 3-state control + maintenance', () => {
	it('renders RouteStateControl reflecting "active" for a plain route', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-active', host: 'active.example.com', disabled: false })
		]);
		render(Page);
		await screen.findByText('active.example.com');
		const group = stateControlFor('active.example.com');
		const activeSeg = group.querySelector('[data-state="active"]') as HTMLButtonElement;
		expect(activeSeg.getAttribute('aria-checked')).toBe('true');
	});

	it('renders RouteStateControl reflecting "disabled" when route.disabled is true', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-off', host: 'off2.example.com', disabled: true })
		]);
		render(Page);
		await screen.findByText('off2.example.com');
		const group = stateControlFor('off2.example.com');
		const seg = group.querySelector('[data-state="disabled"]') as HTMLButtonElement;
		expect(seg.getAttribute('aria-checked')).toBe('true');
	});

	it('renders RouteStateControl reflecting "maintenance" when route.maintenanceConfig is set', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r-maint',
				host: 'maint.example.com',
				disabled: false,
				maintenanceConfig: { retryAfterSeconds: 120, bypassIps: [] }
			})
		]);
		render(Page);
		await screen.findByText('maint.example.com');
		const group = stateControlFor('maint.example.com');
		const seg = group.querySelector('[data-state="maintenance"]') as HTMLButtonElement;
		expect(seg.getAttribute('aria-checked')).toBe('true');
	});

	it('selecting "maintenance" calls enterMaintenance and refreshes the list', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-a', host: 'a.example.com', disabled: false })
		]);
		apiMock.enterMaintenance.mockResolvedValue(
			makeRoute({
				id: 'r-a',
				host: 'a.example.com',
				disabled: false,
				maintenanceConfig: { retryAfterSeconds: 300, bypassIps: [] }
			})
		);
		render(Page);
		await screen.findByText('a.example.com');
		pickSegment(stateControlFor('a.example.com'), 'maintenance');
		await waitFor(() => expect(apiMock.enterMaintenance).toHaveBeenCalledWith('r-a'));
		// Refresh: listRoutes called again after the mutation (mount + post-action).
		await waitFor(() => expect(apiMock.listRoutes).toHaveBeenCalledTimes(2));
		// No confirm dialog for the maintenance transition.
		expect(screen.queryByTestId('route-disable-confirm')).not.toBeInTheDocument();
	});

	it('selecting "active" from maintenance calls exitMaintenance', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r-b',
				host: 'b.example.com',
				disabled: false,
				maintenanceConfig: { retryAfterSeconds: 300, bypassIps: [] }
			})
		]);
		apiMock.exitMaintenance.mockResolvedValue(
			makeRoute({ id: 'r-b', host: 'b.example.com', disabled: false })
		);
		render(Page);
		await screen.findByText('b.example.com');
		pickSegment(stateControlFor('b.example.com'), 'active');
		await waitFor(() => expect(apiMock.exitMaintenance).toHaveBeenCalledWith('r-b'));
		expect(apiMock.enableRoute).not.toHaveBeenCalled();
	});

	it('selecting "active" from disabled calls enableRoute (not exitMaintenance)', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-c', host: 'c.example.com', disabled: true })
		]);
		apiMock.enableRoute.mockResolvedValue(makeRoute({ id: 'r-c', host: 'c.example.com', disabled: false }));
		render(Page);
		await screen.findByText('c.example.com');
		pickSegment(stateControlFor('c.example.com'), 'active');
		await waitFor(() => expect(apiMock.enableRoute).toHaveBeenCalledWith('r-c'));
		expect(apiMock.exitMaintenance).not.toHaveBeenCalled();
	});

	it('switching the LAST TLS route to Maintenance does NOT show the last-HTTPS warning', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-tls-only', host: 'onlytls.example.com', tlsEnabled: true, disabled: false })
		]);
		apiMock.enterMaintenance.mockResolvedValue(
			makeRoute({
				id: 'r-tls-only',
				host: 'onlytls.example.com',
				tlsEnabled: true,
				disabled: false,
				maintenanceConfig: { retryAfterSeconds: 300, bypassIps: [] }
			})
		);
		render(Page);
		await screen.findByText('onlytls.example.com');
		pickSegment(stateControlFor('onlytls.example.com'), 'maintenance');
		await waitFor(() => expect(apiMock.enterMaintenance).toHaveBeenCalledWith('r-tls-only'));
		expect(screen.queryByText('Disable the last HTTPS route?')).not.toBeInTheDocument();
		expect(screen.queryByTestId('route-disable-confirm')).not.toBeInTheDocument();
	});

	it('switching the LAST TLS route to Disabled still shows the last-HTTPS warning', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({ id: 'r-tls-only2', host: 'onlytls2.example.com', tlsEnabled: true, disabled: false })
		]);
		apiMock.disableRoute.mockResolvedValue({
			id: 'r-tls-only2',
			disabled: true,
			lastHttpsRouteAffected: true
		});
		render(Page);
		await screen.findByText('onlytls2.example.com');
		pickSegment(stateControlFor('onlytls2.example.com'), 'disabled');
		expect(await screen.findByText('Disable the last HTTPS route?')).toBeInTheDocument();
	});

	// v2.17.1 Item C — the redundant "Maintenance" text badge near
	// the host cell was REMOVED (the RouteStateControl now carries
	// the state; see 'renders RouteStateControl reflecting
	// "maintenance"...' above for the aria-checked assertion). This
	// test now pins the ABSENCE of the old badge markup instead.
	it('does not render a redundant Maintenance badge near the host (state lives in RouteStateControl)', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r-badge',
				host: 'badge.example.com',
				disabled: false,
				maintenanceConfig: { retryAfterSeconds: 60, bypassIps: [] }
			})
		]);
		render(Page);
		await screen.findByText('badge.example.com');
		expect(screen.queryByText('Maintenance', { selector: '.badge' })).toBeNull();
	});

	it('edit form shows a Maintenance section seeded from route.maintenanceConfig', async () => {
		const seeded = makeRoute({
			id: 'edit-maint',
			host: 'edit-maint.example.com',
			maintenanceConfig: { retryAfterSeconds: 180, bypassIps: ['10.0.0.5', '192.168.1.0/24'] }
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);

		const hostCell = await screen.findByText('edit-maint.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		// v2.18.0 — friendly Retry-After: 180s renders as value "3" with
		// unit "minutes" (largest whole unit that divides evenly).
		const retryInput = screen.getByLabelText(/Retry-After value/i) as HTMLInputElement;
		expect(retryInput.value).toBe('3');
		const retryUnit = screen.getByLabelText(/Retry-After unit/i) as HTMLSelectElement;
		expect(retryUnit.value).toBe('minutes');
		expect(screen.getByDisplayValue('10.0.0.5')).toBeInTheDocument();
		expect(screen.getByDisplayValue('192.168.1.0/24')).toBeInTheDocument();
	});

	it('ships maintenanceConfig in the update payload after editing the Maintenance section', async () => {
		const seeded = makeRoute({
			id: 'edit-maint2',
			host: 'edit-maint2.example.com',
			maintenanceConfig: { retryAfterSeconds: 60, bypassIps: [] }
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);

		const hostCell = await screen.findByText('edit-maint2.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		// v2.18.0 — pick "seconds" unit then type 90 so the wire value is
		// 90s (not 90 * the seeded "minutes" factor). Verifies the
		// number+unit → seconds conversion feeds the payload.
		const retryUnit = screen.getByLabelText(/Retry-After unit/i) as HTMLSelectElement;
		await userEvent.selectOptions(retryUnit, 'seconds');
		const retryInput = screen.getByLabelText(/Retry-After value/i) as HTMLInputElement;
		await userEvent.clear(retryInput);
		await userEvent.type(retryInput, '90');
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		expect(payload.maintenanceConfig).toBeDefined();
		expect(payload.maintenanceConfig.retryAfterSeconds).toBe(90);
	});

	// Finding #1 (final review, v2.17.0) — CRITICAL. A route that is
	// NOT in maintenance (no maintenanceConfig, not disabled) must NOT
	// have maintenanceConfig introduced by a routine edit. Before the
	// fix, the payload assembler always shipped
	// formData.maintenanceConfig, which openEdit seeds with the
	// synthetic default {retryAfterSeconds:300, bypassIps:[]} for a
	// route that has never been put into maintenance — so ANY edit
	// (e.g. changing the upstream URL) silently flipped the route
	// into maintenance (503 to everyone) on the next reload. This
	// test seeds a plain ACTIVE route, edits an unrelated field, and
	// asserts the update payload's maintenanceConfig stays
	// null/absent — i.e. the edit does NOT introduce maintenance.
	it('does NOT ship maintenanceConfig when editing an ACTIVE route (no maintenance introduced)', async () => {
		const seeded = makeRoute({
			id: 'edit-active-no-maint',
			host: 'active-no-maint.example.com'
			// disabled: false (default), maintenanceConfig: undefined (default) — plain active route.
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);

		const hostCell = await screen.findByText('active-no-maint.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		// Edit an unrelated field (the upstream URL) — a routine edit
		// that has nothing to do with maintenance.
		const upstreamInput = upstreamURLInputs()[0];
		await userEvent.clear(upstreamInput);
		await userEvent.type(upstreamInput, 'http://127.0.0.1:9100');
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		// Must NOT be the synthetic default {retryAfterSeconds:300, bypassIps:[]}
		// and must NOT be present at all (undefined/null) — the route
		// must stay active.
		expect(payload.maintenanceConfig == null).toBe(true);
	});
});

// --- v2.19.0 external-certs SOCLE (Task 8) — CertSource picker ------
//
// The route form's TLS area gains a "cert source" <select> (acme /
// internal / manual). Picking "manual" loads the uploaded external
// certs and filters them (RFC 6125 SAN match) to those covering the
// route host; picking one ships cert_source:'manual' + cert_id in the
// payload. These tests pin (a) the SAN filter (only covering certs
// shown), (b) the payload wiring, and (c) the no-eligible-cert
// warning path.

import type { ExternalCertificate } from '$lib/api/types';

function makeExternalCert(overrides: Partial<ExternalCertificate> = {}): ExternalCertificate {
	return {
		id: 'cert-fixture-1',
		name: 'wildcard-example',
		description: '',
		certPEM: '',
		chainPEM: '',
		keyPEM: '',
		issuer: 'CN=Test CA',
		subject: 'CN=*.example.com',
		serialNumber: '01',
		keyAlgorithm: 'ECDSA',
		signatureAlgorithm: 'ECDSA-SHA256',
		notBefore: '2026-01-01T00:00:00.000Z',
		notAfter: '2027-01-01T00:00:00.000Z',
		dnsNames: ['*.example.com'],
		createdAt: '2026-01-01T00:00:00.000Z',
		updatedAt: '2026-01-01T00:00:00.000Z',
		warnings: [],
		...overrides
	};
}

// The cert-source <select> carries a stable id so tests can target it
// without depending on the (Task-9-pending) i18n label text.
function certSourceSelect(): HTMLSelectElement | null {
	return document.getElementById('route-cert-source') as HTMLSelectElement | null;
}

describe('Routes page — CertSource picker (manual external certs)', () => {
	it('lists only certs whose SAN covers the host and ships cert_source:manual + cert_id', async () => {
		// Two certs: one covers app.example.com via *.example.com, the
		// other is for an unrelated host and must NOT appear.
		const covering = makeExternalCert({
			id: 'cert-covering',
			name: 'covers-example',
			dnsNames: ['*.example.com']
		});
		const nonCovering = makeExternalCert({
			id: 'cert-other',
			name: 'covers-other',
			dnsNames: ['app.other.test']
		});
		externalCertsMock.list.mockResolvedValue([covering, nonCovering]);

		const seeded = makeRoute({
			id: 'manual-fixture',
			host: 'app.example.com',
			tlsEnabled: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);

		render(Page);
		const hostCell = await screen.findByText('app.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		// Switch the cert-source select to "manual".
		const sel = certSourceSelect();
		expect(sel).not.toBeNull();
		await fireEvent.change(sel!, { target: { value: 'manual' } });
		await tick();
		// list() is awaited; give the microtask + reactive tick a beat.
		await waitFor(() => expect(externalCertsMock.list).toHaveBeenCalled());
		await tick();

		// The covering cert's radio must be present; the non-covering
		// cert must be filtered out. Each eligible cert renders a radio
		// input whose value is the cert id.
		const coveringRadio = document.querySelector<HTMLInputElement>(
			'input[type="radio"][value="cert-covering"]'
		);
		const otherRadio = document.querySelector<HTMLInputElement>(
			'input[type="radio"][value="cert-other"]'
		);
		expect(coveringRadio).not.toBeNull();
		expect(otherRadio).toBeNull();

		// Pick the covering cert.
		await fireEvent.click(coveringRadio!);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		expect(payload.cert_source).toBe('manual');
		expect(payload.cert_id).toBe('cert-covering');
	});

	it('excludes a pending_csr cert from the manual picker even when its SANs cover the host', async () => {
		// v2.20.0 finding: a pending_csr row has no signed leaf yet, so
		// picking it would create a TLS route serving NO certificate.
		// Spec §6 promises pending rows are never selectable here — this
		// pins the eligibleCerts status exclusion (independent of the
		// SAN-coverage filter, which the pending cert otherwise passes).
		const active = makeExternalCert({
			id: 'cert-active',
			name: 'active-example',
			dnsNames: ['*.example.com']
		});
		const pending = makeExternalCert({
			id: 'cert-pending',
			name: 'pending-example',
			status: 'pending_csr',
			certPEM: '',
			dnsNames: ['app.example.com']
		});
		externalCertsMock.list.mockResolvedValue([active, pending]);

		const seeded = makeRoute({
			id: 'manual-pending-fixture',
			host: 'app.example.com',
			tlsEnabled: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);

		render(Page);
		const hostCell = await screen.findByText('app.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		const sel = certSourceSelect();
		expect(sel).not.toBeNull();
		await fireEvent.change(sel!, { target: { value: 'manual' } });
		await tick();
		await waitFor(() => expect(externalCertsMock.list).toHaveBeenCalled());
		await tick();

		const activeRadio = document.querySelector<HTMLInputElement>(
			'input[type="radio"][value="cert-active"]'
		);
		const pendingRadio = document.querySelector<HTMLInputElement>(
			'input[type="radio"][value="cert-pending"]'
		);
		expect(activeRadio).not.toBeNull();
		expect(pendingRadio).toBeNull();
	});

	it('shows a warning (and no radios) when no uploaded cert covers the host', async () => {
		externalCertsMock.list.mockResolvedValue([
			makeExternalCert({ id: 'cert-other', dnsNames: ['app.other.test'] })
		]);

		const seeded = makeRoute({
			id: 'manual-none',
			host: 'app.example.com',
			tlsEnabled: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);

		render(Page);
		const hostCell = await screen.findByText('app.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		const sel = certSourceSelect();
		await fireEvent.change(sel!, { target: { value: 'manual' } });
		await tick();
		await waitFor(() => expect(externalCertsMock.list).toHaveBeenCalled());
		await tick();

		// No eligible cert → no radios rendered.
		expect(document.querySelector('input[type="radio"][value="cert-other"]')).toBeNull();
		// The warning surface carries a stable testid so the assertion
		// doesn't depend on the (Task-9-pending) i18n copy.
		expect(document.querySelector('[data-testid="cert-manual-none"]')).not.toBeNull();
	});

	it('does not synthesize cert_id on a non-manual (acme) route', async () => {
		const seeded = makeRoute({
			id: 'acme-fixture',
			host: 'app.example.com',
			tlsEnabled: true
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);

		render(Page);
		const hostCell = await screen.findByText('app.example.com');
		await fireEvent.click(hostCell.closest('tr')!);
		await tick();

		// Leave cert-source at its default (acme). Edit an unrelated
		// field so the submit is a routine PUT.
		const upstreamInput = upstreamURLInputs()[0];
		await userEvent.clear(upstreamInput);
		await userEvent.type(upstreamInput, 'http://127.0.0.1:9100');
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.updateRoute).toHaveBeenCalledTimes(1);
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		expect(payload.cert_source).toBe('acme');
		// cert_id must NOT be shipped on a non-manual route.
		expect(payload.cert_id).toBeUndefined();
	});
});

// --- Task 9 — route-level IP filter + path rules wiring ------------

describe('Routes page — Task 9 IP filter + path rules wiring', () => {
	it('includes ipFilter and pathRules in the save payload', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'secure.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		// Route-level IP filter: switch to deny mode + type a CIDR.
		// Only the route-level IPFilterFields instance is mounted at
		// this point (no path rules added yet), so a single
		// getByTestId is unambiguous.
		await userEvent.click(screen.getByTestId('ipfilter-mode-deny'));
		const cidrsTextarea = screen.getByTestId('ipfilter-cidrs') as HTMLTextAreaElement;
		await userEvent.type(cidrsTextarea, '10.0.0.0/8');
		await fireEvent.blur(cidrsTextarea);
		await tick();

		// Add one path rule scoped to /docs with basic auth.
		await userEvent.click(screen.getByTestId('path-rules-add'));
		await tick();
		const prefixInput = screen.getByTestId('path-rule-prefix-0') as HTMLInputElement;
		await userEvent.type(prefixInput, '/docs');
		await userEvent.click(screen.getByTestId('path-rule-basicauth-toggle-0'));
		await tick();
		await userEvent.type(screen.getByTestId('path-rule-basicauth-username-0'), 'docsuser');
		await userEvent.type(screen.getByTestId('path-rule-basicauth-password-0'), 'docspass');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.ipFilter).toMatchObject({ mode: 'deny', cidrs: ['10.0.0.0/8'] });
		expect(payload.pathRules).toHaveLength(1);
		expect(payload.pathRules[0].pathPrefix).toBe('/docs');
		expect(payload.pathRules[0].basicAuth).toMatchObject({
			username: 'docsuser',
			password: 'docspass'
		});
		// CRITICAL WIRE SHAPE — plain password, never passwordHash.
		expect(payload.pathRules[0].basicAuth.passwordHash).toBeUndefined();
	});
});

// v2.27 — geo filtering: continents + deny-only exceptions.
describe('Routes page — v2.27 geo filtering (continents + exceptions)', () => {
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('continents are shown for allow and deny; exceptions only for deny', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		expect(screen.getByTestId('geo-continents')).toBeInTheDocument();
		expect(screen.queryByTestId('geo-exceptions')).not.toBeInTheDocument();
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		expect(screen.getByTestId('geo-exceptions')).toBeInTheDocument();
	});

	it('a continent satisfies the allow-list footgun guard', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		expect(screen.getByTestId('country-block-allow-empty-error')).toBeInTheDocument();
		await userEvent.click(screen.getByTestId('geo-continent-EU'));
		await tick();
		expect(screen.queryByTestId('country-block-allow-empty-error')).not.toBeInTheDocument();
	});

	it('deny: continents + exceptions reach the POST payload and the summary', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ host: 'geo.example.com' }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'geo.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://127.0.0.1:8080');
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		await userEvent.click(screen.getByTestId('geo-continent-AS'));
		await userEvent.type(screen.getByTestId('geo-exceptions-input'), 'JP{enter}');
		await tick();
		expect(screen.getAllByTestId('geo-exception-chip')).toHaveLength(1);
		expect(screen.getByTestId('country-block-summary').textContent).toContain('1 continent(s)');
		expect(screen.getByTestId('country-block-summary').textContent).toContain('1 exception(s)');

		await userEvent.click(screen.getByRole('button', { name: /^Create$/i }));
		await tick();
		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0] as {
			countryBlock: { mode: string; continents: string[]; exceptions: { countries: string[] } };
		};
		expect(payload.countryBlock.mode).toBe('deny');
		expect(payload.countryBlock.continents).toEqual(['AS']);
		expect(payload.countryBlock.exceptions.countries).toEqual(['JP']);
	});

	it('exceptions are not shipped once the mode leaves deny', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ host: 'geo2.example.com' }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'geo2.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://127.0.0.1:8080');
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();
		await userEvent.click(screen.getByTestId('geo-continent-EU'));
		await userEvent.type(screen.getByTestId('geo-exceptions-input'), 'FR{enter}');
		await userEvent.click(screen.getByTestId('country-block-mode-allow'));
		await tick();
		await userEvent.click(screen.getByRole('button', { name: /^Create$/i }));
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0] as {
			countryBlock: { mode: string; continents: string[]; exceptions: { countries: string[] } };
		};
		expect(payload.countryBlock.mode).toBe('allow');
		expect(payload.countryBlock.continents).toEqual(['EU']);
		expect(payload.countryBlock.exceptions.countries).toEqual([]);
	});
});

// v2.28 — ASN rules and ASN exceptions reach the POST payload.
describe('Routes page — v2.28 geo filtering (ASN)', () => {
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('deny: ASN list + ASN exception are shipped; summary counts them', async () => {
		asnMock.namesASN.mockResolvedValue({ loaded: true, indexReady: true, results: [] });
		asnMock.searchASN.mockImplementation(async (q: string) => ({
			loaded: true,
			indexReady: true,
			results: q.includes('digital')
				? [{ asn: 14061, name: 'DigitalOcean' }]
				: [{ asn: 16276, name: 'OVH SAS' }]
		}));
		apiMock.createRoute.mockResolvedValue(makeRoute({ host: 'asn.example.com' }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'asn.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://127.0.0.1:8080');
		await userEvent.click(screen.getByTestId('country-block-mode-deny'));
		await tick();

		await userEvent.type(screen.getByTestId('geo-asns-input'), 'digital');
		await waitFor(() => expect(screen.getByTestId('geo-asns-suggestion')).toBeInTheDocument());
		await userEvent.keyboard('{Enter}');
		await userEvent.type(screen.getByTestId('geo-exception-asns-input'), 'ovh');
		await waitFor(() => expect(screen.getByTestId('geo-exception-asns-suggestion')).toBeInTheDocument());
		await userEvent.keyboard('{Enter}');
		await tick();
		const summary = screen.getByTestId('country-block-summary').textContent ?? '';
		expect(summary).toContain('1 ASN');
		expect(summary).toContain('1 exception(s)');

		await userEvent.click(screen.getByRole('button', { name: /^Create$/i }));
		await tick();
		const payload = apiMock.createRoute.mock.calls[0][0] as {
			countryBlock: { asns: number[]; exceptions: { asns: number[] } };
		};
		expect(payload.countryBlock.asns).toEqual([14061]);
		expect(payload.countryBlock.exceptions.asns).toEqual([16276]);
	});
});

// v2.35 — post-apply route check feedback.
describe('Routes page — post-apply route check', () => {
	async function fillAndSubmit() {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'app.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
	}

	it('warns (long toast) when the saved route does not answer, and creates it once', async () => {
		apiMock.createRoute.mockResolvedValueOnce({
			id: 'r1',
			host: 'app.test',
			check: { status: 'failed', host: 'app.test', httpStatus: 502, detail: 'the route answered 502 Bad Gateway' }
		});
		await fillAndSubmit();
		await waitFor(() => expect(apiMock.createRoute).toHaveBeenCalledTimes(1));
		expect(toastMock.pushToast).toHaveBeenCalledWith(
			'app.test is saved but does not answer: the route answered 502 Bad Gateway. Check that its backend is running.',
			'danger',
			12000
		);
	});

	it('explains a pending certificate without calling it a failure', async () => {
		apiMock.createRoute.mockResolvedValueOnce({
			id: 'r1',
			host: 'app.test',
			check: { status: 'pending_certificate', host: 'app.test' }
		});
		await fillAndSubmit();
		await waitFor(() =>
			expect(toastMock.pushToast).toHaveBeenCalledWith(
				expect.stringContaining('certificate is still being issued'),
				'info',
				12000
			)
		);
		// The check message already says the route is saved.
		expect(toastMock.pushToast).not.toHaveBeenCalledWith('Route created', 'success');
	});

	it('stays on the route, in edit mode, when it is saved but does not answer', async () => {
		const stored = makeRoute({ id: 'r1', host: 'app.test' });
		apiMock.createRoute.mockResolvedValueOnce({
			...stored,
			check: { status: 'failed', host: 'app.test', httpStatus: 502, detail: 'the route answered 502 Bad Gateway' }
		});
		apiMock.listRoutes.mockResolvedValue([stored]);
		await fillAndSubmit();

		const notice = await screen.findByTestId('save-check-failure');
		expect(notice).toHaveTextContent('app.test is saved but does not answer');
		// One message, not "Route created" beside "does not answer".
		expect(toastMock.pushToast).not.toHaveBeenCalledWith('Route created', 'success');
		// Reopened on the stored route: the edit-only pivots are there.
		expect(screen.getByTestId('panel-pivot-metrics')).toBeInTheDocument();
		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
	});

	it('keeps the panel open with the explanation when the change was undone (409)', async () => {
		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('undone', 409, 'validation', undefined, 'route_check_rolled_back', {
				host: 'app.test',
				detail: 'the route answered 502 Bad Gateway'
			})
		);
		await fillAndSubmit();
		expect(
			await screen.findByText(/Change undone: app\.test answered before this change and stopped answering after it/)
		).toBeInTheDocument();
		expect(hostInput()).toBeInTheDocument(); // panel still open
	});
});

// v2.35.1 — connection cut by a Caddy reload (UI reached over HTTP/3).
describe('Routes page — connection lost during a save', () => {
	it('reloads the list and explains instead of showing a raw network error', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'app.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		const listCallsBefore = apiMock.listRoutes.mock.calls.length;
		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('network error: NetworkError when attempting to fetch resource.', 0, 'system')
		);
		await fireEvent.submit(document.querySelector('form')!);
		await waitFor(() =>
			expect(toastMock.pushToast).toHaveBeenCalledWith(
				expect.stringContaining('The connection was cut while Caddy reloaded'),
				'info',
				12000
			)
		);
		expect(apiMock.listRoutes.mock.calls.length).toBeGreaterThan(listCallsBefore);
		expect(toastMock.pushToast).not.toHaveBeenCalledWith(expect.stringContaining('NetworkError'), 'danger');
	});
});

// --- v2.36 — targeted WAF exclusions editor ---------------------------

describe('Routes page — v2.36 targeted WAF exclusions', () => {
	it('loads the persisted exclusions on edit and ships the edited list', async () => {
		const seeded = makeRoute({
			id: 'targeted-edit',
			host: 'targeted.local',
			wafMode: 'block',
			wafTargetedExclusions: [{ ruleId: 942100, target: 'ARGS:content', path: '/api/save' }]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		const hostCell = await screen.findByText('targeted.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		expect(screen.getAllByTestId('waf-targeted-row')).toHaveLength(1);
		await userEvent.type(screen.getByTestId('waf-targeted-rule'), '941100');
		await userEvent.type(screen.getByTestId('waf-targeted-name'), 'body');
		await userEvent.click(screen.getByTestId('waf-targeted-add'));

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.updateRoute.mock.calls[0][1];
		expect(payload.wafTargetedExclusions).toEqual([
			{ ruleId: 942100, target: 'ARGS:content', path: '/api/save' },
			{ ruleId: 941100, target: 'ARGS:body' }
		]);
	});
});

// --- v2.37 — guided WAF rules editor ------------------------------------

describe('Routes page — v2.37 guided WAF rules', () => {
	it('loads the persisted rules on edit and ships them, with a new preset rule', async () => {
		const seeded = makeRoute({
			id: 'rules-edit',
			host: 'rules.local',
			wafMode: 'block',
			wafCustomRules: [
				{ id: 120000, name: 'Admin', conditions: [{ field: 'path', operator: 'begins_with', values: ['/admin'] }] }
			]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		const hostCell = await screen.findByText('rules.local');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		expect(screen.getAllByTestId('waf-rule-row')).toHaveLength(1);
		await userEvent.click(screen.getByTestId('waf-rule-preset-methods'));
		await userEvent.click(screen.getByTestId('waf-rule-ok'));

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.updateRoute.mock.calls[0][1];
		expect(payload.wafCustomRules).toHaveLength(2);
		expect(payload.wafCustomRules[0]).toEqual({
			id: 120000,
			name: 'Admin',
			conditions: [{ field: 'path', operator: 'begins_with', values: ['/admin'] }]
		});
		expect(payload.wafCustomRules[1].id).toBe(0);
		expect(payload.wafCustomRules[1].conditions[0]).toEqual({
			field: 'method',
			operator: 'is_not',
			values: ['GET', 'HEAD', 'POST', 'OPTIONS']
		});
	});
});

describe('Routes page — a guided WAF rule left open', () => {
	// The draft lives in the editor until OK. Save used to ship the
	// route without it, with a success toast.
	it('blocks the save and points at the open rule', async () => {
		const seeded = makeRoute({ id: 'draft-edit', host: 'draft.local', wafMode: 'block' });
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		await userEvent.click((await screen.findByText('draft.local')).closest('tr')!);
		await tick();

		await userEvent.click(screen.getByTestId('waf-rule-preset-methods'));
		await tick();
		// An open draft is unsaved work, even before any other change.
		expect(screen.getByTestId('form-dirty')).toBeInTheDocument();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.updateRoute).not.toHaveBeenCalled();
		expect(screen.getByTestId('waf-rule-draft-error')).toBeInTheDocument();
		expect(screen.getByTestId('section-waf').hasAttribute('data-invalid')).toBe(true);
	});
});

// --- v2.38 — SecLang (advanced) ---------------------------------------

describe('Routes page — v2.38 SecLang', () => {
	beforeEach(() => {
		apiMock.validateSecLang.mockResolvedValue({ errors: [], nextId: 130003 });
	});

	it('converts a guided rule to SecLang and ships both fields', async () => {
		const seeded = makeRoute({
			id: 'convert',
			host: 'convert.local',
			wafMode: 'block',
			wafSecLang: 'SecAction "id:130000,phase:1,pass,nolog"',
			wafCustomRules: [
				{ id: 120000, name: 'Admin', conditions: [{ field: 'path', operator: 'begins_with', values: ['/admin'] }] }
			]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		apiMock.secLangFromGuided.mockResolvedValue({ seclang: '# Admin\nSecRule REQUEST_FILENAME "@rx ^(?:/admin)" "id:130003"\n' });
		render(Page);
		await userEvent.click((await screen.findByText('convert.local')).closest('tr')!);
		await tick();

		await userEvent.click(screen.getByTestId('waf-rule-convert'));
		await waitFor(() => expect(screen.queryAllByTestId('waf-rule-row')).toHaveLength(0));
		expect(apiMock.secLangFromGuided).toHaveBeenCalledWith(seeded.wafCustomRules[0], 130003);

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		const payload = apiMock.updateRoute.mock.calls[0][1];
		expect(payload.wafCustomRules).toEqual([]);
		expect(payload.wafSecLang).toBe(
			'SecAction "id:130000,phase:1,pass,nolog"\n\n# Admin\nSecRule REQUEST_FILENAME "@rx ^(?:/admin)" "id:130003"\n'
		);
	});

	it('keeps the panel open and shows the problems when the save refuses the SecLang', async () => {
		const seeded = makeRoute({ id: 'refused', host: 'refused.local', wafMode: 'block', wafSecLang: 'Include /etc/passwd' });
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockRejectedValue(
			new ApiError('wafSecLang: line 1: directive "include" is not allowed', 400, 'validation', undefined, 'seclang_invalid', {
				errors: [{ line: 1, message: 'directive "include" is not allowed' }]
			})
		);
		render(Page);
		await userEvent.click((await screen.findByText('refused.local')).closest('tr')!);
		await tick();
		await fireEvent.submit(document.querySelector('form')!);
		await waitFor(() => expect(screen.getByTestId('seclang-problems')).toBeInTheDocument());
		expect(screen.getByTestId('seclang-problems').textContent).toContain('include');
		expect(document.querySelector('form')).not.toBeNull();
	});
});

// --- v2.40 — Caddyfile import -----------------------------------------

describe('Routes page — v2.40 Caddyfile import', () => {
	it('the import button is enabled and opens the modal', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await tick();
		const btn = screen.getByTestId('import-caddyfile-open') as HTMLButtonElement;
		expect(btn.disabled).toBe(false);
		expect(screen.queryByTestId('import-caddyfile')).toBeNull();
		await userEvent.click(btn);
		expect(screen.getByTestId('import-caddyfile')).toBeInTheDocument();
	});
});

// --- v2.41 — the form as collapsible sections ---------------------------

describe('Routes page — v2.41 route form sections', () => {
	it('groups the form into sections and keeps every field reachable', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		for (const id of [
			'section-essentials',
			'section-tls',
			'section-auth',
			'section-waf',
			'section-rate-limit',
			'section-geo-ip',
			'section-health-check',
			'section-paths-headers',
			'section-error-pages',
			'section-state'
		]) {
			expect(screen.getByTestId(id)).toBeInTheDocument();
		}
		// Essentials is the only one open on arrival.
		expect((screen.getByTestId('section-essentials') as HTMLDetailsElement).open).toBe(true);
		expect((screen.getByTestId('section-waf') as HTMLDetailsElement).open).toBe(false);

		// Fields of a closed section stay in the DOM (the panel is one form).
		expect(document.getElementById('route-waf-mode')).not.toBeNull();
		expect(hostInput()).toBeInTheDocument();
	});

	it('summarises each section from what is being edited', async () => {
		const seeded = makeRoute({
			id: 'summary',
			host: 'summary.local',
			aliases: ['alias.local'],
			upstreams: [
				{ url: 'http://10.0.0.1:8080', weight: 1 },
				{ url: 'http://10.0.0.2:8080', weight: 1 }
			],
			tlsEnabled: true,
			redirectToHttps: true,
			wafMode: 'block',
			wafCustomRules: [
				{ id: 120000, name: 'r', conditions: [{ field: 'path', operator: 'is', values: ['/x'] }] }
			],
			countryBlock: {
				mode: 'deny',
				countryList: ['RU'],
				continents: [],
				asns: [],
				exceptions: { countries: [], asns: [] },
				statusCode: 403
			}
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		await userEvent.click((await screen.findByText('summary.local')).closest('tr')!);
		await tick();

		const row = (id: string) => screen.getByTestId(id).querySelector('summary')!.textContent ?? '';
		expect(row('section-essentials')).toContain('HTTPS');
		expect(row('section-essentials')).toContain('2 backend');
		expect(row('section-essentials')).toContain('1 alias');
		expect(row('section-tls')).toContain("Let's Encrypt");
		expect(row('section-waf')).toContain('block');
		expect(row('section-waf')).toContain('OWASP CRS');
		expect(row('section-waf')).toContain('1 custom rule');
		expect(row('section-geo-ip')).toContain('deny');
		expect(row('section-state')).toMatch(/active/i);
	});

	// v2.58.3 — an operator pointed out that a Paths & headers section holding
	// five configured rules read as untouched, while every other configured
	// section shows its colour. The cause was worse than cosmetic: the
	// exemption used posture 'off', which RouteSection documents as
	// "configured but inactive". An exemption is active — it is the one thing
	// that changes what reaches the backend — so 'off' was a false statement
	// about the route, in the one place meant to be readable at a glance.
	it('shows a configured auth exemption as active, not as off', async () => {
		const seeded = makeRoute({
			id: 'exempt',
			host: 'exempt.local',
			authMode: 'forward_auth',
			forwardAuth: { providerName: 'authentik' },
			pathRules: [
				{ pathPrefix: '/webhook', disableRouteAuth: true },
				{ pathPrefix: '/form', disableRouteAuth: true }
			]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		await userEvent.click((await screen.findByText('exempt.local')).closest('tr')!);
		await tick();

		const section = screen.getByTestId('section-paths-headers');
		// The rail colour is the glanceable signal, and 'off' means
		// "configured but inactive" in this component's contract.
		expect(section.getAttribute('data-posture')).not.toBe('off');
		expect(section.getAttribute('data-posture')).toBe('allow');
		// And the badge still names what it is, so the colour is never read
		// as a protection the route does not have.
		const row = section.querySelector('summary')?.textContent ?? '';
		expect(row.toLowerCase()).toMatch(/exempt/);
	});

	// v2.58.3 — the operator's actual need: tell, without opening anything,
	// which sections hold configuration. Eight of ten already did, because
	// configuring them means deciding about traffic. These are the two that
	// did not.
	it('marks a configured Error pages section, and leaves an empty one neutral', async () => {
		const configured = makeRoute({
			id: 'errpages',
			host: 'errpages.local',
			errorPageTemplateId: 'tpl-1',
			errorPageOverrides: { '404': 'o1', '503': 'o2' }
		});
		apiMock.listRoutes.mockResolvedValue([configured]);
		render(Page);
		await userEvent.click((await screen.findByText('errpages.local')).closest('tr')!);
		await tick();

		const section = screen.getByTestId('section-error-pages');
		// Configured: visible, and in the accent rather than a traffic colour.
		expect(section.getAttribute('data-posture')).toBe('set');
		const row = section.querySelector('summary')?.textContent ?? '';
		expect(row).toMatch(/2/); // the override count reaches the closed row
	});

	it('leaves an untouched Error pages section with no rail at all', async () => {
		apiMock.listRoutes.mockResolvedValue([makeRoute({ id: 'plain', host: 'plain.local' })]);
		render(Page);
		await userEvent.click((await screen.findByText('plain.local')).closest('tr')!);
		await tick();

		const section = screen.getByTestId('section-error-pages');
		// Nothing in it: no posture. That distinction is the whole point —
		// "empty" must not look like "configured but deciding nothing".
		expect(section.getAttribute('data-posture')).toBeNull();
	});

	it('marks path rules that gate nothing as configured, not as off', async () => {
		const seeded = makeRoute({
			id: 'routingonly',
			host: 'routingonly.local',
			pathRules: [{ pathPrefix: '/old', redirect: { target: '/new', statusCode: 302 } }]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		await userEvent.click((await screen.findByText('routingonly.local')).closest('tr')!);
		await tick();

		const section = screen.getByTestId('section-paths-headers');
		// A redirect is configuration. Grey "off" said the section was empty.
		expect(section.getAttribute('data-posture')).toBe('set');
		expect(section.getAttribute('data-posture')).not.toBe('off');
	});

	it('follows the edits live: switching the WAF mode updates its summary row', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		// The closed row is what must follow the edit, not the body.
		const row = () => screen.getByTestId('section-waf').querySelector('summary')!.textContent ?? '';
		expect(row()).toContain('detect');

		await setWafMode('block');
		expect(row()).toContain('block');
		expect(row()).not.toContain('detect');

		await setWafMode('off');
		expect(row()).toContain('no inspection');
	});
});

describe('Routes page — v2.41 unsaved-changes marker', () => {
	it('appears once the form is touched and goes with the panel', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		expect(screen.queryByTestId('form-dirty')).toBeNull();

		await userEvent.type(hostInput(), 'dirty.example.com');
		await tick();
		expect(screen.getByTestId('form-dirty')).toBeInTheDocument();

		// v2.41 step 3 — Cancel now asks before dropping the edits.
		await userEvent.click(screen.getByText(/^Annuler$|^Cancel$/));
		await userEvent.click(screen.getByText('Discard changes'));
		await tick();
		expect(screen.queryByTestId('form-dirty')).toBeNull();
	});
});

// --- v2.41 step 3 — the unsaved marker now protects something ----
//
// Every path that would drop the edits asks first: Cancel, a click
// outside the panel, and picking another row. Confirming replays the
// action that was interrupted ; declining leaves the form exactly as
// it was. A form with no edits never asks.

describe('Routes page — v2.41 discard guard', () => {
	it('keeps the form when the operator declines, drops it when they confirm', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'guard.example.com');
		await tick();

		await userEvent.click(screen.getByText(/^Annuler$|^Cancel$/));
		expect(screen.getByText('Discard your changes?')).toBeInTheDocument();

		await userEvent.click(screen.getByText('Keep editing'));
		await tick();
		expect(hostInput().value).toBe('guard.example.com');
		expect(screen.getByTestId('form-dirty')).toBeInTheDocument();

		await userEvent.click(screen.getByText(/^Annuler$|^Cancel$/));
		await userEvent.click(screen.getByText('Discard changes'));
		await tick();
		expect(document.querySelector('form')).toBeNull();
	});

	it('asks before switching to another route, then opens the one that was picked', async () => {
		const a = makeRoute({ id: 'a', host: 'a.example.com' });
		const b = makeRoute({ id: 'b', host: 'b.example.com' });
		apiMock.listRoutes.mockResolvedValue([a, b]);
		render(Page);

		await userEvent.click((await screen.findByText('a.example.com')).closest('tr')!);
		await tick();
		await userEvent.type(hostInput(), '-edited');
		await tick();

		await userEvent.click(screen.getByText('b.example.com').closest('tr')!);
		expect(screen.getByText('Discard your changes?')).toBeInTheDocument();
		// Declining leaves the edited route in the form.
		await userEvent.click(screen.getByText('Keep editing'));
		await tick();
		expect(hostInput().value).toBe('a.example.com-edited');

		await userEvent.click(screen.getByText('b.example.com').closest('tr')!);
		await userEvent.click(screen.getByText('Discard changes'));
		await tick();
		expect(hostInput().value).toBe('b.example.com');
	});

	it('does not ask when nothing was edited', async () => {
		const a = makeRoute({ id: 'a', host: 'a.example.com' });
		apiMock.listRoutes.mockResolvedValue([a]);
		render(Page);

		await userEvent.click((await screen.findByText('a.example.com')).closest('tr')!);
		await tick();
		await userEvent.click(screen.getByText(/^Annuler$|^Cancel$/));
		await tick();
		expect(screen.queryByText('Discard your changes?')).toBeNull();
		expect(document.querySelector('form')).toBeNull();
	});
});

// --- v2.41 step 3 — posture chips in the routes list -------------

describe('Routes page — v2.41 posture chips', () => {
	it('shows what guards each route, and a dash when nothing does', async () => {
		const guarded = makeRoute({
			id: 'guarded',
			host: 'guarded.example.com',
			wafMode: 'block',
			rateLimit: { events: 60, window: '1m', key: '{http.request.remote.host}' },
			countryBlock: {
				mode: 'deny',
				countryList: ['RU', 'CN'],
				continents: [],
				asns: [],
				exceptions: { countries: [], asns: [] },
				statusCode: 403
			},
			ipFilter: { mode: 'allow', cidrs: ['192.168.1.0/24'] }
		});
		const open = makeRoute({ id: 'open', host: 'open.example.com' });
		apiMock.listRoutes.mockResolvedValue([guarded, open]);
		render(Page);

		const row = (await screen.findByText('guarded.example.com')).closest('tr')!;
		expect(row.textContent).toContain('Block');
		expect(row.querySelector('[data-testid="posture-geo"]')!.getAttribute('title')).toContain('2');
		expect(row.querySelector('[data-testid="posture-ip"]')!.getAttribute('title')).toContain(
			'only 1'
		);
		expect(row.querySelector('[data-testid="posture-rate-limit"]')!.textContent).toContain('60/1m');

		const bare = screen.getByText('open.example.com').closest('tr')!;
		expect(bare.querySelector('[data-testid="posture-geo"]')).toBeNull();
		expect(bare.querySelector('[data-testid="posture-rate-limit"]')).toBeNull();
	});
});

// --- v2.41 step 2 — WAF section interior -------------------------
//
// The WAF block moved from "a dropdown plus a stack of checkboxes"
// to a segmented control, switch rows and a two-column exceptions
// sub-group. What is pinned here is what the operator reads, not
// the markup: every mode is visible at once, the selected one
// states its consequence, the CRS-off warning is stated once for
// both exclusion lists, and the sub-group counts what it holds.

describe('Routes page — v2.41 WAF section interior', () => {
	it('offers the three modes at once and marks the selected one', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		const seg = (m: string) => screen.getByTestId(`route-waf-mode-${m}`);
		expect(seg('off')).toBeInTheDocument();
		expect(seg('detect').getAttribute('aria-checked')).toBe('true');
		expect(seg('block').getAttribute('aria-checked')).toBe('false');

		await setWafMode('block');
		expect(seg('block').getAttribute('aria-checked')).toBe('true');
		expect(seg('detect').getAttribute('aria-checked')).toBe('false');
	});

	it('states the consequence of the selected mode', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		const waf = () => screen.getByTestId('section-waf').textContent ?? '';
		expect(waf()).toMatch(/never blocked/i);

		await setWafMode('block');
		expect(waf()).toMatch(/403/);

		await setWafMode('off');
		expect(waf()).toMatch(/straight to the backend/i);
	});

	it('ships the mode picked on the segmented control', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ wafMode: 'block' }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'seg.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8080');
		await setWafMode('block');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.createRoute.mock.calls[0][0].wafMode).toBe('block');
	});

	it('counts what the CRS exceptions sub-group holds', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		expect(screen.queryByTestId('waf-exceptions-count')).toBeNull();

		await userEvent.type(screen.getByTestId('waf-exclude-rules-input'), '942100, 920420');
		await userEvent.type(screen.getByTestId('waf-exclude-tags-input'), 'attack-sqli');
		await tick();
		expect(screen.getByTestId('waf-exceptions-count').textContent).toContain('3');
	});

	it('states the CRS-off warning once and disables both exclusion lists', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		expect(screen.queryByTestId('waf-exceptions-crs-off')).toBeNull();

		await userEvent.click(screen.getByTestId('waf-disable-crs-toggle'));
		await userEvent.click(screen.getByText('Disable CRS'));
		await tick();

		expect(screen.getAllByTestId('waf-exceptions-crs-off')).toHaveLength(1);
		expect((screen.getByTestId('waf-exclude-rules-input') as HTMLTextAreaElement).disabled).toBe(true);
		expect((screen.getByTestId('waf-exclude-tags-input') as HTMLTextAreaElement).disabled).toBe(true);
	});
});

// --- v2.41 step 2 — rate limit + authentication interiors --------

describe('Routes page — v2.41 rate limit interior', () => {
	it('states the rule the three fields add up to, and follows them', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		expect(screen.queryByTestId('rate-limit-sentence')).toBeNull();

		await userEvent.click(screen.getByTestId('rate-limit-toggle'));
		await tick();
		const sentence = () => screen.getByTestId('rate-limit-sentence').textContent ?? '';
		// Defaults: 60 requests / 1m, keyed on the peer IP — the raw
		// Caddy placeholder is spelled out, not printed.
		expect(sentence()).toContain('60');
		expect(sentence()).toContain('1m');
		expect(sentence()).toContain('client IP');
		expect(sentence()).toContain('429');
		expect(sentence()).not.toContain('http.request');

		const events = screen.getByTestId('rate-limit-events-input') as HTMLInputElement;
		await userEvent.clear(events);
		await userEvent.type(events, '5');
		await tick();
		expect(sentence()).toContain('5');
	});

	it('names a custom key as the operator typed it', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('rate-limit-toggle'));
		await tick();

		const key = screen.getByTestId('rate-limit-key-input') as HTMLInputElement;
		await userEvent.clear(key);
		await userEvent.type(key, '{{http.request.header.X-Forwarded-For}');
		await tick();
		expect(screen.getByTestId('rate-limit-sentence').textContent).toContain('X-Forwarded-For');
	});
});

describe('Routes page — v2.41 authentication interior', () => {
	it('offers the three auth modes and reveals the fields of the one picked', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		expect(screen.getByTestId('route-auth-mode-none').getAttribute('aria-checked')).toBe('true');
		expect(document.getElementById('basic-auth-password')).toBeNull();

		await userEvent.click(screen.getByTestId('route-auth-mode-basic'));
		await tick();
		expect(document.getElementById('basic-auth-password')).not.toBeNull();
		expect(screen.getByTestId('section-auth').querySelector('summary')!.textContent).toContain(
			'basic auth'
		);

		// forward_auth with no provider configured: say where to make one.
		await userEvent.click(screen.getByTestId('route-auth-mode-forward_auth'));
		await tick();
		expect(document.getElementById('basic-auth-password')).toBeNull();
		expect(screen.getByTestId('forward-auth-no-provider')).toBeInTheDocument();
	});

	it('ships the picked auth mode in the payload', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute({ authMode: 'basic' }));
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'auth.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:8080');

		await userEvent.click(screen.getByTestId('route-auth-mode-basic'));
		await tick();
		await userEvent.type(screen.getByPlaceholderText('admin'), 'ops');
		await userEvent.type(document.getElementById('basic-auth-password') as HTMLInputElement, 'sekret');

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.authMode).toBe('basic');
		expect(payload.basicAuth.username).toBe('ops');
	});
});

// --- v2.41.1 — a section must not close under the operator ------
//
// `open` used to be passed straight through to <details>, so any
// parent re-render re-applied open={false}: picking an auth mode or
// a WAF mode changed the summary and snapped the section shut.

describe('Routes page — v2.41.1 sections stay open while editing', () => {
	it('keeps a section open when a choice inside it changes the summary', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		const auth = screen.getByTestId('section-auth') as HTMLDetailsElement;
		auth.open = true;
		await tick();

		await userEvent.click(screen.getByTestId('route-auth-mode-basic'));
		await tick();
		expect(auth.open).toBe(true);
		expect(document.getElementById('basic-auth-password')).not.toBeNull();

		// And the WAF section, whose summary also follows its mode.
		const waf = screen.getByTestId('section-waf') as HTMLDetailsElement;
		waf.open = true;
		await tick();
		await setWafMode('block');
		expect(waf.open).toBe(true);
	});
});

// --- v2.41.1 — state control, panel chrome, error overrides ------

describe('Routes page — v2.41.1 state section', () => {
	it('sits first, and ships maintenance with the save — not on click', async () => {
		const seeded = makeRoute({ id: 'st', host: 'st.example.com' });
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		await userEvent.click((await screen.findByText('st.example.com')).closest('tr')!);
		await tick();

		// First section of the form.
		const sections = Array.from(document.querySelectorAll('[data-testid^="section-"]'));
		expect(sections[0].getAttribute('data-testid')).toBe('section-state');

		// Maintenance settings only show under Maintenance.
		const state = screen.getByTestId('section-state') as HTMLDetailsElement;
		state.open = true;
		await tick();
		expect(screen.queryByTestId('maintenance-bypass-ip-grid')).toBeNull();

		await userEvent.click(screen.getByTestId('route-state-maintenance'));
		await tick();
		expect(screen.getByTestId('maintenance-bypass-ip-grid')).toBeInTheDocument();
		expect(apiMock.enterMaintenance).not.toHaveBeenCalled();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();
		expect(apiMock.enterMaintenance).not.toHaveBeenCalled();
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		expect(payload.disabled).toBe(false);
		expect(payload.maintenanceConfig).toMatchObject({ retryAfterSeconds: 300 });
	});

	// v2.45.2 — maintenance used to be withheld on a route that does
	// not exist yet, on the grounds that it is a transition rather
	// than a birth state. Defensible in the abstract, confusing in
	// practice: the operator opened a new route, counted three options
	// where four exist, and reported maintenance as missing. Nothing
	// prevents a route from being born in maintenance, and the
	// asymmetry became indefensible once redirect appeared there.
	it('offers every state on a route that does not exist yet', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		expect(screen.getByTestId('route-state-active')).toBeInTheDocument();
		expect(screen.getByTestId('route-state-maintenance')).toBeInTheDocument();
		expect(screen.getByTestId('route-state-disabled')).toBeInTheDocument();
		expect(screen.getByTestId('state-create-hint')).toBeInTheDocument();
	});
});

describe('Routes page — v2.41.1 panel chrome', () => {
	it('keeps the metrics and security links in the sticky header', async () => {
		const seeded = makeRoute({ id: 'piv', host: 'piv.example.com' });
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		await userEvent.click((await screen.findByText('piv.example.com')).closest('tr')!);
		await tick();

		const pivots = screen.getByTestId('panel-pivots');
		// The sticky header is the pivots' ancestor — they no longer
		// scroll out of sight with the form body.
		expect(pivots.closest('.sticky')).not.toBeNull();
		expect(pivots.querySelector('a[href="/observability/piv"]')).not.toBeNull();
		expect(pivots.querySelector('a[href="/security/piv"]')).not.toBeNull();
		// Delete is no longer next to them.
		expect(pivots.textContent ?? '').not.toMatch(/delete|supprimer/i);
	});
});

describe('Routes page — v2.41.1 error-page overrides', () => {
	it('drops the per-code editor but says when overrides are applied', async () => {
		const seeded = makeRoute({
			id: 'ovr',
			host: 'ovr.example.com',
			errorPageOverrides: { '502': '<html>down</html>' }
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		await userEvent.click((await screen.findByText('ovr.example.com')).closest('tr')!);
		await tick();

		expect(screen.queryByTestId('error-override-502')).toBeNull();
		expect(screen.getByTestId('error-overrides-notice').textContent ?? '').toContain('1');
	});
});

// --- v2.41.2 — every section says on/off, and the rate limit is
// a protection in force (green), not traffic turned away (red).

describe('Routes page — v2.41.2 section badges', () => {
	it('badges TLS and the health check, and greens the rate limit', async () => {
		const seeded = makeRoute({
			id: 'badges',
			host: 'badges.example.com',
			tlsEnabled: true,
			rateLimit: { events: 60, window: '1m', key: '{http.request.remote.host}' },
			healthCheck: {
				enabled: true,
				uri: '/health',
				method: 'GET',
				interval: '30s',
				timeout: '5s',
				passes: 1,
				fails: 3,
				expectStatus: 200,
				expectBody: ''
			}
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		render(Page);
		await userEvent.click((await screen.findByText('badges.example.com')).closest('tr')!);
		await tick();

		const row = (id: string) => screen.getByTestId(id).querySelector('summary')!;
		expect(row('section-tls').textContent).toContain('https');
		expect(screen.getByTestId('section-tls').getAttribute('data-posture')).toBe('allow');

		expect(row('section-health-check').textContent).toMatch(/on/i);
		expect(screen.getByTestId('section-health-check').getAttribute('data-posture')).toBe('allow');

		// A cap on abuse reads as a protection in force, like auth.
		expect(screen.getByTestId('section-rate-limit').getAttribute('data-posture')).toBe('allow');
	});

	it('greys them when off', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		expect(screen.getByTestId('section-health-check').getAttribute('data-posture')).toBe('off');
		expect(screen.getByTestId('section-rate-limit').getAttribute('data-posture')).toBe('off');
	});
});

// --- v2.43.1 — the probe's verdict, where you configure it -------
//
// The list has shown the aggregate health since Pack A, but the form
// — the one screen where the URI, the expected status and the
// expected body are set — showed only on/off. After changing a probe
// you had to leave the form to learn whether it now passes. The
// 2026-09-24 session lost an afternoon to that gap: a probe expecting
// "OK" against a backend answering JSON took the route out of service
// while every field on screen looked right.

function routeWithProbe(status: Route['aggregateStatus'], healthy: number): Route {
	return makeRoute({
		id: 'probe-fixture',
		host: 'probe.example.com',
		healthCheck: {
			enabled: true,
			uri: '/healthz/ready',
			method: 'GET',
			interval: '30s',
			timeout: '5s',
			expectStatus: 200,
			expectBody: 'OK',
			passes: 2,
			fails: 3
		},
		aggregateStatus: status,
		healthyUpstreamCount: healthy,
		totalUpstreamCount: 1
	});
}

async function openProbeRoute(route: Route) {
	apiMock.listRoutes.mockResolvedValue([route]);
	render(Page);
	await userEvent.click((await screen.findByText(route.host)).closest('tr')!);
	await tick();
}

describe('Routes page — the health check reports its own verdict', () => {
	it('says the probe is failing, and points at the fields that decide it', async () => {
		await openProbeRoute(routeWithProbe('down', 0));

		const live = screen.getByTestId('health-check-live');
		expect(live.textContent).toMatch(/DOWN/i);
		// The hint must name the probe's own fields — the address is
		// not what is wrong on this path.
		expect(live.textContent).toMatch(/expected body/i);
		// And the section badge must not claim "on" while every
		// backend is down.
		expect(screen.getByTestId('section-health-check').getAttribute('data-posture')).toBe('block');
	});

	it('shows the green verdict without the warning', async () => {
		await openProbeRoute(routeWithProbe('healthy', 1));

		const live = screen.getByTestId('health-check-live');
		expect(live.textContent).toMatch(/HEALTHY/i);
		expect(live.textContent).not.toMatch(/expected body/i);
		expect(screen.getByTestId('section-health-check').getAttribute('data-posture')).toBe('allow');
	});

	it('does not paint warm-up as a failure', async () => {
		await openProbeRoute(routeWithProbe('unknown', 0));

		const live = screen.getByTestId('health-check-live');
		expect(live.textContent).toMatch(/first probe/i);
		expect(live.textContent).not.toMatch(/expected body/i);
		expect(screen.getByTestId('section-health-check').getAttribute('data-posture')).toBe('allow');
	});

	it('says nothing while creating a route, where no probe has run', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByTestId('health-check-toggle'));
		await tick();
		expect(screen.queryByTestId('health-check-live')).toBeNull();
	});
});

describe('Routes page — a rollback caused by the health check', () => {
	it('names the probe instead of sending the operator to the upstream address', async () => {
		apiMock.createRoute.mockRejectedValueOnce(
			new ApiError('undone', 409, 'validation', undefined, 'route_check_rolled_back', {
				host: 'app.test',
				detail: 'the route answered 503 Service Unavailable',
				cause: 'health_check'
			})
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'app.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const shown = await screen.findByRole('alert');
		expect(shown.textContent).toMatch(/active health check/i);
		expect(shown.textContent).toMatch(/expected body/i);
		// The generic wording would have pointed here, and it is the
		// one thing that is not wrong on this path.
		expect(shown.textContent).not.toMatch(/fix the change \(upstream address/i);
	});
});

// --- v2.44 — the redirect state ----------------------------------
//
// A fourth exclusive state, next to Active / Maintenance / Disabled.
// It exists for moving a domain: old.example.com answers 301 to
// new.example.com and proxies nothing. It deliberately cannot express
// "/ goes to /admin/login" — that target is on the same host, so the
// redirect would match its own target and loop. The server refuses
// that at save; the form says so before the operator tries.

describe('Routes page — the redirect state', () => {
	it('offers the state and ships what the form holds', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		apiMock.createRoute.mockResolvedValue({ id: 'r1', host: 'old.test' });
		render(Page);
		await openCreateForm();

		await userEvent.type(hostInput(), 'old.test');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		// The state control carries it, and it is a birth state: a
		// route created purely to forward a retired name never needs
		// to have proxied anything first.
		await userEvent.click(screen.getByText('Redirect'));
		await tick();

		await userEvent.type(screen.getByTestId('redirect-target'), 'https://new.test');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		await waitFor(() => expect(apiMock.createRoute).toHaveBeenCalledTimes(1));
		const payload = apiMock.createRoute.mock.calls[0][0];
		expect(payload.redirectConfig).toMatchObject({
			target: 'https://new.test',
			statusCode: 301,
			preservePath: true
		});
		// The two states are exclusive: choosing one must not ship the
		// other, which the server would refuse.
		expect(payload.maintenanceConfig).toBeUndefined();
	});

	it('says what a redirecting route stops doing', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();
		await userEvent.click(screen.getByText('Redirect'));
		await tick();

		const warning = screen.getByTestId('redirect-warning').textContent ?? '';
		expect(warning).toMatch(/WAF/);
		// TLS is the exception and the form must say so: a redirect
		// served on a broken certificate is a browser warning, not a
		// redirect.
		expect(warning).toMatch(/TLS/);

		// And the loop, named before the operator meets it.
		expect(screen.getByTestId('redirect-fields').textContent).toMatch(/different host/i);
	});

	it('reads a stored redirect back into the form', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'red-1',
				host: 'old.example.com',
				redirectConfig: { target: 'https://new.example.com', statusCode: 302, preservePath: false }
			})
		]);
		render(Page);
		await userEvent.click((await screen.findByText('old.example.com')).closest('tr')!);
		await tick();

		expect((screen.getByTestId('redirect-target') as HTMLInputElement).value).toBe(
			'https://new.example.com'
		);
		expect((screen.getByTestId('redirect-preserve-path') as HTMLInputElement).checked).toBe(false);
	});

	it('shows the state on the row without offering to switch it there', async () => {
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'red-1',
				host: 'old.example.com',
				redirectConfig: { target: 'https://new.example.com' }
			})
		]);
		render(Page);
		const row = (await screen.findByText('old.example.com')).closest('tr')!;

		// The dedicated maintenance/disable endpoints take no argument
		// and a redirect needs a target, so the row states it and the
		// form changes it.
		expect(row.textContent).toMatch(/Redirect/);
	});
});

// --- v2.45.2 — a redirecting route needs no backend --------------
//
// The operator hit this creating a route whose only job was to
// forward a retired name: the form demanded an upstream, which meant
// inventing an address that would never be dialled.

describe('Routes page — a redirect needs no upstream', () => {
	it('saves without a backend', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		apiMock.createRoute.mockResolvedValue({ id: 'r1', host: 'old.test' });
		render(Page);
		await openCreateForm();

		await userEvent.type(hostInput(), 'old.test');
		await userEvent.click(screen.getByText('Redirect'));
		await tick();
		await userEvent.type(screen.getByTestId('redirect-target'), 'https://new.test');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		await waitFor(() => expect(apiMock.createRoute).toHaveBeenCalledTimes(1));
		const payload = apiMock.createRoute.mock.calls[0][0];
		// No invented address travels on the wire.
		expect(payload.upstreams).toEqual([]);
		expect(payload.redirectConfig).toMatchObject({ target: 'https://new.test' });
	});

	// The requirement still stands for every other route: without a
	// pool there is nothing to serve.
	it('still demands one for a proxying route', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		await userEvent.type(hostInput(), 'app.test');
		await fireEvent.submit(document.querySelector('form')!);
		await tick();

		expect(apiMock.createRoute).not.toHaveBeenCalled();
	});
});

// Maintenance is offered when creating a route, not only when editing
// one. The asymmetry was defensible in the abstract and confusing in
// practice: the operator counted three options where four exist.
describe('Routes page — the four states are all offered at creation', () => {
	it('lists active, maintenance, redirect and disabled', async () => {
		apiMock.listRoutes.mockResolvedValue([]);
		render(Page);
		await openCreateForm();

		const state = screen.getByTestId('section-state');
		for (const label of ['Active', 'Maintenance', 'Redirect', 'Disabled']) {
			expect(state.textContent).toContain(label);
		}
	});
});

// --- v2.45.3 — a path redirect must survive Save ------------------
//
// The operator configured "/" exact → /admin/login, got a success
// toast, and the log said "config is unchanged": the submit payload
// rebuilds every path rule field by field, and the two v2.44 fields
// were not on the list. They were dropped between the form and the
// wire, silently, while the UI reported success.
//
// The same hole existed on hydrate, so an unrelated edit to a route
// would have wiped a stored redirect.

const redirectRule = {
	pathPrefix: '/',
	matchExact: true,
	redirect: { target: '/admin/login', statusCode: 302 }
};

describe('Routes page — path-rule redirects survive the round trip', () => {
	it('ships matchExact and the redirect on save', async () => {
		const seeded = makeRoute({ id: 'r-red', host: 'app.example.com' });
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);

		await userEvent.click((await screen.findByText('app.example.com')).closest('tr')!);
		await tick();

		// Add the rule the way the editor does, then save.
		await userEvent.click(screen.getByTestId('path-rules-add'));
		await tick();
		await userEvent.type(screen.getByTestId('path-rule-prefix-0'), '/');
		await userEvent.click(screen.getByTestId('path-rule-exact-toggle-0'));
		await userEvent.click(screen.getByTestId('path-rule-redirect-toggle-0'));
		await tick();
		await userEvent.type(screen.getByTestId('path-rule-redirect-target-0'), '/admin/login');
		await tick();
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		await waitFor(() => expect(apiMock.updateRoute).toHaveBeenCalled());
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		const rule = payload.pathRules?.[0];
		expect(rule?.matchExact).toBe(true);
		expect(rule?.redirect).toMatchObject({ target: '/admin/login', statusCode: 302 });
	});

	// An unrelated edit must not wipe a redirect the route already has.
	it('keeps a stored redirect through an unrelated edit', async () => {
		const seeded = makeRoute({
			id: 'r-red',
			host: 'app.example.com',
			pathRules: [redirectRule]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);

		await userEvent.click((await screen.findByText('app.example.com')).closest('tr')!);
		await tick();
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		await waitFor(() => expect(apiMock.updateRoute).toHaveBeenCalled());
		const [, payload] = apiMock.updateRoute.mock.calls[0];
		const rule = payload.pathRules?.[0];
		expect(rule?.matchExact).toBe(true);
		expect(rule?.redirect).toMatchObject({ target: '/admin/login' });
	});
});

// --- v2.48 — the table owns the page until a route is selected ----

describe('Routes page — the split only opens on demand', () => {
	it('is one column until a route is selected', async () => {
		apiMock.listRoutes.mockResolvedValue([makeRoute({ id: 'r1', host: 'app.example.com' })]);
		render(Page);

		const row = (await screen.findByText('app.example.com')).closest('tr')!;
		const split = row.closest('.split');
		expect(split).not.toBeNull();
		expect(split?.classList.contains('split-open')).toBe(false);

		await userEvent.click(row);
		await tick();
		expect(split?.classList.contains('split-open')).toBe(true);
	});
});

// v2.56.3 — path rules must survive an edit that never touched them.
//
// The route form rebuilds each path rule field by field TWICE: once when
// loading a route into the form, once when assembling the submit payload.
// A field missing from either is silently dropped on the next save, with a
// success toast. That has now happened three times — an upstream pool, a
// redirect, and a rate limit — and each time a warning comment was added
// beside the code rather than a test.
//
// This is that test. It carries every field a rule can hold through the
// round trip, so the next addition fails here instead of deleting an
// operator's configuration.
describe('routes page — path rules survive an unrelated edit', () => {
	const fullRule = {
		pathPrefix: '/admin',
		basicAuth: { username: 'ops', passwordSet: true },
		ipFilter: { mode: 'allow' as const, cidrs: ['10.0.0.0/8'], statusCode: 403 },
		upstreams: [{ url: 'http://10.0.0.9:8080', weight: 2 }],
		lbPolicy: 'least_conn' as const,
		healthCheck: {
			enabled: true,
			uri: '/healthz',
			method: 'GET' as const,
			interval: '30s',
			timeout: '5s',
			expectStatus: 200,
			expectBody: '',
			passes: 1,
			fails: 1
		},
		insecureSkipVerify: true,
		matchExact: true,
		rateLimit: { events: 10, window: '5m', key: '{http.request.remote.host}' }
	};

	it('ships every sub-block back unchanged after an unrelated change', async () => {
		const seeded = makeRoute({
			id: 'keep-path-rules',
			host: 'keep.paths.example.com',
			pathRules: [fullRule]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		const hostCell = await screen.findByText('keep.paths.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.updateRoute.mock.calls[0][1] as {
			pathRules?: Record<string, unknown>[];
		};
		const rules = payload.pathRules ?? [];
		expect(rules, 'the rule was dropped entirely').toHaveLength(1);
		const sent = rules[0];

		// The password is blanked on purpose — the server keeps the stored
		// hash when it receives an empty one. Everything else must return.
		expect(sent.pathPrefix).toBe('/admin');
		expect(sent.ipFilter).toMatchObject({ mode: 'allow', cidrs: ['10.0.0.0/8'], statusCode: 403 });
		expect(sent.upstreams).toEqual([{ url: 'http://10.0.0.9:8080', weight: 2 }]);
		expect(sent.lbPolicy).toBe('least_conn');
		expect(sent.healthCheck).toMatchObject({ enabled: true, uri: '/healthz' });
		expect(sent.insecureSkipVerify).toBe(true);
		expect(sent.matchExact).toBe(true);
		// THE reported one: persisted, enforced, and absent from the form.
		expect(
			sent.rateLimit,
			'the path rate limit was lost on an edit that never touched it'
		).toMatchObject({ events: 10, window: '5m' });
		expect((sent.basicAuth as { username: string }).username).toBe('ops');
	});

	// Every field of the fixture above must actually reach the payload. A
	// field silently missing from BOTH rebuilds would pass the assertions
	// above only if someone forgot to assert it — this counts instead.
	it('sends as many sub-blocks as the rule carried', async () => {
		const seeded = makeRoute({
			id: 'count-path-rules',
			host: 'count.paths.example.com',
			pathRules: [fullRule]
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		const hostCell = await screen.findByText('count.paths.example.com');
		await userEvent.click(hostCell.closest('tr')!);
		await tick();
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		const payload = apiMock.updateRoute.mock.calls[0][1] as {
			pathRules?: Record<string, unknown>[];
		};
		const sent = (payload.pathRules ?? [])[0] ?? {};
		const expected = Object.keys(fullRule);
		const missing = expected.filter((k) => !(k in sent));
		expect(
			missing,
			`these sub-blocks never reached the payload and would be deleted on save: ${missing.join(', ')}`
		).toEqual([]);
	});
});

// v2.56.3 — "the Save button does absolutely nothing".
//
// submitForm returns early when validateBeforeSubmit fails, and used to do
// so with no feedback at all: an error under a key no template renders
// produced no message, no toast and no request. The operator's only signal
// was the absence of one.
describe('routes page — a refused save is always visible', () => {
	it('shows something when the API refuses a path rule', async () => {
		apiMock.createRoute.mockRejectedValue(
			new ApiError('path_rule "/secure": ipfilter: mode "allow" requires at least one IP/CIDR', 400, 'validation')
		);
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'repro2.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByTestId('path-rules-add'));
		await tick();
		await userEvent.type(screen.getByTestId('path-rule-prefix-0') as HTMLInputElement, '/secure');
		const allow = screen.getAllByTestId('ipfilter-mode-allow');
		await userEvent.click(allow[allow.length - 1]);
		await tick();
		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(document.body.textContent).toContain('IP/CIDR');
	});

	// A rule the operator named but left empty is refused — and the refusal
	// has to be SEEN. This is the case that produced "the button does
	// nothing": the error key exists, no template rendered it.
	it('says why when a named but empty path rule blocks the save', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'empty.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');
		await userEvent.click(screen.getByTestId('path-rules-add'));
		await tick();
		await userEvent.type(screen.getByTestId('path-rule-prefix-0') as HTMLInputElement, '/named-but-empty');
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute, 'an empty rule must not be sent').not.toHaveBeenCalled();
		// The refusal is on screen, next to the section that caused it.
		//
		// The toast that also fires is not asserted here: ToastContainer is
		// mounted by the layout, not by this page, so this harness cannot
		// observe it. Asserting it would be asserting the harness.
		expect(screen.getByTestId('path-rule-error-0').textContent).toContain('/named-but-empty');
	});

	// A rule whose only content is an IP filter mode is legitimate content
	// and must reach the API, not be refused locally.
	it('submits when a path rule has an IP filter in allow mode', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'repro.example.com');
		await userEvent.type(upstreamURLInputs()[0], 'http://127.0.0.1:9000');

		// Open Paths & headers and add a rule.
		await userEvent.click(screen.getByTestId('path-rules-add'));
		await tick();
		const prefix = screen.getByTestId('path-rule-prefix-0') as HTMLInputElement;
		await userEvent.type(prefix, '/secure');
		await tick();

		// Set the IP filter to allow.
		const allowRadios = screen.getAllByTestId('ipfilter-mode-allow');
		await userEvent.click(allowRadios[allowRadios.length - 1]);
		await tick();

		await fireEvent.submit(document.querySelector('form')!);
		await tick();
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalled();
	});
});

// -----------------------------------------------------------------
// v2.59 — the list row of a REDIRECTING route.
//
// Three cells lied about it, and all three were invisible to the
// test suite because no test ever rendered a redirecting row:
//   - Upstream was blank (the route legally has no pool), so the one
//     fact that matters — where the visitor is sent — appeared
//     nowhere in the list and was not searchable.
//   - State read UNKNOWN with a tooltip describing a health-check
//     warm-up window, on a route with neither health check nor
//     backend: a window that can never close.
//   - Security advertised the stored WAF / geo / IP / rate-limit
//     config, none of which is emitted for a route that proxies
//     nothing (manager.go:1549 → :1618).
// -----------------------------------------------------------------
describe('Routes page — a redirecting route reads as a redirect', () => {
	function redirectRoute() {
		return makeRoute({
			id: 'redir-1',
			host: 'old.example.com',
			upstreams: [],
			totalUpstreamCount: 0,
			healthyUpstreamCount: 0,
			aggregateStatus: 'not_applicable',
			wafMode: 'block',
			redirectConfig: { target: 'https://new.example.com', statusCode: 301, preservePath: true }
		} as Partial<Route>);
	}

	it('shows the redirect target in the Upstream column', async () => {
		apiMock.listRoutes.mockResolvedValue([redirectRoute()]);
		render(Page);
		const target = await screen.findByTestId('redirect-target-cell');
		expect(target.textContent).toBe('https://new.example.com');
	});

	it('shows a dash instead of UNKNOWN in the State column', async () => {
		apiMock.listRoutes.mockResolvedValue([redirectRoute()]);
		render(Page);
		const dash = await screen.findByTestId('route-status-dash');
		expect(dash.textContent).toBe('—');
		expect(screen.queryByText('UNKNOWN')).not.toBeInTheDocument();
	});

	it('shows no WAF chip although wafMode is block', async () => {
		apiMock.listRoutes.mockResolvedValue([redirectRoute()]);
		render(Page);
		await screen.findByText('old.example.com');
		expect(screen.getByTestId('posture-inert')).toBeInTheDocument();
	});

	it('finds the route by its redirect target in the search box', async () => {
		apiMock.listRoutes.mockResolvedValue([
			redirectRoute(),
			makeRoute({ id: 'other', host: 'app.example.com' })
		]);
		render(Page);
		await screen.findByText('old.example.com');
		const search = screen.getByLabelText(/filter routes/i);
		await userEvent.type(search, 'new.example.com');
		await tick();
		expect(screen.getByText('old.example.com')).toBeInTheDocument();
		expect(screen.queryByText('app.example.com')).not.toBeInTheDocument();
	});

	it('does not count a redirecting route as active, nor as WAF-protected', async () => {
		apiMock.listRoutes.mockResolvedValue([
			redirectRoute(),
			makeRoute({ id: 'live', host: 'app.example.com', wafMode: 'block' })
		]);
		render(Page);
		await screen.findByText('app.example.com');
		// Two routes total, one active, one with a WAF that runs.
		const cards = screen.getAllByTestId(/^stat-card-/);
		const byId = (suffix: string) =>
			cards.find((c) => c.getAttribute('data-testid') === `stat-card-${suffix}`);
		expect(byId('total')?.textContent).toContain('2');
		expect(byId('active')?.textContent).toContain('1');
		expect(byId('waf')?.textContent).toContain('1');
	});
});

// -----------------------------------------------------------------
// v2.60 — the upstream TLS server name.
//
// It exists so a pool addressed by IP can still be authenticated,
// which until now cost either an invisible /etc/hosts pin on the
// Arenet host or turning certificate verification off. The pin, left
// out by one step during a DNS cutover, put Arenet in a self-proxy
// loop in production on 2026-10-03 — so this field's whole value is
// that the backend address and its identity are both on screen.
// -----------------------------------------------------------------
describe('Routes page — upstream TLS server name', () => {
	function firstURL(): HTMLInputElement {
		return upstreamURLInputs()[0];
	}

	it('is offered only on an https pool, and disappears with the scheme', async () => {
		render(Page);
		await openCreateForm();
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://10.0.0.5');
		await tick();
		expect(screen.getByTestId('upstream-tls-server-name')).toBeInTheDocument();

		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.5');
		await tick();
		expect(screen.queryByTestId('upstream-tls-server-name')).not.toBeInTheDocument();
	});

	it('ships the name in the POST payload on an https pool', async () => {
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'forum.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'https://194.163.129.255');
		await tick();
		await userEvent.type(screen.getByTestId('upstream-tls-server-name'), 'forum.example.com');
		await tick();
		await userEvent.click(screen.getByRole('button', { name: /^Create$/i }));
		await tick();

		expect(apiMock.createRoute).toHaveBeenCalledTimes(1);
		const payload = apiMock.createRoute.mock.calls[0][0] as Record<string, unknown>;
		expect(payload.upstreamTlsServerName).toBe('forum.example.com');
	});

	it('omits the name from the payload on an http-only pool', async () => {
		// The server normalises it away there, so sending it would only
		// invite the two layers to disagree.
		apiMock.createRoute.mockResolvedValue(makeRoute());
		render(Page);
		await openCreateForm();
		await userEvent.type(hostInput(), 'plain.example.com');
		await userEvent.clear(firstURL());
		await userEvent.type(firstURL(), 'http://10.0.0.10:8123');
		await tick();
		await userEvent.click(screen.getByRole('button', { name: /^Create$/i }));
		await tick();

		const payload = apiMock.createRoute.mock.calls[0][0] as Record<string, unknown>;
		expect('upstreamTlsServerName' in payload).toBe(false);
	});

	it('loads a stored name back into the form when editing', async () => {
		// The hydration gap this guards: a field absent from openEdit is
		// wiped by the next save, silently.
		apiMock.listRoutes.mockResolvedValue([
			makeRoute({
				id: 'r-sni',
				host: 'forum.example.com',
				upstreams: [{ url: 'https://194.163.129.255', weight: 1 }],
				upstreamTlsServerName: 'forum.example.com'
			})
		]);
		render(Page);
		const row = (await screen.findByText('forum.example.com')).closest('tr')!;
		await userEvent.click(row);
		await tick();
		const input = screen.getByTestId('upstream-tls-server-name') as HTMLInputElement;
		expect(input.value).toBe('forum.example.com');
	});

	it('an emptied field ships as "" so a name can be removed', async () => {
		const seeded = makeRoute({
			id: 'r-sni',
			host: 'forum.example.com',
			upstreams: [{ url: 'https://194.163.129.255', weight: 1 }],
			upstreamTlsServerName: 'forum.example.com'
		});
		apiMock.listRoutes.mockResolvedValue([seeded]);
		apiMock.updateRoute.mockResolvedValue(seeded);
		render(Page);
		const row = (await screen.findByText('forum.example.com')).closest('tr')!;
		await userEvent.click(row);
		await tick();
		await userEvent.clear(screen.getByTestId('upstream-tls-server-name'));
		await tick();
		await userEvent.click(screen.getByRole('button', { name: /^Save$/i }));
		await tick();

		expect(apiMock.updateRoute).toHaveBeenCalled();
		const payload = apiMock.updateRoute.mock.calls[0][1] as Record<string, unknown>;
		expect(payload.upstreamTlsServerName).toBe('');
	});
});

// -----------------------------------------------------------------
// v2.61 — reaching a route's metrics and security.
//
// The operator's words: "on ne voit pas très bien les boutons dans le
// modale d'édition d'une route et comment y arriver". The audit found
// three causes, and only one of them was styling:
//   - the two links were 11px text-secondary chips with no fill, in
//     row 3 of a sticky header, and ABSENT in create mode;
//   - the list rows had no entry point to either page at all;
//   - below 1280px the panel is not beside the list, it is stacked
//     under the entire table, so clicking a route looked like it did
//     nothing.
// -----------------------------------------------------------------
describe('Routes page — reaching metrics and security', () => {
	const seeded = () =>
		makeRoute({ id: 'r-nav', host: 'app.example.com', wafMode: 'block' });

	it('a list row links to the route security page from the Security column', async () => {
		apiMock.listRoutes.mockResolvedValue([seeded()]);
		render(Page);
		await screen.findByText('app.example.com');
		const link = screen.getByTestId('row-pivot-security');
		expect(link.getAttribute('href')).toBe('/security/r-nav');
	});

	it('a list row links to the route metrics page from the State column', async () => {
		apiMock.listRoutes.mockResolvedValue([seeded()]);
		render(Page);
		await screen.findByText('app.example.com');
		const link = screen.getByTestId('row-pivot-metrics');
		expect(link.getAttribute('href')).toBe('/observability/r-nav');
	});

	it('clicking a row link does not also open the edit panel', async () => {
		// The whole <tr> is the affordance for opening the panel, so a
		// link inside it has to stop the event or the operator both
		// navigates and opens a form they did not ask for.
		apiMock.listRoutes.mockResolvedValue([seeded()]);
		render(Page);
		await screen.findByText('app.example.com');
		await userEvent.click(screen.getByTestId('row-pivot-security'));
		await tick();
		expect(screen.queryByTestId('route-row-selected')).not.toBeInTheDocument();
	});

	it('the panel pivots are present before the first save, and say why not yet', async () => {
		// Previously `{#if formMode === 'edit'}` hid them entirely in
		// create mode — the one place a new operator starts.
		render(Page);
		await openCreateForm();
		expect(screen.getByTestId('panel-pivot-pending')).toBeInTheDocument();
		expect(screen.queryByTestId('panel-pivot-metrics')).not.toBeInTheDocument();
	});

	it('the panel pivots become real links once a route is selected', async () => {
		apiMock.listRoutes.mockResolvedValue([seeded()]);
		render(Page);
		const row = (await screen.findByText('app.example.com')).closest('tr')!;
		await userEvent.click(row);
		await tick();
		expect(screen.getByTestId('panel-pivot-metrics').getAttribute('href')).toBe(
			'/observability/r-nav'
		);
		expect(screen.getByTestId('panel-pivot-security').getAttribute('href')).toBe(
			'/security/r-nav'
		);
		expect(screen.queryByTestId('panel-pivot-pending')).not.toBeInTheDocument();
	});
});

// --- Panel header metrics strip ---------------------------------------------
//
// Four numbers in the panel header so "is this route alive and
// healthy?" is answerable without leaving the form. The tests
// below are mostly about what the strip must NOT say: an absent
// measurement and a measurement of zero are different facts, and
// conflating them is the failure that matters here.
describe('routes page: panel header metrics strip', () => {
	function seededRoute() {
		return makeRoute({ id: 'r-strip', host: 'strip.example.com' });
	}

	async function openStripPanel() {
		apiMock.listRoutes.mockResolvedValue([seededRoute()]);
		render(Page);
		const row = (await screen.findByText('strip.example.com')).closest('tr')!;
		await userEvent.click(row);
		await tick();
	}

	function summary(over: Record<string, unknown> = {}) {
		return {
			routeId: 'r-strip',
			generatedAt: '2026-10-04T12:00:00Z',
			windowSeconds: 86400,
			reqs: 1234,
			fourxx: 12,
			fivexx: 0,
			// Legacy field, still on the wire for pre-v15 readers.
			p95LatencyMs: 184.4,
			// Schema v15: the two real quantiles, plus the count that
			// decides whether they may be shown at all.
			totalMs: 340,
			ttfbMs: 110,
			samples: 1234,
			bytesOut: 12_400_000,
			hijacked: 0,
			...over
		};
	}

	it('shows the route traffic once the summary resolves', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary());
		await openStripPanel();

		const strip = await screen.findByTestId('panel-metrics-strip');
		expect(within(strip).getByTestId('panel-metrics-reqs').textContent).toContain('1,234');
		expect(within(strip).getByTestId('panel-metrics-fourxx').textContent).toContain('12');
	});

	it('shows the server time and the transfer time as two figures', async () => {
		// The point of the whole latency-truth change. One number could
		// not tell the operator that their 6701 ms was 0.1 s of server
		// and 23.9 s of a visitor downloading a 2.9 MB file.
		metricsMock.fetchRouteSummary.mockResolvedValue(summary());
		await openStripPanel();

		const strip = await screen.findByTestId('panel-metrics-strip');
		expect(within(strip).getByTestId('panel-metrics-ttfb').textContent).toContain('110 ms');
		expect(within(strip).getByTestId('panel-metrics-total').textContent).toContain('340 ms');
		// And the volume that explains the gap between them.
		expect(within(strip).getByTestId('panel-metrics-bytes').textContent).toContain('12 MB');
	});

	it('keeps a decimal where it changes the reading', async () => {
		// 2.9 MB is the size of the file that actually caused the
		// operator's slow transfers. Rounding it to "3 MB" loses the
		// only digit that distinguishes a heavy asset from a
		// reasonable one, so values under 10 keep one decimal while
		// larger ones do not — roughly constant significant figures,
		// not constant decimals.
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ bytesOut: 2_899_675 }));
		await openStripPanel();
		const bytes = await screen.findByTestId('panel-metrics-bytes');
		expect(bytes.textContent).toContain('2.9 MB');
	});

	it('hides the volume when nothing was served', async () => {
		// Zero bytes on a window with no recorded distribution is not
		// a measurement of zero egress; showing "0 B" would invent one.
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ bytesOut: 0 }));
		await openStripPanel();
		await screen.findByTestId('panel-metrics-strip');
		expect(screen.queryByTestId('panel-metrics-bytes')).not.toBeInTheDocument();
	});

	it('rounds the latency figures to whole milliseconds', async () => {
		// A decimal of a millisecond is noise in a header.
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ ttfbMs: 109.6, totalMs: 184.4 }));
		await openStripPanel();
		const strip = await screen.findByTestId('panel-metrics-strip');
		expect(within(strip).getByTestId('panel-metrics-ttfb').textContent).toContain('110 ms');
		expect(within(strip).getByTestId('panel-metrics-total').textContent).toContain('184 ms');
	});

	it('says the latency was not recorded, not that traffic was thin', async () => {
		// THE case the operator's instance returned the hour v2.63.0
		// landed: samples 0, reqs 44673, partialHistogram true. The
		// requests were counted; the distribution a percentile needs
		// was never kept and cannot be recomputed.
		//
		// "too few requests for a p95" would be a plain lie on 44,673
		// requests — and the two situations are indistinguishable on
		// the wire, both having null quantiles and a sample count under
		// the threshold.
		metricsMock.fetchRouteSummary.mockResolvedValue(
			summary({
				reqs: 44673,
				fourxx: 1464,
				fivexx: 3,
				samples: 0,
				totalMs: null,
				ttfbMs: null,
				bytesOut: 0,
				partialHistogram: true
			})
		);
		await openStripPanel();

		await screen.findByTestId('panel-metrics-nohist');
		expect(screen.queryByTestId('panel-metrics-thin')).not.toBeInTheDocument();
		expect(screen.queryByTestId('panel-metrics-ttfb')).not.toBeInTheDocument();
		// The request counts are real and must still be shown.
		expect(screen.getByTestId('panel-metrics-reqs').textContent).toContain('44,673');
	});

	it('says the traffic was thin when it genuinely was', async () => {
		// The mirror case: 9 requests, 9 samples. Below twenty,
		// ceil(0.95 * n) === n and a "p95" is the slowest request, so
		// the API returns null — but here the sample size IS the honest
		// explanation.
		metricsMock.fetchRouteSummary.mockResolvedValue(
			summary({ reqs: 9, samples: 9, totalMs: null, ttfbMs: null })
		);
		await openStripPanel();

		await screen.findByTestId('panel-metrics-thin');
		expect(screen.queryByTestId('panel-metrics-nohist')).not.toBeInTheDocument();
	});

	it('flags a window that straddles the upgrade boundary', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ partialHistogram: true }));
		await openStripPanel();

		const partial = await screen.findByTestId('panel-metrics-partial');
		// The explanation lives in the title, so the strip stays a row
		// of facts rather than a paragraph.
		expect(partial.getAttribute('title')).toBeTruthy();
	});

	it('keeps the partial marker beside a volume it also qualifies', async () => {
		// The request counts cover the whole window; the percentiles
		// AND the bytes do not, because rows predating schema v15
		// carry neither a distribution nor a byte count. On a freshly
		// upgraded instance that read "1.8 GB served … last 24 h"
		// while the bytes covered about an hour.
		//
		// The marker is the only thing qualifying that number, so a
		// refactor that keeps the volume and drops the marker has to
		// fail here.
		metricsMock.fetchRouteSummary.mockResolvedValue(
			summary({ reqs: 61_786, bytesOut: 1_800_000_000, partialHistogram: true })
		);
		await openStripPanel();

		const strip = await screen.findByTestId('panel-metrics-strip');
		expect(within(strip).getByTestId('panel-metrics-bytes').textContent).toContain('1.8 GB');
		const partial = within(strip).getByTestId('panel-metrics-partial');
		expect(partial).toBeInTheDocument();
		// And the explanation must name the volume, not only the
		// percentiles — the wording was wrong on exactly that point.
		expect(partial.getAttribute('title')).toMatch(/bytes|volume/i);
	});

	it('reports upgraded connections, which explain a missing TTFB', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ hijacked: 37, ttfbMs: null }));
		await openStripPanel();

		const ws = await screen.findByTestId('panel-metrics-hijacked');
		expect(ws.textContent).toContain('37');
		expect(screen.getByTestId('panel-metrics-ttfb').textContent).toContain('—');
	});

	it('asks for the summary of the route that was selected', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary());
		await openStripPanel();
		expect(metricsMock.fetchRouteSummary).toHaveBeenCalledWith('r-strip');
	});

	it('renders no strip at all while the summary is in flight', async () => {
		// A skeleton of zeros would be read as "this route served
		// nothing", which is a different fact from "we do not know
		// yet". Never render a number we do not have.
		metricsMock.fetchRouteSummary.mockReturnValue(new Promise(() => {}));
		await openStripPanel();
		expect(screen.queryByTestId('panel-metrics-strip')).not.toBeInTheDocument();
	});

	it('renders no strip when the summary request fails', async () => {
		metricsMock.fetchRouteSummary.mockRejectedValue(new ApiError('boom', 503, 'system'));
		await openStripPanel();
		await tick();
		expect(screen.queryByTestId('panel-metrics-strip')).not.toBeInTheDocument();
		// And it must not shout about it over a form being edited.
		expect(toastMock.pushToast).not.toHaveBeenCalled();
	});

	it('says the metrics are unavailable rather than showing zeros in degraded mode', async () => {
		// disabled=true means the observability subsystem failed at
		// boot. Its counters are all zero and they mean "unknown".
		metricsMock.fetchRouteSummary.mockResolvedValue(
			summary({ disabled: true, reqs: 0, fourxx: 0, fivexx: 0, p95LatencyMs: null })
		);
		await openStripPanel();

		await screen.findByTestId('panel-metrics-unavailable');
		expect(screen.queryByTestId('panel-metrics-reqs')).not.toBeInTheDocument();
	});

	it('distinguishes a route with no traffic from a route it cannot measure', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(
			summary({ reqs: 0, fourxx: 0, fivexx: 0, p95LatencyMs: null })
		);
		await openStripPanel();

		await screen.findByTestId('panel-metrics-nodata');
		expect(screen.queryByTestId('panel-metrics-unavailable')).not.toBeInTheDocument();
		expect(screen.queryByTestId('panel-metrics-reqs')).not.toBeInTheDocument();
	});

	it('renders a null latency as a dash, never as 0 ms', async () => {
		// Enough samples, but one of the two measurements is missing.
		// 0 ms would read as "instant"; the honest answer is "not
		// measured".
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ totalMs: null }));
		await openStripPanel();

		const total = await screen.findByTestId('panel-metrics-total');
		expect(total.textContent).toContain('—');
		expect(total.textContent).not.toContain('0 ms');
	});

	it('tints the 5xx count only when there are 5xx', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ fivexx: 7 }));
		await openStripPanel();

		const fivexx = await screen.findByTestId('panel-metrics-fivexx');
		expect(fivexx.querySelector('.text-down')).not.toBeNull();
		// A 4xx is ordinary traffic on a public host — tinting it
		// would cry wolf on every route that a bot ever probed.
		const fourxx = screen.getByTestId('panel-metrics-fourxx');
		expect(fourxx.querySelector('.text-down')).toBeNull();
	});

	it('leaves the 5xx count untinted at zero', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary({ fivexx: 0 }));
		await openStripPanel();

		const fivexx = await screen.findByTestId('panel-metrics-fivexx');
		expect(fivexx.querySelector('.text-down')).toBeNull();
	});

	it('shows no strip in create mode', async () => {
		metricsMock.fetchRouteSummary.mockResolvedValue(summary());
		render(Page);
		await openCreateForm();
		expect(screen.queryByTestId('panel-metrics-strip')).not.toBeInTheDocument();
		expect(metricsMock.fetchRouteSummary).not.toHaveBeenCalled();
	});

	it('drops a stale summary that lands after the operator moved on', async () => {
		// Click route A, then B before A's request resolves. A's
		// numbers must not appear under B's host — the bug class
		// where a slow response overwrites a newer selection.
		const a = makeRoute({ id: 'r-a', host: 'a.example.com' });
		const b = makeRoute({ id: 'r-b', host: 'b.example.com' });
		apiMock.listRoutes.mockResolvedValue([a, b]);

		let resolveA: (v: unknown) => void = () => {};
		metricsMock.fetchRouteSummary.mockImplementation((id: string) => {
			if (id === 'r-a') return new Promise((res) => (resolveA = res));
			return Promise.resolve(summary({ routeId: 'r-b', reqs: 42 }));
		});

		render(Page);
		const rowA = (await screen.findByText('a.example.com')).closest('tr')!;
		await userEvent.click(rowA);
		await tick();

		const rowB = (await screen.findByText('b.example.com')).closest('tr')!;
		await userEvent.click(rowB);
		await tick();
		await waitFor(() =>
			expect(screen.getByTestId('panel-metrics-reqs').textContent).toContain('42')
		);

		// A's response arrives late, for a route no longer shown.
		resolveA(summary({ routeId: 'r-a', reqs: 999 }));
		await tick();
		await tick();
		expect(screen.getByTestId('panel-metrics-reqs').textContent).toContain('42');
		expect(screen.getByTestId('panel-metrics-reqs').textContent).not.toContain('999');
	});
});
