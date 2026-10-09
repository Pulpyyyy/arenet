// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /certs page tests — pin the contract of:
//   - #R-6 Pack A migration: editor mounted on /certs,
//     auto-renewal info card rendered, /settings no longer
//     carries the managed-domains UI.
//   - Step T T.4: unified Domaines table fed by GET
//     /api/certificates, runtime KPI cards, Tous/Wildcard/
//     Expirent bientôt tab filter, status badges per AC #10,
//     OBTAIN_FAILED tooltip, empty + error states. Pack A
//     editor must remain functional even when /api/certificates
//     fails (AC #13 degraded mode mirrored on the frontend).

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { Certificate } from '$lib/api/types';

// Mocks. Same vi.hoisted pattern as the Routes page tests so the
// module imports happen after the mock factories are in place.
const { toastMock, apiMock, settingsMock, certsMock, securityMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		listRoutes: vi.fn(),
	},
	settingsMock: {
		settingsApi: {
			listManagedDomains: vi.fn(),
			createManagedDomain: vi.fn(),
			deleteManagedDomain: vi.fn(),
			listDNSProviders: vi.fn(),
		},
	},
	certsMock: {
		certificatesApi: {
			list: vi.fn(),
			deleteCertificate: vi.fn(),
		},
	},
	securityMock: {
		fetchCertEvents: vi.fn(),
	},
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/client', () => apiMock);
vi.mock('$lib/api/settings', () => settingsMock);
vi.mock('$lib/api/certificates', () => certsMock);
vi.mock('$lib/api/security', () => securityMock);

import Page from './+page.svelte';

// Anchor "now" for the fixture so daysUntilExpiry calculations
// land at deterministic values regardless of when CI runs. We
// stub Date in tests that depend on the precise day count;
// fixture timestamps are computed relative to this anchor.
const NOW = new Date('2026-06-05T12:00:00Z');

function daysFromNow(days: number): string {
	return new Date(NOW.getTime() + days * 86400000).toISOString();
}

// Step T T.4 — fixture covering every status the AC #10 badge
// table maps. Tests that don't need the full set reach into this
// list by domain.
const fixtureCerts: Certificate[] = [
	{
		domain: 'valid.example.com',
		sanList: ['valid.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-60),
		notAfter: daysFromNow(60),
		status: 'VALID',
		source: 'specific',
	},
	{
		domain: 'soon.example.com',
		sanList: ['soon.example.com', 'www.soon.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-70),
		notAfter: daysFromNow(15),
		status: 'RENEWAL_PENDING',
		source: 'specific',
	},
	{
		domain: '*.wild.example.com',
		sanList: ['*.wild.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-30),
		notAfter: daysFromNow(60),
		status: 'VALID',
		source: 'wildcard',
	},
	{
		domain: 'expired.example.com',
		sanList: ['expired.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-120),
		notAfter: daysFromNow(-3),
		status: 'EXPIRED',
		source: 'specific',
	},
	{
		// OBTAIN_FAILED fixtures mirror the empirically-captured
		// wire shape against AreNET-test on 2026-06-05: the
		// backend emits sanList=null (hotfix coerces to []),
		// notBefore/notAfter as Go zero-time, and source as
		// empty string for entries that never reached
		// cert_obtained. The polish layer derives the source
		// from the domain string and skips zero-time rendering
		// so the table cells don't surface "il y a 2027 ans"
		// or "expiré" for never-obtained certs.
		domain: '*.test.local',
		sanList: null,
		issuer: '',
		notBefore: '0001-01-01T00:00:00Z',
		notAfter: '0001-01-01T00:00:00Z',
		status: 'OBTAIN_FAILED',
		source: '' as unknown as Certificate['source'],
		lastError: "subject '*.test.local' does not qualify for a public certificate",
		lastErrorAt: daysFromNow(-0.01),
	},
];

beforeEach(() => {
	// Freeze the real clock on the same anchor the fixtures are
	// computed against (NOW). Without this, the component's
	// isExpiringSoon()/daysUntilExpiry() calls fall back to
	// `new Date()` (real wall-clock) while fixture notAfter values
	// stay pinned to 2026-06-05 — so as real time drifts past the
	// anchor, certs authored as "60d out" slide into the 30d
	// renewal window and the KPI/tab counts break. This is the
	// stubbing the header comment (l.55) always intended.
	//
	// toFake:['Date'] ONLY — faking setTimeout/setInterval too would
	// deadlock Testing Library's findBy*/userEvent, which poll on
	// real timers.
	vi.useFakeTimers({ toFake: ['Date'] });
	vi.setSystemTime(NOW);

	toastMock.pushToast.mockReset();
	apiMock.listRoutes.mockReset();
	settingsMock.settingsApi.listManagedDomains.mockReset();
	settingsMock.settingsApi.createManagedDomain.mockReset();
	settingsMock.settingsApi.deleteManagedDomain.mockReset();
	settingsMock.settingsApi.listDNSProviders.mockReset();
	certsMock.certificatesApi.list.mockReset();
	certsMock.certificatesApi.deleteCertificate.mockReset();
	securityMock.fetchCertEvents.mockReset();

	// Sensible defaults: no routes, no domains, DNS provider
	// configured, no certs, no cert events. Individual tests override.
	apiMock.listRoutes.mockResolvedValue([]);
	settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
		domains: [],
	});
	// The DNS-provider warning gate + the wildcard wizard dropdown
	// both read this collection endpoint. Default: one configured
	// OVH provider (so the "unconfigured" warning stays hidden and
	// the wizard has a providerId).
	settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
		{
			id: 'id-1',
			label: 'OVH perso',
			type: 'ovh',
			endpoint: 'ovh-eu',
			configured: true,
			usedBy: [],
		},
	]);
	certsMock.certificatesApi.list.mockResolvedValue([]);
	// Default : no events for any domain. Cert.B tests override
	// per-domain by mockImplementation that matches { domain } param.
	securityMock.fetchCertEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false,
	});
});

afterEach(() => {
	vi.useRealTimers();
});

describe('/certs — auto-renewal info card', () => {
	it('renders the auto-renewal info card post-load', async () => {
		render(Page);

		// The card is keyed on its data-testid so any future
		// copy edit doesn't break the test. The localized title
		// is also asserted so a regression that removes the
		// French copy still fails loudly.
		const card = await screen.findByTestId('auto-renewal-card');
		expect(card).toBeInTheDocument();
		// v2.9.21 i18n — "Renouvellement automatique" → "Automatic
		// renewal" in EN bundle (test boot default). Helper text
		// copy also flipped to EN ("30 days" not "30 jours").
		expect(screen.getByText('Automatic renewal')).toBeInTheDocument();
		expect(card.textContent ?? '').toMatch(/certmagic/i);
		expect(card.textContent ?? '').toMatch(/30 days/);
	});
});

describe('/certs — managed-domains editor (migrated from /settings in #R-6 Pack A; reframed by T.5)', () => {
	it('inline form is gone — only the wizard trigger remains in the policies section', async () => {
		render(Page);
		// Post-T.5 regression check: the legacy inline "Declare
		// managed domain" submit must NOT be in the DOM. The
		// wizard trigger replaces it.
		await screen.findByTestId('open-wildcard-wizard');
		expect(
			screen.queryByRole('button', { name: /declare managed domain/i }),
		).not.toBeInTheDocument();
		// The wizard modal isn't mounted until the trigger fires
		// (Modal is gated by open=false).
		expect(screen.queryByTestId('wildcard-wizard-form')).not.toBeInTheDocument();
	});

	it('clicking "+ Wildcard apex" opens the wizard with the three form controls', async () => {
		render(Page);
		const trigger = await screen.findByTestId('open-wildcard-wizard');
		await userEvent.click(trigger);
		await tick();

		// Wizard fields — same controls the pre-T.5 inline form
		// exposed, just relocated. Labels stay identical so the
		// vocabulary is preserved.
		expect(await screen.findByLabelText('Apex domain')).toBeInTheDocument();
		expect(screen.getByLabelText('DNS provider')).toBeInTheDocument();
		expect(
			screen.getByLabelText('Include bare apex in cert SAN'),
		).toBeInTheDocument();
		// Footer Declare button.
		expect(
			// v2.9.21 i18n — wizard submit button migrated to t() →
			// "Declare" in EN bundle (test boot default).
			screen.getByRole('button', { name: /^declare$/i }),
		).toBeInTheDocument();
	});

	it('renders existing managed domains with inline Delete buttons', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [
				{
					apex: 'example.com',
					includeApex: true,
					providerId: 'id-1',
				},
				{
					apex: 'other.example',
					includeApex: false,
					providerId: 'id-1',
				},
			],
		});

		render(Page);

		// Each domain renders as `*.<apex>` (with optional bare
		// apex suffix when includeApex). The Delete button has a
		// per-domain aria-label so we can target both. Use
		// findByRole on the Delete button as the wait anchor
		// because it's only mounted post-load; matching on the
		// apex text can be ambiguous when includeApex doubles
		// the text occurrences in the same row.
		expect(
			await screen.findByRole('button', {
				name: 'Delete managed domain example.com',
			}),
		).toBeInTheDocument();
		expect(
			screen.getByRole('button', { name: 'Delete managed domain other.example' }),
		).toBeInTheDocument();
	});

	it('submitting the wizard calls settingsApi.createManagedDomain with trimmed apex', async () => {
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});

		render(Page);
		const trigger = await screen.findByTestId('open-wildcard-wizard');
		await userEvent.click(trigger);
		await tick();

		const apexInput = (await screen.findByTestId(
			'wizard-apex-input',
		)) as HTMLInputElement;
		await userEvent.type(apexInput, '  new.example  ');

		// fireEvent.submit on the form so the test exercises the
		// same code path Enter-in-input would (hidden submit button
		// inside the form catches it; the footer Déclarer button
		// has its own onclick wired to the same handler).
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();

		expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});
	});

	// Wizard close/submit/error contracts are unit-tested in
	// WildcardApexWizard.test.ts. The page tests below stay narrow:
	// trigger → wizard mounts → submission reaches the same API
	// the pre-T.5 inline form did, and onCreated refreshes the list.
	// We don't assert the wizard UNMOUNTS post-close at the page
	// level because JSDOM doesn't drive svelte/transition out-
	// animations the way browsers do, leaving the dialog node in
	// the DOM after `open` flips to false. The behavioural
	// contract (onClose fired, list refreshed) is verified at the
	// component level.

	it('successful submit through the page refreshes the policies list', async () => {
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});
		// First call (page load): empty. Second call (after
		// wizard onCreated): the new policy. Reflects the
		// loadManagedDomains-as-onCreated wiring.
		settingsMock.settingsApi.listManagedDomains
			.mockResolvedValueOnce({ domains: [] })
			.mockResolvedValueOnce({
				domains: [
					{ apex: 'new.example', includeApex: true, providerId: 'id-1' },
				],
			});

		render(Page);
		const trigger = await screen.findByTestId('open-wildcard-wizard');
		await userEvent.click(trigger);
		await tick();

		const apexInput = (await screen.findByTestId(
			'wizard-apex-input',
		)) as HTMLInputElement;
		await userEvent.type(apexInput, 'new.example');
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);

		// Newly-declared policy appears in the list (refreshed
		// via the onCreated callback the page passes to the
		// wizard). findByRole waits for the refresh tick.
		expect(
			await screen.findByRole('button', {
				name: 'Delete managed domain new.example',
			}),
		).toBeInTheDocument();
	});

	it('section header carries the T.5-reframed title "Wildcard policies per apex"', async () => {
		// v2.9.21 i18n — section title migrated to t() →
		// "Wildcard policies per apex" in EN bundle.
		render(Page);
		await screen.findByTestId('open-wildcard-wizard');
		expect(
			screen.getByText('Wildcard policies per apex'),
		).toBeInTheDocument();
	});

	it('clicking Delete on a domain opens the revertTo modal', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [
				{
					apex: 'example.com',
					includeApex: true,
					providerId: 'id-1',
				},
			],
		});

		render(Page);
		// Wait via the per-domain Delete button — unique
		// anchor, only mounted post-load.
		const deleteBtn = await screen.findByRole('button', {
			name: 'Delete managed domain example.com',
		});

		// Modal not mounted before the delete click.
		expect(
			screen.queryByLabelText('Revert covered routes to'),
		).not.toBeInTheDocument();

		await userEvent.click(deleteBtn);
		await tick();

		// The dialog mounts with the revertTo select + the
		// per-modal Cancel/Delete buttons. The title carries the
		// apex so the operator sees what they're about to delete.
		expect(
			screen.getByLabelText('Revert covered routes to'),
		).toBeInTheDocument();
		expect(
			screen.getByText(/delete managed domain example\.com/i),
		).toBeInTheDocument();
	});
});

describe('/certs — DNS-provider-unconfigured warning', () => {
	it('renders the warning when no provider is configured', async () => {
		// v2.12 — the warning gate reads listDNSProviders; a
		// not-configured collection trips it.
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			{
				id: 'id-1',
				label: 'OVH perso',
				type: 'ovh',
				endpoint: 'ovh-eu',
				configured: false,
				usedBy: [],
			},
		]);

		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByTestId('open-wildcard-wizard');

		// The warning text is a sentence the test pins partially
		// so a future copy edit doesn't break the contract.
		expect(
			screen.getByText(/DNS provider unconfigured/i),
		).toBeInTheDocument();
	});

	it('hides the warning when a provider is configured', async () => {
		// Default beforeEach lists one configured provider; this
		// test pins the negative-path explicitly.
		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByTestId('open-wildcard-wizard');

		expect(
			screen.queryByText(/DNS provider unconfigured/i),
		).not.toBeInTheDocument();
	});
});

// Step T T.4 — unified Domaines table tests. The fixture covers
// every status the AC #10 badge mapping handles; per-test mocks
// reach into `fixtureCerts` by domain name to keep each test's
// scope narrow.

describe('/certs — runtime KPI cards (T.4)', () => {
	it('Certificats actifs breakdown sums to the total (resolveSource handles empty source)', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-certs-actifs');
		// 5 fixture certs: 2 wildcard (*.wild.example.com explicit +
		// *.test.local derived-from-domain), 3 specific. Polish:
		// resolveSource classifies the OBTAIN_FAILED row by its
		// domain string instead of dropping it (pre-polish the
		// breakdown was 4 total / 1+1 visible).
		expect(card.textContent ?? '').toMatch(/5/);
		expect(card.textContent ?? '').toMatch(/2 wildcard/);
		// v2.9.21 i18n — "spécifique(s)" migrated to "specific(s)"
		// in the EN bundle (test boot default).
		expect(card.textContent ?? '').toMatch(/3 specific/);
	});

	it('Expirent < 30 jours excludes OBTAIN_FAILED + zero-time entries', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-expirent-bientot');
		// fixtureCerts post-polish: soon (15d, RENEWAL_PENDING) +
		// expired (-3d, EXPIRED) = 2. The *.test.local OBTAIN_FAILED
		// row has notAfter = Go zero-time which would have trivially
		// satisfied "<= now+30d" pre-polish; the new isExpiringSoon
		// filter correctly excludes it.
		expect(card.textContent ?? '').toMatch(/2/);
		// v2.9.21 i18n — "renouvellement auto programmé" → EN bundle
		// "auto-renewal scheduled".
		expect(card.textContent ?? '').toMatch(/auto-renewal scheduled/);
	});

	it('Émetteur principal surfaces the dominant issuer', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-emetteur');
		expect(card.textContent ?? '').toMatch(/Let's Encrypt/);
	});

	it('Méthode ACME shows Auto when no managed domain declared', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-methode');
		expect(card.textContent ?? '').toMatch(/Auto/);
	});

	it('Méthode ACME flips to DNS-01 when at least one managed domain is declared', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [{ apex: 'example.com', includeApex: true, providerId: 'id-1' }],
		});
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-methode');
		expect(card.textContent ?? '').toMatch(/DNS-01/);
		expect(card.textContent ?? '').toMatch(/via OVH/);
	});
});

describe('/certs — Domaines table (T.4)', () => {
	it('renders one row per certificate with domain + issuer + SAN cells', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		expect(rows).toHaveLength(fixtureCerts.length);
		// Wildcard row carries 1 SAN; broken carries 1 SAN; soon
		// carries 2 (verifies sanList.length flows through).
		const soonRow = rows.find((r) => r.dataset.domain === 'soon.example.com')!;
		expect(soonRow.textContent ?? '').toMatch(/2 SAN/);
	});

	it('status badge label matches AC #10 vocabulary for each status', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		// VALID → VALID, RENEWAL_PENDING → RENEWING,
		// EXPIRED → EXPIRED, OBTAIN_FAILED → FAILED (English bundle).
		expect(screen.getAllByText('VALID').length).toBeGreaterThan(0);
		expect(screen.getByText('RENEWING')).toBeInTheDocument();
		expect(screen.getByText('EXPIRED')).toBeInTheDocument();
		expect(screen.getByText('FAILED')).toBeInTheDocument();
	});

	it('renders an OBTAIN_FAILED row with null sanList as "0 SAN" without crashing (hotfix regression)', async () => {
		// Pre-hotfix the backend marshaled sanList as JSON null
		// for OBTAIN_FAILED entries that never reached
		// cert_obtained (Go nil-slice gotcha — see
		// internal/certinfo/tracker.go snapshot). The frontend's
		// cert.sanList.length read crashed on null. Both sides
		// fixed; the *.test.local fixture above carries
		// sanList=null to ensure this regression is caught if
		// either side reverts.
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		const broken = rows.find((r) => r.dataset.domain === '*.test.local')!;
		expect(broken).toBeDefined();
		expect(broken.textContent ?? '').toMatch(/0 SAN/);
	});

	it('OBTAIN_FAILED row carries the lastError tooltip', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const echec = screen.getByText('FAILED');
		// Tooltip wraps the badge; the bubble mounts on hover/focus.
		// We assert the wrapper's aria-describedby contract by
		// simulating focus and reading the bubble text.
		const wrapper = echec.closest('.tt-wrapper') as HTMLElement | null;
		expect(wrapper).not.toBeNull();
		await fireEvent.focusIn(wrapper!);
		await tick();
		expect(
			screen.getByText(/does not qualify for a public certificate/),
		).toBeInTheDocument();
	});

	it('expired row labels the EXPIRE DANS cell as "expired"', async () => {
		// v2.9.21 i18n — "expiré" migrated to t() → "expired" in EN
		// bundle (test boot default).
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		const expired = rows.find((r) => r.dataset.domain === 'expired.example.com')!;
		expect(expired.textContent ?? '').toMatch(/expired/);
	});

	it('OBTAIN_FAILED row with zero-time dates renders cells as "—" instead of "expiré" / "il y a 2027 ans"', async () => {
		// Polish regression: pre-polish the EXPIRE DANS column
		// rendered "expiré" for OBTAIN_FAILED entries because
		// daysUntilExpiry returned a huge-negative number for
		// notAfter=0001-01-01, and ÉMIS LE rendered "il y a 2027
		// ans" via the relativeTime helper. Both should now be "—".
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		const broken = rows.find((r) => r.dataset.domain === '*.test.local')!;
		expect(broken).toBeDefined();
		const text = broken.textContent ?? '';
		// v2.9.21 i18n — EN bundle uses "expired" not "expiré".
		expect(text).not.toMatch(/expired/);
		expect(text).not.toMatch(/ans/);
		// Both ÉMIS LE and EXPIRE DANS should render "—".
		// (Two em-dashes minimum in this row.)
		expect((text.match(/—/g) ?? []).length).toBeGreaterThanOrEqual(2);
	});

	it('OBTAIN_FAILED wildcard-domain row classifies as wildcard in the type sub-line', async () => {
		// Polish regression: pre-polish the *.test.local row
		// showed "spécifique · HTTP-01" (because source was empty
		// → fell through to the specific default). With
		// resolveSource + status-aware inferChallengeLabel, the
		// row now reads "wildcard · DNS-01" — operator-correct.
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		const broken = rows.find((r) => r.dataset.domain === '*.test.local')!;
		expect(broken.textContent ?? '').toMatch(/wildcard · DNS-01/);
		expect(broken.textContent ?? '').not.toMatch(/spécifique/);
	});

	it('shows the page-level empty state when no certs exist', async () => {
		// Default mock already returns []; explicit for clarity.
		certsMock.certificatesApi.list.mockResolvedValue([]);
		render(Page);
		const empty = await screen.findByTestId('certs-empty');
		// v2.9.21 i18n — "Aucun certificat actif." → EN "No active certificate."
		expect(empty.textContent ?? '').toMatch(/No active certificate/);
	});

	it('shows the error banner when /api/certificates rejects', async () => {
		certsMock.certificatesApi.list.mockRejectedValue(new Error('boom'));
		render(Page);
		const err = await screen.findByTestId('certs-error');
		// v2.9.21 i18n — "Impossible de récupérer" → EN "Could not fetch".
		expect(err.textContent ?? '').toMatch(/Could not fetch/);
		// Pack A editor MUST still mount even when certs failed
		// (AC #13 degraded mode mirrored on the frontend). Post-
		// T.5 the wizard trigger is the new declaration affordance.
		expect(screen.getByTestId('open-wildcard-wizard')).toBeInTheDocument();
	});
});

// --- Task 7 — per-cert Delete action + confirm/blocked dialogs -----
//
// Reuses the same Modal + pushToast + loadCertificates list-refresh
// the page already wires for the managed-domain delete flow. On 200
// the row disappears (list refreshed) + a success toast fires; on
// 409 a blocked dialog lists the offending routes from
// e.blockingRoutes instead of touching the toast.
describe('/certs — cert delete action (Task 7)', () => {
	function orphanCert(domain: string) {
		return {
			domain,
			sanList: [domain],
			issuer: "Let's Encrypt",
			notBefore: daysFromNow(-30),
			notAfter: daysFromNow(60),
			status: 'VALID' as const,
			source: 'specific' as const,
		};
	}

	it('deletes an orphan cert, toasts success, and refreshes the list', async () => {
		certsMock.certificatesApi.list
			.mockResolvedValueOnce([orphanCert('orphan.example.com')])
			.mockResolvedValueOnce([]);
		certsMock.certificatesApi.deleteCertificate.mockResolvedValue({
			domain: 'orphan.example.com',
			deleted: 3,
		});

		render(Page);
		await userEvent.click(
			await screen.findByTestId('cert-delete-orphan.example.com'),
		);
		await userEvent.click(await screen.findByTestId('cert-delete-confirm'));

		expect(certsMock.certificatesApi.deleteCertificate).toHaveBeenCalledWith(
			'orphan.example.com',
		);
		expect(toastMock.pushToast).toHaveBeenCalledWith(
			expect.stringContaining('orphan.example.com'),
			'success',
		);
		// List refresh (loadCertificates) ran a second time post-delete —
		// the row is gone.
		await tick();
		expect(
			screen.queryByTestId('cert-delete-orphan.example.com'),
		).not.toBeInTheDocument();
	});

	it('shows the blocked dialog with the blocking routes on 409', async () => {
		certsMock.certificatesApi.list.mockResolvedValue([
			orphanCert('used.example.com'),
		]);
		certsMock.certificatesApi.deleteCertificate.mockRejectedValue(
			Object.assign(new Error('in use'), {
				status: 409,
				blockingRoutes: ['used.example.com'],
			}),
		);

		render(Page);
		await userEvent.click(
			await screen.findByTestId('cert-delete-used.example.com'),
		);
		await userEvent.click(await screen.findByTestId('cert-delete-confirm'));

		expect(
			await screen.findByText(/is in use by: used\.example\.com/),
		).toBeInTheDocument();
		// No success toast on the blocked path.
		expect(toastMock.pushToast).not.toHaveBeenCalledWith(
			expect.anything(),
			'success',
		);
	});

	it('delete button carries a per-domain aria-label', async () => {
		certsMock.certificatesApi.list.mockResolvedValue([
			orphanCert('labeled.example.com'),
		]);
		render(Page);
		const btn = await screen.findByTestId('cert-delete-labeled.example.com');
		expect(btn.getAttribute('aria-label')).toBe('Delete certificate');
	});
});

describe('/certs — Domaines tabs (T.4)', () => {
	it('Wildcard tab filters to source=wildcard rows only', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');

		const tab = screen.getByTestId('tab-wildcard');
		await userEvent.click(tab);
		await tick();

		const rows = screen.getAllByTestId('cert-row');
		expect(rows).toHaveLength(1);
		expect(rows[0].dataset.domain).toBe('*.wild.example.com');
	});

	it('Expirent bientôt tab filters to certs within the renewal window OR already expired', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');

		const tab = screen.getByTestId('tab-expiring');
		await userEvent.click(tab);
		await tick();

		const rows = screen.getAllByTestId('cert-row');
		// soon (15d) + expired (-3d) qualify; valid/wild/broken
		// have notAfter beyond the 30d window.
		expect(rows.map((r) => r.dataset.domain).sort()).toEqual(
			['expired.example.com', 'soon.example.com'].sort(),
		);
	});

	it('per-tab empty state surfaces when the active filter yields zero rows', async () => {
		// All-VALID fixture, no wildcards — the Wildcard tab MUST
		// render the per-tab empty branch, NOT the page-level
		// "Aucun certificat actif" copy.
		certsMock.certificatesApi.list.mockResolvedValue([
			{
				domain: 'one.example.com',
				sanList: ['one.example.com'],
				issuer: "Let's Encrypt",
				notBefore: daysFromNow(-30),
				notAfter: daysFromNow(60),
				status: 'VALID',
				source: 'specific',
			},
		]);
		render(Page);
		await screen.findByTestId('certs-table');

		const tab = screen.getByTestId('tab-wildcard');
		await userEvent.click(tab);
		await tick();

		expect(screen.getByTestId('certs-tab-empty')).toBeInTheDocument();
		// And the page-level empty state must NOT be shown — the
		// dataset isn't empty, just the filter.
		expect(screen.queryByTestId('certs-empty')).not.toBeInTheDocument();
	});

	it('Tous tab is the default selection on first render', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const tab = await screen.findByTestId('tab-all');
		expect(tab.getAttribute('aria-selected')).toBe('true');
	});
});

// --- Cert.B (2026-06-23) — stale-failure badge + drill-down --------
//
// Stale failure = most-recent cert_event for the domain is
// cert_failed AND occurred > 24h ago. Distinct from the existing
// certinfo.Tracker OBTAIN_FAILED status which covers fresh failures
// (< 24h FailureFreshness) ; Cert.B covers the gap.
//
// Tests pin :
//   1. Badge appears when last event is cert_failed > 24h ago
//   2. Badge does NOT appear when last event is cert_obtained
//      (successful renewal cleared the stale state)
//   3. Badge does NOT appear when failure is < 24h (fresh, covered
//      by the existing OBTAIN_FAILED tracker badge)
//   4. Click on badge opens drill-down modal with last 5 events
//   5. Modal links to /logs filtered by cert source + domain

describe('/certs — Cert.B stale-failure badge', () => {
	function staleFailureFixture(domain: string) {
		return {
			domain,
			sanList: [domain],
			issuer: "Let's Encrypt",
			notBefore: daysFromNow(-60),
			notAfter: daysFromNow(20),
			// Note: status from the tracker has reverted to VALID
			// since the failure is > 24h old (FailureFreshness
			// expired). The stale badge derives ONLY from the
			// cert_events history, not from the tracker status.
			status: 'VALID' as const,
			source: 'specific' as const,
		};
	}

	it('renders the stale-failure badge when last event is cert_failed > 24h ago', async () => {
		certsMock.certificatesApi.list.mockResolvedValue([
			staleFailureFixture('vault.example.com'),
		]);
		// 48h-old failure, no recovery since.
		securityMock.fetchCertEvents.mockImplementation(
			async (params: { domain?: string }) => {
				if (params.domain === 'vault.example.com') {
					return {
						events: [
							{
								timestamp: new Date(
									Date.now() - 48 * 60 * 60 * 1000
								).toISOString(),
								level: 'ERROR',
								eventType: 'cert_failed',
								domain: 'vault.example.com',
								issuer: "Let's Encrypt",
								challenge: 'DNS-01' as const,
								renewal: true,
								error: 'urn:ietf:params:acme:error:rateLimited',
								details: '',
							},
						],
						total: 1,
						hasMore: false,
					};
				}
				return { events: [], total: 0, hasMore: false };
			}
		);
		render(Page);
		const badge = await screen.findByTestId('cert-stale-badge');
		expect(badge.getAttribute('data-domain')).toBe('vault.example.com');
		// v2.9.21 i18n — stale-badge text migrated to t() →
		// "Failed for {ago}" in EN bundle (test boot default).
		expect(badge.textContent).toContain('Failed for');
	});

	it('does NOT render the stale badge when last event is a successful cert_obtained', async () => {
		certsMock.certificatesApi.list.mockResolvedValue([
			staleFailureFixture('recovered.example.com'),
		]);
		// Failure 48h ago BUT a successful renewal happened 6h ago
		// — the API returns events newest-first so cert_obtained
		// is at index 0 ; the badge derivation reads index 0 only.
		securityMock.fetchCertEvents.mockImplementation(
			async (params: { domain?: string }) => {
				if (params.domain === 'recovered.example.com') {
					return {
						events: [
							{
								timestamp: new Date(
									Date.now() - 6 * 60 * 60 * 1000
								).toISOString(),
								level: 'INFO',
								eventType: 'cert_obtained',
								domain: 'recovered.example.com',
								issuer: "Let's Encrypt",
								challenge: 'DNS-01' as const,
								renewal: true,
								error: '',
								details: '',
							},
							{
								timestamp: new Date(
									Date.now() - 48 * 60 * 60 * 1000
								).toISOString(),
								level: 'ERROR',
								eventType: 'cert_failed',
								domain: 'recovered.example.com',
								issuer: "Let's Encrypt",
								challenge: 'DNS-01' as const,
								renewal: true,
								error: 'transient timeout',
								details: '',
							},
						],
						total: 2,
						hasMore: false,
					};
				}
				return { events: [], total: 0, hasMore: false };
			}
		);
		render(Page);
		await screen.findByText('recovered.example.com');
		// Wait one tick for cert events to load + badge derivation.
		await tick();
		await tick();
		expect(screen.queryByTestId('cert-stale-badge')).toBeNull();
	});

	it('does NOT render the stale badge when failure is fresh (< 24h, covered by tracker)', async () => {
		certsMock.certificatesApi.list.mockResolvedValue([
			staleFailureFixture('fresh-fail.example.com'),
		]);
		// 6h-old failure — within the tracker's FailureFreshness
		// window, so the existing OBTAIN_FAILED badge would cover
		// it. The Cert.B badge intentionally avoids overlap.
		securityMock.fetchCertEvents.mockImplementation(
			async (params: { domain?: string }) => {
				if (params.domain === 'fresh-fail.example.com') {
					return {
						events: [
							{
								timestamp: new Date(
									Date.now() - 6 * 60 * 60 * 1000
								).toISOString(),
								level: 'ERROR',
								eventType: 'cert_failed',
								domain: 'fresh-fail.example.com',
								issuer: "Let's Encrypt",
								challenge: 'DNS-01' as const,
								renewal: true,
								error: 'transient',
								details: '',
							},
						],
						total: 1,
						hasMore: false,
					};
				}
				return { events: [], total: 0, hasMore: false };
			}
		);
		render(Page);
		await screen.findByText('fresh-fail.example.com');
		await tick();
		await tick();
		expect(screen.queryByTestId('cert-stale-badge')).toBeNull();
	});

	it('opens the drill-down modal with last 5 events when the badge is clicked', async () => {
		certsMock.certificatesApi.list.mockResolvedValue([
			staleFailureFixture('drill.example.com'),
		]);
		const events = [
			{
				timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString(),
				level: 'ERROR' as const,
				eventType: 'cert_failed' as const,
				domain: 'drill.example.com',
				issuer: "Let's Encrypt",
				challenge: 'DNS-01' as const,
				renewal: true,
				error: 'urn:ietf:params:acme:error:rateLimited',
				details: '',
			},
			{
				timestamp: new Date(Date.now() - 96 * 60 * 60 * 1000).toISOString(),
				level: 'INFO' as const,
				eventType: 'cert_obtained' as const,
				domain: 'drill.example.com',
				issuer: "Let's Encrypt",
				challenge: 'DNS-01' as const,
				renewal: true,
				error: '',
				details: '',
			},
		];
		securityMock.fetchCertEvents.mockImplementation(
			async (params: { domain?: string }) => {
				if (params.domain === 'drill.example.com') {
					return { events, total: events.length, hasMore: false };
				}
				return { events: [], total: 0, hasMore: false };
			}
		);
		render(Page);
		const badge = await screen.findByTestId('cert-stale-badge');
		await userEvent.click(badge);

		// Modal should render the list with both events.
		const list = await screen.findByTestId('cert-drilldown-list');
		expect(list.children.length).toBe(events.length);

		// The cert_failed row carries the error message verbatim.
		const errorNode = screen.getByTestId('cert-event-error');
		expect(errorNode.textContent).toContain('rateLimited');

		// And the "Voir tous les événements" link points at
		// /logs?source=cert with the domain in the search param.
		const link = screen.getByTestId(
			'cert-drilldown-logs-link'
		) as HTMLAnchorElement;
		const href = link.getAttribute('href') ?? '';
		expect(href).toContain('source=cert');
		expect(href).toContain('drill.example.com');
	});
});


// --- Auto-refresh polling -------------------------------------------------
//
// ACME issuance is asynchronous: certmagic obtains the cert AFTER the
// route/managed-domain is created, so a freshly-issued cert never appears
// on /certs until a manual page reload. This suite pins the fix — the page
// re-fetches the cert list on an interval while mounted, so a new cert
// surfaces on its own within one poll cycle.
//
// This describe fully fakes timers (setInterval included) so we can drive
// the poll deterministically. It deliberately avoids findBy*/userEvent
// (which poll on real timers and would deadlock under faked setInterval) —
// it asserts on the mock call counts directly.
describe('/certs — auto-refresh polling', () => {
	beforeEach(() => {
		vi.useFakeTimers(); // fake ALL timers incl. setInterval
		vi.setSystemTime(NOW);
		apiMock.listRoutes.mockResolvedValue([]);
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({ domains: [] });
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
		// One cert so loadCertEvents() actually queries fetchCertEvents
		// (it early-returns on an empty cert list) — lets the test pin
		// BOTH halves of the poll: the cert list AND the events.
		certsMock.certificatesApi.list.mockResolvedValue([
			{
				domain: 'poll.example.com',
				sanList: ['poll.example.com'],
				issuer: "Let's Encrypt",
				notBefore: daysFromNow(-10),
				notAfter: daysFromNow(80),
				status: 'VALID',
				source: 'specific',
			},
		]);
		securityMock.fetchCertEvents.mockResolvedValue({ events: [], total: 0, hasMore: false });
	});

	it('re-fetches the certificate list AND events on an interval while mounted', async () => {
		const { unmount } = render(Page);

		// Let the onMount load() settle.
		await vi.advanceTimersByTimeAsync(0);
		const listAfterMount = certsMock.certificatesApi.list.mock.calls.length;
		const eventsAfterMount = securityMock.fetchCertEvents.mock.calls.length;
		expect(listAfterMount).toBeGreaterThanOrEqual(1);
		expect(eventsAfterMount).toBeGreaterThanOrEqual(1);

		// Advance one poll cycle (~20s) — BOTH the list and (after it
		// resolves) the events must be fetched again. The events re-fetch
		// pins the load()-mirroring ordering: loadCertEvents runs after
		// loadCertificates resolves, so a cert present this tick gets its
		// events in the same cycle.
		await vi.advanceTimersByTimeAsync(20000);
		expect(certsMock.certificatesApi.list.mock.calls.length).toBeGreaterThan(listAfterMount);
		expect(securityMock.fetchCertEvents.mock.calls.length).toBeGreaterThan(eventsAfterMount);

		// A second cycle keeps polling.
		const listAfterFirstPoll = certsMock.certificatesApi.list.mock.calls.length;
		await vi.advanceTimersByTimeAsync(20000);
		expect(certsMock.certificatesApi.list.mock.calls.length).toBeGreaterThan(listAfterFirstPoll);

		// After unmount, the interval is cleared — no further fetches.
		unmount();
		const listAfterUnmount = certsMock.certificatesApi.list.mock.calls.length;
		const eventsAfterUnmount = securityMock.fetchCertEvents.mock.calls.length;
		await vi.advanceTimersByTimeAsync(60000);
		expect(certsMock.certificatesApi.list.mock.calls.length).toBe(listAfterUnmount);
		expect(securityMock.fetchCertEvents.mock.calls.length).toBe(eventsAfterUnmount);
	});
});

// --- Burst polling after a wildcard declaration ----------------------------
//
// Operator feedback (2026-09-21): after "+ Wildcard apex", the new cert only
// appeared at the next 20 s poll, with no sign that anything was happening,
// so the page looked stuck and was reloaded by hand. The page now polls every
// 3 s for up to 2 min after a declaration and flags the policy row "Issuance
// in progress…" until the wildcard cert lands. Fully faked timers, same
// constraints as the suite above (fireEvent only, no findBy*/userEvent).
describe('/certs — burst polling after a wildcard declaration', () => {
	const wildcardCert = {
		domain: '*.new.example',
		sanList: ['*.new.example', 'new.example'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(0),
		notAfter: daysFromNow(90),
		status: 'VALID' as const,
		source: 'wildcard' as const,
	};

	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(NOW);
		apiMock.listRoutes.mockResolvedValue([]);
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			{
				id: 'p1',
				label: 'OVH',
				type: 'ovh',
				endpoint: 'ovh-eu',
				configured: true,
				usedBy: [],
			},
		]);
		settingsMock.settingsApi.listManagedDomains.mockReset();
		settingsMock.settingsApi.listManagedDomains
			.mockResolvedValueOnce({ domains: [] }) // initial load
			.mockResolvedValue({
				domains: [{ apex: 'new.example', includeApex: true, providerId: 'p1' }],
			});
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({});
		certsMock.certificatesApi.list.mockReset();
		certsMock.certificatesApi.list.mockResolvedValue([]);
		securityMock.fetchCertEvents.mockResolvedValue({ events: [], total: 0, hasMore: false });
	});

	async function declareWildcard(): Promise<void> {
		await fireEvent.click(screen.getByTestId('open-wildcard-wizard'));
		await vi.advanceTimersByTimeAsync(0); // providers load
		await fireEvent.input(screen.getByTestId('wizard-apex-input'), {
			target: { value: 'new.example' },
		});
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await vi.advanceTimersByTimeAsync(0);
	}

	it('polls every 3 s, shows the issuing badge, and stops once the cert lands', async () => {
		render(Page);
		await vi.advanceTimersByTimeAsync(0);
		await declareWildcard();

		expect(screen.getByTestId('md-issuing')).toHaveAttribute('data-apex', 'new.example');
		const before = certsMock.certificatesApi.list.mock.calls.length;
		await vi.advanceTimersByTimeAsync(3000);
		expect(certsMock.certificatesApi.list.mock.calls.length).toBe(before + 1);
		expect(screen.getByTestId('md-issuing')).toBeInTheDocument();

		// The cert lands: the next burst tick picks it up and the badge goes.
		certsMock.certificatesApi.list.mockResolvedValue([wildcardCert]);
		await vi.advanceTimersByTimeAsync(3000);
		expect(screen.queryByTestId('md-issuing')).not.toBeInTheDocument();
		const rows = screen.getAllByTestId('cert-row');
		expect(rows.map((r) => r.getAttribute('data-domain'))).toContain('*.new.example');

		// Burst stopped: the next 9 s would hold 3 burst ticks, while the
		// normal 20 s cadence's first tick (t=20 s after mount) is still ahead.
		const afterSettle = certsMock.certificatesApi.list.mock.calls.length;
		await vi.advanceTimersByTimeAsync(9000);
		expect(certsMock.certificatesApi.list.mock.calls.length).toBe(afterSettle);
	});

	it('gives up after 2 minutes without a cert and drops the badge', async () => {
		render(Page);
		await vi.advanceTimersByTimeAsync(0);
		await declareWildcard();
		expect(screen.getByTestId('md-issuing')).toBeInTheDocument();

		await vi.advanceTimersByTimeAsync(120000);
		expect(screen.queryByTestId('md-issuing')).not.toBeInTheDocument();

		// Back to the 20 s cadence only: 3 burst intervals would add 3 calls.
		const settled = certsMock.certificatesApi.list.mock.calls.length;
		await vi.advanceTimersByTimeAsync(9000);
		expect(certsMock.certificatesApi.list.mock.calls.length - settled).toBeLessThanOrEqual(1);
	});
});
