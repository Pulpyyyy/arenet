// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// CrowdSecDecisionsPanel tests (Step CS.3 — extracted from
// the deleted /security/decisions route's page.test.ts).
//
// Validates the 3-tab structure mounted under the /sécurité
// CrowdSec parent tab:
//   - Tab 1 (Local snapshot) — pre-CS.2 behaviour preserved.
//   - Tab 2 (Live LAPI) — live-poll proxy + filter + error states.
//   - Tab 3 (Scenarios) — LAPI /v1/alerts aggregation + modal.
//
// Polling cadence is not exercised by clock-faking — the
// initial-fetch + manual-refresh paths cover the same data
// flow and avoid the d3.timer-class import-time caching trap
// (Lesson 7 in ENGINEERING-PRACTICES.md). Manual refresh is
// triggered via the refresh button.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type {
	Decision,
	DecisionsResponse,
	LAPIDecisionsResponse
} from '$lib/api/types';
import { ApiError } from '$lib/api/types';

const { toastMock, securityMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: {
		fetchDecisions: vi.fn(),
		fetchLAPIDecisions: vi.fn(),
		fetchScenarios: vi.fn()
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);

import Page from './CrowdSecDecisionsPanel.svelte';
import { auth } from '$lib/stores/auth.svelte';

beforeEach(() => {
	toastMock.pushToast.mockReset();
	securityMock.fetchDecisions.mockReset();
	securityMock.fetchLAPIDecisions.mockReset();
	securityMock.fetchScenarios.mockReset();
	// Default: anonymous (auth.user = null). Tests that need
	// the admin-gated "+ Bannir une IP" button set
	// auth.user = { role: 'admin', ... } explicitly.
	auth.user = null;
});

// --- Fixtures -----------------------------------------------

const sampleSnapshot: DecisionsResponse = {
	events: [
		{
			id: 1,
			uuid: 'snap-1',
			ts: new Date(Date.now() - 5 * 60_000).toISOString(),
			scope: 'ip',
			value: '1.2.3.4',
			type: 'ban',
			scenario: 'crowdsecurity/http-cve',
			expiresAt: new Date(Date.now() + 3600_000).toISOString(),
			durationSeconds: 3600
		}
	]
};

function sampleLAPI(decisions: number = 3): LAPIDecisionsResponse {
	const ds = [
		{
			id: 1,
			duration: '168h',
			origin: 'CAPI',
			scenario: 'crowdsecurity/community-blocklist',
			scope: 'ip',
			type: 'ban',
			value: '1.2.3.4',
			expiresAt: new Date(Date.now() + 7 * 86400_000).toISOString()
		},
		{
			id: 2,
			duration: '24h',
			origin: 'CAPI',
			scenario: 'crowdsecurity/community-blocklist',
			scope: 'range',
			type: 'ban',
			value: '5.6.7.0/24',
			expiresAt: new Date(Date.now() + 86400_000).toISOString()
		},
		{
			id: 3,
			duration: '1h',
			origin: 'cscli',
			scenario: 'manual',
			scope: 'ip',
			type: 'ban',
			value: '192.0.2.42',
			expiresAt: new Date(Date.now() + 3600_000).toISOString()
		}
	].slice(0, decisions);
	const byOrigin: Record<string, number> = {};
	for (const d of ds) byOrigin[d.origin] = (byOrigin[d.origin] ?? 0) + 1;
	return {
		decisions: ds,
		meta: { total: ds.length, totalByOrigin: byOrigin, limit: 100, offset: 0 }
	};
}

// --- Tab navigation -----------------------------------------

describe('CrowdSec decisions panel — tabs', () => {
	it('renders all three tabs with Local snapshot active by default', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		expect(screen.getByTestId('tab-snapshot')).toHaveAttribute('aria-selected', 'true');
		expect(screen.getByTestId('tab-live')).toHaveAttribute('aria-selected', 'false');
		expect(screen.getByTestId('tab-scenarios')).toHaveAttribute('aria-selected', 'false');
	});

	it('switches to Live LAPI tab and triggers the proxy fetch', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('tab-live'));
		await waitFor(() => {
			expect(securityMock.fetchLAPIDecisions).toHaveBeenCalled();
		});
		expect(screen.getByTestId('tab-live')).toHaveAttribute('aria-selected', 'true');
	});

	it('switches to Scenarios tab and triggers the fetchScenarios call', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		securityMock.fetchScenarios.mockResolvedValue({
			scenarios: [],
			meta: { totalAlerts: 0, windowHours: 24 }
		});
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('tab-scenarios'));
		await waitFor(() => {
			expect(securityMock.fetchScenarios).toHaveBeenCalled();
		});
	});

	it('does not fetch LAPI decisions until the Live tab is opened', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		// Local snapshot tab was the initial state; LAPI shouldn't be polled.
		expect(securityMock.fetchLAPIDecisions).not.toHaveBeenCalled();
	});
});

// --- Local snapshot tab -------------------------------------

describe('CrowdSec decisions panel — Local snapshot tab', () => {
	it('renders snapshot rows after fetch', async () => {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => {
			expect(screen.getByText('1.2.3.4')).toBeInTheDocument();
		});
	});

	it('renders the disabled state when /security/decisions returns disabled=true', async () => {
		securityMock.fetchDecisions.mockResolvedValue({ disabled: true, events: [] });
		render(Page);
		await waitFor(() => {
			expect(screen.getByText(/not configured/i)).toBeInTheDocument();
		});
	});
});

// --- Live LAPI tab ------------------------------------------

describe('CrowdSec decisions panel — Live LAPI tab', () => {
	async function openLiveTab(): Promise<void> {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		await fireEvent.click(screen.getByTestId('tab-live'));
	}

	it('renders live decisions in the table after the proxy fetch resolves', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByText('5.6.7.0/24')).toBeInTheDocument();
			expect(screen.getByText('192.0.2.42')).toBeInTheDocument();
		});
	});

	// CS.3 Commit B — the pre-CS.3 breakdown chips were
	// replaced by 4 origin tabs (Toutes/Locales/CAPI/Manuelles).
	// The "filter by clicking a chip" test below now exercises
	// the tab + client-side filter path instead of the
	// chip-triggered backend re-fetch path.

	it('renders the 4 origin tabs with counts from meta.totalByOrigin', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => {
			// Sample LAPI fixture has 2 CAPI + 1 cscli rows, no
			// manual. So: all=3, local=1, capi=2, manual=0.
			expect(screen.getByTestId('live-tab-all').textContent ?? '').toMatch(/All\s*\(3\)/);
			expect(screen.getByTestId('live-tab-local').textContent ?? '').toMatch(/Local\s*\(1\)/);
			expect(screen.getByTestId('live-tab-capi').textContent ?? '').toMatch(/CAPI\s*\(2\)/);
			expect(screen.getByTestId('live-tab-manual').textContent ?? '').toMatch(/Manual\s*\(0\)/);
		});
	});

	it('filters the table client-side when an origin tab is clicked (no re-fetch)', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		// Wait for the initial fetch + table.
		await waitFor(() => {
			expect(screen.getByTestId('live-tab-all')).toBeInTheDocument();
		});

		// Both CAPI and cscli rows present initially.
		expect(screen.getByText('5.6.7.0/24')).toBeInTheDocument(); // CAPI row
		expect(screen.getByText('192.0.2.42')).toBeInTheDocument(); // cscli row

		const fetchCountBefore = securityMock.fetchLAPIDecisions.mock.calls.length;

		// Click "Locales" — should hide the CAPI row, keep
		// the cscli row. Tab change MUST NOT trigger a fetch
		// (filtering happens client-side post-fetch).
		await fireEvent.click(screen.getByTestId('live-tab-local'));

		await waitFor(() => {
			expect(screen.queryByText('5.6.7.0/24')).toBeNull(); // CAPI row hidden
			expect(screen.getByText('192.0.2.42')).toBeInTheDocument(); // cscli row visible
		});

		// CRITICAL: no re-fetch on tab change.
		expect(securityMock.fetchLAPIDecisions.mock.calls.length).toBe(fetchCountBefore);
	});

	it('does NOT send source= to the backend (Commit B drops backend source filter)', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();
		await waitFor(() => expect(securityMock.fetchLAPIDecisions).toHaveBeenCalled());
		// Every call so far must omit the source param. The
		// scope param may or may not be present depending on
		// initial state (currently absent on initial fetch).
		for (const call of securityMock.fetchLAPIDecisions.mock.calls) {
			expect(call[0]).not.toHaveProperty('source');
		}
	});

	it('Locales excludes origin=manual (only crowdsec + cscli)', async () => {
		// Fixture: mix CAPI + cscli + manual. After the
		// Locales tab is selected, only cscli should remain
		// in the rendered table.
		const mixed = {
			decisions: [
				{
					id: 1,
					duration: '24h',
					origin: 'CAPI',
					scenario: 'crowdsecurity/community-blocklist',
					scope: 'ip',
					type: 'ban',
					value: '1.1.1.1',
					expiresAt: new Date(Date.now() + 86400_000).toISOString()
				},
				{
					id: 2,
					duration: '4h',
					origin: 'cscli',
					scenario: 'crowdsecurity/http-cve',
					scope: 'ip',
					type: 'ban',
					value: '2.2.2.2',
					expiresAt: new Date(Date.now() + 14400_000).toISOString()
				},
				{
					id: 3,
					duration: '1h',
					origin: 'manual',
					scenario: 'manual:admin|smoke test ban',
					scope: 'ip',
					type: 'ban',
					value: '3.3.3.3',
					expiresAt: new Date(Date.now() + 3600_000).toISOString()
				}
			],
			meta: {
				total: 3,
				totalByOrigin: { CAPI: 1, cscli: 1, manual: 1 },
				limit: 100,
				offset: 0
			}
		};
		securityMock.fetchLAPIDecisions.mockResolvedValue(mixed);
		await openLiveTab();

		await waitFor(() => expect(screen.getByTestId('live-tab-local')).toBeInTheDocument());

		await fireEvent.click(screen.getByTestId('live-tab-local'));

		await waitFor(() => {
			// cscli row visible, CAPI + manual rows hidden.
			expect(screen.getByText('2.2.2.2')).toBeInTheDocument();
			expect(screen.queryByText('1.1.1.1')).toBeNull();
			expect(screen.queryByText('3.3.3.3')).toBeNull();
		});
	});

	it('renders the operator-friendly origin badge per row', async () => {
		// The Origin column shows "local" / "capi" / "manual"
		// pills regardless of CrowdSec's raw origin value.
		// Use the mixed fixture and assert the column text.
		const mixed = {
			decisions: [
				{
					id: 1, duration: '24h', origin: 'CAPI',
					scenario: 'x', scope: 'ip', type: 'ban',
					value: '1.1.1.1',
					expiresAt: new Date(Date.now() + 86400_000).toISOString()
				},
				{
					id: 2, duration: '4h', origin: 'cscli',
					scenario: 'x', scope: 'ip', type: 'ban',
					value: '2.2.2.2',
					expiresAt: new Date(Date.now() + 14400_000).toISOString()
				}
			],
			meta: {
				total: 2,
				totalByOrigin: { CAPI: 1, cscli: 1 },
				limit: 100, offset: 0
			}
		};
		securityMock.fetchLAPIDecisions.mockResolvedValue(mixed);
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByText('1.1.1.1')).toBeInTheDocument();
		});
		// Both badges visible somewhere on the page.
		const allText = document.body.textContent ?? '';
		expect(allText).toMatch(/capi/);
		expect(allText).toMatch(/local/);
	});

	it('parses scenario "manual:<user>|<reason>" into two-line cell', async () => {
		const manualFixture = {
			decisions: [
				{
					id: 1, duration: '1h', origin: 'manual',
					scenario: 'manual:admin|emergency block during smoke',
					scope: 'ip', type: 'ban',
					value: '198.51.100.1',
					expiresAt: new Date(Date.now() + 3600_000).toISOString()
				}
			],
			meta: {
				total: 1,
				totalByOrigin: { manual: 1 },
				limit: 100, offset: 0
			}
		};
		securityMock.fetchLAPIDecisions.mockResolvedValue(manualFixture);
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByText('198.51.100.1')).toBeInTheDocument();
		});

		const line1 = screen.getByTestId('manual-line1');
		expect(line1.textContent ?? '').toContain('manual / admin');

		const line2 = screen.getByTestId('manual-line2');
		expect(line2.textContent ?? '').toContain('emergency block during smoke');
	});

	it('parses scenario "manual:<user>" with no reason as line 1 only', async () => {
		// cscli-issued manual ban without Arenet's reason
		// encoding — username only, no line 2.
		const noReasonFixture = {
			decisions: [
				{
					id: 1, duration: '1h', origin: 'manual',
					scenario: 'manual:cscli-user',
					scope: 'ip', type: 'ban',
					value: '198.51.100.99',
					expiresAt: new Date(Date.now() + 3600_000).toISOString()
				}
			],
			meta: {
				total: 1,
				totalByOrigin: { manual: 1 },
				limit: 100, offset: 0
			}
		};
		securityMock.fetchLAPIDecisions.mockResolvedValue(noReasonFixture);
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByText('198.51.100.99')).toBeInTheDocument();
		});

		expect(screen.getByTestId('manual-line1').textContent ?? '').toContain('manual / cscli-user');
		// Line 2 is conditionally rendered; with empty reason
		// the element should be absent.
		expect(screen.queryByTestId('manual-line2')).toBeNull();
	});

	it('shows category-empty state when filter has 0 matches but LAPI has data', async () => {
		// CAPI-only fixture, then click Manuelles → expect
		// the "Aucune décision dans cette catégorie" empty.
		const capiOnly = {
			decisions: [
				{
					id: 1, duration: '24h', origin: 'CAPI',
					scenario: 'x', scope: 'ip', type: 'ban',
					value: '4.4.4.4',
					expiresAt: new Date(Date.now() + 86400_000).toISOString()
				}
			],
			meta: {
				total: 1,
				totalByOrigin: { CAPI: 1 },
				limit: 100, offset: 0
			}
		};
		securityMock.fetchLAPIDecisions.mockResolvedValue(capiOnly);
		await openLiveTab();
		await waitFor(() => expect(screen.getByTestId('live-tab-manual')).toBeInTheDocument());

		await fireEvent.click(screen.getByTestId('live-tab-manual'));

		await waitFor(() => {
			const empty = screen.getByTestId('live-empty');
			expect(empty.textContent ?? '').toMatch(/this category/);
			expect(empty.textContent ?? '').toMatch(/1 total/);
		});
	});

	it('shows the not-configured CTA on a 404 from the proxy', async () => {
		securityMock.fetchLAPIDecisions.mockRejectedValue(
			new ApiError('crowdsec bouncer not configured', 404)
		);
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByTestId('live-not-configured')).toBeInTheDocument();
		});
		// Link to settings page.
		expect(screen.getByRole('link', { name: /Settings/i })).toBeInTheDocument();
	});

	it('shows the unreachable banner + Retry button on a 502', async () => {
		securityMock.fetchLAPIDecisions.mockRejectedValue(
			new ApiError('connection refused (LAPI not running)', 502)
		);
		await openLiveTab();

		await waitFor(() => {
			const banner = screen.getByTestId('live-unreachable');
			expect(banner.textContent ?? '').toContain('LAPI unreachable');
			expect(banner.textContent ?? '').toContain('connection refused');
		});
		expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument();
	});

	it('retries the fetch when the Réessayer button is clicked', async () => {
		// First call fails, second succeeds.
		securityMock.fetchLAPIDecisions
			.mockRejectedValueOnce(new ApiError('timeout', 502))
			.mockResolvedValueOnce(sampleLAPI());
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByTestId('live-unreachable')).toBeInTheDocument();
		});

		await fireEvent.click(screen.getByRole('button', { name: /Retry/i }));

		await waitFor(() => {
			expect(screen.getByText('5.6.7.0/24')).toBeInTheDocument();
			expect(screen.queryByTestId('live-unreachable')).toBeNull();
		});
	});

	it('shows the empty state when LAPI returns zero decisions', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue({
			decisions: [],
			meta: { total: 0, totalByOrigin: {}, limit: 100, offset: 0 }
		});
		await openLiveTab();

		await waitFor(() => {
			expect(screen.getByTestId('live-empty')).toBeInTheDocument();
		});
	});

	it('changing the scope filter re-fetches with the scope query param', async () => {
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();

		await waitFor(() => expect(securityMock.fetchLAPIDecisions).toHaveBeenCalled());

		securityMock.fetchLAPIDecisions.mockClear();
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI(1));

		const scopeSelect = screen.getByTestId('live-scope-filter') as HTMLSelectElement;
		await fireEvent.change(scopeSelect, { target: { value: 'range' } });

		await waitFor(() => {
			expect(securityMock.fetchLAPIDecisions).toHaveBeenCalledWith(
				expect.objectContaining({ scope: 'range' })
			);
		});
	});

	// CS.3 Commit D — admin-only "+ Bannir une IP" entry point.
	// Visibility-only assertions here; the modal's submit flow
	// is covered by BanIPModal.test.ts.

	it('does NOT render the "+ Bannir une IP" button for viewer users', async () => {
		// auth.user stays null (default beforeEach) → isAdmin=false.
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();
		await waitFor(() => expect(securityMock.fetchLAPIDecisions).toHaveBeenCalled());
		expect(screen.queryByTestId('ban-open-btn')).toBeNull();
	});

	it('renders the "+ Bannir une IP" button for admin users', async () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();
		await waitFor(() => {
			expect(screen.getByTestId('ban-open-btn')).toBeInTheDocument();
		});
	});

	it('opens the BanIPModal when an admin clicks the button', async () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;
		securityMock.fetchLAPIDecisions.mockResolvedValue(sampleLAPI());
		await openLiveTab();
		await waitFor(() => expect(screen.getByTestId('ban-open-btn')).toBeInTheDocument());

		await fireEvent.click(screen.getByTestId('ban-open-btn'));
		await waitFor(() => {
			// Modal mount surfaces a dialog with the "Bannir
			// une IP" title.
			expect(screen.getByRole('dialog', { name: /Ban an IP/i })).toBeInTheDocument();
		});
	});
});

// --- Scenarios tab (CS.2.C) ---------------------------------

const sampleScenariosOK = {
	scenarios: [
		{
			name: 'crowdsecurity/http-cve',
			alerts24h: 12,
			lastSeen: new Date(Date.now() - 5 * 60_000).toISOString(),
			sampleScope: 'Ip',
			sampleValue: '203.0.113.42'
		},
		{
			name: 'crowdsecurity/http-bf',
			alerts24h: 4,
			lastSeen: new Date(Date.now() - 30 * 60_000).toISOString(),
			sampleScope: 'Ip',
			sampleValue: '198.51.100.7'
		},
		{
			name: 'manual',
			alerts24h: 1,
			lastSeen: new Date(Date.now() - 90 * 60_000).toISOString(),
			sampleScope: 'Ip',
			sampleValue: '192.0.2.1'
		}
	],
	meta: { totalAlerts: 17, windowHours: 24 }
};

describe('CrowdSec decisions panel — Scenarios tab', () => {
	async function openScenariosTab(): Promise<void> {
		securityMock.fetchDecisions.mockResolvedValue(sampleSnapshot);
		render(Page);
		await waitFor(() => expect(securityMock.fetchDecisions).toHaveBeenCalled());
		await fireEvent.click(screen.getByTestId('tab-scenarios'));
	}

	it('renders the table with aggregated rows on 200', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
			expect(screen.getByText('http-bf')).toBeInTheDocument();
			expect(screen.getByText('manual')).toBeInTheDocument();
		});
		// Alerts 24h count rendered.
		expect(screen.getByText('12')).toBeInTheDocument();
	});

	it('renders the Security-Automation CTA on 412', async () => {
		securityMock.fetchScenarios.mockRejectedValue(
			new ApiError('security automation not configured', 412)
		);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByTestId('scenarios-not-configured')).toBeInTheDocument();
		});
		// Must link to /settings so the operator has a direct path.
		const links = screen.getAllByRole('link', { name: /Security Automation/i });
		expect(links.length).toBeGreaterThan(0);
	});

	it('renders the unreachable banner + Retry on 502', async () => {
		securityMock.fetchScenarios.mockRejectedValue(
			new ApiError('machine credentials rejected by LAPI', 502)
		);
		await openScenariosTab();

		await waitFor(() => {
			const banner = screen.getByTestId('scenarios-unreachable');
			expect(banner.textContent ?? '').toContain('LAPI unreachable');
			expect(banner.textContent ?? '').toContain('machine credentials rejected');
		});
		expect(screen.getByRole('button', { name: /Retry/i })).toBeInTheDocument();
	});

	it('retries on Réessayer click after a 502', async () => {
		securityMock.fetchScenarios
			.mockRejectedValueOnce(new ApiError('timeout', 502))
			.mockResolvedValueOnce(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByTestId('scenarios-unreachable')).toBeInTheDocument();
		});

		await fireEvent.click(screen.getByRole('button', { name: /Retry/i }));

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
			expect(screen.queryByTestId('scenarios-unreachable')).toBeNull();
		});
	});

	it('renders the empty state when LAPI has no recent alerts', async () => {
		securityMock.fetchScenarios.mockResolvedValue({
			scenarios: [],
			meta: { totalAlerts: 0, windowHours: 24 }
		});
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByTestId('scenarios-empty')).toBeInTheDocument();
		});
	});

	it('opens the inspect modal with hub link + cscli command on row click', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
		});

		// Click the first row.
		const rows = screen.getAllByTestId('scenario-row');
		await fireEvent.click(rows[0]);

		await waitFor(() => {
			const modal = screen.getByTestId('scenario-modal');
			expect(modal.textContent ?? '').toContain('crowdsecurity/http-cve');
			expect(modal.textContent ?? '').toContain('cscli scenarios inspect crowdsecurity/http-cve');
		});

		// Namespaced scenario → hub link visible.
		const hubLink = screen.getByTestId('modal-hub-link') as HTMLAnchorElement;
		expect(hubLink.href).toContain('hub.crowdsec.net');
		expect(hubLink.href).toContain('crowdsecurity');
		expect(hubLink.href).toContain('http-cve');
	});

	it('closes the modal on Escape keypress (#R-CS2C-modal-esc-key)', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('http-cve')).toBeInTheDocument();
		});

		// Open the modal.
		const rows = screen.getAllByTestId('scenario-row');
		await fireEvent.click(rows[0]);
		await waitFor(() => {
			expect(screen.getByTestId('scenario-modal')).toBeInTheDocument();
		});

		// Esc on the window → modal closes.
		await fireEvent.keyDown(window, { key: 'Escape' });
		await waitFor(() => {
			expect(screen.queryByTestId('scenario-modal')).toBeNull();
		});
	});

	it('hides the hub link for non-namespaced scenarios (e.g. manual)', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => {
			expect(screen.getByText('manual')).toBeInTheDocument();
		});

		// Click the manual row (the 3rd / last).
		const rows = screen.getAllByTestId('scenario-row');
		await fireEvent.click(rows[2]);

		await waitFor(() => {
			expect(screen.getByTestId('scenario-modal')).toBeInTheDocument();
		});
		expect(screen.queryByTestId('modal-hub-link')).toBeNull();
	});

	it('does NOT re-fetch on tab re-open if data already loaded', async () => {
		securityMock.fetchScenarios.mockResolvedValue(sampleScenariosOK);
		await openScenariosTab();

		await waitFor(() => expect(securityMock.fetchScenarios).toHaveBeenCalledTimes(1));

		// Hop to snapshot tab, then back to scenarios.
		await fireEvent.click(screen.getByTestId('tab-snapshot'));
		await fireEvent.click(screen.getByTestId('tab-scenarios'));

		// Refresh button is the explicit re-fetch path; tab
		// re-open is NOT supposed to re-fire.
		expect(securityMock.fetchScenarios).toHaveBeenCalledTimes(1);
	});
});
