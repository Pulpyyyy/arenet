// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// #R-DASHBOARD-WAF-COUNTERS-ZERO + #R-WAF-EVENT-LABEL-INCONSISTENT
// — frontend tests for the dashboard.
//
// Pre-fix the dashboard had:
//   (a) one "WAF BLOCKS / H" KPI sourced from
//       totalWafBlocked which stayed at zero on
//       wafMode=detect routes (the homelab default).
//   (b) hardcoded "block" / "BLOCK 403" labels in the WAF
//       events feed, ignoring the per-event ev.action.
//
// The "Live tail" card that repeated the same five events in UTC is
// gone; the recent-events card is the one place they are shown.
//
// Post-fix we pin:
//   1. Two separate WAF KPI tiles (BLOCKED + DETECTED) with
//      the right values projected to /h.
//   2. Top Routes table renders the new WAF detect column.
//   3. Recent WAF events surface DETECT label on detect-
//      mode rows, BLOCK on block-mode rows.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';

const { metricsMock, securityMock, clientMock, certificatesMock, toastMock } = vi.hoisted(() => ({
	metricsMock: {
		fetchSummary: vi.fn(),
		fetchTimeseries: vi.fn()
	},
	securityMock: {
		fetchEvents: vi.fn(),
		// Phase 5 — dashboard loader calls fetchCertEventsAggregate
		// twice (30d window for the chart, 7d window for the
		// failed-7d KPI). Default stub returns the empty-buckets
		// shape so tests that don't care about cert data just
		// get a clean empty render.
		fetchCertEventsAggregate: vi.fn()
	},
	clientMock: {
		listRoutes: vi.fn()
	},
	certificatesMock: {
		list: vi.fn()
	},
	toastMock: { pushToast: vi.fn() }
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ pushToast: toastMock.pushToast }));
vi.mock('$lib/api/metrics', () => ({
	fetchSummary: (...a: unknown[]) => metricsMock.fetchSummary(...a),
	fetchTimeseries: (...a: unknown[]) => metricsMock.fetchTimeseries(...a)
}));
vi.mock('$lib/api/security', () => ({
	fetchEvents: (...a: unknown[]) => securityMock.fetchEvents(...a),
	fetchCertEventsAggregate: (...a: unknown[]) => securityMock.fetchCertEventsAggregate(...a)
}));
vi.mock('$lib/api/client', () => ({
	listRoutes: (...a: unknown[]) => clientMock.listRoutes(...a)
}));
vi.mock('$lib/api/certificates', () => ({
	certificatesApi: {
		list: (...a: unknown[]) => certificatesMock.list(...a)
	}
}));

import Page from './+page.svelte';
import type { SummaryResponse, WafEvent } from '$lib/api/types';

function makeSummary(overrides: Partial<SummaryResponse> = {}): SummaryResponse {
	return {
		generatedAt: '2026-06-10T22:00:00Z',
		windowSeconds: 60,
		totalReq: 60,
		totalFourXx: 2,
		totalFiveXx: 1,
		totalWafBlocked: 0,
		totalWafDetected: 0,
		totalThrottle: 0,
		totalRateLimitExceeded: 0,
		totalAuthFailures: 0,
		attackerIpsUnique: 0,
		totalCrowdSecDecisions: 0,
		activeCrowdSecIpsUnique: 0,
		wafBlocksByCategory: {},
		wafDetectsByCategory: {},
		globalP95LatencyMs: 12,
		activeRouteCount: 1,
		topRoutes: [],
		topAttackedRoute: null,
		...overrides
	};
}

beforeEach(() => {
	metricsMock.fetchSummary.mockReset();
	metricsMock.fetchTimeseries.mockReset();
	securityMock.fetchEvents.mockReset();
	securityMock.fetchCertEventsAggregate.mockReset();
	clientMock.listRoutes.mockReset();
	certificatesMock.list.mockReset();
	toastMock.pushToast.mockReset();

	metricsMock.fetchTimeseries.mockResolvedValue({ points: [] });
	securityMock.fetchEvents.mockResolvedValue({ events: [] });
	// Phase 5 — default to empty cert state so existing tests
	// (WAF KPIs / Top routes / Recent events) stay focused on
	// the surfaces they care about. Individual cert-KPI tests
	// override below.
	securityMock.fetchCertEventsAggregate.mockResolvedValue({ buckets: [] });
	certificatesMock.list.mockResolvedValue([]);
	clientMock.listRoutes.mockResolvedValue([{
		id: 'r1', host: 'ha.example.com', upstreams: [{ url: 'http://10.0.0.10', weight: 1 }]
	}]);
});

describe('Dashboard — WAF KPI split (#R-DASHBOARD-WAF-COUNTERS-ZERO)', () => {
	it('renders both BLOQUÉ and DÉTECTÉ tiles independently from the summary', async () => {
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				totalWafBlocked: 4,
				totalWafDetected: 11
			})
		);
		render(Page);
		// Wait for mount + async fetches.
		await tick();
		await tick();
		await tick();

		const blocked = screen.getByTestId('kpi-waf-blocked');
		const detected = screen.getByTestId('kpi-waf-detected');
		// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — post-fix the
		// dashboard reads the 24h total directly (no ×60
		// projection). The tiles show raw 4 / 11.
		expect(blocked.textContent).toContain('4');
		expect(detected.textContent).toContain('11');
	});

	it('reads zero for the detect tile when the wire field is absent (graceful default)', async () => {
		// Simulate a stale summary response where the new
		// field is missing: the tile must render 0, not NaN.
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				totalWafBlocked: 6,
				// totalWafDetected intentionally omitted
				totalWafDetected: undefined as unknown as number
			})
		);
		render(Page);
		await tick();
		await tick();
		await tick();

		const detected = screen.getByTestId('kpi-waf-detected');
		expect(detected.textContent).toMatch(/\b0\b/);
		expect(detected.textContent).not.toContain('NaN');
	});
});

describe('Dashboard — WAF event label fix (#R-WAF-EVENT-LABEL-INCONSISTENT)', () => {
	const blockEvent: WafEvent = {
		id: 1,
		ts: '2026-06-10T22:00:00Z',
		routeId: 'r1',
		ruleId: '942100',
		category: 'SQLi',
		severity: 5,
		srcIp: '1.1.1.1',
		requestMethod: 'POST',
		requestPath: '/login',
		payloadSample: "' OR 1=1",
		action: 'BLOCK',
		statusCode: 403
	};
	const detectEvent: WafEvent = {
		id: 2,
		ts: '2026-06-10T22:00:00Z',
		routeId: 'r1',
		ruleId: '930100',
		category: 'LFI',
		severity: 5,
		srcIp: '2.2.2.2',
		requestMethod: 'GET',
		requestPath: '/index.php?file=../etc/passwd',
		payloadSample: '../etc/passwd',
		action: 'DETECT',
		statusCode: 0
	};

	it('renders the BLOCK label on block-mode events, once', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEvents.mockResolvedValue({ events: [blockEvent] });
		render(Page);
		await tick();
		await tick();
		await tick();

		const recent = screen.getByTestId('recent-event-1');
		expect(recent.textContent?.toLowerCase()).toContain('block');
		// The duplicate "Live tail" card is gone: the event is shown once.
		expect(screen.queryByTestId('tail-event-1')).toBeNull();
		expect(screen.getAllByText('SQLi · 942100')).toHaveLength(1);
		// The row reads relative time; the absolute reading on hover is
		// local, never a bare UTC clock.
		const when = recent.querySelector('.when');
		expect(when?.getAttribute('title')).toBe(new Date(blockEvent.ts).toLocaleString('en'));
	});

	it('renders the DETECT label on detect-mode events', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEvents.mockResolvedValue({ events: [detectEvent] });
		render(Page);
		await tick();
		await tick();
		await tick();

		const recent = screen.getByTestId('recent-event-2');
		expect(recent.textContent?.toLowerCase()).toContain('detect');
		// Must NOT carry the misleading "block" label that pre-fix
		// silently rendered on detect events.
		expect(recent.textContent?.toLowerCase()).not.toContain('block');
	});

	it('renders both labels correctly when mixed events are in the feed', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		securityMock.fetchEvents.mockResolvedValue({
			events: [blockEvent, detectEvent]
		});
		render(Page);
		await tick();
		await tick();
		await tick();

		const recent1 = screen.getByTestId('recent-event-1');
		const recent2 = screen.getByTestId('recent-event-2');
		expect(recent1.textContent?.toLowerCase()).toContain('block');
		expect(recent2.textContent?.toLowerCase()).toContain('detect');
	});
});

describe('Dashboard — Top Routes WAF detect column (#R-DASHBOARD-WAF-COUNTERS-ZERO)', () => {
	it('renders the new wafDetected column with per-route values', async () => {
		metricsMock.fetchSummary.mockResolvedValue(
			makeSummary({
				topRoutes: [
					{
						routeId: 'r1',
						host: 'ha.example.com',
						reqs: 60,
						fourxx: 0,
						fivexx: 0,
						wafBlocked: 1,
						wafDetected: 7
					}
				],
				activeRouteCount: 1
			})
		);
		render(Page);
		await tick();
		await tick();
		await tick();

		const headers = screen.getAllByRole('columnheader');
		const labels = headers.map((h) => h.textContent?.trim() ?? '');
		expect(labels).toContain('WAF block');
		expect(labels).toContain('WAF detect');
		// The row's detect cell shows 7; the row's block cell
		// shows 1. Pin both so a swap regression would catch.
		const row = screen.getByText('ha.example.com').closest('tr')!;
		const cells = row.querySelectorAll('td.mono.right');
		// Order: Req/min, 4xx/min, 5xx/min, block, detect.
		expect(cells[3].textContent?.trim()).toBe('1');
		expect(cells[4].textContent?.trim()).toBe('7');
	});
});

// --- Phase 5 — cert KPI tiles + lifecycle panel ----------------------------
//
// Three KPI tiles (total / expiring-30d / failed-7d) + a chart
// panel ("Cycle de vie des certificats") that mounts the
// MultiSeriesTimelineChart component. These tests pin the
// loader's wiring: each tile reads its derived value from a
// distinct source (certificatesApi.list for total + expiring,
// fetchCertEventsAggregate window=7d for failed-7d), and the
// chart panel renders even on an empty buckets payload.

describe('Dashboard — Phase 5 cert KPI tiles', () => {
	function inHorizonISO(daysAhead: number): string {
		return new Date(Date.now() + daysAhead * 24 * 60 * 60 * 1000).toISOString();
	}

	it('"Total certs" tile counts the certificates list length', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		certificatesMock.list.mockResolvedValue([
			{ domain: 'a.example', notAfter: inHorizonISO(60) },
			{ domain: 'b.example', notAfter: inHorizonISO(45) },
			{ domain: 'c.example', notAfter: inHorizonISO(80) }
		]);

		render(Page);
		await tick();
		await tick();
		await tick();

		const tile = screen.getByTestId('kpi-cert-total');
		expect(tile.textContent).toContain('3');
	});

	it('"Expirent dans 30j" tile counts only certs with notAfter inside the 30d horizon', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		certificatesMock.list.mockResolvedValue([
			{ domain: 'soon-a.example', notAfter: inHorizonISO(10) }, // counts
			{ domain: 'soon-b.example', notAfter: inHorizonISO(28) }, // counts
			{ domain: 'far.example', notAfter: inHorizonISO(60) } // doesn't count
		]);

		render(Page);
		await tick();
		await tick();
		await tick();

		const tile = screen.getByTestId('kpi-cert-expiring');
		expect(tile.textContent).toContain('2');
	});

	it('"Failed last 7d" tile sums failed counts across the 7d aggregate', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		// First call (30d for chart) → empty buckets.
		// Second call (7d for failed-7d KPI) → buckets that sum to 5.
		securityMock.fetchCertEventsAggregate
			.mockResolvedValueOnce({ buckets: [] })
			.mockResolvedValueOnce({
				buckets: [
					{ bucketStart: '2026-06-08T00:00:00Z', issued: 0, renewed: 0, failed: 2 },
					{ bucketStart: '2026-06-09T00:00:00Z', issued: 0, renewed: 0, failed: 3 }
				]
			});

		render(Page);
		await tick();
		await tick();
		await tick();

		const tile = screen.getByTestId('kpi-cert-failed-7d');
		expect(tile.textContent).toContain('5');
	});

	it('renders the cert lifecycle panel on every dashboard load', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());

		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('cert-lifecycle-panel')).toBeTruthy();
	});

	it('cert KPI tiles default to zero when /certificates fails (best-effort)', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		certificatesMock.list.mockRejectedValue(new Error('boot failure'));

		render(Page);
		await tick();
		await tick();
		await tick();

		// .catch fallback → empty list → zero counts. Dashboard
		// stays renderable instead of toasting an error.
		expect(screen.getByTestId('kpi-cert-total').textContent).toContain('0');
		expect(screen.getByTestId('kpi-cert-expiring').textContent).toContain('0');
	});
});

// The traffic chart said "Req/s" over counts per minute, kept the
// previous metric's points when a fetch failed, and the page said
// "real-time" over data read once.
describe('Dashboard — traffic chart units and freshness', () => {
	it('labels the series per bucket, from the response', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		metricsMock.fetchTimeseries.mockResolvedValue({ bucketSizeSeconds: 60, points: [] });
		render(Page);

		await waitFor(() => expect(screen.getByTestId('chart-unit')).toHaveTextContent('requests / min'));
		expect(screen.getByRole('button', { name: 'Requests' })).toBeInTheDocument();
		expect(screen.queryByText('Req/s')).toBeNull();
	});

	it('shows the failure instead of the previous metric when a switch fails', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		metricsMock.fetchTimeseries.mockResolvedValueOnce({
			bucketSizeSeconds: 60,
			points: [
				{ ts: '2026-06-10T22:00:00Z', value: 12 },
				{ ts: '2026-06-10T22:01:00Z', value: 14 }
			]
		});
		render(Page);
		await waitFor(() => expect(screen.getByTestId('chart-unit')).toBeInTheDocument());

		metricsMock.fetchTimeseries.mockRejectedValueOnce(new Error('boom'));
		await fireEvent.click(screen.getByRole('button', { name: '5xx' }));

		expect(await screen.findByTestId('chart-error')).toBeInTheDocument();
		expect(screen.getByTestId('chart-unit')).toHaveTextContent('5xx responses / min');
		expect(toastMock.pushToast).not.toHaveBeenCalled();
	});

	it('says when the data was last updated', async () => {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary());
		render(Page);
		expect(await screen.findByTestId('dashboard-updated-at')).toHaveTextContent('Updated at');
	});
});

// The tiles were dead ends, an abnormal value looked like any other,
// and the upstreams header printed the shown slice as the total.
describe('Dashboard — tiles lead somewhere and flag what needs a look', () => {
	async function renderWith(summary: Partial<SummaryResponse>): Promise<void> {
		metricsMock.fetchSummary.mockResolvedValue(makeSummary(summary));
		render(Page);
		await screen.findByTestId('kpi-cert-failed-7d');
	}

	it('links each tile to the page behind its number', async () => {
		await renderWith({});
		const hrefs: Record<string, string> = {
			'kpi-req-per-sec': '/routes',
			'kpi-p95': '/routes',
			'kpi-5xx': '/routes',
			'kpi-waf-blocked': '/waf',
			'kpi-waf-detected': '/waf',
			'kpi-cert-total': '/certs',
			'kpi-cert-expiring': '/certs',
			'kpi-cert-failed-7d': '/certs'
		};
		for (const [id, href] of Object.entries(hrefs)) {
			const tile = screen.getByTestId(id);
			expect(tile.tagName, id).toBe('A');
			expect(tile.getAttribute('href'), id).toBe(href);
		}
	});

	it('gives the alarm tiles the warn tone when they are above zero', async () => {
		certificatesMock.list.mockResolvedValue([
			{ domain: 'soon.example', notAfter: new Date(Date.now() + 5 * 86_400_000).toISOString() }
		]);
		securityMock.fetchCertEventsAggregate
			.mockResolvedValueOnce({ buckets: [] })
			.mockResolvedValueOnce({
				buckets: [{ bucketStart: '2026-06-09T00:00:00Z', issued: 0, renewed: 0, failed: 1 }]
			});
		// One 5xx in 100 000 requests rounds to 0 % and is still flagged.
		await renderWith({
			totalReq: 100_000,
			totalFiveXx: 1,
			totalWafBlocked: 3,
			totalWafDetected: 9
		});

		for (const id of ['kpi-5xx', 'kpi-waf-blocked', 'kpi-cert-expiring', 'kpi-cert-failed-7d']) {
			expect(screen.getByTestId(id).getAttribute('data-tone'), id).toBe('warn');
		}
		// Volumes and detect-mode matches are not alarms.
		for (const id of ['kpi-req-per-sec', 'kpi-p95', 'kpi-waf-detected', 'kpi-cert-total']) {
			expect(screen.getByTestId(id).hasAttribute('data-tone'), id).toBe(false);
		}
	});

	it('keeps the alarm tiles quiet at zero', async () => {
		await renderWith({ totalFiveXx: 0, totalWafBlocked: 0 });
		for (const id of ['kpi-5xx', 'kpi-waf-blocked', 'kpi-cert-expiring', 'kpi-cert-failed-7d']) {
			expect(screen.getByTestId(id).hasAttribute('data-tone'), id).toBe(false);
		}
	});

	it('says "8 of N" and links to /routes when the upstream list is cut', async () => {
		clientMock.listRoutes.mockResolvedValue(
			Array.from({ length: 11 }, (_, i) => ({
				id: `r${i}`,
				host: `h${i}.example.com`,
				upstreams: [{ url: `http://10.0.0.${i}`, weight: 1 }]
			}))
		);
		await renderWith({});

		expect(screen.getByTestId('upstreams-meta')).toHaveTextContent('8 of 11 distinct');
		expect(screen.getByTestId('upstreams-see-all').getAttribute('href')).toBe('/routes');
		expect(document.querySelectorAll('.upstream-row')).toHaveLength(8);
	});

	it('gives the plain count when every upstream is shown', async () => {
		await renderWith({});
		expect(screen.getByTestId('upstreams-meta')).toHaveTextContent('1 distinct');
		expect(screen.queryByTestId('upstreams-see-all')).toBeNull();
	});
});
