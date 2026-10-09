// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /logs page tests — pins the Step U.5 contract: the unified
// table aggregator integrates cert lifecycle events as a 4th
// source alongside WAF, throttle, and auth-failure. First test
// file for this route; created in U.5 to cover the cert
// integration end-to-end (mapper → row render → filter →
// search).
//
// Existing 3 sources (WAF/throttle/auth) are exercised
// indirectly by these tests because they share the same load()
// codepath; this file does NOT attempt to back-fill page-test
// coverage for the pre-U.5 sources.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type {
	AuthFailureRecentEvent,
	CertEvent,
	ThrottleEvent,
	WafEvent
} from '$lib/api/types';

// Mocks — same vi.hoisted pattern as the certs page tests so the
// module imports happen after the mock factories are in place.
const { toastMock, securityMock, clientMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: {
		fetchEvents: vi.fn(),
		fetchThrottleEvents: vi.fn(),
		fetchAuthFailures: vi.fn(),
		fetchCertEvents: vi.fn(),
		// W.5 — 5th source (country-block events).
		fetchCountryBlockEvents: vi.fn(),
		// Z.2 — 6th source (rate-limit 429 events).
		fetchRateLimitEvents: vi.fn(),
		// Z.5.3 — batch GeoIP lookup. Default: degraded
		// shape (every IP returns empty country) so tests
		// don't need to opt-in to enrichment.
		geoLookupBatch: vi.fn()
	},
	// W.7 follow-up — routes API for routeId → host
	// resolution. Default returns an empty list so rows
	// with a routeId fall back to the <RouteHost>
	// truncated-UUID rendering; individual tests
	// override to test the happy path.
	clientMock: {
		listRoutes: vi.fn()
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);
vi.mock('$lib/api/client', () => clientMock);

import Page from './+page.svelte';

// Anchor "now" for fixture timestamps so ts ordering is
// deterministic. Cert events sit at varying offsets from this
// anchor; the most-recent cert event ends up at the top of
// the merged feed.
const NOW = new Date('2026-06-06T12:00:00Z');

function isoOffset(seconds: number): string {
	return new Date(NOW.getTime() + seconds * 1000).toISOString();
}

beforeEach(() => {
	toastMock.pushToast.mockReset();
	securityMock.fetchEvents.mockReset();
	securityMock.fetchThrottleEvents.mockReset();
	securityMock.fetchAuthFailures.mockReset();
	securityMock.fetchCertEvents.mockReset();
	securityMock.fetchCountryBlockEvents.mockReset();
	securityMock.fetchRateLimitEvents.mockReset();
	securityMock.geoLookupBatch.mockReset();
	securityMock.geoLookupBatch.mockResolvedValue({
		results: {},
		degraded: true
	});

	// Defaults: every source returns empty. Individual tests
	// override what they need.
	securityMock.fetchEvents.mockResolvedValue({ events: [] });
	securityMock.fetchThrottleEvents.mockResolvedValue({ events: [] });
	securityMock.fetchAuthFailures.mockResolvedValue({
		window: '24h',
		timeseries: [],
		recent: []
	});
	securityMock.fetchCertEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	});
	securityMock.fetchCountryBlockEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	});
	securityMock.fetchRateLimitEvents.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	});
	clientMock.listRoutes.mockReset();
	clientMock.listRoutes.mockResolvedValue([]);
});

afterEach(() => {
	// The page sets up a setInterval poll on mount; cleanup is
	// the testing-library's auto-cleanup which dispatches
	// onDestroy. No explicit timer-clear needed because the
	// page calls clearInterval in onDestroy.
	vi.clearAllMocks();
	// The filters live in the URL: without this, one test's filter
	// would greet the next one's render.
	window.history.replaceState(null, '', '/');
});

const certFixture = (overrides: Partial<CertEvent> = {}): CertEvent => ({
	timestamp: isoOffset(0),
	level: 'INFO',
	eventType: 'cert_obtained',
	domain: 'example.com',
	issuer: "Let's Encrypt",
	challenge: 'DNS-01',
	renewal: false,
	error: '',
	details: '',
	...overrides
});

describe('/logs — cert events render in the unified table', () => {
	it('cert_obtained row appears with INFO level + "cert.obtained" detail', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					domain: '*.example.com',
					issuer: "Let's Encrypt",
					challenge: 'DNS-01',
					renewal: true
				})
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		// Wait for the row to mount. The filter card renders
		// immediately; the row arrives post-load.
		const row = await screen.findByText(/cert\.obtained/);
		expect(row).toBeInTheDocument();
		// Domain in the path column.
		expect(screen.getByText(/\*\.example\.com/)).toBeInTheDocument();
		// Issuer and challenge included.
		expect(row.textContent ?? '').toMatch(/Let's Encrypt/);
		expect(row.textContent ?? '').toMatch(/DNS-01/);
		// Renewal marker.
		expect(row.textContent ?? '').toMatch(/renewal/);
	});

	it('cert_failed row appears with WARN level + truncated error', async () => {
		const longError =
			"subject 'test.local' does not qualify for a public certificate because the TLD is not on the public suffix list";
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'test.local',
					issuer: '',
					challenge: '',
					error: longError
				})
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		const row = await screen.findByText(/cert\.failed/);
		expect(row).toBeInTheDocument();
		// Truncated to ~60 chars + ellipsis. The "does not
		// qualify" prefix is in the first 60 chars of the
		// fixture's error.
		expect(row.textContent ?? '').toMatch(/does not qualify/);
		// The truncated marker is present.
		expect(row.textContent ?? '').toMatch(/\.\.\./);
	});

	it('cert_ocsp_revoked row appears with WARN level + "OCSP revocation"', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_ocsp_revoked',
					level: 'ERROR',
					domain: 'revoked.example.com'
				})
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		const row = await screen.findByText(/cert\.revoked/);
		expect(row).toBeInTheDocument();
		expect(row.textContent ?? '').toMatch(/OCSP revocation/);
	});

	it('cert events render with method=ACME and srcIp=(interne) for system-emitted rows', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture()],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.obtained/);
		expect(screen.getByText('ACME')).toBeInTheDocument();
		// (interne) marker for system-emitted source IP.
		expect(screen.getByText(/\(interne\)/)).toBeInTheDocument();
	});
});

describe('/logs — level taxonomy mapping for cert events', () => {
	it('cert ERROR rows surface under the warn filter (no Error filter exists)', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'broken.example.com',
					error: 'simulated failure'
				})
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.failed/);

		// Click the "Warn" segmented button.
		const warnBtn = screen.getByRole('button', { name: /^warn$/i });
		await userEvent.click(warnBtn);

		// Row still visible after filter — cert ERROR is
		// pragmatically mapped to 'warn' per the LevelTag
		// union (no 'error' value exists today).
		expect(screen.getByText(/cert\.failed/)).toBeInTheDocument();
	});

	it('cert INFO rows surface under the info filter', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					level: 'INFO',
					domain: 'good.example.com'
				})
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.obtained/);

		const infoBtn = screen.getByRole('button', { name: /^info$/i });
		await userEvent.click(infoBtn);

		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
	});

	it('cert rows hidden under the block filter (no cert events are HTTP blocks)', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					level: 'INFO'
				}),
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'bad.example.com',
					error: 'boom',
					timestamp: isoOffset(-60)
				})
			],
			total: 2,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/cert\.obtained/);

		const blockBtn = screen.getByRole('button', { name: /^block$/i });
		await userEvent.click(blockBtn);

		expect(screen.queryByText(/cert\.obtained/)).not.toBeInTheDocument();
		expect(screen.queryByText(/cert\.failed/)).not.toBeInTheDocument();
	});
});

describe('/logs — search across cert content', () => {
	beforeEach(() => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					eventType: 'cert_obtained',
					domain: 'foo.example.com',
					issuer: "Let's Encrypt",
					challenge: 'DNS-01'
				}),
				certFixture({
					eventType: 'cert_failed',
					level: 'ERROR',
					domain: 'broken.test',
					error: 'DNS lookup failed',
					timestamp: isoOffset(-30)
				}),
				certFixture({
					eventType: 'cert_obtained',
					domain: 'bar.example.com',
					issuer: 'ZeroSSL',
					timestamp: isoOffset(-60)
				})
			],
			total: 3,
			hasMore: false
		});
	});

	it('search "cert" surfaces all 3 cert rows via the detail field', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, 'cert');

		// All 3 cert rows visible (detail contains "cert.").
		expect(screen.getAllByText(/cert\.obtained/).length).toBe(2);
		expect(screen.getAllByText(/cert\.failed/).length).toBe(1);
	});

	it('search "Let\'s Encrypt" matches only Let\'s Encrypt-issued rows', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, "Let's Encrypt");

		// Only foo.example.com (LE-issued) survives.
		expect(screen.getByText(/foo\.example\.com/)).toBeInTheDocument();
		expect(screen.queryByText(/bar\.example\.com/)).not.toBeInTheDocument();
		// broken.test has no issuer (Failed events) so the
		// search "let's encrypt" excludes it.
		expect(screen.queryByText(/broken\.test/)).not.toBeInTheDocument();
	});

	it('search by domain string filters cert rows by path column', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, 'foo.example');

		expect(screen.getByText(/foo\.example\.com/)).toBeInTheDocument();
		expect(screen.queryByText(/bar\.example\.com/)).not.toBeInTheDocument();
		expect(screen.queryByText(/broken\.test/)).not.toBeInTheDocument();
	});

	it('search by issuer "ZeroSSL" matches the ZeroSSL-issued row', async () => {
		render(Page);
		await screen.findAllByText(/cert\./);
		const searchInput = screen.getByLabelText('Filter events');
		await userEvent.type(searchInput, 'ZeroSSL');

		expect(screen.getByText(/bar\.example\.com/)).toBeInTheDocument();
		expect(screen.queryByText(/foo\.example\.com/)).not.toBeInTheDocument();
	});
});

describe('/logs — multi-source merge + cert source resilience', () => {
	it('merges cert events alongside WAF rows, sorted ts-desc', async () => {
		const wafTs = isoOffset(-120);
		const certTs = isoOffset(0); // most recent
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: wafTs,
					routeId: 'r-1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/?id=1',
					payloadSample: 'id=1',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture({ timestamp: certTs })],
			total: 1,
			hasMore: false
		});

		render(Page);
		// Both rows visible: cert (ts=NOW) + WAF (ts=NOW-2m).
		// The cert row sits above the WAF row in the DOM.
		await screen.findByText(/cert\.obtained/);
		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
		expect(screen.getByText(/WAF rule 942100/)).toBeInTheDocument();
	});

	it('cert-events rejection does NOT break the other sources', async () => {
		// fetchCertEvents throws; WAF still returns a row.
		securityMock.fetchCertEvents.mockRejectedValue(
			new Error('simulated 503 from /observability/cert-events')
		);
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-1',
					ruleId: '941100',
					category: 'XSS',
					severity: 3,
					srcIp: '5.6.7.8',
					requestMethod: 'POST',
					requestPath: '/search',
					payloadSample: '<script>',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});

		render(Page);
		// WAF row renders despite the cert source failing —
		// Promise.allSettled isolates failures.
		expect(await screen.findByText(/WAF rule 941100/)).toBeInTheDocument();
		// No cert rows visible.
		expect(screen.queryByText(/cert\.obtained/)).not.toBeInTheDocument();
	});

	it('cert-events degraded response (degraded=true, empty events) renders without crash', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [],
			total: 0,
			hasMore: false,
			degraded: true
		});
		// Add a throttle row so the page has SOMETHING to render
		// once the cert source comes back empty.
		securityMock.fetchThrottleEvents.mockResolvedValue({
			events: [
				{
					id: 99,
					ts: isoOffset(0),
					tier: 1,
					srcIp: '9.9.9.9',
					attemptedUsername: 'admin',
					blockedUntil: isoOffset(900),
					blockDurationSeconds: 900
				} satisfies ThrottleEvent
			]
		});

		render(Page);
		// Throttle row renders.
		expect(await screen.findByText(/Rate-limit tier 1/)).toBeInTheDocument();
		// No cert rows.
		expect(screen.queryByText(/cert\.obtained/)).not.toBeInTheDocument();
		expect(screen.queryByText(/cert\.failed/)).not.toBeInTheDocument();
	});

	it('merge order is purely ts-desc — most recent at top regardless of source', async () => {
		// Cert at ts=NOW-30s, WAF at ts=NOW. WAF should sort
		// above cert.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-1',
					ruleId: '942999',
					category: 'OTHER',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/abuse',
					payloadSample: '',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture({ timestamp: isoOffset(-30) })],
			total: 1,
			hasMore: false
		});

		render(Page);
		await screen.findByText(/942999/);
		// Both rows visible.
		expect(screen.getByText(/WAF rule 942999/)).toBeInTheDocument();
		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
	});
});

describe('/logs — W.bugfix Fix #1 mode-aware WAF labels', () => {
	it('renders a DETECT-mode WAF row with the DETECT level + "—" status', async () => {
		// Pre-fix every WAF row rendered as level="block" + code="403"
		// regardless of what the WAF actually did. Operators in detect
		// mode saw "BLOCK 403" entries while their requests passed
		// through the upstream unimpeded — the source of the original
		// false-positive bug report. Post-fix the row renders with
		// the DETECT pill + "—" for the code (the WAF doesn't capture
		// the upstream's actual status at callback time).
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-detect',
					ruleId: '920420',
					category: 'PROTOCOL',
					severity: 3,
					srcIp: '203.0.113.5',
					requestMethod: 'GET',
					requestPath: '/auth/login_flow',
					payloadSample: 'User-Agent: shellshock-probe',
					action: 'DETECT',
					statusCode: 0
				} satisfies WafEvent
			]
		});

		render(Page);
		// Detail still renders the rule + category.
		await screen.findByText(/WAF rule 920420/);
		// Level pill says DETECT, not BLOCK.
		expect(screen.getByText('DETECT')).toBeInTheDocument();
		expect(screen.queryByText('BLOCK')).not.toBeInTheDocument();
		// Status column renders "—" instead of "403".
		expect(screen.getByText('—')).toBeInTheDocument();
		expect(screen.queryByText('403')).not.toBeInTheDocument();
	});

	it('renders a BLOCK-mode WAF row with the BLOCK level + 403 status', async () => {
		// Symmetric to the DETECT case. Pin the post-fix contract
		// for block-mode rows so a future regression to "always
		// detect" or "always block" is caught.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 2,
					ts: isoOffset(0),
					routeId: 'r-block',
					ruleId: '942100',
					category: 'SQLi',
					severity: 2,
					srcIp: '203.0.113.5',
					requestMethod: 'POST',
					requestPath: '/api/search',
					payloadSample: "' OR 1=1 --",
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});

		render(Page);
		await screen.findByText(/WAF rule 942100/);
		expect(screen.getByText('BLOCK')).toBeInTheDocument();
		expect(screen.getByText('403')).toBeInTheDocument();
	});
});

describe('/logs — existing 3-source aggregation still works (regression)', () => {
	it('renders a WAF + throttle + auth row alongside cert events', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/?id=1',
					payloadSample: '',
					action: 'BLOCK',
					statusCode: 403
				} satisfies WafEvent
			]
		});
		securityMock.fetchThrottleEvents.mockResolvedValue({
			events: [
				{
					id: 2,
					ts: isoOffset(-10),
					tier: 2,
					srcIp: '5.6.7.8',
					attemptedUsername: 'root',
					blockedUntil: isoOffset(3590),
					blockDurationSeconds: 3600
				} satisfies ThrottleEvent
			]
		});
		securityMock.fetchAuthFailures.mockResolvedValue({
			window: '24h',
			timeseries: [],
			recent: [
				{
					ts: isoOffset(-20),
					action: 'login_failure',
					username: 'tester',
					srcIp: '7.7.7.7',
					message: 'bad password'
				} satisfies AuthFailureRecentEvent
			]
		});
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [certFixture({ timestamp: isoOffset(-30) })],
			total: 1,
			hasMore: false
		});

		render(Page);
		await screen.findByText(/WAF rule 942100/);
		// All 4 sources represented in the merged table.
		expect(screen.getByText(/WAF rule 942100/)).toBeInTheDocument();
		expect(screen.getByText(/Rate-limit tier 2/)).toBeInTheDocument();
		expect(screen.getByText(/login_failure/)).toBeInTheDocument();
		expect(screen.getByText(/cert\.obtained/)).toBeInTheDocument();
	});
});

describe('/logs — duplicate-tuple regression (Svelte each_key_duplicate)', () => {
	// Operator-reported regression: the page threw Svelte's
	// each_key_duplicate when two cert events with the same
	// (timestamp, domain, eventType) tuple — or two auth
	// failures with the same (ts, srcIp, username) — landed
	// in the same fetch. Burst login retries hit this
	// trivially (5 failures/second from the same IP at the
	// same username), as do certmagic OBTAIN+FAILED races.
	// Fix: append a source-local array index to the key so
	// the natural-tuple prefix stays stable across polls but
	// uniqueness is guaranteed within a single batch.

	it('renders two cert events sharing (timestamp, domain, eventType) without throwing', async () => {
		const sharedTs = isoOffset(-1);
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				certFixture({
					timestamp: sharedTs,
					domain: 'example.com',
					eventType: 'cert_failed',
					level: 'ERROR',
					error: 'first failure'
				}),
				certFixture({
					timestamp: sharedTs,
					domain: 'example.com',
					eventType: 'cert_failed',
					level: 'ERROR',
					error: 'second failure (same second, same domain)'
				})
			],
			total: 2,
			hasMore: false
		});

		render(Page);
		// Both rows must mount — a duplicate-key throw would
		// either render nothing (boot crashed) or render only
		// one row (Svelte silently drops the dup before HMR).
		await screen.findByText(/first failure/);
		expect(screen.getByText(/first failure/)).toBeInTheDocument();
		expect(screen.getByText(/second failure/)).toBeInTheDocument();
	});

	it('renders two auth failures sharing (ts, srcIp, username) without throwing', async () => {
		const sharedTs = isoOffset(-1);
		securityMock.fetchAuthFailures.mockResolvedValue({
			window: '24h',
			timeseries: [],
			recent: [
				{
					ts: sharedTs,
					action: 'login_failure',
					username: 'admin',
					srcIp: '203.0.113.42',
					message: 'wrong password'
				} satisfies AuthFailureRecentEvent,
				{
					ts: sharedTs,
					action: 'login_failure',
					username: 'admin',
					srcIp: '203.0.113.42',
					message: 'wrong password (retry)'
				} satisfies AuthFailureRecentEvent
			]
		});

		render(Page);
		// Two distinct rows from the same (ts, srcIp, username)
		// tuple must both mount. The message column carries
		// the disambiguator that lets us assert on both.
		await screen.findByText(/wrong password \(retry\)/);
		expect(screen.getByText(/wrong password \(retry\)/)).toBeInTheDocument();
		// The first row's message is "wrong password" — used
		// as a substring it would match the retry row too,
		// so use a stricter regex that excludes the suffix.
		expect(screen.getByText(/wrong password$/)).toBeInTheDocument();
	});
});

describe('/logs — W.5 country-block source (W.7 follow-up: humanized + host-resolved)', () => {
	it('renders a country-block row with COUNTRY pill + status + humanized detail + host badge', async () => {
		// W.5 introduced the country-block row; W.7 follow-
		// up replaced the raw "deny-deny-match" detail with
		// the humanized "country denied" + routes the host
		// badge through <RouteHost> resolving routeId →
		// hostname via listRoutes(). Both changes are
		// asserted here; the W.7-follow-up describe block
		// below adds the fallback + WAF coverage tests.
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-uuid-1', host: 'ha.example.test' }
		]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 7,
					ts: isoOffset(0),
					routeId: 'route-uuid-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 451,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});

		render(Page);
		// Host badge replaces the raw UUID — operator sees
		// the friendly hostname.
		await screen.findByText('ha.example.test');
		// Phase Z.4 — the level column now renders the actual
		// level (BLOCK) consistently across every source. The
		// SOURCE column carries the "COUNTRY" badge.
		expect(screen.getByText('BLOCK')).toBeInTheDocument();
		// Phase Z.5.4 — "COUNTRY" now also appears in the
		// histogram legend below the table, so scope the
		// match to the .log-src pill on the row.
		const matches = screen.getAllByText('COUNTRY');
		const rowBadge = matches.find((el) => el.classList.contains('log-src'));
		expect(rowBadge).toBeDefined();
		// Status code from the persisted row, not hardcoded.
		expect(screen.getByText('451')).toBeInTheDocument();
		// Humanized detail string (W.7 follow-up).
		expect(screen.getByText(/RU · country denied/)).toBeInTheDocument();
		// Raw "deny-deny-match" must NOT be visible body text.
		expect(
			screen.queryByText(/deny-deny-match/)
		).not.toBeInTheDocument();
		// Phase Z.5.3 — SOURCE IP is now octet-masked. Both
		// the masked label and the full-IP title tooltip are
		// pinned : the visible label keeps shoulder-surfing
		// hygiene, the title preserves forensic copy-paste.
		expect(screen.getByText('203.0.113.x')).toBeInTheDocument();
		const ipCell = screen.getByText('203.0.113.x');
		expect(ipCell).toHaveAttribute('title', '203.0.113.5');
	});
});

describe('/logs — W.7 follow-up: humanize reason + host resolution', () => {
	it('allow-miss → "country not allowed"', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-uuid-allow', host: 'app.example.test' }
		]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 8,
					ts: isoOffset(0),
					routeId: 'route-uuid-allow',
					srcIp: '203.0.113.6',
					country: 'IN',
					mode: 'allow',
					statusCode: 403,
					reason: 'allow-miss'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText('app.example.test');
		expect(screen.getByText(/IN · country not allowed/)).toBeInTheDocument();
	});

	it('raw reason stays in title tooltip on the detail span', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-uuid-1', host: 'ha.example.test' }
		]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 9,
					ts: isoOffset(0),
					routeId: 'route-uuid-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 403,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		const detail = await screen.findByText(/RU · country denied/);
		// title="" carries the raw mode-reason for
		// forensic ops that grep journalctl by code.
		expect(detail).toHaveAttribute('title', 'deny-match');
	});

	it('falls back to truncated UUID when route was deleted', async () => {
		// listRoutes returns an empty list — the routeId
		// in the event row is "deleted" from the operator's
		// perspective. <RouteHost> should render a
		// truncated UUID + the full UUID as the title.
		clientMock.listRoutes.mockResolvedValue([]);
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 10,
					ts: isoOffset(0),
					routeId: 'gone-uuid-xxxxxxxx-yyyyyy',
					srcIp: '203.0.113.7',
					country: 'BR',
					mode: 'deny',
					statusCode: 403,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		// Truncated UUID renders: first 8 chars + ellipsis.
		const host = await screen.findByTestId('route-host');
		expect(host.textContent?.trim()).toBe('gone-uui…');
		expect(host).toHaveAttribute('title', 'gone-uuid-xxxxxxxx-yyyyyy');
		// Fallback CSS hook present so styling can pick
		// up the muted variant.
		expect(host).toHaveClass('route-host--fallback');
	});

	it('WAF events also render the host badge (shared component)', async () => {
		// The same <RouteHost> resolver runs across per-
		// route log sources. WAF events carry routeId
		// already; W.7 follow-up wires it through the
		// mapWaf path so operators see "ha.example.test"
		// instead of grep'ing the UUID.
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-waf-1', host: 'waf.example.test' }
		]);
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 11,
					ts: isoOffset(0),
					routeId: 'route-waf-1',
					ruleId: '942100',
					category: 'SQLi',
					severity: 4,
					srcIp: '1.2.3.4',
					requestMethod: 'GET',
					requestPath: '/?id=1',
					payloadSample: '',
					action: 'BLOCK',
					statusCode: 403
				}
			]
		});
		render(Page);
		await screen.findByText('waf.example.test');
		// The technical request path is still visible — host
		// badge + path render side-by-side for WAF rows.
		expect(screen.getByText(/\/\?id=1/)).toBeInTheDocument();
	});

	it('routeMap refresh failures do not crash the page', async () => {
		// Routes API hiccup → routeMap stays empty →
		// rows fall back gracefully. Page must render
		// without throwing.
		clientMock.listRoutes.mockRejectedValue(new Error('boom'));
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 12,
					ts: isoOffset(0),
					routeId: 'route-uuid-1',
					srcIp: '203.0.113.5',
					country: 'RU',
					mode: 'deny',
					statusCode: 403,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		// Row still mounts via the fallback path.
		await screen.findByText(/RU · country denied/);
		expect(screen.getByTestId('route-host')).toHaveClass(
			'route-host--fallback'
		);
	});
});

// --- Phase Z.4 polish : SOURCE column badge rendering ----------------------

// The /logs unified stream merges 6 sources, each with a
// distinct semantic. Pre-Z.4 the source was buried in the
// REQUEST column's method-tag prefix (visible: 'RL ' for
// rate-limit, 'GEO ' for country-block, 'ACME' for cert,
// 'OIDC' for OIDC auth, etc. — opaque to a fresh operator).
// Z.4 promotes source to its own column with colored badges.
// These tests pin :
//   - the column exists in the header
//   - each source produces the correct badge label + slug class
//   - the rate-limit row no longer carries the artificial 'RL '
//     method-tag prefix in the REQUEST column (the source
//     badge replaces it cleanly)
describe('/logs — Phase Z.4 SOURCE column rendering', () => {
	// Phase Z.5.4 — the histogram legend below the table
	// renders the same source labels (WAF / RATE-LIMIT /
	// ...) so findByText collides. These tests filter
	// matches to the SOURCE pill in the activity table by
	// requiring the .log-src CSS class hook.
	async function findRowBadge(label: string): Promise<HTMLElement> {
		// Wait for at least one match to appear, then narrow
		// to the .log-src pill.
		await screen.findAllByText(label);
		const matches = screen.getAllByText(label);
		const badge = matches.find((el) => el.classList.contains('log-src'));
		if (!badge) {
			throw new Error(`no .log-src badge with text ${JSON.stringify(label)} found`);
		}
		return badge;
	}

	it('renders a SOURCE column header', async () => {
		render(Page);
		await screen.findByText('Timestamp');
		expect(screen.getByText('Source')).toBeInTheDocument();
	});

	it('rate_limit row renders RATE-LIMIT badge + drops the RL method-tag prefix', async () => {
		securityMock.fetchRateLimitEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'route-rl',
					zone: 'route-route-rl',
					remoteIp: '198.51.100.7',
					waitMs: 1500
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		// Badge label.
		const badge = await findRowBadge('RATE-LIMIT');
		expect(badge).toBeInTheDocument();
		expect(badge).toHaveClass('log-src');
		expect(badge).toHaveClass('rate-limit');
		// REQUEST column no longer carries the artificial 'RL'
		// method-tag — pre-Z.4 a <span class="k">RL</span>
		// rendered alongside the wait detail.
		expect(screen.queryByText(/^RL$/)).not.toBeInTheDocument();
		// Wait detail still surfaced.
		expect(screen.getByText(/wait 1500ms/)).toBeInTheDocument();
	});

	it('waf row renders WAF badge with the waf slug class', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 11,
					ts: isoOffset(0),
					routeId: 'route-waf',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'SQL injection',
					requestMethod: 'POST',
					requestPath: '/login',
					srcIp: '203.0.113.10'
				}
			]
		});
		render(Page);
		const badge = await findRowBadge('WAF');
		expect(badge).toHaveClass('log-src');
		expect(badge).toHaveClass('waf');
	});

	it('throttle row renders THROTTLE badge with the throttle slug class', async () => {
		securityMock.fetchThrottleEvents.mockResolvedValue({
			events: [
				{
					id: 22,
					ts: isoOffset(0),
					tier: 2,
					srcIp: '198.51.100.20',
					attemptedUsername: 'admin',
					blockedUntil: isoOffset(60),
					blockDurationSeconds: 60
				}
			]
		});
		render(Page);
		const badge = await findRowBadge('THROTTLE');
		expect(badge).toHaveClass('log-src');
		expect(badge).toHaveClass('throttle');
	});

	it('country_block row renders COUNTRY badge with the country-block slug class', async () => {
		securityMock.fetchCountryBlockEvents.mockResolvedValue({
			events: [
				{
					id: 33,
					ts: isoOffset(0),
					routeId: 'route-cb',
					srcIp: '203.0.113.30',
					country: 'KP',
					mode: 'deny',
					statusCode: 451,
					reason: 'deny-match'
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		const badge = await findRowBadge('COUNTRY');
		expect(badge).toHaveClass('log-src');
		expect(badge).toHaveClass('country-block');
		// Phase Z.4 cleanup — the level pill renders BLOCK
		// consistently across every block-level source now.
		expect(screen.getByText('BLOCK')).toBeInTheDocument();
	});

	it('cert row renders CERT badge with the cert slug class', async () => {
		securityMock.fetchCertEvents.mockResolvedValue({
			events: [
				{
					timestamp: isoOffset(0),
					level: 'INFO',
					eventType: 'cert_obtained',
					domain: 'example.com',
					issuer: "Let's Encrypt",
					challenge: 'DNS-01',
					renewal: false,
					error: '',
					details: ''
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		const badge = await findRowBadge('CERT');
		expect(badge).toHaveClass('log-src');
		expect(badge).toHaveClass('cert');
	});

	it('auth row renders AUTH badge with the auth slug class', async () => {
		securityMock.fetchAuthFailures.mockResolvedValue({
			window: '24h',
			timeseries: [],
			recent: [
				{
					timestamp: isoOffset(0),
					action: 'login_failure',
					ip: '203.0.113.40',
					username: 'root'
				}
			]
		});
		render(Page);
		const badge = await findRowBadge('AUTH');
		expect(badge).toHaveClass('log-src');
		expect(badge).toHaveClass('auth');
	});
});

// --- Phase Z.5.2 : route + HTTP code filters + educational placeholder ----

describe('/logs — Phase Z.5.2 filters', () => {
	it('renders the educational search placeholder (V2 syntax foreshadowed)', async () => {
		render(Page);
		const input = await screen.findByLabelText('Filter events');
		// Pre-Z.5.2 placeholder was "Filter by path, IP, detail…"
		// Z.5.2 surfaces the literal-substring V1 examples
		// (429 / auth / 185.142.*) and parenthetically hints
		// at the V2 structured syntax.
		expect(input).toHaveAttribute(
			'placeholder',
			expect.stringContaining('429')
		);
		expect(input).toHaveAttribute(
			'placeholder',
			expect.stringContaining('V2')
		);
	});

	it('renders a route dropdown populated from listRoutes()', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-a', host: 'api.example.test' },
			{ id: 'route-b', host: 'admin.example.test' }
		]);
		render(Page);
		const select = await screen.findByLabelText('Filter by route');
		// Both routes present + the "Toutes routes" default.
		expect(select).toHaveTextContent('All routes');
		expect(select).toHaveTextContent('api.example.test');
		expect(select).toHaveTextContent('admin.example.test');
	});

	it('routes dropdown options are sorted by host', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'r-z', host: 'zeta.example.test' },
			{ id: 'r-a', host: 'alpha.example.test' },
			{ id: 'r-m', host: 'mu.example.test' }
		]);
		render(Page);
		const select = (await screen.findByLabelText(
			'Filter by route'
		)) as HTMLSelectElement;
		// The first option after "Toutes routes" should be
		// alpha (lexicographic ascending). One Phase Z.5.2
		// invariant.
		await screen.findByText('alpha.example.test');
		const optionHosts = Array.from(select.options)
			.map((o) => o.textContent ?? '')
			.filter((t) => t !== 'All routes');
		expect(optionHosts).toEqual([
			'alpha.example.test',
			'mu.example.test',
			'zeta.example.test'
		]);
	});

	it('selecting a route filter hides rows from other routes', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-keep', host: 'keep.test' },
			{ id: 'route-drop', host: 'drop.test' }
		]);
		// Seed two WAF events on different routes.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'route-keep',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'kept',
					requestMethod: 'POST',
					requestPath: '/keep',
					srcIp: '1.1.1.1'
				},
				{
					id: 2,
					ts: isoOffset(-60),
					routeId: 'route-drop',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'dropped',
					requestMethod: 'POST',
					requestPath: '/drop',
					srcIp: '2.2.2.2'
				}
			]
		});
		render(Page);
		// Both rows visible before filter.
		await screen.findByText('/keep');
		expect(screen.getByText('/drop')).toBeInTheDocument();
		// Select route-keep ; only the keep row remains.
		const user = userEvent.setup();
		await user.selectOptions(
			screen.getByLabelText('Filter by route'),
			'route-keep'
		);
		expect(screen.getByText('/keep')).toBeInTheDocument();
		expect(screen.queryByText('/drop')).not.toBeInTheDocument();
	});

	it('renders an HTTP code dropdown with operator-triage order (5xx first)', async () => {
		render(Page);
		const select = (await screen.findByLabelText(
			'Filter by HTTP code'
		)) as HTMLSelectElement;
		const values = Array.from(select.options).map((o) => o.value);
		// First option is the default ("").
		expect(values[0]).toBe('');
		// Then 5xx codes (500/502/503/504) come before 4xx.
		const fiveHundredIdx = values.indexOf('500');
		const fourXxIdx = values.indexOf('403');
		expect(fiveHundredIdx).toBeLessThan(fourXxIdx);
		// Then 4xx-attack codes (403/429/451) come before 2xx.
		const twoHundredIdx = values.indexOf('200');
		expect(fourXxIdx).toBeLessThan(twoHundredIdx);
	});

	it('selecting code=429 keeps only rate-limit rows', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 11,
					ts: isoOffset(0),
					routeId: 'r',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'waf hit',
					requestMethod: 'POST',
					requestPath: '/waf-path',
					srcIp: '1.1.1.1'
				}
			]
		});
		securityMock.fetchRateLimitEvents.mockResolvedValue({
			events: [
				{
					id: 22,
					ts: isoOffset(-30),
					routeId: 'r',
					zone: 'route-r',
					remoteIp: '2.2.2.2',
					waitMs: 1500
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		// Both rows visible before filter.
		await screen.findByText('/waf-path');
		expect(screen.getByText(/wait 1500ms/)).toBeInTheDocument();
		// Select code 429 ; WAF row disappears.
		const user = userEvent.setup();
		await user.selectOptions(
			screen.getByLabelText('Filter by HTTP code'),
			'429'
		);
		expect(screen.queryByText('/waf-path')).not.toBeInTheDocument();
		expect(screen.getByText(/wait 1500ms/)).toBeInTheDocument();
	});

	it('search input now indexes source + method + code (Z.5.2 wider hay)', async () => {
		// Pre-Z.5.2 typing "RATE-LIMIT" or "429" in the
		// search did not match because the haystack only
		// covered path/IP/detail. Z.5.2 extends hay to
		// source/method/code so literal-substring lookups
		// work as the educational placeholder advertises.
		securityMock.fetchRateLimitEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r',
					zone: 'route-r',
					remoteIp: '198.51.100.7',
					waitMs: 1500
				}
			],
			total: 1,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/wait 1500ms/);
		const user = userEvent.setup();
		// Type 429 → row remains (matches the code field).
		await user.type(screen.getByLabelText('Filter events'), '429');
		expect(screen.getByText(/wait 1500ms/)).toBeInTheDocument();
	});

	it('route filter + code filter combine (AND semantics)', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'r-a', host: 'a.test' },
			{ id: 'r-b', host: 'b.test' }
		]);
		securityMock.fetchRateLimitEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r-a',
					zone: 'route-r-a',
					remoteIp: '1.1.1.1',
					waitMs: 100
				},
				{
					id: 2,
					ts: isoOffset(-30),
					routeId: 'r-b',
					zone: 'route-r-b',
					remoteIp: '2.2.2.2',
					waitMs: 200
				}
			],
			total: 2,
			hasMore: false
		});
		render(Page);
		await screen.findByText(/wait 100ms/);
		expect(screen.getByText(/wait 200ms/)).toBeInTheDocument();
		const user = userEvent.setup();
		// Filter to route r-a + code 429 → only the r-a row.
		await user.selectOptions(screen.getByLabelText('Filter by route'), 'r-a');
		await user.selectOptions(
			screen.getByLabelText('Filter by HTTP code'),
			'429'
		);
		expect(screen.getByText(/wait 100ms/)).toBeInTheDocument();
		expect(screen.queryByText(/wait 200ms/)).not.toBeInTheDocument();
	});
});

// --- Filters in the URL ------------------------------------------------------

describe('/logs — filters live in the URL', () => {
	const wafEvent = (overrides: Partial<WafEvent>): WafEvent =>
		({
			id: 1,
			ts: isoOffset(0),
			routeId: 'route-keep',
			action: 'BLOCK',
			statusCode: 403,
			ruleId: '942100',
			category: 'SQLi',
			message: 'm',
			requestMethod: 'GET',
			requestPath: '/keep',
			srcIp: '1.1.1.1',
			...overrides
		}) as WafEvent;

	it('applies ?route= on arrival, before the dropdown has its options', async () => {
		clientMock.listRoutes.mockResolvedValue([
			{ id: 'route-keep', host: 'keep.test' },
			{ id: 'route-drop', host: 'drop.test' }
		]);
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				wafEvent({ id: 1, routeId: 'route-keep', requestPath: '/keep' }),
				wafEvent({ id: 2, ts: isoOffset(-60), routeId: 'route-drop', requestPath: '/drop' })
			]
		});
		window.history.replaceState(null, '', '/logs?route=route-keep');
		render(Page);
		await screen.findByText('/keep');
		expect(screen.queryByText('/drop')).not.toBeInTheDocument();
		// Once the routes arrive, the dropdown shows the same filter.
		await waitFor(() =>
			expect(screen.getByLabelText('Filter by route')).toHaveValue('route-keep')
		);
	});

	it('applies ?q=, ?code= and ?level= on arrival', async () => {
		window.history.replaceState(null, '', '/logs?q=942100&code=403&level=block');
		render(Page);
		expect(await screen.findByLabelText('Filter events')).toHaveValue('942100');
		expect(screen.getByLabelText('Filter by HTTP code')).toHaveValue('403');
		expect(screen.getByRole('button', { name: 'Block' })).toHaveClass('on');
		expect(screen.getByRole('button', { name: 'All' })).not.toHaveClass('on');
	});

	it('falls back to the defaults for values it does not know', async () => {
		window.history.replaceState(null, '', '/logs?code=999&level=bogus');
		render(Page);
		expect(await screen.findByLabelText('Filter by HTTP code')).toHaveValue('');
		expect(screen.getByRole('button', { name: 'All' })).toHaveClass('on');
	});

	it('matches ?q=<ruleId> on a guided rule, whose row shows its name', async () => {
		// /waf links here with the rule id; a guided rule's detail
		// carries its name instead, so the id has to be searched too.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				wafEvent({ id: 1, ruleId: '9100042', ruleName: 'admin-only', requestPath: '/guided' }),
				wafEvent({ id: 2, ts: isoOffset(-60), requestPath: '/crs' })
			]
		});
		window.history.replaceState(null, '', '/logs?q=9100042');
		render(Page);
		await screen.findByText('/guided');
		expect(screen.queryByText('/crs')).not.toBeInTheDocument();
	});

	it('writes a changed filter to the URL, without adding history', async () => {
		clientMock.listRoutes.mockResolvedValue([{ id: 'route-keep', host: 'keep.test' }]);
		window.history.replaceState(null, '', '/logs');
		const historyLength = window.history.length;
		render(Page);
		await screen.findByText('keep.test');
		const user = userEvent.setup();

		await user.selectOptions(screen.getByLabelText('Filter by route'), 'route-keep');
		await user.selectOptions(screen.getByLabelText('Filter by HTTP code'), '429');
		await user.click(screen.getByRole('button', { name: 'Warn' }));
		await user.type(screen.getByLabelText('Filter events'), 'login');
		await waitFor(() => {
			const params = new URLSearchParams(window.location.search);
			expect(params.get('route')).toBe('route-keep');
			expect(params.get('code')).toBe('429');
			expect(params.get('level')).toBe('warn');
			expect(params.get('q')).toBe('login');
		});
		expect(window.location.pathname).toBe('/logs');
		expect(window.history.length).toBe(historyLength);

		// Back at a default, the param leaves the URL.
		await user.selectOptions(screen.getByLabelText('Filter by route'), '');
		await user.click(screen.getByRole('button', { name: 'All' }));
		await waitFor(() => {
			const params = new URLSearchParams(window.location.search);
			expect(params.has('route')).toBe(false);
			expect(params.has('level')).toBe(false);
			expect(params.get('code')).toBe('429');
		});
	});
});

// --- Phase Z.5.3 : SOURCE IP enrichment with country code -----------------

describe('/logs — Phase Z.5.3 SOURCE IP country enrichment', () => {
	it('octet-masks the IP and shows raw IP in the title tooltip', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 1,
					ts: isoOffset(0),
					routeId: 'r',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'm',
					requestMethod: 'POST',
					requestPath: '/p',
					srcIp: '82.65.1.2'
				}
			]
		});
		render(Page);
		const cell = await screen.findByText('82.65.1.x');
		expect(cell).toHaveAttribute('title', '82.65.1.2');
	});

	it('appends " · <country>" once geoLookupBatch resolves', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 2,
					ts: isoOffset(0),
					routeId: 'r',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'm',
					requestMethod: 'POST',
					requestPath: '/p',
					srcIp: '203.0.113.7'
				}
			]
		});
		securityMock.geoLookupBatch.mockResolvedValue({
			results: { '203.0.113.7': 'US' }
		});
		render(Page);
		await screen.findByText(/203\.0\.113\.x · US/);
	});

	it('renders "· LAN" for RFC1918 sentinel', async () => {
		securityMock.fetchRateLimitEvents.mockResolvedValue({
			events: [
				{
					id: 3,
					ts: isoOffset(0),
					routeId: 'r',
					zone: 'route-r',
					remoteIp: '192.168.1.5',
					waitMs: 100
				}
			],
			total: 1,
			hasMore: false
		});
		securityMock.geoLookupBatch.mockResolvedValue({
			results: { '192.168.1.5': 'LAN' }
		});
		render(Page);
		await screen.findByText(/192\.168\.1\.x · LAN/);
	});

	it('renders "· ?" when the backend answered with empty country (MMDB miss)', async () => {
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 4,
					ts: isoOffset(0),
					routeId: 'r',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'm',
					requestMethod: 'POST',
					requestPath: '/p',
					srcIp: '203.0.113.99'
				}
			]
		});
		securityMock.geoLookupBatch.mockResolvedValue({
			results: { '203.0.113.99': '' }
		});
		render(Page);
		await screen.findByText(/203\.0\.113\.x · \?/);
	});

	it('renders the masked IP alone when lookup throws (silent degraded)', async () => {
		// Backend wired but the call fails — operator should
		// still see the activity log, just without the country
		// suffix. No toast, no error state.
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				{
					id: 5,
					ts: isoOffset(0),
					routeId: 'r',
					action: 'BLOCK',
					statusCode: 403,
					ruleId: '942100',
					category: 'SQLi',
					message: 'm',
					requestMethod: 'POST',
					requestPath: '/p',
					srcIp: '198.51.100.10'
				}
			]
		});
		securityMock.geoLookupBatch.mockRejectedValue(new Error('boom'));
		render(Page);
		await screen.findByText('198.51.100.x');
		// No "· ?" suffix because countryMap never received a
		// resolution — the row renders raw masked.
		expect(screen.queryByText(/198\.51\.100\.x · \?/)).not.toBeInTheDocument();
		// And no toast (silent degraded).
		expect(toastMock.pushToast).not.toHaveBeenCalled();
	});
});

// allSettled kept one failing source from taking the page down, but
// nothing said a source had failed: its rows were simply missing,
// and with every source down the page read "No event in this
// window" — an outage that looked like a quiet system.
describe('/logs — a source that does not answer is named', () => {
	const rejectAll = () => {
		for (const fn of [
			securityMock.fetchEvents,
			securityMock.fetchThrottleEvents,
			securityMock.fetchAuthFailures,
			securityMock.fetchCertEvents,
			securityMock.fetchCountryBlockEvents,
			securityMock.fetchRateLimitEvents
		]) {
			fn.mockRejectedValue(new Error('503'));
		}
	};

	it('lists the failed sources and keeps the pill live', async () => {
		securityMock.fetchCertEvents.mockRejectedValue(new Error('503'));
		securityMock.fetchRateLimitEvents.mockRejectedValue(new Error('503'));
		render(Page);

		const banner = await screen.findByTestId('logs-sources-failed');
		expect(banner).toHaveTextContent('2 of 6 sources did not answer: CERT, RATE-LIMIT');
		expect(screen.getByTestId('logs-status')).toHaveTextContent('live');
	});

	it('does not call an outage "no event" when every source fails', async () => {
		rejectAll();
		render(Page);

		expect(await screen.findByTestId('logs-unavailable')).toBeInTheDocument();
		expect(screen.queryByTestId('logs-empty')).toBeNull();
		expect(screen.getByTestId('logs-status')).toHaveTextContent('stale');
		expect(screen.getByTestId('logs-sources-failed')).toHaveTextContent('No source answered');
	});

	it('retries from the unavailable state', async () => {
		rejectAll();
		render(Page);
		await screen.findByTestId('logs-unavailable');

		securityMock.fetchEvents.mockResolvedValue({ events: [] });
		await userEvent.click(screen.getByText('Retry'));

		expect(await screen.findByTestId('logs-empty')).toBeInTheDocument();
		// One source answered: no longer stale, the five others named.
		expect(screen.getByTestId('logs-status')).toHaveTextContent('live');
		expect(screen.getByTestId('logs-sources-failed')).toHaveTextContent('5 of 6');
	});
});

