// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Tests for the security/observability API client wrappers.
// First test file for security.ts — created in Step U.4 to
// cover fetchCertEvents. The existing fetch* methods
// (fetchEvents, fetchThrottleEvents, etc.) are covered
// indirectly via the page-level Logs tests; this file
// establishes the per-method unit-test convention for the
// future.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { CertEventsResponse } from './types';

const requestMock = vi.fn();
vi.mock('./client', () => ({ request: requestMock }));

const { fetchCertEvents, deleteCrowdSecDecision } = await import('./security');

beforeEach(() => {
	requestMock.mockReset();
	requestMock.mockResolvedValue({
		events: [],
		total: 0,
		hasMore: false
	} satisfies CertEventsResponse);
});

describe('fetchCertEvents: URL parameter encoding', () => {
	it('hits /observability/cert-events without query string when params are empty', async () => {
		await fetchCertEvents();
		expect(requestMock).toHaveBeenCalledWith('GET', '/observability/cert-events');
	});

	it('hits the /observability/ path (NOT /security/)', async () => {
		// Path-rename regression check: cert events live under
		// /observability/ per Step U.3's convention call (the
		// page rename to "Activity log" widens scope beyond
		// security). A future refactor that moves them back to
		// /security/cert-events would break the U.3 backend
		// route registration AND any downstream consumer.
		await fetchCertEvents({ limit: 10 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('/observability/cert-events');
		expect(path).not.toContain('/security/cert-events');
	});

	it('serializes numeric limit as a string', async () => {
		await fetchCertEvents({ limit: 250 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=250');
	});

	it('forwards since/until RFC 3339 strings as-is', async () => {
		await fetchCertEvents({
			since: '2026-06-01T00:00:00Z',
			until: '2026-06-06T12:00:00Z'
		});
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('since=2026-06-01T00%3A00%3A00Z');
		expect(path).toContain('until=2026-06-06T12%3A00%3A00Z');
	});

	it('joins multi-value level filter with comma', async () => {
		await fetchCertEvents({ level: ['INFO', 'ERROR'] });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('level=INFO%2CERROR');
	});

	it('emits single-value level filter without trailing comma', async () => {
		await fetchCertEvents({ level: ['ERROR'] });
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('level=ERROR');
		expect(path).not.toContain('level=ERROR%2C');
	});

	it('omits empty level array (no filter)', async () => {
		await fetchCertEvents({ level: [] });
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('level=');
	});

	it('URL-encodes search containing spaces and special chars', async () => {
		await fetchCertEvents({ search: "let's encrypt" });
		const [, path] = requestMock.mock.calls[0];
		// URLSearchParams encodes ' as %27, space as +.
		expect(path).toContain('search=let');
		expect(path).toMatch(/search=let.+encrypt/);
	});

	it('omits empty search (no filter)', async () => {
		await fetchCertEvents({ search: '' });
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('search=');
	});

	it('omits undefined limit (allows server default of 100)', async () => {
		await fetchCertEvents({});
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('limit=');
	});

	it('omits undefined since/until', async () => {
		await fetchCertEvents({ limit: 10 });
		const [, path] = requestMock.mock.calls[0];
		expect(path).not.toContain('since=');
		expect(path).not.toContain('until=');
	});

	it('combines multiple filters into one query string', async () => {
		await fetchCertEvents({
			limit: 50,
			level: ['ERROR'],
			search: 'failed'
		});
		const [, path] = requestMock.mock.calls[0];
		expect(path).toContain('limit=50');
		expect(path).toContain('level=ERROR');
		expect(path).toContain('search=failed');
	});
});

describe('fetchCertEvents: response shape', () => {
	it('returns the typed CertEventsResponse from the request helper', async () => {
		requestMock.mockResolvedValue({
			events: [
				{
					timestamp: '2026-06-06T12:00:00.000Z',
					level: 'INFO',
					eventType: 'cert_obtained',
					domain: '*.example.com',
					issuer: "Let's Encrypt",
					challenge: 'DNS-01',
					renewal: true,
					error: '',
					details: ''
				}
			],
			total: 1,
			hasMore: false
		} satisfies CertEventsResponse);

		const result = await fetchCertEvents();
		expect(result.events).toHaveLength(1);
		expect(result.events[0].domain).toBe('*.example.com');
		expect(result.events[0].level).toBe('INFO');
		expect(result.events[0].eventType).toBe('cert_obtained');
		expect(result.events[0].renewal).toBe(true);
		expect(result.total).toBe(1);
		expect(result.hasMore).toBe(false);
		expect(result.degraded).toBeUndefined();
	});

	it('passes degraded=true through verbatim (AC #13 degraded mode)', async () => {
		requestMock.mockResolvedValue({
			events: [],
			total: 0,
			hasMore: false,
			degraded: true
		} satisfies CertEventsResponse);

		const result = await fetchCertEvents();
		expect(result.degraded).toBe(true);
		expect(result.events).toHaveLength(0);
		expect(result.total).toBe(0);
	});

	it('passes hasMore=true through verbatim', async () => {
		requestMock.mockResolvedValue({
			events: new Array(100).fill({
				timestamp: '2026-06-06T12:00:00.000Z',
				level: 'INFO',
				eventType: 'cert_obtained',
				domain: 'x',
				issuer: '',
				challenge: '',
				renewal: false,
				error: '',
				details: ''
			}),
			total: 250,
			hasMore: true
		} satisfies CertEventsResponse);

		const result = await fetchCertEvents();
		expect(result.hasMore).toBe(true);
		expect(result.total).toBe(250);
		expect(result.events).toHaveLength(100);
	});
});

describe('fetchCertEvents: error propagation', () => {
	it('rejects with the underlying ApiError when request throws', async () => {
		// The request() helper handles 401/403/429 with its own
		// interceptor logic and throws ApiError for the rest;
		// fetchCertEvents just returns the promise. This test
		// pins that the wrapper does NOT swallow errors — the
		// Activity log page is responsible for the empty-state
		// fallback, not the API client.
		const boom = new Error('simulated 503 service unavailable');
		requestMock.mockRejectedValueOnce(boom);

		await expect(fetchCertEvents()).rejects.toThrow('simulated 503');
	});
});

describe('deleteCrowdSecDecision', () => {
	it('sends DELETE to the decision id, with no body', async () => {
		requestMock.mockResolvedValueOnce({ id: 42, nbDeleted: 1 });
		await expect(deleteCrowdSecDecision(42)).resolves.toEqual({ id: 42, nbDeleted: 1 });
		expect(requestMock).toHaveBeenCalledWith('DELETE', '/security/crowdsec/decisions/42');
	});
});
