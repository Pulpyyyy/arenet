// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock $lib/stores/auth so the interceptor tests can spy on
// clear() and setLocked() without exercising the real store.
const authMock = {
	user: null,
	state: 'authenticated' as 'authenticated' | 'anonymous' | 'locked' | 'unknown' | 'error',
	clear: vi.fn(),
	setLocked: vi.fn()
};
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authMock }));

// Mock $lib/stores/idle to spy on idle.reset() invocations.
const idleMock = { reset: vi.fn(), userActiveSinceReset: true };
vi.mock('$lib/stores/idle.svelte', () => ({ idle: idleMock }));

// Mock $lib/stores/toast (pushToast) for 429 toast tests.
const toastMock = { pushToast: vi.fn() };
vi.mock('$lib/stores/toast', () => ({
	pushToast: toastMock.pushToast
}));

// Mock $lib/stores/loading for beginRequest/endRequest no-op.
vi.mock('$lib/stores/loading', () => ({
	beginRequest: vi.fn(),
	endRequest: vi.fn()
}));

const { request, disableRoute, enableRoute, enterMaintenance, exitMaintenance } =
	await import('./client');
const { ApiError } = await import('./types');
type ApiErrorType = InstanceType<typeof ApiError>;
const { goto } = await import('$app/navigation');

// Helper: install a mock fetch returning the given response.
function mockFetch(status: number, body: unknown | undefined, headers: Record<string, string> = {}): void {
	(globalThis as { fetch?: unknown }).fetch = vi.fn(async () => {
		return new Response(body === undefined ? null : JSON.stringify(body), {
			status,
			headers: { 'Content-Type': 'application/json', ...headers }
		});
	});
}

beforeEach(() => {
	authMock.state = 'authenticated';
	authMock.clear.mockReset();
	authMock.setLocked.mockReset();
	idleMock.reset.mockReset();
	idleMock.userActiveSinceReset = true;
	toastMock.pushToast.mockReset();
	(goto as ReturnType<typeof vi.fn>).mockReset();
	// Default to a path that is not /login or /setup so 401 triggers goto.
	Object.defineProperty(window, 'location', {
		value: { pathname: '/routes' },
		writable: true
	});
});

describe('request: credentials always included', () => {
	it('sets credentials: include in the fetch init', async () => {
		const fetchSpy = vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify({}), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		);
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		await request('GET', '/routes');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		const init = fetchSpy.mock.calls[0][1];
		expect(init?.credentials).toBe('include');
	});
});

describe('request: 401 interceptor', () => {
	it('clears auth and navigates to /login, carrying the page as ?next=', async () => {
		mockFetch(401, { error: 'no active session' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 401, kind: 'auth' });
		expect(authMock.clear).toHaveBeenCalledTimes(1);
		expect(goto).toHaveBeenCalledWith('/login?next=%2Froutes');
	});

	it('keeps the query string of the page in ?next=', async () => {
		Object.defineProperty(window, 'location', {
			value: { pathname: '/certs', search: '?tab=acme' },
			writable: true
		});
		mockFetch(401, { error: 'no active session' });
		await expect(request('GET', '/certs')).rejects.toMatchObject({ status: 401 });
		expect(goto).toHaveBeenCalledWith('/login?next=%2Fcerts%3Ftab%3Dacme');
	});

	it.each(['unknown', 'error'] as const)(
		'does NOT goto during the bootstrap (state %s): the layout owns that redirect',
		async (state) => {
			authMock.state = state;
			mockFetch(401, { error: 'no active session' });
			await expect(request('GET', '/auth/me')).rejects.toMatchObject({ status: 401 });
			expect(authMock.clear).toHaveBeenCalledTimes(1);
			expect(goto).not.toHaveBeenCalled();
		}
	);

	it('does NOT goto when already on /login (no redirect loop)', async () => {
		Object.defineProperty(window, 'location', {
			value: { pathname: '/login' },
			writable: true
		});
		mockFetch(401, { error: 'no active session' });
		await expect(request('POST', '/auth/login', { username: 'a', password: 'b' })).rejects.toMatchObject({
			status: 401
		});
		expect(goto).not.toHaveBeenCalled();
	});

	it('does NOT goto when already on /setup', async () => {
		Object.defineProperty(window, 'location', {
			value: { pathname: '/setup' },
			writable: true
		});
		mockFetch(401, { error: 'no active session' });
		await expect(request('POST', '/auth/setup', {})).rejects.toMatchObject({ status: 401 });
		expect(goto).not.toHaveBeenCalled();
	});
});

describe('request: 403 interceptor', () => {
	it('calls auth.setLocked when body is "session locked"', async () => {
		mockFetch(403, { error: 'session locked' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({
			status: 403,
			kind: 'forbidden',
			message: 'session locked'
		});
		expect(authMock.setLocked).toHaveBeenCalledTimes(1);
	});

	it('does NOT call setLocked for other 403 messages (forward-compat with Phase 2 role-based 403)', async () => {
		mockFetch(403, { error: 'forbidden by role' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 403, kind: 'forbidden' });
		expect(authMock.setLocked).not.toHaveBeenCalled();
	});
});

describe('request: 429 interceptor', () => {
	it('pushes a toast and surfaces retryAfterSeconds from Retry-After header', async () => {
		mockFetch(
			429,
			{ error: 'too many attempts, retry after 15 minutes' },
			{ 'Retry-After': '900' }
		);
		let err: ApiErrorType | undefined;
		try {
			await request('POST', '/auth/login', { username: 'a', password: 'b' });
		} catch (e) {
			err = e as ApiErrorType;
		}
		expect(err).toBeInstanceOf(ApiError);
		expect(err?.status).toBe(429);
		expect(err?.kind).toBe('rate_limited');
		expect(err?.retryAfterSeconds).toBe(900);
		expect(toastMock.pushToast).toHaveBeenCalledTimes(1);
	});

	it('tolerates missing Retry-After header (retryAfterSeconds=0)', async () => {
		mockFetch(429, { error: 'too many attempts' });
		let err: ApiErrorType | undefined;
		try {
			await request('POST', '/auth/login', {});
		} catch (e) {
			err = e as ApiErrorType;
		}
		expect(err?.status).toBe(429);
		expect(err?.retryAfterSeconds).toBe(0);
	});
});

describe('request: background requests (v2.32)', () => {
	function spyFetch() {
		const spy = vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify({}), { status: 200, headers: { 'Content-Type': 'application/json' } })
		);
		(globalThis as { fetch?: unknown }).fetch = spy;
		return spy;
	}
	const sentHeaders = (spy: ReturnType<typeof spyFetch>) =>
		(spy.mock.calls[0][1]?.headers ?? {}) as Record<string, string>;

	it('marks a request made without user interaction and does not reset the idle timer', async () => {
		idleMock.userActiveSinceReset = false;
		const spy = spyFetch();
		await request('GET', '/system/version');
		expect(sentHeaders(spy)['X-Arenet-Background']).toBe('1');
		expect(idleMock.reset).not.toHaveBeenCalled();
	});

	it('keeps the JSON content type when a background request has a body', async () => {
		idleMock.userActiveSinceReset = false;
		const spy = spyFetch();
		await request('POST', '/auth/heartbeat', {});
		expect(sentHeaders(spy)).toMatchObject({ 'Content-Type': 'application/json', 'X-Arenet-Background': '1' });
	});

	it('sends a user-triggered request as activity', async () => {
		idleMock.userActiveSinceReset = true;
		const spy = spyFetch();
		await request('GET', '/routes');
		expect(sentHeaders(spy)['X-Arenet-Background']).toBeUndefined();
		expect(idleMock.reset).toHaveBeenCalledTimes(1);
	});
});

describe('request: idle timer reset gate', () => {
	it('calls idle.reset on 200 success', async () => {
		mockFetch(200, { ok: true });
		await request('GET', '/routes');
		expect(idleMock.reset).toHaveBeenCalledTimes(1);
	});

	it('calls idle.reset on 4xx (excluding the auth-related interceptor branches)', async () => {
		// 400 — validation. Must still count as server interaction.
		mockFetch(400, { error: 'validation' });
		await expect(request('POST', '/routes', {})).rejects.toMatchObject({ status: 400 });
		expect(idleMock.reset).toHaveBeenCalledTimes(1);
	});

	it('does NOT call idle.reset on 5xx', async () => {
		mockFetch(500, { error: 'server error' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 500 });
		expect(idleMock.reset).not.toHaveBeenCalled();
	});

	it('does NOT call idle.reset on network failure (status 0)', async () => {
		(globalThis as { fetch?: unknown }).fetch = vi.fn(async () => {
			throw new Error('boom');
		});
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 0 });
		expect(idleMock.reset).not.toHaveBeenCalled();
	});

	it('does NOT call idle.reset on 401 (interceptor returns early)', async () => {
		mockFetch(401, { error: 'no active session' });
		await expect(request('GET', '/routes')).rejects.toMatchObject({ status: 401 });
		expect(idleMock.reset).not.toHaveBeenCalled();
	});
});

describe('request: 204 No Content', () => {
	it('returns undefined for 204 responses', async () => {
		mockFetch(204, undefined);
		const out = await request<void>('POST', '/auth/logout');
		expect(out).toBeUndefined();
	});
});

// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT regression pins. The
// request() helper now wraps every fetch in an AbortController
// with a 30 s ceiling. These tests verify (a) that ceiling fires
// when fetch stalls indefinitely, (b) the signature stays
// backward-compatible for already-aborted-style native errors,
// and (c) the AbortController properly cancels the underlying
// fetch on timeout (signal.aborted state).

describe('request: timeout aborts a stalled fetch', () => {
	it('throws ApiError(kind=system) when fetch never resolves within the ceiling', async () => {
		vi.useFakeTimers();
		// Stalled fetch: returns a promise that rejects with
		// AbortError only when the controller's signal aborts.
		// This is what native fetch does when the AbortController
		// it was given fires.
		(globalThis as { fetch?: unknown }).fetch = vi.fn(
			(_input: RequestInfo | URL, init?: RequestInit) =>
				new Promise((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => {
						const err = new DOMException('Aborted', 'AbortError');
						reject(err);
					});
				})
		);

		const pending = request<void>('PUT', '/routes/some-id', { foo: 1 }).catch(
			(e: unknown) => e
		);
		// Advance the fake timer past REQUEST_TIMEOUT_MS (30 s).
		await vi.advanceTimersByTimeAsync(30_001);
		const err = (await pending) as ApiErrorType;
		expect(err).toBeInstanceOf(ApiError);
		expect(err.status).toBe(0);
		expect(err.kind).toBe('system');
		expect(err.message).toMatch(/timed out/);

		vi.useRealTimers();
	});
});

describe('request: passes a non-aborted AbortSignal on the happy path', () => {
	it('signal.aborted stays false when the fetch resolves before the ceiling', async () => {
		const fetchSpy = vi.fn(
			async (_input: RequestInfo | URL, init?: RequestInit) => {
				expect(init?.signal).toBeDefined();
				expect((init?.signal as AbortSignal).aborted).toBe(false);
				return new Response(JSON.stringify({}), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				});
			}
		);
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		await request('GET', '/routes');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});
});

describe('request: signature stays backward-compatible', () => {
	it('keeps the (method, path, body?) shape — body=undefined skips Content-Type', async () => {
		const fetchSpy = vi.fn(
			async (_input: RequestInfo | URL, _init?: RequestInit) =>
				new Response(JSON.stringify({}), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		);
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		await request('GET', '/routes');
		const init = fetchSpy.mock.calls[0][1];
		// Body-less call: no Content-Type header, no body.
		expect(init?.headers).toBeUndefined();
		expect(init?.body).toBeUndefined();
		// AbortController machinery is invisible to the caller —
		// no change to the public shape.
		expect((init?.signal as AbortSignal).aborted).toBe(false);
	});
});

// v2.14.3 — route disable/enable client wrappers.
describe('disableRoute / enableRoute', () => {
	it('disableRoute POSTs to /routes/{id}/disable and returns the route + lastHttpsRouteAffected', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toContain('/routes/abc/disable');
			expect(init?.method).toBe('POST');
			return new Response(JSON.stringify({ id: 'abc', disabled: true, lastHttpsRouteAffected: true }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			});
		});
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		const result = await disableRoute('abc');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(result).toEqual({ id: 'abc', disabled: true, lastHttpsRouteAffected: true });
	});

	it('enableRoute POSTs to /routes/{id}/enable and returns the route + lastHttpsRouteAffected', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toContain('/routes/abc/enable');
			expect(init?.method).toBe('POST');
			return new Response(JSON.stringify({ id: 'abc', disabled: false, lastHttpsRouteAffected: false }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			});
		});
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		const result = await enableRoute('abc');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(result).toEqual({ id: 'abc', disabled: false, lastHttpsRouteAffected: false });
	});
});

// Task 8 — route maintenance client wrappers. Mirrors disableRoute/
// enableRoute exactly (same fetch/error style, same POST-and-return-
// route shape).
describe('enterMaintenance / exitMaintenance', () => {
	it('enterMaintenance POSTs to /routes/{id}/maintenance and returns the route', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toContain('/routes/abc/maintenance');
			expect(init?.method).toBe('POST');
			return new Response(JSON.stringify({ id: 'abc', maintenance: true }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			});
		});
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		const result = await enterMaintenance('abc');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(result).toEqual({ id: 'abc', maintenance: true });
	});

	it('exitMaintenance POSTs to /routes/{id}/maintenance/off and returns the route', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toContain('/routes/abc/maintenance/off');
			expect(init?.method).toBe('POST');
			return new Response(JSON.stringify({ id: 'abc', maintenance: false }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			});
		});
		(globalThis as { fetch?: unknown }).fetch = fetchSpy;
		const result = await exitMaintenance('abc');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect(result).toEqual({ id: 'abc', maintenance: false });
	});
});

// -----------------------------------------------------------------
// v2.61.2 — a locked session refuses background traffic, so asking is
// pointless.
//
// v2.32 taught the server to enforce the idle lock on background
// requests without refreshing the session. The consequence was never
// handled on this side: while locked, every poller kept firing and each
// tick wrote a 403 to the access log. The operator's instance produced
// 233 in one day — 117 on /system/version and 116 on
// /observability/alert-events, the notification bell's two calls at 60s
// over roughly two hours of being locked. The notifications store
// swallows the error by design, so nothing ever stopped.
//
// Not cosmetic: CrowdSec parses that access log, and
// http-admin-interface-probing bans an IP for a handful of 403s on
// admin paths. /api/v1/... is not in that scenario's path list today —
// luck, not safety.
// -----------------------------------------------------------------
describe('request: no background traffic while the session is locked', () => {
	function spyFetch() {
		const spy = vi.fn(
			async () =>
				new Response(JSON.stringify({}), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		);
		(globalThis as { fetch?: unknown }).fetch = spy;
		return spy;
	}

	it('does not even reach the network', async () => {
		authMock.state = 'locked';
		idleMock.userActiveSinceReset = false;
		const spy = spyFetch();

		await expect(request('GET', '/system/version')).rejects.toThrow(ApiError);
		expect(spy).not.toHaveBeenCalled();
	});

	it('still lets a USER-triggered request through while locked', async () => {
		// The unlock is user-initiated, so it never carries the
		// background header. Short-circuiting it would lock the
		// operator out of their own instance — the one failure mode
		// this change must not have.
		authMock.state = 'locked';
		idleMock.userActiveSinceReset = true;
		const spy = spyFetch();

		await request('POST', '/auth/unlock', { passphrase: 'x' });
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it('lets background requests through once the session is authenticated again', async () => {
		authMock.state = 'authenticated';
		idleMock.userActiveSinceReset = false;
		const spy = spyFetch();

		await request('GET', '/system/version');
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it('reports it as a 403 so existing callers behave unchanged', async () => {
		// The pollers already swallow a 403 from this path; the
		// short-circuit must look the same to them, or a store that
		// special-cases status 403 would start showing an error banner
		// where it used to stay quiet.
		authMock.state = 'locked';
		idleMock.userActiveSinceReset = false;
		spyFetch();

		await expect(request('GET', '/observability/alert-events')).rejects.toMatchObject({
			status: 403,
			kind: 'forbidden'
		});
	});
});
