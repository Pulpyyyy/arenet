// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// HTTP client for /api/v1/*. Step C handled routes; Step D extends it
// with auth-aware interceptors (spec §6.4):
//   1. credentials: 'include' on every request (sends the
//      arenet_session cookie even cross-origin in dev).
//   2. 401 → auth.clear() + redirect to /login (unless already there).
//   3. 403 with body "session locked" → auth.setLocked().
//   4. 429 → toast notification with Retry-After.
//   5. Successful responses (status < 500) reset the idle timer —
//      only for requests made after a user interaction (v2.32).
//      Others (polling, heartbeat, auto-refresh) carry the
//      X-Arenet-Background header: the server still enforces the
//      lock but does not refresh the session's LastActivity.
//
// The signature request(method, path, body?) is unchanged from Step C
// so existing call sites in lib/api/client.ts and beyond keep working.

import type {
	Route,
	AddWafExclusionRequest,
	CaddyfileImportResult,
	CaddyfilePreview,
	SecLangValidateResponse,
	WafCustomRule,
	WafTestRequest,
	WafTestResponse,
	RouteRequest,
	TestHealthCheckRequest,
	TestHealthCheckResponse,
	TestUpstreamRequest,
	TestUpstreamResponse
} from './types';
import { ApiError } from './types';
import { beginRequest, endRequest } from '$lib/stores/loading';
import { auth } from '$lib/stores/auth.svelte';
import { idle } from '$lib/stores/idle.svelte';
import { pushToast } from '$lib/stores/toast';
import { goto } from '$app/navigation';
import { isEntryPath, withNext } from '$lib/utils/safe-next';

// In production (the binary serves both API and frontend), always use
// same-origin paths regardless of any VITE_API_BASE_URL value baked
// into the bundle. Step #S-21 fix: without this guard, a non-empty
// VITE_API_BASE_URL in .env (intentional for dev — see vite.config
// proxy) gets compiled into the prod bundle, breaking every admin
// context other than localhost (LAN HTTP admin, FQDN admin, etc.)
// with cross-origin fetches that the binary cannot satisfy via CORS.
const BASE: string = import.meta.env.DEV
	? ((import.meta.env.VITE_API_BASE_URL ?? '') as string)
	: '';

/**
 * REQUEST_TIMEOUT_MS bounds every fetch issued via request() with
 * an AbortController-driven hard ceiling. Without this, a backend
 * stuck in a Caddy admin deadlock (#R-FRONTEND-PUT-NO-TIMEOUT,
 * observed Day 13: PUT /api/v1/routes/<id> stalled 5.7min in
 * DevTools Network) leaves the calling component's spinner
 * running forever — submitForm's `finally` block only runs when
 * the fetch promise settles.
 *
 * Why 30 s: a route PUT under normal load is well under 10 s
 * (Caddy reload + cert provisioning on first HTTPS — measured
 * ~5 s typical, ~8 s p99). 30 s = 4× the steady-state worst
 * case — generous enough to never false-positive a healthy
 * slow boot, tight enough to bound user-visible stall to a
 * surface that's still recoverable (operator can dismiss the
 * toast and retry). V2 may add a signature override for
 * known-slow endpoints; V1 ships the single ceiling.
 *
 * Why AbortController (not Promise.race against setTimeout):
 * Promise.race would resolve the outer promise but leave the
 * underlying fetch + TCP connection in flight, leaking a
 * goroutine-equivalent on long-running tabs. AbortController
 * properly cancels the fetch via signal.aborted semantics, so
 * the socket gets freed and the in-flight server-side handler
 * sees a client-closed-connection.
 */
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * Send an HTTP request to /api/v1/<path> with JSON body/response
 * semantics. Generic on the response type T. Throws ApiError on any
 * non-2xx outcome (or on network failure with status 0). After
 * REQUEST_TIMEOUT_MS without a response, the fetch is aborted and
 * ApiError(status=0, kind='system', message='request timed out
 * after 30s') is thrown.
 *
 * Exported so the new Step D modules (lib/api/auth.ts, lib/api/audit.ts)
 * can compose typed wrappers on top.
 */
/** Optional knobs of request(). */
export interface RequestOptions {
	/** Extra request headers (merged after Content-Type). */
	headers?: Record<string, string>;
	/** Resolve with the response body as a Blob (file downloads). */
	asBlob?: boolean;
}

/** Header marking a request the user did not trigger (v2.32). */
export const BACKGROUND_HEADER = 'X-Arenet-Background';

export async function request<T>(
	method: string,
	path: string,
	body?: unknown,
	opts: RequestOptions = {}
): Promise<T> {
	beginRequest();
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
	// Decided when the request starts: a poll tick with no user
	// interaction since the last activity must not keep the session
	// awake.
	const background = !idle.userActiveSinceReset;

	// A locked session refuses background traffic, so asking is
	// pointless. Short-circuit BEFORE the fetch.
	//
	// v2.32 taught the server to enforce the idle lock on background
	// requests without refreshing the session (the fix for polls that
	// defeated the lock). The consequence was never handled on this
	// side: while locked, every poller kept firing on its own timer and
	// every tick wrote a 403 to the access log. The operator's instance
	// produced 233 of them in one day -- 117 on /system/version and 116
	// on /observability/alert-events, the notification bell's two calls
	// at 60s over about two hours of being locked. The notifications
	// store swallows the error by design ("a version-check failure must
	// not break the panel"), so nothing ever stopped.
	//
	// That noise is not cosmetic. CrowdSec parses this access log, and
	// crowdsecurity/http-admin-interface-probing bans an IP for a
	// handful of 403s on admin paths -- which is how two of the
	// operator's blog editors were banned on 2026-10-04 by Ghost's own
	// 403s. /api/v1/... is not in that scenario's path list today. That
	// is luck, not safety: Arenet should not generate hundreds of 403s
	// from its own idle interface.
	//
	// The layout heartbeat already had this gate, with the reasoning in
	// its comment ("locked sessions get a 403 ... we skip to avoid the
	// noise"). Putting it here covers every poller instead of three,
	// and any poller added later inherits it.
	//
	// Only BACKGROUND requests are short-circuited. The unlock itself
	// is user-initiated, so it never carries the header and always
	// reaches the server.
	try {
		// Inside the try so the finally below clears the abort timer and
		// closes the loading counter — the same cleanup every other
		// exit path gets. Outside it, this would leak the setTimeout
		// the line above just armed.
		if (background && auth.state === 'locked') {
			throw new ApiError('session locked', 403, 'forbidden');
		}

		const init: RequestInit = {
			method,
			credentials: 'include',
			signal: controller.signal
		};
		if (body !== undefined) {
			init.headers = { 'Content-Type': 'application/json' };
			init.body = JSON.stringify(body);
		}
		if (opts.headers) {
			init.headers = { ...(init.headers as Record<string, string> | undefined), ...opts.headers };
		}
		if (background) {
			init.headers = { ...(init.headers as Record<string, string> | undefined), [BACKGROUND_HEADER]: '1' };
		}
		let res: Response;
		try {
			res = await fetch(`${BASE}/api/v1${path}`, init);
		} catch (err) {
			// AbortError fires whether the abort was triggered by
			// the timer above OR by an explicit consumer-side
			// abort. We translate uniformly to a system-level
			// ApiError so submitForm-style callers see a
			// consistent shape across stall + cancel cases.
			if (err instanceof DOMException && err.name === 'AbortError') {
				throw new ApiError(`request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`, 0, 'system');
			}
			throw new ApiError(`network error: ${(err as Error).message}`, 0, 'system');
		}

		// Step D interceptors BEFORE body parsing.
		if (res.status === 401) {
			// A 401 on the /me bootstrap (or its retry) is not a lost
			// session: the root layout owns that redirect, because it
			// also has to choose /setup on a fresh install. Navigating
			// from here as well would race it.
			const bootstrapping = auth.state === 'unknown' || auth.state === 'error';
			auth.clear();
			// Avoid redirect loops: only navigate when not already on
			// an unauthenticated entry page. ?next= brings the user back
			// here once signed in again.
			const loc = typeof window !== 'undefined' ? window.location : undefined;
			const here = loc?.pathname ?? '';
			if (!bootstrapping && !isEntryPath(here)) {
				void goto(withNext('/login', here + (loc?.search ?? '')));
			}
			throw new ApiError('authentication required', 401, 'auth');
		}

		if (res.status === 403) {
			// Step D has exactly one cause for 403 (session locked).
			// Phase 2 may introduce role-based 403s; this is where we'd
			// disambiguate by body.error.
			const body403 = await safeJSON(res);
			const msg = typeof body403?.error === 'string' ? body403.error : 'forbidden';
			if (msg === 'session locked') {
				auth.setLocked();
				throw new ApiError('session locked', 403, 'forbidden');
			}
			throw new ApiError(msg, 403, 'forbidden');
		}

		if (res.status === 429) {
			const retryHdr = res.headers.get('Retry-After') ?? '0';
			const retryAfter = parseInt(retryHdr, 10) || 0;
			const body429 = await safeJSON(res);
			const msg = typeof body429?.error === 'string' ? body429.error : 'rate limited';
			pushToast(msg, 'danger');
			throw new ApiError(msg, 429, 'rate_limited', retryAfter);
		}

		// Idle reset gate: a user-triggered response < 500 counts as
		// server interaction. 5xx and network errors (status 0) do not
		// reset (spec §6.4), nor do background requests (v2.32).
		if (res.status < 500 && !background) {
			idle.reset();
		}

		if (!res.ok) {
			// 4xx (other than 401/403/429) → validation error.
			// 5xx → system error.
			const errBody = await safeJSON(res);
			const msg =
				typeof errBody?.error === 'string' ? errBody.error : `HTTP ${res.status}`;
			const code = typeof errBody?.code === 'string' ? errBody.code : undefined;
			const params =
				errBody && typeof errBody.params === 'object' && errBody.params !== null
					? (errBody.params as Record<string, unknown>)
					: undefined;
			const kind = res.status >= 500 ? 'system' : 'validation';
			throw new ApiError(msg, res.status, kind, undefined, code, params);
		}

		if (res.status === 204) return undefined as T;
		if (opts.asBlob) return (await res.blob()) as T;
		return (await res.json()) as T;
	} finally {
		// Clear the timer regardless of outcome (success, error,
		// abort). Leaving it unclear would leak the setTimeout
		// reference + log a spurious AbortError later.
		clearTimeout(timeoutId);
		endRequest();
	}
}

/** safeJSON returns the parsed JSON body or null if parsing fails. */
async function safeJSON(res: Response): Promise<Record<string, unknown> | null> {
	try {
		return (await res.json()) as Record<string, unknown>;
	} catch {
		return null;
	}
}

// Step C route operations preserved verbatim — call sites in the UI
// keep working unchanged.
export const listRoutes = (): Promise<Route[]> => request<Route[]>('GET', '/routes');
export const getRoute = (id: string): Promise<Route> => request<Route>('GET', `/routes/${id}`);
export const createRoute = (r: RouteRequest): Promise<Route> =>
	request<Route>('POST', '/routes', r);
export const updateRoute = (id: string, r: RouteRequest): Promise<Route> =>
	request<Route>('PUT', `/routes/${id}`, r);
export const deleteRoute = (id: string): Promise<void> => request<void>('DELETE', `/routes/${id}`);

// v2.14.3 — route disable/enable. Idempotent on the backend; both
// return the updated route plus lastHttpsRouteAffected (true when
// this action flips the last active HTTPS route, so the UI can warn
// the operator the HTTPS server (:443) is stopping/starting).
export const disableRoute = (id: string): Promise<Route & { lastHttpsRouteAffected?: boolean }> =>
	request('POST', `/routes/${id}/disable`);
export const enableRoute = (id: string): Promise<Route & { lastHttpsRouteAffected?: boolean }> =>
	request('POST', `/routes/${id}/enable`);

// Task 8 — route maintenance mode. Mirrors disableRoute/enableRoute's
// fetch/error style exactly.
export const enterMaintenance = (id: string): Promise<Route> =>
	request('POST', `/routes/${id}/maintenance`);
export const exitMaintenance = (id: string): Promise<Route> =>
	request('POST', `/routes/${id}/maintenance/off`);

// v2.36 — add one WAF exclusion to a route (usually from a WAF event).
// With `target` it is a targeted exclusion, without it the rule is
// excluded on the whole route. 409 = already present.
export const addWafExclusion = (id: string, body: AddWafExclusionRequest): Promise<Route> =>
	request('POST', `/routes/${id}/waf-exclusions`, body);

// v2.40 — Caddyfile import: the preview writes nothing; the import
// creates the hosts listed (replace = those whose existing route may be
// overwritten).
export const previewCaddyfileImport = (caddyfile: string): Promise<CaddyfilePreview> =>
	request('POST', '/routes/import/caddyfile/preview', { caddyfile });
export const importCaddyfile = (
	caddyfile: string,
	hosts: string[],
	replace: string[]
): Promise<CaddyfileImportResult> =>
	request('POST', '/routes/import/caddyfile', { caddyfile, hosts, replace });

// v2.39 — OpenAPI document of this API, and the raw call used by the
// API docs "Try it" (status + body as returned, errors included, the
// session cookie is sent like any UI call).
export const getOpenAPI = (): Promise<Record<string, unknown>> => request('GET', '/openapi.json');

/** Raw response of a "Try it" call. */
export interface RawResponse {
	status: number;
	body: string;
	contentType: string;
}

export async function rawRequest(method: string, fullPath: string, body?: string): Promise<RawResponse> {
	const init: RequestInit = { method: method.toUpperCase(), credentials: 'include' };
	if (body !== undefined && body.trim() !== '') {
		init.headers = { 'Content-Type': 'application/json' };
		init.body = body;
	}
	const res = await fetch(`${BASE}${fullPath}`, init);
	return { status: res.status, body: await res.text(), contentType: res.headers.get('Content-Type') ?? '' };
}

// v2.38 — per-route SecLang: live check (+ next free rule ID), guided
// rule → SecLang, and the WAF tester (sample request, no traffic).
export const validateSecLang = (seclang: string): Promise<SecLangValidateResponse> =>
	request('POST', '/waf/seclang/validate', { seclang });
export const secLangFromGuided = (rule: WafCustomRule, id: number): Promise<{ seclang: string }> =>
	request('POST', '/waf/seclang/from-guided', { rule, id });
export const testRouteWaf = (id: string, body: WafTestRequest): Promise<WafTestResponse> =>
	request('POST', `/routes/${id}/waf-test`, body);

// Step #R-PROXMOX-HTTPS-LOOP commit 3 — operator-triggered
// upstream probe. Backend is per-URL; the route-form UI
// parallelises pool > 1 via Promise.all so the operator
// sees all rows update concurrently.
export const testUpstream = (req: TestUpstreamRequest): Promise<TestUpstreamResponse> =>
	request<TestUpstreamResponse>('POST', '/routes/test-upstream', req);

/**
 * v2.56 — runs the active health check with the unsaved form settings.
 * Writes nothing and reloads nothing; the point is to find out before
 * committing.
 */
export const testHealthCheck = (
	req: TestHealthCheckRequest
): Promise<TestHealthCheckResponse> =>
	request<TestHealthCheckResponse>('POST', '/routes/test-health-check', req);
