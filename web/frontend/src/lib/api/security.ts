// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step M.3 — typed client wrapper around GET /api/v1/security/events.
// The backend wire shape lives in
// internal/api/security_handlers.go; the response type is
// declared in lib/api/types.ts.

import { request } from './client';
import type {
	AttackersSummaryResponse,
	AuthFailuresResponse,
	CertEventLevel,
	CertEventsAggregateResponse,
	CertEventsResponse,
	CountryBlockEventsResponse,
	CrowdSecDecisionDeleteResponse,
	DecisionsResponse,
	GeoEventsResponse,
	LAPIDecisionsResponse,
	ManualBanRequest,
	ManualBanResponse,
	MetricWindow,
	OwaspCategory,
	RateLimitEventsResponse,
	ScenariosResponse,
	ServerPosition,
	ThrottleEventsResponse,
	WafEventsByRuleResponse,
	WafEventsResponse
} from './types';

export interface FetchEventsParams {
	limit?: number;
	route?: string;
	category?: OwaspCategory;
}

/**
 * Fetch recent WAF events from /api/v1/security/events.
 *
 * Filters are optional:
 *   - `limit` is clamped server-side at 100; values > 100 are
 *     silently capped (no error).
 *   - `route` filters to a single route UUID.
 *   - `category` filters to one OWASP category string.
 *
 * AC #13 degraded-mode path: when the observability subsystem
 * failed at boot, the response carries `disabled: true` and an
 * empty `events` array. Callers should surface a clean empty
 * state in that case, not a hostile error toast.
 */
export function fetchEvents(params: FetchEventsParams = {}): Promise<WafEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.route) qs.set('route', params.route);
	if (params.category) qs.set('category', params.category);
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<WafEventsResponse>('GET', `/security/events${suffix}`);
}

/**
 * Per-(rule, category) aggregate over the window.
 *
 * Two usage modes :
 *  - `fetchEventsByRule({route, window})` : the M.4 drill-
 *    down's per-rule breakdown table for ONE route. Server-
 *    side aggregation avoids the most-recent-100 truncation
 *    that client-side group-by would silently produce on a
 *    30d window.
 *  - `fetchEventsByRule({category, window})` : Phase Y /waf
 *    page cross-route per-category drill-down. Returns every
 *    rule in that category across all routes for the window.
 *  - Both supplied : rules in that category ON that route.
 *
 * The backend requires AT LEAST ONE of route / category — an
 * unfiltered call returns 400. Window is always required.
 */
export interface FetchEventsByRuleParams {
	route?: string;
	category?: string;
	window: MetricWindow;
}

export function fetchEventsByRule(
	params: FetchEventsByRuleParams | string,
	windowArg?: MetricWindow
): Promise<WafEventsByRuleResponse> {
	// Backward compat : legacy (route, window) positional
	// callers still work. New callers pass the object form.
	let qs: URLSearchParams;
	if (typeof params === 'string') {
		// Legacy two-arg call : (route, window).
		qs = new URLSearchParams({ route: params, window: windowArg ?? '24h' });
	} else {
		qs = new URLSearchParams({ window: params.window });
		if (params.route) qs.set('route', params.route);
		if (params.category) qs.set('category', params.category);
	}
	return request<WafEventsByRuleResponse>('GET', `/security/events/by-rule?${qs.toString()}`);
}

/**
 * Step Q.3 — typed client wrapper around GET
 * /api/v1/security/throttle-events.
 *
 * Filters are optional:
 *   - `limit` is clamped server-side at 100.
 *   - `srcIp` filters to a single source IP (exact match).
 *   - `tier` filters to tier 1 or 2; any other value is
 *     rejected by the backend with a 400.
 *
 * AC #14 degraded-mode path: when the observability subsystem
 * failed at boot, the response carries `disabled: true` and an
 * empty `events` array. Same shape contract as fetchEvents.
 */
export interface FetchThrottleEventsParams {
	limit?: number;
	srcIp?: string;
	tier?: 1 | 2;
}

export function fetchThrottleEvents(
	params: FetchThrottleEventsParams = {}
): Promise<ThrottleEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.srcIp) qs.set('srcIp', params.srcIp);
	if (params.tier !== undefined) qs.set('tier', String(params.tier));
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<ThrottleEventsResponse>('GET', `/security/throttle-events${suffix}`);
}

/**
 * Step Q.2 — typed client wrapper around GET
 * /api/v1/security/auth-failures.
 *
 * `window` is REQUIRED (backend returns 400 on missing). The
 * response carries BOTH a per-minute timeseries for the
 * dashboard chart AND a recent feed for the mixed-events
 * widget — single audit-scan, two projections (D4.B).
 *
 * `partial: true` signals the scan hit its 200-row cap before
 * reaching the window's `from`. AC #14 disabled contract on
 * nil reader.
 */
export function fetchAuthFailures(window: MetricWindow): Promise<AuthFailuresResponse> {
	const qs = new URLSearchParams({ window });
	return request<AuthFailuresResponse>('GET', `/security/auth-failures?${qs.toString()}`);
}

/**
 * Step Q.3 — typed client wrapper around GET
 * /api/v1/security/attackers-summary. Server-side union over
 * WAF + throttle + audit source-IP sets over the window.
 *
 * Three-state disabled/partial contract: ALL readers nil →
 * disabled; subset nil → partial; all present → neither.
 * Caller renders an "incomplete data" hint when `partial`
 * is true.
 */
export function fetchAttackersSummary(window: MetricWindow): Promise<AttackersSummaryResponse> {
	const qs = new URLSearchParams({ window });
	return request<AttackersSummaryResponse>('GET', `/security/attackers-summary?${qs.toString()}`);
}

/**
 * Step N.3 — typed client wrapper around GET
 * /api/v1/security/decisions.
 *
 * CS.3 note: this endpoint is no longer reachable via a
 * dedicated /security/decisions page (that route was deleted
 * in Commit A). The CrowdSecDecisionsPanel mounted under
 * /security?tab=crowdsec still calls it for the "Local
 * snapshot" sub-tab, which reads Arenet's local mirror of
 * LAPI decisions persisted in metrics.db decision_event.
 * Backend handler intentionally kept — operators may have
 * external scripts against it; removal would be a separate
 * decision later.
 *
 * Filters are optional:
 *   - `limit` is clamped server-side at 100.
 *   - `scope` filters to a single LAPI scope (`ip`, `range`,
 *     `country`, `as` — free-form string for forward-compat).
 *   - `srcIp` is exact-match on the decision's `value`
 *     field (named `srcIp` for operator-mental-model
 *     consistency with the throttle-events endpoint).
 *   - `scenario` filters on the LAPI scenario name
 *     (e.g. `crowdsecurity/http-probing`).
 *   - `onlyActive` excludes rows whose `expiresAt` is in
 *     the past — i.e. revoked or expired decisions.
 *     Default false: include forensic "what WAS banned
 *     yesterday" rows.
 *
 * AC #15 degraded-mode path: when the LAPI key isn't
 * configured OR the observability subsystem failed at boot,
 * the response carries `disabled: true` and an empty
 * `events` array.
 */
export interface FetchDecisionsParams {
	limit?: number;
	scope?: string;
	srcIp?: string;
	scenario?: string;
	onlyActive?: boolean;
}

export function fetchDecisions(
	params: FetchDecisionsParams = {}
): Promise<DecisionsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.scope) qs.set('scope', params.scope);
	if (params.srcIp) qs.set('srcIp', params.srcIp);
	if (params.scenario) qs.set('scenario', params.scenario);
	if (params.onlyActive) qs.set('onlyActive', 'true');
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<DecisionsResponse>('GET', `/security/decisions${suffix}`);
}

/**
 * Step CS.2.A — Live LAPI decisions proxy. Distinct from
 * fetchDecisions above (which serves the persistent mirror in
 * metrics.db). Use this for "what's enforced RIGHT NOW";
 * use fetchDecisions for "what have we historically seen".
 *
 * Failure modes (codes the typed `request` helper re-throws
 * as ApiError):
 *   404 → bouncer not configured → caller renders the
 *         "Configure CrowdSec" CTA linking to /settings
 *   502 → LAPI unreachable / auth failed — error message
 *         is operator-friendly (timeout / refused / DNS / TLS /
 *         "authentication failed (invalid bouncer API key)")
 *   500 → storage read failed — generic backend error
 */
export interface FetchLAPIDecisionsParams {
	scope?: string;
	source?: string;
	type?: string;
	limit?: number;
	offset?: number;
}

export function fetchLAPIDecisions(
	params: FetchLAPIDecisionsParams = {}
): Promise<LAPIDecisionsResponse> {
	const qs = new URLSearchParams();
	if (params.scope) qs.set('scope', params.scope);
	if (params.source) qs.set('source', params.source);
	if (params.type) qs.set('type', params.type);
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.offset !== undefined) qs.set('offset', String(params.offset));
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<LAPIDecisionsResponse>(
		'GET',
		`/security/crowdsec/decisions${suffix}`
	);
}

/**
 * Step CS.2.C — fetch the aggregated 24h scenarios activity
 * from LAPI's /v1/alerts endpoint (JWT auth via Security
 * Automation credentials, see backend
 * internal/api/crowdsec_scenarios.go).
 *
 * Status codes the caller should distinguish:
 *   412 → Security Automation not configured → render
 *         "Configure Security Automation" CTA
 *   502 → LAPI unreachable OR machine creds rejected
 *         after retry → render error + retry button
 */
export function fetchScenarios(): Promise<ScenariosResponse> {
	return request<ScenariosResponse>('GET', '/security/crowdsec/scenarios');
}

/**
 * Step CS.3 Commit D — POST /api/v1/security/crowdsec/decisions.
 *
 * Manual ban entry point invoked by the "Bannir une IP" modal
 * on the Live LAPI sub-tab. Builds a single LAPI Alert via
 * Security Automation machine creds; on success the response
 * echoes the canonical scenario string (with the
 * "manual:<username>|<reason>" format) and the computed
 * ExpiresAt so the UI can refresh without waiting for the
 * 30s polling tick.
 *
 * Failure modes the caller should distinguish (ApiError
 * statuses thrown by request<T>):
 *   400 → validation failure (bad IP/CIDR, bad duration,
 *         bad type, reason length). Inline form error.
 *   412 → Security Automation not configured. CTA linking
 *         to /settings.
 *   502 → LAPI unreachable OR machine creds rejected after
 *         retry. Inline retry affordance.
 */
export function createManualBan(req: ManualBanRequest): Promise<ManualBanResponse> {
	return request<ManualBanResponse>('POST', '/security/crowdsec/decisions', req);
}

/**
 * DELETE /api/v1/security/crowdsec/decisions/{id} — unban. LAPI
 * expires the decision; it only accepts this from the Security
 * Automation machine credentials, so:
 *   412 → Security Automation not configured
 *   404 → LAPI has no such decision
 *   502 → LAPI unreachable / credentials rejected / other LAPI
 *         error (CrowdSec 1.6 answers 500 for an unknown id)
 */
export function deleteCrowdSecDecision(id: number): Promise<CrowdSecDecisionDeleteResponse> {
	return request<CrowdSecDecisionDeleteResponse>(
		'DELETE',
		`/security/crowdsec/decisions/${encodeURIComponent(String(id))}`
	);
}

/**
 * Step U.4 — typed client wrapper around GET
 * /api/v1/observability/cert-events. The endpoint backs the
 * Activity log page's cert source (U.5 wires it into the
 * unified-table aggregator alongside WAF / throttle / auth
 * failures).
 *
 * Path is /observability/ NOT /security/ because cert
 * lifecycle is broader than security per the §3.4 page
 * rename: the Activity log unifies WAF + throttle + auth +
 * cert events, and the cert source lands under the
 * lifecycle umbrella. Other fetch* methods stay on
 * /security/... unchanged.
 *
 * Filters are all optional per spec §5.1:
 *   - `limit` clamped server-side at 1000 (silent cap; bad
 *     value returns 400 per the U.3 handler).
 *   - `since` / `until` RFC 3339 timestamps. Bad parse → 400,
 *     until <= since → 400.
 *   - `level` is a multi-value subset of {INFO, ERROR},
 *     joined with comma in the URL. Unknown values → 400.
 *   - `search` is a substring match across domain, issuer,
 *     error_msg, details (case-insensitive). Trimmed
 *     server-side; empty = no filter.
 *
 * AC #13 degraded-mode path: when the observability
 * subsystem failed at boot OR the cert-event reader was
 * never wired, the response carries `degraded: true` and an
 * empty `events` array + `total: 0`. Callers should surface
 * a clean empty state, not a hostile error toast.
 */
export interface FetchCertEventsParams {
	limit?: number;
	since?: string;
	until?: string;
	level?: CertEventLevel[];
	search?: string;
	/**
	 * Cert.B (2026-06-23) — exact-match filter on the cert
	 * event's domain field. Different from `search` which does
	 * substring LIKE %X% across multiple columns (and would
	 * match e.g. "foo.example.com" when querying for
	 * "not-foo.example.com"). Use `domain` for the /certs
	 * drill-down where the operator wants ONLY the events for
	 * a specific hostname.
	 */
	domain?: string;
	/**
	 * Cert.B (2026-06-23) — exact-match filter on eventType.
	 * Typical values : "cert_obtained", "cert_failed",
	 * "cert_ocsp_revoked". Unknown values pass through the
	 * backend (defensive against future certmagic event-type
	 * additions) ; expect 0 rows in that case rather than 400.
	 */
	type?: string;
}

export function fetchCertEvents(
	params: FetchCertEventsParams = {}
): Promise<CertEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.since) qs.set('since', params.since);
	if (params.until) qs.set('until', params.until);
	if (params.level && params.level.length > 0) {
		qs.set('level', params.level.join(','));
	}
	if (params.search) qs.set('search', params.search);
	if (params.domain) qs.set('domain', params.domain);
	if (params.type) qs.set('type', params.type);
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<CertEventsResponse>('GET', `/observability/cert-events${suffix}`);
}

/**
 * Phase 5 — typed client wrapper around GET
 * /api/v1/observability/cert-events/aggregate. Backs the
 * dashboard's cert lifecycle panel + the "Failed last 7d"
 * KPI.
 *
 * Params (both optional):
 *   - `windowDays`: clamped server-side at 1h..90d. Default 30d.
 *   - `intervalHours`: clamped server-side at 1h..7d. Default 24h.
 *
 * The server emits a continuous timeline (empty buckets carry
 * zero counts) so callers can pass the response straight into
 * a chart without client-side gap-fill.
 *
 * AC #13 degraded-mode path: when the cert-event reader was
 * never wired, the response carries `degraded: true` and an
 * empty `buckets` array. Callers should surface a clean empty
 * state.
 */
export function fetchCertEventsAggregate(
	params: { windowDays?: number; intervalHours?: number } = {}
): Promise<CertEventsAggregateResponse> {
	const qs = new URLSearchParams();
	if (params.windowDays !== undefined) qs.set('window', `${params.windowDays}d`);
	if (params.intervalHours !== undefined) qs.set('interval', `${params.intervalHours}h`);
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<CertEventsAggregateResponse>(
		'GET',
		`/observability/cert-events/aggregate${suffix}`
	);
}

/**
 * Step W.5 — typed client wrapper around GET
 * /api/v1/observability/country-block-events. The endpoint
 * backs the Activity log page's country-block source (W.4
 * sink writes the rows the W.5 reader serves).
 *
 * Path is /observability/ (lifecycle umbrella) consistent
 * with cert-events. Filters all optional per the W.5
 * handler:
 *   - `limit` clamped server-side at 1000 (silent cap; bad
 *     value returns 400).
 *   - `route` filters to a single route UUID.
 *   - `srcIp` exact-match on src IP.
 *   - `country` exact-match on ISO 3166-1 alpha-2 code.
 *   - `mode` exact-match on "allow" / "deny".
 *   - `since` / `until` RFC 3339, bad parse → 400, until
 *     <= since → 400.
 *
 * AC #13 degraded-mode path: nil reader → `degraded: true`,
 * empty events, total=0. Callers surface a clean empty
 * state.
 */
export interface FetchCountryBlockEventsParams {
	limit?: number;
	route?: string;
	srcIp?: string;
	country?: string;
	mode?: 'allow' | 'deny';
	since?: string;
	until?: string;
}

export function fetchCountryBlockEvents(
	params: FetchCountryBlockEventsParams = {}
): Promise<CountryBlockEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.route) qs.set('route', params.route);
	if (params.srcIp) qs.set('srcIp', params.srcIp);
	if (params.country) qs.set('country', params.country);
	if (params.mode) qs.set('mode', params.mode);
	if (params.since) qs.set('since', params.since);
	if (params.until) qs.set('until', params.until);
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<CountryBlockEventsResponse>(
		'GET',
		`/observability/country-block-events${suffix}`
	);
}

/**
 * Step Z.1 — fetch rate-limit (429) events from the
 * rate_limit_event table. Mirror of fetchCountryBlockEvents
 * (same wire envelope, same AC #13 degraded-mode contract).
 *
 * Backed by GET /api/v1/security/rate-limit-events
 * (hard-auth viewer-accessible). Operator-facing surfaces :
 * the dashboard /logs Activity merge + future per-route
 * timeseries page (Z.3).
 */
export interface FetchRateLimitEventsParams {
	limit?: number;
	route?: string;
	remoteIp?: string;
	since?: string;
	until?: string;
}

export function fetchRateLimitEvents(
	params: FetchRateLimitEventsParams = {}
): Promise<RateLimitEventsResponse> {
	const qs = new URLSearchParams();
	if (params.limit !== undefined) qs.set('limit', String(params.limit));
	if (params.route) qs.set('route', params.route);
	if (params.remoteIp) qs.set('remoteIp', params.remoteIp);
	if (params.since) qs.set('since', params.since);
	if (params.until) qs.set('until', params.until);
	const suffix = qs.toString() ? `?${qs.toString()}` : '';
	return request<RateLimitEventsResponse>(
		'GET',
		`/security/rate-limit-events${suffix}`
	);
}

/**
 * Step V.5 — fetch the Arenet server's current geographic
 * position for the /map page's Mercator center + central
 * pin. Backed by the V.4 GET /api/v1/observability/server-
 * position endpoint.
 *
 * AC #13 degraded-mode path: when no GeoIP MMDB is loaded
 * AND no manual override exists, the response carries
 * `degraded: true` with zeroed lat/lon. Callers MUST check
 * the flag and render the "GeoIP not configured" banner
 * rather than placing a marker at (0, 0).
 */
export function fetchServerPosition(): Promise<ServerPosition> {
	return request<ServerPosition>('GET', '/observability/server-position');
}

/**
 * Step V.7 — operator-supplied manual override of the
 * Arenet server position. Backed by V.4 PUT
 * /api/v1/observability/server-position (commit 822b634).
 *
 * Admin-only on the backend (RequireAdminMiddleware in
 * routes.go); non-admin sessions get 403 surfaced as
 * ApiError. Validation happens server-side per spec §5.2:
 *
 *   - lat ∈ [-90, 90]
 *   - lon ∈ [-180, 180]
 *   - city / country: operator display strings (empty OK).
 *
 * The wrapper does NOT validate client-side — the page
 * component owns the inline form-error UX; this keeps
 * the wire shape honest about which side rejected.
 *
 * Returns the saved position (mode="manual",
 * sourceIp:undefined, detectedAt=time of write).
 */
export function putServerPosition(body: {
	lat: number;
	lon: number;
	city: string;
	country: string;
}): Promise<ServerPosition> {
	return request<ServerPosition>('PUT', '/observability/server-position', body);
}

/**
 * Step V.7 — re-run the V.1 ipify-then-GeoIP auto-detect
 * path without rebooting. Backed by V.4 POST
 * /api/v1/observability/server-position:redetect (commit
 * 822b634; chi router matches the literal `:redetect`
 * suffix because chi does not reserve `:`).
 *
 * Admin-only. Useful when the operator's public IP
 * changes (DDNS, network move) and they want the map to
 * re-center without a restart.
 *
 * Per spec §5.3, returns the degraded shape (200 +
 * degraded:true + zeroed lat/lon) when the redetect
 * itself fails (network down, MMDB absent). The caller
 * should branch on the `degraded` flag rather than
 * treating the 200 as unqualified success.
 */
export function redetectServerPosition(): Promise<ServerPosition> {
	return request<ServerPosition>(
		'POST',
		'/observability/server-position:redetect'
	);
}

/**
 * Step V.5 — fetch the in-memory geo events ring buffer
 * (V.3 spec §5.4). Used by the /map page on mount to
 * populate the initial paint; the WS stream
 * /api/v1/ws/geo-events overlays live events on top (V.6).
 *
 * `limit` defaults to 100 server-side, clamped at 500.
 * Callers SHOULD pass an explicit value when they know
 * what window they want; the default is sized for a
 * comfortable mount-time paint.
 *
 * AC #13 degraded-mode path: the response carries
 * `degraded: true` when the GeoIP lookup is degraded —
 * events still flow but with empty country/lat/lon. The
 * frontend can render a banner alongside the map.
 *
 * V.5 EXPORTS this function but does NOT consume it — V.6
 * wires the replay-then-WS pipeline. Ships now so the wire
 * contract lands in one commit and V.6 reads the test
 * harness from this file.
 */
export function fetchGeoEventsReplay(limit?: number): Promise<GeoEventsResponse> {
	const suffix = limit !== undefined ? `?limit=${encodeURIComponent(String(limit))}` : '';
	return request<GeoEventsResponse>('GET', `/observability/geo-events${suffix}`);
}

/**
 * Phase Z.5.3 — batch GeoIP lookup.
 *
 * Posts a list of IPs and receives a map of ip → country
 * code (ISO 3166-1 alpha-2, "LAN" for RFC1918, "" for
 * MMDB miss / degraded). Used by /logs to enrich the
 * SOURCE IP column with a "· FR" suffix without one
 * round-trip per row.
 *
 * Cap : 256 IPs per request (server-enforced ; the
 * frontend de-duplicates before sending).
 *
 * AC #13 degraded path : the response carries
 * `degraded: true` when the backend has no MMDB ; every
 * `results` entry is "" in that case so the frontend
 * keeps rendering raw IPs without the country suffix.
 */
export interface GeoLookupBatchResponse {
	results: Record<string, string>;
	degraded?: boolean;
}

export function geoLookupBatch(ips: string[]): Promise<GeoLookupBatchResponse> {
	return request<GeoLookupBatchResponse>('POST', '/geo/lookup-batch', { ips });
}

/**
 * v2.28 — GET /api/v1/geo/asn. `loaded` is false when no GeoLite2-ASN
 * database is installed; `indexReady` false while a freshly loaded
 * database's name index is still being built.
 */
export interface ASNInfo {
	asn: number;
	name: string;
}

export interface ASNSearchResponse {
	loaded: boolean;
	indexReady: boolean;
	results: ASNInfo[];
}

/** Search ASes by organisation name or number ("ovh", "16276", "AS16276"). */
export function searchASN(q: string, limit = 20): Promise<ASNSearchResponse> {
	const params = new URLSearchParams({ q, limit: String(limit) });
	return request<ASNSearchResponse>('GET', `/geo/asn?${params.toString()}`);
}

/** Resolve the organisation names of saved AS numbers. */
export function namesASN(asns: number[]): Promise<ASNSearchResponse> {
	return request<ASNSearchResponse>('GET', `/geo/asn?ids=${asns.join(',')}`);
}
