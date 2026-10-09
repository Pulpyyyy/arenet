<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.2.c — Logs page. Replaces the R.2 stub.

  IMPORTANT honesty note: Arenet does NOT currently expose a live
  access-log stream. The mock at
  docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:2352-2400
  shows a live tail of all traffic (info / ok / warn / err / block);
  the closest we can do today is unify the four event streams the
  backend exposes:
    - WAF events (Step M) — blocked requests with rule ID.
    - Throttle events (Step Q) — rate-limited auth attempts.
    - Auth-failure events (Step Q) — login_failure / oidc_*.
    - Cert lifecycle events (Step U) — obtained / failed /
      ocsp_revoked. Added by U.5 (commit d769cad); the page
      title rename "Security events" → "Activity log" lands
      in U.6 (this commit) reflecting the widened scope.
  Each row is mapped to a unified shape sorted ts-desc.

  Filters:
    - Search input (substring on path / IP / username).
    - Level segmented control (Tous / Block / Warn / Info).
    - Refresh interval (auto-poll every 10s; "Pause" toggles).

  Out of scope (matches spec §6 Logs audit):
    - True access-log stream (all 2xx / 3xx / 4xx / 5xx).
    - GeoIP country annotation per row (no MaxMind dep yet).
    - Export action.

  Reuses R.4.1 primitives: .card, .seg, .pill, .stack, .log-row,
  .mono. The page-level .log-table grid extends the dashboard's
  .log-row pattern with a 6-column header row.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Button from '$lib/components/Button.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import RouteHost from '$lib/components/RouteHost.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { listRoutes } from '$lib/api/client';
	import {
		fetchEvents,
		fetchThrottleEvents,
		fetchAuthFailures,
		fetchCertEvents,
		fetchCountryBlockEvents,
		fetchRateLimitEvents,
		geoLookupBatch
	} from '$lib/api/security';
	import { ApiError } from '$lib/api/types';
	import type {
		AuthFailureRecentEvent,
		CertEvent,
		CountryBlockEvent,
		RateLimitEvent,
		ThrottleEvent,
		WafEvent
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { sourceMeta } from '$lib/utils/sourceMeta';
	import { levelMeta } from '$lib/utils/levelMeta';
	import { formatSourceIP } from '$lib/utils/ipClass';
	import ActivityHistogram from '$lib/components/ActivityHistogram.svelte';
	import WafExcludeDialog from '$lib/components/WafExcludeDialog.svelte';
	import { auth } from '$lib/stores/auth.svelte';
	import { isExcludableRule } from '$lib/utils/waf-exclusion';

	// W.bugfix Fix #1 — the WAF event source now distinguishes
	// 'block' (request short-circuited by the WAF, status 403)
	// from 'detect' (rule fired but request reached upstream
	// because the route is in detect mode). Pre-fix all WAF
	// rows rendered as 'block'; the detect rows lied. Detect
	// rows render with a muted amber accent so operators see
	// rule-fire signal without thinking enforcement happened.
	//
	// W.5 — country-block rows render at the 'block' level
	// (the request WAS short-circuited at the Caddy edge by
	// an operator-declared country gate). They distinguish
	// from WAF blocks via source='country_block' on the row
	// + the slate-gray pill styling — same level-block CSS
	// hook reused; visual differentiation lives in the
	// .log-lvl.country variant added in this commit.
	type LevelTag = 'block' | 'detect' | 'warn' | 'info';

	interface UnifiedRow {
		key: string;
		ts: string;
		level: LevelTag;
		code: string;
		source: string; // 'waf' / 'throttle' / 'auth'
		method: string;
		path: string;
		detail: string;
		srcIp: string;
		// W.7 follow-up — optional routeId so per-route
		// sources (waf, country_block) can render a host
		// badge resolved via routeMap. Sources without a
		// per-route shape (throttle, auth, cert) leave
		// this undefined; the template falls back to the
		// existing path-only rendering for those rows.
		routeId?: string;
		// detailTitle is the tooltip shown on hover over
		// the humanized detail string. For country-block
		// rows it surfaces the raw matcher reason ("allow-
		// miss", "deny-match") so forensic ops aren't
		// hidden behind the humanized French label.
		// Unset on other sources (no tooltip).
		detailTitle?: string;
		// v2.36 — the source WAF event, for the "Exclude…" action.
		wafEvent?: WafEvent;
	}

	const REFRESH_MS = 10_000;

	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let rows = $state<UnifiedRow[]>([]);
	let search = $state('');
	let levelFilter = $state<'all' | LevelTag>('all');
	// Phase Z.5.2 — route + HTTP status code filters. Both
	// single-select V1 ('' = no filter). Multi-select is V2
	// backlog (needs a Dropdown.svelte primitive that doesn't
	// exist in the codebase yet).
	let routeFilter = $state('');
	let codeFilter = $state('');

	// The way out of an over-narrow filter, offered by the empty state.
	function clearLogFilters(): void {
		search = '';
		levelFilter = 'all';
		routeFilter = '';
		codeFilter = '';
	}
	// Phase Z.5.2 — static HTTP status code enum surfaced as
	// the codeFilter dropdown options. Order is operator-
	// triage descending (5xx errors first, 4xx attacks
	// second, 2xx healthy last) so the most-investigated
	// codes are nearest the dropdown opener.
	const httpCodeOptions = [
		{ value: '500', label: '500 · Internal Server Error' },
		{ value: '502', label: '502 · Bad Gateway' },
		{ value: '503', label: '503 · Service Unavailable' },
		{ value: '504', label: '504 · Gateway Timeout' },
		{ value: '403', label: '403 · Forbidden (WAF / auth)' },
		{ value: '429', label: '429 · Too Many Requests (rate limit)' },
		{ value: '451', label: '451 · Unavailable for Legal Reasons (country block)' },
		{ value: '404', label: '404 · Not Found' },
		{ value: '401', label: '401 · Unauthorized' },
		{ value: '301', label: '301 · Moved Permanently' },
		{ value: '304', label: '304 · Not Modified' },
		{ value: '204', label: '204 · No Content' },
		{ value: '200', label: '200 · OK' }
	];
	let paused = $state(false);
	let pollId: ReturnType<typeof setInterval> | null = null;

	// W.7 follow-up — routeId → host resolution map.
	// Built ONCE on page mount (parallel with the first
	// event-load Promise.allSettled) + refreshed when the
	// poll loop runs so a newly-created route shows its
	// host on the next refresh. Routes deleted between
	// block time and page load fall back to the truncated
	// UUID in <RouteHost> — defensive, never blank.
	let routeMap = $state(new Map<string, string>());
	// v2.36 — "Exclude…" on a WAF row (admins only; the backend is
	// the authoritative gate).
	const isAdmin = $derived(auth.user?.role === 'admin');
	let excludeEvent = $state<WafEvent | null>(null);

	// Phase Z.5.3 — IP → country code cache, populated by
	// the lookup-batch endpoint after each event load. A
	// missing key means "not yet resolved" ; an empty
	// string means "backend answered, no MMDB record" ;
	// "LAN" means RFC1918 sentinel. formatSourceIP folds
	// the three cases into the SOURCE IP column label.
	//
	// Persistence : cumulative across polls so a known IP
	// keeps its country suffix when a new event arrives,
	// without re-hitting the backend. Bounded implicitly
	// by the row cap (200) + retention horizons.
	let countryMap = $state(new Map<string, string>());

	async function refreshRouteMap(): Promise<void> {
		try {
			const routes = await listRoutes();
			const next = new Map<string, string>();
			for (const r of routes) {
				next.set(r.id, r.host);
			}
			routeMap = next;
		} catch {
			// Non-fatal: a routes-API hiccup just keeps the
			// existing map; subsequent polls retry. Failing
			// hard would take down the activity log, which
			// has its own degraded-mode contract for the
			// event sources.
		}
	}

	// Phase Z.5.4 — per-source colors for the activity
	// histogram below the table. The SOURCE badge column is
	// neutral grey (Z.5.1 decision) ; the per-source color
	// taxonomy lives here, on the chart, where it carries
	// the temporal-distribution story for each signal kind.
	// Stack order is descending by how often the operator
	// scans for that source (WAF first, then HTTP rate-
	// limit, then auth-throttle, then country block, then
	// auth, then cert).
	const histogramSeries = [
		{ key: 'waf', label: 'WAF', color: 'var(--status-down)' },
		{ key: 'rate_limit', label: 'RATE-LIMIT', color: 'var(--status-warn)' },
		{ key: 'throttle', label: 'THROTTLE', color: 'oklch(70% 0.18 300)' },
		{ key: 'country_block', label: 'COUNTRY', color: 'var(--status-meta)' },
		{ key: 'auth', label: 'AUTH', color: 'var(--accent-cyan)' },
		{ key: 'cert', label: 'CERT', color: 'var(--status-up)' }
	];

	// Phase Z.5.2 — flatten routeMap to a sorted [id, host]
	// array for the dropdown <option> emission. Sorted by
	// host (operator scans alphabetically) ; routes deleted
	// between page load and refresh drop out cleanly on the
	// next routeMap refresh.
	const routeOptions = $derived(
		Array.from(routeMap.entries())
			.map(([id, host]) => ({ id, host }))
			.sort((a, b) => a.host.localeCompare(b.host))
	);

	const filteredRows = $derived(
		rows.filter((r) => {
			if (levelFilter !== 'all' && r.level !== levelFilter) return false;
			// Phase Z.5.2 — route filter applies to per-route
			// sources only (waf, country_block, rate_limit).
			// Non-per-route sources (throttle, auth, cert)
			// have no routeId — selecting a route filter
			// hides them, which is the operator-intended
			// behavior when drilling down on one hostname.
			if (routeFilter && r.routeId !== routeFilter) return false;
			// Phase Z.5.2 — exact-match HTTP code filter. The
			// code column carries the string form ("429",
			// "403", ...) on every source ; cert rows carry
			// the cert level code ("INFO" / "WARN" / etc.)
			// which won't match a numeric filter and so will
			// be hidden when the operator picks a numeric
			// code — intended.
			if (codeFilter && r.code !== codeFilter) return false;
			if (search.trim()) {
				const q = search.trim().toLowerCase();
				// Phase Z.5.2 — search now covers source,
				// method, code too. Pre-Z.5.2 only path/IP/
				// detail were indexed, which made the
				// educational placeholder ("ex: status:5xx
				// route:/auth/* ip:185.142.*") misleading
				// because typing "5xx" did not match the
				// row's code field. V1 keeps plain substring
				// match across more fields ; the structured
				// `status:` / `route:` / `ip:` syntax is
				// V2 backlog.
				const hay = `${r.source} ${r.method} ${r.code} ${r.path} ${r.srcIp} ${r.detail}`.toLowerCase();
				if (!hay.includes(q)) return false;
			}
			return true;
		})
	);

	// Phase Z.5.4 — feed the histogram with the SAME
	// filteredRows the table consumes so the chart reflects
	// every dropdown / search filter the operator applies.
	// {ts, source} projection — the histogram doesn't need
	// the rest of the row shape.
	const histogramCells = $derived(
		filteredRows.map((r) => ({ ts: r.ts, source: r.source }))
	);

	function mapWaf(e: WafEvent): UnifiedRow {
		// W.bugfix Fix #1 — read action + statusCode from the
		// wire shape instead of hardcoding "block / 403". A
		// pre-fix row persisted in the legacy schema has the
		// backfilled values (BLOCK / 403); a post-fix detect-
		// mode row has DETECT / 0 — the latter renders the
		// status column as "—" since the WAF doesn't capture
		// the upstream's actual response status at callback
		// time. Defense-in-depth fallback: an action we don't
		// know renders as 'block' (most conservative — operator
		// sees the row at the loudest level rather than
		// silently downgrading an unknown match).
		const isDetect = e.action === 'DETECT';
		return {
			key: `waf-${e.id}`,
			ts: e.ts,
			level: isDetect ? 'detect' : 'block',
			code: e.statusCode > 0 ? String(e.statusCode) : '—',
			source: 'waf',
			method: e.requestMethod,
			path: e.requestPath,
			// v2.37 — guided rules show their name.
			detail: e.ruleName
				? `WAF · ${t('wafRules.historyName', { name: e.ruleName })}`
				: `WAF rule ${e.ruleId} · ${e.category}`,
			srcIp: e.srcIp,
			// W.7 follow-up — WAF rows carry routeId so the
			// host badge resolves the operator-visible
			// hostname (e.g. "ha.example.com" instead
			// of grep'ing a UUID).
			routeId: e.routeId,
			wafEvent: e
		};
	}
	function mapThrottle(e: ThrottleEvent): UnifiedRow {
		return {
			key: `throttle-${e.id}`,
			ts: e.ts,
			level: 'warn',
			code: '429',
			source: 'throttle',
			method: 'POST',
			path: '/auth/login',
			detail: t('logs.detailThrottle', {
				tier: e.tier,
				seconds: e.blockDurationSeconds,
				user: e.attemptedUsername || '?'
			}),
			srcIp: e.srcIp
		};
	}
	// Auth + cert mappers take an `idx` disambiguator because
	// their wire shapes don't carry a per-event id today.
	// The natural (ts, srcIp, username) tuple collides under
	// burst login retries — 5 failures from the same IP at
	// the same username within the same second produce 5
	// rows that Svelte's keyed each-block rejects with
	// `each_key_duplicate` (operator-reported regression on
	// /logs). Appending the source-local array index makes
	// the key unique by construction; the natural prefix
	// keeps the key stable across polls when the backend
	// returns the same rows in the same order. Same shape
	// fix applied to cert events below (eventType + domain +
	// timestamp can collide on a fast OBTAIN / FAILED race).
	function mapAuth(e: AuthFailureRecentEvent, idx: number): UnifiedRow {
		const isOidc = e.action.startsWith('oidc_');
		return {
			key: `auth-${e.ts}-${e.srcIp}-${e.username}-${idx}`,
			ts: e.ts,
			level: 'warn',
			code: '401',
			source: 'auth',
			method: isOidc ? 'OIDC' : 'POST',
			path: isOidc ? '/auth/oidc/callback' : '/auth/login',
			detail: `${e.action} · user "${e.username || '?'}"${e.message ? ' · ' + e.message : ''}`,
			srcIp: e.srcIp || '?'
		};
	}

	// Truncate cert_failed error strings so the row height stays
	// stable. The full error remains queryable via the search
	// textbox (the backend index matches against the full
	// error_msg column).
	const CERT_ERROR_MAX = 60;
	function truncateError(s: string): string {
		if (s.length <= CERT_ERROR_MAX) return s;
		return s.slice(0, CERT_ERROR_MAX - 3) + '...';
	}

	// Compose the REQUEST column content per spec §4 architecture
	// component 7 (frontend additive). Each event type gets a
	// distinct one-line representation so an operator scanning
	// the table can read the row at a glance.
	function formatCertDetail(e: CertEvent): string {
		switch (e.eventType) {
			case 'cert_obtained': {
				const tail: string[] = [];
				if (e.issuer) tail.push(e.issuer);
				if (e.challenge) tail.push(e.challenge);
				if (e.renewal) tail.push(t('logs.detailRenewal'));
				return tail.length > 0
					? `cert.obtained · ${tail.join(' · ')}`
					: 'cert.obtained';
			}
			case 'cert_failed':
				return e.error
					? `cert.failed · ${truncateError(e.error)}`
					: 'cert.failed';
			case 'cert_ocsp_revoked':
				return `cert.revoked · ${t('logs.detailOcspRevoked')}`;
			default:
				return 'cert.event';
		}
	}

	// Map cert events into the unified row shape (Step U.5).
	//
	// Level mapping (flagged in the U.5 commit body for review):
	//   - cert INFO → 'info' (matches the existing taxonomy
	//     verbatim).
	//   - cert ERROR → 'warn' (pragmatic placement). The
	//     existing LevelTag union doesn't have 'error' — adding
	//     one would introduce a new filter button which the U.5
	//     brief explicitly forbids. 'warn' is the right bucket:
	//     a cert failure is an operational concern that demands
	//     attention but isn't an HTTP-block event (cert events
	//     have no Source IP and no request lifecycle). The U.6
	//     page rename to "Activity log" doesn't change this
	//     mapping; a future taxonomy refactor could introduce a
	//     dedicated 'error' level if operators report that warn
	//     clusters obscure security warnings.
	//
	// Other column conventions:
	//   - method = "ACME" (cert events come from the ACME
	//     issuance pipeline; matches the dim-style "method tag"
	//     the other sources use).
	//   - path = domain (the cert subject — the operator's
	//     primary scan target). search across path + detail
	//     covers domain + issuer keywords.
	//   - code = "—" (em-dash; cert events have no HTTP status).
	//   - srcIp = "(interne)" (system-emitted; the existing
	//     mono-dim styling on the Source IP column renders this
	//     unobtrusively).
	function mapCert(e: CertEvent, idx: number): UnifiedRow {
		return {
			// idx disambiguates against the (timestamp, domain,
			// eventType) tuple colliding when certmagic fires
			// two events for the same domain in the same
			// second (e.g. an OBTAIN + a FAILED race, or two
			// ocsp_revoked checks). See mapAuth above for the
			// full rationale.
			key: `cert-${e.timestamp}-${e.domain}-${e.eventType}-${idx}`,
			ts: e.timestamp,
			level: e.level === 'INFO' ? 'info' : 'warn',
			code: '—',
			source: 'cert',
			method: 'ACME',
			path: e.domain,
			detail: formatCertDetail(e),
			srcIp: '(interne)'
		};
	}

	// W.7 follow-up — humanized French label for the W.1
	// matcher reason enum. Persisted rows only ever carry
	// the two block-reaching values (the other 6 enum
	// values are accept paths or fail-open that don't reach
	// the sink), but the fallback handles any future
	// addition by surfacing the raw code so an operator
	// can still grep journalctl.
	//
	// The raw reason stays as a title="" tooltip on the
	// detail span so forensic ops aren't lost: hover →
	// "allow-miss" / "deny-match" verbatim.
	function humanizeCountryBlockReason(reason: string): string {
		switch (reason) {
			case 'allow-miss':
				return t('logs.countryNotAllowed');
			case 'deny-match':
				return t('logs.countryDenied');
			default:
				return reason;
		}
	}

	// Step W.5 / W.7 follow-up — country-block source
	// mapper. Renders as a block-level entry (the request
	// WAS short-circuited at the Caddy edge). W.5 put the
	// raw routeId UUID in the path column and used a
	// "mode-reason" string in the detail; both were
	// operator-unfriendly. The W.7 follow-up moves the
	// routeId to its own field (rendered via <RouteHost>
	// for the visible host badge), keeps the path slot
	// empty (country-block isn't path-scoped — it gates
	// every request to the matched routes), and uses the
	// humanized reason in the detail.
	function mapCountryBlock(e: CountryBlockEvent): UnifiedRow {
		const country = e.country || '—';
		return {
			key: `country-block-${e.id}`,
			ts: e.ts,
			level: 'block',
			code: String(e.statusCode),
			source: 'country_block',
			method: 'GEO',
			path: '', // host resolution moves to the routeId / <RouteHost>
			detail: `${country} · ${humanizeCountryBlockReason(e.reason)}`,
			// W.7 follow-up — title tooltip surfaces the
			// raw matcher reason code per the brief: forensic
			// ops grep by "allow-miss" / "deny-match" without
			// translation. The mode is implicit in the reason
			// (allow-* / deny-*) so duplicating it would just
			// echo W.5's redundancy.
			detailTitle: e.reason,
			srcIp: e.srcIp,
			routeId: e.routeId
		};
	}

	// Step Z.2 — rate-limit (429) row mapper. Level is 'warn'
	// (not 'block') : 429 is recoverable by retrying after
	// waitMs, distinct from WAF/country-block enforcement.
	// The detail surfaces the wait hint so the operator can
	// gauge sustained pressure ("wait 1.5s" vs "wait 30ms"
	// changes the operational story).
	function mapRateLimit(e: RateLimitEvent): UnifiedRow {
		const waitLabel = e.waitMs > 0 ? `${e.waitMs}ms` : '—';
		return {
			key: `rate-limit-${e.id}`,
			ts: e.ts,
			level: 'warn',
			code: '429',
			source: 'rate_limit',
			// Phase Z.4 — the artificial 'RL' method tag is
			// dropped now that SOURCE renders as its own
			// dedicated badge column. Empty string makes the
			// .log-msg path render the detail directly,
			// matching the country-block row shape.
			method: '',
			path: '',
			detail: `wait ${waitLabel}`,
			detailTitle: e.zone,
			srcIp: e.remoteIp,
			routeId: e.routeId
		};
	}

	async function load(): Promise<void> {
		loadError = null;
		try {
			// Step U.5 / W.5 — 5 parallel sources via
			// Promise.allSettled so any one source's failure
			// (degraded endpoint, 5xx, missed wire-up) doesn't
			// take down the page. Each fulfilled result is
			// mapped into UnifiedRow shape and merged.
			const [waf, throttle, auth, certs, countryBlock, rateLimit] = await Promise.allSettled([
				fetchEvents({ limit: 100 }),
				fetchThrottleEvents({ limit: 100 }),
				fetchAuthFailures('24h'),
				fetchCertEvents({ limit: 100 }),
				fetchCountryBlockEvents({ limit: 100 }),
				fetchRateLimitEvents({ limit: 100 })
			]);

			const merged: UnifiedRow[] = [];
			if (waf.status === 'fulfilled') {
				for (const e of waf.value.events ?? []) merged.push(mapWaf(e));
			}
			if (throttle.status === 'fulfilled') {
				for (const e of throttle.value.events ?? []) merged.push(mapThrottle(e));
			}
			if (auth.status === 'fulfilled') {
				const recent = auth.value.recent ?? [];
				for (let i = 0; i < recent.length; i++) merged.push(mapAuth(recent[i], i));
			}
			if (certs.status === 'fulfilled') {
				const events = certs.value.events ?? [];
				for (let i = 0; i < events.length; i++) merged.push(mapCert(events[i], i));
			}
			if (countryBlock.status === 'fulfilled') {
				for (const e of countryBlock.value.events ?? []) merged.push(mapCountryBlock(e));
			}
			if (rateLimit.status === 'fulfilled') {
				for (const e of rateLimit.value.events ?? []) merged.push(mapRateLimit(e));
			}

			merged.sort((a, b) => (a.ts < b.ts ? 1 : a.ts > b.ts ? -1 : 0));
			rows = merged.slice(0, 200);

			// Phase Z.5.3 — enrich SOURCE IP column with
			// country codes. Collect every distinct IP NOT
			// already in the countryMap cache, batch them in
			// one POST. Cap at the server-side limit (256).
			// Failure is silent : the lookup is non-essential
			// to the activity log itself, and a 5xx here would
			// otherwise inflate loadError and trigger the toast
			// — operator-noisy for a cosmetic enrichment.
			const toResolve = new Set<string>();
			for (const r of rows) {
				if (r.srcIp && !countryMap.has(r.srcIp)) toResolve.add(r.srcIp);
			}
			if (toResolve.size > 0) {
				const ips = Array.from(toResolve).slice(0, 256);
				try {
					const resp = await geoLookupBatch(ips);
					const next = new Map(countryMap);
					for (const [ip, country] of Object.entries(resp.results)) {
						next.set(ip, country);
					}
					countryMap = next;
				} catch {
					// Silent — activity log keeps rendering raw IPs.
				}
			}
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load events';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	function startPolling(): void {
		if (pollId !== null) return;
		pollId = setInterval(() => {
			if (paused) return;
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
			void load();
			// W.7 follow-up — refresh routeMap on the same
			// cadence as the event sources. A newly-created
			// route shows its host on the next refresh
			// without a hard page reload; a deleted route
			// falls out of the map and subsequent rows for
			// that routeId render the UUID fallback.
			void refreshRouteMap();
		}, REFRESH_MS);
	}
	function stopPolling(): void {
		if (pollId !== null) {
			clearInterval(pollId);
			pollId = null;
		}
	}

	function togglePause(): void {
		paused = !paused;
	}

	function fmtTime(iso: string): string {
		try {
			const d = new Date(iso);
			const hh = d.getHours().toString().padStart(2, '0');
			const mm = d.getMinutes().toString().padStart(2, '0');
			const ss = d.getSeconds().toString().padStart(2, '0');
			const ms = d.getMilliseconds().toString().padStart(3, '0');
			return `${hh}:${mm}:${ss}.${ms}`;
		} catch {
			return iso;
		}
	}

	onMount(() => {
		// W.7 follow-up — fire the routeMap refresh in
		// parallel with the first event load. Both are
		// non-blocking; if the routes API hiccups the
		// rows still render with the truncated-UUID
		// fallback in <RouteHost>.
		void refreshRouteMap();
		void load();
		startPolling();
	});
	onDestroy(() => {
		stopPolling();
	});
</script>

<svelte:head>
	<title>Logs · Arenet</title>
</svelte:head>

<!--
  Phase Z.5.7 — page-root flex column. The container
  claims the full available viewport height (set on .app-main
  via the global :has rule below) so the activity area can
  flex-grow without ever overflowing the viewport. Page-
  level scroll is disabled ; the table scrolls internally.
-->
<div class="logs-page">

<PageHeader
	eyebrow={language.current && t('logs.pageEyebrow')}
	title={language.current && t('logs.pageTitle')}
	subtitle={language.current && t('logs.pageSubtitle')}
>
	{#snippet actions()}
		<!-- v2.41 — was a page-local .tb-btn copy of Button. -->
		<Button variant="secondary" size="sm" onclick={togglePause}>
			{language.current && (paused ? t('logs.btnResume') : t('logs.btnPause'))}
		</Button>
		<Button variant="secondary" size="sm" disabled title={language.current && t('logs.btnExportTooltip')}
			>{language.current && t('logs.btnExport')}</Button
		>
	{/snippet}
</PageHeader>

<div class="card filters">
	<div class="filters-row">
		<div class="search-inline">
			<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
				<circle cx="7" cy="7" r="5" />
				<path d="M11 11l3 3" />
			</svg>
			<!-- Phase Z.5.2 — educational placeholder. The
			     `status:5xx route:/auth/* ip:185.142.*`
			     syntax is V2 backlog ; V1 plain substring
			     match indexes source/method/code/path/IP/
			     detail so a literal "5xx" or "429" lookup
			     works today. -->
			<input
				type="search"
				bind:value={search}
				placeholder={language.current && t('logs.filterEventsPlaceholder')}
				aria-label={language.current && t('logs.filterEventsAria')}
			/>
		</div>
		<!-- Phase Z.5.2 — route dropdown. Native <select>
		     styled to match the seg-button row. Single-select
		     V1 ; multi-select V2 backlog. -->
		<select
			class="filter-select"
			bind:value={routeFilter}
			aria-label={language.current && t('logs.filterByRouteAria')}
		>
			<option value="">{language.current && t('logs.filterAllRoutes')}</option>
			{#each routeOptions as r (r.id)}
				<option value={r.id}>{r.host}</option>
			{/each}
		</select>
		<!-- Phase Z.5.2 — HTTP code dropdown. Static enum
		     ordered by operator-triage priority (5xx first,
		     attacks second, healthy last). -->
		<select
			class="filter-select"
			bind:value={codeFilter}
			aria-label={language.current && t('logs.filterByCodeAria')}
		>
			<option value="">{language.current && t('logs.filterAllCodes')}</option>
			{#each httpCodeOptions as opt (opt.value)}
				<option value={opt.value}>{opt.label}</option>
			{/each}
		</select>
		<div class="seg" role="group" aria-label={language.current && t('logs.filterByLevelAria')}>
			<button class:on={levelFilter === 'all'} onclick={() => (levelFilter = 'all')}>{language.current && t('logs.filterLevelAll')}</button>
			<button class:on={levelFilter === 'block'} onclick={() => (levelFilter = 'block')}>{language.current && t('logs.filterLevelBlock')}</button>
			<button class:on={levelFilter === 'detect'} onclick={() => (levelFilter = 'detect')}>{language.current && t('logs.filterLevelDetect')}</button>
			<button class:on={levelFilter === 'warn'} onclick={() => (levelFilter = 'warn')}>{language.current && t('logs.filterLevelWarn')}</button>
			<button class:on={levelFilter === 'info'} onclick={() => (levelFilter = 'info')}>{language.current && t('logs.filterLevelInfo')}</button>
		</div>
		<span class="status-pill" class:paused>
			<span class="dot"></span>
			{language.current && (paused ? t('logs.statusPaused') : t('logs.statusLive'))}
		</span>
	</div>
</div>

<!--
  Phase Z.5.6 — viewport-anchored flex column for the
  activity area. table:histogram 70:30 ratio per the
  operator brief. The wrapper claims the full remaining
  page height so the histogram has a real visual presence
  instead of the prior 80px slim band.
-->
<div class="activity-area">
<div class="card log-card">
	<div class="log-header">
		<span>{language.current && t('logs.colTimestamp')}</span>
		<span>{language.current && t('logs.colLevel')}</span>
		<!-- Phase Z.4 polish — dedicated SOURCE column so
		     operator can scan by signal type without parsing
		     the REQUEST column's method-tag (rate_limit's
		     "RL " prefix specifically was opaque). -->
		<span>{language.current && t('logs.colSource')}</span>
		<span>{language.current && t('logs.colCode')}</span>
		<span>{language.current && t('logs.colRequest')}</span>
		<span class="right">{language.current && t('logs.colSourceIP')}</span>
	</div>
	{#if loading && rows.length === 0}
		<div class="loading-wrap"><Spinner /></div>
	{:else if loadError && rows.length === 0}
		<div class="empty-row">{loadError}</div>
	{:else if filteredRows.length === 0}
		<!-- v2.41 — was one italic line for two different situations.
		     A filter that matched nothing offers a way back; a window
		     with no traffic says what will appear here. -->
		{#if rows.length === 0}
			<EmptyState
				testid="logs-empty"
				title={language.current && t('logs.emptyNoEventsTitle')}
				body={language.current && t('logs.emptyNoEventsBody')}
			/>
		{:else}
			<EmptyState
				tone="filter"
				testid="logs-empty-filtered"
				title={language.current && t('logs.emptyNoMatchTitle')}
				body={language.current && t('logs.emptyNoMatch')}
				actionLabel={language.current && t('logs.emptyClearFilters')}
				onAction={clearLogFilters}
			/>
		{/if}
	{:else}
		<div class="logs">
			{#each filteredRows as r (r.key)}
				{@const isCountryBlock = r.source === 'country_block'}
				{@const src = sourceMeta(r.source)}
				<div class="log-row level-{r.level}" class:level-country-block={isCountryBlock}>
					<span class="log-time">{fmtTime(r.ts)}</span>
					<!--
					  Phase Z.4 cleanup — the level pill now
					  consistently renders the actual level
					  (BLOCK / DETECT / WARN / INFO) across every
					  source. The W.5 "COUNTRY" override on the
					  level pill was an early ad-hoc fix to
					  differentiate country-block from WAF blocks
					  at-a-glance, but it overloaded the level
					  column with source taxonomy. The dedicated
					  SOURCE column below carries that signal
					  honestly now ; the slate tint on
					  .log-row.level-country-block still anchors
					  country-block rows visually for fast scrolls.
					-->
					<span class="log-lvl {r.level}">{r.level.toUpperCase()}</span>
					<!-- Phase Z.4 — SOURCE badge. -->
					<span class="log-src {src.slug}" title={r.source}>{src.label}</span>
					<span class="mono">{r.code}</span>
					<span class="log-msg">
						<span class="k">{r.method}</span>
						{#if r.routeId}
							<!-- W.7 follow-up — per-route sources (waf,
							     country_block) render a resolved host
							     badge instead of the raw routeId UUID.
							     The badge falls back to a truncated UUID
							     when the route was deleted between block
							     time and page load (forensic ops still
							     see the full UUID in the title tooltip).
							     The technical path follows the badge
							     when present (waf carries requestPath;
							     country_block has none, so this branch
							     short-circuits before the redundant
							     separator). -->
							<RouteHost routeId={r.routeId} {routeMap} />
							{#if r.path}
								<span class="k">·</span>
								{r.path}
							{/if}
						{:else if r.path}
							{r.path}
						{/if}
						<span class="k">·</span>
						<span title={r.detailTitle ?? ''}>{r.detail}</span>
						{#if isAdmin && r.wafEvent && isExcludableRule(r.wafEvent.ruleId)}
							{@const ev = r.wafEvent}
							<button
								type="button"
								class="exclude-btn"
								onclick={() => (excludeEvent = ev)}
								aria-label={language.current && t('wafExclude.actionAria', { rule: ev.ruleId })}
								data-testid="waf-exclude-open"
							>
								{language.current && t('wafExclude.action')}
							</button>
						{/if}
					</span>
					<!--
					  Phase Z.5.3 — SOURCE IP enriched with the
					  country code resolved by the batch lookup.
					  The title carries the FULL unmasked IP so
					  forensic ops can still copy-paste the
					  exact source ; the visible label is
					  octet-masked for compactness + shoulder-
					  surfing hygiene.
					-->
					<span class="right mono dim" title={r.srcIp}>
						{formatSourceIP(r.srcIp, countryMap.get(r.srcIp))}
					</span>
				</div>
			{/each}
		</div>
	{/if}
</div>

<WafExcludeDialog
	open={excludeEvent !== null}
	event={excludeEvent}
	host={excludeEvent ? (routeMap.get(excludeEvent.routeId) ?? '') : ''}
	onClose={() => (excludeEvent = null)}
/>

<!--
  Phase Z.5.4 — activity histogram. Stacked bars per
  5-minute bucket, segmented by source. Reflects every
  filter the operator applies via the shared filteredRows
  → histogramCells derived.
-->
<div class="card histogram-card">
	<div class="histogram-header">
		<span>{language.current && t('logs.histogramHeader')}</span>
		<div class="histogram-legend">
			{#each histogramSeries as s (s.key)}
				<span class="legend-item">
					<span class="legend-dot" style:background={s.color}></span>
					{s.label}
				</span>
			{/each}
		</div>
	</div>
	<ActivityHistogram
		cells={histogramCells}
		series={histogramSeries}
		label={language.current && t('logs.histogramAriaLabel')}
		height="fill"
	/>
</div>
</div><!-- /.activity-area -->

</div><!-- /.logs-page -->

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}
	.card.filters {
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.filters-row {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		align-items: center;
	}
	.search-inline {
		flex: 1;
		min-width: 240px;
		display: flex;
		align-items: center;
		gap: 8px;
		background: var(--bg);
		border: 1px solid var(--border);
		padding: 5px 10px;
		border-radius: var(--radius);
		color: var(--fg-muted);
		font-size: 12.5px;
	}
	.search-inline input {
		background: none;
		border: none;
		outline: none;
		flex: 1;
		color: var(--fg);
		font-size: 13px;
	}
	/* Phase Z.5.2 — native <select> filters styled to sit in
	   the same filter-row as .seg without screaming. Browser-
	   native popup keeps a11y + keyboard nav free ; the
	   styling only touches the closed-state appearance. */
	.filter-select {
		appearance: none;
		-webkit-appearance: none;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 999px;
		color: var(--fg);
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.04em;
		padding: 5px 28px 5px 14px;
		cursor: pointer;
		/* Inline chevron SVG. Lives in the background so the
		   native option popup keeps its system-default look. */
		background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 16 16' fill='none' stroke='%238a8e96' stroke-width='1.6'%3E%3Cpath d='M4 6l4 4 4-4'/%3E%3C/svg%3E");
		background-repeat: no-repeat;
		background-position: right 10px center;
		max-width: 220px;
	}
	.filter-select:hover {
		border-color: var(--border-hi);
	}
	.filter-select:focus-visible {
		outline: none;
		border-color: var(--accent-cyan);
	}

	.seg {
		display: inline-flex;
		gap: 2px;
		padding: 2px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10.5px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.seg button {
		padding: 4px 12px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-weight: 500;
	}
	.seg button:hover { color: var(--fg); }
	.seg button.on {
		background: var(--surface-hi);
		color: var(--fg);
		box-shadow: inset 0 0 0 1px var(--border-hi);
	}
	.status-pill {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--status-up);
		padding: 4px 10px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--status-up) 14%, transparent);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.status-pill .dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: currentColor;
		box-shadow: 0 0 6px currentColor;
	}
	.status-pill.paused {
		color: var(--fg-muted);
		background: var(--surface-2);
	}
	.status-pill.paused .dot { box-shadow: none; }


	.log-card { padding: 0; overflow: hidden; }

	/* Phase Z.5.7 — strict viewport fit.
	   The page is a flex column that exactly matches the
	   .app-main height (set by the :global rule below) so
	   there's NO page-level scroll. The PageHeader + filters
	   card take their natural height ; .activity-area
	   claims everything else and itself flex-splits into
	   table (70 %) + histogram (30 %). min-height:0 cascades
	   so children can shrink under content pressure instead
	   of overflowing the viewport. */
	.logs-page {
		display: flex;
		flex-direction: column;
		gap: 12px;
		height: 100%;
		min-height: 0;
	}

	/* Z.5.7 — viewport-fit chain. The whole layout stack
	   needs to be height-strict (not min-height) so the
	   page never grows past the viewport. We use :has() to
	   scope the override to the /logs route only ; other
	   pages keep their pre-Z.5.7 min-height: 100vh + natural
	   page scroll.

	   Browser support : :has() has 90%+ support since 2023
	   (Safari 15.4+, Chrome 105+, Firefox 121+). On legacy
	   browsers the override is ignored ; the page falls back
	   to the natural-scroll layout, which is acceptable
	   degraded behavior.

	   100dvh respects mobile address-bar shifts ; 100vh
	   precedes it as the fallback for older Safari. */
	:global(.app-shell:has(.logs-page)) {
		height: 100vh;
		height: 100dvh;
		min-height: 0;
		overflow: hidden;
	}
	:global(.app-col:has(.logs-page)) {
		min-height: 0;
		overflow: hidden;
	}
	/* box-sizing: border-box on .app-main is load-bearing :
	   .app-main has padding:22px globally and the codebase
	   doesn't set a universal box-sizing reset — without
	   this override the padding would push the content past
	   the bounded parent and re-introduce scroll. */
	:global(.app-main:has(.logs-page)) {
		box-sizing: border-box;
		flex: 1;
		min-height: 0;
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	.activity-area {
		display: flex;
		flex-direction: column;
		gap: 12px;
		flex: 1;
		min-height: 0;
	}

	/* Narrow screens : the strict viewport-fit becomes
	   counterproductive (table squeezed to a few rows
	   under a fat header). Drop the constraint and let
	   the page scroll naturally below ~900px. */
	@media (max-width: 900px) {
		:global(.app-main:has(.logs-page)) {
			height: auto;
			max-height: none;
			overflow: visible;
		}
		.logs-page {
			height: auto;
		}
		.activity-area {
			flex: none;
		}
		.log-card { min-height: 480px; }
		.histogram-card { min-height: 220px; }
	}

	/* Z.5.6 — table claims 70 % of the activity area,
	   histogram 30 %. min-height:0 is load-bearing on flex
	   children so the inner scroll container (.logs) can
	   actually shrink under content pressure instead of
	   pushing the parent past its bound. */
	.log-card {
		flex: 7;
		min-height: 0;
		display: flex;
		flex-direction: column;
	}
	.log-card .logs {
		flex: 1;
		min-height: 0;
	}

	/* Phase Z.5.6 — histogram is now 30 % of the activity
	   area instead of a fixed 80px slim band. The card
	   becomes a flex column so its inner header + chart
	   split correctly ; the chart gets `height="fill"` and
	   claims the leftover space. */
	.histogram-card {
		flex: 3;
		min-height: 0;
		padding: 12px 16px 8px;
		display: flex;
		flex-direction: column;
	}
	.histogram-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--fg-dim);
		margin-bottom: 4px;
		flex-wrap: wrap;
		gap: 8px;
	}
	.histogram-legend {
		display: inline-flex;
		gap: 12px;
		flex-wrap: wrap;
	}
	.legend-item {
		display: inline-flex;
		align-items: center;
		gap: 5px;
	}
	.legend-dot {
		width: 8px;
		height: 8px;
		border-radius: 2px;
		display: inline-block;
	}

	.log-header {
		display: grid;
		grid-template-columns: 120px 78px 100px 60px 1fr 140px;
		gap: 10px;
		padding: 10px 16px;
		border-bottom: 1px solid var(--border);
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--fg-dim);
		background: var(--bg-elevated);
	}
	.log-header .right { text-align: right; }

	.logs {
		font-family: var(--font-mono);
		font-size: 11.5px;
		/* Z.5.6 — the table scroll container's height is
		   now driven by the flex slot (.log-card { flex: 7 }
		   inside .activity-area), so the pre-Z.5.6 hard
		   max-height: 540px would silently clip on tall
		   viewports. We keep overflow-y:auto so long lists
		   still scroll inside the slot. */
		overflow-y: auto;
	}
	.log-row {
		display: grid;
		grid-template-columns: 120px 78px 100px 60px 1fr 140px;
		gap: 10px;
		padding: 6px 16px;
		align-items: baseline;
		color: var(--fg);
		border-bottom: 1px solid var(--border);
	}
	.log-row:last-child { border-bottom: none; }
	.exclude-btn {
		margin-left: 8px;
		background: transparent;
		color: var(--fg-muted, var(--text-muted));
		border: 1px solid var(--border);
		padding: 0 6px;
		border-radius: 4px;
		font-size: 11px;
		cursor: pointer;
	}
	.exclude-btn:hover,
	.exclude-btn:focus-visible {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
		outline: none;
	}
	/* Phase Z.5.1 — row tints dialed down to ~5%
	   (rgba 0.05 mock target). The Z.4 tints at 8% were
	   too punchy on long scrolls — the operator's eye
	   needed a quieter anchor that still preserved the
	   at-a-glance "this row stopped a request" signal. */
	.log-row.level-block { background: color-mix(in oklch, var(--status-down) 5%, transparent); }
	/* W.5 — country-block rows. Override the level-block
	   tint with the --status-meta slate so the operator
	   can distinguish them from WAF blocks at-a-glance. */
	.log-row.level-country-block { background: color-mix(in oklch, var(--status-meta) 5%, transparent); }
	.log-row.level-detect { background: color-mix(in oklch, var(--status-warn) 3%, transparent); }
	/* warn rows (rate-limit 429s, recoverable signals) get
	   NO row tint per Z.5.1 brief — the level pill carries
	   the amber accent ; tinting the whole row was visual
	   over-claim ("something was stopped") on a recoverable
	   throttle. */

	.log-time { color: var(--fg-dim); font-size: 11px; }
	.log-lvl {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 4px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		text-align: center;
		justify-self: start;
	}
	.log-lvl.block { background: color-mix(in oklch, var(--status-down) 18%, transparent); color: var(--status-down); }
	/* W.5 — country-block pill. Slate to match the map
	   legend's gray for "policy enforcement, not threat". */
	.log-lvl.country-block { background: color-mix(in oklch, var(--status-meta) 24%, transparent); color: var(--status-meta); }
	.log-lvl.detect { background: color-mix(in oklch, var(--status-warn) 14%, transparent); color: var(--status-warn); }
	.log-lvl.warn { background: color-mix(in oklch, var(--status-warn) 18%, transparent); color: var(--status-warn); }
	.log-lvl.info { background: color-mix(in oklch, var(--status-info) 18%, transparent); color: var(--status-info); }

	/* Phase Z.5.1 — SOURCE badge. NEUTRAL grey across every
	   source : Z.4 had per-source colors (red WAF, amber
	   rate-limit, purple throttle, ...) which duplicated the
	   severity carried by the LEVEL pill. Two color enums
	   fighting for operator attention on the same row. Z.5
	   promotes LEVEL as the carrier of severity color ;
	   SOURCE stays neutral and only IDs the signal kind.
	   The .log-src.<slug> hooks survive even though every
	   rule is currently the same — keeps the door open for
	   a future per-source icon or border-stripe without
	   re-plumbing. */
	.log-src {
		font-size: 10px;
		padding: 1px 6px;
		border-radius: 4px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		text-align: center;
		justify-self: start;
		font-family: var(--font-mono);
		background: color-mix(in oklch, var(--fg-dim) 18%, transparent);
		color: var(--fg-dim);
	}
	.log-msg { color: var(--fg); min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
	.log-msg .k { color: var(--fg-dim); }
	.right { text-align: right; }
	.mono { font-family: var(--font-mono); }
	.dim { color: var(--fg-dim); }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
	.empty-row { color: var(--fg-muted); font-size: 12.5px; padding: 32px; text-align: center; font-style: italic; }
</style>
