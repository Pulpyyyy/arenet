<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step M.4 — Per-route security drill-down.

Renders the security view for a single route. Linkable from:
  - /security dashboard top-5 table → host cell
  - /observability/<routeId> page metadata block →
    "View security drill-down →" link (added in M.4 step 3)
  - direct URL: /security/<routeId>

Layout:
  - Page header with the route's host + WAF-mode badge
  - 24h/30d window toggle
  - 4 independent timeline charts (AC #3):
      WAF blocks   — the headline
      4xx          — context
      5xx          — context
      req          — context
    Reuses TimelineChart unchanged (null-as-gap, trailing
    trim, axes, hover). p95 is omitted on purpose — this
    is the security view, not the perf view; the operator
    pivots back to /observability/<routeId> for latency.
  - Per-rule breakdown table: client-side group-by of the
    recent events for this route (rule / category / count /
    last seen). Derived from a single fetchEvents call —
    no new API.
  - Recent events widget filtered to the route (compact
    mode = no route column).
  - Route metadata strip (host, WAF mode, upstreams, ID)
    + a cross-link back to /observability/<routeId> so the
    operator can pivot to the perf view.

States:
  - 404 from getRoute → "Route introuvable" panel.
  - WAF mode = off → AC #10 dedicated "WAF non activé"
    panel (route exists, but the drill-down has nothing to
    show; offer to go edit the route).
  - AC #13 disabled (req.disabled === true) → "Métriques
    indisponibles" panel.
  - WAF enabled but no events in window → charts render
    their in-SVG "no data" label; per-rule table + events
    list show their empty states.

Viewer-accessible per AC #12 (same gate as M.2 endpoints).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import WafEventList from '$lib/components/WafEventList.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { fetchTimeseries } from '$lib/api/metrics';
	import { fetchEvents, fetchEventsByRule } from '$lib/api/security';
	import { getRoute } from '$lib/api/client';
	import type {
		MetricWindow,
		OwaspCategory,
		Route,
		TimeseriesPoint,
		TimeseriesResponse,
		WafEvent,
		WafEventRuleAggregate
	} from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';

	const routeId = $derived(page.params.routeId ?? '');

	let route = $state<Route | null>(null);
	let routeNotFound = $state(false);
	let window = $state<MetricWindow>('24h');
	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let disabled = $state(false);

	let reqSeries = $state<TimeseriesPoint[]>([]);
	let fourxxSeries = $state<TimeseriesPoint[]>([]);
	let fivexxSeries = $state<TimeseriesPoint[]>([]);
	let wafSeries = $state<TimeseriesPoint[]>([]);
	// Step Z.3 — per-route 429 timeseries from the
	// rate_limit_count bucket column. Populated by the Z.1
	// ratelimit.Sink's BumpRateLimitExceeded path (real
	// route UUID, not the throttle sentinel — distinct
	// signal from auth-throttle).
	let rateLimitSeries = $state<TimeseriesPoint[]>([]);
	let recentEvents = $state<WafEvent[]>([]);

	// Per-rule breakdown over the SELECTED window. Populated
	// server-side via /api/v1/security/events/by-rule (M.2
	// amendment #2). The previous client-side group-by on
	// recentEvents silently truncated to the most-recent 100
	// events, which broke the spec §5.4 "over the window"
	// promise on a 30d window. Now consistent with the
	// charts' window semantics.
	let ruleBreakdown = $state<WafEventRuleAggregate[]>([]);

	const wafEnabled = $derived(
		!!route && (route.wafMode === 'block' || route.wafMode === 'detect')
	);

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		routeNotFound = false;
		try {
			// Fetch the route metadata first; 404 → empty state,
			// no point burning further requests.
			route = await getRoute(routeId);

			// WAF-off route gets the AC #10 dedicated panel. Don't
			// fetch series — they'd be all-zero and the panel
			// already tells the operator why.
			if (route.wafMode === 'off') {
				return;
			}

			// 4 timeline series + recent events list + per-rule
			// aggregate, all in parallel. Charts use the per-
			// route timeseries endpoint (NOT route=all — this
			// IS the per-route view). AC #3 holds: each metric
			// is its own request, response, and chart.
			//
			// The per-rule aggregate is a SEPARATE call from
			// the events list because they answer different
			// questions over different scopes:
			//   - events list: 20 most-recent events for the
			//     events feed widget.
			//   - by-rule:     full GROUP BY over the window
			//     so the breakdown table reflects "over the
			//     window" semantics (spec §5.4).
			const [req, fourxx, fivexx, waf, rateLimit, events, byRule] = await Promise.all([
				fetchTimeseries(routeId, 'req_per_sec', window),
				fetchTimeseries(routeId, 'four_xx_rate', window),
				fetchTimeseries(routeId, 'five_xx_rate', window),
				fetchTimeseries(routeId, 'waf_block_rate', window),
				fetchTimeseries(routeId, 'rate_limit_rate', window),
				fetchEvents({ route: routeId, limit: 20 }),
				fetchEventsByRule(routeId, window)
			]);
			disabled = waf.disabled === true;
			reqSeries = trimTrailing(req);
			fourxxSeries = trimTrailing(fourxx);
			fivexxSeries = trimTrailing(fivexx);
			wafSeries = trimTrailing(waf);
			rateLimitSeries = trimTrailing(rateLimit);
			recentEvents = events.events;
			ruleBreakdown = byRule.rows;
		} catch (err) {
			if (err instanceof ApiError && err.status === 404) {
				routeNotFound = true;
			} else {
				loadError = err instanceof ApiError ? err.message : 'failed to load security data';
				pushToast(loadError, 'danger');
			}
		} finally {
			loading = false;
		}
	}

	function trimTrailing(resp: TimeseriesResponse): TimeseriesPoint[] {
		if (resp.points.length === 0) return [];
		return resp.points.slice(0, -1);
	}

	function switchWindow(w: MetricWindow): void {
		if (w === window) return;
		window = w;
		void load();
	}

	onMount(() => {
		void load();
	});

	const fmtCount = (v: number) => Math.round(v).toString();

	// Phase Y — single source of truth via lib/utils/waf-category.
	// Category colour mapping mirrors the dashboard widgets so a
	// category visually identified on /security stays the same
	// colour here.
	import { categoryMeta } from '$lib/utils/waf-category';

	// v2.41 — this page mixed French empty states with English chart
	// headings; every operator-visible string now goes through t().
	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}
</script>

<PageHeader title={language.current && t('pageTitles.securityRoute')} subtitle={route?.host ?? routeId} />

<div class="back-link">
	<a href="/security">{tl('securityRoute.backLink')}</a>
</div>

{#if loading}
	<div class="loading-wrap">
		<Spinner />
	</div>
{:else if loadError}
	<Card>
		<div class="error-wrap">{loadError}</div>
	</Card>
{:else if routeNotFound}
	<Card>
		<div class="empty-wrap">
			<h3>{tl('securityRoute.notFoundTitle')}</h3>
			<p>
				{tl('securityRoute.notFoundBefore')}
				<code>{routeId}</code>
				{tl('securityRoute.notFoundMiddle')}
				<a href="/security">{tl('securityRoute.notFoundOverviewLink')}</a>
				{tl('securityRoute.notFoundOr')}
				<a href="/routes">{tl('securityRoute.notFoundRoutesLink')}</a>.
			</p>
		</div>
	</Card>
{:else if !wafEnabled}
	<!-- AC #10 dedicated empty state for a WAF-off route. -->
	<Card>
		<div class="empty-wrap">
			<h3>{tl('securityRoute.wafOffTitle')}</h3>
			<p>
				{tl('securityRoute.wafOffBefore')}
				<strong>{route?.host}</strong>
				{tl('securityRoute.wafOffMiddle')}
				<a href={`/routes?edit=${encodeURIComponent(routeId)}`}>{tl('securityRoute.wafOffRoutesLink')}</a>
				{tl('securityRoute.wafOffAfter')}
			</p>
		</div>
	</Card>
{:else if disabled}
	<Card>
		<div class="empty-wrap">
			<h3>{tl('securityRoute.disabledTitle')}</h3>
			<p>{tl('securityRoute.disabledBody')}</p>
		</div>
	</Card>
{:else}
	<!-- Window toggle + WAF mode badge -->
	<div class="header-row">
		<div class="window-toggle">
			<button
				type="button"
				class:active={window === '24h'}
				onclick={() => switchWindow('24h')}>24h</button
			>
			<button
				type="button"
				class:active={window === '30d'}
				onclick={() => switchWindow('30d')}>{tl('securityRoute.window30d')}</button
			>
		</div>
		<div class="waf-badge waf-{route?.wafMode ?? 'off'}">
			WAF: {route?.wafMode}
		</div>
	</div>

	<!-- 4 independent charts. AC #3. WAF first — the headline. -->
	<div class="chart-grid">
		<Card>
			<div class="chart-block">
				<h3>{tl('securityRoute.chartWafBlocks')}</h3>
				<TimelineChart
					points={wafSeries}
					color="var(--status-down)"
					formatValue={fmtCount}
					label={tl('securityRoute.chartWafBlocksAria')}
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>{tl('securityRoute.chart4xx')}</h3>
				<TimelineChart
					points={fourxxSeries}
					color="var(--status-warn)"
					formatValue={fmtCount}
					label={tl('securityRoute.chart4xxAria')}
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>{tl('securityRoute.chart5xx')}</h3>
				<TimelineChart
					points={fivexxSeries}
					color="var(--status-down)"
					formatValue={fmtCount}
					label={tl('securityRoute.chart5xxAria')}
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>{tl('securityRoute.chartRequests')}</h3>
				<TimelineChart
					points={reqSeries}
					color="var(--accent-cyan)"
					formatValue={fmtCount}
					label={tl('securityRoute.chartRequestsAria')}
				/>
			</div>
		</Card>
		<!-- Step Z.3 — per-route 429 timeseries. Captured by
		     the ratelimit.Sink off the mholt/caddy-ratelimit
		     "rate_limit_exceeded" event. Drawn in amber : 429
		     is a recoverable throttle signal (level=warn on the
		     activity log), distinct from the red WAF/4xx/5xx
		     enforcement signals above. -->
		<Card>
			<div class="chart-block">
				<h3>{tl('securityRoute.chartRateLimit')}</h3>
				<TimelineChart
					points={rateLimitSeries}
					color="var(--status-warn)"
					formatValue={fmtCount}
					label={tl('securityRoute.chartRateLimitAria')}
				/>
			</div>
		</Card>
	</div>

	<!-- Per-rule breakdown table (M.4 step 2) -->
	<Card>
		<div class="block">
			<h3>{tl('securityRoute.rulesTitle')}</h3>
			{#if ruleBreakdown.length === 0}
				<div class="empty-inline">{tl('securityRoute.rulesEmpty')}</div>
			{:else}
				<table>
					<thead>
						<tr>
							<th>{tl('securityRoute.colRule')}</th>
							<th>{tl('securityRoute.colCategory')}</th>
							<th class="num">{tl('securityRoute.colCount')}</th>
							<th>{tl('securityRoute.colLastSeen')}</th>
						</tr>
					</thead>
					<tbody>
						{#each ruleBreakdown as row (row.ruleId)}
							<tr>
								<td class="mono">{row.ruleId}</td>
								<td>
									<span
										class="badge"
										style:background={categoryMeta(row.category).color}
									>
										{row.category}
									</span>
								</td>
								<td class="num">{row.count}</td>
								<td class="ts">{relativeTs(row.lastSeen)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>
	</Card>

	<!-- Recent events (route-scoped, compact = no route column) -->
	<Card>
		<div class="block">
			<h3>{tl('securityRoute.recentTitle')}</h3>
			<WafEventList events={recentEvents} compact host={route?.host ?? routeId} onExcluded={() => void load()} />
		</div>
	</Card>

	<!-- Route metadata + pivot to perf view -->
	{#if route}
		<Card>
			<div class="meta-block">
				<h3>{tl('securityRoute.routeTitle')}</h3>
				<dl>
					<dt>{tl('securityRoute.routeHost')}</dt>
					<dd>{route.host}</dd>
					<dt>{tl('securityRoute.routeWafMode')}</dt>
					<dd><code>{route.wafMode}</code></dd>
					<dt>{tl('securityRoute.routeUpstreams')}</dt>
					<dd>
						{#each route.upstreams as up, i (i)}
							<code>{up.url}</code
							>{#if i < route.upstreams.length - 1},
							{/if}
						{/each}
					</dd>
					<dt>ID</dt>
					<dd><code>{routeId}</code></dd>
				</dl>
				<div class="pivot">
					<a href="/observability/{routeId}">{tl('securityRoute.perfPivot')}</a>
				</div>
				<!-- The recent list above stops at 20 WAF events; the
				     log goes further and adds rate-limit and country
				     blocks for this route. -->
				<div class="pivot">
					<a href="/logs?route={encodeURIComponent(routeId)}">{tl('logs.viewInLogs')}</a>
				</div>
			</div>
		</Card>
	{/if}
{/if}

<style>
	.back-link {
		margin: 0 0 0.75rem 0;
		font-size: var(--text-sm);
	}
	.back-link a {
		color: var(--accent-cyan);
		text-decoration: none;
	}
	.back-link a:hover {
		text-decoration: underline;
	}
	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 2rem;
	}
	.error-wrap {
		padding: 1rem;
		color: var(--status-down);
	}
	.empty-wrap {
		padding: 1.5rem;
		text-align: center;
	}
	.empty-wrap h3 {
		font-size: var(--text-lg);
		margin: 0 0 0.5rem 0;
		color: var(--text-primary);
	}
	.empty-wrap p {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		max-width: 36rem;
		margin: 0 auto;
	}
	.empty-wrap code {
		font-family: var(--font-mono, monospace);
		background: var(--bg-surface);
		padding: 0 0.25rem;
		border-radius: 2px;
		color: var(--text-primary);
	}
	.header-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin: 0 0 1rem 0;
		gap: 0.75rem;
	}
	.window-toggle {
		display: flex;
		gap: 0.25rem;
	}
	.window-toggle button {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.window-toggle button.active {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border-color: var(--accent-cyan);
	}
	.waf-badge {
		font-family: var(--font-mono, monospace);
		font-size: var(--text-xs, 11px);
		padding: 0.15rem 0.55rem;
		border-radius: 3px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-on-color, #ffffff);
	}
	.waf-block {
		background: var(--status-down);
	}
	.waf-detect {
		background: var(--status-warn);
	}
	.waf-off {
		background: var(--text-muted);
	}
	.block {
		padding: 1rem;
	}
	.block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.chart-grid {
		display: grid;
		grid-template-columns: 1fr;
		gap: 0.75rem;
		margin: 0 0 1rem 0;
	}
	@media (min-width: 1200px) {
		.chart-grid {
			grid-template-columns: repeat(2, 1fr);
		}
	}
	.chart-block {
		padding: 1rem;
	}
	.chart-block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	th,
	td {
		padding: 0.5rem 0.75rem;
		text-align: left;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
		vertical-align: middle;
	}
	th {
		color: var(--text-secondary);
		font-weight: 500;
		font-size: var(--text-xs);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	td {
		color: var(--text-primary);
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.num {
		text-align: right;
		font-variant-numeric: tabular-nums;
	}
	.ts {
		font-family: var(--font-mono, monospace);
		color: var(--text-secondary);
		white-space: nowrap;
	}
	.badge {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 3px;
		color: var(--text-on-color, #ffffff);
		font-size: var(--text-xs, 11px);
		font-weight: 600;
		letter-spacing: 0.04em;
	}
	.meta-block {
		padding: 1rem;
	}
	.meta-block h3 {
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-secondary);
		margin: 0 0 0.75rem 0;
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.meta-block dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 0.5rem 1rem;
		margin: 0 0 0.75rem 0;
		font-size: var(--text-sm);
	}
	.meta-block dt {
		color: var(--text-secondary);
	}
	.meta-block dd {
		color: var(--text-primary);
		margin: 0;
		word-break: break-all;
	}
	.meta-block code {
		font-family: var(--font-mono, monospace);
		background: var(--bg-surface);
		padding: 0 0.25rem;
		border-radius: 2px;
	}
	.pivot {
		margin-top: 0.75rem;
		font-size: var(--text-sm);
	}
	.pivot a {
		color: var(--accent-cyan);
		text-decoration: none;
	}
	.pivot a:hover {
		text-decoration: underline;
	}
	.empty-inline {
		padding: 0.75rem;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
</style>
