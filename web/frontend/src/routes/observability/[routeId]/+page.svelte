<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step L L.4 — Per-route historical drill-down.

Renders three count charts (req / 4xx / 5xx) plus a two-series
latency chart for one route over the selected window. Linkable from:
  - /observability dashboard top-5 table → "host" cell
  - /topology detail panel footer "Historical →" link
  - direct URL: /observability/<routeId>

Reuses every L.3 primitive — TimelineChart with null-as-gap,
24h/30d window toggle, AC #13 disabled state, AC #7 empty
states, trailing in-progress bucket trim.

v2.65 — the single p95 line became two series, server time and
time with transfer, with a p50/p95/p99 selector. The legacy
p95_latency_ms metric is no longer fetched: it is a mean of
per-bucket percentiles, which is not a percentile. The gap
between the two curves is the diagnosis — on a real instance a
route reading "p95 6701 ms" was 0.1 s of server and 23.9 s of a
visitor downloading a 2.9 MB file.

The AC #5 null-for-gap rule is load-bearing on both latency
series, and MultiSeriesTimelineChart honours it only when passed
nullAsGap: a null plotted at zero would claim the route answered
instantly exactly where nothing was measured.

Viewer-accessible — relies on the API gate (AC #17).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import TimeRange from '$lib/components/TimeRange.svelte';
	import { t } from '$lib/i18n';
	import { bucketUnit } from '$lib/utils/bucket-unit';
	import { language } from '$lib/stores/language.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import MultiSeriesTimelineChart from '$lib/components/MultiSeriesTimelineChart.svelte';
	import { fetchTimeseries } from '$lib/api/metrics';
	import { getRoute } from '$lib/api/client';
	import type {
		MetricWindow,
		MetricQuantile,
		TimeseriesPoint,
		TimeseriesResponse
	} from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import type { Route } from '$lib/api/types';
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
	// The count series hold one bucket's count per point: a minute on
	// 24h, an hour on 30d. The titles said "/ minute" on both.
	let bucketSeconds = $state(60);
	const per = $derived(bucketUnit(bucketSeconds));
	// t() reads the active locale from the module, not from a store,
	// so a derived label has to touch language.current to re-run on a
	// language switch. tl() does that read once instead of repeating
	// `language.current &&` at every call — same helper as the routes
	// page.
	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	// Two latency series instead of one. They answer different
	// questions and the gap between them is the diagnosis: on a real
	// instance a route reading "p95 6701 ms" turned out to be 0.1 s of
	// server and 23.9 s of a visitor downloading a 2.9 MB file. No
	// single line could have said that.
	let totalSeries = $state<TimeseriesPoint[]>([]);
	let ttfbSeries = $state<TimeseriesPoint[]>([]);

	// Which quantile the two lines report. p95 by default, matching
	// what the server returns when the parameter is absent.
	//
	// The selector carries this feature rather than decorating it. At
	// p95 the two lines nearly coincide on both of the operator's
	// routes (212 vs 236 ms, 786 vs 995 ms), because these are
	// percentiles of two different distributions and not two
	// measurements of one request — at the p95 point the transfers are
	// small. The multi-second cases live at p99.
	let quantile = $state<MetricQuantile>('p95');

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		routeNotFound = false;
		try {
			// Fetch the route metadata first; if it 404s, surface
			// a dedicated "route not found" empty state rather
			// than burning four timeseries requests.
			route = await getRoute(routeId);

			// Four independent series in parallel. AC #3: each is
			// its own request, response, and chart — they MUST
			// NOT be folded.
			const [req, fourxx, fivexx, total, ttfb] = await Promise.all([
				fetchTimeseries(routeId, 'req_per_sec', window),
				fetchTimeseries(routeId, 'four_xx_rate', window),
				fetchTimeseries(routeId, 'five_xx_rate', window),
				// total_ms and ttfb_ms read the stored distributions,
				// so they honour the quantile. p95_latency_ms is no
				// longer fetched: it is the legacy scalar, fixed at
				// p95 and computed as a mean of per-bucket
				// percentiles, which is not a percentile.
				fetchTimeseries(routeId, 'total_ms', window, quantile),
				fetchTimeseries(routeId, 'ttfb_ms', window, quantile)
			]);
			disabled = req.disabled === true;
			bucketSeconds = req.bucketSizeSeconds || bucketSeconds;
			reqSeries = trimTrailing(req);
			fourxxSeries = trimTrailing(fourxx);
			fivexxSeries = trimTrailing(fivexx);
			totalSeries = trimTrailing(total);
			ttfbSeries = trimTrailing(ttfb);
		} catch (err) {
			if (err instanceof ApiError && err.status === 404) {
				routeNotFound = true;
			} else {
				loadError = err instanceof ApiError ? err.message : 'failed to load metrics';
				pushToast(loadError, 'danger');
			}
		} finally {
			loading = false;
		}
	}

	/**
	 * Zip the two latency series into the chart's row shape, keyed by
	 * timestamp rather than by index.
	 *
	 * Both series are gap-filled over the same window and step, so the
	 * timestamps do line up today — keying on them anyway means a
	 * future change to either endpoint cannot silently shift one curve
	 * against the other, which would be invisible on screen and
	 * perfectly wrong.
	 *
	 * null is preserved, not coerced: the chart's nullAsGap prop turns
	 * it into a break in the line. A zero here would draw a dip to
	 * "instant" exactly where nothing was measured.
	 */
	const latencyRows = $derived.by(() => {
		const byTs = new Map<string, { bucketStart: string; ttfb: number | null; total: number | null }>();
		for (const p of ttfbSeries) {
			byTs.set(p.ts, { bucketStart: p.ts, ttfb: p.value, total: null });
		}
		for (const p of totalSeries) {
			const row = byTs.get(p.ts);
			if (row) row.total = p.value;
			else byTs.set(p.ts, { bucketStart: p.ts, ttfb: null, total: p.value });
		}
		return Array.from(byTs.values()).sort((a, b) => a.bucketStart.localeCompare(b.bucketStart));
	});

	const latencySeries = $derived([
		{
			key: 'ttfb',
			label: tl('observability.latencySeriesTtfb'),
			color: 'var(--status-info)'
		},
		{
			key: 'total',
			label: tl('observability.latencySeriesTotal'),
			color: 'var(--accent-cyan)'
		}
	]);

	function switchQuantile(q: MetricQuantile): void {
		if (q === quantile) return;
		quantile = q;
		void load();
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
	const fmtMs = (v: number) => `${Math.round(v)} ms`;
</script>

<svelte:head>
	<title>{language.current && t('observability.headTitle')}</title>
</svelte:head>

<PageHeader title={language.current && t('pageTitles.observability')} subtitle={route?.host ?? routeId} />

<div class="back-link">
	<a href="/dashboard">← Dashboard</a>
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
			<h3>{tl('observability.notFoundTitle')}</h3>
			<p>
				{tl('observability.notFoundBefore')}
				<code>{routeId}</code>
				{tl('observability.notFoundMiddle')}
				<a href="/dashboard">{tl('observability.notFoundDashboardLink')}</a>
				{tl('observability.notFoundOr')}
				<a href="/routes">{tl('observability.notFoundRoutesLink')}</a>.
			</p>
		</div>
	</Card>
{:else if disabled}
	<Card>
		<div class="empty-wrap">
			<h3>{tl('observability.disabledTitle')}</h3>
			<p>{tl('observability.disabledBody')}</p>
		</div>
	</Card>
{:else}
	<!-- Window toggle -->
	<div class="window-toggle">
		<TimeRange value={window} options={['24h', '30d']} onChange={switchWindow} testIdPrefix="window" />
		<!-- The numbers say something happened; the log says what. -->
		<a class="logs-link" href="/logs?route={encodeURIComponent(routeId)}">{tl('logs.viewInLogs')}</a>
	</div>

	<!-- Four independent charts. AC #3: req / 4xx / 5xx / p95
	     are SEPARATE visual blocks, never stacked or overlaid.
	     The p95 chart deserves particular attention: null gaps
	     in the series MUST render as breaks in the line, never
	     as 0 ms (AC #5). The TimelineChart guarantees that. -->
	<div class="chart-grid">
		<Card>
			<div class="chart-block">
				<h3 data-testid="obs-title-req">{tl('observability.chartRequests', { per })}</h3>
				<TimelineChart
					points={reqSeries}
					color="var(--accent-cyan)"
					formatValue={fmtCount}
					label={tl('observability.chartRequests', { per })}
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>{tl('observability.chart4xx', { per })}</h3>
				<TimelineChart
					points={fourxxSeries}
					color="var(--status-warn)"
					formatValue={fmtCount}
					label={tl('observability.chart4xx', { per })}
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<h3>{tl('observability.chart5xx', { per })}</h3>
				<TimelineChart
					points={fivexxSeries}
					color="var(--status-down)"
					formatValue={fmtCount}
					label={tl('observability.chart5xx', { per })}
				/>
			</div>
		</Card>
		<Card>
			<div class="chart-block">
				<div class="latency-head">
					<h3>{tl('observability.latencyTitle')}</h3>
					<div
						class="quantile-toggle"
						role="group"
						aria-label={tl('observability.quantileAria')}
					>
						{#each ['p50', 'p95', 'p99'] as const as q (q)}
							<button
								type="button"
								class:active={quantile === q}
								aria-pressed={quantile === q}
								data-testid={`quantile-${q}`}
								onclick={() => switchQuantile(q)}>{q}</button
							>
						{/each}
					</div>
				</div>
				<MultiSeriesTimelineChart
					data={latencyRows}
					series={latencySeries}
					label={tl('observability.latencyAria')}
					formatValue={fmtMs}
					nullAsGap
				/>
				<p class="latency-hint">{tl('observability.latencyHint')}</p>
			</div>
		</Card>
	</div>

	<!-- Route metadata strip — context for the operator who
	     landed directly via a bookmarked URL. -->
	{#if route}
		<Card>
			<div class="meta-block">
				<h3>Route</h3>
				<dl>
					<dt>Host</dt>
					<dd>{route.host}</dd>
					<dt>Upstreams</dt>
					<dd>
						{#each route.upstreams as up, i (i)}
							<code>{up.url}</code>{#if i < route.upstreams.length - 1}, {/if}
						{/each}
					</dd>
					<dt>ID</dt>
					<dd><code>{routeId}</code></dd>
				</dl>
				<!-- M.4 step 3 cross-link: pivot to the security view
				     for this route. Hidden when WAF is off — the
				     security drill-down would just show its AC #10
				     "WAF non activé" panel; offering the link from
				     the perf view would be misleading. -->
				{#if route.wafMode === 'detect' || route.wafMode === 'block'}
					<div class="pivot">
						<a href="/security/{routeId}">
							View security drill-down (WAF events) →
						</a>
					</div>
				{/if}
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
		max-width: 32rem;
		margin: 0 auto;
	}
	.empty-wrap code {
		font-family: var(--font-mono, monospace);
		background: var(--bg-surface);
		padding: 0 0.25rem;
		border-radius: 2px;
		color: var(--text-primary);
	}
	.window-toggle {
		display: flex;
		gap: 0.25rem;
		margin: 0 0 1rem 0;
	}
	.logs-link {
		margin-left: auto;
		align-self: center;
		font-size: var(--text-sm);
		color: var(--accent-cyan);
		text-decoration: none;
	}
	.logs-link:hover {
		text-decoration: underline;
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
	.latency-head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.quantile-toggle {
		display: inline-flex;
		gap: 2px;
	}

	.quantile-toggle button {
		border: 1px solid var(--border);
		background: transparent;
		color: var(--text-secondary);
		font-size: 11px;
		font-variant-numeric: tabular-nums;
		padding: 2px 8px;
		cursor: pointer;
	}

	.quantile-toggle button:first-child {
		border-radius: 4px 0 0 4px;
	}

	.quantile-toggle button:last-child {
		border-radius: 0 4px 4px 0;
	}

	.quantile-toggle button.active {
		background: var(--surface-raised);
		color: var(--text-primary);
		border-color: var(--text-muted);
	}

	.latency-hint {
		margin: 6px 0 0;
		font-size: 11px;
		line-height: 1.45;
		color: var(--text-muted);
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
		margin: 0;
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
</style>
