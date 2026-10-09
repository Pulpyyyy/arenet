<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.1 — Dashboard. Replaces the R.2 stub with the mock's
  layout at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
  :749-948.

  Sources for each block (real backend, AC #1 anti-regression):
  - 4 KPI tiles: GET /api/v1/metrics/summary (Step L) — req/s,
    p95, 5xx rate, WAF blocks per hour.
  - Traffic chart: GET /api/v1/metrics/timeseries with switchable
    metric (req_per_sec / p95_latency_ms / five_xx_rate). The
    existing TimelineChart component handles the rendering; the
    new wrapper card mirrors the mock's segmented switcher.
  - WAF events recent: GET /api/v1/security/events (Step M).
  - Top routes: summary.topRoutes (Step L).
  - Upstreams flat list: GET /api/v1/routes flattened per upstream
    URL. The mock's "Services amont" card aggregates by service
    name with per-service health; we ship the per-upstream-URL
    variant in v1.4 because per-service-name aggregation +
    health-rollup is not a backend feature today (tracked as a
    R.5 backlog candidate).
  - The "Live tail" card that used to close the page repeated the
    same five WAF events as the recent-events card, in UTC while
    the rest of the page reads local time. It is gone; its "Open
    Logs →" link moved to the recent-events card header, which is
    the one place those events are shown.

  Each KPI tile links to the page behind its number, and the
  alarm-type ones (5xx, WAF blocks, expiring / failed certs) take
  the warn tone when above zero.

  Empty + disabled states preserved from Step L:
  - disabled (summary.disabled=true): single panel, no charts.
  - noRoutes (0 routes): clean message + link to /routes.
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { fetchSummary, fetchTimeseries } from '$lib/api/metrics';
	import { fetchEvents as fetchWafEvents, fetchCertEventsAggregate } from '$lib/api/security';
	import { certificatesApi } from '$lib/api/certificates';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Spinner from '$lib/components/Spinner.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import TimelineChart from '$lib/components/TimelineChart.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import { bucketUnit } from '$lib/utils/bucket-unit';
	import MultiSeriesTimelineChart from '$lib/components/MultiSeriesTimelineChart.svelte';
	import type {
		Certificate,
		CertEventBucket,
		SummaryResponse,
		TimeseriesPoint,
		WafEvent,
		Route,
		MetricName,
		MetricWindow
	} from '$lib/api/types';

	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let summary = $state<SummaryResponse | null>(null);
	let recentEvents = $state<WafEvent[]>([]);
	let routes = $state<Route[]>([]);
	let chartMetric = $state<MetricName>('req_per_sec');
	let chartPoints = $state<TimeseriesPoint[]>([]);
	let chartLoading = $state(false);
	// The series are counts per bucket, not per second: the unit is the
	// bucket, read from the response (see lib/utils/bucket-unit).
	let chartBucketSeconds = $state(60);
	// A failed fetch used to toast and leave the PREVIOUS metric's
	// points under the new metric's button and colour.
	let chartError = $state<string | null>(null);
	// Only the latest request may write: a fast switch could otherwise
	// land an older metric's answer last.
	let chartSeq = 0;
	const window: MetricWindow = '24h';

	// The subtitle said "real-time" over data read once at load. The
	// page now refreshes quietly and says when it last did.
	const REFRESH_MS = 60_000;
	let lastUpdatedAt = $state<Date | null>(null);
	let refreshFailed = $state(false);

	// Phase 5 — cert lifecycle data. certificates feeds the
	// total + "expiring in 30d" KPI cards; certBuckets feeds
	// the chart; certFailed7d feeds the third KPI card. All
	// three are best-effort — degraded mode + fetch error
	// both collapse to zero counts / empty chart rather than
	// breaking the dashboard.
	let certificates = $state<Certificate[]>([]);
	let certBuckets = $state<CertEventBucket[]>([]);
	let certFailed7d = $state(0);

	const disabled = $derived(summary?.disabled === true);
	const noRoutes = $derived(!disabled && routes.length === 0);

	// 4 KPI derivations from the summary response.
	// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — pre-fix the
	// summary endpoint returned just-closed-minute counters
	// and the frontend multiplied by 60 (for "/h") or
	// 60×24 (for "/24h") to project rates. On bursty
	// homelab traffic the just-closed minute was often
	// empty, surfacing as zero everywhere. Post-fix the
	// summary returns 24h totals directly; the frontend
	// reads them raw (no projection).
	//
	// req/s is derived by dividing the 24h total by the
	// window length in seconds (windowSeconds = 86400).
	// The displayed average isn't instantaneous traffic
	// but a 24h-average rate, which is what an operator
	// reading the card actually wants to know about
	// sustained activity.
	const kpiReqPerSec = $derived.by(() => {
		const total = summary?.totalReq ?? 0;
		const win = summary?.windowSeconds ?? 86400;
		if (win <= 0) return 0;
		return Math.round((total / win) * 10) / 10;
	});
	const kpiP95 = $derived(summary?.globalP95LatencyMs ?? null);
	const kpi5xxPct = $derived(
		(() => {
			const req = summary?.totalReq ?? 0;
			const fivexx = summary?.totalFiveXx ?? 0;
			if (req <= 0) return 0;
			return Math.round((fivexx / req) * 10000) / 100;
		})()
	);
	// Two parallel WAF tiles. Values are 24h absolute
	// counts (no rate projection); the labels read
	// "/ 24h" to match the wire semantics.
	const kpiWafBlocked24h = $derived(summary?.totalWafBlocked ?? 0);
	const kpiWafDetected24h = $derived(summary?.totalWafDetected ?? 0);

	// Phase 5 — cert KPI derivations.
	const kpiCertTotal = $derived(certificates.length);
	const kpiCertExpiringSoon = $derived.by(() => {
		const horizon = Date.now() + 30 * 24 * 60 * 60 * 1000;
		return certificates.filter((c) => {
			const t = new Date(c.notAfter).getTime();
			return !isNaN(t) && t < horizon;
		}).length;
	});
	const kpiCertFailed7d = $derived(certFailed7d);

	// Alarm-type tiles take the warn tone above zero. The 5xx tile reads
	// the raw count, not the rounded percentage: one 5xx in a busy day
	// rounds to 0.00 % and would otherwise go unflagged.
	function alarmTone(n: number): 'default' | 'warn' {
		return n > 0 ? 'warn' : 'default';
	}

	// The chart's series definition lives at module scope
	// so the operator's theme-token references stay readable.
	// status-up / accent-cyan / status-down map respectively
	// to the green/blue/red triad the operator brief asked for.
	const certChartSeries = $derived(
		language.current
			? [
					{ key: 'issued' as const, label: t('dashboard.certChartIssued'), color: 'var(--status-up)' },
					{ key: 'renewed' as const, label: t('dashboard.certChartRenewed'), color: 'var(--accent-cyan)' },
					{ key: 'failed' as const, label: t('dashboard.certChartFailed'), color: 'var(--status-down)' }
				]
			: [
					{ key: 'issued' as const, label: 'Issued', color: 'var(--status-up)' },
					{ key: 'renewed' as const, label: 'Renewed', color: 'var(--accent-cyan)' },
					{ key: 'failed' as const, label: 'Failed', color: 'var(--status-down)' }
				]
	);

	// Distinct upstream URLs across all routes — the v1.4 stand-in
	// for the mock's per-service-name aggregation. The card shows the
	// first UPSTREAMS_SHOWN; the header used to print that slice's
	// length as if it were the total.
	const UPSTREAMS_SHOWN = 8;
	const allUpstreams = $derived(
		(() => {
			const seen = new Set<string>();
			const result: Array<{ url: string; routes: string[] }> = [];
			for (const r of routes) {
				for (const u of r.upstreams ?? []) {
					if (seen.has(u.url)) {
						const existing = result.find((x) => x.url === u.url);
						existing?.routes.push(r.host);
					} else {
						seen.add(u.url);
						result.push({ url: u.url, routes: [r.host] });
					}
				}
			}
			return result;
		})()
	);
	const upstreams = $derived(allUpstreams.slice(0, UPSTREAMS_SHOWN));

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			// Phase 5 — cert calls are best-effort: a failure
			// must NOT take down the dashboard, the existing
			// KPIs / chart / WAF panel stay valuable on a fresh
			// install with zero certificates. .catch returns
			// the empty-shape default so the destructure stays
			// safe.
			const [rs, sum, evs, certs, certAgg, failed7d] = await Promise.all([
				listRoutes(),
				fetchSummary(),
				fetchWafEvents({ limit: 5 }).catch(() => ({ events: [] })),
				certificatesApi.list().catch(() => [] as Certificate[]),
				fetchCertEventsAggregate({ windowDays: 30, intervalHours: 24 }).catch(() => ({
					buckets: [] as CertEventBucket[]
				})),
				fetchCertEventsAggregate({ windowDays: 7, intervalHours: 24 }).catch(() => ({
					buckets: [] as CertEventBucket[]
				}))
			]);
			routes = rs;
			summary = sum;
			recentEvents = evs.events ?? [];
			certificates = certs;
			certBuckets = certAgg.buckets ?? [];
			// Sum failed across the 7d window — one round-trip
			// to the same aggregate endpoint, no extra surface.
			certFailed7d = (failed7d.buckets ?? []).reduce((acc, b) => acc + (b.failed ?? 0), 0);
			lastUpdatedAt = new Date();
			refreshFailed = false;
			if (!sum.disabled) {
				void loadChart();
			}
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load dashboard';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	async function loadChart(quiet = false): Promise<void> {
		const seq = ++chartSeq;
		if (!quiet) chartLoading = true;
		try {
			const resp = await fetchTimeseries('all', chartMetric, window);
			if (seq !== chartSeq) return;
			// Drop the in-progress last point (#L.2-2 trailing bucket).
			chartPoints = resp.points.length > 0 ? resp.points.slice(0, -1) : [];
			chartBucketSeconds = resp.bucketSizeSeconds || chartBucketSeconds;
			chartError = null;
		} catch (err) {
			if (seq !== chartSeq) return;
			// A quiet refresh keeps the series on screen; the header
			// says the refresh failed.
			if (quiet) {
				refreshFailed = true;
				return;
			}
			chartPoints = [];
			chartError = err instanceof ApiError ? err.message : t('dashboard.chartLoadFailed');
		} finally {
			if (seq === chartSeq) chartLoading = false;
		}
	}

	// Quiet: no page spinner, and a failure keeps what is on screen
	// and marks the header instead of replacing the page with an error.
	async function refresh(): Promise<void> {
		try {
			const [rs, sum, evs] = await Promise.all([
				listRoutes(),
				fetchSummary(),
				fetchWafEvents({ limit: 5 }).catch(() => ({ events: recentEvents }))
			]);
			routes = rs;
			summary = sum;
			recentEvents = evs.events ?? [];
			lastUpdatedAt = new Date();
			refreshFailed = false;
			if (!sum.disabled) void loadChart(true);
		} catch {
			refreshFailed = true;
		}
	}

	const chartUnitLabel = $derived(
		language.current &&
			(chartMetric === 'p95_latency_ms'
				? t('dashboard.chartUnitLatency')
				: t(chartMetric === 'five_xx_rate' ? 'dashboard.chartUnit5xx' : 'dashboard.chartUnitRequests', {
						per: bucketUnit(chartBucketSeconds)
					}))
	);

	function switchMetric(m: MetricName): void {
		if (m === chartMetric) return;
		chartMetric = m;
		void loadChart();
	}

	function fmtP95(v: number | null): string {
		return v === null ? '—' : `${Math.round(v)}`;
	}

	// v2.9.22 i18n — delegate to the shared relativeTime helper so
	// the dashboard footers ("2 hours ago" / "il y a 2 heures") respect
	// the active language preference instead of being locked to FR.
	function fmtRelative(iso: string): string {
		return relativeTime(iso);
	}

	function chartColor(m: MetricName): string {
		switch (m) {
			case 'req_per_sec':
				return 'var(--accent)';
			case 'p95_latency_ms':
				return 'var(--status-info)';
			case 'five_xx_rate':
				return 'var(--status-down)';
			default:
				return 'var(--accent)';
		}
	}

	let refreshId: ReturnType<typeof setInterval> | null = null;
	onMount(() => {
		void load();
		refreshId = setInterval(() => {
			if (loading || document.visibilityState !== 'visible') return;
			void refresh();
		}, REFRESH_MS);
	});
	onDestroy(() => {
		if (refreshId !== null) clearInterval(refreshId);
	});
</script>

<svelte:head>
	<title>{language.current && t('dashboard.headTitle')}</title>
</svelte:head>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else if loadError}
	<div class="card error">{loadError}</div>
{:else if disabled}
	<PageHeader
		eyebrow={language.current && t('dashboard.eyebrow')}
		title={language.current && t('pageTitles.dashboard')}
	/>
	<div class="card empty">
		<h3>{language.current && t('dashboard.disabledTitle')}</h3>
		<p>{language.current && t('dashboard.disabledBody')}</p>
	</div>
{:else if noRoutes}
	<PageHeader
		eyebrow={language.current && t('dashboard.eyebrow')}
		title={language.current && t('pageTitles.dashboard')}
	/>
	<div class="card empty">
		<h3>{language.current && t('dashboard.noRoutesTitle')}</h3>
		<p>
			{language.current && t('dashboard.noRoutesBodyBefore')}
			<a href="/routes">{language.current && t('dashboard.noRoutesBodyLink')}</a>
			{language.current && t('dashboard.noRoutesBodyAfter')}
		</p>
	</div>
{:else}
	<PageHeader
		eyebrow={language.current && t('dashboard.eyebrow')}
		title={language.current && t('pageTitles.dashboard')}
		subtitle={language.current && t('dashboard.subtitle', { count: routes.length, window })}
	>
		{#snippet actions()}
			{#if lastUpdatedAt}
				<span class="updated-at" class:failed={refreshFailed} data-testid="dashboard-updated-at">
					{language.current &&
						t(refreshFailed ? 'dashboard.updatedAtFailed' : 'dashboard.updatedAt', {
							time: lastUpdatedAt.toLocaleTimeString(language.current)
						})}
				</span>
			{/if}
		{/snippet}
	</PageHeader>

	<!-- KPIs -->
	<!-- v2.41 — the eight tiles were a scoped-CSS copy of StatCard,
	     which now carries this exact treatment plus the unit and the
	     foot line the copy had and it lacked. -->
	<div class="kpis">
		<!--
			Each tile leads to the page behind its number. Traffic,
			latency and 5xx go to /routes, where each route's panel
			breaks them down: /logs is the security-event log, it holds
			no access log and so no 5xx to filter on.
		-->
		<StatCard
			testid="kpi-req-per-sec"
			href="/routes"
			label={language.current && t('dashboard.kpiReqPerSec')}
			value={kpiReqPerSec}
			unit="req/s"
			hint={language.current && t('dashboard.kpiReqPerSecFoot', { total: summary?.totalReq ?? 0, routes: summary?.activeRouteCount ?? 0 })}
		/>
		<StatCard
			testid="kpi-p95"
			href="/routes"
			label={language.current && t('dashboard.kpiP95')}
			value={fmtP95(kpiP95)}
			unit="ms"
			hint={language.current && (kpiP95 === null ? t('dashboard.kpiP95FootNoData') : t('dashboard.kpiP95FootData'))}
		/>
		<StatCard
			testid="kpi-5xx"
			href="/routes"
			tone={alarmTone(summary?.totalFiveXx ?? 0)}
			label={language.current && t('dashboard.kpi5xxRate')}
			value={kpi5xxPct}
			unit="%"
			hint={language.current && t('dashboard.kpi5xxRateFoot', { five: summary?.totalFiveXx ?? 0, four: summary?.totalFourXx ?? 0 })}
		/>
		<!--
			#R-DASHBOARD-WAF-COUNTERS-ZERO + #R-WAF-METRICS-
			WINDOW-1MIN-PROJECTION — two parallel tiles showing
			24h absolute counts. Blocked reads the canonical
			block counter; Detected reads the detect counter so
			detect-mode activity stays visible on homelab routes
			using the wafMode=detect default.
		-->
		<StatCard
			testid="kpi-waf-blocked"
			href="/waf"
			tone={alarmTone(kpiWafBlocked24h)}
			label={language.current && t('dashboard.kpiWafBlocked')}
			value={kpiWafBlocked24h}
			hint={language.current && t('dashboard.kpiWafBlockedFoot', { ips: summary?.attackerIpsUnique ?? 0, throttle: summary?.totalThrottle ?? 0, rl: summary?.totalRateLimitExceeded ?? 0 })}
		/>
		<StatCard
			testid="kpi-waf-detected"
			href="/waf"
			label={language.current && t('dashboard.kpiWafDetected')}
			value={kpiWafDetected24h}
			hint={language.current && t('dashboard.kpiWafDetectedFoot')}
		/>
		<!--
			Phase 5 — cert KPIs. The three tiles split the cert
			lifecycle into "what's deployed", "what's expiring",
			"what's failing" — the operator brief's triad.
		-->
		<StatCard
			testid="kpi-cert-total"
			href="/certs"
			label={language.current && t('dashboard.kpiCertTotal')}
			value={kpiCertTotal}
			hint={language.current && t('dashboard.kpiCertTotalFoot')}
		/>
		<StatCard
			testid="kpi-cert-expiring"
			href="/certs"
			tone={alarmTone(kpiCertExpiringSoon)}
			label={language.current && t('dashboard.kpiCertExpiring')}
			value={kpiCertExpiringSoon}
			hint={language.current && (kpiCertExpiringSoon === 0 ? t('dashboard.kpiCertExpiringFootZero') : t('dashboard.kpiCertExpiringFootWatch'))}
		/>
		<StatCard
			testid="kpi-cert-failed-7d"
			href="/certs"
			tone={alarmTone(kpiCertFailed7d)}
			label={language.current && t('dashboard.kpiCertFailed7d')}
			value={kpiCertFailed7d}
			hint={language.current && (kpiCertFailed7d === 0 ? t('dashboard.kpiCertFailedFootZero') : t('dashboard.kpiCertFailedFootInvestigate'))}
		/>
	</div>

	<!-- Main row: traffic chart + WAF events recent -->
	<div class="two-col main-row">
		<div class="card">
			<div class="card-h">
				<h3>
					{language.current && t('dashboard.trafficCardTitle', { window })}
					<span class="chart-unit" data-testid="chart-unit">{chartUnitLabel}</span>
				</h3>
				<div class="seg">
					<button
						class:on={chartMetric === 'req_per_sec'}
						onclick={() => switchMetric('req_per_sec')}>{language.current && t('dashboard.trafficBtnReq')}</button
					>
					<button
						class:on={chartMetric === 'p95_latency_ms'}
						onclick={() => switchMetric('p95_latency_ms')}>{language.current && t('dashboard.trafficBtnLatency')}</button
					>
					<button
						class:on={chartMetric === 'five_xx_rate'}
						onclick={() => switchMetric('five_xx_rate')}>{language.current && t('dashboard.trafficBtnErrors')}</button
					>
				</div>
			</div>
			<div class="chart-wrap">
				{#if chartLoading}
					<div class="chart-loading"><Spinner size="sm" /></div>
				{:else if chartError}
					<p class="chart-error" role="alert" data-testid="chart-error">{chartError}</p>
				{:else}
					<TimelineChart
						points={chartPoints}
						color={chartColor(chartMetric)}
						label={`Series for ${chartMetric}`}
					/>
				{/if}
			</div>
		</div>

		<div class="card">
			<div class="card-h">
				<h3>{language.current && t('dashboard.recentWafCardTitle')}</h3>
				<div class="meta">
					{language.current && t('dashboard.recentWafCardMeta')} ·
					<a href="/logs" class="meta-link">{language.current && t('dashboard.recentWafOpenLogs')}</a>
				</div>
			</div>
			<div class="stack">
				{#each recentEvents as ev (ev.id)}
					<!--
						#R-WAF-EVENT-LABEL-INCONSISTENT — read
						ev.action instead of hardcoding "block".
						Pre-fix every event surfaced as a "block"
						pill regardless of whether the WAF actually
						rejected the request (BLOCK) or merely
						matched the rule and let it pass (DETECT).
						The Step W.bugfix migration backfilled
						legacy rows to "BLOCK" so old data still
						renders correctly.
					-->
					<div class="event" data-testid="recent-event-{ev.id}">
						<span class="pill {ev.action === 'DETECT' ? 'warn' : 'bad'}">
							{language.current && (ev.action === 'DETECT' ? t('dashboard.recentWafPillDetect') : t('dashboard.recentWafPillBlock'))}
						</span>
						<div class="what">
							<b>{ev.category} · {ev.ruleId}</b>
							<span>{language.current && t('dashboard.recentWafFromIp', { method: ev.requestMethod, path: ev.requestPath, ip: ev.srcIp })}</span>
						</div>
						<div class="when" title={new Date(ev.ts).toLocaleString(language.current)}>
							{fmtRelative(ev.ts)}
						</div>
					</div>
				{:else}
					<div class="empty-row">{language.current && t('dashboard.recentWafEmpty')}</div>
				{/each}
			</div>
		</div>
	</div>

	<!--
		Phase 5 — cert lifecycle panel. Sits between the main
		traffic / WAF row and the bottom routes / upstreams row.
		Three series: issued (fresh certs), renewed (renewals),
		failed. Legend is click-to-toggle; tooltip on hover.
	-->
	<div class="card" data-testid="cert-lifecycle-panel">
		<div class="card-h">
			<h3>{language.current && t('dashboard.certLifecycleTitle')}</h3>
			<div class="meta">{language.current && t('dashboard.certLifecycleMeta')}</div>
		</div>
		<div class="chart-wrap">
			<MultiSeriesTimelineChart
				data={certBuckets}
				series={certChartSeries}
				label={language.current && t('dashboard.certLifecycleAria')}
				height={180}
			/>
		</div>
	</div>

	<!-- Bottom row: top routes + upstreams -->
	<div class="two-col bottom-row">
		<div class="card">
			<div class="card-h">
				<h3>{language.current && t('dashboard.topRoutesTitle')}</h3>
				<div class="meta">{language.current && t('dashboard.topRoutesMeta')}</div>
			</div>
			<table>
				<thead>
					<tr>
						<th>{language.current && t('dashboard.topRoutesColRoute')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColReq')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColFourXX')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColFiveXX')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColWAFBlock')}</th>
						<th class="right">{language.current && t('dashboard.topRoutesColWAFDetect')}</th>
					</tr>
				</thead>
				<tbody>
					{#each summary?.topRoutes ?? [] as r (r.routeId)}
						<tr>
							<td class="mono">
								<a href={`/observability/${r.routeId}`} class="host-link">{r.host}</a>
							</td>
							<td class="mono right">{r.reqs}</td>
							<td class="mono right warn-text">{r.fourxx}</td>
							<td class="mono right bad-text">{r.fivexx}</td>
							<td class="mono right bad-text">{r.wafBlocked}</td>
							<td class="mono right warn-text">{r.wafDetected}</td>
						</tr>
					{:else}
						<tr><td colspan="6" class="empty-row">{language.current && t('dashboard.topRoutesEmpty')}</td></tr>
					{/each}
				</tbody>
			</table>
		</div>

		<div class="card">
			<div class="card-h">
				<h3>{language.current && t('dashboard.upstreamsTitle')}</h3>
				<div class="meta" data-testid="upstreams-meta">
					{#if allUpstreams.length > upstreams.length}
						{language.current &&
							t('dashboard.upstreamsMetaTruncated', {
								shown: upstreams.length,
								total: allUpstreams.length
							})} ·
						<a href="/routes" class="meta-link" data-testid="upstreams-see-all"
							>{language.current && t('dashboard.upstreamsSeeAll')}</a
						>
					{:else}
						{language.current && t('dashboard.upstreamsMetaCount', { count: allUpstreams.length })}
					{/if}
				</div>
			</div>
			<div class="stack">
				{#each upstreams as u (u.url)}
					<div class="upstream-row">
						<span class="mono">{u.url}</span>
						<span class="mono dim">{language.current && t('dashboard.upstreamsRouteSuffix', { count: u.routes.length, plural: u.routes.length > 1 ? 's' : '' })}</span>
					</div>
				{:else}
					<div class="empty-row">{language.current && t('dashboard.upstreamsEmpty')}</div>
				{/each}
			</div>
		</div>
	</div>
{/if}

<style>
	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
	.card.error { padding: 16px; color: var(--status-down); border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border); }

	/* v2.41 — .screen-head / .eyebrow / h1 / .sub used to live here as
	   a copy of PageHeader (which was itself modelled on this very
	   block, see PageHeader.svelte). The page now uses the component. */

	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
	}
	.card.empty {
		padding: 32px;
		text-align: center;
	}
	.card.empty h3 { color: var(--fg); font-size: 16px; margin: 0 0 8px; font-weight: 500; }
	.card.empty p { color: var(--fg-muted); font-size: 13px; max-width: 480px; margin: 0 auto; line-height: 1.6; }
	.card.empty a { color: var(--accent); }
	.card-h {
		display: flex; align-items: center; gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 { color: var(--fg); font-size: 13.5px; font-weight: 500; margin: 0; }
	.card-h .meta { margin-left: auto; color: var(--fg-dim); font-size: 11.5px; font-family: var(--font-mono); }
	.meta-link { color: var(--accent); text-decoration: none; }
	.meta-link:hover { text-decoration: underline; }

	.kpis {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 18px;
	}
	/* v2.41 — the .kpi / .kpi-label / .kpi-val / .kpi-foot rules
	   moved into StatCard.svelte; only the grid stays here. */

	.two-col {
		display: grid;
		gap: 14px;
		margin-bottom: 18px;
	}
	.main-row { grid-template-columns: 1fr 1fr; }
	.bottom-row { grid-template-columns: 1.4fr 1fr; }

	.seg {
		margin-left: auto;
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
		padding: 4px 10px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-weight: 500;
		transition: background 0.12s, color 0.12s;
	}
	.seg button:hover { color: var(--fg); }
	.seg button.on { background: var(--surface-hi); color: var(--fg); box-shadow: inset 0 0 0 1px var(--border-hi); }

	.chart-wrap { min-height: 160px; }
	.chart-loading { display: flex; justify-content: center; padding: 48px; }
	.chart-error { color: var(--status-down); font-size: 13px; padding: 48px 16px; text-align: center; }
	.chart-unit { margin-left: 8px; font-size: 12px; font-weight: 400; color: var(--text-secondary); }
	.updated-at { font-size: 12px; color: var(--text-secondary); }
	.updated-at.failed { color: var(--status-warn); }

	.stack { display: flex; flex-direction: column; gap: 10px; }
	.event {
		display: flex; align-items: center; gap: 10px;
		padding: 8px 0;
		border-bottom: 1px solid var(--border);
	}
	.event:last-child { border-bottom: none; }
	.event .what { flex: 1; min-width: 0; font-size: 12.5px; line-height: 1.4; }
	.event .what b { display: block; color: var(--fg); font-weight: 500; }
	.event .what span { color: var(--fg-muted); font-family: var(--font-mono); font-size: 11.5px; }
	.event .when { color: var(--fg-dim); font-size: 11px; font-family: var(--font-mono); text-align: right; flex: none; }

	.pill {
		display: inline-flex; align-items: center; padding: 2px 8px;
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		flex: none;
	}
	.pill.bad { background: color-mix(in oklch, var(--status-down) 18%, transparent); color: var(--status-down); }
	/* #R-WAF-EVENT-LABEL-INCONSISTENT — amber detect badge, parallel to the .bad red block badge. */
	.pill.warn { background: color-mix(in oklch, var(--status-warn) 18%, transparent); color: var(--status-warn-fg); }

	table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
	th, td { padding: 7px 8px; text-align: left; }
	th { color: var(--fg-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }
	td { color: var(--fg); border-bottom: 1px solid var(--border); }
	tbody tr:last-child td { border-bottom: none; }
	.mono { font-family: var(--font-mono); font-size: 12px; }
	.right { text-align: right; }
	.dim { color: var(--fg-dim); }
	.host-link {
		color: var(--fg);
		text-decoration: none;
		border-bottom: 1px dashed var(--fg-dim);
	}
	.host-link:hover {
		color: var(--accent);
		border-bottom-color: var(--accent);
	}
	.warn-text { color: var(--status-warn-fg); }
	.bad-text { color: var(--status-down); }
	.empty-row { color: var(--fg-muted); font-size: 12px; padding: 12px 0; text-align: center; font-style: italic; }

	.upstream-row {
		display: flex; align-items: center; justify-content: space-between;
		padding: 8px 0;
		border-bottom: 1px solid var(--border);
		font-size: 12.5px;
	}
	.upstream-row:last-child { border-bottom: none; }
</style>
