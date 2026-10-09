<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.3.a — /waf page. Replaces the R.2 stub.

  Per spec §6.1 WAF audit, this page renders ONLY the parts
  backed by real backend instrumentation today:

  - 4 KPI tiles: requests inspected, blocked, mode, paranoia.
    Mode + paranoia are STATIC reads of Coraza defaults (no
    backend API to mutate them today — read-only display).
  - OWASP CRS category event-count grid: read-only tiles per
    category, derived from summary.wafBlocksByCategory. The
    mock shows on/off switches per category; backend has NO
    such API (spec §6.1 GAP BACKEND). The grid surfaces the
    counts without claiming togglability — and ships an inline
    banner explicitly stating "granular control deferred".

  Omitted entirely (per spec §6.1):
  - Rate-limit named-rules card: backend has per-route limits
    only (Step Q); no named-rules engine. Operators configure
    rate limits in /routes detail.
  - IP allow/deny manual lists card: backend has NO manual
    list storage. The link "Voir toute la timeline →" points
    to /security?tab=crowdsec (per D8, post-CS.3) which is
    the CrowdSec drill-down — the closest real surface.
  - Geo-blocking section: zero backend (no MaxMind dep).
    Omitted; tracked in backlog #R-WAF-geo.

  All data from existing endpoints (anti-regression AC #1):
  - GET /api/v1/metrics/summary (Step L + M extensions).
  - GET /api/v1/security/events (Step M).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { fetchSummary } from '$lib/api/metrics';
	import { fetchEventsByRule } from '$lib/api/security';
	import { ApiError } from '$lib/api/types';
	import type {
		SummaryResponse,
		OwaspCategory,
		WafEventRuleAggregate
	} from '$lib/api/types';
	import { ALL_OWASP_CATEGORIES } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import {
		categoryMeta,
		categoriesByFamily,
		FAMILY_LABEL,
		type CategoryFamily
	} from '$lib/utils/waf-category';

	let loading = $state(true);
	let loadError = $state<string | null>(null);
	let summary = $state<SummaryResponse | null>(null);

	const disabled = $derived(summary?.disabled === true);

	// Phase Y — drill-down state. Per category : whether the
	// card is expanded + the loaded rule rows + a per-card
	// loading flag. Map shape keeps the page reactive ;
	// flipping a key replaces the whole map so $derived
	// pickups don't miss.
	type CategoryDrill = {
		open: boolean;
		loading: boolean;
		error: string | null;
		rows: WafEventRuleAggregate[];
	};
	let drill = $state<Record<string, CategoryDrill>>({});

	async function toggleDrill(cat: OwaspCategory): Promise<void> {
		const current = drill[cat] ?? {
			open: false,
			loading: false,
			error: null,
			rows: []
		};
		// Close immediately if already open ; on first open
		// fetch the data before flipping the flag so the
		// expand surface doesn't flicker through a "loading
		// empty" state.
		if (current.open) {
			drill = { ...drill, [cat]: { ...current, open: false } };
			return;
		}
		// Already loaded once — just re-open.
		if (current.rows.length > 0 || current.error) {
			drill = { ...drill, [cat]: { ...current, open: true } };
			return;
		}
		drill = { ...drill, [cat]: { ...current, open: true, loading: true } };
		try {
			const resp = await fetchEventsByRule({ category: cat, window: '24h' });
			drill = {
				...drill,
				[cat]: { open: true, loading: false, error: null, rows: resp.rows ?? [] }
			};
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'failed to load rules';
			drill = {
				...drill,
				[cat]: { open: true, loading: false, error: msg, rows: [] }
			};
		}
	}

	// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — pre-fix these
	// were per-minute values multiplied by 60×24 to project
	// "/ 24h". Post-fix the summary endpoint returns 24h
	// totals natively; the frontend reads them raw.
	const totalInspected24h = $derived(summary?.totalReq ?? 0);
	const totalBlocked24h = $derived(summary?.totalWafBlocked ?? 0);
	const totalDetected24h = $derived(summary?.totalWafDetected ?? 0);
	const blockRatioPct = $derived(
		(() => {
			if (totalInspected24h <= 0) return 0;
			return (
				Math.round((totalBlocked24h / totalInspected24h) * 10000) / 100
			);
		})()
	);

	// Per-category counts. Pre-#R-DASHBOARD-WAF-COUNTERS-
	// ZERO the rows read from a single wafBlocksByCategory
	// map that silently aggregated BLOCK and DETECT
	// populations; post-fix each row reports the two
	// separately so the operator sees real attack volume
	// on detect-mode routes.
	//
	// Phase Y — labels + descriptions read from the shared
	// lib/utils/waf-category helper (single source of truth
	// across CategoryDistribution + WafEventList + this page +
	// /security/[routeId]). Categories grouped by operator-
	// meaningful family for the new collapsible-section render.
	type CategoryRow = {
		cat: OwaspCategory;
		label: string;
		description: string;
		block24h: number;
		detect24h: number;
	};
	type FamilyGroup = {
		family: CategoryFamily;
		familyLabel: string;
		rows: CategoryRow[];
		totalEvents: number;
	};
	const families = $derived.by<FamilyGroup[]>(() => {
		const blocks = summary?.wafBlocksByCategory ?? {};
		const detects = summary?.wafDetectsByCategory ?? {};
		return categoriesByFamily(ALL_OWASP_CATEGORIES).map((g) => {
			const rows = g.categories.map<CategoryRow>((cat) => {
				const meta = categoryMeta(cat);
				return {
					cat,
					label: meta.label,
					description: meta.description,
					block24h: blocks[cat] ?? 0,
					detect24h: detects[cat] ?? 0
				};
			});
			const totalEvents = rows.reduce((s, r) => s + r.block24h + r.detect24h, 0);
			return {
				family: g.family,
				familyLabel: FAMILY_LABEL[g.family],
				rows,
				totalEvents
			};
		});
	});

	async function load(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			summary = await fetchSummary();
		} catch (err) {
			loadError = err instanceof ApiError ? err.message : 'failed to load summary';
			pushToast(loadError, 'danger');
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<svelte:head>
	<title>{language.current && t('waf.headTitle')}</title>
</svelte:head>

<PageHeader
	eyebrow={language.current && t('waf.pageEyebrow')}
	title={language.current && t('pageTitles.wafRules')}
	subtitle={language.current && t('waf.pageSubtitle')}
>
	{#snippet actions()}
		<!-- v2.41 — the .tb-btn copies of Button are gone. The history
		     entry stays an <a> (it navigates) and borrows Button's
		     secondary shape through the shared .btn-link class. -->
		<a href="/security?tab=crowdsec" class="btn-link">{language.current && t('waf.actionHistory')}</a>
		<Button size="sm" disabled title={language.current && t('waf.actionApplyTooltip')}
			>{language.current && t('waf.actionApply')}</Button
		>
	{/snippet}
</PageHeader>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else if loadError}
	<div class="card error">{loadError}</div>
{:else if disabled}
	<div class="card empty">
		<h3>{language.current && t('waf.disabledTitle')}</h3>
		<p>{language.current && t('waf.disabledHelper')}</p>
	</div>
{:else}
	<!-- KPIs. v2.41 — third copy of StatCard, now the component. -->
	<div class="kpis">
		<StatCard
			label={language.current && t('waf.kpiRequestsInspected')}
			value={totalInspected24h.toLocaleString(language.current)}
			unit="/ 24h"
			hint={language.current && t('waf.kpiRequestsInspectedFoot')}
		/>
		<!--
			#R-DASHBOARD-WAF-COUNTERS-ZERO — Blocked and Detected
			reported as parallel tiles. On a homelab with every
			route in wafMode=detect (the recommended I.4 default),
			the Blocked tile stays at zero while Detected carries
			the real attack volume.
		-->
		<StatCard
			testid="kpi-blocked"
			label={language.current && t('waf.kpiBlocked')}
			value={totalBlocked24h.toLocaleString(language.current)}
			hint={language.current && t('waf.kpiBlockedFoot', { pct: blockRatioPct })}
		/>
		<StatCard
			testid="kpi-detected"
			label={language.current && t('waf.kpiDetected')}
			value={totalDetected24h.toLocaleString(language.current)}
			hint={language.current && t('waf.kpiDetectedFoot')}
		/>
		<StatCard
			label={language.current && t('waf.kpiMode')}
			value={language.current && t('waf.kpiModeBlocking')}
			variant="text"
			hint={language.current && t('waf.kpiModeFoot')}
		/>
		<StatCard
			label={language.current && t('waf.kpiParanoiaLevel')}
			value={2}
			unit="/ 4"
			hint={language.current && t('waf.kpiParanoiaLevelFoot')}
		/>
	</div>

	<!-- OWASP CRS categories — read-only event-count tiles -->
	<div class="card">
		<div class="card-h">
			<h3>{language.current && t('waf.categoriesTitle')}</h3>
			<div class="meta">{language.current && t('waf.categoriesMeta', { count: ALL_OWASP_CATEGORIES.length })}</div>
		</div>
		<div class="ro-notice">
			<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
				<circle cx="8" cy="8" r="6.5" />
				<path d="M8 5v3.5M8 11v.5" />
			</svg>
			<span>{language.current && t('waf.categoriesReadOnlyNotice')}</span>
		</div>
		<!--
			#R-DASHBOARD-WAF-COUNTERS-ZERO — each category
			row now reports BLOCK and DETECT counts
			separately, matching the split on the KPI tiles
			above. Pre-fix the single `blocks / 24h` cell
			silently aggregated both populations under a
			misleading "blocks" label; this resserement
			makes the operator-visible numbers honest about
			what the WAF actually did with the request.
		-->
		<!-- Phase Y — 25-category taxonomy grouped in operator-
		     meaningful families. Each category row is clickable
		     and drills down to the rule-id breakdown for that
		     category (across all routes, 24 h window). The
		     expand uses GET /security/events/by-rule?category=
		     which is server-side aggregated, so the row count
		     is not bound by the 100-event filter the /security/
		     events endpoint applies. -->
		{#each families as fam (fam.family)}
			<div class="fam-block" data-testid="fam-{fam.family}">
				<div class="fam-h">
					<h4>{fam.familyLabel}</h4>
					<span class="fam-meta">{language.current && t('waf.familyEventsCounter', { count: fam.totalEvents.toLocaleString(language.current) })}</span>
				</div>
				<div class="cat-grid">
					{#each fam.rows as row (row.cat)}
						{@const d = drill[row.cat] ?? {
							open: false,
							loading: false,
							error: null,
							rows: []
						}}
						<div class="cat-row" data-testid="cat-row-{row.cat}">
							<button
								type="button"
								class="cat-row-head"
								onclick={() => toggleDrill(row.cat)}
								data-testid="cat-toggle-{row.cat}"
								aria-expanded={d.open}
							>
								<div class="cat-info">
									<div class="cat-name">
										<svg
											class="chev"
											class:open={d.open}
											viewBox="0 0 16 16"
											width="10"
											height="10"
											aria-hidden="true"
										>
											<path
												d="M5 3l5 5-5 5"
												fill="none"
												stroke="currentColor"
												stroke-width="2"
												stroke-linecap="round"
												stroke-linejoin="round"
											/>
										</svg>
										{row.label}
									</div>
									<div class="cat-desc">{row.description}</div>
								</div>
								<div class="cat-meta">
									<div class="cat-meta-val cat-meta-block">
										{row.block24h.toLocaleString(language.current)}
									</div>
									<div class="cat-meta-foot">{language.current && t('waf.blocks24hFoot')}</div>
								</div>
								<div class="cat-meta">
									<div class="cat-meta-val cat-meta-detect">
										{row.detect24h.toLocaleString(language.current)}
									</div>
									<div class="cat-meta-foot">{language.current && t('waf.detects24hFoot')}</div>
								</div>
							</button>
							{#if d.open}
								<div class="cat-drill" data-testid="cat-drill-{row.cat}">
									{#if d.loading}
										<div class="cat-drill-state">{language.current && t('waf.drillLoading')}</div>
									{:else if d.error}
										<div class="cat-drill-state error">{d.error}</div>
									{:else if d.rows.length === 0}
										<div class="cat-drill-state muted">
											{language.current && t('waf.drillEmpty')}
										</div>
									{:else}
										<table class="rule-table">
											<thead>
												<tr>
													<th>{language.current && t('waf.drillColRuleID')}</th>
													<th>{language.current && t('waf.drillColCategory')}</th>
													<th class="num">{language.current && t('waf.drillColCount')}</th>
													<th>{language.current && t('waf.drillColLastSeen')}</th>
												</tr>
											</thead>
											<tbody>
												{#each d.rows as rule (rule.ruleId)}
													<tr>
														<td class="mono">{rule.ruleId}</td>
														<td class="mono">{rule.category}</td>
														<td class="num">{rule.count.toLocaleString(language.current)}</td>
														<td class="mono">{new Date(rule.lastSeen).toLocaleString(language.current)}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									{/if}
								</div>
							{/if}
						</div>
					{/each}
				</div>
			</div>
		{/each}
	</div>

	<!-- Phase Y — removed the misleading "Per-route rate
	     limits" link (no per-route rate-limit feature exists
	     in current storage ; Step Q's planned per-route rate
	     limiting is V3 backlog). Kept the CrowdSec link, which
	     correctly deep-links to /security?tab=crowdsec. -->
	<div class="card">
		<div class="card-h">
			<h3>{language.current && t('waf.ipEnforcementTitle')}</h3>
		</div>
		<div class="link-list">
			<a href="/security?tab=crowdsec" class="link-row">
				<div>
					<b>{language.current && t('waf.ipEnforcementActiveDecisions')}</b>
					<span>{language.current && t('waf.ipEnforcementHelper')}</span>
				</div>
				<span class="arrow">→</span>
			</a>
		</div>
	</div>
{/if}

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.card.error { color: var(--status-down); }
	.card.empty {
		padding: 32px;
		text-align: center;
	}
	.card.empty h3 { color: var(--fg); font-size: 16px; margin: 0 0 8px; font-weight: 500; }
	.card.empty p { color: var(--fg-muted); font-size: 13px; max-width: 480px; margin: 0 auto; line-height: 1.6; }

	.card-h {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 { color: var(--fg); font-size: 13.5px; font-weight: 500; margin: 0; }
	.card-h .meta { margin-left: auto; color: var(--fg-dim); font-size: 11.5px; font-family: var(--font-mono); }

	.kpis {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 18px;
	}
	/* v2.41 — the tile rules live in StatCard.svelte now. */

	.ro-notice {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 10px 12px;
		margin-bottom: 14px;
		background: color-mix(in oklch, var(--status-warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 28%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		font-size: 12px;
		line-height: 1.5;
	}
	.ro-notice svg { flex: none; color: var(--status-warn); margin-top: 2px; }

	/* Phase Y — family block grouping. Each fam-block wraps a
	   list of category rows in the same operator family
	   (request attacks, protocol/behaviour, etc.) with a
	   small header showing the family label + a 24h event
	   tally for the family. */
	.fam-block {
		margin-top: 14px;
	}
	.fam-block:first-of-type {
		margin-top: 0;
	}
	.fam-h {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 6px;
	}
	.fam-h h4 {
		color: var(--fg);
		font-size: 12px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		margin: 0;
	}
	.fam-meta {
		color: var(--fg-dim);
		font-size: 11px;
		font-family: var(--font-mono);
	}

	.cat-grid {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.cat-row {
		display: flex;
		flex-direction: column;
		background: var(--surface-2);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		overflow: hidden;
	}
	/* Phase Y — .cat-row-head is the clickable button that
	   toggles the drill-down. Was a plain div pre-Y. Reset
	   button defaults so it visually integrates with the
	   surrounding card. */
	.cat-row-head {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 10px 12px;
		background: transparent;
		border: 0;
		text-align: left;
		cursor: pointer;
		color: inherit;
		font: inherit;
		width: 100%;
	}
	.cat-row-head:hover {
		background: var(--bg-hover, rgba(255, 255, 255, 0.02));
	}
	.cat-info { flex: 1; min-width: 0; }
	.cat-name {
		display: flex;
		align-items: center;
		gap: 6px;
		color: var(--fg);
		font-size: 13px;
		font-weight: 500;
		margin-bottom: 2px;
	}
	.chev {
		flex: none;
		color: var(--fg-dim);
		transition: transform 120ms ease;
	}
	.chev.open {
		transform: rotate(90deg);
	}
	.cat-desc { color: var(--fg-muted); font-size: 11.5px; line-height: 1.5; }
	.cat-meta { text-align: right; flex: none; font-family: var(--font-mono); margin-left: 18px; min-width: 80px; }
	.cat-meta-val { color: var(--fg); font-size: 16px; font-weight: 500; }
	/* #R-DASHBOARD-WAF-COUNTERS-ZERO — colour-code BLOCK red and DETECT amber so the split is recognisable at a glance. */
	.cat-meta-val.cat-meta-block { color: var(--status-down); }
	.cat-meta-val.cat-meta-detect { color: var(--status-warn); }
	.cat-meta-foot { color: var(--fg-dim); font-size: 10.5px; margin-top: 2px; text-transform: uppercase; letter-spacing: 0.04em; }

	/* Phase Y — drill-down expand-below-the-head pane. Same
	   visual language as /security/[routeId] rule table for
	   consistency. */
	.cat-drill {
		border-top: 1px solid var(--border);
		background: var(--surface);
		padding: 10px 12px;
	}
	.cat-drill-state {
		color: var(--fg-muted);
		font-size: 12px;
		padding: 6px 0;
	}
	.cat-drill-state.error {
		color: var(--status-down);
	}
	.cat-drill-state.muted {
		font-style: italic;
	}
	.rule-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12px;
	}
	.rule-table th,
	.rule-table td {
		padding: 6px 8px;
		text-align: left;
		border-bottom: 1px solid var(--border);
	}
	.rule-table th {
		color: var(--fg-muted);
		font-weight: 500;
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
	}
	.rule-table td.num,
	.rule-table th.num {
		text-align: right;
		font-family: var(--font-mono);
	}
	.rule-table td.mono {
		font-family: var(--font-mono);
	}

	.link-list {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.link-row {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 12px 14px;
		background: var(--surface-2);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		text-decoration: none;
		transition: background 0.12s, border-color 0.12s;
	}
	.link-row:hover {
		background: var(--surface-hi);
		border-color: var(--border-hi);
	}
	.link-row > div { flex: 1; min-width: 0; }
	.link-row b { display: block; color: var(--fg); font-weight: 500; font-size: 13px; margin-bottom: 2px; }
	.link-row span { color: var(--fg-muted); font-size: 12px; line-height: 1.5; }
	.arrow { color: var(--accent); font-size: 18px; flex: none; }

	/* A link, not a button: keeps <a> semantics while wearing the
	   same shape as Button's secondary variant. */
	.btn-link {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		padding: 6px 12px;
		border-radius: var(--radius-md, 8px);
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
		color: var(--text-primary);
		background: var(--bg-elevated);
		border: 1px solid var(--border-default);
		transition: background 0.15s ease;
	}
	.btn-link:hover {
		background: var(--bg-hover);
	}

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
</style>
