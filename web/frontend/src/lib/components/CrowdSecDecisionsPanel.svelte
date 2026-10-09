<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step CS.3 Commit A — CrowdSec decisions drill-down extracted
  from the deleted /security/decisions route. Same 3-sub-tab
  structure (Local snapshot / Live LAPI / Scenarios), same data
  paths, same testIds. The only structural change is the
  PageHeader being dropped — the parent /sécurité page owns
  the page-level header now and this component renders only
  the inner sub-tabs + content.

  See the deleted /security/decisions/+page.svelte git history
  for the layered evolution (N.4 → CS.2.A → CS.2.C → CS.3).
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Tabs from '$lib/components/Tabs.svelte';
	import BanIPModal from '$lib/components/BanIPModal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import {
		deleteCrowdSecDecision,
		fetchDecisions,
		fetchLAPIDecisions,
		fetchScenarios
	} from '$lib/api/security';
	import type {
		Decision,
		LAPIDecision,
		LAPIDecisionsMeta,
		ScenarioAggregate,
		ScenariosMeta
	} from '$lib/api/types';
	import { ApiError, isArenetAutoScenario } from '$lib/api/types';
	import { auth } from '$lib/stores/auth.svelte';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { formatTime } from '$lib/utils/format';

	// Step CS.3 Commit D — admin gate for the "Bannir une IP"
	// button. Mirrors the backend RequireAdminMiddleware on
	// POST /api/v1/security/crowdsec/decisions. Viewer-role
	// users see neither the button nor the modal mount; the
	// backend remains the authoritative gate even if a
	// determined operator bypassed the UI check.
	const isAdmin = $derived(auth.user?.role === 'admin');
	let banModalOpen = $state(false);
	function openBanModal(): void {
		banModalOpen = true;
	}
	function closeBanModal(): void {
		banModalOpen = false;
	}
	function onBanSuccess(): void {
		// Optimistic refresh: re-fetch the live LAPI list
		// IMMEDIATELY after a successful ban so the operator
		// sees their new row without waiting for the 30s poll.
		void loadLive();
	}

	// Unban (DELETE /security/crowdsec/decisions/{id}), admin-only
	// like the ban. Offered on decisions authored on this install:
	// Arenet's manual bans ("manual"), its auto-classify bans
	// ("arenet"), local scenarios ("crowdsec") and cscli ("cscli")
	// — where a typo or a false positive here lands. Not on CAPI
	// or lists:* rows: those come from community / subscribed
	// feeds, where the lasting fix for a false positive is a
	// CrowdSec allowlist rather than expiring one entry by hand
	// (cscli still can).
	function canUnban(d: LAPIDecision): boolean {
		return d.origin === 'manual' || d.origin === 'arenet' || isLocalOrigin(d.origin);
	}
	let unbanTarget = $state<LAPIDecision | null>(null);
	let unbanDialogOpen = $state(false);
	function askUnban(d: LAPIDecision): void {
		unbanTarget = d;
		unbanDialogOpen = true;
	}
	function unbanErrorMessage(err: unknown): string {
		if (err instanceof ApiError) {
			if (err.status === 412) return t('crowdsecDecisions.unbanNotConfigured');
			if (err.status === 404) return t('crowdsecDecisions.unbanNotFound');
		}
		const detail = err instanceof Error ? err.message : String(err);
		return t('crowdsecDecisions.toastUnbanFailed', { error: detail });
	}
	async function confirmUnban(): Promise<void> {
		const target = unbanTarget;
		if (target === null) return;
		try {
			await deleteCrowdSecDecision(target.id);
			pushToast(t('crowdsecDecisions.toastUnbanned', { value: target.value }), 'success');
		} catch (err) {
			pushToast(unbanErrorMessage(err), 'danger');
		}
		unbanDialogOpen = false;
		unbanTarget = null;
		// Refresh either way: on success the row is gone; on a
		// failure the decision may have expired meanwhile.
		await loadLive();
	}

	type Tab = 'snapshot' | 'live' | 'scenarios';
	let activeTab = $state<Tab>('snapshot');

	// Tab descriptors consumed by the Tabs component (CS.3
	// extraction). Existing data-testid values preserved so the
	// CrowdSecDecisionsPanel tests inherited from the deleted
	// /security/decisions tests run untouched.
	const tabDescriptors: ReadonlyArray<{ id: Tab; label: string; testId: string }> = [
		{ id: 'snapshot', label: 'Local snapshot', testId: 'tab-snapshot' },
		{ id: 'live', label: 'Live LAPI', testId: 'tab-live' },
		{ id: 'scenarios', label: 'Scenarios', testId: 'tab-scenarios' }
	];

	// --- Tab 1: Local snapshot (Step N.4, unchanged data path) ---

	let snapshotLoading = $state(true);
	let snapshotError = $state<string | null>(null);
	let snapshotDisabled = $state(false);
	let onlyActive = $state(false);
	let decisions = $state<Decision[]>([]);

	async function loadSnapshot(): Promise<void> {
		snapshotLoading = true;
		snapshotError = null;
		try {
			const resp = await fetchDecisions({ limit: 100, onlyActive });
			snapshotDisabled = resp.disabled === true;
			decisions = resp.events;
		} catch (err) {
			snapshotError = err instanceof ApiError ? err.message : 'failed to load decisions';
			pushToast(snapshotError, 'danger');
		} finally {
			snapshotLoading = false;
		}
	}

	function toggleActive(next: boolean): void {
		onlyActive = next;
		void loadSnapshot();
	}

	// --- Tab 2: Live LAPI (Step CS.2.A) ---

	type LiveErrorKind = 'not_configured' | 'unreachable' | 'other' | null;

	let liveLoading = $state(false);
	let liveErrorKind = $state<LiveErrorKind>(null);
	let liveErrorMsg = $state<string | null>(null);
	let liveDecisions = $state<LAPIDecision[]>([]);
	let liveMeta = $state<LAPIDecisionsMeta>({
		total: 0,
		totalByOrigin: {},
		limit: 100,
		offset: 0
	});
	let liveScope = $state<string>('');
	// Step CS.3 Commit B — origin filter tabs replace the
	// pre-CS.3 free-form Source dropdown. Four buckets:
	//   - 'all'        no origin filter
	//   - 'local'      origin ∈ {crowdsec, cscli} BUT excludes
	//                  origin === 'manual' (which is its own
	//                  bucket per Commit C payload). Note: cscli
	//                  decisions that DON'T have origin='manual'
	//                  set (e.g. `cscli decisions add` without
	//                  Arenet) DO land in Locales — they were
	//                  authored on the LAPI host, which matches
	//                  the operator's mental model.
	//   - 'capi'       origin === 'CAPI'
	//   - 'manual'     origin === 'manual'
	// Backend filter is no longer used: we fetch the full
	// page once and filter client-side. The breakdown counts
	// per tab use the FULL response (pre-filter), so toggling
	// tabs never under-counts.
	type LiveOriginTab = 'all' | 'local' | 'capi' | 'manual';
	let liveOriginTab = $state<LiveOriginTab>('all');
	let liveLastFetched = $state<number | null>(null);
	// 30s polling tick. Set up when the user opens the Live
	// tab; torn down when leaving (or on component destroy).
	// 30s matches CrowdSec's default bouncer pull interval —
	// the chosen cadence is the natural rhythm of the data,
	// not a guess.
	const LIVE_POLL_MS = 30_000;
	let livePollHandle: ReturnType<typeof setInterval> | null = null;

	async function loadLive(): Promise<void> {
		liveLoading = true;
		liveErrorMsg = null;
		try {
			// CS.3 Commit B: do NOT pass `source` to the
			// backend. Filtering by origin happens client-side
			// so the 4-tab UI can show accurate counts for
			// every bucket without re-fetching when the
			// operator switches tabs.
			const resp = await fetchLAPIDecisions({
				scope: liveScope || undefined,
				limit: 100
			});
			liveDecisions = resp.decisions;
			liveMeta = resp.meta;
			liveErrorKind = null;
			liveLastFetched = Date.now();
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 404) {
					liveErrorKind = 'not_configured';
					liveErrorMsg = err.message;
				} else if (err.status === 502) {
					liveErrorKind = 'unreachable';
					liveErrorMsg = err.message;
				} else {
					liveErrorKind = 'other';
					liveErrorMsg = err.message;
				}
			} else {
				liveErrorKind = 'other';
				liveErrorMsg = err instanceof Error ? err.message : 'failed to load live decisions';
			}
			// Don't clear the existing decisions on a polling
			// failure — operators reading the table mid-poll
			// shouldn't see it blank out on a single hiccup.
			// The badge above the table flips to the error
			// state; data underneath stays as the last known
			// good response.
		} finally {
			liveLoading = false;
		}
	}

	function startLivePolling(): void {
		if (livePollHandle !== null) return;
		void loadLive();
		livePollHandle = setInterval(() => {
			// Skip the tick if the tab isn't visible (operator
			// navigated to a different tab in-app); the next
			// tab-open will refetch fresh.
			if (activeTab !== 'live') return;
			void loadLive();
		}, LIVE_POLL_MS);
	}

	function stopLivePolling(): void {
		if (livePollHandle !== null) {
			clearInterval(livePollHandle);
			livePollHandle = null;
		}
	}

	function onTabChange(next: Tab): void {
		activeTab = next;
		if (next === 'live') {
			startLivePolling();
		} else if (next === 'scenarios' && scenariosLastFetched === null) {
			void loadScenarios();
		}
		// Don't stop polling on a different tab change — the
		// timer skips ticks when activeTab !== 'live' (see
		// startLivePolling). This lets the operator hop between
		// snapshot ↔ live without paying the connect-startup
		// latency every flip.
	}

	// --- Tab 3: Scenarios (Step CS.2.C) ---

	type ScenariosErrorKind = 'not_configured' | 'unreachable' | 'other' | null;

	let scenariosLoading = $state(false);
	let scenariosErrorKind = $state<ScenariosErrorKind>(null);
	let scenariosErrorMsg = $state<string | null>(null);
	let scenarios = $state<ScenarioAggregate[]>([]);
	let scenariosMeta = $state<ScenariosMeta>({ totalAlerts: 0, windowHours: 24 });
	let scenariosLastFetched = $state<number | null>(null);
	let modalScenario = $state<ScenarioAggregate | null>(null);

	async function loadScenarios(): Promise<void> {
		scenariosLoading = true;
		scenariosErrorMsg = null;
		try {
			const resp = await fetchScenarios();
			scenarios = resp.scenarios;
			scenariosMeta = resp.meta;
			scenariosErrorKind = null;
			scenariosLastFetched = Date.now();
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 412) {
					scenariosErrorKind = 'not_configured';
					scenariosErrorMsg = err.message;
				} else if (err.status === 502) {
					scenariosErrorKind = 'unreachable';
					scenariosErrorMsg = err.message;
				} else {
					scenariosErrorKind = 'other';
					scenariosErrorMsg = err.message;
				}
			} else {
				scenariosErrorKind = 'other';
				scenariosErrorMsg =
					err instanceof Error ? err.message : 'failed to load scenarios';
			}
		} finally {
			scenariosLoading = false;
		}
	}

	function refreshScenarios(): void {
		void loadScenarios();
	}

	function openScenarioModal(s: ScenarioAggregate): void {
		modalScenario = s;
	}
	// Escape, backdrop click, the focus trap and returning focus
	// to the row that opened the dialog all come from Modal.
	function closeScenarioModal(): void {
		modalScenario = null;
	}

	// Hub URL builder. CrowdSec scenarios are named
	// "<author>/<scenario>" (e.g. "crowdsecurity/http-cve");
	// the hub URL is https://hub.crowdsec.net/author/<author>/configurations/<scenario>.
	// For non-org-prefixed scenarios (e.g. "manual" from cscli,
	// or unknown) the function returns null and the UI hides
	// the hub link.
	function hubURL(scenario: string): string | null {
		const i = scenario.indexOf('/');
		if (i <= 0 || i === scenario.length - 1) return null;
		const author = scenario.slice(0, i);
		const name = scenario.slice(i + 1);
		return `https://hub.crowdsec.net/author/${encodeURIComponent(author)}/configurations/${encodeURIComponent(name)}`;
	}

	function cscliCommand(scenario: string): string {
		return `sudo cscli scenarios inspect ${scenario}`;
	}

	let copyToast = $state<string | null>(null);
	let copyToastTimer: ReturnType<typeof setTimeout> | null = null;
	async function copyToClipboard(text: string): Promise<void> {
		try {
			await navigator.clipboard.writeText(text);
			copyToast = t('crowdsecDecisions.copyToast');
		} catch {
			copyToast = t('crowdsecDecisions.copyUnavailable');
		}
		if (copyToastTimer !== null) clearTimeout(copyToastTimer);
		copyToastTimer = setTimeout(() => {
			copyToast = null;
		}, 1800);
	}

	function onLiveFilterChange(): void {
		// Filter change re-fetches immediately, then continues
		// the polling cadence.
		void loadLive();
	}

	function refreshLive(): void {
		void loadLive();
	}

	// --- Shared helpers (same as the pre-CS.2 page) ---

	const SCOPE_COLOR: Record<string, string> = {
		ip: 'var(--status-down)',
		range: 'var(--status-warn)',
		country: 'var(--status-info)',
		as: 'var(--accent-cyan)'
	};
	function scopeColor(scope: string): string {
		return SCOPE_COLOR[scope] ?? 'var(--text-muted)';
	}

	const TYPE_COLOR: Record<string, string> = {
		ban: 'var(--status-down)',
		captcha: 'var(--status-down)',
		throttle: 'var(--status-warn)'
	};
	function typeColor(t: string): string {
		return TYPE_COLOR[t] ?? 'var(--text-muted)';
	}

	function shortScenario(s: string): string {
		if (!s) return 'ban';
		const i = s.lastIndexOf('/');
		return i >= 0 ? s.slice(i + 1) : s;
	}

	function relativeTs(iso: string): string {
		const then = new Date(iso).getTime();
		const now = Date.now();
		const secs = Math.max(0, Math.floor((now - then) / 1000));
		if (secs < 60) return `${secs}s ago`;
		const mins = Math.floor(secs / 60);
		if (mins < 60) return `${mins}m ago`;
		return formatTime(new Date(iso));
	}

	function formatExpiry(iso: string): string {
		if (!iso) return '—';
		const target = new Date(iso).getTime();
		const now = Date.now();
		const diffSecs = Math.floor((target - now) / 1000);
		if (diffSecs <= 0) {
			const past = Math.abs(diffSecs);
			if (past < 60) return `expired ${past}s ago`;
			if (past < 3600) return `expired ${Math.floor(past / 60)}m ago`;
			if (past < 86400) return `expired ${Math.floor(past / 3600)}h ago`;
			return `expired ${Math.floor(past / 86400)}d ago`;
		}
		if (diffSecs < 60) return `in ${diffSecs}s`;
		if (diffSecs < 3600) return `in ${Math.floor(diffSecs / 60)}m`;
		if (diffSecs < 86400) {
			const h = Math.floor(diffSecs / 3600);
			const m = Math.floor((diffSecs % 3600) / 60);
			return m > 0 ? `in ${h}h ${m}m` : `in ${h}h`;
		}
		return `in ${Math.floor(diffSecs / 86400)}d`;
	}

	// CS.3 Commit B — per-tab counts computed from the FULL
	// LAPI response (liveMeta.totalByOrigin). Counts stay
	// stable across tab switches and are NOT affected by the
	// scope select either, since both filters apply after the
	// fetch (scope is forwarded to LAPI but the meta.total
	// already reflects the scope-narrowed set).
	//
	// Note on the predicates: "manual" is BOTH a top-level
	// origin AND a possible value of the legacy scenario field
	// (e.g. cscli emits scenario:"manual" with origin:"cscli"
	// for ad-hoc bans without origin set). The brief explicitly
	// pins origin === "manual" as the Manuelles bucket, so the
	// Locales bucket excludes ONLY origin === "manual", not
	// scenarios that start with "manual:". A cscli-issued ban
	// from the LAPI host that did NOT use Arenet's POST
	// endpoint lands in Locales by origin, as intended.
	function isLocalOrigin(o: string): boolean {
		return o === 'crowdsec' || o === 'cscli';
	}
	const liveCountAll = $derived(liveMeta.total);
	const liveCountLocal = $derived(
		Object.entries(liveMeta.totalByOrigin)
			.filter(([o]) => isLocalOrigin(o))
			.reduce((s, [, n]) => s + n, 0)
	);
	const liveCountCAPI = $derived(liveMeta.totalByOrigin['CAPI'] ?? 0);
	const liveCountManual = $derived(liveMeta.totalByOrigin['manual'] ?? 0);

	// Tabs.svelte expects a static label per tab — we want
	// the count to flow live, so we build the array as a
	// $derived. Each label embeds the count; when a tab's
	// count is zero, the tab still renders (operator can
	// click to confirm "yes, 0 matches" without thinking
	// the UI is broken). t() reads language.current, so the
	// labels also follow a language switch.
	const liveOriginTabDescriptors = $derived<
		ReadonlyArray<{ id: LiveOriginTab; label: string; testId: string }>
	>([
		{ id: 'all', label: `${t('crowdsecDecisions.tabAll')} (${liveCountAll})`, testId: 'live-tab-all' },
		{ id: 'local', label: `${t('crowdsecDecisions.tabLocal')} (${liveCountLocal})`, testId: 'live-tab-local' },
		{ id: 'capi', label: `CAPI (${liveCountCAPI})`, testId: 'live-tab-capi' },
		{ id: 'manual', label: `${t('crowdsecDecisions.tabManual')} (${liveCountManual})`, testId: 'live-tab-manual' }
	]);

	// Filtered view derived from liveDecisions + active tab.
	// Visible table rows come from this; the table also
	// renders the operator-friendly origin badge per row.
	const liveDecisionsFiltered = $derived(
		liveDecisions.filter((d) => {
			switch (liveOriginTab) {
				case 'all':
					return true;
				case 'local':
					return isLocalOrigin(d.origin);
				case 'capi':
					return d.origin === 'CAPI';
				case 'manual':
					return d.origin === 'manual';
			}
		})
	);

	// CS.3 Commit B — parse manual:<username>|<reason>
	// payload format (operator-confirmed Option 1).
	// Backend Commit C builds this exact string in the
	// Decision.scenario field. Non-manual scenarios pass
	// through verbatim.
	type ParsedManual = {
		username: string;
		reason: string;
	};
	function parseManualScenario(scenario: string): ParsedManual | null {
		if (!scenario.startsWith('manual:')) return null;
		const afterPrefix = scenario.slice('manual:'.length);
		const pipe = afterPrefix.indexOf('|');
		if (pipe < 0) {
			// Legacy / cscli-issued manual ban with no reason
			// embedded — show the raw value as username, no
			// line 2.
			return { username: afterPrefix.trim(), reason: '' };
		}
		return {
			username: afterPrefix.slice(0, pipe).trim(),
			reason: afterPrefix.slice(pipe + 1).trim()
		};
	}

	// Operator-facing origin label — collapses CrowdSec's
	// raw vocabulary into the 3 buckets the UI surfaces.
	// "unknown" / empty falls through to "—" so the badge
	// never shows a blank pill.
	function originBucket(origin: string): 'local' | 'capi' | 'manual' | 'other' {
		if (origin === 'manual') return 'manual';
		if (origin === 'CAPI') return 'capi';
		if (isLocalOrigin(origin)) return 'local';
		return 'other';
	}
	const ORIGIN_BADGE_COLOR: Record<string, string> = {
		local: 'var(--status-warn)',
		capi: 'var(--status-info)',
		manual: 'var(--accent-cyan)',
		other: 'var(--text-muted)'
	};
	function originBadgeColor(origin: string): string {
		return ORIGIN_BADGE_COLOR[originBucket(origin)];
	}
	function originBadgeLabel(origin: string): string {
		const b = originBucket(origin);
		if (b === 'other') return origin || '—';
		return b;
	}

	function onLiveOriginTabChange(next: LiveOriginTab): void {
		liveOriginTab = next;
	}

	function lastFetchedLabel(ts: number | null): string {
		if (ts === null) return '';
		const ago = Math.floor((Date.now() - ts) / 1000);
		if (ago < 5) return 'just now';
		if (ago < 60) return `${ago}s ago`;
		const mins = Math.floor(ago / 60);
		return `${mins}m ago`;
	}

	onMount(() => {
		void loadSnapshot();
	});

	onDestroy(() => {
		stopLivePolling();
	});
</script>

<Tabs
	bind:value={activeTab}
	tabs={tabDescriptors}
	ariaLabel="CrowdSec decisions tabs"
	onChange={onTabChange}
/>

{#if activeTab === 'snapshot'}
	<p class="tab-subtitle">
		{language.current && t('crowdsecDecisions.panelSubtitle')}
	</p>

	{#if snapshotLoading}
		<div class="loading-wrap">
			<Spinner />
		</div>
	{:else if snapshotError}
		<Card>
			<div class="error-wrap">{snapshotError}</div>
		</Card>
	{:else if snapshotDisabled}
		<Card>
			<div class="empty-wrap">
				<h3>{language.current && t('crowdsecDecisions.mirrorNotConfiguredTitle')}</h3>
				<p>
					{language.current && t('crowdsecDecisions.mirrorNotConfiguredBody')}
				</p>
			</div>
		</Card>
	{:else}
		<div class="filter-row">
			<div class="active-toggle">
				<button
					type="button"
					class:active={!onlyActive}
					onclick={() => toggleActive(false)}
				>
					{language.current && t('crowdsecDecisions.tabAll')}
				</button>
				<button
					type="button"
					class:active={onlyActive}
					onclick={() => toggleActive(true)}
				>
					{language.current && t('crowdsecDecisions.tabActiveOnly')}
				</button>
			</div>
			<div class="meta">
				{decisions.length}{decisions.length === 100 ? '+' : ''} {language.current && (decisions.length > 1 ? t('crowdsecDecisions.decisionsSuffixPlural') : t('crowdsecDecisions.decisionsSuffix'))}
			</div>
		</div>

		<Card>
			<div class="block">
				{#if decisions.length === 0}
					<div class="empty-inline">
						{language.current && (onlyActive
							? t('crowdsecDecisions.emptyActive')
							: t('crowdsecDecisions.emptyWindow'))}
					</div>
				{:else}
					<table>
						<thead>
							<tr>
								<th>Captured</th>
								<th>Scope</th>
								<th>Value</th>
								<th>Scenario</th>
								<th>Type</th>
								<th>Expires</th>
							</tr>
						</thead>
						<tbody>
							{#each decisions as d (d.uuid)}
								<tr>
									<td class="ts" title={d.ts}>{relativeTs(d.ts)}</td>
									<td>
										<span class="badge" style:background={scopeColor(d.scope)}>
											{d.scope || '—'}
										</span>
									</td>
									<td class="mono">{d.value || '—'}</td>
									<td class="mono">
										{shortScenario(d.scenario)}
										{#if isArenetAutoScenario(d.scenario)}
											<span class="badge auto-badge" title={language.current && t('crowdsecDecisions.autoBadgeTitle')}>
												auto
											</span>
										{/if}
									</td>
									<td>
										<span class="badge" style:background={typeColor(d.type)}>
											{d.type || 'ban'}
										</span>
									</td>
									<td class="ts" title={d.expiresAt}>{formatExpiry(d.expiresAt)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		</Card>
	{/if}
{:else if activeTab === 'live'}
	<p class="tab-subtitle">
		{language.current && t('crowdsecDecisions.liveSubtitleBefore')}
		<strong>{language.current && t('crowdsecDecisions.liveSubtitleStrong')}</strong>
		{language.current && t('crowdsecDecisions.liveSubtitleAfter')}
	</p>

	{#if liveErrorKind === 'not_configured'}
		<Card>
			<div class="empty-wrap" data-testid="live-not-configured">
				<h3>{language.current && t('crowdsecDecisions.liveNotConfiguredTitle')}</h3>
				<p>
					{language.current && t('crowdsecDecisions.liveNotConfiguredBody')}
					<a href="/settings" class="link">{language.current && t('crowdsecDecisions.liveNotConfiguredLink')}</a>
					{language.current && t('crowdsecDecisions.liveNotConfiguredSuffix')}
				</p>
			</div>
		</Card>
	{:else}
		<!-- CS.3 Commit B — origin filter tabs replace the
		     pre-CS.3 Source dropdown + breakdown chips. Scope
		     dropdown stays — it filters on a different axis
		     (ip / range / country / as) and is forwarded
		     server-side to LAPI. -->
		<div class="origin-tabs-row" data-testid="live-origin-tabs">
			<Tabs
				bind:value={liveOriginTab}
				tabs={liveOriginTabDescriptors}
				ariaLabel={language.current && t('crowdsecDecisions.filterAriaLabel')}
				onChange={onLiveOriginTabChange}
			/>
		</div>

		<div class="filter-row">
			<div class="live-filters">
				<label class="filter-label">
					Scope
					<select bind:value={liveScope} onchange={onLiveFilterChange} data-testid="live-scope-filter">
						<option value="">{language.current && t('crowdsecDecisions.scopeAll')}</option>
						<option value="ip">ip</option>
						<option value="range">range</option>
						<option value="country">country</option>
						<option value="as">as</option>
					</select>
				</label>
			</div>
			<div class="meta">
				{#if liveLoading && liveDecisions.length === 0}
					<Spinner size="sm" /> {language.current && t('crowdsecDecisions.loading')}
				{:else}
					{liveDecisionsFiltered.length}
					{#if liveDecisionsFiltered.length !== liveMeta.total}
						<span class="muted">/ {liveMeta.total}</span>
					{/if}
					{language.current && (liveDecisionsFiltered.length > 1 ? t('crowdsecDecisions.liveDecisionsSuffixPlural') : t('crowdsecDecisions.liveDecisionsSuffix'))}
					{#if liveLastFetched !== null}
						<span class="muted">· fetched {lastFetchedLabel(liveLastFetched)}</span>
					{/if}
					<button type="button" class="refresh-btn" onclick={refreshLive} aria-label="Refresh">
						↻
					</button>
					{#if isAdmin}
						<!-- Step CS.3 Commit D — admin-only "Bannir
						     une IP" entry point. Modal mount lives at
						     the bottom of the template. The button
						     groups with the refresh affordance because
						     both are "operator actions on the current
						     LAPI snapshot". -->
						<button
							type="button"
							class="ban-btn"
							onclick={openBanModal}
							data-testid="ban-open-btn"
						>
							{language.current && t('crowdsecDecisions.btnBanIp')}
						</button>
					{/if}
				{/if}
			</div>
		</div>

		{#if liveErrorKind === 'unreachable'}
			<Card>
				<div class="error-banner" role="alert" data-testid="live-unreachable">
					<strong>{language.current && t('banIp.errLapiUnreachablePrefix')}</strong> {liveErrorMsg ?? (language.current && t('banIp.errUnknownError'))}
					{#if liveDecisions.length > 0}
						<p class="muted">
							{language.current && t('crowdsecDecisions.liveStaleNotice')} {language.current && t('crowdsecDecisions.liveStaleNoticeSuffix')}
						</p>
					{/if}
					<button type="button" class="retry-btn" onclick={refreshLive}>
						{language.current && t('crowdsecDecisions.btnRetry')}
					</button>
				</div>
			</Card>
		{:else if liveErrorKind === 'other' && liveErrorMsg}
			<Card>
				<div class="error-wrap" role="alert">{liveErrorMsg}</div>
			</Card>
		{/if}

		<Card>
			<div class="block">
				{#if liveDecisionsFiltered.length === 0 && !liveLoading && !liveErrorKind}
					<div class="empty-inline" data-testid="live-empty">
						{#if liveMeta.total === 0}
							{language.current && t('crowdsecDecisions.emptyLiveAll')}
						{:else}
							<!-- CS.3 Commit B — the LAPI returned data, but the
							     selected origin tab has zero matches. Distinct
							     empty state so the operator knows the filter is
							     the cause, not LAPI emptiness. -->
							{language.current && t('crowdsecDecisions.emptyLiveFiltered', { total: liveMeta.total, tabAll: t('crowdsecDecisions.tabAll') })}
						{/if}
					</div>
				{:else if liveDecisionsFiltered.length > 0}
					<table>
						<thead>
							<tr>
								<th>Type</th>
								<th>Scope</th>
								<th>Value</th>
								<th>Origin</th>
								<th>Scenario</th>
								<th>Expires</th>
								{#if isAdmin}
									<th>{language.current && t('crowdsecDecisions.colActions')}</th>
								{/if}
							</tr>
						</thead>
						<tbody>
							{#each liveDecisionsFiltered as d (d.id)}
								{@const parsedManual = parseManualScenario(d.scenario)}
								<tr>
									<td>
										<span class="badge" style:background={typeColor(d.type)}>
											{d.type || 'ban'}
										</span>
									</td>
									<td>
										<span class="badge" style:background={scopeColor(d.scope)}>
											{d.scope || '—'}
										</span>
									</td>
									<td class="mono">{d.value || '—'}</td>
									<td>
										<span class="badge" style:background={originBadgeColor(d.origin)}>
											{originBadgeLabel(d.origin)}
										</span>
									</td>
									<td class="mono">
										{#if parsedManual !== null}
											<!-- Manual ban — two-line cell. Line 1
											     "manual / <username>"; line 2 the
											     reason (italic gray, smaller). -->
											<div class="manual-line1" data-testid="manual-line1">
												manual / {parsedManual.username || 'unknown'}
											</div>
											{#if parsedManual.reason !== ''}
												<div class="manual-line2" data-testid="manual-line2">
													{parsedManual.reason}
												</div>
											{/if}
										{:else}
											{shortScenario(d.scenario)}
											{#if isArenetAutoScenario(d.scenario)}
												<span class="badge auto-badge" title={language.current && t('crowdsecDecisions.autoBadgeTitle')}>
													auto
												</span>
											{/if}
										{/if}
									</td>
									<td class="ts" title={d.expiresAt ?? ''}>
										{d.expiresAt ? formatExpiry(d.expiresAt) : d.duration || '—'}
									</td>
									{#if isAdmin}
										<td>
											{#if canUnban(d)}
												<button
													type="button"
													class="unban-btn"
													onclick={() => askUnban(d)}
													aria-label={language.current && t('crowdsecDecisions.unbanAria', { value: d.value })}
													data-testid="unban-btn"
												>
													{language.current && t('crowdsecDecisions.btnUnban')}
												</button>
											{/if}
										</td>
									{/if}
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		</Card>
	{/if}
{:else if activeTab === 'scenarios'}
	<p class="tab-subtitle">
		{language.current && t('crowdsecDecisions.scenariosSubtitle')}
		<strong>{scenariosMeta.windowHours}h</strong>.
	</p>

	{#if scenariosLoading && scenarios.length === 0}
		<div class="loading-wrap">
			<Spinner />
		</div>
	{:else if scenariosErrorKind === 'not_configured'}
		<Card>
			<div class="empty-wrap" data-testid="scenarios-not-configured">
				<h3>{language.current && t('crowdsecDecisions.automationNotConfiguredTitle')}</h3>
				<p>
					{language.current && t('crowdsecDecisions.automationNotConfiguredBody', { endpoint: '/v1/alerts' })}
					<a href="/settings#security-automation" class="link">Settings → Security Automation</a>
				</p>
				<p class="muted">
					{language.current && t('crowdsecDecisions.automationNotConfiguredFooter')} Scenarios.
				</p>
			</div>
		</Card>
	{:else}
		<div class="filter-row">
			<div class="meta">
				{#if scenariosLoading}
					<Spinner size="sm" /> {language.current && t('crowdsecDecisions.loading')}
				{:else}
					{language.current &&
						t('crowdsecDecisions.scenariosCount', {
							alerts: scenariosMeta.totalAlerts,
							alertsPlural: scenariosMeta.totalAlerts > 1 ? 's' : '',
							scenarios: scenarios.length,
							scenariosPlural: scenarios.length > 1 ? 's' : ''
						})}
					{#if scenariosLastFetched !== null}
						<span class="muted">· fetched {lastFetchedLabel(scenariosLastFetched)}</span>
					{/if}
					<button type="button" class="refresh-btn" onclick={refreshScenarios} aria-label="Refresh">
						↻
					</button>
				{/if}
			</div>
		</div>

		{#if scenariosErrorKind === 'unreachable'}
			<Card>
				<div class="error-banner" role="alert" data-testid="scenarios-unreachable">
					<strong>{language.current && t('banIp.errLapiUnreachablePrefix')}</strong>
					{scenariosErrorMsg ?? (language.current && t('banIp.errUnknownError'))}
					<button type="button" class="retry-btn" onclick={refreshScenarios}>
						{language.current && t('crowdsecDecisions.scenariosBtnRetry')}
					</button>
				</div>
			</Card>
		{:else if scenariosErrorKind === 'other' && scenariosErrorMsg}
			<Card>
				<div class="error-wrap" role="alert">{scenariosErrorMsg}</div>
			</Card>
		{/if}

		<Card>
			<div class="block">
				{#if scenarios.length === 0 && !scenariosLoading && !scenariosErrorKind}
					<div class="empty-inline" data-testid="scenarios-empty">
						{language.current && t('crowdsecDecisions.scenariosEmptyWindow', { hours: scenariosMeta.windowHours })}
						{language.current && t('crowdsecDecisions.scenariosEmptyHelp')}
					</div>
				{:else if scenarios.length > 0}
					<table>
						<thead>
							<tr>
								<th>Scenario</th>
								<th>Alerts 24h</th>
								<th>Last seen</th>
								<th>Sample source</th>
							</tr>
						</thead>
						<tbody>
							{#each scenarios as s (s.name)}
								<tr
									class="scenario-row"
									data-testid="scenario-row"
									tabindex="0"
									role="button"
									aria-label={`Inspect ${s.name}`}
									onclick={() => openScenarioModal(s)}
									onkeydown={(e) => {
										if (e.key === 'Enter' || e.key === ' ') {
											e.preventDefault();
											openScenarioModal(s);
										}
									}}
								>
									<td class="mono">
										{shortScenario(s.name)}
										{#if s.name.includes('/')}
											<span class="muted org">{s.name.split('/')[0]}</span>
										{/if}
									</td>
									<td><strong>{s.alerts24h}</strong></td>
									<td class="ts" title={s.lastSeen}>
										{s.lastSeen ? relativeTs(s.lastSeen) : '—'}
									</td>
									<td class="mono">
										{s.sampleValue || '—'}
										{#if s.sampleScope}
											<span class="muted">({s.sampleScope})</span>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		</Card>
	{/if}

	{#if modalScenario !== null}
		{@const ms = modalScenario}
		<!-- Built on Modal so the dialog is named by its title and
		     gets Escape, the focus trap and focus restore for free.
		     Mounted under the {#if}, as ConfirmDialog does, so
		     closing removes it at once. -->
		<Modal open title={ms.name} onClose={closeScenarioModal} width="lg">
		<div class="scenario-modal-body" data-testid="scenario-modal">
			<dl class="modal-dl">
				<dt>Alerts {scenariosMeta.windowHours}h</dt>
				<dd><strong>{ms.alerts24h}</strong></dd>

				{#if ms.lastSeen}
					<dt>Last seen</dt>
					<dd class="ts" title={ms.lastSeen}>
						{relativeTs(ms.lastSeen)}
					</dd>
				{/if}

				{#if ms.sampleScope || ms.sampleValue}
					<dt>Sample alert source</dt>
					<dd class="mono">
						{ms.sampleValue}
						{#if ms.sampleScope}
							<span class="muted">({ms.sampleScope})</span>
						{/if}
					</dd>
				{/if}
			</dl>

			<div class="modal-section">
				<h4>Documentation</h4>
				{#if hubURL(ms.name)}
					<a
						href={hubURL(ms.name)!}
						target="_blank"
						rel="noopener noreferrer"
						class="link"
						data-testid="modal-hub-link"
					>
						{language.current && t('crowdsecDecisions.hubLink')}
					</a>
				{:else}
					<p class="muted">
						{language.current && t('crowdsecDecisions.hubNone')}
					</p>
				{/if}
			</div>

			<div class="modal-section">
				<h4>Inspect</h4>
				<div class="copy-row">
					<code class="copy-code">{cscliCommand(ms.name)}</code>
					<button
						type="button"
						class="copy-btn"
						onclick={() => copyToClipboard(cscliCommand(ms.name))}
					>
						{language.current && t('crowdsecDecisions.copyButton')}
					</button>
				</div>
				<p class="muted">
					{language.current && t('crowdsecDecisions.cscliHintBefore')}
					<code>cscli</code>
					{language.current && t('crowdsecDecisions.cscliHintAfter')}
				</p>
			</div>

			{#if copyToast !== null}
				<div class="copy-toast" role="status">{copyToast}</div>
			{/if}
		</div>
		{#snippet footer()}
			<Button variant="ghost" onclick={closeScenarioModal}>
				{language.current && t('crowdsecDecisions.scenarioModalClose')}
			</Button>
		{/snippet}
		</Modal>
	{/if}
{/if}

<!-- Step CS.3 Commit D — modal mount. Lives OUTSIDE the
     activeTab branches so closing it doesn't depend on a
     specific sub-tab being active. Admin gate: viewer-role
     users never trigger openBanModal (button is hidden) +
     even if they somehow do, the backend rejects with 403.
     We still guard the mount with isAdmin so the modal
     isn't even in the DOM for non-admins. -->
{#if isAdmin}
	<BanIPModal
		bind:open={banModalOpen}
		onClose={closeBanModal}
		onSuccess={onBanSuccess}
	/>
	<ConfirmDialog
		bind:open={unbanDialogOpen}
		title={language.current &&
			t('crowdsecDecisions.unbanConfirmTitle', { value: unbanTarget?.value ?? '' })}
		message={language.current &&
			t('crowdsecDecisions.unbanConfirmMessage', {
				value: unbanTarget?.value ?? '',
				type: unbanTarget?.type || 'ban',
				origin: unbanTarget?.origin || '—'
			})}
		confirmLabel={language.current && t('crowdsecDecisions.btnUnban')}
		cancelLabel={language.current && t('common.cancel')}
		onConfirm={confirmUnban}
	/>
{/if}

<style>
	.tab-subtitle {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0.5rem 0 1rem 0;
		max-width: 56rem;
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
	.error-banner {
		padding: 0.75rem 1rem;
		color: var(--status-down);
		background: rgba(255, 0, 0, 0.05);
		border-radius: 4px;
	}
	.error-banner .muted {
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
		margin: 0.4rem 0 0 0;
	}
	.retry-btn {
		display: inline-block;
		margin-top: 0.5rem;
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
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
		max-width: 40rem;
		margin: 0 auto;
	}
	.link {
		color: var(--accent-cyan);
		text-decoration: underline;
	}
	.filter-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
		margin: 0 0 1rem 0;
		flex-wrap: wrap;
	}
	.active-toggle,
	.live-filters {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}
	.active-toggle button {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.active-toggle button.active {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border-color: var(--accent-cyan);
	}
	.filter-label {
		display: inline-flex;
		gap: 0.4rem;
		align-items: center;
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.filter-label select {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.2rem 0.5rem;
		border-radius: 4px;
		font-size: var(--text-sm);
	}
	.meta {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		display: inline-flex;
		gap: 0.4rem;
		align-items: center;
	}
	.meta .muted {
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
	}
	.refresh-btn {
		background: transparent;
		color: var(--text-secondary);
		border: none;
		padding: 0 0.4rem;
		font-size: 1rem;
		cursor: pointer;
	}
	.refresh-btn:hover {
		color: var(--accent-cyan);
	}
	/* CS.3 Commit D — Bannir une IP button. Distinct visual
	   from the refresh chevron because it triggers a
	   destructive action (admin-only ban modal). */
	.ban-btn {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border: 1px solid var(--accent-cyan);
		padding: 0.2rem 0.6rem;
		border-radius: 4px;
		font-size: var(--text-xs, 11px);
		font-weight: 600;
		cursor: pointer;
		margin-left: 0.5rem;
	}
	.ban-btn:hover {
		filter: brightness(1.05);
	}
	.ban-btn:focus-visible {
		outline: 2px solid var(--text-primary);
		outline-offset: 1px;
	}
	/* Unban row action — quiet until hovered: the table is read
	   far more often than it is edited. */
	.unban-btn {
		background: transparent;
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.1rem 0.5rem;
		border-radius: 4px;
		font-size: var(--text-xs, 11px);
		cursor: pointer;
		white-space: nowrap;
	}
	.unban-btn:hover {
		color: var(--status-down);
		border-color: var(--status-down);
	}
	.unban-btn:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	/* CS.3 Commit B — origin tabs row.
	   .breakdown / .breakdown-chip / .chip-count / .chip-label
	   styles deleted (chips replaced by Tabs.svelte). */
	.origin-tabs-row {
		margin: 0 0 0.5rem 0;
	}
	/* Manual-ban scenario cell — two lines stacked. Line 1
	   keeps the table's primary readability; line 2 is the
	   operator reason in italic gray smaller text. */
	.manual-line1 {
		font-family: var(--font-mono, monospace);
	}
	.manual-line2 {
		margin-top: 0.15rem;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
		white-space: normal;
		word-break: break-word;
	}
	.block {
		padding: 1rem;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm, 13px);
	}
	th,
	td {
		padding: 0.4rem 0.6rem;
		text-align: left;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
		vertical-align: top;
	}
	th {
		color: var(--text-secondary);
		font-weight: 500;
		font-size: var(--text-xs, 11px);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.ts {
		font-family: var(--font-mono, monospace);
		color: var(--text-secondary);
		white-space: nowrap;
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.badge {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 3px;
		color: var(--text-on-color, #ffffff);
		font-size: var(--text-xs, 11px);
		font-weight: 600;
		letter-spacing: 0.04em;
		white-space: nowrap;
	}
	.auto-badge {
		background: var(--accent-cyan);
		margin-left: 0.4rem;
		font-size: var(--text-xs, 10px);
		text-transform: uppercase;
	}
	.empty-inline {
		padding: 1rem;
		text-align: center;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm, 13px);
	}
	/* Step CS.2.C — Scenarios tab */
	.scenario-row {
		cursor: pointer;
	}
	.scenario-row:hover {
		background: var(--bg-hover);
	}
	.scenario-row:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
	.muted {
		color: var(--text-muted);
		font-size: var(--text-xs, 11px);
	}
	.org {
		margin-left: 0.4rem;
		font-family: var(--font-mono, monospace);
	}
	/* Anchors the copy toast now that Modal owns the dialog box. */
	.scenario-modal-body {
		position: relative;
	}
	.modal-dl {
		display: grid;
		grid-template-columns: 10rem 1fr;
		gap: 0.4rem 0.75rem;
		margin: 0 0 1rem 0;
		font-size: var(--text-sm);
	}
	.modal-dl dt {
		color: var(--text-secondary);
	}
	.modal-dl dd {
		margin: 0;
		color: var(--text-primary);
	}
	.modal-section {
		margin: 0.75rem 0;
		padding-top: 0.5rem;
		border-top: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.modal-section h4 {
		font-size: var(--text-sm);
		margin: 0 0 0.5rem 0;
		color: var(--text-secondary);
		font-weight: 500;
	}
	.copy-row {
		display: flex;
		gap: 0.5rem;
		align-items: stretch;
	}
	.copy-code {
		flex: 1;
		font-family: var(--font-mono, monospace);
		font-size: var(--text-xs, 11px);
		background: var(--bg-default, #000);
		color: var(--text-primary);
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		overflow-x: auto;
		white-space: nowrap;
	}
	.copy-btn {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		cursor: pointer;
	}
	.copy-btn:hover {
		background: var(--bg-hover);
	}
	.copy-toast {
		position: absolute;
		bottom: 0;
		right: 0;
		background: var(--accent-cyan);
		color: var(--text-inverse);
		padding: 0.3rem 0.7rem;
		border-radius: 4px;
		font-size: var(--text-xs, 11px);
		font-weight: 600;
	}
</style>
