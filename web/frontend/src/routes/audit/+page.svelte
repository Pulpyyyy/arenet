<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Audit page (spec §6.11 + §9). Hard-auth gated server-side; the
  parent +layout.svelte gates the rendering by auth.state. Accessing
  this page emits an `audit_viewed` event server-side (spec §4.10).

  UI: filters with 300ms auto-apply debounce, color-coded action
  badges by category, expand/collapse rows showing full JSON.
  Cursor-based pagination via Load more.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { auditApi, type AuditEvent, type AuditFilter } from '$lib/api/audit';
	import { ApiError } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { pushToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Input from '$lib/components/Input.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import AuditRow from '$lib/components/AuditRow.svelte';
	import AuditExpandedDetails from '$lib/components/AuditExpandedDetails.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';

	// 15 action values per D7 (canonical list lives in
	// docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md).
	// Empty string at index 0 = "All actions" in the dropdown.
	const ACTIONS = [
		'',
		'login_success',
		'login_failure',
		'logout',
		'unlock_success',
		'unlock_failure',
		'session_revoked',
		'setup_admin_created',
		'password_changed',
		'route_created',
		'route_updated',
		'route_deleted',
		'audit_viewed',
		'password_hibp_clean',
		'password_hibp_pending',
		'password_compromised_detected'
	];

	const DEBOUNCE_MS = 300;
	const PAGE_SIZE = 50;

	let fromValue = $state('');
	let toValue = $state('');
	let actionFilter = $state('');
	// Step G G.4: actorFilter holds the UUID used for the backend query;
	// actorFilterDisplayName is the cosmetic human label captured at the
	// click moment (admin / username / snapshot). Both states move in
	// lockstep — set together in onFilterByActor, reset together in
	// removePill / clearAllFilters. The displayName is intentionally
	// NOT persisted (filter state is in-memory only, no URL sync, no
	// localStorage), so its lifecycle matches the UUID's.
	let actorFilter = $state('');
	let actorFilterDisplayName = $state('');

	let events = $state<AuditEvent[]>([]);
	let nextCursor = $state('');
	let loading = $state(false);
	let loadMoreLoading = $state(false);
	let loadError = $state('');
	let didInitialLoad = $state(false);

	let debounceTimer: ReturnType<typeof setTimeout> | null = null;
	let suppressEffectReload = true; // skip the very first $effect fire (mount only)

	function buildFilter(append: boolean): AuditFilter {
		const filter: AuditFilter = { limit: PAGE_SIZE };
		if (fromValue) filter.from = fromValue;
		if (toValue) filter.to = toValue;
		if (actionFilter) filter.action = actionFilter;
		if (actorFilter) filter.actorUserId = actorFilter;
		if (append && nextCursor) filter.cursor = nextCursor;
		return filter;
	}

	async function load(reset: boolean): Promise<void> {
		if (reset) {
			loading = true;
		} else {
			loadMoreLoading = true;
		}
		loadError = '';
		try {
			const res = await auditApi.list(buildFilter(!reset));
			events = reset ? res.events : [...events, ...res.events];
			nextCursor = res.nextCursor;
		} catch (err) {
			if (reset) {
				// Initial / filter-change load failure → in-page banner.
				loadError = err instanceof ApiError ? err.message : 'Failed to load audit events';
			} else {
				// "Load more" failure → toast; existing rows stay visible.
				const msg = err instanceof ApiError ? err.message : 'Failed to load more events';
				pushToast(msg, 'danger');
			}
		} finally {
			loading = false;
			loadMoreLoading = false;
			didInitialLoad = true;
		}
	}

	function scheduleReload(): void {
		if (debounceTimer !== null) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => {
			void load(true);
		}, DEBOUNCE_MS);
	}

	// Auto-apply filter changes. The first $effect fire is the mount,
	// which we suppress; subsequent changes go through scheduleReload.
	$effect(() => {
		// Read all filter values to subscribe to changes.
		void (fromValue + toValue + actionFilter + actorFilter);
		if (suppressEffectReload) {
			suppressEffectReload = false;
			return;
		}
		scheduleReload();
	});

	onMount(() => {
		void load(true);
	});

	function onFilterByAction(action: string): void {
		actionFilter = action;
		// The $effect picks up the change and schedules a reload.
	}

	function onFilterByActor(actorUserId: string, displayName: string): void {
		actorFilter = actorUserId;
		actorFilterDisplayName = displayName;
	}

	function removePill(field: 'from' | 'to' | 'action' | 'actor'): void {
		if (field === 'from') fromValue = '';
		else if (field === 'to') toValue = '';
		else if (field === 'action') actionFilter = '';
		else if (field === 'actor') {
			actorFilter = '';
			actorFilterDisplayName = '';
		}
	}

	function clearAllFilters(): void {
		fromValue = '';
		toValue = '';
		actionFilter = '';
		actorFilter = '';
		actorFilterDisplayName = '';
	}

	const hasAnyFilter = $derived(
		Boolean(fromValue || toValue || actionFilter || actorFilter)
	);

	const emptyStateMessage = $derived(
		language.current &&
			(hasAnyFilter
				? t('audit.emptyFiltered')
				: t('audit.emptyNoFilters'))
	);

	// Status line for screen readers (spec §9.10).
	const a11yStatus = $derived.by(() => {
		void language.current;
		if (loading) return t('audit.a11yLoading');
		if (loadError) return t('audit.a11yError', { err: loadError });
		if (events.length === 0 && didInitialLoad) return emptyStateMessage;
		return t('audit.a11yCount', { count: events.length, plural: events.length === 1 ? '' : 's' });
	});
</script>

<svelte:head>
	<title>{language.current && t('audit.headTitle')}</title>
</svelte:head>

<PageHeader
	title={language.current && t('pageTitles.audit')}
	subtitle={language.current && t('audit.subtitle')}
>
	{#snippet actions()}
		{#if hasAnyFilter}
			<Button variant="ghost" size="sm" onclick={clearAllFilters}>
				{language.current && t('audit.btnClearFilters')}
			</Button>
		{/if}
	{/snippet}
</PageHeader>

<div class="space-y-6">
	<!-- Filters: changes auto-apply with 300ms debounce -->
	<div
		class="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-elevated border border-border-default rounded-lg"
	>
		<Input
			bind:value={fromValue}
			label={language.current && t('audit.filterFromLabel')}
			placeholder="2026-05-01T00:00:00Z"
		/>
		<Input
			bind:value={toValue}
			label={language.current && t('audit.filterToLabel')}
			placeholder="2026-05-18T00:00:00Z"
		/>
		<div>
			<label
				for="audit-action-filter"
				class="text-sm font-medium text-secondary mb-1.5 block"
			>
				{language.current && t('audit.filterActionLabel')}
			</label>
			<select
				id="audit-action-filter"
				bind:value={actionFilter}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each ACTIONS as action (action)}
					<option value={action}>{action || (language.current && t('audit.filterAllActions'))}</option>
				{/each}
			</select>
		</div>
	</div>

	{#if hasAnyFilter}
		<!-- Active filter pills (spec §9.3) -->
		<div class="flex flex-wrap items-center gap-2">
			{#if actionFilter}
				<span class="filter-pill">
					{language.current && t('audit.pillActionPrefix', { value: actionFilter })}
					<button
						type="button"
						aria-label={language.current && t('audit.ariaRemoveFilterAction', { value: actionFilter })}
						onclick={() => removePill('action')}
					>×</button>
				</span>
			{/if}
			{#if actorFilter}
				<span class="filter-pill">
					{language.current && t('audit.pillActorPrefix', { value: actorFilterDisplayName || actorFilter })}
					<button
						type="button"
						aria-label={language.current && t('audit.ariaRemoveFilterActor', { value: actorFilterDisplayName || actorFilter })}
						onclick={() => removePill('actor')}
					>×</button>
				</span>
			{/if}
			{#if fromValue}
				<span class="filter-pill">
					{language.current && t('audit.pillFromPrefix', { value: fromValue })}
					<button
						type="button"
						aria-label={language.current && t('audit.ariaRemoveFilterFrom', { value: fromValue })}
						onclick={() => removePill('from')}
					>×</button>
				</span>
			{/if}
			{#if toValue}
				<span class="filter-pill">
					{language.current && t('audit.pillToPrefix', { value: toValue })}
					<button
						type="button"
						aria-label={language.current && t('audit.ariaRemoveFilterTo', { value: toValue })}
						onclick={() => removePill('to')}
					>×</button>
				</span>
			{/if}
			<!-- "Clear all filters" button moved to PageHeader actions
			     slot in Chunk 5.2. The per-pill × buttons stay here for
			     granular removal; the bulk-clear action lives at the
			     page level. -->
		</div>
	{/if}

	{#if loadError}
		<div
			class="p-4 rounded bg-down/10 border border-down text-down flex items-center justify-between"
			role="alert"
		>
			<span>{language.current && t('audit.loadErr', { err: loadError })}</span>
			<Button variant="secondary" size="sm" onclick={() => load(true)} disabled={loading}>
				{#snippet children()}{language.current && t('audit.btnRetry')}{/snippet}
			</Button>
		</div>
	{/if}

	{#if loading && events.length === 0}
		<div class="flex justify-center mt-12">
			<Spinner size="lg" />
		</div>
	{:else if events.length === 0 && didInitialLoad && !loadError}
		<!-- v2.41 — was a single centred line. Two distinct empty
		     situations deserve two answers: a filter that matched
		     nothing (clear it) and a log that has recorded nothing
		     yet (say what will land here). -->
		{#if hasAnyFilter}
			<EmptyState
				tone="filter"
				testid="audit-empty-filtered"
				title={language.current && t('audit.emptyFilteredTitle')}
				body={language.current && t('audit.emptyFiltered')}
				actionLabel={language.current && t('audit.btnClearFilters')}
				onAction={clearAllFilters}
			/>
		{:else}
			<EmptyState
				testid="audit-empty"
				title={language.current && t('audit.emptyNoFiltersTitle')}
				body={language.current && t('audit.emptyNoFiltersBody')}
			/>
		{/if}
	{:else if events.length > 0}
		<DataTable
			items={events}
			headers={language.current ? [
				t('audit.colTime'),
				t('audit.colAction'),
				t('audit.colActor'),
				t('audit.colTarget'),
				t('audit.colIp')
			] : []}
			row={auditRowSnippet}
			expanded={auditExpandedSnippet}
			rowLabel={(ev: AuditEvent) => `${ev.action}, ${relativeTime(ev.timestamp)}`}
		/>

		{#if nextCursor}
			<div class="flex justify-center">
				<Button
					variant="secondary"
					size="md"
					onclick={() => load(false)}
					disabled={loadMoreLoading}
					loading={loadMoreLoading}
				>
					{#snippet children()}
						<span>{language.current && (loadMoreLoading ? t('audit.btnLoading') : t('audit.btnLoadMore'))}</span>
					{/snippet}
				</Button>
			</div>
		{/if}
	{/if}
</div>

<!-- Screen reader status announcer (spec §9.10) -->
<div role="status" aria-live="polite" class="sr-only">{a11yStatus}</div>

{#snippet auditRowSnippet(ev: AuditEvent)}
	<AuditRow
		event={ev}
		onFilterAction={onFilterByAction}
		onFilterActor={onFilterByActor}
	/>
{/snippet}

{#snippet auditExpandedSnippet(ev: AuditEvent)}
	<AuditExpandedDetails event={ev} />
{/snippet}

<style>
	.filter-pill {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.25rem 0.5rem 0.25rem 0.75rem;
		font-size: 12px;
		border-radius: 9999px;
		border: 1px solid var(--border-default);
		background: var(--bg-elevated);
		color: var(--text-primary);
	}
	.filter-pill button {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 1.25rem;
		height: 1.25rem;
		border-radius: 9999px;
		color: var(--text-secondary);
		transition: background-color 100ms, color 100ms;
	}
	.filter-pill button:hover {
		background-color: var(--bg-hover);
		color: var(--text-primary);
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
</style>
