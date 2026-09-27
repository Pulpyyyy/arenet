<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.2 — Channels tab. Table of alerting channels with
  Édit / Test / Supprimer per row + "Ajouter un canal"
  button opening ChannelModal. Mirrors the AL.4.b.1
  HistoryTab structure for empty/loading/error states.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { channelsStore } from '$lib/stores/alerting.svelte';
	import {
		severityBadgeVariant,
		severityLabelFR,
		severityTooltip,
		type AlertChannel
	} from '$lib/api/alerting';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import ChannelModal from './ChannelModal.svelte';
	import ChannelKindIcon from './ChannelKindIcon.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	const channels = $derived(channelsStore.state.channels);
	const loading = $derived(channelsStore.state.loading);
	const loadError = $derived(channelsStore.state.loadError);

	let didInitialLoad = $state(false);

	let modalOpen = $state(false);
	let modalChannel = $state<AlertChannel | null>(null);

	let confirmOpen = $state(false);
	let confirmTarget = $state<AlertChannel | null>(null);

	// Per-row in-flight flags. Keyed by channel ID so the
	// table can disable per-row action buttons while a
	// test / delete is running without freezing the rest
	// of the table.
	let testingIds = $state<Record<string, boolean>>({});
	let deletingIds = $state<Record<string, boolean>>({});

	async function reload() {
		await channelsStore.load();
		didInitialLoad = true;
	}

	onMount(() => {
		void reload();
	});

	function openCreate() {
		modalChannel = null;
		modalOpen = true;
	}

	function openEdit(c: AlertChannel) {
		modalChannel = c;
		modalOpen = true;
	}

	function closeModal() {
		modalOpen = false;
		modalChannel = null;
	}

	async function onModalSaved() {
		modalOpen = false;
		modalChannel = null;
		// The store appended/replaced optimistically; a full
		// reload pulls fresh LastSentAt/LastError fields in
		// case a test was fired from inside the modal.
		await reload();
	}

	async function onTest(c: AlertChannel) {
		testingIds[c.id] = true;
		try {
			const res = await channelsStore.test(c.id);
			if (res.ok) {
				pushToast(t('alerting.channels.toastTestedOk', { name: c.name }), 'success');
			} else {
				pushToast(
					t('alerting.channels.toastTestedFail', { name: c.name, err: res.error ?? t('alerting.channels.toastUnknownErr') }),
					'danger'
				);
			}
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			pushToast(t('alerting.channels.toastTestNamedErr', { name: c.name, err: msg }), 'danger');
		} finally {
			testingIds = { ...testingIds, [c.id]: false };
			// Refresh to pick up LastSentAt/LastError changes.
			void reload();
		}
	}

	function askDelete(c: AlertChannel) {
		confirmTarget = c;
		confirmOpen = true;
	}

	async function confirmDelete() {
		const target = confirmTarget;
		if (!target) return;
		deletingIds[target.id] = true;
		confirmOpen = false;
		try {
			await channelsStore.remove(target.id);
			pushToast(t('alerting.channels.toastDeleted', { name: target.name }), 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			pushToast(t('alerting.channels.toastDeleteFailed', { err: msg }), 'danger');
		} finally {
			deletingIds = { ...deletingIds, [target.id]: false };
			confirmTarget = null;
		}
	}

	// v2.54 — Discord was missing from both switches, so it showed as a
	// bullet next to a lowercase "discord" while Email had an envelope
	// and a capital. The icon now lives in ChannelKindIcon.
	function kindLabel(kind: string): string {
		switch (kind) {
			case 'webhook':
				return 'Webhook';
			case 'email':
				return 'Email';
			case 'discord':
				return 'Discord';
			default:
				return kind;
		}
	}

	function lastSentLabel(c: AlertChannel): string {
		void language.current;
		if (!c.lastSentAt) return t('alerting.never');
		return relativeTime(c.lastSentAt);
	}
</script>

<div class="space-y-4">
	<div class="flex justify-end">
		<Button variant="primary" onclick={openCreate}>
			{#snippet children()}{language.current && t('alerting.channels.addBtn')}{/snippet}
		</Button>
	</div>

	{#if loadError}
		<div
			class="p-4 rounded bg-down/10 border border-down text-down flex items-center justify-between"
			role="alert"
		>
			<span>{language.current && t('alerting.channels.loadErr', { err: loadError })}</span>
			<Button variant="secondary" size="sm" onclick={reload} disabled={loading}>
				{#snippet children()}{language.current && t('alerting.actionRetry')}{/snippet}
			</Button>
		</div>
	{/if}

	{#if loading && channels.length === 0}
		<div class="flex justify-center mt-12">
			<Spinner size="lg" />
		</div>
	{:else if channels.length === 0 && didInitialLoad && !loadError}
		<div class="rounded-lg border border-border-subtle bg-elevated p-8 text-center">
			<div class="text-4xl text-muted mb-3">🔔</div>
			<p class="text-primary font-medium mb-1">{language.current && t('alerting.channels.emptyTitle')}</p>
			<p class="text-secondary text-sm max-w-md mx-auto">
				{language.current && t('alerting.channels.emptyBody')}
			</p>
		</div>
	{:else if channels.length > 0}
		<DataTable
			items={channels}
			headers={language.current ? [
				t('alerting.channels.colName'),
				t('alerting.channels.colType'),
				t('alerting.channels.colState'),
				t('alerting.channels.colMinSeverity'),
				t('alerting.channels.colLastSent'),
				t('alerting.channels.colError'),
				t('alerting.channels.colActions')
			] : []}
			row={channelRow}
			interactive={false}
		/>
	{/if}
</div>

{#snippet channelRow(c: AlertChannel)}
	<td class="px-4 py-3 text-sm text-primary truncate" title={c.name}>{c.name}</td>
	<td class="px-4 py-3 text-sm text-primary">
		<span class="inline-flex items-center gap-1.5">
			<ChannelKindIcon kind={c.kind} />
			{kindLabel(c.kind)}
		</span>
	</td>
	<td class="px-4 py-3 text-sm">
		{#if c.enabled}
			<Badge variant="status-up">
				{#snippet children()}{language.current && t('alerting.stateEnabled')}{/snippet}
			</Badge>
		{:else}
			<Badge variant="neutral">
				{#snippet children()}{language.current && t('alerting.stateDisabled')}{/snippet}
			</Badge>
		{/if}
	</td>
	<td class="px-4 py-3 text-sm">
		<span title={language.current && t('alerting.channels.severityTooltipPrefix', { tooltip: severityTooltip(c.minSeverity) })}>
			<Badge variant={severityBadgeVariant(c.minSeverity)}>
				{#snippet children()}{severityLabelFR(c.minSeverity)}{/snippet}
			</Badge>
		</span>
	</td>
	<td class="px-4 py-3 text-sm text-secondary" title={c.lastSentAt ?? (language.current && t('alerting.never'))}>
		{lastSentLabel(c)}
	</td>
	<td class="px-4 py-3 text-sm">
		{#if c.lastError}
			<span title={`${c.lastError}\n(${c.lastErrorAt ?? ''})`}>
				<Badge variant="status-down">
					{#snippet children()}{language.current && t('alerting.errorBadge')}{/snippet}
				</Badge>
			</span>
		{:else}
			<span class="text-secondary">—</span>
		{/if}
	</td>
	<td class="px-4 py-3 text-sm">
		<div class="flex gap-2">
			<Button
				variant="ghost"
				size="sm"
				onclick={() => openEdit(c)}
				aria-label={language.current && t('alerting.channels.ariaEdit', { name: c.name })}
			>
				{#snippet children()}{language.current && t('alerting.actionEdit')}{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => onTest(c)}
				disabled={testingIds[c.id]}
				loading={testingIds[c.id]}
				aria-label={language.current && t('alerting.channels.ariaTest', { name: c.name })}
			>
				{#snippet children()}{language.current && t('alerting.actionTest')}{/snippet}
			</Button>
			<Button
				variant="ghost"
				size="sm"
				onclick={() => askDelete(c)}
				disabled={deletingIds[c.id]}
				aria-label={language.current && t('alerting.channels.ariaDelete', { name: c.name })}
			>
				{#snippet children()}{language.current && t('alerting.actionDelete')}{/snippet}
			</Button>
		</div>
	</td>
{/snippet}

<ChannelModal
	open={modalOpen}
	channel={modalChannel}
	onClose={closeModal}
	onSaved={onModalSaved}
/>

<ConfirmDialog
	bind:open={confirmOpen}
	title={language.current && t('alerting.channels.confirmTitle')}
	message={confirmTarget && language.current
		? t('alerting.channels.confirmMessage', { name: confirmTarget.name })
		: ''}
	confirmLabel={language.current && t('alerting.channels.confirmDeleteLabel')}
	cancelLabel={language.current && t('alerting.channels.confirmCancelLabel')}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>
