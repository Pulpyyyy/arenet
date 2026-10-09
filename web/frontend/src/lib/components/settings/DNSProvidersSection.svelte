<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  DNSProvidersSection (v2.12 Task 2c, 2026-07-12).

  Replaces the pre-v2.12 singleton OVH credentials form on
  /settings with a multi-config DNS provider collection: a table
  (Label | Type | Endpoint | Status | Used by | Actions) plus an
  add/edit Modal and a delete ConfirmDialog. Mirrors the
  forward-auth providers section's structure + the J.4 secret
  discipline (blank on edit = preserve-on-edit; secrets never
  displayed).

  The section root carries id="dns-providers" so the wildcard
  wizard's empty-state CTA can deep-link to /settings#dns-providers.

  Delete is guarded server-side: a provider still bound to one or
  more wildcard apexes yields a 409 `provider_in_use` whose
  `params.wildcards` names the offending apexes — surfaced verbatim
  in the danger toast so the operator knows exactly what to detach
  first.

  v2.26 — multi-type: the add/edit form is generated from the
  provider-type registry (GET /settings/dns-providers/types): one
  input per credential field, password inputs for secrets, a select
  for enums. The type is chosen at creation and locked on edit. Each
  row gets a read-only "Test connection" action (POST …/{id}/test).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { settingsApi } from '$lib/api/settings';
	import { ApiError } from '$lib/api/types';
	import type {
		DNSProvider,
		DNSProviderField,
		DNSProviderRequest,
		DNSProviderTestResult,
		DNSProviderType,
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import UnsavedMarker from './UnsavedMarker.svelte';

	interface Props {
		/** Out: the add/edit form is open with edits not yet saved. */
		dirty?: boolean;
	}

	let { dirty = $bindable(false) }: Props = $props();

	let providers = $state<DNSProvider[]>([]);
	let types = $state<DNSProviderType[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	// Modal state. editingId === null → add mode (POST); non-null →
	// edit mode (PUT on /{id}). Secret fields are write-only: blank on
	// edit preserves the stored value (the backend merges against the
	// previous row); editingSecretsSet says which ones are stored.
	let modalOpen = $state(false);
	let editingId = $state<string | null>(null);
	let editingSecretsSet = $state<Record<string, boolean>>({});
	let submitting = $state(false);
	let formError = $state<string | null>(null);
	let form = $state<{ label: string; type: string; credentials: Record<string, string> }>({
		label: '',
		type: '',
		credentials: {},
	});

	const formType = $derived(types.find((ty) => ty.type === form.type));

	// The form as the modal opened with it. Stored secrets are blank
	// then ("keep"), so only a typed secret counts as an edit.
	let openedKey = $state('');
	const isDirty = $derived(modalOpen && JSON.stringify(form) !== openedKey);
	$effect(() => {
		dirty = isDirty;
	});

	// Delete state.
	let deleteOpen = $state(false);
	let deleteTarget = $state<DNSProvider | null>(null);

	// Connection-test state.
	let testOpen = $state(false);
	let testTarget = $state<DNSProvider | null>(null);
	let testZone = $state('');
	let testRunning = $state(false);
	let testResult = $state<DNSProviderTestResult | null>(null);
	let testError = $state<string | null>(null);

	function typeLabel(type: string): string {
		return types.find((ty) => ty.type === type)?.label ?? type;
	}

	function fieldLabel(type: string, f: DNSProviderField): string {
		const key = `settings.dnsProviders.fields.${type}.${f.key}`;
		const translated = t(key);
		// A type the UI has no translation for yet falls back to the
		// backend's English label instead of showing the raw key.
		return translated === key ? f.label : translated;
	}

	/** Non-secret credential values shown in the table. */
	function details(p: DNSProvider): string {
		return Object.values(p.fields ?? {})
			.filter((v) => v !== '')
			.join(' · ');
	}

	function defaultsFor(type: string): Record<string, string> {
		const creds: Record<string, string> = {};
		for (const f of types.find((ty) => ty.type === type)?.fields ?? []) {
			creds[f.key] = f.default ?? (f.enum?.[0] ?? '');
		}
		return creds;
	}

	async function loadProviders(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			const [list, registry] = await Promise.all([
				settingsApi.listDNSProviders(),
				types.length > 0 ? Promise.resolve(types) : settingsApi.listDNSProviderTypes(),
			]);
			providers = list;
			types = registry;
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	}

	function openAdd(): void {
		const first = types[0]?.type ?? '';
		editingId = null;
		editingSecretsSet = {};
		form = { label: '', type: first, credentials: defaultsFor(first) };
		openedKey = JSON.stringify(form);
		formError = null;
		modalOpen = true;
	}

	function onTypeChange(type: string): void {
		form.type = type;
		form.credentials = defaultsFor(type);
	}

	function openEdit(p: DNSProvider): void {
		editingId = p.id;
		editingSecretsSet = { ...(p.secretsSet ?? {}) };
		const credentials = defaultsFor(p.type);
		for (const [k, v] of Object.entries(p.fields ?? {})) credentials[k] = v;
		// Secrets stay blank on edit — the wire never carries them and a
		// blank submit preserves the stored value.
		for (const k of Object.keys(editingSecretsSet)) credentials[k] = '';
		form = { label: p.label, type: p.type, credentials };
		openedKey = JSON.stringify(form);
		formError = null;
		modalOpen = true;
	}

	function closeModal(): void {
		if (submitting) return;
		modalOpen = false;
	}

	/** First required field left empty, or null. A stored secret left
	 *  blank on edit counts as set (preserve-on-edit). */
	function missingRequired(): DNSProviderField | null {
		for (const f of formType?.fields ?? []) {
			if (!f.required || (form.credentials[f.key] ?? '').trim() !== '') continue;
			if (f.secret && editingId !== null && editingSecretsSet[f.key]) continue;
			return f;
		}
		return null;
	}

	async function submitForm(): Promise<void> {
		if (submitting) return;
		const label = form.label.trim();
		if (label === '') {
			formError = t('settings.dnsProviders.validation.labelRequired');
			return;
		}
		const missing = missingRequired();
		if (missing) {
			formError = t('settings.dnsProviders.validation.fieldRequired', {
				field: fieldLabel(form.type, missing),
			});
			return;
		}
		submitting = true;
		formError = null;
		// Only non-empty values are sent: a blank secret on edit triggers
		// the backend's preserve-on-edit path, a blank optional field is
		// cleared.
		const credentials: Record<string, string> = {};
		for (const [k, v] of Object.entries(form.credentials)) {
			if (v.trim() !== '') credentials[k] = v.trim();
		}
		const body: DNSProviderRequest = { label, type: form.type, credentials };
		try {
			if (editingId === null) {
				await settingsApi.createDNSProvider(body);
				pushToast(t('settings.dnsProviders.toast.created'), 'success');
			} else {
				await settingsApi.updateDNSProvider(editingId, body);
				pushToast(t('settings.dnsProviders.toast.updated'), 'success');
			}
			modalOpen = false;
			await loadProviders();
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
		} finally {
			submitting = false;
		}
	}

	function openTest(p: DNSProvider): void {
		testTarget = p;
		testZone = p.usedBy[0] ?? '';
		testResult = null;
		testError = null;
		testOpen = true;
	}

	function closeTest(): void {
		if (testRunning) return;
		testOpen = false;
	}

	async function runTest(): Promise<void> {
		const target = testTarget;
		if (!target || testRunning) return;
		testRunning = true;
		testResult = null;
		testError = null;
		try {
			testResult = await settingsApi.testDNSProvider(target.id, testZone.trim());
		} catch (err) {
			if (err instanceof ApiError && err.code === 'zone_required') {
				testError = t('settings.dnsProviders.test.zoneRequired');
			} else if (err instanceof ApiError && err.code === 'invalid_zone') {
				testError = t('settings.dnsProviders.test.invalidZone');
			} else if (err instanceof ApiError && err.code === 'provider_not_configured') {
				testError = t('settings.dnsProviders.test.notConfigured');
			} else {
				testError = err instanceof Error ? err.message : String(err);
			}
		} finally {
			testRunning = false;
		}
	}

	function openDelete(p: DNSProvider): void {
		deleteTarget = p;
		deleteOpen = true;
	}

	async function confirmDelete(): Promise<void> {
		const target = deleteTarget;
		if (!target) return;
		try {
			await settingsApi.deleteDNSProvider(target.id);
			pushToast(t('settings.dnsProviders.toast.deleted'), 'success');
			deleteOpen = false;
			deleteTarget = null;
			await loadProviders();
		} catch (err) {
			if (err instanceof ApiError && err.code === 'provider_in_use') {
				const wildcards = Array.isArray(err.params?.wildcards)
					? (err.params.wildcards as string[])
					: [];
				pushToast(
					t('settings.dnsProviders.delete.error409', {
						wildcards: wildcards.join(', '),
					}),
					'danger',
				);
			} else if (err instanceof ApiError && err.code === 'provider_in_use_by_routes') {
				const routes = Array.isArray(err.params?.routes)
					? (err.params.routes as string[])
					: [];
				pushToast(
					t('settings.dnsProviders.delete.error409Routes', {
						routes: routes.join(', '),
					}),
					'danger',
				);
			} else {
				const msg = err instanceof Error ? err.message : String(err);
				pushToast(
					t('settings.dnsProviders.delete.errorGeneric', { err: msg }),
					'danger',
				);
			}
			// Keep the dialog open so the operator can retry / cancel.
		}
	}

	onMount(() => {
		void loadProviders();
	});
</script>

<div id="dns-providers" class="mb-6">
	<Card padding="p-6">
		<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
			<div>
				<h2 class="text-xl font-semibold">
					{language.current && t('settings.dnsProviders.title')}
				</h2>
				<UnsavedMarker dirty={isDirty} testid="dns-providers-unsaved" />
				<p class="text-xs text-muted mt-1">
					{language.current && t('settings.dnsProviders.subtitle')}
				</p>
			</div>
			{#if !loading && providers.length > 0}
				<Button onclick={openAdd} data-testid="dns-provider-add">
					{language.current && t('settings.dnsProviders.table.addButton')}
				</Button>
			{/if}
		</header>

		{#if loading}
			<div class="flex items-center gap-2 py-4 text-secondary text-sm">
				<Spinner size="sm" />
				{language.current && t('settings.dnsProviders.loading')}
			</div>
		{:else if loadError}
			<p class="text-sm text-down mb-3" role="alert">
				{language.current && t('settings.dnsProviders.loadError', { err: loadError })}
			</p>
		{:else if providers.length === 0}
			<div class="flex flex-col items-start gap-3 py-4">
				<Button onclick={openAdd} data-testid="dns-provider-empty-add">
					{language.current && t('settings.dnsProviders.table.emptyCta')}
				</Button>
			</div>
		{:else}
			<div class="overflow-x-auto">
				<table class="w-full text-sm">
					<thead>
						<tr class="text-left text-xs text-secondary uppercase">
							<th class="py-2 pr-3">{language.current && t('settings.dnsProviders.table.label')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.type')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.details')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.status')}</th>
							<th class="py-2 px-2">{language.current && t('settings.dnsProviders.table.usedBy')}</th>
							<th class="py-2 pl-2 text-right">{language.current && t('settings.dnsProviders.table.actions')}</th>
						</tr>
					</thead>
					<tbody>
						{#each providers as p (p.id)}
							<tr class="border-t border-border-subtle" data-testid={`dns-provider-row-${p.id}`}>
								<td class="py-2 pr-3 text-primary">{p.label}</td>
								<td class="py-2 px-2 text-secondary">{typeLabel(p.type)}</td>
								<td class="py-2 px-2 font-mono text-secondary">{details(p)}</td>
								<td class="py-2 px-2">
									{#if p.configured}
										<Badge variant="status-up"
											>{language.current && t('settings.dnsProviders.badge.configured')}</Badge
										>
									{:else}
										<Badge variant="status-warn"
											>{language.current && t('settings.dnsProviders.badge.notConfigured')}</Badge
										>
									{/if}
								</td>
								<td class="py-2 px-2 text-secondary">
									{#if p.usedBy.length > 0}
										<span class="font-mono">{p.usedBy.join(', ')}</span>
									{:else}
										<span class="text-muted"
											>{language.current && t('settings.dnsProviders.table.usedByNone')}</span
										>
									{/if}
								</td>
								<td class="py-2 pl-2 text-right whitespace-nowrap">
									<Button
										variant="ghost"
										size="sm"
										onclick={() => openTest(p)}
										disabled={!p.configured}
										data-testid={`dns-provider-test-${p.id}`}
										aria-label={language.current && t('settings.dnsProviders.table.test')}
									>
										⚡
									</Button>
									<Button
										variant="ghost"
										size="sm"
										onclick={() => openEdit(p)}
										data-testid={`dns-provider-edit-${p.id}`}
										aria-label={language.current &&
											t('settings.dnsProviders.modal.editTitle')}
									>
										✎
									</Button>
									<Button
										variant="ghost"
										size="sm"
										onclick={() => openDelete(p)}
										data-testid={`dns-provider-delete-${p.id}`}
										aria-label={language.current &&
											t('settings.dnsProviders.delete.confirmTitle')}
									>
										🗑
									</Button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</Card>
</div>

<Modal
	open={modalOpen}
	title={language.current &&
		(editingId === null
			? t('settings.dnsProviders.modal.addTitle')
			: t('settings.dnsProviders.modal.editTitle'))}
	onClose={closeModal}
	width="lg"
>
	<form
		class="grid grid-cols-1 md:grid-cols-2 gap-4"
		data-testid="dns-provider-form"
		onsubmit={(e) => {
			e.preventDefault();
			void submitForm();
		}}
	>
		<div class="md:col-span-2">
			<label for="dnsp-label" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.labelField')}
			</label>
			<input
				id="dnsp-label"
				type="text"
				bind:value={form.label}
				disabled={submitting}
				autocomplete="off"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			/>
		</div>

		<div class="md:col-span-2">
			<label for="dnsp-type" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.modal.typeField')}
			</label>
			<select
				id="dnsp-type"
				value={form.type}
				onchange={(e) => onTypeChange((e.currentTarget as HTMLSelectElement).value)}
				disabled={submitting || editingId !== null}
				data-testid="dns-provider-type"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each types as ty (ty.type)}
					<option value={ty.type}>{ty.label}</option>
				{/each}
			</select>
			{#if editingId !== null}
				<p class="text-xs text-muted mt-1">
					{language.current && t('settings.dnsProviders.modal.typeLocked')}
				</p>
			{/if}
			{#if formType?.docsUrl}
				<a
					href={formType.docsUrl}
					target="_blank"
					rel="noopener noreferrer"
					class="text-xs text-cyan hover:underline mt-1 inline-block"
					data-testid="dns-provider-docs-link"
				>
					{language.current && t('settings.dnsProviders.modal.docsLink')} ↗
				</a>
			{/if}
		</div>

		{#each formType?.fields ?? [] as f (form.type + ':' + f.key)}
			<div>
				<label for={`dnsp-f-${f.key}`} class="text-sm font-medium text-secondary block mb-1">
					{language.current && fieldLabel(form.type, f)}
					{#if f.required}
						<span class="text-down" aria-hidden="true">*</span>
						<span class="sr-only">({language.current && t('settings.dnsProviders.modal.required')})</span>
					{/if}
				</label>
				{#if f.enum && f.enum.length > 0}
					<select
						id={`dnsp-f-${f.key}`}
						bind:value={form.credentials[f.key]}
						disabled={submitting}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						{#each f.enum as opt (opt)}
							<option value={opt}>{opt}</option>
						{/each}
					</select>
				{:else}
					<input
						id={`dnsp-f-${f.key}`}
						type={f.secret ? 'password' : 'text'}
						autocomplete="off"
						bind:value={form.credentials[f.key]}
						disabled={submitting}
						aria-required={f.required}
						placeholder={f.secret && editingId !== null && editingSecretsSet[f.key]
							? (language.current && t('settings.dnsProviders.modal.secretsKeepHint')) || ''
							: ''}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				{/if}
			</div>
		{/each}

		{#if formError}
			<p class="text-sm text-down md:col-span-2" role="alert" data-testid="dns-provider-form-error">
				{formError}
			</p>
		{/if}

		<!-- Hidden submit so Enter inside a field fires the form. -->
		<button type="submit" class="sr-only" tabindex="-1" aria-hidden="true">Submit</button>
	</form>

	{#snippet footer()}
		<Button variant="ghost" onclick={closeModal} disabled={submitting}>
			{language.current && t('settings.dnsProviders.modal.cancel')}
		</Button>
		<Button variant="primary" onclick={() => void submitForm()} loading={submitting}>
			{language.current &&
				(submitting
					? t('settings.dnsProviders.modal.saving')
					: editingId === null
						? t('settings.dnsProviders.modal.add')
						: t('settings.dnsProviders.modal.save'))}
		</Button>
	{/snippet}
</Modal>

<Modal
	open={testOpen}
	title={language.current && t('settings.dnsProviders.test.title')}
	onClose={closeTest}
>
	<form
		class="flex flex-col gap-3"
		data-testid="dns-provider-test-form"
		onsubmit={(e) => {
			e.preventDefault();
			void runTest();
		}}
	>
		<p class="text-sm text-secondary">
			{testTarget?.label} · {testTarget ? typeLabel(testTarget.type) : ''}
		</p>
		<p class="text-xs text-muted">{language.current && t('settings.dnsProviders.test.intro')}</p>
		<div>
			<label for="dnsp-test-zone" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('settings.dnsProviders.test.zoneField')}
			</label>
			<input
				id="dnsp-test-zone"
				type="text"
				autocomplete="off"
				bind:value={testZone}
				disabled={testRunning}
				placeholder={language.current && t('settings.dnsProviders.test.zonePlaceholder')}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>
		<div aria-live="polite">
			{#if testResult?.ok}
				<p class="text-sm text-up" data-testid="dns-provider-test-ok">
					{language.current &&
						t('settings.dnsProviders.test.ok', {
							records: testResult.records,
							zone: testResult.zone,
						})}
				</p>
			{:else if testResult}
				<p class="text-sm text-down" role="alert" data-testid="dns-provider-test-failed">
					{language.current && t('settings.dnsProviders.test.failed', { err: testResult.error ?? '' })}
				</p>
			{:else if testError}
				<p class="text-sm text-down" role="alert" data-testid="dns-provider-test-failed">
					{testError}
				</p>
			{/if}
		</div>
		<button type="submit" class="sr-only" tabindex="-1" aria-hidden="true">Submit</button>
	</form>

	{#snippet footer()}
		<Button variant="ghost" onclick={closeTest} disabled={testRunning}>
			{language.current && t('settings.dnsProviders.test.close')}
		</Button>
		<Button
			variant="primary"
			onclick={() => void runTest()}
			loading={testRunning}
			data-testid="dns-provider-test-run"
		>
			{language.current &&
				(testRunning ? t('settings.dnsProviders.test.running') : t('settings.dnsProviders.test.run'))}
		</Button>
	{/snippet}
</Modal>

<ConfirmDialog
	bind:open={deleteOpen}
	title={language.current && t('settings.dnsProviders.delete.confirmTitle')}
	message={language.current && t('settings.dnsProviders.delete.confirmText')}
	confirmLabel={language.current && t('settings.dnsProviders.delete.confirm')}
	cancelLabel={language.current && t('settings.dnsProviders.delete.cancel')}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>
