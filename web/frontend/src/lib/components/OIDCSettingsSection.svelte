<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step K.2 — OIDC SSO settings section. Two sub-areas in one
  Card:

    1. Provider config (form, single row): issuer URL, client ID,
       client secret (preserve-on-edit), redirect URL, scopes,
       enabled toggle.

    2. Allowlist editor: add by email + display name; list with
       canonicalisation status badge ("pending" until first login
       canonicalises Sub, "linked" after); delete by email.

  The allowlist is preserved across config edits (server-side, in
  putOIDCConfig). Editing the form does NOT mutate the allowlist;
  use the add/delete actions on the list below.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import {
		ApiError,
		OIDC_PROVIDER_KINDS,
		type OIDCAllowedIdentity,
		type OIDCConfig,
		type OIDCProviderKind
	} from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import UnsavedMarker from '$lib/components/settings/UnsavedMarker.svelte';

	interface Props {
		/** Out: the card holds edits not yet saved (see isDirty). */
		dirty?: boolean;
	}

	let { dirty = $bindable(false) }: Props = $props();

	let config = $state<OIDCConfig | null>(null);
	let allowlist = $state<OIDCAllowedIdentity[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let form = $state({
		enabled: false,
		issuerUrl: '',
		clientId: '',
		clientSecret: '',
		redirectUrl: '',
		acceptUnverifiedEmail: false,
		scopes: 'openid profile email', // space-separated for the textarea/input
		kind: '' as OIDCProviderKind | ''
	});
	let formError = $state('');
	let submitting = $state(false);

	let newEntry = $state({ email: '', displayName: '', sub: '' });
	let allowlistError = $state('');
	let allowlistSubmitting = $state(false);

	// Unsaved: the provider form differs from what was last loaded or
	// saved (the secret is blank then — "keep" — so only a typed one
	// counts), or an allowlist entry is typed but not yet added.
	function formKey(): string {
		return JSON.stringify(form);
	}
	let savedKey = $state(formKey());
	const isDirty = $derived(
		formKey() !== savedKey ||
			[newEntry.email, newEntry.displayName, newEntry.sub].some((v) => v.trim() !== '')
	);
	$effect(() => {
		dirty = isDirty;
	});

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const [cfg, list] = await Promise.all([
				settingsApi.getOIDCConfig(),
				settingsApi.listOIDCAllowlist()
			]);
			config = cfg;
			allowlist = list;
			form.enabled = cfg.enabled;
			form.issuerUrl = cfg.issuerUrl;
			form.clientId = cfg.clientId;
			form.redirectUrl = cfg.redirectUrl;
			form.acceptUnverifiedEmail = cfg.acceptUnverifiedEmail ?? false;
			form.scopes = (cfg.scopes ?? []).join(' ');
			form.kind = (cfg.kind ?? '') as OIDCProviderKind | '';
			// clientSecret stays "" — server redacts on GET; user only
			// types it on explicit rotation. The placeholder tells them
			// what the empty state means.
			form.clientSecret = '';
			savedKey = formKey();
		} catch (err) {
			loadError = err instanceof Error ? err.message : t('oidcSettings.loadFailed', { err: '' });
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});

	async function submitConfig(): Promise<void> {
		if (submitting) return;
		formError = '';
		submitting = true;
		try {
			const scopes = form.scopes
				.split(/[\s,]+/)
				.map((s) => s.trim())
				.filter((s) => s.length > 0);
			const saved = await settingsApi.putOIDCConfig({
				enabled: form.enabled,
				issuerUrl: form.issuerUrl.trim(),
				clientId: form.clientId.trim(),
				clientSecret: form.clientSecret, // empty preserves
				redirectUrl: form.redirectUrl.trim(),
				acceptUnverifiedEmail: form.acceptUnverifiedEmail,
				scopes,
				...(form.kind ? { kind: form.kind } : {})
			});
			config = saved;
			form.scopes = (saved.scopes ?? []).join(' ');
			form.clientSecret = ''; // reset the secret field after save
			savedKey = formKey();
			pushToast(t('oidcSettings.toastSaved'), 'success');
		} catch (err) {
			if (err instanceof ApiError) {
				formError = err.message;
			} else if (err instanceof Error) {
				formError = err.message;
			} else {
				formError = t('oidcSettings.saveFailed');
			}
		} finally {
			submitting = false;
		}
	}

	async function addAllowlistEntry(): Promise<void> {
		if (allowlistSubmitting) return;
		allowlistError = '';
		const email = newEntry.email.trim();
		if (!email) {
			allowlistError = t('oidcSettings.allowlistEmailRequired');
			return;
		}
		allowlistSubmitting = true;
		try {
			const sub = newEntry.sub.trim();
			await settingsApi.addOIDCAllowlist({
				email,
				displayName: newEntry.displayName.trim(),
				...(sub ? { sub } : {})
			});
			newEntry = { email: '', displayName: '', sub: '' };
			allowlist = await settingsApi.listOIDCAllowlist();
			pushToast(t('oidcSettings.allowlistAddedToast', { email }), 'success');
		} catch (err) {
			allowlistError =
				err instanceof Error ? err.message : t('oidcSettings.allowlistAddFailed');
		} finally {
			allowlistSubmitting = false;
		}
	}

	async function deleteAllowlistEntry(email: string): Promise<void> {
		try {
			await settingsApi.deleteOIDCAllowlist(email);
			allowlist = allowlist.filter((e) => e.email !== email);
			pushToast(t('oidcSettings.allowlistRemovedToast', { email }), 'success');
		} catch (err) {
			pushToast(
				err instanceof Error ? err.message : t('oidcSettings.allowlistRemoveFailed'),
				'danger'
			);
		}
	}
</script>

<!-- Wrapper div with mb-6 matches the spacing contract used by
     ServerPositionSection + CrowdSecSettingsSection so sibling
     sections in /settings space consistently — without this,
     OIDC sat flush against CrowdSecSettingsSection. -->
<div class="mb-6">
<Card padding="p-6">
	<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
		<div>
			<h2 class="text-xl font-semibold">{language.current && t('oidcSettings.title')}</h2>
			<UnsavedMarker dirty={isDirty} testid="oidc-unsaved" />
			<p class="text-xs text-muted mt-1">
				{language.current && t('oidcSettings.subtitle')}
			</p>
		</div>
		{#if loading}
			<Spinner size="sm" />
		{:else if config}
			{#if config.enabled && config.configured}
				<Badge variant="status-up">{language.current && t('oidcSettings.statusEnabled')}</Badge>
			{:else if config.configured}
				<Badge variant="status-warn">{language.current && t('oidcSettings.statusConfiguredDisabled')}</Badge>
			{:else}
				<Badge variant="status-warn">{language.current && t('oidcSettings.statusNotConfigured')}</Badge>
			{/if}
		{/if}
	</header>

	{#if loadError}
		<p class="text-sm text-down mb-3" role="alert">
			{language.current && t('oidcSettings.loadFailed', { err: loadError })}
		</p>
	{/if}

	<form
		class="grid grid-cols-1 md:grid-cols-2 gap-4"
		onsubmit={(e) => {
			e.preventDefault();
			void submitConfig();
		}}
	>
		<div class="md:col-span-2">
			<label class="text-sm font-medium text-secondary inline-flex items-center gap-2">
				<input
					type="checkbox"
					bind:checked={form.enabled}
					class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
				/>
				{language.current && t('oidcSettings.labelEnable')}
			</label>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-kind" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('oidcSettings.labelProvider')}
			</label>
			<select
				id="oidc-kind"
				bind:value={form.kind}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each OIDC_PROVIDER_KINDS as k (k)}
					<option value={k}>
						{k === '' ? (language.current && t('oidcSettings.providerGeneric')) : k}
					</option>
				{/each}
			</select>
			<p class="text-xs text-muted mt-1">
				{language.current && t('oidcSettings.providerHelper')}
			</p>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-issuer" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('oidcSettings.labelIssuer')}
			</label>
			<input
				id="oidc-issuer"
				type="url"
				bind:value={form.issuerUrl}
				placeholder="https://auth.example.com/application/o/arenet/"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			/>
			<p class="text-xs text-muted mt-1">
				{language.current && t('oidcSettings.issuerHelper')}
			</p>
		</div>

		<div>
			<label for="oidc-client-id" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('oidcSettings.labelClientId')}
			</label>
			<input
				id="oidc-client-id"
				type="text"
				bind:value={form.clientId}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div>
			<label for="oidc-client-secret" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('oidcSettings.labelClientSecret')}
			</label>
			<input
				id="oidc-client-secret"
				type="password"
				autocomplete="off"
				bind:value={form.clientSecret}
				placeholder={config?.clientSecretSet ? (language.current && t('oidcSettings.clientSecretPlaceholder')) : ''}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-redirect" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('oidcSettings.labelRedirect')}
			</label>
			<input
				id="oidc-redirect"
				type="url"
				bind:value={form.redirectUrl}
				placeholder="https://arenet.example.com/api/v1/auth/oidc/callback"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
		</div>

		<div class="md:col-span-2">
			<label for="oidc-scopes" class="text-sm font-medium text-secondary block mb-1">
				{language.current && t('oidcSettings.labelScopes')}
			</label>
			<input
				id="oidc-scopes"
				type="text"
				bind:value={form.scopes}
				placeholder="openid profile email"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
			/>
			<p class="text-xs text-muted mt-1">
				{language.current && t('oidcSettings.scopesHelper')}
			</p>
		</div>

		<div class="md:col-span-2">
			<label class="text-sm font-medium text-secondary inline-flex items-center gap-2">
				<input
					type="checkbox"
					bind:checked={form.acceptUnverifiedEmail}
					class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
				/>
				{language.current && t('oidcSettings.labelAcceptUnverifiedEmail')}
			</label>
			<p class="text-xs text-muted mt-1">
				{language.current && t('oidcSettings.acceptUnverifiedEmailHelper')}
			</p>
		</div>
		{#if formError}
			<p class="text-sm text-down md:col-span-2" role="alert">{formError}</p>
		{/if}

		<div class="md:col-span-2 flex justify-end">
			<Button type="submit" disabled={submitting}>
				{language.current && (submitting ? t('oidcSettings.btnSaving') : t('oidcSettings.btnSave'))}
			</Button>
		</div>
	</form>

	<div class="mt-8 pt-6 border-t border-border-subtle">
		<h3 class="text-base font-semibold text-primary mb-2">{language.current && t('oidcSettings.allowlistTitle')}</h3>
		<p class="text-xs text-muted mb-4">
			{language.current && t('oidcSettings.allowlistSubtitle')}
		</p>

		<form
			class="mb-4 space-y-2"
			onsubmit={(e) => {
				e.preventDefault();
				void addAllowlistEntry();
			}}
		>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
				<input
					type="email"
					bind:value={newEntry.email}
					placeholder={language.current && t('oidcSettings.allowlistEmailPlaceholder')}
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				/>
				<input
					type="text"
					bind:value={newEntry.displayName}
					placeholder={language.current && t('oidcSettings.allowlistDisplayNamePlaceholder')}
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				/>
			</div>
			<div class="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3">
				<input
					type="text"
					bind:value={newEntry.sub}
					placeholder={language.current && t('oidcSettings.allowlistSubPlaceholder')}
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<Button type="submit" disabled={allowlistSubmitting}>
					{language.current && (allowlistSubmitting ? t('oidcSettings.allowlistAdding') : t('oidcSettings.allowlistAdd'))}
				</Button>
			</div>
			<p class="text-xs text-muted">
				{language.current && t('oidcSettings.allowlistAddHelper')}
			</p>
		</form>

		{#if allowlistError}
			<p class="text-sm text-down mb-3" role="alert">{allowlistError}</p>
		{/if}

		{#if allowlist.length === 0}
			<p class="text-sm text-muted">{language.current && t('oidcSettings.allowlistEmpty')}</p>
		{:else}
			<ul class="divide-y divide-border-subtle">
				{#each allowlist as entry (entry.email)}
					<li class="flex items-center justify-between py-2">
						<div class="min-w-0 flex-1">
							<div class="flex items-center gap-2">
								<span class="font-mono text-sm">{entry.email}</span>
								{#if entry.sub}
									<Badge variant="status-up">{language.current && t('oidcSettings.allowlistBadgeLinked')}</Badge>
								{:else}
									<Badge variant="status-warn">{language.current && t('oidcSettings.allowlistBadgePending')}</Badge>
								{/if}
							</div>
							{#if entry.displayName}
								<p class="text-xs text-muted">{entry.displayName}</p>
							{/if}
						</div>
						<Button
							variant="ghost"
							size="sm"
							onclick={() => void deleteAllowlistEntry(entry.email)}
						>
							{language.current && t('oidcSettings.allowlistBtnRemove')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}
	</div>
</Card>
</div>
