<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Phase 4 — "Créer un service account" modal. Two-stage flow:
    1. Form (name, role, expiry preset) → POST /admin/users
       /service-accounts → success
    2. Reveal stage — render the plain token in a monospace
       box, REQUIRE the operator to press "Copier" before
       enabling "Fermer". The token is shown ONCE; navigating
       away without copying is a meaningful loss (the operator
       would have to rotate to get a new one).

  The token is held in component-local state, never persisted
  beyond the modal lifecycle. Closing the modal nukes the
  reference even if the operator copy/pasted into a password
  manager — the component itself doesn't keep a copy.
-->
<script lang="ts">
	import Modal from './Modal.svelte';
	import Button from './Button.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { pushToast } from '$lib/stores/toast';
	import type { CreateServiceAccountResponse, UserRole } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		open: boolean;
		onClose: () => void;
		/**
		 * Called after a successful create so the parent page
		 * can refresh its users list — the new service account
		 * needs to appear in the table without a manual reload.
		 */
		onCreated?: () => void;
	}

	let { open, onClose, onCreated }: Props = $props();

	type ExpiryPreset = '30d' | '90d' | '1y' | 'never';

	let name = $state('');
	let role = $state<UserRole>('viewer');
	let expiry = $state<ExpiryPreset>('never');
	let submitting = $state(false);

	let revealed = $state<CreateServiceAccountResponse | null>(null);
	let copied = $state(false);

	function reset() {
		name = '';
		role = 'viewer';
		expiry = 'never';
		submitting = false;
		revealed = null;
		copied = false;
	}

	function handleClose() {
		// Operator-initiated close OR backdrop click. Reveal stage
		// only allows close once the token has been copied (guarded
		// at the button-disabled level — Modal still honours Esc /
		// backdrop because we can't realistically prevent the user
		// from leaving, only nudge them strongly).
		reset();
		onClose();
	}

	function expiryToISO(preset: ExpiryPreset): string | null {
		if (preset === 'never') return null;
		const d = new Date();
		switch (preset) {
			case '30d':
				d.setDate(d.getDate() + 30);
				break;
			case '90d':
				d.setDate(d.getDate() + 90);
				break;
			case '1y':
				d.setFullYear(d.getFullYear() + 1);
				break;
		}
		return d.toISOString();
	}

	async function submit() {
		const trimmed = name.trim();
		if (!trimmed) {
			pushToast(t('createServiceAccount.toastNameRequired'), 'danger');
			return;
		}
		submitting = true;
		try {
			const expiresAt = expiryToISO(expiry);
			const result = await settingsApi.createServiceAccount({
				name: trimmed,
				role,
				expiresAt: expiresAt ?? undefined
			});
			revealed = result;
			onCreated?.();
		} catch (err) {
			const msg = err instanceof Error ? err.message : t('createServiceAccount.toastNetworkError');
			pushToast(t('createServiceAccount.toastSubmitFailed', { err: msg }), 'danger');
		} finally {
			submitting = false;
		}
	}

	async function copyToken() {
		if (!revealed) return;
		try {
			await navigator.clipboard.writeText(revealed.token);
			copied = true;
			pushToast(t('createServiceAccount.toastTokenCopied'), 'success');
		} catch {
			pushToast(t('createServiceAccount.toastCopyFailed'), 'danger');
		}
	}
</script>

<Modal {open} title={language.current && (revealed ? t('createServiceAccount.titleReveal') : t('createServiceAccount.titleCreate'))} onClose={handleClose}>
	{#if !revealed}
		<form
			class="flex flex-col gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				submit();
			}}
		>
			<label class="flex flex-col gap-1 text-sm">
				<span class="text-secondary">{language.current && t('createServiceAccount.labelName')}</span>
				<input
					type="text"
					bind:value={name}
					placeholder={language.current && t('createServiceAccount.namePlaceholder')}
					required
					autocomplete="off"
					pattern="[a-z0-9_-]+"
					title={language.current && t('createServiceAccount.nameTitle')}
					class="px-2 py-1 rounded-md bg-surface border border-border-default text-primary placeholder-muted outline-none focus:border-accent-cyan"
					data-testid="svc-name-input"
				/>
				<span class="text-xs text-muted">{language.current && t('createServiceAccount.nameHint')}</span>
			</label>

			<label class="flex flex-col gap-1 text-sm">
				<span class="text-secondary">{language.current && t('createServiceAccount.labelRole')}</span>
				<select
					bind:value={role}
					class="px-2 py-1 rounded-md bg-surface border border-border-default text-primary outline-none focus:border-accent-cyan"
					data-testid="svc-role-select"
				>
					<option value="viewer">{language.current && t('createServiceAccount.roleViewerOption')}</option>
					<option value="admin">{language.current && t('createServiceAccount.roleAdminOption')}</option>
				</select>
			</label>

			<label class="flex flex-col gap-1 text-sm">
				<span class="text-secondary">{language.current && t('createServiceAccount.labelExpiry')}</span>
				<select
					bind:value={expiry}
					class="px-2 py-1 rounded-md bg-surface border border-border-default text-primary outline-none focus:border-accent-cyan"
					data-testid="svc-expiry-select"
				>
					<option value="never">{language.current && t('createServiceAccount.expiryNever')}</option>
					<option value="30d">{language.current && t('createServiceAccount.expiry30d')}</option>
					<option value="90d">{language.current && t('createServiceAccount.expiry90d')}</option>
					<option value="1y">{language.current && t('createServiceAccount.expiry1y')}</option>
				</select>
			</label>
		</form>
	{:else}
		<div class="flex flex-col gap-3">
			<p class="text-sm">
				{language.current && t('createServiceAccount.revealedPrefix')} <strong class="text-down">{language.current && t('createServiceAccount.revealedOnce')}</strong>{language.current && t('createServiceAccount.revealedSuffix')}
			</p>
			<pre
				class="px-3 py-2 rounded-md bg-surface border border-border-default font-mono text-xs break-all whitespace-pre-wrap select-all"
				data-testid="svc-revealed-token">{revealed.token}</pre>
			<p class="text-xs text-muted">
				{language.current && t('createServiceAccount.tokenIdLabel')} <code class="font-mono">{revealed.tokenId}</code>
				{#if revealed.expiresAt}
					 {language.current && t('createServiceAccount.expiresOnLabel')} {new Date(revealed.expiresAt).toLocaleString(language.current)}
				{/if}
			</p>
		</div>
	{/if}

	{#snippet footer()}
		{#if !revealed}
			<Button variant="ghost" size="sm" onclick={handleClose}>{language.current && t('createServiceAccount.btnCancel')}</Button>
			<Button
				variant="primary"
				size="sm"
				loading={submitting}
				onclick={submit}
				data-testid="svc-submit-button"
			>
				{language.current && t('createServiceAccount.btnCreate')}
			</Button>
		{:else}
			<Button
				variant="secondary"
				size="sm"
				onclick={copyToken}
				data-testid="svc-copy-button"
			>
				{language.current && (copied ? t('createServiceAccount.btnCopied') : t('createServiceAccount.btnCopy'))}
			</Button>
			<Button
				variant="primary"
				size="sm"
				disabled={!copied}
				onclick={handleClose}
				data-testid="svc-close-button"
			>
				{language.current && t('createServiceAccount.btnClose')}
			</Button>
		{/if}
	{/snippet}
</Modal>
