<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.48 — "Create a local user". Two stages, deliberately modelled on
  CreateServiceAccountModal: a form, then a reveal the operator has to
  copy before the close button unlocks.

  The same shape is right here for the same reason. The first password
  crosses exactly one screen: nothing returns it afterwards, and an
  operator who closes the dialog without copying has to delete the
  account and start again. Making "Close" wait for "Copy" is the only
  honest way to say that. Escape and the backdrop are inert during the
  reveal for the same reason, and "I have saved it" also unlocks Close:
  on a plain-HTTP console the browser may refuse to copy at all.

  Generating is the default. An operator asked to invent a password for
  somebody else reaches for something memorable — and nobody needs to
  remember this one, because the account is required to change it at
  first login. Typing one is still offered: handing over a chosen
  password out of band is a real workflow, and refusing it would just
  push people to generate-then-immediately-change.
-->
<script lang="ts">
	import Modal from './Modal.svelte';
	import Button from './Button.svelte';
	import Input from './Input.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { pushToast } from '$lib/stores/toast';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import type { CreateAdminUserResponse, UserRole } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { copyText } from '$lib/utils/clipboard';

	interface Props {
		open: boolean;
		onClose: () => void;
		/** Lets the parent refresh its table without a manual reload. */
		onCreated?: () => void;
	}

	let { open, onClose, onCreated }: Props = $props();

	let username = $state('');
	let displayName = $state('');
	let email = $state('');
	let role = $state<UserRole>('viewer');
	let generate = $state(true);
	let password = $state('');
	let submitting = $state(false);
	let formError = $state<string | null>(null);

	let revealed = $state<CreateAdminUserResponse | null>(null);
	let copied = $state(false);
	let saved = $state(false);
	let copyFailed = $state(false);
	let secretEl: HTMLElement | undefined = $state(undefined);

	function reset() {
		username = '';
		displayName = '';
		email = '';
		role = 'viewer';
		generate = true;
		password = '';
		submitting = false;
		formError = null;
		revealed = null;
		copied = false;
		saved = false;
		copyFailed = false;
	}

	function handleClose() {
		reset();
		onClose();
	}

	async function submit() {
		formError = null;
		submitting = true;
		try {
			const result = await settingsApi.createAdminUser({
				username: username.trim(),
				displayName: displayName.trim(),
				email: email.trim(),
				role,
				// Empty asks the server to generate; a typed one is sent
				// as-is and is NOT echoed back, since the operator
				// already has it.
				password: generate ? undefined : password
			});
			if (result.generatedPassword) {
				revealed = result;
			} else {
				// Nothing to reveal: they typed it. Close straight away
				// rather than showing an empty ceremony.
				pushToast(t('createUser.toastCreated', { username: result.user.username }), 'success');
				onCreated?.();
				handleClose();
				return;
			}
			onCreated?.();
		} catch (err) {
			// Refusals arrive coded since v2.46, so they are shown in
			// the operator's language.
			formError = serverErrorMessage(err);
		} finally {
			submitting = false;
		}
	}

	async function copyPassword() {
		if (!revealed?.generatedPassword) return;
		if (await copyText(revealed.generatedPassword, secretEl)) {
			copied = true;
			copyFailed = false;
			pushToast(t('createUser.toastCopied'), 'success');
		} else {
			// Said inside the dialog, next to the text to copy by hand.
			copyFailed = true;
		}
	}
</script>

<Modal
	{open}
	title={language.current &&
		(revealed ? t('createUser.titleReveal') : t('createUser.titleCreate'))}
	onClose={handleClose}
	dismissible={!revealed}
>
	{#if !revealed}
		<form
			class="flex flex-col gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				submit();
			}}
		>
			<Input
				id="new-user-username"
				label={language.current && t('createUser.username')}
				bind:value={username}
				placeholder="alice"
				data-testid="new-user-username"
			/>
			<Input
				id="new-user-display-name"
				label={language.current && t('createUser.displayName')}
				bind:value={displayName}
				data-testid="new-user-display-name"
			/>
			<Input
				id="new-user-email"
				type="email"
				label={language.current && t('createUser.email')}
				bind:value={email}
				data-testid="new-user-email"
			/>

			<label class="flex flex-col gap-1">
				<span class="text-sm text-secondary">{language.current && t('createUser.role')}</span>
				<select
					class="h-9 rounded-md border border-border-default bg-surface px-2 text-sm text-primary"
					bind:value={role}
					data-testid="new-user-role"
				>
					<option value="viewer">{language.current && t('createUser.roleViewer')}</option>
					<option value="admin">{language.current && t('createUser.roleAdmin')}</option>
				</select>
				<span class="text-xs text-muted">{language.current && t('createUser.roleHelp')}</span>
			</label>

			<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
				<input
					type="checkbox"
					class="accent-cyan"
					bind:checked={generate}
					data-testid="new-user-generate"
				/>
				{language.current && t('createUser.generate')}
			</label>
			{#if !generate}
				<Input
					id="new-user-password"
					type="password"
					label={language.current && t('createUser.password')}
					bind:value={password}
					data-testid="new-user-password"
				/>
			{/if}
			<p class="text-xs text-muted">{language.current && t('createUser.mustChangeNotice')}</p>

			{#if formError}
				<p class="text-sm text-down" data-testid="new-user-error">{formError}</p>
			{/if}
		</form>
	{:else}
		<div class="flex flex-col gap-3">
			<p class="text-sm">{language.current && t('createUser.revealIntro')}</p>
			<pre
				bind:this={secretEl}
				class="px-3 py-2 rounded-md bg-surface border border-border-default font-mono text-sm break-all whitespace-pre-wrap select-all"
				data-testid="new-user-revealed">{revealed.generatedPassword}</pre>
			{#if copyFailed}
				<p role="alert" class="text-sm text-down" data-testid="new-user-copy-failed">
					{language.current && t('secretReveal.copyFailed')}
				</p>
			{/if}
			<p class="text-xs text-muted">{language.current && t('createUser.revealWarning')}</p>
			<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
				<input
					type="checkbox"
					class="accent-cyan"
					bind:checked={saved}
					data-testid="new-user-saved"
				/>
				{language.current && t('secretReveal.savedConfirm')}
			</label>
		</div>
	{/if}

	{#snippet footer()}
		{#if !revealed}
			<Button variant="ghost" size="sm" onclick={handleClose}
				>{language.current && t('createUser.cancel')}</Button
			>
			<Button
				variant="primary"
				size="sm"
				loading={submitting}
				onclick={submit}
				data-testid="new-user-submit">{language.current && t('createUser.create')}</Button
			>
		{:else}
			<Button variant="secondary" size="sm" onclick={copyPassword} data-testid="new-user-copy">
				{language.current && (copied ? t('createUser.copied') : t('createUser.copy'))}
			</Button>
			<!-- Close waits for Copy (or the "saved" tick): the password
			     is gone once this dialog closes, and the only recovery is
			     deleting the account and creating it again. -->
			<Button
				variant="primary"
				size="sm"
				disabled={!copied && !saved}
				onclick={handleClose}
				data-testid="new-user-close">{language.current && t('createUser.close')}</Button
			>
		{/if}
	{/snippet}
</Modal>
