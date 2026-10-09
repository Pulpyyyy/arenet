<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ChangePasswordModal (spec §6.13). Reaches the user via the
  compromised-password banner (Chunk 7 Étape 2). The modal is always
  mounted in the layout shell with a bindable `open` flag so the form
  state is preserved across show/hide cycles.

  Server-side validation rules: length 15..128, top-10k embedded list,
  HIBP best-effort. The modal stays open on 400 errors with inline
  field-level error display.

  Side effect on success: server revokes ALL OTHER sessions of the
  user; the current session (whose cookie made the request) is
  preserved. A toast + re-bootstrap of the auth store confirm the
  change and clear the compromised-password banner.
-->
<script lang="ts">
	import { authApi } from '$lib/api/auth';
	import { auth } from '$lib/stores/auth.svelte';
	import { pushToast } from '$lib/stores/toast';
	import { ApiError } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Modal from './Modal.svelte';
	import Input from './Input.svelte';
	import Button from './Button.svelte';

	interface Props {
		open: boolean;
	}

	let { open = $bindable() }: Props = $props();

	// Mirrors the server-side minimum (length 15..128, see header).
	const MIN_PASSWORD_LENGTH = 15;

	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let errors = $state<Record<string, string>>({});
	let submitting = $state(false);

	function close(): void {
		open = false;
	}

	function resetForm(): void {
		currentPassword = '';
		newPassword = '';
		confirmPassword = '';
		errors = {};
	}

	async function handleSubmit(): Promise<void> {
		if (submitting) return;
		errors = {};
		if (!currentPassword) {
			errors = { current: t('changePasswordModal.errRequired') };
			return;
		}
		if (newPassword.length < MIN_PASSWORD_LENGTH) {
			errors = { new: t('changePasswordModal.errTooShort', { min: MIN_PASSWORD_LENGTH }) };
			return;
		}
		if (newPassword !== confirmPassword) {
			errors = { confirm: t('changePasswordModal.errMismatch') };
			return;
		}
		submitting = true;
		try {
			await authApi.changePassword(currentPassword, newPassword);
			pushToast(t('changePasswordModal.toastChanged'), 'success');
			// Server cleared passwordCompromised and revoked other sessions.
			// Re-bootstrap to refresh local user fields; the banner unmounts
			// reactively when passwordCompromised flips to false.
			await auth.bootstrap();
			resetForm();
			close();
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 401) {
					errors = { current: t('changePasswordModal.errIncorrectCurrent') };
				} else if (err.status === 400) {
					errors = { new: err.message };
				} else {
					pushToast(err.message, 'danger');
				}
			} else {
				pushToast(t('changePasswordModal.errUnexpected'), 'danger');
			}
		} finally {
			submitting = false;
		}
	}
</script>

<Modal {open} title={language.current && t('changePasswordModal.title')} onClose={close}>
	<Input
		bind:value={currentPassword}
		type="password"
		label={language.current && t('changePasswordModal.currentLabel')}
		autocomplete="current-password"
		error={errors.current ?? ''}
		disabled={submitting}
	/>
	<div class="mt-4">
		<Input
			bind:value={newPassword}
			type="password"
			label={language.current && t('changePasswordModal.newLabel', { min: MIN_PASSWORD_LENGTH })}
			autocomplete="new-password"
			error={errors.new ?? ''}
			disabled={submitting}
		/>
	</div>
	<div class="mt-4">
		<Input
			bind:value={confirmPassword}
			type="password"
			label={language.current && t('changePasswordModal.confirmLabel')}
			autocomplete="new-password"
			error={errors.confirm ?? ''}
			disabled={submitting}
		/>
	</div>
	<div class="mt-3 text-xs text-secondary">
		{language.current && t('changePasswordModal.otherSessionsNote')}
	</div>

	{#snippet footer()}
		<Button variant="ghost" size="md" onclick={close} disabled={submitting}>
			{#snippet children()}{language.current && t('common.cancel')}{/snippet}
		</Button>
		<Button
			variant="primary"
			size="md"
			onclick={handleSubmit}
			loading={submitting}
			disabled={submitting}
		>
			{#snippet children()}{language.current && t('changePasswordModal.submit')}{/snippet}
		</Button>
	{/snippet}
</Modal>
