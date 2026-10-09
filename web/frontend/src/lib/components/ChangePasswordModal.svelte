<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ChangePasswordModal (spec §6.13). Reaches the user via the
  compromised-password banner (Chunk 7 Étape 2) and the Settings
  account card. The modal is always mounted with a bindable `open`
  flag; closing it clears the form, so passwords typed and abandoned
  are not sitting in the fields the next time it opens.

  The fields live in a real <form> and the submit button sits inside
  it (not in Modal's footer slot, which is outside any form), so Enter
  in any field submits, exactly like clicking the button.

  Client-side checks run together and every failing field shows its
  own error at once; after the first attempt they re-run live as the
  user types. Server-side validation rules: length 15..128, top-10k
  embedded list, HIBP best-effort. The modal stays open on 400 errors
  with inline field-level error display.

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

	type Field = 'current' | 'new' | 'confirm';
	type FieldErrors = Partial<Record<Field, string>>;

	const uid = Math.random().toString(36).slice(2, 9);
	const ids: Record<Field, string> = {
		current: `change-password-current-${uid}`,
		new: `change-password-new-${uid}`,
		confirm: `change-password-confirm-${uid}`
	};

	let currentPassword = $state('');
	let newPassword = $state('');
	let confirmPassword = $state('');
	let showCurrent = $state(false);
	let showNew = $state(false);
	let showConfirm = $state(false);
	// Client-side errors stay hidden until the first submit attempt,
	// then track the fields live so a fixed field clears its own error.
	let attempted = $state(false);
	// Errors the server returned for the last attempt. Each one is
	// dropped as soon as the user edits the field it belongs to.
	let serverErrors = $state<FieldErrors>({});
	let submitting = $state(false);

	function validate(): FieldErrors {
		const found: FieldErrors = {};
		if (!currentPassword) {
			found.current = t('changePasswordModal.errRequired');
		}
		if (newPassword.length < MIN_PASSWORD_LENGTH) {
			found.new = t('changePasswordModal.errTooShort', { min: MIN_PASSWORD_LENGTH });
		}
		if (newPassword !== confirmPassword) {
			found.confirm = t('changePasswordModal.errMismatch');
		}
		return found;
	}

	const errors = $derived<FieldErrors>(
		attempted ? { ...serverErrors, ...validate() } : serverErrors
	);

	function clearServerError(field: Field): void {
		if (serverErrors[field] === undefined) return;
		const rest = { ...serverErrors };
		delete rest[field];
		serverErrors = rest;
	}

	function resetForm(): void {
		currentPassword = '';
		newPassword = '';
		confirmPassword = '';
		showCurrent = false;
		showNew = false;
		showConfirm = false;
		attempted = false;
		serverErrors = {};
	}

	function close(): void {
		// Escape / backdrop while the request is in flight: keep the
		// form so the outcome (error or success) lands where it belongs.
		if (submitting) return;
		resetForm();
		open = false;
	}

	function onFormSubmit(event: SubmitEvent): void {
		event.preventDefault();
		void handleSubmit();
	}

	async function handleSubmit(): Promise<void> {
		if (submitting) return;
		attempted = true;
		serverErrors = {};
		if (Object.keys(validate()).length > 0) return;
		submitting = true;
		try {
			await authApi.changePassword(currentPassword, newPassword);
			pushToast(t('changePasswordModal.toastChanged'), 'success');
			// Server cleared passwordCompromised and revoked other sessions.
			// Re-bootstrap to refresh local user fields; the banner unmounts
			// reactively when passwordCompromised flips to false.
			await auth.bootstrap();
			resetForm();
			open = false;
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 401) {
					serverErrors = { current: t('changePasswordModal.errIncorrectCurrent') };
				} else if (err.status === 400) {
					serverErrors = { new: err.message };
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

<!-- Show/hide toggle for one password field. A real <button> in the
     tab order (no tabindex=-1) so keyboard users can reach it. It is a
     toggle button: the label stays "Show" (and the accessible name,
     which contains it, stays constant) while aria-pressed and the
     colour carry the state — flipping the text to "Hide" as well would
     announce a different control on every press. -->
{#snippet visibilityToggle(
	shown: boolean,
	toggle: () => void,
	ariaLabel: string,
	controls: string,
	testId: string
)}
	<button
		type="button"
		class="row-start-1 col-start-2 justify-self-end text-xs font-medium rounded-sm px-1 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan {shown
			? 'text-cyan underline'
			: 'text-secondary hover:text-primary'}"
		aria-pressed={shown ? 'true' : 'false'}
		aria-label={ariaLabel}
		aria-controls={controls}
		data-testid={testId}
		onclick={toggle}
	>
		{language.current && t('changePasswordModal.showPassword')}
	</button>
{/snippet}

<Modal {open} title={language.current && t('changePasswordModal.title')} onClose={close}>
	<form onsubmit={onFormSubmit} data-testid="change-password-form">
		<!-- Each field is a two-column grid: the toggle comes after the
		     input in the DOM (so Tab goes field → its toggle → next field,
		     and the dialog's initial focus lands on the first field) but is
		     placed on the label row, top-right. -->
		<div class="grid grid-cols-[1fr_auto] items-center gap-x-2 gap-y-1.5">
			<label for={ids.current} class="row-start-1 col-start-1 text-sm font-medium text-secondary">
				{language.current && t('changePasswordModal.currentLabel')}
			</label>
			<div class="row-start-2 col-span-2">
				<Input
					id={ids.current}
					bind:value={currentPassword}
					type={showCurrent ? 'text' : 'password'}
					autocomplete="current-password"
					error={errors.current ?? ''}
					disabled={submitting}
					oninput={() => clearServerError('current')}
					data-testid="change-password-current"
				/>
			</div>
			{@render visibilityToggle(
				showCurrent,
				() => (showCurrent = !showCurrent),
				t('changePasswordModal.showCurrentAria'),
				ids.current,
				'change-password-toggle-current'
			)}
		</div>

		<div class="mt-4 grid grid-cols-[1fr_auto] items-center gap-x-2 gap-y-1.5">
			<label for={ids.new} class="row-start-1 col-start-1 text-sm font-medium text-secondary">
				{language.current && t('changePasswordModal.newLabel', { min: MIN_PASSWORD_LENGTH })}
			</label>
			<div class="row-start-2 col-span-2">
				<Input
					id={ids.new}
					bind:value={newPassword}
					type={showNew ? 'text' : 'password'}
					autocomplete="new-password"
					error={errors.new ?? ''}
					disabled={submitting}
					oninput={() => clearServerError('new')}
					data-testid="change-password-new"
				/>
			</div>
			{@render visibilityToggle(
				showNew,
				() => (showNew = !showNew),
				t('changePasswordModal.showNewAria'),
				ids.new,
				'change-password-toggle-new'
			)}
			<p
				class="row-start-3 col-span-2 text-xs {newPassword.length >= MIN_PASSWORD_LENGTH
					? 'text-up'
					: 'text-muted'}"
				data-testid="change-password-counter"
			>
				{language.current &&
					t('changePasswordModal.lengthCounter', {
						count: newPassword.length,
						min: MIN_PASSWORD_LENGTH
					})}
			</p>
		</div>

		<div class="mt-4 grid grid-cols-[1fr_auto] items-center gap-x-2 gap-y-1.5">
			<label for={ids.confirm} class="row-start-1 col-start-1 text-sm font-medium text-secondary">
				{language.current && t('changePasswordModal.confirmLabel')}
			</label>
			<div class="row-start-2 col-span-2">
				<Input
					id={ids.confirm}
					bind:value={confirmPassword}
					type={showConfirm ? 'text' : 'password'}
					autocomplete="new-password"
					error={errors.confirm ?? ''}
					disabled={submitting}
					oninput={() => clearServerError('confirm')}
					data-testid="change-password-confirm"
				/>
			</div>
			{@render visibilityToggle(
				showConfirm,
				() => (showConfirm = !showConfirm),
				t('changePasswordModal.showConfirmAria'),
				ids.confirm,
				'change-password-toggle-confirm'
			)}
		</div>

		<div class="mt-3 text-xs text-secondary">
			{language.current && t('changePasswordModal.otherSessionsNote')}
		</div>

		<!-- Actions live inside the form (not Modal's footer slot) so the
		     submit button is the form's own and Enter submits. The negative
		     margins reproduce Modal's footer band. -->
		<div
			class="-mx-5 -mb-4 mt-4 px-5 py-3 border-t border-border-subtle flex justify-end gap-2"
		>
			<Button
				variant="ghost"
				size="md"
				onclick={close}
				disabled={submitting}
				data-testid="change-password-cancel"
			>
				{#snippet children()}{language.current && t('common.cancel')}{/snippet}
			</Button>
			<Button
				type="submit"
				variant="primary"
				size="md"
				loading={submitting}
				disabled={submitting}
				data-testid="change-password-submit"
			>
				{#snippet children()}{language.current && t('changePasswordModal.submit')}{/snippet}
			</Button>
		</div>
	</form>
</Modal>
