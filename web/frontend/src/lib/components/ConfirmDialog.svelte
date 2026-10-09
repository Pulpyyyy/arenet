<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ConfirmDialog (Step F Chunk 6.4 smoke fix — new).

  Reusable confirmation modal that wraps <Modal> with the two
  standard action buttons (Cancel + Confirm). Replaces ad-hoc
  uses of the native confirm() dialog with a styled surface that
  matches the rest of the app.

  Pattern is intentionally minimal — no form fields, no async
  state, just a yes/no question. For destructive flows, the
  caller sets `confirmVariant="danger"` so the affirmative button
  reads as a red CTA.

  Async behavior: `onConfirm` is awaited if it returns a Promise,
  so the caller can run an API call and the dialog stays open
  while the request is in flight. The dialog DOES NOT close on
  its own — `open` is bindable, the caller decides when to flip
  it. On error the caller can keep the dialog open to retry; on
  success it sets open = false.

  Public API (add-only per §1.3):

    open           — boolean (bindable)
    title          — string (required, dialog header)
    message        — string (required, body paragraph)
    confirmLabel   — string (default t('common.confirm'))
    cancelLabel    — string (default t('common.cancel'))
    confirmVariant — Button variant ('primary'|'secondary'|'ghost'|'danger'),
                     default 'danger' since the common case is destructive
    onConfirm      — () => void | Promise<void>
-->
<script lang="ts">
	import Modal from './Modal.svelte';
	import Button from './Button.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	type ConfirmVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

	interface Props {
		open: boolean;
		title: string;
		message: string;
		confirmLabel?: string;
		cancelLabel?: string;
		confirmVariant?: ConfirmVariant;
		onConfirm: () => void | Promise<void>;
	}

	let {
		open = $bindable(),
		title,
		message,
		confirmLabel,
		cancelLabel,
		confirmVariant = 'danger',
		onConfirm
	}: Props = $props();

	// No string defaults in the destructuring: a default is evaluated
	// once, in whatever language was active at mount. Resolving here
	// keeps the fallback labels following a language switch.
	const confirmText = $derived(confirmLabel ?? (language.current && t('common.confirm')));
	const cancelText = $derived(cancelLabel ?? (language.current && t('common.cancel')));

	let submitting = $state(false);

	function onClose(): void {
		// Don't allow close while submitting — avoids racing the
		// onConfirm promise. The caller can still force-close by
		// resetting the bindable from outside.
		if (submitting) return;
		open = false;
	}

	async function handleConfirm(): Promise<void> {
		submitting = true;
		try {
			await onConfirm();
		} finally {
			submitting = false;
		}
	}
</script>

{#if open}
	<Modal {open} {title} {onClose}>
		{#snippet children()}
			<p class="text-sm text-secondary">{message}</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={onClose} disabled={submitting}>
				{cancelText}
			</Button>
			<Button variant={confirmVariant} onclick={handleConfirm} loading={submitting}>
				{confirmText}
			</Button>
		{/snippet}
	</Modal>
{/if}
