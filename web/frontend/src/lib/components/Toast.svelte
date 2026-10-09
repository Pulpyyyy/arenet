<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { ToastEntry } from '$lib/stores/toast';
	import { dismissToast, pauseToast, resumeToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let { entry }: { entry: ToastEntry } = $props();

	let dismissLabel = $derived(language.current && t('toast.dismiss'));

	// The countdown is paused while the pointer is over the toast OR
	// focus is inside it. Both are tracked so leaving with the mouse
	// while the dismiss button still has focus does not restart it.
	let hovered = false;
	let focused = false;

	function syncTimer(): void {
		if (hovered || focused) pauseToast(entry.id);
		else resumeToast(entry.id);
	}

	function onFocusOut(event: FocusEvent): void {
		const next = event.relatedTarget;
		const root = event.currentTarget as HTMLElement;
		if (next instanceof Node && root.contains(next)) return;
		focused = false;
		syncTimer();
	}
</script>

<!-- No role here on purpose: the live region that announces the toast
     is the container in ToastContainer (role="status" for info/success,
     role="alert" for danger). A role="status" on each toast nested in
     it made screen readers announce every toast twice.
     The a11y_no_static_element_interactions warning is silenced below:
     the pointer and focus handlers only pause the auto-dismiss
     countdown; the one interactive control is the dismiss button. -->
<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
	class="toast pointer-events-auto px-4 py-3 rounded-md border bg-elevated min-w-[16rem] max-w-sm flex items-start gap-3"
	data-variant={entry.variant}
	onmouseenter={() => {
		hovered = true;
		syncTimer();
	}}
	onmouseleave={() => {
		hovered = false;
		syncTimer();
	}}
	onfocusin={() => {
		focused = true;
		syncTimer();
	}}
	onfocusout={onFocusOut}
>
	<!-- Variant icon: the variants must not differ by colour alone
	     (WCAG 1.4.1). Decorative for assistive tech, which already gets
	     the urgency from the live region the toast sits in. -->
	<svg
		class="toast-icon mt-0.5 h-4 w-4 shrink-0"
		viewBox="0 0 24 24"
		fill="none"
		stroke="currentColor"
		stroke-width="2"
		stroke-linecap="round"
		stroke-linejoin="round"
		aria-hidden="true"
		focusable="false"
		data-icon={entry.variant}
	>
		{#if entry.variant === 'success'}
			<circle cx="12" cy="12" r="10" />
			<path d="M8 12.5l3 3 5-6" />
		{:else if entry.variant === 'danger'}
			<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
			<path d="M12 9v4" />
			<path d="M12 17h.01" />
		{:else}
			<circle cx="12" cy="12" r="10" />
			<path d="M12 16v-4" />
			<path d="M12 8h.01" />
		{/if}
	</svg>
	<p class="text-sm flex-1">{entry.message}</p>
	<button
		type="button"
		class="-mr-1 -mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded text-secondary hover:text-primary hover:bg-hover text-lg leading-none focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan"
		aria-label={dismissLabel}
		onclick={() => dismissToast(entry.id)}
	>
		<span aria-hidden="true">×</span>
	</button>
</div>

<style>
	/* Toast variant colors use the --toast-*-{bg,border} tokens from
	 * tokens.css (Chunk 3.1 additions, @20% color-mix tint). The
	 * Step C glow box-shadow becomes the generic --shadow-md so we
	 * don't need three per-color glow tokens — visually slightly
	 * tamer but consistent with cards and modals. A green glow
	 * (success) could be reintroduced as --shadow-glow-green if the
	 * Chunk 7 smoke wants the punchier look back. */
	.toast {
		animation: slide-in var(--motion-base);
		box-shadow: var(--shadow-md);
	}
	.toast[data-variant='success'] {
		border-color: var(--toast-success-border);
		background-color: var(--toast-success-bg);
	}
	.toast[data-variant='danger'] {
		border-color: var(--toast-danger-border);
		background-color: var(--toast-danger-bg);
	}
	.toast[data-variant='info'] {
		border-color: var(--toast-info-border);
		background-color: var(--toast-info-bg);
	}
	/* The icon takes the variant's border colour: same hue the border
	 * already uses, so the shape and the colour say the same thing. */
	.toast[data-variant='success'] .toast-icon {
		color: var(--toast-success-border);
	}
	.toast[data-variant='danger'] .toast-icon {
		color: var(--toast-danger-border);
	}
	.toast[data-variant='info'] .toast-icon {
		color: var(--toast-info-border);
	}
	@keyframes slide-in {
		from {
			opacity: 0;
			transform: translateX(20px);
		}
		to {
			opacity: 1;
			transform: translateX(0);
		}
	}
</style>
