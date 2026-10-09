<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { ToastEntry } from '$lib/stores/toast';
	import { dismissToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let { entry }: { entry: ToastEntry } = $props();
</script>

<div
	role="status"
	class="toast pointer-events-auto px-4 py-3 rounded-md border bg-elevated min-w-[16rem] max-w-sm flex items-start gap-3"
	data-variant={entry.variant}
>
	<p class="text-sm flex-1">{entry.message}</p>
	<button
		class="text-secondary hover:text-primary text-xs"
		aria-label={language.current && t('common.dismissNotification')}
		onclick={() => dismissToast(entry.id)}
	>
		×
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
