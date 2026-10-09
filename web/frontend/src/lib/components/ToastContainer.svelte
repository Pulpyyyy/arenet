<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { toasts } from '$lib/stores/toast';
	import Toast from './Toast.svelte';

	// Two live regions, each announcing its own toasts exactly once:
	// info/success go to a polite one (read when the screen reader is
	// idle), danger to an assertive one (read right away). The toasts
	// themselves carry no role, so nothing is announced twice.
	let politeToasts = $derived($toasts.filter((entry) => entry.variant !== 'danger'));
	let alertToasts = $derived($toasts.filter((entry) => entry.variant === 'danger'));
</script>

<!-- Both regions are always rendered, even empty: a live region must
     already be in the page when content lands in it, or assistive tech
     may not announce that content. aria-atomic="false" overrides the
     implicit "true" of status/alert so adding a toast reads only that
     toast, not every one already on screen. -->
<div class="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col">
	<div
		class="flex flex-col gap-2"
		role="status"
		aria-live="polite"
		aria-atomic="false"
		data-testid="toast-region-polite"
	>
		{#each politeToasts as entry (entry.id)}
			<Toast {entry} />
		{/each}
	</div>
	<div
		class="flex flex-col gap-2"
		class:mt-2={politeToasts.length > 0 && alertToasts.length > 0}
		role="alert"
		aria-live="assertive"
		aria-atomic="false"
		data-testid="toast-region-alert"
	>
		{#each alertToasts as entry (entry.id)}
			<Toast {entry} />
		{/each}
	</div>
</div>
