<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	type Status = 'up' | 'warn' | 'down' | 'info' | 'idle';
	let { status = 'idle' }: { status?: Status } = $props();
	const colorMap: Record<Status, string> = {
		up: 'var(--status-up)',
		warn: 'var(--status-warn)',
		down: 'var(--status-down)',
		info: 'var(--status-info)',
		idle: 'var(--text-muted)'
	};
	const color = $derived(colorMap[status]);
	const pulse = $derived(status !== 'idle');
</script>

<span
	role="img"
	class="inline-block w-2 h-2 rounded-full"
	class:pulse-dot={pulse}
	style:background-color={color}
	aria-label={`Status: ${status}`}
></span>

<style>
	.pulse-dot {
		animation: pulse-status 2s ease-in-out infinite;
	}
	@keyframes pulse-status {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.5;
		}
	}
</style>
