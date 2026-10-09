<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	interface Props {
		label?: string;
		checked?: boolean;
		disabled?: boolean;
		title?: string;
		id?: string;
	}

	let {
		label,
		checked = $bindable(false),
		disabled = false,
		title = '',
		id = `cb-${Math.random().toString(36).slice(2, 9)}`
	}: Props = $props();
</script>

<label
	for={id}
	class="inline-flex items-center gap-2 cursor-pointer select-none"
	class:cursor-not-allowed={disabled}
	{title}
>
	<span class="relative inline-block w-4 h-4">
		<input
			{id}
			type="checkbox"
			bind:checked
			{disabled}
			class="peer absolute inset-0 opacity-0 cursor-pointer disabled:cursor-not-allowed"
		/>
		<!-- The real input is invisible, so the painted box shows its
		     keyboard focus. An outline rather than a ring: its offset gap
		     is transparent, so it reads on any surface the box sits on,
		     and it stays distinct from the cyan fill of a checked box. -->
		<span
			class="absolute inset-0 rounded border transition-all duration-100 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-cyan"
			class:bg-cyan={checked}
			class:border-cyan={checked}
			class:bg-transparent={!checked}
			class:border-border-default={!checked}
			class:opacity-50={disabled}
		>
			{#if checked}
				<svg viewBox="0 0 16 16" class="w-4 h-4 text-on-color" fill="none">
					<path
						d="M3 8.5l3 3 7-7"
						stroke="currentColor"
						stroke-width="2"
						stroke-linecap="round"
						stroke-linejoin="round"
					/>
				</svg>
			{/if}
		</span>
	</span>
	{#if label}
		<span class="text-sm text-primary" class:text-muted={disabled}>{label}</span>
	{/if}
</label>
