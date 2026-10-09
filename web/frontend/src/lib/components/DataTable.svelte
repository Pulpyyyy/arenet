<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts" generics="T extends { id: string }">
	import type { Snippet } from 'svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		headers: string[];
		items: T[];
		row: Snippet<[T]>;
		/** Optional snippet rendered in an extra row beneath the active item. */
		expanded?: Snippet<[T]>;
		/**
		 * Whether rows are click-to-expand interactive. Defaults to `true`
		 * for backward compatibility with Routes / Audit which use the
		 * expanded snippet. Set to `false` for read-only tables (e.g.
		 * Sessions) so rows don't carry cursor-pointer, role=button,
		 * tabindex, hover-rail, or focus-ring — Step G G.3 fix for the
		 * "interactive parasite" cosmetic debt (smoke doc Step F §5 #1).
		 */
		interactive?: boolean;
	}

	let { headers, items, row, expanded, interactive = true }: Props = $props();

	let activeId = $state<string | null>(null);

	function toggle(id: string) {
		activeId = activeId === id ? null : id;
	}

	function onKey(event: KeyboardEvent, id: string) {
		if (event.key === 'Enter' || event.key === ' ') {
			event.preventDefault();
			toggle(id);
		}
	}
</script>

<div class="overflow-hidden border border-border-subtle rounded-lg">
	<table class="w-full text-sm border-collapse table-fixed">
		<thead class="bg-sidebar sticky top-0">
			<tr>
				{#each headers as h (h)}
					<th
						class="px-4 py-3 text-left text-xs uppercase tracking-wide text-secondary font-medium"
					>
						{h}
					</th>
				{/each}
			</tr>
		</thead>
		<tbody>
			{#each items as item (item.id)}
				<tr
					class="data-row border-t border-border-subtle"
					class:interactive
					class:active={interactive && activeId === item.id}
					onclick={interactive ? () => toggle(item.id) : undefined}
					onkeydown={interactive ? (e) => onKey(e, item.id) : undefined}
					tabindex={interactive ? 0 : undefined}
					role={interactive ? 'button' : undefined}
					aria-expanded={interactive && expanded ? activeId === item.id : undefined}
				>
					{@render row(item)}
				</tr>
				{#if expanded && activeId === item.id}
					<tr class="bg-surface">
						<td colspan={headers.length} class="px-6 py-4">
							{@render expanded(item)}
						</td>
					</tr>
				{/if}
			{/each}
			{#if items.length === 0}
				<tr>
					<td
						colspan={headers.length}
						class="px-4 py-6 text-center text-secondary text-sm"
					>
						{language.current && t('common.noItems')}
					</td>
				</tr>
			{/if}
		</tbody>
	</table>
</div>

<style>
	/*
	 * The cyan left "rail" is rendered as an inset box-shadow on the row
	 * itself. This avoids the HTML pitfall of absolutely-positioning a <td>
	 * outside its parent <tr> flow, while still animating smoothly.
	 */
	.data-row {
		transition:
			background-color var(--motion-fast),
			box-shadow var(--motion-fast);
	}
	/* Step G G.3: hover-rail + focus-ring + active-rail only apply to
	 * interactive rows. Read-only tables (Sessions) keep the default
	 * cursor + no rail + no focus outline. */
	.data-row.interactive {
		cursor: pointer;
	}
	.data-row.interactive:hover {
		background-color: var(--bg-hover);
		box-shadow: inset 2px 0 0 var(--accent-cyan);
	}
	.data-row.active {
		background-color: var(--bg-hover);
		box-shadow: inset 2px 0 0 var(--accent-cyan);
	}
	.data-row.interactive:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
</style>
