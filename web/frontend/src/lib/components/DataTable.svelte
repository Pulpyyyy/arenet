<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Accessibility model for expandable rows: the <tr> stays a plain
  table row (screen readers keep the cells and the controls inside
  them). A real disclosure <button aria-expanded aria-controls> in a
  leading cell is the keyboard / AT path; clicking anywhere else on
  the row is kept as a mouse convenience, and clicks that land on a
  control inside the row (filter buttons, links…) are left to that
  control.
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
		 * for backward compatibility with Audit which uses the expanded
		 * snippet. Set to `false` for read-only tables (e.g. Sessions) so
		 * rows don't carry cursor-pointer, hover-rail, or the disclosure
		 * button — Step G G.3 fix for the "interactive parasite" cosmetic
		 * debt (smoke doc Step F §5 #1).
		 */
		interactive?: boolean;
		/**
		 * Optional short text naming a row, used in the disclosure
		 * button's accessible name ("Details for …") so a screen-reader
		 * user tabbing through the buttons knows which row each opens.
		 */
		rowLabel?: (item: T) => string;
	}

	let { headers, items, row, expanded, interactive = true, rowLabel }: Props = $props();

	const uid = $props.id();

	/** Rows get a disclosure button only when there is something to disclose. */
	const disclosure = $derived(interactive && expanded !== undefined);
	const columnCount = $derived(headers.length + (disclosure ? 1 : 0));

	/** Controls whose clicks belong to themselves, not to the row. */
	const OWN_CLICK_SELECTOR =
		'a, button, input, select, textarea, summary, label, [role="button"], [contenteditable="true"]';

	let activeId = $state<string | null>(null);

	function toggle(id: string) {
		activeId = activeId === id ? null : id;
	}

	function onRowClick(event: MouseEvent, id: string) {
		const rowEl = event.currentTarget as HTMLElement;
		const control = (event.target as Element | null)?.closest(OWN_CLICK_SELECTOR);
		if (control && rowEl.contains(control)) return;
		toggle(id);
	}

	function panelId(index: number): string {
		return `${uid}-details-${index}`;
	}

	function disclosureLabel(item: T): string {
		const label = rowLabel?.(item);
		return label
			? t('common.dataTable.toggleDetailsFor', { label })
			: t('common.dataTable.toggleDetails');
	}
</script>

<div class="overflow-hidden border border-border-subtle rounded-lg">
	<table class="w-full text-sm border-collapse table-fixed">
		<thead class="bg-sidebar sticky top-0">
			<tr>
				{#if disclosure}
					<th class="w-10 px-2 py-3">
						<span class="sr-only">{language.current && t('common.dataTable.detailsColumn')}</span>
					</th>
				{/if}
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
			{#each items as item, index (item.id)}
				{@const open = disclosure && activeId === item.id}
				<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions, a11y_no_static_element_interactions -->
				<tr
					class="data-row border-t border-border-subtle"
					class:interactive
					class:active={interactive && activeId === item.id}
					onclick={interactive ? (e) => onRowClick(e, item.id) : undefined}
				>
					{#if disclosure}
						<td class="w-10 px-2 py-3 align-middle">
							<button
								type="button"
								class="disclosure"
								class:open
								aria-expanded={open}
								aria-controls={open ? panelId(index) : undefined}
								aria-label={language.current && disclosureLabel(item)}
								onclick={() => toggle(item.id)}
							>
								<!-- Lucide: chevron-right -->
								<svg
									class="w-4 h-4"
									viewBox="0 0 24 24"
									fill="none"
									stroke="currentColor"
									stroke-width="2"
									stroke-linecap="round"
									stroke-linejoin="round"
									aria-hidden="true"
								>
									<polyline points="9 18 15 12 9 6" />
								</svg>
							</button>
						</td>
					{/if}
					{@render row(item)}
				</tr>
				{#if expanded && open}
					<tr class="bg-surface">
						<td id={panelId(index)} colspan={columnCount} class="px-6 py-4">
							{@render expanded(item)}
						</td>
					</tr>
				{/if}
			{/each}
			{#if items.length === 0}
				<tr>
					<td
						colspan={columnCount}
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
	/* Step G G.3: hover-rail + active-rail only apply to interactive
	 * rows. Read-only tables (Sessions) keep the default cursor + no
	 * rail. Keyboard focus lands on the disclosure button, which
	 * carries its own focus ring. */
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
	.disclosure {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 1.5rem;
		height: 1.5rem;
		padding: 0;
		color: var(--text-secondary);
		background: transparent;
		border: 0;
		border-radius: var(--radius-sm);
		cursor: pointer;
	}
	.disclosure svg {
		transition: transform var(--motion-fast);
	}
	.disclosure.open svg {
		transform: rotate(90deg);
	}
	.disclosure:hover {
		color: var(--text-primary);
	}
	.disclosure:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
</style>
