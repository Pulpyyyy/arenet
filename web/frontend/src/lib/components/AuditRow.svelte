<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AuditRow (spec §9.4). Renders one collapsed-row of the audit table.
  DataTable owns expand/collapse (a disclosure button in its leading
  cell, plus a mouse click anywhere else on the row); this component
  only renders the <td> cells.

  Two interactive elements must not toggle the row: the action badge
  (click → filter by action) and the actor filter icon (click → filter
  by actor user ID). DataTable already ignores row clicks that land on
  a button; they also stop propagation as a belt-and-braces guard.
-->
<script lang="ts">
	import type { AuditEvent } from '$lib/api/audit';
	import {
		categoryOf,
		relativeTime,
		targetDisplayShort,
		actorDisplayShort
	} from '$lib/utils/audit-format';

	interface Props {
		event: AuditEvent;
		/** Called when the action badge is clicked. */
		onFilterAction: (action: string) => void;
		/**
		 * Called when the actor filter icon is clicked. Receives the
		 * resolved display name (displayName / username / snapshot) so
		 * the filter pill can render human-readable text. The backend
		 * query continues to use the UUID. Step G G.4 fix for the
		 * "Actor: <UUID>" cosmetic debt (smoke doc Step F §5 #3).
		 */
		onFilterActor: (actorUserId: string, actorDisplayName: string) => void;
	}

	let { event, onFilterAction, onFilterActor }: Props = $props();

	const category = $derived(categoryOf(event.action));
	const actorInfo = $derived(
		actorDisplayShort({
			actorUserId: event.actorUserId,
			actorUsernameSnapshot: event.actorUsernameSnapshot
		})
	);
	const targetText = $derived(targetDisplayShort(event.targetType, event.targetId));
	const timeShort = $derived(relativeTime(event.timestamp));
	const ipDisplay = $derived(event.ip || '—');

	function handleBadgeClick(e: MouseEvent): void {
		e.stopPropagation();
		onFilterAction(event.action);
	}

	function handleActorFilterClick(e: MouseEvent): void {
		e.stopPropagation();
		onFilterActor(event.actorUserId, actorInfo.text);
	}
</script>

<td class="px-4 py-3 text-sm text-secondary" title={event.timestamp}>{timeShort}</td>
<td class="px-4 py-3">
	<button
		type="button"
		class="audit-badge"
		data-category={category}
		onclick={handleBadgeClick}
		aria-label={`Filter by action: ${event.action}`}
	>
		{event.action}
	</button>
</td>
<td class="px-4 py-3 text-sm">
	{#if actorInfo.anonymous}
		<span class="italic text-muted">{actorInfo.text}</span>
	{:else}
		<span class="inline-flex items-center gap-1.5 group">
			<span class="text-primary">{actorInfo.text}</span>
			<button
				type="button"
				class="text-muted opacity-0 group-hover:opacity-100 transition-opacity"
				onclick={handleActorFilterClick}
				aria-label={`Filter by actor: ${actorInfo.text}`}
				title="Filter by this actor"
			>
				<!-- Lucide: filter (small) -->
				<svg
					class="w-3.5 h-3.5"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
				>
					<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
				</svg>
			</button>
		</span>
	{/if}
</td>
<td class="px-4 py-3 text-sm text-secondary" title={event.targetId || undefined}>
	{targetText}
</td>
<td class="px-4 py-3 text-xs font-mono text-secondary">{ipDisplay}</td>

<style>
	.audit-badge {
		display: inline-flex;
		align-items: center;
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		font-weight: 500;
		border-radius: var(--radius-full);
		border: 1px solid;
		line-height: 1.5;
		cursor: pointer;
		transition: opacity var(--motion-fast);
	}
	.audit-badge:hover {
		opacity: 0.85;
	}
	.audit-badge:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	/*
	 * One rule per category (spec §9.4). Uses --badge-*-{bg-strong,border}
	 * token pairs from tokens.css. The "strong" variant (@30% tint)
	 * is required here because the text is white (--text-on-color)
	 * on top — the base @15% tint dropped below readable contrast
	 * in light theme (Chunk 3.5 smoke fix). Badge.svelte keeps the
	 * @15% base because its text is the saturated color, not white.
	 */
	.audit-badge[data-category='auth'] {
		background: var(--badge-info-bg-strong);
		border-color: var(--badge-info-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='mutation'] {
		background: var(--badge-warning-bg-strong);
		border-color: var(--badge-warning-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='security'] {
		background: var(--badge-danger-bg-strong);
		border-color: var(--badge-danger-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='hibp'] {
		background: var(--badge-violet-bg-strong);
		border-color: var(--badge-violet-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='meta'] {
		background: var(--badge-meta-bg-strong);
		border-color: var(--badge-meta-border);
		color: var(--text-on-color);
	}
	.audit-badge[data-category='unknown'] {
		background: var(--bg-elevated);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}
</style>
