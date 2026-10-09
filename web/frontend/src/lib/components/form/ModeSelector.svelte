<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ModeSelector (v2.41) — a labelled segmented control for the route
  form's small closed sets of modes (WAF off/detect/block, country
  block off/allow/deny, IP filter…). A dropdown hides the other
  choices and says nothing about what they do; the segments show all
  of them at once, each carrying the same colour semantics as the
  section rails: neutral, allow (green), watch (amber), block (red).

  The hint of the SELECTED option is printed under the control, so
  the operator reads the consequence of the mode they are on without
  opening anything.

  Interaction follows the WAI-ARIA radiogroup pattern already used by
  RouteStateControl.svelte (arrow keys move the selection, roving
  tabindex) — this component is its text-labelled sibling. `value` is
  $bindable here because the callers bind plain form fields; a caller
  that needs to gate a change (confirm dialog) passes `onchange` and
  a non-bound `value`.
-->
<script lang="ts" generics="T extends string">
	/** Same four postures as RouteSection's coloured rail. */
	type ModeTone = 'neutral' | 'allow' | 'watch' | 'block';

	interface Option {
		value: T;
		label: string;
		/** One line on what this mode does; shown when selected. */
		hint?: string;
		tone?: ModeTone;
	}

	interface Props {
		options: Option[];
		value: T;
		onchange?: (v: T) => void;
		disabled?: boolean;
		ariaLabel?: string;
		/** id of the group; each segment gets `${id}-${value}` as testid. */
		id?: string;
	}

	let { options, value = $bindable(), onchange, disabled = false, ariaLabel, id }: Props = $props();

	const selected = $derived(options.find((o) => o.value === value));

	function pick(v: T): void {
		if (disabled || v === value) return;
		value = v;
		onchange?.(v);
	}

	function onKeydown(e: KeyboardEvent): void {
		if (disabled) return;
		const idx = options.findIndex((o) => o.value === value);
		let next: number | null = null;
		switch (e.key) {
			case 'ArrowLeft':
			case 'ArrowUp':
				next = (idx - 1 + options.length) % options.length;
				break;
			case 'ArrowRight':
			case 'ArrowDown':
				next = (idx + 1) % options.length;
				break;
			case 'Home':
				next = 0;
				break;
			case 'End':
				next = options.length - 1;
				break;
			default:
				return;
		}
		e.preventDefault();
		pick(options[next].value);
	}
</script>

<div class="wrap">
	<!-- svelte-ignore a11y_interactive_supports_focus -->
	<div
		class="group"
		{id}
		role="radiogroup"
		aria-label={ariaLabel}
		aria-disabled={disabled || undefined}
		onkeydown={onKeydown}
	>
		{#each options as opt (opt.value)}
			<button
				type="button"
				role="radio"
				class="seg"
				data-tone={opt.tone ?? 'neutral'}
				class:active={opt.value === value}
				aria-checked={opt.value === value}
				tabindex={opt.value === value ? 0 : -1}
				data-testid={id ? `${id}-${opt.value}` : undefined}
				{disabled}
				onclick={() => pick(opt.value)}
			>
				{opt.label}
			</button>
		{/each}
	</div>
	{#if selected?.hint}
		<p class="hint">{selected.hint}</p>
	{/if}
</div>

<style>
	.wrap {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.group {
		display: inline-flex;
		flex-wrap: wrap;
		gap: 2px;
		padding: 2px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-full);
		width: fit-content;
		max-width: 100%;
		user-select: none;
	}
	.seg {
		padding: 5px 14px;
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
		background: transparent;
		border: 0;
		border-radius: var(--radius-full);
		cursor: pointer;
		transition:
			color var(--motion-fast),
			background-color var(--motion-fast);
	}
	.seg:hover:not(:disabled):not(.active) {
		color: var(--text-primary);
	}
	/* Same soft-tint pattern as Badge.svelte / RouteStateControl:
	   the selected segment wears its semantic colour, the others
	   stay neutral so the control reads at a glance. */
	.seg.active {
		background: var(--bg-elevated);
		box-shadow: inset 0 0 0 1px var(--border-default);
		color: var(--text-primary);
	}
	.seg[data-tone='allow'].active {
		background: var(--badge-success-bg);
		box-shadow: inset 0 0 0 1px var(--badge-success-border);
		color: var(--status-up);
	}
	.seg[data-tone='watch'].active {
		background: var(--badge-warning-bg);
		box-shadow: inset 0 0 0 1px var(--badge-warning-border);
		color: var(--status-warn-fg);
	}
	.seg[data-tone='block'].active {
		background: var(--badge-danger-bg);
		box-shadow: inset 0 0 0 1px var(--badge-danger-border);
		color: var(--status-down);
	}
	.seg:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.seg:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	.hint {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-muted);
		max-width: 65ch;
	}
</style>
