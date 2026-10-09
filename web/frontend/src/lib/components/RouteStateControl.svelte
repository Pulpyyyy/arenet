<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  RouteStateControl (Task 8). A 3-state segmented control for a
  route's lifecycle: Active / Maintenance / Disabled. Each segment
  has a fixed semantic color + icon (play triangle / wrench / power)
  and the active segment is filled with its semantic color.

  v2.17.1 UX polish (Item A): renders ICONS ONLY — the visible
  `.lbl` text span was dropped. Three (icon+word) segments made the
  control too wide, which pushed the Actions column wider and forced
  the neighbouring Health Check / "Cert dédié (HTTP-01)" cells to
  wrap onto 2 lines. The `labels` prop is kept (parent still passes
  t('routes.state.*')) but now feeds `title` (hover tooltip) and
  `aria-label` per segment instead of visible text — the semantic
  fill color (green/amber/red) + the active-segment highlight convey
  which state is selected to sighted users; screen readers still get
  the full label via aria-label.

  This is a NEW standalone component — it deliberately does NOT
  extend or import Toggle.svelte (which is hardcoded to 2 generic
  slots and used by Theme/Language; touching it risks regressing
  those). It instead copies Toggle's proven patterns:

    - controlled `value` + `onchange` contract (NOT bindable — the
      caller re-renders after onchange, same reasoning as Toggle's
      theme-store integration: a single writer for the value)
    - role="radiogroup" on the container, role="radio" + aria-checked
      per segment
    - keyboard navigation via ArrowLeft/ArrowRight/Home/End with a
      roving tabindex (WAI-ARIA radiogroup pattern), but with MANUAL
      activation: arrows only move focus, Enter/Space commits. Every
      pick is a live change to a route, and arrowing past Maintenance
      on the way to Disabled used to put the route in maintenance.

  Public API (add-only; do not rename/remove props):

    value    — current state: 'active' | 'maintenance' | 'disabled'
    onchange — fired with the new state on user interaction
    disabled — disables interaction entirely (e.g. while isApplying)
    ariaLabel — labels the group for screen readers
    labels   — Final-review Finding #3 (i18n regression) fix: the
               segment labels as a {active, maintenance, disabled}
               map. This is a leaf component with no store/i18n
               import of its own (mirrors Toggle.svelte, its
               closest neighbor, which takes labels via its
               `options` prop) — the PARENT owns `t()` and passes
               translated strings in. Defaults to the English
               literals so existing callers that don't pass `labels`
               keep working unchanged.
-->
<script lang="ts">
	type RouteState = 'active' | 'maintenance' | 'disabled';

	interface Props {
		value: RouteState;
		onchange?: (v: RouteState) => void;
		disabled?: boolean;
		ariaLabel?: string;
		labels?: Record<RouteState, string>;
	}

	const DEFAULT_LABELS: Record<RouteState, string> = {
		active: 'Active',
		maintenance: 'Maintenance',
		disabled: 'Disabled'
	};

	let { value, onchange, disabled = false, ariaLabel, labels = DEFAULT_LABELS }: Props = $props();

	const STATES: RouteState[] = ['active', 'maintenance', 'disabled'];

	function pick(v: RouteState): void {
		if (disabled || v === value) return;
		onchange?.(v);
	}

	// The segment keyboard focus is on while it is inside the group;
	// null otherwise, so the tab stop falls back to the checked one.
	let focused = $state<RouteState | null>(null);
	const tabStop = $derived(focused ?? value);

	function onKeydown(e: KeyboardEvent): void {
		if (disabled) return;
		if (e.key === 'Enter' || e.key === ' ') {
			// The commit is the focused button's own click. Stopped here
			// so an ancestor's key handler (a routes row opens its panel
			// on Enter/Space) does not also act on it.
			e.stopPropagation();
			return;
		}
		const idx = STATES.indexOf(tabStop);
		let next: number | null = null;
		switch (e.key) {
			case 'ArrowLeft':
			case 'ArrowUp':
				next = (idx - 1 + STATES.length) % STATES.length;
				break;
			case 'ArrowRight':
			case 'ArrowDown':
				next = (idx + 1) % STATES.length;
				break;
			case 'Home':
				next = 0;
				break;
			case 'End':
				next = STATES.length - 1;
				break;
			default:
				return;
		}
		e.preventDefault();
		focused = STATES[next];
		const group = (e.target as HTMLElement).closest('[role="radiogroup"]');
		group?.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next]?.focus();
	}

	function onFocusout(e: FocusEvent): void {
		const group = (e.target as HTMLElement).closest('[role="radiogroup"]');
		if (!group?.contains(e.relatedTarget as Node | null)) focused = null;
	}
</script>

<!-- svelte-ignore a11y_interactive_supports_focus -->
<div
	class="route-state-control"
	role="radiogroup"
	aria-label={ariaLabel}
	aria-disabled={disabled || undefined}
	onkeydown={onKeydown}
	onfocusout={onFocusout}
>
	{#each STATES as state (state)}
		<button
			type="button"
			role="radio"
			class="segment"
			data-state={state}
			class:active={state === value}
			aria-checked={state === value}
			aria-label={labels[state]}
			title={labels[state]}
			tabindex={state === tabStop ? 0 : -1}
			{disabled}
			onfocus={() => (focused = state)}
			onclick={() => pick(state)}
		>
			<span class="icon" aria-hidden="true">
				{#if state === 'active'}
					<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
						<path d="M4 2.5v11l10-5.5-10-5.5z" />
					</svg>
				{:else if state === 'maintenance'}
					<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
						<path
							d="M13.7 2.3a3.5 3.5 0 0 1-4.6 4.6l-5.4 5.4a1.2 1.2 0 0 1-1.7-1.7l5.4-5.4a3.5 3.5 0 0 1 4.6-4.6l-2 2 .9 1.8 1.8.9 2-2z"
						/>
					</svg>
				{:else}
					<svg viewBox="0 0 16 16" width="14" height="14" fill="none">
						<path
							d="M8 1.5v6"
							stroke="currentColor"
							stroke-width="1.6"
							stroke-linecap="round"
						/>
						<path
							d="M4.5 3.5a5 5 0 1 0 7 0"
							stroke="currentColor"
							stroke-width="1.6"
							stroke-linecap="round"
							fill="none"
						/>
					</svg>
				{/if}
			</span>
		</button>
	{/each}
</div>

<style>
	.route-state-control {
		display: inline-grid;
		grid-template-columns: repeat(3, 1fr);
		gap: var(--space-1);
		padding: 2px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-full);
		user-select: none;
	}
	.segment {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-2);
		min-width: 32px;
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
	/* Active segment uses the app-wide status badge pattern (Badge.svelte,
	   --badge-*-{bg,border}) — a soft ~15% tint of the status color +
	   that color's border and icon — rather than a full-saturation solid
	   fill, so the selected state reads as the SAME nuance as the status
	   indicators elsewhere without the flashy/pushy look. Green = active
	   (--status-up), amber = maintenance (--status-warn, the WAF-detect
	   amber), red = disabled (--status-down). */
	.segment[data-state='active'].active {
		background: var(--badge-success-bg);
		box-shadow: inset 0 0 0 1px var(--badge-success-border);
		color: var(--status-up);
	}
	.segment[data-state='maintenance'].active {
		background: var(--badge-warning-bg);
		box-shadow: inset 0 0 0 1px var(--badge-warning-border);
		color: var(--status-warn);
	}
	/* Disabled: same tinted pattern but visibly muted ("teinte opaque /
	   atténuée") — a lower-opacity red + dimmed icon so a disabled route
	   reads as switched-off, not alarming. */
	.segment[data-state='disabled'].active {
		background: var(--badge-danger-bg);
		box-shadow: inset 0 0 0 1px var(--badge-danger-border);
		color: color-mix(in oklch, var(--status-down) 75%, var(--text-secondary));
	}
	.segment:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.segment:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	.icon {
		display: inline-flex;
		line-height: 0;
	}
</style>
