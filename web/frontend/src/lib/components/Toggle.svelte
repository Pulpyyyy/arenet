<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Toggle (Step F §4.4). 2-state segmented control rendered as a
  rounded pill with two options side by side and an animated knob
  that slides under the active value.

  Phase 1 (Sub-task 1.2): the knob slide uses a CSS transform with
  `var(--motion-base)` timing. The spring-based motion (SPRING_SNAPPY
  from lib/styles/motion.ts) is wired in Chunk 3 once the animation
  helper layer exists — keeping this component dependency-free for
  now means we don't have to also pull in svelte/motion before its
  surrounding utilities exist.

  Public API (add-only; do not rename or remove props per Step F
  discipline §1.3):

    options  — array of {value, label, icon?}, length === 2
    value    — current selection (controlled prop, NOT bindable —
               the caller drives it via re-render after onchange)
    onchange — fired on user interaction with the new value
    disabled — disables interaction (e.g., while isApplying)
    ariaLabel — labels the group for screen readers

  Why controlled (not bindable): the theme store applies a value
  via applyLocally() which writes BOTH `current` AND the
  `<html data-theme>` attribute. If `value` were bindable, a click
  on the Toggle would mutate `theme.current` directly through the
  bind BEFORE onchange fires, then `theme.set(v)` would early-return
  on `next === this.current` and skip applyLocally — leaving the
  DOM attribute stale (smoke session bug). Controlled mode keeps
  the store as the single writer.
-->
<script lang="ts" generics="T extends string">
	import type { Snippet } from 'svelte';

	interface Option {
		value: T;
		label: string;
		icon?: Snippet;
	}

	interface Props {
		options: [Option, Option];
		value: T;
		onchange?: (v: T) => void;
		disabled?: boolean;
		ariaLabel?: string;
	}

	let { options, value, onchange, disabled = false, ariaLabel }: Props = $props();

	const activeIndex = $derived(options[0].value === value ? 0 : 1);

	function pick(v: T): void {
		if (disabled || v === value) return;
		onchange?.(v);
	}

	/*
	 * WAI-ARIA radiogroup keyboard model, same as ModeSelector.svelte:
	 * the group is ONE Tab stop (roving tabindex — only the checked
	 * option has tabindex=0) and the arrow keys move the selection.
	 * Focus follows to the newly picked option so a second arrow press
	 * keeps going from there even before the controlled `value` prop
	 * comes back from the caller.
	 */
	function onKeydown(e: KeyboardEvent): void {
		if (disabled) return;
		const radios = Array.from(
			(e.currentTarget as HTMLElement).querySelectorAll<HTMLButtonElement>('[role="radio"]')
		);
		const focused = radios.indexOf(document.activeElement as HTMLButtonElement);
		const from = focused >= 0 ? focused : activeIndex;
		let next: number;
		switch (e.key) {
			case 'ArrowLeft':
			case 'ArrowUp':
				next = (from - 1 + options.length) % options.length;
				break;
			case 'ArrowRight':
			case 'ArrowDown':
				next = (from + 1) % options.length;
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
		radios[next]?.focus();
		pick(options[next].value);
	}
</script>

<!-- svelte-ignore a11y_interactive_supports_focus -->
<div
	class="toggle"
	role="radiogroup"
	aria-label={ariaLabel}
	aria-disabled={disabled || undefined}
	onkeydown={onKeydown}
>
	<span class="knob" style:transform="translateX({activeIndex * 100}%)" aria-hidden="true"></span>
	{#each options as opt, i (opt.value)}
		<button
			type="button"
			role="radio"
			class="opt"
			class:active={opt.value === value}
			aria-checked={opt.value === value}
			tabindex={i === activeIndex ? 0 : -1}
			{disabled}
			onclick={() => pick(opt.value)}
		>
			{#if opt.icon}{@render opt.icon()}{/if}
			<span class="lbl">{opt.label}</span>
		</button>
	{/each}
</div>

<style>
	.toggle {
		position: relative;
		display: inline-grid;
		grid-template-columns: 1fr 1fr;
		gap: 0;
		padding: 2px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-full);
		user-select: none;
	}
	.knob {
		position: absolute;
		top: 2px;
		left: 2px;
		width: calc(50% - 2px);
		height: calc(100% - 4px);
		background: var(--bg-elevated);
		border-radius: var(--radius-full);
		box-shadow: var(--shadow-sm);
		transition: transform var(--motion-base);
		pointer-events: none;
	}
	.opt {
		position: relative;
		z-index: 1;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-4);
		min-width: 64px;
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
		background: transparent;
		border: 0;
		border-radius: var(--radius-full);
		cursor: pointer;
		transition: color var(--motion-fast);
	}
	.opt.active {
		color: var(--text-primary);
	}
	.opt:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.opt:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	.lbl {
		line-height: 1;
	}
</style>
