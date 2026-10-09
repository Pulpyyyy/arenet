<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TimeRange — segmented control for a time window (1h / 24h / 7d /
  30d, or any subset of them).

  Several pages grew their own two- or four-button toggle, each with
  its own markup and none with the same keyboard or ARIA story. This
  is the shared one.

  ARIA contract:
    - role="group" wrapper with an aria-label (defaults to
      t('timeRange.ariaLabel'))
    - one toggle <button> per option, aria-pressed reflecting state
    - roving tabindex: only the selected button is in the tab order;
      ArrowLeft / ArrowRight (and Up / Down) move to the previous /
      next option and select it, wrapping at either end; Home / End
      jump to the first / last.

  Public API (Svelte 5 runes):

    value        — selected option (bindable)
    options      — which windows to offer, in display order
                   (default: all four)
    ariaLabel?   — group label override
    onChange?    — fired on user selection with the new value, after
                   `value` is updated. A caller that needs to refetch
                   can pass value={…} (unbound) plus onChange.
    testIdPrefix — data-testid of each button is `${prefix}-${option}`

  Generic T so a caller whose window type is a narrower union (e.g.
  MetricWindow = '24h' | '30d') can bind its own variable without a
  cast.
-->
<script lang="ts" generics="T extends TimeRangeValue">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { TIME_RANGES, type TimeRangeValue } from '$lib/utils/time-range';

	interface Props {
		value: T;
		options?: readonly T[];
		ariaLabel?: string;
		onChange?: (next: T) => void;
		testIdPrefix?: string;
	}

	let {
		value = $bindable(),
		// The default is the full set; T is then TimeRangeValue itself,
		// which TypeScript cannot see through the generic.
		options = TIME_RANGES as unknown as readonly T[],
		ariaLabel,
		onChange,
		testIdPrefix = 'time-range'
	}: Props = $props();

	const buttons = $state<HTMLButtonElement[]>([]);

	// The button that carries tabindex=0: the selected one, or the
	// first when the value is not among the options.
	const tabStop = $derived(Math.max(0, options.indexOf(value)));

	function select(next: T): void {
		if (next === value) return;
		value = next;
		onChange?.(next);
	}

	function onKeydown(e: KeyboardEvent, index: number): void {
		const last = options.length - 1;
		let target: number;
		switch (e.key) {
			case 'ArrowRight':
			case 'ArrowDown':
				target = index === last ? 0 : index + 1;
				break;
			case 'ArrowLeft':
			case 'ArrowUp':
				target = index === 0 ? last : index - 1;
				break;
			case 'Home':
				target = 0;
				break;
			case 'End':
				target = last;
				break;
			default:
				return;
		}
		e.preventDefault();
		select(options[target]);
		buttons[target]?.focus();
	}
</script>

<div
	class="time-range"
	role="group"
	aria-label={ariaLabel ?? (language.current && t('timeRange.ariaLabel'))}
>
	{#each options as option, i (option)}
		<button
			bind:this={buttons[i]}
			type="button"
			class:active={value === option}
			aria-pressed={value === option}
			tabindex={i === tabStop ? 0 : -1}
			data-testid={`${testIdPrefix}-${option}`}
			onclick={() => select(option)}
			onkeydown={(e) => onKeydown(e, i)}
		>
			{language.current && t(`timeRange.${option}`)}
		</button>
	{/each}
</div>

<style>
	.time-range {
		display: inline-flex;
		gap: 0.25rem;
	}
	.time-range button {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.25rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		font-variant-numeric: tabular-nums;
		cursor: pointer;
	}
	.time-range button:hover {
		color: var(--text-primary);
	}
	.time-range button.active {
		background: var(--accent-cyan);
		color: var(--text-inverse);
		border-color: var(--accent-cyan);
	}
	.time-range button:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
</style>
