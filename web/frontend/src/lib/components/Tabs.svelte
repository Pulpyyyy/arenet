<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Tabs (Step CS.3 — extracted from /security/decisions).

  Underline-primary tab navigation. Used at the top of a page
  (or page-section) to switch between sibling views that share
  the same URL slot. NOT for in-card filter chips — /certs has
  a chip-style filter that intentionally diverges, see the
  inline comment near its tablist for the rationale.

  ARIA contract:
    - role="tablist" wrapper with operator-supplied aria-label
    - role="tab" buttons with aria-selected reflecting state
    - the tablist is ONE Tab stop (roving tabindex: only the
      selected tab has tabindex=0)
    - ArrowLeft / ArrowRight move focus between tabs (wrapping),
      Home / End jump to the first / last tab
    - MANUAL activation: moving focus does not select. Enter and
      Space (native <button> behaviour) select the focused tab.
      WAI-ARIA recommends automatic activation only when a panel
      shows without noticeable latency; several callers do real
      work in onChange (CrowdSecDecisionsPanel starts live LAPI
      polling or fetches scenarios, /settings rewrites the hash
      and scrolls to the top), so selecting on every arrow press
      would fire that work for each tab crossed on the way.
    - aria-controls is emitted when the caller gives a tab a
      `panelId` (the id of the element holding that tab's panel)

  Public API (Svelte 5 runes):

    value           — generic string discriminant (bindable)
    tabs            — readonly array of { id, label, testId?,
                      panelId? }
    ariaLabel       — wrapper aria-label (required for a11y)
    onChange?       — optional callback fired on user selection.
                      Receives the new id. If omitted, the
                      bindable `value` is the only signal; if
                      provided, the consumer can run effectful
                      logic (lazy loads, analytics) without
                      reacting to a $derived on `value`.

  testId vs label: label is the user-visible text; testId is
  the data-testid attribute used by tests. Both are owned by
  the consumer so existing test IDs (tab-snapshot, tab-live,
  tab-scenarios on /security/decisions) survive the extraction
  without rewrites.

  Generic T — Svelte 5 components can be made generic via the
  `generics` attribute. Constrained to string so the tab id
  fits as a Map key + a discriminated union in callers.
-->
<script lang="ts" generics="T extends string">
	interface TabDescriptor<TId extends string> {
		id: TId;
		label: string;
		testId?: string;
		/** id of the element holding this tab's panel; emitted as aria-controls. */
		panelId?: string;
	}

	interface Props {
		value: T;
		tabs: readonly TabDescriptor<T>[];
		ariaLabel: string;
		onChange?: (next: T) => void;
	}

	let { value = $bindable(), tabs, ariaLabel, onChange }: Props = $props();

	/** Index of the tab that owns the Tab stop: the selected one, or the
	 *  first tab if `value` matches none (so the list stays reachable). */
	const tabStop = $derived(Math.max(0, tabs.findIndex((tab) => tab.id === value)));

	function select(next: T): void {
		if (next === value) return;
		value = next;
		onChange?.(next);
	}

	function onKeydown(e: KeyboardEvent): void {
		const buttons = Array.from(
			(e.currentTarget as HTMLElement).querySelectorAll<HTMLButtonElement>('[role="tab"]')
		);
		if (buttons.length === 0) return;
		const focused = buttons.indexOf(document.activeElement as HTMLButtonElement);
		const from = focused >= 0 ? focused : tabStop;
		let next: number;
		switch (e.key) {
			case 'ArrowLeft':
				next = (from - 1 + buttons.length) % buttons.length;
				break;
			case 'ArrowRight':
				next = (from + 1) % buttons.length;
				break;
			case 'Home':
				next = 0;
				break;
			case 'End':
				next = buttons.length - 1;
				break;
			default:
				return;
		}
		e.preventDefault();
		buttons[next].focus();
	}
</script>

<!-- svelte-ignore a11y_interactive_supports_focus -->
<div class="tabs" role="tablist" aria-label={ariaLabel} onkeydown={onKeydown}>
	{#each tabs as tab, i (tab.id)}
		<button
			type="button"
			role="tab"
			class="tab"
			class:active={value === tab.id}
			aria-selected={value === tab.id}
			aria-controls={tab.panelId}
			tabindex={i === tabStop ? 0 : -1}
			data-testid={tab.testId}
			onclick={() => select(tab.id)}
		>
			{tab.label}
		</button>
	{/each}
</div>

<style>
	.tabs {
		display: flex;
		gap: 0.25rem;
		margin-bottom: 0.5rem;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.tab {
		background: transparent;
		color: var(--text-secondary);
		border: none;
		padding: 0.5rem 1rem;
		font-size: var(--text-sm);
		cursor: pointer;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
		font-family: inherit;
	}
	.tab:hover {
		color: var(--text-primary);
	}
	.tab.active {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.tab:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
		border-radius: 2px;
	}
</style>
