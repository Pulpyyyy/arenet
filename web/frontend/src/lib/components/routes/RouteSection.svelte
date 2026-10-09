<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  RouteSection (v2.41) — one collapsible section of the route form.
  The closed row carries everything needed to read the route without
  opening anything: the section name, a one-line summary of its state
  and, when the section decides what happens to traffic, a badge and a
  coloured rail:

    allow  (green)  — lets traffic through on a criterion
    block  (red)    — blocks traffic
    watch  (amber)  — observes without blocking (WAF detect)
    off    (grey)   — configured but inactive
    set    (accent) — configured, and decides nothing about traffic

  `set` exists because the colour answers two questions at once, and an
  operator reads the second one first: "what happens to traffic here"
  and "is there anything in here at all". A section that is configured
  but makes no allow/block decision used to show either nothing or the
  grey of `off`, both of which read as empty — so error pages with a
  custom template, or path rules carrying only a redirect, looked
  untouched until opened. `set` says "something is here" in the accent
  colour, which claims nothing about traffic and so leaves green, red
  and amber their meaning.

  A section with nothing in it still passes no posture and stays
  neutral. That distinction is the whole point.
-->
<script lang="ts">
	import { untrack } from 'svelte';
	import type { Snippet } from 'svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	/** What the section does to traffic; undefined = not an authorisation decision. */
	export type Posture = 'allow' | 'block' | 'watch' | 'off' | 'set';

	interface Props {
		/** Section name, e.g. "WAF". */
		name: string;
		/** One-line state summary shown on the closed row. */
		summary?: string;
		/** Short badge (e.g. "block", "detect", "off"). */
		badge?: string;
		posture?: Posture;
		/** Open on first render (the route's essentials). */
		open?: boolean;
		/**
		 * The section holds a field error. Opens it and marks the closed
		 * row, so an error is never left inside a section out of sight.
		 */
		invalid?: boolean;
		testid?: string;
		children: Snippet;
	}

	let {
		name,
		summary = '',
		badge = '',
		posture,
		open = false,
		invalid = false,
		testid,
		children
	}: Props = $props();

	// The open state must live HERE, bound to the element. Passing
	// `open` straight through as an attribute made every section
	// snap shut on any parent re-render: picking an auth mode or a
	// WAF mode changes the summary, Svelte re-applies open={false},
	// and the operator's section closed under their cursor.
	// `open` is only the initial value.
	let isOpen = $state(untrack(() => open));

	// Opens on the transition to invalid only: the operator can still
	// close a section that holds an error, and nothing reopens it until
	// the next refused save.
	$effect(() => {
		if (invalid) untrack(() => (isOpen = true));
	});
</script>

<details
	class="section"
	data-posture={posture}
	data-invalid={invalid ? '' : undefined}
	bind:open={isOpen}
	data-testid={testid}
>
	<summary>
		<span class="name">{name}</span>
		{#if invalid}
			<span class="invalid" data-testid={testid ? `${testid}-invalid` : undefined}>
				{language.current && t('routes.form.sectionInvalid')}
			</span>
		{/if}
		<span class="summary">{summary}</span>
		{#if badge}
			<span class="badge" data-tone={posture ?? 'neutral'}>{badge}</span>
		{/if}
	</summary>
	<div class="body">
		{@render children()}
	</div>
</details>

<style>
	.section {
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		background: var(--bg-elevated);
	}
	.section[open] {
		border-color: var(--border-default);
	}
	.section[data-posture] {
		border-left-width: 3px;
	}
	.section[data-posture='allow'] {
		border-left-color: var(--status-up);
	}
	.section[data-posture='block'] {
		border-left-color: var(--status-down);
	}
	.section[data-posture='watch'] {
		border-left-color: var(--status-warn);
	}
	.section[data-posture='off'] {
		border-left-color: var(--border-default);
	}
	.section[data-posture='set'] {
		border-left-color: var(--accent-cyan);
	}
	/* After the posture rules on purpose: an error outranks the posture
	   colour until it is fixed. */
	.section[data-invalid] {
		border-color: var(--status-down);
	}

	summary {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 10px 12px;
		cursor: pointer;
		list-style: none;
		border-radius: 8px;
	}
	summary::-webkit-details-marker {
		display: none;
	}
	summary::before {
		content: '▸';
		color: var(--text-muted);
		font-size: 11px;
		transition: transform 0.15s ease;
	}
	.section[open] summary::before {
		transform: rotate(90deg);
	}
	summary:hover {
		background: var(--bg-surface);
	}
	summary:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
	.section[open] summary {
		border-bottom: 1px solid var(--border-subtle);
		border-radius: 8px 8px 0 0;
	}

	.name {
		font-weight: 600;
		font-size: 14px;
		color: var(--text-primary);
		min-width: 130px;
	}
	.summary {
		flex: 1;
		min-width: 0;
		font-family: var(--font-mono, monospace);
		font-size: 12.5px;
		color: var(--text-secondary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.badge {
		flex: none;
		font-size: 10.5px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		border: 1px solid currentColor;
		border-radius: 999px;
		padding: 1px 8px;
		color: var(--text-muted);
	}
	.badge[data-tone='allow'] {
		color: var(--status-up);
	}
	.badge[data-tone='block'] {
		color: var(--status-down);
	}
	.badge[data-tone='watch'] {
		color: var(--status-warn-fg);
	}
	.invalid {
		flex: none;
		font-size: 12px;
		font-weight: 600;
		color: var(--status-down);
	}

	.body {
		padding: 14px 12px 16px 26px;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	@media (max-width: 640px) {
		.body {
			padding-left: 12px;
		}
		.name {
			min-width: 0;
		}
		summary {
			flex-wrap: wrap;
		}
		.summary {
			flex-basis: 100%;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		summary::before {
			transition: none;
		}
	}
</style>
