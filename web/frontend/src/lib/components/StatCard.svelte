<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  StatCard — the summary tile, and the only one.

  v2.41: the same tile existed four times — a scoped-CSS `.kpi` copy
  in the dashboard, another in certs, another in the WAF page, and
  this component on routes and users. They differed only in the size
  of the number and the weight of the label: drift, not intent. This
  component now carries the `.kpi` treatment, which was the more
  considered of the two and already the majority, and absorbs what
  the copies could do and it could not:

    unit    — the small suffix after the number (req/s, ms, / 24h)
    hint    — the foot line carrying the breakdown
    variant — 'text' shrinks the value for non-numeric readings
              (an issuer name, an ACME method), like certs' .mode

  `trend` is kept from the pre-v2.41 API: positive is an up arrow in
  the up colour, negative a down arrow in the down colour.

  Both optional, both off by default (existing callers unchanged):

    href — the tile becomes a link to the page behind the number;
           the whole tile is the target, with a visible focus ring
    tone — 'warn' marks a value that wants a look (a 5xx, an
           expiring certificate): warning border and value colour,
           exposed as data-tone for styling and tests
-->
<script lang="ts">
	interface Props {
		label: string;
		value: string | number;
		/** Small suffix after the value, e.g. "req/s", "ms", "/ 24h". */
		unit?: string;
		/**
		 * Positive => up arrow + status-up colour, negative => down arrow +
		 * status-down colour, zero => nothing.
		 */
		trend?: number;
		/** Foot line under the value: the breakdown behind the number. */
		hint?: string;
		/** 'text' shrinks the value: it is a word, not a measurement. */
		variant?: 'number' | 'text';
		/** When set, the tile is a link to the page behind the number. */
		href?: string;
		/** 'warn' flags a value that wants a look; 'default' is quiet. */
		tone?: 'default' | 'warn';
		testid?: string;
	}

	let {
		label,
		value,
		unit = '',
		trend = 0,
		hint = '',
		variant = 'number',
		href,
		tone = 'default',
		testid
	}: Props = $props();

	const trendClass = $derived(trend > 0 ? 'up' : trend < 0 ? 'down' : '');
	const trendArrow = $derived(trend > 0 ? '↗' : '↘');
	const trendAbs = $derived(Math.abs(trend));
</script>

<svelte:element
	this={href ? 'a' : 'div'}
	class="tile"
	{href}
	data-tone={tone === 'default' ? undefined : tone}
	data-testid={testid}
>
	<div class="label">{label}</div>
	<div class="value" data-variant={variant}>
		{value}{#if unit}<span class="unit">{unit}</span>{/if}
		{#if trend !== 0}
			<span class="trend {trendClass}">{trendArrow} {trendAbs}</span>
		{/if}
	</div>
	{#if hint}
		<div class="foot">{hint}</div>
	{/if}
</svelte:element>

<style>
	.tile {
		background: var(--bg-elevated);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius, 8px);
		padding: 14px 16px;
	}
	.tile[href] {
		display: block;
		color: inherit;
		text-decoration: none;
		transition: background 0.12s;
	}
	/* Background, not border: the border carries the warn tone. */
	.tile[href]:hover {
		background: var(--bg-hover);
	}
	.tile[href]:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.tile[data-tone='warn'] {
		border-color: var(--status-warn);
	}
	.tile[data-tone='warn'] .value {
		color: var(--status-warn);
	}
	.label {
		color: var(--text-muted);
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		font-family: var(--font-mono);
		margin-bottom: 6px;
	}
	.value {
		color: var(--text-primary);
		font-size: 28px;
		font-weight: 500;
		letter-spacing: -0.02em;
		font-variant-numeric: tabular-nums;
		line-height: 1.2;
	}
	.value[data-variant='text'] {
		font-size: 18px;
	}
	.unit {
		color: var(--text-muted);
		font-size: 13px;
		margin-left: 4px;
		font-weight: 400;
		font-variant-numeric: normal;
	}
	.trend {
		font-size: 13px;
		margin-left: 8px;
		font-weight: 400;
	}
	.trend.up {
		color: var(--status-up);
	}
	.trend.down {
		color: var(--status-down);
	}
	.foot {
		color: var(--text-muted);
		font-size: 11.5px;
		margin-top: 8px;
		font-family: var(--font-mono);
		line-height: 1.45;
	}
</style>
