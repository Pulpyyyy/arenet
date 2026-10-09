<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V polish — Map legend.

  Visual language mirrors the topology page's
  TopologySidebar.svelte "Légende des flux" panel:
    - section.panel container with surface bg + 1 px border
      + 14/14/12 padding
    - <h3> title at 13 px / weight 600
    - <ul class="legend-list"> with per-row <li>
    - 4-dot SVG inline (viewBox 0 0 56 8) showing the
      category color via currentColor
    - <p class="legend-note"> at the bottom explaining the
      animation lifecycle, mirroring topology's note about
      the 60 s sliding window.

  Mounted as an absolute-positioned overlay in the bottom-
  right of the map frame (unlike topology's side panel
  which lives in a dedicated column — /map has no
  sidebar, the world canvas is full-width). Toggleable
  via the header so operators who don't need the key
  can stash it; default expanded.

  Each row's color sources from CATEGORY_COLORS in
  categoryColors.ts (single source of truth) — adding a
  new category in the future is a one-file change there
  + a one-line addition to LEGEND_ROWS below + its label
  under `map.legend*` in both locale files.

  Step V.1 (commits f657a11 / 09ea2c1 / b778424) ships
  the backend pipeline for the "normal" category: when an
  operator sets ARENET_NORMAL_TRAFFIC_SAMPLE_PCT > 0, the
  Caddy routemetrics middleware fans successful traffic
  through the geo bus → arcs render green on the map.
  V.1.4 drops the "(à venir)" italic marker on the normal
  row accordingly. The legend now reflects the full live
  taxonomy.

  The `comingSoon` flag + the `.legend-coming-soon` CSS
  class + the {#if entry.comingSoon} conditional stay in
  place — future categories (or a future V.1.X feature-
  gate use-case) can re-use them without re-architecting
  the row shape.
-->
<script lang="ts">
	import { CATEGORY_COLORS } from './categoryColors';
	import type { GeoEventCategory } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	// Reading language.current makes every label re-render on a
	// language switch.
	function tl(key: string): string {
		void language.current;
		return t(key);
	}

	interface LegendRow {
		category: GeoEventCategory;
		// i18n key, resolved at render time so the row follows the
		// active language.
		labelKey: string;
		// Reserved for future categories that ship the legend
		// row before the backend emit path lands. V.1.4
		// cleared this flag from the "normal" row since
		// V.1.1-V.1.3 made the green-arc emission live.
		comingSoon?: boolean;
	}

	// Single source of truth for the legend rows. Mirrors
	// topology's LEGEND_ROWS shape (tier + label) — we
	// substitute category + label since the map's color
	// taxonomy is per-category, not per-traffic-tier.
	const LEGEND_ROWS: readonly LegendRow[] = [
		{ category: 'normal', labelKey: 'map.legendNormal' },
		{ category: 'throttle', labelKey: 'map.legendThrottle' },
		{ category: 'waf', labelKey: 'map.legendWaf' },
		{ category: 'crowdsec', labelKey: 'map.legendCrowdsec' },
		{ category: 'auth', labelKey: 'map.legendAuth' },
		// Step W.5 — 6th category. Gray slate to signal
		// "policy enforcement, not threat" per spec §D6.
		// Status code is operator-configurable (403 default,
		// 451 / 444 supported) — the label lists the
		// canonical set rather than picking one.
		{ category: 'country_block', labelKey: 'map.legendCountryBlock' }
	];

	// Default expanded so a first-time visitor sees the
	// key. The toggle persists in-session only (V.7's
	// LAN counter has the same scope) — refresh restores
	// the default.
	let expanded = $state(true);

	function toggle(): void {
		expanded = !expanded;
	}
</script>

<aside
	class="map-legend panel"
	class:map-legend--collapsed={!expanded}
	data-testid="map-legend"
	aria-label={tl('map.legendAria')}
>
	<header class="map-legend__header">
		<button
			type="button"
			class="map-legend__toggle"
			onclick={toggle}
			aria-expanded={expanded}
			aria-controls="map-legend-body"
			data-testid="map-legend-toggle"
		>
			<h3 class="map-legend__title">{tl('map.legendTitle')}</h3>
			<span class="map-legend__chevron" aria-hidden="true">{expanded ? '▾' : '▴'}</span>
		</button>
	</header>
	{#if expanded}
		<ul id="map-legend-body" class="legend-list" data-testid="map-legend-list">
			{#each LEGEND_ROWS as row (row.category)}
				<li
					data-testid={`map-legend-item-${row.category}`}
					data-category={row.category}
				>
					<svg
						class="dots"
						viewBox="0 0 56 8"
						width="56"
						height="8"
						aria-hidden="true"
						style="color: {CATEGORY_COLORS[row.category]};"
					>
						<circle cx="4" cy="4" r="2" fill="currentColor" />
						<circle cx="18" cy="4" r="2" fill="currentColor" />
						<circle cx="32" cy="4" r="2" fill="currentColor" />
						<circle cx="46" cy="4" r="2" fill="currentColor" />
					</svg>
					<span class="legend-label">
						{tl(row.labelKey)}{#if row.comingSoon}
							<em class="legend-coming-soon"> · {tl('map.legendComingSoon')}</em>
						{/if}
					</span>
				</li>
			{/each}
		</ul>
		<p class="legend-note">{tl('map.legendNote')}</p>
	{/if}
</aside>

<style>
	/* Mirror topology's .panel surface — same bg, border,
	   radius, padding — so the two pages feel like one
	   product. */
	.panel {
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		padding: 14px 14px 12px 14px;
	}
	.map-legend {
		position: absolute;
		bottom: 12px;
		right: 12px;
		min-width: 240px;
		max-width: 300px;
		z-index: 1;
		box-shadow: var(--shadow-sm);
	}
	.map-legend--collapsed {
		min-width: 0;
		padding: 6px 10px;
	}

	.map-legend__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.map-legend__toggle {
		display: flex;
		flex: 1 1 auto;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 0;
		margin: 0;
		background: transparent;
		border: 0;
		color: inherit;
		cursor: pointer;
		font-family: inherit;
		text-align: left;
	}
	.map-legend__toggle:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
		border-radius: 4px;
	}
	.map-legend__title {
		font-size: 13px;
		font-weight: 600;
		margin: 0;
		color: var(--text-primary);
	}
	.map-legend--collapsed .map-legend__title {
		font-size: 11px;
		font-weight: 500;
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-family: var(--font-mono);
	}
	.map-legend__chevron {
		font-size: 10px;
		color: var(--text-muted);
	}

	/* Topology-mirrored legend rows. */
	.legend-list {
		list-style: none;
		margin: 12px 0 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.legend-list li {
		display: flex;
		align-items: center;
		gap: 10px;
		font-size: 11px;
		color: var(--text-muted);
	}
	.dots {
		flex: 0 0 auto;
		/* Topology applies drop-shadow glow on tiers; on the
		   map we keep the dots flat — the geographic context
		   already carries the visual weight, and a glow would
		   compete with the arcs' own opacity halo. */
	}
	.legend-label {
		line-height: 1.4;
	}
	.legend-coming-soon {
		font-style: italic;
		color: var(--text-muted);
	}

	.legend-note {
		font-size: 11px;
		line-height: 1.55;
		color: var(--text-muted);
		margin: 12px 0 0 0;
		padding-top: 10px;
		border-top: 1px solid var(--border-subtle);
	}
</style>
