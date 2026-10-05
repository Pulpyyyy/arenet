<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologySidebar — right-side companion to the topology canvas.

  Three stacked panels matching the mock:
   1. Légende des flux  — visual key tying each FlowTier to its
      particle styling (count/glow/color). Reads the same tier
      thresholds as the canvas so they never drift apart.
   2. Top flux           — live list of routes sorted by req/s desc,
      with a per-row tier-colored progress bar relative to the
      busiest route. Surfaces warn/bad badges (p99 spike, 5xx %).
   3. Actions rapides   — quick operator actions. Buttons are
      cosmetic placeholders for Phase 1; wiring lands in Phase 2.
-->
<script lang="ts">
        import type { TopologyRoute, FlowTier } from '../_types';
        import { resolveFlowTier } from '../_types';
        import { t } from '$lib/i18n';
        import { language } from '$lib/stores/language.svelte';

        let { routes }: { routes: TopologyRoute[] } = $props();

        // Sort by req/s desc so the busiest route is on top.
        let sortedRoutes = $derived([...routes].sort((a, b) => b.reqPerSec - a.reqPerSec));

        // Tier for each route's aggregate flow — reuses the canvas resolver.
        function routeTier(r: TopologyRoute): FlowTier {
                return resolveFlowTier({
                        kind: 'flow',
                        reqPerSec: r.reqPerSec,
                        p99LatencyMs: r.p99LatencyMs,
                        errorRate5xx: r.errorRate5xx,
                });
        }

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)}k r/s`;
                return `${Math.round(rps)} r/s`;
        }

        // "→ {host:port}, {host:port}, +N autres" subtitle. The
        // sub-line communicates WHERE the route points (its upstream
        // pool); echoing the FQDN here read as noise (Critique 15b,
        // 2026-06-03). The host:port form mirrors UpstreamNode's
        // scheme-stripped display so the two surfaces speak the same
        // language.
        const TOPFLUX_MAX_INLINE_UPSTREAMS = 3;
        const SCHEME_RX = /^(?:https?|h2c?):\/\//i;
        function stripScheme(url: string): string {
                return url.replace(SCHEME_RX, '');
        }
        function upstreamsLabel(r: TopologyRoute): string {
                if (r.upstreams.length === 0) return '(aucun upstream)';
                const stripped = r.upstreams.map((u) => stripScheme(u.url));
                if (stripped.length <= TOPFLUX_MAX_INLINE_UPSTREAMS) {
                        return stripped.join(', ');
                }
                const head = stripped.slice(0, TOPFLUX_MAX_INLINE_UPSTREAMS).join(', ');
                const extra = stripped.length - TOPFLUX_MAX_INLINE_UPSTREAMS;
                return `${head}, +${extra} autres`;
        }

        // Optional inline badge surfaced next to the upstream label
        // when something operationally interesting needs flagging.
        function topfluxBadge(r: TopologyRoute): string | null {
                // Both values arrive as raw floats from the windowed
                // aggregator, and both were interpolated unrounded: the
                // operator's badge read "5xx 0.8333333333333334%".
                // AliasNode has used toFixed(2) for this since it
                // shipped; this is the one surface that forgot.
                //
                // Two decimals, not zero: a homelab route at 0.83% 5xx
                // would otherwise round to "1%" or "0%", and which of
                // those it picked would carry more meaning than the
                // measurement does. Latency is whole milliseconds —
                // a fraction of one is noise in a badge.
                if (r.errorRate5xx > 0) return `5xx ${r.errorRate5xx.toFixed(2)}%`;
                if (r.p99LatencyMs > 300) return `p99 ${Math.round(r.p99LatencyMs)} ms`;
                return null;
        }

        // Progress bar widths are relative to the busiest route in
        // the list — preserves the visual ranking when absolute rps
        // values cover a wide range.
        let maxRps = $derived(Math.max(1, ...sortedRoutes.map((r) => r.reqPerSec)));

        // Each tier's "dots" preview in the legend. Inline 4-circle
        // SVG so the per-tier color + glow filter can apply via CSS.
        // The 'dead' tier (added 2026-06-03) gets a legend row so the
        // operator can distinguish "no traffic at all" (no particles,
        // dim line) from "quasi-inactif" (pale particles, < 20 req/s).
        //
        // v2.9.18 i18n Phase 3 batch 3 — labels resolved via t() and
        // wrapped in a $derived so the legend re-renders on language
        // switch. Reading language.current inside the derived callback
        // registers the Svelte 5 reactive dependency.
        const LEGEND_ROWS: { tier: FlowTier; label: string }[] = $derived(
                language.current
                        ? [
                                  { tier: 'high', label: t('topology.sidebar.legendHigh') },
                                  { tier: 'mid', label: t('topology.sidebar.legendMid') },
                                  { tier: 'low', label: t('topology.sidebar.legendLow') },
                                  { tier: 'idle', label: t('topology.sidebar.legendIdle') },
                                  { tier: 'dead', label: t('topology.sidebar.legendDead') },
                                  { tier: 'warn', label: t('topology.sidebar.legendWarn') },
                                  { tier: 'bad', label: t('topology.sidebar.legendBad') }
                          ]
                        : []
        );
</script>

<aside class="topo-sidebar" aria-label={language.current && t('topology.sidebar.ariaLabel')}>
        <!-- =========================================================
             Panel 1 — Flow legend
        ========================================================= -->
        <section class="panel">
                <h3>{language.current && t('topology.sidebar.panelLegendTitle')}</h3>
                <ul class="legend-list">
                        {#each LEGEND_ROWS as row (row.tier)}
                                <li>
                                        <svg
                                                class="dots tier-{row.tier}"
                                                viewBox="0 0 56 8"
                                                width="56"
                                                height="8"
                                                aria-hidden="true"
                                        >
                                                <circle cx="4" cy="4" r="2" fill="currentColor" />
                                                <circle cx="18" cy="4" r="2" fill="currentColor" />
                                                <circle cx="32" cy="4" r="2" fill="currentColor" />
                                                <circle cx="46" cy="4" r="2" fill="currentColor" />
                                        </svg>
                                        <span class="legend-label">{row.label}</span>
                                </li>
                        {/each}
                </ul>
                <p class="legend-note">
                        {language.current && t('topology.sidebar.legendNote')}
                </p>
        </section>

        <!-- =========================================================
             Panel 2 — Top flux (live list)

             Header simplified per Critique 15a (2026-06-03): the
             canvas toolbar already shows a live/reconnecting dot,
             so the "live" pill here was redundant noise.
        ========================================================= -->
        <section class="panel">
                <h3>{language.current && t('topology.sidebar.panelTopFluxTitle')}</h3>
                <ul class="topflux-list">
                        {#each sortedRoutes as route (route.id)}
                                {@const tier = routeTier(route)}
                                {@const badge = topfluxBadge(route)}
                                <li class="topflux-row" data-tier={tier}>
                                        <div class="topflux-line-1">
                                                <span class="host">{route.host}</span>
                                                <span class="rps">{formatRate(route.reqPerSec)}</span>
                                        </div>
                                        <div class="topflux-line-2">
                                                <span class="up-label">→ {upstreamsLabel(route)}</span>
                                                {#if badge}
                                                        <span class="badge">{badge}</span>
                                                {/if}
                                        </div>
                                        <div class="topflux-bar" aria-hidden="true">
                                                <div
                                                        class="topflux-bar-fill"
                                                        style:width="{(route.reqPerSec / maxRps) * 100}%"
                                                ></div>
                                        </div>
                                </li>
                        {/each}
                </ul>
        </section>

        <!-- =========================================================
             Panel 3 — Actions rapides
        ========================================================= -->
        <section class="panel">
                <h3>{language.current && t('topology.sidebar.panelActionsTitle')}</h3>
                <ul class="actions-list">
                        <li><button type="button" class="action-btn">{language.current && t('topology.sidebar.actionDrainUpstream')}</button></li>
                        <li><button type="button" class="action-btn">{language.current && t('topology.sidebar.actionReloadCaddy')}</button></li>
                        <li><button type="button" class="action-btn">{language.current && t('topology.sidebar.actionSnapshotJSON')}</button></li>
                </ul>
        </section>
</aside>

<style>
        .topo-sidebar {
                flex: 0 0 280px;
                display: flex;
                flex-direction: column;
                gap: 14px;
                overflow-y: auto;
                min-height: 0;
                padding-right: 2px;
        }

        .panel {
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                padding: 14px 14px 12px 14px;
        }

        .panel h3 {
                font-size: 13px;
                font-weight: 600;
                margin: 0 0 12px 0;
                color: var(--fg, oklch(96% 0.005 250));
        }

        /* ---------- Legend ---------- */
        .legend-list {
                list-style: none;
                margin: 0;
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
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .dots {
                flex: 0 0 auto;
        }

        .tier-idle {
                color: oklch(60% 0.01 250);
                opacity: 0.55;
        }

        .tier-low {
                color: var(--accent, oklch(68% 0.21 255));
                opacity: 0.6;
        }

        .tier-mid {
                color: var(--accent, oklch(68% 0.21 255));
                opacity: 0.85;
                filter: drop-shadow(0 0 1.5px currentColor);
        }

        .tier-high {
                color: var(--accent, oklch(68% 0.21 255));
                filter: drop-shadow(0 0 2px currentColor);
        }

        .tier-warn {
                color: var(--status-warn);
                filter: drop-shadow(0 0 1.5px currentColor);
        }

        .tier-bad {
                color: var(--status-down);
                filter: drop-shadow(0 0 1.5px currentColor);
        }

        .legend-label {
                line-height: 1.4;
        }

        .legend-note {
                font-size: 11px;
                line-height: 1.55;
                color: var(--fg-dim, oklch(54% 0.011 250));
                margin: 12px 0 0 0;
                padding-top: 10px;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
        }

        /* ---------- Top flux ---------- */
        .topflux-list {
                list-style: none;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
        }

        .topflux-row {
                padding: 9px 0;
                border-bottom: 1px solid var(--border, oklch(28% 0.009 250));
        }

        .topflux-row:last-child {
                border-bottom: none;
                padding-bottom: 0;
        }

        .topflux-row:first-child {
                padding-top: 0;
        }

        .topflux-line-1 {
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                margin-bottom: 3px;
        }

        .topflux-line-1 .host {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11.5px;
                font-weight: 500;
                color: var(--fg, oklch(96% 0.005 250));
        }

        .topflux-line-1 .rps {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                white-space: nowrap;
        }

        .topflux-line-2 {
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                gap: 8px;
                margin-bottom: 6px;
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .topflux-line-2 .up-label {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .topflux-line-2 .badge {
                flex: 0 0 auto;
                color: var(--status-warn);
        }

        .topflux-row[data-tier='bad'] .topflux-line-2 .badge {
                color: var(--status-down);
        }

        .topflux-bar {
                width: 100%;
                height: 3px;
                background: var(--border, oklch(28% 0.009 250));
                border-radius: 2px;
                overflow: hidden;
        }

        .topflux-bar-fill {
                height: 100%;
                background: var(--accent, oklch(68% 0.21 255));
                border-radius: 2px;
                transition: width 0.4s ease;
        }

        .topflux-row[data-tier='warn'] .topflux-bar-fill {
                background: var(--status-warn);
        }

        .topflux-row[data-tier='bad'] .topflux-bar-fill {
                background: var(--status-down);
        }

        /* ---------- Actions ---------- */
        .actions-list {
                list-style: none;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
                gap: 6px;
        }

        .action-btn {
                width: 100%;
                padding: 8px 10px;
                background: var(--surface-2, oklch(22% 0.007 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 6px;
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                text-align: left;
                cursor: pointer;
                font-family: inherit;
                transition: background 0.15s ease, border-color 0.15s ease;
        }

        .action-btn:hover {
                background: var(--surface-hi, oklch(26% 0.008 250));
                border-color: var(--border-hi, oklch(34% 0.011 250));
        }
</style>
