<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  UpstreamNode — one row inside a BackendCluster sub-flow group.

  Before the 2026-06-03 restructure the cluster card rendered N
  rows internally. Each row is now its own Svelte Flow node, which
  lets us attach a real edge from `caddy-hub` to each upstream
  (N edges per cluster instead of 1). The fairness bar, p99 and
  req/s rendering moved here from BackendClusterNode.

  C6 polish on top of C6a (2026-06-03):
   - C7 strip scheme on display (http://, https://, h2[c]://). The
     full URL stays accessible via the `title` tooltip. If the
     original scheme was TLS-bearing, a small lock glyph next to
     the URL preserves the visual signal.
   - C8 status indicator: single left accent bar, no inner dot.
     The accent is the only status signal — easier to scan a
     stack of upstreams vertically.
   - C9 health-coherence: when `healthCheckConfigured` is true,
     render a small Activity (ECG-line) glyph next to the URL.
     Conveys "monitored" without lying about probe outcome
     (status stays unknown until Stage B real-probe ingestion).
     Lucide Activity, not a shield — shield reads as security
     (WAF/firewall), Activity is the universal monitoring
     metaphor (Datadog/Grafana/etc) per Critique 12 (2026-06-03).
   - C13 status accent stripe is conditional on
     `healthCheckConfigured`. Routes without a probe have no
     status to report — a permanent gray stripe carried no
     signal and prompted "what is this stripe for?" feedback.
     With Critique 13, the stripe and the Activity glyph appear
     together as the two "monitored" signals (configured + state).
     In Stage B, the stripe takes color from the real probe while
     the glyph stays neutral — two independent signals (configured
     vs. status).
   - C14b load bar (2026-06-04): bar width was a per-cluster
     fairnessRatio (the upstream's weight share), meaningless on
     single-upstream clusters and not comparable across clusters.
     It's now a global-relative loadRatio pre-computed by
     _layout.ts as reqPerSec / globalMax across all upstreams in
     the canvas — single comparison scale, busy upstreams stand
     out regardless of cluster, idle upstreams all read empty.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { UpstreamNodeData } from '../../_types';
        import { t } from '$lib/i18n';
        import { language } from '$lib/stores/language.svelte';

        let { data }: NodeProps & { data: UpstreamNodeData } = $props();
</script>

<div class="upstream-node" data-status={data.status} data-monitored={data.healthCheckConfigured}>
        <!-- Inbound handle (caddy-hub -> upstream). No source handle:
             upstreams never originate flow in our topology. -->
        <Handle type="target" position={Position.Left} />

        <div class="up-line-1">
                <span class="up-url" title={data.url}>{data.displayUrl}</span>
                <span class="up-icons" aria-hidden="true">
                        {#if data.wasHttps}
                                <!-- TLS lock — minimal padlock glyph. Inherits
                                     muted color from .up-icons. -->
                                <svg class="ico ico-lock" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.3" aria-label="TLS">
                                        <rect x="2.5" y="5.5" width="7" height="5" rx="1" />
                                        <path d="M4 5.5 V4 a2 2 0 0 1 4 0 V5.5" />
                                </svg>
                        {/if}
                        {#if data.healthCheckConfigured}
                                <!-- Lucide Activity (ECG line). Carries the
                                     "this upstream is being watched" signal
                                     without claiming anything about the
                                     probe outcome. Universal dashboard
                                     metaphor (Datadog/Grafana) — distinct
                                     from the lock so the two signals don't
                                     get confused. The path is the Lucide
                                     polyline scaled into the 12-unit viewBox
                                     the lock uses, so both glyphs render at
                                     the same visual weight. -->
                                <svg
                                        class="ico ico-monitored"
                                        viewBox="0 0 24 24"
                                        fill="none"
                                        stroke="currentColor"
                                        stroke-width="2"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                        aria-label={language.current && t('topology.nodes.healthCheckWatched')}
                                >
                                        <title>{language.current && t('topology.nodes.healthCheckWatched')}</title>
                                        <path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.5.5 0 0 1-.96 0L9.24 3.18a.5.5 0 0 0-.96 0l-2.35 8.36A2 2 0 0 1 4 13H2" />
                                </svg>
                        {/if}
                </span>
                <span class="up-p99">p99 {Math.round(data.p99LatencyMs)} ms</span>
        </div>
        <div class="up-line-2">
                <div
                        class="load-bar"
                        aria-label={language.current &&
                                t('topology.nodes.relativeLoad', { pct: Math.round(data.loadRatio * 100) })}
                >
                        <div
                                class="load-fill"
                                style:width="{Math.round(data.loadRatio * 100)}%"
                        ></div>
                </div>
                <span class="up-rps">
                        {#if data.reqPerSec >= 1000}
                                {(data.reqPerSec / 1000).toFixed(1)}k r/s
                        {:else}
                                {Math.round(data.reqPerSec)} r/s
                        {/if}
                </span>
        </div>
</div>

<style>
        .upstream-node {
                width: 100%;
                height: 100%;
                box-sizing: border-box;
                padding: 8px 10px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 6px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 11.5px;
                display: flex;
                flex-direction: column;
                justify-content: center;
                gap: 5px;
        }

        /* Left accent — status signal for MONITORED upstreams only
           (C8 + C13). The accent appears in lockstep with the
           Activity glyph: both signal "this upstream is being
           watched". Unmonitored upstreams keep the default 1px
           border on all sides — no signal, neutral visual. In v1.1.0
           every status is 'unknown' so the monitored variant always
           renders gray; Stage B real-probe ingestion will paint
           healthy/unhealthy/draining colors via these same rules. */
        .upstream-node[data-monitored='true'][data-status='healthy'] {
                border-left: 3px solid var(--status-up);
        }
        .upstream-node[data-monitored='true'][data-status='unhealthy'] {
                border-left: 3px solid var(--status-down);
        }
        .upstream-node[data-monitored='true'][data-status='draining'] {
                border-left: 3px solid var(--status-warn);
        }
        .upstream-node[data-monitored='true'][data-status='unknown'] {
                border-left: 3px solid var(--fg-dim, oklch(54% 0.011 250));
        }

        .up-line-1 {
                display: flex;
                align-items: center;
                gap: 6px;
                font-family: var(--font-mono, ui-monospace, monospace);
        }

        .up-line-2 {
                display: flex;
                align-items: center;
                gap: 8px;
        }

        .up-url {
                flex: 1 1 auto;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .up-icons {
                flex: 0 0 auto;
                display: inline-flex;
                align-items: center;
                gap: 3px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .ico {
                width: 11px;
                height: 11px;
        }

        .up-p99 {
                flex: 0 0 auto;
                color: var(--fg-muted, oklch(68% 0.012 250));
                font-size: 10.5px;
        }

        .up-rps {
                flex: 0 0 auto;
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                min-width: 56px;
                text-align: right;
        }

        /* ---------- Load bar (C14b, 2026-06-04) ----------
           Width = reqPerSec / globalMax pre-computed in _layout.ts.
           Was the fairness/weight-share bar before C14b. */
        .load-bar {
                flex: 1 1 auto;
                height: 4px;
                background: var(--border, oklch(28% 0.009 250));
                border-radius: 2px;
                overflow: hidden;
        }

        .load-fill {
                height: 100%;
                background: var(--accent, oklch(68% 0.21 255));
                border-radius: 2px;
                transition: width 0.6s ease;
        }

        /* Fill color follows the same monitored-only rule as the
           accent stripe (C13). When unmonitored, the bar stays the
           default accent blue — there's no probe data to color it
           by, only load to show. */
        .upstream-node[data-monitored='true'][data-status='draining'] .load-fill {
                background: var(--status-warn);
        }
        .upstream-node[data-monitored='true'][data-status='unhealthy'] .load-fill {
                background: var(--status-down);
        }
        .upstream-node[data-monitored='true'][data-status='unknown'] .load-fill {
                background: var(--fg-dim, oklch(54% 0.011 250));
        }

        /* Svelte Flow injects a wrapper around our component. We don't
           want its default border/padding here — the wrapper is just
           a positioning container, the visible card is .upstream-node.
           This mirrors the override pattern used by BackendClusterNode. */
        :global(.svelte-flow__node-upstream) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
