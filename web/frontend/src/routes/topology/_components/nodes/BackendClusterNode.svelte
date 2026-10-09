<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  BackendClusterNode — sub-flow group container for a route's
  upstream pool.

  Restructured 2026-06-03 (#R-TOPO-v2-phase2 C6). Previously this
  node rendered N upstream rows internally and the cluster received
  a single inbound edge from caddy-hub. Now this is purely a
  decorative group: the upstream rows are real Svelte Flow children
  (UpstreamNode), each with its own edge from the hub. The cluster
  payload here only carries header metadata + an optional warning.

  Three operator-feedback driven changes:
   - C1: removed the "Pas de cluster — ≥ 2 réplicas" warning. Single-
         replica is a legitimate homelab pattern; the header already
         shows "1 sain / 1" unambiguously.
   - C2: LB policy chip hides when totalCount === 1 (round_robin
         over 1 target is semantically meaningless).
   - C3: the group container holds the children (parentId+extent).
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { BackendClusterNodeData, LBPolicy } from '../../_types';

        let { data }: NodeProps & { data: BackendClusterNodeData } = $props();

        let clusterState = $derived(deriveClusterState(data));
        let showLBPolicy = $derived(data.totalCount > 1);
        // Header line. Three-state aware (Regression A, 2026-06-03):
        //   - no upstreams              "0 upstream"
        //   - all unknown (v1.1.0 norm) "{N} upstream(s)" (no health
        //                               qualifier — we don't know)
        //   - else                      "{healthy} sains / {total}"
        // The shield glyph in UpstreamNode carries the "monitored"
        // signal; the cluster header doesn't need to repeat it.
        let headerCountLine = $derived(formatHeaderCountLine(data));

        function deriveClusterState(d: BackendClusterNodeData): 'healthy' | 'warn' | 'bad' | 'neutral' {
                // v2.61 — a redirecting route legitimately has no upstream, so
                // zero must not paint it red. It is neutral: configured, not
                // monitored, and not broken.
                if (d.redirectTarget) return 'neutral';
                if (d.totalCount === 0) return 'bad';
                // Strictly-unhealthy upstreams drive the bad/warn states.
                // 'unknown' is now neutral — no green lie, no red panic.
                if (d.unhealthyCount === d.totalCount) return 'bad';
                if (d.unhealthyCount > 0) return 'warn';
                if (d.warning) return 'warn';
                // All upstreams healthy → green. All upstreams unknown
                // (the v1.1.0 reality until Stage B probes land) →
                // neutral gray; the operator can still tell the cluster
                // is configured but shouldn't read it as "validated OK".
                if (d.healthyCount === d.totalCount) return 'healthy';
                return 'neutral';
        }

        // Routes arriving at a redirect destination. A grouped node must
        // say how many and which: without this it would stand for an
        // unknown number of routes and read exactly like a single one.
        let redirectSources = $derived(data.redirectSourceHosts ?? []);

        // Whether an edge terminates on THIS node rather than on one of
        // its upstream children.
        //
        // A cluster with children is never an edge endpoint: _layout.ts
        // draws one edge per upstream, each landing on the child's own
        // handle. With zero children — a redirect, or a route whose pool
        // is empty — the edge lands on the parent, and Svelte Flow needs
        // a handle to anchor it or it silently draws nothing.
        //
        // That is what went wrong: the comment below claimed the
        // zero-upstream case worked "without relying on a custom handle",
        // and it did not. Every redirect destination since v2.61 has sat
        // on the canvas with no visible connection to the host pointing at
        // it, which the operator reported three times before I looked here
        // — once as "rien vers les noeuds a droite" while the hub was
        // still in place, which should have told me the edge, not the hub,
        // was the problem.
        let isEdgeTarget = $derived(data.totalCount === 0);

        function formatHeaderCountLine(d: BackendClusterNodeData): string {
                if (d.redirectTarget) {
                        const n = d.redirectSourceHosts?.length ?? 0;
                        // 1 is the common case and needs no count — the single
                        // source host is already named below.
                        return n > 1 ? `${n} redirections` : 'redirection';
                }
                if (d.totalCount === 0) return '0 upstream';
                // v1.1.0 norm: every upstream reports unknown. Drop the
                // "sains" qualifier entirely — claiming X-of-Y sains
                // when X is always 0 was the second half of Regression A
                // ("0 SAINS / 1" on every single-upstream route).
                const allUnknown = d.healthyCount === 0 && d.unhealthyCount === 0;
                if (allUnknown) {
                        return d.totalCount === 1 ? '1 upstream' : `${d.totalCount} upstreams`;
                }
                return `${d.healthyCount} sains / ${d.totalCount}`;
        }

        function formatLBPolicy(p: LBPolicy): string {
                switch (p) {
                        case 'round_robin':
                                return 'ROUND ROBIN';
                        case 'weighted_round_robin':
                                return 'WEIGHTED RR';
                        case 'least_conn':
                                return 'LEAST CONN';
                        case 'ip_hash':
                                return 'IP HASH (sticky)';
                        case 'random':
                                return 'RANDOM';
                        case 'first':
                                return 'FIRST';
                }
        }
</script>

<div class="cluster-node" data-state={clusterState}>
        <!-- A handle ONLY when an edge actually terminates here, i.e.
             when the cluster has no upstream children.
             Critique 6 (2026-06-03) removed the handle because an
             always-present one implied "connect here" on every cluster
             while no edge ever targeted the parent. That reasoning held
             for a cluster WITH children and was wrong for one without:
             Svelte Flow anchors an edge on a handle, and with none it
             draws nothing at all.
             Rendered invisible, so the anchor exists without bringing
             back the dot that Critique 6 objected to. -->
        {#if isEdgeTarget}
                <Handle
                        type="target"
                        position={Position.Left}
                        class="anchor-only"
                        isConnectable={false}
                />
        {/if}
        <header class="cluster-header">
                <div class="cluster-title">
                        <span class="cluster-label">{data.clusterLabel}</span>
                        {#if data.runtime}
                                <span class="cluster-runtime">({data.runtime})</span>
                        {/if}
                </div>
                <div class="cluster-meta">
                        {#if showLBPolicy}
                                <span class="lb-policy">{formatLBPolicy(data.lbPolicy)}</span>
                                <span class="sep">·</span>
                        {/if}
                        <span class="health-ratio">{headerCountLine}</span>
                </div>
        </header>

        {#if data.redirectTarget}
                <!-- v2.61 — the destination, where an empty pool used to
                     sit under a red warning. The graph's job is to say
                     where traffic goes; for a redirect the answer is
                     simply not a backend. -->
                <div class="cluster-redirect" data-testid="cluster-redirect-target">
                        <span class="redirect-arrow" aria-hidden="true">→</span>
                        <span class="redirect-target">{data.redirectTarget}</span>
                </div>
                <!-- Who arrives here. One node per destination means the
                     node can no longer be identified by its source, so it
                     names them instead. -->
                {#if redirectSources.length > 0}
                        <ul class="redirect-sources" data-testid="cluster-redirect-sources">
                                {#each redirectSources as host (host)}
                                        <li class="redirect-source">{host}</li>
                                {/each}
                        </ul>
                {/if}
        {/if}

        {#if data.warning}
                <footer class="cluster-warning">
                        <svg class="warn-ico" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
                                <path d="M8 2 L14 13 L2 13 Z" />
                                <path d="M8 6 v3" stroke-linecap="round" />
                                <circle cx="8" cy="11" r="0.6" fill="currentColor" stroke="none" />
                        </svg>
                        <span>{data.warning}</span>
                </footer>
        {/if}
</div>

<style>
        /* The anchor handle exists for edge geometry, not for the eye. */
        :global(.anchor-only) {
                opacity: 0;
                pointer-events: none;
                width: 1px;
                min-width: 1px;
                height: 1px;
                min-height: 1px;
                border: 0;
        }

        .redirect-sources {
                list-style: none;
                margin: 2px 0 0;
                padding: 0 10px;
                display: flex;
                flex-direction: column;
                gap: 1px;
        }

        .redirect-source {
                /* Must match REDIRECT_SOURCE_LINE_HEIGHT in _layout.ts,
                   which reserves the group node's extra height. */
                line-height: 17px;
                font-size: 10px;
                color: var(--text-muted);
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
        }

        .cluster-node {
                width: 100%;
                height: 100%;
                box-sizing: border-box;
                background: var(--surface-2, oklch(22% 0.007 250));
                /* Dashed wrapper border (C14a, 2026-06-04) — signals
                   "this is a logical group container", not a regular
                   card. The upstream children inside paint with solid
                   borders so they read as concrete cards, and the
                   group reads as the bounding context. The left edge
                   stays solid + state-colored via the .cluster-node[
                   data-state] rules below so the health-accent
                   doesn't get visually fragmented by the dashes. */
                border: 1px dashed var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
                /* Children paint on top of us — explicit relative
                   positioning so the group footer (warning) stays
                   below the upstream cards. */
                position: relative;
        }

        .cluster-node[data-state='healthy'] {
                border-left: 2px solid var(--accent, oklch(68% 0.21 255));
        }
        .cluster-node[data-state='warn'] {
                border-left: 2px solid var(--status-warn);
        }
        .cluster-node[data-state='bad'] {
                border-left: 2px solid var(--status-down);
        }
        /* Three-state aware accent (Regression A): all-unknown clusters
           — the v1.1.0 default — render with a neutral gray accent.
           Distinct from healthy (blue) so the operator doesn't read
           green into an unverified state. */
        .cluster-node[data-state='neutral'] {
                border-left: 2px solid var(--fg-dim, oklch(54% 0.011 250));
        }

        .cluster-header {
                padding: 10px 12px 8px 12px;
                border-bottom: 1px solid var(--border, oklch(28% 0.009 250));
                background: var(--surface-2, oklch(22% 0.007 250));
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
        }

        .cluster-title {
                display: flex;
                align-items: baseline;
                gap: 6px;
                margin-bottom: 4px;
        }

        .cluster-label {
                font-size: 13px;
                font-weight: 600;
                letter-spacing: 0.01em;
        }

        .cluster-runtime {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .cluster-meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                letter-spacing: 0.03em;
                text-transform: uppercase;
        }

        .cluster-meta .sep {
                margin: 0 6px;
                color: var(--fg-dim, oklch(54% 0.011 250));
        }

        .cluster-redirect {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 8px 10px;
                font-family: var(--font-mono);
                font-size: var(--text-xs);
                color: var(--text-secondary);
                overflow: hidden;
        }
        .cluster-redirect .redirect-arrow {
                color: var(--text-muted);
                flex: 0 0 auto;
        }
        .cluster-redirect .redirect-target {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .cluster-warning {
                position: absolute;
                bottom: 0;
                left: 0;
                right: 0;
                display: flex;
                align-items: flex-start;
                gap: 6px;
                padding: 8px 12px;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
                /* Same as the old oklch(22% … / 0.65) literal in dark, but
                   follows the theme: the literal put the amber warning on
                   a muddy grey in light mode. */
                background: color-mix(in oklch, var(--bg-surface) 65%, transparent);
                color: var(--status-warn-fg);
                font-size: 11px;
                line-height: 1.4;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
        }

        .cluster-warning .warn-ico {
                flex: 0 0 auto;
                width: 12px;
                height: 12px;
                margin-top: 1px;
        }

        .cluster-node[data-state='bad'] .cluster-warning {
                color: var(--status-down);
        }

        /* Svelte Flow wrapper override — same pattern as UpstreamNode.
           Without this, the wrapper's default padding/border would
           double up with our .cluster-node visual frame. */
        :global(.svelte-flow__node-backend-cluster) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
