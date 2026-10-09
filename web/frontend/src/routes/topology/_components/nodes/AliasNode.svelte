<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AliasNode — Sub-node of the col-0 stack representing one alias of
  a route. Sujet 1 Phase 3.a (Topology Plan B frontend).

  Phase 3.d (2026-06-17) polish:
    - The "ALIAS" badge in front of the hostname was removed.
      The RouteGroupNode container (Phase 3.c) already carries
      the visual binding "this card belongs to a route"; the
      redundant badge crowded the host label on narrow cards.
    - Width bumped 140 → 170 px (85% of FQDN 200 px). Still
      clearly smaller than the parent so the visual hierarchy
      reads "primary host first, aliases nested" — but readable
      enough that long subdomains don't truncate at the third
      character.

  Visual hierarchy: ~85% of the FQDNNode footprint (width 170 vs
  200), accent-muted palette (--fg-muted instead of --fg) so the
  primary FQDN remains the focal "row label" while aliases read as
  ancillary entries underneath. The size delta is intentional — at
  realistic homelab scale (e.g. the operator's traefik route with
  21 aliases) the col-0 stack would visually overwhelm the rest
  of the canvas if every alias matched the FQDN size.

  Source handle only (Position.Right). The alias has no inbound
  edge from inside the graph — like the primary FQDN, traffic
  enters from "outside" so a target handle would be cosmetic
  clutter (mirror of FQDNNode C20 decision).

  Idle state: when data.isIdle is true (computed at layout time
  from reqPerSec === 0), the entire card renders muted with an
  inline "idle" tag. The data path stays live (the next tick may
  flip the flag), so this is a pure visual gate, not a model
  change.

  Hover surface: p99 + 5xx rate land in the title attribute on the
  meta row, mirror of FQDNNode's hosts tooltip pattern. Operator
  who needs the precise numbers can hover; the compact card stays
  uncluttered.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { AliasNodeData } from '../../_types';
        import { t } from '$lib/i18n';

        let { data }: NodeProps & { data: AliasNodeData } = $props();

        // Pretty-print req/s with one decimal at low rates (< 10),
        // integer otherwise. Mirrors what the operator already sees
        // on the route-level FQDN meta line via _layout.ts's
        // formatFQDNMeta. Idle aliases (reqPerSec === 0) render as
        // a bare "—" so the eye locates active aliases instantly
        // against a long col-0 stack of zeros.
        let rateLabel = $derived.by(() => {
                if (data.reqPerSec === 0) return '—';
                if (data.reqPerSec < 10) return `${data.reqPerSec.toFixed(2)} r/s`;
                return `${Math.round(data.reqPerSec)} r/s`;
        });

        // Hover tooltip — the precise numbers the compact card hides.
        // p99 ms is the per-tick p95 substitute (Stage A) but we
        // surface it under the operator-facing "p99" label for wire-
        // shape continuity with the FQDN node and the legend.
        let metaTooltip = $derived.by(() => {
                const parts = [
                        `${data.reqPerSec.toFixed(3)} req/s windowed`,
                        `p99 ${data.p99LatencyMs} ms`,
                        `${data.errorRate5xx.toFixed(2)}% 5xx`,
                ];
                if (data.isIdle) parts.push(t('topology.nodes.aliasIdle'));
                return parts.join(' · ');
        });
</script>

<div class="alias-node" class:idle={data.isIdle}>
        <div class="host-row">
                <span class="host" title={data.host}>{data.host}</span>
        </div>
        <div class="meta" title={metaTooltip}>{rateLabel}</div>

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .alias-node {
                width: 170px;
                /* HOTFIX (2026-06-17, post-Phase-3.e ship) — explicit
                   height pins the rendered card at ALIAS_HEIGHT
                   exactly (44 px). Content-driven sizing drifted a
                   couple of px due to font line-height / border /
                   padding combinations, which made the
                   _layout.ts's assumed ALIAS_HEIGHT smaller than
                   reality and pushed the last alias past the
                   RouteGroupNode container's bottom padding. */
                height: 44px;
                padding: 6px 10px;
                box-sizing: border-box;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 6px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 11px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        /* Idle state: muted surface + dimmed text. The border keeps
           a hint of the accent so the layout grid is still readable
           even in a long stack of idle aliases. */
        .alias-node.idle {
                background: var(--surface-idle, oklch(15% 0.004 250));
                color: var(--fg-dim, oklch(54% 0.011 250));
                border-color: var(--border-dim, oklch(22% 0.007 250));
        }

        .host-row {
                display: flex;
                align-items: center;
                gap: 5px;
                margin-bottom: 2px;
        }

        .host {
                flex: 1 1 auto;
                font-size: 11.5px;
                font-weight: 500;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .alias-node.idle .meta {
                color: var(--fg-dim, oklch(54% 0.011 250));
        }

        :global(.svelte-flow__node-alias) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
