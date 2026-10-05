<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AnimatedFlowEdge — custom Svelte Flow edge that paints a bezier
  path between two nodes and overlays animated SVG particles that
  follow the path via <mpath>. The particle count, size, glow, and
  the stroke color/style all derive from the FlowTier computed
  from this edge's live FlowEdgeData (req/s, p99, errorRate).

  Tier mapping is centralized in _types.ts -> resolveFlowTier so
  the legend in the right sidebar can use the exact same thresholds
  without drift.

  Implementation notes:
   - <BaseEdge> renders a <path id={id}> we can reference.
   - Each <circle> uses <animateMotion><mpath href="#{id}"/></animateMotion>
     to follow that path.
   - Particles are staggered by setting `begin` to a negative offset
     so they appear pre-distributed along the path at t=0 instead
     of all bunched up at the source.
-->
<script lang="ts">
        import { BaseEdge, getBezierPath, type EdgeProps } from '@xyflow/svelte';
        import { resolveFlowTier, type FlowEdgeData, type FlowTier } from '../../_types';

        type Props = EdgeProps & { data?: FlowEdgeData };

        let {
                id,
                sourceX,
                sourceY,
                targetX,
                targetY,
                sourcePosition,
                targetPosition,
                data,
                markerEnd,
        }: Props = $props();

        // -----------------------------------------------------------------
        // Geometry — Svelte Flow's bezier helper does the heavy lifting.
        // -----------------------------------------------------------------
        let pathTuple = $derived(
                getBezierPath({
                        sourceX,
                        sourceY,
                        targetX,
                        targetY,
                        sourcePosition,
                        targetPosition,
                }),
        );
        let edgePath = $derived(pathTuple[0]);
        // getBezierPath returns [path, labelX, labelY, offsetX, offsetY].
        let labelX = $derived(pathTuple[1]);
        let labelY = $derived(pathTuple[2]);

        // -----------------------------------------------------------------
        // Tier resolution + visual config tables.
        //
        // Smooth-flow restructure (C4, 2026-06-03): particle count and
        // animation duration are now CONSTANT (MAX_PARTICLES / DUR_S),
        // never tier-derived. Tier instead drives the *visual energy*
        // of each particle (opacity, radius, glow) — the same density-
        // based encoding used by Datadog/Cilium/Linkerd. This matters
        // because SMIL <animateMotion> restarts from t=0 whenever any
        // of its DOM attrs (dur, repeatCount, begin) change, producing
        // the 2 s sawtooth the operator flagged. By keeping the SMIL
        // attrs literally constant for the component's lifetime and
        // animating only CSS properties on tier change, the particle
        // flow stays continuous through ticks AND through tier
        // transitions.
        //
        // The 'dead' tier becomes a special case: opacity falls to 0
        // for all 5 particles, so the edge shows only its stroke. The
        // SMIL clock still ticks — just invisibly — which means a
        // route waking up (e.g. traffic resumes) gets immediate
        // continuous motion without a remount-driven restart.
        // -----------------------------------------------------------------
        const MAX_PARTICLES = 5;
        const DUR_S = 5;

        let tier: FlowTier = $derived(data ? resolveFlowTier(data) : 'idle');

        type TierConfig = {
                count: number;     // # visible particles of MAX_PARTICLES
                radius: number;
                opacity: number;
                glowPx: number;
        };

        function tierConfig(t: FlowTier): TierConfig {
                switch (t) {
                        case 'dead':
                                // Exactly-zero traffic — all particles invisible.
                                // The stroke line still renders.
                                return { count: 0, radius: 1.4, opacity: 0, glowPx: 0 };
                        case 'idle':
                                return { count: 2, radius: 1.4, opacity: 0.55, glowPx: 0 };
                        case 'low':
                                return { count: 3, radius: 1.8, opacity: 0.75, glowPx: 0 };
                        case 'mid':
                                return { count: 4, radius: 2.2, opacity: 0.95, glowPx: 3 };
                        case 'high':
                                return { count: 5, radius: 2.6, opacity: 1.0, glowPx: 5 };
                        case 'warn':
                                return { count: 3, radius: 2.0, opacity: 0.95, glowPx: 4 };
                        case 'bad':
                                return { count: 4, radius: 2.2, opacity: 1.0, glowPx: 4 };
                }
        }

        function tierColor(t: FlowTier): string {
                switch (t) {
                        case 'dead':
                                // Slightly dimmer than 'idle' so the eye
                                // reads "no traffic" rather than "almost no
                                // traffic". Same hue family — still part of
                                // the gray-blue palette, just lower-chroma.
                                return 'oklch(50% 0.008 250)';
                        case 'idle':
                                return 'oklch(60% 0.01 250)';
                        case 'low':
                        case 'mid':
                        case 'high':
                                return 'oklch(68% 0.21 255)';
                        case 'warn':
                                return 'oklch(80% 0.14 85)';
                        case 'bad':
                                return 'oklch(66% 0.20 25)';
                }
        }

        function tierStrokeStyle(t: FlowTier): string {
                const color = tierColor(t);
                // 'dead' lines are dimmer than 'idle' (which is itself the
                // dimmest tier with particles). Stroke opacity 0.2 keeps
                // the edge visible — operator still sees the connection
                // exists — but it recedes visually compared to any route
                // carrying real traffic.
                let opacity: number;
                if (t === 'dead') opacity = 0.2;
                else if (t === 'idle') opacity = 0.3;
                else if (t === 'bad') opacity = 0.6;
                else if (t === 'warn') opacity = 0.5;
                else opacity = 0.45;
                const dashed = t === 'bad' ? ' stroke-dasharray: 4 4;' : '';
                return `stroke: ${color}; stroke-opacity: ${opacity}; stroke-width: 1.5;${dashed}`;
        }

        let cfg = $derived(tierConfig(tier));
        let color = $derived(tierColor(tier));

        // Structural branches (path-pool caddy->cluster edges) carry no
        // measured traffic in v1 and would otherwise render at the
        // near-invisible 'dead' tier (stroke-opacity 0.2, gray on black —
        // the v2.24.0 dogfood finding). Render them as a visible dashed
        // line instead. This is a pure addition: any edge without the
        // flag (every real-traffic edge, and a real idle edge with
        // reqPerSec 0) still renders exactly tierStrokeStyle(tier) as
        // before.
        // v2.25.1: a structural edge follows the SAME tier-driven intensity
        // as a solid line (color/opacity from tierStrokeStyle(tier)) and only
        // ADDS a dash — the operator reads "routing branch" from the DASH, not
        // from a brighter line. At 0 traffic it's as discreet as the solid
        // lines beside it; with traffic it brightens with the tier. (v2.25.0
        // forced opacity 0.5 → the dashes over-stood-out vs the solid backend
        // lines at 0 traffic — the dogfood finding this fixes.) The 'bad' tier
        // sets its own dasharray, so append ours only when absent to avoid a
        // double declaration.
        let isStructural = $derived(data?.structural === true);

        // A redirect edge is a STATEMENT, not a path.
        //
        // For a proxied route the edge is the route traffic takes and the
        // particles are the truth. For a redirect Arenet answers the
        // client and the client goes on by itself: nothing traverses this
        // edge. Animating it claimed a flow that does not exist — the
        // thing the operator questioned when they asked whether the dots
        // on redirects were real.
        //
        // So: dashed like a structural branch, NO particles, and labelled
        // with the code. The traffic that IS real sits on the edge before
        // this one, FQDN to hub, where requests genuinely arrive.
        let redirectCode = $derived(
                typeof data?.redirectStatusCode === 'number' ? data.redirectStatusCode : null
        );
        let isRedirect = $derived(redirectCode !== null);

        let baseStroke = $derived(tierStrokeStyle(tier));
        let strokeStyle = $derived(
                (isStructural || isRedirect) && !baseStroke.includes('stroke-dasharray')
                        ? `${baseStroke} stroke-dasharray: 5 4;`
                        : baseStroke
        );

        // Zero on a redirect edge. The circles still render — the SMIL
        // attributes must stay literally constant for the component's
        // lifetime, see the particle block below — but at opacity 0.
        let particleCount = $derived(isRedirect ? 0 : cfg.count);
</script>

<!-- The path itself; id={id} so our <mpath> below can reference it. -->
<BaseEdge {id} path={edgePath} {markerEnd} style={strokeStyle} />

<!-- The status code, on a redirect edge only. An SVG label rather than
     an HTML one so it pans and scales with the canvas like everything
     else on it; the rect behind keeps the digits legible where they
     cross the dashed line. -->
{#if isRedirect}
        <g class="redirect-label" data-testid={`edge-redirect-label-${id}`} pointer-events="none">
                <rect x={labelX - 13} y={labelY - 8} width="26" height="16" rx="3" />
                <text x={labelX} y={labelY} text-anchor="middle" dominant-baseline="central">
                        {redirectCode}
                </text>
        </g>
{/if}

<!-- Particle trail. ALWAYS MAX_PARTICLES circles, staggered evenly
     along the path. Tier controls visibility/size/glow via reactive
     CSS properties; the SMIL <animateMotion> attrs (dur, begin,
     repeatCount) are LITERALLY CONSTANT for the component's
     lifetime — touching any of them at runtime would restart the
     animation and reintroduce the C4 sawtooth. The CSS transitions
     on opacity/r/filter make tier changes look like a smooth fade
     instead of a pop. -->
{#each Array.from({ length: MAX_PARTICLES }) as _, i (i)}
        <circle
                class="particle"
                r={cfg.radius}
                fill={color}
                style:opacity={i < particleCount ? cfg.opacity : 0}
                style:filter={cfg.glowPx > 0 && i < particleCount
                        ? `drop-shadow(0 0 ${cfg.glowPx}px ${color})`
                        : 'none'}
                style:pointer-events="none"
        >
                <animateMotion
                        dur="{DUR_S}s"
                        repeatCount="indefinite"
                        begin="{-1 * (DUR_S / MAX_PARTICLES) * i}s"
                >
                        <mpath href={`#${id}`} />
                </animateMotion>
        </circle>
{/each}

<style>
        /* Smooth tier transitions — opacity/r/filter changes ease over
           ~0.4 s instead of popping. SMIL motion is untouched: only
           these CSS properties animate. */
        .redirect-label rect {
                fill: var(--surface);
                stroke: var(--border);
                stroke-width: 1;
        }

        .redirect-label text {
                fill: var(--text-secondary);
                font-size: 9px;
                font-variant-numeric: tabular-nums;
        }

        .particle {
                transition:
                        opacity 0.4s ease,
                        r 0.4s ease,
                        filter 0.4s ease;
        }
</style>
