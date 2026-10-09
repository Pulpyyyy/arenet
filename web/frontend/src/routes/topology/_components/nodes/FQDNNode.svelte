<!--
  FQDNNode — Col 1 of the Service→Backend view.

  Represents a primary host (api.arenet.fr, app.arenet.fr…) fed by
  upstream consumers and forwarding to Caddy. Declares both handles
  so edges can attach on the right protocol.

  C16 (2026-06-03): WAF indicator. Route-level attribute carried
  via data.wafLevel. Off → no glyph. Detect → Lucide Shield (muted
  gray). Block → Lucide ShieldCheck (accent blue). Coherent with
  the UpstreamNode icon language: Activity = HC monitored,
  Lock = upstream TLS, Shield = WAF.

  C17 (2026-06-04): aliases tooltip. When the route has aliases,
  the meta line (e.g. "2 aliases") gets a `title` listing the full
  hostnames — primary first, then aliases. Operator can hover to
  see the real names without expanding the node. The "h2 · h3"
  protocol suffix was dropped from the protocols line in _layout.ts
  because the backend doesn't expose real ALPN data yet (see
  #R-TOPO-alpn).

  C17b + C19 (2026-06-04): the alias count moved from "host(s)"
  to "alias(es)" terminology and is omitted when the route has 0
  aliases — both done in _layout.ts's formatFQDNMeta. The component
  just renders whatever string the layout hands it.

  C18 (2026-06-04): protocols line shows "HTTP → HTTPS" when the
  route has TLS + httpRedirect both enabled; "HTTPS" when TLS
  without redirect; "HTTP" otherwise. All decided in
  formatProtocols() in _layout.ts.

  C20 (2026-06-04): no target handle. FQDN is the source-of-flow
  in col 0 — nothing connects into its left edge in the C6b-i
  layout. The leftover orphan handle from earlier views was
  visually confusing, same problem as Critique 6 on the cluster
  parent.

  Phase 3.e (2026-06-17): collapse/expand toggle. When the route
  has aliases (data.aliasCount > 0), a chevron glyph appears in
  the host row — clicking it flips the route's entry in the
  page-local collapsedRoutes store. The meta line also branches:
  collapsed routes display "N aliases · X r/s total" instead of
  the per-route "Y req/s" formatted by _layout.ts. The store is
  imported directly because the alternative — threading a
  callback through NodeProps.data, which must be a plain object —
  would force a serialisable shape on a UI concern.

  v2.14.3 (route disable/enable): disabled routes still appear
  in the topology (Caddy config generation just skips them; the
  canvas reads storage directly), so without a visual cue a
  disabled route reads as a mysterious zero-traffic phantom
  indistinguishable from an idle-but-enabled one. When
  data.disabled is true the card gets the `.disabled` class
  (reduced opacity + dashed border, mirroring the RouteGroupNode
  dashed-border language already used for route framing) plus
  `data-disabled` for tests and a `title` tooltip resolved via
  t('topology.disabled.tooltip') so hovering explains the dim
  state instead of leaving the operator guessing.
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { FQDNNodeData } from '../../_types';
        import { collapsedRoutes } from '../../_collapsed.svelte';
        import { t } from '$lib/i18n';
        import { language } from '$lib/stores/language.svelte';

        let { data }: NodeProps & { data: FQDNNodeData } = $props();

        // v2.14.3 — disabled tooltip. `language.current &&` is the
        // reactivity trigger per the project's i18n idiom (see
        // $lib/i18n/index.ts usage docs): without reading it inside
        // the $derived, the string would not recompute on language
        // change. Empty string when enabled — no title attribute
        // clutter on the common case.
        let disabledTooltip = $derived(
                data.disabled && language.current ? t('topology.disabled.tooltip') : ''
        );

        // Hosts tooltip — primary host first, then aliases, comma-
        // separated. Empty string when the route has no aliases (the
        // count alone is already "1 host"; the hostname is right
        // above, no need to repeat it in a tooltip).
        let hostsTooltip = $derived.by(() => {
                if (!data.aliases || data.aliases.length === 0) return '';
                return [data.host, ...data.aliases].join(', ');
        });

        // Phase 3.e — chevron click handler. Stops propagation so
        // SvelteFlow doesn't also trigger its node-selection
        // outline on the same click.
        function onChevronClick(ev: MouseEvent) {
                ev.stopPropagation();
                collapsedRoutes.toggle(data.routeId);
        }

        // Phase 3.e — collapsed meta line. When folded, the
        // operator can't see the per-alias breakdown, so we
        // surface the aggregate as a hint of what's behind the
        // chevron. Format mirrors the FQDNNode meta line shape
        // (mono font, fg-dim colour, see CSS).
        //
        // HOTFIX (2026-06-17, post-Phase-3.e ship) — overflow
        // bug : the original format "N aliases · X.XX req/s
        // total" wrapped to a 3rd line on the 21-alias traefik
        // route ("21 aliases · 0.10 req/s total" = 32 chars,
        // content width 176 px at the 10.5 px mono font is
        // ~28 chars), pushing the primary FQDN card past the
        // RouteGroupNode container bounds at the top.
        //
        // Fix : tighter format ":
        //  - drop " total" (redundant — "21 aliases" already
        //    implies an aggregate).
        //  - " req/s" → " r/s" (matches AliasNode's rate label
        //    convention so the two surfaces read consistently).
        // Result : "21 aliases · 0.10 r/s" = 21 chars, fits in
        // ~134 px — comfortably under the 176 px budget even at
        // 1000-alias pathological cardinality.
        let collapsedMeta = $derived.by(() => {
                const count = data.aliasCount ?? 0;
                if (count === 0) return data.meta;
                const noun = count === 1 ? 'alias' : 'aliases';
                const total = formatRate(data.aliasTotalRps ?? 0);
                return `${count} ${noun} · ${total}`;
        });

        function formatRate(rps: number): string {
                if (rps === 0) return '0 r/s';
                if (rps < 10) return `${rps.toFixed(2)} r/s`;
                return `${Math.round(rps)} r/s`;
        }
</script>

<div
        class="fqdn-node"
        class:disabled={data.disabled}
        data-disabled={data.disabled}
        title={disabledTooltip || undefined}
>
        <div class="host-row">
                <span class="host">{data.host}</span>
                {#if (data.aliasCount ?? 0) > 0}
                        <button
                                type="button"
                                class="chevron"
                                class:expanded={!data.collapsed}
                                onclick={onChevronClick}
                                aria-label={language.current &&
                                        (data.collapsed
                                                ? t('topology.nodes.expandAliases', { count: data.aliasCount ?? 0 })
                                                : t('topology.nodes.collapseAliases', { count: data.aliasCount ?? 0 }))}
                                aria-expanded={!data.collapsed}
                        >
                                <!-- Lucide ChevronRight; CSS rotates 90° when expanded -->
                                <svg
                                        viewBox="0 0 24 24"
                                        fill="none"
                                        stroke="currentColor"
                                        stroke-width="2"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                        aria-hidden="true"
                                >
                                        <path d="m9 18 6-6-6-6" />
                                </svg>
                        </button>
                {/if}
                {#if data.wafLevel === 'detect'}
                        <svg
                                class="ico ico-waf ico-waf-detect"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                aria-label={language.current && t('topology.nodes.wafDetect')}
                        >
                                <title>{language.current && t('topology.nodes.wafDetect')}</title>
                                <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                        </svg>
                {:else if data.wafLevel === 'block'}
                        <svg
                                class="ico ico-waf ico-waf-block"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                aria-label={language.current && t('topology.nodes.wafBlock')}
                        >
                                <title>{language.current && t('topology.nodes.wafBlock')}</title>
                                <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                                <path d="m9 12 2 2 4-4" />
                        </svg>
                {/if}
        </div>
        <div class="protocols">{data.protocols}</div>
        <div class="meta" title={hostsTooltip}>
                {#if data.collapsed && (data.aliasCount ?? 0) > 0}
                        {collapsedMeta}
                {:else}
                        {data.meta}
                {/if}
        </div>

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .fqdn-node {
                width: 200px;
                /* HOTFIX (2026-06-17, post-Phase-3.e ship) — explicit
                   height pins the rendered card at FQDN_HEIGHT
                   exactly (70 px). Mirrors the AliasNode height
                   pin for the same reason : content-driven sizing
                   drifted a few px due to font line-height /
                   border / padding combinations, leaving the
                   RouteGroupNode bottom padding visually thinner
                   than the symmetric calc promised. */
                height: 70px;
                padding: 10px 12px;
                box-sizing: border-box;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        /* v2.14.3 — disabled route. Reduced opacity + dashed border
           mirrors the RouteGroupNode's dashed-border language
           already used elsewhere on the canvas to say "this is a
           soft/inactive framing element", so a disabled route
           reads as deliberately off rather than a broken card. */
        .fqdn-node.disabled {
                opacity: 0.5;
                border: 1px dashed var(--border, oklch(28% 0.009 250));
        }

        .host-row {
                display: flex;
                align-items: center;
                gap: 6px;
                margin-bottom: 3px;
        }

        .host {
                flex: 1 1 auto;
                font-size: 13px;
                font-weight: 600;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .ico {
                flex: 0 0 auto;
                width: 14px;
                height: 14px;
        }

        /* Detect = muted gray, block = accent blue. Same hue family as
           the UpstreamNode icons so the security indicators read as one
           visual language. */
        .ico-waf-detect {
                color: var(--fg-muted, oklch(68% 0.012 250));
        }
        .ico-waf-block {
                color: var(--accent, oklch(68% 0.21 255));
        }

        .protocols {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                margin-bottom: 4px;
        }

        .meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-dim, oklch(54% 0.011 250));
                /* HOTFIX (2026-06-17) — single-line guarantee.
                   The collapsed meta "N aliases · X r/s" is tight
                   on the 176 px content budget already; an
                   unforeseen growth path (e.g. a 4-digit alias
                   count with a 3-digit rate) must NOT wrap and
                   push the card past the RouteGroupNode container
                   bounds. Truncate with an ellipsis instead — the
                   tooltip on the meta div carries the full text
                   for the curious operator. */
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
        }

        /* Phase 3.e — chevron toggle. Sits between the host name
           and the WAF glyph; muted by default, brightens on hover
           so the operator gets a visible affordance without
           competing with the host label. The rotation is the
           collapsed↔expanded indicator (▶ vs ▼ in glyph terms,
           but rendered as a 90° rotation of a single chevron-
           right so the chevron-down case is one source of
           truth). */
        .chevron {
                flex: 0 0 auto;
                width: 16px;
                height: 16px;
                padding: 0;
                margin: 0;
                background: transparent;
                border: none;
                color: var(--fg-muted, oklch(68% 0.012 250));
                cursor: pointer;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                border-radius: 3px;
                transition: transform 180ms ease, color 120ms ease, background 120ms ease;
        }

        .chevron:hover,
        .chevron:focus-visible {
                color: var(--fg, oklch(96% 0.005 250));
                background: var(--surface-2, oklch(22% 0.007 250));
                outline: none;
        }

        .chevron.expanded {
                transform: rotate(90deg);
        }

        .chevron svg {
                width: 12px;
                height: 12px;
        }

        :global(.svelte-flow__node-fqdn) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
