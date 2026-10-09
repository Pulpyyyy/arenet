<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	type Variant =
		| 'tls'
		| 'waf'
		| 'status-up'
		| 'status-up-outline'
		| 'status-warn'
		| 'status-down'
		| 'status-info'
		| 'neutral'
		| 'current';

	interface Props {
		variant?: Variant;
		children?: Snippet;
	}

	let { variant = 'neutral', children }: Props = $props();
</script>

<span class="badge" data-variant={variant}>
	{@render children?.()}
</span>

<style>
	.badge {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		font-weight: 500;
		border-radius: var(--radius-full);
		border: 1px solid;
		line-height: 1.5;
	}

	/* Variants use the --badge-*-{bg,border} token pairs from
	 * tokens.css (Step F Chunk 3 additions). bg is a 15% tint of
	 * the variant's accent/status color via color-mix(); border is
	 * the saturated source color. Text is also the saturated source.
	 * Pre-Chunk-3 these were 5 rgba() hardcoded blocks per variant. */
	.badge[data-variant='tls'] {
		background: var(--badge-info-bg);
		border-color: var(--badge-info-border);
		color: var(--accent-cyan);
	}
	.badge[data-variant='waf'] {
		background: var(--badge-violet-bg);
		border-color: var(--badge-violet-border);
		color: var(--status-info);
	}
	.badge[data-variant='status-up'] {
		background: var(--badge-success-bg);
		border-color: var(--badge-success-border);
		color: var(--status-up);
	}
	/* Phase 2 OIDC sidebar — transparent-fill variant for the
	 * "CONNECTÉ" status pill in the OIDCConfigSummary sidebar.
	 * Same border + color as status-up but no background fill,
	 * matching the mockup's outline-only badge treatment. */
	.badge[data-variant='status-up-outline'] {
		background: transparent;
		border-color: var(--badge-success-border);
		color: var(--status-up);
	}
	.badge[data-variant='status-warn'] {
		background: var(--badge-warning-bg);
		border-color: var(--badge-warning-border);
		color: var(--status-warn-fg);
	}
	.badge[data-variant='status-down'] {
		background: var(--badge-danger-bg);
		border-color: var(--badge-danger-border);
		color: var(--status-down);
	}
	.badge[data-variant='neutral'] {
		background: var(--bg-elevated);
		border-color: var(--border-default);
		color: var(--text-secondary);
	}
	/* Users-page Phase 1 refactor — blue info palette for OIDC /
	 * Authentik source tags and similar informational markers. */
	.badge[data-variant='status-info'] {
		background: var(--badge-info-bg, color-mix(in oklch, var(--status-info) 14%, transparent));
		border-color: color-mix(in oklch, var(--status-info) 28%, transparent);
		color: var(--status-info);
	}
	/* "current" reuses the cyan info palette but exists as its own
	 * variant name for caller-side semantics. Sessions table marks
	 * the active session with <Badge variant="current">; reading
	 * variant="current" makes the intent obvious, whereas
	 * variant="tls" (the Chunk 6.2 placeholder) suggested a TLS
	 * indicator. Chunk 7.5 smoke fix. */
	.badge[data-variant='current'] {
		background: var(--badge-info-bg);
		border-color: var(--badge-info-border);
		color: var(--accent-cyan);
	}
</style>
