<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  RoutePostureChips (v2.41) — what guards a route, in one table cell.
  Until now the list showed the WAF mode and nothing else: a route
  could block three continents, allow one /24 and cap the rate, and
  the list looked exactly like a wide-open one. The operator had to
  open each route to find out.

  The chips carry the same code as the route form's section rails:
  red blocks, green lets through on a criterion, amber watches
  without blocking. Each chip states its own count in the tooltip,
  and a route with nothing configured shows a dash rather than an
  empty cell.
-->
<script lang="ts">
	import Badge from '$lib/components/Badge.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import type { Route } from '$lib/api/types';
	import { proxiesNothing } from '$lib/utils/route-gates';

	interface Props {
		route: Route;
	}

	let { route }: Props = $props();

	// v2.59 — a route that proxies nothing (redirect, maintenance,
	// disabled) has none of these gates in its emitted Caddy chain,
	// so showing their stored values here was a claim about traffic
	// that no handler backed. See lib/utils/route-gates.ts for the
	// manager.go citations.
	const inert = $derived(proxiesNothing(route));

	const cb = $derived(route.countryBlock);
	const geoActive = $derived(cb?.mode === 'allow' || cb?.mode === 'deny');
	const geoCount = $derived(
		(cb?.countryList?.length ?? 0) + (cb?.continents?.length ?? 0) + (cb?.asns?.length ?? 0)
	);

	const ipMode = $derived(route.ipFilter?.mode);
	const ipActive = $derived(ipMode === 'allow' || ipMode === 'deny');
	const ipCount = $derived(route.ipFilter?.cidrs?.length ?? 0);

	const rl = $derived(route.rateLimit ?? null);

	const empty = $derived(
		inert || (route.wafMode === 'off' && !geoActive && !ipActive && rl === null)
	);
</script>

<div class="chips" data-testid="posture-chips-root">
	{#if !inert}
		<!-- The guard wraps BOTH arms deliberately. Putting `!inert`
		     on the `detect` arm alone leaves the `block` arm live, so
		     an inert route in block mode keeps the red chip — the
		     exact bug this component is being fixed for. -->
		{#if route.wafMode === 'detect'}
			<Badge variant="status-warn">{language.current && t('routes.list.wafDetect')}</Badge>
		{:else if route.wafMode === 'block'}
			<Badge variant="status-down">{language.current && t('routes.list.wafBlock')}</Badge>
		{/if}
	{/if}

	{#if !inert && geoActive}
		<span
			class="cursor-help"
			data-testid="posture-geo"
			title={language.current &&
				t(cb.mode === 'deny' ? 'routes.list.geoDenyTooltip' : 'routes.list.geoAllowTooltip', {
					count: geoCount
				})}
		>
			<Badge variant={cb.mode === 'deny' ? 'status-down' : 'status-up'}>
				{language.current && t('routes.list.geoChip')}
			</Badge>
		</span>
	{/if}

	{#if !inert && ipActive}
		<span
			class="cursor-help"
			data-testid="posture-ip"
			title={language.current &&
				t(ipMode === 'deny' ? 'routes.list.ipDenyTooltip' : 'routes.list.ipAllowTooltip', {
					count: ipCount
				})}
		>
			<Badge variant={ipMode === 'deny' ? 'status-down' : 'status-up'}>
				{language.current && t('routes.list.ipChip')}
			</Badge>
		</span>
	{/if}

	{#if !inert && rl !== null}
		<span
			class="cursor-help"
			data-testid="posture-rate-limit"
			title={language.current &&
				t('routes.list.rateLimitTooltip', { events: rl.events, window: rl.window })}
		>
			<Badge variant="status-down">{rl.events}/{rl.window}</Badge>
		</span>
	{/if}

	{#if empty}
		{#if inert}
			<span class="text-muted cursor-help" data-testid="posture-inert"
				title={language.current && t('routes.list.postureInertTooltip')}>—</span>
		{:else}
			<span class="text-muted">—</span>
		{/if}
	{/if}
</div>

<style>
	.chips {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 4px;
	}
</style>
