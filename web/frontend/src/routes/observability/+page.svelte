<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.5 — /observability index redirects to /dashboard.

  The Step L observability dashboard content was redistributed
  in R.4 across /dashboard (KPI tiles + traffic chart + WAF
  events card) and /logs (live event tail). The legacy URL is
  preserved as a redirect for in-repo links + operator
  bookmarks. v1.5 may drop the redirect entirely once the
  legacy URL has aged out.

  /observability/[routeId] (per-route metrics drill-down) is
  NOT redirected — it stays at the legacy URL until a future
  step folds it into the new Dashboard. Tracked as #R-7 in
  docs/backlog-step-r.md.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	onMount(() => {
		void goto('/dashboard', { replaceState: true });
	});
</script>

<svelte:head>
	<title>{language.current && t('common.redirectingHeadTitle')}</title>
</svelte:head>

<p class="redirect">{language.current && t('common.redirectingTo')} <a href="/dashboard">/dashboard</a>…</p>

<style>
	.redirect {
		color: var(--fg-muted);
		font-size: 13px;
		padding: 24px;
	}
	.redirect a { color: var(--accent); }
</style>
