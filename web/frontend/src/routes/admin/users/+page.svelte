<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.5 — /admin/users redirects to /users.

  Per IA reorg, the users management surface is promoted to a
  top-level /users route. The K.2 content moved verbatim in
  R.4.4.a. This file preserves the legacy URL as a redirect
  for in-repo links + operator bookmarks. v1.5 may drop the
  redirect entirely.

  Backend gate (RequireAdminMiddleware) is unchanged; the
  redirect happens client-side AFTER the new page mounts,
  so role enforcement still runs on the destination's API
  calls.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	onMount(() => {
		void goto('/users', { replaceState: true });
	});
</script>

<svelte:head>
	<title>{language.current && t('common.redirectingHeadTitle')}</title>
</svelte:head>

<p class="redirect">{language.current && t('common.redirectingTo')} <a href="/users">/users</a>…</p>

<style>
	.redirect {
		color: var(--fg-muted);
		font-size: 13px;
		padding: 24px;
	}
	.redirect a { color: var(--accent); }
</style>
