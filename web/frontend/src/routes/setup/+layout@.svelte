<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Layout reset for /setup (spec §6.10). See /login/+layout@.svelte
  for rationale.
-->
<script lang="ts">
	import '../../app.css';
	import favicon from '$lib/assets/arenet-logo.png';
	import ToastContainer from '$lib/components/ToastContainer.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" type="image/png" href={favicon} />
	<title>{language.current && t('setup.headTitle')}</title>
</svelte:head>

{@render children?.()}
<ToastContainer />
