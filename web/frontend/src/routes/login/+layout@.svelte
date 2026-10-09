<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Layout reset for /login (spec §6.9). The parent +layout.svelte mounts
  the Sidebar + main chrome which is inappropriate for unauthenticated
  pages. The `@` suffix on the filename instructs SvelteKit to attach
  this layout directly to the root, bypassing the parent.

  Once Chunk 7 introduces the auth-state-aware layout shell, this reset
  may become redundant; for now it isolates /login cleanly.
-->
<script lang="ts">
	import '../../app.css';
	import favicon from '$lib/assets/arenet-logo.png';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" type="image/png" href={favicon} />
	<title>{language.current && t('auth.signInHeadTitle')}</title>
</svelte:head>

{@render children?.()}
<!-- No ToastContainer here: the root +layout.svelte (which a
     +layout@ reset still sits under) already mounts one around this
     page. A second copy showed, and announced, every toast twice. -->
