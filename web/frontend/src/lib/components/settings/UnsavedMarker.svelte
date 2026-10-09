<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  The "unsaved changes" line under a settings card's title. The
  settings page asks before it is left with unsaved edits; this is
  how the operator finds which cards that question is about, on a
  page of fifteen cards spread over five tabs.
-->
<script lang="ts">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		/** The card holds edits not yet saved. Nothing renders otherwise. */
		dirty: boolean;
		testid?: string;
	}

	let { dirty, testid = 'unsaved-marker' }: Props = $props();
</script>

{#if dirty}
	<span class="mt-1 flex items-center gap-1.5 text-xs font-medium text-warn" data-testid={testid}>
		<span class="inline-block h-1.5 w-1.5 rounded-full bg-warn" aria-hidden="true"></span>
		{language.current && t('settings.unsaved.marker')}
	</span>
{/if}
