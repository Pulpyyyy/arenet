<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V.5 — license attribution footer for the /map page.

  Per spec §3.7 + §3.3:
    - world-atlas TopoJSON is CC0 / public domain — no
      attribution required but we credit the source as a
      courtesy.
    - MaxMind GeoLite2-City is CC BY-SA 4.0 — attribution
      IS required by the license. The footer is rendered
      regardless of whether the MMDB is actually loaded so
      a smoke-time MMDB-absent path doesn't silently drop
      the attribution from a future re-enable; the visual
      cost is one line of muted text.
-->
<script lang="ts">
	// No props — single static footer used by /map. Future
	// pages can reuse via direct import.
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
</script>

<footer class="license-footer">
	<span>
		{language.current && t('map.licenseGeoip')}
		<a href="https://www.maxmind.com" target="_blank" rel="noopener noreferrer">GeoLite2</a>
		© MaxMind (CC BY-SA 4.0)
	</span>
	<span class="license-footer__sep" aria-hidden="true">·</span>
	<span>
		{language.current && t('map.licenseMap')}
		<a
			href="https://github.com/topojson/world-atlas"
			target="_blank"
			rel="noopener noreferrer">world-atlas</a
		>
		(CC0)
	</span>
</footer>

<style>
	.license-footer {
		display: flex;
		flex-wrap: wrap;
		gap: 6px 10px;
		align-items: center;
		padding: 10px 14px;
		margin-top: 12px;
		font-size: 12px;
		color: var(--text-muted);
		border-top: 1px solid var(--border-subtle);
	}
	.license-footer a {
		color: var(--text-secondary);
		text-decoration: underline;
		text-decoration-color: var(--border-default);
		text-underline-offset: 2px;
	}
	.license-footer a:hover {
		color: var(--text-primary);
		text-decoration-color: var(--accent-cyan);
	}
	.license-footer__sep {
		color: var(--text-muted);
		user-select: none;
	}
</style>
