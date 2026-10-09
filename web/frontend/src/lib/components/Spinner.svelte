<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	type Size = 'sm' | 'md' | 'lg';
	type Color = 'cyan' | 'black' | 'white' | 'current';
	let {
		size = 'md',
		color = 'cyan'
	}: { size?: Size; color?: Color } = $props();
	const sizeMap: Record<Size, number> = { sm: 14, md: 20, lg: 32 };
	const sizePx = $derived(sizeMap[size]);

	const arcColorMap: Record<Color, string> = {
		cyan: 'var(--accent-cyan)',
		black: 'var(--text-inverse)',
		white: 'var(--text-primary)',
		current: 'currentColor'
	};
	const arcStroke = $derived(arcColorMap[color]);
	// The muted ring uses a transparent fade of the arc color when 'current',
	// otherwise the design-system muted border.
	const ringStroke = $derived(color === 'current' ? 'currentColor' : 'var(--border-default)');
	const ringOpacity = $derived(color === 'current' ? '0.25' : '1');
</script>

<svg
	width={sizePx}
	height={sizePx}
	viewBox="0 0 24 24"
	fill="none"
	role="status"
	aria-label={language.current && t('common.loadingAria')}
>
	<circle
		cx="12"
		cy="12"
		r="10"
		stroke={ringStroke}
		stroke-opacity={ringOpacity}
		stroke-width="3"
	/>
	<path
		d="M22 12a10 10 0 0 1-10 10"
		stroke={arcStroke}
		stroke-width="3"
		stroke-linecap="round"
	>
		<animateTransform
			attributeName="transform"
			type="rotate"
			from="0 12 12"
			to="360 12 12"
			dur="0.9s"
			repeatCount="indefinite"
		/>
	</path>
</svg>
