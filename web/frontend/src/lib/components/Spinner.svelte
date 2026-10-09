<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
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

<!-- The rotation is a CSS animation on the <svg> itself, not SMIL.
     An <animateTransform> kept spinning under prefers-reduced-motion,
     because no stylesheet reaches SMIL. As CSS it is stopped both by
     the global rule in app.css and by the rule below. The ring is a
     full circle, so turning the whole graphic only moves the arc. -->
<svg
	class="spinner"
	width={sizePx}
	height={sizePx}
	viewBox="0 0 24 24"
	fill="none"
	role="status"
	aria-label="Loading"
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
	/>
</svg>

<style>
	.spinner {
		animation: spinner-rotate 0.9s linear infinite;
	}

	@keyframes spinner-rotate {
		to {
			transform: rotate(360deg);
		}
	}

	/* Static under reduced motion: the ring and arc still say
	   "loading" (and role="status" says it to assistive tech). */
	@media (prefers-reduced-motion: reduce) {
		.spinner {
			animation: none;
		}
	}
</style>
