<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Phase Z.5.4 — stacked-bars activity histogram for /logs.

  Renders one bar per time bucket, segmented by source. The
  caller supplies a flat list of {ts, source} cells already
  filtered upstream — this component does NOT know about the
  source enum or the filter state, which keeps it reusable
  for any future surface that wants a stacked-by-source
  histogram (Step BB alert dispatcher overview, ...).

  Time bucketing is fixed at the caller (bucketMs prop)
  rather than auto-fit because the /logs window changes
  rarely (currently always 24h) and an auto-fit would
  flicker the bucket width on poll-driven re-renders.

  Performance : O(N) bucketing on the input list (typically
  ≤200 rows post-filter). The chart paints with one <rect>
  per (bucket × source) — bounded by 288 × 6 = 1728 rects
  worst case at 5m granularity. Fine for SVG render.

  Accessibility : ARIA label per the existing TimelineChart
  convention. The hover tooltip shows per-source counts so
  a screen-reader user gets the same data via the
  aria-label fallback (TODO V2 : table fallback for full
  a11y parity).
-->

<script lang="ts">
	import { formatTime } from '$lib/utils/format';

	interface Cell {
		/** RFC 3339 timestamp of the event. */
		ts: string;
		/** Source key (matches sourceMeta.ts slugs). */
		source: string;
	}

	interface SeriesDef {
		/** Source key matching Cell.source. */
		key: string;
		/** Operator-readable label rendered in the tooltip. */
		label: string;
		/** CSS color value (rgb / oklch / var). */
		color: string;
	}

	interface Props {
		/** All cells in the current view. Already filtered upstream. */
		cells: Cell[];
		/** Series definitions in stack order (bottom → top). */
		series: SeriesDef[];
		/** Bucket width in ms. Default 5 min. */
		bucketMs?: number;
		/** Window width in ms. Default 24h. */
		windowMs?: number;
		/** Operator-readable label for screen readers. */
		label: string;
		/**
		 * Chart height. Number = fixed pixels (default 80,
		 * slim band). The string literal "fill" makes the
		 * SVG claim 100% of its container's height and
		 * reactively re-measure on resize ; the caller is
		 * responsible for giving the wrapper a bounded
		 * height (e.g. flex:1 inside a flex column whose
		 * height is constrained). Z.5.6 polish on /logs
		 * uses "fill" with a 70/30 table/histogram ratio.
		 */
		height?: number | 'fill';
	}

	let {
		cells,
		series,
		bucketMs = 5 * 60 * 1000,
		windowMs = 24 * 60 * 60 * 1000,
		label,
		height = 80
	}: Props = $props();

	const PAD_L = 36;
	const PAD_R = 8;
	const PAD_T = 6;
	const PAD_B = 18;

	let svgEl: SVGSVGElement | undefined = $state();
	let svgWidth = $state(800);
	// Z.5.6 — measured pixel height when `height === 'fill'`.
	// Initialised to a sensible non-zero value so the first
	// paint isn't a 0px-tall band before ResizeObserver fires.
	let measuredHeight = $state(200);

	// Bucket the cells into a fixed-width grid anchored on
	// the most recent observation. The grid is the *display*
	// window ; cells older than (windowEnd - windowMs) drop
	// out (operator wants 24h, so 25h-old events should not
	// inflate the leftmost bucket).
	const buckets = $derived.by(() => {
		const N = Math.max(1, Math.ceil(windowMs / bucketMs));
		const now = Date.now();
		// Anchor on a bucket boundary so the rightmost bar
		// doesn't jitter every render. Truncate to the
		// nearest bucketMs.
		const windowEnd = Math.ceil(now / bucketMs) * bucketMs;
		const windowStart = windowEnd - windowMs;
		// Pre-allocate the bucket grid : one Map per bucket
		// (source → count). Map keeps insertion order so the
		// stack order matches `series`.
		const grid: Array<Map<string, number>> = Array.from(
			{ length: N },
			() => new Map<string, number>()
		);
		for (const c of cells) {
			const t = Date.parse(c.ts);
			if (!Number.isFinite(t)) continue;
			if (t < windowStart || t >= windowEnd) continue;
			const idx = Math.floor((t - windowStart) / bucketMs);
			if (idx < 0 || idx >= N) continue;
			const m = grid[idx];
			m.set(c.source, (m.get(c.source) ?? 0) + 1);
		}
		return { grid, windowStart, windowEnd, N };
	});

	// Y-axis : max stack height (sum of all sources in the
	// busiest bucket). Caps at 1 to avoid div-by-zero on
	// the empty-state.
	const yMax = $derived.by(() => {
		let m = 1;
		for (const b of buckets.grid) {
			let total = 0;
			for (const v of b.values()) total += v;
			if (total > m) m = total;
		}
		return m;
	});

	function resize(): void {
		if (!svgEl) return;
		const rect = svgEl.getBoundingClientRect();
		svgWidth = rect.width;
		// Z.5.6 — track the SVG's pixel height when in fill
		// mode. Numeric-height callers ignore this state via
		// the `effectiveHeight` derived below.
		if (height === 'fill') {
			measuredHeight = rect.height;
		}
	}

	$effect(() => {
		if (typeof window === 'undefined') return;
		resize();
		window.addEventListener('resize', resize);
		// Z.5.6 — ResizeObserver picks up parent-driven height
		// changes (flex-grow on viewport-relative containers
		// doesn't fire `window.resize`). Guarded for older
		// browsers where ResizeObserver is absent ; on those
		// the chart stays at the initial measuredHeight, which
		// is honest degraded behavior.
		let ro: ResizeObserver | undefined;
		if (height === 'fill' && typeof ResizeObserver !== 'undefined' && svgEl) {
			ro = new ResizeObserver(resize);
			ro.observe(svgEl);
		}
		return () => {
			window.removeEventListener('resize', resize);
			ro?.disconnect();
		};
	});

	// Z.5.6 — resolve the effective pixel height : numeric
	// caller → its literal value ; 'fill' caller → live
	// measured value from the SVG bounding-box. Pre-Z.5.6
	// every consumer passed a number, so the default 80 path
	// is unchanged.
	const effectiveHeight = $derived(
		height === 'fill' ? measuredHeight : (height as number)
	);

	const innerWidth = $derived(Math.max(0, svgWidth - PAD_L - PAD_R));
	const innerHeight = $derived(Math.max(0, effectiveHeight - PAD_T - PAD_B));
	const barWidth = $derived(innerWidth / Math.max(1, buckets.N));

	// Tooltip state on bucket hover.
	interface TooltipState {
		x: number;
		y: number;
		bucketIndex: number;
		ts: number;
	}
	let tooltip = $state<TooltipState | null>(null);

	function onBucketHover(idx: number, ev: MouseEvent): void {
		const bucketTs = buckets.windowStart + idx * bucketMs;
		const rect = svgEl?.getBoundingClientRect();
		if (!rect) return;
		tooltip = {
			x: ev.clientX - rect.left,
			y: ev.clientY - rect.top,
			bucketIndex: idx,
			ts: bucketTs
		};
	}
	function onBucketLeave(): void {
		tooltip = null;
	}

	function formatBucketTime(ts: number): string {
		return formatTime(new Date(ts));
	}

	function tooltipRows(idx: number): Array<{ key: string; label: string; color: string; count: number }> {
		const m = buckets.grid[idx];
		const out: Array<{ key: string; label: string; color: string; count: number }> = [];
		for (const s of series) {
			const count = m.get(s.key) ?? 0;
			if (count > 0) {
				out.push({ key: s.key, label: s.label, color: s.color, count });
			}
		}
		return out;
	}
</script>

<div
	class="activity-histogram"
	class:fill={height === 'fill'}
	data-testid="activity-histogram"
>
	<!--
	  Z.5.6 — when height === 'fill' the SVG claims 100%
	  of the wrapper, which itself claims 100% of its
	  flex slot. Numeric callers get the pre-Z.5.6 fixed-
	  pixel shape unchanged.
	-->
	<svg
		bind:this={svgEl}
		role="img"
		aria-label={label}
		width="100%"
		height={height === 'fill' ? '100%' : height}
		preserveAspectRatio="none"
	>
		<!-- Y axis baseline -->
		<line
			x1={PAD_L}
			y1={PAD_T + innerHeight}
			x2={PAD_L + innerWidth}
			y2={PAD_T + innerHeight}
			stroke="var(--border)"
			stroke-width="1"
		/>

		<!-- Stacked bars -->
		{#each buckets.grid as bucket, i (i)}
			{@const x = PAD_L + i * barWidth}
			{@const segments = series
				.map((s) => ({ s, count: bucket.get(s.key) ?? 0 }))
				.filter((seg) => seg.count > 0)}
			{#if segments.length > 0}
				<g class="bucket" onmouseenter={(ev) => onBucketHover(i, ev)} onmouseleave={onBucketLeave} role="presentation">
					{#each segments as seg, segIdx (seg.s.key)}
						{@const segHeight = (seg.count / yMax) * innerHeight}
						{@const yOffset = segments
							.slice(0, segIdx)
							.reduce(
								(acc, s2) => acc + (s2.count / yMax) * innerHeight,
								0
							)}
						<rect
							x={x + 0.5}
							y={PAD_T + innerHeight - yOffset - segHeight}
							width={Math.max(0, barWidth - 1)}
							height={segHeight}
							fill={seg.s.color}
							class="bar-seg"
						/>
					{/each}
				</g>
			{/if}
		{/each}

		<!-- Y-axis tick at max -->
		<text x={PAD_L - 4} y={PAD_T + 4} text-anchor="end" class="axis-label">
			{yMax}
		</text>
		<!-- X-axis ticks : ends + middle. -->
		<text x={PAD_L} y={effectiveHeight - 4} text-anchor="start" class="axis-label">
			{formatBucketTime(buckets.windowStart)}
		</text>
		<text x={PAD_L + innerWidth / 2} y={effectiveHeight - 4} text-anchor="middle" class="axis-label">
			{formatBucketTime(buckets.windowStart + windowMs / 2)}
		</text>
		<text x={PAD_L + innerWidth} y={effectiveHeight - 4} text-anchor="end" class="axis-label">
			now
		</text>

		{#if tooltip}
			{@const rows = tooltipRows(tooltip.bucketIndex)}
			{@const tx = Math.min(tooltip.x + 8, PAD_L + innerWidth - 130)}
			{@const ty = Math.max(tooltip.y - 8, PAD_T + 14 + rows.length * 12)}
			<g class="tooltip" pointer-events="none">
				<rect
					x={tx}
					y={ty - 14 - rows.length * 12}
					width="130"
					height={16 + rows.length * 12}
					rx="3"
				/>
				<text x={tx + 6} y={ty - 4 - rows.length * 12 + 10} class="tt-time">
					{formatBucketTime(tooltip.ts)}
				</text>
				{#each rows as row, ri (row.key)}
					<g>
						<circle
							cx={tx + 10}
							cy={ty - 2 - (rows.length - ri - 1) * 12 - 4}
							r="3"
							fill={row.color}
						/>
						<text
							x={tx + 18}
							y={ty - 2 - (rows.length - ri - 1) * 12}
							class="tt-row"
						>
							{row.label} · {row.count}
						</text>
					</g>
				{/each}
			</g>
		{/if}
	</svg>
</div>

<style>
	.activity-histogram {
		width: 100%;
	}
	/* Z.5.6 — fill mode : the wrapper claims the leftover
	   space in a flex-column parent (typical: a card with
	   a header above and the chart below). The SVG inside
	   inherits via flex:1 + min-height:0 so its height="100%"
	   attribute resolves to real pixels and the
	   ResizeObserver picks up the measurement.
	   Callers MUST place .activity-histogram.fill inside a
	   bounded flex-column container ; a plain block parent
	   without height context will collapse to 0px. */
	.activity-histogram.fill {
		flex: 1;
		min-height: 0;
		display: flex;
	}
	.activity-histogram.fill svg {
		flex: 1;
		min-height: 0;
	}
	.bucket .bar-seg {
		transition: opacity 0.1s;
	}
	.bucket:hover .bar-seg {
		opacity: 0.85;
	}
	.axis-label {
		fill: var(--fg-dim);
		font-family: var(--font-mono);
		font-size: 9.5px;
	}
	.tooltip rect {
		fill: var(--bg);
		stroke: var(--border);
		stroke-width: 1;
	}
	.tooltip .tt-time {
		fill: var(--fg-dim);
		font-family: var(--font-mono);
		font-size: 10px;
	}
	.tooltip .tt-row {
		fill: var(--fg);
		font-family: var(--font-mono);
		font-size: 10px;
	}
</style>
