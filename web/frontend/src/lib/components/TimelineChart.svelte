<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step L L.3 — Timeline chart for /observability.

Renders a single time series as a thin SVG line chart with
3-tick y-axis + 3-tick x-axis time labels + hover tooltip
(vertical guide line + ts/value readout).

AC #5 (critical): `null` y-values BREAK the line — they are NOT
plotted as 0. We split the input into contiguous non-null
segments and emit one <path> per segment. This is the canonical
d3.line().defined() pattern, done by hand to avoid pulling D3
into the bundle (Spec-1 §10.2: the spec assumed D3 was already
loaded but the project actually uses raw SVG everywhere).

Bundle: pure SVG + Svelte template = ~3 kB minified, fits the
AC #16 10 kB-gz dashboard budget with room to spare.

Trailing in-progress bucket (backlog item #L.2-2): the parent
page is responsible for dropping the last slot — the chart
receives whatever points its caller chose to show.

Zero is data. A window of zeros (no 5xx at all, say) draws a flat
line along the baseline; only a window with no measured point at
all shows the empty state.

The tooltip follows any pointer (mouse, pen, finger) and the
keyboard: the plot is focusable, Left/Right step through the
points, Home/End jump to the ends, Escape hides it.
-->

<script lang="ts">
	import type { TimeseriesPoint } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { chartKeyStep } from '$lib/utils/chart-keys';
	import { chartClock, chartDayTime } from '$lib/utils/chart-time';

	interface Props {
		points: TimeseriesPoint[];
		// CSS var reference (e.g. 'var(--accent-cyan)') so the
		// chart respects light/dark theme switches automatically.
		color: string;
		// Optional formatter for y-axis labels and tooltips —
		// e.g. "12 req" for counts, "32 ms" for latency.
		// Defaults to a rounded integer.
		formatValue?: (v: number) => string;
		// Aria/sr label, plus an in-DOM <title> for accessibility.
		label: string;
		// Optional explicit height. Default 120px.
		height?: number;
	}
	let { points, color, formatValue, label, height = 120 }: Props = $props();

	// Layout constants. Internal padding makes room for y-axis
	// labels on the left, x-axis labels at the bottom, and a
	// margin for the right-edge tick.
	const PAD_L = 36;
	const PAD_R = 12;
	const PAD_T = 8;
	const PAD_B = 22;

	let wrapWidth = $state(640);
	let svgEl: SVGSVGElement | undefined = $state();
	let hoverIdx = $state<number | null>(null);

	const innerWidth = $derived(Math.max(50, wrapWidth - PAD_L - PAD_R));
	const innerHeight = $derived(Math.max(40, height - PAD_T - PAD_B));

	// Max value across all NON-NULL points. Fallback to 1 so the
	// y axis is well-defined on an all-null or all-zero window.
	const maxVal = $derived.by(() => {
		let m = 0;
		for (const p of points) {
			if (p.value !== null && p.value > m) m = p.value;
		}
		return m === 0 ? 1 : m;
	});

	// A zero is a measurement ("no 5xx in this window" is good
	// news), so any non-null point counts; only an all-null window
	// is empty.
	const hasData = $derived(points.some((p) => p.value !== null));

	function xAt(i: number): number {
		if (points.length <= 1) return PAD_L;
		return PAD_L + (i / (points.length - 1)) * innerWidth;
	}
	function yAt(v: number): number {
		return PAD_T + innerHeight - (v / maxVal) * innerHeight;
	}

	// Split the input into contiguous non-null segments. AC #5
	// enforcement at the rendering layer.
	const segments = $derived.by(() => {
		const out: { x: number; y: number; value: number; index: number }[][] = [];
		let cur: { x: number; y: number; value: number; index: number }[] = [];
		for (let i = 0; i < points.length; i++) {
			const v = points[i].value;
			if (v === null) {
				if (cur.length > 0) {
					out.push(cur);
					cur = [];
				}
				continue;
			}
			cur.push({ x: xAt(i), y: yAt(v), value: v, index: i });
		}
		if (cur.length > 0) out.push(cur);
		return out;
	});

	function pathD(segment: { x: number; y: number }[]): string {
		if (segment.length === 0) return '';
		if (segment.length === 1) {
			const { x, y } = segment[0];
			return `M ${x - 1} ${y} L ${x + 1} ${y}`;
		}
		let d = `M ${segment[0].x} ${segment[0].y}`;
		for (let i = 1; i < segment.length; i++) {
			d += ` L ${segment[i].x} ${segment[i].y}`;
		}
		return d;
	}

	const fmt = $derived(formatValue ?? ((v: number) => String(Math.round(v))));

	// Y axis: three ticks — 0, ½ max, max.
	const yTicks = $derived([0, maxVal / 2, maxVal]);

	// X axis: pick three timestamps to label — first / middle /
	// last. Format depends on the spread: < 48h shows HH:MM,
	// longer spreads add the day and month, ordered for the app
	// language. Empty input → no labels.
	const xTicks = $derived.by(() => {
		if (points.length === 0) return [] as { x: number; label: string }[];
		const firstTs = new Date(points[0].ts);
		const lastTs = new Date(points[points.length - 1].ts);
		const spanMs = lastTs.getTime() - firstTs.getTime();
		const compact = spanMs < 48 * 3600 * 1000;
		const fmtTs = (d: Date) => (compact ? chartClock(d) : chartDayTime(d));
		const midIdx = Math.floor(points.length / 2);
		return [
			{ x: xAt(0), label: fmtTs(firstTs) },
			{ x: xAt(midIdx), label: fmtTs(new Date(points[midIdx].ts)) },
			{ x: xAt(points.length - 1), label: fmtTs(lastTs) }
		];
	});

	// Hover: map pointer x → nearest data index. Pointer events
	// cover mouse, pen and touch alike; pointerdown makes a tap show
	// the tooltip even when the finger does not move.
	function handleMove(e: PointerEvent): void {
		if (!svgEl || points.length === 0) return;
		const rect = svgEl.getBoundingClientRect();
		const mx = ((e.clientX - rect.left) / rect.width) * wrapWidth;
		const ratio = (mx - PAD_L) / innerWidth;
		if (ratio < 0 || ratio > 1) {
			hoverIdx = null;
			return;
		}
		const idx = Math.round(ratio * (points.length - 1));
		hoverIdx = Math.max(0, Math.min(points.length - 1, idx));
	}
	function handleLeave(e: PointerEvent): void {
		// A lifted finger fires pointerleave straight after pointerup;
		// hiding there would erase what the tap just showed. A touch
		// tooltip goes on blur (tapping elsewhere) or Escape instead.
		if (e.pointerType === 'touch') return;
		hoverIdx = null;
	}
	function handleKey(e: KeyboardEvent): void {
		const next = chartKeyStep(e.key, tooltip ? hoverIdx : null, points.length);
		if (next === undefined) return;
		e.preventDefault();
		hoverIdx = next;
	}
	function hideTooltip(): void {
		hoverIdx = null;
	}

	// Tooltip data derived from hover index. The bound check covers
	// a poll that shortened the series under a held tooltip.
	const tooltip = $derived.by(() => {
		if (hoverIdx === null || hoverIdx >= points.length) return null;
		const p = points[hoverIdx];
		return {
			x: xAt(hoverIdx),
			tsLabel: chartDayTime(new Date(p.ts)),
			valueLabel: p.value === null ? '—' : fmt(p.value),
			hasValue: p.value !== null
		};
	});

	// What a screen reader hears for the focused plot: the point the
	// tooltip shows, or how to reach one.
	const valueText = $derived(
		tooltip
			? t('chartUi.pointValue', { time: tooltip.tsLabel, value: tooltip.valueLabel })
			: t('chartUi.keyboardHint')
	);
</script>

<div class="chart-wrap" bind:clientWidth={wrapWidth}>
	<!-- role="slider": the focused plot selects one point in time,
	     which is what the arrow keys move. aria-roledescription
	     keeps it announced as a chart, aria-valuetext reads out the
	     point the tooltip shows. -->
	<svg
		bind:this={svgEl}
		role="slider"
		tabindex="0"
		aria-label={label}
		aria-roledescription={t('chartUi.roleDescription')}
		aria-valuemin={0}
		aria-valuemax={Math.max(0, points.length - 1)}
		aria-valuenow={hoverIdx ?? 0}
		aria-valuetext={valueText}
		viewBox="0 0 {wrapWidth} {height}"
		preserveAspectRatio="none"
		width="100%"
		{height}
		onpointermove={handleMove}
		onpointerdown={handleMove}
		onpointerleave={handleLeave}
		onkeydown={handleKey}
		onblur={hideTooltip}
	>
		<title>{label}</title>

		{#if !hasData}
			<text
				x={PAD_L + innerWidth / 2}
				y={PAD_T + innerHeight / 2}
				class="empty-state-text"
				text-anchor="middle"
				dominant-baseline="middle"
				data-testid="chart-empty">{t('chartUi.noData')}</text
			>
		{/if}

		<!-- Y axis ticks. Drawn under the lines. -->
		{#each yTicks as t (t)}
			<line
				x1={PAD_L}
				x2={PAD_L + innerWidth}
				y1={yAt(t)}
				y2={yAt(t)}
				class="grid"
				stroke-dasharray={t === 0 ? '0' : '2 4'}
			/>
			<text
				x={PAD_L - 4}
				y={yAt(t)}
				class="axis-label"
				text-anchor="end"
				dominant-baseline="middle">{fmt(t)}</text
			>
		{/each}

		<!-- X axis time labels at start / middle / end. -->
		{#each xTicks as tick, i (i)}
			<text
				x={tick.x}
				y={height - 6}
				class="axis-label"
				text-anchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}
			>{tick.label}</text>
		{/each}

		<!-- One <path> per non-null segment. Null gaps in the
		     data → gaps in the visual line. AC #5. -->
		{#each segments as seg, i (i)}
			<path
				d={pathD(seg)}
				fill="none"
				stroke={color}
				stroke-width="1.5"
				stroke-linecap="round"
				stroke-linejoin="round"
			/>
		{/each}

		<!-- Hover overlay: vertical guide line + focus dot +
		     small tooltip. Rendered last so it sits on top. -->
		{#if tooltip}
			<line
				x1={tooltip.x}
				x2={tooltip.x}
				y1={PAD_T}
				y2={PAD_T + innerHeight}
				class="guide"
			/>
			{#if tooltip.hasValue && points[hoverIdx!].value !== null}
				<circle
					cx={tooltip.x}
					cy={yAt(points[hoverIdx!].value as number)}
					r="3"
					fill={color}
				/>
			{/if}
			<g
				class="tooltip"
				transform="translate({Math.min(tooltip.x + 8, wrapWidth - PAD_R - 90)}, {PAD_T + 4})"
				data-testid="chart-tooltip"
			>
				<rect width="86" height="32" rx="3" />
				<text x="6" y="13" class="tooltip-ts">{tooltip.tsLabel}</text>
				<text x="6" y="26" class="tooltip-val">{tooltip.valueLabel}</text>
			</g>
		{/if}
	</svg>
</div>

<style>
	.chart-wrap {
		width: 100%;
	}
	/* A sideways drag reads the points; a vertical one still
	   scrolls the page. Without it the browser claims every touch
	   for panning and cancels the pointer after the first move. */
	svg {
		touch-action: pan-y;
	}
	.grid {
		stroke: var(--text-muted);
		stroke-width: 1;
		opacity: 0.35;
	}
	.guide {
		stroke: var(--text-secondary);
		stroke-width: 1;
		stroke-dasharray: 2 3;
		opacity: 0.6;
		pointer-events: none;
	}
	.axis-label {
		font-size: 10px;
		fill: var(--text-secondary);
		font-family: var(--font-mono, monospace);
	}
	.empty-state-text {
		font-size: 11px;
		fill: var(--text-muted);
		font-style: italic;
	}
	.tooltip rect {
		fill: var(--bg-elevated);
		stroke: var(--text-muted);
		stroke-width: 0.5;
		opacity: 0.95;
		pointer-events: none;
	}
	.tooltip-ts {
		font-size: 10px;
		fill: var(--text-secondary);
		font-family: var(--font-mono, monospace);
	}
	.tooltip-val {
		font-size: 11px;
		font-weight: 600;
		fill: var(--text-primary);
		font-family: var(--font-mono, monospace);
	}
</style>
