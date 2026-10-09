<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Phase 5 — Multi-series timeline chart for the dashboard's cert
lifecycle panel.

Mirrors the TimelineChart raw-SVG approach (no d3 import — see
TimelineChart.svelte header for the bundle-size rationale). The
chart paints N independent lines on a shared (x = time, y =
count) plane with:
  - N-line legend with click-to-toggle visibility
  - shared hover tooltip showing the bucket date + per-series
    value
  - 3-tick y axis (0, ½ max, max) anchored on the combined
    max across all visible series
  - 3-tick x axis (first, mid, last bucketStart)

Designed for reuse: the cert dashboard ships first today, the
Phase 6 alerting view will likely call the same component with
different series for rule-trigger histories. Keep props
generic — series.key indexes into each data row, not just
{issued, renewed, failed}.

Data shape (consumer's responsibility): an array of records,
each with a `bucketStart` ISO timestamp + one numeric value
per series key. Empty buckets ARE expected (server emits a
continuous timeline); zero-value buckets render flat at the
baseline.

The tooltip follows any pointer (mouse, pen, finger) and the
keyboard: the plot is focusable, Left/Right step through the
buckets, Home/End jump to the ends, Escape hides it.
-->

<script lang="ts">
	// Aliased: the template iterates its y-axis ticks as `t`.
	import { t as translate } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { t } from '$lib/i18n';
	import { chartKeyStep } from '$lib/utils/chart-keys';
	import { chartDay, chartDayTime } from '$lib/utils/chart-time';

	// Phase 5 — the generic constraint we'd like to express is
	// "T extends { bucketStart: string } AND key ∈ keyof T",
	// but Svelte's `generics=` declaration doesn't currently
	// flow T through to the test harness's render() call (the
	// inferred T collapses to {bucketStart: string} alone,
	// rejecting issued/renewed/failed keys). The implementation
	// never relies on a per-key type narrowing, only on
	// runtime string indexing, so we accept the looser shape:
	// `bucketStart` is still required on rows for the x-axis
	// math, and additional numeric columns are read via
	// `row[s.key]`. Consumers retain full type safety in their
	// own scope (the dashboard's certBuckets is fully typed
	// CertEventBucket).
	interface DataRow {
		bucketStart: string;
		[key: string]: unknown;
	}

	interface SeriesDef {
		/** Property key in each data row. */
		key: string;
		/** Operator-readable label rendered in the legend + tooltip. */
		label: string;
		/** CSS var reference (e.g. 'var(--status-up)'). */
		color: string;
	}

	interface Props {
		data: DataRow[];
		series: SeriesDef[];
		/** Operator-readable label for screen readers + <title>. */
		label: string;
		/** Optional explicit height. Default 200px (taller than
		    single-series TimelineChart so the multi-line story
		    has visual room without crowding). */
		height?: number;
		/** Optional formatter for tooltip values. Default rounds
		    to nearest integer. */
		formatValue?: (v: number) => string;
		/**
		 * Treat a null / missing value as a BREAK in the line rather
		 * than as zero. Opt-in, default false.
		 *
		 * The two readings are both legitimate and the caller is the
		 * only one who knows which applies. For a count, a bucket with
		 * no row genuinely saw zero events, and drawing it at zero is
		 * the truth. For a latency, zero is a claim that the route
		 * answered instantly — so a bucket with no measurement must
		 * leave a hole, or the chart dips to "instant" exactly where it
		 * knows least.
		 *
		 * Added opt-in rather than changed outright because the
		 * existing caller (the dashboard's certificate lifecycle) plots
		 * counts, where the current behaviour is correct.
		 */
		nullAsGap?: boolean;
	}

	let { data, series, label, height = 200, formatValue, nullAsGap = false }: Props = $props();

	/** Raw value for a row/series, or null when there is nothing to
	 *  plot. Only nullAsGap callers can receive null — everyone else
	 *  keeps the zero-coercion they were written against. */
	function valueAt(i: number, key: string): number | null {
		const raw = data[i][key];
		if (nullAsGap && (raw === null || raw === undefined)) return null;
		return Number(raw ?? 0);
	}

	const PAD_L = 36;
	const PAD_R = 12;
	const PAD_T = 8;
	const PAD_B = 22;

	let wrapWidth = $state(640);
	let svgEl: SVGSVGElement | undefined = $state();
	let hoverIdx = $state<number | null>(null);

	// Track which series the operator has toggled OFF. Clicking
	// a legend item flips its presence in this set; the chart
	// re-renders without that series' line + the max-recompute
	// rescales the y axis to the still-visible series. Default:
	// every series visible.
	let hidden = $state<Set<string>>(new Set());

	function toggleSeries(key: string): void {
		const next = new Set(hidden);
		if (next.has(key)) {
			next.delete(key);
		} else {
			next.add(key);
		}
		hidden = next;
	}

	const innerWidth = $derived(Math.max(50, wrapWidth - PAD_L - PAD_R));
	const innerHeight = $derived(Math.max(40, height - PAD_T - PAD_B));

	const visibleSeries = $derived(series.filter((s) => !hidden.has(s.key)));

	// Combined max across every visible series in every bucket.
	// Fallback to 1 so the y axis is well-defined on an all-zero
	// or all-hidden window.
	const maxVal = $derived.by(() => {
		let m = 0;
		for (const s of visibleSeries) {
			for (let i = 0; i < data.length; i++) {
				const v = valueAt(i, s.key);
				if (v !== null && v > m) m = v;
			}
		}
		return m === 0 ? 1 : m;
	});

	const hasData = $derived(
		visibleSeries.length > 0 &&
			data.some((_, i) =>
				visibleSeries.some((s) => {
					const v = valueAt(i, s.key);
					return v !== null && v > 0;
				})
			)
	);

	function xAt(i: number): number {
		if (data.length <= 1) return PAD_L;
		return PAD_L + (i / (data.length - 1)) * innerWidth;
	}
	function yAt(v: number): number {
		return PAD_T + innerHeight - (v / maxVal) * innerHeight;
	}

	function pathDFor(s: SeriesDef): string {
		if (data.length === 0) return '';
		if (data.length === 1) {
			const v = valueAt(0, s.key);
			if (v === null) return '';
			const x = xAt(0);
			const y = yAt(v);
			return `M ${x - 1} ${y} L ${x + 1} ${y}`;
		}
		let d = '';
		// `penDown` restarts the path after every gap, so the line
		// breaks instead of being drawn straight across a stretch
		// where nothing was measured. Interpolating across it would
		// invent the one thing the gap exists to say.
		let penDown = false;
		for (let i = 0; i < data.length; i++) {
			const v = valueAt(i, s.key);
			if (v === null) {
				penDown = false;
				continue;
			}
			const x = xAt(i);
			const y = yAt(v);
			d += penDown ? ` L ${x} ${y}` : ` M ${x} ${y}`;
			penDown = true;
		}
		return d.trim();
	}

	const fmt = $derived(formatValue ?? ((v: number) => String(Math.round(v))));

	const yTicks = $derived([0, maxVal / 2, maxVal]);

	const xTicks = $derived.by(() => {
		if (data.length === 0) return [] as { x: number; label: string }[];
		const fmtTs = (d: Date) => chartDay(d);
		const midIdx = Math.floor(data.length / 2);
		return [
			{ x: xAt(0), label: fmtTs(new Date(data[0].bucketStart)) },
			{ x: xAt(midIdx), label: fmtTs(new Date(data[midIdx].bucketStart)) },
			{ x: xAt(data.length - 1), label: fmtTs(new Date(data[data.length - 1].bucketStart)) }
		];
	});

	// Pointer events cover mouse, pen and touch alike; pointerdown
	// makes a tap show the tooltip even when the finger does not move.
	function handleMove(e: PointerEvent): void {
		if (!svgEl || data.length === 0) return;
		const rect = svgEl.getBoundingClientRect();
		const mx = ((e.clientX - rect.left) / rect.width) * wrapWidth;
		const ratio = (mx - PAD_L) / innerWidth;
		if (ratio < 0 || ratio > 1) {
			hoverIdx = null;
			return;
		}
		const idx = Math.round(ratio * (data.length - 1));
		hoverIdx = Math.max(0, Math.min(data.length - 1, idx));
	}

	function handleLeave(e: PointerEvent): void {
		// A lifted finger fires pointerleave straight after pointerup;
		// hiding there would erase what the tap just showed. A touch
		// tooltip goes on blur (tapping elsewhere) or Escape instead.
		if (e.pointerType === 'touch') return;
		hoverIdx = null;
	}

	function handleKey(e: KeyboardEvent): void {
		const next = chartKeyStep(e.key, tooltip ? hoverIdx : null, data.length);
		if (next === undefined) return;
		e.preventDefault();
		hoverIdx = next;
	}

	function hideTooltip(): void {
		hoverIdx = null;
	}

	const tooltip = $derived.by(() => {
		// The bound check covers a poll that shortened the data
		// under a held tooltip.
		if (hoverIdx === null || hoverIdx >= data.length) return null;
		const row = data[hoverIdx];
		const d = new Date(row.bucketStart);
		// Tooltip shows date only if every bucket starts at
		// midnight (daily granularity); otherwise add the time.
		const sameTime = data.every((r) => {
			const t = new Date(r.bucketStart);
			return t.getHours() === 0 && t.getMinutes() === 0;
		});
		const tsLabel = sameTime ? chartDay(d) : chartDayTime(d);
		// Captured so the narrowing from the hoverIdx === null guard
		// above survives into the closure.
		const idx = hoverIdx;
		const rows = visibleSeries.map((s) => {
			const v = valueAt(idx, s.key);
			return {
				key: s.key,
				label: s.label,
				color: s.color,
				// An em dash, not "0". The tooltip is where an
				// operator looks to confirm what the gap in the line
				// means, so it has to say the same thing the gap does.
				value: v === null ? '—' : fmt(v)
			};
		});
		return { x: xAt(hoverIdx), tsLabel, rows };
	});

	// What a screen reader hears for the focused plot: the bucket the
	// tooltip shows with every visible series, or how to reach one.
	const valueText = $derived(
		tooltip
			? t('chartUi.pointValue', {
					time: tooltip.tsLabel,
					value: tooltip.rows
						.map((r) => t('chartUi.seriesValue', { label: r.label, value: r.value }))
						.join(', ')
				})
			: t('chartUi.keyboardHint')
	);
</script>

<div class="chart-card">
	<!-- Legend row above the chart. Buttons act as toggles so
	     keyboard nav lights them up the same as click. The
	     role=group wrapping signals "related controls" without
	     forcing the listitem role onto each <button> (which
	     loses native button semantics). -->
	<div class="legend" role="group" aria-label={t('chartUi.legend', { label })}>
		{#each series as s (s.key)}
			{@const isHidden = hidden.has(s.key)}
			<button
				type="button"
				class="legend-item"
				class:hidden={isHidden}
				onclick={() => toggleSeries(s.key)}
				data-testid="legend-toggle-{s.key}"
				aria-pressed={!isHidden}
			>
				<span class="legend-swatch" style:background-color={s.color}></span>
				<span class="legend-label">{s.label}</span>
			</button>
		{/each}
	</div>

	<div class="chart-wrap" bind:clientWidth={wrapWidth}>
		<!-- role="slider": the focused plot selects one bucket, which
		     is what the arrow keys move. aria-roledescription keeps it
		     announced as a chart, aria-valuetext reads out the bucket
		     the tooltip shows. -->
		<svg
			bind:this={svgEl}
			role="slider"
			tabindex="0"
			aria-label={label}
			aria-roledescription={t('chartUi.roleDescription')}
			aria-valuemin={0}
			aria-valuemax={Math.max(0, data.length - 1)}
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
					dominant-baseline="middle">{t('chartUi.noEvents')}</text
				>
			{/if}

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

			{#each xTicks as tick, i (i)}
				<text
					x={tick.x}
					y={height - 6}
					class="axis-label"
					text-anchor={i === 0 ? 'start' : i === xTicks.length - 1 ? 'end' : 'middle'}
					>{tick.label}</text
				>
			{/each}

			<!-- One path per visible series. Hidden series simply
			     don't emit a path — the legend toggle re-renders
			     without them. -->
			{#each visibleSeries as s (s.key)}
				<path
					d={pathDFor(s)}
					fill="none"
					stroke={s.color}
					stroke-width="1.5"
					stroke-linecap="round"
					stroke-linejoin="round"
					data-testid="series-path-{s.key}"
				/>
			{/each}

			{#if tooltip}
				<line
					x1={tooltip.x}
					x2={tooltip.x}
					y1={PAD_T}
					y2={PAD_T + innerHeight}
					class="guide"
				/>
				{#each visibleSeries as s (s.key)}
					{@const v = Number(data[hoverIdx!][s.key] ?? 0)}
					<circle cx={tooltip.x} cy={yAt(v)} r="3" fill={s.color} />
				{/each}
				<g
					class="tooltip"
					transform="translate({Math.min(
						tooltip.x + 8,
						wrapWidth - PAD_R - 110
					)}, {PAD_T + 4})"
					data-testid="chart-tooltip"
				>
					<rect width="106" height={18 + tooltip.rows.length * 14} rx="3" />
					<text x="6" y="13" class="tooltip-ts">{tooltip.tsLabel}</text>
					{#each tooltip.rows as row, i (row.key)}
						<g transform="translate(6, {24 + i * 14})">
							<circle cx="3" cy="-3" r="3" fill={row.color} />
							<text x="11" y="0" class="tooltip-label">{row.label}</text>
							<text x="100" y="0" class="tooltip-val" text-anchor="end">{row.value}</text>
						</g>
					{/each}
				</g>
			{/if}
		</svg>
	</div>
</div>

<style>
	.chart-card {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.legend {
		display: flex;
		flex-wrap: wrap;
		gap: 12px;
		font-size: 11px;
	}
	.legend-item {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		background: transparent;
		border: none;
		padding: 2px 4px;
		cursor: pointer;
		color: var(--text-secondary);
		font-family: inherit;
		font-size: inherit;
		border-radius: 3px;
		transition: opacity 120ms;
	}
	.legend-item:hover {
		color: var(--text-primary);
	}
	.legend-item.hidden {
		opacity: 0.4;
	}
	.legend-item.hidden .legend-swatch {
		background: var(--text-muted) !important;
	}
	.legend-swatch {
		display: inline-block;
		width: 10px;
		height: 10px;
		border-radius: 2px;
	}
	.chart-wrap {
		width: 100%;
	}
	/* A sideways drag reads the buckets; a vertical one still
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
		font-weight: 600;
		fill: var(--text-secondary);
		font-family: var(--font-mono, monospace);
	}
	.tooltip-label {
		font-size: 10px;
		fill: var(--text-secondary);
		font-family: var(--font-mono, monospace);
	}
	.tooltip-val {
		font-size: 10px;
		font-weight: 600;
		fill: var(--text-primary);
		font-family: var(--font-mono, monospace);
	}
</style>
