<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V.5 — Mercator world map + Arenet position marker.

  Renders the world-atlas TopoJSON via D3's geoMercator
  projection, centered on the Arenet server's position
  (props arenetLat / arenetLon). The marker is INLINED into
  this component rather than split out so it shares the
  projection scope — projecting (lat, lon) → (x, y) requires
  the same d3.geoMercator instance the country paths use, and
  passing the projection as a prop between sibling
  components is more friction than the encapsulation buys.

  Architecture:
    - svg is bound from Svelte; D3 only mutates the
      <g class="countries"> + <g class="marker"> children.
      The marker uses a Svelte-managed <g> instead of D3-
      mutated SVG so reactive props (city, country, mode)
      update cleanly without re-running render().
    - The projection is recomputed whenever width / height /
      arenetLat / arenetLon change, then countries re-paint
      and the projected marker pixel position recomputes via
      a $derived expression.
    - viewBox + preserveAspectRatio="xMidYMid meet" make the
      SVG responsive within its container while keeping the
      Mercator aspect ratio honest.

  V.6 will mount an arc layer inside this same <svg> (one
  per geo event) so the arcs share the projection. The
  current API is forward-compatible: V.6 just adds a
  <Snippet /> children prop receiving the projection
  function.

  V.5 category colors (locked here for V.6 reuse):
    - normal:   --status-up    (oklch ~72% 0.16 150 — green)
    - throttle: --status-warn  (oklch ~80% 0.14 85  — amber)
    - waf:      --status-down  (oklch ~66% 0.20 25  — red)
    - crowdsec: --status-down  (oklch ~66% 0.20 25  — red)
    - auth:     --status-info  (oklch ~72% 0.12 230 — cyan)
  Crowdsec and waf share the same hue intentionally — both
  are block-class decisions; the tooltip disambiguates the
  source. V.6 may split them via opacity or pattern if the
  visual ambiguity proves confusing in smoke.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import * as d3 from 'd3';
	import { feature } from 'topojson-client';
	import type { GeoProjection, GeoPath } from 'd3-geo';
	import type { Topology } from 'topojson-specification';
	import type { Feature, FeatureCollection, Geometry } from 'geojson';
	import type { GeoEvent } from '$lib/api/types';
	import { CATEGORY_COLORS } from './categoryColors';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		ARC_TOTAL_MS,
		ARC_TRAVEL_MS,
		arcControl,
		arcPathAt,
		arcProgressAt,
		bezierAt
	} from './arcMath';
	// ARC_TRAVEL_MS is imported for symmetry with the
	// timing-constant docblock below; suppress the
	// unused-import lint without removing the explicit
	// reference (a future caller may grep for the constant
	// and expect to see it imported alongside).
	void ARC_TRAVEL_MS;

	interface Props {
		/** Width of the SVG viewBox in pixels (default 1200). */
		width?: number;
		/** Height of the SVG viewBox in pixels (default 600). */
		height?: number;
		/**
		 * Arenet latitude — when null the map centers on the
		 * world (lat=20° for a balanced Mercator) and no
		 * marker is rendered. V.5 callers pass nullable to
		 * cover the degraded-mode case (no MMDB) gracefully.
		 */
		arenetLat?: number | null;
		/** Arenet longitude — see arenetLat. */
		arenetLon?: number | null;
		/** Operator-facing city label rendered next to the marker. */
		city?: string;
		/** Operator-facing country label rendered next to the marker. */
		country?: string;
		/**
		 * "auto" (V.1 ipify-then-GeoIP) or "manual" (V.4 PUT
		 * override). When "manual", a small badge appears
		 * next to the city label so the operator can tell at
		 * a glance whether they're looking at their own
		 * choice or the auto-detected default.
		 */
		mode?: 'auto' | 'manual';
		/**
		 * Optional path to the TopoJSON asset. Default points
		 * at the V.5-bundled /world-50m.topo.json (CC0
		 * world-atlas). Tests override to a fixture or mock.
		 */
		topojsonUrl?: string;
		/**
		 * Step V.6 — geo events to render as animated arcs.
		 * The component watches this array for appends and
		 * spawns a new arc per new event, scoping the spawn
		 * to indices NOT YET seen (so a replay-then-WS flow
		 * doesn't re-animate the same event on every prop
		 * update). LAN events (isLan=true) are skipped per
		 * spec §3.8 — V.7 may add a LAN counter badge.
		 *
		 * The page caps the array at 1000 entries; arcs
		 * self-prune after their travel + fade duration so
		 * the in-DOM arc count stays bounded by N events /
		 * second × ARC_TOTAL_MS.
		 */
		events?: readonly GeoEvent[];
	}

	let {
		width = 1200,
		height = 600,
		arenetLat = null,
		arenetLon = null,
		city = '',
		country = '',
		mode = 'auto',
		topojsonUrl = '/world-50m.topo.json',
		events = []
	}: Props = $props();

	let svg: SVGSVGElement | undefined = $state();
	let countries: FeatureCollection<Geometry> | null = $state(null);
	let loadError: string | null = $state(null);

	// Projection recomputes whenever its inputs change. A
	// scale of 140 gives a comfortable world view at 1200×600;
	// larger scales zoom in. The center falls back to
	// (lon=0, lat=20) when Arenet position is unknown — places
	// the equator slightly below center for a balanced view.
	const projection: GeoProjection = $derived(
		d3
			.geoMercator()
			.center([arenetLon ?? 0, arenetLat ?? 20])
			.scale(140)
			.translate([width / 2, height / 2])
	);
	const path: GeoPath = $derived(d3.geoPath(projection));

	// Projected marker pixel position. null when Arenet
	// coordinates are unknown OR when the projection clips
	// the point (off-screen). The marker <g> is skipped in
	// that case.
	const markerXY: [number, number] | null = $derived.by(() => {
		if (arenetLat === null || arenetLon === null) return null;
		const xy = projection([arenetLon, arenetLat]);
		return xy ?? null;
	});

	onMount(async () => {
		try {
			const resp = await fetch(topojsonUrl);
			if (!resp.ok) {
				throw new Error(`HTTP ${resp.status} loading ${topojsonUrl}`);
			}
			const topo = (await resp.json()) as Topology;
			// world-atlas ships `countries` as the polygon
			// feature set; `land` is a single merged outline
			// (V.5 uses countries for per-border rendering;
			// future steps can switch to `land` for a cleaner
			// silhouette).
			countries = feature(topo, topo.objects.countries) as FeatureCollection<Geometry>;
		} catch (err) {
			loadError = String(err);
			// eslint-disable-next-line no-console
			console.error('[WorldMap] failed to load TopoJSON', err);
		}
	});

	// Paint countries whenever the data or projection changes.
	// D3 handles the join + path d-attribute; Svelte just
	// hosts the <g class="countries"> root.
	$effect(() => {
		if (!svg || !countries) return;
		d3.select(svg)
			.select<SVGGElement>('g.countries')
			.selectAll<SVGPathElement, Feature<Geometry>>('path')
			.data(countries.features)
			.join('path')
			.attr('d', (d) => path(d))
			.attr('fill', 'var(--map-land, var(--bg-surface))')
			.attr('stroke', 'var(--map-border, var(--border-subtle))')
			.attr('stroke-width', 0.5);
	});

	// -------------------------------------------------------
	// Step V.6 — arc animation.
	//
	// Each incoming non-LAN event produces an ArcState whose
	// lifecycle is:
	//
	//   t=0           spawn at `source`; head + line empty
	//   t=ARC_TRAVEL  arrival at Arenet position; line fully drawn
	//   t=ARC_TOTAL   fully faded; pruned from the arcs[] array
	//
	// Timing constants tuned for the spec §3.5 "operator
	// sees the threat arriving" gut feel. 2 s travel is
	// readable without feeling sluggish on a busy attack;
	// 1.5 s fade is long enough for the eye to register a
	// just-arrived arc but short enough that overlapping
	// arcs from the same source don't pile up into a solid
	// blob. ARC_TOTAL caps the DOM-resident arc count to
	// roughly (events/sec × 3.5). Constants live in
	// arcMath.ts so the test suite can pin them without
	// rendering this component.
	//
	// Animation drive: d3.timer (which uses
	// requestAnimationFrame internally). We mutate a
	// `clockMs` $state every frame; the arcs[] array
	// references it inside reactive expressions so Svelte
	// re-renders the SVG paths at native frame rate.
	//
	// LAN events (isLan=true) are skipped per spec §3.8 —
	// the marker pulse on the Arenet position already
	// signals "you are here", and rendering LAN sources as
	// loop arcs would clutter the homelab view (where most
	// of the traffic is LAN). V.7 may add a counter badge.

	interface ArcState {
		id: number;
		event: GeoEvent;
		startMs: number;
		source: [number, number];
		target: [number, number];
	}

	let arcs: ArcState[] = $state([]);
	let clockMs = $state(0);
	// V.8.HF1 — per-frame tick counter. clockMs alone was
	// not driving the {#each arcs} body to re-evaluate
	// between spawn and prune: paths rendered with
	// progress=0 at spawn and stayed visually stuck at the
	// source point until the prune at ARC_TOTAL_MS finally
	// mutated the arcs array. Reading `tick` explicitly
	// inside the {#each} block via {@const _t = tick}
	// forces the body to re-evaluate every animation frame
	// regardless of how Svelte 5's runtime would otherwise
	// dedupe the clockMs subscription. clockMs stays for
	// the math (arcProgressAt consumes it); tick is the
	// reactivity ticket. See v1.4.0-step-v Known
	// limitations + #R-MAP-arc-spawn-glitch.
	let tick = $state(0);
	let arcIdCounter = 0;
	let nextEventIdx = 0;

	// Optional override hook for tests: lets a deterministic
	// time source (vi.fn) replace performance.now() so the
	// progress / opacity math is unit-testable without
	// faking the global clock.
	let nowFn: () => number = () => performance.now();
	// Test-only escape hatch (Svelte runes don't expose a
	// straightforward "test seam" prop, so we attach a
	// global setter the test suite can call before mount).
	// Production code MUST NOT touch this.
	export function _setNowForTest(fn: () => number) {
		nowFn = fn;
	}

	// V.8.HF1 deflake — d3.timer captures `performance` and
	// `window.requestAnimationFrame` at MODULE LOAD time (see
	// d3-timer/src/timer.js lines 10-11). vitest's
	// `useFakeTimers({ toFake: ['performance', 'requestAnimationFrame'] })`
	// replaces the GLOBAL bindings but d3 already holds the
	// original references → `d3.now()` returns wall-clock time
	// and the d3.timer rAF chain runs against the real loop
	// (or jsdom's setTimeout-shimmed loop, which vitest's fake
	// timers don't see either). Net effect: the V.8.HF1 test
	// could observe 0 progress between "spawn" and "later"
	// frames depending on real-clock jitter under -race.
	//
	// Fix: extract the per-frame body into a named function
	// the test calls DIRECTLY via _tickForTest. d3.timer
	// still drives production (where rAF + performance work
	// natively); the test bypasses the d3 timer entirely.
	// Reference: previous fix b0521e0 added 'performance' to
	// toFake — necessary but insufficient because d3 closes
	// over the original object before vitest can swap it.
	function runFrame() {
		const t = nowFn();
		clockMs = t;
		// V.8.HF1 — bump the per-frame tick so the
		// template's {#each arcs} body re-evaluates.
		// Modulo 1e9 guards against the (extremely
		// theoretical) integer-overflow case for a
		// tab left open for years at 60 fps.
		tick = (tick + 1) % 1_000_000_000;
		// Prune expired arcs. Allocate a fresh array
		// only when at least one arc is gone; otherwise
		// keep the same reference so the {#each} block
		// doesn't trigger a full re-key.
		let pruned: ArcState[] | null = null;
		for (let i = 0; i < arcs.length; i++) {
			if (t - arcs[i].startMs >= ARC_TOTAL_MS) {
				if (pruned === null) pruned = arcs.slice(0, i);
			} else if (pruned !== null) {
				pruned.push(arcs[i]);
			}
		}
		if (pruned !== null) {
			arcs = pruned;
		}
	}

	// Test-only escape hatch: drive one animation frame
	// deterministically. Used by WorldMap.test.ts §V.8.HF1
	// to bypass d3.timer's captured-at-module-load rAF +
	// performance refs. Production code MUST NOT call this.
	export function _tickForTest() {
		runFrame();
	}

	let timerHandle: ReturnType<typeof d3.timer> | null = null;

	onMount(() => {
		// d3.timer uses requestAnimationFrame internally;
		// the callback fires on every browser repaint until
		// stopped. Stop on destroy to release the rAF chain.
		timerHandle = d3.timer(runFrame);
	});

	onDestroy(() => {
		timerHandle?.stop();
		timerHandle = null;
	});

	// Watch the `events` prop for new entries beyond
	// nextEventIdx. Run inside an $effect so prop mutations
	// from the page (replay batch + per-WS-frame appends)
	// trigger spawn without double-spawning replayed events.
	//
	// V.8.HF2 — gate spawn on `countries !== null`. The
	// TopoJSON fetch + parse takes ~500-1000 ms on cold
	// load; the page's replay-then-WS pipeline routinely
	// delivered events while the map was still blank,
	// producing arcs animating against an empty black
	// background that the countries layer then "snapped
	// in" around (operator video review,
	// #R-MAP-arc-load-race).
	//
	// Reading `countries` here makes the effect re-fire
	// when the TopoJSON load resolves; nextEventIdx is
	// NOT advanced on the early-return, so accumulated
	// events spawn in one batch as soon as countries
	// becomes available. The {#each arcs} body's
	// per-tick re-render (HF1) then animates them
	// against a fully-painted map.
	$effect(() => {
		if (countries === null) {
			// TopoJSON still loading — defer spawn.
			// Subscribe to countries so the effect re-fires
			// when it lands.
			return;
		}
		if (arenetLat === null || arenetLon === null) {
			// Degraded mode — no Arenet target, no arcs.
			// Skip spawn but DON'T reset nextEventIdx so a
			// re-enable (operator placed MMDB then PUT
			// position) catches up cleanly.
			return;
		}
		if (events.length <= nextEventIdx) {
			// Either the array shrank (page-level cap
			// trimmed older entries) or no new events.
			// Realign the cursor against the new length.
			if (events.length < nextEventIdx) nextEventIdx = events.length;
			return;
		}
		const arenetXY = projection([arenetLon, arenetLat]);
		if (!arenetXY) return;

		const t = nowFn();
		const spawned: ArcState[] = [];
		for (let i = nextEventIdx; i < events.length; i++) {
			const ev = events[i];
			if (ev.isLan) continue;
			// Skip events the GeoIP enricher couldn't place
			// (UNK country, zero lat/lon). Rendering them
			// would draw an arc from the Atlantic null-
			// island — same misleading pin V.5 avoids for
			// the Arenet marker.
			if (ev.sourceLat === 0 && ev.sourceLon === 0) continue;
			const src = projection([ev.sourceLon, ev.sourceLat]);
			if (!src) continue;
			spawned.push({
				id: arcIdCounter++,
				event: ev,
				startMs: t,
				source: src,
				target: arenetXY
			});
		}
		if (spawned.length > 0) {
			arcs = [...arcs, ...spawned];
		}
		nextEventIdx = events.length;
	});

	// Reduce-motion: when the operator's OS reports
	// "prefers-reduced-motion: reduce", static arcs replace
	// the animated lifecycle. The arc is drawn fully at
	// spawn, no head dot, no fade. Pruning still runs at
	// ARC_TOTAL_MS so the SVG doesn't accumulate forever.
	let reduceMotion = $state(false);
	onMount(() => {
		if (typeof window === 'undefined' || !window.matchMedia) return;
		const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
		reduceMotion = mq.matches;
		const listener = (e: MediaQueryListEvent) => {
			reduceMotion = e.matches;
		};
		mq.addEventListener('change', listener);
		return () => mq.removeEventListener('change', listener);
	});

	// Geometry helpers live in arcMath.ts (imported above).
</script>

<div class="worldmap" data-testid="worldmap-container">
	{#if loadError}
		<div class="worldmap__error" role="alert">
			{language.current && t('map.worldMapUnavailable', { error: loadError ?? '' })}
		</div>
	{/if}
	<svg
		bind:this={svg}
		viewBox="0 0 {width} {height}"
		preserveAspectRatio="xMidYMid meet"
		class="worldmap__svg"
		role="img"
		aria-label={language.current &&
			(city || country
				? t('map.worldMapAriaCentred', { place: city || country || '' })
				: t('map.worldMapAria'))}
	>
		<!-- Ocean background — a single rect under the land. -->
		<rect
			x="0"
			y="0"
			width={width}
			height={height}
			fill="var(--map-ocean, var(--bg-base))"
		/>
		<g class="countries" data-testid="worldmap-countries"></g>
		<g class="arcs" data-testid="worldmap-arcs">
			{#each arcs as arc (arc.id)}
				{@const _tick = tick}
				{@const state = arcProgressAt(arc.startMs, clockMs)}
				{#if state.opacity > 0}
					{@const head = bezierAt(arc.source, arcControl(arc.source, arc.target), arc.target, state.progress)}
					<path
						class="arc__line"
						class:arc__line--static={reduceMotion}
						d={reduceMotion
							? arcPathAt(arc.source, arc.target, 1)
							: arcPathAt(arc.source, arc.target, state.progress)}
						stroke={CATEGORY_COLORS[arc.event.category]}
						opacity={state.opacity}
						data-category={arc.event.category}
					/>
					{#if !reduceMotion && state.progress < 1}
						<circle
							class="arc__head"
							cx={head[0]}
							cy={head[1]}
							r="2.5"
							fill={CATEGORY_COLORS[arc.event.category]}
							opacity={state.opacity}
						/>
					{/if}
				{/if}
			{/each}
		</g>
		{#if markerXY}
			<g class="marker" transform="translate({markerXY[0]}, {markerXY[1]})" data-testid="worldmap-marker">
				<!-- Pulsing halo — pure CSS animation, no JS. -->
				<circle r="10" class="marker__pulse" />
				<circle r="5" class="marker__core" />
				{#if city || country}
					<text x="12" y="-10" class="marker__label">
						{city}{#if city && country}, {/if}{country}
						{#if mode === 'manual'}
							<tspan dx="4" class="marker__badge">(manuel)</tspan>
						{/if}
					</text>
				{/if}
			</g>
		{/if}
	</svg>
</div>

<style>
	.worldmap {
		position: relative;
		width: 100%;
		background: var(--map-ocean, var(--bg-base));
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		overflow: hidden;
	}
	.worldmap__svg {
		display: block;
		width: 100%;
		height: auto;
	}
	.worldmap__error {
		position: absolute;
		top: 12px;
		left: 12px;
		right: 12px;
		padding: 10px 14px;
		background: var(--bg-surface);
		border: 1px solid var(--status-warn);
		border-radius: 6px;
		color: var(--text-primary);
		font-size: 13px;
		z-index: 1;
	}

	/* Step V.6 — arc lines. Color comes from the inline
	   stroke attribute (CATEGORY_COLORS); CSS only owns
	   stroke-width + linejoin so the per-category color
	   stays a single source of truth in categoryColors.ts.
	   The `arc__line--static` variant ships under
	   prefers-reduced-motion (no width emphasis at the
	   head, no animation). */
	.arc__line {
		fill: none;
		stroke-width: 1.4;
		stroke-linecap: round;
		stroke-linejoin: round;
		pointer-events: none;
	}
	.arc__line--static {
		stroke-width: 1.1;
	}
	.arc__head {
		pointer-events: none;
	}

	/* Marker — pulsing halo + solid core. */
	.marker__pulse {
		fill: var(--status-info);
		opacity: 0.25;
		transform-origin: center;
		transform-box: fill-box;
		animation: marker-pulse 2.2s ease-in-out infinite;
	}
	.marker__core {
		fill: var(--status-info);
		stroke: var(--bg-base);
		stroke-width: 1.5;
	}
	.marker__label {
		fill: var(--text-primary);
		font-size: 13px;
		font-weight: 600;
		paint-order: stroke fill;
		stroke: var(--bg-base);
		stroke-width: 3;
	}
	.marker__badge {
		fill: var(--text-muted);
		font-size: 11px;
		font-weight: 400;
	}

	@keyframes marker-pulse {
		0%,
		100% {
			transform: scale(0.85);
			opacity: 0.4;
		}
		50% {
			transform: scale(1.8);
			opacity: 0.1;
		}
	}

	/* Respect operator preference — reduced motion stops the
	   pulse animation but keeps the halo visible at its base
	   size so the marker is still distinguishable from a
	   plain dot. */
	@media (prefers-reduced-motion: reduce) {
		.marker__pulse {
			animation: none;
			opacity: 0.3;
		}
	}
</style>
