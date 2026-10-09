// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.5 — WorldMap component tests.
//
// jsdom doesn't implement <svg> layout (getBBox returns
// zeros) and skips the D3 path render that depends on
// SVGMatrix. We assert on:
//   - the SVG element + ocean rect + countries <g> are
//     mounted;
//   - the fetch URL for the TopoJSON is hit with the
//     default path AND a custom prop override;
//   - the marker <g> appears when arenetLat/Lon are
//     supplied and is ABSENT in the null-position case
//     (V.5 degraded-mode path).
//
// The actual country paths are inserted by D3 in an
// $effect; jsdom can't render them visually but we can
// observe the path elements in the DOM after a topojson
// fetch resolves.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import WorldMap from './WorldMap.svelte';
import { CATEGORY_DASHES } from './categoryColors';

// A minimal TopoJSON fixture with one synthetic country
// covering ~0..10 degrees — enough to drive feature() +
// path() through their happy paths without bundling the
// 700+ KB real world-atlas asset into the test environment.
const FIXTURE_TOPOJSON = {
	type: 'Topology',
	arcs: [
		[
			[0, 0],
			[10000, 0],
			[0, 10000],
			[-10000, 0]
		]
	],
	transform: {
		scale: [0.001, 0.001],
		translate: [0, 0]
	},
	objects: {
		countries: {
			type: 'GeometryCollection',
			geometries: [
				{
					type: 'Polygon',
					arcs: [[0]],
					properties: { name: 'Atlantis' }
				}
			]
		}
	}
};

beforeEach(() => {
	vi.restoreAllMocks();
});

function mockTopoJSONFetch() {
	return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input: RequestInfo | URL) => {
		const url = typeof input === 'string' ? input : input.toString();
		void url;
		return new Response(JSON.stringify(FIXTURE_TOPOJSON), {
			status: 200,
			headers: { 'Content-Type': 'application/json' }
		});
	});
}

describe('WorldMap', () => {
	it('mounts the SVG container + ocean rect + countries group', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { arenetLat: 48.8566, arenetLon: 2.3522 });
		expect(screen.getByTestId('worldmap-container')).toBeInTheDocument();
		expect(screen.getByTestId('worldmap-countries')).toBeInTheDocument();
		// The SVG element itself is reachable via the role.
		expect(screen.getByRole('img')).toBeInTheDocument();
	});

	it('fetches the default /world-50m.topo.json URL on mount', async () => {
		const fetchSpy = mockTopoJSONFetch();
		render(WorldMap, { arenetLat: 0, arenetLon: 0 });
		await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
		const calledWith = fetchSpy.mock.calls[0][0];
		expect(String(calledWith)).toBe('/world-50m.topo.json');
	});

	it('honors the topojsonUrl prop override', async () => {
		const fetchSpy = mockTopoJSONFetch();
		render(WorldMap, { props: {
			arenetLat: 0,
			arenetLon: 0,
			topojsonUrl: '/test-fixtures/tiny-world.topo.json'
		} });
		await waitFor(() => expect(fetchSpy).toHaveBeenCalled());
		expect(String(fetchSpy.mock.calls[0][0])).toBe('/test-fixtures/tiny-world.topo.json');
	});

	it('renders the marker when arenet lat/lon are supplied', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { props: {
			arenetLat: 48.8566,
			arenetLon: 2.3522,
			city: 'Paris',
			country: 'FR'
		} });
		expect(screen.getByTestId('worldmap-marker')).toBeInTheDocument();
	});

	it('renders the city, country label and the manual badge', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { props: {
			arenetLat: 45.764,
			arenetLon: 4.8357,
			city: 'Lyon',
			country: 'FR',
			mode: 'manual'
		} });
		const marker = screen.getByTestId('worldmap-marker');
		expect(marker.textContent ?? '').toContain('Lyon');
		expect(marker.textContent ?? '').toContain('FR');
		expect(marker.textContent ?? '').toContain('(manuel)');
	});

	it('omits the (manuel) badge when mode is "auto"', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { props: {
			arenetLat: 48.8566,
			arenetLon: 2.3522,
			city: 'Paris',
			country: 'FR',
			mode: 'auto'
		} });
		const marker = screen.getByTestId('worldmap-marker');
		expect(marker.textContent ?? '').not.toContain('(manuel)');
	});

	it('does NOT render the marker when arenetLat is null (degraded mode)', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { arenetLat: null, arenetLon: null });
		expect(screen.queryByTestId('worldmap-marker')).toBeNull();
	});

	it('surfaces a fetch failure as a visible error banner', async () => {
		vi.spyOn(globalThis, 'fetch').mockResolvedValue(
			new Response('not found', { status: 404 })
		);
		render(WorldMap, { arenetLat: 0, arenetLon: 0 });
		await waitFor(() => {
			expect(screen.getByRole('alert').textContent ?? '').toMatch(/Carte indisponible/);
		});
	});

	it('uses width/height props for the viewBox', async () => {
		mockTopoJSONFetch();
		render(WorldMap, { width: 800, height: 400, arenetLat: 0, arenetLon: 0 });
		const svg = screen.getByRole('img') as unknown as SVGSVGElement;
		expect(svg.getAttribute('viewBox')).toBe('0 0 800 400');
	});
});

// -------------------------------------------------------
// Step V.6 — arc rendering tests.
//
// jsdom can't run the d3.timer (it depends on
// requestAnimationFrame which jsdom shims as setTimeout,
// but the timer drives a $state mutation that needs Svelte
// to flush). We assert at the level we CAN: passing
// `events` triggers an arcs <g> with the right number of
// children, LAN events skip spawn, and a category color
// makes it onto the rendered path's data-attribute.

import type { GeoEvent } from '$lib/api/types';

function mkEvent(overrides: Partial<GeoEvent> = {}): GeoEvent {
	return {
		timestamp: '2026-06-07T10:00:00.000Z',
		category: 'waf',
		sourceIp: '203.0.113.42',
		sourceLat: 51.5074,
		sourceLon: -0.1278,
		sourceCountry: 'GB',
		sourceCity: 'London',
		isLan: false,
		details: 'rule-942100',
		...overrides
	};
}

describe('WorldMap — V.6 arc layer', () => {
	it('mounts the arcs <g> layer between countries and marker', () => {
		mockTopoJSONFetch();
		render(WorldMap, { arenetLat: 48.8566, arenetLon: 2.3522 });
		expect(screen.getByTestId('worldmap-arcs')).toBeInTheDocument();
	});

	it('spawns one arc path per non-LAN event with finite source coords', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [
					mkEvent({ category: 'waf', sourceLat: 51.5074, sourceLon: -0.1278 }),
					mkEvent({ category: 'auth', sourceLat: 35.6762, sourceLon: 139.6503 })
				]
			}
		});
		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(2);
		});
	});

	it('skips LAN events (isLan=true)', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [
					mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0, sourceCountry: 'UNK' }),
					mkEvent({ category: 'waf' })
				]
			}
		});
		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(1);
		});
	});

	it('skips events with zero lat/lon (UNK geo)', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [
					mkEvent({ sourceLat: 0, sourceLon: 0, sourceCountry: 'UNK' }),
					mkEvent({ category: 'auth', sourceLat: 35.6762, sourceLon: 139.6503 })
				]
			}
		});
		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(1);
		});
	});

	it('does not spawn arcs when Arenet position is null (degraded)', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: null,
				arenetLon: null,
				events: [mkEvent(), mkEvent({ category: 'crowdsec' })]
			}
		});
		// Give the $effect a tick to run.
		await new Promise((r) => setTimeout(r, 10));
		const arcs = screen.getByTestId('worldmap-arcs');
		expect(arcs.querySelectorAll('path').length).toBe(0);
	});

	it('attaches a data-category attribute matching the event category', async () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [mkEvent({ category: 'crowdsec' })]
			}
		});
		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			const path = arcs.querySelector('path');
			expect(path?.getAttribute('data-category')).toBe('crowdsec');
		});
	});

	it.each(['normal', 'throttle', 'waf', 'crowdsec', 'auth'] as const)(
		'renders an arc with a category-colored stroke for %s',
		async (category) => {
			mockTopoJSONFetch();
			render(WorldMap, {
				props: {
					arenetLat: 48.8566,
					arenetLon: 2.3522,
					events: [mkEvent({ category })]
				}
			});
			await waitFor(() => {
				const arcs = screen.getByTestId('worldmap-arcs');
				const path = arcs.querySelector('path');
				// Inline stroke attribute carries the CSS var
				// reference — pinned in categoryColors.test.ts.
				expect(path?.getAttribute('stroke') ?? '').toMatch(/^var\(--[a-z-]+\)$/);
			});
		}
	);
});

// -------------------------------------------------------
// Step V.8.HF1 — tick-driven re-render regression test.
//
// The visible bug v1.4.0-step-v shipped with: arcs spawned
// with progress=0 and stayed collapsed at the source pixel
// until the ARC_TOTAL_MS prune finally mutated the arcs
// array, at which point the path "snapped" to the full
// Bezier just before the fade-out. Root cause: relying
// solely on `clockMs = t` to drive the {#each arcs} body
// to re-evaluate per frame. The fix introduces an explicit
// `tick` $state bumped per d3.timer firing, read in the
// template via {@const _tick = tick} so Svelte's per-arc
// {#each} block subscribes to the tick.
//
// Test approach: drive the rAF loop via vitest's fake
// timers (jsdom shims requestAnimationFrame as setTimeout,
// so vi.useFakeTimers + vi.advanceTimersByTime advances
// d3.timer's internal clock). Assert that the path's `d`
// attribute changes between the initial spawn frame
// (progress=0 → path collapsed at source) and a later
// frame (progress>0 → path extends toward the target).

describe('WorldMap — V.8.HF2 TopoJSON load gating', () => {
	// V.8.HF2 regression: arcs MUST NOT spawn before the
	// countries layer is painted. Operator video review
	// surfaced replay arcs animating against a blank black
	// background while the TopoJSON was still parsing
	// (~500-1000 ms on cold load), with the countries
	// "snapping in" around already-moving arcs
	// (#R-MAP-arc-load-race). The fix gates the spawn
	// $effect on `countries !== null`; the test mocks a
	// slow TopoJSON fetch and asserts: 0 arcs while the
	// fetch is pending, then arcs spawn the moment the
	// fetch resolves.
	it('buffers events until TopoJSON loads, then spawns them all', async () => {
		let resolveFetch: (resp: Response) => void = () => {};
		const fetchPromise = new Promise<Response>((resolve) => {
			resolveFetch = resolve;
		});
		vi.spyOn(globalThis, 'fetch').mockReturnValue(fetchPromise);

		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [
					mkEvent({ category: 'waf', sourceLat: 51.5074, sourceLon: -0.1278 }),
					mkEvent({ category: 'auth', sourceLat: 35.6762, sourceLon: 139.6503 })
				]
			}
		});

		// Give Svelte a tick to run the spawn effect against
		// the still-pending TopoJSON. Arcs MUST be empty.
		await new Promise((r) => setTimeout(r, 30));
		expect(screen.getByTestId('worldmap-arcs').querySelectorAll('path').length).toBe(0);

		// Resolve the fetch — countries lands, the spawn
		// effect re-fires, the buffered events spawn.
		resolveFetch(
			new Response(JSON.stringify(FIXTURE_TOPOJSON), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			})
		);

		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(2);
		});
	});
});

describe('WorldMap — V.8.HF1 tick-driven re-render', () => {
	// Why this test uses the component's _setNowForTest +
	// _tickForTest seam instead of vi.useFakeTimers:
	//
	// d3-timer captures `clock = performance` (the object,
	// not the function) and `setFrame = window.requestAnimationFrame.bind(window)`
	// at MODULE LOAD time (d3-timer/src/timer.js:10-11).
	// WorldMap.svelte imports d3 at the top of the test
	// file, BEFORE vi.useFakeTimers runs in beforeEach.
	// vitest's fake-timers patches the GLOBAL bindings but
	// d3 already holds the originals, so:
	//   - d3.now() returns wall-clock time (probe: faked
	//     performance.now advances 500ms, d3.now advances 0ms)
	//   - the d3.timer rAF chain runs against the real (or
	//     jsdom-shimmed-as-setTimeout) loop that vitest's
	//     mock rAF doesn't see, so the d3.timer callback
	//     never fires (probe: samples array stays empty)
	//
	// Symptoms of the bug we're avoiding: the `d` attribute
	// observed initial-vs-later was identical because the
	// d3.timer callback never advanced `clockMs` / `tick`
	// inside the component. Previous fix b0521e0 added
	// 'performance' to toFake — necessary but insufficient,
	// for the reasons above. We can't relocate the d3 import
	// without forking d3-timer (it caches at module top
	// level), so the deterministic path is: bypass d3.timer
	// entirely in the test, drive the frame body directly via
	// the component's _tickForTest seam. nowFn is a
	// monotonic counter we own, so `clockMs - arc.startMs`
	// crosses ARC_TRAVEL_MS predictably and the bezier head
	// extends past the source.
	it('updates the path d-attribute as the tick advances (no spawn-snap)', async () => {
		mockTopoJSONFetch();
		// Test clock: starts at a non-zero baseline so the
		// component's startMs (captured during spawn) and our
		// monotonic counter sit on the same scale. We bump
		// `testNow` between _tickForTest calls to simulate
		// time passing — completely independent of d3-timer
		// and vitest's fake-timer state.
		let testNow = 1_000_000;
		const { component } = render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [mkEvent({ sourceLat: 51.5074, sourceLon: -0.1278 })]
			}
		});
		component._setNowForTest(() => testNow);

		// Wait for the TopoJSON fetch + initial spawn.
		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(1);
		});

		// First frame: capture the spawn-shape `d` (progress
		// near 0 — the bezier head is collapsed at source).
		component._tickForTest();
		// Let Svelte flush the reactive update.
		await new Promise((r) => setTimeout(r, 0));
		const arcsLayer = screen.getByTestId('worldmap-arcs');
		const initialPath = arcsLayer.querySelector('path');
		const initialD = initialPath?.getAttribute('d') ?? '';
		expect(initialD).toMatch(/^M /);

		// Advance the test clock past half of ARC_TRAVEL_MS
		// (ARC_TRAVEL_MS = 1800ms; we jump 900ms to land
		// solidly mid-flight). Then run one more frame so
		// runFrame() reads the new testNow → clockMs jumps →
		// arcProgressAt returns progress > 0 → bezierAt
		// projects the head along the curve → the path's `d`
		// string changes shape.
		testNow += 900;
		component._tickForTest();
		await new Promise((r) => setTimeout(r, 0));

		const laterPath = screen.getByTestId('worldmap-arcs').querySelector('path');
		const laterD = laterPath?.getAttribute('d') ?? '';
		expect(laterD).not.toBe(initialD);
	});
});

// -------------------------------------------------------
// Not colour alone, and not sight alone.
//
// An arc's category was carried only by its stroke hue:
// normal (green) and waf (red) collapse for a deuteranope,
// crowdsec and auth are near-identical blues for everyone.
// Each category now also has a dash pattern. And the arcs,
// moving lines inside an svg role="img", had no text
// alternative at all: a visually hidden list now states the
// recent events as category + country.

describe('WorldMap — category beyond colour', () => {
	it.each(['normal', 'throttle', 'waf', 'crowdsec', 'auth', 'country_block'] as const)(
		'draws a %s arc with its category dash pattern',
		async (category) => {
			mockTopoJSONFetch();
			render(WorldMap, {
				props: {
					arenetLat: 48.8566,
					arenetLon: 2.3522,
					events: [mkEvent({ category })]
				}
			});
			await waitFor(() => {
				const path = screen.getByTestId('worldmap-arcs').querySelector('path');
				expect(path?.getAttribute('stroke-dasharray')).toBe(CATEGORY_DASHES[category]);
			});
		}
	);
});

describe('WorldMap — text alternative for the arcs', () => {
	it('lists recent events as category and country, newest first', () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [
					mkEvent({ category: 'auth', sourceCountry: 'JP' }),
					mkEvent({ category: 'waf', sourceCountry: 'GB' })
				]
			}
		});
		const items = within(screen.getByTestId('worldmap-recent-events')).getAllByRole('listitem');
		expect(items).toHaveLength(2);
		// Newest (the last appended) first.
		expect(items[0].getAttribute('data-category')).toBe('waf');
		expect(items[0].textContent ?? '').toMatch(/WAF/);
		expect(items[0].textContent ?? '').toMatch(/United Kingdom|GB/);
		expect(items[1].getAttribute('data-category')).toBe('auth');
		expect(items[1].textContent ?? '').toMatch(/Japan|JP/);
	});

	it('names the list for assistive technology', () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: { arenetLat: 48.8566, arenetLon: 2.3522, events: [mkEvent()] }
		});
		const list = within(screen.getByTestId('worldmap-recent-events')).getByRole('list');
		expect(list.getAttribute('aria-label') ?? '').not.toBe('');
	});

	it('leaves out what the map does not draw (LAN, unplaced sources)', () => {
		mockTopoJSONFetch();
		render(WorldMap, {
			props: {
				arenetLat: 48.8566,
				arenetLon: 2.3522,
				events: [
					mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0, sourceCountry: 'UNK' }),
					mkEvent({ sourceLat: 0, sourceLon: 0, sourceCountry: 'UNK' }),
					mkEvent({ category: 'crowdsec', sourceCountry: 'DE' })
				]
			}
		});
		const items = within(screen.getByTestId('worldmap-recent-events')).getAllByRole('listitem');
		expect(items).toHaveLength(1);
		expect(items[0].getAttribute('data-category')).toBe('crowdsec');
	});

	it('says so when there is nothing to list', () => {
		mockTopoJSONFetch();
		render(WorldMap, { arenetLat: 48.8566, arenetLon: 2.3522 });
		const box = screen.getByTestId('worldmap-recent-events');
		expect(within(box).queryByRole('list')).toBeNull();
		expect((box.textContent ?? '').trim()).not.toBe('');
	});
});
