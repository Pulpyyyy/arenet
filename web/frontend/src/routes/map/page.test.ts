// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.5 + V.6 — /map page tests.
//
// V.5 pinned the state machine (loading / error / degraded
// / happy). V.6 adds:
//   - replay seeding via fetchGeoEventsReplay (non-fatal
//     on failure);
//   - WS lifecycle via openGeoEventStream (status pill
//     bound to the state callback);
//   - event-cap behavior under the MAX_EVENTS ceiling.
//
// We mock both `$lib/api/security` (for fetchServerPosition
// + fetchGeoEventsReplay) and `$lib/ws/geo-events-stream`
// (for openGeoEventStream). The TopoJSON fetch is stubbed
// globally so WorldMap mounts cleanly without hitting the
// real CDN.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import type { ServerPosition, GeoEvent, GeoEventsResponse } from '$lib/api/types';
import type { GeoEventStreamHandle, GeoEventStreamState } from '$lib/ws/geo-events-stream';

const fetchServerPositionMock = vi.fn<() => Promise<ServerPosition>>();
const fetchGeoEventsReplayMock = vi.fn<(limit?: number) => Promise<GeoEventsResponse>>();

vi.mock('$lib/api/security', () => ({
	fetchServerPosition: () => fetchServerPositionMock(),
	fetchGeoEventsReplay: (limit?: number) => fetchGeoEventsReplayMock(limit)
}));

// Capture the latest call to openGeoEventStream so tests
// can simulate WS events + state changes after mount.
interface StreamCapture {
	onEvent: ((e: GeoEvent) => void) | null;
	onStateChange: ((s: GeoEventStreamState) => void) | null;
	closeCalls: number;
	handle: GeoEventStreamHandle;
}
let streamCapture: StreamCapture;

vi.mock('$lib/ws/geo-events-stream', () => ({
	openGeoEventStream: (
		onEvent: (e: GeoEvent) => void,
		onStateChange?: (s: GeoEventStreamState) => void
	) => {
		streamCapture.onEvent = onEvent;
		streamCapture.onStateChange = onStateChange ?? null;
		return streamCapture.handle;
	}
}));

function makeStreamCapture(): StreamCapture {
	const cap: StreamCapture = {
		onEvent: null,
		onStateChange: null,
		closeCalls: 0,
		handle: {
			close() {
				cap.closeCalls++;
			},
			get state(): GeoEventStreamState {
				return 'connecting';
			}
		}
	};
	return cap;
}

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

beforeEach(() => {
	fetchServerPositionMock.mockReset();
	fetchGeoEventsReplayMock.mockReset();
	fetchGeoEventsReplayMock.mockResolvedValue({ events: [], total: 0 });
	streamCapture = makeStreamCapture();
	vi.spyOn(globalThis, 'fetch').mockResolvedValue(
		new Response(
			JSON.stringify({
				type: 'Topology',
				arcs: [],
				objects: { countries: { type: 'GeometryCollection', geometries: [] } }
			}),
			{ status: 200, headers: { 'Content-Type': 'application/json' } }
		)
	);
});

const { language } = await import('$lib/stores/language.svelte');
const { default: MapPage } = await import('./+page.svelte');

describe('/map page — V.5 state machine', () => {
	it('shows the loading state before the fetch resolves', () => {
		fetchServerPositionMock.mockImplementation(() => new Promise(() => {}));
		render(MapPage);
		expect(screen.getByTestId('map-loading')).toBeInTheDocument();
	});

	it('renders the WorldMap frame on the happy path', async () => {
		fetchServerPositionMock.mockResolvedValue({
			lat: 48.8566,
			lon: 2.3522,
			city: 'Paris',
			country: 'FR',
			mode: 'auto'
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.queryByTestId('map-loading')).toBeNull();
			expect(screen.getByTestId('map-frame')).toBeInTheDocument();
		});
		expect(screen.queryByTestId('map-degraded')).toBeNull();
		expect(screen.queryByTestId('map-error')).toBeNull();
	});

	it('renders the degraded banner AND the map (null coords) when degraded:true', async () => {
		fetchServerPositionMock.mockResolvedValue({
			lat: 0,
			lon: 0,
			city: '',
			country: '',
			mode: 'auto',
			degraded: true
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-degraded')).toBeInTheDocument();
		});
		expect(screen.getByTestId('map-frame')).toBeInTheDocument();
		expect(screen.queryByTestId('worldmap-marker')).toBeNull();
	});

	it('shows the error banner on fetch failure', async () => {
		fetchServerPositionMock.mockRejectedValue(new Error('HTTP 503'));
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-error')).toBeInTheDocument();
		});
		expect(screen.queryByTestId('map-frame')).toBeNull();
	});

	it('mentions ARENET_GEOIP_MMDB in the degraded banner help text', async () => {
		fetchServerPositionMock.mockResolvedValue({
			lat: 0,
			lon: 0,
			city: '',
			country: '',
			mode: 'auto',
			degraded: true
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-degraded').textContent ?? '').toContain(
				'ARENET_GEOIP_MMDB'
			);
		});
	});
});

describe('/map page — V.6 replay + WS', () => {
	const happyPosition: ServerPosition = {
		lat: 48.8566,
		lon: 2.3522,
		city: 'Paris',
		country: 'FR',
		mode: 'auto'
	};

	it('fetches the replay with REPLAY_LIMIT=500 after position resolves', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(fetchGeoEventsReplayMock).toHaveBeenCalled();
		});
		expect(fetchGeoEventsReplayMock).toHaveBeenCalledWith(500);
	});

	it('opens the WS stream after replay completes', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
	});

	it('does NOT open the WS when position fetch fails (no point streaming into a broken UI)', async () => {
		fetchServerPositionMock.mockRejectedValue(new Error('HTTP 503'));
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-error')).toBeInTheDocument();
		});
		// Give the page a chance to (mistakenly) open the WS.
		await new Promise((r) => setTimeout(r, 50));
		expect(streamCapture.onEvent).toBeNull();
	});

	it('still opens the WS when REPLAY fails (replay is non-fatal)', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		fetchGeoEventsReplayMock.mockRejectedValue(new Error('replay 503'));
		// Suppress the console.warn the page emits to keep test
		// output clean.
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
		warnSpy.mockRestore();
	});

	it('renders the WS status pill (initial connecting state)', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			const pill = screen.getByTestId('map-ws-pill');
			expect(pill).toBeInTheDocument();
			expect(pill.getAttribute('data-ws-state')).toBe('connecting');
		});
	});

	it('updates the WS pill when openGeoEventStream reports state changes', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onStateChange).not.toBeNull();
		});
		// Fire a state transition.
		streamCapture.onStateChange?.('open');
		await waitFor(() => {
			const pill = screen.getByTestId('map-ws-pill');
			expect(pill.getAttribute('data-ws-state')).toBe('open');
			expect(pill.textContent ?? '').toContain('Live');
		});
	});

	it('seeds events from replay then appends live frames', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		const replay = [mkEvent({ details: 'replay-1' }), mkEvent({ details: 'replay-2' })];
		fetchGeoEventsReplayMock.mockResolvedValue({ events: replay, total: replay.length });
		render(MapPage);
		await waitFor(() => {
			// Two replay arcs spawn on initial render (the
			// WorldMap mounts after position + replay land).
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(2);
		});
		// Fire a live frame.
		streamCapture.onEvent?.(mkEvent({ details: 'live-1', category: 'auth' }));
		await waitFor(() => {
			const arcs = screen.getByTestId('worldmap-arcs');
			expect(arcs.querySelectorAll('path').length).toBe(3);
		});
	});

	it('closes the WS handle on unmount', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		const { unmount } = render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
		unmount();
		expect(streamCapture.closeCalls).toBe(1);
	});
});

describe('/map page — V.7 LAN counter', () => {
	const happyPosition: ServerPosition = {
		lat: 48.8566,
		lon: 2.3522,
		city: 'Paris',
		country: 'FR',
		mode: 'auto'
	};

	it('does not render the LAN pill when no LAN events have arrived', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
		expect(screen.queryByTestId('map-lan-pill')).toBeNull();
	});

	it('renders the LAN pill once a LAN event arrives', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
		streamCapture.onEvent?.(mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }));
		await waitFor(() => {
			expect(screen.getByTestId('map-lan-pill')).toBeInTheDocument();
			expect(
				screen.getByTestId('map-lan-pill-count').textContent
			).toBe('1');
		});
	});

	it('increments the LAN count per LAN event (not non-LAN)', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
		streamCapture.onEvent?.(mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }));
		streamCapture.onEvent?.(mkEvent({ isLan: false })); // non-LAN, no bump
		streamCapture.onEvent?.(mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }));
		streamCapture.onEvent?.(mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }));
		await waitFor(() => {
			expect(
				screen.getByTestId('map-lan-pill-count').textContent
			).toBe('3');
		});
	});

	it('seeds the LAN counter from the replay', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		fetchGeoEventsReplayMock.mockResolvedValue({
			events: [
				mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }),
				mkEvent({ isLan: false }),
				mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 })
			],
			total: 3
		});
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-lan-pill-count').textContent).toBe('2');
		});
	});

	// v2.41 — the label goes through t() now; the French agreement
	// this pins lives in the fr bundle, so the test drives the page
	// in French instead of matching a hard-coded string.
	it('uses singular "interne" for count=1 and plural "internes" for >1', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		fetchGeoEventsReplayMock.mockResolvedValue({
			events: [mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 })],
			total: 1
		});
		language.applyLocally('fr');
		try {
			render(MapPage);
			await waitFor(() => {
				const pill = screen.getByTestId('map-lan-pill');
				expect(pill.textContent ?? '').toContain('interne');
				expect(pill.textContent ?? '').not.toContain('internes');
			});

			streamCapture.onEvent?.(mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }));
			await waitFor(() => {
				const pill = screen.getByTestId('map-lan-pill');
				expect(pill.textContent ?? '').toContain('internes');
			});
		} finally {
			language.applyLocally('en');
		}
	});

	it('mounts the MapLegend inside the map frame', async () => {
		// Step V polish — legend explains the 5 arc colors
		// in-page so new operators don't need to read the
		// source. Lives in the bottom-right of the frame,
		// next to the WS / LAN pill stack in the top-right.
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(screen.getByTestId('map-legend')).toBeInTheDocument();
		});
	});

	// The counters bump on every WS event; a live region on them
	// would make a screen reader announce each bump. Only the WS
	// connection pill stays role="status".
	it('keeps the counters out of live regions — only the WS pill is role="status"', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		render(MapPage);
		await waitFor(() => {
			expect(streamCapture.onEvent).not.toBeNull();
		});
		streamCapture.onEvent?.(mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 }));
		streamCapture.onEvent?.(mkEvent({ category: 'country_block' }));
		await waitFor(() => {
			expect(screen.getByTestId('map-lan-pill')).toBeInTheDocument();
			expect(screen.getByTestId('map-country-block-pill')).toBeInTheDocument();
		});
		expect(screen.getByTestId('map-lan-pill')).not.toHaveAttribute('role');
		expect(screen.getByTestId('map-country-block-pill')).not.toHaveAttribute('role');
		const statuses = within(screen.getByTestId('map-frame')).getAllByRole('status');
		expect(statuses).toHaveLength(1);
		expect(statuses[0]).toHaveAttribute('data-testid', 'map-ws-pill');
	});

	it('has a tooltip explaining why LAN events do not arc', async () => {
		fetchServerPositionMock.mockResolvedValue(happyPosition);
		fetchGeoEventsReplayMock.mockResolvedValue({
			events: [mkEvent({ isLan: true, sourceLat: 0, sourceLon: 0 })],
			total: 1
		});
		render(MapPage);
		await waitFor(() => {
			const pill = screen.getByTestId('map-lan-pill');
			expect(pill.getAttribute('title') ?? '').toContain('LAN');
		});
	});
});
