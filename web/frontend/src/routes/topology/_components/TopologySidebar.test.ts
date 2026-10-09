// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.62.1 — the Top flows badge read "5xx 0.8333333333333334%".
//
// The error rate and the p99 arrive as raw floats from the windowed
// aggregator and were interpolated straight into the badge string.
// AliasNode has formatted the same field with toFixed(2) since it
// shipped; this panel was the one surface that forgot, and nothing
// tested it — the component had no test file at all, so 104 topology
// tests passed with the defect reinjected.
//
// The assertions below are on the rendered STRING, because that is what
// was wrong. The numbers were always correct.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import TopologySidebar from './TopologySidebar.svelte';
import type { TopologyRoute } from '../_types';

// The snapshot action re-fetches from the server rather than
// serialising the `routes` prop, so the module is the seam.
const fetchSnapshot = vi.hoisted(() => vi.fn());
vi.mock('../_api', () => ({ fetchSnapshot }));

function route(over: Partial<TopologyRoute> = {}): TopologyRoute {
	return {
		id: 'r-1',
		host: 'forum.example.com',
		upstreams: [
			{ id: 'u-0', url: 'http://194.163.129.255', status: 'healthy', reqPerSec: 20, p99LatencyMs: 10 }
		],
		lbPolicy: 'round_robin',
		reqPerSec: 20,
		p99LatencyMs: 0,
		errorRate5xx: 0,
		tlsEnabled: true,
		httpRedirect: false,
		hasHealthCheck: false,
		disabled: false,
		...over
	} as unknown as TopologyRoute;
}

function badgeText(): string {
	const el = document.querySelector('.badge');
	return el?.textContent?.trim() ?? '';
}

describe('TopologySidebar — Top flows badge', () => {
	it('rounds the 5xx rate to two decimals', () => {
		// 1/120 of the requests failing. Unrounded this rendered
		// seventeen digits in a badge about four characters wide.
		render(TopologySidebar, { routes: [route({ errorRate5xx: 100 / 120 })] });
		expect(badgeText()).toBe('5xx 0.83%');
	});

	it('does not round a real error rate away to zero', () => {
		// Two decimals rather than none: 0.83% matters on a forum, and
		// "0%" would deny it while "1%" would overstate it by 20%.
		render(TopologySidebar, { routes: [route({ errorRate5xx: 0.83 })] });
		expect(badgeText()).not.toBe('5xx 0%');
		expect(badgeText()).toBe('5xx 0.83%');
	});

	it('keeps a whole-number rate readable', () => {
		render(TopologySidebar, { routes: [route({ errorRate5xx: 5 })] });
		expect(badgeText()).toBe('5xx 5.00%');
	});

	it('shows no badge on a clean route', () => {
		render(TopologySidebar, { routes: [route()] });
		expect(document.querySelector('.badge')).toBeNull();
	});

	it('rounds the p99 to whole milliseconds', () => {
		// A fraction of a millisecond is noise in a badge. The 5xx rate
		// is zero here so the p99 branch is the one that renders.
		render(TopologySidebar, { routes: [route({ p99LatencyMs: 487.6231 })] });
		expect(badgeText()).toBe('p99 488 ms');
	});

	it('reports the 5xx rate in preference to the latency', () => {
		// Both branches qualify; the error is the more serious fact and
		// the badge has room for one. Pinned so the order cannot drift
		// silently.
		render(TopologySidebar, {
			routes: [route({ errorRate5xx: 2.5, p99LatencyMs: 900 })]
		});
		expect(badgeText()).toBe('5xx 2.50%');
	});

	it('lists the busiest route first', () => {
		render(TopologySidebar, {
			routes: [
				route({ id: 'quiet', host: 'quiet.example.com', reqPerSec: 1 }),
				route({ id: 'busy', host: 'busy.example.com', reqPerSec: 42 })
			]
		});
		const hosts = Array.from(document.querySelectorAll('.host')).map((e) => e.textContent);
		expect(hosts[0]).toBe('busy.example.com');
	});

	it('says so plainly when a route has no upstream', () => {
		render(TopologySidebar, { routes: [route({ upstreams: [] })] });
		expect(screen.getByText(/no upstream/i)).toBeInTheDocument();
	});
});

// v2.68 — the panel that scrolls.
//
// The CSS that bounds this column keys on .panel-topflux and on the
// .topflux-list inside it. I checked empirically whether a mismatch
// would be caught: renaming the selector in the <style> block and
// leaving the markup alone produces 0 errors and 0 warnings from
// svelte-check, and nothing from `npm run build` either. Neither gate
// in this project reports an unused CSS selector, which is the same
// shape as the missing Svelte Flow handle fixed in v2.67.2 — the
// renderer drops it in silence.
//
// So the markup side gets an assertion. It is half a guard, not a
// whole one: renaming the class in the CSS alone still slips through,
// and no test in jsdom can prove the column actually bounds, since
// jsdom has no layout. The operator's screen is the gate for that.
describe('TopologySidebar — the scrolling panel', () => {
	it('puts the Top flows list inside the panel the CSS bounds', () => {
		render(TopologySidebar, { routes: [route()] });
		const list = document.querySelector('.topflux-list');
		expect(list).not.toBeNull();
		expect(list!.closest('.panel-topflux')).not.toBeNull();
	});

	it('leaves the legend and the actions panels unbounded', () => {
		// Only one panel may take the slack; two would fight over it and
		// the legend is a fixed seven rows regardless.
		render(TopologySidebar, { routes: [route()] });
		expect(document.querySelectorAll('.panel-topflux')).toHaveLength(1);
	});
});

// v2.68 — the Quick actions panel.
//
// All three buttons shipped as Phase 1 placeholders with "wiring lands
// in Phase 2" in the component's doc comment, and Phase 2 never came
// back. They sat dead in production until the operator clicked them:
// "a quoi sert les 3 boutons […] car au click dessus il ne se passe
// rien". No test could have caught it — a button with no handler
// renders exactly like a button with one, so the only assertion that
// bites is one that clicks it and demands an effect.
describe('TopologySidebar — Quick actions', () => {
	let objectUrls: Blob[];
	let clicks: HTMLAnchorElement[];
	let clickSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		objectUrls = [];
		clicks = [];
		fetchSnapshot.mockReset();
		// jsdom implements neither of these.
		URL.createObjectURL = vi.fn((b: Blob) => {
			objectUrls.push(b);
			return 'blob:topology';
		}) as unknown as typeof URL.createObjectURL;
		URL.revokeObjectURL = vi.fn() as unknown as typeof URL.revokeObjectURL;
		// Intercepted rather than allowed through: a real anchor click
		// makes jsdom attempt a navigation to blob:topology.
		clickSpy = vi
			.spyOn(HTMLAnchorElement.prototype, 'click')
			.mockImplementation(function (this: HTMLAnchorElement) {
				clicks.push(this);
			});
	});

	afterEach(() => {
		clickSpy.mockRestore();
	});

	function snapshotButton(): HTMLButtonElement {
		return screen.getByTestId('topology-action-snapshot') as HTMLButtonElement;
	}

	it('downloads the snapshot when the button is clicked', async () => {
		fetchSnapshot.mockResolvedValue({ generatedAt: '2026-10-06T10:00:00Z', routes: [] });
		render(TopologySidebar, { routes: [route()] });

		snapshotButton().click();
		await vi.waitFor(() => expect(clicks.length).toBe(1));

		expect(fetchSnapshot).toHaveBeenCalledTimes(1);
		expect(clicks[0].download).toMatch(/^arenet-topology-\d{8}-\d{6}\.json$/);
	});

	it('writes the server payload, not the filtered view it was handed', async () => {
		// The sidebar receives the CURRENT view's routes; a snapshot
		// serialised from that prop would silently ship half the
		// instance and no generatedAt, which is the one field a bug
		// report needs to correlate against the logs.
		fetchSnapshot.mockResolvedValue({
			generatedAt: '2026-10-06T10:00:00Z',
			routes: [{ id: 'from-server' }]
		});
		render(TopologySidebar, { routes: [route({ id: 'from-the-prop' })] });

		snapshotButton().click();
		await vi.waitFor(() => expect(objectUrls.length).toBe(1));

		const text = await objectUrls[0].text();
		expect(text).toContain('"generatedAt": "2026-10-06T10:00:00Z"');
		expect(text).toContain('from-server');
		expect(text).not.toContain('from-the-prop');
	});

	it('disables while in flight and re-enables after a failed fetch', async () => {
		// Both halves in one test because they are one invariant. The
		// disable is what stops a double-click firing two downloads; the
		// re-enable is what keeps a failure from leaving the operator
		// with a button they can never retry, and the fetch fails for
		// the whole of every reconnect window.
		//
		// The promise is held open deliberately — mockRejectedValue
		// settles before the first assertion can observe the disabled
		// state, and the test would pass against a handler that never
		// set it.
		let reject!: (e: Error) => void;
		fetchSnapshot.mockReturnValue(
			new Promise((_resolve, rj) => {
				reject = rj;
			})
		);
		render(TopologySidebar, { routes: [route()] });

		snapshotButton().click();
		await vi.waitFor(() => expect(snapshotButton().disabled).toBe(true));

		reject(new Error('snapshot unavailable'));
		await vi.waitFor(() => expect(snapshotButton().disabled).toBe(false));
		expect(clicks.length).toBe(0);
	});

	it('offers no action that does nothing', async () => {
		// Pinned deliberately. "Reload Caddy config" and "Drain an
		// upstream…" were removed, not wired: Arenet reloads Caddy
		// itself on every change, and a per-upstream drain is a feature
		// with storage and API surface rather than a button. Adding
		// either back as a label fails here, which is the whole point.
		fetchSnapshot.mockResolvedValue({ generatedAt: '2026-10-06T10:00:00Z', routes: [] });
		render(TopologySidebar, { routes: [route()] });

		const buttons = Array.from(document.querySelectorAll('.actions-list button'));
		expect(buttons).toHaveLength(1);
		expect(buttons[0]).toBe(snapshotButton());
	});
});
