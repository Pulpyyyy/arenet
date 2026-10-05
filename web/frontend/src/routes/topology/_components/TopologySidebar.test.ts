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

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import TopologySidebar from './TopologySidebar.svelte';
import type { TopologyRoute } from '../_types';

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
		expect(screen.getByText(/aucun upstream/i)).toBeInTheDocument();
	});
});
