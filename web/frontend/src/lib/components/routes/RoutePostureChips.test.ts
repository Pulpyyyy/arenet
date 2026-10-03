// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.59 — the component had no test, and the defect it shipped with
// was invisible without one: the chips read the STORED config, so a
// route that proxies nothing still advertised its WAF mode, its geo
// gate and its rate limit, none of which reach the emitted Caddy
// chain (manager.go:1549 replaces it and continues at :1618).
//
// The operator could set the WAF to block on a redirecting route,
// see the red BLOCK chip in the list, save without error, and have
// no rule ever evaluated.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import RoutePostureChips from './RoutePostureChips.svelte';
import type { Route } from '$lib/api/types';

function route(overrides: Partial<Route> = {}): Route {
	return {
		id: 'r1',
		host: 'app.example.com',
		upstreams: [{ url: 'http://127.0.0.1:9000', weight: 1 }],
		wafMode: 'off',
		...overrides
	} as unknown as Route;
}

const chipTexts = () =>
	(screen.getByTestId('posture-chips-root')?.textContent ?? '').replace(/\s+/g, ' ').trim();

describe('RoutePostureChips', () => {
	it('a proxying route shows its gates', () => {
		render(RoutePostureChips, { props: { route: route({ wafMode: 'block' }) } });
		expect(chipTexts()).toContain('Block');
	});

	it('a proxying route with nothing configured shows a plain dash', () => {
		render(RoutePostureChips, { props: { route: route() } });
		expect(chipTexts()).toBe('—');
		expect(screen.queryByTestId('posture-inert')).not.toBeInTheDocument();
	});

	it('a redirecting route in WAF block mode shows NO chip', () => {
		// The load-bearing case. 'block' is deliberately on the
		// `:else if` arm of the WAF branch — guarding only the
		// `detect` arm leaves this exact row red.
		render(RoutePostureChips, {
			props: {
				route: route({
					wafMode: 'block',
					upstreams: [],
					redirectConfig: { target: 'https://new.example.com', statusCode: 301 }
				} as Partial<Route>)
			}
		});
		expect(chipTexts()).not.toContain('Block');
		expect(screen.getByTestId('posture-inert')).toBeInTheDocument();
	});

	it('a redirecting route hides geo, IP and rate-limit chips too', () => {
		render(RoutePostureChips, {
			props: {
				route: route({
					wafMode: 'detect',
					upstreams: [],
					redirectConfig: { target: 'https://new.example.com', statusCode: 302 },
					countryBlock: {
						mode: 'deny',
						countryList: ['RU'],
						continents: [],
						asns: [],
						exceptions: { countries: [], asns: [] },
						statusCode: 0
					},
					ipFilter: { mode: 'deny', cidrs: ['10.0.0.0/8'] },
					rateLimit: { events: 100, window: '1m' }
				} as Partial<Route>)
			}
		});
		expect(screen.queryByTestId('posture-geo')).not.toBeInTheDocument();
		expect(screen.queryByTestId('posture-ip')).not.toBeInTheDocument();
		expect(screen.queryByTestId('posture-rate-limit')).not.toBeInTheDocument();
		expect(chipTexts()).toBe('—');
	});

	it('a maintenance route is inert for the same reason', () => {
		render(RoutePostureChips, {
			props: {
				route: route({
					wafMode: 'block',
					maintenanceConfig: { retryAfterSeconds: 300 }
				} as Partial<Route>)
			}
		});
		expect(screen.getByTestId('posture-inert')).toBeInTheDocument();
	});

	it('a disabled route is inert — it sits on neither listener', () => {
		render(RoutePostureChips, {
			props: { route: route({ wafMode: 'block', disabled: true } as Partial<Route>) }
		});
		expect(screen.getByTestId('posture-inert')).toBeInTheDocument();
	});
});
