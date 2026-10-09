// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.41 — StatCard absorbed the three scoped-CSS .kpi copies
// (dashboard, certs, WAF). What the copies could do and it could
// not — a unit after the number, a foot line, a shrunken value for
// a word rather than a measurement — is pinned here, along with the
// trend behaviour kept from the pre-v2.41 API.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import StatCard from './StatCard.svelte';

describe('StatCard', () => {
	it('shows the label, the value and nothing else by default', () => {
		render(StatCard, { props: { label: 'Routes', value: 9, testid: 'tile' } });
		const tile = screen.getByTestId('tile');
		expect(tile.textContent).toContain('Routes');
		expect(tile.textContent).toContain('9');
		expect(tile.querySelector('.unit')).toBeNull();
		expect(tile.querySelector('.foot')).toBeNull();
		expect(tile.querySelector('.trend')).toBeNull();
	});

	it('carries a unit after the value and a foot line under it', () => {
		render(StatCard, {
			props: {
				label: 'Requests / s',
				value: '12.4',
				unit: 'req/s',
				hint: '44 610 requests · 9 routes',
				testid: 'tile'
			}
		});
		const tile = screen.getByTestId('tile');
		expect(tile.querySelector('.unit')?.textContent).toBe('req/s');
		expect(tile.querySelector('.foot')?.textContent).toContain('44 610');
	});

	it('shrinks a value that is a word, not a measurement', () => {
		render(StatCard, {
			props: { label: 'Issuer', value: "Let's Encrypt", variant: 'text', testid: 'tile' }
		});
		expect(screen.getByTestId('tile').querySelector('.value')?.getAttribute('data-variant')).toBe(
			'text'
		);
	});

	it('marks a positive trend up and a negative one down', () => {
		const { unmount } = render(StatCard, {
			props: { label: 'Active', value: 8, trend: 1, testid: 'up' }
		});
		const up = screen.getByTestId('up').querySelector('.trend');
		expect(up?.className).toContain('up');
		expect(up?.textContent).toContain('↗');
		unmount();

		render(StatCard, { props: { label: 'Active', value: 8, trend: -2, testid: 'down' } });
		const down = screen.getByTestId('down').querySelector('.trend');
		expect(down?.className).toContain('down');
		expect(down?.textContent).toContain('2');
	});

	// The tiles were dead ends, and an abnormal value looked like any
	// other. Both props are optional: a caller passing neither gets the
	// same <div> as before.
	it('is a plain block with no tone when neither href nor tone is set', () => {
		render(StatCard, { props: { label: 'Routes', value: 9, testid: 'tile' } });
		const tile = screen.getByTestId('tile');
		expect(tile.tagName).toBe('DIV');
		expect(tile.hasAttribute('href')).toBe(false);
		expect(tile.hasAttribute('data-tone')).toBe(false);
	});

	it('becomes a link to the page behind the number when href is set', () => {
		render(StatCard, {
			props: { label: 'WAF blocked', value: 4, href: '/waf', testid: 'tile' }
		});
		const link = screen.getByRole('link');
		expect(link).toBe(screen.getByTestId('tile'));
		expect(link.getAttribute('href')).toBe('/waf');
		// The whole tile is the link, so its name carries the reading.
		expect(link.textContent).toContain('WAF blocked');
		expect(link.textContent).toContain('4');
	});

	it('exposes the warn tone as data-tone', () => {
		render(StatCard, { props: { label: '5xx', value: 3, tone: 'warn', testid: 'tile' } });
		expect(screen.getByTestId('tile').getAttribute('data-tone')).toBe('warn');
	});
});
