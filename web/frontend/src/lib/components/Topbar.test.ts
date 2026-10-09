// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The status used to be static markup reading "Gateway healthy"
// whatever the gateway's state. These pin that it follows
// GET /system/health, and never claims healthy without a report.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';

const { healthMock } = vi.hoisted(() => ({ healthMock: vi.fn() }));

vi.mock('$app/state', () => ({
	page: { url: new URL('http://localhost/routes') }
}));
vi.mock('$lib/api/system', () => ({
	fetchSystemHealth: () => healthMock()
}));

import Topbar from './Topbar.svelte';

beforeEach(() => {
	healthMock.mockReset();
});

describe('Topbar — gateway status', () => {
	it('says healthy when the report says so', async () => {
		healthMock.mockResolvedValue({ status: 'healthy', timestamp: '', components: [] });
		render(Topbar);
		await waitFor(() =>
			expect(screen.getByTestId('gateway-status')).toHaveAttribute('data-state', 'healthy')
		);
		expect(screen.getByTestId('gateway-status')).toHaveTextContent('Gateway healthy');
	});

	it('says degraded, and names what is wrong', async () => {
		healthMock.mockResolvedValue({
			status: 'degraded',
			timestamp: '',
			components: [
				{ name: 'caddy', status: 'healthy', message: 'ok' },
				{ name: 'crowdsec', status: 'degraded', message: 'LAPI unreachable' }
			]
		});
		render(Topbar);
		await waitFor(() =>
			expect(screen.getByTestId('gateway-status')).toHaveTextContent('Gateway degraded')
		);
		expect(screen.getByTestId('gateway-status').getAttribute('title')).toBe(
			'crowdsec: LAPI unreachable'
		);
	});

	it('says unknown, not healthy, when the report cannot be read', async () => {
		healthMock.mockRejectedValue(new Error('network'));
		render(Topbar);
		await waitFor(() =>
			expect(screen.getByTestId('gateway-status')).toHaveAttribute('data-state', 'unknown')
		);
		expect(screen.getByTestId('gateway-status')).not.toHaveTextContent('Gateway healthy');
	});
});
