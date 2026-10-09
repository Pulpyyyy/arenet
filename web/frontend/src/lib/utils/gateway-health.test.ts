// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { gatewayState, healthProblems } from './gateway-health';
import type { HealthReport } from '$lib/api/system';

const report = (over: Partial<HealthReport> = {}): HealthReport => ({
	status: 'healthy',
	timestamp: '2026-10-09T12:00:00Z',
	components: [],
	...over
});

describe('gatewayState', () => {
	it('follows the report status', () => {
		expect(gatewayState(report())).toBe('healthy');
		expect(gatewayState(report({ status: 'degraded' }))).toBe('degraded');
		expect(gatewayState(report({ status: 'unhealthy' }))).toBe('unhealthy');
	});

	it('is unknown without a report, never healthy by default', () => {
		expect(gatewayState(null)).toBe('unknown');
		expect(gatewayState(report({ status: 'weird' as never }))).toBe('unknown');
	});
});

describe('healthProblems', () => {
	it('lists only the components that are not healthy', () => {
		expect(
			healthProblems(
				report({
					status: 'degraded',
					components: [
						{ name: 'caddy', status: 'healthy', message: 'ok' },
						{ name: 'crowdsec', status: 'degraded', message: 'LAPI unreachable' },
						{ name: 'db', status: 'unhealthy', message: '' }
					]
				})
			)
		).toEqual(['crowdsec: LAPI unreachable', 'db']);
	});
});
