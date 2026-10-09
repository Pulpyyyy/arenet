// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The topbar said "Gateway healthy" with a green dot from static
// markup: it read healthy with Caddy down. It now reads
// GET /system/health; this turns a report into what the badge shows.

import type { HealthReport, HealthStatus } from '$lib/api/system';

/** What the topbar badge shows. `unknown`: no report could be read. */
export type GatewayState = HealthStatus | 'unknown';

/** The components that are not healthy, as "name: message" lines. */
export function healthProblems(report: HealthReport): string[] {
	return (report.components ?? [])
		.filter((c) => c.status !== 'healthy')
		.map((c) => (c.message ? `${c.name}: ${c.message}` : c.name));
}

/** The badge state for a report, or `unknown` when there is none. */
export function gatewayState(report: HealthReport | null): GatewayState {
	if (!report) return 'unknown';
	const s = report.status;
	return s === 'healthy' || s === 'degraded' || s === 'unhealthy' ? s : 'unknown';
}
