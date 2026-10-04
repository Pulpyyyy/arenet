// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step L L.3 — typed client wrappers around /api/v1/metrics/*.
// The backend wire shape lives in internal/api/metrics_handlers.go;
// the response types are declared in lib/api/types.ts.

import { request } from './client';
import type {
	MetricName,
	MetricWindow,
	TimeseriesResponse,
	SummaryResponse,
	RouteSummaryResponse
} from './types';

/**
 * Fetch the historical timeseries for one metric on one route.
 *
 * Returns dense, gap-filled points covering the requested window
 * (per AC #5). For count metrics, missing buckets carry value=0;
 * for `p95_latency_ms`, missing buckets carry value=null —
 * callers MUST treat null as a gap, NOT plot it as 0.
 *
 * On the AC #13 degraded-mode path (observability subsystem
 * down), the response has disabled=true and points=[].
 */
export function fetchTimeseries(
	routeId: string,
	metric: MetricName,
	window: MetricWindow
): Promise<TimeseriesResponse> {
	const qs = new URLSearchParams({ route: routeId, metric, window });
	return request<TimeseriesResponse>('GET', `/metrics/timeseries?${qs.toString()}`);
}

/**
 * Fetch the global summary (aggregate counts over the
 * just-closed minute, top-5 routes by traffic, global weighted
 * p95). 4xx and 5xx fields are independent per AC #6 — never
 * collapsed into a single "errors" number.
 */
export function fetchSummary(): Promise<SummaryResponse> {
	return request<SummaryResponse>('GET', '/metrics/summary');
}

/**
 * Fetch one route's 24h traffic aggregate (requests, 4xx, 5xx,
 * weighted p95).
 *
 * Deliberately a separate endpoint rather than a read of
 * `fetchSummary().topRoutes`: that list keeps only the five
 * busiest routes, so every quieter route would silently show
 * zeros. Server-side this costs one indexed read of bucket_1h
 * over at most 24 rows.
 *
 * On the degraded-mode path the response has disabled=true and
 * every counter at zero — callers MUST treat that as "unknown"
 * and render a placeholder, not as "no traffic".
 */
export function fetchRouteSummary(routeId: string): Promise<RouteSummaryResponse> {
	const qs = new URLSearchParams({ route: routeId });
	return request<RouteSummaryResponse>('GET', `/metrics/route-summary?${qs.toString()}`);
}
