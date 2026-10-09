// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.12.3 — system version / update-checker client. Backs the topbar
// update badge and the /settings Updates section.

import { request } from './client';

export interface SystemVersion {
	current: string;
	latest: string;
	updateAvailable: boolean;
	url: string;
	lastChecked: string;
	lastError: string;
	enabled: boolean;
}

// Brick 3, Task 5 — GeoIP database auto-update client. Backs the
// (future, Brick 4) /settings GeoIP updates panel.

export interface GeoIPUpdateConfig {
	enabled: boolean;
	intervalHours: number;
}

export interface GeoIPUpdateResult {
	status: string;
	error?: string;
	lastModified?: string;
}

export interface GeoIPStatus {
	lastStatus: string;
	lastError?: string;
	lastUpdated?: string;
}

export const systemApi = {
	getVersion: (): Promise<SystemVersion> => request<SystemVersion>('GET', '/system/version'),
	checkVersion: (): Promise<SystemVersion> =>
		request<SystemVersion>('POST', '/system/version/check'),
	setVersionConfig: (body: {
		enabled: boolean;
		intervalOverride?: string;
	}): Promise<SystemVersion> => request<SystemVersion>('PUT', '/system/version/config', body),

	getGeoIPUpdateConfig: (): Promise<GeoIPUpdateConfig> =>
		request<GeoIPUpdateConfig>('GET', '/system/geoip/update-config'),
	putGeoIPUpdateConfig: (body: {
		enabled: boolean;
		intervalHours?: number;
	}): Promise<GeoIPUpdateConfig> =>
		request<GeoIPUpdateConfig>('PUT', '/system/geoip/update-config', body),
	triggerGeoIPUpdate: (): Promise<GeoIPUpdateResult> =>
		request<GeoIPUpdateResult>('POST', '/system/geoip/update'),
	getGeoIPStatus: (): Promise<GeoIPStatus> => request<GeoIPStatus>('GET', '/system/geoip/status')
};

// --- v2.45 — the host Arenet runs on -----------------------------
//
//   GET /api/v1/system/info  (viewer)
//
// Backend mirror: internal/api/system_info.go, internal/sysinfo.

/**
 * Where a figure came from. In a container the two answers differ and
 * only one is useful: /proc reports the HOST, so a container limited
 * to 512 MiB would otherwise show the host's 64 GiB — literally
 * correct, and useless to whoever is working out why Arenet keeps
 * being OOM-killed.
 */
export type MetricSource = 'host' | 'container';

export interface SystemHost {
	hostname?: string;
	os?: string;
	kernel?: string;
	arch?: string;
	/** The machine's uptime, not Arenet's. */
	uptimeSeconds?: number;
	containerised: boolean;
}

export interface SystemCPU {
	model?: string;
	/** What this process may use: the cgroup quota when one is set. */
	cores?: number;
	/** The machine's own count, so a quota reads as a restriction. */
	hostCores?: number;
	/** Absent until two samples exist — a rate needs a baseline. */
	usagePercent?: number;
	load1?: number;
	load5?: number;
	load15?: number;
	source?: MetricSource;
}

export interface SystemMemory {
	totalBytes?: number;
	usedBytes?: number;
	availableBytes?: number;
	source?: MetricSource;
}

/** The filesystem holding the data directory, not the root one. */
export interface SystemDisk {
	path?: string;
	totalBytes?: number;
	usedBytes?: number;
	availableBytes?: number;
}

export interface SystemProcess {
	heapBytes?: number;
	residentBytes?: number;
	goroutines?: number;
	goVersion?: string;
	/** Since this process started, not since boot. */
	uptimeSeconds?: number;
}

export interface SystemInfo {
	host: SystemHost;
	cpu: SystemCPU;
	memory: SystemMemory;
	disk: SystemDisk;
	process: SystemProcess;
	/** Set when the platform cannot answer; the fields are then empty. */
	unsupported?: string;
	timestamp: string;
}

export const getSystemInfo = (): Promise<SystemInfo> =>
	request<SystemInfo>('GET', '/system/info');

// --- Gateway health ------------------------------------------------
//
//   GET /system/health  (no auth; mounted at the root, not /api/v1)
//
// Backend mirror: internal/api/system_health.go, internal/systemhealth.
// Answers 503 with the same JSON body when the gateway is unhealthy,
// so the body is read whatever the status code.

/** Health of one component, or of the gateway as a whole. */
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy';

/** One component's line in the health report. */
export interface HealthComponent {
	name: string;
	status: HealthStatus;
	latency_ms?: number;
	message: string;
}

/** GET /system/health body. */
export interface HealthReport {
	status: HealthStatus;
	timestamp: string;
	version?: string;
	components: HealthComponent[];
}

/** Reads the gateway health report. Throws when no report could be read. */
export async function fetchSystemHealth(): Promise<HealthReport> {
	const res = await fetch('/system/health', { cache: 'no-store' });
	const body = (await res.json()) as HealthReport;
	if (!body || typeof body.status !== 'string') {
		throw new Error(`system health: unexpected body (HTTP ${res.status})`);
	}
	return body;
}
