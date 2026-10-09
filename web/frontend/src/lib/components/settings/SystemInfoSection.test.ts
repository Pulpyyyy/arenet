// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.45 — the host panel.
//
// What is pinned is the honesty of the figures, not their layout.
// The panel must say which ceiling it is showing when running in a
// container, must leave CPU usage blank until a rate can be computed,
// and must keep the last good reading when a tick fails rather than
// blanking a panel the operator is watching.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import type { SystemInfo } from '$lib/api/system';

const { api } = vi.hoisted(() => ({ api: { getSystemInfo: vi.fn() } }));
vi.mock('$lib/api/system', async (importOriginal) => ({
	...((await importOriginal()) as Record<string, unknown>),
	getSystemInfo: (...a: unknown[]) => api.getSystemInfo(...a)
}));

import SystemInfoSection from './SystemInfoSection.svelte';

function info(over: Partial<SystemInfo> = {}): SystemInfo {
	return {
		host: {
			hostname: 'arenet-test',
			os: 'Debian GNU/Linux 12 (bookworm)',
			kernel: '6.1.0-18-amd64',
			arch: 'amd64',
			uptimeSeconds: 123456,
			containerised: false
		},
		cpu: {
			model: 'Intel(R) Xeon(R) CPU',
			cores: 4,
			hostCores: 4,
			usagePercent: 12.5,
			load1: 0.52,
			load5: 0.41,
			load15: 0.38,
			source: 'host'
		},
		memory: {
			totalBytes: 8 * 1024 ** 3,
			usedBytes: 4 * 1024 ** 3,
			availableBytes: 4 * 1024 ** 3,
			source: 'host'
		},
		disk: {
			path: '/var/lib/arenet',
			totalBytes: 100 * 1024 ** 3,
			usedBytes: 20 * 1024 ** 3,
			availableBytes: 80 * 1024 ** 3
		},
		process: { heapBytes: 32 * 1024 ** 2, residentBytes: 64 * 1024 ** 2, goroutines: 42, goVersion: 'go1.26', uptimeSeconds: 3600 },
		timestamp: '2026-09-25T10:00:00Z',
		...over
	};
}

beforeEach(() => {
	api.getSystemInfo.mockReset();
});

describe('SystemInfoSection', () => {
	it('reports the host', async () => {
		api.getSystemInfo.mockResolvedValue(info());
		render(SystemInfoSection);

		await waitFor(() => expect(screen.getByTestId('system-info')).toBeInTheDocument());
		expect(screen.getByTestId('system-hostname').textContent).toContain('arenet-test');
		expect(screen.getByTestId('system-cpu-usage').textContent).toContain('13%');
		expect(screen.getByTestId('system-memory-usage').textContent).toContain('50%');
		expect(screen.getByTestId('system-disk-usage').textContent).toContain('20%');
	});

	// The reason this component is careful: /proc reports the host, so
	// a 512 MiB container would otherwise display the machine's 64 GiB.
	it('says when a figure is the container limit rather than the machine', async () => {
		api.getSystemInfo.mockResolvedValue(
			info({
				host: { hostname: 'c', containerised: true },
				memory: {
					totalBytes: 512 * 1024 ** 2,
					usedBytes: 256 * 1024 ** 2,
					availableBytes: 256 * 1024 ** 2,
					source: 'container'
				},
				cpu: { cores: 2, hostCores: 16, usagePercent: 5, source: 'container' }
			})
		);
		render(SystemInfoSection);

		await waitFor(() => expect(screen.getByTestId('system-info')).toBeInTheDocument());
		expect(screen.getByTestId('system-memory-source').textContent).toMatch(/container/i);
		// Sizes are decimal (lib/utils/format.ts): 512 MiB reads 537 MB.
		expect(screen.getByTestId('system-memory-detail').textContent).toMatch(/537\sMB/);
		// A quota must read as a restriction, not as a smaller machine:
		// the host's real count stays on screen next to it.
		expect(screen.getByTestId('system-cpu-cores').textContent).toContain('16');
	});

	// A rate needs a baseline. The first reading after a restart has
	// none, and inventing a number there would be worse than a dash.
	it('leaves CPU usage blank until it can be computed', async () => {
		api.getSystemInfo.mockResolvedValue(info({ cpu: { cores: 4, load1: 0.1, source: 'host' } }));
		render(SystemInfoSection);

		await waitFor(() => expect(screen.getByTestId('system-info')).toBeInTheDocument());
		expect(screen.getByTestId('system-cpu-usage').textContent).toContain('—');
	});

	it('explains itself when the platform cannot answer', async () => {
		api.getSystemInfo.mockResolvedValue(
			info({ unsupported: 'host metrics need /proc, which this platform does not provide' })
		);
		render(SystemInfoSection);

		await waitFor(() =>
			expect(screen.getByTestId('system-info-unsupported')).toBeInTheDocument()
		);
		expect(screen.getByTestId('system-info-unsupported').textContent).toMatch(/\/proc/);
	});

	it('keeps the last good reading when a refresh fails', async () => {
		vi.useFakeTimers();
		try {
			api.getSystemInfo.mockResolvedValue(info());
			render(SystemInfoSection);
			await vi.waitFor(() => expect(screen.getByTestId('system-hostname')).toBeInTheDocument());

			api.getSystemInfo.mockRejectedValue(new Error('network down'));
			await vi.advanceTimersByTimeAsync(5000);

			// Still there, still the previous values: a supervision
			// panel that blanks on one failed poll is worse than one
			// showing a reading five seconds old.
			expect(screen.getByTestId('system-hostname').textContent).toContain('arenet-test');
			expect(screen.queryByTestId('system-info-error')).toBeNull();
		} finally {
			vi.useRealTimers();
		}
	});
});
