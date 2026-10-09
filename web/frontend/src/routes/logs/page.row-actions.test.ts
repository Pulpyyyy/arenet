// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /logs row actions: "Ban…" (admin-only, opens BanIPModal with the
// full source IP) and the copy button next to the masked SOURCE IP.
// Kept apart from page.test.ts so the two files evolve without
// stepping on each other; the mock setup mirrors it.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { CertEvent, WafEvent } from '$lib/api/types';

const { toastMock, securityMock, clientMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: {
		fetchEvents: vi.fn(),
		fetchThrottleEvents: vi.fn(),
		fetchAuthFailures: vi.fn(),
		fetchCertEvents: vi.fn(),
		fetchCountryBlockEvents: vi.fn(),
		fetchRateLimitEvents: vi.fn(),
		geoLookupBatch: vi.fn(),
		createManualBan: vi.fn()
	},
	clientMock: { listRoutes: vi.fn() }
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);
vi.mock('$lib/api/client', () => clientMock);

import Page from './+page.svelte';
import { auth } from '$lib/stores/auth.svelte';

const FULL_IP = '82.65.1.2';
const MASKED_IP = '82.65.1.x';

function wafEvent(overrides: Partial<WafEvent> = {}): WafEvent {
	return {
		id: 1,
		ts: new Date().toISOString(),
		routeId: 'r',
		action: 'BLOCK',
		statusCode: 403,
		ruleId: '942100',
		category: 'SQLi',
		message: 'm',
		requestMethod: 'POST',
		requestPath: '/p',
		srcIp: FULL_IP,
		...overrides
	} as WafEvent;
}

function certEvent(): CertEvent {
	return {
		timestamp: new Date().toISOString(),
		level: 'INFO',
		eventType: 'cert_obtained',
		domain: 'example.com',
		issuer: "Let's Encrypt",
		challenge: 'DNS-01',
		renewal: false,
		error: '',
		details: ''
	};
}

function asAdmin(): void {
	auth.user = {
		username: 'admin',
		displayName: 'Admin',
		role: 'admin',
		mfa: 'none',
		passwordCompromised: false
	} as never;
}

function asViewer(): void {
	auth.user = {
		username: 'viewer',
		displayName: 'Viewer',
		role: 'viewer',
		mfa: 'none',
		passwordCompromised: false
	} as never;
}

const realClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');

function stubClipboard(writeText: (s: string) => Promise<void>): void {
	Object.defineProperty(navigator, 'clipboard', {
		value: { writeText },
		configurable: true
	});
}

beforeEach(() => {
	auth.user = null;
	toastMock.pushToast.mockReset();
	for (const fn of Object.values(securityMock)) fn.mockReset();
	securityMock.fetchEvents.mockResolvedValue({ events: [wafEvent()] });
	securityMock.fetchThrottleEvents.mockResolvedValue({ events: [] });
	securityMock.fetchAuthFailures.mockResolvedValue({ window: '24h', timeseries: [], recent: [] });
	securityMock.fetchCertEvents.mockResolvedValue({ events: [], total: 0, hasMore: false });
	securityMock.fetchCountryBlockEvents.mockResolvedValue({ events: [], total: 0, hasMore: false });
	securityMock.fetchRateLimitEvents.mockResolvedValue({ events: [], total: 0, hasMore: false });
	securityMock.geoLookupBatch.mockResolvedValue({ results: {}, degraded: true });
	clientMock.listRoutes.mockReset();
	clientMock.listRoutes.mockResolvedValue([]);
});

afterEach(() => {
	auth.user = null;
	if (realClipboard) {
		Object.defineProperty(navigator, 'clipboard', realClipboard);
	} else {
		delete (navigator as unknown as Record<string, unknown>).clipboard;
	}
	vi.clearAllMocks();
});

describe('/logs — Ban… row action', () => {
	it('opens BanIPModal pre-filled with the full (unmasked) source IP', async () => {
		asAdmin();
		render(Page);
		await fireEvent.click(await screen.findByTestId('logs-ban-open'));
		expect(await screen.findByRole('dialog', { name: /Ban an IP/i })).toBeInTheDocument();
		await waitFor(() => expect(screen.getByTestId('ban-input-value')).toHaveValue(FULL_IP));
	});

	it('is not shown to viewers', async () => {
		asViewer();
		render(Page);
		await screen.findByText(MASKED_IP);
		expect(screen.queryByTestId('logs-ban-open')).toBeNull();
	});

	it('is not offered on rows without a real source IP', async () => {
		asAdmin();
		securityMock.fetchEvents.mockResolvedValue({ events: [] });
		securityMock.fetchCertEvents.mockResolvedValue({ events: [certEvent()], total: 1, hasMore: false });
		render(Page);
		await screen.findByText(/\(interne\)/);
		expect(screen.queryByTestId('logs-ban-open')).toBeNull();
		expect(screen.queryByTestId('logs-copy-ip')).toBeNull();
	});
});

describe('/logs — copy the full source IP', () => {
	it('copies the full IP, not the masked label, for viewers too', async () => {
		asViewer();
		const writeText = vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined);
		stubClipboard(writeText);
		render(Page);
		await fireEvent.click(await screen.findByTestId('logs-copy-ip'));
		await waitFor(() => expect(writeText).toHaveBeenCalledWith(FULL_IP));
		expect(toastMock.pushToast).toHaveBeenCalledWith('IP copied', 'success');
	});

	it('falls back to a text selection when the Clipboard API is refused', async () => {
		stubClipboard(() => Promise.reject(new Error('insecure context')));
		const execCommand = vi.fn<(command: string) => boolean>().mockReturnValue(true);
		Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true });
		try {
			render(Page);
			await fireEvent.click(await screen.findByTestId('logs-copy-ip'));
			await waitFor(() => expect(execCommand).toHaveBeenCalledWith('copy'));
			expect(toastMock.pushToast).toHaveBeenCalledWith('IP copied', 'success');
		} finally {
			delete (document as unknown as Record<string, unknown>).execCommand;
		}
	});
});
