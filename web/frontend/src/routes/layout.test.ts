// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Root layout, anonymous visitor. Pins:
//   - on a fresh install (setup/status available) the redirect goes to
//     /setup, otherwise to /login, and a failed probe means /login
//   - the page asked for rides along as ?next=, and the redirect
//     replaces the history entry
//   - /login and /setup are left alone

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

const { authStoreMock, authApiMock, pageMock, gotoMock } = vi.hoisted(() => ({
	// Already anonymous at mount: the plain-object mock is not reactive,
	// so the redirect effect has to see the final state on its first run.
	authStoreMock: {
		state: 'anonymous' as const,
		user: null,
		isBootstrapping: false,
		bootstrapErrorStatus: 0,
		bootstrap: vi.fn(),
		setLocked: vi.fn(),
		clear: vi.fn()
	},
	authApiMock: { setupStatus: vi.fn(), heartbeat: vi.fn() },
	pageMock: { url: new URL('http://localhost/routes') },
	gotoMock: vi.fn()
}));

vi.mock('$app/navigation', () => ({ goto: gotoMock }));
vi.mock('$app/state', () => ({ page: pageMock, navigating: { to: null } }));
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authStoreMock }));
vi.mock('$lib/stores/idle.svelte', () => ({
	idle: { start: vi.fn(), stop: vi.fn(), reset: vi.fn(), userActiveSinceReset: true }
}));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		setupStatus: () => authApiMock.setupStatus(),
		heartbeat: () => authApiMock.heartbeat()
	}
}));

import Layout from './+layout.svelte';

function at(pathAndQuery: string): void {
	pageMock.url = new URL(`http://localhost${pathAndQuery}`);
}

beforeEach(() => {
	at('/certs?tab=acme');
	gotoMock.mockReset();
	gotoMock.mockResolvedValue(undefined);
	authStoreMock.bootstrap.mockReset();
	authStoreMock.bootstrap.mockResolvedValue(undefined);
	authApiMock.setupStatus.mockReset();
});

describe('root layout — anonymous redirect', () => {
	it('sends a fresh install to /setup, with the page asked for', async () => {
		authApiMock.setupStatus.mockResolvedValue({ available: true });
		render(Layout);
		await waitFor(() =>
			expect(gotoMock).toHaveBeenCalledWith('/setup?next=%2Fcerts%3Ftab%3Dacme', {
				replaceState: true
			})
		);
	});

	it('sends everyone else to /login, with the page asked for', async () => {
		authApiMock.setupStatus.mockResolvedValue({ available: false });
		render(Layout);
		await waitFor(() =>
			expect(gotoMock).toHaveBeenCalledWith('/login?next=%2Fcerts%3Ftab%3Dacme', {
				replaceState: true
			})
		);
	});

	it('falls back to /login when the setup probe fails', async () => {
		authApiMock.setupStatus.mockRejectedValue(new Error('network down'));
		render(Layout);
		await waitFor(() =>
			expect(gotoMock).toHaveBeenCalledWith('/login?next=%2Fcerts%3Ftab%3Dacme', {
				replaceState: true
			})
		);
	});

	it('leaves out ?next= for the root page', async () => {
		at('/');
		authApiMock.setupStatus.mockResolvedValue({ available: false });
		render(Layout);
		await waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/login', { replaceState: true }));
	});

	it.each(['/login', '/setup'])('does not redirect away from %s', async (path) => {
		at(path);
		authApiMock.setupStatus.mockResolvedValue({ available: true });
		render(Layout);
		await waitFor(() => expect(authStoreMock.bootstrap).toHaveBeenCalledTimes(1));
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(authApiMock.setupStatus).not.toHaveBeenCalled();
		expect(gotoMock).not.toHaveBeenCalled();
	});
});
