// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import type { User } from './../api/auth';
import { ApiError } from '$lib/api/types';

// Build a fresh mock authApi for each test so the assertions on calls
// don't leak between tests. We import auth via dynamic import after
// the mock is in place.
const authApiMock = {
	me: vi.fn(),
	login: vi.fn(),
	logout: vi.fn(),
	unlock: vi.fn(),
	setup: vi.fn(),
	heartbeat: vi.fn(),
	listSessions: vi.fn(),
	deleteSession: vi.fn(),
	changePassword: vi.fn(),
	setTheme: vi.fn()
};

vi.mock('$lib/api/auth', async () => {
	const actual = await vi.importActual<typeof import('./../api/auth')>('$lib/api/auth');
	return {
		...actual,
		authApi: authApiMock
	};
});

// Import the store AFTER the mock is set up so it picks up the mocked authApi.
const { auth } = await import('./auth.svelte');

function resetStore(): void {
	auth.user = null;
	auth.state = 'unknown';
	auth.isBootstrapping = false;
	auth.bootstrapErrorStatus = 0;
}

const sampleUser: User = {
	id: 'u-1',
	username: 'admin',
	displayName: 'Admin',
	locked: false,
	passwordCompromised: false,
	hibpCheckStatus: 'clean',
	themePreference: '',
	languagePreference: '',
	role: 'admin',
	authSource: 'local'
};

beforeEach(() => {
	resetStore();
	for (const fn of Object.values(authApiMock)) fn.mockReset();
});

describe('AuthStore.bootstrap', () => {
	it('transitions unknown → authenticated when /me returns 200 and locked=false', async () => {
		authApiMock.me.mockResolvedValueOnce(sampleUser);
		await auth.bootstrap();
		expect(auth.state).toBe('authenticated');
		expect(auth.user).toEqual(sampleUser);
	});

	it('transitions unknown → locked when /me returns 200 and locked=true', async () => {
		authApiMock.me.mockResolvedValueOnce({ ...sampleUser, locked: true });
		await auth.bootstrap();
		expect(auth.state).toBe('locked');
		expect(auth.user?.locked).toBe(true);
	});

	it('transitions unknown → anonymous on 401', async () => {
		authApiMock.me.mockRejectedValueOnce(new ApiError('unauth', 401, 'auth'));
		await auth.bootstrap();
		expect(auth.state).toBe('anonymous');
		expect(auth.user).toBeNull();
	});

	// Before the error state, these failures left 'unknown' and the
	// layout spun forever with nothing to press.
	it('transitions unknown → error on a network error (no kick to login)', async () => {
		authApiMock.me.mockRejectedValueOnce(new ApiError('network', 0, 'system'));
		await auth.bootstrap();
		expect(auth.state).toBe('error');
		expect(auth.bootstrapErrorStatus).toBe(0);
		expect(auth.user).toBeNull();
	});

	it('transitions unknown → error on a 5xx and keeps the status', async () => {
		authApiMock.me.mockRejectedValueOnce(new ApiError('boom', 503, 'system'));
		await auth.bootstrap();
		expect(auth.state).toBe('error');
		expect(auth.bootstrapErrorStatus).toBe(503);
	});

	it('treats a non-ApiError throw as unreachable', async () => {
		authApiMock.me.mockRejectedValueOnce(new TypeError('Failed to fetch'));
		await auth.bootstrap();
		expect(auth.state).toBe('error');
		expect(auth.bootstrapErrorStatus).toBe(0);
	});

	it('a retry after an error reaches authenticated', async () => {
		authApiMock.me.mockRejectedValueOnce(new ApiError('network', 0, 'system'));
		await auth.bootstrap();
		expect(auth.state).toBe('error');
		authApiMock.me.mockResolvedValueOnce(sampleUser);
		await auth.bootstrap();
		expect(auth.state).toBe('authenticated');
		expect(auth.user).toEqual(sampleUser);
		expect(authApiMock.me).toHaveBeenCalledTimes(2);
	});

	it('a failed refresh of a live session keeps it (no error panel)', async () => {
		auth.user = sampleUser;
		auth.state = 'authenticated';
		authApiMock.me.mockRejectedValueOnce(new ApiError('network', 0, 'system'));
		await auth.bootstrap();
		expect(auth.state).toBe('authenticated');
		expect(auth.user).toEqual(sampleUser);
	});

	it('a retry after an error that gets a 401 goes anonymous as usual', async () => {
		authApiMock.me.mockRejectedValueOnce(new ApiError('boom', 500, 'system'));
		await auth.bootstrap();
		authApiMock.me.mockRejectedValueOnce(new ApiError('unauth', 401, 'auth'));
		await auth.bootstrap();
		expect(auth.state).toBe('anonymous');
		expect(auth.user).toBeNull();
	});

	it('toggles isBootstrapping around the call', async () => {
		let observedDuring = false;
		authApiMock.me.mockImplementationOnce(async () => {
			observedDuring = auth.isBootstrapping;
			return sampleUser;
		});
		await auth.bootstrap();
		expect(observedDuring).toBe(true);
		expect(auth.isBootstrapping).toBe(false);
	});
});

describe('AuthStore.login', () => {
	it('populates user and transitions to authenticated', async () => {
		authApiMock.login.mockResolvedValueOnce(sampleUser);
		// Sub-task 1.5 wiring: login() follows up with a /me call to
		// pick up themePreference for reconcileFromServer.
		authApiMock.me.mockResolvedValueOnce(sampleUser);
		await auth.login('admin', 'pw', false);
		expect(auth.state).toBe('authenticated');
		expect(auth.user).toEqual(sampleUser);
		expect(authApiMock.login).toHaveBeenCalledWith('admin', 'pw', false);
	});

	it('propagates the error and leaves state unchanged on failure', async () => {
		auth.state = 'anonymous';
		authApiMock.login.mockRejectedValueOnce(new ApiError('invalid credentials', 401, 'auth'));
		await expect(auth.login('admin', 'wrong', false)).rejects.toBeInstanceOf(ApiError);
		expect(auth.state).toBe('anonymous');
		expect(auth.user).toBeNull();
	});
});

describe('AuthStore.logout', () => {
	it('clears local state on success', async () => {
		auth.user = sampleUser;
		auth.state = 'authenticated';
		authApiMock.logout.mockResolvedValueOnce(undefined);
		await auth.logout();
		expect(auth.state).toBe('anonymous');
		expect(auth.user).toBeNull();
	});

	it('clears local state EVEN if the server logout fails (resilience)', async () => {
		auth.user = sampleUser;
		auth.state = 'authenticated';
		authApiMock.logout.mockRejectedValueOnce(new Error('boom'));
		await auth.logout();
		expect(auth.state).toBe('anonymous');
		expect(auth.user).toBeNull();
	});
});

describe('AuthStore.unlock', () => {
	it('transitions locked → authenticated on success', async () => {
		auth.user = { ...sampleUser, locked: true };
		auth.state = 'locked';
		authApiMock.unlock.mockResolvedValueOnce({ unlocked: true });
		await auth.unlock('pw');
		expect(auth.state).toBe('authenticated');
		// User object is preserved.
		expect(auth.user).not.toBeNull();
	});

	it('keeps state on failure', async () => {
		auth.state = 'locked';
		authApiMock.unlock.mockRejectedValueOnce(new ApiError('invalid password', 401, 'auth'));
		await expect(auth.unlock('wrong')).rejects.toBeInstanceOf(ApiError);
		expect(auth.state).toBe('locked');
	});
});

describe('AuthStore.setLocked', () => {
	it('transitions authenticated → locked', () => {
		auth.state = 'authenticated';
		auth.setLocked();
		expect(auth.state).toBe('locked');
	});

	it('is idempotent from locked', () => {
		auth.state = 'locked';
		auth.setLocked();
		expect(auth.state).toBe('locked');
	});

	it('is a no-op from anonymous', () => {
		auth.state = 'anonymous';
		auth.setLocked();
		expect(auth.state).toBe('anonymous');
	});

	it('is a no-op from unknown', () => {
		auth.state = 'unknown';
		auth.setLocked();
		expect(auth.state).toBe('unknown');
	});
});

describe('AuthStore.clear', () => {
	it('resets to anonymous regardless of previous state', () => {
		auth.user = sampleUser;
		auth.state = 'authenticated';
		auth.clear();
		expect(auth.state).toBe('anonymous');
		expect(auth.user).toBeNull();
	});
});
