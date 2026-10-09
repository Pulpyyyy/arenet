// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Login page. Pins:
//   - a fresh install (setup/status available) goes to /setup, ?next= kept
//   - a successful sign-in lands on ?next= when it is a same-origin path
//   - ?reason= maps known codes to an information banner, ignores others
//   - a 429 disables the submit button with a Retry-After countdown and
//     a translated message instead of the raw backend one

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import { flushSync } from 'svelte';
import { ApiError } from '$lib/api/types';
import { t } from '$lib/i18n';

const { authApiMock, authStoreMock, pageMock, gotoMock } = vi.hoisted(() => ({
	authApiMock: { oidcStatus: vi.fn(), setupStatus: vi.fn() },
	authStoreMock: { login: vi.fn() },
	pageMock: { url: new URL('http://localhost/login') },
	gotoMock: vi.fn()
}));

vi.mock('$app/navigation', () => ({ goto: gotoMock }));
vi.mock('$app/state', () => ({ page: pageMock }));
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authStoreMock }));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		oidcStatus: () => authApiMock.oidcStatus(),
		setupStatus: () => authApiMock.setupStatus()
	}
}));

import Page from './+page.svelte';

function at(pathAndQuery: string): void {
	pageMock.url = new URL(`http://localhost${pathAndQuery}`);
}

beforeEach(() => {
	at('/login');
	gotoMock.mockReset();
	authStoreMock.login.mockReset();
	authStoreMock.login.mockResolvedValue(undefined);
	authApiMock.oidcStatus.mockReset();
	authApiMock.oidcStatus.mockResolvedValue({ enabled: false });
	authApiMock.setupStatus.mockReset();
	authApiMock.setupStatus.mockResolvedValue({ available: false });
});

afterEach(() => {
	vi.useRealTimers();
});

function byId(container: HTMLElement, id: string): HTMLInputElement {
	const el = container.querySelector<HTMLInputElement>(`#${id}`);
	if (!el) throw new Error(`#${id} not found`);
	return el;
}

// Lets the probe's promise chain run to its end (real timers only).
function settle(): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, 0));
}

async function signIn(container: HTMLElement, form: HTMLElement): Promise<void> {
	await fireEvent.input(byId(container, 'login-username'), { target: { value: 'admin' } });
	await fireEvent.input(byId(container, 'login-password'), { target: { value: 'hunter2' } });
	await fireEvent.submit(form);
}

describe('/login — fresh install', () => {
	it('goes to /setup when setup is available, keeping ?next=', async () => {
		at('/login?next=%2Fcerts');
		authApiMock.setupStatus.mockResolvedValue({ available: true });
		render(Page);
		await waitFor(() =>
			expect(gotoMock).toHaveBeenCalledWith('/setup?next=%2Fcerts', { replaceState: true })
		);
	});

	it('drops an unsafe ?next= on the way to /setup', async () => {
		at('/login?next=%2F%2Fevil.example');
		authApiMock.setupStatus.mockResolvedValue({ available: true });
		render(Page);
		await waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/setup', { replaceState: true }));
	});

	it('stays on /login when setup is not available', async () => {
		render(Page);
		await waitFor(() => expect(authApiMock.setupStatus).toHaveBeenCalledTimes(1));
		await settle();
		expect(gotoMock).not.toHaveBeenCalled();
	});

	it('stays on /login when the setup probe fails', async () => {
		authApiMock.setupStatus.mockRejectedValue(new Error('network down'));
		render(Page);
		await waitFor(() => expect(authApiMock.setupStatus).toHaveBeenCalledTimes(1));
		await settle();
		expect(gotoMock).not.toHaveBeenCalled();
	});
});

describe('/login — where sign-in lands', () => {
	it('lands on /routes without ?next=', async () => {
		const { container, getByTestId } = render(Page);
		await signIn(container, getByTestId('login-form'));
		await waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/routes'));
	});

	it('lands on ?next= when it is a same-origin path', async () => {
		at('/login?next=%2Fcerts%3Ftab%3Dacme');
		const { container, getByTestId } = render(Page);
		await signIn(container, getByTestId('login-form'));
		await waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/certs?tab=acme'));
	});

	it.each(['//evil.example', 'https://evil.example/', '/\\evil.example'])(
		'ignores ?next=%s and lands on /routes',
		async (next) => {
			at(`/login?next=${encodeURIComponent(next)}`);
			const { container, getByTestId } = render(Page);
			await signIn(container, getByTestId('login-form'));
			await waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/routes'));
		}
	);
});

describe('/login — ?reason=', () => {
	it('explains oidc_unlock_required in an information banner', async () => {
		at('/login?reason=oidc_unlock_required');
		const { findByTestId } = render(Page);
		const banner = await findByTestId('login-reason');
		expect(banner.textContent).toContain(t('auth.reasons.oidcUnlockRequired'));
		expect(banner.getAttribute('role')).toBe('status');
	});

	it.each(['something_else', 'constructor'])('shows nothing for reason=%s', async (reason) => {
		at(`/login?reason=${reason}`);
		const { queryByTestId } = render(Page);
		await waitFor(() => expect(authApiMock.setupStatus).toHaveBeenCalledTimes(1));
		expect(queryByTestId('login-reason')).toBeNull();
	});
});

describe('/login — 429 rate limit', () => {
	it('disables submit with a live Retry-After countdown, then re-enables it', async () => {
		vi.useFakeTimers();
		authStoreMock.login.mockRejectedValue(
			new ApiError('too many attempts, retry after 15 minutes', 429, 'rate_limited', 3)
		);
		const { container, getByTestId, queryByTestId } = render(Page);
		await signIn(container, getByTestId('login-form'));
		await vi.advanceTimersByTimeAsync(0);
		flushSync();

		const button = getByTestId('login-submit') as HTMLButtonElement;
		expect(button.disabled).toBe(true);
		expect(button.textContent).toContain(t('auth.retryIn', { time: '0:03' }));
		expect(getByTestId('login-error').textContent).toContain(t('auth.errors.rateLimited'));
		// The translated message replaces the raw backend one.
		expect(container.textContent).not.toContain('too many attempts');
		// The inputs stay usable: a typo can be fixed while waiting.
		expect(byId(container, 'login-password').disabled).toBe(false);

		await vi.advanceTimersByTimeAsync(1000);
		flushSync();
		expect(button.textContent).toContain(t('auth.retryIn', { time: '0:02' }));

		await vi.advanceTimersByTimeAsync(2000);
		flushSync();
		expect(button.disabled).toBe(false);
		expect(button.textContent).toContain(t('auth.loginButton'));
		expect(queryByTestId('login-error')).toBeNull();
	});

	it('does not submit while the countdown runs', async () => {
		vi.useFakeTimers();
		authStoreMock.login.mockRejectedValue(
			new ApiError('too many attempts', 429, 'rate_limited', 60)
		);
		const { container, getByTestId } = render(Page);
		await signIn(container, getByTestId('login-form'));
		await vi.advanceTimersByTimeAsync(0);
		flushSync();
		expect(authStoreMock.login).toHaveBeenCalledTimes(1);

		// A submit that does not go through the disabled button is
		// refused by the handler as well.
		await fireEvent.submit(getByTestId('login-form'));
		await vi.advanceTimersByTimeAsync(0);
		expect(authStoreMock.login).toHaveBeenCalledTimes(1);
	});

	it('says to try later, without a countdown, when Retry-After is missing', async () => {
		authStoreMock.login.mockRejectedValue(new ApiError('too many attempts', 429, 'rate_limited', 0));
		const { container, getByTestId, findByTestId } = render(Page);
		await signIn(container, getByTestId('login-form'));
		const banner = await findByTestId('login-error');
		expect(banner.textContent).toContain(t('auth.errors.rateLimitedLater'));
		const button = getByTestId('login-submit') as HTMLButtonElement;
		expect(button.disabled).toBe(false);
		expect(button.textContent).toContain(t('auth.loginButton'));
	});
});
