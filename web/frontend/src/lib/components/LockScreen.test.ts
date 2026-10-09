// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// LockScreen. Pins:
//   - focus starts in the password field (the SSO button for an OIDC
//     account, which has no password field)
//   - Tab and Shift+Tab wrap inside the card
//   - "Sign out" is a way out that is not unlocking: it runs the
//     store's logout and lands on /login
//   - the SSO button starts the flow with the page behind the lock as
//     ?next=, so re-authenticating comes back to it
//
// Elements are found by id / test id rather than by their text, so
// the copy can be translated without touching these tests.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { authStoreMock, gotoMock, pageMock } = vi.hoisted(() => ({
	authStoreMock: {
		state: 'locked' as const,
		user: { username: 'alice', authSource: 'local' } as {
			username: string;
			authSource: string;
		},
		logout: vi.fn(),
		unlock: vi.fn(),
		clear: vi.fn()
	},
	gotoMock: vi.fn(),
	pageMock: { url: new URL('http://localhost/routes') }
}));

vi.mock('$app/navigation', () => ({ goto: gotoMock }));
vi.mock('$app/state', () => ({ page: pageMock }));
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authStoreMock }));

import LockScreen from './LockScreen.svelte';

function passwordInput(container: HTMLElement): HTMLInputElement {
	const input = container.querySelector<HTMLInputElement>('#lockscreen-password');
	if (!input) throw new Error('password input not rendered');
	return input;
}

beforeEach(() => {
	authStoreMock.user = { username: 'alice', authSource: 'local' };
	pageMock.url = new URL('http://localhost/routes');
	authStoreMock.logout.mockReset();
	authStoreMock.logout.mockResolvedValue(undefined);
	gotoMock.mockReset();
	gotoMock.mockResolvedValue(undefined);
});

describe('LockScreen', () => {
	it('puts focus in the password field when it appears', async () => {
		const { container } = render(LockScreen);
		await waitFor(() => expect(passwordInput(container)).toHaveFocus());
	});

	it('starts on the SSO button for an OIDC account', async () => {
		authStoreMock.user = { username: 'alice', authSource: 'oidc' };
		const { container } = render(LockScreen);
		expect(container.querySelector('#lockscreen-password')).toBeNull();
		const sso = container.querySelector<HTMLAnchorElement>('a[href="/api/v1/auth/oidc/login"]');
		expect(sso).not.toBeNull();
		await waitFor(() => expect(sso).toHaveFocus());
	});

	it('starts SSO with the page behind the lock as ?next=', () => {
		authStoreMock.user = { username: 'alice', authSource: 'oidc' };
		pageMock.url = new URL('http://localhost/certs?tab=acme');
		const { container } = render(LockScreen);
		const sso = container.querySelector<HTMLAnchorElement>('a.lockscreen-submit');
		expect(sso?.getAttribute('href')).toBe('/api/v1/auth/oidc/login?next=%2Fcerts%3Ftab%3Dacme');
	});

	it('keeps Tab and Shift+Tab inside the card', async () => {
		const user = userEvent.setup();
		const { container } = render(LockScreen);
		const input = passwordInput(container);
		const signOut = screen.getByTestId('lockscreen-signout');
		await waitFor(() => expect(input).toHaveFocus());

		// Shift+Tab off the first control wraps to the last one...
		await user.tab({ shift: true });
		expect(signOut).toHaveFocus();
		// ...and Tab off the last one wraps back to the first.
		await user.tab();
		expect(input).toHaveFocus();
	});

	it('signs out through the store and lands on /login', async () => {
		const user = userEvent.setup();
		render(LockScreen);
		await user.click(screen.getByTestId('lockscreen-signout'));
		await waitFor(() => expect(authStoreMock.logout).toHaveBeenCalledTimes(1));
		await waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/login'));
	});
});
