// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Deleting a forward-auth provider loses its settings and client
// secret, so the Delete button only asks: the API is called once the
// operator confirms in a dialog that names the provider. Kept apart
// from page.test.ts, which is about the page's tab navigation.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { ForwardAuthProvider } from '$lib/api/types';

const { listProvidersMock, deleteProviderMock } = vi.hoisted(() => ({
	listProvidersMock: vi.fn(),
	deleteProviderMock: vi.fn()
}));

// Same stubbing as page.test.ts: every other settings API resolves to
// an empty value, only the forward-auth calls are observed.
vi.mock('$lib/api/settings', () => {
	const known: Record<string, unknown> = {
		getAutomation: vi.fn().mockResolvedValue({
			rules: { rules: {} },
			credentials: { lapiUrl: '', machineId: '', configured: false }
		}),
		listForwardAuthProviders: listProvidersMock,
		deleteForwardAuthProvider: deleteProviderMock
	};
	return {
		settingsApi: new Proxy(known, {
			get: (target, prop: string) => target[prop] ?? vi.fn().mockResolvedValue({})
		})
	};
});
vi.mock('$lib/api/system', () => ({
	systemApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue({}) })
}));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		listSessions: vi.fn().mockResolvedValue({ sessions: [] }),
		deleteSession: vi.fn().mockResolvedValue(undefined)
	}
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));
vi.mock('$app/navigation', () => ({
	afterNavigate: vi.fn(),
	goto: vi.fn()
}));

import Page from './+page.svelte';

const provider: ForwardAuthProvider = {
	name: 'sso-main',
	kind: 'authelia',
	verifyUrl: 'http://authelia:9091/api/verify',
	authRequestUri: 'https://auth.example.com',
	copyHeaders: [],
	clientSecret: '',
	clientSecretSet: true,
	authPassthroughPrefix: '',
	rewriteVerifyHost: false,
	createdAt: '2026-01-01T00:00:00Z',
	updatedAt: '2026-01-01T00:00:00Z'
};

beforeEach(() => {
	Element.prototype.scrollIntoView = vi.fn();
	window.scrollTo = vi.fn();
	window.history.replaceState(null, '', '/settings');
	listProvidersMock.mockReset();
	listProvidersMock.mockResolvedValue([provider]);
	deleteProviderMock.mockReset();
	deleteProviderMock.mockResolvedValue(undefined);
});

/** Opens the Security tab and clicks Delete on the provider row. */
async function clickDelete(): Promise<HTMLElement> {
	render(Page);
	await userEvent.click(screen.getByTestId('settings-tab-security'));
	const name = await screen.findByText('sso-main');
	// name <span> → its column → the provider row holding the buttons.
	const row = name.parentElement?.parentElement as HTMLElement;
	await userEvent.click(within(row).getByRole('button', { name: 'Delete' }));
	return screen.findByRole('dialog', { name: 'Delete forward-auth provider?' });
}

describe('settings — deleting a forward-auth provider', () => {
	it('asks first, naming the provider, and deletes only once confirmed', async () => {
		const dialog = await clickDelete();
		expect(dialog.textContent).toContain('sso-main');
		expect(deleteProviderMock).not.toHaveBeenCalled();

		await userEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(deleteProviderMock).toHaveBeenCalledWith('sso-main'));
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
	});

	it('deletes nothing when the dialog is cancelled', async () => {
		const dialog = await clickDelete();
		await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(deleteProviderMock).not.toHaveBeenCalled();
	});
});
