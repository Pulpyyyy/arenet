// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Removing an allowlist entry shuts that person out of SSO at once,
// so "Remove" only asks: the API is called once the operator
// confirms in a dialog that names the entry.
//
// The redirect URL is always this origin + the callback path, so it
// is filled in when nothing is saved yet (a saved value is kept) and
// can be copied. The allowlist inputs carry real labels, not just
// placeholders.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { OIDCAllowedIdentity, OIDCConfig } from '$lib/api/types';

const { getConfigMock, listAllowlistMock, deleteAllowlistMock } = vi.hoisted(() => ({
	getConfigMock: vi.fn(),
	listAllowlistMock: vi.fn(),
	deleteAllowlistMock: vi.fn()
}));

const CALLBACK_PATH = '/api/v1/auth/oidc/callback';

const config: OIDCConfig = {
	enabled: true,
	issuerUrl: 'https://idp.example.com',
	clientId: 'arenet',
	clientSecret: '',
	clientSecretSet: true,
	scopes: ['openid', 'email'],
	redirectUrl: 'https://arenet.example.com/api/v1/auth/oidc/callback',
	acceptUnverifiedEmail: false,
	kind: '',
	allowedIdentities: [],
	configured: true
};

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getOIDCConfig: () => getConfigMock(),
		listOIDCAllowlist: () => listAllowlistMock(),
		deleteOIDCAllowlist: (email: string) => deleteAllowlistMock(email),
		putOIDCConfig: vi.fn(),
		addOIDCAllowlist: vi.fn()
	}
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

const { default: OIDCSettingsSection } = await import('./OIDCSettingsSection.svelte');

const entry: OIDCAllowedIdentity = {
	email: 'alice@example.com',
	displayName: 'Alice',
	sub: 'sub-123',
	addedAt: '2026-01-01T00:00:00Z'
};

beforeEach(() => {
	getConfigMock.mockReset();
	getConfigMock.mockResolvedValue(config);
	listAllowlistMock.mockReset();
	listAllowlistMock.mockResolvedValue([entry]);
	deleteAllowlistMock.mockReset();
	deleteAllowlistMock.mockResolvedValue(undefined);
});

/** Clicks Remove on Alice's row and returns the dialog it opens. */
async function clickRemove(): Promise<HTMLElement> {
	render(OIDCSettingsSection);
	const email = await screen.findByText('alice@example.com');
	const row = email.closest('li') as HTMLElement;
	await userEvent.click(within(row).getByRole('button', { name: 'Remove' }));
	return screen.findByRole('dialog', { name: 'Remove from the allowlist?' });
}

describe('OIDCSettingsSection — removing an allowlist entry', () => {
	it('asks first, naming the entry, and removes only once confirmed', async () => {
		const dialog = await clickRemove();
		expect(dialog.textContent).toContain('alice@example.com');
		expect(deleteAllowlistMock).not.toHaveBeenCalled();

		await userEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
		await waitFor(() => expect(deleteAllowlistMock).toHaveBeenCalledWith('alice@example.com'));
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(screen.queryByText('alice@example.com')).not.toBeInTheDocument();
	});

	it('removes nothing when the dialog is cancelled', async () => {
		const dialog = await clickRemove();
		await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(deleteAllowlistMock).not.toHaveBeenCalled();
		expect(screen.getByText('alice@example.com')).toBeInTheDocument();
	});
});

describe('OIDCSettingsSection — redirect URL', () => {
	/** Renders and waits until the loaded config reached the form. */
	async function redirectInputAfterLoad(expected: string): Promise<HTMLInputElement> {
		render(OIDCSettingsSection);
		const input = (await screen.findByLabelText('Redirect URL')) as HTMLInputElement;
		await waitFor(() => expect(input).toHaveValue(expected));
		return input;
	}

	/** Replaces navigator.clipboard for this test only. */
	function stubClipboard(writeText: (text: string) => Promise<void>): void {
		Object.defineProperty(window.navigator, 'clipboard', {
			value: { writeText },
			configurable: true
		});
	}

	it('is filled in from this origin and the callback path when nothing is saved', async () => {
		getConfigMock.mockResolvedValue({ ...config, redirectUrl: '', configured: false });
		const input = await redirectInputAfterLoad(`${window.location.origin}${CALLBACK_PATH}`);
		// Still editable, for setups published under another address.
		expect(input).not.toHaveAttribute('readonly');
		expect(input).not.toBeDisabled();
	});

	it('keeps a saved value instead of overwriting it', async () => {
		await redirectInputAfterLoad(config.redirectUrl);
	});

	it('copies the URL to the clipboard', async () => {
		const writeText = vi.fn<(text: string) => Promise<void>>().mockResolvedValue(undefined);
		await redirectInputAfterLoad(config.redirectUrl);
		stubClipboard(writeText);

		await fireEvent.click(screen.getByRole('button', { name: 'Copy the redirect URL' }));
		await waitFor(() => expect(writeText).toHaveBeenCalledWith(config.redirectUrl));
	});

	it('selects the URL for a manual copy when the clipboard is refused', async () => {
		const input = await redirectInputAfterLoad(config.redirectUrl);
		stubClipboard(() => Promise.reject(new Error('denied')));

		await fireEvent.click(screen.getByRole('button', { name: 'Copy the redirect URL' }));
		await waitFor(() => expect(input).toHaveFocus());
	});
});

describe('OIDCSettingsSection — allowlist inputs', () => {
	it('labels each field instead of relying on its placeholder', async () => {
		render(OIDCSettingsSection);
		await screen.findByText('alice@example.com');

		// getByLabelText goes through <label for>, never the placeholder.
		expect(screen.getByLabelText('Email')).toHaveAttribute('type', 'email');
		expect(screen.getByLabelText('Display name (optional)')).toHaveAttribute('type', 'text');
		expect(screen.getByLabelText('OIDC Subject ID (optional)')).toHaveAttribute('type', 'text');

		expect(screen.getByRole('textbox', { name: 'Email' })).toBeInTheDocument();
		expect(screen.getByRole('textbox', { name: 'Display name (optional)' })).toBeInTheDocument();
		expect(screen.getByRole('textbox', { name: 'OIDC Subject ID (optional)' })).toBeInTheDocument();
	});
});
