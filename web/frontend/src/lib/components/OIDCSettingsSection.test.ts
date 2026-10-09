// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Removing an allowlist entry shuts that person out of SSO at once,
// so "Remove" only asks: the API is called once the operator
// confirms in a dialog that names the entry.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { OIDCAllowedIdentity, OIDCConfig } from '$lib/api/types';

const { listAllowlistMock, deleteAllowlistMock } = vi.hoisted(() => ({
	listAllowlistMock: vi.fn(),
	deleteAllowlistMock: vi.fn()
}));

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
		getOIDCConfig: () => Promise.resolve(config),
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
