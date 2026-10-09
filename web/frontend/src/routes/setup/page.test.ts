// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Setup form — email field coverage. Email is OPTIONAL on local
// accounts (contact/display only, never a login/match key — see
// auth_handlers.go setup()). The form previously shipped no email
// field while the backend required one, making first-admin creation
// impossible. Pins:
//   - the form renders an email input
//   - a supplied email is forwarded to authApi.setup
//   - setup still works when email is left blank

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

const { authMock, authStoreMock, pageMock, gotoMock } = vi.hoisted(() => ({
	authMock: { setup: vi.fn() },
	authStoreMock: {
		state: 'unauthenticated' as 'authenticated' | 'unauthenticated',
		user: null as unknown
	},
	pageMock: { url: new URL('http://localhost/setup') },
	gotoMock: vi.fn()
}));

vi.mock('$app/navigation', () => ({ goto: gotoMock }));
vi.mock('$app/state', () => ({ page: pageMock }));
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authStoreMock }));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		setup: (...a: unknown[]) => authMock.setup(...a)
	}
}));

import Page from './+page.svelte';

beforeEach(() => {
	pageMock.url = new URL('http://localhost/setup');
	gotoMock.mockReset();
	authMock.setup.mockReset();
	authMock.setup.mockResolvedValue({
		id: 'admin-id',
		username: 'admin',
		displayName: 'Site Admin',
		role: 'admin'
	});
});

// Query by id — the setup form has hint <small>s and an aria-labelled
// show-password button that make label/text regex queries ambiguous.
function byId(container: HTMLElement, id: string): HTMLInputElement {
	const el = container.querySelector<HTMLInputElement>(`#${id}`);
	if (!el) throw new Error(`#${id} not found`);
	return el;
}

async function fillCommon(container: HTMLElement): Promise<void> {
	await fireEvent.input(byId(container, 'setup-token'), { target: { value: 'tok-123' } });
	await fireEvent.input(byId(container, 'setup-username'), { target: { value: 'admin' } });
	await fireEvent.input(byId(container, 'setup-password'), {
		target: { value: 'correct horse battery staple' }
	});
}

describe('/setup — email field', () => {
	it('renders an email input', () => {
		const { container } = render(Page);
		expect(container.querySelector('#setup-email')).not.toBeNull();
	});

	it('forwards a supplied email to authApi.setup', async () => {
		const { container, getByTestId } = render(Page);
		await fillCommon(container);
		await fireEvent.input(byId(container, 'setup-email'), {
			target: { value: 'admin@example.test' }
		});
		await fireEvent.submit(getByTestId('setup-form'));

		await waitFor(() => expect(authMock.setup).toHaveBeenCalledTimes(1));
		// email must appear in the call args regardless of position.
		expect(authMock.setup.mock.calls[0]).toContain('admin@example.test');
	});

	it('submits successfully when email is left blank', async () => {
		const { container, getByTestId } = render(Page);
		await fillCommon(container);
		await fireEvent.submit(getByTestId('setup-form'));

		await waitFor(() => expect(authMock.setup).toHaveBeenCalledTimes(1));
		// blank email forwarded as an empty string (backend accepts it).
		expect(authMock.setup.mock.calls[0]).toContain('');
	});
});

describe('/setup — where it lands', () => {
	async function completeSetup(): Promise<void> {
		const { container, getByTestId } = render(Page);
		await fillCommon(container);
		await fireEvent.submit(getByTestId('setup-form'));
		await waitFor(() => expect(gotoMock).toHaveBeenCalledTimes(1));
	}

	it('lands on /routes without ?next=', async () => {
		await completeSetup();
		expect(gotoMock).toHaveBeenCalledWith('/routes');
	});

	it('lands on the page asked for when ?next= is a same-origin path', async () => {
		pageMock.url = new URL('http://localhost/setup?next=%2Fcerts%3Ftab%3Dacme');
		await completeSetup();
		expect(gotoMock).toHaveBeenCalledWith('/certs?tab=acme');
	});

	it('ignores a ?next= that leaves the origin', async () => {
		pageMock.url = new URL('http://localhost/setup?next=%2F%2Fevil.example');
		await completeSetup();
		expect(gotoMock).toHaveBeenCalledWith('/routes');
	});
});
