// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.48 — creating a local user.
//
// The property worth pinning is the one-way street: the generated
// password crosses exactly one screen, so Close waits for Copy. An
// operator who leaves without copying has to delete the account and
// start again, and the dialog has to say that by refusing to close.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { api } = vi.hoisted(() => ({ api: { createAdminUser: vi.fn() } }));
vi.mock('$lib/api/settings', async (importOriginal) => {
	const original = (await importOriginal()) as Record<string, unknown>;
	return {
		...original,
		settingsApi: { ...(original.settingsApi as object), createAdminUser: api.createAdminUser }
	};
});
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import CreateUserModal from './CreateUserModal.svelte';

const created = {
	user: { id: 'u1', username: 'alice', displayName: 'Alice', role: 'viewer', authSource: 'local' },
	generatedPassword: 'Abcd-Efgh-Jkmn-Pqrs-Tuvw'
};

// Braces matter. `() => api.createAdminUser.mockReset()` returns the
// mock — mockReset returns it for chaining — and vitest treats a value
// returned from a hook as a teardown callback. A mock IS a function, so
// vitest would call it after every test, running whatever implementation
// the test had installed: the refusal case then threw its ApiError from
// teardown, after a test body that had already passed.
beforeEach(() => {
	api.createAdminUser.mockReset();
});

afterEach(() => {
	// Undo the clipboard stubs; own properties shadow jsdom's.
	delete (navigator as unknown as Record<string, unknown>).clipboard;
	delete (document as unknown as Record<string, unknown>).execCommand;
});

async function reachReveal(onClose: () => void) {
	api.createAdminUser.mockResolvedValue(created);
	const view = render(CreateUserModal, { open: true, onClose });
	await userEvent.type(screen.getByTestId('new-user-username'), 'alice');
	await userEvent.click(screen.getByTestId('new-user-submit'));
	await waitFor(() => expect(screen.getByTestId('new-user-revealed')).toBeInTheDocument());
	return view;
}

describe('CreateUserModal', () => {
	it('generates by default and does not send a password', async () => {
		api.createAdminUser.mockResolvedValue(created);
		render(CreateUserModal, { open: true, onClose: () => {} });

		await userEvent.type(screen.getByTestId('new-user-username'), 'alice');
		await userEvent.type(screen.getByTestId('new-user-display-name'), 'Alice');
		await userEvent.type(screen.getByTestId('new-user-email'), 'alice@example.org');
		await userEvent.click(screen.getByTestId('new-user-submit'));

		await waitFor(() => expect(api.createAdminUser).toHaveBeenCalledTimes(1));
		const payload = api.createAdminUser.mock.calls[0][0];
		expect(payload.password).toBeUndefined();
		expect(payload.role).toBe('viewer');
	});

	it('shows the password once and refuses to close before it is copied', async () => {
		api.createAdminUser.mockResolvedValue(created);
		const onClose = vi.fn();
		render(CreateUserModal, { open: true, onClose });

		await userEvent.type(screen.getByTestId('new-user-username'), 'alice');
		await userEvent.click(screen.getByTestId('new-user-submit'));

		await waitFor(() => expect(screen.getByTestId('new-user-revealed')).toBeInTheDocument());
		expect(screen.getByTestId('new-user-revealed').textContent).toBe(created.generatedPassword);

		// The one-way street: nothing retrieves this afterwards.
		expect((screen.getByTestId('new-user-close') as HTMLButtonElement).disabled).toBe(true);

		Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
		await userEvent.click(screen.getByTestId('new-user-copy'));
		await waitFor(() =>
			expect((screen.getByTestId('new-user-close') as HTMLButtonElement).disabled).toBe(false)
		);
		expect(onClose).not.toHaveBeenCalled();
	});

	// A typed password is already in the operator's hands, so there is
	// nothing to reveal and no ceremony to sit through.
	it('closes straight away when the admin typed the password', async () => {
		api.createAdminUser.mockResolvedValue({ user: created.user });
		const onClose = vi.fn();
		render(CreateUserModal, { open: true, onClose });

		await userEvent.type(screen.getByTestId('new-user-username'), 'carol');
		await userEvent.click(screen.getByTestId('new-user-generate')); // turn generation off
		await userEvent.type(screen.getByTestId('new-user-password'), 'a-long-chosen-password');
		await userEvent.click(screen.getByTestId('new-user-submit'));

		await waitFor(() => expect(onClose).toHaveBeenCalled());
		expect(api.createAdminUser.mock.calls[0][0].password).toBe('a-long-chosen-password');
		expect(screen.queryByTestId('new-user-revealed')).toBeNull();
	});

	it('shows a refused creation in the form, translated', async () => {
		const { ApiError } = await import('$lib/api/types');
		api.createAdminUser.mockRejectedValue(
			new ApiError('username already taken', 409, 'validation', undefined, 'user_username_taken')
		);
		render(CreateUserModal, { open: true, onClose: () => {} });

		await userEvent.type(screen.getByTestId('new-user-username'), 'alice');
		await userEvent.click(screen.getByTestId('new-user-submit'));

		const shown = await screen.findByTestId('new-user-error');
		expect(shown.textContent).toMatch(/taken|pris/i);
	});

	// Escape and the backdrop used to run the same close as the button,
	// discarding the password the dialog was refusing to let go of.
	it('keeps the password on Escape or a backdrop click during the reveal', async () => {
		const onClose = vi.fn();
		await reachReveal(onClose);

		await fireEvent.keyDown(document, { key: 'Escape' });
		const backdrop = document.querySelector('.modal-backdrop') as HTMLElement;
		await fireEvent.click(backdrop);

		expect(onClose).not.toHaveBeenCalled();
		expect(screen.getByTestId('new-user-revealed').textContent).toBe(created.generatedPassword);
	});

	// On plain HTTP the copy can fail for good; ticking the box is the
	// way out that does not lose the password.
	it('unlocks Close once the admin ticks "I have saved it"', async () => {
		const onClose = vi.fn();
		await reachReveal(onClose);

		const close = screen.getByTestId('new-user-close') as HTMLButtonElement;
		expect(close.disabled).toBe(true);
		await userEvent.click(screen.getByTestId('new-user-saved'));
		expect(close.disabled).toBe(false);

		await userEvent.click(close);
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('says so in the dialog when copying fails, and keeps Close locked', async () => {
		await reachReveal(vi.fn());
		// A plain-HTTP origin: no Clipboard API, and the legacy path refused.
		Object.defineProperty(navigator, 'clipboard', {
			value: undefined,
			configurable: true,
			writable: true
		});
		Object.defineProperty(document, 'execCommand', {
			value: vi.fn(() => false),
			configurable: true,
			writable: true
		});

		await fireEvent.click(screen.getByTestId('new-user-copy'));

		const failed = await screen.findByTestId('new-user-copy-failed');
		expect(failed.textContent).toMatch(/by hand|à la main/i);
		expect((screen.getByTestId('new-user-close') as HTMLButtonElement).disabled).toBe(true);
		// The password stays on screen to be copied by hand.
		expect(screen.getByTestId('new-user-revealed').textContent).toBe(created.generatedPassword);
	});
});
