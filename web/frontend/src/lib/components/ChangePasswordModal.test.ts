// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The change-password dialog behaves like a form: Enter submits it,
// closing it forgets what was typed, every failing field says so at
// once, and the show/hide toggles are reachable from the keyboard.
// Test ids are used throughout so the assertions hold in either UI
// language.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { api } = vi.hoisted(() => ({
	api: { changePassword: vi.fn(), me: vi.fn() }
}));
vi.mock('$lib/api/auth', () => ({
	authApi: { changePassword: api.changePassword, me: api.me }
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import ChangePasswordModal from './ChangePasswordModal.svelte';

const NEW_PASSWORD = 'a-long-enough-new-password';

function field(name: 'current' | 'new' | 'confirm'): HTMLInputElement {
	return screen.getByTestId(`change-password-${name}`) as HTMLInputElement;
}

// Braces matter: a hook that returns the mock would have vitest call it
// as a teardown (see CreateUserModal.test.ts).
beforeEach(() => {
	api.changePassword.mockReset();
	api.me.mockReset();
});

describe('ChangePasswordModal', () => {
	it('submits when Enter is pressed in a field', async () => {
		api.changePassword.mockResolvedValue(undefined);
		api.me.mockRejectedValue(new Error('not under test'));
		const user = userEvent.setup();
		render(ChangePasswordModal, { open: true });

		await user.type(field('current'), 'the-old-password');
		await user.type(field('new'), NEW_PASSWORD);
		await user.type(field('confirm'), `${NEW_PASSWORD}{Enter}`);

		await waitFor(() =>
			expect(api.changePassword).toHaveBeenCalledWith('the-old-password', NEW_PASSWORD)
		);
		expect(api.changePassword).toHaveBeenCalledTimes(1);
	});

	it('is empty again when reopened after being closed', async () => {
		const user = userEvent.setup();
		const { rerender } = render(ChangePasswordModal, { open: true });

		await user.type(field('current'), 'typed-then-abandoned');
		await user.type(field('new'), 'also-abandoned');
		await user.click(screen.getByTestId('change-password-toggle-current'));
		await user.click(screen.getByTestId('change-password-cancel'));

		await rerender({ open: false });
		await rerender({ open: true });

		await waitFor(() => expect(field('current').value).toBe(''));
		expect(field('new').value).toBe('');
		expect(field('confirm').value).toBe('');
		// The reveal toggle is part of the form state too.
		expect(field('current').type).toBe('password');
		expect(screen.getByTestId('change-password-toggle-current')).toHaveAttribute(
			'aria-pressed',
			'false'
		);
	});

	it('shows the too-short and the mismatch errors together', async () => {
		const user = userEvent.setup();
		render(ChangePasswordModal, { open: true });

		await user.type(field('current'), 'the-old-password');
		await user.type(field('new'), 'short');
		await user.type(field('confirm'), 'shorter');
		expect(screen.getByTestId('change-password-counter').textContent).toMatch(/5\/15/);

		await user.click(screen.getByTestId('change-password-submit'));

		await waitFor(() => expect(field('new')).toHaveAttribute('aria-invalid', 'true'));
		expect(field('confirm')).toHaveAttribute('aria-invalid', 'true');
		expect(field('current')).not.toHaveAttribute('aria-invalid');
		expect(document.getElementById(`${field('new').id}-err`)?.textContent).toMatch(/15/);
		expect(document.getElementById(`${field('confirm').id}-err`)?.textContent).toMatch(
			/match|correspondent/i
		);
		expect(api.changePassword).not.toHaveBeenCalled();

		// Errors re-run live once shown: fixing the confirmation clears it.
		await user.clear(field('confirm'));
		await user.type(field('confirm'), 'short');
		await waitFor(() => expect(field('confirm')).not.toHaveAttribute('aria-invalid'));
		expect(field('new')).toHaveAttribute('aria-invalid', 'true');
	});

	it('puts the show/hide toggle in the tab order and reports its state', async () => {
		const user = userEvent.setup();
		render(ChangePasswordModal, { open: true });

		const toggle = screen.getByTestId('change-password-toggle-new');
		expect(toggle.tagName).toBe('BUTTON');
		expect(toggle).not.toHaveAttribute('tabindex', '-1');
		expect(toggle).toHaveAttribute('aria-pressed', 'false');

		// The toggle follows its own field in the tab order.
		field('new').focus();
		await user.tab();
		expect(toggle).toHaveFocus();

		await user.keyboard('{Enter}');
		await waitFor(() => expect(toggle).toHaveAttribute('aria-pressed', 'true'));
		expect(field('new').type).toBe('text');
		// The toggle is type="button": pressing it never submits.
		expect(api.changePassword).not.toHaveBeenCalled();
	});
});
