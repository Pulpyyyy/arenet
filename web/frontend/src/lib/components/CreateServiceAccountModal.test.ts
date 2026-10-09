// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 4 — CreateServiceAccountModal tests. Covers the
// two-stage form → reveal flow, the copy-then-close UX
// gate, and the absence of token persistence after close.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type {
	CreateServiceAccountRequest,
	CreateServiceAccountResponse
} from '$lib/api/types';

const createMock = vi.fn<(r: CreateServiceAccountRequest) => Promise<CreateServiceAccountResponse>>();
vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		createServiceAccount: (r: CreateServiceAccountRequest) => createMock(r)
	}
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (m: string, v?: string) => pushToastMock(m, v)
}));

const writeTextMock = vi.fn<(t: string) => Promise<void>>();
Object.defineProperty(global.navigator, 'clipboard', {
	value: { writeText: (t: string) => writeTextMock(t) },
	configurable: true
});

function baseResponse(overrides: Partial<CreateServiceAccountResponse> = {}): CreateServiceAccountResponse {
	return {
		user: {
			id: 'svc-id',
			username: 'ci-deploy',
			displayName: 'ci-deploy',
			authSource: 'service',
			oidcLinked: false,
			role: 'viewer',
			createdAt: '',
			updatedAt: '',
			activeSessionCount: 0
		},
		token: 'arn_revealedrevealedrevealedrevealedrevealedrevea',
		tokenId: 'tok-1',
		...overrides
	};
}

beforeEach(() => {
	createMock.mockReset();
	pushToastMock.mockReset();
	writeTextMock.mockReset();
	writeTextMock.mockResolvedValue();
});

describe('CreateServiceAccountModal', () => {
	it('renders the form with default role=viewer and expiry=never', async () => {
		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		expect(screen.getByTestId('svc-name-input')).toBeTruthy();
		expect(screen.getByTestId('svc-role-select')).toBeTruthy();
		expect(screen.getByTestId('svc-expiry-select')).toBeTruthy();
		expect(screen.getByTestId('svc-submit-button')).toBeTruthy();
	});

	it('calls the API on submit and reveals the token afterward', async () => {
		createMock.mockResolvedValue(baseResponse());

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		const nameInput = screen.getByTestId('svc-name-input') as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'ci-deploy' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));

		await waitFor(() => expect(createMock).toHaveBeenCalled());
		const arg = createMock.mock.calls[0][0];
		expect(arg.name).toBe('ci-deploy');
		expect(arg.role).toBe('viewer');
		expect(arg.expiresAt).toBeUndefined(); // never

		await waitFor(() => expect(screen.getByTestId('svc-revealed-token')).toBeTruthy());
		expect(screen.getByTestId('svc-revealed-token').textContent).toContain('arn_revealed');
	});

	it('"Fermer" stays disabled until the token is copied', async () => {
		createMock.mockResolvedValue(baseResponse());

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		const nameInput = screen.getByTestId('svc-name-input') as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'ci' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));

		await waitFor(() => expect(screen.getByTestId('svc-close-button')).toBeTruthy());
		const closeBtn = screen.getByTestId('svc-close-button') as HTMLButtonElement;
		expect(closeBtn.disabled).toBe(true);

		await fireEvent.click(screen.getByTestId('svc-copy-button'));
		await waitFor(() => expect(writeTextMock).toHaveBeenCalled());

		// The copy resolves through the clipboard helper a few
		// microtasks later; wait for the re-render instead of racing it.
		await waitFor(() => expect(closeBtn.disabled).toBe(false));
	});

	// Escape and the backdrop used to run the same close as the button,
	// throwing away a token that is never shown again.
	it('keeps the token on Escape or a backdrop click during the reveal', async () => {
		createMock.mockResolvedValue(baseResponse());
		const onClose = vi.fn();

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose } });

		await fireEvent.input(screen.getByTestId('svc-name-input'), { target: { value: 'ci' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));
		await waitFor(() => expect(screen.getByTestId('svc-revealed-token')).toBeTruthy());

		await fireEvent.keyDown(document, { key: 'Escape' });
		await fireEvent.click(document.querySelector('.modal-backdrop') as HTMLElement);

		expect(onClose).not.toHaveBeenCalled();
		expect(screen.getByTestId('svc-revealed-token').textContent).toContain('arn_revealed');
	});

	it('unlocks "Fermer" when the operator ticks "I have saved it"', async () => {
		createMock.mockResolvedValue(baseResponse());
		const onClose = vi.fn();

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose } });

		await fireEvent.input(screen.getByTestId('svc-name-input'), { target: { value: 'ci' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));
		await waitFor(() => expect(screen.getByTestId('svc-close-button')).toBeTruthy());

		const closeBtn = screen.getByTestId('svc-close-button') as HTMLButtonElement;
		expect(closeBtn.disabled).toBe(true);
		await fireEvent.click(screen.getByTestId('svc-saved-checkbox'));
		expect(closeBtn.disabled).toBe(false);
		expect(writeTextMock).not.toHaveBeenCalled();

		await fireEvent.click(closeBtn);
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('says so in the dialog when copying fails on a plain-HTTP origin', async () => {
		createMock.mockResolvedValue(baseResponse());

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		await fireEvent.input(screen.getByTestId('svc-name-input'), { target: { value: 'ci' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));
		await waitFor(() => expect(screen.getByTestId('svc-copy-button')).toBeTruthy());

		// No Clipboard API outside a secure context, and the legacy
		// execCommand path refused as well.
		Object.defineProperty(global.navigator, 'clipboard', { value: undefined, configurable: true });
		Object.defineProperty(document, 'execCommand', { value: () => false, configurable: true });
		try {
			await fireEvent.click(screen.getByTestId('svc-copy-button'));
			const failed = await screen.findByTestId('svc-copy-failed');
			expect(failed.textContent).toMatch(/by hand|à la main/i);
			expect((screen.getByTestId('svc-close-button') as HTMLButtonElement).disabled).toBe(true);
			// No success toast for a copy that did not happen.
			expect(pushToastMock).not.toHaveBeenCalledWith(expect.anything(), 'success');
		} finally {
			Object.defineProperty(global.navigator, 'clipboard', {
				value: { writeText: (t: string) => writeTextMock(t) },
				configurable: true
			});
			delete (document as unknown as Record<string, unknown>).execCommand;
		}
	});

	it('clipboard write fires with the plain token on copy', async () => {
		createMock.mockResolvedValue(baseResponse());

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		const nameInput = screen.getByTestId('svc-name-input') as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'ci' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));
		await waitFor(() => screen.getByTestId('svc-copy-button'));

		await fireEvent.click(screen.getByTestId('svc-copy-button'));
		await waitFor(() => expect(writeTextMock).toHaveBeenCalled());

		expect(writeTextMock.mock.calls[0][0]).toContain('arn_revealed');
	});

	it('shows a danger toast when the API fails', async () => {
		createMock.mockRejectedValue(new Error('name already taken'));

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		const nameInput = screen.getByTestId('svc-name-input') as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'dup' } });
		await fireEvent.click(screen.getByTestId('svc-submit-button'));

		await waitFor(() => expect(pushToastMock).toHaveBeenCalled());
		expect(pushToastMock.mock.calls[0][1]).toBe('danger');
	});

	it('computes the expected ISO expiry for non-never presets', async () => {
		createMock.mockResolvedValue(baseResponse());

		const Modal = (await import('./CreateServiceAccountModal.svelte')).default;
		render(Modal, { props: { open: true, onClose: () => {} } });

		await fireEvent.input(screen.getByTestId('svc-name-input'), { target: { value: 'x' } });
		const expirySel = screen.getByTestId('svc-expiry-select') as HTMLSelectElement;
		await fireEvent.change(expirySel, { target: { value: '30d' } });

		await fireEvent.click(screen.getByTestId('svc-submit-button'));
		await waitFor(() => expect(createMock).toHaveBeenCalled());

		const arg = createMock.mock.calls[0][0];
		expect(arg.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
		// ~30 days ahead (allow ±2 days slack for test-machine clock drift).
		const expiry = new Date(arg.expiresAt!).getTime();
		const now = Date.now();
		const deltaDays = (expiry - now) / 86_400_000;
		expect(deltaDays).toBeGreaterThan(28);
		expect(deltaDays).toBeLessThan(32);
	});
});
