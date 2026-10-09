// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Modal component tests (Step F Chunk 7.2, spec §11.3 — 4 tests).
// Behavior-based per §11.2.
//
// Modal's API is { open, title, onClose, children, footer, width,
// dismissible }. `dismissible={false}` is what the spec §11.3 called
// `closeOnOverlay={false}`, extended to Escape: show-once secrets use
// it so a stray key cannot throw the secret away.

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Modal from './Modal.svelte';

function textSnippet(text: string) {
	return createRawSnippet(() => ({
		render: () => `<span>${text}</span>`
	}));
}

describe('Modal', () => {
	it('renders the title and children when open=true', () => {
		render(Modal, {
			open: true,
			title: 'Confirm action',
			onClose: vi.fn(),
			children: textSnippet('Are you sure?')
		});

		// role="dialog" exposes the modal; its accessible name comes
		// from aria-labelledby pointing at the title <h2>.
		const dialog = screen.getByRole('dialog', { name: 'Confirm action' });
		expect(dialog).toBeInTheDocument();
		expect(dialog).toHaveAttribute('aria-modal', 'true');
		expect(screen.getByText('Are you sure?')).toBeInTheDocument();
	});

	it('does not render any dialog when open=false', () => {
		render(Modal, {
			open: false,
			title: 'Hidden',
			onClose: vi.fn(),
			children: textSnippet('No content visible')
		});

		// {#if open} branch is false → nothing in the DOM.
		expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
		expect(screen.queryByText('No content visible')).not.toBeInTheDocument();
	});

	it('calls onClose when the Escape key is pressed', async () => {
		const onClose = vi.fn();
		const user = userEvent.setup();
		render(Modal, {
			open: true,
			title: 'Press Esc',
			onClose,
			children: textSnippet('Body')
		});

		// The Modal listens to keydown at the document level via $effect,
		// not on the dialog itself — userEvent.keyboard targets
		// document.body by default, which matches the real keyboard
		// event path.
		await user.keyboard('{Escape}');
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	it('calls onClose when the backdrop (overlay) is clicked', async () => {
		const onClose = vi.fn();
		const user = userEvent.setup();
		const { container } = render(Modal, {
			open: true,
			title: 'Click outside',
			onClose,
			children: textSnippet('Body')
		});

		// The backdrop is the .modal-backdrop element; its click handler
		// checks `e.target === e.currentTarget` so only clicks on the
		// backdrop itself (not bubbled from the inner dialog) close.
		const backdrop = container.querySelector('.modal-backdrop') as HTMLElement;
		expect(backdrop).not.toBeNull();
		await user.click(backdrop);
		expect(onClose).toHaveBeenCalledTimes(1);
	});

	// AL.4.b.2 — backward-compat pin: default width = 'md'
	// must keep the pre-extension max-w-md class. If a future
	// refactor changes the default token, every existing
	// caller (ConfirmDialog, ChangePasswordModal, ...) would
	// silently get a different width — this test catches
	// that regression.
	it('renders with max-w-md by default (backward-compat for unmodified callers)', () => {
		render(Modal, {
			open: true,
			title: 'Default width',
			onClose: vi.fn(),
			children: textSnippet('Body')
		});
		const dialog = screen.getByRole('dialog');
		expect(dialog.className).toContain('max-w-md');
		expect(dialog.className).not.toContain('max-w-2xl');
		expect(dialog.className).not.toContain('max-w-4xl');
	});

	// AL.4.b.2 — width="lg" maps to max-w-2xl. Pins the
	// token → class mapping so AL.4.b.2 ChannelModal +
	// AL.4.b.3 RuleModal render at the wider layout they
	// were designed against.
	it('renders with max-w-2xl when width="lg"', () => {
		render(Modal, {
			open: true,
			title: 'Wide modal',
			onClose: vi.fn(),
			children: textSnippet('Body'),
			width: 'lg'
		});
		const dialog = screen.getByRole('dialog');
		expect(dialog.className).toContain('max-w-2xl');
		expect(dialog.className).not.toContain('max-w-md');
	});

	// A long form (alert channel, DNS provider) used to grow past the
	// viewport inside the centred backdrop, clipping its Save footer
	// with no way to scroll to it.
	it('caps the dialog to the viewport and scrolls only the body', () => {
		render(Modal, {
			open: true,
			title: 'Long form',
			onClose: vi.fn(),
			children: textSnippet('Body')
		});
		const dialog = screen.getByRole('dialog');
		expect(dialog.className).toContain('max-h-[calc(100dvh-2rem)]');
		expect(dialog.className).toContain('flex-col');
		const body = screen.getByText('Body').closest('.overflow-y-auto');
		expect(body).not.toBeNull();
		expect(body?.className).toContain('min-h-0');
	});

	it('closes only the top-most of two stacked modals on Escape', async () => {
		const lowerClose = vi.fn();
		const upperClose = vi.fn();
		render(Modal, {
			open: true,
			title: 'Form',
			onClose: lowerClose,
			children: textSnippet('Form body')
		});
		const upper = render(Modal, {
			open: true,
			title: 'Discard changes?',
			onClose: upperClose,
			children: textSnippet('Confirm body')
		});

		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(upperClose).toHaveBeenCalledTimes(1);
		expect(lowerClose).not.toHaveBeenCalled();

		// Once the upper one is gone, Escape reaches the one below.
		await upper.rerender({ open: false });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(lowerClose).toHaveBeenCalledTimes(1);
		expect(upperClose).toHaveBeenCalledTimes(1);
	});

	it('ignores Escape and backdrop clicks when dismissible=false', async () => {
		const onClose = vi.fn();
		const { container } = render(Modal, {
			open: true,
			title: 'Secret',
			onClose,
			dismissible: false,
			children: textSnippet('Body')
		});

		await fireEvent.keyDown(document, { key: 'Escape' });
		const backdrop = container.querySelector('.modal-backdrop') as HTMLElement;
		await fireEvent.click(backdrop);

		expect(onClose).not.toHaveBeenCalled();
		expect(screen.getByRole('dialog')).toBeInTheDocument();
	});
});
