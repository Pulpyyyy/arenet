// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Tooltip component tests (Step F Chunk 7.3, spec §11.3).
// Behavior-based per §11.2.
//
// Tooltip shows its label on mouseenter (hover) and focusin (keyboard
// a11y), describes the focusable trigger (aria-describedby on the
// trigger, not on the wrapper) and closes on Escape (WCAG 1.4.13).

import { describe, it, expect } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet } from 'svelte';
import Tooltip from './Tooltip.svelte';

function buttonSnippet() {
	return createRawSnippet(() => ({
		render: () => `<button type="button">Trigger</button>`
	}));
}

describe('Tooltip', () => {
	it('shows the label when the trigger is hovered', async () => {
		const user = userEvent.setup();
		render(Tooltip, {
			label: 'Helpful hint',
			children: buttonSnippet()
		});

		// Before hover: the bubble is `hidden`, so it is not exposed as
		// a tooltip (getByRole skips hidden elements).
		expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

		// Hover the trigger — mouseenter flips `open` to true on the
		// wrapper, which lifts the bubble's `hidden` attribute.
		await user.hover(screen.getByRole('button', { name: 'Trigger' }));
		await waitFor(() => {
			expect(screen.getByRole('tooltip')).toHaveTextContent('Helpful hint');
		});
	});

	it('shows the label when the trigger receives keyboard focus', async () => {
		render(Tooltip, {
			label: 'Keyboard a11y',
			children: buttonSnippet()
		});

		// Programmatic focus on the trigger fires focusin on the wrapper
		// span (focus events bubble), which mirrors what Tab-navigating
		// would do. The tooltip then shows with the label content.
		const trigger = screen.getByRole('button', { name: 'Trigger' });
		trigger.focus();
		expect(trigger).toHaveFocus();

		await waitFor(() => {
			expect(screen.getByRole('tooltip')).toHaveTextContent('Keyboard a11y');
		});
	});

	it('puts aria-describedby on the focusable trigger, not on the wrapper', async () => {
		const { container } = render(Tooltip, {
			label: 'Described',
			children: buttonSnippet()
		});
		const trigger = screen.getByRole('button', { name: 'Trigger' });
		await waitFor(() => {
			expect(trigger.getAttribute('aria-describedby')).toBeTruthy();
		});
		const bubble = document.getElementById(trigger.getAttribute('aria-describedby') as string);
		expect(bubble).toHaveTextContent('Described');
		expect(bubble).toHaveAttribute('role', 'tooltip');

		const wrapper = container.querySelector('.tt-wrapper') as HTMLElement;
		expect(wrapper).not.toHaveAttribute('aria-describedby');
		expect(wrapper).not.toHaveAttribute('tabindex');
	});

	it('keeps ids the caller already put in aria-describedby', async () => {
		render(Tooltip, {
			label: 'Merged',
			children: createRawSnippet(() => ({
				render: () => `<button type="button" aria-describedby="caller-hint">Trigger</button>`
			}))
		});
		const trigger = screen.getByRole('button', { name: 'Trigger' });
		await waitFor(() => {
			const ids = (trigger.getAttribute('aria-describedby') ?? '').split(' ');
			expect(ids).toContain('caller-hint');
			expect(ids).toHaveLength(2);
		});
	});

	it('makes the wrapper the trigger when the child is not focusable', async () => {
		const { container } = render(Tooltip, {
			label: 'Badge hint',
			children: createRawSnippet(() => ({
				render: () => `<span>Badge</span>`
			}))
		});
		const wrapper = container.querySelector('.tt-wrapper') as HTMLElement;
		await waitFor(() => {
			expect(wrapper).toHaveAttribute('tabindex', '0');
		});
		const bubble = document.getElementById(wrapper.getAttribute('aria-describedby') as string);
		expect(bubble).toHaveTextContent('Badge hint');

		wrapper.focus();
		await waitFor(() => {
			expect(screen.getByRole('tooltip')).toHaveTextContent('Badge hint');
		});
	});

	it('closes on Escape, whether opened by focus or by hover', async () => {
		const user = userEvent.setup();
		render(Tooltip, {
			label: 'Dismiss me',
			children: buttonSnippet()
		});
		const trigger = screen.getByRole('button', { name: 'Trigger' });

		// Focus-opened: Escape closes it and focus stays on the trigger.
		trigger.focus();
		await waitFor(() => expect(screen.getByRole('tooltip')).toBeInTheDocument());
		await user.keyboard('{Escape}');
		await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
		expect(trigger).toHaveFocus();

		// Hover-opened with the focus elsewhere: Escape still closes it.
		trigger.blur();
		await user.hover(trigger);
		await waitFor(() => expect(screen.getByRole('tooltip')).toBeInTheDocument());
		await fireEvent.keyDown(window, { key: 'Escape' });
		await waitFor(() => expect(screen.queryByRole('tooltip')).not.toBeInTheDocument());
	});
});
