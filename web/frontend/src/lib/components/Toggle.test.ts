// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Toggle component tests (Step F Chunk 7.1, spec §11.3 — Theme group).
// Behavior-based per §11.2: render + simulate user interaction + assert
// observable outcome. Internal $state is not asserted directly.
//
// The Toggle is a controlled component (Chunk 1.6 fix): the `value`
// prop is NOT bindable; the caller drives it via re-render after
// onchange. Tests therefore assert on the onchange callback, not on
// any internal mutation of `value`.

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Toggle from './Toggle.svelte';

const themeOptions: [
	{ value: 'dark' | 'light'; label: string },
	{ value: 'dark' | 'light'; label: string }
] = [
	{ value: 'dark', label: 'Dark' },
	{ value: 'light', label: 'Light' }
];

describe('Toggle', () => {
	it('renders both options as accessible radio buttons', () => {
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme'
		});

		// Both options become role="radio" buttons inside a radiogroup
		// per Toggle's internal markup. Querying by name (= visible label)
		// is the user-facing path.
		const dark = screen.getByRole('radio', { name: 'Dark' });
		const light = screen.getByRole('radio', { name: 'Light' });
		expect(dark).toBeInTheDocument();
		expect(light).toBeInTheDocument();
		// The currently-active option has aria-checked="true"; the other false.
		expect(dark).toHaveAttribute('aria-checked', 'true');
		expect(light).toHaveAttribute('aria-checked', 'false');
	});

	it('calls onchange with the new value when the inactive option is clicked', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme',
			onchange
		});

		await user.click(screen.getByRole('radio', { name: 'Light' }));
		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('light');
	});

	it('does not call onchange when disabled', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme',
			disabled: true,
			onchange
		});

		// Clicking should be a no-op when disabled — the pick() handler
		// guards with `if (disabled || v === value) return;` before
		// invoking onchange.
		await user.click(screen.getByRole('radio', { name: 'Light' }));
		expect(onchange).not.toHaveBeenCalled();
	});

	it('is a single Tab stop: only the checked option is tabbable (roving tabindex)', () => {
		render(Toggle, {
			options: themeOptions,
			value: 'light',
			ariaLabel: 'Theme'
		});
		expect(screen.getByRole('radio', { name: 'Light' })).toHaveAttribute('tabindex', '0');
		expect(screen.getByRole('radio', { name: 'Dark' })).toHaveAttribute('tabindex', '-1');
	});

	it('moves the selection and the focus with the arrow keys', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme',
			onchange
		});

		await user.tab();
		expect(screen.getByRole('radio', { name: 'Dark' })).toHaveFocus();

		await user.keyboard('{ArrowRight}');
		expect(onchange).toHaveBeenLastCalledWith('light');
		expect(screen.getByRole('radio', { name: 'Light' })).toHaveFocus();

		// Two options: ArrowLeft from the first one wraps to the last.
		onchange.mockClear();
		screen.getByRole('radio', { name: 'Dark' }).focus();
		await user.keyboard('{ArrowLeft}');
		expect(onchange).toHaveBeenCalledWith('light');

		onchange.mockClear();
		await user.keyboard('{End}');
		expect(onchange).toHaveBeenCalledWith('light');
	});

	it('ignores the arrow keys when disabled', async () => {
		const onchange = vi.fn();
		render(Toggle, {
			options: themeOptions,
			value: 'dark',
			ariaLabel: 'Theme',
			disabled: true,
			onchange
		});
		await fireEvent.keyDown(screen.getByRole('radiogroup', { name: 'Theme' }), {
			key: 'ArrowRight'
		});
		expect(onchange).not.toHaveBeenCalled();
	});
});
