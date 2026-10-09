// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// ToastContainer + Toast: each toast is announced exactly once, by the
// right live region (danger → role="alert", the rest → polite
// role="status"), the toasts themselves carry no role, the dismiss
// control is labelled and works, and hover/focus pause the countdown.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, within, fireEvent } from '@testing-library/svelte';
import { tick } from 'svelte';
import { get } from 'svelte/store';
import { toasts, pushToast, dismissToast } from '$lib/stores/toast';
import ToastContainer from './ToastContainer.svelte';

afterEach(() => {
	for (const entry of get(toasts)) dismissToast(entry.id);
	vi.useRealTimers();
});

describe('ToastContainer live regions', () => {
	it('renders both regions up front, before any toast exists', () => {
		render(ToastContainer);
		const polite = screen.getByRole('status');
		const alert = screen.getByRole('alert');
		expect(polite).toHaveAttribute('aria-live', 'polite');
		expect(alert).toHaveAttribute('aria-live', 'assertive');
		expect(polite).toHaveAttribute('aria-atomic', 'false');
		expect(alert).toHaveAttribute('aria-atomic', 'false');
	});

	it('puts danger in the alert region and info/success in the polite one', async () => {
		render(ToastContainer);
		pushToast('Route saved', 'success');
		pushToast('Checking certificate', 'info');
		pushToast('Upstream unreachable', 'danger');
		await tick();

		const polite = screen.getByRole('status');
		const alert = screen.getByRole('alert');
		expect(polite).toHaveTextContent('Route saved');
		expect(polite).toHaveTextContent('Checking certificate');
		expect(polite).not.toHaveTextContent('Upstream unreachable');
		expect(alert).toHaveTextContent('Upstream unreachable');
		expect(alert).not.toHaveTextContent('Route saved');
	});

	it('gives the toasts no role of their own, so nothing is announced twice', async () => {
		const { container } = render(ToastContainer);
		pushToast('Route saved', 'success');
		pushToast('Upstream unreachable', 'danger');
		await tick();

		// Exactly one status and one alert in the whole tree: the regions.
		expect(screen.getAllByRole('status')).toHaveLength(1);
		expect(screen.getAllByRole('alert')).toHaveLength(1);
		for (const toast of container.querySelectorAll('[data-variant]')) {
			expect(toast).not.toHaveAttribute('role');
			expect(toast).not.toHaveAttribute('aria-live');
		}
	});
});

describe('Toast', () => {
	it('shows a decorative icon per variant', async () => {
		const { container } = render(ToastContainer);
		pushToast('a', 'success');
		pushToast('b', 'info');
		pushToast('c', 'danger');
		await tick();

		for (const variant of ['success', 'info', 'danger']) {
			const icon = container.querySelector(`[data-variant="${variant}"] svg[data-icon="${variant}"]`);
			expect(icon).not.toBeNull();
			expect(icon).toHaveAttribute('aria-hidden', 'true');
		}
	});

	it('has a labelled dismiss button that removes the toast', async () => {
		render(ToastContainer);
		pushToast('Upstream unreachable', 'danger');
		await tick();

		const alert = screen.getByRole('alert');
		const button = within(alert).getByRole('button', { name: 'Dismiss notification' });
		expect(button).toHaveAttribute('type', 'button');
		await fireEvent.click(button);
		expect(alert).not.toHaveTextContent('Upstream unreachable');
		expect(get(toasts)).toEqual([]);
	});

	it('pauses the countdown while hovered', async () => {
		vi.useFakeTimers();
		const { container } = render(ToastContainer);
		pushToast('Route saved', 'success'); // 5 s
		await tick();
		const toast = container.querySelector('[data-variant="success"]') as HTMLElement;

		vi.advanceTimersByTime(4000);
		await fireEvent.mouseEnter(toast);
		vi.advanceTimersByTime(30000);
		expect(get(toasts)).toHaveLength(1);

		await fireEvent.mouseLeave(toast);
		vi.advanceTimersByTime(999);
		expect(get(toasts)).toHaveLength(1);
		vi.advanceTimersByTime(1);
		expect(get(toasts)).toHaveLength(0);
	});

	it('pauses the countdown while focus is inside, even after the pointer leaves', async () => {
		vi.useFakeTimers();
		render(ToastContainer);
		pushToast('Route saved', 'success'); // 5 s
		await tick();
		const toast = screen.getByText('Route saved').closest('[data-variant]') as HTMLElement;
		const button = within(toast).getByRole('button');

		vi.advanceTimersByTime(1000);
		await fireEvent.mouseEnter(toast);
		button.focus();
		await fireEvent.mouseLeave(toast);
		vi.advanceTimersByTime(30000);
		expect(get(toasts)).toHaveLength(1);

		button.blur();
		vi.advanceTimersByTime(3999);
		expect(get(toasts)).toHaveLength(1);
		vi.advanceTimersByTime(1);
		expect(get(toasts)).toHaveLength(0);
	});
});
