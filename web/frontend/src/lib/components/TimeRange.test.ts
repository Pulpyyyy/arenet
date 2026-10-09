// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// TimeRange — the shared time-window segmented control.
//
// Pins the contract callers rely on: aria-pressed on the selected
// option, arrow / Home / End navigation with a roving tabindex, the
// configurable subset of windows, onChange on user selection only,
// and a two-way `value` binding.

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import en from '$lib/i18n/locales/en.json';
import TimeRange from './TimeRange.svelte';
import Harness from './_time_range_harness.test.svelte';

const btn = (id: string) => screen.getByTestId(`time-range-${id}`);

describe('TimeRange', () => {
	it('renders all four windows by default, labelled via i18n', () => {
		render(TimeRange, { value: '24h' });
		expect(btn('1h').textContent?.trim()).toBe(en.timeRange['1h']);
		expect(btn('24h').textContent?.trim()).toBe(en.timeRange['24h']);
		expect(btn('7d').textContent?.trim()).toBe(en.timeRange['7d']);
		expect(btn('30d').textContent?.trim()).toBe(en.timeRange['30d']);
	});

	it('renders only the configured subset, in the given order', () => {
		render(TimeRange, { value: '24h', options: ['24h', '30d'] as const });
		const ids = screen.getAllByRole('button').map((b) => b.getAttribute('data-testid'));
		expect(ids).toEqual(['time-range-24h', 'time-range-30d']);
	});

	it('is a labelled group, defaulting to the i18n label', () => {
		render(TimeRange, { value: '24h' });
		expect(screen.getByRole('group', { name: en.timeRange.ariaLabel })).toBeInTheDocument();
	});

	it('marks only the selected window with aria-pressed=true', async () => {
		render(TimeRange, { value: '24h' });
		expect(btn('24h')).toHaveAttribute('aria-pressed', 'true');
		for (const id of ['1h', '7d', '30d']) {
			expect(btn(id)).toHaveAttribute('aria-pressed', 'false');
		}

		await fireEvent.click(btn('7d'));
		expect(btn('7d')).toHaveAttribute('aria-pressed', 'true');
		expect(btn('24h')).toHaveAttribute('aria-pressed', 'false');
	});

	it('keeps only the selected window in the tab order', () => {
		render(TimeRange, { value: '7d' });
		expect(btn('7d')).toHaveAttribute('tabindex', '0');
		for (const id of ['1h', '24h', '30d']) {
			expect(btn(id)).toHaveAttribute('tabindex', '-1');
		}
	});

	it('fires onChange on a new selection, not on the current one', async () => {
		const onChange = vi.fn();
		render(TimeRange, { value: '24h', onChange });

		await fireEvent.click(btn('24h'));
		expect(onChange).not.toHaveBeenCalled();

		await fireEvent.click(btn('30d'));
		expect(onChange).toHaveBeenCalledTimes(1);
		expect(onChange).toHaveBeenCalledWith('30d');
	});

	it('moves selection and focus with the arrow keys, wrapping at the ends', async () => {
		const onChange = vi.fn();
		render(TimeRange, { value: '24h', onChange });

		await fireEvent.keyDown(btn('24h'), { key: 'ArrowRight' });
		expect(btn('7d')).toHaveAttribute('aria-pressed', 'true');
		expect(document.activeElement).toBe(btn('7d'));

		await fireEvent.keyDown(btn('7d'), { key: 'ArrowRight' });
		await fireEvent.keyDown(btn('30d'), { key: 'ArrowRight' });
		expect(btn('1h')).toHaveAttribute('aria-pressed', 'true');
		expect(document.activeElement).toBe(btn('1h'));

		await fireEvent.keyDown(btn('1h'), { key: 'ArrowLeft' });
		expect(btn('30d')).toHaveAttribute('aria-pressed', 'true');

		expect(onChange.mock.calls.map((c) => c[0])).toEqual(['7d', '30d', '1h', '30d']);
	});

	it('jumps to the first and last window with Home and End', async () => {
		render(TimeRange, { value: '24h' });

		await fireEvent.keyDown(btn('24h'), { key: 'End' });
		expect(btn('30d')).toHaveAttribute('aria-pressed', 'true');

		await fireEvent.keyDown(btn('30d'), { key: 'Home' });
		expect(btn('1h')).toHaveAttribute('aria-pressed', 'true');
		expect(document.activeElement).toBe(btn('1h'));
	});

	it('ignores unrelated keys', async () => {
		const onChange = vi.fn();
		render(TimeRange, { value: '24h', onChange });
		await fireEvent.keyDown(btn('24h'), { key: 'a' });
		expect(onChange).not.toHaveBeenCalled();
		expect(btn('24h')).toHaveAttribute('aria-pressed', 'true');
	});

	it('binds value both ways', async () => {
		render(Harness);
		const bound = () => screen.getByTestId('bound').textContent;
		expect(bound()).toBe('24h');

		// Control → parent.
		await fireEvent.click(btn('1h'));
		expect(bound()).toBe('1h');
		await fireEvent.keyDown(btn('1h'), { key: 'ArrowRight' });
		expect(bound()).toBe('24h');

		// Parent → control.
		await fireEvent.click(screen.getByTestId('set-7d'));
		expect(btn('7d')).toHaveAttribute('aria-pressed', 'true');
		expect(btn('24h')).toHaveAttribute('aria-pressed', 'false');
	});
});
