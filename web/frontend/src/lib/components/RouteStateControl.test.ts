// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// RouteStateControl component tests (Task 8). Behavior-based per the
// project's Toggle-neighbor test convention: render + simulate user
// interaction + assert observable outcome, no internal state peeking.
//
// RouteStateControl is a controlled component (mirrors Toggle.svelte's
// contract): `value` is NOT bindable, the caller re-renders after
// `onchange` fires. Unlike Toggle (2 fixed generic options), this
// component has 3 FIXED states: active / maintenance / disabled.

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import RouteStateControl from './RouteStateControl.svelte';
import { t } from '$lib/i18n';
import { language } from '$lib/stores/language.svelte';

describe('RouteStateControl', () => {
	// v2.17.1 UX polish (Item A): the component now renders ICONS
	// ONLY — the visible `.lbl` text span was removed to keep the
	// control compact. The labels still exist, but as `title`
	// (hover tooltip) + `aria-label` per segment rather than a text
	// node. `getByRole('radio', { name })` matches the ACCESSIBLE
	// NAME, which aria-label now supplies directly (no visible text
	// contributes to it), so this continues to locate segments by
	// label while proving the labels are no longer visible text.
	it('renders 3 radio segments with the state labels, active one aria-checked=true', () => {
		render(RouteStateControl, { value: 'active' });

		const active = screen.getByRole('radio', { name: 'Active' });
		const maintenance = screen.getByRole('radio', { name: 'Maintenance' });
		const disabled = screen.getByRole('radio', { name: 'Disabled' });

		expect(active).toBeInTheDocument();
		expect(maintenance).toBeInTheDocument();
		expect(disabled).toBeInTheDocument();

		expect(active).toHaveAttribute('aria-checked', 'true');
		expect(maintenance).toHaveAttribute('aria-checked', 'false');
		expect(disabled).toHaveAttribute('aria-checked', 'false');

		// The label is carried by title + aria-label, NOT a visible
		// text node — this is the crux of Item A.
		expect(active).toHaveAttribute('title', 'Active');
		expect(active).toHaveAttribute('aria-label', 'Active');
		expect(maintenance).toHaveAttribute('title', 'Maintenance');
		expect(maintenance).toHaveAttribute('aria-label', 'Maintenance');
		expect(disabled).toHaveAttribute('title', 'Disabled');
		expect(disabled).toHaveAttribute('aria-label', 'Disabled');
		expect(screen.queryByText('Active')).toBeNull();
		expect(screen.queryByText('Maintenance')).toBeNull();
		expect(screen.queryByText('Disabled')).toBeNull();
	});

	it('calls onchange with "maintenance" when the maintenance segment is clicked', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(RouteStateControl, { value: 'active', onchange });

		// Locate the segment via its aria-label (Item A: the segment
		// with aria-label "Maintenance" fires onchange('maintenance')
		// on click, per the brief).
		await user.click(screen.getByRole('radio', { name: 'Maintenance' }));

		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('maintenance');
	});

	// Manual activation: every pick is a live change to a route, so
	// arrowing across the group must not apply what it passes over.
	it('moves focus with the arrow keys without calling onchange', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(RouteStateControl, { value: 'active', onchange });

		const active = screen.getByRole('radio', { name: 'Active' });
		const maintenance = screen.getByRole('radio', { name: 'Maintenance' });
		const disabled = screen.getByRole('radio', { name: 'Disabled' });
		active.focus();

		await user.keyboard('{ArrowRight}');
		expect(maintenance).toHaveFocus();
		// Roving tabindex follows focus; the checked state does not.
		expect(maintenance).toHaveAttribute('tabindex', '0');
		expect(active).toHaveAttribute('tabindex', '-1');
		expect(active).toHaveAttribute('aria-checked', 'true');

		await user.keyboard('{ArrowRight}');
		expect(disabled).toHaveFocus();
		await user.keyboard('{ArrowRight}');
		expect(active).toHaveFocus();
		await user.keyboard('{End}');
		expect(disabled).toHaveFocus();

		expect(onchange).not.toHaveBeenCalled();
	});

	it('commits the focused segment on Enter', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(RouteStateControl, { value: 'active', onchange });

		screen.getByRole('radio', { name: 'Active' }).focus();
		await user.keyboard('{ArrowRight}');
		await user.keyboard('{Enter}');

		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('maintenance');
	});

	it('commits the focused segment on Space', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(RouteStateControl, { value: 'active', onchange });

		screen.getByRole('radio', { name: 'Active' }).focus();
		await user.keyboard('{ArrowLeft}');
		await user.keyboard(' ');

		expect(onchange).toHaveBeenCalledTimes(1);
		expect(onchange).toHaveBeenCalledWith('disabled');
	});

	it('does nothing while disabled', async () => {
		const onchange = vi.fn();
		const user = userEvent.setup();
		render(RouteStateControl, { value: 'active', onchange, disabled: true });

		const maintenance = screen.getByRole('radio', { name: 'Maintenance' });
		expect(maintenance).toBeDisabled();
		await user.click(maintenance);
		await user.keyboard('{ArrowRight}{Enter}');

		expect(onchange).not.toHaveBeenCalled();
	});

	it('exposes a radiogroup with the given aria-label', () => {
		render(RouteStateControl, { value: 'disabled', ariaLabel: 'Route state' });

		expect(screen.getByRole('radiogroup', { name: 'Route state' })).toBeInTheDocument();
	});

	// Final-review Finding #3 (v2.17.0) — i18n regression. The
	// component previously hardcoded LABELS = {active:'Active', ...}
	// in English regardless of locale, even though the
	// `routes.state.*` i18n keys exist and differ by locale
	// (fr.json disabled: "Désactivée"). The parent (+page.svelte)
	// now passes a `labels` prop built from t('routes.state.*').
	// This test renders the component the way the parent does under
	// the FR locale and asserts the FR label appears — it must FAIL
	// against the old hardcoded-English behavior (which ignores any
	// `labels` prop and always renders "Disabled").
	it('renders the FR-translated label when the parent passes labels resolved via t() under the FR locale', () => {
		language.applyLocally('fr');
		try {
			const labels = {
				active: t('routes.state.active'),
				maintenance: t('routes.state.maintenance'),
				disabled: t('routes.state.disabled')
			};
			expect(labels.disabled).toBe('Désactivée');

			render(RouteStateControl, { value: 'disabled', labels });

			const seg = screen.getByRole('radio', { name: 'Désactivée' });
			expect(seg).toBeInTheDocument();
			expect(seg).toHaveAttribute('title', 'Désactivée');
			expect(screen.queryByRole('radio', { name: 'Disabled' })).toBeNull();
		} finally {
			language.applyLocally('en');
		}
	});
});
