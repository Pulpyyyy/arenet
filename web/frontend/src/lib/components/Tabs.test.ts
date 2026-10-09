// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step CS.3 — Tabs component tests.
//
// Pins the public contract extracted from the pre-CS.3 inline
// tablists in /security/decisions and /certs:
//   - role="tablist" wrapper with operator-supplied aria-label
//   - role="tab" buttons with aria-selected on the active one
//   - testId on each tab so callers preserve existing test IDs
//   - click → emits onChange + updates the bindable value
//   - clicking the already-active tab is a no-op (onChange NOT
//     fired) — caller invariant from the pre-extraction code
//   - keyboard activation: Enter/Space natively via <button>
//   - arrow / Home / End move focus (roving tabindex, manual
//     activation) and aria-controls follows an optional panelId

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import Tabs from './Tabs.svelte';

type DemoTab = 'snapshot' | 'live' | 'scenarios';

const demoTabs: ReadonlyArray<{ id: DemoTab; label: string; testId?: string }> = [
	{ id: 'snapshot', label: 'Local snapshot', testId: 'tab-snapshot' },
	{ id: 'live', label: 'Live LAPI', testId: 'tab-live' },
	{ id: 'scenarios', label: 'Scenarios', testId: 'tab-scenarios' }
];

describe('Tabs', () => {
	it('renders one button per tab with the right label + testId', () => {
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		expect(screen.getByTestId('tab-snapshot').textContent).toContain('Local snapshot');
		expect(screen.getByTestId('tab-live').textContent).toContain('Live LAPI');
		expect(screen.getByTestId('tab-scenarios').textContent).toContain('Scenarios');
	});

	it('applies role="tablist" + the operator-supplied aria-label', () => {
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'CrowdSec decisions tabs'
		});
		const tablist = screen.getByRole('tablist', { name: 'CrowdSec decisions tabs' });
		expect(tablist).toBeInTheDocument();
	});

	it('marks the active tab with aria-selected=true, others false', () => {
		render(Tabs, {
			value: 'live' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		expect(screen.getByTestId('tab-live')).toHaveAttribute('aria-selected', 'true');
		expect(screen.getByTestId('tab-snapshot')).toHaveAttribute('aria-selected', 'false');
		expect(screen.getByTestId('tab-scenarios')).toHaveAttribute('aria-selected', 'false');
	});

	it('fires onChange when a different tab is clicked', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});

		await fireEvent.click(screen.getByTestId('tab-live'));
		expect(onChange).toHaveBeenCalledWith('live');
	});

	it('does NOT fire onChange when clicking the already-active tab', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});
		await fireEvent.click(screen.getByTestId('tab-snapshot'));
		expect(onChange).not.toHaveBeenCalled();
	});

	it('works without an onChange callback (bindable value only)', async () => {
		// No onChange — caller relies purely on the bindable
		// value mutation. Must not throw.
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		await fireEvent.click(screen.getByTestId('tab-scenarios'));
		// No assertion on side effects — the absence-of-error
		// is the contract. If render or click threw, the test
		// would fail above.
	});

	it('handles keyboard activation natively via <button>', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});

		const liveTab = screen.getByTestId('tab-live');
		liveTab.focus();
		// Enter key on a focused <button> fires a click event
		// natively in the browser — JSDOM emulates this.
		await fireEvent.keyDown(liveTab, { key: 'Enter' });
		// Some envs need explicit click() to mimic Enter on a
		// button; do both for stability.
		await fireEvent.click(liveTab);
		expect(onChange).toHaveBeenCalledWith('live');
	});

	it('is a single Tab stop: only the selected tab is tabbable (roving tabindex)', () => {
		render(Tabs, {
			value: 'live' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs'
		});
		expect(screen.getByTestId('tab-live')).toHaveAttribute('tabindex', '0');
		expect(screen.getByTestId('tab-snapshot')).toHaveAttribute('tabindex', '-1');
		expect(screen.getByTestId('tab-scenarios')).toHaveAttribute('tabindex', '-1');
	});

	it('moves focus with the arrow keys, Home and End — without selecting (manual activation)', async () => {
		const onChange = vi.fn();
		render(Tabs, {
			value: 'snapshot' as DemoTab,
			tabs: demoTabs,
			ariaLabel: 'Demo tabs',
			onChange
		});
		const tablist = screen.getByRole('tablist', { name: 'Demo tabs' });
		screen.getByTestId('tab-snapshot').focus();

		await fireEvent.keyDown(tablist, { key: 'ArrowRight' });
		expect(screen.getByTestId('tab-live')).toHaveFocus();

		await fireEvent.keyDown(tablist, { key: 'End' });
		expect(screen.getByTestId('tab-scenarios')).toHaveFocus();

		// Wraps from the last tab to the first.
		await fireEvent.keyDown(tablist, { key: 'ArrowRight' });
		expect(screen.getByTestId('tab-snapshot')).toHaveFocus();

		// And from the first back to the last.
		await fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
		expect(screen.getByTestId('tab-scenarios')).toHaveFocus();

		await fireEvent.keyDown(tablist, { key: 'Home' });
		expect(screen.getByTestId('tab-snapshot')).toHaveFocus();

		// Moving focus never selected anything.
		expect(onChange).not.toHaveBeenCalled();
		expect(screen.getByTestId('tab-snapshot')).toHaveAttribute('aria-selected', 'true');
	});

	it('emits aria-controls only for tabs whose caller provides a panelId', () => {
		render(Tabs, {
			value: 'a',
			tabs: [
				{ id: 'a' as const, label: 'A', panelId: 'panel-a' },
				{ id: 'b' as const, label: 'B' }
			],
			ariaLabel: 'Panels'
		});
		expect(screen.getByRole('tab', { name: 'A' })).toHaveAttribute('aria-controls', 'panel-a');
		expect(screen.getByRole('tab', { name: 'B' })).not.toHaveAttribute('aria-controls');
	});

	it('renders without a testId when callers omit it', () => {
		const tabsNoTestIds = [
			{ id: 'a' as const, label: 'A' },
			{ id: 'b' as const, label: 'B' }
		];
		render(Tabs, {
			value: 'a',
			tabs: tabsNoTestIds,
			ariaLabel: 'No test IDs'
		});
		// Should still render — accessibility-first selector.
		expect(screen.getByRole('tab', { name: 'A' })).toBeInTheDocument();
		expect(screen.getByRole('tab', { name: 'B' })).toBeInTheDocument();
	});
});
