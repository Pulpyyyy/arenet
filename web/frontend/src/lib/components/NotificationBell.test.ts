// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import type { AlertEvent } from '$lib/api/alerting';

const { store, gotoMock } = vi.hoisted(() => ({
	store: {
		recent: [] as AlertEvent[],
		unreadCount: 0,
		loading: false,
		loadError: '',
		load: vi.fn().mockResolvedValue(undefined),
		markAllRead: vi.fn()
	},
	gotoMock: vi.fn()
}));
vi.mock('$lib/stores/notifications.svelte', () => ({
	notificationsStore: store,
	PANEL_LIMIT: 15,
	SYNTHETIC_UPDATE_ID: 'synthetic:update'
}));
vi.mock('$app/navigation', () => ({ goto: (...a: unknown[]) => gotoMock(...a) }));

import NotificationBell from './NotificationBell.svelte';

function evt(over: Partial<AlertEvent> = {}): AlertEvent {
	return { eventId: 'e', timestamp: '2026-07-13T10:00:00Z', ruleId: 'r', ruleName: 'n',
		severity: 0, category: 'c', subject: 'Something happened', channelsFired: [], ...over };
}

beforeEach(() => {
	store.recent = [];
	store.unreadCount = 0;
	store.loading = false;
	store.loadError = '';
	store.load.mockClear();
	store.markAllRead.mockClear();
	gotoMock.mockClear();
});

describe('NotificationBell', () => {
	it('renders the label and no badge when unreadCount is 0', () => {
		const { getByText, queryByTestId } = render(NotificationBell);
		expect(getByText('Notifications')).toBeTruthy();
		expect(queryByTestId('notif-count')).toBeNull();
	});

	it('shows the count badge when unreadCount > 0', () => {
		store.unreadCount = 3;
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-count').textContent).toContain('3');
	});

	it('caps the badge at 99+', () => {
		store.unreadCount = 150;
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-count').textContent).toContain('99+');
	});

	// The aria-label is the button's whole accessible name, so the
	// badge is only announced if the label carries the count.
	it('names the trigger without a count when nothing is unread', () => {
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-trigger')).toHaveAttribute('aria-label', 'Open notifications');
	});

	it('includes the unread count in the trigger label (singular / plural)', async () => {
		store.unreadCount = 1;
		const one = render(NotificationBell);
		expect(one.getByTestId('notif-trigger')).toHaveAttribute(
			'aria-label',
			'Open notifications, 1 unread'
		);
		one.unmount();

		store.unreadCount = 150;
		const many = render(NotificationBell);
		const trigger = many.getByTestId('notif-trigger');
		// The real number, not the 99+ the badge is capped at.
		expect(trigger).toHaveAttribute('aria-label', 'Open notifications, 150 unread');
		await fireEvent.click(trigger);
		expect(trigger).toHaveAttribute('aria-label', 'Close notifications, 150 unread');
	});

	it('calls load() when the panel opens', async () => {
		const { getByTestId } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		await waitFor(() => expect(store.load).toHaveBeenCalled());
	});

	it('renders the empty-state CTA when there are no items', async () => {
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		expect(getByText('Set up alerts in Alerting →')).toBeTruthy();
	});

	it('lists items and marks all read on button click', async () => {
		store.recent = [evt({ subject: 'Cert expiring' })];
		store.unreadCount = 1;
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		expect(getByText('Cert expiring')).toBeTruthy();
		await fireEvent.click(getByTestId('notif-markread'));
		expect(store.markAllRead).toHaveBeenCalled();
	});

	it('navigates to /alerting#history via goto when View all is clicked', async () => {
		store.recent = [evt({ subject: 'Cert expiring' })];
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger')); // open panel
		await fireEvent.click(getByText('View all in Alerting →'));
		expect(gotoMock).toHaveBeenCalledWith('/alerting#history');
	});

	it('navigates internal notification links via goto (no page reload)', async () => {
		// a cert event → internal /certs (notificationHref maps it)
		store.recent = [evt({ subject: 'Cert expiring', category: 'cert_expiry' })];
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		await fireEvent.click(getByText('Cert expiring'));
		expect(gotoMock).toHaveBeenCalledWith('/certs');
	});

	it('polls load() on a 60s interval and stops on unmount (spec §1)', () => {
		vi.useFakeTimers();
		try {
			const { unmount } = render(NotificationBell);
			// one immediate load on mount
			expect(store.load).toHaveBeenCalledTimes(1);
			vi.advanceTimersByTime(60_000);
			expect(store.load).toHaveBeenCalledTimes(2);
			vi.advanceTimersByTime(60_000);
			expect(store.load).toHaveBeenCalledTimes(3);
			unmount();
			vi.advanceTimersByTime(120_000);
			// no further polls after unmount
			expect(store.load).toHaveBeenCalledTimes(3);
		} finally {
			vi.useRealTimers();
		}
	});
});
