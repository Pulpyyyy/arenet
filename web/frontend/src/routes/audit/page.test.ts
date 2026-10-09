// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The audit page's filters: the action dropdown offers the whole
// backend catalogue, grouped, and the date bounds are datetime-local
// inputs applied as UTC ISO — never as half-typed text.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';
import en from '$lib/i18n/locales/en.json';
import { AUDIT_ACTION_GROUPS, AUDIT_ACTIONS } from '$lib/utils/audit-actions';

const { mocks } = vi.hoisted(() => ({
	mocks: { list: vi.fn() }
}));

vi.mock('$lib/api/audit', () => ({
	auditApi: { list: (...a: unknown[]) => mocks.list(...a) }
}));

vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import Page from './+page.svelte';

const DEBOUNCE_WAIT_MS = 450;

beforeEach(() => {
	mocks.list.mockReset();
	mocks.list.mockResolvedValue({ events: [], nextCursor: '' });
});

/** The filter object of the n-th auditApi.list call (0-based). */
function filterOfCall(n: number): Record<string, unknown> {
	return mocks.list.mock.calls[n][0] as Record<string, unknown>;
}

async function renderLoaded() {
	const view = render(Page);
	await waitFor(() => expect(mocks.list).toHaveBeenCalledTimes(1));
	return view;
}

describe('audit page — action filter', () => {
	it('offers every backend action, not the old 16', async () => {
		const { container } = await renderLoaded();
		const select = container.querySelector<HTMLSelectElement>('#audit-action-filter');
		expect(select).not.toBeNull();

		const values = Array.from(select!.querySelectorAll('option'))
			.map((o) => o.value)
			.filter((v) => v !== '');
		expect(values.length).toBe(AUDIT_ACTIONS.length);
		expect(new Set(values)).toEqual(new Set(AUDIT_ACTIONS));
		// "All actions" stays first.
		expect(select!.options[0].value).toBe('');
	});

	it('groups the actions, with a readable group and option label', async () => {
		const { container } = await renderLoaded();
		const groups = Array.from(container.querySelectorAll('#audit-action-filter optgroup'));
		expect(groups.map((g) => g.getAttribute('label'))).toEqual(
			AUDIT_ACTION_GROUPS.map(
				(g) => (en.audit.actionGroups as Record<string, string>)[g.id]
			)
		);

		const tcp = groups.find((g) => g.getAttribute('label') === en.audit.actionGroups.tcp);
		const option = tcp?.querySelector<HTMLOptionElement>('option[value="tcp_service_created"]');
		expect(option?.textContent?.trim()).toBe(en.audit.actions.tcp_service_created);
	});

	it('applies a newly listed action', async () => {
		const { container } = await renderLoaded();
		const select = container.querySelector<HTMLSelectElement>('#audit-action-filter')!;
		select.value = 'external_cert_uploaded';
		await fireEvent.change(select);

		await waitFor(() => expect(mocks.list).toHaveBeenCalledTimes(2));
		expect(filterOfCall(1).action).toBe('external_cert_uploaded');
	});
});

describe('audit page — date bounds', () => {
	it('uses datetime-local inputs', async () => {
		const { container } = await renderLoaded();
		expect(container.querySelector<HTMLInputElement>('#audit-filter-from')?.type).toBe('datetime-local');
		expect(container.querySelector<HTMLInputElement>('#audit-filter-to')?.type).toBe('datetime-local');
	});

	it('applies a complete value as UTC ISO', async () => {
		const { container } = await renderLoaded();
		const from = container.querySelector<HTMLInputElement>('#audit-filter-from')!;
		await fireEvent.input(from, { target: { value: '2026-05-01T14:30' } });

		await waitFor(() => expect(mocks.list).toHaveBeenCalledTimes(2));
		expect(filterOfCall(1).from).toBe(new Date(2026, 4, 1, 14, 30).toISOString());
		expect(filterOfCall(1).to).toBeUndefined();
	});

	it('applies the upper bound the same way', async () => {
		const { container } = await renderLoaded();
		const to = container.querySelector<HTMLInputElement>('#audit-filter-to')!;
		await fireEvent.input(to, { target: { value: '2026-05-18T00:00' } });

		await waitFor(() => expect(mocks.list).toHaveBeenCalledTimes(2));
		expect(filterOfCall(1).to).toBe(new Date(2026, 4, 18, 0, 0).toISOString());
	});

	it('does not fetch for an incomplete value', async () => {
		const { container } = await renderLoaded();
		const from = container.querySelector<HTMLInputElement>('#audit-filter-from')!;
		await fireEvent.input(from, { target: { value: '2026-05-0' } });

		await new Promise((r) => setTimeout(r, DEBOUNCE_WAIT_MS));
		expect(mocks.list).toHaveBeenCalledTimes(1);
	});
});
