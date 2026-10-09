// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Security Automation rules — the window / duration / cooldown fields.
//
// Text the parser could not read ("5 minutes", "1.5h", "abc") used to
// be converted to 0 and saved as 0 without a word: a cooldown of 0 is
// accepted by the backend (internal/automation/rules.go, Rule.Validate)
// and silently means "re-ban straight after an operator unban". The
// field now says it cannot read the value and Save is refused until
// it is fixed.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { api } = vi.hoisted(() => ({
	api: { getAutomation: vi.fn(), putAutomationRules: vi.fn() }
}));

vi.mock('$lib/api/settings', () => {
	const known: Record<string, unknown> = {
		getAutomation: api.getAutomation,
		putAutomationRules: api.putAutomationRules,
		listForwardAuthProviders: vi.fn().mockResolvedValue([]),
		getAccessLog: vi.fn().mockResolvedValue({
			enabled: false,
			rollSizeMB: 10,
			rollKeep: 5,
			compress: true,
			redactQueryParams: []
		})
	};
	return {
		settingsApi: new Proxy(known, {
			get: (target, prop: string) => target[prop] ?? vi.fn().mockResolvedValue({})
		})
	};
});
vi.mock('$lib/api/system', () => ({
	systemApi: new Proxy({}, { get: () => vi.fn().mockResolvedValue({}) })
}));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		listSessions: vi.fn().mockResolvedValue({ sessions: [] }),
		deleteSession: vi.fn().mockResolvedValue(undefined)
	}
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));
vi.mock('$app/navigation', () => ({
	afterNavigate: () => {},
	beforeNavigate: () => {},
	goto: vi.fn()
}));

import Page from './+page.svelte';
import { AUTOMATION_SOURCE_LABELS } from '$lib/api/types';

const S = 1e9;
const sqli = {
	enabled: true,
	threshold: 2,
	window_ns: 60 * S,
	duration_ns: 4 * 3600 * S,
	cooldown_ns: 24 * 3600 * S
};
// The backend always returns every category (automation.DefaultRuleSet
// when nothing is stored). With only waf-sqli, the others would show a
// threshold of 0 against min=1 and the browser would refuse the submit.
const allRules = Object.fromEntries(
	Object.keys(AUTOMATION_SOURCE_LABELS).map((s) => [s, { ...sqli, enabled: false }])
);

beforeEach(() => {
	Element.prototype.scrollIntoView = vi.fn();
	window.scrollTo = vi.fn();
	api.getAutomation.mockReset();
	api.putAutomationRules.mockReset();
	api.getAutomation.mockResolvedValue({
		rules: { rules: { ...allRules, 'waf-sqli': sqli } },
		credentials: { lapiUrl: '', machineId: '', configured: false }
	});
	api.putAutomationRules.mockResolvedValue({});
});

async function openRules(): Promise<HTMLInputElement> {
	render(Page);
	await userEvent.click(screen.getByTestId('settings-tab-security'));
	const card = document.getElementById('security-automation')!;
	// Wait for the load: it reseeds the form and would wipe an edit
	// made before it lands.
	await waitFor(() => expect(within(card).getByText('Not configured')).toBeInTheDocument());
	return screen.getByTestId('automation-waf-sqli-cooldown_ns') as HTMLInputElement;
}

describe('settings — automation rule durations', () => {
	it('documents the accepted format next to the fields', async () => {
		const cooldown = await openRules();
		expect(cooldown.value).toBe('1d');
		const hint = document.getElementById('automation-duration-hint')!;
		expect(hint.textContent).toMatch(/30s, 5m, 2h, 1d/);
		expect(cooldown.getAttribute('aria-describedby')).toBe('automation-duration-hint');
		expect(cooldown.hasAttribute('aria-invalid')).toBe(false);
	});

	it('refuses an unreadable duration instead of saving it as 0', async () => {
		const cooldown = await openRules();
		await fireEvent.change(cooldown, { target: { value: '5 minutes' } });

		// The field says so, and keeps what the operator typed.
		expect(cooldown.getAttribute('aria-invalid')).toBe('true');
		expect(cooldown.value).toBe('5 minutes');
		const errorId = 'automation-waf-sqli-cooldown_ns-error';
		expect(cooldown.getAttribute('aria-describedby')).toContain(errorId);
		expect(document.getElementById(errorId)?.textContent).toMatch(/Not a duration/);

		// Save is blocked, with the reason stated beside it.
		const save = screen.getByTestId('automation-rules-save');
		expect(save).toBeDisabled();
		expect(screen.getByTestId('automation-rules-unreadable').textContent).toMatch(
			/1 duration\(s\) cannot be read/
		);
		// Enter in a field submits the form without the button.
		await fireEvent.submit(save.closest('form')!);
		expect(api.putAutomationRules).not.toHaveBeenCalled();

		// An unreadable entry is an unsaved edit: the card says so.
		expect(screen.getByTestId('automation-unsaved')).toBeInTheDocument();
	});

	it('saves once the duration is fixed', async () => {
		const cooldown = await openRules();
		await fireEvent.change(cooldown, { target: { value: '1.5h' } });
		expect(screen.getByTestId('automation-rules-save')).toBeDisabled();

		await fireEvent.change(cooldown, { target: { value: '90min' } });
		expect(cooldown.hasAttribute('aria-invalid')).toBe(false);
		expect(screen.queryByTestId('automation-rules-unreadable')).toBeNull();
		const save = screen.getByTestId('automation-rules-save');
		expect(save).not.toBeDisabled();

		await userEvent.click(save);
		await waitFor(() => expect(api.putAutomationRules).toHaveBeenCalledTimes(1));
		expect(api.putAutomationRules).toHaveBeenCalledWith({
			rules: { rules: { ...allRules, 'waf-sqli': { ...sqli, cooldown_ns: 90 * 60 * S } } }
		});
	});
});
