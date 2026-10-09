// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.41 — the settings page is five tabs, not one long scroll.
//
// What is pinned here is what the operator relies on: the five
// categories are reachable, only the active one renders, the tab
// survives in the URL, and the deep links that predate the tabs
// (#security-automation, #oidc-config, #dns-providers — used by the
// CrowdSec Decisions panel and the BanIPModal CTA) still land on the
// right tab.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

// Every settings API is stubbed to a resolved empty value: this test
// is about the page's navigation, not about any card's contents.
vi.mock('$lib/api/settings', () => {
	// Shapes the page actually destructures; everything else falls
	// back to a resolved empty value.
	const known: Record<string, unknown> = {
		getAutomation: vi.fn().mockResolvedValue({
			rules: { rules: {} },
			credentials: { lapiUrl: '', machineId: '', configured: false }
		}),
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

const { afterNavigateMock, beforeNavigateMock } = vi.hoisted(() => ({
	afterNavigateMock: { cb: null as null | (() => void | Promise<void>) },
	beforeNavigateMock: { cb: null as null | ((nav: unknown) => void) }
}));
vi.mock('$app/navigation', () => ({
	afterNavigate: (cb: () => void | Promise<void>) => {
		afterNavigateMock.cb = cb;
	},
	// Captured so a test can play a navigation through the page's guard.
	beforeNavigate: (cb: (nav: unknown) => void) => {
		beforeNavigateMock.cb = cb;
	},
	goto: vi.fn()
}));

import { goto } from '$app/navigation';
import Page from './+page.svelte';
import { auth } from '$lib/stores/auth.svelte';
import type { User } from '$lib/api/auth';

function tab(id: string): HTMLElement {
	return screen.getByTestId(`settings-tab-${id}`);
}

beforeEach(() => {
	// jsdom implements neither; the page calls both on tab change.
	Element.prototype.scrollIntoView = vi.fn();
	window.scrollTo = vi.fn();
	window.history.replaceState(null, '', '/settings');
	afterNavigateMock.cb = null;
	beforeNavigateMock.cb = null;
	vi.mocked(goto).mockClear();
});

afterEach(() => {
	window.history.replaceState(null, '', '/settings');
});

describe('Settings page — v2.41 categories', () => {
	it('offers the five categories and opens on the account one', async () => {
		render(Page);
		for (const id of ['account', 'security', 'network', 'backups', 'system']) {
			expect(tab(id)).toBeInTheDocument();
		}
		expect(tab('account').getAttribute('aria-selected')).toBe('true');
		expect(tab('security').getAttribute('aria-selected')).toBe('false');

		// Only the active category is rendered — the whole point of
		// the change is that the other fourteen cards are not there.
		expect(screen.queryByText('Security Automation')).toBeNull();
	});

	it('switches category and records it in the URL', async () => {
		render(Page);
		await userEvent.click(tab('security'));

		expect(tab('security').getAttribute('aria-selected')).toBe('true');
		await waitFor(() => expect(screen.getByText('Security Automation')).toBeInTheDocument());
		expect(window.location.hash).toBe('#security');

		// Back to the first category: the security cards are hidden,
		// not merely scrolled out of sight. They stay mounted so an
		// unsaved edit in them survives the switch (next test).
		await userEvent.click(tab('account'));
		expect(screen.getByText('Security Automation')).not.toBeVisible();
		expect(window.location.hash).toBe('#account');
	});

	// The OIDC, CrowdSec, GeoIP, DNS and backup sections hold their form
	// state inside the component and reload it on mount: unmounting a
	// tab on every switch threw away whatever the operator had typed
	// and not saved. The same node surviving the round trip is the
	// proof the component was not remounted.
	it('keeps a visited tab mounted across a switch', async () => {
		render(Page);
		await userEvent.click(tab('security'));
		await waitFor(() => expect(document.getElementById('oidc-config')).not.toBeNull());
		const oidc = document.getElementById('oidc-config')!;

		await userEvent.click(tab('network'));
		expect(oidc).not.toBeVisible();
		await userEvent.click(tab('security'));

		expect(document.getElementById('oidc-config')).toBe(oidc);
		expect(oidc).toBeVisible();
	});

	it('opens the tab named by the URL hash', async () => {
		window.history.replaceState(null, '', '/settings#network');
		render(Page);
		await afterNavigateMock.cb?.();
		await waitFor(() => expect(tab('network').getAttribute('aria-selected')).toBe('true'));
	});

	it('opens the tab holding a card anchor, for the links that predate the tabs', async () => {
		window.history.replaceState(null, '', '/settings#oidc-config');
		render(Page);
		await afterNavigateMock.cb?.();
		await waitFor(() => expect(tab('security').getAttribute('aria-selected')).toBe('true'));
		expect(document.getElementById('oidc-config')).not.toBeNull();
	});
});

// Leaving /settings — a sidebar link, the back button — dropped every
// card's unsaved draft without a word. It now asks first, naming the
// cards concerned.
describe('Settings page — leaving with unsaved edits', () => {
	function leave(to = 'http://localhost/routes') {
		const cancel = vi.fn();
		beforeNavigateMock.cb!({ type: 'link', to: { url: new URL(to) }, cancel });
		return cancel;
	}

	async function openAccessLog(): Promise<HTMLInputElement> {
		render(Page);
		await userEvent.click(tab('security'));
		// Save is disabled until the card has loaded its settings.
		await waitFor(() => expect(screen.getByTestId('access-log-save')).not.toBeDisabled());
		return screen.getByTestId('access-log-enabled') as HTMLInputElement;
	}

	it('lets the operator leave when nothing is unsaved', async () => {
		await openAccessLog();
		expect(screen.queryByTestId('access-log-unsaved')).toBeNull();
		expect(leave()).not.toHaveBeenCalled();
		expect(screen.queryByText('Discard your unsaved changes?')).toBeNull();
	});

	it('marks the card and its tab, and asks before leaving', async () => {
		const enabled = await openAccessLog();
		await userEvent.click(enabled);

		expect(screen.getByTestId('access-log-unsaved')).toBeInTheDocument();
		expect(tab('security').textContent).toContain('•');
		expect(tab('network').textContent).not.toContain('•');

		const cancel = leave();
		expect(cancel).toHaveBeenCalled();
		expect(await screen.findByText('Discard your unsaved changes?')).toBeInTheDocument();
		expect(screen.getByText(/Not saved yet: HTTP access log\./)).toBeInTheDocument();
		expect(goto).not.toHaveBeenCalled();

		// Keep editing: nothing is lost, nothing navigates.
		await userEvent.click(screen.getByText('Keep editing'));
		await waitFor(() => expect(screen.queryByText('Discard your unsaved changes?')).toBeNull());
		expect(enabled.checked).toBe(true);
		expect(goto).not.toHaveBeenCalled();
	});

	it('resumes the navigation once the operator agrees to discard', async () => {
		const enabled = await openAccessLog();
		await userEvent.click(enabled);

		leave('http://localhost/certs');
		await userEvent.click(await screen.findByText('Discard and leave'));

		expect(goto).toHaveBeenCalledWith(new URL('http://localhost/certs'));
		// The resumed navigation goes through the guard again: it must pass.
		expect(leave('http://localhost/certs')).not.toHaveBeenCalled();
	});

	it('clears the mark when the edit is undone', async () => {
		const enabled = await openAccessLog();
		await userEvent.click(enabled);
		expect(screen.getByTestId('access-log-unsaved')).toBeInTheDocument();

		await userEvent.click(enabled);
		expect(screen.queryByTestId('access-log-unsaved')).toBeNull();
		expect(leave()).not.toHaveBeenCalled();
	});
});

// An OIDC account has no local password — the server answers
// no_local_password — so the account card must not offer to change it.
describe('settings — change password button', () => {
	function signInAs(authSource: User['authSource']): void {
		auth.user = {
			id: 'u1',
			username: 'alice',
			displayName: 'Alice',
			locked: false,
			passwordCompromised: false,
			hibpCheckStatus: 'clean',
			themePreference: '',
			languagePreference: '',
			role: 'admin',
			authSource
		};
	}

	afterEach(() => {
		auth.user = null;
	});

	it('is offered to a local account', () => {
		signInAs('local');
		render(Page);
		expect(screen.getByTestId('settings-change-password')).toBeInTheDocument();
	});

	it('is hidden from an OIDC account', () => {
		signInAs('oidc');
		render(Page);
		expect(screen.queryByTestId('settings-change-password')).toBeNull();
	});
});

// v2.58.2 — the help text under "Rewrite Host of verify sub-request" told
// operators it was "Required for Authentik embedded outpost", and to leave it
// unchecked for "Authentik external outpost". Both framings are wrong: the
// setting depends on whether anything BETWEEN Arenet and the IdP routes by
// Host, not on which IdP or which outpost kind. An operator running an
// embedded outpost reached directly answered 302 with it unchecked, and one
// running Authentik behind Traefik needs it checked — the opposite of what
// the text said in each case.
//
// The wording is pinned here because nothing else would catch it drifting
// back: it is prose in a Svelte template, and no type or build step has an
// opinion about prose.
describe('settings — forward-auth provider help text', () => {
	async function openProviderForm() {
		render(Page);
		await userEvent.click(tab('security'));
		await waitFor(() => expect(screen.getByText('Forward-auth providers')).toBeInTheDocument());
		await userEvent.click(screen.getByText('+ Add provider'));
		await waitFor(() =>
			expect(screen.getByLabelText(/Auth passthrough prefix/i)).toBeInTheDocument()
		);
	}

	it('frames the host rewrite as a property of the network, not of the IdP', async () => {
		await openProviderForm();
		const body = document.body.textContent ?? '';

		// The claims that misled, in both directions. The text is wrapped in
		// the template, so textContent carries newlines and indentation
		// between words — every multi-word pattern matches on \s+.
		expect(body).not.toMatch(/Required\s+for\s+Authentik\s+embedded\s+outpost/i);
		expect(body).not.toMatch(/Authentik\s+external\s+outpost/i);

		// What is actually true, and the signal that decides it.
		expect(body).toMatch(/depends\s+on\s+your\s+network/i);
		expect(body).toMatch(/routes\s+by\s+Host/i);
		expect(body).toMatch(/reverse\s+proxy\s+in\s+front\s+of\s+the\s+IdP/i);
		expect(body).toMatch(/X-Forwarded-Host/i);
	});

	it('says the passthrough carries the same Host as the verify sub-request', async () => {
		await openProviderForm();
		const body = document.body.textContent ?? '';
		// v2.58.1 made the two halves agree; the text has to say so, because
		// "one checkbox covers both" is the whole reason one is enough.
		expect(body).toMatch(/same\s+Host\s+as\s+the\s+verify\s+sub-request/i);
	});
});
