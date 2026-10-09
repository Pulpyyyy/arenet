// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.50 — the access-log card.
//
// The property worth pinning is that the operator is told the path the
// log will ACTUALLY be written to. The default differs between a systemd
// install and a container, only the server knows which applied, and
// pointing CrowdSec at the wrong file is a silent failure: the agent
// reads nothing, bans nothing, and every screen still looks fine.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { api } = vi.hoisted(() => ({
	api: { getAccessLog: vi.fn(), putAccessLog: vi.fn() }
}));

vi.mock('$lib/api/settings', () => {
	const known: Record<string, unknown> = {
		getAccessLog: api.getAccessLog,
		putAccessLog: api.putAccessLog,
		getAutomation: vi.fn().mockResolvedValue({
			rules: { rules: {} },
			credentials: { lapiUrl: '', machineId: '', configured: false }
		}),
		listForwardAuthProviders: vi.fn().mockResolvedValue([])
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
	// The page guards unsaved edits through beforeNavigate.
	beforeNavigate: () => {},
	goto: vi.fn()
}));

import Page from './+page.svelte';

const off = {
	enabled: false,
	rollSizeMB: 10,
	rollKeep: 5,
	compress: true,
	// v2.56 — the server answers with the redaction list, so the field is
	// seeded from it rather than from a second copy of the defaults here.
	redactQueryParams: ['access_token', 'token', 'code'],
	resolvedPath: '/var/log/arenet/access.log',
	ceilingMB: 60
};

beforeEach(() => {
	api.getAccessLog.mockReset();
	api.putAccessLog.mockReset();
	api.getAccessLog.mockResolvedValue(off);
	api.putAccessLog.mockResolvedValue({ ...off, enabled: true });
});

async function openSecurityTab() {
	render(Page);
	await waitFor(() => expect(screen.getByTestId('settings-tab-security')).toBeInTheDocument());
	await userEvent.click(screen.getByTestId('settings-tab-security'));
	await waitFor(() => expect(screen.getByTestId('access-log-enabled')).toBeInTheDocument());
}

describe('settings — access log', () => {
	it('is off, with the detail hidden until it is turned on', async () => {
		await openSecurityTab();

		expect((screen.getByTestId('access-log-enabled') as HTMLInputElement).checked).toBe(false);
		// Nothing about paths or rotation while it is off: the operator
		// has one decision to make first.
		expect(screen.queryByTestId('access-log-resolved')).toBeNull();
		expect(screen.queryByTestId('access-log-path')).toBeNull();
		expect(screen.queryByTestId('access-log-ceiling')).toBeNull();
	});

	// The whole point of the card: the path the operator must hand to
	// CrowdSec, which only the server can resolve.
	it('shows the resolved path once enabled', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));

		await waitFor(() => expect(screen.getByTestId('access-log-resolved')).toBeInTheDocument());
		expect(screen.getByTestId('access-log-resolved').textContent).toBe('/var/log/arenet/access.log');
	});

	// The ceiling is the number an operator actually wants — "10 MB, 5
	// files" answers a question nobody asked — and it must follow the
	// fields rather than being a fixed string.
	it('computes the disk ceiling from the two fields', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await waitFor(() => expect(screen.getByTestId('access-log-ceiling')).toBeInTheDocument());

		// Defaults: 10 * (5 + 1).
		expect(screen.getByTestId('access-log-ceiling').textContent).toContain('60');

		const size = screen.getByTestId('access-log-size') as HTMLInputElement;
		await userEvent.clear(size);
		await userEvent.type(size, '20');
		await waitFor(() =>
			expect(screen.getByTestId('access-log-ceiling').textContent).toContain('120')
		);
	});

	// The payload is rebuilt field by field, which is exactly how the
	// v2.46 path redirect was lost: success toast, nothing stored.
	it('sends every field, and does not drop any', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await waitFor(() => expect(screen.getByTestId('access-log-path')).toBeInTheDocument());

		await userEvent.type(screen.getByTestId('access-log-path'), '/srv/logs/arenet.log');
		const keep = screen.getByTestId('access-log-keep') as HTMLInputElement;
		await userEvent.clear(keep);
		await userEvent.type(keep, '3');
		await userEvent.click(screen.getByTestId('access-log-compress'));
		await userEvent.click(screen.getByTestId('access-log-save'));

		await waitFor(() => expect(api.putAccessLog).toHaveBeenCalledTimes(1));
		expect(api.putAccessLog.mock.calls[0][0]).toEqual({
			enabled: true,
			path: '/srv/logs/arenet.log',
			rollSizeMB: 10,
			rollKeep: 3,
			compress: false,
			redactQueryParams: ['access_token', 'token', 'code']
		});
	});

	// v2.56 — the redaction list.
	//
	// Reported case: Vaultwarden puts the user's access token in the URI,
	// so turning the access log on wrote a live credential to disk, in a
	// file CrowdSec also reads.
	it('seeds the redaction field from the server list', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await waitFor(() => expect(screen.getByTestId('access-log-redact')).toBeInTheDocument());

		const field = screen.getByTestId('access-log-redact') as HTMLInputElement;
		expect(field.value).toBe('access_token, token, code');
	});

	it('sends the edited list, split on commas or spaces', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await waitFor(() => expect(screen.getByTestId('access-log-redact')).toBeInTheDocument());

		const field = screen.getByTestId('access-log-redact') as HTMLInputElement;
		await userEvent.clear(field);
		await userEvent.type(field, 'access_token,  id_token   sig');
		await userEvent.click(screen.getByTestId('access-log-save'));

		await waitFor(() => expect(api.putAccessLog).toHaveBeenCalledTimes(1));
		const sent = api.putAccessLog.mock.calls[0][0] as { redactQueryParams?: string[] };
		expect(sent.redactQueryParams).toEqual(['access_token', 'id_token', 'sig']);
	});

	// Clearing the field is a choice. It has to be sent as an explicit
	// empty list: omitting it means "keep the defaults" server-side, which
	// would put back the redaction the operator just removed.
	it('sends an explicit empty list when the field is cleared', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await waitFor(() => expect(screen.getByTestId('access-log-redact')).toBeInTheDocument());

		await userEvent.clear(screen.getByTestId('access-log-redact'));
		await userEvent.click(screen.getByTestId('access-log-save'));

		await waitFor(() => expect(api.putAccessLog).toHaveBeenCalledTimes(1));
		const sent = api.putAccessLog.mock.calls[0][0] as { redactQueryParams?: string[] };
		expect(sent.redactQueryParams, 'an omitted list would restore the defaults').toEqual([]);
	});

	// An empty path means "use the default", and must not be sent as an
	// empty string — the API would refuse that as not absolute.
	it('omits the path when the operator left it empty', async () => {
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await userEvent.click(screen.getByTestId('access-log-save'));

		await waitFor(() => expect(api.putAccessLog).toHaveBeenCalledTimes(1));
		expect(api.putAccessLog.mock.calls[0][0].path).toBeUndefined();
	});

	it('shows a refusal instead of claiming success', async () => {
		const { ApiError } = await import('$lib/api/types');
		api.putAccessLog.mockImplementation(() => {
			throw new ApiError('access log: path "logs/a.log" must be absolute', 400, 'validation');
		});
		await openSecurityTab();
		await userEvent.click(screen.getByTestId('access-log-enabled'));
		await userEvent.click(screen.getByTestId('access-log-save'));

		const shown = await screen.findByTestId('access-log-error');
		expect(shown.textContent).toMatch(/absolute/i);
	});
});
