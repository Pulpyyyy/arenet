// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step CS.1 — CrowdSecSettingsSection tests.
//
// Mocks settingsApi.getCrowdSecSettings / put / test so the
// component's form state machine can be driven without
// touching the network. pushToast is mocked so success/
// failure toast emissions can be asserted directly.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import type {
	CrowdSecSettings,
	CrowdSecSettingsRequest,
	CrowdSecTestRequest,
	CrowdSecTestResponse
} from '$lib/api/types';
import { ApiError } from '$lib/api/types';

const getMock = vi.fn<() => Promise<CrowdSecSettings>>();
const putMock = vi.fn<(r: CrowdSecSettingsRequest) => Promise<CrowdSecSettings>>();
const testMock = vi.fn<(r: CrowdSecTestRequest) => Promise<CrowdSecTestResponse>>();
const deleteMock = vi.fn<() => Promise<CrowdSecSettings>>();

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		getCrowdSecSettings: () => getMock(),
		putCrowdSecSettings: (r: CrowdSecSettingsRequest) => putMock(r),
		deleteCrowdSecSettings: () => deleteMock(),
		testCrowdSecConnection: (r: CrowdSecTestRequest) => testMock(r)
	}
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (message: string, variant?: string) => pushToastMock(message, variant)
}));

beforeEach(() => {
	getMock.mockReset();
	putMock.mockReset();
	testMock.mockReset();
	deleteMock.mockReset();
	pushToastMock.mockReset();
});

const { default: CrowdSecSettingsSection } = await import('./CrowdSecSettingsSection.svelte');

const notConfiguredSettings: CrowdSecSettings = {
	lapiUrl: 'http://127.0.0.1:8080',
	apiKey: '',
	bouncerName: 'arenet',
	timeoutSeconds: 5,
	configured: false
};

const configuredSettings: CrowdSecSettings = {
	lapiUrl: 'http://127.0.0.1:8080',
	apiKey: '', // server redacts
	bouncerName: 'arenet',
	timeoutSeconds: 5,
	configured: true,
	updatedAt: '2026-06-09T10:00:00.000Z'
};

describe('CrowdSecSettingsSection — mount + load', () => {
	it('renders "Not configured" badge on fresh install', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => {
			expect(screen.getByText(/Not configured/i)).toBeInTheDocument();
		});
	});

	it('renders "Configured" badge when the bouncer is already wired', async () => {
		getMock.mockResolvedValue(configuredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => {
			expect(screen.getByText(/^Configured$/i)).toBeInTheDocument();
		});
	});

	it('pre-fills the LAPI URL + bouncer name from the loaded settings', async () => {
		getMock.mockResolvedValue({
			...configuredSettings,
			lapiUrl: 'http://crowdsec:8080',
			bouncerName: 'arenet-prod'
		});
		render(CrowdSecSettingsSection);
		await waitFor(() => {
			const url = screen.getByLabelText(/LAPI URL/i) as HTMLInputElement;
			expect(url.value).toBe('http://crowdsec:8080');
			const name = screen.getByLabelText(/Bouncer name/i) as HTMLInputElement;
			expect(name.value).toBe('arenet-prod');
		});
	});

	it('leaves the API key field blank on load (never echoes the secret)', async () => {
		getMock.mockResolvedValue(configuredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => {
			const key = screen.getByLabelText(/Bouncer API key/i) as HTMLInputElement;
			expect(key.value).toBe('');
			// Placeholder hints that a key is already stored.
			expect(key.placeholder).toContain('set');
		});
	});
});

describe('CrowdSecSettingsSection — save', () => {
	it('PUTs the form values and shows the success toast', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		putMock.mockResolvedValue({
			...notConfiguredSettings,
			lapiUrl: 'http://192.168.99.10:8080',
			configured: true
		});

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		const url = screen.getByLabelText(/LAPI URL/i) as HTMLInputElement;
		await fireEvent.input(url, { target: { value: 'http://192.168.99.10:8080' } });
		const key = screen.getByLabelText(/Bouncer API key/i) as HTMLInputElement;
		await fireEvent.input(key, { target: { value: 'new-key-abc' } });

		const saveBtn = screen.getByRole('button', { name: /Save & apply/i });
		await fireEvent.click(saveBtn);

		await waitFor(() => {
			expect(putMock).toHaveBeenCalledTimes(1);
			const arg = putMock.mock.calls[0][0];
			expect(arg.lapiUrl).toBe('http://192.168.99.10:8080');
			expect(arg.apiKey).toBe('new-key-abc');
		});

		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(
				expect.stringContaining('saved'),
				'success'
			);
		});
	});

	it('clears the API key field after a successful save (no ghost value)', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		putMock.mockResolvedValue({ ...notConfiguredSettings, configured: true });

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		const key = screen.getByLabelText(/Bouncer API key/i) as HTMLInputElement;
		await fireEvent.input(key, { target: { value: 'temp-key' } });
		expect(key.value).toBe('temp-key');

		await fireEvent.click(screen.getByRole('button', { name: /Save & apply/i }));
		await waitFor(() => expect(putMock).toHaveBeenCalled());
		await waitFor(() => {
			expect(key.value).toBe('');
		});
	});

	it('surfaces backend ApiError as inline form error', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		putMock.mockRejectedValue(
			new ApiError('lapi_url scheme "ftp" must be http or https', 400)
		);

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/Bouncer API key/i), {
			target: { value: 'k' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Save & apply/i }));

		await waitFor(() => {
			expect(screen.getByText(/scheme/i)).toBeInTheDocument();
		});
		expect(pushToastMock).not.toHaveBeenCalled();
	});
});

describe('CrowdSecSettingsSection — test connection', () => {
	it('renders a green Connected badge on ok=true', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		testMock.mockResolvedValue({
			ok: true,
			version: 'v1.6.3',
			statusCode: 200,
			effectiveUrl: 'http://127.0.0.1:8080'
		});

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/Bouncer API key/i), {
			target: { value: 'k' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Test connection/i }));

		await waitFor(() => {
			expect(screen.getByRole('status').textContent ?? '').toContain('Connected');
			expect(screen.getByRole('status').textContent ?? '').toContain('v1.6.3');
		});
	});

	it('renders a red Connection failed badge on ok=false', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		testMock.mockResolvedValue({
			ok: false,
			error: 'authentication failed (invalid bouncer API key)',
			statusCode: 403
		});

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/Bouncer API key/i), {
			target: { value: 'wrong' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Test connection/i }));

		await waitFor(() => {
			const alert = screen.getByRole('alert');
			expect(alert.textContent ?? '').toContain('Connection failed');
			expect(alert.textContent ?? '').toContain('authentication failed');
		});
	});

	it('invalidates a stale test result when the operator edits any field', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		testMock.mockResolvedValue({ ok: true, version: 'v1.6.3' });

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/Bouncer API key/i), {
			target: { value: 'k' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Test connection/i }));
		await waitFor(() => {
			expect(screen.getByRole('status').textContent ?? '').toContain('Connected');
		});

		// Edit a field — badge must disappear.
		await fireEvent.input(screen.getByLabelText(/LAPI URL/i), {
			target: { value: 'http://changed:8080' }
		});
		await waitFor(() => {
			expect(screen.queryByRole('status')).toBeNull();
		});
	});

	// REVERSED, and the old assertion is why.
	//
	// This used to assert `{ useStored: true }` whenever the apiKey
	// field was empty — which it ALWAYS is, because the server redacts
	// the stored secret and never sends it back (see the fixture). So
	// every Test press on a configured install ignored the URL on
	// screen and probed the saved one. Not an edge case: the only case.
	//
	// An operator who moved their LAPI to a WireGuard address, typed the
	// new URL and pressed Test was told "connection refused" — truthful
	// about 127.0.0.1, which nothing was listening on any more, and
	// completely misleading about what they had asked. Reported
	// 2026-09-27.
	//
	// The backend falls back to the stored row per field, so sending an
	// empty apiKey alongside a real URL is exactly right.
	it('probes the URL on screen, falling back to the stored key', async () => {
		getMock.mockResolvedValue(configuredSettings);
		testMock.mockResolvedValue({ ok: true, version: 'v1.6.3' });

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByRole('button', { name: /Test connection/i }));

		await waitFor(() => {
			expect(testMock).toHaveBeenCalledWith({
				lapiUrl: configuredSettings.lapiUrl,
				apiKey: '',
				timeoutSeconds: configuredSettings.timeoutSeconds
			});
		});
	});

	// The operator's actual scenario: the LAPI moved, the new address is
	// typed, the key is untouched. The probe must go to the new address.
	it('probes a URL the operator just changed, not the saved one', async () => {
		getMock.mockResolvedValue(configuredSettings);
		testMock.mockResolvedValue({ ok: true, version: 'v1.8.1' });

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		const url = screen.getByLabelText(/LAPI URL/i);
		await fireEvent.input(url, { target: { value: 'http://10.66.0.1:8080' } });
		await fireEvent.click(screen.getByRole('button', { name: /Test connection/i }));

		await waitFor(() => {
			expect(testMock).toHaveBeenCalledWith(
				expect.objectContaining({ lapiUrl: 'http://10.66.0.1:8080' })
			);
		});
		// And never the address it replaced.
		expect(testMock).not.toHaveBeenCalledWith(expect.objectContaining({ useStored: true }));
	});
});

describe('CrowdSecSettingsSection — LAPI address moved (v2.51)', () => {
	// Moving a LAPI leaves the bouncer dialling the old address until the
	// PROCESS restarts — it logs the new one while using the old. And it
	// fails open, so in the meantime Arenet blocks nothing and nothing
	// else on screen says so. Silence here is the actual danger.
	it('warns, and says a restart is needed', async () => {
		getMock.mockResolvedValue(configuredSettings);
		putMock.mockResolvedValue({
			...configuredSettings,
			lapiUrl: 'http://10.66.0.1:8080',
			restartRequired: true
		});

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/LAPI URL/i), {
			target: { value: 'http://10.66.0.1:8080' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Save/i }));

		const banner = await screen.findByTestId('crowdsec-restart-required');
		expect(banner.textContent).toMatch(/restart/i);
		// The part that matters most: unprotected until then.
		expect(banner.textContent).toMatch(/blocks nothing|fails open/i);
	});

	// Rotating only the key re-provisions cleanly. Warning there too
	// would train the operator to ignore the banner.
	it('stays quiet when only the key changed', async () => {
		getMock.mockResolvedValue(configuredSettings);
		putMock.mockResolvedValue({ ...configuredSettings, restartRequired: false });

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.input(screen.getByLabelText(/API key/i), {
			target: { value: 'a-new-key' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Save/i }));

		await waitFor(() => expect(putMock).toHaveBeenCalled());
		expect(screen.queryByTestId('crowdsec-restart-required')).toBeNull();
	});

	// Sticky on purpose: the condition persists until the operator acts,
	// so a later successful save of something else must not clear it.
	it('keeps the warning until the operator restarts', async () => {
		getMock.mockResolvedValue(configuredSettings);
		putMock.mockResolvedValueOnce({
			...configuredSettings,
			lapiUrl: 'http://10.66.0.1:8080',
			restartRequired: true
		});

		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());
		await fireEvent.input(screen.getByLabelText(/LAPI URL/i), {
			target: { value: 'http://10.66.0.1:8080' }
		});
		await fireEvent.click(screen.getByRole('button', { name: /Save/i }));
		await screen.findByTestId('crowdsec-restart-required');

		// A second save that does not move the address.
		putMock.mockResolvedValueOnce({ ...configuredSettings, restartRequired: false });
		await fireEvent.click(screen.getByRole('button', { name: /Save/i }));
		await waitFor(() => expect(putMock).toHaveBeenCalledTimes(2));

		expect(screen.queryByTestId('crowdsec-restart-required')).not.toBeNull();
	});
});

describe('CrowdSecSettingsSection — Reset (CS.2 follow-up)', () => {
	it('hides the Réinitialiser button on a fresh install', async () => {
		getMock.mockResolvedValue(notConfiguredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());
		// configured=false → no Reset button (nothing to reset).
		expect(screen.queryByTestId('crowdsec-reset-btn')).toBeNull();
	});

	it('shows the Réinitialiser button when the bouncer is configured', async () => {
		getMock.mockResolvedValue(configuredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());
		expect(screen.getByTestId('crowdsec-reset-btn')).toBeInTheDocument();
	});

	it('opens the confirm dialog when Réinitialiser is clicked', async () => {
		getMock.mockResolvedValue(configuredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('crowdsec-reset-btn'));
		// ConfirmDialog renders the message; check for a stable
		// substring from the i18n string.
		await waitFor(() => {
			expect(screen.getByText(/No impact on the Security Automation configuration/i)).toBeInTheDocument();
		});
		// DELETE is NOT called yet — only on confirm.
		expect(deleteMock).not.toHaveBeenCalled();
	});

	it('calls DELETE, refreshes form state, and emits a success toast on confirm', async () => {
		getMock.mockResolvedValue(configuredSettings);
		deleteMock.mockResolvedValue(notConfiguredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('crowdsec-reset-btn'));
		await waitFor(() => expect(screen.getByText(/No impact on the Security Automation configuration/i)).toBeInTheDocument());

		// Click the confirm button — its label is "Reset"
		// in the dialog. Need to scope: there are two buttons with
		// that name now (Section Reset + Dialog Confirm) when the
		// dialog is open.
		const confirmButtons = screen.getAllByRole('button', { name: /Reset/i });
		// The dialog Confirm button is rendered AFTER the section
		// Reset button (the dialog mounts at the end of the
		// component tree). Click the last one.
		await fireEvent.click(confirmButtons[confirmButtons.length - 1]);

		await waitFor(() => {
			expect(deleteMock).toHaveBeenCalledTimes(1);
		});
		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(
				expect.stringMatching(/disabled/i),
				'success'
			);
		});
		// After reset: badge flips to "Not configured" and the
		// Réinitialiser button disappears.
		await waitFor(() => {
			expect(screen.queryByTestId('crowdsec-reset-btn')).toBeNull();
			expect(screen.getByText(/Not configured/i)).toBeInTheDocument();
		});
	});

	it('keeps the dialog open + emits a danger toast on DELETE failure', async () => {
		getMock.mockResolvedValue(configuredSettings);
		deleteMock.mockRejectedValue(
			new ApiError('caddy reload failed: boom', 500)
		);
		render(CrowdSecSettingsSection);
		await waitFor(() => expect(getMock).toHaveBeenCalled());

		await fireEvent.click(screen.getByTestId('crowdsec-reset-btn'));
		await waitFor(() => expect(screen.getByText(/No impact on the Security Automation configuration/i)).toBeInTheDocument());

		const confirmButtons = screen.getAllByRole('button', { name: /Reset/i });
		await fireEvent.click(confirmButtons[confirmButtons.length - 1]);

		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(
				expect.stringMatching(/Reset failed/i),
				'danger'
			);
		});
		// Dialog still open so operator can retry.
		expect(screen.getByText(/No impact on the Security Automation configuration/i)).toBeInTheDocument();
		// Badge still "Configured" — the row wasn't actually
		// wiped on the backend (rollback contract).
		expect(screen.getByText(/^Configured$/i)).toBeInTheDocument();
	});
});

// The settings page asks before it is left with unsaved edits; the card
// says which one holds them.
describe('CrowdSecSettingsSection — unsaved changes', () => {
	async function renderLoaded(): Promise<void> {
		getMock.mockResolvedValue(configuredSettings);
		render(CrowdSecSettingsSection);
		await waitFor(() => expect(screen.getByText(/^Configured$/i)).toBeInTheDocument());
	}

	it('is clean on load: the blank key field means "keep the stored key"', async () => {
		await renderLoaded();
		expect(screen.queryByTestId('crowdsec-unsaved')).toBeNull();
	});

	it('marks an edit, and clears the mark when the edit is undone', async () => {
		await renderLoaded();
		const url = screen.getByLabelText(/LAPI URL/i) as HTMLInputElement;

		await fireEvent.input(url, { target: { value: 'http://crowdsec:8080' } });
		expect(screen.getByTestId('crowdsec-unsaved')).toBeInTheDocument();

		await fireEvent.input(url, { target: { value: configuredSettings.lapiUrl } });
		expect(screen.queryByTestId('crowdsec-unsaved')).toBeNull();

		// A typed key is an edit too.
		const key = screen.getByLabelText(/Bouncer API key/i) as HTMLInputElement;
		await fireEvent.input(key, { target: { value: 'new-key' } });
		expect(screen.getByTestId('crowdsec-unsaved')).toBeInTheDocument();
	});

	it('clears the mark once the edit is saved', async () => {
		putMock.mockResolvedValue({ ...configuredSettings, lapiUrl: 'http://crowdsec:8080' });
		await renderLoaded();
		const url = screen.getByLabelText(/LAPI URL/i) as HTMLInputElement;
		await fireEvent.input(url, { target: { value: 'http://crowdsec:8080' } });
		expect(screen.getByTestId('crowdsec-unsaved')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: /Save & apply/i }));
		await waitFor(() => expect(putMock).toHaveBeenCalled());
		await waitFor(() => expect(screen.queryByTestId('crowdsec-unsaved')).toBeNull());
	});

	it('keeps the mark when the save is refused', async () => {
		putMock.mockRejectedValue(new ApiError('lapiUrl: invalid', 400, 'validation'));
		await renderLoaded();
		const url = screen.getByLabelText(/LAPI URL/i) as HTMLInputElement;
		await fireEvent.input(url, { target: { value: 'not a url' } });

		await fireEvent.click(screen.getByRole('button', { name: /Save & apply/i }));
		await waitFor(() => expect(screen.getByText('lapiUrl: invalid')).toBeInTheDocument());
		expect(screen.getByTestId('crowdsec-unsaved')).toBeInTheDocument();
	});
});
