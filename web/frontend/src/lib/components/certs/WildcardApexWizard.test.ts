// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unit tests for the Step T T.5 wizard. Verifies the open/close/
// submit/error contracts in isolation so the page-level integration
// tests can stay narrow (they just verify the trigger mounts the
// wizard).
//
// Why unit-test here instead of through the page: JSDOM doesn't
// drive the Web Animations API the way browsers do, so Modal's
// out-transition (fly + fade, 400ms) leaves the dialog node in
// the DOM after `open` flips to false. Asserting "form unmounts"
// at the page level is flaky for that reason; asserting "onClose
// was called" at the component level is the actual behavioural
// contract.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { DNSProvider } from '$lib/api/types';

const { settingsMock } = vi.hoisted(() => ({
	settingsMock: {
		settingsApi: {
			createManagedDomain: vi.fn(),
			listDNSProviders: vi.fn(),
		},
	},
}));
vi.mock('$lib/api/settings', () => settingsMock);

import WildcardApexWizard from './WildcardApexWizard.svelte';

function provider(over: Partial<DNSProvider> = {}): DNSProvider {
	return {
		id: 'id-1',
		label: 'OVH perso',
		type: 'ovh',
		endpoint: 'ovh-eu',
		configured: true,
		fields: { endpoint: 'ovh-eu' },
		secretsSet: { application_key: true, application_secret: true, consumer_key: true },
		usedBy: [],
		...over,
	};
}

beforeEach(() => {
	settingsMock.settingsApi.createManagedDomain.mockReset();
	settingsMock.settingsApi.listDNSProviders.mockReset();
	// Default: one configured provider so existing submit/close tests
	// have a providerId to send.
	settingsMock.settingsApi.listDNSProviders.mockResolvedValue([provider()]);
});

describe('WildcardApexWizard', () => {
	it('renders nothing when open=false', () => {
		render(WildcardApexWizard, { open: false, onClose: vi.fn() });
		expect(screen.queryByTestId('wildcard-wizard-form')).not.toBeInTheDocument();
	});

	it('mounts the three form controls when open=true', async () => {
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		expect(screen.getByLabelText('Apex domain')).toBeInTheDocument();
		// The DNS provider dropdown mounts after listDNSProviders resolves.
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);
		expect(
			screen.getByLabelText('Include bare apex in cert SAN'),
		).toBeInTheDocument();
	});

	it('Cancel button fires onClose without submitting', async () => {
		const onClose = vi.fn();
		render(WildcardApexWizard, {
			open: true,
			onClose,
		});
		await userEvent.click(screen.getByRole('button', { name: /cancel/i }));
		expect(onClose).toHaveBeenCalledTimes(1);
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('Escape key fires onClose (via Modal focus-trap handler)', async () => {
		const onClose = vi.fn();
		render(WildcardApexWizard, { open: true, onClose });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onClose).toHaveBeenCalled();
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('submitting with empty apex shows a validation error instead of calling the API', async () => {
		const onClose = vi.fn();
		render(WildcardApexWizard, { open: true, onClose });
		// Wait for the provider fetch so the empty-provider submit guard
		// doesn't short-circuit before the apex-required check.
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();
		expect(screen.getByTestId('wizard-error').textContent ?? '').toMatch(
			/required/i,
		);
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
		expect(onClose).not.toHaveBeenCalled();
	});

	it('successful submit calls API with trimmed apex, onCreated, then onClose', async () => {
		const onClose = vi.fn();
		const onCreated = vi.fn();
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});
		render(WildcardApexWizard, { open: true, onClose, onCreated });

		// Wait for the provider fetch so providerId is populated.
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);

		const input = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(input, '  new.example  ');
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();
		await tick();

		expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith({
			apex: 'new.example',
			includeApex: true,
			providerId: 'id-1',
		});
		expect(onCreated).toHaveBeenCalled();
		expect(onClose).toHaveBeenCalled();
	});

	it('populates the provider dropdown from listDNSProviders', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1', label: 'OVH perso', endpoint: 'ovh-eu' }),
			provider({ id: 'id-2', label: 'OVH pro', endpoint: 'ovh-ca' }),
		]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await waitFor(() =>
			expect(screen.getByText(/OVH perso/)).toBeInTheDocument(),
		);
		expect(screen.getByText(/OVH pro/)).toBeInTheDocument();
	});

	it('sends providerId on submit', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'id-1' }),
		]);
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({});
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await waitFor(() =>
			expect(screen.getByLabelText('DNS provider')).toBeInTheDocument(),
		);
		await fireEvent.input(screen.getByLabelText('Apex domain'), {
			target: { value: 'example.com' },
		});
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await waitFor(() =>
			expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith(
				expect.objectContaining({ apex: 'example.com', providerId: 'id-1' }),
			),
		);
	});

	it('shows an empty-state CTA when no provider is configured and blocks submit', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await waitFor(() =>
			expect(
				screen.getByText(/configure.*dns provider|configurer.*fournisseur/i),
			).toBeInTheDocument(),
		);
		// No dropdown rendered.
		expect(screen.queryByLabelText('DNS provider')).not.toBeInTheDocument();
		// Submitting must not reach the API.
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await tick();
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('failed submit shows the error in the modal and keeps onClose un-called', async () => {
		const onClose = vi.fn();
		settingsMock.settingsApi.createManagedDomain.mockRejectedValue(
			new ApiError('apex already declared', 409, 'validation'),
		);
		render(WildcardApexWizard, { open: true, onClose });

		const input = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(input, 'taken.example');
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();
		await tick();

		expect(screen.getByTestId('wizard-error').textContent ?? '').toMatch(
			/apex already declared/,
		);
		expect(onClose).not.toHaveBeenCalled();
	});

	it('lists an unconfigured provider as disabled and preselects a configured one', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ id: 'half', label: 'Half done', configured: false }),
			provider({ id: 'ready', label: 'Ready' }),
		]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		const select = (await screen.findByLabelText('DNS provider')) as HTMLSelectElement;
		const half = screen.getByRole('option', { name: /Half done/ }) as HTMLOptionElement;
		expect(half.disabled).toBe(true);
		expect(half.textContent ?? '').toMatch(/not configured/);
		expect((screen.getByRole('option', { name: /Ready/ }) as HTMLOptionElement).disabled).toBe(
			false,
		);
		expect(select.value).toBe('ready');
	});

	it('shows the empty state when every provider is unconfigured', async () => {
		settingsMock.settingsApi.listDNSProviders.mockResolvedValue([
			provider({ configured: false }),
		]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		expect(await screen.findByTestId('wizard-provider-empty')).toBeInTheDocument();
		expect(screen.queryByLabelText('DNS provider')).not.toBeInTheDocument();
	});

	it('shows a load error with Retry (not the empty state) when the provider fetch fails', async () => {
		settingsMock.settingsApi.listDNSProviders
			.mockRejectedValueOnce(new Error('boom'))
			.mockResolvedValueOnce([provider()]);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		const err = await screen.findByTestId('wizard-provider-load-error');
		expect(err.textContent ?? '').toMatch(/Could not load the DNS providers/);
		expect(screen.queryByTestId('wizard-provider-empty')).not.toBeInTheDocument();

		await userEvent.click(screen.getByTestId('wizard-provider-retry'));
		expect(await screen.findByLabelText('DNS provider')).toBeInTheDocument();
		expect(settingsMock.settingsApi.listDNSProviders).toHaveBeenCalledTimes(2);
	});

	it('normalises a pasted URL / wildcard apex and submits the bare domain', async () => {
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({});
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await screen.findByLabelText('DNS provider');
		await fireEvent.input(screen.getByLabelText('Apex domain'), {
			target: { value: 'https://*.Example.com/' },
		});
		expect(screen.getByTestId('wizard-apex-normalized').textContent ?? '').toMatch(
			/example\.com/,
		);
		expect(screen.getByTestId('wizard-summary').textContent ?? '').toMatch(
			/\*\.example\.com \+ example\.com via OVH perso \(DNS-01\)/,
		);
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await waitFor(() =>
			expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith(
				expect.objectContaining({ apex: 'example.com' }),
			),
		);
	});

	it('summary drops the bare apex when "include apex" is unticked', async () => {
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await screen.findByLabelText('DNS provider');
		await fireEvent.input(screen.getByLabelText('Apex domain'), {
			target: { value: 'example.com' },
		});
		await userEvent.click(screen.getByLabelText('Include bare apex in cert SAN'));
		const summary = screen.getByTestId('wizard-summary').textContent ?? '';
		expect(summary).toMatch(/\*\.example\.com via OVH perso/);
		expect(summary).not.toMatch(/\+/);
	});

	it('flags an apex that is not a domain inline and keeps Declare disabled', async () => {
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await screen.findByLabelText('DNS provider');
		await fireEvent.input(screen.getByLabelText('Apex domain'), {
			target: { value: 'not a domain' },
		});
		const invalid = screen.getByTestId('wizard-apex-invalid');
		expect(invalid.textContent ?? '').toMatch(/doesn't look like a domain name/);
		expect(screen.getByLabelText('Apex domain')).toHaveAttribute('aria-invalid', 'true');
		expect(screen.queryByTestId('wizard-summary')).not.toBeInTheDocument();
		expect(screen.getByRole('button', { name: /^declare$/i })).toBeDisabled();

		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		await tick();
		expect(settingsMock.settingsApi.createManagedDomain).not.toHaveBeenCalled();
	});

	it('translates a known backend refusal', async () => {
		settingsMock.settingsApi.createManagedDomain.mockRejectedValue(
			new ApiError(
				'managed domain app.example.com is already covered by existing managed domain example.com',
				409,
				'validation',
			),
		);
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		await screen.findByLabelText('DNS provider');
		await fireEvent.input(screen.getByLabelText('Apex domain'), {
			target: { value: 'app.example.com' },
		});
		await fireEvent.submit(screen.getByTestId('wildcard-wizard-form'));
		expect((await screen.findByTestId('wizard-error')).textContent ?? '').toMatch(
			/already covered by the policy for example\.com/,
		);
	});

	it('Declare button is disabled until apex is non-empty', async () => {
		// v2.9.21 i18n — submit button migrated to t() → "Declare"
		// in EN bundle (test boot default).
		render(WildcardApexWizard, { open: true, onClose: vi.fn() });
		const declareBtn = screen.getByRole('button', { name: /^declare$/i });
		expect(declareBtn).toBeDisabled();

		const input = screen.getByLabelText('Apex domain') as HTMLInputElement;
		await userEvent.type(input, 'x.example');
		expect(declareBtn).not.toBeDisabled();
	});
});
