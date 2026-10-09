// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// AL.4.b.2 — ChannelModal behaviour tests. Focus on the
// operator-visible invariants:
//   - kind selector swaps webhook / email field groups
//   - kind selector is disabled in edit mode (can't
//     migrate webhook → email post-create)
//   - password preserve-on-omit UX: edit mode shows the
//     [défini] placeholder until "Modifier le mot de
//     passe" is checked
//   - validation errors block submit
//   - successful submit calls the API + emits onSaved

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { AlertChannel, AlertChannelRequest } from '$lib/api/alerting';
import { ApiError } from '$lib/api/types';

const createMock = vi.fn();
const updateMock = vi.fn();
const testMock = vi.fn();

vi.mock('$lib/api/alerting', async () => {
	const real = await vi.importActual<typeof import('$lib/api/alerting')>('$lib/api/alerting');
	return {
		...real,
		alertingApi: {
			...real.alertingApi,
			createChannel: (r: AlertChannelRequest) => createMock(r),
			updateChannel: (id: string, r: AlertChannelRequest) => updateMock(id, r),
			testChannel: (id: string) => testMock(id)
		}
	};
});

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (m: string, v?: string) => pushToastMock(m, v)
}));

beforeEach(() => {
	createMock.mockReset();
	updateMock.mockReset();
	testMock.mockReset();
	pushToastMock.mockReset();
});

function webhookFixture(): AlertChannel {
	return {
		id: 'ch-1',
		name: 'ops-webhook',
		kind: 'webhook',
		enabled: true,
		minSeverity: 1,
		config: {
			url: 'https://hooks.example.com/x',
			method: 'POST',
			timeoutSeconds: 10,
			headers: { Authorization: '[redacted]' }
		},
		createdAt: '2026-06-15T12:00:00Z',
		updatedAt: '2026-06-15T12:00:00Z'
	};
}

function emailFixture(): AlertChannel {
	return {
		id: 'ch-2',
		name: 'ops-email',
		kind: 'email',
		enabled: true,
		minSeverity: 1,
		config: {
			smtpHost: 'smtp.example.com',
			smtpPort: 587,
			smtpUsername: 'alerts',
			smtpPassword: '', // backend redacts on GET
			from: 'alerts@example.com',
			to: ['ops@example.com'],
			useTLS: false,
			useStartTLS: true
		},
		createdAt: '2026-06-15T12:00:00Z',
		updatedAt: '2026-06-15T12:00:00Z'
	};
}

describe('ChannelModal', () => {
	it('shows webhook fields when kind=webhook (create mode default)', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		expect(screen.getByLabelText(/URL/i)).toBeTruthy();
		// Email-specific labels should NOT be present.
		expect(screen.queryByLabelText(/SMTP host/i)).toBeNull();
		expect(screen.queryByLabelText(/^From$/i)).toBeNull();
	});

	it('swaps to email fields when kind=email is selected', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		const kindSelect = screen.getByLabelText(/^Type$/i) as HTMLSelectElement;
		await fireEvent.change(kindSelect, { target: { value: 'email' } });

		expect(screen.getByLabelText(/SMTP host/i)).toBeTruthy();
		expect(screen.getByLabelText(/^From$/i)).toBeTruthy();
		// Webhook fields should be hidden.
		expect(screen.queryByLabelText(/^URL$/i)).toBeNull();
	});

	// v2.53 — a Discord kind, because pointing the generic webhook at
	// Discord meant hand-writing its payload in a body template with no
	// JSON escaping: an alert whose subject carried a quote produced an
	// opaque HTTP 400, intermittently.
	it('swaps to a single URL field when kind=discord', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		const kindSelect = screen.getByLabelText(/^Type$/i) as HTMLSelectElement;
		await fireEvent.change(kindSelect, { target: { value: 'discord' } });

		expect(screen.getByTestId('discord-url')).toBeTruthy();
		// No body template to write — that is the whole point.
		expect(screen.queryByLabelText(/body template/i)).toBeNull();
		expect(screen.queryByLabelText(/SMTP host/i)).toBeNull();
	});

	it('sends the discord config, and only what Discord needs', async () => {
		createMock.mockResolvedValue({});
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'discord' } });
		await fireEvent.input(screen.getByLabelText(/^Name/i), { target: { value: 'discord-ops' } });
		await fireEvent.input(screen.getByTestId('discord-url'), {
			target: { value: 'https://discord.com/api/webhooks/123/abc' }
		});
		await fireEvent.input(screen.getByTestId('discord-username'), { target: { value: 'arenet' } });
		await fireEvent.click(screen.getByText(/^(Create|Créer)$/));

		await waitFor(() => expect(createMock).toHaveBeenCalledTimes(1));
		const [req] = createMock.mock.calls[0];
		expect(req.kind).toBe('discord');
		expect(req.config.webhookUrl).toBe('https://discord.com/api/webhooks/123/abc');
		expect(req.config.username).toBe('arenet');
		// No url/method/bodyTemplate leaking in from the webhook branch.
		expect(req.config).not.toHaveProperty('bodyTemplate');
		expect(req.config).not.toHaveProperty('url');
	});

	// v2.54 — mentions. The operator asked to be pinged like an @name.
	// Discord only resolves numeric IDs, and only notifies for a mention in
	// the message content, so the UI's job is to collect IDs and refuse
	// names before a save that would silently notify nobody.
	it('sends the mention IDs it was given, split on commas or spaces', async () => {
		createMock.mockResolvedValue({});
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'discord' } });
		await fireEvent.input(screen.getByLabelText(/^Name/i), { target: { value: 'ops' } });
		await fireEvent.input(screen.getByTestId('discord-url'), {
			target: { value: 'https://discord.com/api/webhooks/123/abc' }
		});
		await fireEvent.input(screen.getByTestId('discord-mention-users'), {
			target: { value: '306162232765874176, 847291046728394112' }
		});
		await fireEvent.input(screen.getByTestId('discord-mention-roles'), {
			target: { value: '1180422398765432100' }
		});
		await fireEvent.click(screen.getByText(/^(Create|Créer)$/));

		await waitFor(() => expect(createMock).toHaveBeenCalledTimes(1));
		const [req] = createMock.mock.calls[0];
		expect(req.config.mentionUserIds).toEqual(['306162232765874176', '847291046728394112']);
		expect(req.config.mentionRoleIds).toEqual(['1180422398765432100']);
	});

	it('omits the mention fields entirely when both are left blank', async () => {
		createMock.mockResolvedValue({});
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'discord' } });
		await fireEvent.input(screen.getByLabelText(/^Name/i), { target: { value: 'ops' } });
		await fireEvent.input(screen.getByTestId('discord-url'), {
			target: { value: 'https://discord.com/api/webhooks/123/abc' }
		});
		await fireEvent.click(screen.getByText(/^(Create|Créer)$/));

		await waitFor(() => expect(createMock).toHaveBeenCalledTimes(1));
		const [req] = createMock.mock.calls[0];
		expect(req.config.mentionUserIds).toBeUndefined();
		expect(req.config.mentionRoleIds).toBeUndefined();
	});

	// A pseudo saves cleanly and then notifies nobody — the failure has no
	// error anywhere, so it has to be refused at the form.
	it('refuses a username in the mention field, before sending', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'discord' } });
		await fireEvent.input(screen.getByLabelText(/^Name/i), { target: { value: 'ops' } });
		await fireEvent.input(screen.getByTestId('discord-url'), {
			target: { value: 'https://discord.com/api/webhooks/123/abc' }
		});
		await fireEvent.input(screen.getByTestId('discord-mention-users'), {
			target: { value: '@someone' }
		});
		await fireEvent.click(screen.getByText(/^(Create|Créer)$/));

		expect(createMock).not.toHaveBeenCalled();
		// And it must say what to do instead, not just refuse.
		expect(screen.getByText(/Copy User ID|identifiant utilisateur/i)).toBeTruthy();
	});

	it('refuses a role name too', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'discord' } });
		await fireEvent.input(screen.getByLabelText(/^Name/i), { target: { value: 'ops' } });
		await fireEvent.input(screen.getByTestId('discord-url'), {
			target: { value: 'https://discord.com/api/webhooks/123/abc' }
		});
		await fireEvent.input(screen.getByTestId('discord-mention-roles'), {
			target: { value: 'admins' }
		});
		await fireEvent.click(screen.getByText(/^(Create|Créer)$/));

		expect(createMock).not.toHaveBeenCalled();
	});

	// The host check mirrors the Go validator so the refusal lands while
	// the operator is looking at the field, not as a 400 afterwards.
	it('refuses a URL that is not a Discord webhook, before sending', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'discord' } });
		await fireEvent.input(screen.getByLabelText(/^Name/i), { target: { value: 'oops' } });
		await fireEvent.input(screen.getByTestId('discord-url'), {
			target: { value: 'https://example.com/hook' }
		});
		await fireEvent.click(screen.getByText(/^(Create|Créer)$/));

		expect(createMock).not.toHaveBeenCalled();
	});

	it('disables the kind selector in edit mode', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: webhookFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});
		const kindSelect = screen.getByLabelText(/^Type$/i) as HTMLSelectElement;
		expect(kindSelect.disabled).toBe(true);
	});

	it('shows [set] placeholder for SMTP password in email edit mode', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: emailFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});
		const pwd = screen.getByLabelText(/SMTP password/i) as HTMLInputElement;
		expect(pwd.value).toBe('[set]');
		expect(pwd.disabled).toBe(true);
		// The "Change password" checkbox should be present.
		expect(screen.getByLabelText(/Change password/i)).toBeTruthy();
	});

	it('enables the password input after toggling "Change password"', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: emailFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});
		const toggle = screen.getByLabelText(/Change password/i) as HTMLInputElement;
		await fireEvent.click(toggle);
		const pwd = screen.getByLabelText(/SMTP password/i) as HTMLInputElement;
		// After toggling the readonly [set] input is replaced
		// with a fresh editable password input.
		expect(pwd.disabled).toBe(false);
		expect(pwd.value).toBe('');
	});

	it('blocks submit when the webhook URL is empty', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved }
		});

		const nameInput = screen.getByLabelText(/^Name$/i) as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'test-wh' } });
		// URL intentionally left empty.
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(screen.getByText(/webhook URL is required/i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
		expect(onSaved).not.toHaveBeenCalled();
	});

	it('blocks submit when URL has invalid scheme', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.input(screen.getByLabelText(/^Name$/i), {
			target: { value: 'test-wh' }
		});
		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'ftp://bad.example.com' }
		});
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(screen.getByText(/http:\/\/ or https:\/\//i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
	});

	it('calls createChannel + onSaved on a valid webhook submit', async () => {
		createMock.mockResolvedValue(webhookFixture());
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved }
		});

		await fireEvent.input(screen.getByLabelText(/^Name$/i), {
			target: { value: 'ops-webhook' }
		});
		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'https://hooks.example.com/x' }
		});
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(createMock).toHaveBeenCalledTimes(1);
		});
		const [req] = createMock.mock.calls[0];
		expect(req.kind).toBe('webhook');
		expect(req.name).toBe('ops-webhook');
		expect(onSaved).toHaveBeenCalledTimes(1);
	});

	it('sends smtpPassword="" on edit when "Change password" stays unchecked (preserve)', async () => {
		updateMock.mockResolvedValue(emailFixture());
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: emailFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});

		// Submit without touching the password toggle.
		await fireEvent.click(screen.getByText('Save'));

		await waitFor(() => {
			expect(updateMock).toHaveBeenCalledTimes(1);
		});
		const [id, req] = updateMock.mock.calls[0];
		expect(id).toBe('ch-2');
		expect(req.config.smtpPassword).toBe('');
	});
});

// v2.39 — a channel whose stored webhook URL was overwritten by the
// redaction placeholder is flagged by the backend: warn and force the
// operator to retype it (an empty field, not the masked value).
describe('ChannelModal — lost webhook URL', () => {
	it('warns and clears the URL when secretsLost is set', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		const broken = { ...webhookFixture(), secretsLost: true };
		render(Modal, { props: { open: true, channel: broken, onClose: () => {}, onSaved: () => {} } });

		expect(screen.getByTestId('channel-secrets-lost')).toBeTruthy();
		expect((screen.getByLabelText(/URL/i) as HTMLInputElement).value).toBe('');
	});

	it('keeps the redacted URL for a healthy channel (the backend restores it)', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: webhookFixture(), onClose: () => {}, onSaved: () => {} } });

		expect(screen.queryByTestId('channel-secrets-lost')).toBeNull();
		expect((screen.getByLabelText(/URL/i) as HTMLInputElement).value).not.toBe('');
	});
});

// The only error display used to be one line at the bottom of a long
// form, out of sight of the field it was about. Each error now sits
// under its field, the field says so to assistive tech, a count sits
// by the buttons, and submit lands the operator on the first one.
describe('ChannelModal — field errors', () => {
	it('shows the error under its field, wired with aria-invalid / aria-describedby', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'ops' } });
		await fireEvent.click(screen.getByText('Create'));

		const url = screen.getByLabelText(/^URL$/i) as HTMLInputElement;
		await waitFor(() => expect(url).toHaveAttribute('aria-invalid', 'true'));
		const errId = url.getAttribute('aria-describedby');
		expect(errId).toBeTruthy();
		expect(document.getElementById(errId as string)?.textContent).toMatch(/webhook URL is required/i);
		// The valid field is left alone.
		expect(screen.getByLabelText(/^Name$/i)).not.toHaveAttribute('aria-invalid');
		// A count by the footer buttons, not a copy of the message.
		expect(screen.getByTestId('channel-form-summary').textContent).toMatch(/1 field needs fixing/i);
	});

	it('gives each invalid field its own message', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		await fireEvent.input(screen.getByLabelText(/^URL$/i), { target: { value: 'ftp://bad' } });
		await fireEvent.input(screen.getByLabelText(/Timeout/i), { target: { value: '0' } });
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => expect(screen.getByText(/name is required/i)).toBeTruthy());
		expect(screen.getByText(/http:\/\/ or https:\/\//i)).toBeTruthy();
		expect(screen.getByText(/between 1 and 60/i)).toBeTruthy();
		expect(screen.getByLabelText(/Timeout/i)).toHaveAttribute('aria-invalid', 'true');
		expect(screen.getByTestId('channel-form-summary').textContent).toMatch(/3 fields need fixing/i);
		expect(createMock).not.toHaveBeenCalled();
	});

	it('focuses the first invalid field on submit, in form order', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'ops' } });
		// Two invalid fields: URL comes first in the form, timeout after.
		await fireEvent.input(screen.getByLabelText(/Timeout/i), { target: { value: '99' } });
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => expect(screen.getByLabelText(/^URL$/i)).toHaveFocus());
	});

	it('focuses an invalid email recipient row', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		await fireEvent.change(screen.getByLabelText(/^Type$/i), { target: { value: 'email' } });
		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'mail' } });
		await fireEvent.input(screen.getByLabelText(/SMTP host/i), { target: { value: 'smtp.example.com' } });
		await fireEvent.input(screen.getByLabelText(/^From$/i), { target: { value: 'a@example.com' } });
		const to = screen.getByPlaceholderText('ops@example.com') as HTMLInputElement;
		await fireEvent.input(to, { target: { value: 'not-an-address' } });
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => expect(to).toHaveFocus());
		expect(to).toHaveAttribute('aria-invalid', 'true');
		expect(screen.getByText(/not-an-address/)).toBeTruthy();
	});

	it('clears a field error once the field is fixed', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'ops' } });
		await fireEvent.click(screen.getByText('Create'));
		await waitFor(() => expect(screen.getByText(/webhook URL is required/i)).toBeTruthy());

		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'https://hooks.example.com/x' }
		});
		expect(screen.queryByText(/webhook URL is required/i)).toBeNull();
		expect(screen.getByLabelText(/^URL$/i)).not.toHaveAttribute('aria-invalid');
		expect(screen.queryByTestId('channel-form-summary')).toBeNull();
	});

	it('shows no error before the first submit attempt', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		expect(screen.queryByTestId('channel-form-summary')).toBeNull();
		expect(screen.getByLabelText(/^URL$/i)).not.toHaveAttribute('aria-invalid');
	});

	it('puts an API refusal in the footer summary', async () => {
		createMock.mockRejectedValue(new ApiError('name already taken', 409));
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved } });

		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'ops' } });
		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'https://hooks.example.com/x' }
		});
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() =>
			expect(screen.getByTestId('channel-form-summary').textContent).toMatch(/name already taken/)
		);
		expect(onSaved).not.toHaveBeenCalled();
	});
});

// The backend tests only a stored channel: routes.go mounts
// POST /settings/alerting/channels/{id}/test and nothing that takes an
// unsaved config. So create mode offers "Create and send a test",
// which saves, then fires the existing endpoint on the new ID.
describe('ChannelModal — testing from create mode', () => {
	async function fillValidWebhook() {
		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'ops-webhook' } });
		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'https://hooks.example.com/x' }
		});
	}

	it('offers "Create and send a test" in create mode, and "Send test" only in edit mode', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		const { unmount } = render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});
		expect(screen.getByText('Create and send a test')).toBeTruthy();
		expect(screen.queryByText('Send test')).toBeNull();
		unmount();

		render(Modal, {
			props: { open: true, channel: webhookFixture(), onClose: () => {}, onSaved: () => {} }
		});
		expect(screen.getByText('Send test')).toBeTruthy();
		expect(screen.queryByText('Create and send a test')).toBeNull();
	});

	it('creates the channel, then tests the new ID, then closes', async () => {
		createMock.mockResolvedValue({ ...webhookFixture(), id: 'ch-new' });
		testMock.mockResolvedValue({ ok: true });
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved } });

		await fillValidWebhook();
		await fireEvent.click(screen.getByText('Create and send a test'));

		await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
		expect(createMock).toHaveBeenCalledTimes(1);
		expect(testMock).toHaveBeenCalledWith('ch-new');
		// Create first: the test endpoint needs the ID it returns.
		expect(createMock.mock.invocationCallOrder[0]).toBeLessThan(
			testMock.mock.invocationCallOrder[0]
		);
		expect(pushToastMock).toHaveBeenCalledWith(expect.stringMatching(/send successful/i), 'success');
	});

	it('still closes when the test fails — the channel exists, a retry would duplicate it', async () => {
		createMock.mockResolvedValue({ ...webhookFixture(), id: 'ch-new' });
		testMock.mockResolvedValue({ ok: false, error: 'HTTP 404' });
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved } });

		await fillValidWebhook();
		await fireEvent.click(screen.getByText('Create and send a test'));

		await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
		expect(pushToastMock).toHaveBeenCalledWith(expect.stringMatching(/HTTP 404/), 'danger');
	});

	it('does not test when the creation is refused', async () => {
		createMock.mockRejectedValue(new ApiError('name already taken', 409));
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved } });

		await fillValidWebhook();
		await fireEvent.click(screen.getByText('Create and send a test'));

		await waitFor(() => expect(screen.getByTestId('channel-form-summary')).toBeTruthy());
		expect(testMock).not.toHaveBeenCalled();
		expect(onSaved).not.toHaveBeenCalled();
	});

	it('validates before creating, like the Create button', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, { props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} } });

		await fireEvent.input(screen.getByLabelText(/^Name$/i), { target: { value: 'ops' } });
		await fireEvent.click(screen.getByText('Create and send a test'));

		await waitFor(() => expect(screen.getByLabelText(/^URL$/i)).toHaveFocus());
		expect(createMock).not.toHaveBeenCalled();
		expect(testMock).not.toHaveBeenCalled();
	});
});
