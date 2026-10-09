// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// BackupSection tests — pin the user-facing contracts of the
// /settings Backup & Restore section :
//
//   - Export (redacted) triggers a direct download — no confirmation
//   - Export (with secrets) gates the download behind a danger
//     ConfirmDialog ; only the post-confirm action triggers the
//     download URL
//   - Restore asks first (a typed word when "Allow empty users" is
//     ticked), then parses the selected JSON file before POST +
//     surfaces the typed RestoreReport in a verbose breakdown
//   - Restore error from ApiError is surfaced verbatim — the
//     backend's "two paths forward" wording must reach the operator
//     without rewording
//   - Malformed JSON in the picked file surfaces an inline parse
//     error WITHOUT calling the network
//
// Pure CI hygiene : mirrors the v2.9.1 OIDCConcurrent test pattern.
// Zero production code touched ; only the test file added.
//
// window.location.href stubbing — we don't redefine
// window.location (jsdom resists, and the contract we want to pin
// is "the right URL builder is called with the right flag", not
// "the href setter received exactly this string"). We spy on
// settingsApi.exportBackupURL instead — that returns the URL
// string the component assigns to location.href. The assignment
// itself is a one-liner ; the contract we care about lives in
// the URL-builder call.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { RestoreReport } from '$lib/api/settings';

type RestoreOpts = { allowIncompleteRestore?: boolean; allowEmptyUsers?: boolean; passphrase?: string };
const exportURLMock = vi.fn<() => string>();
const exportEncryptedMock = vi.fn<(passphrase: string) => Promise<Blob>>();
const postRestoreMock = vi.fn<(body: unknown, opts: RestoreOpts) => Promise<RestoreReport>>();

vi.mock('$lib/api/settings', () => ({
	MIN_BACKUP_PASSPHRASE_LEN: 12,
	isEncryptedBackup: (p: unknown) => typeof p === 'object' && p !== null && 'encryption' in p,
	settingsApi: {
		exportBackupURL: () => exportURLMock(),
		exportEncryptedBackup: (passphrase: string) => exportEncryptedMock(passphrase),
		postRestore: (body: unknown, opts: RestoreOpts) => postRestoreMock(body, opts)
	}
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (msg: string, variant?: string) => pushToastMock(msg, variant)
}));

// Stub window.location.href assignment so the download trigger
// doesn't navigate the jsdom window away mid-test. Captures the
// assigned value so a complementary assertion can verify the URL.
//
// Approach : redefine window.location with a setter on `href` that
// records the assignment rather than actually navigating. Restored
// in afterEach via the property descriptor.
let assignedHref: string | null = null;
const originalLocation = window.location;
beforeEach(() => {
	exportURLMock.mockReset();
	exportEncryptedMock.mockReset();
	postRestoreMock.mockReset();
	pushToastMock.mockReset();
	assignedHref = null;

	// jsdom's window.location is read-only at the property level
	// but we can replace it wholesale via defineProperty. The
	// minimal shape we need is a `href` setter ; nothing else in
	// BackupSection touches window.location.
	Object.defineProperty(window, 'location', {
		configurable: true,
		writable: true,
		value: {
			set href(v: string) {
				assignedHref = v;
			},
			get href() {
				return assignedHref ?? '';
			}
		}
	});
});

// Defensive — restore the real window.location after each test so
// any subsequent test in the same vitest worker isn't affected.
afterEach(() => {
	Object.defineProperty(window, 'location', {
		configurable: true,
		writable: true,
		value: originalLocation
	});
});

// Dynamic import AFTER the mocks are in place so the component
// captures the mocked settingsApi.
const { default: BackupSection } = await import('./BackupSection.svelte');

const happyReport: RestoreReport = {
	routesImported: 3,
	usersImported: 1,
	dnsProvidersImported: 1,
	forwardAuthProvidersImported: 0,
	oidcConfigImported: true,
	maxmindConfigImported: false,
	externalCertificatesImported: 0,
	extrasImported: false,
	managedDomainsImported: 0,
	errorTemplatesImported: 0,
	alertChannelsImported: 0,
	alertRulesImported: 0,
	apiTokensImported: 0,
	sentinelsInheritedTotal: 2,
	sentinelsUnresolvedTotal: 0,
	incompleteRows: 0
};

describe('BackupSection — export', () => {
	it('exports redacted without any confirmation', async () => {
		exportURLMock.mockReturnValue('/api/v1/admin/backup');
		render(BackupSection);

		const btn = screen.getByRole('button', { name: 'Export (redacted)' });
		await userEvent.click(btn);

		expect(exportURLMock).toHaveBeenCalledTimes(1);
		expect(assignedHref).toBe('/api/v1/admin/backup');
	});

	it('export-with-secrets asks for a passphrase before anything is requested', async () => {
		render(BackupSection);
		await userEvent.click(screen.getByRole('button', { name: 'Export with secrets…' }));

		expect(screen.getByText(/Export with secrets \(encrypted\)/)).toBeInTheDocument();
		expect(exportEncryptedMock).not.toHaveBeenCalled();
		expect(assignedHref).toBeNull();
	});

	it('rejects a short or mismatched passphrase client-side', async () => {
		render(BackupSection);
		await userEvent.click(screen.getByRole('button', { name: 'Export with secrets…' }));
		const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);

		await userEvent.type(pass, 'short');
		await userEvent.click(screen.getByRole('button', { name: 'Download encrypted backup' }));
		expect(await screen.findByText('At least 12 characters.')).toBeInTheDocument();

		await userEvent.clear(pass);
		await userEvent.type(pass, 'a long enough passphrase');
		await userEvent.type(confirm, 'something else entirely');
		await userEvent.click(screen.getByRole('button', { name: 'Download encrypted backup' }));
		expect(await screen.findByText('The passphrases do not match.')).toBeInTheDocument();
		expect(exportEncryptedMock).not.toHaveBeenCalled();
	});

	it('downloads the encrypted backup with the passphrase', async () => {
		exportEncryptedMock.mockResolvedValue(new Blob(['{}'], { type: 'application/json' }));
		const createURL = vi.fn(() => 'blob:backup');
		const revokeURL = vi.fn();
		Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: revokeURL });
		const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

		render(BackupSection);
		await userEvent.click(screen.getByRole('button', { name: 'Export with secrets…' }));
		const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);
		await userEvent.type(pass, 'a long enough passphrase');
		await userEvent.type(confirm, 'a long enough passphrase');
		await userEvent.click(screen.getByRole('button', { name: 'Download encrypted backup' }));

		await waitFor(() => expect(exportEncryptedMock).toHaveBeenCalledWith('a long enough passphrase'));
		await waitFor(() => expect(clickSpy).toHaveBeenCalled());
		expect(revokeURL).toHaveBeenCalledWith('blob:backup');
		expect(pushToastMock).toHaveBeenCalledWith('Encrypted backup downloaded.', 'success');
		clickSpy.mockRestore();
	});
});

describe('BackupSection — restore', () => {
	function pickFile(content: string): File {
		return new File([content], 'arenet-backup.json', {
			type: 'application/json'
		});
	}

	// Restore only asks; the request leaves once the dialog is
	// confirmed. `word` is typed first when the dialog requires one.
	async function restoreAndConfirm(word?: string): Promise<void> {
		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		const dialog = await screen.findByRole('dialog', { name: 'Restore this backup?' });
		if (word !== undefined) {
			await userEvent.type(within(dialog).getByLabelText(`Type ${word} to confirm`), word);
		}
		await userEvent.click(within(dialog).getByRole('button', { name: 'Replace configuration' }));
	}

	it('asks before restoring, naming the file, and sends nothing on cancel', async () => {
		render(BackupSection);
		const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});

		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		const dialog = await screen.findByRole('dialog', { name: 'Restore this backup?' });
		expect(dialog.textContent).toContain('arenet-backup.json');
		// No bypass ticked: the dialog neither mentions one nor asks for a word.
		expect(dialog.textContent).not.toContain('Allow incomplete restore');
		expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument();
		expect(postRestoreMock).not.toHaveBeenCalled();

		await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
		await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
		expect(postRestoreMock).not.toHaveBeenCalled();
	});

	it('with "Allow empty users" ticked, confirming waits for the typed word', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);
		await fireEvent.click(screen.getByRole('checkbox', { name: /Allow empty users/i }));
		const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});

		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		const dialog = await screen.findByRole('dialog', { name: 'Restore this backup?' });
		// The bypass is restated, with what it can cost.
		expect(dialog.textContent).toContain('Allow empty users');
		expect(dialog.textContent).toContain('nobody can sign in');

		const confirmBtn = within(dialog).getByRole('button', { name: 'Replace configuration' });
		expect(confirmBtn).toBeDisabled();
		const field = within(dialog).getByLabelText('Type RESTORE to confirm');
		await userEvent.type(field, 'RESTOR');
		expect(confirmBtn).toBeDisabled();
		expect(postRestoreMock).not.toHaveBeenCalled();

		await userEvent.type(field, 'E');
		expect(confirmBtn).not.toBeDisabled();
		await userEvent.click(confirmBtn);

		await waitFor(() => expect(postRestoreMock).toHaveBeenCalledTimes(1));
		expect(postRestoreMock.mock.calls[0][1]).toEqual({
			allowIncompleteRestore: false,
			allowEmptyUsers: true
		});
	});

	it('parses the picked file JSON + POSTs with default opts (both flags off)', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		const snapshot = JSON.stringify({
			schema_version: '1.0.0',
			routes: [],
			users: []
		});
		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, { target: { files: [pickFile(snapshot)] } });

		await restoreAndConfirm();
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		expect(postRestoreMock).toHaveBeenCalledTimes(1);
		const [body, opts] = postRestoreMock.mock.calls[0];
		expect((body as Record<string, unknown>).schema_version).toBe('1.0.0');
		// Both flags default to false.
		expect(opts).toEqual({
			allowIncompleteRestore: false,
			allowEmptyUsers: false
		});
	});

	it('propagates the opt-in flags from the checkboxes to the POST', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		// Tick both opt-in checkboxes.
		const incomplete = screen.getByRole('checkbox', {
			name: /Allow incomplete restore/i
		}) as HTMLInputElement;
		const emptyUsers = screen.getByRole('checkbox', {
			name: /Allow empty users/i
		}) as HTMLInputElement;
		await fireEvent.click(incomplete);
		await fireEvent.click(emptyUsers);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});

		// "Allow empty users" is ticked, so the dialog asks for the word.
		await restoreAndConfirm('RESTORE');
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		const [, opts] = postRestoreMock.mock.calls[0];
		expect(opts).toEqual({
			allowIncompleteRestore: true,
			allowEmptyUsers: true
		});
	});

	it('renders the verbose report on a successful restore', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});
		await restoreAndConfirm();
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		// Counts from happyReport must surface in the <dl>.
		await waitFor(() => {
			expect(screen.getByText('3')).toBeInTheDocument(); // routes
		});
		// Boolean field rendered as "yes" / "no" per the
		// component's template.
		expect(screen.getByText('yes')).toBeInTheDocument();
		// Sentinels inherited count.
		expect(screen.getByText('2')).toBeInTheDocument();
	});

	it('shows the extras counts only when the backup carried them', async () => {
		postRestoreMock.mockResolvedValue({
			...happyReport,
			extrasImported: true,
			managedDomainsImported: 4,
			apiTokensImported: 7
		});
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});
		await restoreAndConfirm();

		await waitFor(() => {
			expect(screen.getByText('Managed domains imported')).toBeInTheDocument();
		});
		expect(screen.getByText('4')).toBeInTheDocument();
		expect(screen.getByText('7')).toBeInTheDocument();
		expect(screen.getByText('Service-account tokens imported')).toBeInTheDocument();
	});

	it('hides the extras counts for a pre-v2.26 backup', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});
		await restoreAndConfirm();

		await waitFor(() => expect(screen.getByText('Routes imported')).toBeInTheDocument());
		expect(screen.queryByText('Managed domains imported')).not.toBeInTheDocument();
	});

	it('asks for the passphrase of an encrypted file and sends it', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);
		const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"2.0.0","encryption":{"kdf":"argon2id"}}')] }
		});

		const passField = await screen.findByLabelText('Backup passphrase');
		const restoreBtn = screen.getByRole('button', { name: 'Restore' });
		expect(restoreBtn).toBeDisabled();
		await userEvent.type(passField, 'the backup passphrase');
		await restoreAndConfirm();

		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());
		expect(postRestoreMock.mock.calls[0][1].passphrase).toBe('the backup passphrase');
	});

	it('translates a wrong-passphrase rejection', async () => {
		postRestoreMock.mockRejectedValue(
			new ApiError('backup: wrong passphrase', 400, 'validation', undefined, 'passphrase_invalid')
		);
		render(BackupSection);
		const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"2.0.0","encryption":{"kdf":"argon2id"}}')] }
		});
		await userEvent.type(await screen.findByLabelText('Backup passphrase'), 'not the right one');
		await restoreAndConfirm();

		expect(await screen.findByText('Wrong passphrase (or the file was altered).')).toBeInTheDocument();
	});

	it('surfaces the ApiError message verbatim on restore rejection', async () => {
		// The backend's "two paths forward" reject wording reaches
		// the operator unchanged — the component must NOT reword.
		const verbatim =
			'Restore rejected: schema_version 2.0.0 is MAJOR-incompatible with this binary (1.0.0). Two paths forward: (1) downgrade ... ; (2) export current config and re-import.';
		postRestoreMock.mockRejectedValue(new ApiError(verbatim, 400));
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"2.0.0"}')] }
		});
		await restoreAndConfirm();
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		// The error <pre> carries role=alert ; assert the verbatim
		// substring lands without rewording.
		const alert = await screen.findByRole('alert');
		expect(alert.textContent).toContain('Two paths forward');
		expect(alert.textContent).toContain('schema_version 2.0.0');
	});

	it('surfaces an inline parse error WITHOUT calling postRestore on malformed JSON', async () => {
		// Operator picked a non-JSON file (e.g. a binary dump or a
		// truncated archive). The component catches JSON.parse
		// SyntaxError before any network call.
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{not-json,')] }
		});
		await restoreAndConfirm();
		await waitFor(() => {
			expect(screen.getByRole('alert')).toBeInTheDocument();
		});

		expect(postRestoreMock).not.toHaveBeenCalled();
		const alert = screen.getByRole('alert');
		expect(alert.textContent).toContain('Invalid JSON');
	});
});
