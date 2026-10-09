// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, within, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { BackupSchedule } from '$lib/api/settings';

const baseView: BackupSchedule = {
	enabled: false,
	frequency: 'daily',
	time: '03:00',
	weekday: 0,
	keep: 14,
	dir: '',
	effectiveDir: '/var/lib/arenet/backups',
	passphraseSet: false,
	emailMode: 'never',
	emailChannelId: '',
	alertChannelIds: [],
	timeZone: 'UTC+02:00 (CEST)',
	status: {}
};

const api = {
	getBackupSchedule: vi.fn(),
	putBackupSchedule: vi.fn(),
	runBackupNow: vi.fn(),
	listBackups: vi.fn(),
	deleteBackup: vi.fn(),
	restoreBackupFile: vi.fn(),
	backupDownloadURL: (n: string) => `/api/v1/admin/backups/${n}`
};
const listChannels = vi.fn();
const pushToast = vi.fn();

vi.mock('$lib/api/settings', () => ({ settingsApi: api, MIN_BACKUP_PASSPHRASE_LEN: 12 }));
vi.mock('$lib/api/alerting', () => ({ alertingApi: { listChannels: () => listChannels() } }));
vi.mock('$lib/stores/toast', () => ({ pushToast: (m: string, v?: string) => pushToast(m, v) }));

const { default: Section } = await import('./ScheduledBackupsSection.svelte');

beforeEach(() => {
	for (const f of Object.values(api)) if (typeof f === 'function' && 'mockReset' in f) f.mockReset();
	listChannels.mockReset();
	pushToast.mockReset();
	api.getBackupSchedule.mockResolvedValue({ ...baseView });
	api.listBackups.mockResolvedValue({ dir: baseView.effectiveDir, files: [] });
	listChannels.mockResolvedValue([
		{ id: 'mail1', name: 'ops-mail', kind: 'email', enabled: true, minSeverity: 0, config: {} },
		{ id: 'hook1', name: 'discord', kind: 'webhook', enabled: true, minSeverity: 0, config: {} }
	]);
});

async function renderLoaded() {
	render(Section);
	await screen.findByText('Scheduled backups');
	await screen.findByTestId('sched-enabled');
}

describe('ScheduledBackupsSection', () => {
	it('is hidden when the backend does not offer the feature', async () => {
		api.getBackupSchedule.mockRejectedValue(new ApiError('unavailable', 409, 'validation'));
		render(Section);
		await waitFor(() => expect(api.getBackupSchedule).toHaveBeenCalled());
		expect(screen.queryByText('Scheduled backups')).not.toBeInTheDocument();
	});

	it('requires a passphrase to enable, and checks length and confirmation', async () => {
		await renderLoaded();
		await userEvent.click(screen.getByTestId('sched-enabled'));
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByText('Set a passphrase to enable scheduled backups.')).toBeInTheDocument();

		const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);
		await userEvent.type(pass, 'short');
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByText('At least 12 characters.')).toBeInTheDocument();

		await userEvent.clear(pass);
		await userEvent.type(pass, 'a long enough passphrase');
		await userEvent.type(confirm, 'something different here');
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByText('The passphrases do not match.')).toBeInTheDocument();
		expect(api.putBackupSchedule).not.toHaveBeenCalled();
	});

	it('saves the schedule with an email channel chosen among email channels only', async () => {
		api.putBackupSchedule.mockImplementation(async (r) => ({ ...baseView, ...r, passphraseSet: true }));
		await renderLoaded();
		await userEvent.click(screen.getByTestId('sched-enabled'));
		const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);
		await userEvent.type(pass, 'a long enough passphrase');
		await userEvent.type(confirm, 'a long enough passphrase');
		await userEvent.selectOptions(screen.getByTestId('sched-email-mode'), 'weekly');
		const channelSelect = screen.getByTestId('sched-email-channel');
		expect(within(channelSelect).queryByText('discord')).not.toBeInTheDocument();
		await userEvent.selectOptions(channelSelect, 'mail1');
		await userEvent.click(screen.getByLabelText(/discord/));
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));

		await waitFor(() => expect(api.putBackupSchedule).toHaveBeenCalled());
		expect(api.putBackupSchedule.mock.calls[0][0]).toMatchObject({
			enabled: true,
			passphrase: 'a long enough passphrase',
			emailMode: 'weekly',
			emailChannelId: 'mail1',
			alertChannelIds: ['hook1']
		});
		expect(pushToast).toHaveBeenCalledWith('Scheduled backups saved.', 'success');
	});

	it('runs a backup now and restores one from the list after confirmation', async () => {
		api.getBackupSchedule.mockResolvedValue({ ...baseView, passphraseSet: true });
		api.listBackups.mockResolvedValue({
			dir: baseView.effectiveDir,
			files: [{ name: 'arenet-backup-auto-20260921-030000.json', size: 2048, modTime: '2026-09-21T03:00:00Z' }]
		});
		api.runBackupNow.mockResolvedValue({ file: 'arenet-backup-auto-20260921-221500.json', size: 10, pruned: 0, emailed: false });
		api.restoreBackupFile.mockResolvedValue({ routesImported: 3, usersImported: 1 });
		await renderLoaded();

		await userEvent.click(screen.getByRole('button', { name: 'Back up now' }));
		await waitFor(() =>
			expect(pushToast).toHaveBeenCalledWith('Backup arenet-backup-auto-20260921-221500.json written.', 'success')
		);

		const row = await screen.findByTestId('sched-file-row');
		expect(within(row).getByText('Download').closest('a')).toHaveAttribute(
			'href',
			'/api/v1/admin/backups/arenet-backup-auto-20260921-030000.json'
		);
		await userEvent.click(within(row).getByRole('button', { name: /Restore/ }));
		expect(await screen.findByText('Restore this backup?')).toBeInTheDocument();
		const dialogRestore = screen.getAllByRole('button', { name: 'Restore' }).at(-1)!;
		await userEvent.click(dialogRestore);
		await waitFor(() => expect(api.restoreBackupFile).toHaveBeenCalledWith('arenet-backup-auto-20260921-030000.json'));
	});

	// The settings page asks before it is left with unsaved edits; the
	// card says which one holds them.
	describe('unsaved changes', () => {
		it('marks an edit, and clears the mark when the edit is undone', async () => {
			await renderLoaded();
			expect(screen.queryByTestId('sched-unsaved')).toBeNull();

			const keep = screen.getByTestId('sched-keep');
			await fireEvent.input(keep, { target: { value: '30' } });
			expect(screen.getByTestId('sched-unsaved')).toBeInTheDocument();
			await fireEvent.input(keep, { target: { value: '14' } });
			expect(screen.queryByTestId('sched-unsaved')).toBeNull();

			// Ticking a channel and unticking it again changes nothing.
			await userEvent.click(screen.getByLabelText(/discord/));
			expect(screen.getByTestId('sched-unsaved')).toBeInTheDocument();
			await userEvent.click(screen.getByLabelText(/discord/));
			expect(screen.queryByTestId('sched-unsaved')).toBeNull();

			// A blank passphrase keeps the stored one; a typed one is an edit.
			const [pass] = screen.getAllByLabelText(/passphrase/i);
			await userEvent.type(pass, 'x');
			expect(screen.getByTestId('sched-unsaved')).toBeInTheDocument();
		});

		it('clears the mark once the schedule is saved', async () => {
			api.putBackupSchedule.mockImplementation(async (r) => ({ ...baseView, ...r, passphraseSet: true }));
			await renderLoaded();
			await userEvent.click(screen.getByTestId('sched-enabled'));
			const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);
			await userEvent.type(pass, 'a long enough passphrase');
			await userEvent.type(confirm, 'a long enough passphrase');
			expect(screen.getByTestId('sched-unsaved')).toBeInTheDocument();

			await userEvent.click(screen.getByRole('button', { name: 'Save' }));
			await waitFor(() => expect(api.putBackupSchedule).toHaveBeenCalled());
			await waitFor(() => expect(screen.queryByTestId('sched-unsaved')).toBeNull());
		});
	});
});
