<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Scheduled backups (v2.33). Configures the automatic backups (daily /
  weekly slot, retention, folder — local or a mounted NAS —, passphrase,
  email through an email alert channel, alert channels on failure),
  shows the last-run status, runs a backup on demand and lists the
  backup files (download / restore / delete). Hidden when the backend
  reports the feature unavailable (409).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import {
		settingsApi,
		MIN_BACKUP_PASSPHRASE_LEN,
		type BackupSchedule,
		type BackupFile,
		type BackupFrequency,
		type BackupEmailMode
	} from '$lib/api/settings';
	import { alertingApi, type AlertChannel } from '$lib/api/alerting';
	import { ApiError } from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { formatBytes } from '$lib/utils/format';

	const selectClass =
		'px-2 py-1 rounded-md bg-surface border border-border-default text-primary outline-none focus:border-accent-cyan';
	const translatedCodes = [
		'passphrase_required',
		'passphrase_invalid',
		'passphrase_too_short',
		'backup_dir_unwritable',
		'backup_failed'
	];

	let available = $state(true);
	let loaded = $state(false);
	let view = $state<BackupSchedule | null>(null);
	let channels = $state<AlertChannel[]>([]);
	let files = $state<BackupFile[]>([]);

	let enabled = $state(false);
	let frequency = $state<BackupFrequency>('daily');
	let time = $state('03:00');
	let weekday = $state(0);
	let keep = $state(14);
	let dir = $state('');
	let passphrase = $state('');
	let passphraseConfirm = $state('');
	let emailMode = $state<BackupEmailMode>('never');
	let emailChannelId = $state('');
	let alertChannelIds = $state<string[]>([]);

	let errors = $state<{ passphrase?: string; confirm?: string; form?: string }>({});
	let saving = $state(false);
	let running = $state(false);
	let restoreTarget = $state<string | null>(null);
	let deleteTarget = $state<string | null>(null);
	let restoreOpen = $state(false);
	let deleteOpen = $state(false);

	let emailChannels = $derived(channels.filter((c) => c.kind === 'email'));

	function errorText(err: unknown): string {
		if (err instanceof ApiError) {
			if (err.code && translatedCodes.includes(err.code)) {
				return t('errors.' + err.code, {
					min: MIN_BACKUP_PASSPHRASE_LEN,
					dir: String(err.params?.dir ?? ''),
					detail: err.message
				});
			}
			return err.message;
		}
		return t('scheduledBackups.errUnexpected');
	}

	function applyView(v: BackupSchedule): void {
		view = v;
		enabled = v.enabled;
		frequency = v.frequency;
		time = v.time;
		weekday = v.weekday;
		keep = v.keep;
		dir = v.dir;
		emailMode = v.emailMode;
		emailChannelId = v.emailChannelId;
		alertChannelIds = [...v.alertChannelIds];
		passphrase = '';
		passphraseConfirm = '';
	}

	async function loadFiles(): Promise<void> {
		try {
			files = (await settingsApi.listBackups()).files;
		} catch {
			files = [];
		}
	}

	onMount(async () => {
		try {
			applyView(await settingsApi.getBackupSchedule());
		} catch (err) {
			if (err instanceof ApiError && err.status === 409) {
				available = false;
				return;
			}
			pushToast(errorText(err), 'danger');
		}
		try {
			channels = await alertingApi.listChannels();
		} catch {
			channels = [];
		}
		await loadFiles();
		loaded = true;
	});

	async function save(): Promise<void> {
		if (saving) return;
		errors = {};
		if (passphrase !== '' && [...passphrase].length < MIN_BACKUP_PASSPHRASE_LEN) {
			errors = { passphrase: t('scheduledBackups.errPassphraseTooShort', { min: MIN_BACKUP_PASSPHRASE_LEN }) };
			return;
		}
		if (passphrase !== passphraseConfirm) {
			errors = { confirm: t('scheduledBackups.errPassphraseMismatch') };
			return;
		}
		if (enabled && passphrase === '' && !view?.passphraseSet) {
			errors = { passphrase: t('scheduledBackups.errPassphraseRequired') };
			return;
		}
		saving = true;
		try {
			applyView(
				await settingsApi.putBackupSchedule({
					enabled,
					frequency,
					time,
					weekday,
					keep,
					dir: dir.trim(),
					passphrase,
					emailMode,
					emailChannelId: emailMode === 'never' ? '' : emailChannelId,
					alertChannelIds
				})
			);
			pushToast(t('scheduledBackups.toastSaved'), 'success');
			await loadFiles();
		} catch (err) {
			errors = { form: errorText(err) };
		} finally {
			saving = false;
		}
	}

	async function runNow(): Promise<void> {
		if (running) return;
		running = true;
		try {
			const res = await settingsApi.runBackupNow();
			pushToast(t('scheduledBackups.toastRunOk', { file: res.file ?? '' }), 'success');
		} catch (err) {
			pushToast(errorText(err), 'danger');
		} finally {
			running = false;
			try {
				applyView(await settingsApi.getBackupSchedule());
			} catch {
				// keep the current view
			}
			await loadFiles();
		}
	}

	async function confirmRestore(): Promise<void> {
		const name = restoreTarget;
		restoreOpen = false;
		if (!name) return;
		try {
			const report = await settingsApi.restoreBackupFile(name);
			pushToast(
				t('backupSection.toastRestoreComplete', { routes: report.routesImported, users: report.usersImported }),
				'success'
			);
		} catch (err) {
			pushToast(
				err instanceof ApiError && err.code === 'passphrase_invalid'
					? t('scheduledBackups.errOldPassphrase')
					: errorText(err),
				'danger'
			);
		}
	}

	async function confirmDelete(): Promise<void> {
		const name = deleteTarget;
		deleteOpen = false;
		if (!name) return;
		try {
			await settingsApi.deleteBackup(name);
			await loadFiles();
		} catch (err) {
			pushToast(errorText(err), 'danger');
		}
	}

	function toggleAlertChannel(id: string, on: boolean): void {
		alertChannelIds = on ? [...alertChannelIds, id] : alertChannelIds.filter((x) => x !== id);
	}

	function fmtDate(iso?: string): string {
		if (!iso) return '—';
		return new Date(iso).toLocaleString(language.current === 'fr' ? 'fr-FR' : 'en-GB');
	}

	const weekdays = [0, 1, 2, 3, 4, 5, 6];
</script>

{#if available}
	<Card padding="p-6" class="mb-6">
		<header class="border-b border-border-subtle pb-3 mb-4">
			<h2 class="text-xl font-semibold">{language.current && t('scheduledBackups.title')}</h2>
			<p class="text-xs text-muted mt-1">{language.current && t('scheduledBackups.subtitle')}</p>
		</header>

		{#if loaded && view}
			<div class="space-y-4 text-sm">
				<label class="inline-flex items-center gap-2">
					<input
						type="checkbox"
						bind:checked={enabled}
						class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
						data-testid="sched-enabled"
					/>
					<span class="font-medium">{language.current && t('scheduledBackups.enabledLabel')}</span>
				</label>

				<div class="grid gap-3 sm:grid-cols-4">
					<label class="flex flex-col gap-1">
						<span class="text-secondary">{language.current && t('scheduledBackups.frequencyLabel')}</span>
						<select bind:value={frequency} class={selectClass} data-testid="sched-frequency">
							<option value="daily">{language.current && t('scheduledBackups.daily')}</option>
							<option value="weekly">{language.current && t('scheduledBackups.weekly')}</option>
						</select>
					</label>
					{#if frequency === 'weekly'}
						<label class="flex flex-col gap-1">
							<span class="text-secondary">{language.current && t('scheduledBackups.weekdayLabel')}</span>
							<select bind:value={weekday} class={selectClass} data-testid="sched-weekday">
								{#each weekdays as d (d)}
									<option value={d}>{language.current && t('scheduledBackups.weekday' + d)}</option>
								{/each}
							</select>
						</label>
					{/if}
					<label class="flex flex-col gap-1">
						<span class="text-secondary">{language.current && t('scheduledBackups.timeLabel')}</span>
						<input type="time" bind:value={time} class={selectClass} data-testid="sched-time" />
					</label>
					<label class="flex flex-col gap-1">
						<span class="text-secondary">{language.current && t('scheduledBackups.keepLabel')}</span>
						<input type="number" min="1" max="365" bind:value={keep} class={selectClass} data-testid="sched-keep" />
					</label>
				</div>
				<p class="text-xs text-muted">
					{language.current && t('scheduledBackups.timeZoneHint', { tz: view.timeZone })}
				</p>

				<div>
					<Input
						bind:value={dir}
						label={language.current && t('scheduledBackups.dirLabel')}
						placeholder={view.effectiveDir}
						data-testid="sched-dir"
					/>
					<p class="text-xs text-muted mt-1">{language.current && t('scheduledBackups.dirHelper')}</p>
				</div>

				<div class="grid gap-3 sm:grid-cols-2">
					<Input
						bind:value={passphrase}
						type="password"
						autocomplete="new-password"
						label={language.current &&
							(view.passphraseSet
								? t('scheduledBackups.passphraseChangeLabel')
								: t('scheduledBackups.passphraseLabel', { min: MIN_BACKUP_PASSPHRASE_LEN }))}
						error={errors.passphrase ?? ''}
					/>
					<Input
						bind:value={passphraseConfirm}
						type="password"
						autocomplete="new-password"
						label={language.current && t('scheduledBackups.passphraseConfirmLabel')}
						error={errors.confirm ?? ''}
					/>
				</div>
				<p class="text-xs text-muted">{language.current && t('scheduledBackups.passphraseHelper')}</p>

				<div class="grid gap-3 sm:grid-cols-2">
					<label class="flex flex-col gap-1">
						<span class="text-secondary">{language.current && t('scheduledBackups.emailModeLabel')}</span>
						<select bind:value={emailMode} class={selectClass} data-testid="sched-email-mode">
							<option value="never">{language.current && t('scheduledBackups.emailNever')}</option>
							<option value="each">{language.current && t('scheduledBackups.emailEach')}</option>
							<option value="weekly">{language.current && t('scheduledBackups.emailWeekly')}</option>
						</select>
					</label>
					{#if emailMode !== 'never'}
						<label class="flex flex-col gap-1">
							<span class="text-secondary">{language.current && t('scheduledBackups.emailChannelLabel')}</span>
							<select bind:value={emailChannelId} class={selectClass} data-testid="sched-email-channel">
								<option value="">—</option>
								{#each emailChannels as c (c.id)}
									<option value={c.id}>{c.name}</option>
								{/each}
							</select>
						</label>
					{/if}
				</div>
				{#if emailMode !== 'never' && emailChannels.length === 0}
					<p class="text-xs text-warn">{language.current && t('scheduledBackups.noEmailChannel')}</p>
				{/if}

				<fieldset>
					<legend class="text-secondary mb-1">{language.current && t('scheduledBackups.alertChannelsLabel')}</legend>
					{#if channels.length === 0}
						<p class="text-xs text-muted">{language.current && t('scheduledBackups.noChannels')}</p>
					{:else}
						<div class="flex flex-wrap gap-3">
							{#each channels as c (c.id)}
								<label class="inline-flex items-center gap-2">
									<input
										type="checkbox"
										checked={alertChannelIds.includes(c.id)}
										onchange={(e) => toggleAlertChannel(c.id, (e.target as HTMLInputElement).checked)}
										class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
									/>
									<span>{c.name} <span class="text-xs text-muted">({c.kind})</span></span>
								</label>
							{/each}
						</div>
					{/if}
					<p class="text-xs text-muted mt-1">{language.current && t('scheduledBackups.alertChannelsHelper')}</p>
				</fieldset>

				{#if errors.form}
					<p class="p-3 rounded bg-down/10 border border-down text-down text-xs" role="alert">{errors.form}</p>
				{/if}

				<div class="flex flex-wrap gap-2">
					<Button variant="primary" size="md" onclick={save} loading={saving} disabled={saving}>
						{language.current && t('scheduledBackups.btnSave')}
					</Button>
					<Button
						variant="secondary"
						size="md"
						onclick={runNow}
						loading={running}
						disabled={running || !view.passphraseSet}
					>
						{language.current && t('scheduledBackups.btnRunNow')}
					</Button>
				</div>

				<dl class="grid grid-cols-[12rem_1fr] gap-x-4 gap-y-1 text-xs pt-2 border-t border-border-subtle">
					<dt class="text-secondary">{language.current && t('scheduledBackups.statusDir')}</dt>
					<dd class="font-mono break-all">{view.effectiveDir}</dd>
					<dt class="text-secondary">{language.current && t('scheduledBackups.statusNext')}</dt>
					<dd>{view.enabled ? fmtDate(view.nextRunAt) : language.current && t('scheduledBackups.disabled')}</dd>
					<dt class="text-secondary">{language.current && t('scheduledBackups.statusLast')}</dt>
					<dd data-testid="sched-last-status">
						{fmtDate(view.status.lastRunAt)}
						{#if view.status.lastStatus === 'ok'}
							<span class="text-up">✓ {view.status.lastFile}</span>
						{:else if view.status.lastStatus === 'error'}
							<span class="text-down">✗ {view.status.lastError}</span>
						{/if}
					</dd>
					<dt class="text-secondary">{language.current && t('scheduledBackups.statusEmail')}</dt>
					<dd>
						{fmtDate(view.status.lastEmailAt)}
						{#if view.status.lastEmailError}<span class="text-down">✗ {view.status.lastEmailError}</span>{/if}
					</dd>
				</dl>

				<section class="pt-2">
					<h3 class="text-base font-semibold text-primary mb-2">{language.current && t('scheduledBackups.filesTitle')}</h3>
					{#if files.length === 0}
						<p class="text-xs text-muted">{language.current && t('scheduledBackups.noFiles')}</p>
					{:else}
						<table class="w-full text-xs">
							<thead>
								<tr class="text-left text-secondary">
									<th class="py-1">{language.current && t('scheduledBackups.colFile')}</th>
									<th class="py-1">{language.current && t('scheduledBackups.colSize')}</th>
									<th class="py-1 text-right">{language.current && t('scheduledBackups.colActions')}</th>
								</tr>
							</thead>
							<tbody>
								{#each files as f (f.name)}
									<tr class="border-t border-border-subtle" data-testid="sched-file-row">
										<td class="py-1 font-mono">{f.name}</td>
										<td class="py-1">{formatBytes(f.size)}</td>
										<td class="py-1 text-right space-x-2">
											<a
												href={settingsApi.backupDownloadURL(f.name)}
												class="text-accent-cyan hover:underline"
												aria-label={t('scheduledBackups.download') + ' ' + f.name}
											>{language.current && t('scheduledBackups.download')}</a>
											<button
												type="button"
												class="text-accent-cyan hover:underline"
												aria-label={t('scheduledBackups.restore') + ' ' + f.name}
												onclick={() => {
													restoreTarget = f.name;
													restoreOpen = true;
												}}
											>{language.current && t('scheduledBackups.restore')}</button>
											<button
												type="button"
												class="text-down hover:underline"
												aria-label={t('scheduledBackups.delete') + ' ' + f.name}
												onclick={() => {
													deleteTarget = f.name;
													deleteOpen = true;
												}}
											>{language.current && t('scheduledBackups.delete')}</button>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					{/if}
				</section>
			</div>
		{/if}
	</Card>

	<ConfirmDialog
		bind:open={restoreOpen}
		title={language.current && t('scheduledBackups.confirmRestoreTitle')}
		message={language.current && t('scheduledBackups.confirmRestoreMessage', { file: restoreTarget ?? '' })}
		confirmLabel={language.current && t('scheduledBackups.restore')}
		confirmVariant="danger"
		onConfirm={confirmRestore}
	/>
	<ConfirmDialog
		bind:open={deleteOpen}
		title={language.current && t('scheduledBackups.confirmDeleteTitle')}
		message={language.current && t('scheduledBackups.confirmDeleteMessage', { file: deleteTarget ?? '' })}
		confirmLabel={language.current && t('scheduledBackups.delete')}
		confirmVariant="danger"
		onConfirm={confirmDelete}
	/>
{/if}
