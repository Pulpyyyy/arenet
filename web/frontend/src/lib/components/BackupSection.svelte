<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step K.3 — Backup & Restore section.

  Three operations:

    1. Export (default redacted)  — single click → JSON download.
    2. Export with secrets        — passphrase modal (v2.31): every
                                   secret of the file is encrypted
                                   with it; the file is downloaded.
    3. Restore                    — file picker + opt-in checkboxes
                                   for the two bypass flags. The
                                   backend rejects loud on every
                                   failure path; we surface the
                                   reject body verbatim (it carries
                                   the "Two paths forward" wording).
                                   An encrypted file asks for its
                                   passphrase. Nothing is sent before
                                   the operator confirms in a dialog.
-->
<script lang="ts">
	import { pushToast } from '$lib/stores/toast';
	import {
		settingsApi,
		isEncryptedBackup,
		MIN_BACKUP_PASSPHRASE_LEN,
		type RestoreReport
	} from '$lib/api/settings';
	import { ApiError } from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Input from '$lib/components/Input.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	let confirmIncludeSecretsOpen = $state(false);
	let exportPassphrase = $state('');
	let exportPassphraseConfirm = $state('');
	let exportErrors = $state<{ passphrase?: string; confirm?: string }>({});
	let exporting = $state(false);
	let restoreFile = $state<File | null>(null);
	let restoreEncrypted = $state(false);
	let restorePassphrase = $state('');
	let allowIncompleteRestore = $state(false);
	let allowEmptyUsers = $state(false);
	let restoreError = $state('');
	let restoreReport = $state<RestoreReport | null>(null);
	let restoreSubmitting = $state(false);
	let restoreConfirmOpen = $state(false);

	// A restore replaces the whole configuration, so it is confirmed
	// first, restating the file and every safety check being bypassed.
	// The word to type is translated: the operator types what the
	// dialog shows in their own language, and both sides of the
	// comparison come from the same key, so they cannot disagree.
	const restoreConfirmWord = $derived(language.current && t('backupSection.confirmRestoreWord'));
	const restoreConfirmMessage = $derived(
		language.current &&
			[
				t('backupSection.confirmRestoreMessage', { file: restoreFile?.name ?? '' }),
				allowIncompleteRestore ? t('backupSection.confirmRestoreIncomplete') : '',
				allowEmptyUsers ? t('backupSection.confirmRestoreEmptyUsers', { word: restoreConfirmWord }) : ''
			]
				.filter((s) => s !== '')
				.join(' ')
	);

	const passphraseCodes = ['passphrase_required', 'passphrase_invalid', 'passphrase_too_short'];

	/** Translated message of a passphrase API error, else the raw text. */
	function apiErrorText(err: ApiError): string {
		if (err.code && passphraseCodes.includes(err.code)) {
			return t('errors.' + err.code, { min: MIN_BACKUP_PASSPHRASE_LEN });
		}
		return err.message;
	}

	function exportDefault(): void {
		window.location.href = settingsApi.exportBackupURL();
	}

	function exportIncludeSecrets(): void {
		exportPassphrase = '';
		exportPassphraseConfirm = '';
		exportErrors = {};
		confirmIncludeSecretsOpen = true;
	}

	function closeExportDialog(): void {
		if (exporting) return;
		confirmIncludeSecretsOpen = false;
		exportPassphrase = '';
		exportPassphraseConfirm = '';
	}

	async function confirmIncludeSecretsDownload(): Promise<void> {
		if (exporting) return;
		exportErrors = {};
		if ([...exportPassphrase].length < MIN_BACKUP_PASSPHRASE_LEN) {
			exportErrors = {
				passphrase: t('backupSection.errPassphraseTooShort', { min: MIN_BACKUP_PASSPHRASE_LEN })
			};
			return;
		}
		if (exportPassphrase !== exportPassphraseConfirm) {
			exportErrors = { confirm: t('backupSection.errPassphraseMismatch') };
			return;
		}
		exporting = true;
		try {
			const blob = await settingsApi.exportEncryptedBackup(exportPassphrase);
			const stamp = new Date().toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 15);
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `arenet-backup-encrypted-${stamp}.json`;
			document.body.appendChild(a);
			a.click();
			a.remove();
			URL.revokeObjectURL(url);
			pushToast(t('backupSection.toastExportEncrypted'), 'success');
			exporting = false;
			closeExportDialog();
		} catch (err) {
			if (err instanceof ApiError) {
				exportErrors = { passphrase: apiErrorText(err) };
			} else {
				pushToast(t('backupSection.errUnexpected'), 'danger');
			}
		} finally {
			exporting = false;
		}
	}

	async function onFileChange(e: Event): Promise<void> {
		const input = e.target as HTMLInputElement;
		restoreFile = input.files && input.files.length > 0 ? input.files[0] : null;
		restoreError = '';
		restoreReport = null;
		restorePassphrase = '';
		restoreEncrypted = false;
		if (restoreFile) {
			try {
				restoreEncrypted = isEncryptedBackup(JSON.parse(await restoreFile.text()));
			} catch {
				// Invalid JSON is reported on submit.
			}
		}
	}

	function askRestore(): void {
		if (!restoreFile || restoreSubmitting) return;
		restoreConfirmOpen = true;
	}

	// submitRestore reports every outcome in the section itself (report
	// or role=alert error), so the dialog closes either way.
	async function confirmRestore(): Promise<void> {
		await submitRestore();
		restoreConfirmOpen = false;
	}

	async function submitRestore(): Promise<void> {
		if (!restoreFile || restoreSubmitting) return;
		restoreSubmitting = true;
		restoreError = '';
		restoreReport = null;
		try {
			const text = await restoreFile.text();
			const parsed = JSON.parse(text);
			const report = await settingsApi.postRestore(parsed, {
				allowIncompleteRestore,
				allowEmptyUsers,
				passphrase: restoreEncrypted ? restorePassphrase : undefined
			});
			restoreReport = report;
			pushToast(
				t('backupSection.toastRestoreComplete', { routes: report.routesImported, users: report.usersImported }),
				'success'
			);
		} catch (err) {
			// The backend reject body carries the "Two paths
			// forward" wording verbatim. Surface it as-is.
			if (err instanceof ApiError) {
				restoreError = apiErrorText(err);
			} else if (err instanceof SyntaxError) {
				restoreError = t('backupSection.errInvalidJson');
			} else if (err instanceof Error) {
				restoreError = err.message;
			} else {
				restoreError = t('backupSection.errUnexpected');
			}
		} finally {
			restoreSubmitting = false;
		}
	}
</script>

<!-- mb-6 mirrors the other settings sections (Crowdsec, GeoIP,
     ServerPosition) so the next section below isn't flush against this
     card. Without it, ServerPositionSection sat glued to Backup. -->
<Card padding="p-6" class="mb-6">
	<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
		<div>
			<h2 class="text-xl font-semibold">{language.current && t('backupSection.title')}</h2>
			<p class="text-xs text-muted mt-1">
				{language.current && t('backupSection.subtitle')}
			</p>
		</div>
	</header>

	<div class="space-y-6">
		<section>
			<h3 class="text-base font-semibold text-primary mb-2">{language.current && t('backupSection.exportTitle')}</h3>
			<p class="text-xs text-muted mb-3">
				{language.current && t('backupSection.exportHelper')}
			</p>
			<div class="flex gap-2">
				<Button variant="primary" size="md" onclick={exportDefault}>
					{language.current && t('backupSection.btnExportRedacted')}
				</Button>
				<Button variant="secondary" size="md" onclick={exportIncludeSecrets}>
					{language.current && t('backupSection.btnExportWithSecrets')}
				</Button>
			</div>
		</section>

		<section class="pt-4 border-t border-border-subtle">
			<h3 class="text-base font-semibold text-primary mb-2">{language.current && t('backupSection.restoreTitle')}</h3>
			<p class="text-xs text-muted mb-3">
				{language.current && t('backupSection.restoreHelper')}
			</p>

			<input
				type="file"
				accept="application/json,.json"
				onchange={onFileChange}
				class="block w-full text-sm text-secondary file:mr-3 file:py-2 file:px-3 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-surface file:text-primary hover:file:bg-hover"
			/>

			{#if restoreEncrypted}
				<div class="mt-3">
					<Input
						bind:value={restorePassphrase}
						type="password"
						label={language.current && t('backupSection.restorePassphraseLabel')}
						autocomplete="off"
						disabled={restoreSubmitting}
					/>
					<p class="text-xs text-muted mt-1">
						{language.current && t('backupSection.restorePassphraseHelper')}
					</p>
				</div>
			{/if}

			<div class="mt-3 space-y-2 text-sm">
				<label class="inline-flex items-center gap-2">
					<input
						type="checkbox"
						bind:checked={allowIncompleteRestore}
						class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
					/>
					<span>
						<span class="font-medium">{language.current && t('backupSection.allowIncompleteLabel')}</span>
						<span class="text-xs text-muted block">
							{language.current && t('backupSection.allowIncompleteHelper')}
						</span>
					</span>
				</label>
				<label class="inline-flex items-center gap-2">
					<input
						type="checkbox"
						bind:checked={allowEmptyUsers}
						class="rounded border-border-default bg-surface text-cyan focus:ring-cyan"
					/>
					<span>
						<span class="font-medium">{language.current && t('backupSection.allowEmptyUsersLabel')}</span>
						<span class="text-xs text-muted block">
							{language.current && t('backupSection.allowEmptyUsersHelper')}
						</span>
					</span>
				</label>
			</div>

			<div class="mt-4">
				<Button
					variant="danger"
					size="md"
					disabled={!restoreFile || restoreSubmitting || (restoreEncrypted && !restorePassphrase)}
					onclick={askRestore}
				>
					{language.current && (restoreSubmitting ? t('backupSection.btnRestoring') : t('backupSection.btnRestore'))}
				</Button>
			</div>

			{#if restoreError}
				<pre
					class="mt-4 p-3 rounded bg-down/10 border border-down text-down text-xs whitespace-pre-wrap font-mono"
					role="alert"
				>{restoreError}</pre>
			{/if}

			{#if restoreReport}
				<dl class="mt-4 grid grid-cols-[14rem_1fr] gap-x-4 gap-y-1 text-xs">
					<dt class="text-secondary">{language.current && t('backupSection.reportRoutesImported')}</dt>
					<dd class="font-mono">{restoreReport.routesImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportUsersImported')}</dt>
					<dd class="font-mono">{restoreReport.usersImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportDnsImported')}</dt>
					<dd class="font-mono">{restoreReport.dnsProvidersImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportForwardAuthImported')}</dt>
					<dd class="font-mono">{restoreReport.forwardAuthProvidersImported}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportOidcImported')}</dt>
					<dd class="font-mono">{language.current && (restoreReport.oidcConfigImported ? t('backupSection.yes') : t('backupSection.no'))}</dd>
					{#if restoreReport.extrasImported}
						<dt class="text-secondary">{language.current && t('backupSection.reportManagedDomainsImported')}</dt>
						<dd class="font-mono">{restoreReport.managedDomainsImported}</dd>
						<dt class="text-secondary">{language.current && t('backupSection.reportErrorTemplatesImported')}</dt>
						<dd class="font-mono">{restoreReport.errorTemplatesImported}</dd>
						<dt class="text-secondary">{language.current && t('backupSection.reportAlertChannelsImported')}</dt>
						<dd class="font-mono">{restoreReport.alertChannelsImported}</dd>
						<dt class="text-secondary">{language.current && t('backupSection.reportAlertRulesImported')}</dt>
						<dd class="font-mono">{restoreReport.alertRulesImported}</dd>
						<dt class="text-secondary">{language.current && t('backupSection.reportApiTokensImported')}</dt>
						<dd class="font-mono">{restoreReport.apiTokensImported}</dd>
					{/if}
					<dt class="text-secondary">{language.current && t('backupSection.reportSentinelsInherited')}</dt>
					<dd class="font-mono">{restoreReport.sentinelsInheritedTotal}</dd>
					<dt class="text-secondary">{language.current && t('backupSection.reportSentinelsUnresolved')}</dt>
					<dd class="font-mono">{restoreReport.sentinelsUnresolvedTotal}</dd>
				</dl>
			{/if}
		</section>
	</div>
</Card>

<Modal
	open={confirmIncludeSecretsOpen}
	title={language.current && t('backupSection.confirmDialogTitle')}
	onClose={closeExportDialog}
>
	<p class="text-sm text-secondary mb-4">
		{language.current && t('backupSection.confirmDialogMessage')}
	</p>
	<Input
		bind:value={exportPassphrase}
		type="password"
		label={language.current && t('backupSection.passphraseLabel', { min: MIN_BACKUP_PASSPHRASE_LEN })}
		autocomplete="new-password"
		error={exportErrors.passphrase ?? ''}
		disabled={exporting}
	/>
	<div class="mt-4">
		<Input
			bind:value={exportPassphraseConfirm}
			type="password"
			label={language.current && t('backupSection.passphraseConfirmLabel')}
			autocomplete="new-password"
			error={exportErrors.confirm ?? ''}
			disabled={exporting}
		/>
	</div>

	{#snippet footer()}
		<Button variant="ghost" size="md" onclick={closeExportDialog} disabled={exporting}>
			{#snippet children()}{language.current && t('backupSection.cancel')}{/snippet}
		</Button>
		<Button
			variant="danger"
			size="md"
			onclick={confirmIncludeSecretsDownload}
			loading={exporting}
			disabled={exporting}
		>
			{#snippet children()}{language.current && t('backupSection.confirmDialogConfirm')}{/snippet}
		</Button>
	{/snippet}
</Modal>

<!-- "Allow empty users" can leave nobody able to sign in, so that
     case also asks for a typed word, not just a click. -->
<ConfirmDialog
	bind:open={restoreConfirmOpen}
	title={language.current && t('backupSection.confirmRestoreTitle')}
	message={restoreConfirmMessage}
	confirmLabel={language.current && t('backupSection.confirmRestoreConfirm')}
	cancelLabel={language.current && t('backupSection.cancel')}
	confirmVariant="danger"
	requireText={allowEmptyUsers ? restoreConfirmWord : undefined}
	requireTextLabel={language.current && t('backupSection.confirmRestoreTypeLabel', { word: restoreConfirmWord })}
	onConfirm={confirmRestore}
/>
