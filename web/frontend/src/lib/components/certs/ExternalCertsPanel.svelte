<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ExternalCertsPanel (v2.19.0 external-certs SOCLE, Task 7;
  v2.20.0 CSR generation adds the Active/Pending CSR tabs, Task 10).

  Bring-your-own-certificate surface for /certs. Self-contained: owns
  its own data load, upload form, list table, and delete/blocked
  dialogs, so the parent /certs page mounts it as a single card without
  threading state through.

  Sections:
    - Upload form: name (+ optional description) + 3 textareas
      (cert / chain / key PEM) + Upload button. On success the returned
      non-blocking `warnings` render as an inline notice. Each PEM
      field takes a pasted value or a picked file (PemFileButton), and
      content in the wrong field (key in Certificate, cert in Key,
      fullchain + Chain…) is flagged inline before upload.
    - Active / Pending CSR tabs (v2.20.0): rows split on
      `status === 'pending_csr'` — NEVER on `csrSubject`
      truthiness/presence (Go's `omitempty` is a no-op on struct-typed
      fields, so an active row can carry a non-nil, empty-looking
      `csrSubject: {}` on the wire).
    - Active tab: one row per uploaded/active cert (name, subject/
      issuer, DNS names, expiry) with an expiry BADGE — amber when
      < 30 days to notAfter, red when < 7 days (or already expired).
      The backend returns the list already sorted soonest-first
      (notAfter ascending); the panel preserves that order verbatim —
      no client re-sort.
    - Pending tab: one row per `pending_csr` cert (name, requested
      CN/SANs, a created-age BADGE bucketed by `csrAgeBadge()`) with
      Download CSR / Upload signed cert (cert-only PUT re-import,
      keyPEM left empty so the backend's preserve-on-edit semantics
      keep the server-generated private key) / Delete actions. A
      pending row is never route-referenced, so its delete never 409s.
    - Generate CSR: a button opens Task 9's GenerateCSRForm in a
      modal; its `onCreated` callback prop (NOT a DOM `created` event
      — this codebase has zero createEventDispatcher usage) refreshes
      the list and switches to the Pending tab.
    - Delete: a confirm dialog whose copy is explicit that removal is
      Arenet-local and does NOT revoke the cert with the issuing CA
      (active rows) or destroys the generated private key (pending
      rows). A 409 opens a blocked dialog listing the offending routes
      (active rows only).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Tabs from '$lib/components/Tabs.svelte';
	import GenerateCSRForm from './GenerateCSRForm.svelte';
	import PemFileButton from './PemFileButton.svelte';
	import { externalCertsApi } from '$lib/api/external-certs';
	import type { ExternalCertificate, CertWarning } from '$lib/api/external-certs';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { pushToast } from '$lib/stores/toast';
	import { csrAgeBadge } from '$lib/utils/csr-age';
	import { resolveCertError } from '$lib/utils/cert-errors';
	import { pemFieldIssue, type PemIssue } from '$lib/utils/cert-input';
	import { absoluteDate } from '$lib/utils/date-format';

	// Expiry-badge thresholds (days-to-notAfter). Amber inside the
	// warning window, red inside the danger window OR already expired.
	const EXPIRY_WARN_DAYS = 30;
	const EXPIRY_DANGER_DAYS = 7;

	type PanelTab = 'active' | 'pending';

	let loading = $state(true);
	let loadError = $state(false);
	let certs = $state<ExternalCertificate[]>([]);

	// v2.20.0 CSR generation — Active / Pending CSR tab split. The
	// pending signal is EXCLUSIVELY `status === 'pending_csr'`. NEVER
	// key off `csrSubject` truthiness/presence: Go's `omitempty` is a
	// no-op on struct-typed fields, so an ACTIVE row re-saved after
	// this feature shipped can carry a non-nil, empty-looking
	// `csrSubject: {}` on the wire (see the CROSS-TASK RULE doc comment
	// on ExternalCertificate.status in lib/api/types.ts).
	let activeTab = $state<PanelTab>('active');
	const activeCerts = $derived(certs.filter((c) => c.status !== 'pending_csr'));
	const pendingCerts = $derived(certs.filter((c) => c.status === 'pending_csr'));

	// Generate-CSR modal.
	let generateOpen = $state(false);

	// Cert-only re-import ("Upload signed cert") modal, opened from a
	// pending row. Holds the target row awaiting a signed cert PUT.
	let reimportTarget = $state<ExternalCertificate | null>(null);
	let reimportCertPEM = $state('');
	let reimportChainPEM = $state('');
	let reimporting = $state(false);
	let reimportError = $state<string | null>(null);
	// Non-blocking advisories from the most recent successful re-import
	// (subject/SANs diff between the requested CSR and the signed cert
	// the CA returned, e.g. subject_cn_rewritten / sans_missing).
	// Mirrors lastWarnings from the upload path. Cleared when the
	// re-import modal (re)opens.
	let reimportWarnings = $state<CertWarning[]>([]);

	// Upload form state.
	let name = $state('');
	let description = $state('');
	let certPEM = $state('');
	let chainPEM = $state('');
	let keyPEM = $state('');
	let uploading = $state(false);
	let uploadError = $state<string | null>(null);
	// Set only for the chain_specified_twice case, so the same friendly
	// message can ALSO render inline next to the Chain field (Fix B) in
	// addition to the bottom form-error (Fix A). Cleared alongside
	// uploadError.
	let uploadErrorCode = $state<string | null>(null);
	// Non-blocking advisories from the most recent successful upload.
	// Cleared on the next upload attempt / form reset.
	let lastWarnings = $state<CertWarning[]>([]);

	// Backend validation-400 codes ("code: human detail") are mapped to
	// friendly, translated messages by resolveCertError
	// ($lib/utils/cert-errors), shared with the re-import modal and the
	// CSR form. Unmapped codes fall back to the raw backend message.

	// Wrong-content checks on the PEM fields, from their BEGIN headers,
	// shown inline before upload (a key in the Certificate field, a
	// certificate in the Key field, a fullchain plus a filled Chain
	// field…). Any of them blocks the upload: the backend would refuse
	// it, or — a key pasted next to the certificate — store the private
	// key in the certificate field.
	const certIssue = $derived(pemFieldIssue('cert', certPEM, { chain: chainPEM }));
	const chainIssue = $derived(pemFieldIssue('chain', chainPEM));
	const keyIssue = $derived(pemFieldIssue('key', keyPEM));
	const reimportCertIssue = $derived(
		pemFieldIssue('cert', reimportCertPEM, { chain: reimportChainPEM })
	);
	const reimportChainIssue = $derived(pemFieldIssue('chain', reimportChainPEM));

	/** i18n key of the inline message for a PEM wrong-content issue. */
	function pemIssueKey(issue: PemIssue): string {
		return `certificates.external.upload.mismatch.${issue}`;
	}

	// Delete-dialog state. deleteTarget holds the cert awaiting
	// confirmation; blockedDialog holds the 409 outcome (the routes
	// still referencing the cert) so the operator knows what to clear.
	let deleteTarget = $state<ExternalCertificate | null>(null);
	let blockedDialog = $state<{ name: string; routes: string[] } | null>(null);

	const canSubmit = $derived(
		name.trim() !== '' &&
			certPEM.trim() !== '' &&
			keyPEM.trim() !== '' &&
			certIssue === null &&
			chainIssue === null &&
			keyIssue === null &&
			!uploading
	);

	/**
	 * Whole days until notAfter (negative once expired). Returns null
	 * for an unparseable / missing timestamp so the badge can render a
	 * neutral placeholder instead of NaN.
	 */
	function daysUntil(notAfter: string): number | null {
		const ts = Date.parse(notAfter);
		if (Number.isNaN(ts)) return null;
		return Math.floor((ts - Date.now()) / 86_400_000);
	}

	/** Badge variant per the expiry thresholds. */
	function expiryVariant(
		days: number | null
	): 'status-up' | 'status-warn' | 'status-down' | 'neutral' {
		if (days === null) return 'neutral';
		if (days <= EXPIRY_DANGER_DAYS) return 'status-down';
		if (days <= EXPIRY_WARN_DAYS) return 'status-warn';
		return 'status-up';
	}

	/** Badge variant per the CSR age bucket (see csrAgeBadge). */
	function ageVariant(
		age: ReturnType<typeof csrAgeBadge>
	): 'neutral' | 'status-info' | 'status-warn' | 'status-down' {
		switch (age) {
			case 'recent':
				return 'neutral';
			case 'waiting':
				return 'status-info';
			case 'old':
				return 'status-warn';
			case 'stale':
				return 'status-down';
		}
	}

	/** i18n label key for the CSR age bucket. */
	function ageLabelKey(age: ReturnType<typeof csrAgeBadge>): string {
		return `certs.externalCerts.pending.age${age.charAt(0).toUpperCase()}${age.slice(1)}`;
	}

	/** "CN, san1, san2" summary of the requested CSR subject. */
	function csrSubjectSummary(cert: ExternalCertificate): string {
		const subject = cert.csrSubject;
		if (!subject || subject.commonName.trim() === '') return '—';
		const sans = (subject.sans ?? []).filter((s) => s.trim() !== '');
		return sans.length > 0 ? `${subject.commonName} (${sans.join(', ')})` : subject.commonName;
	}

	async function loadCerts(): Promise<void> {
		try {
			// The backend returns the list already sorted by notAfter
			// ascending (soonest-first). Assign verbatim — NO re-sort.
			certs = await externalCertsApi.list();
			loadError = false;
		} catch {
			certs = [];
			loadError = true;
		} finally {
			loading = false;
		}
	}

	function resetForm(): void {
		name = '';
		description = '';
		certPEM = '';
		chainPEM = '';
		keyPEM = '';
		uploadError = null;
		uploadErrorCode = null;
	}

	async function handleUpload(): Promise<void> {
		if (uploading) return;
		if (name.trim() === '' || certPEM.trim() === '' || keyPEM.trim() === '') {
			uploadError = t('certificates.external.upload.requiredError');
			uploadErrorCode = null;
			return;
		}
		// The inline wrong-content messages already explain the problem.
		if (certIssue !== null || chainIssue !== null || keyIssue !== null) return;
		uploading = true;
		uploadError = null;
		uploadErrorCode = null;
		lastWarnings = [];
		try {
			const created = await externalCertsApi.upload({
				name: name.trim(),
				description: description.trim() || undefined,
				certPEM: certPEM.trim(),
				keyPEM: keyPEM.trim(),
				chainPEM: chainPEM.trim() || undefined
			});
			lastWarnings = created.warnings ?? [];
			pushToast(t('certificates.external.upload.success', { name: created.name }), 'success');
			resetForm();
			await loadCerts();
		} catch (err) {
			const resolved = resolveCertError(err);
			uploadError = resolved.message;
			uploadErrorCode = resolved.code;
		} finally {
			uploading = false;
		}
	}

	async function confirmDelete(): Promise<void> {
		const target = deleteTarget;
		if (!target) return;
		try {
			await externalCertsApi.remove(target.id);
			pushToast(
				t('certificates.external.delete.success', { name: target.name }),
				'success'
			);
			deleteTarget = null;
			await loadCerts();
		} catch (err) {
			deleteTarget = null;
			const e = err as { status?: number; blockingRoutes?: string[]; message?: string };
			if (e?.status === 409) {
				blockedDialog = { name: target.name, routes: e.blockingRoutes ?? [] };
			} else {
				pushToast(e?.message ?? t('certificates.external.delete.action'), 'danger');
			}
		}
	}

	/** Opens the "Generate CSR" modal. */
	function openGenerate(): void {
		generateOpen = true;
	}

	/**
	 * GenerateCSRForm's onCreated callback prop (NOT a DOM `created`
	 * event — this codebase has zero createEventDispatcher usage; see
	 * GenerateCSRForm.svelte's header comment). Refreshes the list so
	 * the new pending_csr row appears, closes the modal, and switches
	 * to the Pending tab so the operator sees it immediately.
	 */
	function handleCSRCreated(): void {
		generateOpen = false;
		activeTab = 'pending';
		void loadCerts();
	}

	/** Opens the cert-only "Upload signed cert" re-import modal. */
	function openReimport(cert: ExternalCertificate): void {
		reimportTarget = cert;
		reimportCertPEM = '';
		reimportChainPEM = '';
		reimportError = null;
		reimportWarnings = [];
	}

	function closeReimport(): void {
		reimportTarget = null;
		reimportCertPEM = '';
		reimportChainPEM = '';
		reimportError = null;
	}

	/**
	 * Cert-only re-import onto a pending_csr row: PUT with certPEM (+
	 * optional chainPEM) but keyPEM left empty so the backend's
	 * preserve-on-edit semantics keep the server-generated private key
	 * (the frontend never has it — it is never returned on the wire).
	 * On success the backend flips status back to '' and the row moves
	 * to the Active tab. The response's non-blocking `warnings`
	 * (subject/SANs diff between the requested CSR and the CA-issued
	 * cert, e.g. subject_cn_rewritten / sans_missing) are captured into
	 * reimportWarnings and rendered via the same warn-box notice the
	 * upload path uses — closeReimport() intentionally does NOT clear
	 * reimportWarnings, so the notice stays visible on the panel after
	 * the modal closes.
	 */
	async function confirmReimport(): Promise<void> {
		const target = reimportTarget;
		if (!target || reimporting) return;
		if (reimportCertPEM.trim() === '') {
			reimportError = t('certs.externalCerts.pending.certRequiredError');
			return;
		}
		if (reimportCertIssue !== null || reimportChainIssue !== null) return;
		reimporting = true;
		reimportError = null;
		try {
			const updated = await externalCertsApi.update(target.id, {
				name: target.name,
				description: target.description,
				certPEM: reimportCertPEM.trim(),
				keyPEM: '',
				chainPEM: reimportChainPEM.trim() || undefined
			});
			reimportWarnings = updated.warnings ?? [];
			pushToast(
				t('certs.externalCerts.pending.reimportSuccess', { name: updated.name }),
				'success'
			);
			closeReimport();
			await loadCerts();
		} catch (err) {
			reimportError = resolveCertError(err).message;
		} finally {
			reimporting = false;
		}
	}

	onMount(() => {
		void loadCerts();
	});
</script>

<div class="card" data-testid="external-certs-card">
	<div class="card-h">
		<h3>{language.current && t('certificates.external.title')}</h3>
	</div>

	<p class="section-lead">
		{language.current && t('certificates.external.lead')}
	</p>

	<!-- Upload form -->
	<form
		class="upload-form"
		data-testid="external-cert-upload-form"
		onsubmit={(e) => {
			e.preventDefault();
			void handleUpload();
		}}
	>
		<div class="field">
			<label for="ext-name">{language.current && t('certificates.external.upload.nameLabel')}</label>
			<input
				id="ext-name"
				type="text"
				bind:value={name}
				autocomplete="off"
				class="ext-input"
				disabled={uploading}
				data-testid="external-cert-name"
			/>
		</div>
		<div class="field">
			<label for="ext-desc"
				>{language.current && t('certificates.external.upload.descriptionLabel')}</label
			>
			<input
				id="ext-desc"
				type="text"
				bind:value={description}
				autocomplete="off"
				class="ext-input"
				disabled={uploading}
				data-testid="external-cert-description"
			/>
		</div>

		<div class="field field-full">
			<label for="ext-cert">{language.current && t('certificates.external.upload.certLabel')}</label>
			<textarea
				id="ext-cert"
				bind:value={certPEM}
				rows="5"
				class="ext-input mono"
				placeholder="-----BEGIN CERTIFICATE-----"
				spellcheck="false"
				disabled={uploading}
				data-testid="external-cert-cert-pem"
				aria-invalid={certIssue !== null}
				aria-describedby={certIssue !== null ? 'ext-cert-issue' : undefined}
			></textarea>
			<PemFileButton
				fieldLabel={language.current && t('certificates.external.upload.certLabel')}
				disabled={uploading}
				testId="external-cert-cert-file"
				onLoad={(text) => (certPEM = text)}
			/>
			{#if certIssue}
				<p
					id="ext-cert-issue"
					class="form-error field-error-inline"
					role="alert"
					data-testid="external-cert-cert-issue"
				>
					{language.current && t(pemIssueKey(certIssue))}
				</p>
			{/if}
			<p class="field-help">{language.current && t('certificates.external.upload.certHelp')}</p>
		</div>

		<div class="field field-full">
			<label for="ext-chain"
				>{language.current && t('certificates.external.upload.chainLabel')}</label
			>
			<textarea
				id="ext-chain"
				bind:value={chainPEM}
				rows="4"
				class="ext-input mono"
				placeholder="-----BEGIN CERTIFICATE-----"
				spellcheck="false"
				disabled={uploading}
				data-testid="external-cert-chain-pem"
				aria-invalid={chainIssue !== null}
				aria-describedby={chainIssue !== null ? 'ext-chain-issue' : undefined}
			></textarea>
			<PemFileButton
				fieldLabel={language.current && t('certificates.external.upload.chainLabel')}
				disabled={uploading}
				testId="external-cert-chain-file"
				onLoad={(text) => (chainPEM = text)}
			/>
			{#if chainIssue}
				<p
					id="ext-chain-issue"
					class="form-error field-error-inline"
					role="alert"
					data-testid="external-cert-chain-issue"
				>
					{language.current && t(pemIssueKey(chainIssue))}
				</p>
			{/if}
			<p class="field-help">{language.current && t('certificates.external.upload.chainHelp')}</p>
			{#if uploadErrorCode === 'chain_specified_twice'}
				<p
					class="form-error field-error-inline"
					role="alert"
					data-testid="external-cert-chain-error-inline"
				>
					{uploadError}
				</p>
			{/if}
		</div>

		<div class="field field-full">
			<label for="ext-key">{language.current && t('certificates.external.upload.keyLabel')}</label>
			<textarea
				id="ext-key"
				bind:value={keyPEM}
				rows="5"
				class="ext-input mono"
				placeholder="-----BEGIN PRIVATE KEY-----"
				spellcheck="false"
				disabled={uploading}
				data-testid="external-cert-key-pem"
				aria-invalid={keyIssue !== null}
				aria-describedby={keyIssue !== null ? 'ext-key-issue' : undefined}
			></textarea>
			<PemFileButton
				fieldLabel={language.current && t('certificates.external.upload.keyLabel')}
				disabled={uploading}
				testId="external-cert-key-file"
				onLoad={(text) => (keyPEM = text)}
			/>
			{#if keyIssue}
				<p
					id="ext-key-issue"
					class="form-error field-error-inline"
					role="alert"
					data-testid="external-cert-key-issue"
				>
					{language.current && t(pemIssueKey(keyIssue))}
				</p>
			{/if}
			<p class="field-help">{language.current && t('certificates.external.upload.keyHelp')}</p>
		</div>

		{#if uploadError}
			<p class="form-error" role="alert" data-testid="external-cert-upload-error">
				{uploadError}
			</p>
		{/if}

		<div class="form-actions">
			<Button
				variant="primary"
				size="sm"
				type="submit"
				loading={uploading}
				disabled={!canSubmit}
				data-testid="external-cert-upload-btn"
			>
				{#snippet children()}{language.current &&
					(uploading
						? t('certificates.external.upload.submitting')
						: t('certificates.external.upload.submit'))}{/snippet}
			</Button>
		</div>
	</form>

	<!-- Post-upload warnings notice (non-blocking advisories) -->
	{#if lastWarnings.length > 0}
		<div class="warn-box" role="status" data-testid="external-cert-warnings">
			<strong>{language.current && t('certificates.external.upload.warningsTitle')}</strong>
			<ul>
				{#each lastWarnings as w (w.code)}
					<li data-testid="external-cert-warning">{w.message}</li>
				{/each}
			</ul>
		</div>
	{/if}

	<!-- Post-re-import warnings notice (non-blocking subject/SANs diff
	     between the requested CSR and the CA-issued cert). Mirrors the
	     upload warnings notice above. -->
	{#if reimportWarnings.length > 0}
		<div class="warn-box" role="status" data-testid="external-cert-reimport-warnings">
			<strong>{language.current && t('certs.externalCerts.pending.reimportWarningsTitle')}</strong>
			<ul>
				{#each reimportWarnings as w (w.code)}
					<li data-testid="external-cert-reimport-warning">{w.message}</li>
				{/each}
			</ul>
		</div>
	{/if}

	<!-- Active / Pending CSR tabs. Pending count badge steers the
	     operator to un-actioned CSRs without opening the tab. -->
	<div class="tabs-row">
		<Tabs
			bind:value={activeTab}
			ariaLabel={language.current && t('certs.externalCerts.pending.tabsLabel')}
			tabs={[
				{
					id: 'active',
					label: `${language.current && t('certs.externalCerts.pending.activeTab')} (${activeCerts.length})`,
					testId: 'external-certs-tab-active'
				},
				{
					id: 'pending',
					label: `${language.current && t('certs.externalCerts.pending.tab')} (${pendingCerts.length})`,
					testId: 'external-certs-tab-pending'
				}
			]}
		/>
		<Button
			variant="secondary"
			size="sm"
			data-testid="external-cert-generate-csr-btn"
			onclick={openGenerate}
		>
			{#snippet children()}{language.current &&
				t('certs.externalCerts.generate.openButton')}{/snippet}
		</Button>
	</div>

	<!-- List -->
	{#if loading}
		<div class="loading-wrap"><Spinner /></div>
	{:else if loadError}
		<div class="empty-row" data-testid="external-certs-error">
			{language.current && t('certificates.external.loadError')}
		</div>
	{:else if activeTab === 'active'}
		{#if activeCerts.length === 0}
			<div class="empty-row" data-testid="external-certs-empty">
				{language.current && t('certificates.external.empty')}
			</div>
		{:else}
			<table data-testid="external-certs-table">
				<thead>
					<tr>
						<th>{language.current && t('certificates.external.colName')}</th>
						<th>{language.current && t('certificates.external.colSubject')}</th>
						<th>{language.current && t('certificates.external.colDNS')}</th>
						<th>{language.current && t('certificates.external.colExpiry')}</th>
						<th class="col-actions"
							><span class="visually-hidden"
								>{language.current && t('certificates.external.delete.action')}</span
							></th
						>
					</tr>
				</thead>
				<tbody>
					{#each activeCerts as cert (cert.id)}
						{@const days = daysUntil(cert.notAfter)}
						<tr data-testid="external-cert-row" data-id={cert.id}>
							<td>
								<div class="name-cell">{cert.name}</div>
								{#if cert.description}
									<div class="dim cell-sub">{cert.description}</div>
								{/if}
							</td>
							<td>
								<div class="mono">{cert.subject || '—'}</div>
								<div class="dim cell-sub">{cert.issuer || '—'}</div>
							</td>
							<td class="mono">
								{(cert.dnsNames ?? []).length > 0 ? (cert.dnsNames ?? []).join(', ') : '—'}
							</td>
							<td>
								<Badge variant={expiryVariant(days)}>
									{#if days === null}
										—
									{:else if days <= 0}
										{language.current && t('certificates.external.expiryExpired')}
									{:else}
										{language.current &&
											t('certificates.external.expiryDays', {
												days,
												plural: days === 1 ? '' : 's'
											})}
									{/if}
								</Badge>
								<!-- Uploaded certs are never renewed by Arenet, unlike
								     the ACME ones above on the page: say so next to
								     the exact expiry date. -->
								<div
									class="dim cell-sub"
									data-testid="external-cert-expiry-hint"
									title={language.current && t('certificates.external.manualRenewalTitle')}
								>
									{#if days !== null}
										<time datetime={cert.notAfter}
											>{language.current && absoluteDate(cert.notAfter)}</time
										> ·
									{/if}
									{language.current && t('certificates.external.manualRenewal')}
								</div>
							</td>
							<td class="col-actions">
								<button
									type="button"
									class="row-delete-btn"
									data-testid={`external-cert-delete-${cert.id}`}
									aria-label={language.current &&
										t('certificates.external.delete.actionAria', { name: cert.name })}
									onclick={() => (deleteTarget = cert)}
								>
									{language.current && t('certificates.external.delete.action')}
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	{:else if pendingCerts.length === 0}
		<div class="empty-row" data-testid="external-certs-pending-empty">
			{language.current && t('certs.externalCerts.pending.empty')}
		</div>
	{:else}
		{#if pendingCerts.length > 1}
			<p class="pending-hint" data-testid="external-certs-pending-multi-hint">
				{language.current && t('certs.externalCerts.pending.multiplePendingHint')}
			</p>
		{/if}
		<table data-testid="external-certs-pending-table">
			<thead>
				<tr>
					<th>{language.current && t('certificates.external.colName')}</th>
					<th>{language.current && t('certs.externalCerts.pending.colSubject')}</th>
					<th>{language.current && t('certs.externalCerts.pending.colAge')}</th>
					<th class="col-actions"
						><span class="visually-hidden"
							>{language.current && t('certificates.external.delete.action')}</span
						></th
					>
				</tr>
			</thead>
			<tbody>
				{#each pendingCerts as cert (cert.id)}
					{@const age = csrAgeBadge(cert.createdAt)}
					<tr
						data-testid={`external-cert-pending-row-${cert.id}`}
						data-id={cert.id}
					>
						<td>
							<div class="name-cell">{cert.name}</div>
							{#if cert.description}
								<div class="dim cell-sub">{cert.description}</div>
							{/if}
						</td>
						<td class="mono">{csrSubjectSummary(cert)}</td>
						<td data-age={age}>
							<Badge variant={ageVariant(age)}>
								{language.current && t(ageLabelKey(age))}
							</Badge>
						</td>
						<td class="col-actions pending-actions">
							<a
								href={externalCertsApi.csrDownloadUrl(cert.id)}
								class="row-link-btn"
								data-testid={`external-cert-csr-download-${cert.id}`}
							>
								{language.current && t('certs.externalCerts.pending.downloadCSR')}
							</a>
							<button
								type="button"
								class="row-link-btn"
								data-testid={`external-cert-reimport-${cert.id}`}
								onclick={() => openReimport(cert)}
							>
								{language.current && t('certs.externalCerts.pending.uploadSigned')}
							</button>
							<button
								type="button"
								class="row-delete-btn"
								data-testid={`external-cert-pending-delete-${cert.id}`}
								aria-label={language.current &&
									t('certs.externalCerts.pending.deleteAria', { name: cert.name })}
								onclick={() => (deleteTarget = cert)}
							>
								{language.current && t('certificates.external.delete.action')}
							</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</div>

<!-- Delete confirm dialog. Active-row copy is explicit that removal is
     Arenet-local and does NOT revoke the cert with the issuing CA. A
     pending_csr row instead gets the key-destruction warning (Task
     11): deleting it destroys the server-generated private key, and a
     CA signing the CSR afterwards can never be imported — a new CSR
     is required. A pending row is never route-referenced so it never
     409s / opens the blocked dialog below. -->
{#if deleteTarget}
	{@const isPending = deleteTarget.status === 'pending_csr'}
	<Modal
		open={deleteTarget !== null}
		title={language.current &&
			t(
				isPending
					? 'certs.externalCerts.pending.deleteConfirmTitle'
					: 'certificates.external.delete.confirm.title'
			)}
		onClose={() => (deleteTarget = null)}
	>
		{#snippet children()}
			{#if isPending}
				<p class="modal-warn" role="alert" data-testid="external-cert-key-destruction-notice">
					{language.current &&
						t('certs.externalCerts.pending.deleteConfirmText', { name: deleteTarget?.name ?? '' })}
				</p>
			{:else}
				<p class="modal-lead">
					{language.current &&
						t('certificates.external.delete.confirm.text', { name: deleteTarget?.name ?? '' })}
				</p>
				<p class="modal-warn" role="alert" data-testid="external-cert-revoke-notice">
					{language.current && t('certificates.external.delete.confirm.revokeNotice')}
				</p>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (deleteTarget = null)}>
				{#snippet children()}{language.current && t('common.cancel')}{/snippet}
			</Button>
			<Button
				variant="danger"
				data-testid="external-cert-delete-confirm"
				onclick={() => void confirmDelete()}
			>
				{#snippet children()}{language.current &&
					t('certificates.external.delete.confirm.action')}{/snippet}
			</Button>
		{/snippet}
	</Modal>
{/if}

<!-- Blocked-delete dialog. Surfaces the 409 outcome: the cert is still
     referenced by one or more routes, listed verbatim so the operator
     knows what to clear first. -->
{#if blockedDialog}
	<Modal
		open={blockedDialog !== null}
		title={language.current && t('certificates.external.delete.blocked.title')}
		onClose={() => (blockedDialog = null)}
	>
		{#snippet children()}
			<p class="modal-lead" role="alert" data-testid="external-cert-blocked-text">
				{language.current &&
					t('certificates.external.delete.blocked.text', {
						name: blockedDialog?.name ?? '',
						routes: (blockedDialog?.routes ?? []).join(', ')
					})}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (blockedDialog = null)}>
				{#snippet children()}{language.current && t('common.confirm')}{/snippet}
			</Button>
		{/snippet}
	</Modal>
{/if}

<!-- Generate CSR modal (Task 9's GenerateCSRForm). onCreated is a
     callback PROP, not a DOM `created` event — see the doc comment on
     handleCSRCreated above. -->
{#if generateOpen}
	<Modal
		open={generateOpen}
		title={language.current && t('certs.externalCerts.generate.title')}
		width="lg"
		onClose={() => (generateOpen = false)}
	>
		{#snippet children()}
			<GenerateCSRForm onCreated={handleCSRCreated} />
		{/snippet}
	</Modal>
{/if}

<!-- Upload signed cert (cert-only re-import onto a pending_csr row).
     keyPEM is intentionally never collected here — the private key
     stays server-side and PUT's preserve-on-edit semantics (keyPEM:
     '') keep it untouched. -->
{#if reimportTarget}
	<Modal
		open={reimportTarget !== null}
		title={language.current && t('certs.externalCerts.pending.uploadSignedTitle')}
		onClose={closeReimport}
	>
		{#snippet children()}
			<form
				class="reimport-form"
				data-testid="external-cert-reimport-form"
				onsubmit={(e) => {
					e.preventDefault();
					void confirmReimport();
				}}
			>
				<div class="field field-full">
					<label for="reimport-cert"
						>{language.current && t('certs.externalCerts.pending.certLabel')}</label
					>
					<textarea
						id="reimport-cert"
						bind:value={reimportCertPEM}
						rows="6"
						class="ext-input mono"
						placeholder="-----BEGIN CERTIFICATE-----"
						spellcheck="false"
						disabled={reimporting}
						data-testid="external-cert-reimport-cert-pem"
						aria-invalid={reimportCertIssue !== null}
						aria-describedby={reimportCertIssue !== null ? 'reimport-cert-issue' : undefined}
					></textarea>
					<PemFileButton
						fieldLabel={language.current && t('certs.externalCerts.pending.certLabel')}
						disabled={reimporting}
						testId="external-cert-reimport-cert-file"
						onLoad={(text) => (reimportCertPEM = text)}
					/>
					{#if reimportCertIssue}
						<p
							id="reimport-cert-issue"
							class="form-error field-error-inline"
							role="alert"
							data-testid="external-cert-reimport-cert-issue"
						>
							{language.current && t(pemIssueKey(reimportCertIssue))}
						</p>
					{/if}
				</div>
				<div class="field field-full">
					<label for="reimport-chain"
						>{language.current && t('certs.externalCerts.pending.chainLabel')}</label
					>
					<textarea
						id="reimport-chain"
						bind:value={reimportChainPEM}
						rows="4"
						class="ext-input mono"
						placeholder="-----BEGIN CERTIFICATE-----"
						spellcheck="false"
						disabled={reimporting}
						data-testid="external-cert-reimport-chain-pem"
						aria-invalid={reimportChainIssue !== null}
						aria-describedby={reimportChainIssue !== null ? 'reimport-chain-issue' : undefined}
					></textarea>
					<PemFileButton
						fieldLabel={language.current && t('certs.externalCerts.pending.chainLabel')}
						disabled={reimporting}
						testId="external-cert-reimport-chain-file"
						onLoad={(text) => (reimportChainPEM = text)}
					/>
					{#if reimportChainIssue}
						<p
							id="reimport-chain-issue"
							class="form-error field-error-inline"
							role="alert"
							data-testid="external-cert-reimport-chain-issue"
						>
							{language.current && t(pemIssueKey(reimportChainIssue))}
						</p>
					{/if}
				</div>
				{#if reimportError}
					<p class="form-error" role="alert" data-testid="external-cert-reimport-error">
						{reimportError}
					</p>
				{/if}
			</form>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={closeReimport}>
				{#snippet children()}{language.current && t('common.cancel')}{/snippet}
			</Button>
			<Button
				variant="primary"
				loading={reimporting}
				disabled={reimporting ||
					reimportCertPEM.trim() === '' ||
					reimportCertIssue !== null ||
					reimportChainIssue !== null}
				data-testid="external-cert-reimport-submit"
				onclick={() => void confirmReimport()}
			>
				{#snippet children()}{language.current &&
					t('certs.externalCerts.pending.uploadSignedSubmit')}{/snippet}
			</Button>
		{/snippet}
	</Modal>
{/if}

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.card-h {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 {
		color: var(--fg);
		font-size: 13.5px;
		font-weight: 500;
		margin: 0;
	}
	.section-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		line-height: 1.55;
		margin: 0 0 12px 0;
	}

	.upload-form {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		margin-bottom: 12px;
	}
	.field label {
		display: block;
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
		margin-bottom: 4px;
	}
	.field-full {
		grid-column: 1 / -1;
	}
	.field-help {
		margin: 4px 0 0;
		color: var(--fg-muted);
		font-size: 11.5px;
		line-height: 1.45;
	}
	.ext-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}
	.ext-input.mono {
		font-family: var(--font-mono);
		font-size: 11.5px;
		resize: vertical;
		line-height: 1.4;
	}
	.form-error {
		grid-column: 1 / -1;
		color: var(--status-down);
		font-size: 12.5px;
		margin: 0;
	}
	.field-error-inline {
		margin-top: 6px;
	}
	.form-actions {
		grid-column: 1 / -1;
		display: flex;
		justify-content: flex-end;
	}

	.warn-box {
		margin-bottom: 12px;
		padding: 10px 12px;
		background: color-mix(in oklch, var(--status-warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 32%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		line-height: 1.5;
	}
	.warn-box ul {
		margin: 6px 0 0 0;
		padding-left: 18px;
	}
	.warn-box li {
		margin-top: 2px;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12.5px;
	}
	th,
	td {
		padding: 8px 10px;
		text-align: left;
		vertical-align: top;
	}
	th {
		color: var(--fg-muted);
		font-weight: 500;
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid var(--border);
	}
	td {
		color: var(--fg);
		border-bottom: 1px solid var(--border);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
		word-break: break-all;
	}
	.dim {
		color: var(--fg-dim);
	}
	.name-cell {
		font-weight: 500;
	}
	.cell-sub {
		font-size: 11px;
		margin-top: 3px;
	}

	.empty-row {
		color: var(--fg-muted);
		font-size: 12.5px;
		padding: 24px;
		text-align: center;
	}
	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 32px;
	}

	.modal-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		margin: 0 0 12px 0;
	}
	.modal-warn {
		padding: 8px 12px;
		background: color-mix(in oklch, var(--status-warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 30%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		margin: 0;
	}

	.col-actions {
		width: 1%;
		white-space: nowrap;
		text-align: right;
	}
	.row-delete-btn {
		appearance: none;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--fg-muted);
		font-size: 11px;
		font-family: inherit;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition:
			color var(--motion-fast, 120ms),
			background var(--motion-fast, 120ms),
			border-color var(--motion-fast, 120ms);
	}
	.row-delete-btn:hover {
		color: var(--status-down);
		border-color: var(--status-down);
		background: color-mix(in oklch, var(--status-down) 8%, transparent);
	}
	.row-delete-btn:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.visually-hidden {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}

	.tabs-row {
		display: flex;
		align-items: flex-end;
		justify-content: space-between;
		gap: 12px;
		margin-bottom: 4px;
	}
	.tabs-row :global(.tabs) {
		margin-bottom: 0;
		flex: 1;
	}
	.pending-hint {
		color: var(--fg-muted);
		font-size: 12px;
		line-height: 1.5;
		margin: 0 0 10px 0;
	}
	.pending-actions {
		display: flex;
		gap: 6px;
		justify-content: flex-end;
	}
	.row-link-btn {
		appearance: none;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--fg-muted);
		font-size: 11px;
		font-family: inherit;
		text-decoration: none;
		display: inline-flex;
		align-items: center;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition:
			color var(--motion-fast, 120ms),
			background var(--motion-fast, 120ms),
			border-color var(--motion-fast, 120ms);
	}
	.row-link-btn:hover {
		color: var(--accent);
		border-color: var(--accent);
		background: color-mix(in oklch, var(--accent) 8%, transparent);
	}
	.row-link-btn:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.reimport-form {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.reimport-form label {
		display: block;
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
		margin-bottom: 4px;
	}
</style>
