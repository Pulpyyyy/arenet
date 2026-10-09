<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  GenerateCSRForm (v2.20.0 CSR generation, Task 9).

  Collects a certificate subject (Common Name required, SANs +
  optional DN components) and a key algorithm choice, then asks the
  backend to generate a keypair + CSR server-side
  (externalCertsApi.generateCSR). The backend never returns the
  private key; it stores a `pending_csr` row and returns the CSR PEM
  alongside it.

  On success the CSR is downloaded immediately via a transient
  <a href={csrDownloadUrl(id)} download> (synthesized + clicked, never
  appended to the DOM) so the operator can hand it to their CA, and
  `onCreated` is invoked with the new row so the parent (Task 10) can
  refresh its list and switch to the Pending tab. This mirrors the
  callback-prop pattern used across the codebase (e.g. RuleModal's
  `onSaved`) rather than a DOM CustomEvent.

  Key algorithm defaults to 'rsa_4096' on mount (widest CA
  compatibility, incl. legacy PKI like Windows AD CS); 'ecdsa_p256' is
  offered as a faster/smaller alternative with a caveat that some
  legacy CAs reject it.
-->
<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import { externalCertsApi } from '$lib/api/external-certs';
	import type { ExternalCertificate } from '$lib/api/external-certs';
	import { t } from '$lib/i18n';
	import { resolveCertError } from '$lib/utils/cert-errors';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		onCreated?: (cert: ExternalCertificate) => void;
	}

	let { onCreated }: Props = $props();

	// Subject fields.
	let name = $state('');
	let description = $state('');
	let commonName = $state('');
	let sansInput = $state('');
	let organization = $state('');
	let orgUnit = $state('');
	let country = $state('');
	let locality = $state('');
	let stateOrProvince = $state('');
	let keyAlgorithm = $state<'rsa_4096' | 'ecdsa_p256'>('rsa_4096');

	let submitting = $state(false);
	let submitError = $state<string | null>(null);

	/**
	 * Comma-separated SANs -> a trimmed, de-duplicated, non-empty list.
	 * Kept as a plain comma input (not a chip widget) to match the
	 * lightweight-input style used elsewhere in this panel family; the
	 * parsing rule (split on comma, trim, drop empties) is the whole
	 * contract.
	 */
	function parseSANs(raw: string): string[] {
		const seen = new Set<string>();
		for (const part of raw.split(',')) {
			const v = part.trim();
			if (v !== '') seen.add(v);
		}
		return [...seen];
	}

	function resetForm(): void {
		name = '';
		description = '';
		commonName = '';
		sansInput = '';
		organization = '';
		orgUnit = '';
		country = '';
		locality = '';
		stateOrProvince = '';
		keyAlgorithm = 'rsa_4096';
		submitError = null;
	}

	/**
	 * Synthesizes a transient <a download> pointed at the CSR download
	 * URL and clicks it. Never appended to the DOM — Firefox/Chrome
	 * both honor a click on a detached anchor for triggering a
	 * download.
	 */
	function triggerCSRDownload(id: string): void {
		const a = document.createElement('a');
		a.href = externalCertsApi.csrDownloadUrl(id);
		a.download = '';
		a.click();
	}

	async function handleSubmit(): Promise<void> {
		if (submitting) return;
		if (commonName.trim() === '') {
			submitError = t('certs.externalCerts.generate.commonNameRequiredError');
			return;
		}
		submitting = true;
		submitError = null;
		try {
			const created = await externalCertsApi.generateCSR({
				name: name.trim(),
				description: description.trim() || undefined,
				csrSubject: {
					commonName: commonName.trim(),
					sans: parseSANs(sansInput),
					organization: organization.trim() || undefined,
					orgUnit: orgUnit.trim() || undefined,
					country: country.trim() || undefined,
					locality: locality.trim() || undefined,
					state: stateOrProvince.trim() || undefined,
					keyAlgorithm
				}
			});
			triggerCSRDownload(created.id);
			resetForm();
			onCreated?.(created);
		} catch (err) {
			// cn_required / invalid_country / invalid_key_algorithm
			// (internal/storage/csr.go:40-42) → translated messages.
			submitError = resolveCertError(err).message;
		} finally {
			submitting = false;
		}
	}
</script>

<form
	class="csr-form"
	data-testid="generate-csr-form"
	onsubmit={(e) => {
		e.preventDefault();
		void handleSubmit();
	}}
>
	<div class="field">
		<label for="csr-name">{language.current && t('certs.externalCerts.generate.nameLabel')}</label>
		<input
			id="csr-name"
			type="text"
			bind:value={name}
			autocomplete="off"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-name"
		/>
	</div>
	<div class="field">
		<label for="csr-desc"
			>{language.current && t('certs.externalCerts.generate.descriptionLabel')}</label
		>
		<input
			id="csr-desc"
			type="text"
			bind:value={description}
			autocomplete="off"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-description"
		/>
	</div>

	<div class="field field-full">
		<label for="csr-cn"
			>{language.current && t('certs.externalCerts.generate.commonNameLabel')}</label
		>
		<input
			id="csr-cn"
			type="text"
			bind:value={commonName}
			autocomplete="off"
			required
			aria-required="true"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-common-name"
		/>
	</div>

	<div class="field field-full">
		<label for="csr-sans">{language.current && t('certs.externalCerts.generate.sansLabel')}</label>
		<input
			id="csr-sans"
			type="text"
			bind:value={sansInput}
			autocomplete="off"
			class="csr-input"
			placeholder="app.corp.local, app2.corp.local"
			disabled={submitting}
			data-testid="csr-sans"
		/>
		<p class="field-help">{language.current && t('certs.externalCerts.generate.sansHelp')}</p>
	</div>

	<div class="field">
		<label for="csr-org">{language.current && t('certs.externalCerts.generate.organizationLabel')}</label>
		<input
			id="csr-org"
			type="text"
			bind:value={organization}
			autocomplete="off"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-organization"
		/>
	</div>
	<div class="field">
		<label for="csr-ou">{language.current && t('certs.externalCerts.generate.orgUnitLabel')}</label>
		<input
			id="csr-ou"
			type="text"
			bind:value={orgUnit}
			autocomplete="off"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-org-unit"
		/>
	</div>

	<div class="field">
		<label for="csr-country">{language.current && t('certs.externalCerts.generate.countryLabel')}</label>
		<input
			id="csr-country"
			type="text"
			bind:value={country}
			autocomplete="off"
			maxlength="2"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-country"
		/>
	</div>
	<div class="field">
		<label for="csr-locality"
			>{language.current && t('certs.externalCerts.generate.localityLabel')}</label
		>
		<input
			id="csr-locality"
			type="text"
			bind:value={locality}
			autocomplete="off"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-locality"
		/>
	</div>
	<div class="field">
		<label for="csr-state">{language.current && t('certs.externalCerts.generate.stateLabel')}</label>
		<input
			id="csr-state"
			type="text"
			bind:value={stateOrProvince}
			autocomplete="off"
			class="csr-input"
			disabled={submitting}
			data-testid="csr-state"
		/>
	</div>

	<fieldset class="field field-full csr-algo-fieldset">
		<legend>{language.current && t('certs.externalCerts.generate.keyAlgorithmLegend')}</legend>
		<div class="csr-algo-options">
			<label class="csr-algo-option">
				<input
					type="radio"
					name="csr-key-algorithm"
					value="rsa_4096"
					bind:group={keyAlgorithm}
					disabled={submitting}
					data-testid="csr-algo-rsa"
				/>
				<span class="csr-algo-text">
					<span class="csr-algo-name"
						>{language.current && t('certs.externalCerts.generate.keyAlgorithmRSA')}</span
					>
					<span class="field-help"
						>{language.current && t('certs.externalCerts.generate.keyAlgorithmRSAHelp')}</span
					>
				</span>
			</label>
			<label class="csr-algo-option">
				<input
					type="radio"
					name="csr-key-algorithm"
					value="ecdsa_p256"
					bind:group={keyAlgorithm}
					disabled={submitting}
					data-testid="csr-algo-ecdsa"
				/>
				<span class="csr-algo-text">
					<span class="csr-algo-name"
						>{language.current && t('certs.externalCerts.generate.keyAlgorithmECDSA')}</span
					>
					<span class="field-help"
						>{language.current && t('certs.externalCerts.generate.keyAlgorithmECDSAHelp')}</span
					>
				</span>
			</label>
		</div>
	</fieldset>

	{#if submitError}
		<p class="form-error" role="alert" data-testid="csr-submit-error">
			{submitError}
		</p>
	{/if}

	<div class="form-actions">
		<Button
			variant="primary"
			size="sm"
			type="submit"
			loading={submitting}
			disabled={submitting}
			data-testid="csr-generate-btn"
		>
			{#snippet children()}{language.current &&
				(submitting
					? t('certs.externalCerts.generate.submitting')
					: t('certs.externalCerts.generate.submit'))}{/snippet}
		</Button>
	</div>
</form>

<style>
	.csr-form {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
	}
	.field label,
	.csr-algo-fieldset legend {
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
	.csr-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}
	.csr-algo-fieldset {
		border: none;
		padding: 0;
		margin: 0;
	}
	.csr-algo-options {
		display: flex;
		flex-direction: column;
		gap: 10px;
	}
	.csr-algo-option {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		font-weight: normal;
		cursor: pointer;
	}
	.csr-algo-option input[type='radio'] {
		margin-top: 3px;
	}
	.csr-algo-text {
		display: flex;
		flex-direction: column;
	}
	.csr-algo-name {
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
	}
	.form-error {
		grid-column: 1 / -1;
		color: var(--status-down);
		font-size: 12.5px;
		margin: 0;
	}
	.form-actions {
		grid-column: 1 / -1;
		display: flex;
		justify-content: flex-end;
	}
</style>
