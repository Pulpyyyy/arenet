<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WildcardApexWizard (Step T T.5, 2026-06-05).

  Modal wizard that packages the pre-T.5 inline "Declare managed
  domain" form into a Modal dialog. Same wire contract (POST
  /api/v1/settings/managed-domains via settingsApi.create-
  ManagedDomain) — no backend changes. The rename to "Politique
  wildcard par apex" lives in the section header and modal title;
  the API surface keeps its frozen v1 vocabulary.

  Satisfies AC #9 ("+ Wildcard apex" wizard) — Step T spec
  v1.2.0-step-t-spec, implemented by 6b03f1c (T.5).

  Stays mounted across show/hide cycles so the parent can keep
  form state via the bindable `open` prop (matches the
  ChangePasswordModal pattern shipped in Chunk 7).

  Behaviour:
    - Click "+ Wildcard apex" (parent) → open=true → modal mounts.
    - Submit "Déclarer" → calls settingsApi.createManagedDomain,
      invokes onCreated() (parent refreshes the list), resets the
      form, closes the modal.
    - Submission error → translated message (resolveManagedDomainError)
      displayed inline inside the modal, modal stays open, fields
      untouched.
    - Apex is normalised as typed (scheme, path, port, leading "*.",
      trailing dot stripped; lowercased) and validated against the
      backend's apex grammar; a one-line summary states what will be
      requested ("*.example.com + example.com via <provider> (DNS-01)").
    - Only providers with `configured` set can be picked; a failed
      provider fetch shows an error with Retry, not the empty state.
    - Cancel / overlay click / Escape → modal closes via the
      Modal primitive's existing focus-trap + onClose contract;
      form state is preserved until the next successful submit
      (operator can re-open and continue where they left off).
-->
<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { settingsApi } from '$lib/api/settings';
	import type { DNSProvider } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { isValidApex, normalizeApexInput } from '$lib/utils/cert-input';
	import { resolveManagedDomainError } from '$lib/utils/cert-errors';

	interface Props {
		open: boolean;
		onClose: () => void;
		onCreated?: () => void | Promise<void>;
	}

	let { open, onClose, onCreated }: Props = $props();

	let apex = $state('');
	let providers = $state<DNSProvider[]>([]);
	let providerId = $state<string>('');
	let providersLoading = $state(true);
	let providersLoadFailed = $state(false);
	let includeApex = $state(true);
	let submitting = $state(false);
	let formError = $state<string | null>(null);

	// Only a provider with its secrets set can solve DNS-01 — the same
	// `configured` gate the /certs page uses for its "DNS provider
	// unconfigured" warning. Unconfigured ones stay listed (so the
	// operator sees them) but can't be picked.
	const configuredProviders = $derived(providers.filter((p) => p.configured));

	// The apex as it will be sent: "https://*.Example.com/" → "example.com".
	const normalizedApex = $derived(normalizeApexInput(apex));
	const apexValid = $derived(isValidApex(normalizedApex));
	const showApexInvalid = $derived(apex.trim() !== '' && !apexValid);
	const showApexNormalized = $derived(apexValid && normalizedApex !== apex.trim());
	const selectedProvider = $derived(configuredProviders.find((p) => p.id === providerId));

	/**
	 * Fetches the DNS providers. The dropdown is fed dynamically
	 * (multi-config backend). A failure is shown as such, with a retry —
	 * not as the "no provider configured" empty state, which would send
	 * the operator to Settings for nothing.
	 */
	function loadProviders(): void {
		providersLoading = true;
		providersLoadFailed = false;
		settingsApi
			.listDNSProviders()
			.then((list) => {
				providers = list;
				const usable = list.filter((p) => p.configured);
				if (!usable.some((p) => p.id === providerId)) {
					providerId = usable[0]?.id ?? '';
				}
			})
			.catch(() => {
				providers = [];
				providersLoadFailed = true;
			})
			.finally(() => {
				providersLoading = false;
			});
	}

	$effect(() => {
		if (open) loadProviders();
	});

	/** "OVH perso · OVH", suffixed with "not configured" when unusable. */
	function providerOptionLabel(p: DNSProvider): string {
		const base = `${p.label} · ${p.type.toUpperCase()}`;
		return p.configured
			? base
			: `${base} — ${t('certs.wildcardWizard.dnsProvider.notConfigured')}`;
	}

	function close(): void {
		onClose();
	}

	function resetForm(): void {
		apex = '';
		providerId = configuredProviders[0]?.id ?? '';
		includeApex = true;
		formError = null;
	}

	async function handleSubmit(): Promise<void> {
		if (submitting) return;
		// No usable provider — the empty / error state already blocks
		// this path, but guard the handler so an Enter keypress can't
		// submit an unusable request.
		if (selectedProvider === undefined) return;
		if (apex.trim() === '') {
			formError = t('certs.wizardApexRequiredError');
			return;
		}
		// The inline field message already says what's wrong.
		if (!apexValid) return;
		submitting = true;
		formError = null;
		try {
			await settingsApi.createManagedDomain({
				apex: normalizedApex,
				includeApex,
				providerId,
			});
			// onCreated lets the parent refresh the declared-policies
			// list BEFORE we reset/close so the new row is visible
			// the moment the wizard goes away.
			await onCreated?.();
			resetForm();
			close();
		} catch (err) {
			formError = resolveManagedDomainError(err);
		} finally {
			submitting = false;
		}
	}
</script>

<Modal {open} title={language.current && t('certs.wizardTitle')} onClose={close}>
	<form
		class="wizard-form"
		data-testid="wildcard-wizard-form"
		onsubmit={(e) => {
			e.preventDefault();
			void handleSubmit();
		}}
	>
		<div class="field field-full">
			<label for="wz-apex">{language.current && t('certs.wizardApexLabel')}</label>
			<input
				id="wz-apex"
				type="text"
				bind:value={apex}
				placeholder="example.com"
				autocomplete="off"
				class="md-input mono"
				disabled={submitting}
				data-testid="wizard-apex-input"
				aria-invalid={showApexInvalid}
				aria-describedby={showApexInvalid ? 'wz-apex-error' : undefined}
			/>
			{#if showApexInvalid}
				<p id="wz-apex-error" class="field-error" role="alert" data-testid="wizard-apex-invalid">
					{language.current &&
						t('certs.wildcardWizard.apexInvalid', { value: apex.trim() })}
				</p>
			{:else if showApexNormalized}
				<p class="hint" data-testid="wizard-apex-normalized">
					{language.current &&
						t('certs.wildcardWizard.apexNormalized', { apex: normalizedApex })}
				</p>
			{/if}
			<!--
				The hint carries a live <code>*.{apex}</code> that can't
				go through t() interpolation, so the sentence is split
				around it (before / code / after) in each language.
			-->
			<p class="hint">
				{language.current && t('certs.wizardApexHintBefore')}
				<code>*.{apex || 'example.com'}</code>{language.current && t('certs.wizardApexHintAfter')}
			</p>
		</div>

		<div class="field">
			{#if providersLoading}
				<div class="providers-loading" data-testid="wizard-providers-loading">
					<Spinner />
				</div>
			{:else if providersLoadFailed}
				<div class="wizard-empty" role="alert" data-testid="wizard-provider-load-error">
					<p>
						{language.current && t('certs.wildcardWizard.dnsProvider.loadError')}
					</p>
					<Button
						variant="secondary"
						size="sm"
						onclick={loadProviders}
						data-testid="wizard-provider-retry"
					>
						{#snippet children()}{language.current &&
							t('certs.wildcardWizard.dnsProvider.retry')}{/snippet}
					</Button>
				</div>
			{:else if configuredProviders.length === 0}
				<div class="wizard-empty" role="alert" data-testid="wizard-provider-empty">
					<p>
						{language.current &&
							t('certs.wildcardWizard.dnsProvider.emptyState.message')}
					</p>
					<a href="/settings#dns-providers">
						{language.current &&
							t('certs.wildcardWizard.dnsProvider.emptyState.ctaLabel')}
					</a>
				</div>
			{:else}
				<label for="wz-provider"
					>{language.current && t('certs.wildcardWizard.dnsProvider.label')}</label
				>
				<select
					id="wz-provider"
					bind:value={providerId}
					class="md-input"
					disabled={submitting}
				>
					{#each providers as p (p.id)}
						<option value={p.id} disabled={!p.configured}
							>{language.current && providerOptionLabel(p)}</option
						>
					{/each}
				</select>
			{/if}
		</div>

		<div class="field field-checkbox">
			<input
				id="wz-include-apex"
				type="checkbox"
				bind:checked={includeApex}
				disabled={submitting}
			/>
			<label for="wz-include-apex">{language.current && t('certs.wizardIncludeApexLabel')}</label>
		</div>

		<!-- What will actually be requested, once apex + provider are
		     usable: "*.example.com + example.com via OVH perso (DNS-01)". -->
		{#if apexValid && selectedProvider}
			<p class="summary" role="status" data-testid="wizard-summary">
				{language.current &&
					t(
						includeApex
							? 'certs.wildcardWizard.summaryWithApex'
							: 'certs.wildcardWizard.summaryWildcardOnly',
						{
							wildcard: `*.${normalizedApex}`,
							apex: normalizedApex,
							provider: selectedProvider.label
						}
					)}
			</p>
		{/if}

		{#if formError}
			<p class="form-error" role="alert" data-testid="wizard-error">
				{formError}
			</p>
		{/if}

		<!-- Hidden submit so Enter inside the apex input still
		     triggers submission. The visible Declare button in the
		     Modal footer also wires to handleSubmit via onclick. -->
		<button type="submit" class="hidden-submit" tabindex="-1" aria-hidden="true"
			>Submit</button
		>
	</form>

	{#snippet footer()}
		<Button variant="ghost" size="md" onclick={close} disabled={submitting}>
			{#snippet children()}{language.current && t('certs.wizardCancelButton')}{/snippet}
		</Button>
		<Button
			variant="primary"
			size="md"
			onclick={() => void handleSubmit()}
			loading={submitting}
			disabled={submitting || !apexValid || selectedProvider === undefined}
		>
			{#snippet children()}{language.current && (submitting ? t('certs.wizardSubmitting') : t('certs.wizardSubmitButton'))}{/snippet}
		</Button>
	{/snippet}
</Modal>

<style>
	.wizard-form {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 14px;
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
	.field-checkbox {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 23px;
	}
	.field-checkbox label {
		margin-bottom: 0;
		font-weight: 400;
		color: var(--fg-muted);
	}
	.md-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}
	.md-input.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.hint {
		font-size: 11.5px;
		color: var(--fg-muted);
		margin: 6px 0 0 0;
	}
	.hint code {
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--fg);
	}
	.form-error {
		grid-column: 1 / -1;
		color: var(--status-down);
		font-size: 12.5px;
		margin: 0;
	}
	.field-error {
		color: var(--status-down);
		font-size: 11.5px;
		margin: 6px 0 0 0;
	}
	.summary {
		grid-column: 1 / -1;
		margin: 0;
		padding: 8px 10px;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.providers-loading {
		display: flex;
		align-items: center;
		padding: 8px 0;
	}
	.wizard-empty {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 10px 12px;
	}
	.wizard-empty p {
		margin: 0 0 6px 0;
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.wizard-empty a {
		font-size: 12.5px;
		color: var(--accent);
		text-decoration: none;
	}
	.wizard-empty a:hover {
		text-decoration: underline;
	}
	/* Hidden but functional submit button so pressing Enter inside
	   the apex input fires the form submission. The visible
	   Déclarer button lives in the Modal footer outside the form. */
	.hidden-submit {
		position: absolute;
		left: -9999px;
		width: 1px;
		height: 1px;
		opacity: 0;
		pointer-events: none;
	}
</style>
