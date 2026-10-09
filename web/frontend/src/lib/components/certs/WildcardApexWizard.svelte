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
    - Submission error → error message displayed inline inside
      the modal, modal stays open, fields untouched.
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
	import { ApiError } from '$lib/api/types';
	import type { DNSProvider } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

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
	let includeApex = $state(true);
	let submitting = $state(false);
	let formError = $state<string | null>(null);

	// Fetch the configured DNS providers when the wizard opens. The
	// dropdown is fed dynamically (multi-config backend) instead of a
	// hardcoded single OVH option. On error we fall back to an empty
	// list, which renders the empty-state CTA.
	$effect(() => {
		if (open) {
			providersLoading = true;
			settingsApi
				.listDNSProviders()
				.then((list) => {
					providers = list;
					if (list.length > 0 && providerId === '') {
						providerId = list[0].id;
					}
				})
				.catch(() => {
					providers = [];
				})
				.finally(() => {
					providersLoading = false;
				});
		}
	});

	function close(): void {
		onClose();
	}

	function resetForm(): void {
		apex = '';
		providerId = providers[0]?.id ?? '';
		includeApex = true;
		formError = null;
	}

	async function handleSubmit(): Promise<void> {
		if (submitting) return;
		// No provider configured — the empty-state CTA already blocks
		// this path, but guard the handler so an Enter keypress can't
		// submit an unusable request.
		if (providers.length === 0) return;
		const trimmed = apex.trim();
		if (trimmed === '') {
			formError = t('certs.wizardApexRequiredError');
			return;
		}
		submitting = true;
		formError = null;
		try {
			await settingsApi.createManagedDomain({
				apex: trimmed,
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
			formError = err instanceof ApiError ? err.message : String(err);
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
			/>
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
			{:else if providers.length === 0}
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
						<option value={p.id}>{p.label} · {p.type.toUpperCase()}</option>
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
			disabled={submitting || apex.trim() === '' || providers.length === 0}
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
