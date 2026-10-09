<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step CS.1 — CrowdSec bouncer settings section. Single Card,
  one form, two submit paths:

    1. "Save & apply" — persists via PUT /api/v1/settings/
       crowdsec and triggers a backend mgr.ApplyCrowdSecConfig
       which rebuilds the Caddy config + reloads — no process
       restart required.

    2. "Test connection" — probes LAPI /v1/decisions via
       POST /api/v1/settings/crowdsec/test without mutating
       state. Renders a green / red badge with the diagnostic
       string (auth failed / timeout / connection refused / …).

  Deployment-agnostic: the LAPI URL accepts ANY http(s) URL.
  apt systemd → http://127.0.0.1:8080. Docker port-mapped →
  http://127.0.0.1:8080. Docker sibling network →
  http://crowdsec:8080. See docs/setup/crowdsec.md.

  Secret discipline: apiKey field always renders empty;
  placeholder reads "••• set (leave blank to keep)" when
  configured. Submitting with blank apiKey preserves the
  stored value (server-side merge, mirror of OIDC / DNS
  provider). Submitting all blank clears the configuration
  entirely — operator's "Disable bouncer" path.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import {
		ApiError,
		type CrowdSecSettings,
		type CrowdSecTestResponse
	} from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import UnsavedMarker from '$lib/components/settings/UnsavedMarker.svelte';

	interface Props {
		/** Out: the form differs from what was last loaded or saved. */
		dirty?: boolean;
	}

	let { dirty = $bindable(false) }: Props = $props();

	let settings = $state<CrowdSecSettings | null>(null);
	// Sticky: set when a save moved the LAPI address, and NOT cleared by
	// a later reload of the settings. Until Arenet restarts, the bouncer
	// still dials the old address and — failing open — blocks nothing.
	// An operator who dismisses this by navigating away would be
	// unprotected with no other sign of it.
	let restartRequired = $state(false);
	let loading = $state(true);
	let loadError = $state('');

	let form = $state({
		lapiUrl: 'http://127.0.0.1:8080',
		apiKey: '',
		bouncerName: 'arenet',
		timeoutSeconds: 5
	});
	let formError = $state('');
	let submitting = $state(false);

	// The form as last loaded or saved. The key field is always blank
	// then ("keep the stored key"), so only a typed key is an edit.
	function formKey(): string {
		return JSON.stringify(form);
	}
	let savedKey = $state(formKey());
	const isDirty = $derived(formKey() !== savedKey);
	$effect(() => {
		dirty = isDirty;
	});

	// Test connection state. `testResult` is set after a probe
	// completes; null when no probe has run yet (or the form
	// was edited since the last probe — the UI invalidates the
	// stale badge to avoid showing "Connected" against a URL
	// the operator has since modified).
	let testResult = $state<CrowdSecTestResponse | null>(null);
	let testing = $state(false);

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const cfg = await settingsApi.getCrowdSecSettings();
			settings = cfg;
			form.lapiUrl = cfg.lapiUrl || 'http://127.0.0.1:8080';
			form.bouncerName = cfg.bouncerName || 'arenet';
			form.timeoutSeconds = cfg.timeoutSeconds || 5;
			form.apiKey = ''; // never round-trip the secret
			savedKey = formKey();
		} catch (err) {
			loadError = err instanceof Error ? err.message : t('crowdsecSettings.loadFailed', { err: '' });
		} finally {
			loading = false;
		}
	}

	async function submit(): Promise<void> {
		submitting = true;
		formError = '';
		try {
			const next = await settingsApi.putCrowdSecSettings({
				lapiUrl: form.lapiUrl.trim(),
				apiKey: form.apiKey,
				bouncerName: form.bouncerName.trim(),
				timeoutSeconds: form.timeoutSeconds
			});
			settings = next;
			if (next.restartRequired) restartRequired = true;
			form.apiKey = ''; // clear so a re-visit doesn't show ghost value
			savedKey = formKey();
			pushToast(
				next.configured
					? t('crowdsecSettings.saveAppliedToast')
					: t('crowdsecSettings.saveClearedToast'),
				'success'
			);
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
		} finally {
			submitting = false;
		}
	}

	async function testConnection(): Promise<void> {
		testing = true;
		formError = '';
		try {
			// Send whatever the form holds. The backend falls back to
			// the stored row PER FIELD, so an empty apiKey — which is
			// the normal case, since a saved secret is never echoed
			// back into the form — still probes with the stored key
			// while honouring a URL the operator has just changed.
			//
			// This used to key off the apiKey alone: an empty key meant
			// useStored, which ignores the wire fields wholesale. So an
			// operator who moved their LAPI, typed the new URL and
			// pressed Test was told the connection failed — against the
			// OLD address, which they had never asked to probe. Exactly
			// what happened on 2026-09-27 when a LAPI moved from
			// 127.0.0.1 to a WireGuard address: "connection refused",
			// reported for a URL that was no longer on screen.
			//
			// useStored now means what its name says: nothing in the
			// form, probe what is saved.
			const untouched = form.lapiUrl.trim() === '' && form.apiKey === '';
			const useStored = untouched && (settings?.configured ?? false);
			const res = await settingsApi.testCrowdSecConnection(
				useStored
					? { useStored: true }
					: {
							lapiUrl: form.lapiUrl.trim(),
							apiKey: form.apiKey,
							timeoutSeconds: form.timeoutSeconds
					  }
			);
			testResult = res;
			if (!res.ok) {
				// Surface the error inline in the badge area; no
				// toast (the badge IS the affordance).
			}
		} catch (err) {
			formError = err instanceof ApiError ? err.message : String(err);
			testResult = null;
		} finally {
			testing = false;
		}
	}

	// Invalidate the test result whenever the operator edits
	// any URL / key / timeout — showing "Connected" against
	// values the user has since changed would be misleading.
	function onFormEdit(): void {
		testResult = null;
	}

	// Reset configuration (Step CS.2 follow-up). Confirms via
	// ConfirmDialog, then DELETEs the row, then refreshes the
	// section's state so the badge flips back to "Not
	// configured" and the form returns to its defaults.
	// Distinct from "Save with all blank" — the operator's
	// intent (audit row crowdsec_reset) is the deliberate
	// "disable the bouncer" signal.
	let resetConfirmOpen = $state(false);
	function openResetConfirm(): void {
		resetConfirmOpen = true;
	}
	async function confirmReset(): Promise<void> {
		try {
			const next = await settingsApi.deleteCrowdSecSettings();
			settings = next;
			form.lapiUrl = next.lapiUrl || 'http://127.0.0.1:8080';
			form.bouncerName = next.bouncerName || 'arenet';
			form.timeoutSeconds = next.timeoutSeconds || 5;
			form.apiKey = '';
			savedKey = formKey();
			testResult = null;
			pushToast(t('crowdsecSettings.resetToastSuccess'), 'success');
			resetConfirmOpen = false;
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(t('crowdsecSettings.resetToastFailed', { err: msg }), 'danger');
			// Keep the dialog open so the operator can retry.
		}
	}

	onMount(() => {
		void load();
	});
</script>

<div class="mb-6">
	<Card padding="p-6">
		<header
			class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4"
		>
			<div>
				<h2 class="text-xl font-semibold">{language.current && t('crowdsecSettings.title')}</h2>
				<UnsavedMarker dirty={isDirty} testid="crowdsec-unsaved" />
				<p class="text-xs text-muted mt-1">
					{language.current && t('crowdsecSettings.subtitle')}
				</p>
			</div>
			{#if loading}
				<Spinner size="sm" />
			{:else if settings?.configured}
				<Badge variant="status-up">{language.current && t('crowdsecSettings.statusConfigured')}</Badge>
			{:else}
				<Badge variant="status-warn">{language.current && t('crowdsecSettings.statusNotConfigured')}</Badge>
			{/if}
		</header>

		{#if loadError}
			<p class="text-sm text-down mb-3" role="alert">
				{language.current && t('crowdsecSettings.loadFailed', { err: loadError })}
			</p>
		{/if}

		<form
			class="grid grid-cols-1 md:grid-cols-2 gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				void submit();
			}}
		>
			<div class="md:col-span-2">
				<label for="cs-lapi-url" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('crowdsecSettings.labelLapiUrl')}
				</label>
				<input
					id="cs-lapi-url"
					type="text"
					bind:value={form.lapiUrl}
					oninput={onFormEdit}
					placeholder={language.current && t('crowdsecSettings.lapiUrlPlaceholder')}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('crowdsecSettings.lapiUrlHelper')}
				</p>
			</div>

			<div>
				<label for="cs-api-key" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('crowdsecSettings.labelApiKey')}
				</label>
				<input
					id="cs-api-key"
					type="password"
					autocomplete="off"
					bind:value={form.apiKey}
					oninput={onFormEdit}
					placeholder={settings?.configured ? (language.current && t('crowdsecSettings.apiKeyPlaceholder')) : ''}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('crowdsecSettings.apiKeyHelper')}
				</p>
			</div>

			<div>
				<label for="cs-bouncer-name" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('crowdsecSettings.labelBouncerName')}
				</label>
				<input
					id="cs-bouncer-name"
					type="text"
					bind:value={form.bouncerName}
					oninput={onFormEdit}
					placeholder={language.current && t('crowdsecSettings.bouncerNamePlaceholder')}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('crowdsecSettings.bouncerNameHelper')}
				</p>
			</div>

			<div>
				<label for="cs-timeout" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('crowdsecSettings.labelTimeout')}
				</label>
				<input
					id="cs-timeout"
					type="number"
					min="1"
					max="60"
					bind:value={form.timeoutSeconds}
					oninput={onFormEdit}
					class="w-32 bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('crowdsecSettings.timeoutHelper')}
				</p>
			</div>

			{#if testResult}
				<div class="md:col-span-2">
					{#if testResult.ok}
						<div
							class="rounded border border-up/40 bg-up/10 px-3 py-2 text-sm text-up"
							role="status"
						>
							<strong class="font-semibold">{language.current && t('crowdsecSettings.testConnected')}</strong>
							{#if testResult.version}
								{language.current && t('crowdsecSettings.testConnectedToLapi')} <code class="font-mono">{testResult.version}</code>
							{/if}
							{#if testResult.effectiveUrl}
								{language.current && t('crowdsecSettings.testConnectedAt')} <code class="font-mono">{testResult.effectiveUrl}</code>
							{/if}
						</div>
					{:else}
						<div
							class="rounded border border-down/40 bg-down/10 px-3 py-2 text-sm text-down"
							role="alert"
						>
							<strong class="font-semibold">{language.current && t('crowdsecSettings.testConnectionFailed')}</strong>
							{testResult.error ?? (language.current && t('crowdsecSettings.testUnknownError'))}
							{#if testResult.statusCode}
								<span class="text-xs ml-1">(HTTP {testResult.statusCode})</span>
							{/if}
						</div>
					{/if}
				</div>
			{/if}

			{#if restartRequired}
				<!-- Deliberately an alert, not a toast: a toast disappears
				     and this state persists until the operator acts. While
				     it stands, the bouncer is dialling the previous LAPI
				     address and, failing open, blocking nothing. -->
				<div
					class="md:col-span-2 rounded border border-warn/40 bg-warn/10 px-3 py-2"
					role="alert"
					data-testid="crowdsec-restart-required"
				>
					<p class="text-sm font-medium text-warn">
						{t('crowdsecSettings.restartRequiredTitle')}
					</p>
					<p class="text-xs text-secondary mt-1">
						{t('crowdsecSettings.restartRequiredBody')}
					</p>
					<code class="text-xs mt-2 block">sudo systemctl restart arenet</code>
				</div>
			{/if}
			{#if formError}
				<p class="text-sm text-down md:col-span-2" role="alert">{formError}</p>
			{/if}

			<div class="md:col-span-2 flex justify-between gap-2 flex-wrap">
				<div>
					{#if settings?.configured}
						<!-- Reset is visually separated from the
						     Save / Test pair (left edge instead of
						     right) so a misclick can't confuse it
						     with the primary action. Only shown when
						     a row exists — there's nothing to reset
						     on a fresh install. -->
						<Button
							variant="ghost"
							type="button"
							disabled={submitting || testing}
							onclick={openResetConfirm}
							data-testid="crowdsec-reset-btn"
						>
							{language.current && t('crowdsecSettings.btnReset')}
						</Button>
					{/if}
				</div>
				<div class="flex gap-2">
					<Button
						variant="secondary"
						type="button"
						disabled={testing || submitting}
						onclick={testConnection}
					>
						{language.current && (testing ? t('crowdsecSettings.btnTesting') : t('crowdsecSettings.btnTest'))}
					</Button>
					<Button type="submit" disabled={submitting || testing}>
						{language.current && (submitting ? t('crowdsecSettings.btnSaving') : t('crowdsecSettings.btnSave'))}
					</Button>
				</div>
			</div>
		</form>

		<p class="text-xs text-muted mt-4">
			{language.current && t('crowdsecSettings.saveFooter')}
		</p>
	</Card>
</div>

<ConfirmDialog
	bind:open={resetConfirmOpen}
	title={language.current && t('crowdsecSettings.resetDialogTitle')}
	message={language.current && t('crowdsecSettings.resetDialogMessage')}
	confirmLabel={language.current && t('crowdsecSettings.resetDialogConfirm')}
	cancelLabel={language.current && t('crowdsecSettings.resetDialogCancel')}
	confirmVariant="danger"
	onConfirm={confirmReset}
/>
