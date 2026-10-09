<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Brick 4, Task 2 — GeoIP settings section. Single Card, two
  halves:

    1. MaxMind credentials (account ID + license key) with a
       Save (preserve-on-empty, mirrors CrowdSec/OIDC) and a
       Test button probing the real MaxMind API without
       mutating state. Mirrors CrowdSecSettingsSection.svelte's
       secret discipline: licenseKey never round-trips from the
       backend; placeholder reads "set (leave blank to keep)"
       when configured.

    2. Auto-update: an opt-in toggle (gated on credentials being
       configured — there is nothing to auto-update without
       them), an interval preset select, a manual "Update now"
       trigger, and the last-check status line. Mirrors
       settings/UpdatesSection.svelte's toggle+manual+status
       shape.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import { systemApi, type GeoIPUpdateConfig, type GeoIPStatus } from '$lib/api/system';
	import { ApiError, type MaxMindConfig, type MaxMindTestResult } from '$lib/api/types';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import UnsavedMarker from './UnsavedMarker.svelte';

	interface Props {
		/** Out: the credentials form differs from what was last loaded or saved. */
		dirty?: boolean;
	}

	let { dirty = $bindable(false) }: Props = $props();

	// Interval presets in hours, mapped to i18n leaves below.
	const PRESETS = [24, 168, 336] as const;

	let maxmind = $state<MaxMindConfig | null>(null);
	let form = $state({ accountId: 0, licenseKey: '' });
	let updateCfg = $state<GeoIPUpdateConfig | null>(null);
	let status = $state<GeoIPStatus | null>(null);
	let testResult = $state<MaxMindTestResult | null>(null);

	let loading = $state(true);
	let loadError = $state('');
	let saving = $state(false);
	let saveError = $state('');
	let testing = $state(false);
	let updating = $state(false);
	let resetOpen = $state(false);

	// Only the credentials form can hold an edit: the auto-update
	// controls save as they change. A blank key means "keep", so only
	// a typed key counts.
	function formKey(): string {
		return JSON.stringify(form);
	}
	let savedKey = $state(formKey());
	const isDirty = $derived(formKey() !== savedKey);
	$effect(() => {
		dirty = isDirty;
	});

	/** Maps the API's lastStatus / triggerGeoIPUpdate status strings
	 * to the i18n leaf under geoipSettings.status.*. */
	function statusKey(s: string): string {
		switch (s) {
			case 'updated':
				return 'updated';
			case 'up_to_date':
				return 'upToDate';
			case 'no_credentials':
				return 'noCredentials';
			default:
				return 'error';
		}
	}

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const [mm, cfg, st] = await Promise.all([
				settingsApi.getMaxMind(),
				systemApi.getGeoIPUpdateConfig(),
				systemApi.getGeoIPStatus()
			]);
			maxmind = mm;
			updateCfg = cfg;
			status = st;
			form.accountId = mm.accountId;
			form.licenseKey = ''; // never round-trip the secret
			savedKey = formKey();
		} catch (err) {
			loadError = err instanceof Error ? err.message : t('geoipSettings.loadFailed');
		} finally {
			loading = false;
		}
	}

	function onFormEdit(): void {
		testResult = null;
	}

	async function save(): Promise<void> {
		saving = true;
		saveError = '';
		try {
			const next = await settingsApi.putMaxMind({
				accountId: form.accountId,
				licenseKey: form.licenseKey
			});
			maxmind = next;
			form.accountId = next.accountId;
			form.licenseKey = ''; // clear so a re-visit doesn't show ghost value
			savedKey = formKey();
			await load();
			pushToast(t('geoipSettings.saveAppliedToast'), 'success');
		} catch (err) {
			saveError = err instanceof ApiError ? err.message : String(err);
		} finally {
			saving = false;
		}
	}

	async function testCredentials(): Promise<void> {
		testing = true;
		saveError = '';
		try {
			const useStored = form.licenseKey === '' && (maxmind?.configured ?? false);
			const res = await settingsApi.testMaxMind(
				useStored
					? ({ useStored: true } as Parameters<typeof settingsApi.testMaxMind>[0])
					: { accountId: form.accountId, licenseKey: form.licenseKey }
			);
			testResult = res;
		} catch (err) {
			saveError = err instanceof ApiError ? err.message : String(err);
			testResult = null;
		} finally {
			testing = false;
		}
	}

	function openResetConfirm(): void {
		resetOpen = true;
	}

	async function confirmReset(): Promise<void> {
		try {
			await settingsApi.deleteMaxMind();
			testResult = null;
			await load();
			pushToast(t('geoipSettings.resetAppliedToast'), 'success');
			resetOpen = false;
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(msg, 'danger');
			// Keep the dialog open so the operator can retry.
		}
	}

	async function toggleEnabled(next: boolean): Promise<void> {
		try {
			updateCfg = await systemApi.putGeoIPUpdateConfig({
				enabled: next,
				intervalHours: updateCfg?.intervalHours ?? 168
			});
		} catch {
			/* keep prior state */
		}
	}

	async function changeInterval(hours: number): Promise<void> {
		try {
			updateCfg = await systemApi.putGeoIPUpdateConfig({
				enabled: updateCfg?.enabled ?? false,
				intervalHours: hours
			});
		} catch {
			/* keep prior state */
		}
	}

	async function updateNow(): Promise<void> {
		updating = true;
		try {
			const res = await systemApi.triggerGeoIPUpdate();
			switch (res.status) {
				case 'updated':
					pushToast(t('geoipSettings.status.updated'), 'success');
					break;
				case 'up_to_date':
					pushToast(t('geoipSettings.status.upToDate'), 'info');
					break;
				case 'no_credentials':
					pushToast(t('geoipSettings.status.noCredentials'), 'danger');
					break;
				default:
					pushToast(
						res.error
							? `${t('geoipSettings.status.error')}: ${res.error}`
							: t('geoipSettings.status.error'),
						'danger'
					);
			}
			status = await systemApi.getGeoIPStatus();
		} catch {
			/* status refresh below reflects any backend-side error */
			try {
				status = await systemApi.getGeoIPStatus();
			} catch {
				/* keep prior status */
			}
		} finally {
			updating = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<div id="geoip" class="mb-6">
	<Card padding="p-6">
		<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
			<div>
				<h2 class="text-xl font-semibold">{language.current && t('geoipSettings.title')}</h2>
				<UnsavedMarker dirty={isDirty} testid="geoip-unsaved" />
				<p class="text-xs text-muted mt-1">{language.current && t('geoipSettings.subtitle')}</p>
			</div>
			{#if loading}
				<Spinner size="sm" />
			{:else if maxmind?.configured}
				<Badge variant="status-up">{language.current && t('geoipSettings.statusConfigured')}</Badge>
			{:else}
				<Badge variant="status-warn"
					>{language.current && t('geoipSettings.statusNotConfigured')}</Badge
				>
			{/if}
		</header>

		{#if loadError}
			<p class="text-sm text-down mb-3" role="alert">
				{language.current && t('geoipSettings.loadFailed')}
			</p>
		{/if}

		<h3 class="text-sm font-semibold text-secondary mb-3">
			{language.current && t('geoipSettings.credsTitle')}
		</h3>

		<form
			class="grid grid-cols-1 md:grid-cols-2 gap-4"
			onsubmit={(e) => {
				e.preventDefault();
				void save();
			}}
		>
			<div>
				<label for="geoip-account-id" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('geoipSettings.labelAccountId')}
				</label>
				<input
					id="geoip-account-id"
					type="number"
					min="0"
					bind:value={form.accountId}
					oninput={onFormEdit}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
			</div>

			<div>
				<label for="geoip-license-key" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('geoipSettings.labelLicenseKey')}
				</label>
				<input
					id="geoip-license-key"
					type="password"
					autocomplete="off"
					bind:value={form.licenseKey}
					oninput={onFormEdit}
					placeholder={maxmind?.configured
						? language.current && t('geoipSettings.licenseKeyPlaceholder')
						: ''}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('geoipSettings.licenseKeyHelper')}
				</p>
			</div>

			{#if testResult}
				<div class="md:col-span-2">
					{#if testResult.reachable}
						<div
							class="rounded border border-up/40 bg-up/10 px-3 py-2 text-sm text-up"
							role="status"
						>
							<strong class="font-semibold">{language.current && t('geoipSettings.testValid')}</strong>
						</div>
					{:else}
						<div
							class="rounded border border-down/40 bg-down/10 px-3 py-2 text-sm text-down"
							role="alert"
						>
							<strong class="font-semibold"
								>{language.current && t('geoipSettings.testFailed')}</strong
							>
							{testResult.error ?? (language.current && t('geoipSettings.testUnknownError'))}
						</div>
					{/if}
				</div>
			{/if}

			{#if saveError}
				<p class="text-sm text-down md:col-span-2" role="alert">{saveError}</p>
			{/if}

			<div class="md:col-span-2 flex justify-between gap-2 flex-wrap">
				<div>
					{#if maxmind?.configured}
						<Button
							variant="ghost"
							type="button"
							disabled={saving || testing}
							onclick={openResetConfirm}
							data-testid="geoip-reset-btn"
						>
							{language.current && t('geoipSettings.btnReset')}
						</Button>
					{/if}
				</div>
				<div class="flex gap-2">
					<Button variant="secondary" type="button" disabled={testing || saving} onclick={testCredentials}>
						{language.current &&
							(testing ? t('geoipSettings.btnTesting') : t('geoipSettings.btnTest'))}
					</Button>
					<Button type="submit" disabled={saving || testing}>
						{language.current && (saving ? t('geoipSettings.btnSaving') : t('geoipSettings.btnSave'))}
					</Button>
				</div>
			</div>
		</form>

		<hr class="border-border-subtle my-6" />

		<h3 class="text-sm font-semibold text-secondary mb-3">
			{language.current && t('geoipSettings.autoUpdateTitle')}
		</h3>

		<div class="flex flex-col gap-3 text-sm">
			<label class="flex items-center gap-2">
				<input
					type="checkbox"
					data-testid="geoip-enable"
					aria-label={language.current && t('geoipSettings.enableToggle')}
					checked={(maxmind?.configured ?? false) && (updateCfg?.enabled ?? false)}
					disabled={!maxmind?.configured}
					onchange={(e) => toggleEnabled((e.currentTarget as HTMLInputElement).checked)}
				/>
				<span>{language.current && t('geoipSettings.enableToggle')}</span>
			</label>

			{#if !maxmind?.configured && updateCfg?.enabled}
				<p class="text-xs text-down" role="status">
					{language.current && t('geoipSettings.enablePaused')}
				</p>
			{:else if !maxmind?.configured}
				<p class="text-xs text-muted">{language.current && t('geoipSettings.enableNeedsCreds')}</p>
			{/if}

			<div>
				<label for="geoip-interval" class="text-sm font-medium text-secondary block mb-1">
					{language.current && t('geoipSettings.intervalLabel')}
				</label>
				<select
					id="geoip-interval"
					data-testid="geoip-interval"
					class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					disabled={!updateCfg?.enabled || !maxmind?.configured}
					value={updateCfg?.intervalHours ?? 168}
					onchange={(e) =>
						changeInterval(Number((e.currentTarget as HTMLSelectElement).value))}
				>
					<option value={24}>{language.current && t('geoipSettings.intervalDaily')}</option>
					<option value={168}>{language.current && t('geoipSettings.intervalWeekly')}</option>
					<option value={336}>{language.current && t('geoipSettings.intervalBiweekly')}</option>
					{#if updateCfg && !PRESETS.includes(updateCfg.intervalHours as (typeof PRESETS)[number])}
						<option value={updateCfg.intervalHours}>
							{language.current &&
								t('geoipSettings.intervalCustom', { hours: updateCfg.intervalHours })}
						</option>
					{/if}
				</select>
			</div>

			<div>
				<Button
					onclick={updateNow}
					disabled={updating || !maxmind?.configured}
					data-testid="geoip-update-now"
				>
					{#if updating}
						<Spinner size="sm" color="current" />
					{/if}
					{language.current &&
						(updating ? t('geoipSettings.btnUpdating') : t('geoipSettings.btnUpdateNow'))}
				</Button>
			</div>

			{#if status}
				<div class="text-xs text-muted">
					{language.current && t('geoipSettings.status.' + statusKey(status.lastStatus))}
					<br />
					{language.current && t('geoipSettings.lastCheckedLabel')}:
					{status.lastUpdated
						? relativeTime(status.lastUpdated)
						: language.current && t('geoipSettings.never')}
					{#if status.lastError}
						<div class="text-down mt-1">{status.lastError}</div>
					{/if}
				</div>
			{/if}
		</div>
	</Card>
</div>

<ConfirmDialog
	bind:open={resetOpen}
	title={language.current && t('geoipSettings.resetDialogTitle')}
	message={language.current && t('geoipSettings.resetDialogMessage')}
	confirmLabel={language.current && t('geoipSettings.resetDialogConfirm')}
	cancelLabel={language.current && t('geoipSettings.resetDialogCancel')}
	confirmVariant="danger"
	onConfirm={confirmReset}
/>
