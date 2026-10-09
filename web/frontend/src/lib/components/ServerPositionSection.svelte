<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V.7 — Server geographic position settings section.

  Operator-facing UI for the V.4 server-position endpoints
  (commit 822b634):

    - GET   /api/v1/observability/server-position
    - PUT   /api/v1/observability/server-position
    - POST  /api/v1/observability/server-position:redetect

  Three actions surfaced as buttons:

    1. Enregistrer    — PUT with the form values; sets mode=manual.
    2. Re-détecter    — POST :redetect; re-runs V.1 ipify+GeoIP.
    3. Réinitialiser  — drop the form's edits, restore from the
                        last-known backend state. NO endpoint call.

  Validation per spec §5.2:

    - lat ∈ [-90, 90], lon ∈ [-180, 180] (inline form errors).
    - city + country: operator-supplied display strings, empty
      allowed — NO ISO 3166 enforcement (the V.4 backend confirms
      this; the operator might want "European Union" as a label).

  The degraded shape (spec §5.1) renders an inline banner
  pointing the operator at the ARENET_GEOIP_MMDB env var, the
  same actionable hint /map's V.5 banner carries.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { pushToast } from '$lib/stores/toast';
	import {
		fetchServerPosition,
		putServerPosition,
		redetectServerPosition
	} from '$lib/api/security';
	import { ApiError, type ServerPosition } from '$lib/api/types';
	import { relativeTime } from '$lib/utils/audit-format';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Input from '$lib/components/Input.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import UnsavedMarker from '$lib/components/settings/UnsavedMarker.svelte';

	interface Props {
		/** Out: the form differs from the last-known backend state. */
		dirty?: boolean;
	}

	let { dirty = $bindable(false) }: Props = $props();

	// Last-known backend state. Used both to populate the form
	// on mount and as the "reset to" reference. null while
	// loading; the load error path renders a separate banner.
	let position = $state<ServerPosition | null>(null);
	let loading = $state(true);
	let loadError = $state('');

	// Form state — strings so the <Input> binding works without
	// per-keystroke coercion. Parsed to numbers + validated at
	// submit time. Bound to text fields so the empty case ("")
	// can be distinguished from 0 (lat=0 is legal — Greenwich /
	// equator intersection).
	let latStr = $state('');
	let lonStr = $state('');
	let city = $state('');
	let country = $state('');

	// Per-field validation errors. Surfaced inline via the
	// <Input> component's `error` slot. Cleared on field
	// change so the operator sees their fix take effect.
	let latError = $state('');
	let lonError = $state('');

	// The form as resetForm last filled it. String() because the
	// number inputs hand back numbers once typed in.
	function formKey(): string {
		return JSON.stringify([latStr, lonStr, city, country].map((v) => String(v ?? '')));
	}
	let savedKey = $state(formKey());
	const isDirty = $derived(formKey() !== savedKey);
	$effect(() => {
		dirty = isDirty;
	});

	// Submit + redetect spinners. Disabled state on the
	// buttons prevents double-submits.
	let saving = $state(false);
	let redetecting = $state(false);

	async function loadPosition(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const p = await fetchServerPosition();
			position = p;
			resetForm();
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	}

	function resetForm(): void {
		if (!position) {
			latStr = '';
			lonStr = '';
			city = '';
			country = '';
		} else {
			// Trim trailing-zeros that toFixed leaves behind
			// (operator-friendly: "48.8566" not "48.85660000").
			latStr = position.degraded ? '' : trimNumber(position.lat);
			lonStr = position.degraded ? '' : trimNumber(position.lon);
			city = position.city;
			country = position.country;
		}
		latError = '';
		lonError = '';
		savedKey = formKey();
	}

	function trimNumber(n: number): string {
		// 6 decimal places ≈ 11 cm precision; more than enough
		// for the operator's mental map. parseFloat() then
		// String() strips trailing zeros automatically.
		return String(parseFloat(n.toFixed(6)));
	}

	function validate(): boolean {
		let ok = true;
		latError = '';
		lonError = '';

		// String(...) coerces both string and number values
		// (the <Input> binding to a type="number" input
		// yields a number in some test harnesses). The
		// trim() then runs uniformly.
		const latRaw = String(latStr ?? '').trim();
		const lat = Number(latRaw);
		if (latRaw === '' || Number.isNaN(lat)) {
			latError = t('serverPosition.errValueRequired');
			ok = false;
		} else if (lat < -90 || lat > 90) {
			latError = t('serverPosition.errLatRange');
			ok = false;
		}

		const lonRaw = String(lonStr ?? '').trim();
		const lon = Number(lonRaw);
		if (lonRaw === '' || Number.isNaN(lon)) {
			lonError = t('serverPosition.errValueRequired');
			ok = false;
		} else if (lon < -180 || lon > 180) {
			lonError = t('serverPosition.errLonRange');
			ok = false;
		}

		return ok;
	}

	async function submitSave(): Promise<void> {
		if (saving || redetecting) return;
		if (!validate()) return;
		saving = true;
		try {
			const saved = await putServerPosition({
				lat: Number(latStr),
				lon: Number(lonStr),
				city,
				country
			});
			position = saved;
			resetForm();
			pushToast(t('serverPosition.toastSaved'), 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(t('serverPosition.toastSaveFailed', { err: msg }), 'danger');
		} finally {
			saving = false;
		}
	}

	async function submitRedetect(): Promise<void> {
		if (saving || redetecting) return;
		redetecting = true;
		try {
			const detected = await redetectServerPosition();
			position = detected;
			resetForm();
			if (detected.degraded) {
				pushToast(
					t('serverPosition.toastDetectFailed'),
					'danger'
				);
			} else {
				pushToast(
					t('serverPosition.toastDetected', { city: detected.city || '—', country: detected.country || '—' }),
					'success'
				);
			}
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(t('serverPosition.toastDetectError', { err: msg }), 'danger');
		} finally {
			redetecting = false;
		}
	}

	function onLatInput(): void {
		latError = '';
	}
	function onLonInput(): void {
		lonError = '';
	}

	onMount(() => {
		void loadPosition();
	});
</script>

<div class="mb-6">
	<Card padding="p-6">
		<header
			class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4"
			data-testid="server-position-header"
		>
			<div>
				<h2 class="text-xl font-semibold">{language.current && t('serverPosition.title')}</h2>
				<UnsavedMarker dirty={isDirty} testid="server-position-unsaved" />
				<p class="text-xs text-muted mt-1">
					{language.current && t('serverPosition.subtitle')}
				</p>
			</div>
			{#if loading}
				<Spinner size="sm" />
			{:else if position}
				{#if position.degraded}
					<Badge variant="status-warn">{language.current && t('serverPosition.badgeDegraded')}</Badge>
				{:else if position.mode === 'manual'}
					<Badge variant="current">{language.current && t('serverPosition.badgeManual')}</Badge>
				{:else}
					<Badge variant="status-up">{language.current && t('serverPosition.badgeAuto')}</Badge>
				{/if}
			{/if}
		</header>

		{#if loadError}
			<p class="text-sm text-down mb-3" role="alert" data-testid="server-position-load-error">
				{language.current && t('serverPosition.loadErr', { err: loadError })}
			</p>
		{/if}

		{#if position && position.degraded}
			<div
				class="mb-4 rounded border border-warn/40 bg-warn/10 px-3 py-2 text-sm text-warn"
				role="status"
				data-testid="server-position-degraded"
			>
				<strong class="font-semibold">{language.current && t('serverPosition.degradedTitle')}</strong>
				{language.current && t('serverPosition.degradedBody')}
			</div>
		{/if}

		{#if position && !position.degraded && position.detectedAt}
			<p
				class="text-xs text-muted mb-4"
				data-testid="server-position-detected-at"
			>
				{language.current && t('serverPosition.detectedAtPrefix')} {relativeTime(position.detectedAt)}
				{#if position.mode === 'auto' && position.sourceIp}
					{language.current && t('serverPosition.detectedAtSourceIp')} <code>{position.sourceIp}</code>
				{/if}
			</p>
		{/if}

		<form
			class="grid grid-cols-1 md:grid-cols-2 gap-4"
			data-testid="server-position-form"
			onsubmit={(e) => {
				e.preventDefault();
				void submitSave();
			}}
		>
			<Input
				label={language.current && t('serverPosition.labelLatitude')}
				type="number"
				step="0.0001"
				min="-90"
				max="90"
				placeholder="48.8566"
				bind:value={latStr}
				error={latError}
				oninput={onLatInput}
				data-testid="server-position-lat-input"
			/>
			<Input
				label={language.current && t('serverPosition.labelLongitude')}
				type="number"
				step="0.0001"
				min="-180"
				max="180"
				placeholder="2.3522"
				bind:value={lonStr}
				error={lonError}
				oninput={onLonInput}
				data-testid="server-position-lon-input"
			/>
			<Input
				label={language.current && t('serverPosition.labelCity')}
				placeholder="Paris"
				bind:value={city}
				data-testid="server-position-city-input"
			/>
			<Input
				label={language.current && t('serverPosition.labelCountry')}
				placeholder="FR"
				bind:value={country}
				data-testid="server-position-country-input"
			/>

			<div class="md:col-span-2 flex flex-wrap items-center gap-2 pt-2">
				<Button
					type="submit"
					variant="primary"
					size="sm"
					loading={saving}
					disabled={loading || saving || redetecting}
				>
					{#snippet children()}
						{language.current && t('serverPosition.btnSave')}
					{/snippet}
				</Button>
				<Button
					type="button"
					variant="secondary"
					size="sm"
					loading={redetecting}
					disabled={loading || saving || redetecting}
					onclick={() => void submitRedetect()}
				>
					{#snippet children()}
						{language.current && t('serverPosition.btnRedetect')}
					{/snippet}
				</Button>
				<Button
					type="button"
					variant="ghost"
					size="sm"
					disabled={loading || saving || redetecting}
					onclick={resetForm}
				>
					{#snippet children()}
						{language.current && t('serverPosition.btnReset')}
					{/snippet}
				</Button>
			</div>
		</form>
	</Card>
</div>
