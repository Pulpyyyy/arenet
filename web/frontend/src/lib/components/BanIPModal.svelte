<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step CS.3 Commit D — "Bannir une IP" modal.

  Admin-only manual ban form invoked from the Live LAPI sub-
  tab in CrowdSecDecisionsPanel. Validates client-side
  (friendly errors before the network) but the backend
  remains the authoritative validator — the same rules live
  in internal/api/crowdsec_manual_ban.go and the same wire
  format ("manual:<username>|<reason>" via Decision.scenario)
  ships from there.

  Submit flow:
    201 → close modal + green toast + onSuccess() callback
          (parent calls loadLive() to refresh the table
          without waiting for the 30s polling tick)
    400 → inline form error, dialog stays open
    412 → "Security Automation not configured" CTA linking
          to /settings, dialog stays open
    502 → inline error banner with Réessayer button, dialog
          stays open (preserves operator input)
    other → generic inline error
-->
<script lang="ts">
	import { pushToast } from '$lib/stores/toast';
	import { createManualBan } from '$lib/api/security';
	import { ApiError, type ManualBanRequest } from '$lib/api/types';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		open: boolean;
		onClose: () => void;
		onSuccess?: () => void;
	}

	let { open = $bindable(), onClose, onSuccess }: Props = $props();

	// Form state. Defaults match the brief's dropdowns.
	type BanType = 'ban' | 'captcha' | 'throttle';
	type DurationPreset = '1h' | '4h' | '24h' | '7d' | '30d' | 'custom';

	let value = $state('');
	let durationPreset = $state<DurationPreset>('24h');
	let customDuration = $state('');
	let banType = $state<BanType>('ban');
	let reason = $state('');

	// Submit + error state. errorKind disambiguates the inline
	// surface (validation vs 412 vs 502 vs generic) so each
	// surfaces with the right wording / CTAs.
	type SubmitErrorKind = 'validation' | 'not_configured' | 'unreachable' | 'other' | null;
	let submitting = $state(false);
	let errorKind = $state<SubmitErrorKind>(null);
	let errorMsg = $state<string | null>(null);

	// Form-reset on modal open. The parent toggles `open`; an
	// $effect catches the false → true transition and zeroes
	// the form so a previous attempt doesn't bleed into the
	// next session. Closing-then-reopening is the operator's
	// natural "undo" affordance.
	let wasOpen = false;
	$effect(() => {
		if (open && !wasOpen) {
			resetForm();
		}
		wasOpen = open;
	});

	function resetForm(): void {
		value = '';
		durationPreset = '24h';
		customDuration = '';
		banType = 'ban';
		reason = '';
		errorKind = null;
		errorMsg = null;
		submitting = false;
	}

	// Effective duration sent to the backend. When the preset
	// dropdown is "custom", we use the custom field verbatim
	// (backend's validateManualBanDuration accepts Go duration
	// strings + the "Nd" suffix).
	const effectiveDuration = $derived(
		durationPreset === 'custom' ? customDuration.trim() : durationPreset
	);

	// Mask-warning state. Per the brief: inline INFO (not
	// blocking) when the operator is about to ban a wide
	// range (≥ /16 v4 or ≥ /48 v6). Computed live as the
	// operator types so the warning appears as soon as the
	// CIDR is syntactically valid.
	type MaskWarn = { wide: boolean; approxIPs: string };
	function classifyMask(raw: string): MaskWarn {
		const trimmed = raw.trim();
		const slash = trimmed.lastIndexOf('/');
		if (slash <= 0) return { wide: false, approxIPs: '' };
		const maskStr = trimmed.slice(slash + 1);
		const mask = Number(maskStr);
		if (!Number.isFinite(mask) || mask < 0) return { wide: false, approxIPs: '' };
		// v4 vs v6 inferred by colon presence in the IP part.
		const ipPart = trimmed.slice(0, slash);
		const isV6 = ipPart.includes(':');
		const totalBits = isV6 ? 128 : 32;
		if (mask > totalBits) return { wide: false, approxIPs: '' };
		const hostBits = totalBits - mask;
		// Wide threshold per the brief: v4 ≥ /16 = hostBits ≥ 16; v6 ≥ /48 = hostBits ≥ 80.
		const wide = (isV6 && mask <= 48) || (!isV6 && mask <= 16);
		if (!wide) return { wide: false, approxIPs: '' };
		// Format the rough magnitude. 2^hostBits fits easily in
		// Number for v4 (up to 2^32); for v6 we use the
		// exponent form (~10^N) which is friendlier than the
		// raw integer.
		const count = Math.pow(2, hostBits);
		let approxIPs: string;
		if (count >= 1e9) {
			const exp = Math.round(Math.log10(count));
			approxIPs = `≈ 10^${exp}`;
		} else if (count >= 1e6) {
			approxIPs = `≈ ${(count / 1e6).toFixed(1)} M`;
		} else if (count >= 1e3) {
			approxIPs = `≈ ${(count / 1e3).toFixed(1)} k`;
		} else {
			approxIPs = String(count);
		}
		return { wide: true, approxIPs };
	}
	const maskWarn = $derived(classifyMask(value));

	// Client-side validation. Mirrors the backend so the
	// operator gets feedback without paying a round-trip.
	// Returns an error string OR null on success.
	function validateClientSide(): string | null {
		if (value.trim() === '') return t('banIp.errValueRequired');
		if (effectiveDuration === '') return t('banIp.errDurationRequired');
		if (reason.trim() === '') return t('banIp.errReasonRequired');
		if (reason.trim().length > 256) {
			return t('banIp.errReasonTooLong', { count: reason.trim().length });
		}
		// Defer IP / duration syntax to the backend — keeping
		// the client-side checks light avoids two-validator
		// drift. The 400 response from the backend surfaces
		// precise error text in the inline area.
		return null;
	}

	async function submit(): Promise<void> {
		errorKind = null;
		errorMsg = null;
		const clientErr = validateClientSide();
		if (clientErr !== null) {
			errorKind = 'validation';
			errorMsg = clientErr;
			return;
		}
		submitting = true;
		try {
			const req: ManualBanRequest = {
				value: value.trim(),
				duration: effectiveDuration,
				type: banType,
				reason: reason.trim()
			};
			const resp = await createManualBan(req);
			pushToast(t('banIp.toastBanned', { value: resp.value, scope: resp.scope }), 'success');
			onSuccess?.();
			// Close the modal AFTER onSuccess so the parent's
			// loadLive() fires before the visual transition.
			onClose();
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 400) {
					errorKind = 'validation';
				} else if (err.status === 412) {
					errorKind = 'not_configured';
				} else if (err.status === 502) {
					errorKind = 'unreachable';
				} else {
					errorKind = 'other';
				}
				errorMsg = err.message;
			} else {
				errorKind = 'other';
				errorMsg = err instanceof Error ? err.message : t('banIp.errSubmitFailed');
			}
		} finally {
			submitting = false;
		}
	}

	function onCancel(): void {
		// Modal's own Esc + backdrop click both call onClose
		// already; this is the explicit Cancel button.
		onClose();
	}

	function onRetry(): void {
		void submit();
	}
</script>

<Modal {open} title={language.current && t('banIp.title')} onClose={() => {
	if (submitting) return;
	onClose();
}}>
	{#snippet children()}
		<form
			class="ban-form"
			onsubmit={(e) => {
				e.preventDefault();
				void submit();
			}}
		>
			<div class="field">
				<label for="ban-value">{language.current && t('banIp.labelValue')}</label>
				<input
					id="ban-value"
					type="text"
					autocomplete="off"
					placeholder={language.current && t('banIp.valuePlaceholder')}
					bind:value
					data-testid="ban-input-value"
					required
				/>
				{#if maskWarn.wide}
					<p class="warn" role="status" data-testid="ban-mask-warn">
						{language.current && t('banIp.maskWarn', { count: maskWarn.approxIPs })}
					</p>
				{/if}
			</div>

			<div class="row">
				<div class="field">
					<label for="ban-duration">{language.current && t('banIp.labelDuration')}</label>
					<select id="ban-duration" bind:value={durationPreset} data-testid="ban-input-duration">
						<option value="1h">{language.current && t('banIp.duration1h')}</option>
						<option value="4h">{language.current && t('banIp.duration4h')}</option>
						<option value="24h">{language.current && t('banIp.duration24h')}</option>
						<option value="7d">{language.current && t('banIp.duration7d')}</option>
						<option value="30d">{language.current && t('banIp.duration30d')}</option>
						<option value="custom">{language.current && t('banIp.durationCustom')}</option>
					</select>
					{#if durationPreset === 'custom'}
						<input
							class="custom-duration"
							type="text"
							placeholder={language.current && t('banIp.customDurationPlaceholder')}
							autocomplete="off"
							bind:value={customDuration}
							data-testid="ban-input-custom-duration"
						/>
					{/if}
				</div>

				<div class="field">
					<label for="ban-type">{language.current && t('banIp.labelAction')}</label>
					<select id="ban-type" bind:value={banType} data-testid="ban-input-type">
						<option value="ban">ban</option>
						<option value="captcha">captcha</option>
						<option value="throttle">throttle</option>
					</select>
				</div>
			</div>

			<div class="field">
				<label for="ban-reason">{language.current && t('banIp.labelReason')}</label>
				<input
					id="ban-reason"
					type="text"
					autocomplete="off"
					placeholder={language.current && t('banIp.reasonPlaceholder')}
					bind:value={reason}
					data-testid="ban-input-reason"
					required
				/>
				<p class="hint">
					{language.current && t('banIp.reasonHint', { count: reason.trim().length })}
				</p>
			</div>

			{#if errorKind === 'not_configured'}
				<div class="error-block cta" role="alert" data-testid="ban-not-configured">
					<strong>{language.current && t('banIp.notConfiguredTitle')}</strong>
					{language.current && t('banIp.notConfiguredBody')} <a href="/settings#security-automation" class="link">{language.current && t('banIp.notConfiguredLink')}</a>
					{language.current && t('banIp.notConfiguredSuffix', { cmd: 'cscli machines add arenet-writer' })}
				</div>
			{:else if errorKind === 'unreachable'}
				<div class="error-block error" role="alert" data-testid="ban-unreachable">
					<strong>{language.current && t('banIp.errLapiUnreachablePrefix')}</strong> {errorMsg ?? (language.current && t('banIp.errUnknownError'))}
					<button type="button" class="retry-btn" onclick={onRetry}>{language.current && t('banIp.btnRetry')}</button>
				</div>
			{:else if errorKind !== null && errorMsg !== null}
				<div class="error-block error" role="alert" data-testid="ban-error">
					{errorMsg}
				</div>
			{/if}
		</form>
	{/snippet}

	{#snippet footer()}
		<Button variant="ghost" type="button" onclick={onCancel} disabled={submitting}>
			{language.current && t('banIp.btnCancel')}
		</Button>
		<Button
			variant="danger"
			type="button"
			onclick={() => void submit()}
			disabled={submitting}
			data-testid="ban-submit"
		>
			{language.current && (submitting ? t('banIp.btnSubmitting') : t('banIp.btnSubmit'))}
		</Button>
	{/snippet}
</Modal>

<style>
	.ban-form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.row {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}
	.field label {
		font-size: var(--text-xs, 11px);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 500;
	}
	.field input,
	.field select {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		font-size: var(--text-sm);
		font-family: inherit;
	}
	.field input:focus-visible,
	.field select:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.custom-duration {
		margin-top: 0.25rem;
	}
	.hint {
		margin: 0;
		font-size: var(--text-xs, 11px);
		color: var(--text-muted);
		text-align: right;
	}
	.warn {
		margin: 0.25rem 0 0 0;
		font-size: var(--text-xs, 11px);
		color: var(--status-warn-fg);
	}
	.error-block {
		padding: 0.6rem 0.75rem;
		border-radius: 4px;
		font-size: var(--text-sm);
	}
	.error-block.error {
		background: rgba(255, 0, 0, 0.05);
		border: 1px solid color-mix(in oklch, var(--status-down) 30%, transparent);
		color: var(--status-down);
	}
	.error-block.cta {
		background: color-mix(in oklch, var(--accent-cyan) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--accent-cyan) 30%, transparent);
		color: var(--text-primary);
	}
	.retry-btn {
		display: inline-block;
		margin-top: 0.4rem;
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.2rem 0.6rem;
		border-radius: 4px;
		font-size: var(--text-xs, 11px);
		cursor: pointer;
	}
	.link {
		color: var(--accent-cyan);
		text-decoration: underline;
	}
</style>
