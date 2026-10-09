<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step CS.3 Commit D — "Bannir une IP" modal.

  Admin-only manual ban form invoked from the Live LAPI sub-
  tab in CrowdSecDecisionsPanel, and from the "Ban…" action on
  /logs and WafEventList rows (initialValue = the row's source
  IP). Validates client-side
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
    409 crowdsec_self_ban → the value covers the operator's
          own client IP: explained inline; the override
          (confirmSelfBan) needs a ticked acknowledgement and
          a second, separate button
    other → generic inline error

  Range guard: a wide range (IPv4 /16 or wider, IPv6 /48 or
  wider) or one touching a private / loopback / link-local block
  takes a second click — the first submit only arms the
  confirmation for the exact value typed (lib/utils/ban-range).
-->
<script lang="ts">
	import { pushToast } from '$lib/stores/toast';
	import { createManualBan } from '$lib/api/security';
	import { ApiError, type ManualBanRequest } from '$lib/api/types';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import { classifyBanTarget } from '$lib/utils/ban-range';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		open: boolean;
		onClose: () => void;
		onSuccess?: () => void;
		/** Pre-fills the IP / CIDR field each time the modal opens
		 *  (ban from a log or WAF row). Still editable. */
		initialValue?: string;
	}

	let { open = $bindable(), onClose, onSuccess, initialValue = '' }: Props = $props();

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
	type SubmitErrorKind =
		| 'validation'
		| 'not_configured'
		| 'unreachable'
		| 'self_ban'
		| 'other'
		| null;
	let submitting = $state(false);
	let errorKind = $state<SubmitErrorKind>(null);
	let errorMsg = $state<string | null>(null);

	// Self-ban (409 crowdsec_self_ban): the value the refusal was
	// about, and the operator's explicit acknowledgement. The
	// override button only shows for that exact value and stays
	// disabled until the box is ticked.
	const SELF_BAN_CODE = 'crowdsec_self_ban';
	let selfBanFor = $state<string | null>(null);
	let selfBanAck = $state(false);

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
		value = initialValue;
		durationPreset = '24h';
		customDuration = '';
		banType = 'ban';
		reason = '';
		errorKind = null;
		errorMsg = null;
		submitting = false;
		rangeConfirmedFor = null;
		selfBanFor = null;
		selfBanAck = false;
	}

	// Effective duration sent to the backend. When the preset
	// dropdown is "custom", we use the custom field verbatim
	// (backend's validateManualBanDuration accepts Go duration
	// strings + the "Nd" suffix).
	const effectiveDuration = $derived(
		durationPreset === 'custom' ? customDuration.trim() : durationPreset
	);

	// Range risk, computed live as the operator types: the wide-
	// range INFO line shows as soon as the CIDR parses; on submit,
	// a wide or private / loopback / link-local target arms a
	// confirmation instead of sending. The confirmation is tied to
	// the exact value — editing it disarms the guard again.
	const maskWarn = $derived(classifyBanTarget(value));
	const needsRangeConfirm = $derived(maskWarn.wide || maskWarn.sensitiveBlock !== null);
	let rangeConfirmedFor = $state<string | null>(null);
	const rangeConfirmArmed = $derived(needsRangeConfirm && rangeConfirmedFor === value.trim());

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

	async function submit(opts: { confirmSelfBan?: boolean } = {}): Promise<void> {
		errorKind = null;
		errorMsg = null;
		const clientErr = validateClientSide();
		if (clientErr !== null) {
			errorKind = 'validation';
			errorMsg = clientErr;
			return;
		}
		if (needsRangeConfirm && rangeConfirmedFor !== value.trim()) {
			// First click on a risky range: show what it covers
			// and wait for a second, deliberate click.
			rangeConfirmedFor = value.trim();
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
			if (opts.confirmSelfBan === true) req.confirmSelfBan = true;
			const resp = await createManualBan(req);
			pushToast(t('banIp.toastBanned', { value: resp.value, scope: resp.scope }), 'success');
			onSuccess?.();
			// Close the modal AFTER onSuccess so the parent's
			// loadLive() fires before the visual transition.
			onClose();
		} catch (err) {
			if (err instanceof ApiError && err.status === 409 && err.code === SELF_BAN_CODE) {
				errorKind = 'self_ban';
				errorMsg = serverErrorMessage(err);
				selfBanFor = value.trim();
				selfBanAck = false;
			} else if (err instanceof ApiError) {
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

			{#if rangeConfirmArmed}
				<div class="error-block warn-block" role="alert" data-testid="ban-confirm-range">
					{#if maskWarn.wide}
						<p>{language.current && t('banIp.confirmWideRange', { value: value.trim(), count: maskWarn.approxIPs })}</p>
					{/if}
					{#if maskWarn.sensitiveBlock !== null}
						<p>{language.current && t('banIp.confirmSensitiveRange', { value: value.trim(), block: maskWarn.sensitiveBlock ?? '' })}</p>
					{/if}
					<p>{language.current && t('banIp.confirmRangeHint', { btn: t('banIp.btnConfirmBan') })}</p>
				</div>
			{/if}

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
			{:else if errorKind === 'self_ban'}
				<!-- Shown only while the value is the one refused:
				     the override must never carry over to an edit. -->
				{#if selfBanFor === value.trim()}
					<div class="error-block error" role="alert" data-testid="ban-self-ban">
						<strong>{language.current && t('banIp.selfBanTitle')}</strong>
						{errorMsg}
						<label class="ack">
							<input type="checkbox" bind:checked={selfBanAck} data-testid="ban-self-ban-ack" />
							{language.current && t('banIp.selfBanAck')}
						</label>
						<Button
							variant="danger"
							size="sm"
							type="button"
							onclick={() => void submit({ confirmSelfBan: true })}
							disabled={!selfBanAck || submitting}
							data-testid="ban-self-ban-confirm"
						>
							{language.current && t('banIp.btnBanAnyway')}
						</Button>
					</div>
				{/if}
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
			{language.current &&
				(submitting
					? t('banIp.btnSubmitting')
					: rangeConfirmArmed
						? t('banIp.btnConfirmBan')
						: t('banIp.btnSubmit'))}
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
		color: var(--status-warn);
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
	.error-block.warn-block {
		background: color-mix(in oklch, var(--status-warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 40%, transparent);
		color: var(--text-primary);
	}
	.error-block p {
		margin: 0 0 0.35rem 0;
	}
	.error-block p:last-child {
		margin-bottom: 0;
	}
	.ack {
		display: flex;
		gap: 0.4rem;
		align-items: flex-start;
		margin: 0.5rem 0;
		color: var(--text-primary);
		font-size: var(--text-xs, 11px);
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
