<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WafExcludeDialog (v2.36) — "Exclude…" on a WAF event. When the
  event names the triggering field (matchedVar, e.g. ARGS:content)
  it creates a targeted exclusion: the rule stops inspecting that
  field, by default only on the event's path. Without a field
  (older events, rules on the URL) it falls back to excluding the
  rule on the whole route, with a warning, a danger button and an
  explicit acknowledgement checkbox.

  Evidence: the event's matched value, source IP, field and request,
  plus the rule's hits on the route over 24h (GET /security/events/
  by-rule) and the distinct source IPs among the most recent of those
  hits (GET /security/events, route + category, newest 100) — "12
  hits from 1 IP" and "12 hits from 9 IPs" call for different
  decisions. The IP count is labelled as covering only the loaded
  sample when the sample is shorter than the hit count.

  Submit: POST /routes/{id}/waf-exclusions.
    200 → success toast, onSuccess(), close
    409 → "already exists" info toast, close
    other → inline error, dialog stays open
-->
<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { addWafExclusion } from '$lib/api/client';
	import { fetchEvents, fetchEventsByRule } from '$lib/api/security';
	import { ApiError, type AddWafExclusionRequest, type WafEvent } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		eventExclusionPath,
		isValidExclusionPath,
		parseWafTarget,
		summariseRuleEvidence,
		type RuleEvidence
	} from '$lib/utils/waf-exclusion';

	/** Window of the hit / source-IP counts (matches the by-rule window). */
	const EVIDENCE_WINDOW_MS = 24 * 60 * 60 * 1000;
	/** Recent events loaded to count source IPs (server cap). */
	const EVIDENCE_SAMPLE_LIMIT = 100;

	type Counts =
		| { state: 'loading' }
		| { state: 'unavailable' }
		| { state: 'ready'; evidence: RuleEvidence };

	interface Props {
		open: boolean;
		event: WafEvent | null;
		/** Friendly host of the event's route (falls back to the id). */
		host?: string;
		onClose: () => void;
		onSuccess?: () => void;
	}

	let { open, event, host = '', onClose, onSuccess }: Props = $props();

	let onlyThisPath = $state(true);
	let pathPrefix = $state(false);
	let path = $state('');
	let submitting = $state(false);
	let errorMsg = $state<string | null>(null);
	let wholeRouteAck = $state(false);
	let counts = $state<Counts>({ state: 'loading' });

	const target = $derived(parseWafTarget(event?.matchedVar));
	const eventPath = $derived(event ? eventExclusionPath(event.requestPath) : '');
	const hostLabel = $derived(host || event?.routeId || '');
	const pathInvalid = $derived(target !== null && onlyThisPath && !isValidExclusionPath(path.trim()));
	// The whole-route fallback is the broad, risky one: it needs the
	// operator's explicit acknowledgement before it can be submitted.
	const needsAck = $derived(target === null && !wholeRouteAck);
	const requestLine = $derived(
		event ? [event.requestMethod, event.requestPath].filter(Boolean).join(' ') : ''
	);

	function hitsLabel(n: number): string {
		return n === 1 ? t('wafExclude.countHitOne') : t('wafExclude.countHits', { count: n });
	}
	function ipsLabel(n: number): string {
		return n === 1 ? t('wafExclude.countIpOne') : t('wafExclude.countIps', { count: n });
	}

	const countsText = $derived.by(() => {
		const c = counts;
		if (!language.current) return '';
		if (c.state === 'loading') return t('wafExclude.evidenceCountsLoading');
		if (c.state === 'unavailable') return t('wafExclude.evidenceCountsUnavailable');
		const { hits, sampled, distinctIps } = c.evidence;
		if (hits === 0) return t('wafExclude.evidenceCountsNone');
		if (sampled === 0 || distinctIps === 0) {
			return t('wafExclude.evidenceCountsHitsOnly', { hits: hitsLabel(hits) });
		}
		if (sampled >= hits) {
			return t('wafExclude.evidenceCountsComplete', { hits: hitsLabel(hits), ips: ipsLabel(distinctIps) });
		}
		return t('wafExclude.evidenceCountsPartial', {
			hits: hitsLabel(hits),
			sampled,
			ips: ipsLabel(distinctIps)
		});
	});

	// Guards against a slow response landing after the dialog was
	// reopened on another event.
	let loadSeq = 0;
	async function loadCounts(ev: WafEvent): Promise<void> {
		const seq = ++loadSeq;
		counts = { state: 'loading' };
		if (!ev.routeId) {
			counts = { state: 'unavailable' };
			return;
		}
		try {
			const since = Date.now() - EVIDENCE_WINDOW_MS;
			const [byRule, recent] = await Promise.all([
				fetchEventsByRule({ route: ev.routeId, window: '24h' }),
				fetchEvents({ route: ev.routeId, category: ev.category, limit: EVIDENCE_SAMPLE_LIMIT })
			]);
			if (seq !== loadSeq) return;
			if (byRule.disabled) {
				counts = { state: 'unavailable' };
				return;
			}
			const hits = byRule.rows.filter((r) => r.ruleId === ev.ruleId).reduce((n, r) => n + r.count, 0);
			const events = recent.disabled ? [] : recent.events;
			counts = { state: 'ready', evidence: summariseRuleEvidence(ev.ruleId, hits, events, since) };
		} catch {
			if (seq === loadSeq) counts = { state: 'unavailable' };
		}
	}

	// Reset on every open so a previous event does not bleed in.
	let wasOpen = false;
	$effect(() => {
		if (open && !wasOpen) {
			path = eventPath;
			onlyThisPath = eventPath !== '';
			pathPrefix = false;
			errorMsg = null;
			submitting = false;
			wholeRouteAck = false;
			if (event) void loadCounts(event);
		}
		wasOpen = open;
	});

	async function submit(): Promise<void> {
		if (!event || pathInvalid || needsAck) return;
		const body: AddWafExclusionRequest = { ruleId: Number(event.ruleId) };
		if (target) {
			body.target = `${target.variable}:${target.key}`;
			if (onlyThisPath) {
				body.path = path.trim();
				if (pathPrefix) body.pathPrefix = true;
			}
		}
		submitting = true;
		errorMsg = null;
		try {
			await addWafExclusion(event.routeId, body);
			pushToast(t('wafExclude.toastAdded', { rule: event.ruleId, host: hostLabel }), 'success');
			onSuccess?.();
			onClose();
		} catch (err) {
			if (err instanceof ApiError && err.status === 409) {
				pushToast(t('wafExclude.toastExists'), 'info');
				onClose();
				return;
			}
			errorMsg = err instanceof Error && err.message ? err.message : t('wafExclude.errFailed');
		} finally {
			submitting = false;
		}
	}
</script>

<Modal
	{open}
	title={language.current && event ? t('wafExclude.title', { rule: event.ruleId }) : ''}
	onClose={() => {
		if (!submitting) onClose();
	}}
>
	{#snippet children()}
		{#if event}
			<div class="exclude-form" data-testid="waf-exclude-dialog">
				<section class="evidence" aria-labelledby="waf-exclude-evidence-title" data-testid="waf-exclude-evidence">
					<h3 id="waf-exclude-evidence-title" class="evidence-title">
						{language.current && t('wafExclude.evidenceTitle')}
					</h3>
					<dl>
						<dt>{language.current && t('wafExclude.evidencePayload')}</dt>
						<dd>
							{#if event.payloadSample}
								<code class="payload" data-testid="waf-exclude-evidence-payload">{event.payloadSample}</code>
							{:else}
								<span class="muted" data-testid="waf-exclude-evidence-payload">
									{language.current && t('wafExclude.evidenceNoPayload')}
								</span>
							{/if}
						</dd>
						<dt>{language.current && t('wafExclude.evidenceIp')}</dt>
						<dd class="mono" data-testid="waf-exclude-evidence-ip">{event.srcIp || '—'}</dd>
						<dt>{language.current && t('wafExclude.evidenceField')}</dt>
						<dd data-testid="waf-exclude-evidence-field">
							{#if event.matchedVar}
								<span class="mono">{event.matchedVar}</span>
							{:else}
								<span class="muted">{language.current && t('wafExclude.evidenceFieldUnknown')}</span>
							{/if}
						</dd>
						<dt>{language.current && t('wafExclude.evidenceRequest')}</dt>
						<dd class="mono request" data-testid="waf-exclude-evidence-request">{requestLine || '—'}</dd>
						<dt>{language.current && t('wafExclude.evidenceRecent')}</dt>
						<dd data-testid="waf-exclude-evidence-counts" aria-live="polite">{countsText}</dd>
					</dl>
				</section>
				{#if target}
					<p class="intro" data-testid="waf-exclude-intro">
						{language.current &&
							t('wafExclude.intro', {
								rule: event.ruleId,
								kind: t(`wafExclude.kind.${target.variable}`),
								name: target.key
							})}
					</p>
					{#if eventPath === ''}
						<p class="hint">{language.current && t('wafExclude.noEventPath')}</p>
					{/if}
					<label class="check">
						<input type="checkbox" bind:checked={onlyThisPath} data-testid="waf-exclude-only-path" />
						{language.current && t('wafExclude.onlyThisPath')}
					</label>
					{#if onlyThisPath}
						<div class="field">
							<label for="waf-exclude-path">{language.current && t('wafExclude.pathLabel')}</label>
							<input
								id="waf-exclude-path"
								type="text"
								autocomplete="off"
								class="mono"
								bind:value={path}
								aria-invalid={pathInvalid}
								data-testid="waf-exclude-path"
							/>
							{#if pathInvalid}
								<p class="error-text" role="alert">{language.current && t('wafExclude.pathInvalid')}</p>
							{/if}
						</div>
						<label class="check">
							<input type="checkbox" bind:checked={pathPrefix} data-testid="waf-exclude-prefix" />
							{language.current && t('wafExclude.andBelow')}
						</label>
					{/if}
				{:else}
					<div class="warn-block" role="note" data-testid="waf-exclude-whole-route">
						<strong>{language.current && t('wafExclude.wholeRouteTitle')}</strong>
						<p>
							{language.current && t('wafExclude.wholeRouteBody', { rule: event.ruleId, host: hostLabel })}
						</p>
						<label class="check ack">
							<input type="checkbox" bind:checked={wholeRouteAck} data-testid="waf-exclude-whole-route-ack" />
							{language.current && t('wafExclude.wholeRouteAck', { rule: event.ruleId })}
						</label>
					</div>
				{/if}
				<p class="hint">{language.current && t('wafExclude.detectHint')}</p>
				{#if errorMsg}
					<div class="error-block" role="alert" data-testid="waf-exclude-error">{errorMsg}</div>
				{/if}
			</div>
		{/if}
	{/snippet}

	{#snippet footer()}
		<Button variant="ghost" type="button" onclick={onClose} disabled={submitting}>
			{language.current && t('wafExclude.cancel')}
		</Button>
		<Button
			variant={target ? 'primary' : 'danger'}
			type="button"
			onclick={() => void submit()}
			disabled={submitting || pathInvalid || needsAck}
			loading={submitting}
			data-testid="waf-exclude-submit"
		>
			{language.current && t(target ? 'wafExclude.submit' : 'wafExclude.wholeRouteSubmit')}
		</Button>
	{/snippet}
</Modal>

<style>
	.exclude-form {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.intro {
		margin: 0;
		line-height: 1.5;
	}
	.evidence {
		padding: 0.6rem 0.75rem;
		border-radius: 4px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle, var(--bg-hover));
	}
	.evidence-title {
		margin: 0 0 0.4rem 0;
		font-size: var(--text-xs, 11px);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 500;
	}
	.evidence dl {
		display: grid;
		grid-template-columns: max-content minmax(0, 1fr);
		gap: 0.3rem 0.75rem;
		margin: 0;
	}
	.evidence dt {
		color: var(--text-muted);
	}
	.evidence dd {
		margin: 0;
		min-width: 0;
	}
	.payload {
		display: block;
		max-height: 6rem;
		overflow: auto;
		white-space: pre-wrap;
		word-break: break-all;
		font-family: var(--font-mono, monospace);
		color: var(--status-warn);
	}
	.request {
		word-break: break-all;
	}
	.muted {
		color: var(--text-muted);
	}
	.ack {
		margin-top: 0.5rem;
		align-items: flex-start;
		color: var(--text-primary);
	}
	.ack input {
		margin-top: 0.2rem;
	}
	.check {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--text-secondary);
		cursor: pointer;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		margin-left: 1.5rem;
	}
	.field label {
		font-size: var(--text-xs, 11px);
		color: var(--text-secondary);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		font-weight: 500;
	}
	.field input {
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.4rem 0.6rem;
		border-radius: 4px;
		font-size: var(--text-sm);
	}
	.field input:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.field + .check {
		margin-left: 1.5rem;
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.hint {
		margin: 0;
		font-size: var(--text-xs, 11px);
		color: var(--text-muted);
	}
	.error-text {
		margin: 0;
		font-size: var(--text-xs, 11px);
		color: var(--status-down);
	}
	.warn-block {
		padding: 0.6rem 0.75rem;
		border-radius: 4px;
		background: color-mix(in oklch, var(--status-warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 35%, transparent);
	}
	.warn-block p {
		margin: 0.35rem 0 0 0;
		color: var(--text-secondary);
	}
	.error-block {
		padding: 0.6rem 0.75rem;
		border-radius: 4px;
		border: 1px solid color-mix(in oklch, var(--status-down) 30%, transparent);
		color: var(--status-down);
	}
</style>
