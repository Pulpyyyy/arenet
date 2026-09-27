<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.3 — Create / edit modal for alerting rules. Three
  dynamic sub-forms:
    1. SourceParams form, switched on the operator's Source
       choice (waf_event_rate / cert_expiry / system_health).
    2. EvalParams form, switched on the Kind choice
       (threshold / state).
    3. Channels multi-select (mandatory min 1, enforced
       client-side AND server-side via AL.3b's validator).

  Source picker is hardcoded V1 per brief D5 — the registry
  is static at boot and exposing it via an endpoint would be
  zero ergonomic gain.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import {
		alertingApi,
		SEVERITY_TOKENS,
		severityLabelFR,
		type AlertRule,
		type AlertRuleRequest,
		type AlertRuleTestResponse,
		type RuleKind
	} from '$lib/api/alerting';
	import { rulesStore, channelsStore } from '$lib/stores/alerting.svelte';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type { Route } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		open: boolean;
		rule: AlertRule | null;
		onClose: () => void;
		onSaved: () => void;
	}

	let { open, rule, onClose, onSaved }: Props = $props();

	const isEdit = $derived(rule !== null);

	// --- supported sources / kinds ----------------------------

	type SourceName =
		| 'waf_event_rate'
		| 'cert_expiry'
		| 'cert_renewal_failed'
		| 'system_health'
		| 'update_available'
		| 'cert_manual_expiring';
	const SOURCES = $derived(
		language.current
			? [
					{ value: 'waf_event_rate' as SourceName, label: t('alerting.ruleModal.sourceWafEventRate') },
					{ value: 'cert_expiry' as SourceName, label: t('alerting.ruleModal.sourceCertExpiry') },
					{ value: 'cert_renewal_failed' as SourceName, label: t('alerting.ruleModal.sourceCertRenewalFailed') },
					{ value: 'system_health' as SourceName, label: t('alerting.ruleModal.sourceSystemHealth') },
					{ value: 'update_available' as SourceName, label: t('alerting.ruleModal.sourceUpdateAvailable') },
					{ value: 'cert_manual_expiring' as SourceName, label: t('alerting.ruleModal.sourceCertManualExpiring') }
				]
			: [
					{ value: 'waf_event_rate' as SourceName, label: 'WAF event rate' },
					{ value: 'cert_expiry' as SourceName, label: 'Certificate expiry' },
					{ value: 'cert_renewal_failed' as SourceName, label: 'Certificate renewal failure' },
					{ value: 'system_health' as SourceName, label: 'System health' },
					{ value: 'update_available' as SourceName, label: 'Update available' },
					{ value: 'cert_manual_expiring' as SourceName, label: 'External cert expiring' }
				]
	);

	const HEALTH_COMPONENTS = $derived(
		language.current
			? [
					{ value: '', label: t('alerting.ruleModal.healthGlobal') },
					{ value: 'caddy', label: 'Caddy' },
					{ value: 'db', label: 'BoltDB' },
					{ value: 'metrics', label: 'Metrics' },
					{ value: 'crowdsec', label: 'CrowdSec' },
					{ value: 'certmagic', label: 'Certmagic' }
				]
			: [
					{ value: '', label: 'Global (all system health)' },
					{ value: 'caddy', label: 'Caddy' },
					{ value: 'db', label: 'BoltDB' },
					{ value: 'metrics', label: 'Metrics' },
					{ value: 'crowdsec', label: 'CrowdSec' },
					{ value: 'certmagic', label: 'Certmagic' }
				]
	);

	/**
	 * Maps a component name this editor used to offer onto the one the
	 * health report actually publishes.
	 *
	 * v2.54 — the list above once offered `boltdb` while the check is named
	 * `db`. The evaluator was taught to accept both in v2.52, so those
	 * rules fire again, but the editor was not: it binds the stored string
	 * to a <select> that has no option with that value, so reopening such a
	 * rule shows the wrong component. The rule works and its own editor
	 * misreports it — worth the three lines to keep the two in step.
	 *
	 * Mirrors legacyHealthComponentNames in
	 * internal/alerting/source_system_health.go.
	 */
	const LEGACY_HEALTH_COMPONENTS: Record<string, string> = { boltdb: 'db' };

	function canonicalHealthComponent(name: string): string {
		return LEGACY_HEALTH_COMPONENTS[name] ?? name;
	}

	const OPERATORS = ['>', '>=', '<', '<=', '==', '!='] as const;
	type Operator = (typeof OPERATORS)[number];

	// --- common form state ------------------------------------

	let name = $state('');
	let enabled = $state(true);
	let category = $state('');
	let severity = $state(1);
	let kind = $state<RuleKind>('threshold');
	let source = $state<SourceName>('waf_event_rate');

	// update_available is a state-only source (it emits "available" /
	// "up_to_date", never a number). Selecting it forces a state rule
	// and defaults the expected value to "available" so the operator
	// can't accidentally build a meaningless threshold rule. Only runs
	// on create (kind is locked after create — see isEdit).
	$effect(() => {
		if (!isEdit && source === 'update_available') {
			kind = 'state';
			if (stateExpected !== 'available') stateExpected = 'available';
		}
	});
	let channelIds = $state<string[]>([]);
	let cooldownSecs = $state(300);
	let subjectTemplate = $state('');
	let bodyTemplate = $state('');

	// --- source-specific fields -------------------------------

	// waf_event_rate
	let wafRouteId = $state('');
	let wafWindowSecs = $state(300);
	let wafAction = $state<'' | 'BLOCK' | 'DETECT'>('');

	// cert_expiry
	let certHost = $state('');
	// The seuil-en-jours number is stored on the rule's
	// EvalParams (threshold), not on SourceParams. We surface
	// it inline in the SourceParams form for UX convenience
	// when kind=threshold + source=cert_expiry; on submit we
	// route it into EvalParams.value with operator "<".
	// When kind=state or source != cert_expiry this state is
	// ignored.

	// cert_renewal_failed
	let certRenewalDomain = $state('');
	let certRenewalWindowSecs = $state(86400);
	// v2.52 — cert_manual_expiring had no form at all, so this never left
	// the backend default of 30. See the payload builder.
	let certManualThresholdDays = $state(30);

	// system_health
	let healthComponent = $state('');

	// --- eval-specific fields ---------------------------------

	// threshold
	let thresholdOp = $state<Operator>('>');
	let thresholdValue = $state(50);

	// state
	let stateExpected = $state('degraded');

	// --- async deps -------------------------------------------

	let routes = $state<Route[]>([]);
	let routesLoaded = $state(false);

	const availableChannels = $derived(
		channelsStore.state.channels.filter((c) => c.enabled)
	);

	let submitting = $state(false);
	let testing = $state(false);
	let validationError = $state('');
	let testResultLine = $state(''); // inline result of "Tester la règle"

	onMount(() => {
		// Load both lookups in parallel; failures are non-fatal.
		void channelsStore.load();
		void listRoutes()
			.then((rs) => {
				routes = rs;
				routesLoaded = true;
			})
			.catch(() => {
				routesLoaded = true;
			});
	});

	// Reset / pre-populate when the modal opens or the
	// target rule changes.
	$effect(() => {
		if (!open) return;
		validationError = '';
		testResultLine = '';
		if (rule) {
			name = rule.name;
			enabled = rule.enabled;
			category = rule.category;
			severity = rule.severity;
			kind = rule.kind;
			source = (rule.source as SourceName) ?? 'waf_event_rate';
			channelIds = [...rule.channels];
			cooldownSecs = rule.cooldownSecs;
			subjectTemplate = rule.subjectTemplate ?? '';
			bodyTemplate = rule.bodyTemplate ?? '';

			// Decode source-specific params.
			const sp = (rule.sourceParams ?? {}) as Record<string, unknown>;
			if (source === 'waf_event_rate') {
				wafRouteId = typeof sp.routeId === 'string' ? sp.routeId : '';
				wafWindowSecs = typeof sp.windowSecs === 'number' ? sp.windowSecs : 300;
				wafAction = (sp.action as '' | 'BLOCK' | 'DETECT') ?? '';
			} else if (source === 'cert_expiry') {
				certHost = typeof sp.host === 'string' ? sp.host : '';
			} else if (source === 'cert_renewal_failed') {
				certRenewalDomain = typeof sp.domain === 'string' ? sp.domain : '';
				certRenewalWindowSecs =
					typeof sp.windowSecs === 'number' ? sp.windowSecs : 86400;
			} else if (source === 'system_health') {
				healthComponent =
					typeof sp.component === 'string' ? canonicalHealthComponent(sp.component) : '';
			} else if (source === 'cert_manual_expiring') {
				certManualThresholdDays =
					typeof sp.thresholdDays === 'number' ? sp.thresholdDays : 30;
			}

			// Decode eval-specific params.
			const ep = (rule.evalParams ?? {}) as Record<string, unknown>;
			if (kind === 'threshold') {
				thresholdOp = (ep.operator as Operator) ?? '>';
				thresholdValue = typeof ep.value === 'number' ? ep.value : 50;
			} else if (kind === 'state') {
				stateExpected = typeof ep.expected === 'string' ? ep.expected : 'degraded';
			}
		} else {
			// Create defaults.
			name = '';
			enabled = true;
			category = '';
			severity = 1;
			kind = 'threshold';
			source = 'waf_event_rate';
			channelIds = [];
			cooldownSecs = 300;
			subjectTemplate = '';
			bodyTemplate = '';
			wafRouteId = '';
			wafWindowSecs = 300;
			wafAction = '';
			certHost = '';
			certRenewalDomain = '';
			certRenewalWindowSecs = 86400;
			certManualThresholdDays = 30;
			healthComponent = '';
			thresholdOp = '>';
			thresholdValue = 50;
			stateExpected = 'degraded';
		}
	});

	// --- channel toggle ---------------------------------------

	function toggleChannel(id: string, on: boolean) {
		if (on) {
			if (!channelIds.includes(id)) {
				channelIds = [...channelIds, id];
			}
		} else {
			channelIds = channelIds.filter((cid) => cid !== id);
		}
	}

	function isChannelSelected(id: string): boolean {
		return channelIds.includes(id);
	}

	// --- formatting helpers -----------------------------------

	function cooldownFormatted(secs: number): string {
		void language.current;
		if (secs < 60) return t('alerting.ruleModal.fmtSecondsShort', { n: secs });
		if (secs < 3600) {
			const m = Math.floor(secs / 60);
			const s = secs % 60;
			if (s !== 0) return t('alerting.ruleModal.fmtMinSecs', { m, s });
			return m > 1 ? t('alerting.ruleModal.fmtMinutesPlural', { n: m }) : t('alerting.ruleModal.fmtMinuteSingular', { n: m });
		}
		const h = Math.floor(secs / 3600);
		const m = Math.floor((secs % 3600) / 60);
		if (m !== 0) return t('alerting.ruleModal.fmtHourMin', { h, m });
		return h > 1 ? t('alerting.ruleModal.fmtHoursPlural', { n: h }) : t('alerting.ruleModal.fmtHourSingular', { n: h });
	}

	// --- build request from form state ------------------------

	function buildSourceParams(): Record<string, unknown> {
		switch (source) {
			case 'waf_event_rate': {
				const p: Record<string, unknown> = { windowSecs: wafWindowSecs };
				if (wafRouteId) p.routeId = wafRouteId;
				if (wafAction) p.action = wafAction;
				return p;
			}
			case 'cert_expiry': {
				const p: Record<string, unknown> = {};
				if (certHost.trim()) p.host = certHost.trim();
				return p;
			}
			case 'cert_renewal_failed': {
				const p: Record<string, unknown> = { windowSecs: certRenewalWindowSecs };
				if (certRenewalDomain.trim()) p.domain = certRenewalDomain.trim();
				return p;
			}
			case 'system_health': {
				const p: Record<string, unknown> = {};
				if (healthComponent) p.component = healthComponent;
				return p;
			}
			case 'update_available': {
				// State source, no per-source params (the checker's
				// status drives it). The rule fires when the state
				// equals the expected value (default "available").
				return {};
			}
			case 'cert_manual_expiring': {
				// v2.52 — thresholdDays IS a source param, and it is sent.
				//
				// The comment here used to claim it travelled in the
				// threshold eval params. It does not: the eval `value` is
				// compared against the COUNT of matching certificates, so
				// thresholdDays never reached the source and every rule
				// silently used the backend default of 30 days.
				//
				// Reading the resulting rule: "how many manually uploaded
				// certificates expire within thresholdDays", compared
				// against your threshold — so `> 0` means "at least one".
				return { thresholdDays: certManualThresholdDays };
			}
		}
	}

	function buildEvalParams(): Record<string, unknown> {
		if (kind === 'threshold') {
			return { operator: thresholdOp, value: thresholdValue };
		}
		return { expected: stateExpected };
	}

	function buildRequest(): AlertRuleRequest | null {
		if (!name.trim()) {
			validationError = t('alerting.ruleModal.errNameRequired');
			return null;
		}
		if (!/^[a-z0-9-]{1,64}$/.test(name.trim())) {
			validationError = t('alerting.ruleModal.errNameSlug');
			return null;
		}
		if (cooldownSecs < 30 || cooldownSecs > 86400) {
			validationError = t('alerting.ruleModal.errCooldownRange');
			return null;
		}
		if (channelIds.length === 0) {
			validationError = t('alerting.ruleModal.errAtLeastOneChannel');
			return null;
		}
		if (kind === 'threshold') {
			if (!OPERATORS.includes(thresholdOp)) {
				validationError = t('alerting.ruleModal.errOperatorUnsupported', { op: thresholdOp });
				return null;
			}
			if (!Number.isFinite(thresholdValue)) {
				validationError = t('alerting.ruleModal.errThresholdNumeric');
				return null;
			}
		} else if (kind === 'state') {
			if (!stateExpected.trim()) {
				validationError = t('alerting.ruleModal.errExpectedEmpty');
				return null;
			}
		}
		if (source === 'waf_event_rate') {
			if (wafWindowSecs < 60 || wafWindowSecs > 86400) {
				validationError = t('alerting.ruleModal.errWafWindowRange');
				return null;
			}
		}
		if (source === 'cert_renewal_failed') {
			// Mirror backend cert_renewal_failed bounds
			// (source_cert_renewal_failed.go [60s, 7d]).
			if (certRenewalWindowSecs < 60 || certRenewalWindowSecs > 604800) {
				validationError = t('alerting.ruleModal.errCertRenewalWindowRange');
				return null;
			}
		}

		return {
			name: name.trim(),
			enabled,
			kind,
			severity,
			category: category.trim(),
			source,
			sourceParams: buildSourceParams(),
			evalParams: buildEvalParams(),
			channels: channelIds,
			cooldownSecs,
			subjectTemplate: subjectTemplate.trim() || undefined,
			bodyTemplate: bodyTemplate.trim() || undefined
		};
	}

	async function onSubmit(e: SubmitEvent) {
		e.preventDefault();
		validationError = '';
		const req = buildRequest();
		if (!req) return;
		submitting = true;
		try {
			if (rule) {
				await rulesStore.update(rule.id, req);
				pushToast(t('alerting.ruleModal.toastSaved', { name: req.name }), 'success');
			} else {
				await rulesStore.create(req);
				pushToast(t('alerting.ruleModal.toastCreated', { name: req.name }), 'success');
			}
			onSaved();
		} catch (err) {
			validationError = err instanceof ApiError ? err.message : t('alerting.networkError');
		} finally {
			submitting = false;
		}
	}

	function summariseTest(res: AlertRuleTestResponse): string {
		if (res.sent) {
			return t('alerting.ruleModal.summaryTestOk', { count: res.channelsFired.length });
		}
		const lines: string[] = [];
		lines.push(t('alerting.ruleModal.summaryTestSentLine', { count: res.channelsFired.length }));
		if (res.errors && Object.keys(res.errors).length > 0) {
			lines.push(t('alerting.ruleModal.summaryTestErrorsLine', { count: Object.keys(res.errors).length }));
		}
		if (res.skipped && Object.keys(res.skipped).length > 0) {
			lines.push(t('alerting.ruleModal.summaryTestSkippedLine', { count: Object.keys(res.skipped).length }));
		}
		return lines.join(' · ');
	}

	async function onTest() {
		if (!rule) return;
		testing = true;
		testResultLine = '';
		try {
			const res = await alertingApi.testRule(rule.id);
			testResultLine = summariseTest(res);
			pushToast(t('alerting.ruleModal.toastRuleResult', { name: rule.name, line: testResultLine }), res.sent ? 'success' : 'info');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			testResultLine = msg;
			pushToast(t('alerting.ruleModal.toastRuleErr', { name: rule.name, err: msg }), 'danger');
		} finally {
			testing = false;
		}
	}
</script>

<Modal {open} title={language.current && (isEdit ? t('alerting.ruleModal.titleEdit') : t('alerting.ruleModal.titleCreate'))} {onClose} width="lg">
	<form onsubmit={onSubmit} class="space-y-4">
		<!-- Common: identity + severity -->
		<Input bind:value={name} label={language.current && t('alerting.ruleModal.labelName')} placeholder={t('alerting.ruleModal.placeholderName')} required />

		<div class="flex items-center gap-4">
			<Checkbox bind:checked={enabled} label={language.current && t('alerting.ruleModal.labelEnabled')} />
		</div>

		<div class="grid grid-cols-2 gap-4">
			<Input bind:value={category} label={language.current && t('alerting.ruleModal.labelCategory')} placeholder={t('alerting.ruleModal.placeholderCategory')} />
			<div>
				<label for="rule-severity" class="text-sm font-medium text-secondary mb-1.5 block">
					{language.current && t('alerting.ruleModal.labelSeverity')}
				</label>
				<select
					id="rule-severity"
					bind:value={severity}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				>
					{#each SEVERITY_TOKENS as _tok, i (i)}
						<option value={i}>{severityLabelFR(i)}</option>
					{/each}
				</select>
			</div>
		</div>

		<hr class="border-border-subtle" />

		<!-- Source picker + dynamic per-source form -->
		<div>
			<label for="rule-source" class="text-sm font-medium text-secondary mb-1.5 block">
				{language.current && t('alerting.ruleModal.labelSource')}
			</label>
			<select
				id="rule-source"
				bind:value={source}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				{#each SOURCES as s (s.value)}
					<option value={s.value}>{s.label}</option>
				{/each}
			</select>
		</div>

		{#if source === 'waf_event_rate'}
			<div class="grid grid-cols-3 gap-4">
				<div>
					<label for="waf-route" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.ruleModal.labelRoute')}
					</label>
					<select
						id="waf-route"
						bind:value={wafRouteId}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="">{language.current && t('alerting.ruleModal.routeAll')}</option>
						{#each routes as r (r.id)}
							<option value={r.id}>{r.host}</option>
						{/each}
					</select>
				</div>
				<div>
					<label
						for="waf-window"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelWindowSecs')}
					</label>
					<input
						id="waf-window"
						type="number"
						bind:value={wafWindowSecs}
						min="60"
						max="86400"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
				<div>
					<label
						for="waf-action"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelAction')}
					</label>
					<select
						id="waf-action"
						bind:value={wafAction}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="">{language.current && t('alerting.ruleModal.actionAll')}</option>
						<option value="BLOCK">BLOCK</option>
						<option value="DETECT">DETECT</option>
					</select>
				</div>
			</div>
		{:else if source === 'cert_expiry'}
			<Input
				bind:value={certHost}
				label={language.current && t('alerting.ruleModal.labelHostOptional')}
				placeholder={t('alerting.ruleModal.placeholderHostOptional')}
			/>
			<p class="text-xs text-secondary -mt-2">
				{language.current && t('alerting.ruleModal.certExpiryHelper')}
			</p>
		{:else if source === 'cert_renewal_failed'}
			<div class="grid grid-cols-2 gap-4">
				<Input
					bind:value={certRenewalDomain}
					label={language.current && t('alerting.ruleModal.labelDomainOptional')}
					placeholder={t('alerting.ruleModal.placeholderDomainOptional')}
				/>
				<div>
					<label
						for="cert-renewal-window"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelRenewalWindow')}
					</label>
					<input
						id="cert-renewal-window"
						type="number"
						bind:value={certRenewalWindowSecs}
						min="60"
						max="604800"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
			</div>
			<p class="text-xs text-secondary -mt-2">
				{language.current && t('alerting.ruleModal.certRenewalHelper')}
			</p>
		{:else if source === 'system_health'}
			<div>
				<label
					for="health-component"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.ruleModal.labelComponent')}
				</label>
				<select
					id="health-component"
					bind:value={healthComponent}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				>
					{#each HEALTH_COMPONENTS as c (c.value)}
						<option value={c.value}>{c.label}</option>
					{/each}
				</select>
			</div>
		{:else if source === 'cert_manual_expiring'}
			<!-- v2.52 — this source had no form branch at all, so its
			     threshold was stuck on the backend default of 30 days and
			     an operator could not change it. -->
			<div>
				<label
					for="cert-manual-days"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.ruleModal.labelManualCertDays')}
				</label>
				<input
					id="cert-manual-days"
					type="number"
					min="1"
					max="365"
					bind:value={certManualThresholdDays}
					data-testid="cert-manual-days"
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('alerting.ruleModal.hintManualCertDays')}
				</p>
			</div>
		{/if}

		<hr class="border-border-subtle" />

		<!-- Kind picker + dynamic per-kind eval form -->
		<fieldset>
			<legend class="text-sm font-medium text-secondary mb-1.5">{language.current && t('alerting.ruleModal.ruleTypeLegend')}</legend>
			<div class="flex gap-4">
				<label class="flex items-center gap-2 text-sm" class:opacity-50={isEdit}>
					<input
						type="radio"
						bind:group={kind}
						value="threshold"
						disabled={isEdit}
					/>
					{language.current && t('alerting.ruleModal.kindThresholdRadio')}
				</label>
				<label class="flex items-center gap-2 text-sm" class:opacity-50={isEdit}>
					<input
						type="radio"
						bind:group={kind}
						value="state"
						disabled={isEdit}
					/>
					{language.current && t('alerting.ruleModal.kindStateRadio')}
				</label>
			</div>
			{#if isEdit}
				<p class="text-xs text-secondary mt-1">
					{language.current && t('alerting.ruleModal.kindLockedAfterCreate')}
				</p>
			{/if}
		</fieldset>

		{#if kind === 'threshold'}
			<div class="grid grid-cols-2 gap-4">
				<div>
					<label
						for="threshold-op"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelOperator')}
					</label>
					<select
						id="threshold-op"
						bind:value={thresholdOp}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						{#each OPERATORS as op (op)}
							<option value={op}>{op}</option>
						{/each}
					</select>
				</div>
				<div>
					<label
						for="threshold-value"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelThresholdValue')}
					</label>
					<input
						id="threshold-value"
						type="number"
						bind:value={thresholdValue}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
			</div>
		{:else}
			<Input
				bind:value={stateExpected}
				label={language.current && t('alerting.ruleModal.labelExpectedValue')}
				placeholder={t('alerting.ruleModal.placeholderExpectedValue')}
				required
			/>
		{/if}

		<hr class="border-border-subtle" />

		<!-- Channels multi-select -->
		<div>
			<span class="text-sm font-medium text-secondary mb-1.5 block">
				{language.current && t('alerting.ruleModal.channelsLabel', { count: channelIds.length })}
			</span>
			{#if channelsStore.state.loading && availableChannels.length === 0}
				<p class="text-xs text-secondary">{language.current && t('alerting.ruleModal.channelsLoading')}</p>
			{:else if availableChannels.length === 0}
				<p class="text-xs text-secondary">
					{language.current && t('alerting.ruleModal.channelsEmpty')}
				</p>
			{:else}
				<div class="space-y-1 max-h-40 overflow-y-auto border border-border-subtle rounded p-2">
					{#each availableChannels as c (c.id)}
						<label class="flex items-center gap-2 text-sm py-1">
							<input
								type="checkbox"
								checked={isChannelSelected(c.id)}
								onchange={(e) => toggleChannel(c.id, (e.target as HTMLInputElement).checked)}
							/>
							<span class="text-primary">{c.name}</span>
							<span class="text-xs text-secondary">({c.kind})</span>
						</label>
					{/each}
				</div>
			{/if}
		</div>

		<!-- Cooldown -->
		<div>
			<label for="rule-cooldown" class="text-sm font-medium text-secondary mb-1.5 block">
				{language.current && t('alerting.ruleModal.labelCooldownSecs')}
			</label>
			<input
				id="rule-cooldown"
				type="number"
				bind:value={cooldownSecs}
				min="30"
				max="86400"
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			/>
			<p class="text-xs text-secondary mt-1">{language.current && t('alerting.ruleModal.cooldownApprox', { formatted: cooldownFormatted(cooldownSecs) })}</p>
		</div>

		<!-- Templates -->
		<details>
			<summary class="text-sm text-secondary cursor-pointer">
				{language.current && t('alerting.ruleModal.templatesSection')}
			</summary>
			<div class="mt-3 space-y-3 pl-2 border-l border-border-subtle">
				<div>
					<label
						for="rule-subject-tmpl"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelSubjectTemplate')}
					</label>
					<input
						id="rule-subject-tmpl"
						bind:value={subjectTemplate}
						placeholder={`[{{.Severity}}] {{.RuleName}}`}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>
				<div>
					<label
						for="rule-body-tmpl"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.ruleModal.labelBodyTemplate')}
					</label>
					<textarea
						id="rule-body-tmpl"
						bind:value={bodyTemplate}
						rows="3"
						placeholder={`Source {{.Source}} fired at {{.Value}}`}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					></textarea>
				</div>
				<p class="text-xs text-secondary">
					{language.current && t('alerting.ruleModal.templatesPlaceholdersAvailable')} <code>{`{{.RuleName}}`}</code>,
					<code>{`{{.Severity}}`}</code>, <code>{`{{.Source}}`}</code>,
					<code>{`{{.Value}}`}</code>, <code>{`{{.Subject}}`}</code>.
				</p>
			</div>
		</details>

		{#if testResultLine}
			<div class="p-3 rounded bg-elevated border border-border-default text-sm text-primary">
				{language.current && t('alerting.ruleModal.testResultLine', { line: testResultLine })}
			</div>
		{/if}

		{#if validationError}
			<div class="p-3 rounded bg-down/10 border border-down text-down text-sm" role="alert">
				{validationError}
			</div>
		{/if}
	</form>

	{#snippet footer()}
		{#if isEdit}
			<Button
				variant="secondary"
				onclick={onTest}
				disabled={testing || submitting}
				loading={testing}
			>
				{#snippet children()}{language.current && t('alerting.ruleModal.btnTest')}{/snippet}
			</Button>
		{/if}
		<Button variant="ghost" onclick={onClose} disabled={submitting}>
			{#snippet children()}{language.current && t('alerting.ruleModal.btnCancel')}{/snippet}
		</Button>
		<Button
			variant="primary"
			onclick={(e) => onSubmit(e as unknown as SubmitEvent)}
			disabled={submitting}
			loading={submitting}
		>
			{#snippet children()}{language.current && (isEdit ? t('alerting.ruleModal.btnSave') : t('alerting.ruleModal.btnCreate'))}{/snippet}
		</Button>
	{/snippet}
</Modal>
