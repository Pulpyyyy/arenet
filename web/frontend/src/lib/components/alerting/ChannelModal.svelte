<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AL.4.b.2 — Create / edit modal for alerting channels.
  Two kinds: webhook (URL + method + headers + timeout +
  optional templates) and email (SMTP host/port/user/pass +
  From + To/Cc/Bcc + TLS/STARTTLS + optional templates).

  Password preserve-on-omit (J.4 pattern, mirrors backend
  AL.1.b mergeAlertChannelSecrets):
    - Create: password input always editable, required.
    - Edit  : the stored password is rendered as the
      placeholder "[défini]" with a "Modifier le mot de
      passe" checkbox. Unchecked → submit sends "" so the
      backend preserves the stored value. Checked → an
      editable input appears for the operator to type the
      new password.

  Send-test button: fires POST /channels/{id}/test on the
  CURRENTLY-STORED channel. The backend has no endpoint that
  tests an unsaved config (internal/api/routes.go mounts only
  /settings/alerting/channels/{id}/test, and testAlertChannel
  loads the channel from the store by ID), so on create the
  button becomes "Create and send a test": it saves the channel,
  then fires the same endpoint on the new ID.

  Validation errors sit next to the field they concern
  (aria-invalid + aria-describedby); a count sits next to the
  footer buttons, and submit focuses the first invalid field.
  Errors appear on the first submit attempt and then follow the
  form live, so fixing a field clears its message.
-->
<script lang="ts">
	import { tick } from 'svelte';
	import {
		alertingApi,
		SEVERITY_TOKENS,
		severityLabelFR,
		type AlertChannel,
		type AlertChannelRequest,
		type ChannelKind,
		type DiscordConfig,
		type EmailConfig,
		type WebhookConfig
	} from '$lib/api/alerting';
	import { channelsStore } from '$lib/stores/alerting.svelte';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		open: boolean;
		channel: AlertChannel | null;
		onClose: () => void;
		onSaved: () => void;
	}

	let { open, channel, onClose, onSaved }: Props = $props();

	const isEdit = $derived(channel !== null);

	// --- form state -----------------------------------------

	let name = $state('');
	let enabled = $state(true);
	let kind = $state<ChannelKind>('webhook');
	// v2.53 — Discord fields. The URL is a secret (it is the credential),
	// so it comes back redacted and an untouched edit must not overwrite
	// the stored one — the backend inherits it when we send the
	// placeholder back, same contract as the webhook URL.
	let discordUrl = $state('');
	let discordUsername = $state('');
	// v2.54 — mentions. Kept as free text so the operator can paste IDs
	// separated however they like; split and validated on save.
	let discordMentionUsers = $state('');
	let discordMentionRoles = $state('');
	let discordTimeout = $state(10);
	let minSeverity = $state(0);

	// Webhook fields.
	let webhookUrl = $state('');
	let webhookMethod = $state<'POST'>('POST'); // V1 = POST only
	let webhookTimeout = $state(10);
	let webhookHeaders = $state<{ key: string; value: string }[]>([]);
	let webhookBodyTemplate = $state('');

	// Email fields.
	let smtpHost = $state('');
	let smtpPort = $state(587);
	let smtpUsername = $state('');
	let smtpPassword = $state('');
	let smtpPasswordDirty = $state(false); // true = operator wants to rotate
	let from = $state('');
	let toList = $state<string[]>(['']);
	let ccList = $state<string[]>([]);
	let bccList = $state<string[]>([]);
	let tlsMode = $state<'none' | 'tls' | 'starttls'>('starttls');
	let emailHeloName = $state('');
	let emailSubjectTemplate = $state('');
	let emailBodyTemplate = $state('');

	let submitting = $state(false);
	let testing = $state(false);
	// True while the create-mode "Create and send a test" flow runs,
	// so only that button shows the spinner.
	let creatingThenTesting = $state(false);
	// Set by the first submit attempt: errors are not shown on a
	// pristine form, then follow the fields live.
	let attempted = $state(false);
	// An error that belongs to no field (API refusal, network).
	let formError = $state('');
	let formEl: HTMLFormElement | undefined = $state(undefined);

	// Reset the form when the modal opens or the target
	// channel changes. The reactive guard means edit-mode
	// pre-populates from the supplied channel; create-mode
	// resets to clean defaults.
	$effect(() => {
		if (!open) return;
		attempted = false;
		formError = '';
		if (channel) {
			name = channel.name;
			enabled = channel.enabled;
			kind = channel.kind;
			minSeverity = channel.minSeverity;
			if (channel.kind === 'discord') {
				const cfg = (channel.config ?? {}) as unknown as Record<string, unknown>;
				discordUrl = typeof cfg.webhookUrl === 'string' ? cfg.webhookUrl : '';
				discordUsername = typeof cfg.username === 'string' ? cfg.username : '';
				discordMentionUsers = Array.isArray(cfg.mentionUserIds) ? cfg.mentionUserIds.join(', ') : '';
				discordMentionRoles = Array.isArray(cfg.mentionRoleIds) ? cfg.mentionRoleIds.join(', ') : '';
				discordTimeout = typeof cfg.timeoutSeconds === 'number' ? cfg.timeoutSeconds : 10;
			}
			if (channel.kind === 'webhook') {
				const cfg = channel.config as WebhookConfig;
				// v2.39 — a channel whose stored URL was overwritten by the
				// redaction placeholder starts empty: the operator must
				// retype it (the warning below says so).
				webhookUrl = channel.secretsLost ? '' : (cfg.url ?? '');
				webhookMethod = 'POST';
				webhookTimeout = cfg.timeoutSeconds ?? 10;
				webhookHeaders = cfg.headers
					? Object.entries(cfg.headers).map(([key, value]) => ({ key, value }))
					: [];
				webhookBodyTemplate = cfg.bodyTemplate ?? '';
			} else {
				const cfg = channel.config as EmailConfig;
				smtpHost = cfg.smtpHost ?? '';
				smtpPort = cfg.smtpPort ?? 587;
				smtpUsername = cfg.smtpUsername ?? '';
				smtpPassword = '';
				smtpPasswordDirty = false;
				from = cfg.from ?? '';
				toList = cfg.to && cfg.to.length > 0 ? [...cfg.to] : [''];
				ccList = cfg.cc ? [...cfg.cc] : [];
				bccList = cfg.bcc ? [...cfg.bcc] : [];
				if (cfg.useTLS) tlsMode = 'tls';
				else if (cfg.useStartTLS) tlsMode = 'starttls';
				else tlsMode = 'none';
				emailHeloName = cfg.heloName ?? '';
				emailSubjectTemplate = cfg.subjectTemplate ?? '';
				emailBodyTemplate = cfg.bodyTemplate ?? '';
			}
		} else {
			// Create defaults.
			name = '';
			enabled = true;
			kind = 'webhook';
			discordUrl = '';
			discordUsername = '';
			discordMentionUsers = '';
			discordMentionRoles = '';
			discordTimeout = 10;
			minSeverity = 0;
			webhookUrl = '';
			webhookMethod = 'POST';
			webhookTimeout = 10;
			webhookHeaders = [];
			webhookBodyTemplate = '';
			smtpHost = '';
			smtpPort = 587;
			smtpUsername = '';
			smtpPassword = '';
			smtpPasswordDirty = true; // required on create
			from = '';
			toList = [''];
			ccList = [];
			bccList = [];
			tlsMode = 'starttls';
			emailHeloName = '';
			emailSubjectTemplate = '';
			emailBodyTemplate = '';
		}
	});

	// --- dynamic list helpers ----------------------------------

	function addHeader() {
		webhookHeaders = [...webhookHeaders, { key: '', value: '' }];
	}
	function removeHeader(i: number) {
		webhookHeaders = webhookHeaders.filter((_, idx) => idx !== i);
	}

	function addRecipient(list: string[], setter: (next: string[]) => void) {
		setter([...list, '']);
	}
	function removeRecipient(list: string[], i: number, setter: (next: string[]) => void) {
		setter(list.filter((_, idx) => idx !== i));
	}

	// --- validation --------------------------------------------

	/**
	 * Splits a pasted list of Discord IDs on commas or whitespace.
	 *
	 * Operators paste from Discord's "Copy ID" one at a time, so the
	 * separator they end up with is whichever key they happened to press.
	 * Accepting both costs nothing and removes a pointless refusal.
	 */
	function parseMentionIds(raw: string): string[] {
		return raw
			.split(/[\s,;]+/)
			.map((s) => s.trim())
			.filter((s) => s.length > 0);
	}

	/**
	 * DOM ids of the validated fields. Each error is keyed by the id of
	 * the control it concerns, so the message renders next to it as
	 * `${id}-err` and the control points at it via aria-describedby.
	 */
	const FIELD = {
		name: 'channel-name',
		discordUrl: 'discord-url',
		discordTimeout: 'discord-timeout',
		discordMentionUsers: 'discord-mention-users',
		discordMentionRoles: 'discord-mention-roles',
		webhookUrl: 'webhook-url',
		webhookTimeout: 'webhook-timeout',
		smtpHost: 'smtp-host',
		smtpPort: 'smtp-port',
		from: 'email-from'
	} as const;

	function toFieldId(i: number): string {
		return `email-to-${i}`;
	}

	const DISCORD_URL_RE = /^https:\/\/(discord|discordapp)\.com\//;
	const HTTP_URL_RE = /^https?:\/\//;
	const NUMERIC_ID_RE = /^\d+$/;
	const TIMEOUT_MIN = 1;
	const TIMEOUT_MAX = 60;
	const PORT_MIN = 1;
	const PORT_MAX = 65535;

	function outOfRange(v: number | null | undefined, min: number, max: number): boolean {
		return typeof v !== 'number' || Number.isNaN(v) || v < min || v > max;
	}

	/**
	 * Every field error of the current form, keyed by field id.
	 *
	 * Pure: reads the form state, writes nothing, so it can back a
	 * $derived and the messages follow the operator's edits.
	 */
	function validate(): Record<string, string> {
		const errs: Record<string, string> = {};
		if (!name.trim()) errs[FIELD.name] = t('alerting.channelModal.errNameRequired');

		if (kind === 'discord') {
			const url = discordUrl.trim();
			if (!url) {
				errs[FIELD.discordUrl] = t('alerting.channelModal.errDiscordUrlRequired');
			} else if (!DISCORD_URL_RE.test(url)) {
				// Mirrors the Go validator so the refusal arrives while the
				// operator is looking at the field, not as a 400 afterwards.
				errs[FIELD.discordUrl] = t('alerting.channelModal.errDiscordUrlHost');
			}
			if (outOfRange(discordTimeout, TIMEOUT_MIN, TIMEOUT_MAX)) {
				errs[FIELD.discordTimeout] = t('alerting.channelModal.errTimeoutRange');
			}
			// A name instead of an ID is the mistake worth catching here: it
			// would save cleanly and then notify nobody, with no error
			// anywhere. Mirrors the Go validator.
			const badUser = parseMentionIds(discordMentionUsers).find((id) => !NUMERIC_ID_RE.test(id));
			if (badUser !== undefined) {
				errs[FIELD.discordMentionUsers] = t('alerting.channelModal.errDiscordMentionUser', {
					value: badUser
				});
			}
			const badRole = parseMentionIds(discordMentionRoles).find((id) => !NUMERIC_ID_RE.test(id));
			if (badRole !== undefined) {
				errs[FIELD.discordMentionRoles] = t('alerting.channelModal.errDiscordMentionRole', {
					value: badRole
				});
			}
			return errs;
		}

		if (kind === 'webhook') {
			const url = webhookUrl.trim();
			if (!url) {
				errs[FIELD.webhookUrl] = t('alerting.channelModal.errWebhookUrlRequired');
			} else if (!HTTP_URL_RE.test(url)) {
				errs[FIELD.webhookUrl] = t('alerting.channelModal.errWebhookUrlScheme');
			}
			if (outOfRange(webhookTimeout, TIMEOUT_MIN, TIMEOUT_MAX)) {
				errs[FIELD.webhookTimeout] = t('alerting.channelModal.errTimeoutRange');
			}
			return errs;
		}

		// email
		if (!smtpHost.trim()) errs[FIELD.smtpHost] = t('alerting.channelModal.errSmtpHostRequired');
		if (outOfRange(smtpPort, PORT_MIN, PORT_MAX)) {
			errs[FIELD.smtpPort] = t('alerting.channelModal.errSmtpPortRange');
		}
		if (!from.trim() || !from.includes('@')) {
			errs[FIELD.from] = t('alerting.channelModal.errFromEmail');
		}
		let anyTo = false;
		toList.forEach((raw, i) => {
			const addr = raw.trim();
			if (addr === '') return;
			anyTo = true;
			if (!addr.includes('@')) {
				errs[toFieldId(i)] = t('alerting.channelModal.errInvalidAddress', { addr });
			}
		});
		if (!anyTo) errs[toFieldId(0)] = t('alerting.channelModal.errAtLeastOneTo');
		return errs;
	}

	// Recomputed on every edit; only displayed once a submit was tried.
	const liveErrors = $derived(validate());
	const shownErrors: Record<string, string> = $derived(attempted ? liveErrors : {});
	const errorCount = $derived(Object.keys(shownErrors).length);

	/** aria-describedby value for a raw control: its error, if any. */
	function describedBy(id: string): string | undefined {
		return shownErrors[id] ? `${id}-err` : undefined;
	}

	/** Border token for a raw control, red when it carries an error. */
	function borderFor(id: string): string {
		return shownErrors[id] ? 'border-down' : 'border-border-default';
	}

	/** Moves focus to the first invalid control, in DOM order. */
	async function focusFirstInvalid() {
		await tick();
		const el = formEl?.querySelector<HTMLElement>('[aria-invalid="true"]');
		if (!el) return;
		el.focus();
		// jsdom has no scrollIntoView; browsers do.
		if (typeof el.scrollIntoView === 'function') {
			el.scrollIntoView({ block: 'center', behavior: 'smooth' });
		}
	}

	/** Builds the API request. Call only once validate() is empty. */
	function buildRequest(): AlertChannelRequest {
		if (kind === 'discord') {
			const users = parseMentionIds(discordMentionUsers);
			const roles = parseMentionIds(discordMentionRoles);
			const cfg: DiscordConfig = {
				webhookUrl: discordUrl.trim(),
				username: discordUsername.trim() || undefined,
				mentionUserIds: users.length > 0 ? users : undefined,
				mentionRoleIds: roles.length > 0 ? roles : undefined,
				timeoutSeconds: discordTimeout
			};
			return { name: name.trim(), kind: 'discord', enabled, minSeverity, config: cfg };
		}
		if (kind === 'webhook') {
			const headers: Record<string, string> = {};
			for (const h of webhookHeaders) {
				if (h.key.trim() === '') continue;
				headers[h.key.trim()] = h.value;
			}
			const cfg: WebhookConfig = {
				url: webhookUrl.trim(),
				method: 'POST',
				timeoutSeconds: webhookTimeout,
				headers: Object.keys(headers).length > 0 ? headers : undefined,
				bodyTemplate: webhookBodyTemplate.trim() || undefined
			};
			return {
				name: name.trim(),
				kind: 'webhook',
				enabled,
				minSeverity,
				config: cfg
			};
		}
		// email
		const tos = toList.map((s) => s.trim()).filter((s) => s !== '');
		const cc = ccList.map((s) => s.trim()).filter((s) => s !== '');
		const bcc = bccList.map((s) => s.trim()).filter((s) => s !== '');
		// Password: edit + unchecked → send "" so backend
		// preserves stored value. Otherwise send the typed
		// value (may be empty on create, in which case backend
		// may reject if it's a real SMTP relay).
		const password = !isEdit || smtpPasswordDirty ? smtpPassword : '';
		const cfg: EmailConfig = {
			smtpHost: smtpHost.trim(),
			smtpPort,
			smtpUsername: smtpUsername.trim(),
			smtpPassword: password,
			from: from.trim(),
			to: tos,
			cc: cc.length > 0 ? cc : undefined,
			bcc: bcc.length > 0 ? bcc : undefined,
			useTLS: tlsMode === 'tls',
			useStartTLS: tlsMode === 'starttls',
			heloName: emailHeloName.trim() || undefined,
			subjectTemplate: emailSubjectTemplate.trim() || undefined,
			bodyTemplate: emailBodyTemplate.trim() || undefined
		};
		return {
			name: name.trim(),
			kind: 'email',
			enabled,
			minSeverity,
			config: cfg
		};
	}

	/**
	 * Fires the test endpoint on a stored channel and reports the
	 * outcome as a toast. Never throws: a failed test is information,
	 * not a reason to keep the modal open.
	 */
	async function runTest(id: string, channelName: string) {
		testing = true;
		try {
			const res = await alertingApi.testChannel(id);
			if (res.ok) {
				pushToast(t('alerting.channelModal.toastTestedOk', { name: channelName }), 'success');
			} else {
				pushToast(
					t('alerting.channelModal.toastTestedFail', {
						name: channelName,
						err: res.error ?? t('alerting.channelModal.toastUnknownErr')
					}),
					'danger'
				);
			}
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			pushToast(t('alerting.channelModal.toastTestErr', { name: channelName, err: msg }), 'danger');
		} finally {
			testing = false;
		}
	}

	/**
	 * Validates, then creates or updates the channel. With thenTest
	 * (create mode only) the new channel is tested right after it is
	 * stored: the backend can only test a channel that has an ID.
	 */
	async function save(thenTest: boolean) {
		attempted = true;
		formError = '';
		if (Object.keys(validate()).length > 0) {
			await focusFirstInvalid();
			return;
		}
		const req = buildRequest();
		submitting = true;
		creatingThenTesting = thenTest;
		let created: AlertChannel | null = null;
		try {
			if (channel) {
				await channelsStore.update(channel.id, req);
				pushToast(t('alerting.channelModal.toastSaved', { name: req.name }), 'success');
			} else {
				created = await channelsStore.create(req);
				pushToast(t('alerting.channelModal.toastCreated', { name: req.name }), 'success');
			}
		} catch (err) {
			formError = err instanceof ApiError ? err.message : t('alerting.networkError');
			submitting = false;
			creatingThenTesting = false;
			return;
		}
		// The channel exists from here on: whatever the test says, the
		// modal must close, or a second click would create a duplicate.
		if (thenTest && created) {
			await runTest(created.id, created.name || req.name);
		}
		submitting = false;
		creatingThenTesting = false;
		onSaved();
	}

	function onSubmit(e: SubmitEvent) {
		e.preventDefault();
		void save(false);
	}

	async function onTest() {
		if (!channel) return;
		await runTest(channel.id, channel.name);
	}
</script>

<!-- Error line under a raw control. The Input component renders its
     own, with the same `${id}-err` id. -->
{#snippet fieldError(id: string)}
	{#if shownErrors[id]}
		<p id={`${id}-err`} class="text-xs text-down mt-1">{shownErrors[id]}</p>
	{/if}
{/snippet}

<Modal {open} title={language.current && (isEdit ? t('alerting.channelModal.titleEdit') : t('alerting.channelModal.titleCreate'))} {onClose} width="lg">
	<!-- novalidate: the browser bubbles would duplicate (and pre-empt)
	     the messages rendered next to each field. The body scrolls so
	     the footer — buttons and error count — stays in view. -->
	<form
		bind:this={formEl}
		onsubmit={onSubmit}
		novalidate
		class="space-y-4"
	>
		<!-- Common fields -->
		<Input
			id={FIELD.name}
			bind:value={name}
			label={language.current && t('alerting.channelModal.labelName')}
			placeholder={t('alerting.channelModal.placeholderName')}
			error={shownErrors[FIELD.name]}
			required
		/>

		<div class="flex items-center gap-4">
			<Checkbox bind:checked={enabled} label={language.current && t('alerting.channelModal.labelEnabled')} />
		</div>

		<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
			<div>
				<label for="channel-kind" class="text-sm font-medium text-secondary mb-1.5 block">
					{language.current && t('alerting.channelModal.labelType')}
				</label>
				<select
					id="channel-kind"
					bind:value={kind}
					disabled={isEdit}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50"
				>
					<option value="webhook">Webhook</option>
					<option value="email">Email</option>
					<option value="discord">Discord</option>
				</select>
				{#if isEdit}
					<p class="text-xs text-secondary mt-1">
						{language.current && t('alerting.channelModal.typeLockedAfterCreate')}
					</p>
				{/if}
			</div>
			<div>
				<label
					for="channel-severity"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.channelModal.labelMinSeverity')}
				</label>
				<select
					id="channel-severity"
					bind:value={minSeverity}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
				>
					{#each SEVERITY_TOKENS as _token, i (i)}
						<option value={i}>{severityLabelFR(i)}</option>
					{/each}
				</select>
			</div>
		</div>

		<hr class="border-border-subtle" />

		<!-- Webhook fields -->
		{#if kind === 'discord'}
			<!-- v2.53 — one field is enough.
			     Pointing the generic webhook at Discord required hand-writing
			     its payload in a body template, with no JSON escaping: an
			     alert whose subject carried a quote produced an opaque 400.
			     Here the sender builds the payload, so the operator pastes a
			     URL and nothing else. -->
			<div>
				<label for="discord-url" class="text-sm font-medium text-secondary mb-1.5 block">
					{language.current && t('alerting.channelModal.labelDiscordUrl')}
				</label>
				<input
					id={FIELD.discordUrl}
					type="text"
					bind:value={discordUrl}
					placeholder="https://discord.com/api/webhooks/…"
					data-testid="discord-url"
					aria-invalid={shownErrors[FIELD.discordUrl] ? 'true' : undefined}
					aria-describedby={[describedBy(FIELD.discordUrl), 'discord-url-hint'].filter(Boolean).join(' ')}
					class="w-full bg-surface border {borderFor(FIELD.discordUrl)} rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				{@render fieldError(FIELD.discordUrl)}
				<p id="discord-url-hint" class="text-xs text-secondary mt-1">
					{language.current && t('alerting.channelModal.hintDiscordUrl')}
				</p>
			</div>
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<div>
					<label for="discord-username" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelDiscordUsername')}
					</label>
					<input
						id="discord-username"
						type="text"
						bind:value={discordUsername}
						data-testid="discord-username"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				</div>
				<div>
					<label for="discord-timeout" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelTimeout')}
					</label>
					<input
						id={FIELD.discordTimeout}
						type="number"
						min="1"
						max="60"
						bind:value={discordTimeout}
						data-testid="discord-timeout"
						aria-invalid={shownErrors[FIELD.discordTimeout] ? 'true' : undefined}
						aria-describedby={describedBy(FIELD.discordTimeout)}
						class="w-full bg-surface border {borderFor(FIELD.discordTimeout)} rounded-md px-3 py-2 text-sm text-primary"
					/>
					{@render fieldError(FIELD.discordTimeout)}
				</div>
			</div>
			<!-- v2.54 — mentions.
			     Discord raises a notification only for a mention in the
			     message content, never one inside an embed, so Arenet posts
			     these as a line above the alert. They are IDs because that
			     is all Discord resolves: a name posts as plain text and
			     notifies no one. -->
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<div>
					<label for="discord-mention-users" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelDiscordMentionUsers')}
					</label>
					<input
						id={FIELD.discordMentionUsers}
						type="text"
						bind:value={discordMentionUsers}
						placeholder="306162232765874176, 847291046728394112"
						data-testid="discord-mention-users"
						aria-invalid={shownErrors[FIELD.discordMentionUsers] ? 'true' : undefined}
						aria-describedby={[describedBy(FIELD.discordMentionUsers), 'discord-mentions-hint'].filter(Boolean).join(' ')}
						class="w-full bg-surface border {borderFor(FIELD.discordMentionUsers)} rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
					{@render fieldError(FIELD.discordMentionUsers)}
				</div>
				<div>
					<label for="discord-mention-roles" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelDiscordMentionRoles')}
					</label>
					<input
						id={FIELD.discordMentionRoles}
						type="text"
						bind:value={discordMentionRoles}
						placeholder="1180422398765432100"
						data-testid="discord-mention-roles"
						aria-invalid={shownErrors[FIELD.discordMentionRoles] ? 'true' : undefined}
						aria-describedby={[describedBy(FIELD.discordMentionRoles), 'discord-mentions-hint'].filter(Boolean).join(' ')}
						class="w-full bg-surface border {borderFor(FIELD.discordMentionRoles)} rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
					{@render fieldError(FIELD.discordMentionRoles)}
				</div>
			</div>
			<p id="discord-mentions-hint" class="text-xs text-secondary">
				{language.current && t('alerting.channelModal.hintDiscordMentions')}
			</p>
		{/if}

		{#if kind === 'webhook'}
			{#if channel?.secretsLost}
				<p class="text-xs text-warn" role="alert" data-testid="channel-secrets-lost">
					{language.current && t('alerting.channelModal.secretsLost')}
				</p>
			{/if}
			<Input
				id={FIELD.webhookUrl}
				bind:value={webhookUrl}
				label={language.current && t('alerting.channelModal.labelWebhookUrl')}
				placeholder={t('alerting.channelModal.placeholderWebhookUrl')}
				error={shownErrors[FIELD.webhookUrl]}
				required
			/>

			<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
				<div>
					<label
						for="webhook-method"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.channelModal.labelMethod')}
					</label>
					<select
						id="webhook-method"
						bind:value={webhookMethod}
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					>
						<option value="POST">POST</option>
					</select>
					<p class="text-xs text-secondary mt-1">{language.current && t('alerting.channelModal.methodLocked')}</p>
				</div>
				<div>
					<label
						for="webhook-timeout"
						class="text-sm font-medium text-secondary mb-1.5 block"
					>
						{language.current && t('alerting.channelModal.labelTimeout')}
					</label>
					<input
						id={FIELD.webhookTimeout}
						type="number"
						bind:value={webhookTimeout}
						min="1"
						max="60"
						aria-invalid={shownErrors[FIELD.webhookTimeout] ? 'true' : undefined}
						aria-describedby={describedBy(FIELD.webhookTimeout)}
						class="w-full bg-surface border {borderFor(FIELD.webhookTimeout)} rounded-md px-3 py-2 text-sm text-primary"
					/>
					{@render fieldError(FIELD.webhookTimeout)}
				</div>
			</div>

			<div>
				<div class="flex items-center justify-between mb-2">
					<span class="text-sm font-medium text-secondary">{language.current && t('alerting.channelModal.labelHttpHeaders')}</span>
					<Button variant="ghost" size="sm" onclick={addHeader}>
						{#snippet children()}{language.current && t('alerting.channelModal.btnAdd')}{/snippet}
					</Button>
				</div>
				{#if webhookHeaders.length === 0}
					<p class="text-xs text-secondary">{language.current && t('alerting.channelModal.noCustomHeader')}</p>
				{:else}
					<div class="space-y-2">
						{#each webhookHeaders as h, i (i)}
							<div class="flex gap-2 items-start">
								<Input bind:value={h.key} placeholder={t('alerting.channelModal.placeholderHeaderKey')} />
								<Input
									bind:value={h.value}
									placeholder={isEdit && h.value === '[redacted]'
										? t('alerting.channelModal.placeholderHeaderRedacted')
										: t('alerting.channelModal.placeholderHeaderValue')}
								/>
								<Button
									variant="ghost"
									size="sm"
									onclick={() => removeHeader(i)}
									aria-label={language.current && t('alerting.channelModal.ariaRemoveHeader')}
								>
									{#snippet children()}×{/snippet}
								</Button>
							</div>
						{/each}
					</div>
				{/if}
				{#if isEdit}
					<p class="text-xs text-secondary mt-2">
						{language.current && t('alerting.channelModal.redactedHeadersNote')}
					</p>
				{/if}
			</div>

			<div>
				<label
					for="webhook-body-template"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.channelModal.labelBodyTemplate')}
				</label>
				<textarea
					id="webhook-body-template"
					bind:value={webhookBodyTemplate}
					rows="3"
					placeholder={`{"text":"[{{.Severity}}] {{.Subject}}"}`}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				></textarea>
				<p class="text-xs text-secondary mt-1">
					{language.current && t('alerting.channelModal.bodyTemplatePlaceholders')}
					<code>{`{{.RuleName}}`}</code>, <code>{`{{.Severity}}`}</code>,
					<code>{`{{.Subject}}`}</code>.
				</p>
			</div>
		{/if}

		<!-- Email fields -->
		{#if kind === 'email'}
			<div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
				<div class="sm:col-span-2">
					<Input
						id={FIELD.smtpHost}
						bind:value={smtpHost}
						label={language.current && t('alerting.channelModal.labelSmtpHost')}
						placeholder={t('alerting.channelModal.placeholderSmtpHost')}
						error={shownErrors[FIELD.smtpHost]}
						required
					/>
				</div>
				<div>
					<label for={FIELD.smtpPort} class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelSmtpPort')}
					</label>
					<input
						id={FIELD.smtpPort}
						type="number"
						bind:value={smtpPort}
						min="1"
						max="65535"
						aria-invalid={shownErrors[FIELD.smtpPort] ? 'true' : undefined}
						aria-describedby={describedBy(FIELD.smtpPort)}
						class="w-full bg-surface border {borderFor(FIELD.smtpPort)} rounded-md px-3 py-2 text-sm text-primary"
					/>
					{@render fieldError(FIELD.smtpPort)}
				</div>
			</div>

			<Input
				bind:value={smtpUsername}
				label={language.current && t('alerting.channelModal.labelSmtpUsername')}
				placeholder={t('alerting.channelModal.placeholderSmtpUsername')}
			/>

			<div>
				<label
					for="smtp-password"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.channelModal.labelSmtpPassword')}
				</label>
				{#if isEdit && !smtpPasswordDirty}
					<div class="flex items-center gap-3">
						<input
							id="smtp-password"
							type="text"
							value={language.current && t('alerting.channelModal.passwordPlaceholder')}
							readonly
							disabled
							class="flex-1 bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-secondary"
						/>
						<Checkbox
							bind:checked={smtpPasswordDirty}
							label={language.current && t('alerting.channelModal.labelChangePassword')}
						/>
					</div>
				{:else}
					<input
						id="smtp-password"
						type="password"
						bind:value={smtpPassword}
						placeholder="••••••••"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
				{/if}
			</div>

			<Input
				id={FIELD.from}
				bind:value={from}
				label={language.current && t('alerting.channelModal.labelFrom')}
				type="email"
				placeholder={t('alerting.channelModal.placeholderFromEmail')}
				error={shownErrors[FIELD.from]}
				required
			/>

			<div>
				<div class="flex items-center justify-between mb-2">
					<span class="text-sm font-medium text-secondary">{language.current && t('alerting.channelModal.labelTo')}</span>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => addRecipient(toList, (n) => (toList = n))}
					>
						{#snippet children()}{language.current && t('alerting.channelModal.btnAdd')}{/snippet}
					</Button>
				</div>
				<div class="space-y-2">
					{#each toList as _r, i (i)}
						<div class="flex gap-2 items-start">
							<Input
								id={toFieldId(i)}
								bind:value={toList[i]}
								placeholder={t('alerting.channelModal.placeholderTo')}
								error={shownErrors[toFieldId(i)]}
							/>
							{#if toList.length > 1}
								<Button
									variant="ghost"
									size="sm"
									onclick={() =>
										removeRecipient(toList, i, (n) => (toList = n))}
									aria-label={language.current && t('alerting.channelModal.ariaRemoveTo')}
								>
									{#snippet children()}×{/snippet}
								</Button>
							{/if}
						</div>
					{/each}
				</div>
			</div>

			<details>
				<summary class="text-sm text-secondary cursor-pointer">{language.current && t('alerting.channelModal.advancedOptions')}</summary>
				<div class="mt-3 space-y-3 pl-2 border-l border-border-subtle">
					<div>
						<div class="flex items-center justify-between mb-2">
							<span class="text-sm font-medium text-secondary">{language.current && t('alerting.channelModal.labelCc')}</span>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => addRecipient(ccList, (n) => (ccList = n))}
							>
								{#snippet children()}{language.current && t('alerting.channelModal.btnAdd')}{/snippet}
							</Button>
						</div>
						{#each ccList as _r, i (i)}
							<div class="flex gap-2 items-start mb-2">
								<Input bind:value={ccList[i]} placeholder={t('alerting.channelModal.placeholderCc')} />
								<Button
									variant="ghost"
									size="sm"
									onclick={() =>
										removeRecipient(ccList, i, (n) => (ccList = n))}
									aria-label={language.current && t('alerting.channelModal.ariaRemoveCc')}
								>
									{#snippet children()}×{/snippet}
								</Button>
							</div>
						{/each}
					</div>
					<div>
						<div class="flex items-center justify-between mb-2">
							<span class="text-sm font-medium text-secondary">{language.current && t('alerting.channelModal.labelBcc')}</span>
							<Button
								variant="ghost"
								size="sm"
								onclick={() => addRecipient(bccList, (n) => (bccList = n))}
							>
								{#snippet children()}{language.current && t('alerting.channelModal.btnAdd')}{/snippet}
							</Button>
						</div>
						{#each bccList as _r, i (i)}
							<div class="flex gap-2 items-start mb-2">
								<Input bind:value={bccList[i]} placeholder={t('alerting.channelModal.placeholderBcc')} />
								<Button
									variant="ghost"
									size="sm"
									onclick={() =>
										removeRecipient(bccList, i, (n) => (bccList = n))}
									aria-label={language.current && t('alerting.channelModal.ariaRemoveBcc')}
								>
									{#snippet children()}×{/snippet}
								</Button>
							</div>
						{/each}
					</div>
				</div>
			</details>

			<fieldset>
				<legend class="text-sm font-medium text-secondary mb-1.5">{language.current && t('alerting.channelModal.legendEncryption')}</legend>
				<div class="flex gap-4">
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" bind:group={tlsMode} value="none" />
						{language.current && t('alerting.channelModal.encryptionNone')}
					</label>
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" bind:group={tlsMode} value="starttls" />
						{language.current && t('alerting.channelModal.encryptionStartTLS')}
					</label>
					<label class="flex items-center gap-2 text-sm">
						<input type="radio" bind:group={tlsMode} value="tls" />
						{language.current && t('alerting.channelModal.encryptionTLS')}
					</label>
				</div>
			</fieldset>

			<div>
				<label for="email-helo-name" class="text-sm font-medium text-secondary mb-1.5 block">
					{language.current && t('alerting.channelModal.labelHeloName')}
				</label>
				<input
					id="email-helo-name"
					bind:value={emailHeloName}
					placeholder="arenet.example.com"
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-muted mt-1">
					{language.current && t('alerting.channelModal.helpHeloName')}
				</p>
			</div>

			<div>
				<label
					for="email-subject-template"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.channelModal.labelSubjectTemplate')}
				</label>
				<input
					id="email-subject-template"
					bind:value={emailSubjectTemplate}
					placeholder={`[{{.Severity}}] {{.Subject}}`}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
			</div>

			<div>
				<label
					for="email-body-template"
					class="text-sm font-medium text-secondary mb-1.5 block"
				>
					{language.current && t('alerting.channelModal.labelEmailBodyTemplate')}
				</label>
				<textarea
					id="email-body-template"
					bind:value={emailBodyTemplate}
					rows="4"
					placeholder={`Rule: {{.RuleName}}\nSeverity: {{.Severity}}\nDetail: {{.Body}}`}
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				></textarea>
			</div>
		{/if}

		{#if !isEdit}
			<!-- The backend tests stored channels only (POST
			     /channels/{id}/test), so the create-mode test button
			     says up front that it saves first. -->
			<p id="channel-create-test-hint" class="text-xs text-secondary">
				{language.current && t('alerting.channelModal.hintCreateAndTest')}
			</p>
		{/if}
	</form>

	{#snippet footer()}
		<div class="flex w-full flex-wrap items-center justify-end gap-2">
			{#if errorCount > 0 || formError}
				<div
					class="mr-auto flex flex-wrap items-center gap-x-2 text-sm text-down"
					data-testid="channel-form-summary"
				>
					<p role="alert">
						{#if errorCount > 0}
							{language.current &&
								(errorCount === 1
									? t('alerting.channelModal.errSummaryOne')
									: t('alerting.channelModal.errSummaryMany', { count: errorCount }))}
						{:else}
							{formError}
						{/if}
					</p>
					{#if errorCount > 0}
						<button
							type="button"
							class="underline hover:no-underline rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan"
							onclick={focusFirstInvalid}
						>
							{language.current && t('alerting.channelModal.btnGoToError')}
						</button>
					{/if}
				</div>
			{/if}
			{#if isEdit}
				<Button
					variant="secondary"
					onclick={onTest}
					disabled={testing || submitting}
					loading={testing}
				>
					{#snippet children()}{language.current && t('alerting.channelModal.btnSendTest')}{/snippet}
				</Button>
			{:else}
				<Button
					variant="secondary"
					onclick={() => save(true)}
					disabled={testing || submitting}
					loading={creatingThenTesting}
					aria-describedby="channel-create-test-hint"
				>
					{#snippet children()}{language.current && t('alerting.channelModal.btnCreateAndTest')}{/snippet}
				</Button>
			{/if}
			<Button variant="ghost" onclick={onClose} disabled={submitting}>
				{#snippet children()}{language.current && t('alerting.channelModal.btnCancel')}{/snippet}
			</Button>
			<Button
				variant="primary"
				onclick={(e) => onSubmit(e as unknown as SubmitEvent)}
				disabled={submitting || testing}
				loading={submitting && !creatingThenTesting}
			>
				{#snippet children()}{language.current && (isEdit ? t('alerting.channelModal.btnSave') : t('alerting.channelModal.btnCreate'))}{/snippet}
			</Button>
		</div>
	{/snippet}
</Modal>
