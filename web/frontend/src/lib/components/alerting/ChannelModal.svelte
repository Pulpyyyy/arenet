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
  CURRENTLY-STORED channel (edit mode only — a not-yet-
  persisted draft has no ID). On create the button is
  hidden; the operator can test after first save.
-->
<script lang="ts">
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
	let validationError = $state('');

	// Reset the form when the modal opens or the target
	// channel changes. The reactive guard means edit-mode
	// pre-populates from the supplied channel; create-mode
	// resets to clean defaults.
	$effect(() => {
		if (!open) return;
		validationError = '';
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

	function buildRequest(): AlertChannelRequest | null {
		if (!name.trim()) {
			validationError = t('alerting.channelModal.errNameRequired');
			return null;
		}
		if (kind === 'discord') {
			if (!discordUrl.trim()) {
				validationError = t('alerting.channelModal.errDiscordUrlRequired');
				return null;
			}
			// Mirrors the Go validator so the refusal arrives while the
			// operator is looking at the field, not as a 400 afterwards.
			if (!/^https:\/\/(discord|discordapp)\.com\//.test(discordUrl.trim())) {
				validationError = t('alerting.channelModal.errDiscordUrlHost');
				return null;
			}
			if (discordTimeout < 1 || discordTimeout > 60) {
				validationError = t('alerting.channelModal.errTimeoutRange');
				return null;
			}
			const users = parseMentionIds(discordMentionUsers);
			const roles = parseMentionIds(discordMentionRoles);
			// A name instead of an ID is the mistake worth catching here: it
			// would save cleanly and then notify nobody, with no error
			// anywhere. Mirrors the Go validator.
			const badUser = users.find((id) => !/^\d+$/.test(id));
			if (badUser !== undefined) {
				validationError = t('alerting.channelModal.errDiscordMentionUser', { value: badUser });
				return null;
			}
			const badRole = roles.find((id) => !/^\d+$/.test(id));
			if (badRole !== undefined) {
				validationError = t('alerting.channelModal.errDiscordMentionRole', { value: badRole });
				return null;
			}
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
			if (!webhookUrl.trim()) {
				validationError = t('alerting.channelModal.errWebhookUrlRequired');
				return null;
			}
			if (!/^https?:\/\//.test(webhookUrl)) {
				validationError = t('alerting.channelModal.errWebhookUrlScheme');
				return null;
			}
			if (webhookTimeout < 1 || webhookTimeout > 60) {
				validationError = t('alerting.channelModal.errTimeoutRange');
				return null;
			}
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
		if (!smtpHost.trim()) {
			validationError = t('alerting.channelModal.errSmtpHostRequired');
			return null;
		}
		if (smtpPort < 1 || smtpPort > 65535) {
			validationError = t('alerting.channelModal.errSmtpPortRange');
			return null;
		}
		if (!from.trim() || !from.includes('@')) {
			validationError = t('alerting.channelModal.errFromEmail');
			return null;
		}
		const tos = toList.map((s) => s.trim()).filter((s) => s !== '');
		if (tos.length === 0) {
			validationError = t('alerting.channelModal.errAtLeastOneTo');
			return null;
		}
		for (const addr of tos) {
			if (!addr.includes('@')) {
				validationError = t('alerting.channelModal.errInvalidAddress', { addr });
				return null;
			}
		}
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

	async function onSubmit(e: SubmitEvent) {
		e.preventDefault();
		validationError = '';
		const req = buildRequest();
		if (!req) return;
		submitting = true;
		try {
			if (channel) {
				await channelsStore.update(channel.id, req);
				pushToast(t('alerting.channelModal.toastSaved', { name: req.name }), 'success');
			} else {
				await channelsStore.create(req);
				pushToast(t('alerting.channelModal.toastCreated', { name: req.name }), 'success');
			}
			onSaved();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			validationError = msg;
		} finally {
			submitting = false;
		}
	}

	async function onTest() {
		if (!channel) return;
		testing = true;
		try {
			const res = await alertingApi.testChannel(channel.id);
			if (res.ok) {
				pushToast(t('alerting.channelModal.toastTestedOk', { name: channel.name }), 'success');
			} else {
				pushToast(
					t('alerting.channelModal.toastTestedFail', { name: channel.name, err: res.error ?? t('alerting.channelModal.toastUnknownErr') }),
					'danger'
				);
			}
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('alerting.networkError');
			pushToast(t('alerting.channelModal.toastTestErr', { name: channel.name, err: msg }), 'danger');
		} finally {
			testing = false;
		}
	}
</script>

<Modal {open} title={language.current && (isEdit ? t('alerting.channelModal.titleEdit') : t('alerting.channelModal.titleCreate'))} {onClose} width="lg">
	<form onsubmit={onSubmit} class="space-y-4">
		<!-- Common fields -->
		<Input bind:value={name} label={language.current && t('alerting.channelModal.labelName')} placeholder={t('alerting.channelModal.placeholderName')} required />

		<div class="flex items-center gap-4">
			<Checkbox bind:checked={enabled} label={language.current && t('alerting.channelModal.labelEnabled')} />
		</div>

		<div class="grid grid-cols-2 gap-4">
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
					id="discord-url"
					type="text"
					bind:value={discordUrl}
					placeholder="https://discord.com/api/webhooks/…"
					data-testid="discord-url"
					class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
				/>
				<p class="text-xs text-secondary mt-1">
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
						id="discord-timeout"
						type="number"
						min="1"
						max="60"
						bind:value={discordTimeout}
						data-testid="discord-timeout"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
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
						id="discord-mention-users"
						type="text"
						bind:value={discordMentionUsers}
						placeholder="306162232765874176, 847291046728394112"
						data-testid="discord-mention-users"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>
				<div>
					<label for="discord-mention-roles" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelDiscordMentionRoles')}
					</label>
					<input
						id="discord-mention-roles"
						type="text"
						bind:value={discordMentionRoles}
						placeholder="1180422398765432100"
						data-testid="discord-mention-roles"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
					/>
				</div>
			</div>
			<p class="text-xs text-secondary">
				{language.current && t('alerting.channelModal.hintDiscordMentions')}
			</p>
		{/if}

		{#if kind === 'webhook'}
			{#if channel?.secretsLost}
				<p class="text-xs text-status-warn" role="alert" data-testid="channel-secrets-lost">
					{language.current && t('alerting.channelModal.secretsLost')}
				</p>
			{/if}
			<Input
				bind:value={webhookUrl}
				label={language.current && t('alerting.channelModal.labelWebhookUrl')}
				placeholder={t('alerting.channelModal.placeholderWebhookUrl')}
				required
			/>

			<div class="grid grid-cols-2 gap-4">
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
						id="webhook-timeout"
						type="number"
						bind:value={webhookTimeout}
						min="1"
						max="60"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
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
			<div class="grid grid-cols-3 gap-4">
				<div class="col-span-2">
					<Input
						bind:value={smtpHost}
						label={language.current && t('alerting.channelModal.labelSmtpHost')}
						placeholder={t('alerting.channelModal.placeholderSmtpHost')}
						required
					/>
				</div>
				<div>
					<label for="smtp-port" class="text-sm font-medium text-secondary mb-1.5 block">
						{language.current && t('alerting.channelModal.labelSmtpPort')}
					</label>
					<input
						id="smtp-port"
						type="number"
						bind:value={smtpPort}
						min="1"
						max="65535"
						class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
					/>
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
				bind:value={from}
				label={language.current && t('alerting.channelModal.labelFrom')}
				type="email"
				placeholder={t('alerting.channelModal.placeholderFromEmail')}
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
							<Input bind:value={toList[i]} placeholder={t('alerting.channelModal.placeholderTo')} />
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

		{#if validationError}
			<div
				class="p-3 rounded bg-down/10 border border-down text-down text-sm"
				role="alert"
			>
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
				{#snippet children()}{language.current && t('alerting.channelModal.btnSendTest')}{/snippet}
			</Button>
		{/if}
		<Button variant="ghost" onclick={onClose} disabled={submitting}>
			{#snippet children()}{language.current && t('alerting.channelModal.btnCancel')}{/snippet}
		</Button>
		<Button
			variant="primary"
			onclick={(e) => onSubmit(e as unknown as SubmitEvent)}
			disabled={submitting}
			loading={submitting}
		>
			{#snippet children()}{language.current && (isEdit ? t('alerting.channelModal.btnSave') : t('alerting.channelModal.btnCreate'))}{/snippet}
		</Button>
	{/snippet}
</Modal>
