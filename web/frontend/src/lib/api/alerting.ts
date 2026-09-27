// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrappers for the AL.1.b / AL.3b / AL.4.a alerting
// endpoints:
//   - /api/v1/settings/alerting/channels      (CRUD + /test)
//   - /api/v1/settings/alerting/rules         (CRUD + /test)
//   - /api/v1/observability/alert-events       (read-only)
//
// AL.4.b.1 ships every interface + client method so the
// History tab + future Channels/Rules tabs (AL.4.b.2 / .3)
// import from this single module. Field naming mirrors the
// Go wire shape exactly (camelCase as already emitted by
// the handlers).

import { request } from './client';

// -- Channels -----------------------------------------------

export type ChannelKind = 'webhook' | 'email' | 'discord';

/**
 * Discord channel config (v2.53).
 *
 * A dedicated kind rather than a webhook body template, because the
 * template is string interpolation with no JSON escaping: an alert whose
 * subject carries a quote produced an invalid body and an opaque HTTP 400
 * from Discord — intermittently, which is worse than always. The Go
 * sender marshals a struct instead.
 */
export interface DiscordConfig {
	/**
	 * The Discord-provided endpoint. It carries the credential in its
	 * path, so GET returns it redacted and an edit that does not retype
	 * it inherits the stored value.
	 */
	webhookUrl: string;
	/** Optional display-name override; empty keeps Discord's own. */
	username?: string;
	timeoutSeconds?: number;
}

export interface WebhookConfig {
	url: string;
	method: string;
	headers?: Record<string, string>;
	timeoutSeconds: number;
	bodyTemplate?: string;
}

export interface EmailConfig {
	smtpHost: string;
	/**
	 * v2.42 — name announced in EHLO. Empty lets the server work it
	 * out: the machine's hostname when fully qualified, otherwise the
	 * From domain. Arenet used to announce `localhost`, which strict
	 * MTAs refuse.
	 */
	heloName?: string;
	smtpPort: number;
	smtpUsername: string;
	// On GET this is always empty (server-side redaction).
	// On PUT, empty means "preserve the stored value"
	// (J.4 preserve-on-edit semantics).
	smtpPassword: string;
	from: string;
	to: string[];
	cc?: string[];
	bcc?: string[];
	useTLS: boolean;
	useStartTLS: boolean;
	subjectTemplate?: string;
	bodyTemplate?: string;
}

export interface AlertChannel {
	id: string;
	name: string;
	kind: ChannelKind;
	enabled: boolean;
	minSeverity: number;
	// Per-kind blob; the per-kind config types above decode it.
	// Backend returns it pre-redacted (header values blanked
	// for webhook, smtpPassword empty for email).
	config: WebhookConfig | EmailConfig | DiscordConfig;
	lastSentAt?: string;
	lastError?: string;
	lastErrorAt?: string;
	createdAt: string;
	updatedAt: string;
	/**
	 * v2.39 — true when the stored webhook URL is the redaction
	 * placeholder: an edit made before the fix overwrote it, so the
	 * channel cannot send until the URL is retyped.
	 */
	secretsLost?: boolean;
}

export interface AlertChannelRequest {
	name: string;
	kind: ChannelKind;
	enabled: boolean;
	minSeverity: number;
	config: WebhookConfig | EmailConfig | DiscordConfig;
}

export interface AlertChannelTestResponse {
	ok: boolean;
	error?: string;
}

// -- Rules --------------------------------------------------

export type RuleKind = 'threshold' | 'state';

export interface AlertRule {
	id: string;
	name: string;
	enabled: boolean;
	kind: RuleKind;
	severity: number;
	category: string;
	source: string;
	sourceParams: unknown;
	evalParams: unknown;
	channels: string[];
	cooldownSecs: number;
	subjectTemplate?: string;
	bodyTemplate?: string;
	createdAt: string;
	updatedAt: string;
	lastFiredAt?: string;
	lastEvalAt?: string;
	lastError?: string;
	lastErrorAt?: string;
}

export interface AlertRuleRequest {
	name: string;
	enabled: boolean;
	kind: RuleKind;
	severity: number;
	category: string;
	source: string;
	sourceParams: unknown;
	evalParams: unknown;
	channels: string[];
	cooldownSecs: number;
	subjectTemplate?: string;
	bodyTemplate?: string;
}

export interface AlertRuleTestResponse {
	sent: boolean;
	channelsFired: string[];
	errors?: Record<string, string>;
	skipped?: Record<string, string>;
}

// -- Alert events (History tab) -----------------------------

export interface AlertEvent {
	eventId: string;
	timestamp: string;
	ruleId: string;
	ruleName: string;
	severity: number;
	category: string;
	subject: string;
	body?: string;
	context?: Record<string, unknown>;
	labels?: Record<string, string>;
	channelsFired: string[];
	channelsFailed?: Record<string, string>;
}

export interface AlertEventsResponse {
	events: AlertEvent[];
	nextCursor: string;
	degraded?: boolean;
}

export interface AlertEventsFilter {
	ruleId?: string;
	severity?: number;
	category?: string;
	since?: string; // RFC 3339
	until?: string; // RFC 3339
	limit?: number;
	cursor?: string;
}

// -- Constants surfaced to the UI ---------------------------

export const SEVERITY_TOKENS = ['info', 'warning', 'critical', 'emergency'] as const;
export type SeverityToken = (typeof SEVERITY_TOKENS)[number];

/** Map severity int → wire token. Mirrors alerting.Severity.String() Go-side. */
export function severityToken(n: number): SeverityToken | 'unknown' {
	if (n < 0 || n > 3) return 'unknown';
	return SEVERITY_TOKENS[n];
}

/** Map severity int → human label.
 *  Operator-locked EN labels (v2.9.23 decision) — coherent with
 *  DEBUG/INFO/WARN/ERROR pattern from logs v2.9.18. The function
 *  name stays severityLabelFR for backwards-compat with existing
 *  call sites. */
export function severityLabelFR(n: number): string {
	switch (n) {
		case 0:
			return 'Info';
		case 1:
			return 'Warning';
		case 2:
			return 'Critical';
		case 3:
			return 'Emergency';
		default:
			return 'Unknown';
	}
}

/** Map severity int → Badge variant token (matches Badge.svelte
 * `status-*` variants). */
export function severityBadgeVariant(
	n: number
): 'status-info' | 'status-warn' | 'status-down' | 'neutral' {
	switch (n) {
		case 0:
			return 'status-info';
		case 1:
			return 'status-warn';
		case 2:
		case 3:
			return 'status-down';
		default:
			return 'neutral';
	}
}

/**
 * severityTooltip returns the long-form description used on
 * hover. AL.5 — surfaces the int → token mapping so the
 * operator doesn't have to memorise that "Critique" is 2 and
 * "Urgence" is 3 (it matters when reading the API directly
 * or matching with the audit log). Same wording across the
 * 3 tabs.
 */
export function severityTooltip(n: number): string {
	switch (n) {
		case 0:
			return 'Info (level 0) — informational, no action required.';
		case 1:
			return 'Warning (level 1) — degraded condition to monitor.';
		case 2:
			return 'Critical (level 2) — operator action required soon.';
		case 3:
			return 'Emergency (level 3) — Arenet in trouble, data plane impact possible.';
		default:
			return 'Unknown — severity value out of range [0..3].';
	}
}

// -- API client ---------------------------------------------

export const alertingApi = {
	// --- channels ---
	listChannels(): Promise<AlertChannel[]> {
		return request<AlertChannel[]>('GET', '/settings/alerting/channels');
	},
	getChannel(id: string): Promise<AlertChannel> {
		return request<AlertChannel>('GET', `/settings/alerting/channels/${id}`);
	},
	createChannel(req: AlertChannelRequest): Promise<AlertChannel> {
		return request<AlertChannel>('POST', '/settings/alerting/channels', req);
	},
	updateChannel(id: string, req: AlertChannelRequest): Promise<AlertChannel> {
		return request<AlertChannel>('PUT', `/settings/alerting/channels/${id}`, req);
	},
	deleteChannel(id: string): Promise<void> {
		return request<void>('DELETE', `/settings/alerting/channels/${id}`);
	},
	testChannel(id: string): Promise<AlertChannelTestResponse> {
		return request<AlertChannelTestResponse>('POST', `/settings/alerting/channels/${id}/test`);
	},

	// --- rules ---
	listRules(): Promise<AlertRule[]> {
		return request<AlertRule[]>('GET', '/settings/alerting/rules');
	},
	getRule(id: string): Promise<AlertRule> {
		return request<AlertRule>('GET', `/settings/alerting/rules/${id}`);
	},
	createRule(req: AlertRuleRequest): Promise<AlertRule> {
		return request<AlertRule>('POST', '/settings/alerting/rules', req);
	},
	updateRule(id: string, req: AlertRuleRequest): Promise<AlertRule> {
		return request<AlertRule>('PUT', `/settings/alerting/rules/${id}`, req);
	},
	deleteRule(id: string): Promise<void> {
		return request<void>('DELETE', `/settings/alerting/rules/${id}`);
	},
	testRule(id: string): Promise<AlertRuleTestResponse> {
		return request<AlertRuleTestResponse>('POST', `/settings/alerting/rules/${id}/test`);
	},

	// --- alert events (History tab) ---
	listAlertEvents(filter: AlertEventsFilter = {}): Promise<AlertEventsResponse> {
		const params = new URLSearchParams();
		if (filter.ruleId) params.set('rule_id', filter.ruleId);
		if (filter.severity !== undefined) params.set('severity', String(filter.severity));
		if (filter.category) params.set('category', filter.category);
		if (filter.since) params.set('since', filter.since);
		if (filter.until) params.set('until', filter.until);
		if (filter.limit !== undefined) params.set('limit', String(filter.limit));
		if (filter.cursor) params.set('cursor', filter.cursor);
		const query = params.toString();
		return request<AlertEventsResponse>(
			'GET',
			`/observability/alert-events${query ? '?' + query : ''}`
		);
	}
};
