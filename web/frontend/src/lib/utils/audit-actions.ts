// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The audit action catalogue the /audit filter offers.
//
// The backend does not expose its action list over the API, so this
// mirrors internal/audit/actions.go by hand. audit-actions.test.ts
// reads that Go file and fails when an action exists on one side only,
// which is what kept the old hard-coded dropdown at 16 entries while
// the backend grew to 77.
//
// Each action renders through t('audit.actions.<value>') and each group
// through t('audit.actionGroups.<id>'), so both locale bundles carry a
// readable label for every entry.

import { t } from '$lib/i18n';

/** One <optgroup> of the action filter. */
export interface AuditActionGroup {
	/** i18n key suffix under audit.actionGroups. */
	id: string;
	/** Canonical action values, as persisted by the backend. */
	actions: readonly string[];
}

/** Every backend audit action, grouped by the area it concerns. */
export const AUDIT_ACTION_GROUPS: readonly AuditActionGroup[] = [
	{
		id: 'auth',
		actions: [
			'login_success',
			'login_failure',
			'logout',
			'login_break_glass',
			'unlock_success',
			'unlock_failure',
			'session_revoked',
			'oidc_login_rejected',
			'oidc_callback_invalid'
		]
	},
	{
		id: 'users',
		actions: [
			'setup_admin_created',
			'user_created',
			'user_deleted',
			'user_role_changed',
			'password_changed',
			'local_admin_password_rotated',
			'password_hibp_clean',
			'password_hibp_pending',
			'password_compromised_detected',
			'service_account_created',
			'service_account_token_rotated',
			'service_account_deleted'
		]
	},
	{
		id: 'routes',
		actions: [
			'route_created',
			'route_updated',
			'route_deleted',
			'route_enabled',
			'route_disabled',
			'route_maintenance_on',
			'route_maintenance_off',
			'route_update_rolled_back',
			'route_check_updated',
			'access_log_updated'
		]
	},
	{
		id: 'tcp',
		actions: ['tcp_service_created', 'tcp_service_updated', 'tcp_service_deleted']
	},
	{
		id: 'probes',
		actions: ['probe_upstream', 'probe_health_check', 'probe_refused']
	},
	{
		id: 'certificates',
		actions: [
			'cert_deleted',
			'external_cert_uploaded',
			'external_cert_updated',
			'external_cert_deleted',
			'external_cert_csr_generated',
			'managed_domain_created',
			'managed_domain_deleted',
			'dns_provider_created',
			'dns_provider_updated',
			'dns_provider_deleted'
		]
	},
	{
		id: 'crowdsec',
		actions: [
			'crowdsec_configured',
			'crowdsec_updated',
			'crowdsec_reset',
			'crowdsec_decision_create',
			'crowdsec_decision_delete',
			'automation_decision_pushed',
			'automation_rule_changed',
			'automation_reset'
		]
	},
	{
		id: 'backups',
		actions: [
			'config_exported',
			'config_restored',
			'config_restored_rejected',
			'backup_schedule_updated',
			'backup_deleted'
		]
	},
	{
		id: 'alerting',
		actions: [
			'alert_channel_created',
			'alert_channel_updated',
			'alert_channel_deleted',
			'alert_rule_created',
			'alert_rule_updated',
			'alert_rule_deleted'
		]
	},
	{
		id: 'settings',
		actions: [
			'oidc_configured',
			'oidc_updated',
			'forward_auth_provider_updated',
			'forward_auth_provider_deleted',
			'error_template_created',
			'error_template_updated',
			'error_template_deleted',
			'maxmind_config_updated',
			'maxmind_config_deleted',
			'server_position_updated',
			'server_position_redetected'
		]
	},
	{
		id: 'audit',
		actions: ['audit_viewed']
	}
];

/** Flat list of every action in AUDIT_ACTION_GROUPS, in display order. */
export const AUDIT_ACTIONS: readonly string[] = AUDIT_ACTION_GROUPS.flatMap((g) => g.actions);

const KNOWN = new Set(AUDIT_ACTIONS);

/** Whether the frontend catalogue knows this action value. */
export function isKnownAuditAction(action: string): boolean {
	return KNOWN.has(action);
}

/**
 * Readable label for an action. An action this build does not know
 * (a newer backend) falls back to its raw value rather than to the
 * missing i18n key.
 */
export function auditActionLabel(action: string): string {
	return KNOWN.has(action) ? t(`audit.actions.${action}`) : action;
}
