// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package audit

import "slices"

// Step D audit action constants, per decision D7 in
// docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md.
// The 15 string values are the canonical names persisted in the audit
// bucket and exposed via the API. Tests in actions_test.go assert the
// enum is exactly these 15 values; the frontend audit page hardcodes
// the same set in its filter dropdown (Chunk 8).
const (
	// Authentication (3)
	ActionLoginSuccess = "login_success"
	ActionLoginFailure = "login_failure"
	ActionLogout       = "logout"

	// Lock screen (2)
	ActionUnlockSuccess = "unlock_success"
	ActionUnlockFailure = "unlock_failure"

	// Sessions (1)
	ActionSessionRevoked = "session_revoked"

	// Setup (1)
	ActionSetupAdminCreated = "setup_admin_created"

	// Password (1)
	ActionPasswordChanged = "password_changed"

	// Routes (3) — past tense per D7
	ActionRouteCreated = "route_created"
	ActionRouteUpdated = "route_updated"
	ActionRouteDeleted = "route_deleted"

	// v2.42 — TCP (layer 4) services. Same three verbs as routes:
	// a relay that exposes a port deserves the same trail as an HTTP
	// route, and for the same reason — it is a change to what this
	// host answers on the network.
	ActionTCPServiceCreated = "tcp_service_created"
	ActionTCPServiceUpdated = "tcp_service_updated"
	ActionTCPServiceDeleted = "tcp_service_deleted"

	// v2.14.3 — per-route enable/disable toggle. Emitted AFTER the
	// Caddy reload succeeds, mirroring route_updated. Distinct from
	// route_updated so operators see "took the route down" vs a
	// config edit in the audit trail.
	ActionRouteDisabled = "route_disabled"
	ActionRouteEnabled  = "route_enabled"

	// Certificate deletion (1) — emitted when a certificate is deleted
	// via the certificate management endpoints.
	ActionCertDeleted = "cert_deleted"

	// Route maintenance (2) — emitted when maintenance mode is toggled
	// on or off for a route.
	ActionRouteMaintenanceOn  = "route_maintenance_on"
	ActionRouteMaintenanceOff = "route_maintenance_off"

	// Audit (1)
	ActionAuditViewed = "audit_viewed"

	// HIBP (3)
	ActionPasswordHIBPClean           = "password_hibp_clean"
	ActionPasswordHIBPPending         = "password_hibp_pending"
	ActionPasswordCompromisedDetected = "password_compromised_detected"

	// Step J.4 — DNS provider (1)
	//
	// The string value is duplicated as a separate constant in
	// internal/api/dns_provider.go (api.ActionDNSProviderUpdated)
	// to keep the API's source-of-truth near the only emission
	// site; tests in actions_test.go pin the enum count.
	ActionDNSProviderUpdated = "dns_provider_updated"

	// v2.11 multi-config DNS providers (+2) — the singleton OVH
	// endpoint became a UUID-keyed collection (Task 1c). Create and
	// delete join the pre-existing dns_provider_updated. No secrets
	// are ever written to the audit row (endpoint + label only).
	ActionDNSProviderCreated = "dns_provider_created"
	ActionDNSProviderDeleted = "dns_provider_deleted"

	// v2.56 — diagnostic probes.
	//
	// The Test buttons fetch a URL the request names, so the admin API can
	// reach whatever the host can. Creating a route to do the same is
	// audited; a probe was not, which made it the quiet way to find out
	// what answers on an internal address. Recorded so it never is.
	ActionProbeUpstream    = "probe_upstream"
	ActionProbeHealthCheck = "probe_health_check"
	ActionProbeRefused     = "probe_refused"

	// Step K.1 — forward-auth provider (2)
	ActionForwardAuthProviderUpdated = "forward_auth_provider_updated"
	ActionForwardAuthProviderDeleted = "forward_auth_provider_deleted"

	// Step K.2 — OIDC admin auth + roles (7)
	ActionOIDCConfigured            = "oidc_configured"
	ActionOIDCUpdated               = "oidc_updated"
	ActionOIDCLoginRejected         = "oidc_login_rejected"
	ActionOIDCCallbackInvalid       = "oidc_callback_invalid"
	ActionLoginBreakGlass           = "login_break_glass"
	ActionLocalAdminPasswordRotated = "local_admin_password_rotated"
	ActionUserRoleChanged           = "user_role_changed"
	// User deletion (users-page Phase 1 refactor).
	// Mirrors ActionRouteDeleted shape: emitted AFTER the
	// bbolt delete succeeds, with BeforeJSON capturing the
	// deleted user's wire response and AfterJSON empty. The
	// last-admin guard rejects deletes of the only local
	// admin before this audit ever fires.
	ActionUserDeleted = "user_deleted"

	// ActionUserCreated (v2.48) — an administrator created a local
	// account. The event records who, for whom, and with which role.
	// It deliberately carries NO password material: an audit trail
	// that holds credentials is a credential store.
	ActionUserCreated = "user_created"

	// Phase 4 — service-account lifecycle (3 actions). The plain
	// token is NEVER recorded in BeforeJSON / AfterJSON; only the
	// service-account user identity + token metadata (id, name,
	// expiry presence) lands in the audit row. Token issuance
	// events are NOT per-request — only create / rotate / delete
	// land here; the LastUsedAt timestamp on the token row
	// covers the "was this token used recently?" question without
	// flooding audit on every Bearer call.
	ActionServiceAccountCreated      = "service_account_created"
	ActionServiceAccountTokenRotated = "service_account_token_rotated"
	ActionServiceAccountDeleted      = "service_account_deleted"

	// Step AL.1.a — alerting channel lifecycle (3). Wired
	// in AL.1.c when the CRUD HTTP handlers ship; this
	// file ships the action constants now so a future
	// audit pass against the channel CRUD doesn't have to
	// touch the count test in this same commit.
	//
	// Secret discipline (mirrors J.4 / CrowdSec / OIDC):
	// audit BeforeJSON + AfterJSON MUST be redacted by a
	// channel-specific adapter at emission time. The
	// SMTP password + webhook auth tokens never reach
	// the audit row. AL.1.c documents the redaction
	// contract per kind.
	ActionAlertChannelCreated = "alert_channel_created"
	ActionAlertChannelUpdated = "alert_channel_updated"
	ActionAlertChannelDeleted = "alert_channel_deleted"

	// Step AL.3b — alerting rule lifecycle (3). Emitted
	// by the operator-facing CRUD handlers in
	// internal/api/alerting_rules.go on successful
	// create / update / delete. The /test endpoint does
	// NOT emit an audit event (operator-pressed test is
	// a transient probe, not a state mutation).
	//
	// Templates are operator-supplied text/template
	// strings; they're not expected to carry secrets, so
	// full diff cleartext in BeforeJSON / AfterJSON.
	ActionAlertRuleCreated = "alert_rule_created"
	ActionAlertRuleUpdated = "alert_rule_updated"
	ActionAlertRuleDeleted = "alert_rule_deleted"

	// Step R — operator-defined HTML error page templates (3).
	// Body content is operator-typed HTML, no secrets ; full
	// diff in BeforeJSON / AfterJSON. Same admin-only gating
	// as the alert rules.
	ActionErrorTemplateCreated = "error_template_created"
	ActionErrorTemplateUpdated = "error_template_updated"
	ActionErrorTemplateDeleted = "error_template_deleted"

	// Step K.3 — backup / restore (3). The restore is significantly
	// more destructive than the export; both must be audited and the
	// failure path emits its own dedicated event so a rejected
	// restore is still traceable ("did someone try to take over my
	// instance?" — spec §5.3).
	ActionConfigExported         = "config_exported"
	ActionConfigRestored         = "config_restored"
	ActionConfigRestoredRejected = "config_restored_rejected"

	// v2.33 — scheduled backups (2). ScheduleUpdated carries
	// before/after JSON of the schedule (passphrase redacted);
	// Deleted carries the removed file name. Scheduled / manual runs
	// reuse ActionConfigExported with trigger= in the message.
	ActionBackupScheduleUpdated = "backup_schedule_updated"
	ActionBackupDeleted         = "backup_deleted"

	// v2.35 — post-apply route check (2). UpdateRolledBack: an update
	// broke a working route and was undone (before = the change,
	// after = the restored route). CheckUpdated: the setting toggled.
	ActionRouteUpdateRolledBack = "route_update_rolled_back"
	ActionRouteCheckUpdated     = "route_check_updated"
	ActionAccessLogUpdated      = "access_log_updated"

	// Step O.3 — managed-domain CRUD (2). The Created event
	// also carries the count of covered routes whose ACMEChallenge
	// was mutated to "inherited" (D8.A migration), so the audit
	// log records the cross-cutting effect of the operator action.
	// The Deleted event symmetrically carries the count of routes
	// reverted from "inherited" to the operator-chosen revertTo
	// value (AC #21).
	ActionManagedDomainCreated = "managed_domain_created"
	ActionManagedDomainDeleted = "managed_domain_deleted"

	// Step P.3 — auto-classify lifecycle (2). DecisionPushed
	// emitted by the trigger engine's writer goroutine after
	// a successful POST /v1/alerts to LAPI; carries
	// target_id = "<scope>:<value>" + after_json with the
	// scenario, duration, and triggering event ID for
	// operator drill-down. RuleChanged emitted by the
	// PUT /settings/automation/* handlers with before/after
	// JSON (watcher passwords redacted, J.4 pattern).
	ActionAutomationDecisionPushed = "automation_decision_pushed"
	ActionAutomationRuleChanged    = "automation_rule_changed"

	// Step V.4 — server geographic position admin actions.
	// PositionUpdated emitted by PUT /api/v1/observability/
	// server-position when the operator sets a manual override.
	// Carries target_id="default" (single-row bucket key) and
	// before/after JSON with the lat/lon/city/country diff.
	// PositionRedetected emitted by POST /api/v1/observability/
	// server-position:redetect — same target_id, after_json
	// reflects the newly-detected position, before_json
	// reflects whatever was persisted before the redetect.
	ActionServerPositionUpdated    = "server_position_updated"
	ActionServerPositionRedetected = "server_position_redetected"

	// Step CS.1 — CrowdSec bouncer config admin actions.
	// CrowdSecConfigured emitted by PUT /api/v1/settings/crowdsec
	// on the first write (no previous row in storage).
	// CrowdSecUpdated emitted by subsequent PUTs. Both carry
	// before/after JSON with APIKey scrubbed (SECRET — same
	// shape as oidcConfigForAudit / dnsProviderForAudit).
	ActionCrowdSecConfigured = "crowdsec_configured"
	ActionCrowdSecUpdated    = "crowdsec_updated"
	// Step CS.2 follow-up — operator-pressed Reset button on
	// the Settings UI emits this action. Distinct from
	// crowdsec_updated so the audit log makes the deliberate
	// "bouncer disabled" intent visible. BeforeJSON carries
	// the wiped row (APIKey scrubbed); AfterJSON is omitted
	// (the row no longer exists).
	ActionCrowdSecReset = "crowdsec_reset"
	// Step CS.3 Commit C — operator-pressed "Bannir une IP"
	// button on the Décisions actives tab. POST creates a
	// single LAPI alert+decision via the Security Automation
	// machine credentials. Scenario carries "manual:<user>|
	// <reason>". TargetID is the IP/CIDR value;
	// ActorUsernameSnapshot (auto-set by appendAudit)
	// duplicates the username so the audit log is searchable
	// by operator independently of the encoded scenario.
	ActionCrowdSecDecisionCreate = "crowdsec_decision_create"
	// Unban from the Live LAPI table: DELETE
	// /api/v1/security/crowdsec/decisions/{id} expires one LAPI
	// decision via the same machine credentials. TargetID is the
	// LAPI decision id; AfterJSON carries the id and LAPI's
	// nbDeleted count.
	ActionCrowdSecDecisionDelete = "crowdsec_decision_delete"
	// Step CS.3 follow-up — operator-pressed "Reset Security
	// Automation" button on the Settings UI. DELETE wipes
	// the persisted watcher credentials AND clears the
	// in-memory automation.Manager's writer so the
	// auto-classify pipeline stops emitting decisions to
	// LAPI immediately (no Arenet restart required). Mirror
	// of ActionCrowdSecReset (CS.2.C f1fe919): distinct from
	// automation_rule_changed so the audit log makes the
	// deliberate "auto-writer disabled" intent visible.
	// BeforeJSON carries the wiped row (Password scrubbed);
	// AfterJSON is omitted (the row no longer exists).
	ActionAutomationReset = "automation_reset"

	// Brick 2 Task 2 — MaxMind GeoIP account credential admin
	// actions. ConfigUpdated emitted by PUT
	// /api/v1/settings/maxmind (both first write and subsequent
	// updates); ConfigDeleted emitted by DELETE. Mirror of the
	// CrowdSec pattern above: before/after JSON carries the
	// MaxMind config with the license key scrubbed (SECRET —
	// same shape as APIKey scrubbing for crowdsec/oidc/dns).
	ActionMaxMindConfigUpdated = "maxmind_config_updated"
	ActionMaxMindConfigDeleted = "maxmind_config_deleted"

	// External certificates (3) — v2.19.0. Operator-uploaded TLS
	// certs served via load_pem. The private key (KeyPEM) is a
	// SECRET and is NEVER recorded in the audit row — only the
	// certificate identity (target_id = external cert UUID) lands
	// here. Uploaded on POST, Updated on PUT, Deleted on DELETE.
	ActionExternalCertUploaded     = "external_cert_uploaded"
	ActionExternalCertUpdated      = "external_cert_updated"
	ActionExternalCertDeleted      = "external_cert_deleted"
	ActionExternalCertCSRGenerated = "external_cert_csr_generated"
)

// allActions is the canonical set of audit action values for Step D.
// Unexported to prevent callers from mutating the slice; use AllActions()
// to obtain a fresh copy.
var allActions = []string{
	ActionLoginSuccess,
	ActionLoginFailure,
	ActionLogout,
	ActionUnlockSuccess,
	ActionUnlockFailure,
	ActionSessionRevoked,
	ActionSetupAdminCreated,
	ActionPasswordChanged,
	ActionRouteCreated,
	ActionRouteUpdated,
	ActionRouteDeleted,
	ActionTCPServiceCreated,
	ActionTCPServiceUpdated,
	ActionTCPServiceDeleted,
	ActionRouteDisabled,
	ActionRouteEnabled,
	ActionCertDeleted,
	ActionRouteMaintenanceOn,
	ActionRouteMaintenanceOff,
	ActionAuditViewed,
	ActionPasswordHIBPClean,
	ActionPasswordHIBPPending,
	ActionPasswordCompromisedDetected,
	ActionDNSProviderUpdated,
	ActionDNSProviderCreated,
	ActionDNSProviderDeleted,
	ActionForwardAuthProviderUpdated,
	ActionForwardAuthProviderDeleted,
	ActionProbeUpstream,
	ActionProbeHealthCheck,
	ActionProbeRefused,
	ActionOIDCConfigured,
	ActionOIDCUpdated,
	ActionOIDCLoginRejected,
	ActionOIDCCallbackInvalid,
	ActionLoginBreakGlass,
	ActionLocalAdminPasswordRotated,
	ActionUserRoleChanged,
	ActionUserCreated,
	ActionUserDeleted,
	ActionServiceAccountCreated,
	ActionServiceAccountTokenRotated,
	ActionServiceAccountDeleted,
	ActionAlertChannelCreated,
	ActionAlertChannelUpdated,
	ActionAlertChannelDeleted,
	ActionAlertRuleCreated,
	ActionAlertRuleUpdated,
	ActionAlertRuleDeleted,
	ActionErrorTemplateCreated,
	ActionErrorTemplateUpdated,
	ActionErrorTemplateDeleted,
	ActionConfigExported,
	ActionConfigRestored,
	ActionConfigRestoredRejected,
	ActionBackupScheduleUpdated,
	ActionBackupDeleted,
	ActionRouteUpdateRolledBack,
	ActionRouteCheckUpdated,
	ActionAccessLogUpdated,
	ActionManagedDomainCreated,
	ActionManagedDomainDeleted,
	ActionAutomationDecisionPushed,
	ActionAutomationRuleChanged,
	ActionServerPositionUpdated,
	ActionServerPositionRedetected,
	ActionCrowdSecConfigured,
	ActionCrowdSecUpdated,
	ActionCrowdSecReset,
	ActionCrowdSecDecisionCreate,
	ActionCrowdSecDecisionDelete,
	ActionAutomationReset,
	ActionMaxMindConfigUpdated,
	ActionMaxMindConfigDeleted,
	ActionExternalCertUploaded,
	ActionExternalCertUpdated,
	ActionExternalCertDeleted,
	ActionExternalCertCSRGenerated,
}

// AllActions returns a fresh copy of the canonical Step D action set.
// Used to validate enum cohesion (backend / frontend / tests).
//
// A new slice is returned on every call so callers cannot mutate the
// package-level source of truth.
func AllActions() []string {
	return slices.Clone(allActions)
}

// authFailureActions is the canonical set of audit actions that
// represent an authentication-failure event. Listed in Step Q spec
// §1.2 as the source for the /security/auth-failures timeline.
//
// Note: ActionUnlockFailure is included because the unlock flow is
// the same credential surface (it shares the rate limiter); a
// credential-stuffing attack against /unlock looks identical to one
// against /login from an operator perspective.
var authFailureActions = []string{
	ActionLoginFailure,
	ActionUnlockFailure,
	ActionOIDCLoginRejected,
	ActionOIDCCallbackInvalid,
}

// AuthFailureActions returns a fresh copy of the auth-failure action
// set. Used by the Step Q audit-scan path (/security/auth-failures
// handler + /metrics/timeseries?metric=auth_failure_rate detour).
//
// A new slice is returned on every call so callers cannot mutate the
// package-level source of truth.
func AuthFailureActions() []string {
	return slices.Clone(authFailureActions)
}
