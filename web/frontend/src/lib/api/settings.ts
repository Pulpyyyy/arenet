// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Typed wrappers for the Settings endpoints
// (`/api/v1/settings/...`). Step J.4 added DNS provider; Step K.1
// adds forward-auth provider CRUD. Future Settings endpoints
// (OIDC, theme defaults, ...) land here.

import { request } from './client';
import type {
	AccessLogRequest,
	AccessLogSettings,
	AdminUser,
	AutomationCredentialsRequest,
	AutomationCredentialsView,
	AutomationResponse,
	AutomationRulesRequest,
	AutomationRuleSet,
	CreateServiceAccountRequest,
	CreateAdminUserRequest,
	CreateAdminUserResponse,
	CreateServiceAccountResponse,
	CrowdSecSettings,
	CrowdSecSettingsRequest,
	CrowdSecTestRequest,
	CrowdSecTestResponse,
	DNSProvider,
	DNSProviderRequest,
	DNSProviderTestResult,
	DNSProviderType,
	ForwardAuthProvider,
	ForwardAuthProviderRequest,
	ManagedDomain,
	ManagedDomainDeleteResponse,
	ManagedDomainRequest,
	ManagedDomainRevertTo,
	ManagedDomainsListResponse,
	MaxMindConfig,
	MaxMindRequest,
	MaxMindTestResult,
	OIDCAllowedIdentity,
	OIDCAllowlistAddRequest,
	OIDCConfig,
	OIDCConfigRequest,
	OIDCTestResult,
	RotateServiceAccountTokenRequest,
	RotateServiceAccountTokenResponse,
	UpdateUserRoleRequest
} from './types';

export const settingsApi = {
	// v2.12 — multi-config DNS provider collection CRUD. Mirrors the
	// forward-auth provider pattern below. The list/view responses
	// carry no secrets; create/update send them in DNSProviderRequest
	// (blank on edit = preserve-on-edit). 409 `provider_in_use` on
	// delete carries `params.wildcards` via ApiError.params.
	listDNSProviders: (): Promise<DNSProvider[]> =>
		request<DNSProvider[]>('GET', '/settings/dns-providers'),
	getDNSProvider: (id: string): Promise<DNSProvider> =>
		request<DNSProvider>('GET', `/settings/dns-providers/${encodeURIComponent(id)}`),
	createDNSProvider: (r: DNSProviderRequest): Promise<DNSProvider> =>
		request<DNSProvider>('POST', '/settings/dns-providers', r),
	updateDNSProvider: (id: string, r: DNSProviderRequest): Promise<DNSProvider> =>
		request<DNSProvider>('PUT', `/settings/dns-providers/${encodeURIComponent(id)}`, r),
	deleteDNSProvider: (id: string): Promise<void> =>
		request<void>('DELETE', `/settings/dns-providers/${encodeURIComponent(id)}`),
	// v2.29 — provider-type registry (drives the form) and the
	// read-only connection test. An empty zone lets the backend default
	// to the first wildcard apex bound to the provider.
	listDNSProviderTypes: (): Promise<DNSProviderType[]> =>
		request<DNSProviderType[]>('GET', '/settings/dns-providers/types'),
	testDNSProvider: (id: string, zone: string): Promise<DNSProviderTestResult> =>
		request<DNSProviderTestResult>(
			'POST',
			`/settings/dns-providers/${encodeURIComponent(id)}/test`,
			{ zone },
		),

	// Step K.1 — forward-auth provider CRUD.
	listForwardAuthProviders: (): Promise<ForwardAuthProvider[]> =>
		request<ForwardAuthProvider[]>('GET', '/settings/forward-auth/providers'),
	getForwardAuthProvider: (name: string): Promise<ForwardAuthProvider> =>
		request<ForwardAuthProvider>(
			'GET',
			`/settings/forward-auth/providers/${encodeURIComponent(name)}`
		),
	createForwardAuthProvider: (r: ForwardAuthProviderRequest): Promise<ForwardAuthProvider> =>
		request<ForwardAuthProvider>('POST', '/settings/forward-auth/providers', r),
	updateForwardAuthProvider: (
		name: string,
		r: ForwardAuthProviderRequest
	): Promise<ForwardAuthProvider> =>
		request<ForwardAuthProvider>(
			'PUT',
			`/settings/forward-auth/providers/${encodeURIComponent(name)}`,
			r
		),
	deleteForwardAuthProvider: (name: string): Promise<void> =>
		request<void>('DELETE', `/settings/forward-auth/providers/${encodeURIComponent(name)}`),

	// Step O.3 — managed-domain (wildcard certificate) CRUD.
	// Viewer-accessible GET; admin-only POST + DELETE. The
	// DELETE endpoint accepts an explicit `revertTo` query
	// parameter so the operator chooses the post-revert
	// ACMEChallenge value for the covered routes (AC #21).
	listManagedDomains: (): Promise<ManagedDomainsListResponse> =>
		request<ManagedDomainsListResponse>('GET', '/settings/managed-domains'),
	createManagedDomain: (r: ManagedDomainRequest): Promise<ManagedDomain> =>
		request<ManagedDomain>('POST', '/settings/managed-domains', r),
	deleteManagedDomain: (
		apex: string,
		revertTo: ManagedDomainRevertTo
	): Promise<ManagedDomainDeleteResponse> => {
		const qs = revertTo ? `?revertTo=${encodeURIComponent(revertTo)}` : '';
		return request<ManagedDomainDeleteResponse>(
			'DELETE',
			`/settings/managed-domains/${encodeURIComponent(apex)}${qs}`
		);
	},

	// Step P.3 — auto-classify (write-back to LAPI) config.
	// GET is viewer-accessible (returns rules + credentials.
	// configured boolean). The two PUTs are admin-only:
	// /rules atomically swaps the live RuleSet; /credentials
	// recreate-and-swaps the live WatcherClient (J.4
	// preserve-on-empty-password).
	getAutomation: (): Promise<AutomationResponse> =>
		request<AutomationResponse>('GET', '/settings/automation'),
	putAutomationRules: (r: AutomationRulesRequest): Promise<AutomationRulesRequest> =>
		request<AutomationRulesRequest>('PUT', '/settings/automation/rules', r),
	putAutomationCredentials: (
		r: AutomationCredentialsRequest
	): Promise<AutomationCredentialsView> =>
		request<AutomationCredentialsView>('PUT', '/settings/automation/credentials', r),
	// Step CS.3 follow-up — DELETE wipes the stored watcher
	// row + tells the in-memory automation.Manager to drop
	// the writer. Distinct from "PUT all blank" (which emits
	// automation_rule_changed in the audit log) — DELETE
	// emits automation_reset so the deliberate "auto-writer
	// disabled" intent is traceable. Response shape mirrors
	// a fresh-install GET (configured=false + defaults).
	// Mirror of settingsApi.deleteCrowdSecSettings (CS.2.C).
	deleteAutomationCredentials: (): Promise<AutomationCredentialsView> =>
		request<AutomationCredentialsView>('DELETE', '/settings/automation/credentials'),

	// Step K.2 — OIDC config (single row, "default" key on the
	// backend). PUT preserves the clientSecret when empty (J.4
	// preserve-on-edit). The allowlist is preserved across config
	// edits server-side; mutate it via the /allowlist endpoints.
	getOIDCConfig: (): Promise<OIDCConfig> => request<OIDCConfig>('GET', '/settings/oidc'),
	putOIDCConfig: (r: OIDCConfigRequest): Promise<OIDCConfig> =>
		request<OIDCConfig>('PUT', '/settings/oidc', r),
	// Phase 2 Users-page refactor — operator-triggered discovery
	// probe. No request body (backend reads the saved config).
	testOIDCConnection: (): Promise<OIDCTestResult> =>
		request<OIDCTestResult>('POST', '/settings/oidc/test'),

	// Step K.2 — OIDC allowlist. add lower-cases the email; delete
	// is keyed by the same lower-cased email. The Sub canonicalises
	// on first login (§5.2).
	listOIDCAllowlist: (): Promise<OIDCAllowedIdentity[]> =>
		request<OIDCAllowedIdentity[]>('GET', '/settings/oidc/allowlist'),
	addOIDCAllowlist: (r: OIDCAllowlistAddRequest): Promise<OIDCAllowedIdentity> =>
		request<OIDCAllowedIdentity>('POST', '/settings/oidc/allowlist', r),
	deleteOIDCAllowlist: (email: string): Promise<void> =>
		request<void>('DELETE', `/settings/oidc/allowlist/${encodeURIComponent(email)}`),

	// Step K.2 — admin Users management. The list response omits
	// PasswordHash and surfaces OIDCSub as a boolean (oidcLinked).
	listAdminUsers: (): Promise<AdminUser[]> => request<AdminUser[]>('GET', '/admin/users'),
	/**
	 * v2.48 — create a local account.
	 *
	 * Leaving `password` empty asks Arenet to generate one, which is
	 * the default and the safe path; the response then carries it
	 * ONCE, in `generatedPassword`. Nothing returns it afterwards.
	 */
	createAdminUser: (r: CreateAdminUserRequest): Promise<CreateAdminUserResponse> =>
		request<CreateAdminUserResponse>('POST', '/admin/users', r),
	updateUserRole: (id: string, r: UpdateUserRoleRequest): Promise<AdminUser> =>
		request<AdminUser>('POST', `/admin/users/${encodeURIComponent(id)}/role`, r),
	// Users-page Phase 1 refactor — hard delete with last-admin
	// guard + session cascade (backend handler at
	// internal/api/users_admin.go:deleteAdminUser).
	deleteAdminUser: (id: string): Promise<void> =>
		request<void>('DELETE', `/admin/users/${encodeURIComponent(id)}`),

	// Phase 4 — service-account lifecycle. The create response
	// carries the plain Bearer token — shown ONCE by the modal,
	// not stored beyond its lifecycle.
	createServiceAccount: (r: CreateServiceAccountRequest): Promise<CreateServiceAccountResponse> =>
		request<CreateServiceAccountResponse>('POST', '/admin/users/service-accounts', r),
	rotateServiceAccountToken: (
		id: string,
		r: RotateServiceAccountTokenRequest = {}
	): Promise<RotateServiceAccountTokenResponse> =>
		request<RotateServiceAccountTokenResponse>(
			'POST',
			`/admin/users/service-accounts/${encodeURIComponent(id)}/rotate-token`,
			r
		),
	deleteServiceAccount: (id: string): Promise<void> =>
		request<void>('DELETE', `/admin/users/service-accounts/${encodeURIComponent(id)}`),

	// Step CS.1 — CrowdSec bouncer settings. GET returns the
	// stored row (apiKey redacted) + the configured boolean.
	// PUT persists + hot-reloads Caddy via the manager's
	// ApplyCrowdSecConfig seam (no process restart needed).
	// POST /test probes LAPI's /v1/decisions without mutating
	// state — returns ok=true on 200/204, ok=false with a
	// friendly error otherwise.
	getCrowdSecSettings: (): Promise<CrowdSecSettings> =>
		request<CrowdSecSettings>('GET', '/settings/crowdsec'),
	putCrowdSecSettings: (r: CrowdSecSettingsRequest): Promise<CrowdSecSettings> =>
		request<CrowdSecSettings>('PUT', '/settings/crowdsec', r),
	// Step CS.2 follow-up — DELETE wipes the stored row +
	// hot-reloads Caddy so the bouncer drops out of the data
	// plane. Distinct from "PUT all blank" (which also clears
	// the row but emits crowdsec_updated, not crowdsec_reset)
	// — DELETE is the operator-deliberate "disable" path
	// surfaced by the Réinitialiser button in the Settings UI.
	// Response shape is the same as GET on a fresh install
	// (configured=false + defaults), so the UI can re-render
	// without a separate GET round-trip.
	deleteCrowdSecSettings: (): Promise<CrowdSecSettings> =>
		request<CrowdSecSettings>('DELETE', '/settings/crowdsec'),
	testCrowdSecConnection: (r: CrowdSecTestRequest): Promise<CrowdSecTestResponse> =>
		request<CrowdSecTestResponse>('POST', '/settings/crowdsec/test', r),

	// Brick 2 — MaxMind GeoIP account credentials. GET returns the
	// stored row (licenseKey redacted) + the configured boolean,
	// mirroring the CrowdSec/OIDC pattern. PUT preserves the
	// licenseKey when empty (preserve-on-edit). DELETE wipes the
	// row. POST /test probes the real MaxMind API without mutating
	// state — useStored=true reuses the saved credentials.
	getMaxMind: (): Promise<MaxMindConfig> => request<MaxMindConfig>('GET', '/settings/maxmind'),
	putMaxMind: (r: MaxMindRequest): Promise<MaxMindConfig> =>
		request<MaxMindConfig>('PUT', '/settings/maxmind', r),
	deleteMaxMind: (): Promise<void> => request<void>('DELETE', '/settings/maxmind'),
	testMaxMind: (r: MaxMindRequest & { useStored?: boolean }): Promise<MaxMindTestResult> =>
		request<MaxMindTestResult>('POST', '/settings/maxmind/test', r),

	// Step K.3 — backup / restore. The redacted export is a plain
	// download link. The export WITH secrets (v2.31) is encrypted
	// with a passphrase: a POST whose response is the file (Blob).
	// An encrypted backup is restored with the passphrase in the
	// X-Arenet-Backup-Passphrase header, base64 of its UTF-8 bytes
	// (fetch rejects non-Latin-1 header values).
	// v2.35 — post-apply route check toggle.
	getRouteCheck: (): Promise<{ enabled: boolean }> => request<{ enabled: boolean }>('GET', '/settings/route-check'),
	putRouteCheck: (enabled: boolean): Promise<{ enabled: boolean }> =>
		request<{ enabled: boolean }>('PUT', '/settings/route-check', { enabled }),
	// v2.50 — the HTTP access log CrowdSec parses. `resolvedPath` is
	// what acquisition must point at: it carries the per-install default
	// the operator cannot work out from the UI alone.
	getAccessLog: (): Promise<AccessLogSettings> =>
		request<AccessLogSettings>('GET', '/settings/access-log'),
	putAccessLog: (r: AccessLogRequest): Promise<AccessLogSettings> =>
		request<AccessLogSettings>('PUT', '/settings/access-log', r),
	// v2.33 — scheduled backups.
	getBackupSchedule: (): Promise<BackupSchedule> =>
		request<BackupSchedule>('GET', '/settings/backup-schedule'),
	putBackupSchedule: (r: BackupScheduleRequest): Promise<BackupSchedule> =>
		request<BackupSchedule>('PUT', '/settings/backup-schedule', r),
	runBackupNow: (): Promise<BackupRunResult> => request<BackupRunResult>('POST', '/admin/backups/run', {}),
	listBackups: (): Promise<BackupFileList> => request<BackupFileList>('GET', '/admin/backups'),
	backupDownloadURL: (name: string): string => `/api/v1/admin/backups/${encodeURIComponent(name)}`,
	deleteBackup: (name: string): Promise<void> =>
		request<void>('DELETE', `/admin/backups/${encodeURIComponent(name)}`),
	restoreBackupFile: (name: string): Promise<RestoreReport> =>
		request<RestoreReport>('POST', `/admin/backups/${encodeURIComponent(name)}/restore`, {}),
	exportBackupURL: (): string => '/api/v1/admin/backup',
	exportEncryptedBackup: (passphrase: string): Promise<Blob> =>
		request<Blob>('POST', '/admin/backup', { passphrase }, { asBlob: true }),
	postRestore: (
		body: unknown,
		opts: { allowIncompleteRestore?: boolean; allowEmptyUsers?: boolean; passphrase?: string }
	): Promise<RestoreReport> => {
		const params = new URLSearchParams();
		if (opts.allowIncompleteRestore) params.set('allow-incomplete-restore', 'true');
		if (opts.allowEmptyUsers) params.set('allow-empty-users', 'true');
		const qs = params.toString();
		const url = qs ? `/admin/restore?${qs}` : '/admin/restore';
		const headers = opts.passphrase
			? { 'X-Arenet-Backup-Passphrase': utf8ToBase64(opts.passphrase) }
			: undefined;
		return request<RestoreReport>('POST', url, body, { headers });
	}
};

/** Scheduled backups (v2.33) — GET/PUT /settings/backup-schedule. */
export type BackupFrequency = 'daily' | 'weekly';
export type BackupEmailMode = 'never' | 'each' | 'weekly';

export interface BackupScheduleStatus {
	lastRunAt?: string;
	lastStatus?: 'ok' | 'error';
	lastError?: string;
	lastFile?: string;
	lastEmailAt?: string;
	lastEmailError?: string;
}

export interface BackupSchedule {
	enabled: boolean;
	frequency: BackupFrequency;
	time: string;
	weekday: number;
	keep: number;
	dir: string;
	effectiveDir: string;
	passphraseSet: boolean;
	emailMode: BackupEmailMode;
	emailChannelId: string;
	alertChannelIds: string[];
	timeZone: string;
	nextRunAt?: string;
	status: BackupScheduleStatus;
}

/** PUT body; an empty passphrase keeps the stored one. */
export interface BackupScheduleRequest {
	enabled: boolean;
	frequency: BackupFrequency;
	time: string;
	weekday: number;
	keep: number;
	dir: string;
	passphrase: string;
	emailMode: BackupEmailMode;
	emailChannelId: string;
	alertChannelIds: string[];
}

export interface BackupRunResult {
	file?: string;
	size: number;
	pruned: number;
	emailed: boolean;
	emailError?: string;
}

export interface BackupFile {
	name: string;
	size: number;
	modTime: string;
}

export interface BackupFileList {
	dir: string;
	files: BackupFile[];
}

/** Minimum backup passphrase length (mirrors backup.MinPassphraseLen). */
export const MIN_BACKUP_PASSPHRASE_LEN = 12;

/** Base64 of the UTF-8 bytes of s (btoa alone only handles Latin-1). */
export function utf8ToBase64(s: string): string {
	let bin = '';
	for (const b of new TextEncoder().encode(s)) bin += String.fromCharCode(b);
	return btoa(bin);
}

/** True when a parsed backup file is passphrase-encrypted (v2.31). */
export function isEncryptedBackup(parsed: unknown): boolean {
	return typeof parsed === 'object' && parsed !== null && 'encryption' in parsed;
}

// RestoreReport is the wire shape returned by POST /admin/restore.
// Mirrors the Go restoreResponse struct in
// internal/api/backup_handlers.go.
export interface RestoreReport {
	routesImported: number;
	usersImported: number;
	dnsProvidersImported: number;
	forwardAuthProvidersImported: number;
	oidcConfigImported: boolean;
	maxmindConfigImported: boolean;
	externalCertificatesImported: number;
	// v2.29 extras — false / 0 when restoring a pre-v2.29 backup.
	extrasImported: boolean;
	managedDomainsImported: number;
	errorTemplatesImported: number;
	alertChannelsImported: number;
	alertRulesImported: number;
	apiTokensImported: number;
	sentinelsInheritedTotal: number;
	sentinelsUnresolvedTotal: number;
	incompleteRows: number;
}
