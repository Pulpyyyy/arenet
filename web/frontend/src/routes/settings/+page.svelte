<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Settings (Step F §8.6 / §9). Three sections in a single page:

    1. Account  — display name + username (read-only), HIBP status
                  indicator (discreet — the compromised banner lives
                  in +layout.svelte, this is just an inline mirror),
                  Change password button.
    2. Appearance — theme Toggle (Chunk 1.6 wiring preserved),
                  Reduce motion read-only indicator.
    3. Sessions — DataTable (lands in Chunk 6.2).
    4. About — version / license / source (lands in Chunk 6.3).

  This file replaces the Chunk 1.6 placeholder (debug strip + footer
  note removed). The wrapper max-w-2xl is preserved — Settings is a
  configuration page, not a dashboard, so a column layout reads
  better than full-bleed.
-->
<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { afterNavigate } from '$app/navigation';
	import { prefersReducedMotion } from 'svelte/motion';
	import { auth } from '$lib/stores/auth.svelte';
	import { theme, type Theme } from '$lib/stores/theme.svelte';
	import { language, type Language } from '$lib/stores/language.svelte';
	import { t } from '$lib/i18n';
	import { pushToast } from '$lib/stores/toast';
	import { authApi, type Session } from '$lib/api/auth';
	import { settingsApi } from '$lib/api/settings';
	import { systemApi } from '$lib/api/system';
	import {
		AUTOMATION_SOURCES,
		AUTOMATION_SOURCE_LABELS,
		FORWARD_AUTH_PROVIDER_KINDS,
		type AutomationCredentialsView,
		type AutomationRule,
		type AutomationRuleSet,
		type AutomationSource,
		type ForwardAuthProvider,
		type ForwardAuthProviderKind
	} from '$lib/api/types';
	import { ApiError, type AccessLogSettings } from '$lib/api/types';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import { relativeTime } from '$lib/utils/audit-format';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Tabs from '$lib/components/Tabs.svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import ChangePasswordModal from '$lib/components/ChangePasswordModal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DNSProvidersSection from '$lib/components/settings/DNSProvidersSection.svelte';
	import SystemInfoSection from '$lib/components/settings/SystemInfoSection.svelte';
	import UpdatesSection from '$lib/components/settings/UpdatesSection.svelte';
	import GeoIPSettingsSection from '$lib/components/settings/GeoIPSettingsSection.svelte';
	import OIDCSettingsSection from '$lib/components/OIDCSettingsSection.svelte';
	import CrowdSecSettingsSection from '$lib/components/CrowdSecSettingsSection.svelte';
	import BackupSection from '$lib/components/BackupSection.svelte';
	import ScheduledBackupsSection from '$lib/components/ScheduledBackupsSection.svelte';
	import RouteCheckSection from '$lib/components/RouteCheckSection.svelte';
	import ServerPositionSection from '$lib/components/ServerPositionSection.svelte';

	// v2.9.12 i18n Phase 2 — theme toggle options are derived from
	// the active language so the on-screen labels switch live with
	// the Language toggle next to them. Reading language.current
	// registers the reactive dependency.
	const options = $derived<
		[
			{ value: Theme; label: string },
			{ value: Theme; label: string }
		]
	>(
		language.current
			? [
					{ value: 'dark', label: t('settings.themeDark') },
					{ value: 'light', label: t('settings.themeLight') }
				]
			: [
					{ value: 'dark', label: 'Dark' },
					{ value: 'light', label: 'Light' }
				]
	);

	// Local ChangePasswordModal instance (Decision: Option B from the
	// Chunk 6 brief). The layout-shell instance handles the
	// compromised-password banner flow; this one is wired to the
	// explicit "Change password" button in the Account section.
	// Two instances of the same component, each with its own `open`
	// state — the component supports that by design.
	let changePasswordOpen = $state(false);

	async function onThemeChange(v: Theme): Promise<void> {
		try {
			await theme.set(v);
		} catch (_) {
			// theme store already reverted + toast emitted; just swallow
			// here so the smoke session sees no unhandled rejection.
		}
	}

	// v2.9.11 i18n Phase 1 — language selector. Same shape as the
	// theme toggle: 2-option Toggle, store handles revert + toast on
	// failure, this handler just swallows the rejection to keep the
	// browser console clean during smoke testing.
	//
	// v2.9.12 — option labels are language names rendered in their
	// own language ("English" / "Français") regardless of the
	// active locale, mirroring how OS-level locale pickers behave.
	// Keeping them as a $derived is symmetric with the theme
	// options above; the values themselves don't change.
	const languageOptions = $derived<
		[
			{ value: Language; label: string },
			{ value: Language; label: string }
		]
	>(
		language.current
			? [
					{ value: 'en', label: t('settings.languageEnglish') },
					{ value: 'fr', label: t('settings.languageFrench') }
				]
			: [
					{ value: 'en', label: 'English' },
					{ value: 'fr', label: 'Français' }
				]
	);

	async function onLanguageChange(v: Language): Promise<void> {
		try {
			await language.set(v);
		} catch (_) {
			// language store already reverted + toast emitted.
		}
	}

	// --- Sessions section (Step F Chunk 6.2 / spec §9.2) -------------------

	let sessions = $state<Session[]>([]);
	let sessionsLoading = $state(true);
	let sessionsError = $state<string | null>(null);

	async function loadSessions(): Promise<void> {
		sessionsLoading = true;
		sessionsError = null;
		try {
			const res = await authApi.listSessions();
			sessions = res.sessions;
		} catch (err) {
			sessionsError = err instanceof Error ? err.message : 'Failed to load sessions';
		} finally {
			sessionsLoading = false;
		}
	}

	// Revoke confirmation state — replaces the native confirm() that
	// broke the Linear-like visual consistency. The ConfirmDialog
	// (Chunk 6.4) wraps Modal with a standard yes/no surface.
	let revokeConfirmOpen = $state(false);
	let revokeTarget = $state<Session | null>(null);

	function onRevokeClick(s: Session): void {
		// Hard safety even though the button is `disabled` on isCurrent —
		// keyboard activation on a disabled button is browser-dependent.
		if (s.isCurrent) return;
		revokeTarget = s;
		revokeConfirmOpen = true;
	}

	async function confirmRevoke(): Promise<void> {
		const target = revokeTarget;
		if (!target) return;
		try {
			await authApi.deleteSession(target.id);
			// Optimistic local filter — no re-fetch unless we hit an error.
			// The server is the source of truth, but a session listing
			// rarely diverges in the ~50 ms window between delete and
			// next request.
			sessions = sessions.filter((x) => x.id !== target.id);
			pushToast('Session revoked', 'success');
			revokeConfirmOpen = false;
			revokeTarget = null;
		} catch (_) {
			pushToast('Failed to revoke session', 'danger');
			// Re-fetch on error to recover the truth — the delete might
			// have partially succeeded or the local list might be stale.
			// Keep the dialog open so the user can retry if they want.
			void loadSessions();
		}
	}

	function truncate(s: string, max: number): string {
		if (s.length <= max) return s;
		return s.slice(0, max) + '…';
	}

	// --- DNS providers section (v2.12) -----------------------------------
	//
	// The pre-v2.12 singleton OVH credentials form + its DNS-01
	// consistency bandeau were replaced by the self-contained
	// DNSProvidersSection component (multi-config collection: table +
	// add/edit modal + delete). It owns its own load / state, so the
	// page no longer carries any dnsProvider* state here.

	// --- SSL / Certificates state — MIGRATED to /certs (#R-6 Pack A) ---------
	//
	// The managed-domain CRUD UI moved to web/frontend/src/routes/
	// certs/+page.svelte. State, helpers, and the delete modal
	// were lifted verbatim — see backlog-step-r.md §1 #R-6.
	// The DNS provider OVH credentials section above remains in
	// /settings since credentials are instance-level secrets,
	// distinct from per-apex managed-domain declarations.

	// --- Security Automation section (Step P.4 / spec D8.A) ------------------

	// Rule set (one row per Source) + credentials view. The
	// load fetches both in one GET; the persistence path is
	// two distinct PUTs so an operator who edits only rules
	// doesn't have to re-enter their watcher password.
	let automationRules = $state<AutomationRuleSet>({
		rules: {} as Record<AutomationSource, AutomationRule>
	});
	let automationCreds = $state<AutomationCredentialsView>({
		lapiUrl: '',
		machineId: '',
		configured: false
	});
	let automationLoading = $state(true);
	let automationLoadError = $state<string | null>(null);

	// Rules form working copy. The operator edits in this
	// shape (rule fields as nanosecond numbers — matches the
	// wire). On save we ship the full set; backend validate
	// rejects partial.
	let rulesDraft = $state<Record<AutomationSource, AutomationRule>>(
		{} as Record<AutomationSource, AutomationRule>
	);
	let rulesSubmitting = $state(false);
	let rulesFormError = $state<string | null>(null);

	// Credentials form. Empty password triggers the J.4
	// preserve-on-edit path (server keeps stored value).
	// Operator-visible placeholder when configured:
	// "leave blank to keep current" (P.3 commit forward
	// note #2).
	let credsForm = $state({ lapiUrl: '', machineId: '', password: '' });
	let credsSubmitting = $state(false);
	let credsFormError = $state<string | null>(null);

	async function loadAutomation(): Promise<void> {
		automationLoading = true;
		automationLoadError = null;
		try {
			const res = await settingsApi.getAutomation();
			automationRules = res.rules;
			automationCreds = res.credentials;
			// Seed the working copy from the loaded set;
			// re-runs on every load so the operator sees
			// the live state, not a stale draft.
			rulesDraft = { ...res.rules.rules };
			credsForm = {
				lapiUrl: res.credentials.lapiUrl,
				machineId: res.credentials.machineId,
				password: ''
			};
		} catch (err) {
			automationLoadError =
				err instanceof Error ? err.message : 'Failed to load automation config';
		} finally {
			automationLoading = false;
		}
	}

	async function submitAutomationRules(): Promise<void> {
		rulesSubmitting = true;
		rulesFormError = null;
		try {
			await settingsApi.putAutomationRules({
				rules: { rules: rulesDraft }
			});
			pushToast('Automation rules saved', 'success');
			await loadAutomation();
		} catch (err) {
			rulesFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			rulesSubmitting = false;
		}
	}

	async function submitAutomationCredentials(): Promise<void> {
		credsSubmitting = true;
		credsFormError = null;
		try {
			const res = await settingsApi.putAutomationCredentials({
				lapiUrl: credsForm.lapiUrl,
				machineId: credsForm.machineId,
				password: credsForm.password
			});
			automationCreds = res;
			pushToast(
				res.configured
					? 'Automation credentials saved'
					: 'Automation credentials cleared',
				'success'
			);
			credsForm.password = '';
		} catch (err) {
			credsFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			credsSubmitting = false;
		}
	}

	// Step CS.3 follow-up — Reset Security Automation. Mirror
	// of the CrowdSec Reset button (CS.2.C f1fe919): wipes
	// the watcher row + the in-memory writer via DELETE,
	// emits the audit row automation_reset (distinct from
	// automation_rule_changed). ConfirmDialog gates the
	// destructive intent. Operator-recommended path to
	// disable the auto-classifier cleanly; the legacy
	// "PUT all blank" still works but is less discoverable
	// in /audit.
	let automationResetConfirmOpen = $state(false);
	function openAutomationResetConfirm(): void {
		automationResetConfirmOpen = true;
	}
	async function confirmAutomationReset(): Promise<void> {
		try {
			const next = await settingsApi.deleteAutomationCredentials();
			automationCreds = next;
			credsForm.lapiUrl = next.lapiUrl;
			credsForm.machineId = next.machineId;
			credsForm.password = '';
			credsFormError = null;
			pushToast(t('settingsSubcards.automationResetToastSuccess'), 'success');
			automationResetConfirmOpen = false;
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(t('settingsSubcards.automationResetToastFailed', { err: msg }), 'danger');
			// Keep the dialog open so the operator can retry.
		}
	}

	// Helper: ns ↔ "60s" / "4h" / "7d" round-trip. Keep the
	// UI numbers operator-friendly without abandoning the
	// wire's nanosecond format.
	function nsToHuman(ns: number): string {
		if (ns <= 0) return '0s';
		const s = Math.floor(ns / 1e9);
		if (s % 86400 === 0) return `${s / 86400}d`;
		if (s % 3600 === 0) return `${s / 3600}h`;
		if (s % 60 === 0) return `${s / 60}m`;
		return `${s}s`;
	}
	function humanToNs(s: string): number {
		const m = s.trim().match(/^(\d+)\s*([smhd]?)$/);
		if (!m) return 0;
		const n = Number(m[1]);
		switch (m[2]) {
			case 'd': return n * 86400 * 1e9;
			case 'h': return n * 3600 * 1e9;
			case 'm': return n * 60 * 1e9;
			default:  return n * 1e9; // 's' or empty = seconds
		}
	}

	// Per-rule field accessors. Svelte 5 runes work better
	// with explicit getter / setter than direct bind:value
	// on a nested map field.
	function getRule(s: AutomationSource): AutomationRule {
		return rulesDraft[s] ?? {
			enabled: false, threshold: 0, window_ns: 0, duration_ns: 0, cooldown_ns: 0
		};
	}
	function setRuleField<K extends keyof AutomationRule>(
		s: AutomationSource,
		key: K,
		value: AutomationRule[K]
	): void {
		const r = getRule(s);
		rulesDraft = { ...rulesDraft, [s]: { ...r, [key]: value } };
	}

	// --- Forward-auth providers section (Step K.1 §5.1) ----------------------

	// List + an inline form for create-or-edit. The form keeps an
	// `editingName` slot: null = create mode (POST), non-null =
	// edit mode (PUT on /providers/{name}). Same client-secret
	// preserve-on-edit pattern as the DNS provider above (empty
	// secret on PUT keeps the stored value).
	let fwdAuthList = $state<ForwardAuthProvider[]>([]);
	let fwdAuthLoading = $state(true);
	let fwdAuthListError = $state<string | null>(null);

	let fwdAuthEditingName = $state<string | null>(null);
	let fwdAuthForm = $state({
		name: '',
		kind: 'authelia' as ForwardAuthProviderKind,
		verifyUrl: '',
		authRequestUri: '/api/authz/forward-auth',
		copyHeaders: 'Remote-User, Remote-Email',
		clientSecret: '',
		authPassthroughPrefix: '',
		rewriteVerifyHost: false
	});
	let fwdAuthFormOpen = $state(false);
	let fwdAuthSubmitting = $state(false);
	let fwdAuthFormError = $state<string | null>(null);
	let fwdAuthDeleteError = $state<string | null>(null);
	// Edit-mode flag for the placeholder pattern on the secret input.
	let fwdAuthEditingSecretSet = $state(false);

	async function loadForwardAuthProviders(): Promise<void> {
		fwdAuthLoading = true;
		fwdAuthListError = null;
		try {
			fwdAuthList = await settingsApi.listForwardAuthProviders();
		} catch (err) {
			fwdAuthListError =
				err instanceof Error ? err.message : 'Failed to load forward-auth providers';
		} finally {
			fwdAuthLoading = false;
		}
	}

	function openFwdAuthCreate(): void {
		fwdAuthEditingName = null;
		fwdAuthEditingSecretSet = false;
		fwdAuthForm = {
			name: '',
			kind: 'authelia',
			verifyUrl: '',
			authRequestUri: '/api/authz/forward-auth',
			copyHeaders: 'Remote-User, Remote-Email',
			clientSecret: '',
			authPassthroughPrefix: '',
			rewriteVerifyHost: false
		};
		fwdAuthFormError = null;
		fwdAuthFormOpen = true;
	}

	function openFwdAuthEdit(p: ForwardAuthProvider): void {
		fwdAuthEditingName = p.name;
		fwdAuthEditingSecretSet = p.clientSecretSet;
		fwdAuthForm = {
			name: p.name,
			kind: p.kind,
			verifyUrl: p.verifyUrl,
			authRequestUri: p.authRequestUri,
			copyHeaders: (p.copyHeaders ?? []).join(', '),
			clientSecret: '',
			authPassthroughPrefix: p.authPassthroughPrefix ?? '',
			rewriteVerifyHost: p.rewriteVerifyHost ?? false
		};
		fwdAuthFormError = null;
		fwdAuthFormOpen = true;
	}

	async function submitFwdAuth(): Promise<void> {
		fwdAuthSubmitting = true;
		fwdAuthFormError = null;
		try {
			const passthrough = fwdAuthForm.authPassthroughPrefix.trim();
			const req = {
				name: fwdAuthForm.name.trim(),
				kind: fwdAuthForm.kind,
				verifyUrl: fwdAuthForm.verifyUrl.trim(),
				authRequestUri: fwdAuthForm.authRequestUri.trim(),
				copyHeaders: fwdAuthForm.copyHeaders
					.split(',')
					.map((h) => h.trim())
					.filter((h) => h.length > 0),
				clientSecret: fwdAuthForm.clientSecret,
				...(passthrough ? { authPassthroughPrefix: passthrough } : {}),
				...(fwdAuthForm.rewriteVerifyHost ? { rewriteVerifyHost: true } : {})
			};
			if (fwdAuthEditingName === null) {
				await settingsApi.createForwardAuthProvider(req);
				pushToast('Forward-auth provider created', 'success');
			} else {
				await settingsApi.updateForwardAuthProvider(fwdAuthEditingName, req);
				pushToast('Forward-auth provider updated', 'success');
			}
			fwdAuthFormOpen = false;
			await loadForwardAuthProviders();
		} catch (err) {
			fwdAuthFormError = err instanceof ApiError ? err.message : String(err);
		} finally {
			fwdAuthSubmitting = false;
		}
	}

	async function deleteFwdAuth(name: string): Promise<void> {
		fwdAuthDeleteError = null;
		try {
			await settingsApi.deleteForwardAuthProvider(name);
			pushToast('Forward-auth provider deleted', 'success');
			await loadForwardAuthProviders();
		} catch (err) {
			fwdAuthDeleteError = err instanceof ApiError ? err.message : String(err);
		}
	}

	// License URL ref resolution (Step G G.2).
	// Version for the About card. The authoritative source is the
	// backend's main.version (ldflag-injected), exposed by
	// GET /api/v1/system/version → `current`. We prefer it over the
	// build-time VITE_APP_VERSION because the latter comes from
	// `git describe` at frontend-build time, which yields "unknown" in
	// the Docker image (.git is excluded from the build context) even
	// though the binary knows its real version. VITE_APP_VERSION is the
	// resilience fallback when the API hasn't answered yet.
	const appVersion = import.meta.env.VITE_APP_VERSION;
	let apiVersion = $state<string>('');
	const displayVersion = $derived(apiVersion || appVersion);

	// GitHub ref for the License link. `git describe --tags --always`
	// produces three shapes:
	//   - clean tag   → `v0.4.0-step-f`           (valid GitHub ref)
	//   - describe    → `v0.4.0-step-f-3-g7471243` (NOT a ref → 404)
	//   - bare sha    → `7471243`                  (NOT a ref → 404)
	// Also `unknown` when git is unavailable (vite.config.ts fallback).
	// The API `current` (main.version) is a clean tag when built from a
	// release, so prefer it; only a clean tag can be used as a GitHub ref,
	// every other shape falls back to `main` to avoid the 404.
	const refCandidate = $derived(apiVersion || appVersion);
	const licenseRef = $derived(
		/^v[^\s]+$/.test(refCandidate) && !/-\d+-g[0-9a-f]{7,40}$/.test(refCandidate)
			? refCandidate
			: 'main'
	);

	async function loadVersion(): Promise<void> {
		try {
			const v = await systemApi.getVersion();
			if (v.current) apiVersion = v.current;
		} catch {
			// Leave apiVersion empty → displayVersion falls back to
			// VITE_APP_VERSION. No toast: the About card is passive.
		}
	}

	onMount(() => {
		void loadSessions();
		// DNS providers now load inside DNSProvidersSection (v2.12).
		void loadForwardAuthProviders();
		// loadManagedDomains() moved to /certs in #R-6 Pack A.
		void loadAutomation();
		void loadAccessLog();
		void loadVersion();
	});

	// #R-CS2C-anchor-link follow-up — SPA hash scroll.
	// On initial /settings#security-automation hard-load the
	// browser tries the fragment BEFORE Svelte hydrates the
	// route, so the anchor isn't in the DOM yet and the
	// browser silently gives up. By the time the section
	// renders, no scroll happens and the operator lands at
	// the top of the page. afterNavigate fires after the
	// route is mounted (covers both hard-load and SPA-nav
	// from the CrowdSec Decisions panel + BanIPModal CTAs).
	// We await tick() to let Svelte commit the first render
	// pass, then scrollIntoView the target if it exists.
	//
	// Loading branches inside the section render their
	// spinner first; the anchor wrapper itself is
	// unconditional so the target IS in the DOM after the
	// first tick. When the data lands and the spinner
	// swaps for the form, the viewport position adjusts
	// naturally to follow the now-grown section.
	// v2.41 — the page is now five tabs, so a hash can name either a
	// tab ("#security") or a card anchor inside one ("#oidc-config").
	// Both must land the operator on the right tab: the deep links
	// from the CrowdSec Decisions panel and the BanIPModal CTA point
	// at card anchors and predate the tabs.
	type SettingsTab = 'account' | 'security' | 'network' | 'backups' | 'system';
	// tl reads language.current so the new v2.50 strings re-render on a
	// language switch, like the `language.current && t(...)` guards used
	// throughout this page.
	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	// --- v2.50 access log ------------------------------------------
	//
	// Off by default and that is the point: the file records every
	// visitor's IP and every URL they asked for. What it buys is that
	// CrowdSec can finally detect something about THIS host — before
	// this, Arenet emitted no access log at all, so an agent beside it
	// only ever enforced the community blocklist.
	let accessLog = $state<AccessLogSettings | null>(null);
	let accessLogLoading = $state(true);
	let accessLogSaving = $state(false);
	let accessLogError = $state<string | null>(null);
	// Draft fields, so a failed save does not leave the form showing
	// values the server rejected.
	let alEnabled = $state(false);
	let alPath = $state('');
	let alRollSizeMB = $state(10);
	let alRollKeep = $state(5);
	let alCompress = $state(true);
	// v2.56 — the redaction list, edited as one comma-separated line.
	// A list of names is what it is; a row editor would be four clicks to
	// add "code".
	let alRedactInput = $state('');

	// The number the operator actually wants: how big can this get.
	const alCeilingMB = $derived(alRollSizeMB * (alRollKeep + 1));

	async function loadAccessLog(): Promise<void> {
		accessLogLoading = true;
		accessLogError = null;
		try {
			const cfg = await settingsApi.getAccessLog();
			accessLog = cfg;
			alEnabled = cfg.enabled;
			alPath = cfg.path ?? '';
			alRollSizeMB = cfg.rollSizeMB ?? 10;
			alRollKeep = cfg.rollKeep ?? 5;
			alCompress = cfg.compress ?? true;
			alRedactInput = (cfg.redactQueryParams ?? []).join(', ');
		} catch (err) {
			accessLogError = serverErrorMessage(err);
		} finally {
			accessLogLoading = false;
		}
	}

	/** Splits the redaction field on commas or whitespace. */
	function parseRedactList(raw: string): string[] {
		return raw
			.split(/[\s,;]+/)
			.map((s) => s.trim())
			.filter((s) => s.length > 0);
	}

	async function saveAccessLog(): Promise<void> {
		accessLogSaving = true;
		accessLogError = null;
		try {
			accessLog = await settingsApi.putAccessLog({
				enabled: alEnabled,
				path: alPath.trim() || undefined,
				rollSizeMB: alRollSizeMB,
				rollKeep: alRollKeep,
				compress: alCompress,
				// Always sent, so clearing the field is honoured. Omitting
				// it would mean "keep the defaults" and silently put back
				// the redaction the operator just removed.
				redactQueryParams: parseRedactList(alRedactInput)
			});
			// Re-read what the server stored: it normalises zeros to the
			// defaults, and resolvedPath only exists server-side.
			alPath = accessLog.path ?? '';
			alRollSizeMB = accessLog.rollSizeMB ?? 10;
			alRollKeep = accessLog.rollKeep ?? 5;
			alRedactInput = (accessLog.redactQueryParams ?? []).join(', ');
			pushToast(tl('settings.accessLog.saved'), 'success');
		} catch (err) {
			accessLogError = serverErrorMessage(err);
		} finally {
			accessLogSaving = false;
		}
	}

	const TAB_IDS: SettingsTab[] = ['account', 'security', 'network', 'backups', 'system'];
	const ANCHOR_TAB: Record<string, SettingsTab> = {
		'security-automation': 'security',
		'oidc-config': 'security',
		'dns-providers': 'network'
	};

	let activeTab = $state<SettingsTab>('account');

	const settingsTabs = $derived(
		TAB_IDS.map((id) => ({
			id,
			label: (language.current && t(`settings.tab.${id}`)) as string,
			testId: `settings-tab-${id}`
		}))
	);

	// The tab lives in the URL hash so a category stays linkable.
	// replaceState, not a hash assignment: assigning window.location
	// .hash would re-trigger the browser's own fragment scroll.
	function onTabChange(next: string): void {
		if (typeof window === 'undefined') return;
		window.history.replaceState(null, '', `#${next}`);
		window.scrollTo({ top: 0, behavior: 'smooth' });
	}

	afterNavigate(async () => {
		await tick();
		const hash = window.location.hash.slice(1);
		if (!hash) return;
		if ((TAB_IDS as string[]).includes(hash)) {
			activeTab = hash as SettingsTab;
			return;
		}
		const tab = ANCHOR_TAB[hash];
		if (tab) activeTab = tab;
		// The card only exists once its tab is rendered.
		await tick();
		const target = document.getElementById(hash);
		if (target instanceof Element) {
			target.scrollIntoView({ behavior: 'smooth', block: 'start' });
		}
	});
</script>

<svelte:head>
	<title>Settings — Arenet</title>
</svelte:head>

<div class="mx-auto max-w-5xl">
	<PageHeader
		eyebrow={language.current && t('settings.eyebrow')}
		title={language.current && t('pageTitles.settings')}
		subtitle={language.current && t('settings.subtitle')}
	/>

	<!-- Asymmetric layout (Chunk 6.5 smoke fix):
	     - Row 1: 2-column grid (lg+) → Account + Appearance.
	       Both are form-narrow Cards (short labels, short values),
	       fit comfortably in 480 px columns.
	     - Row 2: full-width → Sessions DataTable.
	       Needs horizontal real estate for IP + UA + timestamp
	       columns; 480 px wraps it to 7+ lines per row (smoke fail).
	     - Row 3: full-width → About.
	       Short content, intentionally aerated as a "footer-meta"
	       section that closes the page.
	     The 6.4 attempt put everything in a single 2-col grid which
	     compressed Sessions to illegibility — this asymmetric form
	     is the corrective. -->

	<!-- v2.41 — the fifteen settings cards used to be stacked in one
	     long scroll. They are now grouped into five categories behind
	     the app's own Tabs component (the one /security already uses),
	     on the horizontal axis: the left sidebar stays the only
	     vertical navigation, so the two are never confused. The tab is
	     carried in the URL hash, and a deep link to a card's anchor
	     (#security-automation, #oidc-config, #dns-providers) still
	     opens the right tab and scrolls to it. -->
	<Tabs bind:value={activeTab} tabs={settingsTabs} ariaLabel={language.current && t('settings.tabsAria')} onChange={onTabChange} />

	<div class="mt-6">
		{#if activeTab === 'account'}
			<!-- ROW 1 — Account + Appearance (2-col on lg+, 1-col below) -->
			<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
				<!-- ACCOUNT SECTION -->
				<Card padding="p-6">
					<header class="border-b border-border-subtle pb-3 mb-4">
						<h2 class="text-xl font-semibold">
							{language.current && t('settings.accountSection')}
						</h2>
					</header>

					<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-3 text-sm">
						<dt class="text-secondary">Display name</dt>
						<dd class="text-primary">{auth.user?.displayName ?? '—'}</dd>

						<dt class="text-secondary">Username</dt>
						<dd class="text-primary font-mono">{auth.user?.username ?? '—'}</dd>

						<dt class="text-secondary">Password security</dt>
						<dd>
							<!-- Discreet inline indicator — the compromised banner
							     in +layout.svelte handles the urgent attention
							     path; this is just a mirror so the user can read
							     their breach status without scrolling to the top.
							     Chunk 6.4: wording switched from HIBP jargon to
							     user-friendly equivalents. -->
							{#if auth.user?.passwordCompromised}
								<span class="text-down">Found in known breaches — change required</span>
							{:else if auth.user?.hibpCheckStatus === 'clean'}
								<span class="text-up">Not found in known breaches</span>
							{:else if auth.user?.hibpCheckStatus === 'pending'}
								<span class="text-muted">Verification in progress</span>
							{:else if auth.user?.hibpCheckStatus === 'skipped'}
								<span class="text-muted">Verification skipped</span>
							{:else}
								<span class="text-muted">Status unknown</span>
							{/if}
						</dd>
					</dl>

					<div class="mt-6">
						<Button variant="secondary" onclick={() => (changePasswordOpen = true)}>
							{language.current && t('settings.changePassword')}
						</Button>
					</div>
				</Card>

				<!-- APPEARANCE SECTION -->
				<Card padding="p-6">
					<header class="border-b border-border-subtle pb-3 mb-4">
						<!-- v2.9.12 i18n Phase 2 — section + row labels resolved
						     via t(). Reading language.current registers the
						     reactive dependency on each surface. -->
						<h2 class="text-xl font-semibold">
							{language.current && t('settings.appearanceSection')}
						</h2>
					</header>

					<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-4 text-sm items-center">
						<dt class="text-secondary">{language.current && t('settings.themeLabel')}</dt>
						<dd>
							<Toggle
								ariaLabel={language.current && t('settings.themeLabel')}
								{options}
								value={theme.current}
								disabled={theme.isApplying}
								onchange={onThemeChange}
							/>
						</dd>

						<!--
							v2.9.11 i18n Phase 1 — Language selector. Symmetric to
							the theme toggle above (same component, same handler
							shape). Round-trips through POST /auth/me/language and
							refreshes the arenet_language cookie so the FOUC
							bootstrap picks up the new value on the next paint.
						-->
						<dt class="text-secondary">{language.current && t('settings.languageLabel')}</dt>
						<dd>
							<Toggle
								ariaLabel={language.current && t('settings.languageLabel')}
								options={languageOptions}
								value={language.current}
								disabled={language.isApplying}
								onchange={onLanguageChange}
							/>
						</dd>

						<dt class="text-secondary">{language.current && t('settings.reduceMotion')}</dt>
						<dd class="text-primary">
							{language.current &&
								(prefersReducedMotion.current
									? t('settings.reduceMotionEnabled')
									: t('settings.reduceMotionDisabled'))}
							<span class="text-muted ml-2 text-xs">
								{language.current && t('settings.reduceMotionHint')}
							</span>
						</dd>
					</dl>
				</Card>
			</div>
			<!-- ROW 2 — Sessions, full-width (DataTable needs the room) -->
			<div class="mb-6">
				<Card padding="p-6">
					<header class="border-b border-border-subtle pb-3 mb-4">
						<h2 class="text-xl font-semibold">
							{language.current && t('settings.sessionsSection')}
						</h2>
					</header>

					{#if sessionsLoading}
						<div class="flex items-center gap-2 py-4 text-secondary text-sm">
							<Spinner size="sm" /> Loading sessions…
						</div>
					{:else if sessionsError}
						<div class="py-4 text-sm" role="alert">
							<p class="text-down">Failed to load sessions: {sessionsError}</p>
							<div class="mt-3">
								<Button variant="ghost" size="sm" onclick={loadSessions}>Retry</Button>
							</div>
						</div>
					{:else}
						<!-- Sessions table is read-only: no expanded snippet, no
						     click-to-expand. Step G G.3 introduced `interactive`
						     prop on DataTable to drop cursor-pointer + role=button
						     + tabindex + hover-rail + focus-ring when interactive
						     is false. -->
						<DataTable
							headers={['Issued', 'Last activity', 'IP', 'Browser', 'Status', '']}
							items={sessions}
							interactive={false}
						>
							{#snippet row(s: Session)}
								<td class="px-4 py-3 text-sm" title={s.issuedAt}>
									{relativeTime(s.issuedAt)}
								</td>
								<td class="px-4 py-3 text-sm" title={s.lastActivity}>
									{relativeTime(s.lastActivity)}
								</td>
								<td class="px-4 py-3 text-sm font-mono text-secondary">{s.ip}</td>
								<td class="px-4 py-3 text-sm text-secondary" title={s.userAgent}>
									{truncate(s.userAgent, 40)}
								</td>
								<td class="px-4 py-3 text-sm">
									{#if s.isCurrent}
										<Badge variant="current">Current</Badge>
									{/if}
								</td>
								<td class="px-4 py-3 text-sm text-right">
									<Button
										variant="ghost"
										size="sm"
										disabled={s.isCurrent}
										onclick={() => onRevokeClick(s)}
									>
										Revoke
									</Button>
								</td>
							{/snippet}
						</DataTable>
					{/if}
				</Card>
			</div>
		{/if}

		{#if activeTab === 'security'}
			<!-- ROW 2.7 — Security Automation (Step P.4 / spec D8.A).
			     New top-level Settings section, sibling of SSL /
			     Certificates. Two forms in one Card: per-category
			     rule toggles (top) + watcher credentials (bottom).
			     The two persist via independent PUTs so an
			     operator who edits only rules doesn't re-enter
			     their watcher password.

			     #R-CS2C-anchor-link — id is the scroll-anchor
			     target for /settings#security-automation links
			     from the CrowdSec Decisions 412 state +
			     BanIPModal CTA. Without it the operator landed
			     at the top of /settings and had to scroll. -->
			<!-- v2.50 — the HTTP access log.
			     Sits above Security Automation on purpose: automation
			     pushes bans from what Arenet already observes, while
			     this is what lets CrowdSec observe anything at all.
			     Without it an agent only ever enforces the community
			     blocklist, and nothing on screen said so. -->
			<div id="access-log" class="mb-6">
				<Card padding="p-6">
					<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
						<div>
							<h2 class="text-xl font-semibold">{tl('settings.accessLog.title')}</h2>
							<p class="text-xs text-muted mt-1">{tl('settings.accessLog.subtitle')}</p>
						</div>
						{#if accessLogLoading}
							<Spinner size="sm" />
						{:else if accessLog?.enabled}
							<Badge variant="status-up">{tl('settings.accessLog.badgeOn')}</Badge>
						{:else}
							<Badge variant="neutral">{tl('settings.accessLog.badgeOff')}</Badge>
						{/if}
					</header>

					{#if accessLogError}
						<p class="text-sm text-down mb-3" role="alert" data-testid="access-log-error">
							{accessLogError}
						</p>
					{/if}

					<label class="flex items-start gap-3 mb-4">
						<input
							id="access-log-enabled"
							type="checkbox"
							bind:checked={alEnabled}
							data-testid="access-log-enabled"
							class="mt-1"
						/>
						<span>
							<span class="text-sm font-medium text-secondary block"
								>{tl('settings.accessLog.enableLabel')}</span
							>
							<span class="text-xs text-muted">{tl('settings.accessLog.enableHint')}</span>
						</span>
					</label>

					{#if alEnabled}
						<!-- The resolved path, not the typed one: the default
						     differs between a systemd install and a container,
						     and this is the value CrowdSec must be pointed at. -->
						{#if accessLog?.resolvedPath}
							<div class="mb-4">
								<span class="text-sm font-medium text-secondary block mb-1"
									>{tl('settings.accessLog.resolvedLabel')}</span
								>
								<code class="text-xs break-all" data-testid="access-log-resolved"
									>{accessLog.resolvedPath}</code
								>
								<p class="text-xs text-muted mt-1">{tl('settings.accessLog.resolvedHint')}</p>
							</div>
						{/if}

						<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
							<div class="md:col-span-3">
								<label for="access-log-path" class="text-sm font-medium text-secondary block mb-1"
									>{tl('settings.accessLog.pathLabel')}</label
								>
								<input
									id="access-log-path"
									type="text"
									bind:value={alPath}
									placeholder={accessLog?.resolvedPath ?? ''}
									data-testid="access-log-path"
									class="w-full h-9 rounded-md border border-border-subtle bg-surface px-2 text-sm text-primary font-mono"
								/>
								<p class="text-xs text-muted mt-1">{tl('settings.accessLog.pathHint')}</p>
							</div>
							<div>
								<label for="access-log-size" class="text-sm font-medium text-secondary block mb-1"
									>{tl('settings.accessLog.sizeLabel')}</label
								>
								<input
									id="access-log-size"
									type="number"
									min="1"
									max="1024"
									bind:value={alRollSizeMB}
									data-testid="access-log-size"
									class="w-full h-9 rounded-md border border-border-subtle bg-surface px-2 text-sm text-primary"
								/>
							</div>
							<div>
								<label for="access-log-keep" class="text-sm font-medium text-secondary block mb-1"
									>{tl('settings.accessLog.keepLabel')}</label
								>
								<input
									id="access-log-keep"
									type="number"
									min="1"
									max="100"
									bind:value={alRollKeep}
									data-testid="access-log-keep"
									class="w-full h-9 rounded-md border border-border-subtle bg-surface px-2 text-sm text-primary"
								/>
							</div>
							<div class="flex items-end">
								<label class="flex items-center gap-2 text-sm text-secondary">
									<input type="checkbox" bind:checked={alCompress} data-testid="access-log-compress" />
									{tl('settings.accessLog.compressLabel')}
								</label>
							</div>
						</div>

						<!-- The ceiling, because "10 MB, 5 files" answers a
						     question nobody asked. -->
						<p class="text-xs text-muted mb-4" data-testid="access-log-ceiling">
							{tl('settings.accessLog.ceiling', { mb: alCeilingMB })}
						</p>

						<!-- v2.56 — masked query parameters.
						     Some applications carry a credential in the URI
						     (Vaultwarden puts the session access token there),
						     so the log would write it to disk in clear, in a
						     file CrowdSec also reads. -->
						<div class="mb-4">
							<label
								for="access-log-redact"
								class="block text-sm font-medium text-secondary mb-1"
							>
								{tl('settings.accessLog.redactLabel')}
							</label>
							<input
								id="access-log-redact"
								type="text"
								bind:value={alRedactInput}
								placeholder="access_token, token, code, state"
								data-testid="access-log-redact"
								class="w-full h-9 rounded-md border border-border-subtle bg-surface px-2 text-sm text-primary font-mono"
							/>
							<p class="text-xs text-muted mt-1">
								{tl('settings.accessLog.redactHint')}
							</p>
						</div>
					{/if}

					<Button
						variant="primary"
						disabled={accessLogSaving || accessLogLoading}
						onclick={() => void saveAccessLog()}
						data-testid="access-log-save"
					>
						{accessLogSaving ? tl('settings.accessLog.saving') : tl('settings.accessLog.save')}
					</Button>
				</Card>
			</div>

			<div id="security-automation" class="mb-6">
				<Card padding="p-6">
					<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
						<div>
							<h2 class="text-xl font-semibold">Security Automation</h2>
							<p class="text-xs text-muted mt-1">
								Push CrowdSec bans to LAPI automatically when WAF / throttle / auth-failure events cross operator-configured thresholds. Decisions appear in the CrowdSec dashboard with scenario prefix <code>arenet/</code>.
							</p>
						</div>
						{#if automationLoading}
							<Spinner size="sm" />
						{:else if automationCreds.configured}
							<Badge variant="status-up">Configured</Badge>
						{:else}
							<Badge variant="status-warn">Not configured</Badge>
						{/if}
					</header>

					{#if automationLoadError}
						<p class="text-sm text-down mb-3" role="alert">
							Failed to load automation config: {automationLoadError}
						</p>
					{/if}

					<!-- Watcher credentials sub-form -->
					<section class="mb-6">
						<h3 class="text-base font-medium text-primary mb-2">Watcher credentials</h3>
						<p class="text-xs text-muted mb-3">
							Run <code>cscli machines add arenet-writer</code> on your CrowdSec host and paste the resulting credentials here. Distinct from the read-side bouncer key (Step N): writes to LAPI require a watcher per CrowdSec's auth model.
						</p>
						<form
							class="grid grid-cols-1 md:grid-cols-2 gap-4"
							onsubmit={(e) => {
								e.preventDefault();
								void submitAutomationCredentials();
							}}
						>
							<div class="md:col-span-2">
								<label for="auto-lapi-url" class="text-sm font-medium text-secondary block mb-1">
									LAPI URL
								</label>
								<input
									id="auto-lapi-url"
									type="text"
									bind:value={credsForm.lapiUrl}
									placeholder="http://127.0.0.1:8080/"
									autocomplete="off"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>
							<div>
								<label for="auto-machine-id" class="text-sm font-medium text-secondary block mb-1">
									Machine ID
								</label>
								<input
									id="auto-machine-id"
									type="text"
									bind:value={credsForm.machineId}
									placeholder="arenet-writer"
									autocomplete="off"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>
							<div>
								<label for="auto-password" class="text-sm font-medium text-secondary block mb-1">
									Password
								</label>
								<input
									id="auto-password"
									type="password"
									autocomplete="off"
									bind:value={credsForm.password}
									placeholder={automationCreds.configured ? '••• set (leave blank to keep)' : ''}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>
							{#if credsFormError}
								<p class="text-sm text-down md:col-span-2" role="alert">{credsFormError}</p>
							{/if}
							<div class="md:col-span-2 flex justify-between gap-2 flex-wrap">
								<div>
									{#if automationCreds.configured}
										<!-- CS.3 follow-up — Reset Security
										     Automation. Mirror of the CrowdSec
										     bouncer Reset button (CS.2.C
										     f1fe919): left edge, ghost variant
										     so a misclick can't confuse it with
										     Save. Only shown when configured —
										     nothing to reset on a fresh install. -->
										<Button
											variant="ghost"
											type="button"
											disabled={credsSubmitting}
											onclick={openAutomationResetConfirm}
											data-testid="automation-reset-btn"
										>
											{language.current && t('settingsSubcards.automationReset')}
										</Button>
									{/if}
								</div>
								<Button type="submit" disabled={credsSubmitting}>
									{language.current && (credsSubmitting ? t('settingsSubcards.saving') : t('settingsSubcards.saveCredentials'))}
								</Button>
							</div>
						</form>
						<p class="text-xs text-muted mt-2">
							{language.current && t('settingsSubcards.automationResetHelper')}
						</p>
					</section>

					<!-- Per-category rule toggles -->
					<section>
						<h3 class="text-base font-medium text-primary mb-2">Trigger rules</h3>
						<p class="text-xs text-muted mb-3">
							Each category is disabled by default. When enabled, Arenet bans a source IP after <em>threshold</em> events in <em>window</em>, for <em>duration</em>, with a <em>cooldown</em> after an operator unban that suppresses re-ban for that long.
						</p>
						<form
							onsubmit={(e) => {
								e.preventDefault();
								void submitAutomationRules();
							}}
						>
							<div class="overflow-x-auto">
								<table class="w-full text-sm">
									<thead>
										<tr class="text-left text-xs text-secondary uppercase">
											<th class="py-2 pr-3">Category</th>
											<th class="py-2 px-2">Enabled</th>
											<th class="py-2 px-2">Threshold</th>
											<th class="py-2 px-2">Window</th>
											<th class="py-2 px-2">Duration</th>
											<th class="py-2 px-2">Cooldown</th>
										</tr>
									</thead>
									<tbody>
										{#each AUTOMATION_SOURCES as src (src)}
											<tr class="border-t border-border-subtle">
												<td class="py-2 pr-3 font-mono">{AUTOMATION_SOURCE_LABELS[src]}</td>
												<td class="py-2 px-2">
													<input
														type="checkbox"
														checked={getRule(src).enabled}
														onchange={(e) =>
															setRuleField(src, 'enabled', (e.target as HTMLInputElement).checked)}
														aria-label={`Enable ${AUTOMATION_SOURCE_LABELS[src]}`}
													/>
												</td>
												<td class="py-2 px-2">
													<input
														type="number"
														min="1"
														value={getRule(src).threshold}
														oninput={(e) =>
															setRuleField(src, 'threshold', Number((e.target as HTMLInputElement).value))}
														class="w-16 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
														aria-label={`Threshold for ${AUTOMATION_SOURCE_LABELS[src]}`}
													/>
												</td>
												<td class="py-2 px-2">
													<input
														type="text"
														value={nsToHuman(getRule(src).window_ns)}
														onchange={(e) =>
															setRuleField(src, 'window_ns', humanToNs((e.target as HTMLInputElement).value))}
														placeholder="60s"
														class="w-20 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
														aria-label={`Window for ${AUTOMATION_SOURCE_LABELS[src]}`}
													/>
												</td>
												<td class="py-2 px-2">
													<input
														type="text"
														value={nsToHuman(getRule(src).duration_ns)}
														onchange={(e) =>
															setRuleField(src, 'duration_ns', humanToNs((e.target as HTMLInputElement).value))}
														placeholder="4h"
														class="w-20 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
														aria-label={`Duration for ${AUTOMATION_SOURCE_LABELS[src]}`}
													/>
												</td>
												<td class="py-2 px-2">
													<input
														type="text"
														value={nsToHuman(getRule(src).cooldown_ns)}
														onchange={(e) =>
															setRuleField(src, 'cooldown_ns', humanToNs((e.target as HTMLInputElement).value))}
														placeholder="24h"
														class="w-20 bg-surface border border-border-default rounded-md px-2 py-1 text-sm font-mono"
														aria-label={`Cooldown for ${AUTOMATION_SOURCE_LABELS[src]}`}
													/>
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
							{#if rulesFormError}
								<p class="text-sm text-down mt-3" role="alert">{rulesFormError}</p>
							{/if}
							<div class="flex justify-end mt-4">
								<Button type="submit" disabled={rulesSubmitting}>
									{rulesSubmitting ? 'Saving…' : 'Save rules'}
								</Button>
							</div>
						</form>
						<p class="text-xs text-muted mt-2">
							Cooldown defaults reflect category mistake-distribution: AUTH 7 days (operator unbans typically reflect real users), WAF SQLi/RCE/XSS/LFI 24 hours (suspected false positives), PROTOCOL/OTHER/Throttle 4 hours (maintenance-action unbans). Tune per-row.
						</p>
					</section>
				</Card>
			</div>
			<!-- ROW 2.75 — Forward-auth providers (Step K.1 §5.1).
			     Full-width like DNS provider: list of configured providers
			     with add/edit/delete + an inline form. The form pattern
			     mirrors the DNS provider's secret discipline — empty
			     clientSecret on PUT preserves the stored value, with the
			     "••• set (leave blank to keep)" placeholder. -->
			<div class="mb-6">
				<Card padding="p-6">
					<header class="flex items-center justify-between border-b border-border-subtle pb-3 mb-4">
						<div>
							<h2 class="text-xl font-semibold">Forward-auth providers</h2>
							<p class="text-xs text-muted mt-1">
								Configure identity providers (Authelia / Authentik /
								Keycloak / generic) that routes delegate auth to.
							</p>
						</div>
						<Button onclick={openFwdAuthCreate}>+ Add provider</Button>
					</header>

					{#if fwdAuthLoading}
						<div class="flex items-center gap-2 py-4 text-secondary text-sm">
							<Spinner size="sm" /> Loading providers…
						</div>
					{:else if fwdAuthListError}
						<p class="text-sm text-down mb-3" role="alert">
							Failed to load forward-auth providers: {fwdAuthListError}
						</p>
					{:else if fwdAuthList.length === 0 && !fwdAuthFormOpen}
						<p class="text-sm text-secondary py-2">
							No forward-auth provider configured yet.
						</p>
					{:else}
						<div class="flex flex-col gap-2 mb-3">
							{#each fwdAuthList as p (p.name)}
								<div class="flex items-center justify-between border border-border-subtle rounded px-3 py-2">
									<div class="flex flex-col text-sm">
										<span class="font-mono text-primary">{p.name}</span>
										<span class="text-xs text-muted">
											{p.kind} · {p.verifyUrl}
											{#if p.clientSecretSet}
												· <span class="text-up">secret set</span>
											{:else}
												· <span class="text-secondary">no secret</span>
											{/if}
										</span>
									</div>
									<div class="flex items-center gap-1">
										<Button variant="ghost" size="sm" onclick={() => openFwdAuthEdit(p)}>
											Edit
										</Button>
										<Button variant="ghost" size="sm" onclick={() => deleteFwdAuth(p.name)}>
											Delete
										</Button>
									</div>
								</div>
							{/each}
						</div>
					{/if}

					{#if fwdAuthDeleteError}
						<p class="text-sm text-down mb-3" role="alert">{fwdAuthDeleteError}</p>
					{/if}

					{#if fwdAuthFormOpen}
						<form
							class="grid grid-cols-1 md:grid-cols-2 gap-4 border-t border-border-subtle pt-4"
							onsubmit={(e) => {
								e.preventDefault();
								void submitFwdAuth();
							}}
						>
							<div>
								<label for="fwdauth-name" class="text-sm font-medium text-secondary block mb-1">
									Name (slug)
								</label>
								<input
									id="fwdauth-name"
									type="text"
									bind:value={fwdAuthForm.name}
									placeholder="authelia-prod"
									disabled={fwdAuthEditingName !== null}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono disabled:opacity-60 disabled:cursor-not-allowed"
								/>
								{#if fwdAuthEditingName !== null}
									<p class="text-xs text-muted mt-1">
										Name is immutable after creation.
									</p>
								{/if}
							</div>

							<div>
								<label for="fwdauth-kind" class="text-sm font-medium text-secondary block mb-1">
									Kind
								</label>
								<select
									id="fwdauth-kind"
									bind:value={fwdAuthForm.kind}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								>
									{#each FORWARD_AUTH_PROVIDER_KINDS as k (k)}
										<option value={k}>{k}</option>
									{/each}
								</select>
							</div>

							<div class="md:col-span-2">
								<label
									for="fwdauth-verify-url"
									class="text-sm font-medium text-secondary block mb-1"
								>
									Verify URL
								</label>
								<input
									id="fwdauth-verify-url"
									type="text"
									bind:value={fwdAuthForm.verifyUrl}
									placeholder="http://authelia:9091"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>

							<div>
								<label
									for="fwdauth-auth-request-uri"
									class="text-sm font-medium text-secondary block mb-1"
								>
									Auth request URI
								</label>
								<input
									id="fwdauth-auth-request-uri"
									type="text"
									bind:value={fwdAuthForm.authRequestUri}
									placeholder="/api/authz/forward-auth"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>

							<div>
								<label
									for="fwdauth-copy-headers"
									class="text-sm font-medium text-secondary block mb-1"
								>
									Copy headers (comma-separated)
								</label>
								<input
									id="fwdauth-copy-headers"
									type="text"
									bind:value={fwdAuthForm.copyHeaders}
									placeholder="Remote-User, Remote-Email"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								/>
							</div>

							<div class="md:col-span-2">
								<label
									for="fwdauth-client-secret"
									class="text-sm font-medium text-secondary block mb-1"
								>
									Client secret (optional)
								</label>
								<input
									id="fwdauth-client-secret"
									type="password"
									autocomplete="off"
									bind:value={fwdAuthForm.clientSecret}
									placeholder={fwdAuthEditingSecretSet
										? '••• set (leave blank to keep)'
										: ''}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>

							<div class="md:col-span-2">
								<label
									for="fwdauth-passthrough"
									class="text-sm font-medium text-secondary block mb-1"
								>
									Auth passthrough prefix (optional)
								</label>
								<input
									id="fwdauth-passthrough"
									type="text"
									bind:value={fwdAuthForm.authPassthroughPrefix}
									placeholder="/outpost.goauthentik.io"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
								<p class="text-xs text-muted mt-1">
									Path prefix served by the IdP itself on the
									application's host (e.g. <code class="font-mono">/outpost.goauthentik.io</code> for
									Authentik embedded outpost, <code class="font-mono">/oauth2</code> for
									oauth2-proxy). Requests under this prefix bypass
									the forward_auth gate and are reverse-proxied
									directly to the verify URL host, carrying the same
									Host as the verify sub-request so a reverse proxy in
									front of the IdP routes both the same way. Leave
									empty for providers that don't need it (Authelia
									standalone, generic).
								</p>
							</div>

							<div class="md:col-span-2">
								<label class="inline-flex items-start gap-2 text-sm font-medium text-secondary">
									<input
										type="checkbox"
										bind:checked={fwdAuthForm.rewriteVerifyHost}
										class="mt-0.5 rounded border-border-default bg-surface text-cyan focus:ring-cyan"
									/>
									<span>
										Rewrite Host of verify sub-request to verify URL host
										<span class="block text-xs font-normal text-muted mt-0.5">
											Depends on your network, not on which IdP you run.
											Check it when something between Arenet and the IdP
											routes by Host — typically a reverse proxy in front
											of the IdP, such as Authentik behind Traefik or
											nginx. Leave it unchecked when Arenet reaches the IdP
											directly. Either way the IdP still identifies the
											application from X-Forwarded-Host, which Arenet sends
											from the original request.
										</span>
									</span>
								</label>
							</div>

							{#if fwdAuthFormError}
								<p class="text-sm text-down md:col-span-2" role="alert">{fwdAuthFormError}</p>
							{/if}

							<div class="md:col-span-2 flex justify-end gap-2">
								<Button variant="ghost" onclick={() => (fwdAuthFormOpen = false)} type="button">
									Cancel
								</Button>
								<Button type="submit" disabled={fwdAuthSubmitting}>
									{fwdAuthSubmitting
										? 'Saving…'
										: fwdAuthEditingName === null
											? 'Create'
											: 'Save'}
								</Button>
							</div>
						</form>
					{/if}
				</Card>
			</div>
			<!-- ROW 2.85 — OIDC SSO (Step K.2 §5.2). Self-contained
			     component to keep the settings page tractable.
			     Phase 2 Users-page refactor — id anchor target for
			     the "Modifier la config" button in the
			     OIDCConfigSummary sidebar on /utilisateurs. -->
			<div id="oidc-config">
				<OIDCSettingsSection />
			</div>
			<!-- ROW 2.87 — CrowdSec bouncer (Step CS.1). Sits next
			     to OIDC since both are admin-facing secret-config
			     sections that hot-reload Caddy on save. The chain
			     position #2 implication (country_block fires first)
			     is documented in docs/setup/crowdsec.md. -->
			<CrowdSecSettingsSection />
		{/if}

		{#if activeTab === 'network'}
			<!-- ROW 2.5 — DNS providers (v2.12). Self-contained collection
			     component: table + add/edit modal + delete. Replaces the
			     pre-v2.12 singleton OVH credentials form. The section root
			     carries id="dns-providers" so the wildcard wizard's
			     empty-state CTA can deep-link here. -->
			<DNSProvidersSection />
			<!-- Brick 4, Task 3 — GeoIP settings (MaxMind credentials +
			     auto-update). Mounted right after UpdatesSection: both are
			     opt-in "keep this data fresh" mini-sections. -->
			<GeoIPSettingsSection />
			<!-- ROW 2.85 — Post-apply route check (v2.35). -->
			<RouteCheckSection />
			<!-- ROW 2.95 — Server geographic position (Step V.7 §5.1-§5.3).
			     Operator-facing UI for the V.4 server-position endpoints:
			     mode badge (Auto/Manuel/Dégradé), lat/lon/city/country
			     form with [-90, 90] / [-180, 180] inline validation,
			     Re-détecter button driving the POST :redetect path. -->
			<ServerPositionSection />
		{/if}

		{#if activeTab === 'backups'}
			<!-- ROW 2.9 — Backup & restore (Step K.3 §5.3). -->
			<BackupSection />
			<!-- ROW 2.91 — Scheduled backups (v2.33): folder / NAS / email. -->
			<ScheduledBackupsSection />
		{/if}

		{#if activeTab === 'system'}
			<!-- v2.45 — the machine under Arenet, refreshed live. It
			     sits first because it answers the question an operator
			     opens this tab with: is the host healthy? -->
			<SystemInfoSection />
			<!-- v2.12.3 — opt-in update checker mini-card. -->
			<UpdatesSection />
			<!-- Error pages left the sidebar: it is a settings sub-page,
			     so its way in is here. -->
			<Card padding="p-6">
				<div class="flex items-center justify-between gap-4">
					<div>
						<h2 class="text-xl font-semibold">
							{language.current && t('errorPages.settingsCardTitle')}
						</h2>
						<p class="text-xs text-muted mt-1">
							{language.current && t('errorPages.settingsCardDescription')}
						</p>
					</div>
					<a
						href="/settings/error-pages"
						class="text-sm text-cyan hover:underline shrink-0"
						data-testid="settings-error-pages-link"
					>
						{language.current && t('errorPages.settingsCardLink')}
					</a>
				</div>
			</Card>
			<!-- ROW 3 — About, full-width (footer-meta, intentionally aerated) -->
			<Card padding="p-6">
				<header class="border-b border-border-subtle pb-3 mb-4">
					<h2 class="text-xl font-semibold">About</h2>
				</header>

				<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-3 text-sm">
					<dt class="text-secondary">Version</dt>
					<dd class="text-primary font-mono" data-testid="about-version">{displayVersion}</dd>

					<dt class="text-secondary">License</dt>
					<dd>
						<a
							href="https://github.com/barto95100/arenet/blob/{licenseRef}/LICENSE"
							target="_blank"
							rel="noopener noreferrer"
							class="text-cyan hover:underline"
						>
							AGPL v3
						</a>
					</dd>

					<dt class="text-secondary">Source</dt>
					<dd>
						<a
							href="https://github.com/barto95100/arenet"
							target="_blank"
							rel="noopener noreferrer"
							class="text-cyan hover:underline"
						>
							github.com/barto95100/arenet
						</a>
					</dd>
				</dl>
			</Card>
		{/if}

	</div>

	<!-- ChangePasswordModal mounted locally (Option B). The
	     layout-level instance handles the compromised-banner flow;
	     this one handles the explicit user click in Settings. They're
	     independent instances of the same component — both safe by
	     ChangePasswordModal's `bind:open` design. -->
	<ChangePasswordModal bind:open={changePasswordOpen} />

	<!-- Revoke confirmation (Chunk 6.4 — replaces native confirm()). -->
	<ConfirmDialog
		bind:open={revokeConfirmOpen}
		title={language.current && t('settingsSubcards.revokeSessionTitle')}
		message={language.current && t('settingsSubcards.revokeSessionMessage')}
		confirmLabel={language.current && t('settingsSubcards.revokeSessionConfirm')}
		confirmVariant="danger"
		onConfirm={confirmRevoke}
	/>

	<!-- Step CS.3 follow-up — Reset Security Automation
	     confirmation. Mirror of CrowdSecSettingsSection's
	     Réinitialiser dialog. -->
	<ConfirmDialog
		bind:open={automationResetConfirmOpen}
		title={language.current && t('settingsSubcards.automationResetDialogTitle')}
		message={language.current && t('settingsSubcards.automationResetDialogMessage')}
		confirmLabel={language.current && t('settingsSubcards.automationResetDialogConfirm')}
		cancelLabel={language.current && t('settingsSubcards.automationResetDialogCancel')}
		confirmVariant="danger"
		onConfirm={confirmAutomationReset}
	/>

	<!-- Step O.4 delete-managed-domain dialog migrated to /certs
	     in #R-6 Pack A (2026-06-04). See
	     web/frontend/src/routes/certs/+page.svelte. -->
</div>
