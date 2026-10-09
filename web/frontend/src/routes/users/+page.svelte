<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Users-page Phase 1 refactor — full rewrite matching the
  operator-supplied mockup at
  docs/mocks/pages/screen/users-page-tarfer.png. Surfaces the
  enriched backend response (email, lastActivityAt,
  activeSessionCount) from commit 1 and adds:
    - 4 KPI cards (Total / Admins / OIDC / Local)
    - Search + role + source filters (frontend-pure)
    - 2-col layout (table left + OIDC summary sidebar right)
    - Online / Actif / Hors-ligne indicator
    - BREAK-GLASS badge on local admins when OIDC is active
    - DELETE action with ConfirmDialog + self-row UX guard

  Out-of-scope (Phase 2-4): "Tester connexion" SSO button,
  invitations card, service accounts, manual email edit.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { relativeTime } from '$lib/utils/audit-format';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import { authApi } from '$lib/api/auth';
	import {
		ApiError,
		type AdminUser,
		type UserRole
	} from '$lib/api/types';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Card from '$lib/components/Card.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import OIDCConfigSummary from '$lib/components/OIDCConfigSummary.svelte';
	import UserAvatar from '$lib/components/UserAvatar.svelte';
	import StatusDot from '$lib/components/StatusDot.svelte';
	import CreateServiceAccountModal from '$lib/components/CreateServiceAccountModal.svelte';
	import CreateUserModal from '$lib/components/CreateUserModal.svelte';
	import { oidcProviderLabel, oidcProviderColors } from '$lib/utils/oidc-labels';
	import { copyText } from '$lib/utils/clipboard';
	import type { OIDCProviderKind } from '$lib/api/types';

	let users = $state<AdminUser[]>([]);
	let loading = $state(true);
	let loadError = $state('');
	let oidcEnabled = $state(false);
	let oidcKind = $state<OIDCProviderKind | ''>('');

	let confirmRoleOpen = $state(false);
	let pendingRole = $state<{ user: AdminUser; nextRole: UserRole } | null>(null);

	let confirmDeleteOpen = $state(false);
	let pendingDelete = $state<AdminUser | null>(null);

	// Phase 4 — service-account modals.
	let createSvcOpen = $state(false);
	// v2.48 — creating a human account, which had no path at all:
	// the only ways one existed were the setup flow and OIDC.
	let createUserOpen = $state(false);
	let confirmRotateOpen = $state(false);
	let pendingRotate = $state<AdminUser | null>(null);
	let revealedRotateToken = $state<string | null>(null);
	let rotateCopied = $state(false);
	let rotateSaved = $state(false);
	let rotateCopyFailed = $state(false);
	let rotating = $state(false);
	let rotateTokenEl: HTMLElement | undefined = $state(undefined);

	// Search + filter state — pure frontend filtering over the
	// full users[] (admin volumes < 50 — no API surface needed).
	let search = $state('');
	type RoleFilter = 'all' | 'admin' | 'viewer';
	type SourceFilter = 'all' | 'local' | 'oidc';
	let roleFilter = $state<RoleFilter>('all');
	let sourceFilter = $state<SourceFilter>('all');

	onMount(async () => {
		// Belt-and-braces: viewers can type /users directly. The
		// sidebar hides the Administration group for non-admins,
		// the API gate 403s the request, but skipping the doomed
		// fetch reads nicer.
		if (auth.state === 'authenticated' && auth.user?.role !== 'admin') {
			void goto('/dashboard');
			return;
		}
		await load();
	});

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const [list, oidcStatus] = await Promise.all([
				settingsApi.listAdminUsers(),
				// Anonymous endpoint — break-glass criterion is
				// "OIDC currently active". If OIDC is disabled, no
				// admin is in break-glass mode anymore (no SSO
				// channel to be the alternative to).
				authApi.oidcStatus().catch(() => ({ enabled: false, kind: '' as const }))
			]);
			users = list;
			oidcKind = oidcStatus.kind ?? '';
			oidcEnabled = oidcStatus.enabled ?? false;
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	// --- KPI derivations --------------------------------------

	const counts = $derived.by(() => {
		const total = users.length;
		const admins = users.filter((u) => u.role === 'admin').length;
		const viewers = total - admins;
		const oidc = users.filter((u) => u.authSource === 'oidc').length;
		const local = total - oidc;
		const localAdmins = users.filter(
			(u) => u.authSource === 'local' && u.role === 'admin'
		).length;
		// Service accounts are machines: an admin token cannot sign
		// in to this page, so it does not count as a way back in.
		const humanAdmins = users.filter(
			(u) => u.authSource !== 'service' && u.role === 'admin'
		).length;
		return { total, admins, viewers, oidc, local, localAdmins, humanAdmins };
	});

	const subtitle = $derived(
		language.current &&
			t('users.subtitle', {
				total: counts.total,
				plural_total: counts.total > 1 ? 's' : '',
				admins: counts.admins,
				plural_admins: counts.admins > 1 ? 's' : '',
				viewers: counts.viewers,
				plural_viewers: counts.viewers > 1 ? 's' : '',
				oidc: counts.oidc,
				local: counts.local
			})
	);

	// --- Filtering --------------------------------------------

	// The way out of an over-narrow filter, offered by the empty state.
	function clearUserFilters(): void {
		search = '';
		roleFilter = 'all';
		sourceFilter = 'all';
	}

	const filteredUsers = $derived.by(() => {
		const q = search.trim().toLowerCase();
		return users.filter((u) => {
			if (roleFilter !== 'all' && u.role !== roleFilter) return false;
			if (sourceFilter !== 'all' && u.authSource !== sourceFilter) return false;
			if (q === '') return true;
			return (
				u.username.toLowerCase().includes(q) ||
				u.displayName.toLowerCase().includes(q) ||
				(u.email ?? '').toLowerCase().includes(q) ||
				u.role.includes(q) ||
				u.authSource.includes(q)
			);
		});
	});

	// --- Activity & break-glass derivations -------------------

	type ActivityState = 'online' | 'active' | 'offline';
	function activityFor(u: AdminUser): ActivityState {
		if (u.activeSessionCount > 0 && u.lastActivityAt) {
			const lastMs = new Date(u.lastActivityAt).getTime();
			const ageMs = Date.now() - lastMs;
			if (ageMs <= 5 * 60 * 1000) return 'online';
			if (ageMs <= 60 * 60 * 1000) return 'active';
		}
		return 'offline';
	}

	function activityLabel(state: ActivityState): string {
		void language.current;
		switch (state) {
			case 'online':
				return t('users.activityOnline');
			case 'active':
				return t('users.activityActive');
			case 'offline':
				return t('users.activityOffline');
		}
	}

	// Map activity state to the StatusDot variant. Online users
	// pulse green, idle-but-recent users pulse amber, fully-
	// offline users render a flat muted dot (no pulse, see
	// StatusDot.svelte — only non-idle statuses pulse).
	function activityDotStatus(
		state: ActivityState
	): 'up' | 'warn' | 'idle' {
		switch (state) {
			case 'online':
				return 'up';
			case 'active':
				return 'warn';
			case 'offline':
				return 'idle';
		}
	}

	function isBreakGlass(u: AdminUser): boolean {
		// Break-glass criterion (Phase 1 simplification): local
		// admin while OIDC is currently active. If OIDC is
		// disabled, every admin is equivalent — no break-glass
		// distinction needed.
		return u.authSource === 'local' && u.role === 'admin' && oidcEnabled;
	}

	function initials(u: AdminUser): string {
		const source = u.displayName || u.username;
		const parts = source.split(/[\s.\-_]+/).filter(Boolean);
		if (parts.length === 0) return '?';
		if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
		return (parts[0][0] + parts[1][0]).toUpperCase();
	}

	// v2.9.22 i18n — delegate to the shared relativeTime helper so
	// the user-list "last login" cells respect the active language
	// preference instead of being locked to FR.
	function relativeFromNow(iso: string | undefined): string {
		if (!iso) return '—';
		return relativeTime(iso);
	}

	// --- Action handlers --------------------------------------

	function nextRoleFor(u: AdminUser): UserRole {
		return u.role === 'admin' ? 'viewer' : 'admin';
	}

	// Why a demotion is not offered, or null when it is. The last
	// admin would leave nobody able to administer the instance; the
	// last LOCAL admin is the way back in when the SSO is down, and
	// the backend refuses that one too (UserStore.UpdateRole). Counts
	// run over every user, not the filtered list.
	type RoleLock = 'lastAdmin' | 'lastLocalAdmin';
	function roleLockFor(u: AdminUser): RoleLock | null {
		if (u.role !== 'admin') return null;
		if (counts.humanAdmins <= 1) return 'lastAdmin';
		if (u.authSource === 'local' && counts.localAdmins <= 1) return 'lastLocalAdmin';
		return null;
	}

	function roleLockHint(lock: RoleLock): string {
		void language.current;
		return lock === 'lastAdmin'
			? t('users.roleLastAdminHint')
			: t('users.roleLastLocalAdminHint');
	}

	function onRoleClick(u: AdminUser): void {
		// The buttons are not offered in these cases; this keeps the
		// rule in one place should another caller appear.
		if (auth.user?.id === u.id || roleLockFor(u) !== null) return;
		pendingRole = { user: u, nextRole: nextRoleFor(u) };
		confirmRoleOpen = true;
	}

	async function confirmRoleChange(): Promise<void> {
		if (!pendingRole) return;
		const { user, nextRole } = pendingRole;
		try {
			const updated = await settingsApi.updateUserRole(user.id, { role: nextRole });
			users = users.map((u) => (u.id === updated.id ? updated : u));
			pushToast(
				`${user.username} → ${nextRole === 'admin' ? 'admin' : 'viewer'}`,
				'success'
			);
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : (err instanceof Error ? err.message : 'Failed to change role');
			pushToast(msg, 'danger');
		} finally {
			confirmRoleOpen = false;
			pendingRole = null;
		}
	}

	function onDeleteClick(u: AdminUser): void {
		pendingDelete = u;
		confirmDeleteOpen = true;
	}

	function onRotateClick(u: AdminUser): void {
		pendingRotate = u;
		revealedRotateToken = null;
		rotateCopied = false;
		rotateSaved = false;
		rotateCopyFailed = false;
		confirmRotateOpen = true;
	}

	async function confirmRotate(): Promise<void> {
		if (!pendingRotate || rotating) return;
		const u = pendingRotate;
		rotating = true;
		try {
			const result = await settingsApi.rotateServiceAccountToken(u.id);
			revealedRotateToken = result.token;
			rotateCopied = false;
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : (err instanceof Error ? err.message : 'Failed to rotate token');
			pushToast(msg, 'danger');
			confirmRotateOpen = false;
			pendingRotate = null;
		} finally {
			rotating = false;
		}
	}

	async function copyRotateToken(): Promise<void> {
		if (!revealedRotateToken) return;
		if (await copyText(revealedRotateToken, rotateTokenEl)) {
			rotateCopied = true;
			rotateCopyFailed = false;
			pushToast(t('users.toastTokenCopied'), 'success');
		} else {
			// Said inside the dialog, next to the text to copy by hand.
			rotateCopyFailed = true;
		}
	}

	function closeRotateModal(): void {
		confirmRotateOpen = false;
		pendingRotate = null;
		revealedRotateToken = null;
		rotateCopied = false;
		rotateSaved = false;
		rotateCopyFailed = false;
	}

	async function confirmDelete(): Promise<void> {
		if (!pendingDelete) return;
		const u = pendingDelete;
		try {
			if (u.authSource === 'service') {
				await settingsApi.deleteServiceAccount(u.id);
			} else {
				await settingsApi.deleteAdminUser(u.id);
			}
			users = users.filter((x) => x.id !== u.id);
			pushToast(t('users.toastDeleted', { username: u.username }), 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : (err instanceof Error ? err.message : 'Failed to delete user');
			pushToast(msg, 'danger');
		} finally {
			confirmDeleteOpen = false;
			pendingDelete = null;
		}
	}
</script>

<svelte:head>
	<title>{language.current && t('users.headTitle')}</title>
</svelte:head>

<PageHeader
	eyebrow={language.current && t('users.pageEyebrow')}
	title={language.current && t('pageTitles.users')}
	subtitle={subtitle}
/>

{#if loading}
	<div class="flex justify-center py-12"><Spinner size="md" /></div>
{:else if loadError}
	<Card padding="p-6">
		<p class="text-sm text-down" role="alert">
			{language.current && t('users.loadFailed', { err: loadError })}
		</p>
	</Card>
{:else}
	<!-- KPI strip (4-up). All values derive from users[]. -->
	<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6" data-testid="users-kpi-strip">
		<StatCard
			label={language.current && t('users.kpiTotalLabel')}
			value={counts.total}
			hint={language.current && t('users.kpiTotalHint')}
		/>
		<StatCard
			label={language.current && t('users.kpiAdminsLabel')}
			value={counts.admins}
			hint={language.current && t('users.kpiAdminsHint', { local: counts.localAdmins, oidc: counts.admins - counts.localAdmins })}
		/>
		<StatCard
			label={language.current && t('users.kpiSSOLabel')}
			value={counts.oidc}
			hint={language.current && t('users.kpiSSOHint')}
		/>
		<StatCard
			label={language.current && t('users.kpiLocalLabel')}
			value={counts.local}
			hint={language.current && (oidcEnabled
				? t('users.kpiLocalHintBreakGlass', { count: counts.localAdmins })
				: t('users.kpiLocalHintManual'))}
		/>
	</div>

	<!-- Phase 4 — Service account create CTA. Above the grid so
	     it stays visible regardless of sidebar collapse state. -->
	<div class="mb-4 flex justify-end gap-2">
		<!-- v2.48 — a human account. Listed first because it is the
		     common case; a service account is the specialist one. -->
		<Button
			variant="primary"
			size="sm"
			onclick={() => (createUserOpen = true)}
			data-testid="create-user-button"
		>
			{language.current && t('users.createUser')}
		</Button>
		<Button
			variant="secondary"
			size="sm"
			onclick={() => (createSvcOpen = true)}
			data-testid="create-svc-button"
		>
			{language.current && t('users.createServiceAccount')}
		</Button>
	</div>

	<div class="grid grid-cols-1 xl:grid-cols-[1.3fr_1fr] gap-4 items-start">
		<!-- LEFT — users table -->
		<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden">
			<!-- Filter bar -->
			<div class="px-4 py-3 border-b border-border-subtle flex items-center gap-3 flex-wrap">
				<div class="flex-1 min-w-[200px] flex items-center gap-2 px-2 py-1 rounded-md bg-surface border border-border-default">
					<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
						<circle cx="7" cy="7" r="5" />
						<path d="M11 11l3 3" />
					</svg>
					<input
						type="search"
						bind:value={search}
						placeholder={language.current && t('users.searchPlaceholder')}
						aria-label={language.current && t('users.filterUsersAria')}
						class="flex-1 bg-transparent outline-none text-sm text-primary placeholder-muted"
					/>
				</div>
				<div class="flex items-center gap-1" data-testid="role-filter">
					{#each (language.current ? [['all', t('users.filterAll')], ['admin', t('users.filterAdmins')], ['viewer', t('users.filterViewers')]] : []) as [val, label] (val)}
						<button
							type="button"
							class:active={roleFilter === val}
							class="filter-chip"
							aria-pressed={roleFilter === val}
							onclick={() => (roleFilter = val as RoleFilter)}
						>
							{label}
						</button>
					{/each}
				</div>
				<div class="flex items-center gap-1" data-testid="source-filter">
					{#each (language.current ? [['all', t('users.filterAll')], ['local', t('users.filterLocal')], ['oidc', t('users.filterOIDC')]] : []) as [val, label] (val)}
						<button
							type="button"
							class:active={sourceFilter === val}
							class="filter-chip"
							aria-pressed={sourceFilter === val}
							onclick={() => (sourceFilter = val as SourceFilter)}
						>
							{label}
						</button>
					{/each}
				</div>
			</div>

			{#if filteredUsers.length === 0}
				<!-- v2.41 — was a single muted line; an operator who
				     filters everything out needs to be told the filter
				     is why, and how to get back. -->
				<EmptyState
					tone="filter"
					testid="users-empty"
					title={language.current && t('users.emptyFilteredTitle')}
					body={language.current && t('users.emptyFilteredBody')}
					actionLabel={language.current && t('users.emptyFilteredAction')}
					onAction={clearUserFilters}
				/>
			{:else}
				<table class="w-full">
					<thead>
						<tr class="text-left text-xs uppercase tracking-wider text-muted border-b border-border-subtle">
							<th class="px-4 py-3 font-medium">{language.current && t('users.colUser')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('users.colSource')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('users.colRole')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('users.colLastActivity')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('users.colState')}</th>
							<th class="px-4 py-3 font-medium text-right">{language.current && t('users.colActions')}</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-border-subtle">
						{#each filteredUsers as u (u.id)}
							{@const isSelf = auth.user?.id === u.id}
							{@const breakGlass = isBreakGlass(u)}
							{@const state = activityFor(u)}
							<tr data-testid="user-row-{u.id}" data-source={u.authSource}>
								<td class="px-4 py-3 text-sm">
									<div class="flex items-center gap-3">
										<UserAvatar
											seed={u.username}
											initials={initials(u)}
											service={u.authSource === 'service'}
										/>
										<div>
											<div class="font-medium text-primary flex items-center gap-2">
												<span>{u.displayName || u.username}</span>
												{#if isSelf}
													<span data-testid="self-badge-{u.id}">
														<Badge variant="status-info">{language.current && t('users.badgeYou')}</Badge>
													</span>
												{/if}
											</div>
											<div class="text-xs text-muted">
												{u.email || '—'}
											</div>
										</div>
									</div>
								</td>
								<td class="px-4 py-3 text-sm">
									{#if u.authSource === 'oidc'}
										{@const colors = oidcProviderColors(oidcKind)}
										<span
											class="provider-badge"
											style:background-color={colors.badgeBg}
											style:border-color={colors.badgeBorder}
											style:color={colors.badgeText}
											data-testid="source-badge-{u.id}"
										>
											<!-- Globe glyph = "external identity provider"
											     affordance. Reuses the meridian+equator
											     stroke shape used by Sidebar's map icon.
											     Inherits currentColor so the glyph
											     follows the provider's badgeText hue. -->
											<svg
												width="12"
												height="12"
												viewBox="0 0 16 16"
												fill="none"
												stroke="currentColor"
												stroke-width="1.4"
												stroke-linecap="round"
												stroke-linejoin="round"
												aria-hidden="true"
												data-testid="source-globe-{u.id}"
											>
												<circle cx="8" cy="8" r="6" />
												<path d="M2 8h12M8 2c2 1.8 2 10.2 0 12M8 2c-2 1.8-2 10.2 0 12" />
											</svg>
											<span>{oidcProviderLabel(oidcKind)}</span>
										</span>
									{:else if u.authSource === 'service'}
										<span class="inline-flex items-center gap-1">
											<Badge variant="neutral">Local</Badge>
											<span
												class="text-[10px] uppercase tracking-wider text-muted font-semibold"
												data-testid="service-suffix-{u.id}"
											>
												{language.current && t('users.badgeServiceSuffix')}
											</span>
										</span>
									{:else}
										<Badge variant="neutral">Local</Badge>
									{/if}
									{#if breakGlass}
										<span class="ml-1" data-testid="break-glass-badge-{u.id}">
											<Badge variant="status-warn">{language.current && t('users.badgeBreakGlass')}</Badge>
										</span>
									{/if}
								</td>
								<td class="px-4 py-3 text-sm">
									{#if u.role === 'admin'}
										<span class="inline-flex items-center gap-2">
											<Badge variant="status-up">{language.current && t('users.roleAdmin')}</Badge>
											{#if u.authSource === 'oidc'}
												<span
													class="text-xs text-muted"
													data-testid="promoted-label-{u.id}"
												>
													{language.current && t('users.badgePromoted')}
												</span>
											{/if}
										</span>
									{:else}
										<Badge variant="neutral">{language.current && t('users.roleViewer')}</Badge>
									{/if}
								</td>
								<td class="px-4 py-3 text-sm text-secondary">
									{relativeFromNow(u.lastActivityAt ?? u.lastLoginAt)}
								</td>
								<td class="px-4 py-3 text-sm">
									<span
										class="inline-flex items-center gap-2"
										data-testid="activity-state-{u.id}"
									>
										<StatusDot status={activityDotStatus(state)} />
										<span class="text-secondary">{activityLabel(state)}</span>
									</span>
								</td>
								<td class="px-4 py-3 text-sm text-right">
									<div class="flex justify-end gap-1">
										{#if u.authSource === 'service'}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => onDeleteClick(u)}
												data-testid="delete-btn-{u.id}"
											>
												{language.current && t('users.actionDelete')}
											</Button>
											<Button
												variant="ghost"
												size="sm"
												onclick={() => onRotateClick(u)}
												data-testid="rotate-btn-{u.id}"
											>
												{language.current && t('users.actionRotate')}
											</Button>
										{:else}
											{#if !isSelf}
												<Button
													variant="ghost"
													size="sm"
													onclick={() => onDeleteClick(u)}
													data-testid="delete-btn-{u.id}"
												>
													{language.current && t('users.actionDelete')}
												</Button>
											{/if}
											{#if isSelf}
												<!-- Your own role is changed by another admin,
												     never by you: no button, and a word on why. -->
												<span
													class="px-2.5 py-1 text-xs text-muted"
													title={language.current && t('users.roleSelfHint')}
													data-testid="role-self-hint-{u.id}"
												>
													{language.current && t('users.roleSelfLabel')}
													<span class="sr-only">{language.current && t('users.roleSelfHint')}</span>
												</span>
											{:else}
												{@const lock = roleLockFor(u)}
												<!-- Disabled for the last admin. A disabled
												     button gets no hover in every browser, so
												     the tooltip sits on a wrapper; the hidden
												     text gives screen readers the same reason. -->
												<span title={lock ? roleLockHint(lock) : undefined}>
													<Button
														variant="ghost"
														size="sm"
														disabled={lock !== null}
														aria-describedby={lock ? `role-lock-${u.id}` : undefined}
														onclick={() => onRoleClick(u)}
														data-testid="role-btn-{u.id}"
													>
														{language.current && (u.role === 'admin' ? t('users.actionDemote') : t('users.actionPromote'))}
													</Button>
													{#if lock}
														<span id="role-lock-{u.id}" class="sr-only" data-testid="role-lock-hint-{u.id}">
															{roleLockHint(lock)}
														</span>
													{/if}
												</span>
											{/if}
										{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		<!-- RIGHT — sidebar with OIDC read-only summary -->
		<div class="flex flex-col gap-4">
			<OIDCConfigSummary />
		</div>
	</div>
{/if}

<ConfirmDialog
	bind:open={confirmRoleOpen}
	title={pendingRole && language.current
		? t('users.roleConfirmTitle', {
				action: pendingRole.nextRole === 'admin' ? t('users.roleConfirmActionPromote') : t('users.roleConfirmActionDemote'),
				username: pendingRole.user.username
			})
		: ''}
	message={pendingRole && language.current
		? pendingRole.nextRole === 'admin'
			? t('users.roleConfirmPromoteBody', { username: pendingRole.user.username })
			: t('users.roleConfirmDemoteBody', { username: pendingRole.user.username })
		: ''}
	confirmLabel={language.current && (pendingRole?.nextRole === 'admin' ? t('users.roleConfirmActionPromote') : t('users.roleConfirmActionDemote'))}
	confirmVariant={pendingRole?.nextRole === 'admin' ? 'primary' : 'danger'}
	onConfirm={confirmRoleChange}
/>

<ConfirmDialog
	bind:open={confirmDeleteOpen}
	title={pendingDelete && language.current ? t('users.deleteConfirmTitle', { username: pendingDelete.username }) : ''}
	message={pendingDelete && language.current
		? pendingDelete.authSource === 'service'
			? t('users.deleteConfirmServiceBody', { username: pendingDelete.username })
			: t('users.deleteConfirmLocalBody', { username: pendingDelete.username })
		: ''}
	confirmLabel={language.current && t('users.deleteConfirmLabel')}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>

<!-- Phase 4 — Create service account modal -->
<CreateServiceAccountModal
	open={createSvcOpen}
	onClose={() => (createSvcOpen = false)}
	onCreated={load}
/>

<!-- v2.48 — create a local human account. -->
<CreateUserModal
	open={createUserOpen}
	onClose={() => (createUserOpen = false)}
	onCreated={load}
/>

<!-- Phase 4 — Token rotation: a confirm step, then a show-once reveal,
     so not a plain ConfirmDialog. Built on Modal for its labelling and
     focus handling. Rotating revokes the current token at once, hence
     the danger button; the reveal (and the request in flight) cannot be
     dismissed, or the new token would be lost with the old one revoked. -->
<Modal
	open={confirmRotateOpen && pendingRotate !== null}
	title={language.current &&
		(revealedRotateToken
			? t('users.rotateNewTitle')
			: t('users.rotateConfirmTitle', { username: pendingRotate?.username ?? '' }))}
	onClose={closeRotateModal}
	dismissible={revealedRotateToken === null && !rotating}
>
	<div class="text-sm flex flex-col gap-3" data-testid="rotate-modal">
		{#if !revealedRotateToken}
			<p>
				{language.current && t('users.rotateModalIntro')}
			</p>
		{:else}
			<p>
				{language.current && t('users.rotateRevealedShownOnce')}
			</p>
			<pre
				bind:this={rotateTokenEl}
				class="px-3 py-2 rounded-md bg-surface border border-border-default font-mono text-xs break-all whitespace-pre-wrap select-all"
				data-testid="rotate-revealed-token">{revealedRotateToken}</pre>
			{#if rotateCopyFailed}
				<p role="alert" class="text-down" data-testid="rotate-copy-failed">
					{language.current && t('secretReveal.copyFailed')}
				</p>
			{/if}
			<label class="inline-flex items-center gap-2 text-secondary cursor-pointer">
				<input
					type="checkbox"
					class="accent-cyan"
					bind:checked={rotateSaved}
					data-testid="rotate-saved-checkbox"
				/>
				{language.current && t('secretReveal.savedConfirm')}
			</label>
		{/if}
	</div>
	{#snippet footer()}
		{#if !revealedRotateToken}
			<Button variant="ghost" size="sm" disabled={rotating} onclick={closeRotateModal}
				>{language.current && t('users.rotateBtnCancel')}</Button
			>
			<Button
				variant="danger"
				size="sm"
				loading={rotating}
				onclick={confirmRotate}
				data-testid="rotate-confirm-btn"
			>
				{language.current && t('users.rotateBtnConfirm')}
			</Button>
		{:else}
			<Button variant="secondary" size="sm" onclick={copyRotateToken} data-testid="rotate-copy-btn">
				{language.current && (rotateCopied ? t('users.rotateBtnCopied') : t('users.rotateBtnCopy'))}
			</Button>
			<Button
				variant="primary"
				size="sm"
				disabled={!rotateCopied && !rotateSaved}
				onclick={closeRotateModal}
				data-testid="rotate-close-btn"
			>
				{language.current && t('users.rotateBtnClose')}
			</Button>
		{/if}
	{/snippet}
</Modal>

<style>
	/* Phase 2 follow-up — provider-coloured pill rendered in the
	 * SOURCE column. Colours come from oidcProviderColors() so
	 * the badge and the sidebar SSOProviderLogo tile share a
	 * single source of truth. Inline style overrides the
	 * background/border/colour per-render; this block just sets
	 * the shared shape. */
	.provider-badge {
		display: inline-flex;
		align-items: center;
		gap: var(--space-1);
		padding: 2px var(--space-2);
		font-size: var(--text-xs);
		font-weight: 500;
		border-radius: var(--radius-full);
		border: 1px solid;
		line-height: 1.5;
	}

	/* Phase 2 follow-up — subtle row hover to match the mockup's
	 * blue-tinted row affordance. zebra striping kept off; the
	 * divide-y on tbody already separates rows visually, and
	 * stacking another shade on top read as noisy in the smoke. */
	tbody tr {
		transition: background-color 120ms;
	}
	tbody tr:hover {
		background: color-mix(in oklch, var(--accent-cyan) 5%, transparent);
	}

	.filter-chip {
		font-size: 12px;
		padding: 4px 10px;
		border-radius: 6px;
		color: var(--text-secondary);
		background: transparent;
		border: 1px solid transparent;
		cursor: pointer;
		transition: background-color 120ms, color 120ms, border-color 120ms;
	}
	.filter-chip:hover {
		background: var(--bg-elevated);
		color: var(--text-primary);
	}
	.filter-chip.active {
		background: color-mix(in oklch, var(--accent-cyan) 16%, transparent);
		color: var(--accent-cyan);
		border-color: color-mix(in oklch, var(--accent-cyan) 32%, transparent);
	}
</style>
