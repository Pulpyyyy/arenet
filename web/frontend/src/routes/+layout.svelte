<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Root layout shell. Drives the auth state machine and hosts the
  always-mounted ChangePasswordModal, the conditional LockScreen
  overlay, the compromised-password banner, and the heartbeat
  lifecycle.

  Step R.2 chrome (2026-06-01): replaces the Step F collapsed-
  capable sidebar with the new fixed-width Sidebar + Topbar combo
  matching docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html.
  The mock has no collapse mode — sidebar is fixed --sb-width
  (232px). The SIDEBAR_STORAGE_KEY persistence is removed because
  there is nothing to persist.

  State transitions:

    unknown      → centered Spinner (bootstrap pending)
    error        → centered panel: why /me failed + Retry (no redirect)
    anonymous    → render children unchanged on /login and /setup
                   (which use +layout@.svelte resets); anywhere else
                   a spinner while redirecting to /setup on a fresh
                   install, /login otherwise, with ?next=<the page>
    authenticated → Sidebar + Topbar + main + optional banner
                    + LockScreen=false
    locked       → Sidebar + Topbar + main + LockScreen overlay (z-1000)

  Bootstrap runs once at mount, and again only from the error panel's
  Retry button. Subsequent state changes happen via
  the API client interceptors (401 → clear, 403 → setLocked) and the
  client-side idle timer.
-->
<script lang="ts">
	import '../app.css';
	// Country flag SVGs (flag-icons) — served locally, no CDN. Used by the
	// Flag component in the GeoIP / country-block selector.
	import 'flag-icons/css/flag-icons.min.css';
	import { onMount, onDestroy, untrack } from 'svelte';
	import { goto } from '$app/navigation';
	import { navigating, page } from '$app/state';
	import favicon from '$lib/assets/arenet-logo.png';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import Topbar from '$lib/components/Topbar.svelte';
	import LockScreen from '$lib/components/LockScreen.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import ChangePasswordModal from '$lib/components/ChangePasswordModal.svelte';
	import ToastContainer from '$lib/components/ToastContainer.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { loading } from '$lib/stores/loading';
	import { auth } from '$lib/stores/auth.svelte';
	import { idle } from '$lib/stores/idle.svelte';
	import { authApi } from '$lib/api/auth';
	import { isEntryPath, withNext } from '$lib/utils/safe-next';

	const HEARTBEAT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes (spec §6.7)

	let { children } = $props();

	let heartbeatId: ReturnType<typeof setInterval> | null = null;
	let changePasswordModalOpen = $state(false);

	onMount(async () => {
		await startSession();
	});

	// Shared by mount and the error panel's Retry: whichever bootstrap
	// succeeds needs the same idle/heartbeat wiring.
	async function startSession(): Promise<void> {
		// Bootstrap the auth store. This call sets state to one of
		// authenticated / locked / anonymous, or error when /me failed
		// without a 401 (the panel below then offers a retry).
		await auth.bootstrap();

		// Wire idle timer + heartbeat once we know we're in a session
		// (locked is still a valid session — the lock just gates
		// hard-auth endpoints).
		if (auth.state === 'authenticated' || auth.state === 'locked') {
			idle.start();
			startHeartbeat();
		}

		// An anonymous result is handled by the redirect effect below.
	}

	// Send an anonymous visitor away from any page but /login and
	// /setup. An effect rather than a step of startSession, so it also
	// covers a session cleared later by the 401 interceptor and a Back
	// navigation onto a protected page: the anonymous branch below
	// shows a spinner there, and nothing else would move it.
	$effect(() => {
		if (auth.state !== 'anonymous') return;
		// A navigation already under way (LockScreen and sign-out go to
		// /login themselves, LockScreen with a ?reason=) lands first;
		// this effect runs again once it has.
		if (navigating.to) return;
		const here = page.url.pathname;
		if (isEntryPath(here)) return;
		const target = here + page.url.search;
		// untrack: the request() call reads stores of its own (idle,
		// auth) that must not become dependencies of this effect.
		untrack(() => void redirectAnonymous(target));
	});

	let anonymousRedirectInFlight = false;

	// On a fresh install there is no account to sign in with, so the
	// visitor goes to /setup instead of /login. Either way the page
	// asked for rides along as ?next= and is where they land after.
	async function redirectAnonymous(target: string): Promise<void> {
		if (anonymousRedirectInFlight) return;
		anonymousRedirectInFlight = true;
		try {
			// A failed probe means "not a fresh install", like on /login:
			// /login is the page that works in both cases.
			const fresh = await authApi.setupStatus().then(
				(s) => s.available,
				() => false
			);
			// Signed in, moved to an entry page, or navigating, meanwhile.
			// In the last case the effect runs again once that lands.
			if (auth.state !== 'anonymous' || navigating.to || isEntryPath(page.url.pathname)) {
				return;
			}
			// replaceState: Back must not return to the page that just
			// bounced the visitor here.
			await goto(withNext(fresh ? '/setup' : '/login', target), { replaceState: true });
		} catch (err) {
			console.warn('anonymous redirect failed:', err);
		} finally {
			anonymousRedirectInFlight = false;
		}
	}

	function retryBootstrap(): void {
		// The button is disabled while loading; this guards a double
		// activation landing before the re-render.
		if (auth.isBootstrapping) return;
		void startSession();
	}

	onDestroy(() => {
		idle.stop();
		stopHeartbeat();
	});

	function startHeartbeat(): void {
		if (heartbeatId !== null) return;
		heartbeatId = setInterval(() => {
			// Tab-visibility gate: do nothing in background tabs.
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
				return;
			}
			// State gate: heartbeat only when actively authenticated
			// (locked sessions get a 403 from /heartbeat, handled by
			// the interceptor; we skip to avoid the noise).
			if (auth.state !== 'authenticated') return;
			authApi.heartbeat().catch((err) => {
				// 401 and 403 already handled by the client interceptor.
				// Anything else: log and continue.
				console.warn('heartbeat failed:', err);
			});
		}, HEARTBEAT_INTERVAL_MS);
	}

	function stopHeartbeat(): void {
		if (heartbeatId !== null) {
			clearInterval(heartbeatId);
			heartbeatId = null;
		}
	}
</script>

<svelte:head>
	<link rel="icon" type="image/png" href={favicon} />
	<title>Arenet</title>
</svelte:head>

{#if auth.state === 'unknown'}
	<!-- Bootstrap in flight: minimal centered spinner, no chrome.
	     Prevents flashing /login before /me resolves. -->
	<div class="flex items-center justify-center min-h-screen bg-base">
		<Spinner size="lg" />
	</div>
{:else if auth.state === 'error'}
	<!-- /me failed without a 401: say so instead of spinning, and do not
	     redirect to /login, which would hide the outage and lose the
	     page asked for. The only spinner is the button's, while a retry
	     is in flight. -->
	<div class="flex items-center justify-center min-h-screen bg-base p-4">
		<div
			class="max-w-md rounded-xl border border-border-default bg-surface p-6 text-center"
			role="alert"
			data-testid="bootstrap-error"
		>
			<p class="text-sm text-primary mb-4">
				{language.current &&
					(auth.bootstrapErrorStatus === 0
						? t('bootstrap.unreachable')
						: t('bootstrap.serverError', { status: auth.bootstrapErrorStatus }))}
			</p>
			<Button variant="primary" loading={auth.isBootstrapping} onclick={retryBootstrap}>
				{#snippet children()}{language.current && t('bootstrap.retry')}{/snippet}
			</Button>
		</div>
	</div>
{:else if auth.state === 'anonymous'}
	<!-- /login and /setup own their layout via +layout@.svelte resets
	     and render as a passthrough. Any other page is on its way to
	     one of them (the redirect effect): a spinner rather than a
	     protected page that would only fire requests to be refused. -->
	{#if isEntryPath(page.url.pathname)}
		{@render children?.()}
	{:else}
		<div class="flex items-center justify-center min-h-screen bg-base">
			<Spinner size="lg" />
		</div>
	{/if}
	<ToastContainer />
{:else}
	<!-- Skip link: first stop for Tab, hidden until focused. Focuses
	     <main> by hand rather than following the #main hash, which
	     would overwrite a hash the page uses (/alerting#history). -->
	<a
		href="#main"
		class="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[1001] focus:rounded-md focus:border focus:border-border-strong focus:bg-elevated focus:px-3 focus:py-2 focus:text-sm focus:text-primary"
		onclick={(e) => {
			e.preventDefault();
			document.getElementById('main')?.focus();
		}}>{language.current && t('a11y.skipToContent')}</a
	>
	<!-- authenticated or locked: full layout. Compromised-password
	     banner above; LockScreen overlay on locked. -->
	<!-- v2.48 — an account created by an administrator cannot be used
	     for anything until it changes its first password, because that
	     administrator knows it: they either typed it or read it off the
	     screen once.
	     
	     A blocking overlay rather than a banner. A banner is a
	     suggestion, and the whole property here is that the window
	     between creation and the user's own password is one login long.
	     
	     It sits BELOW LockScreen (z-index 999 against 1000) on purpose:
	     a locked session has to be unlocked first, and stacking this on
	     top would leave the operator facing a password form they cannot
	     submit.
	     
	     The modal is opened from here rather than forced: dismissing it
	     returns to this overlay, so there is no state in which someone
	     is blocked with nothing to press. A successful change refreshes
	     the session, the flag clears, and this disappears on its own. -->
	{#if auth.user?.mustChangePassword}
		<div class="must-change" role="alertdialog" aria-modal="true" data-testid="must-change-gate">
			<div class="must-change-card">
				<h1 class="text-lg font-semibold text-primary mb-2">
					{language.current && t('mustChange.title')}
				</h1>
				<p class="text-sm text-secondary mb-4">{language.current && t('mustChange.body')}</p>
				<Button variant="primary" onclick={() => (changePasswordModalOpen = true)}>
					{#snippet children()}{language.current && t('mustChange.action')}{/snippet}
				</Button>
			</div>
		</div>
	{/if}

	{#if auth.user?.passwordCompromised}
		<div
			class="bg-down/10 border-b border-down text-down px-6 py-3 flex items-center justify-between"
			role="alert"
		>
			<div>
				<strong>{language.current && t('passwordBreach.title')}</strong>
				{language.current && t('passwordBreach.body')}
			</div>
			<Button
				variant="danger"
				size="sm"
				onclick={() => (changePasswordModalOpen = true)}
			>
				{#snippet children()}{language.current && t('passwordBreach.action')}{/snippet}
			</Button>
		</div>
	{/if}

	<!-- Locked: the shell behind LockScreen leaves the tab order and
	     the accessibility tree. `|| undefined` drops the attribute
	     rather than writing inert="false". -->
	<div class="app-shell" inert={auth.state === 'locked' || undefined}>
		<Sidebar />
		<div class="app-col">
			<Topbar />
			{#if auth.user?.role === 'viewer'}
				<div class="ro-banner" role="status">
					<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
						<rect x="3" y="7" width="10" height="7" rx="1" />
						<path d="M5 7V5a3 3 0 016 0v2" />
					</svg>
					<!-- Split around the two bold words because their position
					     differs between languages; "after" carries its own
					     leading space or punctuation. -->
					<span
						>{language.current && t('readOnlyBanner.before')}
						<b>{language.current && t('readOnlyBanner.strong')}</b>
						{language.current && t('readOnlyBanner.middle')}
						<b>viewer</b>{language.current && t('readOnlyBanner.after')}</span
					>
				</div>
			{/if}
			<!-- No aria-live here: it made the whole page a live region, so
			     every 1 s metrics push and re-render was read out. Route
			     changes are already announced by SvelteKit's own announcer
			     (it reads document.title after each navigation). -->
			<main id="main" tabindex="-1" class="app-main focus:outline-none" aria-busy={$loading}>
				{#if $loading}
					<div class="loading-bar">
						<div class="loading-shimmer"></div>
					</div>
				{/if}
				{@render children?.()}
			</main>
		</div>
	</div>

	<ToastContainer />

	<!-- Always mounted: preserves form state across show/hide. -->
	<ChangePasswordModal bind:open={changePasswordModalOpen} />

	{#if auth.state === 'locked'}
		<LockScreen />
	{/if}
{/if}

<style>
	/* v2.48 — see the markup comment: blocking, and below LockScreen. */
	.must-change {
		position: fixed;
		inset: 0;
		z-index: 999;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 16px;
		background: color-mix(in oklch, var(--bg-base) 88%, transparent);
		backdrop-filter: blur(4px);
	}
	.must-change-card {
		max-width: 28rem;
		border: 1px solid var(--border-default);
		background: var(--bg-surface);
		border-radius: 12px;
		padding: 24px;
		text-align: center;
	}

	.app-shell {
		display: flex;
		min-height: 100vh;
		background: var(--bg);
	}
	.app-col {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-width: 0; /* allow inner content to scroll horizontally if needed */
	}
	.app-main {
		flex: 1;
		padding: 22px;
		position: relative;
	}
	.ro-banner {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 8px 14px;
		background: oklch(80% 0.14 85 / 0.10);
		border-bottom: 1px solid oklch(80% 0.14 85 / 0.3);
		color: var(--status-warn-fg);
		font-size: 12.5px;
	}
	.ro-banner svg { flex: none; }
	.ro-banner b { color: var(--status-warn-fg); font-weight: 500; }

	.loading-bar {
		position: absolute;
		left: 0;
		right: 0;
		top: 0;
		height: 2px;
		overflow: hidden;
	}
	.loading-shimmer {
		height: 100%;
		width: 33%;
		background: var(--accent);
		animation: shimmer 1.5s ease-in-out infinite;
	}
	@keyframes shimmer {
		0% { transform: translateX(-100%); }
		100% { transform: translateX(400%); }
	}
</style>
