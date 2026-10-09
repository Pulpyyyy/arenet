<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  LockScreen (spec §6.8). Full-screen overlay rendered above the
  existing UI when the session is in the `locked` state. Backdrop-
  blur preserves the underlying UI in the DOM (open modals,
  scroll position, form drafts) so the user resumes exactly where
  they were after unlocking.

  Re-skinned in symmetry with /login and /setup (LSC port,
  2026-05): tokens OKLCH scoped to .lockscreen-page, glass card
  with backdrop-filter, translated copy, eye toggle on the password
  field, local cyan/violet halo behind the card. The
  constellation background is NOT reused on purpose — the
  LockScreen invariant is "underlying UI must remain visible
  through blur" (cf. spec §6.8); painting a full-screen
  decoration on top would defeat that.

  Mounted conditionally by +layout.svelte (Chunk 7 Étape 2) via
  {#if auth.state === 'locked'}, which also makes the app shell
  behind it `inert`. No escape handler: the way out is to unlock
  or to sign out (same flow as the sidebar's sign-out, then
  /login). Focus starts in the password field (the SSO button for
  an OIDC account) and Tab cycles inside the card.

  Auth logic preserved verbatim: auth.unlock(password) → POST
  /api/v1/auth/unlock, 401 → "wrong password", other → the
  server's message.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { fade } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import { ApiError } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { withNext } from '$lib/utils/safe-next';

	// Reading language.current makes every label re-render on a
	// language switch — same helper as the routes page.
	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	let password = $state('');
	let showPassword = $state(false);
	let error = $state('');
	let submitting = $state(false);
	let passwordInput: HTMLInputElement | undefined = $state();
	let card: HTMLDivElement | undefined = $state();
	let signingOut = $state(false);

	// SSO re-authentication comes back to the page behind the lock
	// (the backend keeps ?next=, same rules as safeNext).
	const ssoHref = $derived(
		withNext('/api/v1/auth/oidc/login', page.url.pathname + page.url.search)
	);

	// Focusable descendants of the card, in tab order (same selector
	// as Modal's trap).
	function focusable(): HTMLElement[] {
		if (!card) return [];
		const selector =
			'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
		return Array.from(card.querySelectorAll<HTMLElement>(selector));
	}

	onMount(() => {
		// An OIDC account has no password field: start on its button.
		(passwordInput ?? focusable()[0])?.focus();
	});

	// Focus trap. The layout makes the app shell inert, but the
	// banners and gates outside it are still in the tab order, and so
	// is the browser chrome: keep Tab and Shift+Tab inside the card.
	function onKeydown(event: KeyboardEvent): void {
		if (event.key !== 'Tab') return;
		const items = focusable();
		if (items.length === 0) {
			event.preventDefault();
			return;
		}
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		if (!active || !card?.contains(active)) {
			event.preventDefault();
			(event.shiftKey ? last : first).focus();
		} else if (event.shiftKey && active === first) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && active === last) {
			event.preventDefault();
			first.focus();
		}
	}

	// The way out that is not unlocking: the sidebar's sign-out flow.
	// Logging out turns the state anonymous, which unmounts this.
	async function signOut(): Promise<void> {
		if (signingOut) return;
		signingOut = true;
		try {
			await auth.logout();
		} finally {
			signingOut = false;
			void goto('/login');
		}
	}

	function togglePassword(): void {
		showPassword = !showPassword;
		// Re-focus the input after toggling so the user can keep
		// typing without grabbing the mouse.
		setTimeout(() => passwordInput?.focus(), 0);
	}

	async function handleSubmit(e: Event): Promise<void> {
		e.preventDefault();
		if (submitting) return;
		if (!password) {
			error = t('auth.errors.passwordRequired');
			return;
		}
		submitting = true;
		error = '';
		try {
			await auth.unlock(password);
			// On success the auth store transitions to 'authenticated'
			// and this component unmounts via the parent's {#if} guard.
		} catch (err) {
			if (err instanceof ApiError) {
				// Step #S-24: OIDC users have no local password — backend
				// returns 400 + code:oidc_unlock_unsupported. Logout +
				// redirect to /login so the user can re-authenticate via
				// SSO. The full fix #S-25 (v1.0.2) will replace this modal
				// entirely with a "Sign in again via SSO" button for OIDC
				// users — for now we hand off to the login screen.
				if (err.code === 'oidc_unlock_unsupported') {
					auth.clear();
					await goto('/login?reason=oidc_unlock_required');
					return;
				}				
				error = err.status === 401 ? t('auth.lock.wrongPassword') : err.message;
			} else {
				error = t('auth.errors.unexpected');
			}
			password = '';
			passwordInput?.focus();
		} finally {
			submitting = false;
		}
	}
</script>

<svelte:document onkeydown={onKeydown} />

<div
	class="lockscreen-page"
	role="dialog"
	aria-modal="true"
	aria-labelledby="lockscreen-title"
	transition:fade={{ duration: 200, easing: cubicOut }}
>
	<div class="lockscreen-halo" aria-hidden="true"></div>

	<div class="lockscreen-card" bind:this={card}>
		<h2 id="lockscreen-title" class="lockscreen-title">{tl('auth.lock.title')}</h2>

		{#if auth.user?.authSource === 'oidc'}
			<!-- Step #S-25: OIDC users have no local password.
				Render a re-authenticate button that hands off to
				the existing /api/v1/auth/oidc/login endpoint, which
				starts a fresh SSO flow and lands the user back here
				authenticated. The quick-fix #S-24 (backend returns
				400 + code:oidc_unlock_unsupported on POST /unlock)
				remains in place as a safety net. -->
			<p class="lockscreen-sub">
				{tl('auth.lock.signedInAs')}
				<span class="lockscreen-user">{auth.user?.username ?? ''}</span>
				{tl('auth.lock.viaSso')}
				{tl('auth.lock.ssoPrompt')}
			</p>
			<a class="lockscreen-submit" href={ssoHref}>
				<span class="lockscreen-submit-label">{tl('auth.lock.ssoButton')}</span>
			</a>
		{:else}
		<p class="lockscreen-sub">
			{tl('auth.lock.signedInAs')}
			<span class="lockscreen-user">{auth.user?.username ?? ''}</span>.
			{tl('auth.lock.passwordPrompt')}
		</p>

		{#if error}
			<div class="lockscreen-banner" role="alert">
				<svg
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
				>
					<circle cx="12" cy="12" r="10" />
					<line x1="12" y1="8" x2="12" y2="12" />
					<line x1="12" y1="16" x2="12.01" y2="16" />
				</svg>
				<div>{error}</div>
			</div>
		{/if}

		<form onsubmit={handleSubmit} autocomplete="on" novalidate>
			<div class="lockscreen-field">
				<label for="lockscreen-password">{tl('auth.passwordLabel')}</label>
				<div class="lockscreen-input-wrap">
					<input
						id="lockscreen-password"
						class="lockscreen-input lockscreen-input-with-toggle"
						type={showPassword ? 'text' : 'password'}
						autocomplete="current-password"
						bind:value={password}
						bind:this={passwordInput}
						disabled={submitting}
						aria-invalid={error ? 'true' : undefined}
					/>
					<button
						type="button"
						class="lockscreen-pw-toggle"
						onclick={togglePassword}
						aria-pressed={showPassword ? 'true' : 'false'}
						aria-controls="lockscreen-password"
						aria-label={tl('auth.showPassword')}
					>
						{#if showPassword}
							<svg
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
								aria-hidden="true"
							>
								<path
									d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"
								/>
								<line x1="1" y1="1" x2="23" y2="23" />
							</svg>
						{:else}
							<svg
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
								aria-hidden="true"
							>
								<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
								<circle cx="12" cy="12" r="3" />
							</svg>
						{/if}
					</button>
				</div>
			</div>

			<button
				type="submit"
				class="lockscreen-submit"
				class:loading={submitting}
				disabled={submitting}
			>
				<span class="lockscreen-spin" aria-hidden="true"></span>
				<span class="lockscreen-submit-label">{tl('auth.lock.unlock')}</span>
			</button>
		</form>
		{/if}

		<button
			type="button"
			class="lockscreen-signout"
			onclick={signOut}
			disabled={signingOut}
			data-testid="lockscreen-signout"
		>
			{tl('common.signOut')}
		</button>
	</div>
</div>

<style>
	/* Tokens scoped to the lockscreen overlay. Same OKLCH palette
	 * as the .login-page / .setup-page (visual continuity through
	 * the auth corridor). tokens.css unchanged. */
	.lockscreen-page {
		--bg: oklch(15% 0.005 250);
		--surface: oklch(19% 0.006 250);
		--surface-2: oklch(22% 0.007 250);
		--border: oklch(28% 0.009 250);
		--border-hi: oklch(34% 0.011 250);
		--fg: oklch(96% 0.005 250);
		--fg-muted: oklch(68% 0.012 250);
		--fg-dim: oklch(54% 0.011 250);
		--accent: oklch(68% 0.21 255);
		--accent-soft: oklch(68% 0.21 255 / 0.14);
		--accent-line: oklch(68% 0.21 255 / 0.45);
		--radius: 8px;
		--radius-lg: 14px;
		--font-display: 'Inter', system-ui, -apple-system, sans-serif;
		--font-body: 'Inter', system-ui, -apple-system, sans-serif;
		--font-mono: 'Geist Mono', ui-monospace, monospace;

		position: fixed;
		inset: 0;
		z-index: 1000;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 28px 22px;
		color: var(--fg);
		font-family: var(--font-body);
		font-size: 14px;
		line-height: 1.5;
		-webkit-font-smoothing: antialiased;
		font-variant-numeric: tabular-nums;

		/* The dim+blur layer that preserves the underlying UI's
		 * shape behind the glass card. Spec §6.8 invariant: the
		 * user must see they're locked on top of their previous
		 * context, not on a new full-screen scene. */
		background-color: var(--overlay-lock);
		backdrop-filter: blur(8px);
		-webkit-backdrop-filter: blur(8px);
	}

	/* Local breathing halo just behind the card — apporte la
	 * signature cyan/violet du couloir d'auth sans peindre un
	 * fond constellation entier (qui effacerait le contexte). */
	.lockscreen-halo {
		position: absolute;
		top: 50%;
		left: 50%;
		width: 520px;
		height: 520px;
		transform: translate(-50%, -50%);
		border-radius: 50%;
		background: radial-gradient(
			circle,
			oklch(68% 0.21 255 / 0.16) 0%,
			oklch(52% 0.22 265 / 0.07) 35%,
			transparent 70%
		);
		filter: blur(40px);
		pointer-events: none;
		animation: lockscreenBreathe 9s ease-in-out infinite;
	}
	@keyframes lockscreenBreathe {
		0%,
		100% {
			transform: translate(-50%, -50%) scale(0.94);
			opacity: 0.75;
		}
		50% {
			transform: translate(-50%, -50%) scale(1.05);
			opacity: 1;
		}
	}

	.lockscreen-card {
		position: relative;
		width: 100%;
		max-width: 400px;
		padding: 32px;
		background: oklch(19% 0.006 250 / 0.85);
		backdrop-filter: blur(18px) saturate(140%);
		-webkit-backdrop-filter: blur(18px) saturate(140%);
		border: 1px solid var(--border-hi);
		border-radius: var(--radius-lg);
		box-shadow:
			0 1px 0 0 oklch(60% 0.012 250 / 0.06) inset,
			0 32px 80px -32px oklch(0% 0 0 / 0.65),
			0 2px 6px oklch(0% 0 0 / 0.3);
	}

	.lockscreen-title {
		font-family: var(--font-display);
		font-size: 22px;
		font-weight: 600;
		letter-spacing: -0.025em;
		margin: 0 0 6px;
	}
	.lockscreen-sub {
		color: var(--fg-muted);
		font-size: 13.5px;
		margin: 0 0 22px;
	}
	.lockscreen-user {
		color: var(--fg);
		font-family: var(--font-mono);
		font-size: 12.5px;
	}

	.lockscreen-banner {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 10px 12px;
		border-radius: var(--radius);
		background: oklch(66% 0.20 25 / 0.10);
		border: 1px solid oklch(66% 0.20 25 / 0.4);
		color: oklch(86% 0.12 25);
		font-size: 12.5px;
		line-height: 1.45;
		margin-bottom: 16px;
	}
	.lockscreen-banner :global(svg) {
		width: 16px;
		height: 16px;
		flex: none;
		margin-top: 1px;
	}

	.lockscreen-field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-bottom: 16px;
	}
	.lockscreen-field label {
		font-size: 12.5px;
		color: var(--fg-muted);
	}

	.lockscreen-input-wrap {
		position: relative;
	}
	.lockscreen-input {
		width: 100%;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 10px 12px;
		color: var(--fg);
		font: inherit;
		font-size: 14px;
		outline: none;
		transition: border-color 0.12s, box-shadow 0.12s, background 0.12s;
	}
	.lockscreen-input:hover:not(:disabled) {
		border-color: var(--border-hi);
	}
	.lockscreen-input:focus {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px var(--accent-soft);
		background: var(--bg-elevated);
	}
	.lockscreen-input:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.lockscreen-input-with-toggle {
		padding-right: 42px;
	}

	.lockscreen-pw-toggle {
		position: absolute;
		right: 8px;
		top: 50%;
		transform: translateY(-50%);
		width: 28px;
		height: 28px;
		border-radius: 6px;
		display: grid;
		place-items: center;
		color: var(--fg-dim);
		background: none;
		border: none;
		cursor: pointer;
	}
	.lockscreen-pw-toggle:hover {
		color: var(--fg-muted);
		background: var(--surface-2);
	}
	.lockscreen-pw-toggle:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.lockscreen-pw-toggle :global(svg) {
		width: 16px;
		height: 16px;
	}

	.lockscreen-submit {
		width: 100%;
		padding: 11px 14px;
		background: var(--accent);
		color: #fff;
		font: inherit;
		font-weight: 500;
		font-size: 14px;
		border-radius: var(--radius);
		border: 1px solid transparent;
		cursor: pointer;
		transition: background 0.12s, transform 0.04s;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 8px;
	}
	.lockscreen-submit:hover:not(:disabled) {
		background: oklch(62% 0.22 255);
	}
	.lockscreen-submit:active:not(:disabled) {
		transform: translateY(1px);
	}
	.lockscreen-submit:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}
	.lockscreen-spin {
		display: none;
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 2px solid oklch(98% 0.005 250 / 0.4);
		border-top-color: #fff;
		animation: lockscreenSpin 0.8s linear infinite;
	}
	.lockscreen-submit.loading .lockscreen-spin {
		display: inline-block;
	}
	.lockscreen-submit.loading .lockscreen-submit-label {
		opacity: 0.85;
	}
	.lockscreen-signout {
		display: block;
		margin: 14px auto 0;
		padding: 4px 8px;
		background: none;
		border: none;
		border-radius: 6px;
		color: var(--fg-muted);
		font: inherit;
		font-size: 12.5px;
		cursor: pointer;
	}
	.lockscreen-signout:hover:not(:disabled) {
		color: var(--fg);
		text-decoration: underline;
	}
	.lockscreen-signout:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.lockscreen-signout:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	@keyframes lockscreenSpin {
		to {
			transform: rotate(360deg);
		}
	}

	@media (max-width: 480px) {
		.lockscreen-card {
			padding: 24px;
		}
		.lockscreen-halo {
			width: 360px;
			height: 360px;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.lockscreen-halo,
		.lockscreen-spin {
			animation: none !important;
		}
	}
</style>
