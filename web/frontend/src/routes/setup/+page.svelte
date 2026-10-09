<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Setup page (spec §6.10). First-boot admin creation flow. Re-
  skinned in symmetry with /login (same constellation background,
  same OKLCH tokens scoped to .setup-page, same glass card
  treatment) so the bootstrap flow doesn't look orphaned vs the
  signed-in chrome.

  The token is regenerated on every server restart while no admin
  exists; an admin already exists → the server returns 404 and the
  page surfaces "Setup indisponible : un compte admin existe déjà."

  Logic is preserved verbatim from the pre-reskin iteration: same
  authApi.setup call, same 403 → token error, 404 → admin exists,
  400 → heuristic field mapping (username / password / displayName).
  Visual rewrite only.
-->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { authApi } from '$lib/api/auth';
	import { safeNext } from '$lib/utils/safe-next';
	import { auth } from '$lib/stores/auth.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { ApiError } from '$lib/api/types';
	import LoginBackground from '$lib/components/LoginBackground.svelte';
	import logoUrl from '$lib/assets/arenet-logo.png';

	let setupToken = $state('');
	let username = $state('');
	let displayName = $state('');
	let email = $state('');
	let password = $state('');
	let showPassword = $state(false);
	let errors = $state<Record<string, string>>({});
	let formError = $state('');
	let submitting = $state(false);

	function togglePassword(): void {
		showPassword = !showPassword;
	}

	async function handleSubmit(e: Event): Promise<void> {
		e.preventDefault();
		if (submitting) return;
		errors = {};
		formError = '';
		submitting = true;
		try {
			const user = await authApi.setup(setupToken, username, displayName, email, password);
			// /setup directly populates the auth store (the server sets
			// the cookie; the auth store now reflects the authenticated
			// admin without a follow-up /me round-trip).
			auth.user = user;
			auth.state = 'authenticated';
			// Back to the page the visitor first asked for, when the
			// layout sent them here with ?next= (same-origin paths only).
			void goto(safeNext(page.url.searchParams.get('next')));
		} catch (err) {
			if (err instanceof ApiError) {
				if (err.status === 403) {
					errors = { setupToken: t('setup.errInvalidToken') };
				} else if (err.status === 404) {
					formError = t('setup.errAdminExists');
				} else if (err.status === 400) {
					// Heuristic field mapping based on the error message text
					// (spec §6.10). Phase 2 will replace this with structured
					// field-level errors from the wire format.
					const msg = err.message.toLowerCase();
					if (msg.includes('username')) errors = { username: err.message };
					else if (msg.includes('password')) errors = { password: err.message };
					else if (msg.includes('displayname')) errors = { displayName: err.message };
					else if (msg.includes('email')) errors = { email: err.message };
					else formError = err.message;
				} else {
					formError = err.message;
				}
			} else {
				formError = t('setup.errUnexpected');
			}
		} finally {
			submitting = false;
		}
	}
</script>

<LoginBackground />

<div class="setup-page">
	<div class="setup-topbar">
		<div class="setup-brand">
			<img class="setup-brand-logo" src={logoUrl} alt="" aria-hidden="true" width="34" height="34" />
			<div class="setup-brand-name">Arenet</div>
		</div>
	</div>

	<div class="setup-card">
		<h1 class="setup-title">{language.current && t('pageTitles.setupFirstInstall')}</h1>
		<p class="setup-sub">{language.current && t('setup.subtitle')}</p>

		<div class="setup-info-banner">
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
				<line x1="12" y1="16" x2="12" y2="12" />
				<line x1="12" y1="8" x2="12.01" y2="8" />
			</svg>
			<div>
				<b>{language.current && t('setup.infoBannerTitle')}</b> {language.current && t('setup.infoBannerBody')}
				<code>Setup token:</code>. {language.current && t('setup.infoBannerBodySuffix')}
			</div>
		</div>

		{#if formError}
			<div class="setup-banner" role="alert">
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
				<div>{formError}</div>
			</div>
		{/if}

		<form onsubmit={handleSubmit} autocomplete="on" novalidate data-testid="setup-form">
			<div class="setup-field">
				<label for="setup-token">{language.current && t('setup.labelSetupToken')}</label>
				<div class="setup-input-wrap">
					<input
						id="setup-token"
						class="setup-input setup-input-mono"
						type="text"
						placeholder={language.current && t('setup.placeholderSetupToken')}
						bind:value={setupToken}
						disabled={submitting}
						aria-invalid={errors.setupToken ? 'true' : undefined}
						aria-describedby={errors.setupToken ? 'setup-token-error' : undefined}
					/>
				</div>
				{#if errors.setupToken}
					<small id="setup-token-error" class="setup-field-error">{errors.setupToken}</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-username">{language.current && t('setup.labelUsername')}</label>
				<div class="setup-input-wrap">
					<input
						id="setup-username"
						class="setup-input"
						type="text"
						placeholder={language.current && t('setup.placeholderUsername')}
						autocomplete="username"
						bind:value={username}
						disabled={submitting}
						aria-invalid={errors.username ? 'true' : undefined}
						aria-describedby={errors.username ? 'setup-username-error' : undefined}
					/>
				</div>
				{#if errors.username}
					<small id="setup-username-error" class="setup-field-error">{errors.username}</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-displayname">{language.current && t('setup.labelDisplayName')} <small>{language.current && t('setup.labelDisplayNameOptional')}</small></label>
				<div class="setup-input-wrap">
					<input
						id="setup-displayname"
						class="setup-input"
						type="text"
						placeholder={language.current && t('setup.placeholderDisplayName')}
						bind:value={displayName}
						disabled={submitting}
						aria-invalid={errors.displayName ? 'true' : undefined}
						aria-describedby={errors.displayName ? 'setup-displayname-error' : undefined}
					/>
				</div>
				{#if errors.displayName}
					<small id="setup-displayname-error" class="setup-field-error">
						{errors.displayName}
					</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-email">{language.current && t('setup.labelEmail')} <small>{language.current && t('setup.labelEmailOptional')}</small></label>
				<div class="setup-input-wrap">
					<input
						id="setup-email"
						class="setup-input"
						type="email"
						autocomplete="email"
						placeholder={language.current && t('setup.placeholderEmail')}
						bind:value={email}
						disabled={submitting}
						aria-invalid={errors.email ? 'true' : undefined}
						aria-describedby={errors.email ? 'setup-email-error' : undefined}
					/>
				</div>
				{#if errors.email}
					<small id="setup-email-error" class="setup-field-error">
						{errors.email}
					</small>
				{/if}
			</div>

			<div class="setup-field">
				<label for="setup-password">{language.current && t('setup.labelPassword')} <small>{language.current && t('setup.labelPasswordHint')}</small></label>
				<div class="setup-input-wrap">
					<input
						id="setup-password"
						class="setup-input setup-input-with-toggle"
						type={showPassword ? 'text' : 'password'}
						autocomplete="new-password"
						bind:value={password}
						disabled={submitting}
						aria-invalid={errors.password ? 'true' : undefined}
						aria-describedby={errors.password ? 'setup-password-error' : undefined}
					/>
					<button
						type="button"
						class="setup-pw-toggle"
						onclick={togglePassword}
						aria-pressed={showPassword ? 'true' : 'false'}
						aria-controls="setup-password"
						aria-label={language.current && t('setup.ariaShowPassword')}
						data-testid="setup-password-toggle"
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
				{#if errors.password}
					<small id="setup-password-error" class="setup-field-error">{errors.password}</small>
				{/if}
			</div>

			<button
				type="submit"
				class="setup-submit"
				class:loading={submitting}
				disabled={submitting}
			>
				<span class="setup-spin" aria-hidden="true"></span>
				<span class="setup-submit-label">{language.current && t('setup.btnSubmit')}</span>
			</button>
		</form>
	</div>
</div>

<style>
	/* Tokens scoped to the setup page only. Same OKLCH palette as
	 * the login page (lib/components/LoginBackground.svelte) for
	 * visual continuity through the bootstrap flow. tokens.css
	 * unchanged. */
	.setup-page {
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
		--radius-sm: 6px;
		--radius-lg: 14px;
		--font-display: 'Inter', system-ui, -apple-system, sans-serif;
		--font-body: 'Inter', system-ui, -apple-system, sans-serif;
		--font-mono: 'Geist Mono', ui-monospace, monospace;

		position: relative;
		min-height: 100vh;
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
		z-index: 10;
	}

	/* Topbar — absolute so the card stays viewport-centered
	 * (and thus aligned with the breathing halo behind it). Same
	 * approach as /login. */
	.setup-topbar {
		position: absolute;
		top: 28px;
		left: 22px;
		right: 22px;
		max-width: 1180px;
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.setup-brand {
		display: flex;
		align-items: center;
		gap: 11px;
	}
	.setup-brand-logo {
		width: 34px;
		height: 34px;
		object-fit: contain;
		flex-shrink: 0;
		filter: drop-shadow(0 12px 36px oklch(60% 0.22 260 / 0.5));
	}
	.setup-brand-name {
		font-family: var(--font-display);
		font-size: 16px;
		font-weight: 600;
		letter-spacing: -0.02em;
	}

	.setup-card {
		width: 100%;
		max-width: 480px; /* slightly wider than /login because the form has 4 fields + an info banner */
		padding: 34px;
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

	.setup-title {
		font-family: var(--font-display);
		font-size: 24px;
		font-weight: 600;
		letter-spacing: -0.025em;
		margin: 0 0 6px;
	}
	.setup-sub {
		color: var(--fg-muted);
		font-size: 13.5px;
		margin: 0 0 18px;
	}

	/* Info banner (token-from-logs note) — cyan accent variant. */
	.setup-info-banner {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		padding: 12px 14px;
		border-radius: var(--radius);
		background: var(--accent-soft);
		border: 1px solid oklch(68% 0.21 255 / 0.3);
		color: var(--fg-muted);
		font-size: 12.5px;
		line-height: 1.5;
		margin-bottom: 20px;
	}
	.setup-info-banner :global(svg) {
		width: 16px;
		height: 16px;
		flex: none;
		margin-top: 1px;
		color: var(--accent);
	}
	.setup-info-banner b {
		color: var(--fg);
		font-weight: 600;
	}
	.setup-info-banner code {
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--accent);
		padding: 1px 5px;
		background: var(--bg-sidebar);
		border-radius: 4px;
		border: 1px solid var(--border);
	}

	/* Error banner — red variant (port of the /login banner). */
	.setup-banner {
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
	.setup-banner :global(svg) {
		width: 16px;
		height: 16px;
		flex: none;
		margin-top: 1px;
	}

	.setup-field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-bottom: 14px;
	}
	.setup-field label {
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.setup-field label small {
		color: var(--fg-dim);
		font-size: 11.5px;
		font-weight: normal;
	}
	.setup-field-error {
		color: oklch(75% 0.16 25);
		font-size: 11.5px;
	}

	.setup-input-wrap {
		position: relative;
	}
	.setup-input {
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
	.setup-input:hover:not(:disabled) {
		border-color: var(--border-hi);
	}
	.setup-input:focus {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px var(--accent-soft);
		background: var(--bg-elevated);
	}
	.setup-input:disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}
	.setup-input-mono {
		font-family: var(--font-mono);
		font-size: 12.5px;
		letter-spacing: 0.01em;
	}
	.setup-input-with-toggle {
		padding-right: 42px;
	}

	.setup-pw-toggle {
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
	.setup-pw-toggle:hover {
		color: var(--fg-muted);
		background: var(--surface-2);
	}
	.setup-pw-toggle:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.setup-pw-toggle :global(svg) {
		width: 16px;
		height: 16px;
	}

	.setup-submit {
		width: 100%;
		margin-top: 6px;
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
	.setup-submit:hover:not(:disabled) {
		background: oklch(62% 0.22 255);
	}
	.setup-submit:active:not(:disabled) {
		transform: translateY(1px);
	}
	.setup-submit:disabled {
		opacity: 0.7;
		cursor: not-allowed;
	}
	.setup-spin {
		display: none;
		width: 14px;
		height: 14px;
		border-radius: 50%;
		border: 2px solid oklch(98% 0.005 250 / 0.4);
		border-top-color: #fff;
		animation: setupSpin 0.8s linear infinite;
	}
	.setup-submit.loading .setup-spin {
		display: inline-block;
	}
	.setup-submit.loading .setup-submit-label {
		opacity: 0.85;
	}
	@keyframes setupSpin {
		to {
			transform: rotate(360deg);
		}
	}

	@media (max-width: 640px) {
		.setup-page {
			padding: 80px 14px 18px;
		}
		.setup-topbar {
			top: 18px;
			left: 14px;
			right: 14px;
		}
		.setup-card {
			padding: 26px;
		}
	}
	@media (max-width: 480px) {
		.setup-card {
			padding: 22px;
		}
	}
</style>
