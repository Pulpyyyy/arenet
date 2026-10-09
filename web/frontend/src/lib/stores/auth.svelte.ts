// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Auth store: current user identity + authentication state. Exposed as
// Svelte 5 runes for fine-grained reactivity (spec §6.2).
//
// Singleton class instance pattern, consistent with Step C's toast.ts
// and loading.ts. The `unknown` state signals that bootstrap has not
// yet completed; the layout shell displays a spinner during that window
// to avoid flashing the login page. `error` means /me failed for a
// reason other than 401 (unreachable, 5xx): we do not know who the user
// is, so the layout says so and offers a retry instead of spinning.

import { authApi, type User } from '$lib/api/auth';
import { ApiError } from '$lib/api/types';
import { theme } from './theme.svelte';
import { language } from './language.svelte';

export type AuthState = 'unknown' | 'anonymous' | 'authenticated' | 'locked' | 'error';

class AuthStore {
	user = $state<User | null>(null);
	state = $state<AuthState>('unknown');
	isBootstrapping = $state(false);
	// HTTP status of the failed bootstrap while state is 'error'; 0 means
	// no response at all (network down, server stopped, timeout).
	bootstrapErrorStatus = $state(0);

	async bootstrap(): Promise<void> {
		this.isBootstrapping = true;
		try {
			const me = await authApi.me();
			this.user = me;
			this.state = me.locked ? 'locked' : 'authenticated';
			// Phase 2 reconciliation (Step F §4.3): align the theme that
			// the FOUC bootstrap picked with whatever the server stores.
			// No-op when they already agree, which is the common case.
			theme.reconcileFromServer(me.themePreference);
			// v2.9.11 i18n Phase 1 — same reconciliation for the
			// language bootstrap. me.languagePreference may be "" for
			// pre-v2.9.11 rows; the store normalises that to "en".
			language.reconcileFromServer(me.languagePreference);
		} catch (err) {
			if (err instanceof ApiError && err.status === 401) {
				this.state = 'anonymous';
				this.user = null;
			} else {
				// Not a 401, so not a reason to send the user to /login:
				// that would hide the outage and lose the page they asked
				// for. Leaving 'unknown' kept a spinner up forever.
				console.error('auth bootstrap failed:', err);
				// Only a first bootstrap (or a retry of one) has nothing to
				// show without /me. A refresh of a live session, as after a
				// password change, keeps the session it already has.
				if (this.state === 'unknown' || this.state === 'error') {
					this.state = 'error';
					this.bootstrapErrorStatus = err instanceof ApiError ? err.status : 0;
				}
			}
		} finally {
			this.isBootstrapping = false;
		}
	}

	async login(username: string, password: string, rememberMe: boolean): Promise<void> {
		const user = await authApi.login(username, password, rememberMe);
		this.user = user;
		this.state = 'authenticated';
		// /auth/login returns a slimmer loginResponse than /me — themePreference
		// isn't on the wire there. The cookie has just been refreshed by the
		// server, but the DOM still shows whatever the bootstrap picked on
		// initial load (or the previous user's theme on a re-login). Fetch
		// /me once to pull the authoritative preference, then reconcile.
		try {
			const me = await authApi.me();
			this.user = me;
			theme.reconcileFromServer(me.themePreference);
			// v2.9.11 i18n Phase 1 — language reconcile mirrors theme.
			language.reconcileFromServer(me.languagePreference);
		} catch (err) {
			// Non-fatal: leave the bootstrap's theme in place. The next
			// page navigation that hits bootstrap will pick up the
			// freshly-set cookie anyway.
			console.warn('login: post-login /me failed (non-fatal):', err);
		}
	}

	async logout(): Promise<void> {
		try {
			await authApi.logout();
		} catch (err) {
			// Even if the server fails, clear local state.
			console.warn('logout request failed (clearing local state anyway):', err);
		}
		this.user = null;
		this.state = 'anonymous';
	}

	async unlock(password: string): Promise<void> {
		await authApi.unlock(password);
		this.state = 'authenticated';
		// The user object is still valid; only the state changes.
	}

	// setLocked is idempotent: it only transitions from 'authenticated'.
	// Trying to lock from 'anonymous' or 'unknown' is a no-op, preventing
	// race conditions during page transitions (spec §6.2 design notes).
	setLocked(): void {
		if (this.state === 'authenticated') {
			this.state = 'locked';
		}
	}

	// clear is called by the API client's 401 interceptor (spec §6.4).
	clear(): void {
		this.user = null;
		this.state = 'anonymous';
	}
}

export const auth = new AuthStore();
