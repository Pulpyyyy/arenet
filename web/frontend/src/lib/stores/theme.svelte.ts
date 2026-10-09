// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Theme store (Step F §4). Singleton class instance pattern,
// consistent with auth.svelte.ts and topology.svelte.ts.
//
// `current` mirrors the `<html data-theme>` attribute. The bootstrap
// script in app.html (§4.3) sets the attribute before the first
// paint to avoid FOUC; this store takes over once the app boots.
//
// Sub-task 1.5 wires the server round-trip via authApi.setTheme:
//   - applyLocally optimistically + persist to localStorage
//   - await POST /auth/me/theme
//   - on failure, revert applyLocally and surface a toast
// The Phase 2 reconciliation step (§4.3, last paragraph) compares
// the server's value to whatever the bootstrap picked and adjusts
// silently if they differ (e.g., user changed theme on another
// device since the cookie was last refreshed).

import { authApi } from '$lib/api/auth';
import { pushToast } from './toast';
import { t } from '$lib/i18n';

export type Theme = 'dark' | 'light';

/** Normalize any input (including '', null, undefined, garbage) to
 *  a strict Theme value. Per spec §4.2: only the exact string
 *  `'light'` returns `'light'`; everything else falls back to dark. */
function normalize(t: unknown): Theme {
	return t === 'light' ? 'light' : 'dark';
}

class ThemeStore {
	current = $state<Theme>('dark');
	isApplying = $state(false);

	/** Apply a theme, optimistically, then persist via the server.
	 *  On failure, revert to the previous value and surface a toast.
	 *  Resolves once the round-trip completes (or rejects). Callers
	 *  may ignore the rejection — the store already reverted. */
	async set(t: Theme): Promise<void> {
		const next = normalize(t);
		if (next === this.current) return; // no-op
		const previous = this.current;

		this.applyLocally(next);
		this.persistLocally(next);
		this.isApplying = true;
		try {
			await authApi.setTheme(next);
			// The server refreshed the arenet_theme cookie; nothing more
			// to do here. localStorage already holds `next`.
		} catch (err) {
			// Revert. The cookie + server still hold `previous`, so the
			// next reload will be consistent — but we also rewrite
			// localStorage so a refresh during the failed window doesn't
			// linger on the wrong value.
			this.applyLocally(previous);
			this.persistLocally(previous);
			pushToast(t('settings.themeSaveFailed'), 'danger');
			throw err;
		} finally {
			this.isApplying = false;
		}
	}

	/** Apply WITHOUT touching localStorage or the server. Used by
	 *  reconcileFromServer after /auth/me resolves, and internally
	 *  by set() when reverting. */
	applyLocally(t: Theme): void {
		const next = normalize(t);
		this.current = next;
		if (typeof document !== 'undefined') {
			document.documentElement.dataset.theme = next;
		}
	}

	/** Reconcile against the server's value after /auth/me resolves
	 *  (spec §4.3 Phase 2). If the server's value differs from what
	 *  bootstrap picked, swap silently — the 200 ms transition on
	 *  body background+color animates the difference. Empty / unknown
	 *  values are mapped to "dark" via normalize().
	 *
	 *  This is a no-op when the bootstrap and server already agree,
	 *  which is the common case (the cookie is refreshed on every
	 *  successful /auth/me/theme call). */
	reconcileFromServer(serverTheme: unknown): void {
		const next = normalize(serverTheme);
		if (next === this.current) return;
		this.applyLocally(next);
	}

	/** Mirror the chosen theme into localStorage so subsequent paints
	 *  in private-cookie scenarios (or cookie-deletion edge cases)
	 *  still hit the bootstrap's localStorage tier (§4.3). */
	private persistLocally(t: Theme): void {
		if (typeof localStorage === 'undefined') return;
		try {
			localStorage.setItem('arenet_theme', t);
		} catch (_) {
			// Private browsing / quota — ignore. The cookie + server
			// remain authoritative.
		}
	}
}

export const theme = new ThemeStore();
