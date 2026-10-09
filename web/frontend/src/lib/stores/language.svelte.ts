// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Language store (v2.9.11 i18n Phase 1). Singleton class instance
// pattern, byte-for-byte mirror of theme.svelte.ts. Same lifecycle:
//   - applyLocally optimistically + persist to localStorage
//   - await POST /auth/me/language
//   - on failure, revert applyLocally and surface a toast
// reconcileFromServer runs after /auth/me resolves; it adjusts the
// active language silently if the server differs from whatever the
// bootstrap script picked (e.g., user changed language on another
// device since the cookie was last refreshed).
//
// `current` mirrors <html lang>. The bootstrap script in app.html
// sets the attribute before the first paint to avoid FOUC; this
// store takes over once the app boots.

import { authApi } from '$lib/api/auth';
import { pushToast } from './toast';
// Circular on purpose: $lib/i18n reads `language` from this module.
// Neither side touches the other at import time (only inside
// functions), so ES module evaluation order is not an issue.
import { t } from '$lib/i18n';

export type Language = 'en' | 'fr';

/** Normalize any input (including '', null, undefined, garbage) to
 *  a strict Language value. Empty / unknown collapse to 'en' — the
 *  hardcoded default per the i18n Phase 1 spec edge-cases section.
 *  Identical shape to theme.svelte.ts normalize(). */
function normalize(l: unknown): Language {
	return l === 'fr' ? 'fr' : 'en';
}

class LanguageStore {
	current = $state<Language>('en');
	isApplying = $state(false);

	/** Apply a language, optimistically, then persist via the server.
	 *  On failure, revert to the previous value and surface a toast.
	 *  Resolves once the round-trip completes (or rejects). Callers
	 *  may ignore the rejection — the store already reverted. */
	async set(l: Language): Promise<void> {
		const next = normalize(l);
		if (next === this.current) return; // no-op
		const previous = this.current;

		this.applyLocally(next);
		this.persistLocally(next);
		this.isApplying = true;
		try {
			await authApi.setLanguage(next);
			// The server refreshed the arenet_language cookie; nothing
			// more to do here. localStorage already holds `next`.
		} catch (err) {
			this.applyLocally(previous);
			this.persistLocally(previous);
			// Resolved AFTER the revert above, so the toast speaks the
			// language the UI is back in — the one the operator was
			// reading when the change failed.
			pushToast(t('settings.languageSaveFailed'), 'danger');
			throw err;
		} finally {
			this.isApplying = false;
		}
	}

	/** Apply WITHOUT touching localStorage or the server. Used by
	 *  reconcileFromServer after /auth/me resolves, and internally
	 *  by set() when reverting. */
	applyLocally(l: Language): void {
		const next = normalize(l);
		this.current = next;
		if (typeof document !== 'undefined') {
			document.documentElement.lang = next;
		}
	}

	/** Reconcile against the server's value after /auth/me resolves.
	 *  If the server's value differs from what bootstrap picked, swap
	 *  silently. Empty / unknown values are mapped to 'en' via
	 *  normalize() — pre-v2.9.11 rows (LanguagePreference == "") land
	 *  on the hardcoded default until the user picks one in Settings.
	 *
	 *  This is a no-op when the bootstrap and server already agree,
	 *  which is the common case (the cookie is refreshed on every
	 *  successful POST /auth/me/language call). */
	reconcileFromServer(serverLanguage: unknown): void {
		const next = normalize(serverLanguage);
		if (next === this.current) return;
		this.applyLocally(next);
	}

	/** Mirror the chosen language into localStorage so subsequent
	 *  paints in private-cookie scenarios (or cookie-deletion edge
	 *  cases) still hit the bootstrap's localStorage tier. */
	private persistLocally(l: Language): void {
		if (typeof localStorage === 'undefined') return;
		try {
			localStorage.setItem('arenet_language', l);
		} catch (_) {
			// Private browsing / quota — ignore. The cookie + server
			// remain authoritative.
		}
	}
}

export const language = new LanguageStore();
