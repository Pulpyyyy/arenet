// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Unsaved edits used to be protected only from the controls a page
// knew about (its own Cancel, a row click). A sidebar link, a pivot
// link in the panel header, the back button or closing the tab left
// the page and dropped the edits without a word.
//
// guardNavigation hooks SvelteKit's beforeNavigate, so every way out
// goes through the page's own discard question.

import { beforeNavigate, goto } from '$app/navigation';

/**
 * Holds back any navigation away from the page while `isDirty()` is
 * true. In-app navigation is cancelled and `ask` is called with a
 * `proceed` callback that resumes it; `ask` must make `isDirty()`
 * false before calling `proceed`, or the guard stops it again.
 * Leaving the app (closing or reloading the tab, an external link)
 * gets the browser's own "leave site?" prompt instead.
 *
 * Must be called during component initialisation, like beforeNavigate.
 */
export function guardNavigation(isDirty: () => boolean, ask: (proceed: () => void) => void): void {
	beforeNavigate((nav) => {
		if (!isDirty()) return;
		nav.cancel();
		// On 'leave', cancel() is what makes the browser show its prompt;
		// there is no in-app destination to resume.
		if (nav.type === 'leave' || !nav.to) return;
		const url = nav.to.url;
		ask(() => void goto(url));
	});
}
