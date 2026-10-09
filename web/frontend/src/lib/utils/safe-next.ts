// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The page to come back to after signing in or finishing setup,
// carried as ?next= by the redirect that sent an anonymous visitor to
// /login or /setup.
//
// ?next= is attacker-controlled: anyone can send a link to
// /login?next=https://evil.example. Only a path on this origin is
// honoured, anything else falls back to the default landing page.

/** Where sign-in and setup land when ?next= is absent or unusable. */
export const DEFAULT_LANDING = '/routes';

/** The pages an anonymous visitor is allowed to stay on. */
const ENTRY_PATHS = ['/login', '/setup'];

// The last C0 control character; DEL is the one above it.
const LAST_CONTROL_CHAR = 0x1f;
const DEL_CHAR = 0x7f;

// The URL parser drops tabs and newlines anywhere in the input, so
// "/\t/evil.example" resolves as "//evil.example": any control
// character is a reason to refuse.
function hasControlChar(s: string): boolean {
	for (let i = 0; i < s.length; i++) {
		const c = s.charCodeAt(i);
		if (c <= LAST_CONTROL_CHAR || c === DEL_CHAR) return true;
	}
	return false;
}

// "/login/" is the same page as "/login" (SvelteKit drops the slash).
function normalisePath(pathname: string): string {
	return pathname.replace(/\/+$/, '') || '/';
}

/** True for /login and /setup, the pages an anonymous visitor is not
 *  redirected away from. */
export function isEntryPath(pathname: string): boolean {
	return ENTRY_PATHS.includes(normalisePath(pathname));
}

/**
 * safeNext returns `raw` when it is a path on this origin (it starts
 * with exactly one "/", has no backslash and no control character),
 * and DEFAULT_LANDING otherwise. "//host" and "/\host" are refused
 * because browsers read both as another host. /login and /setup are
 * refused too: landing there after signing in would be a loop.
 */
export function safeNext(raw: string | null | undefined): string {
	if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')) {
		return DEFAULT_LANDING;
	}
	if (raw.includes('\\') || hasControlChar(raw)) {
		return DEFAULT_LANDING;
	}
	const pathname = raw.split(/[?#]/, 1)[0];
	if (isEntryPath(pathname)) {
		return DEFAULT_LANDING;
	}
	return raw;
}

/**
 * withNext builds the URL of an entry page (/login or /setup, or the
 * SSO start /api/v1/auth/oidc/login, whose backend applies the same
 * rules) that carries `target` as ?next=. The parameter is left out
 * when the target is unusable, the default landing or the root, which
 * all end on the default landing anyway.
 */
export function withNext(entry: string, target: string | null | undefined): string {
	const safe = safeNext(target);
	if (safe === DEFAULT_LANDING || safe === '/') {
		return entry;
	}
	return `${entry}?next=${encodeURIComponent(safe)}`;
}
