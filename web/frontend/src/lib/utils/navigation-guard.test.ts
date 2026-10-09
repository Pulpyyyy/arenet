// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';

const { nav } = vi.hoisted(() => ({
	nav: {
		callback: null as ((n: unknown) => void) | null,
		goto: vi.fn()
	}
}));

vi.mock('$app/navigation', () => ({
	beforeNavigate: (cb: (n: unknown) => void) => {
		nav.callback = cb;
	},
	goto: nav.goto
}));

import { guardNavigation } from './navigation-guard';

function navigate(type: string, to: string | null) {
	const cancel = vi.fn();
	nav.callback!({ type, to: to ? { url: new URL(to) } : null, cancel });
	return cancel;
}

beforeEach(() => {
	nav.callback = null;
	nav.goto.mockReset();
});

describe('guardNavigation', () => {
	it('lets navigation through when nothing is unsaved', () => {
		const ask = vi.fn();
		guardNavigation(() => false, ask);
		const cancel = navigate('link', 'http://localhost/settings');
		expect(cancel).not.toHaveBeenCalled();
		expect(ask).not.toHaveBeenCalled();
	});

	it('holds an in-app navigation and resumes it once the page agrees', () => {
		// An object, not a `let`: TS narrows a `let` assigned only in a
		// callback to its initial null.
		const held: { proceed?: () => void } = {};
		guardNavigation(
			() => true,
			(p) => (held.proceed = p)
		);
		const cancel = navigate('link', 'http://localhost/settings');
		expect(cancel).toHaveBeenCalled();
		expect(nav.goto).not.toHaveBeenCalled();

		held.proceed!();
		expect(nav.goto).toHaveBeenCalledWith(new URL('http://localhost/settings'));
	});

	it('leaves closing the tab to the browser prompt', () => {
		const ask = vi.fn();
		guardNavigation(() => true, ask);
		const cancel = navigate('leave', null);
		// cancel() on 'leave' is what triggers the native prompt.
		expect(cancel).toHaveBeenCalled();
		expect(ask).not.toHaveBeenCalled();
	});
});
