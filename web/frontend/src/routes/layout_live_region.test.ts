// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Source-level guard, in the style of routes/split_overflow.test.ts:
// mounting the root layout needs the whole auth/bootstrap chain, and
// the invariant is one attribute.
//
// <main> carried aria-live="polite", which made the entire page a live
// region: screen readers read out every 1 s metrics push and every
// re-render. Route changes are announced by SvelteKit's own announcer,
// so <main> needs no live region at all.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const layoutSource = readFileSync(resolve(process.cwd(), 'src/routes/+layout.svelte'), 'utf8');

describe('root layout <main>', () => {
	it('is not a live region', () => {
		// `<main\s` skips the bare "<main>" mentioned in a markup comment.
		const tags = layoutSource.match(/<main\s[^>]*>/g) ?? [];
		expect(tags).toHaveLength(1);
		expect(tags[0]).toContain('id="main"');
		expect(tags[0]).not.toMatch(/aria-live/);
	});
});
