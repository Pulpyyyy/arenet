// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// v2.55 — the edit panel could not be scrolled to its Save button.
//
// This is a source-level guard, and deliberately so: jsdom performs no
// layout, so no rendering test can observe a clipped box. The invariant
// below is the one that took the debugging, and it is exactly the kind a
// later tidy-up reverts by accident.
//
// What happened: `.split > *` set the `overflow` shorthand to clip the
// collapsed grid track during the width animation. Svelte's scoping
// compiles that selector to `.split.svelte-HASH > :where(.svelte-HASH)`
// — `:where()` contributes nothing, but `.split` plus the scoping class
// make it (0,2,0), which outranks the panel's own `overflow-auto`
// utility at (0,1,0).
//
// So above 1280px the panel carried `max-height: calc(100vh - …)` AND
// `overflow: hidden`: everything past the cap was cut with no scrollbar.
// Opening a form section pushed the footer out of reach; collapsing it
// brought Save back, which is how it was found.
//
// The animation only ever needed HORIZONTAL clipping.

// Resolved from the vitest root (web/frontend) rather than import.meta.url,
// which is not a file: URL under the Vite transform pipeline.
const pageSource = readFileSync(
	resolve(process.cwd(), 'src/routes/routes/+page.svelte'),
	'utf-8'
);

/** The body of the `.split > *` rule, or null when the rule is gone. */
function splitChildRule(source: string): string | null {
	const match = source.match(/\.split\s*>\s*\*\s*\{([^}]*)\}/);
	return match ? match[1] : null;
}

describe('routes page — the split grid must not clip the edit panel vertically', () => {
	it('clips the collapsed track on the x axis only', () => {
		const rule = splitChildRule(pageSource);
		expect(rule, 'the .split > * rule vanished; this guard needs rewriting').not.toBeNull();

		// The shorthand is the bug: it sets overflow-y too, and this
		// selector outranks the panel's overflow-auto.
		expect(
			rule,
			'`.split > *` sets the overflow shorthand again — it will clip the edit ' +
				'panel vertically and put Save out of reach past 1280px'
		).not.toMatch(/(^|[;\s])overflow\s*:/);

		expect(rule, 'the horizontal clipping the width animation needs is missing').toMatch(
			/overflow-x\s*:\s*hidden/
		);
	});

	// overflow-y must stay unset so it resolves to auto. Naming it
	// `hidden` would reintroduce the bug while keeping overflow-x correct,
	// which the assertion above would not catch on its own.
	it('does not pin overflow-y to hidden', () => {
		const rule = splitChildRule(pageSource) ?? '';
		expect(rule, 'overflow-y:hidden re-clips the panel and Save is unreachable again').not.toMatch(
			/overflow-y\s*:\s*hidden/
		);
	});

	// The cap is the other half of the failure: without it nothing clips,
	// so if it ever moves this guard is no longer guarding anything.
	it('still caps the panel height, which is why clipping mattered', () => {
		expect(
			pageSource,
			'the panel no longer has a max-height; re-check whether this guard is still needed'
		).toMatch(/xl:max-h-\[calc\(100vh/);
	});
});
