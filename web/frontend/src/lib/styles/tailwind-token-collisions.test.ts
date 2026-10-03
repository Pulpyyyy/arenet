// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.58.4 — a colour must never share a name with a font size.
//
// `colors.base` existed alongside `fontSize.base`, so Tailwind generated
// BOTH `.text-base { font-size: … }` and `.text-base { color: var(--bg-base) }`.
// Writing `class="text-base"` — which is simply how you ask for a 1rem font —
// painted the text the colour of the page background. Invisible in light AND
// in dark, which is exactly what made it hard to recognise as a colour bug:
// a theme problem shows up in one theme, not both.
//
// Ten of the eleven call sites carried an explicit `text-primary` after it and
// were saved by the cascade. Two headings in Settings did not, and an operator
// reported them unreadable in both themes before anyone noticed the cause.
//
// This guards the shape rather than the one token: any future colour named
// after a font size would reintroduce it, and nothing else in the toolchain
// would complain — Tailwind considers both utilities perfectly valid.

import { describe, it, expect } from 'vitest';
import config from '../../../tailwind.config';

type Palette = Record<string, unknown>;

const extend = (config.theme?.extend ?? {}) as {
	colors?: Palette;
	fontSize?: Palette;
	backgroundColor?: Palette;
};

describe('tailwind theme', () => {
	it('has no colour named after a font size', () => {
		const colours = Object.keys(extend.colors ?? {});
		const sizes = new Set(Object.keys(extend.fontSize ?? {}));
		const collisions = colours.filter((name) => sizes.has(name));

		expect(
			collisions,
			`these colour names also exist as font sizes, so "text-<name>" would set BOTH ` +
				`a size and a colour: ${collisions.join(', ')}. Move the token to the ` +
				`utility it is actually for (backgroundColor, borderColor…) instead of the ` +
				`shared colors palette.`
		).toEqual([]);
	});

	it('keeps bg-base available, since 17 call sites use it', () => {
		expect(extend.backgroundColor).toBeDefined();
		expect(extend.backgroundColor?.base).toBe('var(--bg-base)');
	});

	it('does not expose base as a general colour', () => {
		// The whole point: text-base, border-base and friends must not be
		// colour utilities.
		expect(extend.colors?.base).toBeUndefined();
	});
});
