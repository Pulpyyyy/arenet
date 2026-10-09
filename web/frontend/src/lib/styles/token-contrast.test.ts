// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Text tokens must stay readable on the surfaces they sit on, in both
// themes. Most of the UI's secondary copy is 10-11px, so the bar is WCAG
// AA for normal text: 4.5:1.
//
// Before this guard --text-muted was ~3.4:1 (dark) / ~3.5:1 (light) on
// --bg-surface, and the light amber used as text was ~3.3:1 — legible to
// whoever picked the value on a good monitor, not to everyone else.
//
// Self-contained: the colours are parsed straight out of tokens.css and
// converted OKLCH → OKLab → linear sRGB → relative luminance here, so a
// token edit is checked against the real file, with no colour library.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const AA_NORMAL_TEXT = 4.5;

// Resolved from the vitest root (web/frontend), like split_overflow.test.ts.
const tokensCss = readFileSync(resolve(process.cwd(), 'src/lib/styles/tokens.css'), 'utf-8');

/** The declarations of the first rule whose selector matches `selector`. */
function block(selector: RegExp): string {
	const m = tokensCss.match(new RegExp(selector.source + String.raw`\s*\{([^}]*)\}`));
	if (!m) throw new Error(`no ${selector} block in tokens.css`);
	return m[1];
}

// `:root, [data-theme='dark'] {` is the dark block; the alias block that
// follows lists [data-theme='light'] too, so it has a comma where this
// pattern wants the brace. The first bare [data-theme='light'] block is
// the light theme.
const THEMES = {
	dark: block(/:root,\s*\[data-theme='dark'\]/),
	light: block(/\[data-theme='light'\]/)
};

type Oklch = [l: number, c: number, h: number];

function token(theme: keyof typeof THEMES, name: string): Oklch {
	const re = new RegExp(String.raw`${name}:\s*oklch\(\s*([\d.]+)%\s+([\d.]+)\s+([\d.]+)\s*\)`);
	const m = THEMES[theme].match(re);
	if (!m) throw new Error(`${name} is not a plain oklch() in the ${theme} block`);
	return [Number(m[1]) / 100, Number(m[2]), Number(m[3])];
}

/** Relative luminance (WCAG) of an OKLCH colour. Out-of-gamut channels
 *  are clipped, which is what the browser paints. */
function luminance([l, c, h]: Oklch): number {
	const a = c * Math.cos((h * Math.PI) / 180);
	const b = c * Math.sin((h * Math.PI) / 180);
	const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
	const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
	const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
	const clip = (x: number): number => Math.min(1, Math.max(0, x));
	const r = clip(4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_);
	const g = clip(-1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_);
	const bl = clip(-0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_);
	return 0.2126 * r + 0.7152 * g + 0.0722 * bl;
}

function contrast(x: Oklch, y: Oklch): number {
	const [hi, lo] = [luminance(x), luminance(y)].sort((p, q) => q - p);
	return (hi + 0.05) / (lo + 0.05);
}

const TEXT = ['--text-primary', '--text-secondary', '--text-muted', '--status-warn-fg'];
const SURFACES = ['--bg-base', '--bg-elevated', '--bg-surface'];

describe('token contrast', () => {
	it('computes the textbook ratio for black on white', () => {
		// Guards the maths: 21:1 is the WCAG maximum.
		expect(contrast([0, 0, 0], [1, 0, 0])).toBeCloseTo(21, 1);
	});

	for (const theme of ['dark', 'light'] as const) {
		for (const fg of TEXT) {
			for (const bg of SURFACES) {
				it(`${theme}: ${fg} on ${bg} is at least ${AA_NORMAL_TEXT}:1`, () => {
					const ratio = contrast(token(theme, fg), token(theme, bg));
					expect(ratio, `${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA_NORMAL_TEXT);
				});
			}
		}
	}
});
