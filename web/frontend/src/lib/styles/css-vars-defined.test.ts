// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Every `var(--x)` in a component or stylesheet must name a token that
// tokens.css or app.css actually defines.
//
// An undefined custom property fails silently: the declaration becomes
// "invalid at computed-value time" and the property falls back to its
// inherited/initial value, or to the hard-coded fallback if one was
// written. Three slipped through that way:
//
//   - CrowdSecDecisionsPanel `var(--bg-default, #000)` — the copy-code box
//     was always black, so black-on-light text in the light theme;
//   - observability `var(--surface-raised)` — the active quantile button
//     had no background at all;
//   - NotificationBell `var(--danger, #d9534f)` — a hard-coded red that
//     ignored the theme.
//
// A fallback does not make a reference safe (two of the three had one),
// so this check is strict: a name is either defined globally or listed
// in RUNTIME_VARS below with the reason it is allowed.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import config from '../../../tailwind.config';

// Resolved from the vitest root (web/frontend) rather than import.meta.url,
// which is not a file: URL under the Vite transform pipeline.
const SRC = resolve(process.cwd(), 'src');

const TOKEN_FILES = ['lib/styles/tokens.css', 'app.css'];

/**
 * Custom properties that are legitimately NOT in the global token files,
 * because something sets them per element at runtime. Keep this short:
 * a new entry should be a deliberate per-instance knob, never a colour
 * that ought to be a token.
 */
const RUNTIME_VARS: Record<string, string> = {
	// Per-row badge colour, set with `style:--badge-c={…}` (or by the
	// .auto-badge rule) and consumed by the tinted-pill .badge rule.
	'--badge-c': 'WafEventList / CrowdSecDecisionsPanel badge colour, set inline per row',
	// Grid track widths, set with style="--split-open-cols: …" on the
	// split container of the routes and tcp-services pages.
	'--split-open-cols': 'routes / tcp-services split layout, set inline',
	// LoginBackground randomises each dot via element.style.setProperty.
	'--mx': 'LoginBackground dot drift, set by setProperty',
	'--my': 'LoginBackground dot drift, set by setProperty',
	'--dur': 'LoginBackground dot animation duration, set by setProperty',
	'--delay': 'LoginBackground dot animation delay, set by setProperty',
	// Optional theming hooks on WorldMap; each reference falls back to a
	// real token (--bg-surface / --border-subtle / --bg-base).
	'--map-land': 'WorldMap override hook, falls back to --bg-surface',
	'--map-border': 'WorldMap override hook, falls back to --border-subtle',
	'--map-ocean': 'WorldMap override hook, falls back to --bg-base'
};

function walk(dir: string, out: string[] = []): string[] {
	for (const name of readdirSync(dir)) {
		const full = join(dir, name);
		if (statSync(full).isDirectory()) walk(full, out);
		else if (/\.(svelte|css)$/.test(name)) out.push(full);
	}
	return out;
}

/** Strip block comments so a token named in prose is neither a
 *  definition nor a use. Newlines are kept so line numbers hold. */
function stripComments(source: string): string {
	return source.replace(/\/\*[\s\S]*?\*\//g, (c) => c.replace(/[^\n]/g, ' '));
}

function definedTokens(): Set<string> {
	const defined = new Set<string>();
	for (const file of TOKEN_FILES) {
		const css = stripComments(readFileSync(join(SRC, file), 'utf-8'));
		for (const m of css.matchAll(/(--[\w-]+)\s*:/g)) defined.add(m[1]);
	}
	return defined;
}

interface Use {
	name: string;
	where: string;
}

function varUses(): Use[] {
	const uses: Use[] = [];
	for (const file of walk(SRC)) {
		const source = stripComments(readFileSync(file, 'utf-8'));
		for (const m of source.matchAll(/var\(\s*(--[\w-]+)/g)) {
			const line = source.slice(0, m.index).split('\n').length;
			uses.push({ name: m[1], where: `${relative(SRC, file)}:${line}` });
		}
	}
	return uses;
}

describe('CSS custom properties', () => {
	const defined = definedTokens();
	const uses = varUses();

	it('finds the token files and a meaningful number of uses', () => {
		// Guards the guard: a broken path or regex would make the real
		// assertion below pass vacuously.
		expect(defined.has('--bg-base')).toBe(true);
		expect(defined.has('--status-warn-fg')).toBe(true);
		expect(uses.length).toBeGreaterThan(500);
	});

	it('only references tokens that are defined (or runtime-set and listed)', () => {
		const undefinedUses = uses
			.filter((u) => !defined.has(u.name) && !(u.name in RUNTIME_VARS))
			.map((u) => `${u.name} at ${u.where}`);
		expect(
			undefinedUses,
			'these var() references name no token in tokens.css/app.css. Map them to an ' +
				'existing token, add the token, or — only for a per-element value set at ' +
				'runtime — list it in RUNTIME_VARS with the reason.'
		).toEqual([]);
	});

	it('keeps the runtime allowlist minimal', () => {
		const used = new Set(uses.map((u) => u.name));
		const stale = Object.keys(RUNTIME_VARS).filter((n) => !used.has(n));
		const shadowing = Object.keys(RUNTIME_VARS).filter((n) => defined.has(n));
		expect(stale, 'no longer referenced anywhere — drop from RUNTIME_VARS').toEqual([]);
		expect(shadowing, 'now a real token — drop from RUNTIME_VARS').toEqual([]);
	});

	it('only points Tailwind utilities at defined tokens', () => {
		const out: string[] = [];
		const visit = (value: unknown, path: string): void => {
			if (typeof value === 'string') {
				for (const m of value.matchAll(/var\(\s*(--[\w-]+)/g)) {
					if (!defined.has(m[1])) out.push(`${path} → ${m[1]}`);
				}
			} else if (value && typeof value === 'object' && !Array.isArray(value)) {
				for (const [k, v] of Object.entries(value)) visit(v, `${path}.${k}`);
			}
		};
		visit(config.theme?.extend ?? {}, 'theme.extend');
		expect(out).toEqual([]);
	});

	it('uses no text-/bg-/border-status-* utility, which the palette never generates', () => {
		// The palette names are up / warn / down / violet / meta, so
		// `text-status-warn` compiled to nothing and the text silently
		// inherited its parent's colour.
		const hits: string[] = [];
		for (const file of walk(SRC)) {
			const source = readFileSync(file, 'utf-8');
			for (const m of source.matchAll(/(?<![\w-])(?:text|bg|border)-status-[a-z]+(?![\w-])/g)) {
				// The Badge variant names ('status-warn' …) are props, not
				// classes, and never carry the text-/bg-/border- prefix.
				const line = source.slice(0, m.index).split('\n').length;
				hits.push(`${m[0]} at ${relative(SRC, file)}:${line}`);
			}
		}
		expect(hits).toEqual([]);
	});
});

describe('tailwind dark variant', () => {
	it('follows the app theme attribute, not the OS colour scheme', () => {
		// Default `media` made `dark:` utilities track prefers-color-scheme,
		// so the light theme on a dark-mode OS rendered the dark palette.
		expect(config.darkMode).toEqual(['selector', '[data-theme="dark"]']);
	});

	it('reads warn text from the text token, not the fill', () => {
		const extend = config.theme?.extend as { textColor?: Record<string, unknown> };
		expect(extend.textColor?.warn).toBe('var(--status-warn-fg)');
	});
});
