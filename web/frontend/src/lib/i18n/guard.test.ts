// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Source-level i18n guards.
//
// The UI audit found 352 user-visible strings written straight into
// .svelte templates across 59 files: French shown in the English UI,
// English in the French one. Fixing them is a series of PRs; this
// stops the count from growing back meanwhile.
//
// 1. No .svelte file may gain hardcoded text. Each file's current
//    count is recorded in hardcoded-baseline.json; a file over its
//    baseline fails and the new strings are listed. Moving a string
//    to t() lowers the count — refresh the baseline so it stays
//    lowered:
//      UPDATE_I18N_BASELINE=1 npx vitest run src/lib/i18n/guard.test.ts
// 2. Every key passed literally to t() / tl() exists in en.json, so a
//    typo does not ship as a raw key on screen.
//
// "Hardcoded text" is approximated, deliberately simply: markup text
// and title / placeholder / aria-label / alt / label attribute values
// that contain a word, once <script>, <style>, comments and every
// {expression} are removed. It also counts brand and protocol tokens
// (WAF, TLS) — harmless, since only growth fails.

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import en from './locales/en.json';

const SRC = resolve(process.cwd(), 'src');
const BASELINE_PATH = resolve(SRC, 'lib/i18n/hardcoded-baseline.json');

const WORD = /[A-Za-zÀ-ÖØ-öø-ÿ]{2,}/;

function walk(dir: string, ext: string, out: string[] = []): string[] {
	for (const entry of readdirSync(dir, { withFileTypes: true })) {
		const full = join(dir, entry.name);
		if (entry.isDirectory()) walk(full, ext, out);
		else if (entry.name.endsWith(ext)) out.push(full);
	}
	return out;
}

/** Removes every {…} expression, nested ones included. */
function stripBraces(s: string): string {
	let out = '';
	let depth = 0;
	for (const ch of s) {
		if (ch === '{') depth++;
		else if (ch === '}') {
			if (depth > 0) depth--;
		} else if (depth === 0) out += ch;
	}
	return out;
}

/** The hardcoded user-visible strings of one .svelte source. */
function hardcodedText(src: string): string[] {
	let s = src
		.replace(/<script[\s\S]*?<\/script>/g, '')
		.replace(/<style[\s\S]*?<\/style>/g, '')
		.replace(/<!--[\s\S]*?-->/g, '');
	s = stripBraces(s).replace(/&[a-zA-Z]+;/g, ' ');
	const found: string[] = [];
	for (const m of s.matchAll(/>([^<]*)</g)) {
		const text = m[1].trim();
		if (WORD.test(text)) found.push(text);
	}
	for (const m of s.matchAll(/\b(?:title|placeholder|aria-label|alt|label)="([^"]*)"/g)) {
		if (WORD.test(m[1])) found.push(m[1]);
	}
	return found;
}

function hasKey(bundle: unknown, key: string): boolean {
	let node: unknown = bundle;
	for (const part of key.split('.')) {
		if (typeof node !== 'object' || node === null || !(part in node)) return false;
		node = (node as Record<string, unknown>)[part];
	}
	return typeof node === 'string';
}

describe('i18n guard', () => {
	it('no .svelte file gains hardcoded user-visible text', () => {
		const current: Record<string, string[]> = {};
		for (const file of walk(SRC, '.svelte').sort()) {
			const hits = hardcodedText(readFileSync(file, 'utf8'));
			if (hits.length > 0) current[relative(SRC, file).split('\\').join('/')] = hits;
		}

		if (process.env.UPDATE_I18N_BASELINE) {
			const counts = Object.fromEntries(
				Object.entries(current).map(([file, hits]) => [file, hits.length])
			);
			writeFileSync(BASELINE_PATH, JSON.stringify(counts, null, '\t') + '\n');
			return;
		}

		const baseline = JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as Record<string, number>;
		const grown = Object.entries(current)
			.filter(([file, hits]) => hits.length > (baseline[file] ?? 0))
			.map(
				([file, hits]) =>
					`${file}: ${hits.length} (baseline ${baseline[file] ?? 0}) — ${hits.join(' | ')}`
			);
		expect(
			grown,
			'Hardcoded text added to a template: put it in en.json + fr.json and use t()'
		).toEqual([]);
	});

	it('every literal t() / tl() key exists in en.json', () => {
		const missing: string[] = [];
		const files = [...walk(SRC, '.svelte'), ...walk(SRC, '.ts')].filter(
			(f) => !f.endsWith('.test.ts')
		);
		for (const file of files) {
			const src = readFileSync(file, 'utf8');
			// Only a whole literal argument: t('a.b' + x) is a prefix,
			// built at runtime, and is not checked here.
			for (const m of src.matchAll(/\b(?:t|tl)\(\s*'([a-zA-Z][\w.]*)'\s*[,)]/g)) {
				if (!hasKey(en, m[1])) missing.push(`${relative(SRC, file)}: ${m[1]}`);
			}
		}
		expect(missing).toEqual([]);
	});
});
