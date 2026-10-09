// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import en from '$lib/i18n/locales/en.json';
import fr from '$lib/i18n/locales/fr.json';
import {
	AUDIT_ACTION_GROUPS,
	AUDIT_ACTIONS,
	auditActionLabel,
	isKnownAuditAction
} from './audit-actions';

// The backend's canonical list. Resolved from the vitest root
// (web/frontend), like split_overflow.test.ts; absent when the
// frontend is checked out or packaged on its own, in which case the
// parity check is skipped rather than failed.
const GO_ACTIONS_PATH = resolve(process.cwd(), '../../internal/audit/actions.go');
const goSourceAvailable = existsSync(GO_ACTIONS_PATH);

/** Every string value of an `ActionXxx = "..."` constant in actions.go. */
function goActionValues(source: string): string[] {
	const values: string[] = [];
	const re = /^\s*Action\w+\s*=\s*"([^"]+)"/gm;
	let m: RegExpExecArray | null;
	while ((m = re.exec(source)) !== null) values.push(m[1]);
	return values;
}

describe('audit action catalogue mirrors internal/audit/actions.go', () => {
	it.skipIf(!goSourceAvailable)('lists every backend action', () => {
		const goValues = goActionValues(readFileSync(GO_ACTIONS_PATH, 'utf-8'));
		// Guard the parser itself: a regex that matched nothing would
		// make both checks below pass vacuously.
		expect(goValues.length).toBeGreaterThanOrEqual(77);

		const missing = goValues.filter((a) => !AUDIT_ACTIONS.includes(a));
		expect(missing, 'add these to AUDIT_ACTION_GROUPS and both locale bundles').toEqual([]);
		// An entry the backend does not define yet is tolerated: UI and
		// backend PRs land in either order (crowdsec_decision_delete ships
		// with the unban endpoint), and an unused filter option is harmless.
	});
});

describe('audit action catalogue', () => {
	it('lists each action exactly once', () => {
		expect(new Set(AUDIT_ACTIONS).size).toBe(AUDIT_ACTIONS.length);
	});

	it('includes the actions the old dropdown never offered', () => {
		for (const a of ['tcp_service_created', 'external_cert_uploaded', 'crowdsec_reset', 'config_restored']) {
			expect(isKnownAuditAction(a)).toBe(true);
		}
	});

	it('has a label for every action and group in both locales', () => {
		const bundles = { en, fr } as Record<
			string,
			{ audit: { actions: Record<string, string>; actionGroups: Record<string, string> } }
		>;
		for (const [lang, bundle] of Object.entries(bundles)) {
			for (const a of AUDIT_ACTIONS) {
				expect(bundle.audit.actions[a], `${lang}: audit.actions.${a}`).toBeTruthy();
			}
			for (const g of AUDIT_ACTION_GROUPS) {
				expect(bundle.audit.actionGroups[g.id], `${lang}: audit.actionGroups.${g.id}`).toBeTruthy();
			}
		}
	});

	it('labels a known action and falls back to the raw value for an unknown one', () => {
		expect(auditActionLabel('route_created')).toBe(en.audit.actions.route_created);
		expect(auditActionLabel('some_future_action')).toBe('some_future_action');
	});
});
