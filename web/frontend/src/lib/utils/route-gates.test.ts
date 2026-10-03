// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import {
	ALL_ROUTE_GATES,
	emittedGates,
	gateApplies,
	proxiesNothing
} from './route-gates';

describe('route-gates', () => {
	it('a proxying route emits every gate', () => {
		const r = {};
		expect(emittedGates(r)).toEqual(ALL_ROUTE_GATES);
		expect(proxiesNothing(r)).toBe(false);
		for (const g of ALL_ROUTE_GATES) {
			expect(gateApplies(r, g)).toBe(true);
		}
	});

	it('a redirecting route emits none — the chain is replaced, not extended', () => {
		// manager.go:1549 builds one replacement handler and
		// continues at :1618, before the normal chain is assembled
		// at :1640. The stored wafMode is irrelevant: this is the
		// case where the list showed a red BLOCK chip for a rule
		// that could never run.
		const r = { redirectConfig: { target: 'https://new.example.com' } };
		expect(proxiesNothing(r)).toBe(true);
		expect(emittedGates(r)).toEqual([]);
		expect(gateApplies(r, 'waf')).toBe(false);
		expect(gateApplies(r, 'rateLimit')).toBe(false);
	});

	it('a maintenance route emits none either — same branch, same truth', () => {
		const r = { maintenanceConfig: { retryAfterSeconds: 300 } };
		expect(proxiesNothing(r)).toBe(true);
		expect(emittedGates(r)).toEqual([]);
	});

	it('a disabled route emits none — it is on neither listener', () => {
		expect(emittedGates({ disabled: true })).toEqual([]);
	});

	it('disabled wins over an otherwise normal config', () => {
		// Precedence mirrors routeState(): disabled serves nothing at
		// all, which is stronger than serving a redirect.
		const r = { disabled: true, redirectConfig: { target: 'https://x' } };
		expect(emittedGates(r)).toEqual([]);
	});
});
