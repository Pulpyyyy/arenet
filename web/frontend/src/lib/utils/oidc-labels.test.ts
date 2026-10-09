// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { oidcProviderLabel, hostnameOf, oidcProviderColors } from './oidc-labels';
import { language } from '$lib/stores/language.svelte';

describe('oidcProviderLabel', () => {
	it('maps known kinds to their brand-cased label', () => {
		expect(oidcProviderLabel('authentik')).toBe('GoAuthentik');
		expect(oidcProviderLabel('keycloak')).toBe('Keycloak');
		expect(oidcProviderLabel('authelia')).toBe('Authelia');
	});

	it('falls back to the generic label for empty / undefined kinds', () => {
		expect(oidcProviderLabel('')).toBe('Generic OIDC');
		expect(oidcProviderLabel(undefined)).toBe('Generic OIDC');
		expect(oidcProviderLabel('generic')).toBe('Generic OIDC');
	});

	it('translates the generic label when French is chosen', () => {
		language.current = 'fr';
		try {
			expect(oidcProviderLabel('generic')).toBe('OIDC générique');
			// Brand names are never translated.
			expect(oidcProviderLabel('keycloak')).toBe('Keycloak');
		} finally {
			language.current = 'en';
		}
	});

	it('Title-cases unknown kinds (admin typo-resilience)', () => {
		expect(oidcProviderLabel('zitadel')).toBe('Zitadel');
	});
});

describe('hostnameOf', () => {
	it('returns the hostname of a valid URL', () => {
		expect(hostnameOf('https://authentik.arenet.fr')).toBe('authentik.arenet.fr');
		expect(hostnameOf('https://idp.example.com/realms/main')).toBe('idp.example.com');
	});

	it('returns the raw input for a malformed URL', () => {
		expect(hostnameOf('not a url')).toBe('not a url');
	});

	it('returns empty string for empty input', () => {
		expect(hostnameOf('')).toBe('');
	});
});

describe('oidcProviderColors', () => {
	it('returns the authentik red/orange palette for authentik', () => {
		const c = oidcProviderColors('authentik');
		// The exact oklch values are documented in the helper; we
		// just assert the structure to keep the test resilient to
		// fine-tuning the shades.
		expect(c.gradFrom).toMatch(/^oklch/);
		expect(c.gradTo).toMatch(/^oklch/);
		expect(c.badgeText).toMatch(/^oklch/);
	});

	it('falls back to the generic palette for unknown / empty kinds', () => {
		const generic = oidcProviderColors('generic');
		expect(oidcProviderColors('')).toEqual(generic);
		expect(oidcProviderColors(undefined)).toEqual(generic);
		expect(oidcProviderColors('zitadel')).toEqual(generic);
	});

	it('returns different palettes for distinct known kinds', () => {
		const auth = oidcProviderColors('authentik');
		const kc = oidcProviderColors('keycloak');
		const auli = oidcProviderColors('authelia');
		expect(auth.gradFrom).not.toBe(kc.gradFrom);
		expect(kc.gradFrom).not.toBe(auli.gradFrom);
		expect(auth.gradFrom).not.toBe(auli.gradFrom);
	});
});
