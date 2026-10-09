// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 2 Users-page refactor — provider-kind → operator-facing
// label mapping. The storage Kind enum is normalised lowercase
// for machine matching ('authentik', 'keycloak', 'authelia',
// 'generic'); the sidebar header in the OIDCConfigSummary
// renders the prettier brand-cased form shown in the mockup.
//
// Unknown / empty kinds fall back to a Title-cased echo of the
// raw value so an operator who hand-edits storage with a typo
// still sees their input rather than a generic placeholder.

import type { OIDCProviderKind } from '$lib/api/types';
import { t } from '$lib/i18n';

// Brand names stay as-is in every language; only the generic
// label is translated (resolved per call so it follows the
// active language).
const KIND_LABELS: Record<string, string> = {
	authentik: 'GoAuthentik',
	keycloak: 'Keycloak',
	authelia: 'Authelia'
};

export function oidcProviderLabel(kind: OIDCProviderKind | string | undefined): string {
	const k = (kind || '').toLowerCase();
	if (k in KIND_LABELS) return KIND_LABELS[k];
	if (!k || k === 'generic') return t('oidcSettings.providerGenericLabel');
	// Title-case echo for unknown kinds.
	return k.charAt(0).toUpperCase() + k.slice(1);
}

// hostnameOf extracts the host portion of an issuer URL for the
// sidebar subtitle ("OIDC · authentik.arenet.fr"). Returns the
// raw input if it doesn't parse — better than a blank subtitle
// when an admin has saved a malformed URL.
export function hostnameOf(issuerUrl: string): string {
	if (!issuerUrl) return '';
	try {
		return new URL(issuerUrl).hostname;
	} catch {
		return issuerUrl;
	}
}

// Phase 2 follow-up — provider-kind → brand-aligned colour
// pair. Single source of truth shared by:
//   - SSOProviderLogo.svelte (sidebar header tile gradient)
//   - the SOURCE column badge on /utilisateurs
// so the carre "G" rouge dans le sidebar et le badge
// "GoAuthentik" dans la table parlent le meme langage visuel.
//
// Each entry returns oklch colour strings:
//   gradFrom / gradTo — used by SSOProviderLogo to keep the
//     subtle 2-stop gradient on the brand tile (chunkier than a
//     flat colour, matches the depth in the mockup).
//   badgeBg / badgeBorder / badgeText — used by Badge in
//     table cells (transparent-fill, saturated border + text).
export interface OIDCProviderColors {
	gradFrom: string;
	gradTo: string;
	badgeBg: string;
	badgeBorder: string;
	badgeText: string;
}

const PROVIDER_COLORS: Record<string, OIDCProviderColors> = {
	// authentik = red/orange (their goauthentik logo).
	authentik: {
		gradFrom: 'oklch(70% 0.20 35)',
		gradTo: 'oklch(58% 0.18 30)',
		badgeBg: 'color-mix(in oklch, oklch(62% 0.20 30) 14%, transparent)',
		badgeBorder: 'color-mix(in oklch, oklch(62% 0.20 30) 38%, transparent)',
		badgeText: 'oklch(70% 0.20 35)'
	},
	// keycloak = blue (their brand SSO key glyph).
	keycloak: {
		gradFrom: 'oklch(62% 0.18 250)',
		gradTo: 'oklch(50% 0.20 255)',
		badgeBg: 'color-mix(in oklch, oklch(58% 0.18 255) 14%, transparent)',
		badgeBorder: 'color-mix(in oklch, oklch(58% 0.18 255) 38%, transparent)',
		badgeText: 'oklch(68% 0.18 250)'
	},
	// authelia = purple/violet (their brand palette).
	authelia: {
		gradFrom: 'oklch(60% 0.22 295)',
		gradTo: 'oklch(48% 0.22 300)',
		badgeBg: 'color-mix(in oklch, oklch(58% 0.20 295) 14%, transparent)',
		badgeBorder: 'color-mix(in oklch, oklch(58% 0.20 295) 38%, transparent)',
		badgeText: 'oklch(66% 0.20 295)'
	},
	// generic = neutral cyan (matches arenet's accent).
	generic: {
		gradFrom: 'oklch(60% 0.14 220)',
		gradTo: 'oklch(50% 0.14 230)',
		badgeBg: 'color-mix(in oklch, oklch(58% 0.13 220) 14%, transparent)',
		badgeBorder: 'color-mix(in oklch, oklch(58% 0.13 220) 38%, transparent)',
		badgeText: 'oklch(68% 0.13 220)'
	}
};

export function oidcProviderColors(
	kind: OIDCProviderKind | string | undefined
): OIDCProviderColors {
	const k = (kind || '').toLowerCase();
	return PROVIDER_COLORS[k] || PROVIDER_COLORS.generic;
}
