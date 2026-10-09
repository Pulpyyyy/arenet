// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.6 — color taxonomy for the GeoEvent categories
// spec §5.6 locks. Each category maps to ONE existing
// design token from tokens.css so the dark/light theme
// switch carries the map colors for free.
//
// V.5 deviation flagged: V.5's WorldMap.svelte file-
// header comment proposed mapping waf + crowdsec onto the
// same `--status-down` token (red), with the operator
// tooltip disambiguating. The V.6 brief explicitly asked
// for distinct colors. To satisfy that without inventing
// new tokens, V.6 maps:
//
//   - waf      → --status-down  (red — "request blocked
//                                 by WAF rule")
//   - crowdsec → --accent-cyan  (purple-blue — "IP banned
//                                 by reputation feed")
//
// `--accent-cyan` is the brand accent (despite the legacy
// "cyan" name; current token resolves to purple-blue —
// commit history under R.2 documents the rename in flight).
// Using the brand accent for crowdsec underlines that it
// is a NETWORK-LEVEL block, distinct from WAF's
// REQUEST-LEVEL block.
//
// Step W.5 — extends the enum to 6 with the
// `country_block` category mapped to `--status-meta`
// (slate gray, oklch 62 0.012 250). The gray hue carries
// the spec §D6 "policy enforcement, not threat" semantic:
// operators see country-block arcs at-a-glance as
// "expected enforcement" rather than alarming red, which
// is reserved for actual threat signals (waf / down /
// auth-failure). `--status-meta` was already defined in
// tokens.css for both themes — no new token needed.

import type { GeoEventCategory } from '$lib/api/types';

/**
 * SVG stroke / fill value for an arc of the given category.
 * Each value is a CSS `var(--token)` reference so the dark/
 * light theme switch picks up automatically — never hard-
 * code hex/oklch literals here.
 */
export const CATEGORY_COLORS: Record<GeoEventCategory, string> = {
	normal: 'var(--status-up)',
	throttle: 'var(--status-warn)',
	waf: 'var(--status-down)',
	crowdsec: 'var(--accent-cyan)',
	auth: 'var(--status-info)',
	country_block: 'var(--status-meta)'
};

/**
 * SVG `stroke-dasharray` for an arc of the given category — the
 * second channel next to the hue.
 *
 * Hue alone did not separate the categories: normal (green) and
 * waf (red) collapse for a deuteranope, and crowdsec (brand
 * purple-blue) and auth (info blue) sit close together for
 * everyone. Each category therefore also has its own line rhythm.
 * Arcs use a round linecap, so a `0.1` dash draws a dot and every
 * gap is chosen wide enough to survive the caps eating into it.
 *
 *   normal         ───────────  solid
 *   throttle       ── ── ── ──  long dash
 *   waf            · · · · · ·  dotted
 *   crowdsec       ── · ── · ─  dash-dot
 *   auth           - - - - - -  short dash
 *   country_block  ── · · ── ·  dash-dot-dot
 *
 * The legend draws the same patterns (MapLegend.svelte), so the
 * key matches the map.
 */
export const CATEGORY_DASHES: Record<GeoEventCategory, string> = {
	normal: 'none',
	throttle: '8 4',
	waf: '0.1 4',
	crowdsec: '10 4 0.1 4',
	auth: '3 4',
	country_block: '10 4 0.1 4 0.1 4'
};

/**
 * Operator-facing French labels for each category. Used by
 * tooltips and the future legend. Kept here next to the
 * color map so adding a category requires touching one file.
 */
export const CATEGORY_LABELS_FR: Record<GeoEventCategory, string> = {
	normal: 'Requête',
	throttle: 'Throttle (429)',
	waf: 'WAF (403)',
	crowdsec: 'CrowdSec (403)',
	auth: 'Échec d’auth (401/403)',
	country_block: 'Pays bloqué (403/451/444)'
};
