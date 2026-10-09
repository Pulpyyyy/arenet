// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { Config } from 'tailwindcss';

// Tailwind tokens are an `extend` layer that surfaces every
// design token from src/lib/styles/tokens.css through utility
// class names. Components are free to write either `bg-elevated`
// (Tailwind) or `style:background={var(--bg-elevated)}` — both
// resolve to the same custom property value.
//
// IMPORTANT: keep this file in sync with tokens.css. Drift bites
// — pre-Chunk-3 the fontFamily and fontSize blocks here had their
// own values (16px base etc.) that disagreed with what tokens.css
// declared (14px base etc.). Step F Chunk 3 re-aligns them so the
// Tailwind utilities and the var(--...) references read identical.
const config: Config = {
	content: ['./src/**/*.{html,js,ts,svelte}'],
	// `dark:` follows the app's theme, not the OS. Without this Tailwind
	// defaults to `media` (prefers-color-scheme), so an operator who
	// picked the light theme on a dark-mode OS got the `dark:` amber
	// on white. app.html sets data-theme on <html> before first paint.
	// Tailwind 3.4 `selector` strategy → `&:where([data-theme="dark"],
	// [data-theme="dark"] *)` (corePlugins.js darkVariants, v3.4.19).
	darkMode: ['selector', '[data-theme="dark"]'],
	theme: {
		extend: {
			// v2.58.4 — `base` lives here and NOT in `colors`, on purpose.
			//
			// In `colors` it generated `.text-base { color: var(--bg-base) }`
			// alongside the font-size utility of the same name. So
			// `class="text-base"` — which every developer writes for a 1rem
			// font — silently painted the text the colour of the page
			// background. Invisible in light AND dark, which is what made it
			// hard to recognise as a colour bug at all.
			//
			// Ten of the eleven `text-base` call sites happened to carry an
			// explicit `text-primary` after it and were saved by luck of the
			// cascade. Two headings in Settings did not, and an operator
			// reported them unreadable.
			//
			// Only `bg-base` is ever wanted (17 call sites); no `border-base`,
			// `ring-base` or any other `-base` utility is used anywhere. So
			// the token belongs to backgroundColor alone, and `text-base`
			// goes back to meaning a font size.
			backgroundColor: {
				base: 'var(--bg-base)'
			},
			// `text-warn` reads the text amber (--status-warn-fg); `bg-warn`,
			// `border-warn` etc. keep the fill below. The light-theme fill
			// is only ~3.5:1 as text on white — see tokens.css.
			textColor: {
				warn: 'var(--status-warn-fg)'
			},
			colors: {
				// Background surfaces (§2.1) — `base` is in backgroundColor
				// above; see the note there.
				sidebar: 'var(--bg-sidebar)',
				elevated: 'var(--bg-elevated)',
				surface: 'var(--bg-surface)',
				hover: 'var(--bg-hover)',
				// Borders (§2.1)
				'border-subtle': 'var(--border-subtle)',
				'border-default': 'var(--border-default)',
				'border-strong': 'var(--border-strong)',
				// Text (§2.1)
				primary: 'var(--text-primary)',
				secondary: 'var(--text-secondary)',
				muted: 'var(--text-muted)',
				inverse: 'var(--text-inverse)',
				'on-color': 'var(--text-on-color)', // Chunk 3 — text on filled colored bg
				// Accents + status (§2.1)
				cyan: 'var(--accent-cyan)',
				'cyan-dark': 'var(--accent-cyan-d)',
				up: 'var(--status-up)',
				warn: 'var(--status-warn)',
				down: 'var(--status-down)',
				violet: 'var(--status-info)', // semantic alias — historic name "info"
				meta: 'var(--status-meta)' // Chunk 3 — slate, AuditRow Meta category
			},
			fontFamily: {
				// Match tokens.css §2.7 stacks exactly.
				sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
				mono: ['Geist Mono', 'ui-monospace', 'monospace']
			},
			fontSize: {
				// Match tokens.css §2.7 sizing exactly (was 12/14/16/20/28/36
				// pre-Chunk-3; tokens.css uses 11/13/14/16/18/22).
				xs: 'var(--text-xs)',
				sm: 'var(--text-sm)',
				base: 'var(--text-base)',
				lg: 'var(--text-lg)',
				xl: 'var(--text-xl)',
				'2xl': 'var(--text-2xl)'
			},
			borderRadius: {
				sm: 'var(--radius-sm)',
				md: 'var(--radius-md)',
				lg: 'var(--radius-lg)',
				xl: 'var(--radius-xl)',
				full: 'var(--radius-full)'
			},
			spacing: {
				// Bridge tokens.css spacing scale to Tailwind's numeric
				// scale where they overlap. Tailwind already covers most
				// of these (1=4px, 2=8px, etc.) so we only override where
				// our values differ; keeping it minimal avoids
				// surprising Tailwind defaults.
				'tk-1': 'var(--space-1)',
				'tk-2': 'var(--space-2)',
				'tk-3': 'var(--space-3)',
				'tk-4': 'var(--space-4)',
				'tk-5': 'var(--space-5)',
				'tk-6': 'var(--space-6)',
				'tk-8': 'var(--space-8)',
				'tk-10': 'var(--space-10)',
				'tk-12': 'var(--space-12)',
				'tk-16': 'var(--space-16)'
			},
			boxShadow: {
				// Forward tokens.css shadows. Glow shadows are
				// per-mode through their respective custom properties.
				sm: 'var(--shadow-sm)',
				md: 'var(--shadow-md)',
				lg: 'var(--shadow-lg)',
				'glow-cyan': 'var(--shadow-glow-cyan)',
				'glow-red': 'var(--shadow-glow-red)'
			},
			transitionDuration: {
				// Surface motion-* timings as Tailwind transition utilities.
				// Note Tailwind expects bare numbers; we cast the token
				// values' time portion via a thin alias.
				fast: '100ms',
				base: '200ms',
				slow: '400ms'
			}
		}
	},
	plugins: []
};

export default config;
