<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Sidebar (Step R.2 refonte). Fixed-width primary nav matching the
  mock at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
  :655-714. Replaces the Step F collapsed/expanded sidebar with a
  fixed 232px layout — the mock is intentionally not collapsible.

  Structure: brand block (gradient mark + name + env pill) + 4
  nav-sections (Aperçu / Trafic / Sécurité / Administration) +
  10 nav items + sidebar-foot (avatar + identity + sign-out).

  Per spec D8 outcome, /security/[routeId] is NOT exposed in
  the sidebar — it remains reachable via "Voir tout" links
  injected from /routes detail pages in R.4 (the "Threats"
  item, /security, is highlighted while on it). Same for
  /admin/users which is still routed but the sidebar entry
  points to the new /users top-level route.

  Step CS.3 update: /security/decisions was deleted; its
  content moved to /security?tab=crowdsec (a parent tab on
  /sécurité). Sidebar entry "Security" → /security lands on
  the Vue d'ensemble tab by default; the CrowdSec drill-down
  is one click away. The R.4 D8 rationale (don't surface
  contextual sub-routes in the sidebar) still applies — the
  parent /security entry covers both surfaces.

  Step CS.2 follow-up: /audit IS exposed (Administration
  section, after Settings). Operator-flagged gap
  (#R-AUDIT-not-in-nav from docs/backlog-crowdsec.md): the
  page existed but had no menu link, forcing operators to
  type the URL by hand. /audit has no equivalent contextual
  entry point elsewhere in the app, so the sidebar is the
  right home.

  Admin-only filter: viewer-role users see Aperçu / Trafic /
  Sécurité; the Administration section is hidden in its entirety.

  Width is locked to var(--sb-width); no collapsed mode (mock has
  no collapse button, by design).
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import logoUrl from '$lib/assets/arenet-logo.png';
	import { systemApi } from '$lib/api/system';
	import NotificationBell from './NotificationBell.svelte';

	// Brand badge next to the logo. Shows the RUNNING version
	// (SystemVersion.current) — a release binary reports its tag
	// (e.g. "v2.20.2"), a local `go build` without ldflags reports the
	// default "DEV" (main.go var version = "DEV"). Empty until loaded /
	// on error, so the badge never shows a stale or misleading value
	// (it previously hard-coded "dev" regardless of the real version).
	let version = $state('');
	// True when this is an un-versioned local/dev build, so the badge
	// can flag it visually instead of blending in like a release tag.
	let isDevBuild = $derived(version.toUpperCase() === 'DEV');

	onMount(async () => {
		try {
			const v = await systemApi.getVersion();
			version = v.current ?? '';
		} catch {
			version = ''; // no badge rather than a wrong one
		}
	});

	type IconName =
		| 'dashboard'
		| 'topology'
		| 'map'
		| 'routes'
		| 'tcp'
		| 'logs'
		| 'waf'
		| 'security'
		| 'certs'
		| 'users'
		| 'settings'
		| 'audit'
		| 'alerting'
		| 'api';

	// v2.9.12 i18n Phase 2 — section / nav structures now carry
	// bundle KEYS (labelKey) instead of literal labels. Resolution
	// happens in the template via t(labelKey), wrapped in a derived
	// that reads language.current so it recomputes on switch. The
	// admin-only flag and href stay structural — those don't change
	// across locales.
	type NavItem = {
		href: string;
		labelKey: string;
		icon: IconName;
		adminOnly?: boolean;
	};

	type NavSection = {
		labelKey: string;
		items: NavItem[];
		adminOnly?: boolean;
	};

	const sections: NavSection[] = [
		{
			labelKey: 'sidebar.sectionOverview',
			items: [
				{ href: '/dashboard', labelKey: 'sidebar.navDashboard', icon: 'dashboard' },
				{ href: '/topology', labelKey: 'sidebar.navTopology', icon: 'topology' },
				{ href: '/map', labelKey: 'sidebar.navMap', icon: 'map' }
			]
		},
		{
			labelKey: 'sidebar.sectionTraffic',
			items: [
				{ href: '/routes', labelKey: 'sidebar.navRoutes', icon: 'routes' },
				// v2.42 — layer-4 relays. Next to Routes because it is
				// the same question (what does this host serve?), one
				// layer down.
				{ href: '/tcp-services', labelKey: 'sidebar.navTCPServices', icon: 'tcp' },
				{ href: '/logs', labelKey: 'sidebar.navLogs', icon: 'logs' }
			]
		},
		{
			labelKey: 'sidebar.sectionSecurity',
			items: [
				{ href: '/waf', labelKey: 'sidebar.navWAF', icon: 'waf' },
				{ href: '/security', labelKey: 'sidebar.navSecurity', icon: 'security' },
				{ href: '/certs', labelKey: 'sidebar.navCertificates', icon: 'certs' },
				// AL.4.b.1 — alerting subsystem entry.
				{ href: '/alerting', labelKey: 'sidebar.navAlerting', icon: 'alerting' }
			]
		},
		{
			labelKey: 'sidebar.sectionAdministration',
			adminOnly: true,
			items: [
				{ href: '/users', labelKey: 'sidebar.navUsers', icon: 'users', adminOnly: true },
				// Error pages is reached from Settings → System, not
				// from here: it is a settings sub-page, and the prefix
				// match below lights Settings up while on it.
				{ href: '/settings', labelKey: 'sidebar.navSettings', icon: 'settings', adminOnly: true },
				{ href: '/audit', labelKey: 'sidebar.navAuditLog', icon: 'audit', adminOnly: true },
				// v2.39 — OpenAPI documentation of the admin API.
				{ href: '/api-docs', labelKey: 'sidebar.navApiDocs', icon: 'api', adminOnly: true }
			]
		}
	];

	// Prefix for the section-label ids the lists point at
	// (aria-labelledby), unique per mounted instance.
	const uid = $props.id();

	const isAdmin = $derived(auth.user?.role === 'admin');
	const visibleSections = $derived(sections.filter((s) => !s.adminOnly || isAdmin));

	const currentPath = $derived(page.url.pathname);
	// Longest-prefix match over the visible items, so a sub-page
	// lights up its parent: /security/<routeId> → Threats,
	// /settings/error-pages → Settings. Exact match alone left
	// nothing highlighted on those pages. The trailing '/' in the
	// prefix test keeps /users from matching /users-something, and
	// pages with no parent item (/observability/<routeId>) stay
	// unhighlighted.
	const activeHref = $derived(
		visibleSections
			.flatMap((s) => s.items)
			.map((i) => i.href)
			.filter((h) => currentPath === h || currentPath.startsWith(h + '/'))
			.reduce<string | null>((best, h) => (best === null || h.length > best.length ? h : best), null)
	);
	function isActive(href: string): boolean {
		return href === activeHref;
	}

	// Identity block: 2-letter avatar derived from displayName / username.
	const userInitials = $derived(
		(() => {
			const name = auth.user?.displayName || auth.user?.username || '?';
			const parts = name.split(/\s+/).filter(Boolean);
			if (parts.length >= 2) {
				return (parts[0][0] + parts[1][0]).toUpperCase();
			}
			return name.slice(0, 2).toUpperCase();
		})()
	);
	const userLabel = $derived(auth.user?.displayName || auth.user?.username || '');
	const userRole = $derived(auth.user?.role ?? '');

	// Sign-out (preserved from Step F sidebar). Sign-out lives in the
	// sidebar-foot as an icon button to the right of the identity block,
	// per the mock's compact footer layout.
	let signingOut = $state(false);
	async function signOut(): Promise<void> {
		if (signingOut) return;
		signingOut = true;
		try {
			await auth.logout();
		} finally {
			signingOut = false;
			void goto('/login');
		}
	}
</script>

{#snippet itemIcon(icon: IconName)}
	<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
		{#if icon === 'dashboard'}
			<rect x="2" y="2" width="5" height="6" rx="1" />
			<rect x="9" y="2" width="5" height="4" rx="1" />
			<rect x="2" y="10" width="5" height="4" rx="1" />
			<rect x="9" y="8" width="5" height="6" rx="1" />
		{:else if icon === 'topology'}
			<circle cx="3" cy="3" r="1.5" />
			<circle cx="3" cy="13" r="1.5" />
			<circle cx="13" cy="3" r="1.5" />
			<circle cx="13" cy="13" r="1.5" />
			<circle cx="8" cy="8" r="2" />
			<path d="M4.2 4 6.5 6.6M9.5 6.6 11.8 4M4.2 12 6.5 9.4M9.5 9.4 11.8 12" />
		{:else if icon === 'map'}
			<circle cx="8" cy="8" r="6" />
			<path d="M2 8h12M8 2c2 1.8 2 10.2 0 12M8 2c-2 1.8-2 10.2 0 12" />
		{:else if icon === 'routes'}
			<circle cx="3" cy="8" r="2" />
			<circle cx="13" cy="8" r="2" />
			<path d="M5 8h6" />
		{:else if icon === 'tcp'}
			<path d="M2 4h5v8H2z" />
			<path d="M9 8h5" />
			<path d="M12 6l2 2-2 2" />
		{:else if icon === 'logs'}
			<path d="M3 3h10v10H3z" />
			<path d="M5 6h6M5 8.5h6M5 11h4" />
		{:else if icon === 'waf'}
			<path d="M8 1l5 2v5c0 3.5-2.5 6-5 7-2.5-1-5-3.5-5-7V3l5-2z" />
		{:else if icon === 'security'}
			<rect x="3" y="7" width="10" height="7" rx="1" />
			<path d="M5 7V5a3 3 0 016 0v2" />
		{:else if icon === 'certs'}
			<rect x="2.5" y="3" width="11" height="8" rx="1" />
			<path d="M5.5 13l1 2 1.5-1 1.5 1 1-2" />
			<circle cx="8" cy="7" r="2" />
		{:else if icon === 'users'}
			<circle cx="6" cy="5.5" r="2.5" />
			<path d="M1.5 13.5c.5-2.5 2.4-4 4.5-4s4 1.5 4.5 4" />
			<circle cx="11.5" cy="6.5" r="1.8" />
			<path d="M11.5 10c1.7 0 3 1.1 3.2 2.8" />
		{:else if icon === 'settings'}
			<circle cx="8" cy="8" r="2" />
			<path d="M8 1v2M8 13v2M1 8h2M13 8h2M3 3l1.5 1.5M11.5 11.5L13 13M3 13l1.5-1.5M11.5 4.5L13 3" />
		{:else if icon === 'audit'}
			<!-- Clipboard / ledger glyph: document outline + clip + 3 horizontal rows. -->
			<rect x="3.5" y="3" width="9" height="11" rx="1" />
			<rect x="6" y="1.75" width="4" height="2.5" rx="0.5" fill="currentColor" stroke="none" />
			<path d="M5.5 7h5M5.5 9.25h5M5.5 11.5h3" />
		{:else if icon === 'alerting'}
			<!-- Bell glyph: dome + base + clapper. AL.4.b.1. -->
			<path d="M8 2c-2.5 0-4 1.7-4 4v3l-1.5 2h11L12 9V6c0-2.3-1.5-4-4-4z" />
			<path d="M6.5 13.5a1.5 1.5 0 003 0" />
		{:else if icon === 'api'}
			<!-- Braces glyph "{ }": the API / code documentation. v2.39. -->
			<path d="M5.5 2.5c-1.5 0-2 .7-2 2v1.5c0 1-.5 1.5-1.5 2 1 .5 1.5 1 1.5 2v1.5c0 1.3.5 2 2 2" />
			<path d="M10.5 2.5c1.5 0 2 .7 2 2v1.5c0 1 .5 1.5 1.5 2-1 .5-1.5 1-1.5 2v1.5c0 1.3-.5 2-2 2" />
		{/if}
	</svg>
{/snippet}

<!--
	A navigation landmark (was an <aside>, i.e. "complementary", with
	a hardcoded English name). Each section is a list named by its
	label, so a screen reader says "Traffic, list, 3 items" instead of
	reading a flat run of links.
-->
<nav class="sidebar" aria-label={language.current && t('sidebar.navLabel')}>
	<div class="brand">
		<img class="brand-logo" src={logoUrl} alt="" aria-hidden="true" width="30" height="30" />
		<div class="brand-name">AreNET</div>
		{#if version}
			<div class="brand-env" class:brand-env-dev={isDevBuild} data-testid="brand-version">
				{version}
			</div>
		{/if}
	</div>

	{#each visibleSections as section (section.labelKey)}
		{@const headingId = `${uid}-${section.labelKey}`}
		<!--
			v2.9.12 i18n Phase 2 — section labels resolved live via t().
			Reading language.current inline registers the reactive
			dependency so the whole sidebar re-renders on language
			switch without needing a $derived wrapper per row.
		-->
		<div class="nav-section" id={headingId}>{language.current && t(section.labelKey)}</div>
		<ul class="nav-list" aria-labelledby={headingId}>
			{#each section.items as item (item.href)}
				{@const active = isActive(item.href)}
				<li>
					<a
						href={item.href}
						class="nav-item"
						class:active
						aria-current={active ? 'page' : undefined}
					>
						{@render itemIcon(item.icon)}
						<span>{language.current && t(item.labelKey)}</span>
					</a>
				</li>
			{/each}
		</ul>
	{/each}

	<div class="sidebar-bottom">
		<NotificationBell />
	</div>

	<div class="sidebar-foot">
		<!-- role="img": an aria-label on a role-less div is ignored, and
		     the initials alone read as nonsense letters. -->
		<div
			class="avatar"
			role="img"
			aria-label={language.current && t('common.signedInAs', { name: userLabel })}
		>{userInitials}</div>
		<div class="who">
			{userLabel}
			<small>{userRole}</small>
		</div>
		<button
			type="button"
			class="signout"
			aria-label={language.current && t('common.signOut')}
			title={language.current && t('common.signOut')}
			disabled={signingOut}
			onclick={signOut}
		>
			<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
				<path d="M6 13H4a1 1 0 01-1-1V4a1 1 0 011-1h2" />
				<path d="M10 11l3-3-3-3" />
				<line x1="13" y1="8" x2="6" y2="8" />
			</svg>
		</button>
	</div>
</nav>

<style>
	.sidebar {
		width: var(--sb-width);
		background: var(--bg-sidebar);
		border-right: 1px solid var(--border);
		padding: 18px 12px;
		display: flex;
		flex-direction: column;
		gap: 4px;
		position: sticky;
		top: 0;
		height: 100vh;
		flex: none;
		/* The sidebar is a sticky positioned element, so it forms its own
		   stacking context. Without an explicit z-index it loses to
		   later-in-DOM page content (graphs/charts in .app-main have no
		   z-index but paint after the sidebar), which then covers the
		   NotificationBell popover and swallows its clicks. Lift the whole
		   sidebar above page content — but keep it below true overlays
		   (tooltips z-50/51, modals z-1000). */
		z-index: 40;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 8px 18px;
		margin-bottom: 6px;
		border-bottom: 1px solid var(--border);
	}
	.brand-logo {
		width: 30px;
		height: 30px;
		object-fit: contain;
		flex-shrink: 0;
		/* The logo PNG is 126×106 (~1.19:1 landscape). object-fit:
		   contain keeps the aspect ratio inside the 30×30 box —
		   the bouclier carries its own visual identity ; the
		   pre-logo gradient + "A" letter mark is dropped. */
	}
	.brand-name {
		font-family: var(--font-display);
		font-size: 16px;
		font-weight: 600;
		letter-spacing: -0.02em;
		color: var(--fg);
	}
	.brand-env {
		margin-left: auto;
		font-family: var(--font-mono);
		font-size: 10px;
		color: var(--fg-muted);
		background: var(--surface);
		border: 1px solid var(--border);
		padding: 2px 6px;
		border-radius: 4px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}
	/* Un-versioned local/dev build: flag it so a test instance is never
	   mistaken for a release. A real version tag keeps the neutral style. */
	.brand-env-dev {
		color: var(--status-down, #f85149);
		border-color: var(--status-down, #f85149);
		background: color-mix(in srgb, var(--status-down, #f85149) 12%, transparent);
	}

	.nav-section {
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--fg-dim);
		padding: 14px 10px 6px;
	}

	/* The lists are semantics only: no bullets or indent, and the same
	   4px rhythm the items had as direct children of .sidebar. */
	.nav-list {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}

	.nav-item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 7px 10px;
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		font-size: 13.5px;
		font-weight: 450;
		text-decoration: none;
		transition: background 0.12s, color 0.12s;
	}
	.nav-item:hover {
		background: var(--surface);
		color: var(--fg);
	}
	.nav-item.active {
		background: var(--accent-soft);
		color: var(--accent-fg);
		box-shadow: inset 2px 0 0 var(--accent);
	}
	.nav-item .ic {
		width: 16px;
		height: 16px;
		flex: none;
		opacity: 0.9;
	}

	/* Pushes the whole bottom cluster (Notifications entry + user/foot
	   block) to the bottom of the sidebar. margin-top:auto lives on the
	   first bottom element so the Notifications entry and the foot stay
	   grouped together at the very bottom, above nothing. */
	.sidebar-bottom {
		margin-top: auto;
	}

	.sidebar-foot {
		padding: 10px;
		border-top: 1px solid var(--border);
		display: flex;
		align-items: center;
		gap: 10px;
	}
	.avatar {
		width: 28px;
		height: 28px;
		border-radius: 50%;
		background: var(--surface-hi);
		display: grid;
		place-items: center;
		font-size: 11px;
		font-weight: 500;
		color: var(--fg);
		font-family: var(--font-mono);
		flex: none;
	}
	.who {
		font-size: 12.5px;
		line-height: 1.25;
		color: var(--fg);
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.who small {
		display: block;
		color: var(--fg-dim);
		font-size: 11px;
		text-transform: capitalize;
	}
	.signout {
		width: 26px;
		height: 26px;
		display: grid;
		place-items: center;
		background: transparent;
		border: 1px solid transparent;
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		cursor: pointer;
		flex: none;
		transition: background 0.12s, color 0.12s, border-color 0.12s;
	}
	.signout:hover:not(:disabled) {
		background: var(--surface);
		color: var(--fg);
		border-color: var(--border);
	}
	.signout:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.signout svg {
		width: 14px;
		height: 14px;
	}
</style>
