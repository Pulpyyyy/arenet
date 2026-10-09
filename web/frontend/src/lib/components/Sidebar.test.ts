// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sidebar component tests (Step R.2 refonte + CS.2 follow-up).
//
// The mock at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
// :655-714 specifies 4 nav-sections (Aperçu / Trafic / Sécurité /
// Administration) + 10 nav items + a sidebar-foot with avatar +
// identity + sign-out icon. There is no collapsed mode (the prior
// Step F tests covered collapse+expand; those assertions are
// dropped because the feature is removed by design).
//
// CS.2 follow-up: Administration section now contains 3 items
// (Utilisateurs / Settings / Audit log) — total 11 admin-visible
// items. The /audit entry closes #R-AUDIT-not-in-nav (operator
// flagged that the page existed but had no menu link). Note
// CS.3 update: /security/decisions was deleted; its content
// moved into the CrowdSec parent tab on /security (URL
// ?tab=crowdsec). The /security entry alone covers both Vue
// d'ensemble and CrowdSec drill-down. The /security/[routeId]
// per-route page remains intentionally hidden per R.4 D8
// design rationale documented in Sidebar.svelte's header.
//
// Sidebar depends on:
//   - $app/state's `page` rune for currentPath → mocked.
//   - auth store: defaults are OK for the "renders 10 items" base
//     case (no user → role !== 'admin' → Administration hidden).
//     The admin-visibility test sets the role explicitly via the
//     store.
//   - NotificationBell (mounted before .sidebar-foot, Task 5): pulls
//     in notifications.svelte's store, which calls load() on mount
//     and hits the real alerting API client. Mocked the same way
//     NotificationBell.test.ts does, so Sidebar's own tests don't
//     trigger a real (and here, unmockable-URL) fetch.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Mutable so the active-item tests can set the path before render.
// Hoisted because vi.mock factories run before top-level consts.
const { pageMock } = vi.hoisted(() => ({
	pageMock: { url: new URL('http://localhost/routes') }
}));
vi.mock('$app/state', () => ({ page: pageMock }));

// systemApi.getVersion backs the brand version badge next to the logo.
// Default: a release-shaped version. Individual tests override it.
const getVersionMock = vi.fn();
vi.mock('$lib/api/system', () => ({
	systemApi: {
		getVersion: () => getVersionMock()
	}
}));

function sysVersion(over: Record<string, unknown> = {}) {
	return {
		current: 'v2.20.2',
		latest: 'v2.20.2',
		updateAvailable: false,
		url: '',
		lastChecked: '',
		lastError: '',
		enabled: true,
		...over
	};
}

vi.mock('$lib/stores/notifications.svelte', () => ({
	notificationsStore: {
		recent: [],
		unreadCount: 0,
		loading: false,
		loadError: '',
		load: vi.fn().mockResolvedValue(undefined),
		markAllRead: vi.fn()
	},
	PANEL_LIMIT: 15,
	SYNTHETIC_UPDATE_ID: 'synthetic:update'
}));

import { render, screen, waitFor, within } from '@testing-library/svelte';
import Sidebar from './Sidebar.svelte';
import { auth } from '$lib/stores/auth.svelte';

describe('Sidebar', () => {
	beforeEach(() => {
		// Reset the auth store between tests so admin-visibility
		// assertions start from a known state.
		auth.user = null;
		pageMock.url = new URL('http://localhost/routes');
		// Default: a release-shaped version so unrelated tests don't
		// hit an unresolved getVersion() promise.
		getVersionMock.mockReset().mockResolvedValue(sysVersion());
	});

	it('renders the 3 always-visible nav sections + 8 items for an anonymous/viewer user', () => {
		render(Sidebar);

		// v2.9.12 i18n Phase 2 — labels resolve through the i18n
		// resolver; the EN bundle is the default at test boot
		// (no cookie / no localStorage in jsdom).
		expect(screen.getByText('Overview')).toBeInTheDocument();
		expect(screen.getByText('Traffic')).toBeInTheDocument();
		// The section is "Security"; the /security item under it is
		// "Threats" — it used to be "Security" too, the same word
		// twice in a row.
		expect(screen.getAllByText('Security')).toHaveLength(1);
		expect(screen.getByText('Threats')).toBeInTheDocument();
		// Administration is admin-only; default = no user set in store.
		expect(screen.queryByText('Administration')).not.toBeInTheDocument();

		// The other non-admin nav items.
		expect(screen.getByText('Dashboard')).toBeInTheDocument();
		expect(screen.getByText('Topology')).toBeInTheDocument();
		expect(screen.getByText('Map')).toBeInTheDocument();
		expect(screen.getByText('Routes')).toBeInTheDocument();
		expect(screen.getByText('Logs')).toBeInTheDocument();
		expect(screen.getByText('WAF')).toBeInTheDocument();
		expect(screen.getByText('Certificates')).toBeInTheDocument();

		// Admin items absent (EN labels post v2.9.12).
		expect(screen.queryByText('Users')).not.toBeInTheDocument();
		expect(screen.queryByText('Settings')).not.toBeInTheDocument();
		expect(screen.queryByText('Audit log')).not.toBeInTheDocument();
	});

	it('renders all 4 sections + 11 items for an admin user', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never; // shape compatibility — we only read role here.

		render(Sidebar);

		expect(screen.getByText('Administration')).toBeInTheDocument();
		expect(screen.getByText('Users')).toBeInTheDocument();
		expect(screen.getByText('Settings')).toBeInTheDocument();
		// CS.2 follow-up — Audit log entry closes
		// #R-AUDIT-not-in-nav. Admin-only.
		expect(screen.getByText('Audit log')).toBeInTheDocument();
	});

	it('audit log link points to /audit', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;

		render(Sidebar);
		const auditLink = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Audit log'));
		expect(auditLink).toBeDefined();
		expect(auditLink).toHaveAttribute('href', '/audit');
	});

	// Error pages is a settings sub-page: Settings → System links to
	// it, so the sidebar no longer carries its own entry.
	it('has no Error pages item, even for an admin', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;

		render(Sidebar);
		expect(screen.queryByText('Error pages')).not.toBeInTheDocument();
		const hrefs = screen
			.getAllByRole('link', { hidden: false })
			.map((l) => l.getAttribute('href'));
		expect(hrefs).not.toContain('/settings/error-pages');
	});

	it('keeps /security sub-routes OUT of the sidebar (R.4 D8 design)', () => {
		// CS.3 update: the regression now covers two things:
		//   1. /security/decisions stays absent (it was deleted
		//      in CS.3 Commit A; its content moved into the
		//      CrowdSec parent tab on /security)
		//   2. /security/[routeId] stays absent (R.4 D8 per-route
		//      drill-down remains intentionally hidden)
		// If a future patch adds either to the sidebar without
		// updating Sidebar.svelte's header rationale, the assertion
		// catches the silent regression.
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;

		render(Sidebar);
		const allLinks = screen.getAllByRole('link', { hidden: false });
		const hrefs = allLinks.map((l) => l.getAttribute('href'));
		expect(hrefs).not.toContain('/security/decisions');
		// The catch-all route /security/[routeId] doesn't
		// resolve to a single static href; just make sure no
		// link points under /security/ that isn't /security
		// itself.
		const securitySubLinks = hrefs.filter(
			(h) => h !== null && h.startsWith('/security/') && h !== '/security'
		);
		expect(securitySubLinks).toEqual([]);
	});

	it('marks the current-path item with aria-current="page"', () => {
		// Mock returns pathname='/routes' so Routes is the active item.
		render(Sidebar);

		const routes = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Routes'));
		expect(routes).toBeDefined();
		expect(routes).toHaveAttribute('aria-current', 'page');

		// Dashboard (non-current) should NOT have aria-current.
		const dashboard = screen
			.getAllByRole('link', { hidden: false })
			.find((l) => l.textContent?.includes('Dashboard'));
		expect(dashboard).not.toHaveAttribute('aria-current');
	});

	// Sub-pages light up their parent item (longest-prefix match);
	// exact match left nothing highlighted on them.
	function activeHrefs(): (string | null)[] {
		return screen
			.getAllByRole('link', { hidden: false })
			.filter((l) => l.getAttribute('aria-current') === 'page')
			.map((l) => l.getAttribute('href'));
	}

	it('highlights Threats on a per-route /security/<id> page', () => {
		pageMock.url = new URL('http://localhost/security/f2aa08ff-8c86-4ede-8bc1-96670b1342a5');
		render(Sidebar);
		expect(activeHrefs()).toEqual(['/security']);
	});

	it('highlights Settings on /settings/error-pages', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;
		pageMock.url = new URL('http://localhost/settings/error-pages');
		render(Sidebar);
		expect(activeHrefs()).toEqual(['/settings']);
	});

	it('highlights nothing on a page without a parent item', () => {
		pageMock.url = new URL('http://localhost/observability/f2aa08ff-8c86-4ede-8bc1-96670b1342a5');
		render(Sidebar);
		expect(activeHrefs()).toEqual([]);
	});

	it('matches whole segments only, not a bare string prefix', () => {
		// /routes-archive is not under /routes.
		pageMock.url = new URL('http://localhost/routes-archive');
		render(Sidebar);
		expect(activeHrefs()).toEqual([]);
	});

	// Landmarks: a named navigation region, one list per section
	// named by its label, items still links carrying aria-current.
	it('is a navigation landmark named "Main navigation"', () => {
		render(Sidebar);
		const nav = screen.getByRole('navigation', { name: 'Main navigation' });
		expect(nav.tagName).toBe('NAV');
		// Not the old "complementary" region.
		expect(screen.queryByRole('complementary')).toBeNull();
	});

	it('puts each section in a list named by its label', () => {
		render(Sidebar);
		const nav = screen.getByRole('navigation', { name: 'Main navigation' });
		// Viewer: 3 sections (Administration is admin-only).
		expect(within(nav).getAllByRole('list')).toHaveLength(3);

		const traffic = within(nav).getByRole('list', { name: 'Traffic' });
		const items = within(traffic).getAllByRole('listitem');
		expect(items).toHaveLength(3);
		const hrefs = items.map((li) => within(li).getByRole('link').getAttribute('href'));
		expect(hrefs).toEqual(['/routes', '/tcp-services', '/logs']);

		// The current page (/routes) is still marked inside its list.
		expect(within(traffic).getByRole('link', { name: 'Routes' })).toHaveAttribute(
			'aria-current',
			'page'
		);
		expect(within(nav).getByRole('list', { name: 'Overview' })).toBeInTheDocument();
		expect(within(nav).getByRole('list', { name: 'Security' })).toBeInTheDocument();
	});

	it('adds the Administration list for an admin', () => {
		auth.user = {
			username: 'admin',
			displayName: 'Admin',
			role: 'admin',
			mfa: 'none',
			passwordCompromised: false
		} as never;
		render(Sidebar);
		const admin = screen.getByRole('list', { name: 'Administration' });
		expect(within(admin).getAllByRole('listitem')).toHaveLength(4);
	});

	it('announces the avatar as an image named after the user', () => {
		auth.user = {
			username: 'jdoe',
			displayName: 'Jane Doe',
			role: 'viewer',
			mfa: 'none',
			passwordCompromised: false
		} as never;
		render(Sidebar);
		const avatar = screen.getByRole('img', { name: 'Signed in as Jane Doe' });
		expect(avatar.textContent).toBe('JD');
	});

	it('exposes a sign-out button in the sidebar-foot', () => {
		render(Sidebar);
		const signOut = screen.getByRole('button', { name: 'Sign out' });
		expect(signOut).toBeInTheDocument();
		expect(signOut).not.toBeDisabled();
	});

	it('shows the running version in the brand badge (release build)', async () => {
		getVersionMock.mockResolvedValue(sysVersion({ current: 'v2.20.2' }));
		render(Sidebar);
		const badge = await screen.findByTestId('brand-version');
		expect(badge.textContent?.trim()).toBe('v2.20.2');
		// A release tag is NOT flagged as a dev build.
		expect(badge).not.toHaveClass('brand-env-dev');
	});

	it('flags a DEV build in the brand badge', async () => {
		getVersionMock.mockResolvedValue(sysVersion({ current: 'DEV' }));
		render(Sidebar);
		const badge = await screen.findByTestId('brand-version');
		expect(badge.textContent?.trim()).toBe('DEV');
		expect(badge).toHaveClass('brand-env-dev');
	});

	it('renders no brand badge when the version cannot be loaded', async () => {
		getVersionMock.mockRejectedValue(new Error('boom'));
		render(Sidebar);
		// Give onMount's rejected promise a tick to settle, then assert
		// the badge never appears (no stale / misleading "dev").
		await waitFor(() => {
			expect(screen.queryByTestId('brand-version')).toBeNull();
		});
	});
});

// Source-level guard: jsdom resolves no custom properties and does no
// cascade, so a rendering test cannot see which colour the active item
// gets. The active item used to hardcode oklch(82% 0.16 255) — fine on
// the dark sidebar, ~1.4:1 on the light one. It must read a token that
// each theme defines for itself.
describe('Sidebar active item colour', () => {
	const sidebarSource = readFileSync(
		resolve(process.cwd(), 'src/lib/components/Sidebar.svelte'),
		'utf8'
	);
	const tokensSource = readFileSync(
		resolve(process.cwd(), 'src/lib/styles/tokens.css'),
		'utf8'
	);

	it('takes its text colour from --accent-fg, not a literal', () => {
		const rule = sidebarSource.match(/\.nav-item\.active\s*\{([^}]*)\}/);
		expect(rule).not.toBeNull();
		const body = rule![1];
		expect(body).toMatch(/(^|[\s;])color:\s*var\(--accent-fg\)/);
		expect(body).not.toMatch(/(^|[\s;])color:\s*oklch\(/);
	});

	it('has --accent-fg defined separately for the dark and light themes', () => {
		const block = (selector: RegExp) => {
			const m = tokensSource.match(selector);
			return m ? m[1] : '';
		};
		const dark = block(/:root,\s*\[data-theme='dark'\]\s*\{([^}]*)\}/);
		const light = block(/\[data-theme='light'\]\s*\{([^}]*)\}/);
		const value = (b: string) => b.match(/--accent-fg:\s*([^;]+);/)?.[1].trim();
		expect(value(dark)).toBeTruthy();
		expect(value(light)).toBeTruthy();
		// One value for both themes would be the old bug with extra steps.
		expect(value(light)).not.toBe(value(dark));
	});
});
