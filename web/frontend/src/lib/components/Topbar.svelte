<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topbar (Step R.2, slimmed in Phase 5 follow-up).

  Layout: crumbs · status

  Pre-cleanup the topbar carried three additional affordances
  inherited from the original aesthetic mock: a non-functional
  search input + ⌘K hint, a cosmetic Admin/Viewer view-as
  toggle, and a permanently-disabled "Déployer" button. The
  operator called the trio out as zero-value clutter:
    - the search was a visual placeholder with no command
      palette wired behind it (spec §6.2 out of scope)
    - the view-as toggle was advertised as "cosmetic only"
      and could only confuse operators about who they really
      were
    - the Déployer button surfaced a "Bientôt disponible"
      tooltip that pointed at no real feature

  We retain ONE piece of the view-as machinery: the effect
  that auto-applies the `body.viewer` class when the backend
  session is actually role=viewer. The class still drives the
  app-wide read-only affordances in app.css (.viewer
  .admin-only hidden, .viewer .write-action disabled,
  .ro-banner shown). That mechanism is genuine, not cosmetic,
  and removing the explicit toggle does not remove the
  underlying gating.
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { fetchSystemHealth, type HealthReport } from '$lib/api/system';
	import { gatewayState, healthProblems } from '$lib/utils/gateway-health';

	// The status used to be static markup: "Gateway healthy" with a
	// green dot, Caddy up or not. It now reads GET /system/health
	// (Caddy admin, BoltDB, CrowdSec, certificates, metrics store) and
	// says "unknown" when that cannot be read, never healthy by default.
	const HEALTH_POLL_MS = 30_000;
	let health = $state<HealthReport | null>(null);
	const gwState = $derived(gatewayState(health));
	const gwProblems = $derived(health ? healthProblems(health) : []);

	async function refreshHealth(): Promise<void> {
		try {
			health = await fetchSystemHealth();
		} catch {
			health = null;
		}
	}

	let healthPoll: ReturnType<typeof setInterval> | null = null;
	onMount(() => {
		void refreshHealth();
		healthPoll = setInterval(() => {
			if (document.visibilityState !== 'visible') return;
			void refreshHealth();
		}, HEALTH_POLL_MS);
	});
	onDestroy(() => {
		if (healthPoll !== null) clearInterval(healthPoll);
	});

	const statusKey: Record<string, string> = {
		healthy: 'topbar.statusHealthy',
		degraded: 'topbar.statusDegraded',
		unhealthy: 'topbar.statusUnhealthy',
		unknown: 'topbar.statusUnknown'
	};

	// v2.9.12 i18n Phase 2 — crumb labels resolved from the active
	// bundle. Each entry maps a pathname to a bundle key under
	// sidebar.* (reusing the sidebar nav-item translations so the
	// crumb and the nav stay in sync). The `language.current &&`
	// dependency trigger inside $derived recomputes on every
	// language change.
	//
	// Kept by hand in step with the sidebar's hrefs (sharing one
	// config would mean a new module imported by both): when a page
	// is added, add it here too, or its crumb shows the raw slug.
	// Pages without a sidebar item (error pages, observability) have
	// their own keys.
	const pathToBundleKey: Record<string, string> = {
		'/dashboard': 'sidebar.navDashboard',
		'/topology': 'sidebar.navTopology',
		'/map': 'sidebar.navMap',
		'/routes': 'sidebar.navRoutes',
		'/tcp-services': 'sidebar.navTCPServices',
		'/logs': 'sidebar.navLogs',
		'/waf': 'sidebar.navWAF',
		'/security': 'sidebar.navSecurity',
		'/certs': 'sidebar.navCertificates',
		'/alerting': 'sidebar.navAlerting',
		'/users': 'sidebar.navUsers',
		'/settings': 'sidebar.navSettings',
		'/settings/error-pages': 'sidebar.navErrorPages',
		'/audit': 'sidebar.navAuditLog',
		'/api-docs': 'sidebar.navApiDocs',
		'/observability': 'sidebar.crumbObservability',
		'/admin/users': 'sidebar.navUsers'
	};

	// A UUID (what the backend mints for route IDs) or a long hex
	// string. Such a segment means nothing to the operator, so the
	// crumb names what it is instead of printing it.
	const ID_SEGMENT = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$/i;

	const currentPath = $derived(page.url.pathname);
	const crumbLabel = $derived(
		// Touching language.current registers the reactive dependency
		// so the crumb re-resolves on language switch (see
		// $lib/i18n/index.ts docstring for the idiom).
		language.current &&
			(() => {
				const segs = currentPath.split('/').filter(Boolean);
				if (segs.length === 0) return 'Arenet';
				// Longest mapped prefix names the page; whatever is left
				// is appended (e.g. /security/<id> → "Threats · Route").
				let depth = segs.length;
				while (depth > 0 && !pathToBundleKey['/' + segs.slice(0, depth).join('/')]) depth--;
				const rootLabel =
					depth > 0 ? t(pathToBundleKey['/' + segs.slice(0, depth).join('/')]) : segs[0];
				const rest = segs
					.slice(Math.max(depth, 1))
					.map((s) => (ID_SEGMENT.test(s) ? t('sidebar.crumbRoute') : s));
				return rest.length > 0 ? `${rootLabel} · ${rest.join('/')}` : rootLabel;
			})()
	);

	// Backend-driven viewer gating. When the session role IS
	// viewer, set body.viewer so the app-wide CSS rules in
	// app.css (.admin-only hidden, .write-action disabled,
	// .ro-banner visible) light up. The class is removed when
	// the operator is admin so an admin->viewer->admin user
	// flip (rare but possible across sessions) clears the
	// stale state.
	$effect(() => {
		if (typeof document === 'undefined') return;
		if (auth.user?.role === 'viewer') {
			document.body.classList.add('viewer');
		} else {
			document.body.classList.remove('viewer');
		}
	});
</script>

<header class="topbar">
	<div class="crumbs">
		<b>{crumbLabel}</b>
	</div>

	<!-- role="status": a change (healthy → degraded) is announced.
	     The tooltip names what is wrong. -->
	<div
		class="tb-status"
		role="status"
		data-testid="gateway-status"
		data-state={gwState}
		title={language.current &&
			(gwState === 'unknown'
				? t('topbar.statusUnknownTitle')
				: gwProblems.length > 0
					? gwProblems.join(' · ')
					: undefined)}
	>
		<span class="dot {gwState}" aria-hidden="true"></span>
		<span>{language.current && t(statusKey[gwState])}</span>
	</div>
</header>

<style>
	.topbar {
		height: var(--tb-height);
		background: var(--bg-topbar);
		backdrop-filter: blur(8px);
		-webkit-backdrop-filter: blur(8px);
		border-bottom: 1px solid var(--border);
		display: flex;
		align-items: center;
		gap: 14px;
		padding: 0 22px;
		position: sticky;
		top: 0;
		z-index: 10;
	}

	.crumbs {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
		color: var(--fg-muted);
	}
	.crumbs b {
		color: var(--fg);
		font-weight: 500;
	}

	.tb-status {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex: none;
	}
	.dot.healthy {
		background: var(--status-up);
		box-shadow: 0 0 8px var(--status-up);
	}
	.dot.degraded {
		background: var(--status-warn);
	}
	.dot.unhealthy {
		background: var(--status-down);
	}
	.dot.unknown {
		background: var(--text-muted);
	}
</style>
