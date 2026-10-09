<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step CS.3 Commit A — /sécurité parent-tabs refactor.

  Pre-CS.3 history: this page was a posture overview with a
  promoted D8 entry card pointing to the now-deleted
  /security/decisions sub-route + /dashboard. CS.3 reorganises
  it into TWO parent tabs sharing the same URL:

    • Vue d'ensemble — the pre-CS.3 posture readout (TLS,
      Security headers placeholder, Auth providers). Preserved
      verbatim, with the D8 entry card removed because
      /security/decisions is gone and its content lives in
      THIS page now as the CrowdSec tab.

    • CrowdSec — mounts the CrowdSecDecisionsPanel component
      (Local snapshot / Live LAPI / Scenarios sub-tabs) that
      was lifted from /security/decisions/+page.svelte.

  URL state: ?tab=overview (default) or ?tab=crowdsec. Deep
  links from /waf, /security-section CTAs, and external doc
  references point at ?tab=crowdsec. Tab change updates the
  URL via history.replaceState so refreshes preserve the
  surface but the back button doesn't fill with intra-page
  tab toggles. Same convention as other SPA tab UIs in the
  codebase.

  CS.4 → CS.6 will progressively enrich the CrowdSec tab
  (KPI strip, agents panel, bouncers connected, CAPI status,
  hub collections, recent alerts widget). Not in CS.3 scope.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import Tabs from '$lib/components/Tabs.svelte';
	import CrowdSecDecisionsPanel from '$lib/components/CrowdSecDecisionsPanel.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { settingsApi } from '$lib/api/settings';
	import type { OIDCConfig } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { ApiError } from '$lib/api/types';

	type ParentTab = 'overview' | 'crowdsec';

	function parseTabFromURL(): ParentTab {
		const t = page.url.searchParams.get('tab');
		return t === 'crowdsec' ? 'crowdsec' : 'overview';
	}

	let activeTab = $state<ParentTab>(parseTabFromURL());

	const parentTabDescriptors = $derived<
		ReadonlyArray<{ id: ParentTab; label: string; testId: string }>
	>([
		{ id: 'overview', label: tl('security.tabOverview'), testId: 'tab-overview' },
		{ id: 'crowdsec', label: 'CrowdSec', testId: 'tab-crowdsec' }
	]);

	function onTabChange(next: ParentTab): void {
		activeTab = next;
		// Sync the URL so a refresh lands on the same tab and
		// deep-links from /waf etc. work. replaceState (not
		// pushState) — intra-page tab hops shouldn't fill the
		// back-button history.
		if (typeof window === 'undefined') return;
		const url = new URL(window.location.href);
		if (next === 'overview') {
			url.searchParams.delete('tab');
		} else {
			url.searchParams.set('tab', next);
		}
		window.history.replaceState({}, '', url.toString());
	}

	// --- Vue d'ensemble: OIDC fetch (preserved from pre-CS.3) ---

	let loading = $state(true);
	let oidc = $state<OIDCConfig | null>(null);

	async function load(): Promise<void> {
		try {
			oidc = await settingsApi.getOIDCConfig();
		} catch (err) {
			if (err instanceof ApiError) {
				pushToast(err.message, 'danger');
			}
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void load();
	});

	// v2.41 — this page had three t() calls; every card title, the
	// TLS grid and the security-header empty state were hard-coded
	// English (one of them even quoted a repo path at the operator).
	function tl(key: string): string {
		void language.current;
		return t(key);
	}

	const oidcStatusLabel = $derived(
		oidc?.enabled
			? tl('security.oidcEnabled')
			: oidc?.configured
				? tl('security.oidcConfiguredDisabled')
				: tl('security.oidcNotConfigured')
	);
</script>

<svelte:head>
	<title>{tl('security.headTitle')}</title>
</svelte:head>

<PageHeader
	eyebrow={tl('security.eyebrow')}
	title={language.current && t('pageTitles.security')}
	subtitle={tl('security.subtitle')}
/>

<Tabs
	bind:value={activeTab}
	tabs={parentTabDescriptors}
	ariaLabel={tl('security.tabsAria')}
	onChange={onTabChange}
/>

{#if activeTab === 'overview'}
	{#if loading}
		<div class="loading-wrap"><Spinner /></div>
	{:else}
		<!-- TLS read-only card -->
		<div class="card">
			<div class="card-h">
				<h3>TLS</h3>
				<div class="meta">{tl('security.tlsMeta')}</div>
			</div>
			<div class="ro-banner">
				<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
					<circle cx="8" cy="8" r="6.5" />
					<path d="M8 5v3.5M8 11v.5" />
				</svg>
				<span>{tl('security.tlsBanner')}</span>
			</div>
			<div class="kv-grid">
				<div class="kv"><span class="k">{tl('security.tlsMinVersion')}</span><span class="v">TLS 1.2</span></div>
				<div class="kv"><span class="k">HTTP/3 (QUIC)</span><span class="v">{tl('security.tlsHttp3')}</span></div>
				<div class="kv"><span class="k">OCSP stapling</span><span class="v">{tl('security.tlsEnabled')}</span></div>
				<div class="kv"><span class="k">{tl('security.tlsSessionTickets')}</span><span class="v">{tl('security.tlsAutoRotated')}</span></div>
				<div class="kv"><span class="k">{tl('security.tlsCiphers')}</span><span class="v">{tl('security.tlsCaddyAuto')}</span></div>
				<div class="kv"><span class="k">{tl('security.tlsCurves')}</span><span class="v">{tl('security.tlsCaddyAuto')}</span></div>
			</div>
		</div>

		<!-- Security headers placeholder -->
		<div class="card">
			<div class="card-h">
				<h3>{tl('security.headersTitle')}</h3>
				<div class="meta">HSTS · X-Frame · CSP · Referrer-Policy</div>
			</div>
			<div class="empty">
				<p>{tl('security.headersEmptyTitle')}</p>
				<p class="dim">
					{tl('security.headersEmptyBodyBefore')}
					<a href="/routes">{tl('security.headersEmptyBodyLink')}</a>
					{tl('security.headersEmptyBodyAfter')}
				</p>
			</div>
		</div>

		<!-- Auth providers summary -->
		<div class="card">
			<div class="card-h">
				<h3>{tl('security.authProvidersTitle')}</h3>
				<a href="/settings" class="meta-link">{tl('security.configureLink')}</a>
			</div>
			<div class="kv-grid">
				<div class="kv">
					<span class="k">OIDC (SSO)</span>
					<span class="v">
						<span class="pill" class:on={oidc?.enabled} class:configured={oidc?.configured && !oidc?.enabled}>
							{oidcStatusLabel}
						</span>
					</span>
				</div>
				{#if oidc?.enabled}
					<div class="kv">
						<span class="k">{tl('security.issuer')}</span>
						<span class="v mono">{oidc.issuerUrl || '—'}</span>
					</div>
					<div class="kv">
						<span class="k">{tl('security.providerKind')}</span>
						<span class="v mono">{oidc.kind || 'generic'}</span>
					</div>
					<div class="kv">
						<span class="k">{tl('security.allowlist')}</span>
						<span class="v mono"
							>{language.current &&
								t('security.allowlistEntries', {
									count: oidc.allowedIdentities?.length ?? 0
								})}</span
						>
					</div>
				{/if}
				<div class="kv">
					<span class="k">Forward-auth</span>
					<span class="v dim"
						>{tl('security.perRouteBefore')} <a href="/routes">/routes</a>
						{tl('security.perRouteAfter')}</span
					>
				</div>
				<div class="kv">
					<span class="k">Basic auth</span>
					<span class="v dim"
						>{tl('security.perRouteBefore')} <a href="/routes">/routes</a>
						{tl('security.perRouteAfter')}</span
					>
				</div>
			</div>
		</div>
	{/if}
{:else if activeTab === 'crowdsec'}
	<CrowdSecDecisionsPanel />
{/if}

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 14px 16px;
		margin-bottom: 14px;
	}
	.card-h {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-bottom: 12px;
	}
	.card-h h3 { color: var(--fg); font-size: 13.5px; font-weight: 500; margin: 0; }
	.card-h .meta {
		margin-left: auto;
		color: var(--fg-dim);
		font-size: 11.5px;
		font-family: var(--font-mono);
	}
	.meta-link {
		margin-left: auto;
		color: var(--accent);
		font-size: 12.5px;
		text-decoration: none;
	}
	.meta-link:hover { text-decoration: underline; }

	.ro-banner {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 10px 12px;
		margin-bottom: 14px;
		background: color-mix(in oklch, var(--status-warn) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 28%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg-muted);
		font-size: 12px;
		line-height: 1.5;
	}
	.ro-banner svg { flex: none; color: var(--status-warn); margin-top: 2px; }

	.kv-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 8px 16px;
	}
	.kv {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 6px 0;
		border-bottom: 1px solid var(--border);
		font-size: 12.5px;
	}
	.kv:last-child { border-bottom: none; }
	.kv .k { color: var(--fg-muted); flex: 0 0 140px; }
	.kv .v { color: var(--fg); flex: 1; min-width: 0; }
	.kv .v a { color: var(--accent); text-decoration: none; }
	.kv .v a:hover { text-decoration: underline; }

	.pill {
		display: inline-flex;
		align-items: center;
		padding: 2px 8px;
		border-radius: 999px;
		font-family: var(--font-mono);
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		background: color-mix(in oklch, var(--fg-muted) 18%, transparent);
		color: var(--fg-muted);
	}
	.pill.on {
		background: color-mix(in oklch, var(--status-up) 18%, transparent);
		color: var(--status-up);
	}
	.pill.configured {
		background: color-mix(in oklch, var(--status-warn) 18%, transparent);
		color: var(--status-warn);
	}

	.empty {
		padding: 8px 0;
	}
	.empty p { color: var(--fg); margin: 0 0 8px; font-size: 13px; }
	.empty p.dim { color: var(--fg-muted); font-size: 12.5px; line-height: 1.6; }
	.empty a { color: var(--accent); text-decoration: none; }
	.empty a:hover { text-decoration: underline; }

	.mono { font-family: var(--font-mono); font-size: 12px; }
	.dim { color: var(--fg-muted); }

	.loading-wrap { display: flex; justify-content: center; padding: 48px; }
</style>
