<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  /certs — top-level Sécurité IA entry for certificate visibility
  and managed-domain configuration.

  History:
  - R.2 (`4691eb2`): shipped as a minimal stub.
  - R.4.3.c: promoted to a read-only catalog summarising managed
    domains + TLS-enabled routes.
  - #R-6 Pack A (`06ba97a`): completed the §R-6 migration —
    Managed domains editor moved here from /settings, auto-renewal
    info card added.
  - Step T T.4 (`e8e6311`): consumed the T.1 GET /api/certificates
    runtime metadata. KPI cards reflect the live cert pool;
    the previous "TLS-enabled routes" read-only table replaced
    by the unified Domaines table with status badges and a
    Tous / Wildcard / Expirent bientôt tab filter. The stale
    "runtime metadata not exposed" banner removed (T.1 ships
    the data). Force-renew button intentionally absent per the
    Step T amendment (docs/step-t-spec-amendment.md, commit
    `c62d657`) — Caddy v2.11.3's renewal seam is unexported.
  - Step T T.5 (this commit): reframes the bottom section from
    "Managed domains" to "Politiques wildcard par apex" (the
    semantically honest name — each row IS a per-apex wildcard
    policy). Inline declaration form is hoisted into a modal
    wizard launched by a header "+ Wildcard apex" button (matches
    the existing add-flow pattern used by ChangePasswordModal).
    Wire contract unchanged: same settingsApi.createManagedDomain
    POST, same payload shape, same delete-with-revertTo modal.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import WildcardApexWizard from '$lib/components/certs/WildcardApexWizard.svelte';
	import ExternalCertsPanel from '$lib/components/certs/ExternalCertsPanel.svelte';
	import { settingsApi } from '$lib/api/settings';
	import { certificatesApi } from '$lib/api/certificates';
	import { fetchCertEvents } from '$lib/api/security';
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import type {
		Certificate,
		CertEvent,
		ManagedDomain,
		ManagedDomainRevertTo,
		Route,
	} from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { relativeTime } from '$lib/utils/audit-format';
	import {
		RENEWAL_WINDOW_DAYS,
		certificateSourceLabel,
		certificateStatusLabel,
		certificateStatusToBadgeVariant,
		countByEffectiveSource,
		daysUntilExpiry,
		dominantIssuer,
		inferChallengeLabel,
		isExpiringSoon,
		isZeroTimestamp,
		resolveSource,
	} from '$lib/utils/certificate-format';

	let loading = $state(true);
	let domains = $state<ManagedDomain[]>([]);
	let routes = $state<Route[]>([]);
	let certs = $state<Certificate[]>([]);
	// Tab filter for the Domaines table (AC #6 LOCKED). Local
	// component state, not URL-anchored — sharing the page link
	// implicitly means sharing the "Tous" default, which matches
	// the operator's "what's the state of all my certs?" entry
	// intent. URL-anchored tabs can be revisited if the dashboard
	// gains deep-link conventions elsewhere.
	type DomaineTab = 'all' | 'wildcard' | 'expiring';
	let activeTab = $state<DomaineTab>('all');
	// Distinct from the page-level `loading` (which gates the
	// editor markup): certsLoadError is the soft-fail state for
	// the Domaines table specifically. A 5xx on /api/certificates
	// must NOT take down the managed-domains editor (AC #13
	// degraded-mode policy mirrored on the frontend).
	let certsLoadError = $state(false);

	// DNS provider state — used to render the "DNS provider
	// unconfigured" warning in the editor. The page reads it on
	// load and on every successful managed-domain mutation
	// (settings already mirrors the same dependency). nil-safe
	// when the GET fails (network blip / not-configured shape).
	let dnsProviderConfigured = $state(false);

	// v2.12 — providerId → label map, built from the DNS providers
	// collection. Used to resolve a managed domain's `providerId` to
	// its human label in the policies list + the ACME-method KPI
	// sub-line. Falls back to the raw id when the provider isn't in
	// the map (deleted / not yet loaded).
	let providerLabels = $state<Record<string, string>>({});
	function labelForProvider(id: string): string {
		return providerLabels[id] ?? id;
	}

	// Step T T.5 — wizard-open state. Bindable; the wizard
	// component handles its own form state (apex / provider /
	// includeApex) so the page doesn't carry that anymore.
	let wizardOpen = $state(false);

	// Delete-confirmation modal state. Mirrors the settings
	// page pre-migration verbatim — the revertTo dropdown is
	// the spec O.4 AC #21 affordance and must not change shape.
	let mdDeleteOpen = $state(false);
	let mdDeleteApex = $state('');
	let mdDeleteRevertTo = $state<ManagedDomainRevertTo>('');
	let mdDeleteError = $state<string | null>(null);

	// Task 7 — per-row certificate delete. Mirrors the
	// managed-domain delete flow's shape (a target + a Modal
	// gated by it) rather than inventing a new dialog primitive.
	// deleteTarget holds the domain awaiting confirmation;
	// blockedDialog holds the 409 outcome (domain + the routes
	// still referencing it) so the operator knows what to fix
	// before retrying the delete.
	let deleteTarget = $state<string | null>(null);
	let blockedDialog = $state<{ domain: string; routes: string[] } | null>(null);

	// Cert.B (2026-06-23) — per-domain cert events cache. Used by
	// both the stale-failure badge derivation and the drill-down
	// modal. Lazy-loaded after the certs list paints (loadCertEvents)
	// so initial page render isn't blocked by N concurrent HTTP
	// fetches. SvelteKit reactive map : assigning to a new Map
	// triggers $derived recomputation.
	let certEventsByDomain = $state<Map<string, CertEvent[]>>(new Map());

	// Stale-failure threshold = 24h post-failure with no
	// cert_obtained since. Stricter than the certinfo.Tracker's
	// existing FailureFreshness 24h window (which surfaces the
	// OBTAIN_FAILED status badge for fresh failures). This badge
	// covers the gap : failures > 24h old where no recovery
	// happened, currently invisible to the operator because
	// FailureFreshness expired and the tracker reverted to the
	// pre-failure status. Operator visiting /certs cold sees
	// the badge and knows to investigate.
	const STALE_FAILURE_THRESHOLD_MS = 24 * 60 * 60 * 1000;

	// Auto-refresh cadence for the cert list + events while /certs is
	// mounted (see onMount). ACME issuance is rare and slow, so 20s is
	// proportionate without hammering the backend GETs.
	const CERT_REFRESH_INTERVAL_MS = 20000;

	// Burst polling right after a wildcard apex is declared: DNS-01
	// issuance typically lands 10-60 s later, so waiting for the 20 s
	// cadence left the operator staring at an unchanged page (and
	// reloading by hand). Poll every 3 s for up to 2 min, then fall
	// back to the normal cadence.
	const ISSUANCE_POLL_INTERVAL_MS = 3000;
	const ISSUANCE_POLL_WINDOW_MS = 120000;

	// Apexes declared in this session whose wildcard cert has not
	// landed yet: apex → declaration time (ms). Drives the burst poll
	// and the "Issuance in progress…" badge on the policy row. An apex
	// leaves the map when its cert settles or its window expires (an
	// OBTAIN_FAILED or stale failure is then surfaced by the Domaines
	// table's own badges).
	let issuing = $state<Record<string, number>>({});
	let issuanceTimer: ReturnType<typeof setInterval> | null = null;

	// Drill-down modal state. drillDownDomain holds the domain
	// the operator clicked the badge for ; null = closed. The
	// modal reads certEventsByDomain[drillDownDomain] to render
	// the 5-event list, so opening the modal is instant for any
	// already-loaded domain.
	let drillDownDomain = $state<string | null>(null);

	const tlsRoutes = $derived(routes.filter((r) => r.tlsEnabled));
	const tlsCount = $derived(tlsRoutes.length);
	const managedCount = $derived(domains.length);

	// Warning shown above the editor when no DNS provider is
	// configured: ACME wildcard issuance via DNS-01 is disabled,
	// the editor stays enabled so the operator can stage a
	// managed domain ahead of configuring OVH credentials.
	const sslDNSUnconfigured = $derived(!dnsProviderConfigured);

	// Step T T.4 — runtime KPI derivations from the cert list.
	// All four cards must reflect the LIVE state (T.4 brief A);
	// the pre-T.4 cards were config viewers that didn't change
	// when a cert was issued or expired.
	const certsTotal = $derived(certs.length);
	// Breakdown via resolveSource so OBTAIN_FAILED entries (which
	// carry source="" on the wire) still classify correctly —
	// pre-polish the breakdown didn't sum to the total.
	const certsBreakdown = $derived(countByEffectiveSource(certs));
	const certsWildcard = $derived(certsBreakdown.wildcard);
	const certsSpecific = $derived(certsBreakdown.specific);
	// isExpiringSoon now excludes OBTAIN_FAILED + zero-time
	// entries, so the count matches operator expectations
	// ("renewal scheduled" should not include certs that haven't
	// been obtained yet).
	const certsExpiringSoon = $derived(certs.filter((c) => isExpiringSoon(c)).length);
	const principalIssuer = $derived(dominantIssuer(certs));
	// ACME method KPI: DNS-01 wins as soon as at least one
	// managed-domain is declared (we're using DNS-01 for at least
	// some of the cert pool); else "Auto" (HTTP-01 default).
	const acmeMethodLabel = $derived(
		language.current &&
			(domains.length > 0 ? 'DNS-01' : t('certs.kpiACMEMethodAuto'))
	);
	const acmeMethodSub = $derived(
		language.current &&
			(domains.length > 0
				? t('certs.kpiACMEMethodVia', { provider: labelForProvider(domains[0].providerId) })
				: t('certs.kpiACMEMethodHttp01'))
	);

	// Filtered cert list per the active tab. Pure client-side —
	// no refetch — so tab switching is instant. Empty-state copy
	// branches on activeTab so the operator sees the right
	// "nothing in this category" message.
	const filteredCerts = $derived.by(() => {
		switch (activeTab) {
			case 'wildcard':
				return certs.filter((c) => c.source === 'wildcard');
			case 'expiring':
				return certs.filter((c) => isExpiringSoon(c));
			case 'all':
			default:
				return certs;
		}
	});

	async function loadDNSProvider(): Promise<void> {
		try {
			const list = await settingsApi.listDNSProviders();
			// "Configured" for the warning gate = at least one provider
			// has its secrets set (v2.12 multi-config semantic).
			dnsProviderConfigured = list.some((p) => p.configured);
			// Build the id → label map for the policies list + KPI.
			const next: Record<string, string> = {};
			for (const p of list) next[p.id] = p.label;
			providerLabels = next;
		} catch {
			// Treat fetch failures as "not configured" so the
			// warning still surfaces. Logging is left to the
			// upstream request helper.
			dnsProviderConfigured = false;
			providerLabels = {};
		}
	}

	async function loadManagedDomains(): Promise<void> {
		try {
			const res = await settingsApi.listManagedDomains();
			domains = res.domains ?? [];
		} catch (err) {
			if (err instanceof ApiError) pushToast(err.message, 'danger');
		}
	}

	// Step T T.4 — load the runtime cert list. Soft-failing on
	// purpose: a 5xx must NOT block the rest of the page (the
	// managed-domains editor and renewal info card stay
	// functional). The Domaines table renders the certsLoadError
	// branch instead.
	async function loadCertificates(): Promise<void> {
		try {
			certs = await certificatesApi.list();
			certsLoadError = false;
		} catch {
			certs = [];
			certsLoadError = true;
		}
	}

	/**
	 * Cert.B (2026-06-23) — fetch the 5 most recent cert events
	 * per domain, after the certs list lands. Soft-failing : a
	 * 5xx on a single domain doesn't block the others, and the
	 * absence of events leaves the badge derivation unchanged
	 * (no badge shown — same as "no failures observed").
	 *
	 * N domains = N concurrent HTTP calls. Typical homelab :
	 * 5-50 domains, well within browser parallel-request limits.
	 * The per-call payload is bounded by limit=5 so the total
	 * bandwidth stays trivial.
	 */
	async function loadCertEvents(): Promise<void> {
		if (certs.length === 0) return;
		const settled = await Promise.allSettled(
			certs.map((c) =>
				fetchCertEvents({ domain: c.domain, limit: 5 }).then(
					(resp) => ({ domain: c.domain, events: resp.events ?? [] })
				)
			)
		);
		const next = new Map<string, CertEvent[]>();
		for (const result of settled) {
			if (result.status === 'fulfilled') {
				next.set(result.value.domain, result.value.events);
			}
		}
		certEventsByDomain = next;
	}

	/**
	 * Cert.B stale-failure detection. Returns the timestamp of
	 * the most-recent cert_failed event for `domain` IF :
	 *   - That failure is the most recent event of any type
	 *   - AND it occurred > STALE_FAILURE_THRESHOLD_MS ago
	 *
	 * Otherwise returns null = no stale-failure badge.
	 *
	 * Distinct from cert.status === 'OBTAIN_FAILED' which uses
	 * the certinfo.Tracker's 24h FailureFreshness — that badge
	 * covers fresh failures (< 24h) ; this one covers stale
	 * failures (> 24h, no recovery) that the tracker has
	 * forgotten about.
	 */
	function staleFailureSince(domain: string): Date | null {
		const events = certEventsByDomain.get(domain);
		if (!events || events.length === 0) return null;
		// API returns newest-first by ts DESC convention (verified
		// against observability.QueryCertEvents ORDER BY ts DESC).
		const mostRecent = events[0];
		if (mostRecent.eventType !== 'cert_failed') return null;
		const failTime = new Date(mostRecent.timestamp);
		if (Date.now() - failTime.getTime() < STALE_FAILURE_THRESHOLD_MS) return null;
		return failTime;
	}

	/**
	 * How many cert_failed events in the loaded window. Used in
	 * the badge tooltip ("3 tentatives") so the operator knows
	 * whether this is a single-shot fluke or a persistent issue.
	 */
	function failureCountSince(domain: string): number {
		const events = certEventsByDomain.get(domain);
		if (!events) return 0;
		return events.filter((e) => e.eventType === 'cert_failed').length;
	}

	/**
	 * "Xh", "Xd" / "Xj" duration string for the badge label.
	 * Compact ; the full timestamp lives in the tooltip.
	 *
	 * The narrow unit style of Intl.NumberFormat yields exactly that
	 * compact form in the app language ("5h", "3d" / "3j"), so no
	 * suffix is hand-coded. Reading language.current inline lets a
	 * $derived caller pick up the switch reactively.
	 */
	function staleAgo(failTime: Date): string {
		const ms = Date.now() - failTime.getTime();
		const hours = Math.floor(ms / (60 * 60 * 1000));
		const inDays = hours >= 48;
		return new Intl.NumberFormat(language.current, {
			style: 'unit',
			unit: inDays ? 'day' : 'hour',
			unitDisplay: 'narrow'
		}).format(inDays ? Math.floor(hours / 24) : hours);
	}

	/** True once the apex's wildcard cert is in the list with a real
	 *  status (issued, renewing, expired or failed). */
	function wildcardSettled(apex: string): boolean {
		const cert = certs.find((c) => c.domain === `*.${apex}`);
		return cert !== undefined && cert.status !== 'UNKNOWN';
	}

	function isIssuing(apex: string): boolean {
		return apex in issuing && !wildcardSettled(apex);
	}

	function stopIssuancePolling(): void {
		if (issuanceTimer !== null) {
			clearInterval(issuanceTimer);
			issuanceTimer = null;
		}
	}

	async function issuanceTick(): Promise<void> {
		await loadCertificates();
		const now = Date.now();
		const next: Record<string, number> = {};
		let settledAny = false;
		for (const [apex, startedAt] of Object.entries(issuing)) {
			if (wildcardSettled(apex)) {
				settledAny = true;
			} else if (now - startedAt < ISSUANCE_POLL_WINDOW_MS) {
				next[apex] = startedAt;
			}
		}
		issuing = next;
		// Same ordering as load(): events after the cert list, so a
		// cert that just landed gets its badge data this tick.
		if (settledAny) void loadCertEvents();
		if (Object.keys(next).length === 0) stopIssuancePolling();
	}

	/** Wizard onCreated: refresh the policies, mark every newly
	 *  declared apex as issuing and start the burst poll. */
	async function onWildcardCreated(): Promise<void> {
		const before = new Set(domains.map((d) => d.apex));
		await loadManagedDomains();
		const now = Date.now();
		const next = { ...issuing };
		for (const d of domains) {
			if (!before.has(d.apex)) next[d.apex] = now;
		}
		issuing = next;
		if (issuanceTimer === null && Object.keys(issuing).length > 0) {
			issuanceTimer = setInterval(() => void issuanceTick(), ISSUANCE_POLL_INTERVAL_MS);
		}
	}

	async function load(): Promise<void> {
		try {
			const [rs] = await Promise.all([
				listRoutes(),
				loadManagedDomains(),
				loadDNSProvider(),
				loadCertificates(),
			]);
			routes = rs;
			// Cert.B — load events AFTER certificates have landed
			// (we need the cert list to know which domains to
			// query). Fire-and-forget : badges will render once
			// the events resolve, table is otherwise interactive.
			void loadCertEvents();
		} catch (err) {
			if (err instanceof ApiError) pushToast(err.message, 'danger');
		} finally {
			loading = false;
		}
	}

	function openDeleteManagedDomain(apex: string): void {
		mdDeleteApex = apex;
		mdDeleteRevertTo = '';
		mdDeleteError = null;
		mdDeleteOpen = true;
	}

	async function confirmDeleteManagedDomain(): Promise<void> {
		mdDeleteError = null;
		try {
			await settingsApi.deleteManagedDomain(mdDeleteApex, mdDeleteRevertTo);
			if (mdDeleteApex in issuing) {
				const { [mdDeleteApex]: _removed, ...rest } = issuing;
				issuing = rest;
			}
			mdDeleteOpen = false;
			await loadManagedDomains();
		} catch (err) {
			mdDeleteError = err instanceof ApiError ? err.message : String(err);
		}
	}

	/**
	 * Task 7 — confirm handler for the per-row certificate delete.
	 * On 200: success toast + list refresh (loadCertificates, same
	 * fn the T.4 auto-poll uses). On 409 (still referenced by a
	 * route or a wildcard policy): opens the blocked dialog with
	 * the offending hosts from `e.blockingRoutes` instead of
	 * toasting an error. Any other failure falls back to a danger
	 * toast.
	 */
	async function doDeleteCert(domain: string): Promise<void> {
		try {
			await certificatesApi.deleteCertificate(domain);
			pushToast(t('certs.delete.success', { domain }), 'success');
			deleteTarget = null;
			await loadCertificates();
		} catch (err) {
			deleteTarget = null;
			const e = err as { status?: number; blockingRoutes?: string[]; message?: string };
			if (e?.status === 409) {
				blockedDialog = { domain, routes: e.blockingRoutes ?? [] };
			} else {
				pushToast(e?.message ?? t('certs.delete.action'), 'danger');
			}
		}
	}

	onMount(() => {
		void load();
		// Auto-refresh: ACME issuance is asynchronous (certmagic obtains
		// the cert AFTER the route/managed-domain is created), so a
		// freshly-issued cert would otherwise only appear on a manual
		// page reload. Poll the cert list + events every 20s while the
		// page is mounted. Issuance is a rare, low-frequency event, so
		// polling is proportionate — no WS needed. Interval cleared on
		// unmount via the returned cleanup.
		//
		// Ordering mirrors load(): events are fetched AFTER the cert list
		// lands (loadCertEvents reads the current certs array to know
		// which domains to query), so a cert appearing this cycle gets
		// its events in the same tick rather than lagging one cycle.
		const id = setInterval(() => {
			void loadCertificates().then(() => loadCertEvents());
		}, CERT_REFRESH_INTERVAL_MS);
		return () => {
			clearInterval(id);
			stopIssuancePolling();
		};
	});
</script>

<svelte:head>
	<title>{language.current && t('certs.headTitle')}</title>
</svelte:head>

<PageHeader
	eyebrow={language.current && t('certs.pageEyebrow')}
	title={language.current && t('pageTitles.certs')}
	subtitle={language.current && t('certs.pageSubtitle')}
/>

{#if loading}
	<div class="loading-wrap"><Spinner /></div>
{:else}
	<!-- v2.41 — these four tiles were a scoped-CSS copy of StatCard;
	     the component now carries the same treatment, with variant
	     "text" for the two readings that are words, not numbers. -->
	<div class="kpis">
		<StatCard
			testid="kpi-certs-actifs"
			label={language.current && t('certs.kpiActiveCertsLabel')}
			value={certsTotal}
			hint={language.current && t('certs.kpiActiveCertsFoot', { wildcard: certsWildcard, specific: certsSpecific, plural: certsSpecific === 1 ? '' : 's' })}
		/>
		<StatCard
			testid="kpi-expirent-bientot"
			label={language.current && t('certs.kpiExpiringLabel', { days: RENEWAL_WINDOW_DAYS })}
			value={certsExpiringSoon}
			hint={language.current && (certsExpiringSoon > 0 ? t('certs.kpiExpiringFootAuto') : '—')}
		/>
		<StatCard
			testid="kpi-emetteur"
			label={language.current && t('certs.kpiIssuerLabel')}
			value={principalIssuer}
			variant="text"
		/>
		<StatCard
			testid="kpi-methode"
			label={language.current && t('certs.kpiACMEMethodLabel')}
			value={acmeMethodLabel}
			variant="text"
			hint={acmeMethodSub}
		/>
	</div>

	<!-- Auto-renewal info card (Pack A).
	     Placed between the KPI row and the read-only metadata
	     banner so it's the first content the operator sees after
	     the at-a-glance numbers. Reassures that renewal is
	     automatic — addresses the operator's "is renewal
	     automated?" gap.

	     Satisfies AC #13 (auto-renewal info card preserved) —
	     Step T spec v1.2.0-step-t-spec. Originally shipped in
	     06ba97a (Pack A); carried forward unchanged through T.4. -->
	<div class="renewal-card" data-testid="auto-renewal-card">
		<div class="renewal-icon" aria-hidden="true">
			<svg
				width="20"
				height="20"
				viewBox="0 0 24 24"
				fill="none"
				stroke="currentColor"
				stroke-width="1.8"
				stroke-linecap="round"
				stroke-linejoin="round"
			>
				<path d="M12 2 L20 6 V12 C20 17 16 21 12 22 C8 21 4 17 4 12 V6 Z" />
				<path d="m9 12 2 2 4-4" />
			</svg>
		</div>
		<div class="renewal-body">
			<div class="renewal-title">{language.current && t('certs.renewalTitle')}</div>
			<!--
				The sentence is split around the link (before / link /
				after) so the <a> sits where each language puts it, with
				no HTML interpolation.
			-->
			<p>
				{language.current && t('certs.renewalHelperBefore')}
				<a href="/logs">{language.current && t('certs.renewalLogsLink')}</a>{language.current && t('certs.renewalHelperAfter')}
			</p>
		</div>
	</div>

	<!-- Step T T.4 — unified Domaines table. Live runtime cert
	     metadata from GET /api/certificates (T.1, commit 1350777).
	     Replaces the pre-T.4 "TLS-enabled routes" read-only table
	     (which only knew the configured shape, never the actual
	     cert state). No row actions — force-renew button absent
	     per the Step T amendment (Caddy renewal seam unexported).

	     Satisfies AC #5 (unified Domaines table) + AC #6 (tabs
	     filter Tous / Wildcard / Expirent bientôt) — Step T spec
	     v1.2.0-step-t-spec, implemented by e8e6311 (T.4). -->
	<div class="card" data-testid="domaines-card">
		<div class="card-h">
			<h3>{language.current && t('certs.domainsCardTitle')}</h3>
			<!-- NOTE (CS.3 extraction audit): this tablist is
			     intentionally NOT migrated to lib/components/
			     Tabs.svelte. The two surfaces share role="tablist"
			     but serve different UI primitives:
			       - Tabs.svelte = full-width primary page nav,
			         underline-accent style, content-switching
			         (see /security/decisions, /sécurité in CS.3).
			       - This tablist = in-card filter chips, pill
			         style, FILTER the same list in place (Tous /
			         Wildcard / Expirent bientôt). Forcing
			         convergence would either visually break this
			         page or pollute Tabs.svelte with a variant
			         prop that gates two CSS branches. If /certs
			         ever switches to a different filter UX
			         (e.g. dropdown, segmented control), revisit
			         here. -->
			<div class="tabs" role="tablist" aria-label={language.current && t('certs.filterCertsAria')}>
				<button
					type="button"
					role="tab"
					class="tab"
					class:active={activeTab === 'all'}
					aria-selected={activeTab === 'all'}
					data-testid="tab-all"
					onclick={() => (activeTab = 'all')}
				>
					{language.current && t('certs.tabAll')}
				</button>
				<button
					type="button"
					role="tab"
					class="tab"
					class:active={activeTab === 'wildcard'}
					aria-selected={activeTab === 'wildcard'}
					data-testid="tab-wildcard"
					onclick={() => (activeTab = 'wildcard')}
				>
					{language.current && t('certs.tabWildcard')}
				</button>
				<button
					type="button"
					role="tab"
					class="tab"
					class:active={activeTab === 'expiring'}
					aria-selected={activeTab === 'expiring'}
					data-testid="tab-expiring"
					onclick={() => (activeTab = 'expiring')}
				>
					{language.current && t('certs.tabExpiring')}
				</button>
			</div>
		</div>

		{#if certsLoadError}
			<div class="empty-row" data-testid="certs-error">
				{language.current && t('certs.certsLoadError')}
			</div>
		{:else if certs.length === 0}
			<div class="empty-row" data-testid="certs-empty">
				{language.current && t('certs.certsEmptyTitle')}
				<div class="empty-sub">
					{language.current && t('certs.certsEmptyHelper')}
				</div>
			</div>
		{:else if filteredCerts.length === 0}
			<div class="empty-row" data-testid="certs-tab-empty">
				{language.current && t('certs.certsTabEmpty')}
			</div>
		{:else}
			<table data-testid="certs-table">
				<thead>
					<tr>
						<th>{language.current && t('certs.colDomain')}</th>
						<th>{language.current && t('certs.colIssuer')}</th>
						<th>{language.current && t('certs.colSAN')}</th>
						<th>{language.current && t('certs.colIssuedAt')}</th>
						<th>{language.current && t('certs.colExpiresIn')}</th>
						<th>{language.current && t('certs.colState')}</th>
						<th class="col-actions"><span class="visually-hidden">{language.current && t('certs.delete.action')}</span></th>
					</tr>
				</thead>
				<tbody>
					{#each filteredCerts as cert (cert.domain)}
						{@const effectiveSource = resolveSource(cert)}
						{@const days = daysUntilExpiry(cert)}
						{@const notBeforeMissing = isZeroTimestamp(cert.notBefore)}
						{@const staleFailedAt = staleFailureSince(cert.domain)}
						{@const failCount = failureCountSince(cert.domain)}
						<tr data-testid="cert-row" data-domain={cert.domain}>
							<td>
								<div class="domain-cell">
									<span class="mono">{cert.domain}</span>
									{#if staleFailedAt}
										<!-- Cert.B stale-failure badge — clickable,
										     opens the drill-down modal pre-loaded
										     with the last 5 events for this domain. -->
										<button
											type="button"
											class="stale-badge"
											data-testid="cert-stale-badge"
											data-domain={cert.domain}
											title={language.current && t('certs.staleBadgeTooltip', {
												ago: relativeTime(staleFailedAt.toISOString()),
												count: failCount,
												plural: failCount === 1 ? '' : 's'
											})}
											onclick={() => (drillDownDomain = cert.domain)}
										>
											{language.current && t('certs.staleBadgeText', { ago: staleAgo(staleFailedAt) })}
										</button>
									{/if}
								</div>
								<div class="dim cell-sub">
									{certificateSourceLabel(effectiveSource)} · {inferChallengeLabel(
										effectiveSource,
										cert.status
									)}
								</div>
							</td>
							<td>{cert.issuer || '—'}</td>
							<td class="mono">
								{language.current && t('certs.sanCount', { count: (cert.sanList ?? []).length })}
							</td>
							<td class="dim">
								{notBeforeMissing ? '—' : relativeTime(cert.notBefore)}
							</td>
							<td>
								<span
									class="expiry"
									class:expiry-warn={days !== null &&
										days <= RENEWAL_WINDOW_DAYS &&
										days > 0}
									class:expiry-down={days !== null && days <= 0}
								>
									{#if days === null}
										—
									{:else if days <= 0}
										{language.current && t('certs.expiryExpired')}
									{:else}
										{language.current && t('certs.expiryDays', { days, plural: days === 1 ? '' : 's' })}
									{/if}
								</span>
							</td>
							<td>
								{#if cert.status === 'OBTAIN_FAILED' && cert.lastError}
									<Tooltip
										label={`${cert.lastError}${
											cert.lastErrorAt
												? ` (${relativeTime(cert.lastErrorAt)})`
												: ''
										}`}
									>
										<Badge variant={certificateStatusToBadgeVariant(cert.status)}>
											{certificateStatusLabel(cert.status)}
										</Badge>
									</Tooltip>
								{:else}
									<Badge variant={certificateStatusToBadgeVariant(cert.status)}>
										{certificateStatusLabel(cert.status)}
									</Badge>
								{/if}
							</td>
							<td class="col-actions">
								<button
									type="button"
									class="row-delete-btn"
									data-testid={`cert-delete-${cert.domain}`}
									aria-label={language.current && t('certs.delete.action')}
									onclick={() => (deleteTarget = cert.domain)}
								>
									{language.current && t('certs.delete.action')}
								</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>

	<!-- Step T T.5 — Politiques wildcard par apex. Reframe of the
	     pre-T.5 "Managed domains" section: same wire contract,
	     semantically honest French copy, declaration form hoisted
	     into the WildcardApexWizard modal (header "+ Wildcard apex"
	     button). Delete flow (revertTo modal) is unchanged.

	     Satisfies AC #11 (reframe copy LOCKED) + AC #12 (delete-
	     with-revertTo modal preserved) — Step T spec
	     v1.2.0-step-t-spec, implemented by 6b03f1c (T.5). -->
	<div class="card" data-testid="policies-card">
		<div class="card-h">
			<h3>{language.current && t('certs.policiesCardTitle')}</h3>
			<span class="card-h-meta">
				{#if domains.length > 0}
					{language.current && t('certs.policiesDeclaredCounter', { count: domains.length, plural: domains.length === 1 ? '' : 's' })}
				{:else}
					{language.current && t('certs.policiesEmpty')}
				{/if}
			</span>
			<div class="card-h-actions">
				<Button
					variant="primary"
					size="sm"
					onclick={() => (wizardOpen = true)}
					data-testid="open-wildcard-wizard"
				>
					{#snippet children()}{language.current && t('certs.wildcardApexButton')}{/snippet}
				</Button>
			</div>
		</div>

		<p class="section-lead">
			{language.current && t('certs.policiesLeadBefore')}
			<a href="/settings">{language.current && t('certs.settingsLink')}</a>{language.current && t('certs.policiesLeadAfter')}
		</p>

		{#if sslDNSUnconfigured}
			<div class="warn-box" role="alert">
				<strong>{language.current && t('certs.dnsUnconfiguredTitle')}</strong>
				{language.current && t('certs.dnsUnconfiguredHelper')}
				<a href="/settings">/settings</a>.
			</div>
		{/if}

		{#if domains.length > 0}
			<ul class="md-list">
				{#each domains as md (md.apex)}
					<li class="md-row">
						<div class="md-meta">
							<div class="mono md-apex">
								*.{md.apex}{#if md.includeApex}<span class="dim"
										>, {md.apex}</span
									>{/if}
							</div>
							<div class="md-sub">
								{language.current && t('certs.policiesProviderLabel')} <span class="mono">{labelForProvider(md.providerId)}</span>
								{#if md.includeApex}· {language.current && t('certs.policiesIncludesApex')}{/if}
							</div>
							{#if isIssuing(md.apex)}
								<div
									class="md-issuing"
									role="status"
									data-testid="md-issuing"
									data-apex={md.apex}
									title={language.current && t('certs.policiesIssuingHint')}
								>
									<Spinner size="sm" />
									{language.current && t('certs.policiesIssuing')}
								</div>
							{/if}
						</div>
						<Button
							variant="ghost"
							onclick={() => openDeleteManagedDomain(md.apex)}
							aria-label={language.current && t('certs.policiesDeleteAriaLabel', { apex: md.apex })}
						>
							{language.current && t('certs.policiesDeleteButton')}
						</Button>
					</li>
				{/each}
			</ul>
		{/if}

		<p class="section-lead md-foot">
			{language.current && t('certs.policiesFoot')}
		</p>
	</div>

	<!-- v2.19.0 external-certs SOCLE (Task 7) — bring-your-own-cert
	     upload panel + list. Self-contained component: owns its own
	     data load, upload form, list table, and delete/blocked
	     dialogs. Placed below the wildcard policies section as the
	     distinct "certificates I supply myself" surface (vs. the
	     ACME-issued certs the Domaines table above tracks). -->
	<ExternalCertsPanel />

{/if}

<!-- Step T T.5 — wizard mount. Always mounted, gated by `open`
     prop so form state survives reopens within a session.
     onWildcardCreated is the onCreated callback: the new policy
     row appears the moment the wizard closes, flagged "Issuance
     in progress…" while a 3 s burst poll waits for its cert.
     One-way prop + explicit onClose callback (same pattern as
     the delete-managed-domain Modal above) avoids the
     bidirectional-state surprises of $bindable. -->
<WildcardApexWizard
	open={wizardOpen}
	onClose={() => (wizardOpen = false)}
	onCreated={onWildcardCreated}
/>

<!-- Delete-managed-domain modal — verbatim port of the
     /settings dialog so the revertTo dropdown (spec O.4 AC #21)
     keeps its contract. The warning text on the "" / "http-01"
     branches stays unchanged. -->
{#if mdDeleteOpen}
	<Modal
		open={mdDeleteOpen}
		title={language.current && t('certs.mdDeleteTitle', { apex: mdDeleteApex })}
		onClose={() => (mdDeleteOpen = false)}
	>
		{#snippet children()}
			<p class="modal-lead">
				{language.current && t('certs.mdDeleteLead')}
			</p>
			<div class="modal-field">
				<label for="md-delete-revert-to">{language.current && t('certs.mdDeleteRevertToLabel')}</label>
				<select
					id="md-delete-revert-to"
					bind:value={mdDeleteRevertTo}
					class="md-input"
				>
					<option value="">{language.current && t('certs.mdDeleteOptDefault')}</option>
					<option value="http-01">{language.current && t('certs.mdDeleteOptHTTP01')}</option>
					<option value="dns-01">{language.current && t('certs.mdDeleteOptDNS01')}</option>
				</select>
			</div>
			{#if mdDeleteRevertTo === '' || mdDeleteRevertTo === 'http-01'}
				<p class="modal-warn" role="alert">
					{language.current && t('certs.mdDeleteWarning')}
				</p>
			{/if}
			{#if mdDeleteError}
				<p class="modal-error" role="alert">{mdDeleteError}</p>
			{/if}
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (mdDeleteOpen = false)}
				>{language.current && t('certs.mdDeleteCancel')}</Button
			>
			<Button
				variant="danger"
				onclick={() => void confirmDeleteManagedDomain()}>{language.current && t('certs.mdDeleteConfirm')}</Button
			>
		{/snippet}
	</Modal>
{/if}

<!-- Task 7 — certificate delete confirm dialog. Same Modal
     component + footer button pair as the managed-domain delete
     dialog above; the confirm button carries the fixed testid the
     brief's tests key on. -->
{#if deleteTarget}
	<Modal
		open={deleteTarget !== null}
		title={language.current && t('certs.delete.confirm.title')}
		onClose={() => (deleteTarget = null)}
	>
		{#snippet children()}
			<p class="modal-lead">
				{language.current && t('certs.delete.confirm.text', { domain: deleteTarget ?? '' })}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (deleteTarget = null)}
				>{language.current && t('common.cancel')}</Button
			>
			<Button
				variant="danger"
				data-testid="cert-delete-confirm"
				onclick={() => void doDeleteCert(deleteTarget ?? '')}
			>
				{language.current && t('certs.delete.confirm.action')}
			</Button>
		{/snippet}
	</Modal>
{/if}

<!-- Task 7 — blocked-delete dialog. Surfaces the 409 outcome: the
     certificate is still referenced by one or more routes /
     wildcard policies, listed verbatim from e.blockingRoutes so the
     operator knows what to clear first. Single "Got it"
     acknowledgement button — there is nothing to confirm here. -->
{#if blockedDialog}
	<Modal
		open={blockedDialog !== null}
		title={language.current && t('certs.delete.blocked.title')}
		onClose={() => (blockedDialog = null)}
	>
		{#snippet children()}
			<p class="modal-lead" role="alert">
				{language.current && t('certs.delete.blocked.text', {
					domain: blockedDialog?.domain ?? '',
					routes: (blockedDialog?.routes ?? []).join(', ')
				})}
			</p>
		{/snippet}
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (blockedDialog = null)}>
				{language.current && t('common.confirm')}
			</Button>
		{/snippet}
	</Modal>
{/if}

<!-- Cert.B drill-down modal — last 5 cert events for a single
     domain. Reads from certEventsByDomain cache populated by
     loadCertEvents, so opening the modal is instant for any
     domain whose events have landed. The "Voir tous les
     événements" link routes to /logs?source=cert which is the
     existing global activity log filtered by cert source. -->
{#if drillDownDomain}
	<Modal
		open={drillDownDomain !== null}
		title={language.current && t('certs.drillTitle', { domain: drillDownDomain ?? '' })}
		onClose={() => (drillDownDomain = null)}
	>
		{#snippet children()}
			{@const events = certEventsByDomain.get(drillDownDomain ?? '') ?? []}
			{#if events.length === 0}
				<p class="modal-lead" data-testid="cert-drilldown-empty">
					{language.current && t('certs.drillEmpty')}
				</p>
			{:else}
				<p class="modal-lead">
					{language.current && t('certs.drillLead', { count: events.length, plural: events.length === 1 ? '' : 's' })}
				</p>
				<ul class="event-list" data-testid="cert-drilldown-list">
					{#each events as ev (ev.timestamp + ev.eventType)}
						<li
							class="event-item"
							class:event-failed={ev.eventType === 'cert_failed'}
							class:event-obtained={ev.eventType === 'cert_obtained'}
						>
							<div class="event-head">
								<span class="event-type mono">{ev.eventType}</span>
								<span class="event-time dim">{relativeTime(ev.timestamp)}</span>
							</div>
							{#if ev.error}
								<div class="event-error mono" data-testid="cert-event-error">
									{ev.error}
								</div>
							{:else if ev.eventType === 'cert_obtained'}
								<div class="event-success dim">
									{language.current && (ev.renewal ? t('certs.drillEventRenewal') : t('certs.drillEventInitial'))} ·
									{ev.issuer || (language.current && t('certs.drillEventIssuerUnknown'))}
									{#if ev.challenge}· {ev.challenge}{/if}
								</div>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		{/snippet}
		{#snippet footer()}
			<a
				href={`/logs?source=cert&search=${encodeURIComponent(drillDownDomain ?? '')}`}
				class="modal-link"
				data-testid="cert-drilldown-logs-link"
			>
				{language.current && t('certs.drillFooterLink')}
			</a>
			<Button variant="ghost" onclick={() => (drillDownDomain = null)}>
				{language.current && t('certs.drillFooterClose')}
			</Button>
		{/snippet}
	</Modal>
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
	.card-h h3 {
		color: var(--fg);
		font-size: 13.5px;
		font-weight: 500;
		margin: 0;
	}
	.card-h-meta {
		margin-left: auto;
		color: var(--fg-muted);
		font-size: 11.5px;
		font-family: var(--font-mono);
	}
	.section-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		line-height: 1.55;
		margin: 0 0 12px 0;
	}
	.section-lead a {
		color: var(--accent);
		text-decoration: none;
	}
	.section-lead a:hover {
		text-decoration: underline;
	}
	.md-foot {
		margin-top: 14px;
		margin-bottom: 0;
	}

	.kpis {
		display: grid;
		grid-template-columns: repeat(4, 1fr);
		gap: 12px;
		margin-bottom: 14px;
	}
	/* v2.41 — the tile rules live in StatCard.svelte now. */

	/* Auto-renewal info card. Uses the accent token for the
	   border + a soft accent tint for the background so the
	   panel reads as "informational + assuring", not a
	   warning. */
	.renewal-card {
		display: flex;
		gap: 14px;
		padding: 14px 16px;
		margin-bottom: 14px;
		background: color-mix(in oklch, var(--accent) 8%, transparent);
		border: 1px solid color-mix(in oklch, var(--accent) 30%, transparent);
		border-radius: var(--radius);
		color: var(--fg);
		font-size: 13px;
		line-height: 1.55;
	}
	.renewal-icon {
		flex: none;
		color: var(--accent);
		margin-top: 2px;
	}
	.renewal-title {
		font-weight: 500;
		font-size: 13.5px;
		margin-bottom: 4px;
		color: var(--fg);
	}
	.renewal-body p {
		margin: 0;
		color: var(--fg-muted);
		font-size: 12.5px;
	}
	.renewal-body a {
		color: var(--accent);
		text-decoration: none;
	}
	.renewal-body a:hover {
		text-decoration: underline;
	}

	.warn-box {
		margin-bottom: 12px;
		padding: 10px 12px;
		background: color-mix(in oklch, var(--status-warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 32%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		line-height: 1.5;
	}
	.warn-box a {
		color: var(--accent);
	}

	/* Managed-domains editor */
	.md-list {
		list-style: none;
		margin: 0 0 16px 0;
		padding: 0;
		border-top: 1px solid var(--border);
	}
	.md-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 10px 0;
		border-bottom: 1px solid var(--border);
	}
	.md-meta {
		min-width: 0;
	}
	.md-issuing {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-top: 4px;
		font-size: 12px;
		color: var(--fg-muted);
	}
	.md-apex {
		font-size: 13px;
	}
	.md-sub {
		font-size: 11.5px;
		color: var(--fg-muted);
		margin-top: 3px;
	}
	/* Delete-modal select reuses .md-input — kept after the T.5
	   wizard hoist; the wizard owns its own scoped copy so this
	   one survives only for the modal-field <select>. */
	.md-input {
		width: 100%;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius-sm);
		padding: 8px 10px;
		color: var(--fg);
		font-size: 13px;
		font-family: inherit;
	}

	/* Step T T.5 — right-side actions area inside the section
	   header. The container's flex gap separates it from the
	   adjacent .card-h-meta count chip; no extra margin needed. */
	.card-h-actions {
		display: inline-flex;
	}

	/* Delete-managed-domain modal */
	.modal-lead {
		color: var(--fg-muted);
		font-size: 12.5px;
		margin: 0 0 12px 0;
	}
	.modal-field {
		margin-bottom: 12px;
	}
	.modal-field label {
		display: block;
		color: var(--fg);
		font-size: 12.5px;
		font-weight: 500;
		margin-bottom: 4px;
	}
	.modal-warn {
		padding: 8px 12px;
		background: color-mix(in oklch, var(--status-warn) 10%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-warn) 30%, transparent);
		border-radius: var(--radius-sm);
		color: var(--fg);
		font-size: 12.5px;
		margin: 0;
	}
	.modal-error {
		color: var(--status-down);
		font-size: 12.5px;
		margin: 12px 0 0 0;
	}

	table {
		width: 100%;
		border-collapse: collapse;
		font-size: 12.5px;
	}
	th,
	td {
		padding: 8px 10px;
		text-align: left;
	}
	th {
		color: var(--fg-muted);
		font-weight: 500;
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		border-bottom: 1px solid var(--border);
	}
	td {
		color: var(--fg);
		border-bottom: 1px solid var(--border);
	}
	tbody tr:last-child td {
		border-bottom: none;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	.dim {
		color: var(--fg-dim);
	}

	/* Step T T.4 — Domaines table tab filter (AC #6 LOCKED).
	   Renders top-right of the card header; small pills styled
	   like text-tabs (subtle separation, accent underline on
	   active). The button reset matches the other inline
	   tablists in the app (Topology Phase 2 protocol toggles). */
	.tabs {
		margin-left: auto;
		display: inline-flex;
		gap: 4px;
	}
	.tab {
		appearance: none;
		background: transparent;
		border: 1px solid transparent;
		color: var(--fg-muted);
		font-size: 11.5px;
		font-family: inherit;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: color var(--motion-fast, 120ms), background var(--motion-fast, 120ms);
	}
	.tab:hover {
		color: var(--fg);
		background: var(--bg-elevated);
	}
	.tab.active {
		color: var(--fg);
		background: var(--bg-elevated);
		border-color: var(--border-default);
	}

	/* Sub-line under a primary cell (e.g. "<source> · <challenge>"
	   under DOMAINE). Smaller + dim so it doesn't compete with
	   the cell's main content. */
	.cell-sub {
		font-size: 11px;
		margin-top: 3px;
	}

	/* Cert.B (2026-06-23) — domain cell now hosts the stale-
	   failure badge alongside the hostname. flex inline-row keeps
	   the badge on the same line as the domain unless the row
	   wraps on narrow viewports. */
	.domain-cell {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-wrap: wrap;
	}
	.stale-badge {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font-size: 10.5px;
		font-weight: 500;
		font-family: var(--font-display);
		padding: 2px 8px;
		border-radius: 999px;
		color: var(--text-inverse);
		background: var(--status-down);
		border: none;
		cursor: pointer;
		white-space: nowrap;
		transition: filter 0.12s ease-out;
	}
	.stale-badge:hover {
		filter: brightness(1.1);
	}
	.stale-badge:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	/* Cert.B drill-down modal — event list. Vertical stack of
	   timeline-like cards, newest first, colored by event type
	   (red for cert_failed, green for cert_obtained). */
	.event-list {
		list-style: none;
		padding: 0;
		margin: 12px 0 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.event-item {
		padding: 10px 12px;
		border-radius: var(--radius);
		border-left: 3px solid var(--border);
		background: var(--bg-elevated);
	}
	.event-failed {
		border-left-color: var(--status-down);
	}
	.event-obtained {
		border-left-color: var(--status-up);
	}
	.event-head {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		gap: 12px;
	}
	.event-type {
		font-size: 12px;
		color: var(--text-primary);
	}
	.event-time {
		font-size: 11px;
	}
	.event-error {
		margin-top: 6px;
		font-size: 11.5px;
		color: var(--status-down);
		word-break: break-word;
	}
	.event-success {
		margin-top: 6px;
		font-size: 11.5px;
	}
	.modal-link {
		font-size: 12px;
		color: var(--accent);
		text-decoration: none;
		margin-right: auto;
	}
	.modal-link:hover {
		text-decoration: underline;
	}

	/* EXPIRE DANS column color states — amber inside the renewal
	   window, red once expired. Plain text color flip (not a
	   pill) per the mock's minimalist treatment. */
	.expiry {
		font-variant-numeric: tabular-nums;
	}
	.expiry-warn {
		color: var(--status-warn);
	}
	.expiry-down {
		color: var(--status-down);
	}

	.empty-row {
		color: var(--fg-muted);
		font-size: 12.5px;
		padding: 24px;
		text-align: center;
	}
	.empty-sub {
		margin-top: 6px;
		font-size: 11.5px;
		color: var(--fg-dim);
	}

	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 48px;
	}

	/* Task 7 — per-row certificate delete action. Narrow column,
	   right-aligned so it doesn't compete with the domain/issuer
	   cells' left-aligned reading flow. */
	.col-actions {
		width: 1%;
		white-space: nowrap;
		text-align: right;
	}
	.row-delete-btn {
		appearance: none;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--fg-muted);
		font-size: 11px;
		font-family: inherit;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
		transition: color var(--motion-fast, 120ms), background var(--motion-fast, 120ms),
			border-color var(--motion-fast, 120ms);
	}
	.row-delete-btn:hover {
		color: var(--status-down);
		border-color: var(--status-down);
		background: color-mix(in oklch, var(--status-down) 8%, transparent);
	}
	.row-delete-btn:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	/* Visually-hidden column header — the Actions column has no
	   printed label (bare icon-less button), but a screen-reader
	   user still needs a header cell name. Standard clip-based
	   visually-hidden pattern. */
	.visually-hidden {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
</style>
