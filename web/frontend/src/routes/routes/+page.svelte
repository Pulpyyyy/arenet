<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import {
		listRoutes,
		createRoute,
		secLangFromGuided,
		validateSecLang,
		updateRoute,
		deleteRoute,
		testUpstream,
		testHealthCheck,
		disableRoute,
		enableRoute,
		enterMaintenance,
		exitMaintenance
	} from '$lib/api/client';
	import { settingsApi } from '$lib/api/settings';
	import {
		errorTemplatesApi,
		SUPPORTED_ERROR_STATUS_CODES,
		type ErrorTemplate
	} from '$lib/api/error-templates';
	import { externalCertsApi } from '$lib/api/external-certs';
	import { hostMatchesSAN } from '$lib/utils/san-match';
	import { pathRuleContentChecks, sanitizePathRules } from '$lib/utils/path-rules';
	import { manualCertDisplayName } from '$lib/utils/manual-cert-name';
	import { gateApplies } from '$lib/utils/route-gates';
	import type {
		SecLangError,
		WafCustomRule,
		WafTargetedExclusion,
		ACMEChallenge,
		CountryBlockRequest,
		ExternalCertificate,
		ForwardAuthProvider,
		HealthCheck,
		IPFilter,
		LBPolicy,
		MaintenanceConfig,
		ManagedDomain,
		PathRule,
		Route,
		RouteCheck,
		RouteRateLimit,
		RouteRequest,
		TestUpstreamResponse,
		Upstream
	} from '$lib/api/types';
	import { countryName, matchCountries, type CountryMatch } from '$lib/data/countries';
	import { secondsToParts, partsToSeconds, type DurationUnit } from '$lib/utils/duration';
	import { ApiError, type TestHealthCheckResult, type RouteSummaryResponse } from '$lib/api/types';
	import { fetchRouteSummary } from '$lib/api/metrics';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import { pushToast } from '$lib/stores/toast';
	import { auth } from '$lib/stores/auth.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import CertSourceBadge from '$lib/components/CertSourceBadge.svelte';
	import RoutePostureChips from '$lib/components/routes/RoutePostureChips.svelte';
	import Flag from '$lib/components/Flag.svelte';
	import ContinentPicker from '$lib/components/routes/ContinentPicker.svelte';
	import CountryExceptionsPicker from '$lib/components/routes/CountryExceptionsPicker.svelte';
	import ASNPicker from '$lib/components/routes/ASNPicker.svelte';
	import GeoRuleSentence from '$lib/components/routes/GeoRuleSentence.svelte';
	import WafTargetedExclusionsEditor from '$lib/components/routes/WafTargetedExclusionsEditor.svelte';
	import WafCustomRulesEditor from '$lib/components/routes/WafCustomRulesEditor.svelte';
	import WafSecLangSection from '$lib/components/routes/WafSecLangSection.svelte';
	import RouteSection, { type Posture } from '$lib/components/routes/RouteSection.svelte';
	import ModeSelector from '$lib/components/form/ModeSelector.svelte';
	import SwitchRow from '$lib/components/form/SwitchRow.svelte';
	import PostureSentence from '$lib/components/form/PostureSentence.svelte';
	import ImportCaddyfileModal from '$lib/components/routes/ImportCaddyfileModal.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import RouteStateControl from '$lib/components/RouteStateControl.svelte';
	import IPFilterFields from '$lib/components/routes/IPFilterFields.svelte';
	import PathRulesSection from '$lib/components/routes/PathRulesSection.svelte';

	let routes = $state<Route[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	type FormMode = 'create' | 'edit';
	let formOpen = $state(false);
	let formMode = $state<FormMode>('create');
	let editingId = $state<string | null>(null);

	// --- Panel header metrics strip ---------------------------------
	// The operator's complaint about the per-route metrics was partly
	// that the drill-down was hard to find (fixed in v2.61) and partly
	// that you had to leave the panel to learn anything at all. Four
	// numbers in the header answer "is this route alive and healthy?"
	// without a navigation; the link beside them is still how you get
	// the chart.
	//
	// Fetched once per panel open, NOT polled. Arenet has just spent a
	// release removing background chatter it generated against its own
	// API, and a figure that is at most a few minutes stale is worth
	// nothing less than a live one over a 24h window.
	//
	// `null` while loading or after a failure: the strip renders
	// nothing rather than zeros. A route whose metrics could not be
	// read must never look like a route with no traffic.
	let routeSummary = $state<RouteSummaryResponse | null>(null);
	// Guards against a late response from a previously-selected route
	// landing in the panel of the current one. Compared against
	// editingId at resolve time rather than cancelling the request,
	// which would need an AbortController per open for no gain.
	let routeSummaryFor = $state<string | null>(null);

	// Mirrors histogram.MinSamplesFor(0.95) on the server, which derives
	// it rather than choosing it: Quantile takes rank ceil(0.95 * n),
	// and that rank equals n — making the "percentile" the slowest
	// request — for every n below twenty. The API already returns null
	// under this threshold; the constant is here only so the panel can
	// say WHY instead of rendering a dash.
	const MIN_QUANTILE_SAMPLES = 20;

	/** null is "not measured", which is not 0 ms — rendering zero would
	 *  read as "instant". */
	function formatMs(v: number | null): string {
		return v === null ? '—' : `${Math.round(v)} ms`;
	}

	/** Bytes at the scale an operator reads them. Deliberately decimal
	 *  (kB = 1000), matching how bandwidth and file sizes are quoted
	 *  everywhere the number will be compared against. */
	function formatBytes(n: number, locale: string): string {
		if (n < 1000) return `${n} B`;
		const units = ['kB', 'MB', 'GB', 'TB'];
		let v = n / 1000;
		let i = 0;
		while (v >= 1000 && i < units.length - 1) {
			v /= 1000;
			i++;
		}
		return `${v.toLocaleString(locale, { maximumFractionDigits: v < 10 ? 1 : 0 })} ${units[i]}`;
	}

	function clearRouteSummary() {
		routeSummary = null;
		routeSummaryFor = null;
	}

	async function loadRouteSummary(id: string) {
		clearRouteSummary();
		routeSummaryFor = id;
		try {
			const s = await fetchRouteSummary(id);
			// Panel closed or moved to another route while in flight.
			if (routeSummaryFor !== id) return;
			routeSummary = s;
		} catch {
			// Deliberately silent. The strip is supplementary; a
			// metrics read that fails must not raise a toast over a
			// form the operator is editing, and it must not render a
			// misleading zero either — so it renders nothing.
			if (routeSummaryFor === id) routeSummary = null;
		}
	}
	// v2.40 — Caddyfile import modal.
	let importOpen = $state(false);

	// v2.38 — SecLang problems returned by a refused save.
	let secLangSaveErrors = $state<SecLangError[]>([]);

	// v2.38 — "→ SecLang" on a guided rule: append its SecLang (next
	// free ID) to the route's SecLang and drop the guided rule.
	async function convertGuidedRule(index: number): Promise<void> {
		const rule = formData.wafCustomRules[index];
		if (!rule) return;
		try {
			const { nextId } = await validateSecLang(formData.wafSecLang);
			const { seclang } = await secLangFromGuided(rule, nextId);
			const current = formData.wafSecLang.trimEnd();
			formData.wafSecLang = (current === '' ? '' : current + '\n\n') + seclang;
			formData.wafCustomRules = formData.wafCustomRules.filter((_, i) => i !== index);
		} catch (err) {
			pushToast(t('wafSecLang.convertFailed', { error: err instanceof Error ? err.message : String(err) }), 'danger');
		}
	}
	let submitting = $state(false);
	let formError = $state<string | null>(null);

	// Phase 1 split layout (2026-06-02) — list filter state.
	// The search input filters on host / aliases / upstream URL /
	// redirect target; the segmented tab filters on the per-route
	// aggregateStatus.
	//
	// The comment here used to say the two non-default tabs were
	// "visual stubs" and "no-ops with a tooltip explaining the
	// deferral", with a TODO Phase 2. That stopped being true when
	// Critique 11 Pack A put aggregateStatus on the wire and
	// filteredRoutes started reading it (2026-06-05) — the tabs
	// work. The stub tooltip stayed attached to both buttons for
	// four months, telling the operator a working control was
	// unfinished. Removed in v2.59 along with its i18n key.
	type ListTab = 'all' | 'healthy' | 'alerts';
	let listFilter = $state('');
	let listTab = $state<ListTab>('all');

	// Step J.3: §5.2 default values. Source of truth on the client
	// for the four defaultable text/number placeholders + the
	// initial `method` select value. Must stay in sync with §1.3
	// decision 4 (Arenet-owned defaults) and validation.go's
	// defaultHC* constants. uri and expectStatus placeholders are
	// illustrative — not in this object — because they are not
	// server-defaultable.
	const HEALTH_CHECK_DEFAULTS = {
		method: 'GET',
		interval: '30s',
		timeout: '5s',
		passes: 1,
		fails: 1
	} as const;

	// Step J.3: minimal duration regex matching Go's
	// time.ParseDuration shape ("30s", "1m30s", "500ms", etc.).
	// Client-side pre-check; server validation is authoritative.
	const DURATION_RE = /^(\d+(?:\.\d+)?(?:ns|us|µs|μs|ms|s|m|h))+$/;

	// Step J.3: form state. The Step I.5 BasicAuth password is
	// write-only on the wire; the rest of the form is bound 1:1 to
	// the storage shape, with the J.3 additions for the upstream
	// pool, LB policy, and health check.
	//
	// `healthCheckTouched` tracks whether the user opened the
	// health-check sub-form during this edit session. When false on
	// submit, we OMIT the healthCheck key from the payload so the
	// server takes the preserve-previous path (J.2 decision: PUT
	// without healthCheck preserves the stored value). When true,
	// we ship the complete 9-field block (full replacement).
	type FormData = Omit<RouteRequest, 'healthCheck' | 'countryBlock' | 'insecureSkipVerify' | 'upstreamTlsServerName' | 'uploadStreamingMode' | 'wafDisableCRS' | 'wafExcludeRules' | 'wafExcludeTags' | 'wafTargetedExclusions' | 'wafCustomRules' | 'wafSecLang' | 'rateLimit' | 'errorPageTemplateId' | 'errorPageOverrides' | 'disabled' | 'cert_source' | 'cert_id' | 'ipFilter' | 'pathRules'> & {
		healthCheck: HealthCheck;
		// v2.14.3 — narrowed to a non-optional boolean, same
		// pattern as insecureSkipVerify/uploadStreamingMode: the
		// form always carries a definite value (default false on
		// create), and it's always shipped full-replacement on
		// both POST and PUT (no preserve-on-omit semantic needed
		// here — the operator's checkbox state is the truth).
		disabled: boolean;
		// W.5 — narrow to the non-optional shape. The form
		// always carries a CountryBlockRequest (mode="off"
		// when disabled); the wire optionality lives on
		// the RouteRequest side for callers that want
		// preserve-previous semantics.
		// v2.27 — the form always carries the optional lists.
		countryBlock: Required<CountryBlockRequest>;
		// Step #R-PROXMOX-HTTPS-LOOP — narrowed to a non-
		// optional boolean. The form always carries a
		// definite value; the on-wire optionality
		// (preserve-on-omit semantic) is reapplied at
		// payload-assembly time below.
		insecureSkipVerify: boolean;
		// v2.60 — same narrowing: the form holds a definite string
		// ('' = Caddy's default), and the wire's optional-pointer
		// semantic is reapplied at payload time.
		upstreamTlsServerName: string;
		// Phase 4.5 — same narrowing pattern as
		// insecureSkipVerify: form holds a definite bool,
		// payload re-introduces undefined for preserve-on-
		// omit semantics on PUT.
		uploadStreamingMode: boolean;
		// Step X.2 — same narrowing as uploadStreamingMode :
		// form holds a definite bool ; payload reintroduces
		// undefined for preserve-on-omit on PUT.
		wafDisableCRS: boolean;
		// Step X Option (c) — form holds a definite number[]
		// (always non-nil, empty array when no exclusions
		// configured). The on-wire optionality (nil to preserve,
		// [] to clear) is reapplied at payload assembly time.
		// Storing the array on formData rather than the raw
		// input string means the dedupe / parse logic lives in
		// one place (the change handler) and the rest of the
		// form code reads a clean typed array.
		wafExcludeRules: number[];
		// Step X Option (e) — same shape pattern as
		// wafExcludeRules. Form holds a definite string[]
		// (always non-nil, [] when no tag exclusions
		// configured). The textarea binds to a derived
		// string view (wafExcludeTagsInput) ; the parsed
		// canonical-ish list lives here for clean payload
		// assembly. Frontend doesn't apply lowercase/dedup
		// (server canonicalises on write).
		wafExcludeTags: string[];
		// v2.36 — targeted exclusions (edited by
		// WafTargetedExclusionsEditor, shipped full-replace).
		wafTargetedExclusions: WafTargetedExclusion[];
		// v2.37 — guided WAF rules (WafCustomRulesEditor), full-replace.
		wafCustomRules: WafCustomRule[];
		// v2.38 — expert SecLang (WafSecLangSection), shipped as is.
		wafSecLang: string;
		// Step Q — rate-limit holds the object when the
		// toggle is on, null when off. Distinct from the
		// wire shape's optional (undefined) because the
		// form always carries a definite "on or off" state ;
		// the payload assembler converts null → omitted +
		// object → present.
		rateLimit: RouteRateLimit | null;
		// Step R Phase 2.b — error-page wiring.
		// Empty string means "use built-in Arenet default" ;
		// non-empty is a template UUID. The wire shape uses
		// omitempty so empty string round-trips as field-
		// absent — the form holds it as definite "" for
		// reactive binding.
		errorPageTemplateId: string;
		// Per-route override sub-form. Codes absent fall
		// through to template / default layers at caddymgr
		// emit time (Phase 1 3-layer resolution). Form
		// always carries a definite Record (possibly empty) ;
		// payload assembler converts empty → undefined for
		// preserve-on-omit semantic on PUT.
		errorPageOverrides: Record<number, string>;
		// Task 9 — maintenance-mode sub-form. Always a definite
		// object (never null/undefined) so the section's inputs
		// have something to bind to regardless of whether the
		// route is currently in maintenance; the 3-state control
		// (derived separately from route.disabled/maintenanceConfig)
		// is the actual on/off switch. Full-replacement on submit,
		// same shape as the wire's MaintenanceConfig.
		maintenanceConfig: MaintenanceConfig;
		// v2.44 — the redirect state's own fields. Kept in the form
		// whatever the current state, so switching away and back does
		// not lose what was typed.
		redirectConfig: { target: string; statusCode: number; preservePath: boolean };
		// v2.19.0 external-certs SOCLE — narrowed to definite
		// strings for reactive binding. cert_source defaults to
		// 'acme' (the wire "" / "acme" default); cert_id is '' unless
		// cert_source==='manual' AND the operator has picked a cert.
		// The payload assembler drops cert_id on any non-manual source
		// (mirrors the acmeChallenge-only-under-tls discipline).
		cert_source: string;
		cert_id: string;
		// path-based-rules Task 9 — narrowed to a definite IPFilter
		// (mode defaults to 'off') so the route-level IPFilterFields
		// instance always has something to bind to, mirroring
		// countryBlock's always-present-on-the-form discipline. The
		// wire-side optionality (RouteRequest.ipFilter?) is re-applied
		// at payload-assembly time — full-replacement, no preserve-
		// on-omit ambiguity (same rationale as countryBlock).
		ipFilter: IPFilter;
		// path-based-rules Task 9 — narrowed to a definite (possibly
		// empty) array, mirrors wafExcludeRules/wafExcludeTags. The
		// PathRulesSection component always has an array to bind to;
		// full-replacement on submit.
		pathRules: PathRule[];
	};
	let formData = $state<FormData>(emptyFormData());
	// v2.19.0 external-certs SOCLE — uploaded external certs, loaded
	// lazily the first time the operator opens a form (openCreate /
	// openEdit) so the "manual" cert picker can filter them to the
	// route host. Empty until the load resolves; a failed load leaves
	// it empty (the picker then shows the no-eligible-cert warning,
	// which links to the upload surface — a graceful degrade).
	let externalCerts = $state<ExternalCertificate[]>([]);
	// Eligible = uploaded certs whose SANs cover the current host
	// (RFC 6125 single-label wildcard, case-insensitive — same rule
	// the backend re-checks). Preserves the server's notAfter-ascending
	// order (externalCertsApi.list already sorts). Pending CSR rows
	// (status === 'pending_csr') have no leaf yet — picking one would
	// create a TLS route serving no certificate (spec §6: pending rows
	// are never selectable here), so they're excluded regardless of
	// SAN coverage.
	let eligibleCerts = $derived(
		externalCerts.filter(
			(c) => c.status !== 'pending_csr' && hostMatchesSAN(formData.host.trim(), c.dnsNames ?? [])
		)
	);
	let healthCheckTouched = $state(false);

	// v2.55 — the probe's extra headers, edited as rows so the operator can
	// add and remove them; collapsed back to an object on submit. Host is
	// NOT one of these: it has its own field, and the server refuses it
	// here so there is one place to look for it.
	let healthCheckHeaderRows = $state<{ name: string; value: string }[]>([]);

	// v2.56 — run the check before saving it.
	//
	// A misconfigured check used to surface only as a post-save 503 and an
	// undone change, which protected the site and said nothing about why.
	let hcProbeRunning = $state(false);
	let hcProbeError = $state<string | null>(null);
	let hcProbeResults = $state<TestHealthCheckResult[]>([]);

	async function runHealthCheckProbe(): Promise<void> {
		hcProbeRunning = true;
		hcProbeError = null;
		hcProbeResults = [];
		try {
			const res = await testHealthCheck({
				upstreams: formData.upstreams
					.filter((u) => (u.url ?? '').trim() !== '')
					.map((u) => ({ url: u.url.trim(), weight: u.weight })),
				healthCheck: {
					...formData.healthCheck,
					hostHeader: formData.healthCheck.hostHeader?.trim() || undefined,
					headers: (() => {
						const h = headersFromRows(healthCheckHeaderRows);
						return Object.keys(h).length > 0 ? h : undefined;
					})()
				},
				routeHost: formData.host?.trim() || undefined,
				insecureSkipVerify: formData.insecureSkipVerify,
				upstreamTlsServerName: formData.upstreamTlsServerName.trim() || undefined,
				routeId: editingId ?? undefined
			});
			hcProbeResults = res.results;
		} catch (err) {
			hcProbeError = err instanceof ApiError ? err.message : t('routes.form.healthCheckProbeNetworkError');
		} finally {
			hcProbeRunning = false;
		}
	}

	/**
	 * Whether an upstream probe's status deserves the green tick.
	 *
	 * The probe reaching the upstream and the upstream answering usefully
	 * are two different facts. 2xx and 3xx mean the backend served the
	 * request; 4xx and 5xx mean it refused it, and showing that with a
	 * tick read as "all good" for a 404.
	 */
	function probeStatusOk(status: number | undefined): boolean {
		return status !== undefined && status >= 200 && status < 400;
	}

	function headerRowsFrom(headers: Record<string, string> | undefined) {
		if (!headers) return [];
		return Object.entries(headers).map(([name, value]) => ({ name, value }));
	}

	/** Collapses the rows, dropping any with an empty name. */
	function headersFromRows(rows: { name: string; value: string }[]): Record<string, string> {
		const out: Record<string, string> = {};
		for (const row of rows) {
			const name = row.name.trim();
			if (name !== '') out[name] = row.value;
		}
		return out;
	}

	function addHealthCheckHeader() {
		healthCheckHeaderRows = [...healthCheckHeaderRows, { name: '', value: '' }];
		markHealthCheckTouched();
	}

	function removeHealthCheckHeader(index: number) {
		healthCheckHeaderRows = healthCheckHeaderRows.filter((_, i) => i !== index);
		markHealthCheckTouched();
	}

	function emptyFormData(): FormData {
		return {
			host: '',
			upstreams: [{ url: '', weight: 1 }],
			lbPolicy: 'round_robin',
			tlsEnabled: false,
			redirectToHttps: false,
			// v2.14.3 — default unchecked (enabled) for new routes.
			disabled: false,
			aliases: [],
			authMode: 'none',
			basicAuth: { username: '', password: '' },
			forwardAuth: { providerName: '' },
			requestHeaders: {},
			responseHeaders: {},
			wafMode: 'detect',
			acmeChallenge: 'http-01',
			useDedicatedCert: false,
			// Step #R-PROXMOX-HTTPS-LOOP — strict default on
			// create. The disclosure that exposes this toggle
			// is itself hidden until the upstream pool uses
			// `https://`, so an operator must (1) type https://
			// in at least one upstream and (2) explicitly tick
			// the toggle to flip this true. Self-heal $effect
			// below also resets it to false on every https→http
			// scheme transition so the on-screen + storage
			// states stay aligned.
			insecureSkipVerify: false,
		upstreamTlsServerName: '',
			// Phase 4.5 — strict default. Opt-in only: the
			// toggle is visible in the WAF settings block and
			// the operator must tick it explicitly to skip
			// body inspection + Caddy buffering. Independent
			// from wafMode (any combination is valid).
			uploadStreamingMode: false,
			// Step X.2 — CRS is loaded by default. Opt-in only
			// (security-reducing) — the toggle in the WAF
			// settings block triggers the ADR-D4 confirm
			// dialog before this can flip true. Independent
			// from wafMode (any combination is valid).
			wafDisableCRS: false,
			// Step X Option (c) — empty exclusion list by
			// default. The textarea binds to a derived string
			// view via wafExcludeRulesInput ; the parsed
			// number[] lives here for type-clean payload
			// assembly. The frontend doesn't apply the server's
			// dedupe / sort policy ; we ship the raw operator
			// list, the server canonicalises on write and the
			// next GET → openEdit reload picks up the canonical
			// form.
			wafExcludeRules: [] as number[],
			// Step X Option (e) — empty tag exclusion list by
			// default ; mirrors wafExcludeRules.
			wafExcludeTags: [] as string[],
			wafTargetedExclusions: [] as WafTargetedExclusion[],
			wafCustomRules: [] as WafCustomRule[],
			wafSecLang: '',
			// Step Q — rate limit OFF by default. Toggle in
			// the form's "Limitation de débit" section flips
			// to a default-seeded RouteRateLimit on. Operator
			// keeps the toggle off for routes that don't need
			// protection (the global throttle still applies
			// system-wide).
			rateLimit: null as RouteRateLimit | null,
			// Step R Phase 2.b — error-page defaults : no
			// template attached (built-in Arenet default
			// will apply automatically on every code), no
			// per-route overrides. Operator opts in via the
			// "Pages d'erreur" section below.
			errorPageTemplateId: '',
			errorPageOverrides: {} as Record<number, string>,
			// Task 9 — maintenance defaults: no bypass IPs, a
			// 300s (5 minute) Retry-After — an operator-friendly
			// default matching a typical short maintenance window.
			// The section is inert until the operator selects
			// "Maintenance" on the 3-state control.
			maintenanceConfig: {
				retryAfterSeconds: 300,
				bypassIps: [] as string[],
				message: ''
			},
			// v2.44 — redirect defaults. 301 because a domain move is
			// permanent far more often than not, and preservePath on
			// because old.example.com/a/b should land on
			// new.example.com/a/b rather than dumping every visitor
			// on the target's home page.
			redirectConfig: {
				target: '',
				statusCode: 301,
				preservePath: true
			},
			// v2.19.0 external-certs SOCLE — default to the ACME cert
			// source (byte-equivalent to the pre-v2.19.0 "" wire
			// value). cert_id stays empty until the operator picks
			// "manual" AND selects an eligible uploaded cert.
			cert_source: 'acme',
			cert_id: '',
			// path-based-rules Task 9 — no gate by default. Mode 'off'
			// mirrors countryBlock's disabled default; the operator
			// opts in via the mode pill toggle in IPFilterFields.
			ipFilter: { mode: 'off', cidrs: [] as string[], statusCode: 0 },
			// path-based-rules Task 9 — no path rules by default.
			pathRules: [] as PathRule[],
			// W.5 — country-block defaults to disabled. The form
			// surface lives in the country-block details block
			// further down; operators opting in pick a mode +
			// type ISO 3166-1 alpha-2 codes (FR / DE / RU / ...).
			countryBlock: {
				mode: 'off' as 'off' | 'allow' | 'deny',
				countryList: [] as string[],
				continents: [] as string[],
				asns: [] as number[],
				exceptions: { countries: [] as string[], asns: [] as number[] },
				statusCode: 0
			},
			healthCheck: {
				enabled: false,
				uri: '',
				// Method is deliberately pre-set to GET (a binary
				// select offers no useful blank state — §5.3
				// contained exception). Server uppercases on the
				// way in, but we send the explicit value.
				method: HEALTH_CHECK_DEFAULTS.method,
				// Four defaultable fields stay blank on create so
				// the server materialises them and the form
				// surfaces the §1.3 values as placeholders only.
				interval: '',
				timeout: '',
				expectStatus: 0,
				expectBody: '',
				passes: 0,
				fails: 0,
				hostHeader: '',
				headers: {}
			}
		};
	}

	// Step I.5: tracked separately from formData because it reflects
	// the SERVER state (does a hash exist on the route being edited),
	// not the form's write-only password input.
	let basicAuthPasswordSet = $state(false);

	// Step I.6 — header repeater state. Tuples here, converted to
	// Record<string,string> at submit (see tuplesToRecord).
	let requestHeaderRows = $state<Array<[string, string]>>([]);
	let responseHeaderRows = $state<Array<[string, string]>>([]);

	function addRequestHeader() {
		requestHeaderRows = [...requestHeaderRows, ['', '']];
	}
	function removeRequestHeader(i: number) {
		requestHeaderRows = requestHeaderRows.filter((_, idx) => idx !== i);
	}
	function addResponseHeader() {
		responseHeaderRows = [...responseHeaderRows, ['', '']];
	}
	function removeResponseHeader(i: number) {
		responseHeaderRows = responseHeaderRows.filter((_, idx) => idx !== i);
	}

	function tuplesToRecord(rows: Array<[string, string]>): Record<string, string> {
		const out: Record<string, string> = {};
		for (const [k, v] of rows) {
			const key = k.trim();
			if (key === '') continue;
			out[key] = v;
		}
		return out;
	}

	function recordToTuples(rec: Record<string, string>): Array<[string, string]> {
		return Object.entries(rec ?? {});
	}

	// Step J.3: upstream pool repeater helpers.
	function addUpstream() {
		formData.upstreams = [...formData.upstreams, { url: '', weight: 1 }];
	}
	function removeUpstream(i: number) {
		// Server enforces "at least one upstream"; we mirror it on
		// the client by disabling the remove button on the last row
		// (see markup below). Defensive: refuse to remove the last
		// row if we are ever called with len == 1.
		if (formData.upstreams.length <= 1) return;
		formData.upstreams = formData.upstreams.filter((_, idx) => idx !== i);
		// Step #R-PROXMOX-HTTPS-LOOP commit 3 — drop the
		// matching test-state entry so the chip doesn't
		// orphan a now-removed row's result. Indices shift
		// after the splice; rebuild the map cleanly.
		const shifted: Record<number, UpstreamTestState> = {};
		for (const [k, v] of Object.entries(upstreamTests)) {
			const idx = Number(k);
			if (idx < i) shifted[idx] = v;
			else if (idx > i) shifted[idx - 1] = v;
		}
		upstreamTests = shifted;
	}

	// Step #R-PROXMOX-HTTPS-LOOP commit 3 — per-row probe
	// state. Indexed by upstream-row index (0-based). The
	// shape mirrors a state machine:
	//   undefined → never tested (chip hidden)
	//   { running: true }                  → spinner
	//   { running: false, result, error? } → outcome chip
	//
	// Cleared on form close (closePanel) so a stale result
	// from a previous edit doesn't bleed into the next.
	type UpstreamTestState =
		| { running: true }
		| { running: false; result?: TestUpstreamResponse; error?: string };
	let upstreamTests = $state<Record<number, UpstreamTestState>>({});

	async function runUpstreamTest(i: number) {
		const url = formData.upstreams[i]?.url?.trim() ?? '';
		if (url === '') return;
		upstreamTests = { ...upstreamTests, [i]: { running: true } };
		try {
			const result = await testUpstream({
				url,
				// Mirror the route-level toggle ONLY when the
				// pool is https — on http pools the backend
				// would self-heal anyway, and sending true on
				// an http URL would be a misleading user
				// signal. Storage-layer alignment with the
				// route's saved posture.
				insecureSkipVerify:
					poolScheme === 'https' ? formData.insecureSkipVerify : false,
				upstreamTlsServerName:
					poolScheme === 'https' ? formData.upstreamTlsServerName.trim() : undefined,
				// v2.55 — probe with the Host a visitor sends, not the
				// upstream's address. Behind a backend that routes on Host
				// the old probe got a 404 for a service that serves this
				// route perfectly. Same resolution as the health check:
				// the check's override if set, otherwise the route's host.
				hostHeader:
					formData.healthCheck.hostHeader?.trim() || formData.host?.trim() || undefined,
				// v2.56.2 — so the audit row carries the route it was launched
				// from, not just the address. Absent in create mode: there is
				// no route yet, and an empty string would read as one.
				routeId: editingId ?? undefined
			});
			upstreamTests = {
				...upstreamTests,
				[i]: { running: false, result }
			};
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			upstreamTests = {
				...upstreamTests,
				[i]: { running: false, error: msg }
			};
		}
	}

	// "Tester tous" — parallelise pool > 1 via Promise.all
	// so the operator sees every chip update concurrently
	// (wall-clock bounded by the slowest dial). Skips empty
	// URL rows (no probe to run).
	async function runAllUpstreamTests() {
		const targets: number[] = [];
		formData.upstreams.forEach((u, i) => {
			if (u.url.trim() !== '') targets.push(i);
		});
		if (targets.length === 0) return;
		await Promise.all(targets.map((i) => runUpstreamTest(i)));
	}

	let confirmTarget = $state<Route | null>(null);
	let deleting = $state(false);

	// Step X.2 — confirm dialog state for the security-reducing
	// wafDisableCRS toggle (ADR D4). Opened ONLY when the operator
	// flips the toggle from false → true ; the reverse flip
	// (re-enabling CRS) is always safe so it bypasses the dialog.
	let confirmDisableCRSOpen = $state(false);

	// v2.14.3 — row-level disable/enable toggle.
	//
	// Disable gates behind a ConfirmDialog (destructive: stops
	// traffic to the route). Enable is a direct call — re-enabling
	// is always safe, mirrors the wafDisableCRS "reverse flip
	// bypasses the dialog" precedent above.
	//
	// The "last active HTTPS route" warning: the disableRoute
	// response carries `lastHttpsRouteAffected` but that's only
	// known AFTER the call — too late to pick which confirm COPY
	// to show before the operator commits. So we compute the same
	// invariant PRE-call on the client from the currently-loaded
	// route list: if exactly one route has tlsEnabled && !disabled
	// and it's the row being disabled, showing the special
	// last-HTTPS confirm copy is the correct prediction (matches
	// the backend's HasHTTPSServer gate — see caddymgr).
	let disableTarget = $state<Route | null>(null);
	let disableIsLastHttps = $state(false);
	let disablingRoute = $state(false);

	function isLastActiveHTTPSRoute(r: Route): boolean {
		if (!r.tlsEnabled) return false;
		const activeHTTPSCount = routes.filter((x) => x.tlsEnabled && !x.disabled).length;
		return activeHTTPSCount === 1;
	}

	function openDisableConfirm(r: Route) {
		disableTarget = r;
		disableIsLastHttps = isLastActiveHTTPSRoute(r);
	}

	async function confirmDisableRoute() {
		if (!disableTarget) return;
		disablingRoute = true;
		try {
			await disableRoute(disableTarget.id);
			// No dedicated "toasts.disabled" i18n key exists (out of
			// this task's key set); the confirm dialog's own action
			// label already told the operator what just happened, so
			// reuse the disabled badge label for the toast text.
			pushToast(t('routes.disabled.badge'), 'success');
			disableTarget = null;
			await loadRoutes();
		} catch (err) {
			if (isConnectionLost(err)) {
				disableTarget = null;
				await reportConnectionLost();
			} else {
				const msg = err instanceof ApiError ? err.message : String(err);
				pushToast(msg, 'danger');
			}
		} finally {
			disablingRoute = false;
		}
	}

	// v2.35.1 — the browser's connection can die DURING a route
	// change when the UI is reached through Arenet over HTTP/3: Caddy
	// closes every open HTTP/3 connection on reload. The server still
	// finished the change (and its check / rollback), so reload the
	// list and say so instead of showing a raw network error.
	function isConnectionLost(err: unknown): boolean {
		return err instanceof ApiError && err.status === 0 && err.message.startsWith('network error');
	}
	async function reportConnectionLost(): Promise<void> {
		pushToast(t('routes.toasts.connectionLost'), 'info', ROUTE_CHECK_TOAST_MS);
		await loadRoutes();
	}

	// v2.35 — post-apply check feedback: a route saved but not
	// answering stays on screen long enough to be read.
	const ROUTE_CHECK_TOAST_MS = 12_000;
	function reportRouteCheck(check: RouteCheck | undefined): void {
		if (!check) return;
		if (check.status === 'failed') {
			pushToast(
				t('routes.check.failed', { host: check.host ?? '', detail: check.detail ?? '' }),
				'danger',
				ROUTE_CHECK_TOAST_MS
			);
		} else if (check.status === 'pending_certificate') {
			pushToast(t('routes.check.pendingCertificate', { host: check.host ?? '' }), 'info', ROUTE_CHECK_TOAST_MS);
		}
	}

	async function handleEnableRoute(r: Route) {
		try {
			const res = await enableRoute(r.id);
			pushToast(t('routes.enable.action'), 'success');
			reportRouteCheck(res.check);
			await loadRoutes();
		} catch (err) {
			if (isConnectionLost(err)) {
				await reportConnectionLost();
			} else {
				const msg = err instanceof ApiError ? err.message : String(err);
				pushToast(msg, 'danger');
			}
		}
	}

	// Task 9 — 3-state control wiring.
	//
	// Derives the RouteStateControl value from the two independent
	// wire fields: `disabled` (v2.14.3) and `maintenanceConfig`
	// (Task 8). `disabled` takes precedence if a route somehow
	// carries both (shouldn't happen via this UI, since the 3
	// states are mutually exclusive on the control, but a future
	// API caller could set both — disabled wins because it's the
	// stronger "serves no traffic at all" state).
	function routeState(r: Route): 'active' | 'maintenance' | 'redirect' | 'disabled' {
		if (r.disabled) return 'disabled';
		if (r.maintenanceConfig) return 'maintenance';
		// v2.44 — a redirecting route serves no upstream either; it is
		// the fourth exclusive state, after disabled in precedence for
		// the same reason maintenance is: disabled serves nothing at
		// all, which is stronger than serving a redirect.
		if (r.redirectConfig) return 'redirect';
		return 'active';
	}

	// The three states the row control can actually switch between.
	// Only called on a route that is not redirecting — the template
	// branches before this — so the fallback never fires in practice.
	function rowState(r: Route): 'active' | 'maintenance' | 'disabled' {
		const s = routeState(r);
		return s === 'redirect' ? 'active' : s;
	}

	async function handleEnterMaintenance(r: Route) {
		try {
			await enterMaintenance(r.id);
			pushToast(t('routes.state.maintenance'), 'success');
			await loadRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(msg, 'danger');
		}
	}

	async function handleExitMaintenance(r: Route) {
		try {
			await exitMaintenance(r.id);
			pushToast(t('routes.state.active'), 'success');
			await loadRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(msg, 'danger');
		}
	}

	// Task 9 — RouteStateControl onchange router. Maps the 3-state
	// control's target value + the route's CURRENT derived state to
	// the right endpoint:
	//   → 'disabled'                    : disableRoute (gated behind
	//                                     the existing ConfirmDialog
	//                                     — see openDisableConfirm;
	//                                     the last-HTTPS warning is
	//                                     wired ONLY to this branch)
	//   → 'maintenance'                 : enterMaintenance (direct,
	//                                     no confirm — a maintenance
	//                                     route keeps :443 alive, so
	//                                     the last-HTTPS invariant
	//                                     the disable warning guards
	//                                     against doesn't apply)
	//   → 'active', from 'disabled'     : enableRoute (direct, always
	//                                     safe — mirrors the pre-
	//                                     existing enable semantics)
	//   → 'active', from 'maintenance'  : exitMaintenance (direct)
	function onRouteStateChange(r: Route, next: 'active' | 'maintenance' | 'disabled') {
		const current = routeState(r);
		if (next === 'disabled') {
			openDisableConfirm(r);
			return;
		}
		if (next === 'maintenance') {
			void handleEnterMaintenance(r);
			return;
		}
		// next === 'active'
		if (current === 'disabled') {
			void handleEnableRoute(r);
		} else if (current === 'maintenance') {
			void handleExitMaintenance(r);
		}
	}


	// Step J.3: errors map keyed by formData field path. Replaces
	// the per-field $state<string> pattern from Step I (hostError,
	// upstreamError) — that pattern doesn't scale to the ~13 new
	// J.1/J.2 fields. formError remains as a top-of-form banner
	// for non-field-attributable messages.
	let errors = $state<Record<string, string>>({});

	function resetFormErrors() {
		formError = null;
		errors = {};
	}

	// Phase 1 split layout — close/cancel the right panel and
	// return to the empty state. Used by the "Cancel" button in
	// the panel footer. The route stays in the list; only the
	// selection + form state are dropped.
	// Step X.2 — change handler for the wafDisableCRS checkbox.
	// The checkbox is BOUND to formData.wafDisableCRS via the
	// `checked` prop (one-way), and `onchange` is mediated here so
	// the false → true transition can be guarded behind the
	// ADR-D4 confirm dialog without losing the operator's click.
	//
	// Logic :
	//   - intent true (operator just ticked the box) while
	//     formData.wafDisableCRS is still false : open the
	//     dialog. We DO NOT mutate ev.target.checked manually —
	//     instead we leave formData unchanged ; Svelte's next
	//     render pass synchronises ev.target.checked back to the
	//     formData value (false) automatically. The
	//     dialog's onConfirm commits the true ; cancel is a no-op
	//     by construction (formData stays false ⇒ visual stays
	//     false on next render).
	//   - intent false (operator unticked an already-checked box):
	//     flip immediately, no dialog. Re-enabling CRS is a
	//     security-improving action ; the ADR only gates the
	//     security-reducing direction.
	function onWAFDisableCRSChange(ev: Event): void {
		const target = ev.target as HTMLInputElement;
		const next = target.checked;
		if (next && !formData.wafDisableCRS) {
			// false → true requested. Roll the visual tick back
			// immediately so the checkbox shows unchecked while
			// the dialog awaits confirmation. Svelte's reactive
			// `checked={formData.wafDisableCRS}` would normally do
			// this on next render, but the browser-set property
			// can race the render in jsdom — explicit reset keeps
			// the test + the live UX deterministic.
			target.checked = false;
			confirmDisableCRSOpen = true;
			return;
		}
		formData.wafDisableCRS = next;
	}

	function onConfirmDisableCRS(): void {
		formData.wafDisableCRS = true;
		confirmDisableCRSOpen = false;
	}

	// Step Q — rate-limit toggle handler.
	// Off → on : seed with operator-meaningful defaults
	//   (60 requests / 1 minute, key {http.request.remote.host}).
	// On → off : clear formData.rateLimit to null. The submit
	//   path omits the field when null so PUT preserves the
	//   stored value — operator who wants to genuinely CLEAR
	//   a stored rate limit needs to recreate the route or
	//   use the API directly (frontend V2 backlog : explicit-
	//   null PUT support).
	function onRateLimitToggle(ev: Event): void {
		const next = (ev.target as HTMLInputElement).checked;
		if (next) {
			formData.rateLimit = {
				events: 60,
				window: '1m',
				key: '{http.request.remote.host}'
			};
		} else {
			formData.rateLimit = null;
		}
	}

	// Step X Option (c) — exclude-rules input parsing.
	//
	// The operator types a comma- / whitespace-separated list of
	// 6-digit rule IDs into the textarea. Two-way binding via a
	// derived getter/setter pair would entangle the parse with
	// the input event ; instead we keep formData.wafExcludeRules
	// as the source of truth (typed number[]) and expose a
	// derived string for the textarea's `value` binding. The
	// onchange handler parses + validates + writes back.
	//
	// Validation is mirror-of-backend : per-ID 6-digit positive
	// integer, range [200000, 999999] (the [100000, 199999]
	// Arenet-reserved range is rejected client-side too so the
	// operator gets an immediate visual signal rather than a
	// 400 round-trip surprise). Frontend errors land in
	// `errors.wafExcludeRules` ; the form-level submit guard
	// already blocks the PUT/POST when `errors` has any key.
	//
	// The textarea is GATED (disabled) when wafDisableCRS is
	// true : exclusions against a CRS that isn't loaded are a
	// no-op, surfacing the input as editable would be
	// misleading. We don't CLEAR the stored list in that case —
	// the operator may toggle CRS back on later and want the
	// exclusions to still apply.
	let wafExcludeRulesInput = $state('');

	function parseExcludeRulesInput(raw: string): { ids: number[]; error: string | null } {
		const trimmed = raw.trim();
		if (trimmed === '') return { ids: [], error: null };
		const tokens = trimmed
			.split(/[,\s]+/)
			.map((t) => t.trim())
			.filter((t) => t.length > 0);
		const ids: number[] = [];
		for (const token of tokens) {
			if (!/^\d+$/.test(token)) {
				return { ids: [], error: `"${token}" n'est pas un entier valide` };
			}
			const n = parseInt(token, 10);
			if (n < 100000 || n > 999999) {
				return { ids: [], error: `${n} n'est pas un ID CRS valide (doit être un entier 6 chiffres 100000..999999)` };
			}
			if (n <= 199999) {
				return { ids: [], error: `${n} est dans la plage réservée Arenet (100000..199999), choisissez un ID >= 200000` };
			}
			ids.push(n);
		}
		// Dedup + ascending sort to mirror the server's
		// canonical form. Cuts noise round-trips when the
		// operator re-edits.
		const unique = Array.from(new Set(ids));
		unique.sort((a, b) => a - b);
		return { ids: unique, error: null };
	}

	function onExcludeRulesInputChange(ev: Event): void {
		const raw = (ev.target as HTMLTextAreaElement).value;
		wafExcludeRulesInput = raw;
		const { ids, error } = parseExcludeRulesInput(raw);
		if (error) {
			errors = { ...errors, wafExcludeRules: error };
			// Keep the previous parsed value on formData ; the
			// submit guard blocks PUT/POST while the error is
			// surfaced, so a transient typo doesn't lose the
			// previously-valid list.
			return;
		}
		const next = { ...errors };
		delete next.wafExcludeRules;
		errors = next;
		formData.wafExcludeRules = ids;
	}

	function formatExcludeRulesInput(ids: number[]): string {
		return ids.join(', ');
	}

	// Step X Option (e) — exclude-tags input parsing.
	//
	// Operator types a comma- / whitespace-separated list of CRS
	// tags into the textarea backed by an HTML5 <datalist> for
	// autocomplete-lite. formData.wafExcludeTags holds the typed
	// string[]; wafExcludeTagsInput is the textarea projection.
	// Mirrors the wafExcludeRules pipeline.
	//
	// Frontend validation rejects characters that would smuggle
	// ctl: actions into the SecAction directive line (comma,
	// whitespace, double-quote — same as the backend
	// normalizeExcludeTags). Length cap + count cap mirror the
	// server-side limits so the operator gets immediate feedback
	// rather than a 400 round-trip surprise.
	let wafExcludeTagsInput = $state('');

	const WAF_EXCLUDE_TAG_MAX_LEN = 128;
	const WAF_EXCLUDE_TAGS_MAX_COUNT = 64;

	// Curated CRS v4 tag catalog (24 entries). Extracted
	// empirically from the embedded coraza-coreruleset v4.25.0
	// — these are the high-traffic / operator-relevant tags
	// most likely to surface false positives on real workloads.
	// CRS v4 dropped OWASP_TOP_10 + PCI tags (present in v3) so
	// they're intentionally absent from this list. Hardcoded
	// because the CRS is embedded at binary build time → the
	// catalog is static cross-build ; no need for an API
	// endpoint that just serves a constant string array.
	const CRS_TAG_CATALOG: readonly string[] = [
		'attack-disclosure',
		'attack-fixation',
		'attack-generic',
		'attack-injection-generic',
		'attack-injection-java',
		'attack-injection-php',
		'attack-injection-sqli',
		'attack-injection-xss',
		'attack-lfi',
		'attack-protocol',
		'attack-rce',
		'attack-reputation-crawler',
		'attack-reputation-scanner',
		'attack-rfi',
		'attack-session-fixation',
		'language-java',
		'language-multi',
		'language-php',
		'paranoia-level/1',
		'paranoia-level/2',
		'paranoia-level/3',
		'paranoia-level/4',
		'platform-multi',
		'platform-unix'
	] as const;

	function parseExcludeTagsInput(raw: string): { tags: string[]; error: string | null } {
		const trimmed = raw.trim();
		if (trimmed === '') return { tags: [], error: null };
		const tokens = trimmed
			.split(/[,\n]+/)
			.map((t) => t.trim())
			.filter((t) => t.length > 0);
		if (tokens.length > WAF_EXCLUDE_TAGS_MAX_COUNT) {
			return {
				tags: [],
				error: `Trop de tags (${tokens.length}) — max ${WAF_EXCLUDE_TAGS_MAX_COUNT}`
			};
		}
		const seen = new Set<string>();
		const tags: string[] = [];
		for (const token of tokens) {
			if (token.length > WAF_EXCLUDE_TAG_MAX_LEN) {
				return {
					tags: [],
					error: `"${token.slice(0, 24)}…" dépasse ${WAF_EXCLUDE_TAG_MAX_LEN} caractères`
				};
			}
			// Mirror backend normalizeExcludeTags rejection of
			// characters that would smuggle a second ctl: action
			// into the SecAction directive line. Whitespace
			// (other than the comma/newline separators already
			// split above) inside a tag, double-quote, and stray
			// commas are all caught.
			if (/[\s,"]/.test(token)) {
				return {
					tags: [],
					error: `"${token}" contient un caractère invalide pour SecAction (espace, virgule ou guillemet)`
				};
			}
			const lower = token.toLowerCase();
			if (seen.has(lower)) continue;
			seen.add(lower);
			tags.push(lower);
		}
		tags.sort();
		return { tags, error: null };
	}

	function onExcludeTagsInputChange(ev: Event): void {
		const raw = (ev.target as HTMLTextAreaElement).value;
		wafExcludeTagsInput = raw;
		const { tags, error } = parseExcludeTagsInput(raw);
		if (error) {
			errors = { ...errors, wafExcludeTags: error };
			return;
		}
		const next = { ...errors };
		delete next.wafExcludeTags;
		errors = next;
		formData.wafExcludeTags = tags;
	}

	function formatExcludeTagsInput(tags: string[]): string {
		return tags.join(', ');
	}

	function closePanel() {
		formOpen = false;
		formSnapshot = '';
		formMode = 'create';
		editingId = null;
		clearRouteSummary();
		formError = null;
		errors = {};
		// Step #R-PROXMOX-HTTPS-LOOP commit 3 — clear per-row
		// probe state so a stale result from a previous edit
		// session doesn't bleed into the next form open.
		upstreamTests = {};
		syncEditParam(null);
	}

	// DOM refs for the click-outside action (C11 Pack A polish
	// round 3, 2026-06-06). panelEl bounds the inspector; tableEl
	// bounds the routes table — clicks inside either are ignored
	// by the outside-close logic. Clicks inside the table are
	// handled by the per-row onclick (which calls
	// selectOrToggleRoute), so the outside-close handler doesn't
	// fight with row-targeted interactions.
	let panelEl = $state<HTMLDivElement | null>(null);
	let tableEl = $state<HTMLTableElement | null>(null);

	// W.7 — country-block autocomplete state. The input
	// value is held locally (not bound to formData) so the
	// dropdown can preview matches without polluting the
	// committed country list until the operator picks an
	// entry. activeIndex drives keyboard navigation (Arrow
	// Up/Down + Enter). cbInputEl is the focus target for
	// the "+ Ajouter un pays" CTA below.
	let cbInputValue = $state('');
	let cbDropdownOpen = $state(false);
	let cbActiveIndex = $state(0);
	let cbInputEl = $state<HTMLInputElement | null>(null);

	// W.7 follow-up — the section's open/closed state is
	// tracked SEPARATELY from formData.countryBlock.mode.
	// The W.7 polish initially tied <details open={...}>
	// to (mode !== 'off'), which made the section collapse
	// out of view the instant the operator clicked
	// "Désactivé" — they made a deliberate choice and lost
	// the UI confirmation of it. The fix: cbSectionOpen
	// holds the operator's open/close intent (toggled via
	// the summary click); mode flips never touch it.
	//
	// Auto-open shorthand: when the operator picks Allow
	// or Deny from a closed section, force-open it so the
	// newly-revealed input + chip list aren't hidden
	// behind a collapsed details. Going off → on is a
	// deliberate "I want to configure this" signal; going
	// on → off is "I want this off but I'm still looking
	// at the section to confirm". Both should keep the
	// section visible.
	let cbSectionOpen = $state(false);

	// Pick mode + force-open helper bundled together so
	// every mode button calls the same code path. Used by
	// both the 3-button toggle and any future shortcut
	// affordance.
	function cbPickMode(next: 'off' | 'allow' | 'deny'): void {
		formData.countryBlock.mode = next;
		cbSectionOpen = true;
	}

	// Derived autocomplete matches, excluding codes already
	// in the chip list (no point re-suggesting a code that
	// is already added). Empty when the input is empty AND
	// the dropdown isn't explicitly open (clicking the CTA
	// opens it without text — surfaces the first 8 codes
	// alphabetically for "I don't know what I want" browsing).
	const cbSuggestions = $derived<CountryMatch[]>(
		cbDropdownOpen
			? matchCountries(cbInputValue, formData.countryBlock.countryList)
			: []
	);

	// W.7 — counter label tied to mode. The brief asked
	// for "{N} pays {bloqué(s)|autorisé(s)}" matching the
	// active mode; the singular/plural pluralization
	// matches French agreement.
	const cbCounterLabel = $derived.by(() => {
		const n = formData.countryBlock.countryList.length;
		if (n === 0) return '';
		const key =
			formData.countryBlock.mode === 'allow'
				? 'routes.form.geoCountryCounterAllow'
				: formData.countryBlock.mode === 'deny'
					? 'routes.form.geoCountryCounterDeny'
					: 'routes.form.geoCountryCounter';
		return (language.current && t(key, { count: n })) || '';
	});

	// v2.27 — section-title summary per rule type, e.g.
	// "2 continent(s), 1 country(ies), 1 exception(s)". Empty
	// lists are omitted; exceptions count only in deny mode.
	const geoSummary = $derived.by(() => {
		const cb = formData.countryBlock;
		const parts: string[] = [];
		if (cb.continents.length > 0)
			parts.push(t('routes.form.geoSummaryContinents', { count: cb.continents.length }));
		parts.push(t('routes.form.geoSummaryCountries', { count: cb.countryList.length }));
		if (cb.asns.length > 0) parts.push(t('routes.form.geoSummaryASNs', { count: cb.asns.length }));
		const nExc = cb.exceptions.countries.length + cb.exceptions.asns.length;
		if (cb.mode === 'deny' && nExc > 0)
			parts.push(t('routes.form.geoSummaryExceptions', { count: nExc }));
		return (language.current && parts.join(', ')) || parts.join(', ');
	});

	// W.7 — add a country code to the list if not already
	// present + close the dropdown. Shared by the keyboard
	// Enter handler, the click-on-suggestion handler, and
	// the CTA button's quick-add path. Trim + uppercase
	// applied at the boundary so the chip list is always
	// canonical.
	function cbAddCode(rawCode: string): void {
		const code = rawCode.trim().toUpperCase();
		if (!/^[A-Z]{2}$/.test(code)) return;
		if (formData.countryBlock.countryList.includes(code)) {
			cbInputValue = '';
			return;
		}
		formData.countryBlock.countryList = [
			...formData.countryBlock.countryList,
			code
		];
		cbInputValue = '';
		cbActiveIndex = 0;
		cbDropdownOpen = false;
	}

	function cbRemoveCode(code: string): void {
		formData.countryBlock.countryList =
			formData.countryBlock.countryList.filter((c) => c !== code);
	}

	function cbOpenDropdown(): void {
		cbDropdownOpen = true;
		cbActiveIndex = 0;
		// requestAnimationFrame is the canonical way to focus
		// after Svelte reactive paint; the input may have just
		// been rendered if the mode toggle revealed the field.
		requestAnimationFrame(() => cbInputEl?.focus());
	}

	function cbInputKeydown(e: KeyboardEvent): void {
		// Operator may pick from the dropdown OR type the
		// 2-char code raw + Enter. Both paths must add the
		// code; the dropdown takes precedence (the operator's
		// arrow-selected match) so an ambiguous "FR" → Enter
		// with the dropdown active selects the highlighted
		// suggestion.
		if (e.key === 'Enter') {
			e.preventDefault();
			if (cbDropdownOpen && cbSuggestions.length > 0) {
				cbAddCode(cbSuggestions[cbActiveIndex]?.code ?? cbInputValue);
			} else {
				cbAddCode(cbInputValue);
			}
			return;
		}
		if (e.key === ',') {
			// Comma is the secondary delimiter so an operator
			// pasting "FR,DE,RU" can chain entries quickly. We
			// add the buffer + clear; the next paste segment
			// re-triggers the dropdown for visual confirmation.
			e.preventDefault();
			cbAddCode(cbInputValue);
			return;
		}
		if (e.key === 'Escape') {
			cbDropdownOpen = false;
			return;
		}
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			if (cbSuggestions.length === 0) return;
			cbActiveIndex = (cbActiveIndex + 1) % cbSuggestions.length;
			return;
		}
		if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (cbSuggestions.length === 0) return;
			cbActiveIndex =
				(cbActiveIndex - 1 + cbSuggestions.length) % cbSuggestions.length;
			return;
		}
	}

	function cbInputOnInput(e: Event): void {
		cbInputValue = (e.currentTarget as HTMLInputElement).value;
		cbDropdownOpen = true;
		cbActiveIndex = 0;
	}

	// Svelte action: bind to the panel root, listens on document
	// mousedown for the lifetime of the node, calls closePanel
	// when the event target is outside BOTH the panel and the
	// table. mousedown (not click) so the listener wins the race
	// against any same-target click handlers — and because
	// mousedown more naturally maps to "dismiss the inspector"
	// (matches macOS list inspectors).
	function clickOutsideToClose(node: HTMLElement) {
		function handle(event: MouseEvent) {
			if (!formOpen) return;
			// Step X.2 — when a child confirm dialog (ConfirmDialog
			// for the wafDisableCRS toggle) is open, clicks on
			// its buttons land OUTSIDE the form panel (the dialog
			// is portalled to body via <Modal>) and would
			// otherwise trigger closePanel here, unmounting the
			// route form while the operator is still interacting
			// with the dialog. Suppressing the outside-close while
			// any guarded dialog is open keeps the form alive
			// across the dialog round-trip. Same guard the wider
			// Modal pattern would benefit from if more dialogs
			// are wired in the future.
			if (confirmDisableCRSOpen) return;
			// v2.41 — same reasoning for the discard confirm: it is
			// portalled to body, so its own buttons are "outside".
			if (confirmDiscardOpen) return;
			const target = event.target;
			if (!(target instanceof Node)) return;
			if (node.contains(target)) return;
			if (tableEl?.contains(target)) return;
			guardUnsaved(closePanel);
		}
		document.addEventListener('mousedown', handle, true);
		return {
			destroy() {
				document.removeEventListener('mousedown', handle, true);
			},
		};
	}

	function openCreate() {
		secLangSaveErrors = [];
		formMode = 'create';
		editingId = null;
		clearRouteSummary();
		formData = emptyFormData();
		basicAuthPasswordSet = false;
		healthCheckTouched = false;
		healthCheckHeaderRows = [];
		requestHeaderRows = [];
		responseHeaderRows = [];
		// Step X Option (c) — clear the exclude-rules textarea
		// view alongside the formData reset. The string state
		// lives outside formData (it's a UX projection, not a
		// payload field) so it needs an explicit reset.
		wafExcludeRulesInput = '';
		// Step X Option (e) — same projection reset as rules.
		wafExcludeTagsInput = '';
		// W.7 follow-up — country-block section starts
		// closed for a fresh create form (matches the
		// healthCheck details discipline; mode=off doesn't
		// auto-expand). The operator can open it via the
		// summary click whenever they want to see the
		// three modes.
		cbSectionOpen = false;
		resetFormErrors();
		// v2.18.0 — sync the friendly Retry-After input from the
		// seeded seconds (create default is 300 → "5 minutes").
		seedRetryParts();
		stateChoice = 'active';
		formOpen = true;
		syncEditParam(null);
		// v2.61 — same reveal as selecting a route: in create mode the
		// panel is just as far down the page when the layout is stacked.
		revealPanelIfStacked();
		// v2.41 — reference point for the "unsaved changes" marker.
		snapshotForm();
		// Step J.4: refresh provider status whenever the form opens
		// so the inline hint reflects any provider changes the
		// operator may have just made in Settings.
		void loadDNSProvider();
		void loadForwardAuthProviders();
		// Step O.4: refresh managed-domains too — operator may
		// have just declared a new apex; the form's contextual
		// inheritance badge needs the up-to-date list.
		void loadManagedDomainsForRoutes();
		// v2.19.0 external-certs SOCLE — load the uploaded certs so
		// the "manual" cert picker is ready the moment the operator
		// selects that source.
		void loadExternalCerts();
	}

	// Row click semantics (C11 Pack A polish round 3, 2026-06-06):
	// clicking the already-selected row toggles the panel closed —
	// macOS-Finder-list behaviour. Clicking any other row (or the
	// same row when nothing is selected) opens the edit panel
	// against it via openEdit. The keyboard Enter/Space path uses
	// the same helper so the toggle is reachable without a mouse.
	function selectOrToggleRoute(r: Route) {
		guardUnsaved(() => {
			if (editingId === r.id && formOpen) {
				closePanel();
				return;
			}
			openEdit(r);
			revealPanelIfStacked();
		});
	}

	// v2.61 — below the `split` breakpoint the edit panel is not beside
	// the list, it is stacked UNDERNEATH the whole table (see the
	// .split grid: single column until 1280px). On a laptop window
	// that is not maximised, clicking a route appeared to do nothing —
	// the panel had opened, several screens down, past every other
	// route. That is most of what "on ne voit pas comment y arriver"
	// was about, and no amount of button styling would have fixed it.
	//
	// matchMedia rather than innerWidth so the query and the CSS can
	// never drift apart on a resize.
	function revealPanelIfStacked(): void {
		if (typeof window === 'undefined' || !window.matchMedia) return;
		if (!window.matchMedia('(max-width: 1279px)').matches) return;
		// After the panel has actually rendered, not before. panelEl is
		// already bound for the click-outside handler, so there is no
		// reason to go through the DOM by selector.
		queueMicrotask(() => {
			panelEl?.scrollIntoView({ behavior: 'smooth', block: 'start' });
		});
	}

	// The route being edited lives in ?edit=<id> so its form can be
	// linked to (e.g. from /security/<id>) and survives a refresh. Called
	// only from openEdit / openCreate / closePanel, the three places
	// the panel changes route. replaceState, not pushState: opening
	// rows one after another must not fill the back-button history
	// (same reasoning as the ?tab sync on /security).
	const EDIT_PARAM = 'edit';

	function syncEditParam(id: string | null): void {
		if (typeof window === 'undefined') return;
		const url = new URL(window.location.href);
		if (id === null) {
			url.searchParams.delete(EDIT_PARAM);
		} else {
			url.searchParams.set(EDIT_PARAM, id);
		}
		if (url.href === window.location.href) return;
		// Keep SvelteKit's own history entry state (its navigation
		// index lives there) rather than wiping it.
		window.history.replaceState(window.history.state, '', url);
	}

	// Deep link: open the form of the route named by ?edit=, once the
	// first list has arrived. An id that no longer exists is dropped
	// silently; if the list failed to load we cannot tell, so the
	// link is left for the next attempt.
	function openEditFromURL(): void {
		if (typeof window === 'undefined') return;
		const id = new URL(window.location.href).searchParams.get(EDIT_PARAM);
		if (id === null) return;
		const r = routes.find((x) => x.id === id);
		if (r) {
			openEdit(r);
			revealPanelIfStacked();
		} else if (loadError === null) {
			syncEditParam(null);
		}
	}

	function openEdit(r: Route) {
		secLangSaveErrors = [];
		formMode = 'edit';
		editingId = r.id;
		void loadRouteSummary(r.id);
		// Step J.3: populate the pool from the stored route as-is.
		// A one-upstream route (e.g. migrated from Step I) shows a
		// single-row repeater; multi-upstream routes show every row.
		formData = {
			host: r.host,
			upstreams: r.upstreams.map((u) => ({ url: u.url, weight: u.weight })),
			lbPolicy: r.lbPolicy,
			tlsEnabled: r.tlsEnabled,
			redirectToHttps: r.redirectToHttps,
			// v2.14.3 — load the persisted disabled flag so the
			// checkbox reflects what's actually saved. Storage
			// zero-value reads back as false/undefined.
			disabled: r.disabled ?? false,
			aliases: [...(r.aliases ?? [])],
			authMode: r.authMode,
			basicAuth: {
				username: r.basicAuth?.username ?? '',
				password: ''
			},
			forwardAuth: {
				providerName: r.forwardAuth?.providerName ?? ''
			},
			requestHeaders: { ...(r.requestHeaders ?? {}) },
			responseHeaders: { ...(r.responseHeaders ?? {}) },
			wafMode: r.wafMode,
			// W.5 — clone the stored country-block config so
			// the form can mutate locally without touching
			// the loaded route reference. The list is
			// shallow-copied (string array; no nested refs).
			countryBlock: {
				mode: r.countryBlock.mode,
				countryList: [...r.countryBlock.countryList],
				// v2.27 — `?? []`: tolerate a pre-v2.27 API.
				continents: [...(r.countryBlock.continents ?? [])],
				asns: [...(r.countryBlock.asns ?? [])],
				exceptions: {
					countries: [...(r.countryBlock.exceptions?.countries ?? [])],
					asns: [...(r.countryBlock.exceptions?.asns ?? [])]
				},
				statusCode: r.countryBlock.statusCode
			},
			// Step O: "inherited" is a server-derived value the
			// frontend never sends back. Reload it as "" (empty)
			// rather than "http-01" so the dropdown doesn't show
			// a misleading default if the operator opts out of
			// the wildcard via useDedicatedCert. The form state
			// is "no per-route challenge picked yet" — accurate
			// to what's stored.
			//
			// Per backlog #O.4-2: the onUseDedicatedCertToggle
			// handler ALSO clears acmeChallenge to "" on every
			// false → true transition, AND the Save button is
			// gated by dedicatedOptOutPendingChoice. So even if
			// a stored value sneaks through here (e.g. a covered
			// route with acmeChallenge="dns-01" in storage, which
			// shouldn't happen under D8.A but is defended against),
			// the operator must explicitly re-pick on opt-out.
			acmeChallenge:
				r.acmeChallenge === 'inherited' ? '' : r.acmeChallenge,
			useDedicatedCert: r.useDedicatedCert ?? false,
			// Step #R-PROXMOX-HTTPS-LOOP — load the persisted
			// value so the disclosure toggle reflects what the
			// route actually carries. Backend always emits a
			// definite bool (no omitempty on Route.insecure-
			// SkipVerify in the response), so the fallback to
			// false here is a safety net rather than the
			// expected path.
			insecureSkipVerify: r.insecureSkipVerify ?? false,
			upstreamTlsServerName: r.upstreamTlsServerName ?? '',
			// Phase 4.5 — load the persisted streaming-mode
			// state so the toggle on the form reflects what's
			// actually saved. The API response is non-omitempty
			// (false echoed explicitly), so the ?? false here is
			// purely defensive for very old pre-4.5 snapshots
			// that might have been restored without the field.
			uploadStreamingMode: r.uploadStreamingMode ?? false,
			// Step X.2 — load the persisted CRS-disable state
			// so the toggle reflects what's actually saved.
			// Pre-X.1 snapshots decode as undefined → defaults
			// to false (CRS loaded — byte-equivalent to the
			// pre-X.1 runtime, per ADR D2).
			wafDisableCRS: r.wafDisableCRS ?? false,
			// Step X Option (c) — load the persisted exclusion
			// list. The server normalises to ascending sort +
			// dedup on write, so what the form receives is
			// already the canonical form ; just clone it so
			// future formData mutations don't ripple back into
			// the source route object.
			wafExcludeRules: [...(r.wafExcludeRules ?? [])],
			// Step X Option (e) — load the persisted tag
			// exclusion list (server-canonicalised).
			wafExcludeTags: [...(r.wafExcludeTags ?? [])],
			wafTargetedExclusions: (r.wafTargetedExclusions ?? []).map((e) => ({ ...e })),
			wafSecLang: r.wafSecLang ?? '',
			wafCustomRules: (r.wafCustomRules ?? []).map((rule) => ({
				...rule,
				conditions: rule.conditions.map((c) => ({ ...c, values: [...(c.values ?? [])] }))
			})),
			// Step Q — load the persisted rate-limit. Clone
			// to break the formData ↔ source route reference
			// so toggling the form section doesn't ripple
			// back into the list view's Route object.
			rateLimit: r.rateLimit
				? { events: r.rateLimit.events, window: r.rateLimit.window, key: r.rateLimit.key ?? '' }
				: null,
			// Step R Phase 2.b — load persisted error-page
			// wiring. Both fields are passed through as-is ;
			// the response shape mirrors the storage shape
			// directly (camelCase via the route response
			// pass-through landed Phase 1).
			errorPageTemplateId: r.errorPageTemplateId ?? '',
			errorPageOverrides: { ...(r.errorPageOverrides ?? {}) },
			// Task 9 — seed the maintenance sub-form from the
			// loaded route. Clone bypassIps to break the formData
			// ↔ source route reference (same pattern as rateLimit
			// / errorPageOverrides above). Falls back to the
			// emptyFormData defaults when the route has never been
			// put into maintenance (r.maintenanceConfig undefined).
			maintenanceConfig: r.maintenanceConfig
				? {
						retryAfterSeconds: r.maintenanceConfig.retryAfterSeconds,
						bypassIps: [...(r.maintenanceConfig.bypassIps ?? [])],
						message: r.maintenanceConfig.message ?? ''
					}
				: { retryAfterSeconds: 300, bypassIps: [], message: '' },
			// v2.44 — seed the redirect sub-form, falling back to the
			// same defaults as a new route when this one has never
			// redirected.
			redirectConfig: r.redirectConfig
				? {
						target: r.redirectConfig.target,
						statusCode: r.redirectConfig.statusCode ?? 301,
						preservePath: r.redirectConfig.preservePath ?? false
					}
				: { target: '', statusCode: 301, preservePath: true },
			// v2.19.0 external-certs SOCLE — seed the cert source from
			// the persisted route. The backend emits "" for pre-v2.19.0
			// rows (omitempty) which we normalise to 'acme' so the
			// dropdown shows a definite selection. cert_id is only
			// meaningful under 'manual'; carry it through so an edit of
			// an unrelated field round-trips the manual reference.
			cert_source: r.cert_source && r.cert_source !== '' ? r.cert_source : 'acme',
			cert_id: r.cert_id ?? '',
			// path-based-rules Task 9 — seed the route-level IP filter
			// from the loaded route. An absent r.ipFilter (pre-Task-6
			// snapshot) falls back to a definite 'off' default so the
			// IPFilterFields instance always has something to bind to
			// (mirrors countryBlock's always-present contract). Clone
			// cidrs to break the formData ↔ source route reference.
			ipFilter: r.ipFilter
				? {
						mode: r.ipFilter.mode,
						cidrs: [...(r.ipFilter.cidrs ?? [])],
						statusCode: r.ipFilter.statusCode ?? 0
					}
				: { mode: 'off', cidrs: [], statusCode: 0 },
			// path-based-rules Task 9 — seed path rules from the loaded
			// route. Deep-clone each rule (including nested basicAuth/
			// ipFilter) so formData mutations don't ripple back into
			// the source route object. The response never echoes the
			// basic-auth password (server always blanks it — see the
			// PathRule type doc), so basicAuth.password reloads as ''
			// (the operator must re-type it to change/keep it set).
			pathRules: (r.pathRules ?? []).map((rule) => ({
				pathPrefix: rule.pathPrefix,
				basicAuth: rule.basicAuth
					? { username: rule.basicAuth.username, password: '' }
					: undefined,
				ipFilter: rule.ipFilter
					? {
							mode: rule.ipFilter.mode,
							cidrs: [...(rule.ipFilter.cidrs ?? [])],
							statusCode: rule.ipFilter.statusCode ?? 0
						}
					: { mode: 'off', cidrs: [], statusCode: 0 },
				// Task 7 (per-path upstream routing) — carry the pool /
				// LB policy / health check through on hydrate. Without
				// this, editing a route whose path-rule has its own
				// upstream pool and clicking Save would silently wipe
				// that pool (the submit payload re-sends pathRules from
				// formData, which would otherwise never have seen these
				// fields). Deep-copy upstreams/healthCheck so formData
				// mutations don't ripple back into the source route
				// object, mirroring the ipFilter.cidrs clone above.
				// Absent/empty on the source stays undefined (not an
				// empty array/object) so a pool-less rule stays
				// pool-less.
				upstreams: rule.upstreams
					? rule.upstreams.map((u) => ({ url: u.url, weight: u.weight }))
					: undefined,
				lbPolicy: rule.lbPolicy,
				healthCheck: rule.healthCheck ? { ...rule.healthCheck } : undefined,
				// v2.23.1 — carry the per-path skip-TLS-verify toggle through
				// hydration alongside upstreams/lbPolicy/healthCheck above, or
				// editing a route with an https path-pool and clicking Save
				// would silently reset it.
				insecureSkipVerify: rule.insecureSkipVerify,
				upstreamTlsServerName: rule.upstreamTlsServerName ?? '',
				// v2.45.3 — same reasoning as the pool above, which this
				// block already warns about: the submit payload re-sends
				// pathRules from formData, so a field not hydrated here
				// is wiped the next time the operator saves an unrelated
				// change on the route.
				matchExact: rule.matchExact,
				redirect: rule.redirect ? { ...rule.redirect } : undefined,
				// v2.56.3 — and the same omission caught the rate limit, in
				// the block that already warns about it twice above. A rule's
				// limit was persisted and enforced, but the form reopened with
				// the box unticked, so the next save on an unrelated field
				// shipped the rule without it and deleted the protection with
				// a green toast.
				rateLimit: rule.rateLimit ? { ...rule.rateLimit } : undefined,
				// v2.57 — and the IdP gate, for the same reason, which this
				// block now warns about three times. Hydrating it matters more
				// than the fields above: dropping it on an unrelated save does
				// not degrade the path, it unprotects it.
				forwardAuth: rule.forwardAuth ? { ...rule.forwardAuth } : undefined,
				// v2.58 — and the exemption. Of everything in this block it is
				// the one whose loss is not a lost setting but a path that
				// silently starts demanding a login again.
				disableRouteAuth: rule.disableRouteAuth
			})),
			// (subform expansion handled below — needs to fire
			// AFTER formData assignment so the $effect sees the
			// new state.)
			// Step J.2: the server's HealthCheck is always present
			// on the wire (no omitempty). The form holds it as-is;
			// edit-mode shows explicit values (server materialised
			// defaults at original create), edit-mode users see
			// populated fields with no blanks to misinterpret.
			healthCheck: {
				enabled: r.healthCheck.enabled,
				uri: r.healthCheck.uri,
				method: r.healthCheck.method || HEALTH_CHECK_DEFAULTS.method,
				interval: r.healthCheck.interval,
				timeout: r.healthCheck.timeout,
				expectStatus: r.healthCheck.expectStatus,
				expectBody: r.healthCheck.expectBody,
				passes: r.healthCheck.passes,
				fails: r.healthCheck.fails,
				hostHeader: r.healthCheck.hostHeader ?? '',
				headers: r.healthCheck.headers ?? {}
			}
		};
		healthCheckHeaderRows = headerRowsFrom(r.healthCheck.headers);
		basicAuthPasswordSet = r.basicAuth?.passwordSet ?? false;
		// Step X Option (c) — seed the textarea string view from
		// the loaded canonical list so the operator sees what's
		// stored.
		wafExcludeRulesInput = formatExcludeRulesInput(r.wafExcludeRules ?? []);
		// Step X Option (e) — same seeding for the tags textarea.
		wafExcludeTagsInput = formatExcludeTagsInput(r.wafExcludeTags ?? []);
		void loadDNSProvider();
		void loadForwardAuthProviders();
		// Step O.4: refresh managed-domains snapshot — see comment
		// on the create-form openCreate path.
		void loadManagedDomainsForRoutes();
		// v2.19.0 external-certs SOCLE — load the uploaded certs so
		// the "manual" cert picker can filter to the route host.
		void loadExternalCerts();
		// Step J.2 preserve-or-replace: the user has not touched the
		// HC sub-form yet, so a submit without further interaction
		// omits the block and triggers the preserve path. Any
		// interaction with an HC input flips this to true (see
		// markHealthCheckTouched).
		healthCheckTouched = false;
		requestHeaderRows = recordToTuples(r.requestHeaders ?? {});
		responseHeaderRows = recordToTuples(r.responseHeaders ?? {});
		// W.7 follow-up — auto-open the country-block
		// section on edit IF the route already has a mode
		// set (allow / deny). The operator opening an
		// existing gated route should see the country list
		// immediately without a second click on the summary;
		// the off-state stays collapsed to match the create-
		// form default.
		cbSectionOpen = r.countryBlock.mode !== 'off';
		// Step R Phase 2.b — auto-expand the per-route
		// overrides sub-form if the loaded route already
		// has any. The operator returning to a mid-edit
		// should see what's there immediately.
		resetFormErrors();
		// v2.18.0 — sync the friendly Retry-After input from the loaded
		// route's stored seconds (shows the largest round unit).
		seedRetryParts();
		stateChoice = routeState(r);
		formOpen = true;
		syncEditParam(r.id);
		// v2.41 — reference point for the "unsaved changes" marker.
		snapshotForm();
	}

	// Step J.2 preserve-or-replace: any user interaction with the
	// HC sub-form (the enabled checkbox or any sub-field) flips
	// healthCheckTouched to true, so the submit ships the complete
	// block. Without this, a PUT would omit `healthCheck` even
	// though the user intentionally changed something. The on:*
	// handlers in the markup call this.
	function markHealthCheckTouched() {
		healthCheckTouched = true;
	}

	function addAlias() {
		formData.aliases = [...formData.aliases, ''];
	}
	function removeAlias(i: number) {
		formData.aliases = formData.aliases.filter((_, idx) => idx !== i);
	}

	// Task 9 — maintenance bypass-IP repeater. Mirrors the alias
	// repeater above: an ordinary string[] with add/remove rows;
	// blank rows are dropped at submit time (see submitForm's
	// payload assembly), not here, so an operator mid-typing a
	// CIDR doesn't lose the row on every keystroke re-render.
	function addBypassIp() {
		formData.maintenanceConfig.bypassIps = [...formData.maintenanceConfig.bypassIps, ''];
	}
	function removeBypassIp(i: number) {
		formData.maintenanceConfig.bypassIps = formData.maintenanceConfig.bypassIps.filter(
			(_, idx) => idx !== i
		);
	}

	// v2.18.0 — friendly Retry-After input. formData holds the wire
	// value (retryAfterSeconds); these two drive the UI (a number +
	// unit selector). Seeded from the seconds whenever the form opens
	// (seedRetryParts, called from openCreate/openEdit), then any edit
	// to either recomputes retryAfterSeconds. The wire value stays in
	// seconds — nothing about storage or the Retry-After header changes.
	let retryValue = $state(5);
	let retryUnit = $state<DurationUnit>('minutes');

	// Order for the unit <select>, aligned with i18n option keys.
	const RETRY_UNITS: DurationUnit[] = ['seconds', 'minutes', 'hours', 'days'];

	function seedRetryParts() {
		const parts = secondsToParts(formData.maintenanceConfig.retryAfterSeconds);
		retryValue = parts.value;
		retryUnit = parts.unit;
	}

	// Recompute the wire seconds from the current (value, unit) pair.
	// Called on both the number input and the unit selector change.
	function syncRetryAfterSeconds() {
		formData.maintenanceConfig.retryAfterSeconds = partsToSeconds(retryValue, retryUnit);
	}

	// Step I.7 hotfix (Finding #5): TLS off ⇒ no HTTP→HTTPS redirect.
	$effect(() => {
		if (!formData.tlsEnabled && formData.redirectToHttps) {
			formData.redirectToHttps = false;
		}
	});

	// Step J.4: DNS provider status (snapshot loaded on mount and
	// re-fetched whenever we open the form). The Routes page uses
	// this for three things:
	//   (1) the inline hint in the ACME challenge selector when the
	//       user picks "dns-01" without a configured provider;
	//   (2) the form-level disabled state on "dns-01" — keeps the
	//       backend's edit-time 400 from being the only signal;
	//   (3) the page-level (β) bandeau when any persisted route
	//       carries acmeChallenge="dns-01" while the provider is
	//       missing / incomplete (provider deleted AFTER routes
	//       were saved).
	// v2.12 — the Routes page only needs "is any DNS provider
	// configured" (the DNS-01 selector hint + the (β) bandeau gate),
	// not the full provider config. Collapse to a boolean fed by the
	// multi-config collection endpoint.
	let dnsProviderConfigured = $state(false);

	async function loadDNSProvider() {
		try {
			const list = await settingsApi.listDNSProviders();
			dnsProviderConfigured = list.some((p) => p.configured);
		} catch {
			dnsProviderConfigured = false;
		}
	}

	// v2.19.0 external-certs SOCLE — refresh the uploaded external-cert
	// snapshot whenever the form opens, so the "manual" cert picker
	// sees any cert the operator may have just uploaded on /certs. A
	// failed load degrades to an empty list (the picker then surfaces
	// the no-eligible-cert warning + upload link rather than blowing up
	// the form).
	async function loadExternalCerts() {
		try {
			externalCerts = await externalCertsApi.list();
		} catch {
			externalCerts = [];
		}
	}

	// Step K.1: forward-auth providers snapshot, loaded on mount
	// and on form open. Drives the per-route forward_auth selector
	// (options = configured providers) and the inline hint when
	// the user picks forward_auth but no provider is configured.
	let forwardAuthProviders = $state<ForwardAuthProvider[]>([]);

	async function loadForwardAuthProviders() {
		try {
			forwardAuthProviders = await settingsApi.listForwardAuthProviders();
		} catch (_err) {
			forwardAuthProviders = [];
		}
	}

	// Step O.4 — managed-domains snapshot, loaded on mount + on
	// form open (same cadence as the DNS provider snapshot). Used
	// to drive (a) the route-list `effectiveCertSource` badge
	// already populated server-side and (b) the form's contextual
	// "host is covered by *.<apex>" hint + useDedicatedCert toggle.
	let managedDomains = $state<ManagedDomain[]>([]);
	// Step R Phase 2.b — error-page templates list for the
	// RouteForm's "Pages d'erreur" dropdown. Loaded once on
	// mount alongside routes/managedDomains. Sorted alpha
	// at populate time so the dropdown's render is stable.
	let errorTemplates = $state<ErrorTemplate[]>([]);
	// Whether the per-route override sub-form is expanded.
	// Collapsed by default ; auto-expands on edit when the
	// loaded route already has overrides (operator returns
	// to a form mid-edit, expects to see what's there).

	async function loadManagedDomainsForRoutes() {
		try {
			const res = await settingsApi.listManagedDomains();
			managedDomains = res.domains;
		} catch (_err) {
			managedDomains = [];
		}
	}

	// Pure JS port of caddymgr.IsHostCoveredByManagedDomain (spec
	// §3.2 + RFC 6125 §6.4.3). Single-label wildcard, case-
	// insensitive, trailing dot canonicalised. Returns the matching
	// ManagedDomain or null. Kept in this file rather than a
	// shared util because it's the only frontend caller for now;
	// extract when a second caller lands (likely never — server
	// emits effectiveCertSource directly).
	function findCoveringManagedDomain(host: string): ManagedDomain | null {
		if (!host) return null;
		const h = host.toLowerCase().replace(/\.$/, '');
		if (h.startsWith('*.')) return null;
		for (const md of managedDomains) {
			const apex = md.apex.toLowerCase().replace(/\.$/, '');
			if (!apex) continue;
			if (h === apex) {
				if (md.includeApex) return md;
				continue;
			}
			const suffix = '.' + apex;
			if (!h.endsWith(suffix)) continue;
			const prefix = h.slice(0, -suffix.length);
			if (prefix === '' || prefix.includes('.')) continue;
			return md;
		}
		return null;
	}

	// (β) bandeau gate: any persisted route is on dns-01 while the
	// provider is not fully configured. Derived from the loaded
	// routes + provider snapshot; updates automatically when either
	// list changes after a refresh.
	const dns01Inconsistent = $derived.by(() => {
		if (dnsProviderConfigured) return false;
		return routes.some((r) => r.acmeChallenge === 'dns-01');
	});

	// Step J.4 wildcard detection — mirrors the backend's
	// wildcardHostRE. Single-leading-`*` only; multi-wildcards are
	// rejected upstream as malformed hostnames.
	function isWildcardHost(h: string): boolean {
		return /^\*\.[A-Za-z0-9-.]+$/.test(h.trim());
	}

	// Step O.4 — derived covering managed domain for the form's
	// current host. When non-null, the per-route ACME selector is
	// hidden and an inheritance badge is shown (AC #11). Operator
	// can opt out via the useDedicatedCert checkbox to fall back
	// to the J-era per-route ACME path. Wildcard route-hosts
	// (`*.foo`) are never "covered" — the wildcard IS the cert,
	// not a consumer of one — so the predicate returns null and
	// the J-era acmeLockedToDNS01 path takes over.
	const coveringManagedDomain = $derived(findCoveringManagedDomain(formData.host));

	// Step O.4 backlog #O.4-2 — handler for the useDedicatedCert
	// checkbox. The plain bind:checked path would have silently
	// left the route's previous acmeChallenge value in place when
	// the operator toggles the opt-out on — but for routes that
	// were previously on a managed-domain wildcard, the form-load
	// path normalised acmeChallenge "inherited" → "http-01" as a
	// non-restorable default (the operator's original per-route
	// choice was lost at managed-domain-create time). Defaulting
	// the dropdown to http-01 on opt-out toggle would mean ANY
	// operator clicking the toggle accidentally provisions an
	// HTTP-01 cert with no explicit decision.
	//
	// Fix per backlog #O.4-2 Option B: when the toggle flips
	// false → true, clear acmeChallenge to "" so the dropdown
	// renders unselected. Submit is disabled until the operator
	// picks. Toggling back true → false re-engages the managed-
	// domain wildcard and the dropdown disappears, so we don't
	// need to restore anything.
	function onUseDedicatedCertToggle(next: boolean): void {
		const wasOptedOut = formData.useDedicatedCert;
		formData.useDedicatedCert = next;
		if (!wasOptedOut && next) {
			// false → true: force explicit choice. Empty
			// acmeChallenge is rejected by the backend
			// reconcile too, so this matches server contract.
			formData.acmeChallenge = '';
		}
	}

	// Step O.4 backlog #O.4-2 — submit guard. Covered + opted out
	// + no acmeChallenge picked = pending operator decision.
	// Button stays disabled until the dropdown resolves.
	const dedicatedOptOutPendingChoice = $derived(
		coveringManagedDomain !== null &&
			formData.useDedicatedCert &&
			(formData.acmeChallenge === '' || formData.acmeChallenge === 'inherited')
	);

	// Step J.4: when the host or any alias is a wildcard, the
	// challenge selector is LOCKED to "dns-01" (greyed). Used as
	// `disabled` on the selector AND to force-flip the formData
	// value if the user pastes a wildcard host into a form that
	// was previously on http-01.
	const acmeLockedToDNS01 = $derived.by(() => {
		if (isWildcardHost(formData.host)) return true;
		return formData.aliases.some(isWildcardHost);
	});

	$effect(() => {
		if (acmeLockedToDNS01 && formData.acmeChallenge !== 'dns-01') {
			formData.acmeChallenge = 'dns-01';
		}
	});

	// Step J.4: when TLS gets turned off the ACMEChallenge value is
	// irrelevant. We don't reset it (so the user can toggle TLS off
	// and back on without losing the choice), but the selector is
	// hidden — see the markup.
	// Step J.3: derive whether the LB-policy selector is visible.
	// Hidden when the pool has one upstream — selection is moot;
	// formData.lbPolicy is preserved across visibility flips so an
	// admin who picked weighted_round_robin, removed an upstream,
	// then re-added one keeps the choice.
	const lbSelectorVisible = $derived(formData.upstreams.length >= 2);

	// v2.41.2 — the state is a form field like any other: picking it
	// changes nothing until Save. (v2.41.1 applied it on click, which
	// the operator rightly refused — a form where one control commits
	// and the others wait is a trap.) It is seeded from the stored
	// route when the panel opens and shipped in the payload: the PUT
	// carries all three states, since `disabled:false` with no
	// maintenance block clears maintenance server-side
	// (internal/api/routes.go, v2.39 preserve-or-replace rules).
	// The icons in the routes list keep applying immediately — there,
	// the click IS the action.
	let stateChoice = $state<'active' | 'maintenance' | 'redirect' | 'disabled'>('active');
	let stateSnapshot = $state<'active' | 'maintenance' | 'redirect' | 'disabled'>('active');

	// v2.41 — "unsaved changes" marker: the panel snapshots the form when
	// it opens; anything different afterwards is unsaved work. Compared as
	// JSON because formData is a plain object of plain values.
	let formSnapshot = $state('');
	const formDirty = $derived(
		formSnapshot !== '' &&
			(JSON.stringify(formData) !== formSnapshot || stateChoice !== stateSnapshot)
	);

	// v2.41 — the unsaved marker now protects something: any path
	// that would drop the edits (Cancel, a click outside the panel,
	// picking another row, opening a create form) goes through
	// guardUnsaved, which asks first and replays the action only if
	// the operator confirms. Saving is NOT guarded — it keeps the
	// edits by definition — and neither is a close that follows a
	// successful save (formDirty is false by then).
	let confirmDiscardOpen = $state(false);
	let pendingAfterDiscard: (() => void) | null = null;

	function guardUnsaved(action: () => void): void {
		if (formOpen && formDirty) {
			pendingAfterDiscard = action;
			confirmDiscardOpen = true;
			return;
		}
		action();
	}

	function onConfirmDiscard(): void {
		confirmDiscardOpen = false;
		const action = pendingAfterDiscard;
		pendingAfterDiscard = null;
		action?.();
	}

	// ConfirmDialog only reports the affirmative answer; its cancel
	// path just flips `open` through the bind. onConfirmDiscard
	// clears the pending action before running it, so a dialog that
	// closed any other way leaves nothing armed.
	$effect(() => {
		if (!confirmDiscardOpen) pendingAfterDiscard = null;
	});

	function snapshotForm(): void {
		formSnapshot = JSON.stringify(formData);
		stateSnapshot = stateChoice;
	}


	// v2.41 — one-line state summary per collapsible section, so the
	// closed form still reads as the route's configuration. Each
	// summary is derived from formData, never from the stored route:
	// it must follow what the operator is editing.
	// t() is a plain function, so a $derived that calls it only
	// recomputes on a language switch if it READS language.current
	// (lib/i18n/index.ts). tl() does that read for every derived
	// label below, instead of repeating `language.current &&`.
	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	// v2.41 — WAF mode as a segmented control: all three modes stay
	// visible and each one states its consequence when selected.
	const wafModeOptions = $derived([
		{
			value: 'off' as const,
			label: tl('routes.form.wafModeOff'),
			hint: tl('routes.form.wafModeOffHint'),
			tone: 'neutral' as const
		},
		{
			value: 'detect' as const,
			label: tl('routes.form.wafModeDetect'),
			hint: tl('routes.form.wafModeDetectHint'),
			tone: 'watch' as const
		},
		{
			value: 'block' as const,
			label: tl('routes.form.wafModeBlock'),
			hint: tl('routes.form.wafModeBlockHint'),
			tone: 'block' as const
		}
	]);

	// What the "CRS exceptions" sub-group holds (the targeted
	// exclusions below carry their own count).
	const wafExceptionCount = $derived(
		formData.wafExcludeRules.length + formData.wafExcludeTags.length
	);

	// v2.58.3 — the posture union is taken from RouteSection rather than
	// restated here. It was restated, and adding `set` to the component left
	// this copy behind: the type error that produced is the only reason the
	// drift surfaced at all.
	type SectionBadge = { badge: string; posture: Posture | undefined };

	const summaryEssentials = $derived(
		[
			tl('routes.form.summaryUpstreams', { count: formData.upstreams.filter((u) => u.url.trim() !== '').length }),
			formData.aliases.filter((a) => a.trim() !== '').length > 0
				? tl('routes.form.summaryAliases', { count: formData.aliases.filter((a) => a.trim() !== '').length })
				: ''
		]
			.filter(Boolean)
			.join(' · ')
	);

	const summaryTLS = $derived(
		!formData.tlsEnabled
			? tl('routes.form.summaryTLSOff')
			: [
					formData.cert_source === 'manual'
						? tl('routes.form.summaryCertManual')
						: tl('routes.form.summaryCertAcme'),
					formData.acmeChallenge === 'dns-01' ? 'DNS-01' : 'HTTP-01',
					formData.redirectToHttps ? tl('routes.form.summaryRedirect') : ''
				]
					.filter(Boolean)
					.join(' · ')
	);

	// v2.41 — auth as a segmented control: the three choices are
	// exclusive, and each states what it asks of the visitor.
	const authModeOptions = $derived([
		{
			value: 'none' as const,
			label: tl('routes.form.authNoneOption'),
			hint: tl('routes.form.authNoneHint'),
			tone: 'neutral' as const
		},
		{
			value: 'basic' as const,
			label: tl('routes.form.authBasicRadioLabel'),
			hint: tl('routes.form.authBasicHint'),
			tone: 'allow' as const
		},
		{
			value: 'forward_auth' as const,
			label: tl('routes.form.authForwardRadioLabel'),
			hint: tl('routes.form.authForwardHint'),
			tone: 'allow' as const
		}
	]);

	// v2.41.2 — TLS and the health check had a summary but no badge,
	// so the badge column stopped halfway down the form. They are
	// on/off facts rather than traffic decisions: green when on, grey
	// when off.
	const tlsBadge = $derived<SectionBadge>(
		formData.tlsEnabled
			? { badge: 'https', posture: 'allow' }
			: { badge: 'http', posture: 'off' }
	);

	// v2.43.1 — the probe's live verdict, inside the form.
	//
	// The list has carried it since Pack A, but the form — the one
	// screen where you set the URI, the expected status and the
	// expected body — showed only on/off. So after changing a probe
	// you had to leave the form to find out whether it now passes.
	// The 2026-09-24 session lost an afternoon to exactly that gap.
	//
	// Null while creating: there is no running probe to report yet.
	const healthCheckLive = $derived(
		editingId ? (routes.find((r) => r.id === editingId) ?? null) : null
	);

	// Only 'degraded' and 'down' mean the probe is actually failing;
	// 'unknown' is the warm-up window and must not be painted red.
	const healthCheckFailing = $derived(
		healthCheckLive?.aggregateStatus === 'down' ||
			healthCheckLive?.aggregateStatus === 'degraded'
	);

	const healthCheckLiveLabel = $derived(
		healthCheckLive ? tl(`routes.form.healthCheckLive.${healthCheckLive.aggregateStatus}`) : ''
	);

	// The badge follows the verdict rather than the switch: a section
	// that says "on" while every backend is down is worse than no
	// badge at all.
	const healthCheckBadge = $derived<SectionBadge>(
		!formData.healthCheck.enabled
			? { badge: tl('routes.form.badgeOff'), posture: 'off' }
			: healthCheckFailing
				? { badge: healthCheckLiveLabel, posture: 'block' }
				: healthCheckLive?.aggregateStatus === 'healthy'
					? { badge: healthCheckLiveLabel, posture: 'allow' }
					: { badge: tl('routes.form.badgeOn'), posture: 'allow' }
	);

	const summaryAuth = $derived(
		formData.authMode === 'basic'
			? tl('routes.form.summaryAuthBasic', { user: formData.basicAuth.username || '—' })
			: formData.authMode === 'forward_auth'
				? tl('routes.form.summaryAuthForward', { provider: formData.forwardAuth.providerName || '—' })
				: tl('routes.form.summaryAuthNone')
	);
	const authBadge = $derived<SectionBadge>(
		formData.authMode === 'none'
			? { badge: tl('routes.form.badgeOff'), posture: 'off' }
			: { badge: tl('routes.form.badgeOn'), posture: 'allow' }
	);

	const summaryWAF = $derived(
		formData.wafMode === 'off'
			? tl('routes.form.summaryWAFOff')
			: [
					formData.wafDisableCRS ? tl('routes.form.summaryCRSOff') : tl('routes.form.summaryCRSOn'),
					formData.wafTargetedExclusions.length + formData.wafExcludeRules.length + formData.wafExcludeTags.length > 0
						? tl('routes.form.summaryExclusions', {
								count:
									formData.wafTargetedExclusions.length +
									formData.wafExcludeRules.length +
									formData.wafExcludeTags.length
							})
						: '',
					formData.wafCustomRules.length > 0
						? tl('routes.form.summaryCustomRules', { count: formData.wafCustomRules.length })
						: '',
					formData.wafSecLang.trim() !== '' ? 'SecLang' : ''
				]
					.filter(Boolean)
					.join(' · ')
	);
	const wafBadge = $derived<SectionBadge>(
		formData.wafMode === 'block'
			? { badge: 'block', posture: 'block' }
			: formData.wafMode === 'detect'
				? { badge: 'detect', posture: 'watch' }
				: { badge: tl('routes.form.badgeOff'), posture: 'off' }
	);

	// The stored key is a Caddy placeholder ; the form says what it
	// means. Anything custom is shown as the operator typed it.
	const rateLimitKeyLabel = $derived.by(() => {
		const key = (formData.rateLimit?.key ?? '').trim();
		return key === '' || key === 'remote_ip' || key === '{http.request.remote.host}'
			? tl('routes.form.rateLimitKeyDefault')
			: key;
	});

	const summaryRateLimit = $derived(
		formData.rateLimit === null
			? tl('routes.form.summaryRateLimitOff')
			: tl('routes.form.summaryRateLimitOn', {
					events: formData.rateLimit.events,
					window: formData.rateLimit.window,
					key: rateLimitKeyLabel
				})
	);
	// v2.41 — the three rate-limit fields only mean something as the
	// rule they add up to; the sentence says it in one line.
	const rateLimitSentence = $derived.by(() => {
		const rl = formData.rateLimit;
		if (rl === null) return '';
		return tl('routes.form.rateLimitSentence', {
			events: rl.events,
			window: rl.window || '—',
			key: rateLimitKeyLabel
		});
	});

	// v2.41.2 — green, not red: a rate limit does not turn a category
	// of traffic away, it caps abuse while everyone else goes through.
	// Same reading as authentication.
	const rateLimitBadge = $derived<SectionBadge>(
		formData.rateLimit === null
			? { badge: tl('routes.form.badgeOff'), posture: 'off' }
			: { badge: tl('routes.form.badgeOn'), posture: 'allow' }
	);

	const geoActive = $derived(formData.countryBlock.mode === 'allow' || formData.countryBlock.mode === 'deny');
	const ipActive = $derived(formData.ipFilter.mode === 'allow' || formData.ipFilter.mode === 'deny');
	const summaryGeoIP = $derived(
		[
			geoActive
				? t(
						formData.countryBlock.mode === 'allow'
							? 'routes.form.summaryGeoAllow'
							: 'routes.form.summaryGeoDeny',
						{
							count:
								formData.countryBlock.countryList.length +
								formData.countryBlock.continents.length +
								formData.countryBlock.asns.length
						}
					)
				: '',
			ipActive
				? t(formData.ipFilter.mode === 'allow' ? 'routes.form.summaryIPAllow' : 'routes.form.summaryIPDeny', {
						count: (formData.ipFilter.cidrs ?? []).filter((c) => c.trim() !== '').length
					})
				: ''
		]
			.filter(Boolean)
			.join(' · ') || tl('routes.form.summaryGeoIPOff')
	);
	const geoIPBadge = $derived<SectionBadge>(
		!geoActive && !ipActive
			? { badge: tl('routes.form.badgeOff'), posture: 'off' }
			: formData.countryBlock.mode === 'deny' || formData.ipFilter.mode === 'deny'
				? { badge: tl('routes.form.badgeDeny'), posture: 'block' }
				: { badge: tl('routes.form.badgeAllow'), posture: 'allow' }
	);

	const summaryHealthCheck = $derived(
		formData.healthCheck.enabled
			? tl('routes.form.summaryHealthCheckOn', {
					uri: formData.healthCheck.uri || '/',
					interval: formData.healthCheck.interval || '30s'
				})
			: tl('routes.form.summaryHealthCheckOff')
	);

	const namedHeaderCount = $derived(
		requestHeaderRows.filter(([k]) => k.trim() !== '').length +
			responseHeaderRows.filter(([k]) => k.trim() !== '').length
	);
	const summaryPathsHeaders = $derived(
		[
			formData.pathRules.length > 0 ? tl('routes.form.summaryPathRules', { count: formData.pathRules.length }) : '',
			namedHeaderCount > 0 ? tl('routes.form.summaryHeaders', { count: namedHeaderCount }) : ''
		]
			.filter(Boolean)
			.join(' · ') || tl('routes.form.summaryPathsHeadersOff')
	);

	const errorOverrideCount = $derived(Object.keys(formData.errorPageOverrides ?? {}).length);

	// v2.56.3 — Paths & headers gets a posture, like the sections it now
	// resembles.
	//
	// It was neutral by design, and RouteSection documents why: sections
	// that do not decide what happens to traffic pass no posture, so the
	// colour keeps its meaning. That was written when a path rule carried
	// headers. A rule can now carry basic auth, an IP filter and a rate
	// limit — the same gates as Auth, GeoIP and Rate limit, all of which
	// are coloured — so the section decides, and staying grey made it the
	// one place a gate is invisible until opened.
	//
	// The postures follow the meanings already in use here rather than a
	// new scheme: a deny-list blocks (as GeoIP deny does), while an
	// allow-list, basic auth or a rate limit lets traffic through on a
	// criterion (as GeoIP allow and the route's own rate limit do). A rate
	// limit is NOT block: it permits, within a budget.
	//
	// block wins over allow when rules disagree, because a restriction is
	// what deserves to be seen first — and it mirrors how GeoIP reports a
	// deny over an allow.
	const pathsHeadersBadge = $derived.by<SectionBadge | undefined>(() => {
		if (formData.pathRules.length === 0) {
			// No rules: the section carries headers at most, which decide
			// nothing. Neutral, exactly as before.
			return undefined;
		}
		let blocks = false;
		let allows = false;
		let opens = false;
		for (const rule of formData.pathRules) {
			if (rule.ipFilter?.mode === 'deny') blocks = true;
			if (rule.ipFilter?.mode === 'allow') allows = true;
			if (rule.basicAuth && rule.basicAuth.username.trim() !== '') allows = true;
			if ((rule.rateLimit?.events ?? 0) > 0) allows = true;
			// v2.57 — an IdP gate is a gate. Without this line a path
			// protected by forward auth and nothing else made the section
			// read "off", telling the operator their protection was absent.
			if ((rule.forwardAuth?.providerName ?? '').trim() !== '') allows = true;
			// v2.58 — an exemption is tracked separately from the gates: it
			// is not a protection, so the badge must not claim one.
			if (rule.disableRouteAuth) opens = true;
		}
		if (blocks) return { badge: tl('routes.form.badgeDeny'), posture: 'block' };
		if (allows) return { badge: tl('routes.form.badgeAllow'), posture: 'allow' };
		// v2.58.3 — a rule that only removes authentication. This shipped as
		// posture 'off', which the RouteSection contract defines as
		// "configured but inactive" — and an exemption is anything but
		// inactive, so the section read as untouched next to every other
		// configured one. It is 'allow' instead: the contract's own wording
		// for that colour is "lets traffic through on a criterion", which is
		// literally what an exemption does, the criterion being the path. The
		// badge still says "auth exempt" so the green is never read as a
		// protection.
		if (opens) return { badge: tl('routes.form.badgeAuthExempt'), posture: 'allow' };
		// v2.58.3 — rules exist but gate nothing: a redirect, or a per-path
		// backend. That is configuration, so it no longer reads "off" in grey,
		// which said the section was empty. It says how many rules there are,
		// in the accent colour that claims nothing about traffic.
		return {
			badge: tl('routes.form.badgeRules', { count: formData.pathRules.length }),
			posture: 'set'
		};
	});

	// v2.58.3 — Error pages was the one section that showed nothing at all
	// when configured: no badge, no rail. An operator could not tell a route
	// with a custom template and three per-code overrides from an untouched
	// one without opening it. It decides nothing about traffic, so it takes
	// the `set` posture rather than a traffic colour, and nothing at all when
	// there is nothing in it.
	const errorPagesBadge = $derived.by<SectionBadge | undefined>(() => {
		const parts: string[] = [];
		if (formData.errorPageTemplateId) parts.push(tl('routes.form.badgeTemplate'));
		if (errorOverrideCount > 0) {
			parts.push(tl('routes.form.badgeOverrides', { count: errorOverrideCount }));
		}
		if (parts.length === 0) return undefined;
		return { badge: parts.join(' · '), posture: 'set' };
	});

	const summaryErrorPages = $derived(
		formData.errorPageTemplateId
			? tl('routes.form.summaryErrorPagesTemplate')
			: tl('routes.form.summaryErrorPagesDefault')
	);

	const summaryState = $derived(
		stateChoice === 'disabled'
			? tl('routes.form.summaryStateDisabled')
			: stateChoice === 'maintenance'
				? tl('routes.form.summaryStateMaintenance')
				: stateChoice === 'redirect'
					? tl('routes.form.summaryStateRedirect', {
							target: formData.redirectConfig.target || '—'
						})
					: tl('routes.form.summaryStateActive')
	);

	const stateOptions = $derived(
		[
			{
				value: 'active' as const,
				label: tl('routes.state.active'),
				hint: tl('routes.form.stateActiveHint'),
				tone: 'allow' as const
			},
			// v2.45.2 — offered at creation too. It used to be hidden
			// there on the grounds that maintenance is a transition
			// rather than a birth state, which is defensible in the
			// abstract and confusing in practice: the operator opened
			// a new route, counted three options where four exist, and
			// reported maintenance as missing. Nothing prevents a
			// route from being born in maintenance, and the asymmetry
			// became indefensible the moment redirect appeared there.
			{
				value: 'maintenance' as const,
				label: tl('routes.state.maintenance'),
				hint: tl('routes.form.stateMaintenanceHint'),
				tone: 'watch' as const
			},
			{
				value: 'redirect' as const,
				label: tl('routes.state.redirect'),
				hint: tl('routes.form.stateRedirectHint'),
				tone: 'watch' as const
			},
			{
				value: 'disabled' as const,
				label: tl('routes.state.disabled'),
				hint: tl('routes.form.stateDisabledHint'),
				tone: 'neutral' as const
			}
		]
	);

	// 301 vs 302: the only pair offered. 307/308 preserve the request
	// method, which means a browser re-POSTing to another host — a
	// different decision, deliberately out of scope (spec D2).
	const redirectCodeOptions = $derived([
		{
			value: '301',
			label: '301',
			hint: tl('routes.form.redirect.code301Hint'),
			tone: 'neutral' as const
		},
		{
			value: '302',
			label: '302',
			hint: tl('routes.form.redirect.code302Hint'),
			tone: 'neutral' as const
		}
	]);

	function onFormStateChange(next: string): void {
		// Kept in sync so anything still reading formData.disabled
		// (the payload's other branches, the summary) agrees with the
		// control. The transition itself happens on submit.
		formData.disabled = next === 'disabled';
	}

	const stateBadge = $derived<SectionBadge>(
		stateChoice === 'disabled'
			? { badge: tl('routes.form.badgeDisabled'), posture: 'off' }
			: stateChoice === 'maintenance'
				? { badge: tl('routes.form.badgeMaintenance'), posture: 'watch' }
				: stateChoice === 'redirect'
					? { badge: tl('routes.form.badgeRedirect'), posture: 'watch' }
					: { badge: tl('routes.form.badgeActive'), posture: 'allow' }
	);

	// Step J.3: derive whether the weight column is visible.
	// Shown only for weighted_round_robin; per-row Weight value is
	// preserved across visibility flips (the form state isn't
	// touched when we hide the column).
	const weightVisible = $derived(formData.lbPolicy === 'weighted_round_robin');

	// Step #R-PROXMOX-HTTPS-LOOP — derived helpers for the
	// upstream-pool scheme + per-row UX hints. Mirror of the
	// storage `Route.PoolUsesHTTPS` predicate and the
	// `validateSameSchemePool` invariant, surfaced at form
	// time so the operator gets fast feedback instead of a
	// 400 on submit.
	//
	// poolScheme one of:
	//   - 'empty'  — no rows have a URL yet (form just opened)
	//   - 'http'   — every parseable row is http://
	//   - 'https'  — every parseable row is https://
	//   - 'mixed'  — at least one http and at least one https row
	//
	// Unparseable rows are ignored by the predicate (their own
	// per-row error already blocks submit). The "mixed" state
	// triggers a row-level error AND suppresses the TLS
	// advanced disclosure (the storage validator would reject
	// the submit anyway).
	type PoolScheme = 'empty' | 'http' | 'https' | 'mixed';
	function schemeOf(u: { url: string }): 'http' | 'https' | null {
		const s = u.url.trim().toLowerCase();
		if (s.startsWith('http://')) return 'http';
		if (s.startsWith('https://')) return 'https';
		return null;
	}
	const poolScheme = $derived.by<PoolScheme>(() => {
		let sawHTTP = false;
		let sawHTTPS = false;
		for (const u of formData.upstreams) {
			const sc = schemeOf(u);
			if (sc === 'http') sawHTTP = true;
			else if (sc === 'https') sawHTTPS = true;
		}
		if (sawHTTP && sawHTTPS) return 'mixed';
		if (sawHTTPS) return 'https';
		if (sawHTTP) return 'http';
		return 'empty';
	});

	// Disclosure visibility for the "Options avancées TLS"
	// block — visible ONLY on a clean all-https pool. When
	// the pool is mixed, the row error suppresses the
	// disclosure too (the operator can't make a meaningful
	// choice until the pool is consistent).
	const tlsAdvancedVisible = $derived(poolScheme === 'https');

	// Self-heal on https→http transition: reset the toggle
	// to false so the on-screen state and the storage state
	// stay aligned. Mirror of the backend self-heal at
	// internal/api/routes.go createRoute / updateRoute
	// (silent normalisation + warn-log). Without this
	// $effect the form would hide a still-true value when
	// the operator switched a Proxmox route's pool to an
	// http upstream, then re-expose it (checked) on a
	// re-flip — exactly the surprise the operator flagged
	// during plan review.
	$effect(() => {
		if (poolScheme !== 'https' && formData.insecureSkipVerify) {
			formData.insecureSkipVerify = false;
		}
		// v2.60 — same reset for the server name: the backend
		// normalises it away on an http pool, so leaving it in the
		// form would display a value the next save silently drops.
		if (poolScheme !== 'https' && formData.upstreamTlsServerName !== '') {
			formData.upstreamTlsServerName = '';
		}
	});

	// Per-row "private IP + https" hint. Recognises RFC 1918
	// (10/8, 172.16/12, 192.168/16), 127/8 loopback, and the
	// IPv6 ULA range fc00::/7 plus ::1. Hostnames are NOT
	// flagged (a homelab might use mDNS or a private DNS
	// suffix that the operator already trusts). The hint is
	// advisory only — it never blocks submit; the operator
	// might intentionally use a public-CA cert behind a
	// private network (split-horizon DNS), in which case
	// the hint is benign.
	const RFC1918_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/;
	const IPV6_PRIVATE_RE = /^(::1|f[cd][0-9a-f]{2}:)/i;
	function hasPrivateUpstreamHost(rawURL: string): boolean {
		const url = rawURL.trim();
		if (url === '') return false;
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			return false;
		}
		// new URL() wraps bracketed IPv6 hostnames in [...]; strip
		// before matching the regex. IPv4 + hostnames are
		// untouched.
		const host = parsed.hostname.replace(/^\[|\]$/g, '');
		return RFC1918_RE.test(host) || IPV6_PRIVATE_RE.test(host);
	}
	function showPrivateIPHint(rawURL: string): boolean {
		return schemeOf({ url: rawURL }) === 'https' && hasPrivateUpstreamHost(rawURL);
	}

	// Per-row path warning. Caddy reverse_proxy targets the
	// upstream at host:port; any path component on the upstream
	// URL is silently dropped (the dial field never carries a
	// path). Operators routinely paste full URLs from a browser
	// address bar (e.g. https://pve.local:8006/api2/json) and
	// expect the path to be honoured — the warning surfaces the
	// truth without rejecting the value (they may want to keep
	// the input as a reminder of where the API root sits, then
	// configure path forwarding via request headers in a future
	// commit).
	function nonRootPath(rawURL: string): string | null {
		const url = rawURL.trim();
		if (url === '') return null;
		let parsed: URL;
		try {
			parsed = new URL(url);
		} catch {
			return null;
		}
		if (parsed.pathname === '' || parsed.pathname === '/') return null;
		return parsed.pathname;
	}

	// --- Client-side validation (Step J.3) -----------------------------------

	function parseDuration(s: string): number | null {
		if (!DURATION_RE.test(s)) return null;
		// We do not need the actual ns count — just whether it
		// parses. The "positive" check is done indirectly by
		// requiring at least one digit (the regex ensures \d+).
		// Comparison timeout < interval falls back on string
		// equality for the common case where the operator typed the
		// same value twice; rare edge cases (e.g. "60s" vs "1m")
		// are caught by the server validator.
		return s.length;
	}

	function validateBeforeSubmit(): boolean {
		const next: Record<string, string> = {};

		if (formData.host.trim() === '') {
			next['host'] = 'Host must not be empty';
		}

		// Step J.1: per-upstream URL + weight validation.
		//
		// v2.45.2 — skipped entirely for a redirecting route: it
		// proxies nothing, so demanding a backend means asking the
		// operator to invent an address that will never be dialled.
		const needsUpstream = stateChoice !== 'redirect';
		if (needsUpstream && formData.upstreams.length === 0) {
			next['upstreams'] = 'At least one upstream is required';
		}
		formData.upstreams.forEach((u, i) => {
			const url = u.url.trim();
			if (url === '') {
				if (!needsUpstream) return;
				next[`upstreams[${i}].url`] = 'URL must not be empty';
			} else {
				try {
					const parsed = new URL(url);
					if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
						next[`upstreams[${i}].url`] = 'URL must use http or https';
					}
				} catch {
					next[`upstreams[${i}].url`] = 'URL is malformed';
				}
			}
			if (weightVisible && u.weight < 1) {
				next[`upstreams[${i}].weight`] = 'Weight must be >= 1';
			}
		});
		// Step #R-PROXMOX-HTTPS-LOOP — same-scheme pool
		// invariant. Mirror of storage.validateSameSchemePool;
		// surfacing it at the form's submit boundary spares the
		// operator a 400 round-trip. Pool-level error rendered
		// under the pool header; individual rows keep their own
		// per-URL errors.
		if (poolScheme === 'mixed') {
			next['upstreams'] =
				'All upstreams must share the same scheme (http:// or https://) — mixed pools are not supported.';
		}

		// Step J.2: health-check sub-form validation, gated on enabled.
		if (formData.healthCheck.enabled) {
			const hc = formData.healthCheck;
			if (hc.uri.trim() === '') {
				next['healthCheck.uri'] = 'URI is required';
			} else if (!hc.uri.startsWith('/')) {
				next['healthCheck.uri'] = 'URI must start with /';
			}
			// method: a binary select bound to a fixed set, so
			// validation is unreachable through the UI; defensive
			// check kept anyway.
			if (hc.method !== 'GET' && hc.method !== 'HEAD') {
				next['healthCheck.method'] = 'Method must be GET or HEAD';
			}
			// Defaultable fields: blank passes through to the
			// server, which materialises defaults. Validate only
			// non-blank inputs.
			if (hc.interval !== '' && parseDuration(hc.interval) === null) {
				next['healthCheck.interval'] = 'Interval must be a duration (e.g. 30s)';
			}
			if (hc.timeout !== '' && parseDuration(hc.timeout) === null) {
				next['healthCheck.timeout'] = 'Timeout must be a duration (e.g. 5s)';
			}
			// timeout < interval: only checked when BOTH are
			// supplied (string equality catches the common typo).
			if (
				hc.interval !== '' &&
				hc.timeout !== '' &&
				parseDuration(hc.interval) !== null &&
				parseDuration(hc.timeout) !== null &&
				hc.timeout === hc.interval
			) {
				next['healthCheck.timeout'] = 'Timeout must be less than interval';
			}
			// v2.55 — 1-5 is Caddy's status-class shorthand (3 = any 3xx), so
			// an app that answers 302 on / is not pinned to one code it may
			// stop using. Mirrors storage.ValidateExpectStatus.
			if (
				hc.expectStatus !== 0 &&
				!(hc.expectStatus >= 1 && hc.expectStatus <= 5) &&
				(hc.expectStatus < 100 || hc.expectStatus > 599)
			) {
				next['healthCheck.expectStatus'] = t('routes.form.healthCheckExpectStatusError');
			}
			const badHeader = healthCheckHeaderRows.find(
				(row) => row.name.trim() !== '' && row.name.trim().toLowerCase() === 'host'
			);
			if (badHeader) {
				next['healthCheck.headers'] = t('routes.form.healthCheckHeaderHostError');
			}
			if (hc.expectBody !== '') {
				try {
					// eslint-disable-next-line no-new
					new RegExp(hc.expectBody);
				} catch {
					next['healthCheck.expectBody'] = 'Expected body is not a valid regex';
				}
			}
			// passes / fails: 0 means "use default" → blank-equiv,
			// don't reject. Negative values are rejected.
			if (hc.passes < 0) {
				next['healthCheck.passes'] = 'Passes must be >= 1';
			}
			if (hc.fails < 0) {
				next['healthCheck.fails'] = 'Fails must be >= 1';
			}
		}

		// v2.56.3 — a path rule the operator named but never filled is
		// refused instead of dropped.
		//
		// sanitizePathRules removes rules carrying no content, which is
		// right for a row added and abandoned. It is wrong for a row with
		// a path typed into it: the rule vanished on save, with a success
		// toast and nothing said. Telling the operator is the difference
		// between a filter and a deletion.
		formData.pathRules.forEach((rule, i) => {
			if (rule.pathPrefix.trim() === '') return;
			if (!pathRuleContentChecks.some((has) => has(rule))) {
				next[`pathRules.${i}`] = t('routes.pathRules.emptyRuleError', {
					path: rule.pathPrefix.trim()
				});
			}
		});

		// Step X Option (c) — re-parse the exclusion-rules
		// textarea at submit time so a stale invalid input
		// surfaces here even if the operator never blurred /
		// triggered an oninput event after the typo (paste +
		// submit). Mirror of the openEdit-time canonicalisation.
		const reparsed = parseExcludeRulesInput(wafExcludeRulesInput);
		if (reparsed.error) {
			next.wafExcludeRules = reparsed.error;
		}

		// Step X Option (e) — same paste-then-submit guard
		// against stale invalid tag input that escaped the
		// onchange path.
		const reparsedTags = parseExcludeTagsInput(wafExcludeTagsInput);
		if (reparsedTags.error) {
			next.wafExcludeTags = reparsedTags.error;
		}

		errors = next;
		return Object.keys(next).length === 0;
	}

	// Step I.7 / J.3: server validation error → which field path
	// does it apply to? The server uses both camelCase ("upstreams[0]
	// .url", "healthCheck.method") and prefixes the message with the
	// field path verbatim, so we read up to the first colon or space.
	function fieldFromMessage(msg: string): string | null {
		// Patterns observed:
		//   "host must not be empty"
		//   "upstreams[1]: upstreamUrl must use http or https scheme"
		//   "upstreams[1].weight must be >= 1"
		//   "healthCheck.uri must not be empty when enabled"
		//   "healthCheck.timeout must be strictly less than interval"
		//   "lbPolicy "foo" is not a valid policy"
		const lower = msg.toLowerCase();
		if (lower.startsWith('host ')) return 'host';
		if (lower.startsWith('lbpolicy ')) return 'lbPolicy';
		// upstreams[N]:... or upstreams[N].field …
		const upstreamsMatch = /^upstreams\[(\d+)\]/.exec(msg);
		if (upstreamsMatch) {
			const idx = upstreamsMatch[1];
			if (msg.startsWith(`upstreams[${idx}].weight`)) {
				return `upstreams[${idx}].weight`;
			}
			return `upstreams[${idx}].url`;
		}
		if (lower.startsWith('upstreams ')) {
			return 'upstreams';
		}
		// healthCheck.<subfield>
		const hcMatch = /^healthCheck\.(\w+)/.exec(msg);
		if (hcMatch) {
			return `healthCheck.${hcMatch[1]}`;
		}
		return null;
	}

	async function submitForm() {
		// 2026-06-25 — empirical double-PUT guard.
		// The visible Save button has `disabled={submitting}` which
		// SHOULD prevent re-fire, but Svelte 5's reactivity → DOM
		// commit window has a microtask gap where a queued 2nd click
		// (OS-level double-click setting, accessibility tool, or
		// rapid touch) can pass through before the disabled attribute
		// lands. Belt + braces : the disabled attribute is UX polish,
		// this guard is the correctness primitive. With it, even 100
		// queued click events fire submitForm() only once for the
		// in-flight save.
		if (submitting) {
			return;
		}
		submitting = true;
		resetFormErrors();
		if (!validateBeforeSubmit()) {
			submitting = false;
			// v2.56.3 — never refuse silently.
			//
			// This returned with no feedback of any kind, so a validation
			// error under a key no template renders made the Save button do
			// nothing at all: no message, no toast, no network request. The
			// operator's only signal was the absence of one.
			//
			// Every field error should be rendered next to its field, and
			// most are. This is the net under that: it says the form was
			// refused and names what, so a key nobody displays still
			// produces a visible refusal rather than silence.
			const unresolved = Object.values(errors).filter((m) => (m ?? '').trim() !== '');
			pushToast(
				unresolved.length > 0
					? tl('routes.form.validationFailed', { reason: unresolved[0] })
					: tl('routes.form.validationFailedGeneric'),
				'danger'
			);
			return;
		}
		try {
			// Step J.3: build the payload from formData. The pool +
			// lbPolicy + healthCheck are shipped explicitly. lbPolicy
			// is sent as the empty string when the selector is
			// hidden (pool size == 1) so the server applies the
			// default round_robin on create / preserves on update.
			// Step K.1: zero out the inactive auth sub-shape based on
			// AuthMode. The server enforces mutual exclusion via
			// validateAuthFieldsMutex; the form mirrors the same
			// invariant on the way out so an in-place mode switch
			// in the radio group never ships stale fields.
			const basicAuth =
				formData.authMode === 'basic'
					? {
							username: formData.basicAuth.username,
							password: formData.basicAuth.password
						}
					: { username: '', password: '' };
			const forwardAuth =
				formData.authMode === 'forward_auth'
					? { providerName: formData.forwardAuth.providerName }
					: { providerName: '' };
			const payload: RouteRequest = {
				host: formData.host,
				// v2.45.2 — a redirecting route ships no pool: an empty
				// backend row would otherwise travel as {url: ""} and be
				// refused by the storage validator.
				upstreams:
					stateChoice === 'redirect'
						? formData.upstreams
								.filter((u) => u.url.trim() !== '')
								.map((u) => ({ url: u.url.trim(), weight: u.weight }))
						: formData.upstreams.map((u) => ({ url: u.url.trim(), weight: u.weight })),
				lbPolicy: lbSelectorVisible ? (formData.lbPolicy as LBPolicy) : '',
				tlsEnabled: formData.tlsEnabled,
				redirectToHttps: formData.redirectToHttps,
				// v2.14.3 — always ship the Disabled checkbox state,
				// full-replacement semantic (mirrors uploadStreamingMode).
				disabled: formData.disabled,
				aliases: formData.aliases.map((a) => a.trim()).filter((a) => a.length > 0),
				authMode: formData.authMode,
				basicAuth,
				forwardAuth,
				requestHeaders: tuplesToRecord(requestHeaderRows),
				responseHeaders: tuplesToRecord(responseHeaderRows),
				wafMode: formData.wafMode,
				acmeChallenge: formData.acmeChallenge,
				// W.5 — country-block always shipped (POST and
				// PUT). Unlike healthCheck's preserve-or-replace
				// pattern, the form always shows the current
				// state and the operator's intent is explicit:
				// "off" is the canonical disabled state, NOT
				// "preserve previous". Mirrors wafMode's
				// always-shipped semantic (which the API maps
				// to preserve-on-empty for PUT, full set on
				// POST). The W.2 API tolerates both modes.
				countryBlock: {
					mode: formData.countryBlock.mode,
					countryList: [...formData.countryBlock.countryList],
					continents: [...formData.countryBlock.continents],
					asns: [...formData.countryBlock.asns],
					// v2.27 — exceptions are deny-only (the API rejects
					// them otherwise); kept in the form state across
					// mode flips but only shipped for deny.
					exceptions: {
						countries:
							formData.countryBlock.mode === 'deny'
								? [...formData.countryBlock.exceptions.countries]
								: [],
						asns:
							formData.countryBlock.mode === 'deny'
								? [...formData.countryBlock.exceptions.asns]
								: []
					},
					statusCode: formData.countryBlock.statusCode
				},
				// path-based-rules Task 9 — route-level IP filter always
				// shipped (POST and PUT), same always-shipped/full-
				// replacement discipline as countryBlock above: the form
				// shows the current state and "off" is the explicit
				// disabled state, not "preserve previous".
				ipFilter: {
					mode: formData.ipFilter.mode,
					cidrs: [...(formData.ipFilter.cidrs ?? [])],
					statusCode: formData.ipFilter.statusCode
				},
				// path-based-rules Task 9 — path rules always shipped as
				// a full-replacement array (possibly empty), mirroring
				// wafExcludeRules/wafExcludeTags. Blank path-prefix rows
				// are dropped (mirrors the aliases/header-tuple trim-and-
				// filter discipline elsewhere in this assembler); the
				// basic-auth block is included only when the toggle is
				// on (rule.basicAuth is undefined otherwise) and always
				// carries a PLAIN password on the wire — the backend
				// hashes it server-side (never send passwordHash).
				//
				// fix/path-rule-empty-500 — sanitizePathRules then drops
				// any rule left with NO active protection (mode "off"
				// ipFilter + no basic-auth username): removing a rule's
				// protection reads as removing the rule, and shipping a
				// dead rule is exactly what the backend 500'd on. It also
				// clears a kept rule's cidrs when its ipFilter mode is
				// "off" (residual CIDRs under "off" are meaningless).
				pathRules: sanitizePathRules(
					formData.pathRules
						.filter((rule) => rule.pathPrefix.trim().length > 0)
						.map((rule) => ({
							pathPrefix: rule.pathPrefix.trim(),
							...(rule.basicAuth
								? {
										basicAuth: {
											username: rule.basicAuth.username,
											password: rule.basicAuth.password ?? ''
										}
									}
								: {}),
							ipFilter: {
								mode: rule.ipFilter?.mode ?? 'off',
								cidrs: [...(rule.ipFilter?.cidrs ?? [])],
								statusCode: rule.ipFilter?.statusCode ?? 0
							},
							// Task 7 (per-path upstream routing) — ship the
							// pool/LB policy only when a pool is actually
							// configured (mirrors the basicAuth conditional
							// spread above), so a pool-less rule doesn't
							// send an empty upstreams array the backend
							// would reject. healthCheck ships whenever the
							// operator has one configured on the rule.
							...(rule.upstreams && rule.upstreams.length > 0
								? {
										upstreams: rule.upstreams.map((u) => ({
											url: u.url,
											weight: u.weight
										})),
										lbPolicy: rule.lbPolicy ?? 'round_robin',
										insecureSkipVerify: !!rule.insecureSkipVerify,
										upstreamTlsServerName: (rule.upstreamTlsServerName ?? '').trim()
									}
								: {}),
							...(rule.healthCheck ? { healthCheck: { ...rule.healthCheck } } : {}),
							// v2.45.3 — the two v2.44 fields. This payload
							// rebuilds each rule field by field, so anything
							// not listed here is dropped on Save — silently,
							// with a success toast, which is exactly how the
							// operator lost a path redirect and saw "config is
							// unchanged" in the log.
							...(rule.matchExact ? { matchExact: true } : {}),
							// v2.56.3 — and the same trap caught the rate limit.
							// The comment above was already there, written after
							// a path redirect was lost the same way; the field was
							// added to the type without it being read.
							...(rule.rateLimit && rule.rateLimit.events > 0
								? {
										rateLimit: {
											events: rule.rateLimit.events,
											window: rule.rateLimit.window,
											...(rule.rateLimit.key ? { key: rule.rateLimit.key } : {})
										}
									}
								: {}),
							// v2.58 — the exemption. Dropped here, an exempted
							// webhook path starts answering with a redirect to the
							// IdP and the calling service breaks, with a green
							// toast to say the save worked.
							...(rule.disableRouteAuth ? { disableRouteAuth: true } : {}),
							// v2.57 — the IdP gate. Dropping this one here would
							// not lose a setting, it would serve a protected
							// path to anyone, with a success toast.
							...(rule.forwardAuth && rule.forwardAuth.providerName.trim() !== ''
								? {
										forwardAuth: {
											providerName: rule.forwardAuth.providerName.trim()
										}
									}
								: {}),
							...(rule.redirect && rule.redirect.target.trim() !== ''
								? {
										redirect: {
											target: rule.redirect.target.trim(),
											statusCode: rule.redirect.statusCode ?? 302
										}
									}
								: {})
						}))
				)
			};
			// Step #R-PROXMOX-HTTPS-LOOP — only ship
			// insecureSkipVerify when the pool is https. On an
			// http-only pool the field is meaningless (the
			// backend self-heals to false either way), and
			// omitting it on PUT triggers the preserve-previous
			// path which is the right shape for an unrelated
			// edit. On https pools ship the explicit boolean so
			// the operator's intent (true or freshly-unchecked
			// false) is full-replacement, mirroring the wafMode
			// always-ship pattern.
			if (poolScheme === 'https') {
				payload.insecureSkipVerify = formData.insecureSkipVerify;
				// v2.60 — shipped even when empty, so clearing the field
				// reaches the server: the API reads "" as an explicit
				// clear and an absent key as "preserve what you have".
				payload.upstreamTlsServerName = formData.upstreamTlsServerName.trim();
			}
			// Phase 4.5 — always ship uploadStreamingMode. No
			// scheme-dependent self-heal applies (the toggle
			// affects WAF body inspection + Caddy buffering on
			// any pool), so the form's explicit value is the
			// authoritative one. On POST this captures the
			// strict-false default cleanly; on PUT it's a full
			// replacement aligned with the visible toggle state.
			payload.uploadStreamingMode = formData.uploadStreamingMode;
			// Step X.2 — always ship wafDisableCRS. Same shape
			// as uploadStreamingMode : POST captures the
			// strict-false default ; PUT is full replacement
			// aligned with the toggle state the operator
			// confirmed via the ADR-D4 dialog.
			payload.wafDisableCRS = formData.wafDisableCRS;
			// Step X Option (c) — always ship the exclusion
			// list (full-replace semantic). POST captures the
			// empty-default cleanly ; PUT replaces with the
			// operator's current list. The server canonicalises
			// (sort + dedup) before persist.
			payload.wafExcludeRules = formData.wafExcludeRules;
			// Step X Option (e) — always ship the tag
			// exclusion list, same full-replace semantic.
			payload.wafExcludeTags = formData.wafExcludeTags;
			// v2.36 — targeted exclusions, same full-replace semantic.
			payload.wafTargetedExclusions = formData.wafTargetedExclusions;
			// v2.37 — guided rules, same full-replace semantic.
			payload.wafCustomRules = formData.wafCustomRules;
			// v2.38 — expert SecLang ("" clears).
			payload.wafSecLang = formData.wafSecLang;
			// Step Q + v2.9.13 Phase Q.2 — rate limit.
			//
			// Toggle ON  → ship the rateLimit object (POST = new,
			//              PUT = full replace).
			// Toggle OFF → ship clearRateLimit:true so the backend
			//              actively clears the previously stored
			//              value. Pre-Phase-Q.2 the OFF case
			//              omitted both fields, which left the
			//              backend in preserve-on-omit mode — the
			//              UI toggle "succeeded" but the state
			//              persisted (operator-reported 2026-06-26
			//              bug closure).
			if (formData.rateLimit !== null) {
				payload.rateLimit = formData.rateLimit;
			} else {
				payload.clearRateLimit = true;
			}
			// Step R Phase 2.b — error-page wiring. Both
			// fields are omitempty on the wire ; we ship them
			// only when non-default to keep the PUT shape
			// tight + preserve-on-omit semantics for unrelated
			// edits (a PUT that doesn't touch error config
			// should NOT clear an existing template ref).
			if (formData.errorPageTemplateId) {
				payload.errorPageTemplateId = formData.errorPageTemplateId;
			}
			const overrideKeys = Object.keys(formData.errorPageOverrides);
			if (overrideKeys.length > 0) {
				// Filter blank-string overrides (operator-meaningful
				// "I cleared this code's override" gesture) before
				// ship — same canonicalisation as the saveTemplate
				// flow on /settings/error-pages.
				const clean: Record<number, string> = {};
				for (const k of overrideKeys) {
					const v = formData.errorPageOverrides[Number(k)];
					if (v && v.trim()) clean[Number(k)] = v;
				}
				if (Object.keys(clean).length > 0) {
					payload.errorPageOverrides = clean;
				}
			}
			// v2.41.2 — the state section's choice is what ships, and
			// it ships only on save. The PUT expresses all three
			// states: `disabled` carries active vs disabled, and a
			// maintenance block carries maintenance. Sending
			// `disabled:false` with no block clears maintenance
			// server-side (internal/api/routes.go, v2.39 rules), so
			// leaving maintenance is simply not shipping the block. A
			// route being created can only be born active or disabled
			// — the control offers nothing else.
			if (stateChoice === 'redirect') {
				// Full replacement, like the maintenance block. Leaving
				// the state is simply not shipping it: the server clears
				// a stored redirect when a PUT re-enables the route
				// without one.
				payload.redirectConfig = {
					target: formData.redirectConfig.target.trim(),
					statusCode: formData.redirectConfig.statusCode,
					preservePath: formData.redirectConfig.preservePath
				};
			}
			if (stateChoice === 'maintenance') {
				payload.maintenanceConfig = {
					retryAfterSeconds: formData.maintenanceConfig.retryAfterSeconds,
					bypassIps: formData.maintenanceConfig.bypassIps
						.map((ip) => ip.trim())
						.filter((ip) => ip.length > 0),
					// v2.18.1 — per-route message (trimmed). Empty → the
					// backend falls back to the global message.
					message: (formData.maintenanceConfig.message ?? '').trim()
				};
			}
			// Step J.2 preserve-or-replace: ship the HC block only
			// if the user touched it. Otherwise omit, letting the
			// server preserve the previously stored value (on PUT)
			// or default to disabled (on POST — emptyFormData makes
			// the un-touched HC zero anyway, but omitting is
			// cleaner and symmetric with PUT).
			if (healthCheckTouched) {
				payload.healthCheck = {
					enabled: formData.healthCheck.enabled,
					uri: formData.healthCheck.uri,
					method: formData.healthCheck.method as 'GET' | 'HEAD',
					interval: formData.healthCheck.interval,
					timeout: formData.healthCheck.timeout,
					expectStatus: formData.healthCheck.expectStatus,
					expectBody: formData.healthCheck.expectBody,
					passes: formData.healthCheck.passes,
					fails: formData.healthCheck.fails,
					hostHeader: formData.healthCheck.hostHeader?.trim() || undefined,
					headers: (() => {
						const h = headersFromRows(healthCheckHeaderRows);
						return Object.keys(h).length > 0 ? h : undefined;
					})()
				};
			}
			// v2.19.0 external-certs SOCLE — cert source is always
			// shipped full-replacement (POST captures the 'acme'
			// default; PUT replaces with the operator's selection).
			// cert_id is shipped ONLY under 'manual' — mirroring the
			// acmeChallenge-only-under-tls discipline, we never
			// synthesize a manual cert reference onto a non-manual
			// route. On a non-manual source the field is omitted so a
			// stale cert_id from a previous manual selection is dropped
			// (the backend clears its stored CertID when CertSource
			// leaves "manual").
			payload.cert_source = formData.cert_source;
			if (formData.cert_source === 'manual') {
				payload.cert_id = formData.cert_id;
			}
			if (formMode === 'create') {
				const saved = await createRoute(payload);
				pushToast(t('routes.toasts.created'), 'success');
				reportRouteCheck(saved.check);
			} else if (editingId) {
				const saved = await updateRoute(editingId, payload);
				pushToast(t('routes.toasts.updated'), 'success');
				reportRouteCheck(saved.check);
			}
			// Bug 1 fix (C11 Pack A polish round 3, 2026-06-06):
			// Save MUST clear editingId so the route-row-selected
			// highlight goes away — same symmetry Cancel has via
			// closePanel(). Previously this only flipped
			// formOpen=false, leaving editingId set and producing
			// a phantom-selected row with no panel open.
			closePanel();
			await loadRoutes();
		} catch (err) {
			if (isConnectionLost(err)) {
				closePanel();
				await reportConnectionLost();
			} else if (err instanceof ApiError && err.code === 'seclang_invalid') {
				// v2.38 — refused SecLang: keep the panel open, show the
				// problems on their line under the editor.
				secLangSaveErrors = (err.params?.errors as SecLangError[] | undefined) ?? [];
				formError = t('wafSecLang.saveRefused');
			} else if (err instanceof ApiError && err.code === 'route_check_rolled_back') {
				// v2.35 — the change broke a working route and was undone:
				// keep the panel open with the explanation.
				//
				// v2.43.1 — when the server could attribute the 503 to the
				// route's own health check, say so. The generic wording
				// sends the operator to check the upstream address, which
				// on that path is the one thing that is not wrong.
				// v2.45.1 — three messages, not two. "maybe" is the
				// honest one: no upstream was available, and Arenet
				// cannot tell from here whether the backend or the
				// probe is at fault, so it names both.
				const key =
					err.params?.cause === 'health_check'
						? 'errors.route_check_rolled_back_health_check'
						: err.params?.cause === 'maybe_health_check'
							? 'errors.route_check_rolled_back_maybe_health_check'
							: 'errors.route_check_rolled_back';
				formError = t(key, {
					host: String(err.params?.host ?? ''),
					detail: String(err.params?.detail ?? err.message)
				});
			} else if (err instanceof ApiError && err.kind === 'validation') {
				// v2.46 — a coded refusal is shown in the operator's
				// language; anything else falls back to the server's own
				// sentence, so an untranslated code stays readable.
				//
				// The field-mapping below still reads the English
				// sentence: it exists to attach a message to the input
				// that caused it, and the server's wording is the stable
				// thing to pattern-match on. The text displayed is the
				// translated one.
				const shown = serverErrorMessage(err);
				const field = fieldFromMessage(err.message);
				if (field) {
					errors = { ...errors, [field]: shown };
				} else {
					formError = shown;
				}
			} else if (auth.state === 'locked') {
				// Day 13 — #R-FRONTEND-PUT-NO-TIMEOUT layer B.
				// If the session lock fired while the save was in
				// flight (heartbeat 403 OR this very request's
				// 403), the LockScreen overlay already mounted on
				// top of the route panel. Suppress the toast — a
				// second alert on top of the unlock dialog is
				// noise + steals operator focus from the password
				// prompt. The 403 is still logged at info level
				// via the client interceptor; nothing is hidden,
				// just deduplicated for the operator.
			} else {
				const msg = err instanceof ApiError ? err.message : String(err);
				pushToast(msg, 'danger');
			}
		} finally {
			submitting = false;
		}
	}

	async function confirmDelete() {
		if (!confirmTarget) return;
		deleting = true;
		try {
			await deleteRoute(confirmTarget.id);
			pushToast(t('routes.toasts.deleted'), 'success');
			confirmTarget = null;
			await loadRoutes();
		} catch (err) {
			if (isConnectionLost(err)) {
				confirmTarget = null;
				await reportConnectionLost();
			} else {
				const msg = err instanceof ApiError ? err.message : String(err);
				pushToast(msg, 'danger');
			}
		} finally {
			deleting = false;
		}
	}

	// v2.45.1 — the verdict in the form has to be live.
	//
	// It was derived from the routes list, which is fetched once on
	// mount: an operator who broke a probe on purpose and watched the
	// section saw nothing change until they reloaded the page. The
	// panel claimed to report the probe and reported a memory of it.
	//
	// Polled only while the edit panel is open on a route with an
	// active check — that is the one moment the number matters, and
	// the routes list is too heavy to poll for the sake of a tab
	// nobody is looking at. refreshRoutes never raises the spinner
	// and keeps the last good list on failure.
	const HEALTH_REFRESH_MS = 10000;
	let healthPollId: ReturnType<typeof setInterval> | null = null;

	async function refreshRoutes() {
		try {
			routes = await listRoutes();
		} catch {
			// A failed tick leaves the page as it was; the next one
			// corrects it.
		}
	}

	$effect(() => {
		const watching = formOpen && editingId !== null && formData.healthCheck.enabled;
		if (watching && healthPollId === null) {
			healthPollId = setInterval(() => {
				if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
				void refreshRoutes();
			}, HEALTH_REFRESH_MS);
		} else if (!watching && healthPollId !== null) {
			clearInterval(healthPollId);
			healthPollId = null;
		}
	});

	onDestroy(() => {
		if (healthPollId !== null) clearInterval(healthPollId);
	});

	async function loadRoutes() {
		loading = true;
		loadError = null;
		try {
			routes = await listRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			loadError = msg;
			pushToast(msg, 'danger');
		} finally {
			loading = false;
		}
	}

	onMount(async () => {
		await Promise.all([
			loadRoutes().then(openEditFromURL),
			loadDNSProvider(),
			loadForwardAuthProviders(),
			loadManagedDomainsForRoutes(),
			loadErrorTemplates()
		]);
	});

	// Step R Phase 2.b — load templates for the dropdown.
	// Failure is non-fatal : the dropdown falls back to
	// "Aucun" as the only option, the operator still gets
	// the built-in Arenet branded default for every route.
	async function loadErrorTemplates(): Promise<void> {
		try {
			const list = await errorTemplatesApi.list();
			// Alpha sort by name for stable dropdown order.
			errorTemplates = list.sort((a, b) => a.name.localeCompare(b.name));
		} catch {
			errorTemplates = [];
		}
	}

	// v2.59 — "Active" counted routes.length, so it was a second
	// copy of "Total" that no state could ever change: a disabled
	// route, one in maintenance and one redirecting all counted as
	// active. "With WAF" had the subtler version of the same bug —
	// it counted a stored wafMode on routes whose WAF is never
	// emitted (see lib/utils/route-gates.ts), so turning the WAF on
	// for a redirecting route moved a number on the dashboard while
	// changing nothing about the traffic.
	const stats = $derived({
		total: routes.length,
		active: routes.filter((r) => routeState(r) === 'active').length,
		tls: routes.filter((r) => r.tlsEnabled).length,
		waf: routes.filter((r) => r.wafMode !== 'off' && gateApplies(r, 'waf')).length
	});

	// Filtered list view. Two independent filters that AND
	// together: the search input (case-insensitive substring on
	// host / aliases / upstream URL) and the segmented Healthy /
	// Alerts tab (Critique 11 Pack A, 2026-06-05).
	//
	// Healthy / Alerts semantics:
	//   - 'all'     → no health filter; show every route
	//   - 'healthy' → only routes with aggregateStatus === 'healthy'
	//     (unknown does NOT count as healthy — gray ≠ green,
	//     consistent with the Topology C13 gate.)
	//   - 'alerts'  → routes in {degraded, down}. Unknown is also
	//     excluded from alerts: we don't have a confirmed problem.
	const filteredRoutes = $derived.by(() => {
		const q = listFilter.trim().toLowerCase();
		let pool = routes;
		if (listTab === 'healthy') {
			pool = pool.filter((r) => r.aggregateStatus === 'healthy');
		} else if (listTab === 'alerts') {
			pool = pool.filter(
				(r) => r.aggregateStatus === 'degraded' || r.aggregateStatus === 'down',
			);
		}
		if (!q) return pool;
		return pool.filter((r) => {
			if (r.host.toLowerCase().includes(q)) return true;
			for (const a of r.aliases ?? []) {
				if (a.toLowerCase().includes(q)) return true;
			}
			for (const u of r.upstreams ?? []) {
				if (u.url.toLowerCase().includes(q)) return true;
			}
			// v2.59 — a redirecting route has no upstream, so until
			// now the only thing matching it was its own host. Its
			// target is the other half of "where does this name go",
			// and it is what the Upstream column now displays.
			const target = r.redirectConfig?.target;
			if (target && target.toLowerCase().includes(q)) return true;
			return false;
		});
	});

	// Map the wire-level aggregate health to a Badge presentation
	// (label + variant). The variant names map directly onto the
	// shared --status-* design tokens, the same ones Topology
	// UpstreamNode / BackendClusterNode + the TLS / Detect /
	// Block badges already in this table use. No inline colors —
	// a future theme change propagates everywhere automatically.
	//
	// Originally rendered as a StatusDot during C11 Pack A; the
	// operator's smoke surfaced the dot-alone was ambiguous to
	// scan, so the polish round swapped it for an explicit
	// uppercase text badge matching the existing pill style.
	// v2.59 — the two tooltips here were hard-coded French string
	// literals, so an operator on the English locale read them in
	// French. They go through i18n like every other string in this
	// file now. The four status LABELS stay as uppercase literals:
	// HEALTHY / DEGRADED / DOWN / UNKNOWN are codes shared with the
	// topology badges, not prose — but HC INACTIF was French, so it
	// moved too.
	function aggregateToBadge(s: Route['aggregateStatus']): {
		label: string;
		variant: 'status-up' | 'status-warn' | 'status-down' | 'neutral';
		tooltip?: string;
		/** Render as a muted dash instead of a pill — "there is no
		 *  state here", as opposed to a state we don't know yet. */
		dash?: boolean;
	} {
		switch (s) {
			case 'not_applicable':
				// v2.59 — a redirecting route answers from Caddy and
				// has no backend to probe. It used to fall into the
				// default arm below and read UNKNOWN, promising a
				// warm-up window that can never close. A dash is the
				// same idiom the TLS column already uses for "this
				// column does not apply to this row".
				return {
					label: '—',
					variant: 'neutral',
					tooltip: language.current ? t('routes.list.statusNotApplicableTooltip') : undefined,
					dash: true
				};
			case 'healthy':
				return { label: 'HEALTHY', variant: 'status-up' };
			case 'degraded':
				return { label: 'DEGRADED', variant: 'status-warn' };
			case 'down':
				return { label: 'DOWN', variant: 'status-down' };
			case 'not_monitored':
				// 2026-06-25 — distinct from "unknown" (warm-up).
				// The operator deliberately chose not to wire HC
				// on this route ; surface the choice explicitly
				// rather than leaving an ambiguous gray badge.
				return {
					label: language.current ? t('routes.list.statusNotMonitored') : 'HC INACTIF',
					variant: 'neutral',
					tooltip: language.current ? t('routes.list.statusNotMonitoredTooltip') : undefined
				};
			default:
				return {
					label: 'UNKNOWN',
					variant: 'neutral',
					tooltip: language.current ? t('routes.list.statusUnknownTooltip') : undefined
				};
		}
	}

	function fmtDate(iso: string): string {
		return new Date(iso).toLocaleString();
	}
</script>

<PageHeader
	eyebrow={language.current && t('routes.pageEyebrow')}
	title={language.current && t('routes.pageTitle')}
	subtitle={language.current && t('routes.pageSubtitle')}
>
	{#snippet actions()}
		<!-- v2.40 — the button is finally wired (it was a disabled
		     placeholder since the first versions). -->
		<Button variant="ghost" onclick={() => (importOpen = true)} data-testid="import-caddyfile-open"
			>{language.current && t('routes.importCaddyfile')}</Button
		>
		<Button onclick={() => guardUnsaved(openCreate)}>{language.current && t('routes.addButton')}</Button>
	{/snippet}
</PageHeader>

<ImportCaddyfileModal
	open={importOpen}
	onClose={() => (importOpen = false)}
	onImported={() => void loadRoutes()}
/>

<!-- Step J.4 (β) bandeau: at least one persisted route uses
     DNS-01 ACME but the OVH DNS provider is not configured (or is
     partially configured). The (α) edit-time validation prevents
     creating new dns-01 routes in this state; this bandeau catches
     the case where the provider is removed AFTER routes were
     saved. Cert renewal will fail until the provider is
     re-completed. -->
{#if dns01Inconsistent}
	<div
		class="mt-4 mb-2 rounded border border-down/40 bg-down/10 px-4 py-3 text-sm text-down"
		role="alert"
	>
		<strong class="font-semibold">{language.current && t('routes.dns01Banner.title')}</strong>
		{language.current && t('routes.dns01Banner.message')}
		<a href="/settings" class="underline">{language.current && t('routes.dns01Banner.settingsLink')}</a>{language.current && t('routes.dns01Banner.tail')}
	</div>
{/if}

{#if loading}
	<div class="flex items-center gap-2 mt-12 text-secondary">
		<Spinner /> {language.current && t('routes.loadingLabel')}
	</div>
{:else if loadError}
	<div class="mt-12 text-down" role="alert">{language.current && t('routes.loadFailed', { err: loadError })}</div>
{:else if routes.length === 0 && !formOpen}
	<!-- Empty-state CTA. Skipped when formOpen is true so the new-
	     route create flow drops directly into the split layout's
	     right panel (operator who clicked "+ Add route" expects to
	     see the form, not an empty-state encore). -->
	<div class="mt-16 flex flex-col items-center text-center gap-4">
		<div class="text-6xl text-muted">◉</div>
		<p class="text-secondary">{language.current && t('routes.emptyState')}</p>
		<Button onclick={() => guardUnsaved(openCreate)}
			>{language.current && t('routes.emptyStateAddFirst')}</Button
		>
	</div>
{:else}
	<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-6">
		<StatCard label={language.current && t('routes.stats.total')} value={stats.total} testid="stat-card-total" />
		<StatCard label={language.current && t('routes.stats.active')} value={stats.active} testid="stat-card-active" />
		<StatCard label={language.current && t('routes.stats.withTLS')} value={stats.tls} testid="stat-card-tls" />
		<StatCard label={language.current && t('routes.stats.withWAF')} value={stats.waf} testid="stat-card-waf" />
	</div>

	<!-- Phase 1 split layout (2026-06-02) — replaces the Step I/J
	     DataTable + Modal-form combo with a 2-column grid: list on
	     the left, sticky edit panel on the right. The form contents
	     are unchanged; only the wrapping moved out of Modal into
	     the right-card.
	     Tests rely on the "+ Add route" button + form-field labels
	     being queryable AFTER an openCreate click — that contract
	     holds: openCreate() still flips formOpen=true and the
	     right-card renders the same Input/Checkbox/select fields. -->
	<div class="split mt-6" class:split-open={formOpen} style="--split-open-cols: 1.3fr 1fr">
		<!-- LEFT — routes list -->
		<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden">
			<div class="px-4 py-3 border-b border-border-subtle flex items-center gap-3 flex-wrap">
				<!-- Search input — filters host / aliases / upstream URL
				     substring via the filteredRoutes $derived. -->
				<div class="flex-1 min-w-[200px] flex items-center gap-2 px-2 py-1 rounded-md bg-surface border border-border-default">
					<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
						<circle cx="7" cy="7" r="5" />
						<path d="M11 11l3 3" />
					</svg>
					<input
						type="search"
						bind:value={listFilter}
						placeholder={language.current && t('routes.list.filterPlaceholder')}
						aria-label={language.current && t('routes.list.filterAriaLabel')}
						class="flex-1 bg-transparent outline-none text-sm text-primary placeholder-muted"
					/>
				</div>
				<!-- Segmented tabs, filtering on aggregateStatus. All
				     three work; they stopped being stubs when Pack A
				     put the per-route rollup on the wire. Note that a
				     route with no health (redirect: not_applicable)
				     appears under All only, which is now the honest
				     answer rather than a side effect of 'unknown'. -->
				<div class="inline-flex gap-0.5 p-0.5 rounded-full bg-surface border border-border-default text-xs">
					<button
						type="button"
						onclick={() => (listTab = 'all')}
						class="px-3 py-1 rounded-full transition-colors"
						class:bg-hover={listTab === 'all'}
						class:text-primary={listTab === 'all'}
						class:text-secondary={listTab !== 'all'}
					>{language.current && t('routes.list.tabAll')}</button>
					<button
						type="button"
						onclick={() => (listTab = 'healthy')}
						class="px-3 py-1 rounded-full transition-colors"
						class:bg-hover={listTab === 'healthy'}
						class:text-primary={listTab === 'healthy'}
						class:text-secondary={listTab !== 'healthy'}
					>{language.current && t('routes.list.tabHealthy')}</button>
					<button
						type="button"
						onclick={() => (listTab = 'alerts')}
						class="px-3 py-1 rounded-full transition-colors"
						class:bg-hover={listTab === 'alerts'}
						class:text-primary={listTab === 'alerts'}
						class:text-secondary={listTab !== 'alerts'}
					>{language.current && t('routes.list.tabAlerts')}</button>
				</div>
			</div>

			{#if filteredRoutes.length === 0}
				<div class="p-6 text-center text-sm text-secondary">
					{language.current &&
						(routes.length === 0
							? t('routes.emptyState')
							: t('routes.noMatchFilter'))}
				</div>
			{:else}
				<table class="w-full text-sm" bind:this={tableEl}>
					<thead>
						<tr class="text-left text-xs uppercase tracking-wider text-secondary border-b border-border-subtle">
							<th class="px-4 py-3 font-medium">{language.current && t('routes.list.colHost')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('routes.list.colUpstream')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('routes.list.colTLS')}</th>
							<th class="px-4 py-3 font-medium">{language.current && t('routes.list.colSecurity')}</th>
							<th class="px-4 py-3 font-medium text-center">{language.current && t('routes.list.colState')}</th>
							<!-- Task 9 — was sr-only (icon-only ghost button
							     needed no visible header); now a visible
							     column header since the cell holds the
							     3-state RouteStateControl, a labeled
							     interactive control worth naming in the
							     table's structure for sighted + assistive
							     users alike. v2.17.1 Item B — centered
							     (was text-right) so the header sits over
							     the now-compact, icon-only control. -->
							<th class="px-4 py-3 font-medium text-center">{language.current && t('routes.list.colActions')}</th>
						</tr>
					</thead>
					<tbody>
						{#each filteredRoutes as r (r.id)}
							{@const selected = editingId === r.id}
							{@const statusBadge = aggregateToBadge(r.aggregateStatus)}
							<tr
								class="route-row border-b border-border-subtle last:border-b-0 cursor-pointer transition-colors hover:bg-hover"
								class:route-row-selected={selected}
								class:opacity-50={r.disabled}
								data-testid={selected ? 'route-row-selected' : 'route-row'}
								onclick={() => selectOrToggleRoute(r)}
								onkeydown={(e) => {
									if (e.key === 'Enter' || e.key === ' ') {
										e.preventDefault();
										selectOrToggleRoute(r);
									}
								}}
								tabindex="0"
								aria-current={selected ? 'true' : undefined}
								role="button"
							>
								<td class="px-4 py-3 font-mono">
									<!-- v2.17.1 Item C — the Maintenance /
									     Disabled text badges that used to sit
									     here were REMOVED: the RouteStateControl
									     (Actions column) now carries the state
									     via its fill color + active segment, so
									     the badges were a redundant text
									     duplicate. The dimmed row (opacity-50,
									     set via class:opacity-50={r.disabled}
									     on the <tr>) remains as the secondary
									     disabled cue. -->
									{r.host}
									{#if r.aliases && r.aliases.length > 0}
										<span
											class="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-sans text-secondary bg-elevated border border-border-subtle cursor-help"
											title={language.current && `${t('routes.list.aliasesTooltip')}\n${r.aliases.join('\n')}`}
										>+{r.aliases.length}</span>
									{/if}
									<!-- v2.59 — gated on gateApplies: the lock /
									     arrow icon claims "this host asks for
									     credentials". On a route that proxies
									     nothing (redirect, maintenance) no auth
									     handler is emitted, so the icon was
									     promising a gate that does not exist. -->
									{#if gateApplies(r, 'auth') && r.authMode === 'basic'}
										<span
											class="ml-1.5 inline-flex items-center text-muted cursor-help"
											title={language.current && t('routes.list.basicAuthTooltip', { username: r.basicAuth?.username ?? '' })}
											aria-label={language.current && t('routes.list.basicAuthRequired')}
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												class="w-3.5 h-3.5"
												viewBox="0 0 24 24"
												fill="none"
												stroke="currentColor"
												stroke-width="2"
												stroke-linecap="round"
												stroke-linejoin="round"
												aria-hidden="true"
											>
												<rect width="18" height="11" x="3" y="11" rx="2" />
												<path d="M7 11V7a5 5 0 0 1 10 0v4" />
											</svg>
										</span>
									{:else if gateApplies(r, 'auth') && r.authMode === 'forward_auth'}
										<span
											class="ml-1.5 inline-flex items-center text-muted cursor-help"
											title={language.current && t('routes.list.forwardAuthTooltip', { provider: r.forwardAuth?.providerName ?? '' })}
											aria-label={language.current && t('routes.list.forwardAuthRequired')}
										>
											<svg
												xmlns="http://www.w3.org/2000/svg"
												class="w-3.5 h-3.5"
												viewBox="0 0 24 24"
												fill="none"
												stroke="currentColor"
												stroke-width="2"
												stroke-linecap="round"
												stroke-linejoin="round"
												aria-hidden="true"
											>
												<path d="M21 12H9" />
												<path d="m12 5 7 7-7 7" />
												<path d="M5 21V3" />
											</svg>
										</span>
									{/if}
								</td>
								<td
									class="px-4 py-3 font-mono text-secondary truncate max-w-[14rem]"
									title={r.redirectConfig?.target ?? r.upstreams[0]?.url ?? ''}
								>
									{#if r.redirectConfig}
										<!-- v2.59 — a redirecting route has no
										     upstream, so this cell was simply
										     blank: the one fact that matters
										     about the route — where it sends
										     the visitor — appeared nowhere in
										     the list, and was not searchable
										     either. The column answers "where
										     does this traffic go", and for a
										     redirect the answer is the target. -->
										<span class="text-muted">→</span>
										<span data-testid="redirect-target-cell">{r.redirectConfig.target}</span>
									{:else}
										{r.upstreams[0]?.url ?? ''}{r.upstreams.length > 1
											? ` (+${r.upstreams.length - 1})`
											: ''}
									{/if}
									<!-- Critique 11 Pack A: "N/M sains" counter on
									     multi-upstream routes whose HC tracker has
									     a verdict. Hidden for single-upstream
									     pools (noise) and for unknown-status pools
									     (no verdict to count). -->
									{#if r.totalUpstreamCount > 1 && r.aggregateStatus !== 'unknown' && r.aggregateStatus !== 'not_monitored'}
										<span class="ml-1 text-xs text-muted"
											>· {language.current && t('routes.list.healthyCounter', { healthy: r.healthyUpstreamCount, total: r.totalUpstreamCount })}</span>
									{/if}
								</td>
								<td class="px-4 py-3">
									{#if r.tlsEnabled}
										<!-- Sujet 2 (2026-06-17) — CertSourceBadge
										     surfaces the covering apex on the badge
										     label ("Couvert par *.example.com")
										     instead of hiding it in a tooltip the
										     operator had to discover. Single source
										     of truth for the cert-source copy
										     (lib/utils/effective-cert-source.ts);
										     all variants (managed-domain / per-
										     route-acme dns-01 / per-route-acme
										     http-01 / per-route-internal) handled
										     in one component, so a future variant
										     lands here too. -->
										<div class="flex flex-wrap items-center gap-1">
											<Badge variant="tls">{language.current && t('routes.list.tlsBadge')}</Badge>
											<CertSourceBadge
												source={r.effectiveCertSource}
												certName={manualCertDisplayName(r.cert_id, externalCerts)}
											/>
										</div>
									{:else}
										<span class="text-muted">—</span>
									{/if}
								</td>
								<td class="px-4 py-3">
									<!-- v2.41 — the column answers "what guards this
									     route?", not just "is the WAF on?": the geo,
									     IP-filter and rate-limit postures were
									     invisible from the list until now.

									     v2.61 — and it is now the door to the page
									     that details it. The chips named the WAF, the
									     geo gate and the rate limit while being
									     cursor-help text with a tooltip, when
									     /security/<id> is exactly the screen that
									     explains them. The information and the link
									     are the same object; the list had no entry
									     point to either per-route page before this.
									     stopPropagation so the row's own click does
									     not open the edit panel underneath. -->
									<a
										href={`/security/${r.id}`}
										class="cell-pivot"
										data-testid="row-pivot-security"
										title={language.current && t('routes.list.securityPivotTitle')}
										onclick={(e) => e.stopPropagation()}
									>
										<RoutePostureChips route={r} />
									</a>
								</td>
								<td class="px-4 py-3 text-center">
									<!-- Critique 11 Pack A (2026-06-05): per-route
									     health rollup driven by the Stage B HC
									     tracker. aggregateToBadge maps the wire-
									     level enum to a Badge label + variant,
									     sharing the --status-* CSS tokens with
									     Topology AND the existing TLS / Detect /
									     Block badges in this same table. The
									     Healthy / Alerts segmented tabs above
									     filter on the same aggregateStatus.
									     Polish round (2026-06-06): removed the
									     redundant per-row "Edit" button — the
									     whole <tr> is the affordance (cursor-
									     pointer + hover tint + selected accent),
									     matching the mock and avoiding the
									     double-action anti-pattern. -->
									<!-- v2.61 — the state badge is the door to the route's
									     performance page. Same reasoning as the Security
									     column: the badge already names the health, and
									     /observability/<id> is the screen that charts it.
									     Skipped for the not_applicable dash, which links to
									     nothing worth reading. -->
									{#if statusBadge.dash}
										<span
											title={statusBadge.tooltip}
											class="text-muted cursor-help"
											data-testid="route-status-dash">{statusBadge.label}</span>
									{:else}
										<a
											href={`/observability/${r.id}`}
											class="cell-pivot"
											data-testid="row-pivot-metrics"
											title={statusBadge.tooltip ?? (language.current && t('routes.list.metricsPivotTitle'))}
											onclick={(e) => e.stopPropagation()}
										>
											<Badge variant={statusBadge.variant}>{statusBadge.label}</Badge>
										</a>
									{/if}
								</td>
								<td class="px-4 py-3 text-center">
									<!-- Task 9 — row-level 3-state control,
									     replacing the v2.14.3 Activer/Désactiver
									     ghost button. stopPropagation on the
									     wrapper so a segment click doesn't also
									     fire the row's onclick (which would open
									     the edit panel). onRouteStateChange
									     routes 'disabled' to the existing
									     ConfirmDialog-gated flow (destructive:
									     stops traffic; last-HTTPS warning lives
									     there) and 'maintenance'/'active' to
									     direct, always-safe calls. v2.17.1 Item
									     B — centered (was text-right) to match
									     the centered header + the narrower
									     icon-only control. -->
									<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
									<div class="flex justify-center" onclick={(e) => e.stopPropagation()}>
										{#if r.redirectConfig}
											<!-- v2.44 — a redirect cannot be switched on from
											     a row: the dedicated maintenance/disable
											     endpoints take no argument, and a redirect
											     needs a target. The row states it, the form
											     changes it. -->
											<Badge variant="status-warn">
												{language.current && t('routes.state.redirect')}
											</Badge>
										{:else}
										<RouteStateControl
											value={rowState(r)}
											ariaLabel={language.current && t('routes.list.colActions')}
											labels={language.current && {
												active: t('routes.state.active'),
												maintenance: t('routes.state.maintenance'),
												disabled: t('routes.state.disabled')
											}}
											onchange={(next) => onRouteStateChange(r, next)}
										/>
										{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		<!-- RIGHT — route detail / edit panel. Sticky on wide
		     screens so it stays in view as the left list scrolls.
		     bind:this + use:clickOutsideToClose wire the
		     C11 Pack A polish round 3 dismiss-on-outside-click
		     behaviour: a document mousedown landing outside this
		     element AND outside the routes table closes the
		     panel. Clicks on the table are left to the row
		     onclick handlers (selectOrToggleRoute) so the toggle
		     semantic for the already-selected row works without
		     racing the outside listener. -->
		<div
			bind:this={panelEl}
			use:clickOutsideToClose
			class="relative rounded-lg border border-border-subtle bg-elevated xl:sticky xl:top-[calc(var(--tb-height)+14px)] xl:max-h-[calc(100vh-var(--tb-height)-40px)] overflow-auto"
		>
			{#if !formOpen}
				<!-- Empty state: nothing selected, not in create mode. -->
				<div class="p-10 text-center text-secondary text-sm">
					{language.current && t('routes.panel.emptyHint')}
					<span class="font-medium text-primary">{language.current && t('routes.panel.emptyHintAction')}</span>
					{language.current && t('routes.panel.emptyHintTail')}
				</div>
			{:else}
				<!-- Panel header — pill + title + meta. The pill border
				     uses `border-cyan` (full opacity, same hue as the
				     text) instead of the previous `border-cyan/30`
				     which Tailwind v4 was resolving to a default-gray
				     fallback (reading as a white-ish outline on dark
				     mode and clashing visually with the cyan text). -->
				<!-- v2.41 — the panel header sticks while the sections scroll,
				     and says when there is something to save. -->
				<div class="sticky top-0 z-10 bg-elevated px-5 py-4 border-b border-border-subtle flex flex-col gap-2">
					<div class="flex items-center gap-3">
					<span class="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] uppercase tracking-wider font-mono bg-accent-soft text-cyan border border-cyan">
						{language.current && (formMode === 'create' ? t('routes.panel.pillNew') : t('routes.panel.pillEdit'))}
					</span>
					<h3 class="text-base font-semibold text-primary truncate">
						{language.current && (formMode === 'create' ? t('routes.panel.titleNew') : (formData.host || t('routes.panel.titleEdit')))}
					</h3>
					{#if formDirty}
						<span class="ml-auto text-xs text-warn shrink-0" data-testid="form-dirty">
							{language.current && t('routes.panel.unsaved')}
						</span>
					{/if}
					{#if formMode === 'edit' && editingId}
						<span class="text-xs text-muted font-mono shrink-0" class:ml-auto={!formDirty}>{language.current && t('routes.panel.idLabel')} <span class="text-secondary">{editingId.slice(0, 7)}</span></span>
					{/if}
					</div>
				<!-- v2.41.1 — the two drill-down links used to sit in a row
				     BELOW the sticky header, so they scrolled out of sight as
				     soon as the operator moved down the form. They belong to
				     the route's identity, so they live in the header itself
				     and stay reachable. Delete moved to the footer, away from
				     Save: a destructive action does not share a row with the
				     links you click to read a chart.

				     v2.61 — they were 11px text-secondary chips with no fill,
				     in the third row of the header, and absent in create mode.
				     The operator said it plainly: "on ne voit pas très bien les
				     boutons et comment y arriver". They now carry real button
				     chrome, and they are PRESENT but disabled before the first
				     save, with the reason — a control that appears only once
				     you have guessed it exists teaches nothing. -->
				<div class="flex flex-wrap items-center gap-2" data-testid="panel-pivots">
					{#if formMode === 'edit' && editingId}
						<a
							href={`/observability/${editingId}`}
							data-testid="panel-pivot-metrics"
							class="pivot-btn"
						>
							<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
								<path d="M3 3v10h10" />
								<path d="M5 11l3-3 2 2 3-4" />
							</svg>
							{language.current && t('routes.panel.metricsLink')}
						</a>
						<a
							href={`/security/${editingId}`}
							data-testid="panel-pivot-security"
							class="pivot-btn"
						>
							<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
								<rect x="3" y="7" width="10" height="7" rx="1" />
								<path d="M5 7V5a3 3 0 016 0v2" />
							</svg>
							{language.current && t('routes.panel.securityLink')}
						</a>
					{:else}
						<span class="pivot-btn pivot-btn-disabled" data-testid="panel-pivot-pending"
							title={language.current && t('routes.panel.pivotsAfterSave')}>
							{language.current && t('routes.panel.pivotsAfterSave')}
						</span>
					{/if}

					<!-- Four numbers, same row as the link that explains
					     them: the strip is for the glance, the link is for
					     the chart. Rendered only once there is something
					     true to say — no skeleton, no zeros while loading,
					     because a zero here is indistinguishable from a
					     real "this route served nothing". -->
					{#if routeSummary}
						<div
							class="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted"
							data-testid="panel-metrics-strip"
						>
							{#if routeSummary.disabled}
								<span data-testid="panel-metrics-unavailable"
									>{language.current && t('routes.panel.stripUnavailable')}</span
								>
							{:else if routeSummary.reqs === 0}
								<span data-testid="panel-metrics-nodata"
									>{language.current && t('routes.panel.stripNoData')}
									<span class="text-secondary"
										>· {language.current && t('routes.panel.stripWindow')}</span
									></span
								>
							{:else}
								<span data-testid="panel-metrics-reqs">
									<span class="text-primary font-medium tabular-nums"
										>{routeSummary.reqs.toLocaleString(language.current)}</span
									>
									{language.current && t('routes.panel.stripReqs')}
								</span>
								<span data-testid="panel-metrics-fourxx">
									<span class="text-secondary tabular-nums"
										>{routeSummary.fourxx.toLocaleString(language.current)}</span
									>
									{language.current && t('routes.panel.stripFourxx')}
								</span>
								<!-- Only the 5xx gets a colour. A 4xx is ordinary
								     traffic on a public host (bots probing for
								     /wp-login.php); tinting it would cry wolf on
								     every route. A 5xx is the upstream failing. -->
								<span data-testid="panel-metrics-fivexx">
									<span
										class="tabular-nums"
										class:text-secondary={routeSummary.fivexx === 0}
										class:text-down={routeSummary.fivexx > 0}
										class:font-medium={routeSummary.fivexx > 0}
										>{routeSummary.fivexx.toLocaleString(language.current)}</span
									>
									{language.current && t('routes.panel.stripFivexx')}
								</span>
								<!-- Two latency figures, because one cannot answer the
								     question. The operator read "p95 6701 ms" on a blog
								     that loads instantly: the server had answered in
								     0.1 s and the remaining 23.9 s was a visitor
								     downloading a 2.9 MB file. Total duration carries
								     the transfer; TTFB stops when the response
								     committed. Shown side by side, the gap between
								     them IS the diagnosis. -->
								{#if routeSummary.samples === 0 && routeSummary.reqs > 0}
									<!-- Requests were counted and no distribution was
									     recorded for them. That is the upgrade boundary,
									     NOT thin traffic, and saying "too few requests"
									     here would be a plain lie on a route serving
									     44,673 of them — which is exactly what the
									     operator's instance returned the hour the
									     release landed.
									     The two cases read identically on the wire
									     (samples below the threshold, quantiles null)
									     and mean completely different things. -->
									<span
										class="text-secondary"
										data-testid="panel-metrics-nohist"
										title={language.current && t('routes.panel.stripNoHistogramHint')}
									>
										{language.current && t('routes.panel.stripNoHistogram')}
									</span>
								{:else if routeSummary.samples < MIN_QUANTILE_SAMPLES}
									<!-- Genuinely thin traffic. Below twenty
									     observations ceil(0.95 * n) === n, so a "p95" is
									     just the slowest request. The API returns null;
									     this says WHY, because a bare dash teaches
									     nothing. -->
									<span class="text-secondary" data-testid="panel-metrics-thin">
										{language.current && t('routes.panel.stripThinData')}
									</span>
								{:else}
									<span data-testid="panel-metrics-ttfb">
										{language.current && t('routes.panel.stripP95')}
										<span class="text-primary font-medium tabular-nums"
											>{formatMs(routeSummary.ttfbMs)}</span
										>
										{language.current && t('routes.panel.stripTtfb')}
									</span>
									<span data-testid="panel-metrics-total">
										<span class="text-secondary tabular-nums"
											>{formatMs(routeSummary.totalMs)}</span
										>
										{language.current && t('routes.panel.stripTotal')}
									</span>
								{/if}
								{#if routeSummary.bytesOut > 0}
									<span data-testid="panel-metrics-bytes">
										<span class="text-secondary tabular-nums"
											>{formatBytes(routeSummary.bytesOut, language.current)}</span
										>
										{language.current && t('routes.panel.stripBytes')}
									</span>
								{/if}
								{#if routeSummary.hijacked > 0}
									<!-- Explains a missing TTFB rather than leaving the
									     operator to wonder: these never committed a
									     response, so there was no first byte to time. -->
									<span
										class="text-secondary"
										data-testid="panel-metrics-hijacked"
										title={language.current && t('routes.panel.stripHijacked')}
									>
										{routeSummary.hijacked.toLocaleString(language.current)} WS
									</span>
								{/if}
								{#if routeSummary.partialHistogram}
									<span
										class="text-warn"
										data-testid="panel-metrics-partial"
										title={language.current && t('routes.panel.stripPartialHint')}
									>
										{language.current && t('routes.panel.stripPartial')}
									</span>
								{/if}
								<span class="text-secondary" data-testid="panel-metrics-window"
									>· {language.current && t('routes.panel.stripWindow')}</span
								>
							{/if}
						</div>
					{/if}
				</div>
				</div>

				<!-- Form body — moved verbatim out of the prior Modal
				     wrapper. All field bindings, validation, and
				     submit flow are unchanged. -->
				<form
					onsubmit={(e) => {
						e.preventDefault();
						// submitForm() carries its own `if
						// (submitting) return` guard since v2.9.7,
						// so a form-Enter + button-click combo is
						// safe — the 2nd entry is a no-op.
						submitForm();
					}}
					class="flex flex-col gap-4 p-5"
				>
					{#if formError}
						<p
							class="px-3 py-2 rounded bg-down/10 border border-down/40 text-sm text-down"
							role="alert"
						>
							{formError}
						</p>
					{/if}
					<!-- v2.41 — the form is read as one collapsible section per concern;
					     each closed row carries the state it holds (see RouteSection). -->
					<!-- v2.41.1 — State first: what the route does right now is
					     read before anything else, and the operator asked for it
					     at the top. The three states are exclusive, so they are a
					     segmented control like the country filter's — and, like
					     the icons in the routes list, picking one APPLIES it
					     through the dedicated endpoints (disable keeps its
					     confirm dialog and its last-HTTPS warning). The
					     maintenance settings appear only under Maintenance,
					     because that is the only state they describe. -->
					<RouteSection
						name={language.current && t('routes.form.sectionState')}
						summary={summaryState}
						badge={stateBadge.badge}
						posture={stateBadge.posture}
						testid="section-state"
					>
						<ModeSelector
							id="route-state"
							bind:value={stateChoice}
							options={stateOptions}
							onchange={onFormStateChange}
							ariaLabel={language.current && t('routes.form.sectionState')}
						/>
						{#if formMode !== 'edit'}
							<p class="text-xs text-muted" data-testid="state-create-hint">
								{language.current && t('routes.form.stateCreateHint')}
							</p>
						{/if}
						{#if stateChoice === 'redirect'}
							<!-- v2.44 — the redirect state's fields. The route
							     stops proxying and answers a 301/302; the
							     target must be a DIFFERENT host, which the
							     server refuses at save with an explanation
							     rather than letting the operator discover the
							     loop from their browser. -->
							<div
								class="flex flex-col gap-3 p-3 rounded-md border border-border-subtle"
								data-testid="redirect-fields"
							>
								<span class="text-sm font-medium text-secondary">
									{language.current && t('routes.form.redirect.sectionTitle')}
								</span>
								<div class="flex flex-col gap-1">
									<!-- v2.45.2 — the shared Input, like every other
									     field on this form. A bare <input class="input">
									     inherited nothing and rendered white on white:
									     the operator could not read what they typed. -->
									<Input
										id="redirect-target"
										type="url"
										label={language.current && t('routes.form.redirect.targetLabel')}
										placeholder="https://new.example.com"
										bind:value={formData.redirectConfig.target}
										data-testid="redirect-target"
									/>
									<span class="text-xs text-muted"
										>{language.current && t('routes.form.redirect.targetHelper')}</span
									>
								</div>

								<ModeSelector
									id="redirect-status"
									value={String(formData.redirectConfig.statusCode)}
									options={redirectCodeOptions}
									onchange={(v) => (formData.redirectConfig.statusCode = Number(v))}
									ariaLabel={language.current && t('routes.form.redirect.codeLabel')}
								/>

								<SwitchRow
									checked={formData.redirectConfig.preservePath}
									onchange={(v) => (formData.redirectConfig.preservePath = v)}
									label={language.current && t('routes.form.redirect.preservePathLabel')}
									helper={language.current && t('routes.form.redirect.preservePathHelper')}
									testid="redirect-preserve-path"
								/>

								<p class="text-xs text-muted" data-testid="redirect-warning">
									{language.current && t('routes.form.redirect.noProxyWarning')}
								</p>
							</div>
						{/if}
						{#if stateChoice === 'maintenance'}
						<!-- Task 9 — Maintenance section. Shown always (not
						     gated behind the route's current state) so an
						     operator can pre-configure retryAfter / bypass
						     IPs before switching the row's 3-state control
						     to "Maintenance", and can still tune them while
						     already in maintenance. The section itself
						     doesn't turn maintenance on/off — that's the
						     RouteStateControl's job via the dedicated
						     enterMaintenance/exitMaintenance endpoints; this
						     is config-only, shipped full-replacement on every
						     submit (see payload.maintenanceConfig above). -->
						<div class="flex flex-col gap-2 p-3 rounded-md border border-border-subtle">
							<span class="text-sm font-medium text-secondary">
								{language.current && t('routes.form.maintenance.sectionTitle')}
							</span>
							<!-- v2.18.0 — friendly Retry-After: number + unit
							     selector. The wire value (retryAfterSeconds,
							     recomputed via syncRetryAfterSeconds) stays in
							     seconds; the operator picks e.g. "5 minutes"
							     instead of typing "300". -->
							<div class="flex flex-col gap-1">
								<span class="text-sm text-secondary">
									{language.current && t('routes.form.maintenance.retryAfter')}
								</span>
								<div class="flex items-center gap-2">
									<div class="w-28">
										<Input
											type="number"
											min="0"
											value={String(retryValue)}
											aria-label={language.current &&
												t('routes.form.maintenance.retryAfterValueAria')}
											oninput={(e: Event) => {
												const raw = (e.target as HTMLInputElement).value;
												const n = parseInt(raw, 10);
												retryValue = Number.isNaN(n) || n < 0 ? 0 : n;
												syncRetryAfterSeconds();
											}}
										/>
									</div>
									<select
										class="h-9 rounded-md border border-border-subtle bg-surface px-2 text-sm text-primary"
										aria-label={language.current &&
											t('routes.form.maintenance.retryAfterUnitAria')}
										bind:value={retryUnit}
										onchange={syncRetryAfterSeconds}
									>
										{#each RETRY_UNITS as u (u)}
											<option value={u}>{language.current && t(`routes.form.maintenance.unit.${u}`)}</option>
										{/each}
									</select>
								</div>
								<span class="text-xs text-muted">
									{language.current &&
										t('routes.form.maintenance.retryAfterHelp', {
											seconds: String(formData.maintenanceConfig.retryAfterSeconds)
										})}
								</span>
							</div>
							<!-- v2.18.1 — per-route maintenance message. Empty → the
							     global message (Settings → Error Pages → Maintenance)
							     is used instead. -->
							<div class="flex flex-col gap-1">
								<span class="text-sm text-secondary">
									{language.current && t('routes.form.maintenance.message')}
								</span>
								<textarea
									class="w-full box-border resize-y rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary"
									rows="2"
									bind:value={formData.maintenanceConfig.message}
									placeholder={t('routes.form.maintenance.messagePlaceholder')}
									aria-label={language.current && t('routes.form.maintenance.message')}
								></textarea>
								<span class="text-xs text-muted">
									{language.current && t('routes.form.maintenance.messageHelp')}
								</span>
							</div>
							<div class="flex flex-col gap-2">
								<div class="flex items-center justify-between">
									<span class="text-sm text-secondary">
										{language.current && t('routes.form.maintenance.bypassIps')}
									</span>
									<Button variant="ghost" size="sm" onclick={addBypassIp} type="button"
										>{language.current && t('routes.form.maintenance.bypassIpsAdd')}</Button
									>
								</div>
								<div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2" data-testid="maintenance-bypass-ip-grid">
									{#each formData.maintenanceConfig.bypassIps as _, i (i)}
										<div class="flex items-center gap-2">
											<div class="flex-1">
												<Input
													bind:value={formData.maintenanceConfig.bypassIps[i]}
													placeholder="10.0.0.5 or 192.168.1.0/24"
												/>
											</div>
											<Button variant="ghost" size="sm" onclick={() => removeBypassIp(i)} type="button">×</Button>
										</div>
									{/each}
								</div>
							</div>
						</div>
						{/if}
					</RouteSection>

					<RouteSection name={language.current && t('routes.form.sectionEssentials')} summary={summaryEssentials} open testid="section-essentials">
						<Input
							label={language.current && t('routes.form.hostLabel')}
							bind:value={formData.host}
							placeholder={language.current && t('routes.form.hostPlaceholder')}
							error={errors['host'] ?? undefined}
						/>
						<!-- Step I.3: alias hostnames repeater. Auto-fit grid so
						     multiple aliases sit side by side and wrap to width
						     instead of stacking and pushing the form down. -->
						<div class="flex flex-col gap-2">
							<div class="flex items-center justify-between">
								<span class="text-sm text-secondary">{language.current && t('routes.form.aliasesLabel')}</span>
								<Button variant="ghost" size="sm" onclick={addAlias} type="button">{language.current && t('routes.form.aliasesAdd')}</Button>
							</div>
							<div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2" data-testid="alias-grid">
								{#each formData.aliases as _, i (i)}
									<div class="flex items-center gap-2">
										<div class="flex-1">
											<Input bind:value={formData.aliases[i]} placeholder={language.current && t('routes.form.aliasesPlaceholder')} />
										</div>
										<Button variant="ghost" size="sm" onclick={() => removeAlias(i)} type="button">×</Button>
									</div>
								{/each}
							</div>
						</div>
						<!-- Step J.3: upstream pool repeater (replaces the Step I single
						     Upstream URL input). Each row binds to one pool element.
						     The weight column is hidden unless lbPolicy is
						     weighted_round_robin. Per-row state is preserved across
						     visibility flips. -->
						<div class="flex flex-col gap-2">
							<div class="flex items-center justify-between">
								<span class="text-sm font-medium text-secondary">{language.current && t('routes.form.upstreamsLabel')}</span>
								<div class="flex items-center gap-2">
									<Button
										variant="ghost"
										size="sm"
										onclick={runAllUpstreamTests}
										type="button"
										disabled={formData.upstreams.every((u) => u.url.trim() === '')}
										data-testid="test-all-upstreams"
									>
										{language.current && t('routes.form.upstreamsTestAll')}
									</Button>
									<Button variant="ghost" size="sm" onclick={addUpstream} type="button"
										>{language.current && t('routes.form.upstreamsAdd')}</Button
									>
								</div>
							</div>
							{#if errors['upstreams']}
								<p class="text-xs text-down">{errors['upstreams']}</p>
							{/if}
							{#each formData.upstreams as _, i (i)}
								<div class="flex items-start gap-2">
									<div class="flex-1 flex flex-col gap-1">
										<Input
											bind:value={formData.upstreams[i].url}
											placeholder={language.current && t('routes.form.upstreamsPlaceholder')}
											error={errors[`upstreams[${i}].url`] ?? undefined}
										/>
										<!--
											Step #R-PROXMOX-HTTPS-LOOP — per-row UX
											advisories. Path warning + private-IP
											hint are non-blocking; the URL value is
											preserved (operator may want to fix the
											URL themselves rather than have the form
											strip it).
										-->
										{#if nonRootPath(formData.upstreams[i].url)}
											<p
												class="text-xs text-amber-700 dark:text-amber-300"
												data-testid="upstream-path-warning"
											>
												Le chemin <code class="font-mono"
													>{nonRootPath(formData.upstreams[i].url)}</code
												> sera ignoré — Caddy proxyfie uniquement vers <code class="font-mono"
													>host:port</code
												>.
											</p>
										{/if}
										{#if showPrivateIPHint(formData.upstreams[i].url)}
											<p
												class="text-xs text-amber-700 dark:text-amber-300"
												data-testid="upstream-private-ip-hint"
											>
												{language.current && t('routes.form.upstreamPrivateIPHint')}
											</p>
										{/if}
										<!--
											Step #R-PROXMOX-HTTPS-LOOP commit 3 — per-row
											probe result chip. Three states: hidden
											(undefined), spinner (running), outcome
											(reachable✓ or error✗). Outcome chip shows
											status code + latency for reachable, error
											text otherwise.
										-->
										{#if upstreamTests[i]}
											{@const ts = upstreamTests[i]}
											<div
												class="text-xs flex items-center gap-2 flex-wrap"
												data-testid="upstream-test-chip-{i}"
											>
												{#if ts.running}
													<span class="text-secondary">⏳ {language.current && t('routes.form.upstreamTestRunning')}</span>
												{:else if ts.error}
													<span class="text-down">✗ {ts.error}</span>
												{:else if ts.result}
													{#if ts.result.reachable}
														<!-- v2.55 — reachable is a network fact, not a verdict on
														     the answer. A 404 used to show a green tick, which read
														     as "all good" for a backend that had just refused the
														     request. The status class decides the mark now. -->
														<span class={probeStatusOk(ts.result.statusCode) ? 'text-up' : 'text-warn'}>
															{probeStatusOk(ts.result.statusCode) ? '✓' : '⚠'} HTTP {ts.result.statusCode}
															({ts.result.latencyMs}ms)
														</span>
														{#if ts.result.serverHeader}
															<span class="text-muted font-mono">
																{ts.result.serverHeader}
															</span>
														{/if}
														{#if ts.result.cert?.selfSigned}
															<span
																class="text-amber-700 dark:text-amber-300"
																title={language.current && t('routes.form.upstreamTestSelfSignedTooltip')}
															>
																⚠ self-signed
															</span>
														{/if}
													{:else}
														<span class="text-down">
															✗ {ts.result.error || (language.current && t('routes.form.upstreamTestConnectionFailed'))}
														</span>
														{#if ts.result.cert?.commonName}
															<span class="text-muted font-mono">
																cert CN={ts.result.cert.commonName}
															</span>
														{/if}
													{/if}
												{/if}
											</div>
										{/if}
									</div>
									<!--
										Step #R-PROXMOX-HTTPS-LOOP commit 3 — per-row
										"Tester" button. Disabled when the URL is
										empty (no probe target) or while the row is
										already running. Spinner is in the chip below.
									-->
									<Button
										variant="ghost"
										size="sm"
										onclick={() => runUpstreamTest(i)}
										type="button"
										disabled={formData.upstreams[i].url.trim() === '' ||
											!!(upstreamTests[i] && (upstreamTests[i] as { running?: boolean }).running)}
										data-testid="test-upstream-{i}"
									>
										{language.current && t('routes.form.upstreamTestButton')}
									</Button>
									{#if weightVisible}
										<div class="w-24 flex flex-col gap-1.5">
											<input
												type="number"
												min="1"
												bind:value={formData.upstreams[i].weight}
												placeholder={language.current && t('routes.form.upstreamsWeightPlaceholder')}
												class="bg-surface border rounded-md px-3 py-2 text-sm text-primary focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
												class:border-down={!!errors[`upstreams[${i}].weight`]}
												class:border-border-default={!errors[`upstreams[${i}].weight`]}
											/>
											{#if errors[`upstreams[${i}].weight`]}
												<p class="text-xs text-down">{errors[`upstreams[${i}].weight`]}</p>
											{/if}
										</div>
									{/if}
									<Button
										variant="ghost"
										size="sm"
										onclick={() => removeUpstream(i)}
										disabled={formData.upstreams.length <= 1}
										type="button">×</Button
									>
								</div>
							{/each}
						</div>
						<!--
							Step #R-PROXMOX-HTTPS-LOOP — advanced TLS options
							disclosure. Mounted ONLY when the pool is a clean
							all-https; the entire block leaves the DOM on http
							/ mixed / empty pools so the operator can't set a
							meaningless flag. The scheme-transition $effect
							resets formData.insecureSkipVerify to false on
							https→http so the toggle state stays aligned with
							both the on-screen disclosure visibility and the
							storage row.
						-->
						<!--
							v2.61 — the server name was INSIDE the advanced-TLS
							disclosure, which is itself inside a collapsed
							section: two invisible clicks deep, for a field the
							operator needed the day after it shipped. It now
							sits in the TLS section directly, beside the
							disclosure rather than within it. Same scheme gate
							(https pools only), one fewer thing to discover.
						-->
						{#if tlsAdvancedVisible}
							<div class="flex flex-col gap-1">
								<Input
									id="route-upstream-tls-server-name"
									label={language.current && t('routes.form.upstreamTlsServerNameLabel')}
									placeholder={language.current && t('routes.form.upstreamTlsServerNamePlaceholder')}
									bind:value={formData.upstreamTlsServerName}
									data-testid="upstream-tls-server-name"
								/>
								<p class="text-xs text-muted">
									{language.current && t('routes.form.upstreamTlsServerNameHelper')}
								</p>
							</div>
						{/if}

						{#if tlsAdvancedVisible}
							<details
								class="rounded-md border border-border-default bg-surface px-3 py-2"
								data-testid="tls-advanced-disclosure"
							>
								<summary class="text-sm font-medium text-secondary cursor-pointer">
									{language.current && t('routes.form.tlsAdvancedSummary')}
								</summary>
								<div class="mt-2 flex flex-col gap-1">
									<Checkbox
										label={language.current && t('routes.form.upstreamsInsecureSkipVerifyLabel')}
										bind:checked={formData.insecureSkipVerify}
									/>
									<p class="text-xs text-muted ml-6">
										{language.current && t('routes.form.tlsAdvancedHelper')}
									</p>
								</div>
							</details>
						{/if}
						<!-- Step J.3: LB policy selector. Hidden when the pool has
						     one upstream (selection is moot). formData.lbPolicy is
						     preserved across visibility flips. -->
						{#if lbSelectorVisible}
							<div>
								<label
									for="route-lb-policy"
									class="text-sm font-medium text-secondary block mb-1"
								>
									{language.current && t('routes.form.lbSectionLabel')}
								</label>
								<select
									id="route-lb-policy"
									bind:value={formData.lbPolicy}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								>
									<option value="round_robin">{language.current && t('routes.form.lbRoundRobin')}</option>
									<option value="weighted_round_robin">{language.current && t('routes.form.lbWeightedRoundRobin')}</option>
									<option value="least_conn">{language.current && t('routes.form.lbLeastConn')}</option>
									<option value="ip_hash">{language.current && t('routes.form.lbIPHash')}</option>
									<option value="random">{language.current && t('routes.form.lbRandom')}</option>
									<option value="first">{language.current && t('routes.form.lbFirst')}</option>
								</select>
							</div>
						{/if}
					</RouteSection>

					<!-- TLS: HTTPS, redirection, certificate source and ACME challenge. -->
					<RouteSection
						name={language.current && t('routes.form.sectionTLS')}
						summary={summaryTLS}
						badge={tlsBadge.badge}
						posture={tlsBadge.posture}
						testid="section-tls"
					>
						<div class="flex flex-col gap-1">
							<Checkbox label={language.current && t('routes.form.tlsEnabledLabel')} bind:checked={formData.tlsEnabled} />
							<p class="text-xs text-muted ml-6">
								{language.current && t('routes.form.tlsEnableHelper')}
							</p>
						</div>
						<Checkbox
							label={language.current && t('routes.form.tlsRedirectLabel')}
							bind:checked={formData.redirectToHttps}
							disabled={!formData.tlsEnabled}
							title={formData.tlsEnabled
								? 'Automatically redirects HTTP requests to HTTPS with a 301.'
								: 'Enable TLS to use HTTPS redirect.'}
						/>

						<!-- v2.19.0 external-certs SOCLE (Task 8) — cert source
						     selector. Visible only when TLS is on. Chooses which
						     provider issues/serves this route's cert: ACME (the
						     default — managed-domain wildcard or per-route
						     http-01/dns-01), Caddy internal self-signed CA, or a
						     manual operator-uploaded external cert. The ACME
						     challenge sub-selector below only shows under 'acme'. -->
						{#if formData.tlsEnabled}
							<div>
								<label
									for="route-cert-source"
									class="text-sm font-medium text-secondary block mb-1"
								>
									{language.current && t('routes.form.certSourceLabel')}
								</label>
								<select
									id="route-cert-source"
									bind:value={formData.cert_source}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								>
									<option value="acme">{language.current && t('routes.form.certSourceAcme')}</option>
									<option value="internal">{language.current && t('routes.form.certSourceInternal')}</option>
									<option value="manual">{language.current && t('routes.form.certSourceManual')}</option>
								</select>
								{#if formData.cert_source === 'internal'}
									<p class="text-xs text-muted mt-1">
										{language.current && t('routes.form.certSourceInternalHelper')}
									</p>
								{:else if formData.cert_source === 'manual'}
									<!-- Manual sub-form: the eligible external certs
									     (those whose SANs cover the route host, RFC
									     6125). Empty → warning + upload link. -->
									{#if eligibleCerts.length === 0}
										<p
											data-testid="cert-manual-none"
											class="text-xs text-down mt-2"
										>
											{language.current && t('routes.form.certSourceManualNone')}
											<a href="/certs" class="text-cyan hover:underline"
												>{language.current && t('routes.form.certSourceManualUploadLink')}</a
											>
										</p>
									{:else}
										<fieldset class="mt-2 flex flex-col gap-2">
											<legend class="text-xs text-muted mb-1">
												{language.current && t('routes.form.certSourceManualPickLabel')}
											</legend>
											{#each eligibleCerts as cert (cert.id)}
												<label
													class="flex items-start gap-2 text-sm text-secondary cursor-pointer rounded border border-border-default px-3 py-2 hover:bg-surface"
												>
													<input
														type="radio"
														name="route-manual-cert"
														value={cert.id}
														checked={formData.cert_id === cert.id}
														onchange={() => (formData.cert_id = cert.id)}
														class="mt-1"
													/>
													<span class="flex flex-col">
														<span class="font-medium text-primary">{cert.name}</span>
														<span class="font-mono text-xs text-muted"
															>{(cert.dnsNames ?? []).join(', ')}</span
														>
														<span class="text-xs text-muted"
															>{language.current && t('routes.form.certSourceManualExpiry')}
															{new Date(cert.notAfter).toLocaleDateString()}</span
														>
													</span>
												</label>
											{/each}
										</fieldset>
									{/if}
								{/if}
							</div>
						{/if}
						<!-- Step J.4 + O.4: ACME challenge selector. Visible only
						     when TLS is on AND the cert source is ACME. Locked to
						     "dns-01" when host or any alias is a wildcard. Step O.4
						     (AC #11 + #12): when the host is covered by a managed
						     domain AND the operator hasn't opted out via
						     useDedicatedCert, the selector hides entirely and an
						     inheritance badge takes its place. When covered + opted
						     out, the selector returns and the operator picks
						     http-01/dns-01 like J. -->
						{#if formData.tlsEnabled && formData.cert_source === 'acme'}
							{#if coveringManagedDomain && !formData.useDedicatedCert}
								<!-- AC #11: covered + inheriting. Show the wildcard
								     badge + the opt-out toggle. The selector is
								     gone — the wildcard cert serves this route. -->
								<div>
									<span class="text-sm font-medium text-secondary block mb-1"
										>{language.current && t('routes.form.tlsCertificateLabel')}</span
									>
									<!--
										v2.9.16 i18n hotfix — the "Inherits wildcard from
										X (managed via Y)" line mixes a code span, a
										settings link, and parenthetical chrome. Rather
										than weave a single template literal through all
										three, render the static prefix via t() and keep
										the dynamic <code> + <a> as inline JSX. Same
										pattern used by the dns01Banner above.
									-->
									<div
										class="rounded border border-info/40 bg-info/10 px-3 py-2 text-sm"
									>
										<span class="font-medium">{language.current && t('routes.form.tlsCertificateInherits')}</span>
										<code class="font-mono">*.{coveringManagedDomain.apex}</code>
										<span class="text-muted">
											({language.current && t('routes.form.tlsCertificateInheritsManagedVia')} <a href="/settings" class="text-cyan hover:underline"
												>{language.current && t('routes.form.tlsCertificateLink')}</a
											>)
										</span>
									</div>
									<label class="inline-flex items-center gap-2 text-sm text-secondary mt-2 cursor-pointer">
										<input
											type="checkbox"
											checked={formData.useDedicatedCert}
											onchange={(e) =>
												onUseDedicatedCertToggle((e.target as HTMLInputElement).checked)}
										/>
										{language.current && t('routes.form.tlsUseDedicatedCertLabel')}
									</label>
									<p class="text-xs text-muted mt-1">
										{language.current && t('routes.form.tlsUseDedicatedCertHelper')}
									</p>
								</div>
							{:else}
								<div>
									<label
										for="route-acme-challenge"
										class="text-sm font-medium text-secondary block mb-1"
									>
										ACME challenge
									</label>
									<select
										id="route-acme-challenge"
										bind:value={formData.acmeChallenge}
										disabled={acmeLockedToDNS01}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-60 disabled:cursor-not-allowed"
									>
										{#if dedicatedOptOutPendingChoice}
											<!-- #O.4-2 force-explicit-choice — empty value
											     is the unselected state forced by the
											     toggle handler. The placeholder option
											     renders the empty selection clearly to
											     the operator (otherwise the browser
											     would silently render the first option
											     as visually selected without it being
											     the bound value). -->
											<option value="" disabled>— pick one —</option>
										{/if}
										<option value="http-01">{language.current && t('routes.form.tlsAcmeHTTP01')}</option>
										<option value="dns-01">{language.current && t('routes.form.tlsAcmeDNS01')}</option>
									</select>
									{#if coveringManagedDomain && formData.useDedicatedCert}
										<!-- AC #11 opt-out path: show the per-route
										     selector AND the toggle (checked) so the
										     operator can flip back to inheritance. -->
										<label class="inline-flex items-center gap-2 text-sm text-secondary mt-2 cursor-pointer">
											<input
												type="checkbox"
												checked={formData.useDedicatedCert}
												onchange={(e) =>
													onUseDedicatedCertToggle(
														(e.target as HTMLInputElement).checked
													)}
											/>
											Use a dedicated cert (inherits <code class="font-mono"
												>*.{coveringManagedDomain.apex}</code
											> when unchecked)
										</label>
									{/if}
									{#if dedicatedOptOutPendingChoice}
										<!-- #O.4-2 force-explicit-choice — submit is
										     disabled until the operator picks. The
										     hint sits next to the now-unselected
										     dropdown so the cause is obvious. -->
										<p class="text-xs text-warn mt-1">
											Pick HTTP-01 or DNS-01 above — opting out of the wildcard
											requires an explicit per-route ACME challenge.
										</p>
									{/if}
									{#if acmeLockedToDNS01}
										<p class="text-xs text-muted mt-1">
											Wildcard hosts require DNS-01.
										</p>
									{:else if formData.acmeChallenge === 'dns-01' && !dnsProviderConfigured}
										<p class="text-xs text-down mt-1">
											DNS-01 requires a configured DNS provider —
											<a href="/settings" class="text-cyan hover:underline"
												>configure it under Settings</a
											>.
										</p>
									{:else}
										<p class="text-xs text-muted mt-1">
											HTTP-01 proves control via port 80. DNS-01 proves it
											via a `_acme-challenge` TXT record and is the only
											option for wildcard certs.
										</p>
									{/if}
								</div>
							{/if}
						{/if}
					</RouteSection>

					<!-- Authentication in front of the backend. -->
					<RouteSection name={language.current && t('routes.form.sectionAuth')} summary={summaryAuth} badge={authBadge.badge} posture={authBadge.posture} testid="section-auth">
						<!-- Step K.1 — per-route auth: none / basic / forward_auth,
						     mutually exclusive by shape (the server re-checks with
						     validateAuthFieldsMutex as defence in depth).
						     v2.41 — the three-way choice is a segmented control like
						     the other modes, and each option states what it asks of
						     the visitor. -->
						<div class="flex flex-col gap-2">
							<span class="text-sm font-medium text-secondary"
								>{language.current && t('routes.form.authSectionLabel')}</span
							>
							<ModeSelector
								id="route-auth-mode"
								bind:value={formData.authMode}
								options={authModeOptions}
								ariaLabel={language.current && t('routes.form.authSectionLabel')}
							/>
						</div>

						{#if formData.authMode === 'basic'}
							<div class="rounded-md border border-border-subtle bg-surface p-3 flex flex-col gap-2">
								<Input
									label={language.current && t('routes.form.authBasicUsernameLabel')}
									bind:value={formData.basicAuth.username}
									placeholder={language.current && t('routes.form.authBasicUsernamePlaceholder')}
								/>
								<div>
									<label for="basic-auth-password" class="text-sm font-medium text-secondary block mb-1">
										{language.current && t('routes.form.authBasicPasswordLabel')}
									</label>
									<input
										id="basic-auth-password"
										type="password"
										bind:value={formData.basicAuth.password}
										placeholder={formMode === 'edit' && basicAuthPasswordSet
											? language.current && t('routes.form.authBasicPasswordPlaceholderSet')
											: ''}
										class="w-full bg-elevated border border-border-default rounded-md px-3 py-2 text-sm text-primary"
									/>
								</div>
							</div>
						{:else if formData.authMode === 'forward_auth'}
							<div class="rounded-md border border-border-subtle bg-surface p-3 flex flex-col gap-2">
								<label for="route-forward-auth-provider" class="text-sm font-medium text-secondary block">
									{language.current && t('routes.form.authForwardProviderLabel')}
								</label>
								{#if forwardAuthProviders.length === 0}
									<!-- Empty state: the choice is unusable until a provider
									     exists, so say where to create one. -->
									<p class="text-xs text-down" data-testid="forward-auth-no-provider">
										{language.current && t('routes.form.authForwardNoProvider')}
										<a href="/settings" class="text-cyan hover:underline"
											>{language.current && t('routes.form.authForwardConfigureLink')}</a
										>.
									</p>
								{:else}
									<select
										id="route-forward-auth-provider"
										bind:value={formData.forwardAuth.providerName}
										class="w-full bg-elevated border border-border-default rounded-md px-3 py-2 text-sm text-primary"
									>
										<option value="" disabled
											>{language.current && t('routes.form.authForwardSelectPlaceholder')}</option
										>
										{#each forwardAuthProviders as p (p.name)}
											<option value={p.name}>{p.name} ({p.kind})</option>
										{/each}
									</select>
									<p class="text-xs text-muted">
										{language.current && t('routes.form.authForwardDelegatesTo')}
										<code
											>{forwardAuthProviders.find((p) => p.name === formData.forwardAuth.providerName)
												?.verifyUrl ?? '...'}</code
										>
										{language.current && t('routes.form.authForwardViaCaddy')}
									</p>
								{/if}
							</div>
						{/if}
					</RouteSection>

					<!-- WAF: mode, CRS, exclusions, guided rules and SecLang. -->
					<RouteSection name={language.current && t('routes.form.sectionWAF')} summary={summaryWAF} badge={wafBadge.badge} posture={wafBadge.posture} testid="section-waf">
						<!-- v2.41 — WAF interior. Reading order is deliberate and
						     unchanged: what inspects (mode), how the body is read
						     (streaming), turning the whole CRS off, then the three
						     narrowing escape hatches (rule/tag exclusions, targeted
						     exclusions), then the rules the operator adds (guided,
						     SecLang). What changed is the treatment: a segmented
						     control instead of a dropdown, switches that carry their
						     helper line, and the exclusion lists side by side. -->
						<div class="flex flex-col gap-2">
							<span class="text-sm font-medium text-secondary" id="route-waf-mode-label">
								WAF (Coraza + OWASP CRS)
							</span>
							<ModeSelector
								id="route-waf-mode"
								bind:value={formData.wafMode}
								options={wafModeOptions}
								ariaLabel={language.current && t('routes.form.wafModeAria')}
							/>
						</div>

						<!-- Phase 4.5 (#R-WAF-BUFFER-OOM-ON-LARGE-UPLOADS)
						     — upload-streaming toggle. Sits inside the WAF block
						     on purpose: it modulates the WAF body-inspection
						     behaviour, so the operator reads it as a WAF-adjacent
						     knob, not as an advanced-TLS bolt-on. Independent of
						     wafMode — even with WAF=off the toggle still controls
						     Caddy's flush_interval. -->
						<SwitchRow
							checked={formData.uploadStreamingMode}
							onchange={(v) => (formData.uploadStreamingMode = v)}
							label={language.current && t('routes.form.uploadStreamingToggleLabel')}
							helper={language.current && t('routes.form.uploadStreamingHelper')}
							testid="upload-streaming-toggle"
							labelTestid="upload-streaming-toggle-label"
						/>

						<!-- Step X.2 — wafDisableCRS toggle. The change is mediated
						     by onWAFDisableCRSChange instead of a direct bind so the
						     false → true direction can be gated behind the ADR-D4
						     confirm dialog ; the visual checked state still reflects
						     formData.wafDisableCRS so an operator who cancels the
						     dialog sees the switch flip back. v2.41 dresses it as a
						     danger row — it removes a protection. -->
						<SwitchRow
							danger
							checked={formData.wafDisableCRS}
							onchange={(_v, e) => onWAFDisableCRSChange(e)}
							label={language.current && t('routes.form.wafDisableCRSLabel')}
							helper={language.current && t('routes.form.wafDisableCRSHelper')}
							testid="waf-disable-crs-toggle"
							labelTestid="waf-disable-crs-toggle-label"
						/>

						<!-- Step X options (c) + (e) — the two list-shaped escape
						     hatches, side by side: "just these rule IDs" and "just
						     these tags". Both are no-ops when the whole CRS is
						     unloaded, so both are disabled (never cleared — the
						     operator may put the CRS back) and the sub-group says
						     so once, instead of each list repeating the warning. -->
						<div class="rounded-md border border-border-subtle bg-surface p-3">
							<div class="flex items-baseline justify-between gap-3 mb-2">
								<span class="text-sm font-medium text-secondary"
									>{language.current && t('routes.form.wafExceptionsTitle')}</span
								>
								{#if wafExceptionCount > 0}
									<span class="text-xs text-muted" data-testid="waf-exceptions-count"
										>{language.current && t('routes.form.summaryExclusions', { count: wafExceptionCount })}</span
									>
								{/if}
							</div>
							{#if formData.wafDisableCRS}
								<p class="text-xs text-status-warn mb-2" data-testid="waf-exceptions-crs-off">
									{language.current && t('routes.form.wafExcludeRulesCRSDisabledWarning')}
								</p>
							{/if}
							<div class="grid gap-3 md:grid-cols-2">
								<div>
									<label for="route-waf-exclude-rules" class="text-sm font-medium text-secondary block mb-1">
										{language.current && t('routes.form.wafExcludeRulesLabelFull')}
										<span class="text-muted text-xs"
											>{language.current && t('routes.form.wafExcludeRulesLabelHint')}</span
										>
									</label>
									<textarea
										id="route-waf-exclude-rules"
										data-testid="waf-exclude-rules-input"
										value={wafExcludeRulesInput}
										onchange={onExcludeRulesInputChange}
										oninput={onExcludeRulesInputChange}
										disabled={formData.wafDisableCRS}
										placeholder={language.current && t('routes.form.wafExcludeRulesPlaceholder')}
										rows="2"
										class="w-full bg-elevated border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono disabled:opacity-50 disabled:cursor-not-allowed"
									></textarea>
									{#if errors.wafExcludeRules}
										<p class="text-xs text-status-down mt-1" data-testid="waf-exclude-rules-error">
											{errors.wafExcludeRules}
										</p>
									{/if}
									<p class="text-xs text-muted mt-1 max-w-prose">
										{language.current && t('routes.form.wafExcludeRulesHelper')}
										{#if formMode === 'edit' && editingId}
											{language.current && t('routes.form.wafExcludeRulesIdentifyRules')}
											<a
												href="/security/{editingId}"
												class="text-cyan hover:underline"
												data-testid="waf-exclude-rules-security-link"
												>{language.current && t('routes.form.wafExcludeRulesWAFHistory')}</a
											>.
										{:else}
											{language.current && t('routes.form.wafExcludeRulesIdentifyRulesGeneric')}
											<a href="/security" class="text-cyan hover:underline"
												>{language.current && t('routes.form.wafExcludeRulesSecurityPage')}</a
											>.
										{/if}
									</p>
								</div>

								<div>
									<label for="route-waf-exclude-tags" class="text-sm font-medium text-secondary block mb-1">
										{language.current && t('routes.form.wafExcludeTagsLabelFull')}
										<span class="text-muted text-xs"
											>{language.current && t('routes.form.wafExcludeTagsLabelHint')}</span
										>
									</label>
									<textarea
										id="route-waf-exclude-tags"
										data-testid="waf-exclude-tags-input"
										value={wafExcludeTagsInput}
										onchange={onExcludeTagsInputChange}
										oninput={onExcludeTagsInputChange}
										disabled={formData.wafDisableCRS}
										placeholder={language.current && t('routes.form.wafExcludeTagsPlaceholder')}
										rows="2"
										{...{ list: 'waf-exclude-tags-catalog' }}
										class="w-full bg-elevated border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono disabled:opacity-50 disabled:cursor-not-allowed"
									></textarea>
									<datalist id="waf-exclude-tags-catalog">
										{#each CRS_TAG_CATALOG as tag (tag)}
											<option value={tag}></option>
										{/each}
									</datalist>
									{#if errors.wafExcludeTags}
										<p class="text-xs text-status-down mt-1" data-testid="waf-exclude-tags-error">
											{errors.wafExcludeTags}
										</p>
									{/if}
									<p class="text-xs text-muted mt-1 max-w-prose">
										{language.current && t('routes.form.wafExcludeTagsHelper')}
									</p>
								</div>
							</div>
						</div>

						<!-- v2.36 — targeted exclusions (one rule stops inspecting
						     one field, optionally on one path). -->
						<WafTargetedExclusionsEditor
							bind:value={formData.wafTargetedExclusions}
							crsDisabled={formData.wafDisableCRS}
						/>
						<!-- v2.37 — guided WAF rules (block when every condition
						     matches, follows the route mode). -->
						<WafCustomRulesEditor
							bind:value={formData.wafCustomRules}
							wafMode={formData.wafMode}
							onConvert={convertGuidedRule}
						/>
						<!-- v2.38 — expert SecLang + templates + request tester. -->
						<WafSecLangSection
							bind:value={formData.wafSecLang}
							routeId={formMode === 'edit' ? editingId : null}
							wafMode={formData.wafMode}
							saveErrors={secLangSaveErrors}
						/>
					</RouteSection>

					<!-- Rate limit. -->
					<RouteSection name={language.current && t('routes.form.sectionRateLimit')} summary={summaryRateLimit} badge={rateLimitBadge.badge} posture={rateLimitBadge.posture} testid="section-rate-limit">
						<!-- Step Q (2026-06-18) — per-route rate limit section.
						     Lives in its own block (not inside the WAF section)
						     because rate limiting is orthogonal to the WAF
						     posture : a route can have WAF=off + rate limit on
						     (trusted internal LAN with brute-force protection on
						     /login), or WAF=block + no rate limit (public API
						     where the WAF is the only gate).
						     v2.41 — switch row + a live sentence: the numbers are
						     only meaningful as the rule they add up to. -->
						<SwitchRow
							checked={formData.rateLimit !== null}
							onchange={(_v, e) => onRateLimitToggle(e)}
							label={language.current && t('routes.form.rateLimitToggleLabelFull')}
							inputId="route-rate-limit-toggle"
							testid="rate-limit-toggle"
							labelTestid="rate-limit-toggle-label"
						/>

						{#if formData.rateLimit !== null}
							<PostureSentence posture="block" testid="rate-limit-sentence">
								{rateLimitSentence}
							</PostureSentence>
							<div class="grid gap-3 sm:grid-cols-2">
								<div>
									<label for="route-rl-events" class="text-xs font-medium text-secondary block mb-1">
										{language.current && t('routes.form.rateLimitMaxRequestsLabel')}
									</label>
									<input
										id="route-rl-events"
										data-testid="rate-limit-events-input"
										type="number"
										min="1"
										step="1"
										bind:value={formData.rateLimit.events}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
									/>
								</div>
								<div>
									<label for="route-rl-window" class="text-xs font-medium text-secondary block mb-1">
										{language.current && t('routes.form.rateLimitPeriodLabel')}
										<span class="text-muted">{language.current && t('routes.form.rateLimitPeriodHint')}</span>
									</label>
									<input
										id="route-rl-window"
										data-testid="rate-limit-window-input"
										type="text"
										placeholder={language.current && t('routes.form.rateLimitWindowPlaceholder')}
										bind:value={formData.rateLimit.window}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
									/>
								</div>
								<div class="sm:col-span-2">
									<label for="route-rl-key" class="text-xs font-medium text-secondary block mb-1">
										{language.current && t('routes.form.rateLimitKeyLabelFull')}
									</label>
									<input
										id="route-rl-key"
										data-testid="rate-limit-key-input"
										type="text"
										placeholder="{'{http.request.remote.host}'}"
										bind:value={formData.rateLimit.key}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
									/>
								</div>
							</div>
							<p class="text-xs text-muted max-w-prose">
								{language.current && t('routes.form.rateLimitHelper')}
							</p>
						{/if}
					</RouteSection>

					<!-- Country and source-IP filtering: both must accept the request. -->
					<RouteSection name={language.current && t('routes.form.sectionGeoIP')} summary={summaryGeoIP} badge={geoIPBadge.badge} posture={geoIPBadge.posture} testid="section-geo-ip">
						<!-- W.5 — country-block per-route gate. Operator
						     picks mode + countries; the W.1 Caddy module
						     short-circuits at the edge before the request
						     reaches crowdsec/auth/waf. ALLOW mode + empty
						     list is rejected by the API (and surfaced here
						     as a red error) — it would block all
						     non-RFC1918 traffic. DENY mode + empty list is
						     accepted (legal no-op; server logs a Warn).
						     The "Add country" input takes ISO 3166-1
						     alpha-2 codes (2 uppercase letters); Enter or
						     comma adds the chip. -->
						<!-- W.7 polish: pill-style mode toggle (Off / Allow /
						     Deny) replaces the dropdown so operators see the
						     three states at a glance; the active button picks
						     up the mode-colored border (slate / green / red).
						     Chips recolor to match the active mode. Counter
						     "{N} pays autorisé(s) / bloqué(s)" surfaces the
						     count + mode-meaningful pluralization. Autocomplete
						     dropdown matches by alpha-2 code OR French name
						     prefix (Intl.DisplayNames) — operator types "russ"
						     to find RU/Russie. "+ Ajouter un pays" CTA improves
						     discoverability over the previous bare input. -->
						<details
							class="rounded border border-border-subtle cb-section cb-mode-{formData.countryBlock.mode}"
							bind:open={cbSectionOpen}
							data-testid="country-block-section"
						>
							<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
								{language.current && t('routes.form.countryBlockBlockedListLabel')}
								{#if formData.countryBlock.mode !== 'off'}
									<span class="ml-1 text-xs text-muted" data-testid="country-block-summary">
										({formData.countryBlock.mode} · {geoSummary})
									</span>
								{:else}
									<!-- W.7 follow-up: surface the "off" state in
									     the summary too, so when the operator
									     manually collapses the section after
									     picking Désactivé the closed-state
									     header isn't ambiguous. -->
									<span
										class="ml-1 text-xs text-muted"
										data-testid="country-block-summary-off"
									>
										{language.current && t('routes.form.countryBlockDisabledLabel')}
									</span>
								{/if}
							</summary>
							<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
								<!-- Mode pill toggle — 3 buttons in a segmented group.
								     The "Mode" caption is a <span> rather than a
								     <label> because the toggle has no single control
								     to bind to (group's aria-label carries the
								     accessible name). -->
								<div>
									<span class="text-sm font-medium text-secondary block mb-1">
										Mode
									</span>
									<div
										class="cb-mode-toggle"
										role="group"
										aria-label={language.current && t('routes.form.countryBlockModeLabel')}
										data-testid="country-block-mode-toggle"
									>
										<button
											type="button"
											class="cb-mode-btn cb-mode-btn--off"
											class:active={formData.countryBlock.mode === 'off'}
											data-testid="country-block-mode-off"
											aria-pressed={formData.countryBlock.mode === 'off'}
											onclick={() => cbPickMode('off')}
										>
											<span class="cb-mode-btn__label">{language.current && t('routes.form.countryBlockModeOff')}</span>
											<span class="cb-mode-btn__hint">{language.current && t('routes.form.countryBlockModeOffHint')}</span>
										</button>
										<button
											type="button"
											class="cb-mode-btn cb-mode-btn--allow"
											class:active={formData.countryBlock.mode === 'allow'}
											data-testid="country-block-mode-allow"
											aria-pressed={formData.countryBlock.mode === 'allow'}
											onclick={() => cbPickMode('allow')}
										>
											<span class="cb-mode-btn__label">{language.current && t('routes.form.countryBlockModeAllow')}</span>
											<span class="cb-mode-btn__hint">{language.current && t('routes.form.countryBlockModeAllowHint')}</span>
										</button>
										<button
											type="button"
											class="cb-mode-btn cb-mode-btn--deny"
											class:active={formData.countryBlock.mode === 'deny'}
											data-testid="country-block-mode-deny"
											aria-pressed={formData.countryBlock.mode === 'deny'}
											onclick={() => cbPickMode('deny')}
										>
											<span class="cb-mode-btn__label">{language.current && t('routes.form.countryBlockModeDeny')}</span>
											<span class="cb-mode-btn__hint">{language.current && t('routes.form.countryBlockModeDenyHint')}</span>
										</button>
									</div>
								</div>

								{#if formData.countryBlock.mode !== 'off'}
									<!-- v2.34 — live sentence: what the filter does, with
									     the OR between the lists spelled out. -->
									<GeoRuleSentence
										mode={formData.countryBlock.mode}
										continents={formData.countryBlock.continents}
										countries={formData.countryBlock.countryList}
										asns={formData.countryBlock.asns}
										exceptionCountries={formData.countryBlock.exceptions.countries}
										exceptionAsns={formData.countryBlock.exceptions.asns}
										{countryName}
									/>
									<!-- v2.34 — the three lists form ONE "matches if" group
									     (continent OR country OR network); each is optional. -->
									<section class="geo-match-group" data-testid="geo-match-group">
										<header class="geo-match-group__head">
											<span class="text-sm font-medium text-primary">
												{language.current &&
													t(formData.countryBlock.mode === 'deny' ? 'routes.form.geoMatchTitleDeny' : 'routes.form.geoMatchTitleAllow')}
											</span>
											<span class="text-xs text-muted">{language.current && t('routes.form.geoMatchHelper')}</span>
										</header>
									<ContinentPicker bind:value={formData.countryBlock.continents} />
									<div class="geo-or" aria-hidden="true"><span>{language.current && t('routes.form.geoSentenceOr')}</span></div>
									<!-- Counter + autocomplete combo. The counter
									     uses mode-meaningful copy + plural agrees
									     with N; hidden when N=0 so the empty
									     state stays uncluttered. -->
									<div>
										<div class="flex items-baseline justify-between mb-1">
											<label
												for="route-country-block-list-input"
												class="text-sm font-medium text-secondary"
											>
												{language.current && t('routes.form.countryBlockAddCountryLabel')}
											</label>
											{#if cbCounterLabel}
												<span
													class="text-xs text-muted"
													data-testid="country-block-counter"
												>
													{cbCounterLabel}
												</span>
											{/if}
										</div>

										<!-- Chip list — rendered above the input so
										     the operator's "what's in" is the
										     primary visual focus, with the
										     "add more" affordance below. -->
										<div
											class="flex flex-wrap gap-2 mb-2"
											data-testid="country-block-chip-list"
										>
											{#each formData.countryBlock.countryList as code, i (code + i)}
												<span
													class="cb-chip"
													data-testid="country-block-chip"
													title={countryName(code)}
												>
													<Flag {code} />
													<span class="cb-chip__name">{countryName(code)}</span>
													<button
														type="button"
														class="cb-chip__remove"
														aria-label={language.current && t('routes.form.countryBlockRemoveAria', { name: countryName(code) })}
														onclick={() => cbRemoveCode(code)}
													>
														×
													</button>
												</span>
											{/each}
										</div>

										<!-- Input + CTA row. The input is wrapped in
										     a positioned container so the
										     suggestion dropdown can float below it
										     without disturbing the form layout. -->
										<div class="flex gap-2">
											<div class="cb-input-wrap flex-1">
												<input
													id="route-country-block-list-input"
													type="text"
													placeholder={language.current && t('routes.form.countryBlockSearchPlaceholder')}
													data-testid="country-block-input"
													autocomplete="off"
													bind:this={cbInputEl}
													value={cbInputValue}
													oninput={cbInputOnInput}
													onfocus={() => (cbDropdownOpen = true)}
													onblur={() => {
														// Defer close so a click on a
														// suggestion fires its onclick
														// BEFORE the dropdown unmounts.
														setTimeout(() => (cbDropdownOpen = false), 120);
													}}
													onkeydown={cbInputKeydown}
													class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
												/>
												{#if cbDropdownOpen && cbSuggestions.length > 0}
													<ul
														class="cb-dropdown"
														role="listbox"
														data-testid="country-block-dropdown"
													>
														{#each cbSuggestions as match, idx (match.code)}
															<li
																role="option"
																class="cb-dropdown__item"
																class:active={idx === cbActiveIndex}
																data-testid="country-block-suggestion"
																aria-selected={idx === cbActiveIndex}
																onmousedown={(e) => {
																	// onmousedown (not onclick) so it
																	// fires BEFORE the input's onblur
																	// closes the dropdown.
																	e.preventDefault();
																	cbAddCode(match.code);
																}}
																onmouseenter={() => (cbActiveIndex = idx)}
															>
																<Flag code={match.code} />
																<span class="cb-dropdown__name">
																	{match.name}
																</span>
															</li>
														{/each}
													</ul>
												{/if}
											</div>
											<button
												type="button"
												class="cb-add-btn"
												data-testid="country-block-add-cta"
												aria-label={language.current && t('routes.form.countryBlockAddCountryAria')}
												onclick={cbOpenDropdown}
											>
												{language.current && t('routes.form.countryBlockAddBtn')}
											</button>
										</div>

										{#if formData.countryBlock.mode === 'allow' && formData.countryBlock.countryList.length === 0 && formData.countryBlock.continents.length === 0 && formData.countryBlock.asns.length === 0}
											<p
												class="text-xs text-down mt-1"
												data-testid="country-block-allow-empty-error"
											>
												{language.current && t('routes.form.geoAllowEmptyError')}
											</p>
										{/if}
									</div>
									<div class="geo-or" aria-hidden="true"><span>{language.current && t('routes.form.geoSentenceOr')}</span></div>
									<!-- v2.28 — ASN block (spec D1/D3). -->
									<ASNPicker
										bind:value={formData.countryBlock.asns}
										exclude={formData.countryBlock.exceptions.asns}
										label={(language.current && t('routes.form.geoASNLabel')) || ''}
										testid="geo-asns"
									/>
									</section>
									{#if formData.countryBlock.mode === 'deny'}
										<!-- v2.27 — deny-only exceptions (spec D4), in their
										     own box: they win over every rule above. -->
										<section class="geo-exceptions" data-testid="geo-exceptions-box">
											<header class="geo-match-group__head">
												<span class="text-sm font-medium text-primary">
													{language.current && t('routes.form.geoExceptionsTitle')}
												</span>
												<span class="text-xs text-muted">{language.current && t('routes.form.geoExceptionsHelper')}</span>
											</header>
											<CountryExceptionsPicker
												bind:value={formData.countryBlock.exceptions.countries}
												blocked={formData.countryBlock.countryList}
											/>
											<ASNPicker
												bind:value={formData.countryBlock.exceptions.asns}
												exclude={formData.countryBlock.asns}
												label={(language.current && t('routes.form.geoASNExceptionsLabel')) || ''}
												testid="geo-exception-asns"
											/>
										</section>
									{/if}
									<div>
										<label
											for="route-country-block-status"
											class="text-sm font-medium text-secondary block mb-1"
										>
											{language.current && t('routes.form.countryBlockStatusCodeLabelFull')}
										</label>
										<select
											id="route-country-block-status"
											bind:value={formData.countryBlock.statusCode}
											class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
										>
											<option value={0}>{language.current && t('routes.form.countryBlockStatusDefault')}</option>
											<option value={403}>403 Forbidden</option>
											<option value={451}>451 Unavailable For Legal Reasons</option>
											<option value={444}>{language.current && t('routes.form.countryBlockStatusCode444')}</option>
										</select>
									</div>
								{:else}
									<!-- mode=off — muted hint so the operator
									     understands what happens when they pick
									     a mode (rather than seeing an empty
									     section that looks broken). -->
									<p
										class="text-xs text-muted"
										data-testid="country-block-off-hint"
									>
										Aucun gate par pays. Choisissez Allow-list ou Deny-list
										pour activer.
									</p>
								{/if}
							</div>
						</details>
						<!-- path-based-rules Task 9 — route-level IP allow/deny
						     gate. Sits alongside the country-block section
						     (both are edge-level traffic gates evaluated
						     before auth/WAF); IPFilterFields is the shared
						     Task 7 component, also reused per-path-rule
						     below. -->
						<div>
							<span class="text-sm font-medium text-secondary block mb-1">
								{language.current && t('routes.ipFilter.sectionLabel')}
							</span>
							<IPFilterFields bind:value={formData.ipFilter} />
						</div>
					</RouteSection>

					<!-- Health check of the upstream pool. -->
					<RouteSection
						name={language.current && t('routes.form.sectionHealthCheck')}
						summary={summaryHealthCheck}
						badge={healthCheckBadge.badge}
						posture={healthCheckBadge.posture}
						testid="section-health-check"
					>
						<!-- Step J.3: active health-check sub-form. Gated by the
						     enabled checkbox. Sub-fields disabled when off; their
						     state is PRESERVED across the toggle so a user who
						     flips off-and-on keeps their typed values.
						     Any interaction marks healthCheckTouched so submit ships
						     the complete 9-field block (J.2 preserve-or-replace). -->
						<!-- v2.41 — the <details> that used to wrap this block
						     is gone: the section itself collapses, and two
						     levels of the same affordance is exactly the
						     inconsistency the redesign is removing. The enable
						     switch marks the block as touched, which drives the
						     J.2 preserve-or-replace decision on submit. -->
						<div class="flex flex-col gap-3">
								<!-- v2.43.1 — what the probe is actually saying, next
								     to the fields that decide it. Only shown for a
								     saved route: while creating, no probe has run. -->
								{#if formData.healthCheck.enabled && healthCheckLive}
									<div
										class="rounded-md border p-3 text-xs"
										class:border-border-subtle={!healthCheckFailing}
										class:bg-surface={!healthCheckFailing}
										class:border-down={healthCheckFailing}
										data-testid="health-check-live"
									>
										<div class="flex flex-wrap items-center gap-2">
											<span class="text-secondary"
												>{language.current && t('routes.form.healthCheckLiveLabel')}</span
											>
											<span
												class="font-medium"
												class:text-down={healthCheckFailing}
												class:text-up={healthCheckLive.aggregateStatus === 'healthy'}
												>{healthCheckLiveLabel}</span
											>
											{#if healthCheckLive.totalUpstreamCount > 0}
												<span class="text-muted"
													>· {language.current &&
														t('routes.list.healthyCounter', {
															healthy: healthCheckLive.healthyUpstreamCount,
															total: healthCheckLive.totalUpstreamCount
														})}</span
												>
											{/if}
										</div>
										{#if healthCheckFailing}
											<p class="text-muted mt-1">
												{language.current && t('routes.form.healthCheckLiveFailingHint')}
											</p>
										{/if}
									</div>
								{/if}

								<SwitchRow
									checked={formData.healthCheck.enabled}
									onchange={(v) => {
										formData.healthCheck.enabled = v;
										markHealthCheckTouched();
									}}
									label={language.current && t('routes.form.healthCheckEnableLabel')}
									testid="health-check-toggle"
									labelTestid="health-check-toggle-label"
								/>
								<div>
									<label
										for="hc-uri"
										class="text-sm font-medium text-secondary block mb-1"
									>
										URI <span class="text-down" aria-hidden="true">*</span>
									</label>
									<input
										id="hc-uri"
										type="text"
										bind:value={formData.healthCheck.uri}
										placeholder={language.current && t('routes.form.healthCheckURIPlaceholder')}
										disabled={!formData.healthCheck.enabled}
										aria-required="true"
										oninput={markHealthCheckTouched}
										class="w-full bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed"
										class:border-down={!!errors['healthCheck.uri']}
										class:border-border-default={!errors['healthCheck.uri']}
									/>
									{#if errors['healthCheck.uri']}
										<p class="text-xs text-down mt-1">{errors['healthCheck.uri']}</p>
									{/if}
								</div>
								<div>
									<label
										for="hc-method"
										class="text-sm font-medium text-secondary block mb-1"
									>
										Method
									</label>
									<select
										id="hc-method"
										bind:value={formData.healthCheck.method}
										disabled={!formData.healthCheck.enabled}
										onchange={markHealthCheckTouched}
										class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed"
									>
										<option value="GET">GET</option>
										<option value="HEAD">HEAD</option>
									</select>
									{#if errors['healthCheck.method']}
										<p class="text-xs text-down mt-1">{errors['healthCheck.method']}</p>
									{/if}
								</div>
								<div class="grid grid-cols-2 gap-3">
									<Input
										label={language.current && t('routes.form.healthCheckIntervalLabel')}
										bind:value={formData.healthCheck.interval}
										placeholder={HEALTH_CHECK_DEFAULTS.interval}
										disabled={!formData.healthCheck.enabled}
										oninput={markHealthCheckTouched}
										error={errors['healthCheck.interval'] ?? undefined}
									/>
									<Input
										label={language.current && t('routes.form.healthCheckTimeoutLabel')}
										bind:value={formData.healthCheck.timeout}
										placeholder={HEALTH_CHECK_DEFAULTS.timeout}
										disabled={!formData.healthCheck.enabled}
										oninput={markHealthCheckTouched}
										error={errors['healthCheck.timeout'] ?? undefined}
									/>
								</div>
								<div class="grid grid-cols-2 gap-3">
									<div class="flex flex-col gap-1.5">
										<label
											for="hc-passes"
											class="text-sm font-medium text-secondary">Passes</label
										>
										<input
											id="hc-passes"
											type="number"
											min="1"
											bind:value={formData.healthCheck.passes}
											placeholder={String(HEALTH_CHECK_DEFAULTS.passes)}
											disabled={!formData.healthCheck.enabled}
											oninput={markHealthCheckTouched}
											class="bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
											class:border-down={!!errors['healthCheck.passes']}
											class:border-border-default={!errors['healthCheck.passes']}
										/>
										{#if errors['healthCheck.passes']}
											<p class="text-xs text-down">{errors['healthCheck.passes']}</p>
										{/if}
									</div>
									<div class="flex flex-col gap-1.5">
										<label
											for="hc-fails"
											class="text-sm font-medium text-secondary">Fails</label
										>
										<input
											id="hc-fails"
											type="number"
											min="1"
											bind:value={formData.healthCheck.fails}
											placeholder={String(HEALTH_CHECK_DEFAULTS.fails)}
											disabled={!formData.healthCheck.enabled}
											oninput={markHealthCheckTouched}
											class="bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
											class:border-down={!!errors['healthCheck.fails']}
											class:border-border-default={!errors['healthCheck.fails']}
										/>
										{#if errors['healthCheck.fails']}
											<p class="text-xs text-down">{errors['healthCheck.fails']}</p>
										{/if}
									</div>
								</div>
								<div class="flex flex-col gap-1.5">
									<label
										for="hc-expect-status"
										class="text-sm font-medium text-secondary">{language.current && t('routes.form.healthCheckExpectStatusLabelHTTP')}</label
									>
									<input
										id="hc-expect-status"
										type="number"
										min="0"
										max="599"
										bind:value={formData.healthCheck.expectStatus}
										placeholder={language.current && t('routes.form.healthCheckExpectStatusPlaceholder')}
										disabled={!formData.healthCheck.enabled}
										oninput={markHealthCheckTouched}
										class="bg-surface border rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
										class:border-down={!!errors['healthCheck.expectStatus']}
										class:border-border-default={!errors['healthCheck.expectStatus']}
									/>
									{#if errors['healthCheck.expectStatus']}
										<p class="text-xs text-down">{errors['healthCheck.expectStatus']}</p>
									{/if}
									<p class="text-xs text-secondary">
										{language.current && t('routes.form.healthCheckExpectStatusHint')}
									</p>
								</div>
								<!-- v2.55 — the probe's Host.
								     Caddy builds the probe from the upstream's dial
								     address, so it used to ask for `Host: 10.0.0.2:80`.
								     A backend that routes on Host answered 404 and every
								     upstream went down while serving its route fine. -->
								<div class="flex flex-col gap-1.5">
									<label for="hc-host-header" class="text-sm font-medium text-secondary">
										{language.current && t('routes.form.healthCheckHostHeaderLabel')}
									</label>
									<input
										id="hc-host-header"
										type="text"
										bind:value={formData.healthCheck.hostHeader}
										placeholder={formData.host || 'app.example.com'}
										disabled={!formData.healthCheck.enabled}
										oninput={markHealthCheckTouched}
										data-testid="hc-host-header"
										class="bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary disabled:opacity-50 disabled:cursor-not-allowed"
									/>
									<p class="text-xs text-secondary">
										{language.current && t('routes.form.healthCheckHostHeaderHint')}
									</p>
								</div>
								<div class="flex flex-col gap-1.5">
									<span class="text-sm font-medium text-secondary">
										{language.current && t('routes.form.healthCheckHeadersLabel')}
									</span>
									{#each healthCheckHeaderRows as row, i (i)}
										<div class="flex gap-2 items-start">
											<input
												type="text"
												bind:value={row.name}
												placeholder="Authorization"
												disabled={!formData.healthCheck.enabled}
												oninput={markHealthCheckTouched}
												aria-label={language.current && t('routes.form.healthCheckHeaderNameLabel')}
												data-testid="hc-header-name"
												class="flex-1 min-w-0 bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono disabled:opacity-50"
											/>
											<input
												type="text"
												bind:value={row.value}
												placeholder="Bearer …"
												disabled={!formData.healthCheck.enabled}
												oninput={markHealthCheckTouched}
												aria-label={language.current && t('routes.form.healthCheckHeaderValueLabel')}
												data-testid="hc-header-value"
												class="flex-1 min-w-0 bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono disabled:opacity-50"
											/>
											<Button
												variant="ghost"
												size="sm"
												onclick={() => removeHealthCheckHeader(i)}
												disabled={!formData.healthCheck.enabled}
											>
												{#snippet children()}{language.current && t('routes.form.healthCheckHeaderRemove')}{/snippet}
											</Button>
										</div>
									{/each}
									{#if errors['healthCheck.headers']}
										<p class="text-xs text-down">{errors['healthCheck.headers']}</p>
									{/if}
									<Button
										variant="secondary"
										size="sm"
										onclick={addHealthCheckHeader}
										disabled={!formData.healthCheck.enabled}
									>
										{#snippet children()}{language.current && t('routes.form.healthCheckHeaderAdd')}{/snippet}
									</Button>
								</div>

								<!-- v2.56 — run the check before saving it.
								     Until now a misconfigured check surfaced only as
								     a post-save 503 and an undone change, which
								     protected the site and explained nothing. -->
								<div class="flex flex-col gap-2 pt-2 border-t border-border-subtle">
									<div class="flex items-center gap-2">
										<Button
											variant="secondary"
											size="sm"
											onclick={runHealthCheckProbe}
											loading={hcProbeRunning}
											disabled={!formData.healthCheck.enabled || hcProbeRunning}
										>
											{#snippet children()}{language.current && t('routes.form.healthCheckProbeButton')}{/snippet}
										</Button>
										<span class="text-xs text-secondary">
											{language.current && t('routes.form.healthCheckProbeHint')}
										</span>
									</div>

									{#if hcProbeError}
										<p class="text-xs text-down" role="alert" data-testid="hc-probe-error">
											{hcProbeError}
										</p>
									{/if}

									{#each hcProbeResults as res (res.upstream)}
										<div
											class="rounded-md border p-2.5 text-xs flex flex-col gap-1.5"
											class:border-up={res.healthy}
											class:border-down={!res.healthy}
											data-testid="hc-probe-result"
										>
											<div class="flex items-center gap-2 flex-wrap">
												<span class={res.healthy ? 'text-up font-medium' : 'text-down font-medium'}>
													{res.healthy ? '✓' : '✗'} {res.upstream}
												</span>
												{#if res.got}
													<span class="text-secondary font-mono">
														HTTP {res.got.statusCode} · {res.got.durationMs}ms
													</span>
												{/if}
											</div>

											{#if res.reason}
												<p class="text-down" data-testid="hc-probe-reason">{res.reason}</p>
											{/if}
											{#if res.hint}
												<p class="text-warn" data-testid="hc-probe-hint">{res.hint}</p>
											{/if}

											<!-- What went out, so the operator reads the request
											     instead of reconstructing it. -->
											<p class="text-muted font-mono break-all">
												{res.sent.method} {res.sent.url} — Host: {res.sent.host}
											</p>
											{#if res.sent.headers}
												{#each Object.entries(res.sent.headers) as [name, value] (name)}
													<p class="text-muted font-mono break-all">{name}: {value}</p>
												{/each}
											{/if}

											{#if res.got?.location}
												<p class="text-secondary font-mono break-all">
													Location: {res.got.location}
												</p>
											{/if}
											{#if res.got?.bodyExcerpt}
												<details>
													<summary class="cursor-pointer text-secondary">
														{language.current && t('routes.form.healthCheckProbeBody')}
														{#if res.got.bodyMatched === false}
															— {language.current && t('routes.form.healthCheckProbeBodyNoMatch')}
														{:else if res.got.bodyMatched === true}
															— {language.current && t('routes.form.healthCheckProbeBodyMatch')}
														{/if}
													</summary>
													<pre class="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all text-muted">{res.got
															.bodyExcerpt}{res.got.bodyTruncated ? '\n…' : ''}</pre>
												</details>
											{/if}
										</div>
									{/each}
								</div>
								<Input
									label={language.current && t('routes.form.healthCheckExpectBodyLabel')}
									bind:value={formData.healthCheck.expectBody}
									disabled={!formData.healthCheck.enabled}
									oninput={markHealthCheckTouched}
									error={errors['healthCheck.expectBody'] ?? undefined}
								/>
								<p class="text-xs text-muted">
									{language.current && t('routes.form.healthCheckHelper')}
								</p>
						</div>
					</RouteSection>

					<!-- Path rules and custom headers. -->
					<RouteSection
						name={language.current && t('routes.form.sectionPathsHeaders')}
						summary={summaryPathsHeaders}
						badge={pathsHeadersBadge?.badge}
						posture={pathsHeadersBadge?.posture}
						testid="section-paths-headers"
					>
						{#each formData.pathRules as _rule, i (i)}
							{#if errors[`pathRules.${i}`]}
								<p class="text-xs text-down" role="alert" data-testid="path-rule-error-{i}">
									{errors[`pathRules.${i}`]}
								</p>
							{/if}
						{/each}
						<!-- path-based-rules Task 9 — collapsed path-scoped
						     rules editor (Task 8 component): per-prefix basic
						     auth override + IP filter. -->
						<PathRulesSection bind:value={formData.pathRules} {forwardAuthProviders} />
						<!-- Step I.6: custom request headers. v2.41 — one
						     labelled group instead of a second collapse level
						     inside an already-collapsible section, with an
						     empty state that says what the group is for. -->
						<div class="rounded-md border border-border-subtle bg-surface p-3 flex flex-col gap-2">
							<div class="flex items-baseline justify-between gap-3">
								<span class="text-sm font-medium text-secondary"
									>{language.current && t('routes.form.requestHeadersLabel')}</span
								>
								{#if requestHeaderRows.length > 0}
									<span class="text-xs text-muted">({requestHeaderRows.length})</span>
								{/if}
							</div>
							{#if requestHeaderRows.length === 0}
								<p class="text-xs text-muted" data-testid="request-headers-empty">
									{language.current && t('routes.form.headersEmpty')}
								</p>
							{/if}
							{#each requestHeaderRows as _, i (i)}
								<div class="flex items-center gap-2">
									<Input bind:value={requestHeaderRows[i][0]} placeholder={language.current && t('routes.form.headerNamePlaceholder')} />
									<Input bind:value={requestHeaderRows[i][1]} placeholder={language.current && t('routes.form.headerValuePlaceholder')} />
									<Button variant="ghost" size="sm" onclick={() => removeRequestHeader(i)} type="button">×</Button>
								</div>
							{/each}
							<div>
								<Button variant="ghost" size="sm" onclick={addRequestHeader} type="button"
									>{language.current && t('routes.form.requestHeadersAdd')}</Button
								>
							</div>
						</div>
						<!-- Step I.6: custom response headers. v2.41 — one
						     labelled group instead of a second collapse level
						     inside an already-collapsible section, with an
						     empty state that says what the group is for. -->
						<div class="rounded-md border border-border-subtle bg-surface p-3 flex flex-col gap-2">
							<div class="flex items-baseline justify-between gap-3">
								<span class="text-sm font-medium text-secondary"
									>{language.current && t('routes.form.responseHeadersLabel')}</span
								>
								{#if responseHeaderRows.length > 0}
									<span class="text-xs text-muted">({responseHeaderRows.length})</span>
								{/if}
							</div>
							{#if responseHeaderRows.length === 0}
								<p class="text-xs text-muted" data-testid="response-headers-empty">
									{language.current && t('routes.form.headersEmptyResponse')}
								</p>
							{/if}
							{#each responseHeaderRows as _, i (i)}
								<div class="flex items-center gap-2">
									<Input bind:value={responseHeaderRows[i][0]} placeholder={language.current && t('routes.form.headerNamePlaceholder')} />
									<Input bind:value={responseHeaderRows[i][1]} placeholder={language.current && t('routes.form.headerValuePlaceholder')} />
									<Button variant="ghost" size="sm" onclick={() => removeResponseHeader(i)} type="button">×</Button>
								</div>
							{/each}
							<div>
								<Button variant="ghost" size="sm" onclick={addResponseHeader} type="button"
									>{language.current && t('routes.form.responseHeadersAdd')}</Button
								>
							</div>
						</div>
					</RouteSection>

					<!-- Error pages. -->
					<RouteSection
						name={language.current && t('routes.form.sectionErrorPages')}
						summary={summaryErrorPages}
						badge={errorPagesBadge?.badge}
						posture={errorPagesBadge?.posture}
						testid="section-error-pages"
					>
						<!--
						  Step R Phase 2.b — error pages section.
						  Sits between Rate Limit and Country Block
						  to match the operator's mental model :
						  "what happens when this route returns
						  something the client shouldn't normally
						  see". The built-in Arenet branded default
						  applies AUTOMATICALLY (Phase 1.1 FIX 1)
						  for every code on every route ; the
						  template dropdown lets the operator
						  override the visual branding ; the per-
						  route overrides sub-form lets the operator
						  override individual codes (highest
						  precedence in the 3-layer resolution).
						-->
						<div>
							<label
								class="text-sm font-medium text-secondary block mb-1"
								for="route-error-template"
							>
								{language.current && t('routes.form.errorPagesSection')}
							</label>
							<div class="mt-2 flex items-center gap-2">
								<select
									id="route-error-template"
									bind:value={formData.errorPageTemplateId}
									class="flex-1 bg-surface border border-default rounded text-sm px-2 py-1.5 text-primary"
									data-testid="error-template-select"
								>
									<option value="">{language.current && t('routes.form.errorPagesTemplateNoneOption')}</option>
									{#each errorTemplates as t (t.id)}
										<option value={t.id}>{t.name}</option>
									{/each}
								</select>
								<a
									href="/settings/error-pages"
									class="text-xs text-cyan whitespace-nowrap"
									title={language.current && t('routes.form.errorPagesTemplateManageTooltip')}
								>
									{language.current && t('routes.form.errorPagesTemplateManageLink')}
								</a>
							</div>
							<p class="text-xs text-muted mt-1">
								{language.current && t('routes.form.errorPagesTemplateHelper')}
							</p>

							<!-- v2.41.1 — the per-code override editor was a second
							     collapse level inside an already-collapsible section
							     for something an operator sets once, if ever. It
							     lives in Settings → Error pages now. Overrides
							     already stored on a route keep applying and are
							     preserved on save; the line below exists so they are
							     never silently invisible. -->
							{#if errorOverrideCount > 0}
								<p class="text-xs text-muted mt-2" data-testid="error-overrides-notice">
									{language.current &&
										t('routes.form.errorPagesOverrideNotice', { count: errorOverrideCount })}
									<a href="/settings/error-pages" class="text-cyan hover:underline"
										>{language.current && t('routes.form.errorPagesTemplateManageLink')}</a
									>
								</p>
							{/if}
						</div>
					</RouteSection>


					<button type="submit" class="hidden" aria-hidden="true"></button>
				</form>

				<!-- Panel footer — Cancel + Save. Cancel calls
				     closePanel() (drops selection + form state, back
				     to empty state). Save reuses the existing
				     submitForm() flow. On success submitForm clears
				     formOpen via the existing path; on validation
				     errors the panel stays open with field-level
				     messages. -->
				<div class="px-5 pb-5 pt-2 flex items-center justify-between gap-2 border-t border-border-subtle">
					{#if formMode === 'edit' && editingId}
						<div class="delete-slot">
							<Button
								variant="ghost"
								onclick={() => {
									if (editingId) {
										const target = routes.find((r) => r.id === editingId);
										if (target) confirmTarget = target;
									}
								}}>{language.current && t('routes.panel.deleteButton')}</Button
							>
						</div>
					{:else}
						<span></span>
					{/if}
					<div class="flex gap-2">
					<Button variant="ghost" onclick={() => guardUnsaved(closePanel)}
						>{language.current && t('routes.form.cancel')}</Button
					>
					<Button
						onclick={submitForm}
						loading={submitting}
						disabled={submitting || dedicatedOptOutPendingChoice}
					>
						{language.current && (formMode === 'create' ? t('routes.form.create') : t('routes.form.save'))}
					</Button>
					</div>
				</div>
			{/if}

			<!--
				Phase 5 follow-up — Caddy-reload overlay (T2). Sits
				on top of the form/footer while submitForm() is
				awaiting the PUT/POST. Mirrors the spinner on the
				Save button but at panel-scale so the operator
				perceives the ~5s wait as "Caddy is being reloaded",
				not as "the UI is frozen". The veil also blocks
				accidental input edits during the in-flight save —
				clicks pass through to the veil, not to the form
				underneath.
			-->
			{#if submitting}
				<div
					class="absolute inset-0 z-10 flex items-center justify-center bg-elevated/85 backdrop-blur-sm rounded-lg"
					role="status"
					aria-live="polite"
					aria-busy="true"
					data-testid="route-save-overlay"
				>
					<div class="flex flex-col items-center gap-3 px-4 py-3 rounded-md">
						<Spinner size="md" />
						<p class="text-sm text-secondary">
							Application des modifications Caddy…
						</p>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}

<Modal
	open={confirmTarget !== null}
	title={language.current && t('routes.delete.title')}
	onClose={() => (confirmTarget = null)}
>
	{#if confirmTarget}
		<p class="text-sm">
			{language.current && t('routes.delete.confirmText')}
			<code class="font-mono text-cyan">{confirmTarget.host}</code>?
		</p>
		<p class="text-xs text-secondary mt-2">
			{language.current && t('routes.delete.warning')}
		</p>
	{/if}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (confirmTarget = null)}>{language.current && t('routes.delete.cancel')}</Button>
		<Button variant="danger" loading={deleting} onclick={confirmDelete}>{language.current && t('routes.delete.confirm')}</Button>
	{/snippet}
</Modal>

<!-- Step X.2 — ADR-D4 confirm dialog. Gates the wafDisableCRS
     false → true transition so the operator can't accidentally
     disable the OWASP CRS by a stray click. The dialog is bound
     to `confirmDisableCRSOpen` ; the toggle's onchange handler
     opens it before any state mutation, and onConfirm commits
     the formData flip. Cancel (or any other close path) leaves
     formData.wafDisableCRS at false ; the checkbox's visual
     state reflects formData via the `checked` prop so the tick
     reverts automatically. -->
<!-- v2.41 — leaving the form with unsaved changes asks first. -->
<ConfirmDialog
	bind:open={confirmDiscardOpen}
	title={language.current && t('routes.discardDialog.title')}
	message={language.current && t('routes.discardDialog.message')}
	confirmLabel={language.current && t('routes.discardDialog.confirmLabel')}
	cancelLabel={language.current && t('routes.discardDialog.cancelLabel')}
	confirmVariant="danger"
	onConfirm={onConfirmDiscard}
/>

<ConfirmDialog
	bind:open={confirmDisableCRSOpen}
	title={language.current && t('routes.wafCRSDialog.title')}
	message={language.current && t('routes.wafCRSDialog.message')}
	confirmLabel={language.current && t('routes.wafCRSDialog.confirmLabel')}
	cancelLabel={language.current && t('routes.wafCRSDialog.cancelLabel')}
	confirmVariant="danger"
	onConfirm={onConfirmDisableCRS}
/>

<!-- v2.14.3 — row-level Disable confirm. Uses the Modal + manual
     footer pattern (matching the Delete dialog above) rather than
     ConfirmDialog, because the test-driven contract needs a
     data-testid on the confirm button (ConfirmDialog's internal
     Button doesn't expose one). Copy branches on disableIsLastHttps,
     computed PRE-call in openDisableConfirm() from the currently-
     loaded route list (see the function's doc comment): true only
     when the row being disabled is the sole active TLS route. -->
<Modal
	open={disableTarget !== null}
	title={language.current &&
		(disableIsLastHttps
			? t('routes.disable.confirm.lastHttps.title')
			: t('routes.disable.confirm.title'))}
	onClose={() => (disableTarget = null)}
>
	{#if disableTarget}
		<p class="text-sm">
			{language.current &&
				(disableIsLastHttps
					? t('routes.disable.confirm.lastHttps.text')
					: t('routes.disable.confirm.text'))}
		</p>
	{/if}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (disableTarget = null)}>{language.current && t('routes.delete.cancel')}</Button>
		<Button
			variant="danger"
			loading={disablingRoute}
			data-testid="route-disable-confirm"
			onclick={confirmDisableRoute}
		>
			{language.current &&
				(disableIsLastHttps
					? t('routes.disable.confirm.lastHttps.action')
					: t('routes.disable.confirm.action'))}
		</Button>
	{/snippet}
</Modal>

<style>

	/* v2.48 — the table owns the page until something is selected.
	   
	   The split was fixed at two columns, so the list sat squeezed
	   into 55% of the width even with nothing open beside it — every
	   column truncated for a panel that was not there.
	   
	   Both tracks always exist; the second animates between 0fr and
	   1fr. That is what makes the transition possible at all:
	   grid-template-columns interpolates when the two sides have the
	   same structure, which swapping between one and two tracks does
	   not. The collapsed track needs overflow hidden and min-width 0
	   or its content refuses to shrink below its intrinsic size and
	   the animation fights itself. */
	/* v2.61 — the two drill-down links, given the chrome of a real
	   secondary button. They were 11px text-secondary on a bare
	   surface, which read as help text rather than as something you
	   click. Same tokens as Button variant="secondary". */
	/* v2.61 — a list cell that is also a link. No underline, no colour
	   change: the chips and the badge already carry their own meaning,
	   and turning them blue would say "this is a link" twice while
	   making the posture harder to read. The cursor and the hover tint
	   are the affordance. */
	.cell-pivot {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		border-radius: var(--radius-sm);
		padding: 2px 4px;
		margin: -2px -4px;
		text-decoration: none;
		color: inherit;
		transition: background var(--motion-fast);
	}
	.cell-pivot:hover {
		background: var(--bg-hover);
	}
	.cell-pivot:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 1px;
	}

	.pivot-btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		border-radius: var(--radius-md);
		border: 1px solid var(--border-strong);
		background: var(--bg-elevated);
		color: var(--text-primary);
		font-size: var(--text-sm);
		font-weight: 500;
		padding: 6px 12px;
		text-decoration: none;
		transition:
			background var(--motion-fast),
			border-color var(--motion-fast);
	}
	.pivot-btn:hover {
		background: var(--bg-hover);
		border-color: var(--accent);
	}
	.pivot-btn:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	/* Present before the first save, and plainly not yet usable. A
	   control that only appears once you have guessed it exists
	   teaches nothing. */
	.pivot-btn-disabled {
		opacity: 0.55;
		cursor: not-allowed;
		color: var(--text-muted);
		border-style: dashed;
	}

	.split {
		display: grid;
		grid-template-columns: 1fr;
		gap: 1rem;
		align-items: start;
	}
	@media (min-width: 1280px) {
		.split {
			grid-template-columns: 1fr 0fr;
			transition: grid-template-columns 260ms ease;
		}
		.split.split-open {
			grid-template-columns: var(--split-open-cols, 1.3fr 1fr);
		}
		/* v2.55 — overflow-x, NOT the shorthand.

		   The animation needs the collapsed track to clip HORIZONTALLY.
		   The shorthand also clipped vertically, and Svelte's scoping
		   makes this selector (0,2,0) — two classes — so it beat the
		   edit panel's own `overflow-auto` utility at (0,1,0).

		   The panel therefore had `max-height: calc(100vh - …)` with
		   `overflow: hidden`: everything past the cap was cut off with
		   no scrollbar. Opening a form section pushed the footer past
		   the cap and Save became unreachable — collapsing the section
		   brought it back, which is how the operator found it.

		   Leaving overflow-y alone lets it resolve to auto (a box with
		   one axis hidden and the other visible computes to auto), so
		   the panel scrolls again while the track still clips sideways. */
		.split > * {
			min-width: 0;
			overflow-x: hidden;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.split {
			transition: none;
		}
	}
	/* v2.41.1 — Delete sits in the footer, left, away from Save.
	   Ghost shape so it doesn't compete with the primary action,
	   red text so it is unmistakably the destructive one. */
	.delete-slot :global(button) {
		color: var(--status-down);
	}
	.delete-slot :global(button:hover) {
		color: var(--status-down);
		background: color-mix(in oklch, var(--status-down) 12%, transparent);
	}

	/* Selected-row visual state for the Routes table (C11 Pack A
	   polish, 2026-06-06). The Tailwind classes on the row carry
	   the base + hover styles; this block layers the
	   selected-when-editing affordance on top.

	   The brief calls for "subtle accent tint + left-border
	   accent" — using the shared --accent token (same as the
	   .nav-item.active state and Topology's hub border) so a
	   future theme change propagates everywhere. Inset
	   box-shadow gives the left edge a 3px solid accent stripe
	   without requiring a layout-shifting border. */
	:global(tr.route-row-selected) {
		background: color-mix(in oklch, var(--accent) 10%, transparent);
		box-shadow: inset 3px 0 0 0 var(--accent);
	}
	/* Slightly stronger hover on the selected row so the click
	   target still feels "live", not visually frozen. */
	:global(tr.route-row-selected:hover) {
		background: color-mix(in oklch, var(--accent) 16%, transparent);
	}

	/* W.5 + W.7 — country-block UI styles.
	   W.5 introduced the chip; W.7 polishes the surface:
	   - Mode-colored section border (slate / green / red).
	   - 3-button pill toggle replaces the mode dropdown.
	   - Chips recolor to the active mode + show resolved
	     country name next to the code.
	   - Autocomplete dropdown styled to match the form's
	     existing select aesthetic.
	   Color tokens reused from styles/tokens.css: --status-up
	   (success green), --status-down (danger red),
	   --status-meta (neutral slate). Spec brief mentioned
	   --status-success / --status-danger which don't exist
	   in the design system — using the canonical *-up / *-down
	   tokens instead (same hues; the project already maps
	   them to success/danger semantics via the --badge-*
	   derived tokens). */

	/* Section border tinted by active mode so the operator's
	   choice radiates outward from the toggle to the whole
	   panel. cb-mode-off is the default border-subtle. */
	.cb-section.cb-mode-allow {
		border-color: color-mix(in oklch, var(--status-up) 50%, var(--border-subtle));
	}
	.cb-section.cb-mode-deny {
		border-color: color-mix(in oklch, var(--status-down) 50%, var(--border-subtle));
	}

	/* Mode toggle — 3 segmented buttons. Active button picks
	   up the mode color; inactive buttons stay neutral. */
	.cb-mode-toggle {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 6px;
	}
	.cb-mode-btn {
		appearance: none;
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		padding: 8px 10px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: 6px;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: 12px;
		font-weight: 500;
		text-align: left;
		transition: border-color 80ms ease-out, background 80ms ease-out;
	}
	.cb-mode-btn:hover {
		background: color-mix(in oklch, var(--accent) 6%, var(--bg-surface));
	}
	.cb-mode-btn__label {
		font-size: 12.5px;
		font-weight: 600;
		color: var(--text-primary);
	}
	.cb-mode-btn__hint {
		font-size: 10.5px;
		color: var(--text-muted);
	}
	.cb-mode-btn.active.cb-mode-btn--off {
		border-color: var(--status-meta);
		background: color-mix(in oklch, var(--status-meta) 12%, var(--bg-surface));
	}
	.cb-mode-btn.active.cb-mode-btn--allow {
		border-color: var(--status-up);
		background: color-mix(in oklch, var(--status-up) 12%, var(--bg-surface));
	}
	.cb-mode-btn.active.cb-mode-btn--allow .cb-mode-btn__label {
		color: var(--status-up);
	}
	.cb-mode-btn.active.cb-mode-btn--deny {
		border-color: var(--status-down);
		background: color-mix(in oklch, var(--status-down) 12%, var(--bg-surface));
	}
	.cb-mode-btn.active.cb-mode-btn--deny .cb-mode-btn__label {
		color: var(--status-down);
	}

	/* Chip — recolors based on the section's mode class.
	   Default (off / no mode) keeps the original slate tint
	   in case a chip is rendered outside an active section
	   (shouldn't happen today, but defensive). */
	.cb-chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 3px 4px 3px 8px;
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		color: var(--text-secondary);
		background: color-mix(in oklch, var(--status-meta) 14%, transparent);
		border: 1px solid color-mix(in oklch, var(--status-meta) 40%, var(--border-subtle));
		border-radius: 999px;
	}
	.cb-mode-allow .cb-chip {
		background: color-mix(in oklch, var(--status-up) 12%, transparent);
		border-color: color-mix(in oklch, var(--status-up) 45%, var(--border-subtle));
		color: var(--status-up);
	}
	.cb-mode-deny .cb-chip {
		background: color-mix(in oklch, var(--status-down) 12%, transparent);
		border-color: color-mix(in oklch, var(--status-down) 45%, var(--border-subtle));
		color: var(--status-down);
	}
	.cb-chip__name {
		font-family: var(--font-sans);
		font-weight: 400;
		letter-spacing: 0;
		font-size: 11.5px;
		color: var(--text-secondary);
		max-width: 140px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	/* In allow/deny modes the chip text picks up the mode
	   color; let the name follow too (slightly muted via
	   color-mix so it doesn't compete with the code). */
	.cb-mode-allow .cb-chip__name {
		color: color-mix(in oklch, var(--status-up) 75%, var(--text-secondary));
	}
	.cb-mode-deny .cb-chip__name {
		color: color-mix(in oklch, var(--status-down) 75%, var(--text-secondary));
	}
	.cb-chip__remove {
		appearance: none;
		background: none;
		border: 0;
		color: currentColor;
		opacity: 0.6;
		cursor: pointer;
		font-size: 14px;
		line-height: 1;
		padding: 0 4px;
		border-radius: 999px;
		transition: opacity 80ms ease-out, background 80ms ease-out;
	}
	.cb-chip__remove:hover {
		opacity: 1;
		background: color-mix(in oklch, currentColor 15%, transparent);
	}

	/* Autocomplete dropdown — absolute-positioned under
	   the input. Uses surface bg + subtle shadow for
	   focal weight; mirrors the form's existing select
	   panels. */
	.cb-input-wrap {
		position: relative;
	}
	.cb-dropdown {
		position: absolute;
		top: calc(100% + 4px);
		left: 0;
		right: 0;
		max-height: 240px;
		overflow-y: auto;
		background: var(--bg-surface);
		border: 1px solid var(--border-default);
		border-radius: 6px;
		box-shadow: 0 6px 18px color-mix(in oklch, var(--bg-base) 30%, transparent);
		z-index: 10;
		list-style: none;
		margin: 0;
		padding: 4px 0;
	}
	.cb-dropdown__item {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 6px 10px;
		cursor: pointer;
		font-size: 12.5px;
		color: var(--text-secondary);
	}
	.cb-dropdown__item.active,
	.cb-dropdown__item:hover {
		background: color-mix(in oklch, var(--accent) 12%, transparent);
		color: var(--text-primary);
	}
	.cb-dropdown__name {
		flex: 1;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* "+ Ajouter un pays" CTA — pill-shaped accent button
	   that opens the dropdown + focuses the input. */
	.cb-add-btn {
		appearance: none;
		padding: 6px 12px;
		background: color-mix(in oklch, var(--accent) 14%, transparent);
		border: 1px solid color-mix(in oklch, var(--accent) 40%, var(--border-subtle));
		border-radius: 6px;
		color: var(--accent);
		font-size: 12px;
		font-weight: 600;
		cursor: pointer;
		white-space: nowrap;
		transition: background 80ms ease-out;
	}
	.cb-add-btn:hover {
		background: color-mix(in oklch, var(--accent) 22%, transparent);
	}
	/* v2.34 — geo filter: one "matches if" group (continent OR country
	   OR network) and a separate exceptions box. */
	.geo-match-group,
	.geo-exceptions {
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 10px 12px;
		border-radius: 8px;
		border: 1px solid var(--border-subtle);
	}
	.geo-exceptions {
		border-style: dashed;
		border-color: color-mix(in oklch, var(--status-up) 45%, var(--border-subtle));
	}
	.geo-match-group__head {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.geo-or {
		display: flex;
		align-items: center;
		gap: 8px;
		color: var(--text-muted);
		font-size: 11px;
		text-transform: uppercase;
		letter-spacing: 0.08em;
	}
	.geo-or::before,
	.geo-or::after {
		content: '';
		flex: 1;
		border-top: 1px dashed var(--border-subtle);
	}
</style>
