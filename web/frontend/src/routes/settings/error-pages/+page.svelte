<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R Phase 2.a — /settings/error-pages

  Operator-facing CRUD for custom HTML error-page templates.
  State-driven (no sub-routes) : `view` toggles between
  'list' (DataTable of templates with row actions) and
  'edit' (8 status-code tabs + CodeMirror + iframe preview
  + Variables panel + Save/Cancel).

  Backend reference : POST/GET/PUT/DELETE /api/v1/error-
  templates + GET /api/v1/error-templates/{id}/preview
  (commit f51167c Phase 1).

  3-layer resolution at serve time (caddymgr-side, Phase 1) :
    1. Route.ErrorPageOverrides[code]
    2. Template.Pages[code]
    3. Built-in Arenet branded default
  This page only manages templates (layer 2) ; the per-route
  override layer (1) lives in the RouteForm "Pages d'erreur"
  section (R.2.b sibling work).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import HtmlEditor from '$lib/components/HtmlEditor.svelte';
	import Button from '$lib/components/Button.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import {
		errorTemplatesApi,
		BUILTIN_TEMPLATE_ID,
		SUPPORTED_ERROR_STATUS_CODES,
		ERROR_PAGE_PLACEHOLDERS,
		type ErrorTemplate,
		type SupportedErrorStatusCode
	} from '$lib/api/error-templates';
	import { pushToast } from '$lib/stores/toast';
	import { ApiError } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	// --- Top-level section tabs ----------------------------

	// Task 10 — the page now has two top-level sections :
	// "Templates" (the pre-existing list/edit CRUD, unchanged
	// below) and "Maintenance" (a single global HTML page
	// served on any route toggled into maintenance mode).
	// Kept as a sibling state machine rather than folding
	// Maintenance into the `view` union above so the existing
	// list/edit toggle (and its many call sites) stay untouched.
	type Section = 'templates' | 'maintenance';
	let section = $state<Section>('templates');

	// --- View state ---------------------------------------

	type View = 'list' | 'edit';
	let view = $state<View>('list');

	// --- List state ---------------------------------------

	let templates = $state<ErrorTemplate[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	async function loadTemplates(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			templates = await errorTemplatesApi.list();
		} catch (err) {
			// Surface ApiError.message verbatim ; for plain Error
			// (network down, abort, etc.) use .message too rather
			// than a generic "failed to load" so the operator sees
			// the actual cause without opening DevTools.
			loadError =
				err instanceof ApiError
					? err.message
					: err instanceof Error
						? err.message
						: t('errorPages.errFailedLoad');
			templates = [];
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void loadTemplates();
	});

	// --- Editor state -------------------------------------

	// Null when creating a new template, populated when editing.
	let editingId = $state<string | null>(null);
	// Step R Phase 2.1 — when the operator opens the virtual
	// builtin for inspection, the editor runs in read-only
	// mode : Save is hidden, Delete is hidden, the only
	// available action is Duplicate. The flag distinguishes
	// "editing a real DB template" (false) from "previewing
	// the builtin to decide whether to duplicate" (true).
	let editingBuiltin = $state(false);
	let editName = $state('');
	let editDescription = $state('');
	// v2.9.10 Bug 1 — when true, this template's pages[404] body
	// is served by Arenet's catch-all (host not configured on any
	// route). Storage enforces mutual exclusion: at most one
	// template carries the flag at a time. Setting it true on
	// save auto-clears any previously-flagged template.
	let editIsCatchallDefault = $state(false);
	let editIsRouteDefault = $state(false);
	// Sparse Pages map ; codes absent fall back to template-side
	// default at serve time. Active tab governs which buffer is
	// shown in the CodeMirror editor.
	let editPages = $state<Record<number, string>>({});
	let activeCode = $state<SupportedErrorStatusCode>(403);
	let saving = $state(false);
	let editorRef = $state<HtmlEditor | undefined>();

	// Two-way bound to the editor : reads the active code's
	// body from editPages, writes back on user typing. Mirrored
	// into editPages on every change (Svelte 5 $effect).
	let activeBuffer = $state('');

	// When the active tab changes, snap activeBuffer to the
	// corresponding editPages entry. When activeBuffer changes
	// (user typed), write back to editPages.
	//
	// $state(activeCode) for the previous-tab snapshot so the
	// effect re-reads it reactively (Svelte 5 warns when a
	// top-level `let x = activeCode` is referenced inside an
	// effect because it captures the initial value only — the
	// $state wrapper makes the comparison reactive).
	let lastActiveCode = $state<SupportedErrorStatusCode>(403);
	$effect(() => {
		if (activeCode !== lastActiveCode) {
			activeBuffer = editPages[activeCode] ?? '';
			lastActiveCode = activeCode;
		}
	});
	$effect(() => {
		// Only write back when editing (not during reset).
		if (view !== 'edit') return;
		editPages[activeCode] = activeBuffer;
	});

	// Unsaved edits: Cancel used to drop the name, the flags and all
	// eight status-code bodies without asking. The editor is
	// snapshotted when it opens; Cancel asks when anything differs.
	// Empty bodies are dropped on both sides, as save does, so moving
	// between code tabs alone is not an edit.
	function editState(): string {
		const pages = Object.entries(editPages)
			.filter(([, body]) => body.trim() !== '')
			.sort(([a], [b]) => Number(a) - Number(b));
		return JSON.stringify([
			editName,
			editDescription,
			editIsCatchallDefault,
			editIsRouteDefault,
			pages
		]);
	}
	let editSnapshot = $state('');
	const editDirty = $derived(view === 'edit' && !editingBuiltin && editState() !== editSnapshot);
	let confirmDiscardOpen = $state(false);

	function startCreate(): void {
		editingId = null;
		editingBuiltin = false;
		editName = '';
		editDescription = '';
		editIsCatchallDefault = false;
		editIsRouteDefault = false;
		editPages = {};
		activeCode = 403;
		activeBuffer = '';
		previewHtml = '';
		view = 'edit';
		editSnapshot = editState();
	}

	function startEdit(t: ErrorTemplate): void {
		editingId = t.id;
		editingBuiltin = t.isBuiltin === true;
		editName = t.name;
		editDescription = t.description ?? '';
		editIsCatchallDefault = t.isCatchallDefault === true;
		editIsRouteDefault = t.isRouteDefault === true;
		// Cast key strings back to numbers (server returns
		// Record<string, string> by JSON convention).
		const pages: Record<number, string> = {};
		for (const [k, v] of Object.entries(t.pages)) {
			pages[Number(k)] = v;
		}
		editPages = pages;
		activeCode = 403;
		activeBuffer = pages[403] ?? '';
		previewHtml = '';
		view = 'edit';
		editSnapshot = editState();
	}

	// Step R Phase 2.1 — duplicate flow.
	//
	// Operator clicks "Dupliquer" on the builtin card (or on
	// any editable row's hypothetical future Duplicate
	// button) → we create a fresh DB template with the source
	// content + a unique-among-existing name following the
	// macOS Finder pattern: "Copy of X", "Copy of X (2)",
	// "Copy of X (3)" ... Backend has no name uniqueness
	// constraint (Phase 1 storage validate) so the suffix
	// strategy is pure UX hygiene ; collisions would be
	// silently accepted server-side, but the operator
	// shouldn't see two rows with the same name.
	//
	// On success : reload list, switch to editing the new
	// (now editable) row so the operator can immediately
	// customise.
	async function duplicateTemplate(source: ErrorTemplate): Promise<void> {
		const baseName = `Copy of ${source.name}`;
		const uniqueName = computeUniqueCopyName(baseName, templates);
		const pages: Record<string, string> = { ...source.pages };
		try {
			const created = await errorTemplatesApi.create({
				name: uniqueName,
				description: source.description,
				pages
			});
			pushToast(t('errorPages.toastDuplicated', { name: uniqueName }), 'success');
			await loadTemplates();
			startEdit(created);
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('errorPages.errFailedDuplicate');
			pushToast(msg, 'danger');
		}
	}

	// macOS Finder-style copy naming. Returns baseName if no
	// row already uses it ; otherwise appends "(N)" with the
	// smallest N >= 2 that resolves the conflict.
	//
	// Exported via export shim at the bottom of the script so
	// the page.test.ts can pin the algorithm without going
	// through the full duplicate-and-create round-trip.
	function computeUniqueCopyName(baseName: string, existing: ErrorTemplate[]): string {
		const names = new Set(existing.map((t) => t.name));
		if (!names.has(baseName)) return baseName;
		for (let n = 2; n < 1000; n++) {
			const candidate = `${baseName} (${n})`;
			if (!names.has(candidate)) return candidate;
		}
		// Operator has somehow created 998 copies of the same
		// template ; degrade with a timestamp rather than loop
		// forever. Genuinely never reached in practice.
		return `${baseName} (${Date.now()})`;
	}

	function cancelEdit(): void {
		if (editDirty) {
			confirmDiscardOpen = true;
			return;
		}
		leaveEdit();
	}

	function leaveEdit(): void {
		confirmDiscardOpen = false;
		view = 'list';
		previewHtml = '';
	}

	async function saveTemplate(): Promise<void> {
		// Phase 2.1 — the read-only builtin path : the Save
		// button is hidden in the template (see {#if !editingBuiltin}
		// guard around the actions snippet) so this branch
		// should be unreachable. Defence-in-depth in case a
		// future refactor surfaces the button :
		if (editingBuiltin) {
			pushToast(t('errorPages.toastReadOnly'), 'danger');
			return;
		}
		if (!editName.trim()) {
			pushToast(t('errorPages.toastNameRequired'), 'danger');
			return;
		}
		saving = true;
		try {
			// Strip empty bodies before submit — the operator
			// "cleared this code's override" gesture should not
			// persist as an explicit empty-string entry.
			const cleanPages: Record<number, string> = {};
			for (const [code, body] of Object.entries(editPages)) {
				if (body.trim()) cleanPages[Number(code)] = body;
			}
			const req = {
				name: editName.trim(),
				description: editDescription.trim() || undefined,
				pages: Object.fromEntries(
					Object.entries(cleanPages).map(([k, v]) => [String(k), v])
				),
				isCatchallDefault: editIsCatchallDefault,
				isRouteDefault: editIsRouteDefault
			};
			if (editingId === null) {
				await errorTemplatesApi.create(req);
				pushToast(t('errorPages.toastCreated', { name: editName }), 'success');
			} else {
				await errorTemplatesApi.update(editingId, req);
				pushToast(t('errorPages.toastUpdated', { name: editName }), 'success');
			}
			await loadTemplates();
			view = 'list';
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('errorPages.errFailedSave');
			pushToast(msg, 'danger');
		} finally {
			saving = false;
		}
	}

	// --- Delete with confirmation -------------------------

	let deleteTarget = $state<ErrorTemplate | null>(null);
	let deleting = $state(false);

	function askDelete(t: ErrorTemplate): void {
		deleteTarget = t;
	}

	async function confirmDelete(): Promise<void> {
		if (!deleteTarget) return;
		const target = deleteTarget;
		deleting = true;
		try {
			await errorTemplatesApi.delete(target.id);
			pushToast(t('errorPages.toastDeleted', { name: target.name }), 'success');
			deleteTarget = null;
			await loadTemplates();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : t('errorPages.errFailedDelete');
			pushToast(msg, 'danger');
		} finally {
			deleting = false;
		}
	}

	// --- Preview pane -------------------------------------

	// Held outside the active-code reactive chain so it only
	// updates on debounced keystrokes (300ms idle). iframe srcdoc
	// rerender on every char would flicker badly and trigger
	// excessive backend preview round-trips.
	let previewHtml = $state('');
	let previewLoading = $state(false);
	let previewError = $state<string | null>(null);
	let previewTimer: ReturnType<typeof setTimeout> | null = null;

	const PREVIEW_DEBOUNCE_MS = 300;

	function schedulePreview(): void {
		if (previewTimer !== null) {
			clearTimeout(previewTimer);
		}
		previewTimer = setTimeout(() => {
			void renderPreview();
			previewTimer = null;
		}, PREVIEW_DEBOUNCE_MS);
	}

	async function renderPreview(): Promise<void> {
		// The preview endpoint needs a persisted template ID.
		// For a freshly-created (unsaved) template, we fall
		// back to a client-side substitution mirror of the
		// backend's previewSubstitute() helper.
		previewError = null;
		previewLoading = true;
		try {
			if (editingId !== null && editPages[activeCode]) {
				// Persisted template : use server-side preview
				// (matches what'll render in prod via the same
				// placeholder substitution path).
				previewHtml = await errorTemplatesApi.preview(editingId, activeCode);
			} else {
				// Unsaved template : substitute client-side
				// using the same fixture values as the backend.
				previewHtml = clientSidePreview(activeBuffer, activeCode);
			}
		} catch (err) {
			previewError = err instanceof Error ? err.message : t('errorPages.errPreviewFailed');
			previewHtml = '';
		} finally {
			previewLoading = false;
		}
	}

	// Trigger preview render on activeBuffer change (debounced)
	// and immediately on tab switch.
	$effect(() => {
		if (view !== 'edit') return;
		// Read activeBuffer to register dependency.
		activeBuffer;
		schedulePreview();
	});

	// Client-side preview substitution. Mirror of the Go
	// previewSubstitute() in internal/api/error_templates.go.
	// Kept narrow + literal for transparency : operator sees
	// the same SHAPE they'll see in prod for these specific
	// tokens. Unknown placeholders pass through untouched.
	function clientSidePreview(body: string, code: number): string {
		const statusText: Record<number, string> = {
			401: 'Unauthorized',
			403: 'Forbidden',
			404: 'Not Found',
			429: 'Too Many Requests',
			500: 'Internal Server Error',
			502: 'Bad Gateway',
			503: 'Service Unavailable',
			504: 'Gateway Timeout'
		};
		const replacements: Record<string, string> = {
			'{http.error.status_code}': String(code),
			'{http.error.status_text}': statusText[code] ?? '',
			'{http.error.id}': 'preview-error-id-0000',
			'{http.error.message}': statusText[code] ?? '',
			'{http.reverse_proxy.status_code}': String(code),
			'{http.request.method}': 'GET',
			'{http.request.host}': 'preview.example.com',
			'{http.request.uri}': '/preview/path',
			'{http.request.uri.path}': '/preview/path',
			'{http.request.uuid}': '00000000-0000-4000-8000-000000000000',
			'{http.request.remote.host}': '203.0.113.42',
			'{time.now.year}': String(new Date().getFullYear()),
			'{system.hostname}': 'arenet-preview'
		};
		let out = body;
		for (const [k, v] of Object.entries(replacements)) {
			out = out.split(k).join(v);
		}
		return out;
	}

	// v2.69.0 — the maintenance preview substituted NOTHING: the iframe
	// took maintenanceHtml verbatim, so the operator judged their page
	// with the raw sentinels sitting in the middle of it, and could not
	// see the retry sentence at all — the built-in page's whole retry
	// line is one sentinel.
	//
	// Sibling of clientSidePreview above and literal for the same
	// reason — the operator sees the SHAPE prod will serve. The source of
	// truth for the wording is formatRetryAfterHuman in
	// internal/caddymgr/maintenance.go; 1800 → "30 minutes" is pinned by
	// a case in TestFormatRetryAfterHuman that names this file, so a
	// change there fails the Go suite instead of silently making this
	// preview lie.
	// 1800 seconds is the preview's notional Retry-After. It is written
	// out rather than inlined into the string because it is what makes
	// '30 minutes' checkable: TestFormatRetryAfterHuman's 1800 case is
	// the other half of this pair.
	const MAINTENANCE_PREVIEW_RETRY_HUMAN = '30 minutes'; // = 1800 seconds

	function maintenancePreview(body: string): string {
		const replacements: Record<string, string> = {
			'{arenet.maintenance.retry_after_human}': MAINTENANCE_PREVIEW_RETRY_HUMAN,
			'{arenet.maintenance.retry_after_line}': `<p class="retry">Retry in ${MAINTENANCE_PREVIEW_RETRY_HUMAN}</p>`,
			'{arenet.maintenance.message}': t('errorPages.maintenance.previewMessage'),
			// Emptied on purpose, not forgotten: substituting the real
			// <meta http-equiv="refresh"> would make the preview iframe
			// reload itself while the operator is editing.
			'{arenet.maintenance.refresh_meta}': '',
			'{http.request.method}': 'GET',
			'{http.request.host}': 'preview.example.com',
			'{http.request.uri}': '/preview/path',
			'{http.request.uri_escaped}': '/preview/path',
			'{http.request.uuid}': '00000000-0000-4000-8000-000000000000'
		};
		let out = body;
		for (const [k, v] of Object.entries(replacements)) {
			out = out.split(k).join(v);
		}
		return out;
	}

	// --- Variables panel ---------------------------------

	function insertPlaceholder(token: string): void {
		editorRef?.insertAtCursor(token);
	}

	// --- Maintenance section (Task 10) ---------------------
	//
	// Single global HTML page served on any route toggled into
	// maintenance mode (backend Task 7 : GET/PUT
	// /api/v1/settings/maintenance-page). Reuses HtmlEditor.svelte
	// (same component as the templates editor above) but is NOT
	// per-status-code — there's exactly one buffer.
	//
	// Loaded lazily on first visit to the Maintenance tab rather
	// than on page mount, so opening /settings/error-pages doesn't
	// pay for a request the operator may never need.

	let maintenanceHtml = $state('');
	let maintenanceLoading = $state(false);
	let maintenanceLoadError = $state<string | null>(null);
	let maintenanceSaving = $state(false);
	let maintenanceLoadedOnce = false;
	let maintenanceEditorRef = $state<HtmlEditor | undefined>();
	// v2.17.1 Item E — true when the buffer currently shown IS the
	// Arenet built-in default (backend reported isDefault:true because
	// the stored page is empty), false once the operator has a saved
	// custom page. Mirrors the templates tab's `tpl.isBuiltin` concept
	// (its "Built-in" badge) so the maintenance editor shows the same
	// visual cue instead of looking like an empty, unstarted buffer.
	let maintenanceIsDefault = $state(false);
	// v2.18.0 — the global maintenance message rendered by the built-in
	// default page (and any custom page) via {arenet.maintenance.message}.
	// Plain text, independent of the HTML buffer / isDefault flag.
	let maintenanceMessage = $state('');

	// v2.18.1 — placeholders usable in the maintenance page HTML, shown
	// as a click-to-insert palette under the editor. The Arenet
	// sentinels are baked in Go at emission ; the {http.request.*} ones
	// are expanded by Caddy at serve time (same set the templates editor
	// offers). {env.*}/{file.*} are intentionally absent — they're
	// neutralized for security.
	//
	// {arenet.maintenance.retry_after_line} is deliberately NOT here: it
	// expands to the built-in page's whole <p class="retry"> paragraph,
	// English prose and a class a custom page has no reason to inherit.
	// A custom page composes its own sentence around retry_after_human.
	const maintenancePlaceholders = $derived([
		{
			token: '{arenet.maintenance.retry_after_human}',
			desc: t('errorPages.maintenance.ph.retryAfterHuman')
		},
		{ token: '{arenet.maintenance.message}', desc: t('errorPages.maintenance.ph.message') },
		{ token: '{arenet.maintenance.refresh_meta}', desc: t('errorPages.maintenance.ph.refreshMeta') },
		{ token: '{http.request.method}', desc: t('errorPages.maintenance.ph.method') },
		{ token: '{http.request.host}', desc: t('errorPages.maintenance.ph.host') },
		{ token: '{http.request.uri}', desc: t('errorPages.maintenance.ph.uri') },
		{ token: '{http.request.uuid}', desc: t('errorPages.maintenance.ph.uuid') }
	]);

	async function loadMaintenancePage(): Promise<void> {
		maintenanceLoading = true;
		maintenanceLoadError = null;
		try {
			const res = await errorTemplatesApi.getMaintenancePage();
			maintenanceHtml = res.html;
			maintenanceIsDefault = res.isDefault;
			maintenanceMessage = res.message;
			maintenanceLoadedOnce = true;
		} catch (err) {
			maintenanceLoadError =
				err instanceof ApiError
					? err.message
					: err instanceof Error
						? err.message
						: t('errorPages.maintenance.errFailedLoad');
		} finally {
			maintenanceLoading = false;
		}
	}

	function selectSection(next: Section): void {
		section = next;
		if (next === 'maintenance' && !maintenanceLoadedOnce) {
			void loadMaintenancePage();
		}
	}

	async function saveMaintenancePage(): Promise<void> {
		maintenanceSaving = true;
		try {
			const res = await errorTemplatesApi.putMaintenancePage(maintenanceHtml, maintenanceMessage);
			maintenanceHtml = res.html;
			maintenanceIsDefault = res.isDefault;
			maintenanceMessage = res.message;
			pushToast(t('errorPages.maintenance.toastSaved'), 'success');
		} catch (err) {
			const msg =
				err instanceof ApiError ? err.message : t('errorPages.maintenance.errFailedSave');
			pushToast(msg, 'danger');
		} finally {
			maintenanceSaving = false;
		}
	}

	// "Reset to default" only clears the local buffer — the operator
	// must still click Save to persist an empty string server-side
	// (mirrors the rest of the page's explicit-Save contract; nothing
	// is written until Save is clicked). `maintenanceIsDefault` flips
	// to true immediately: an empty buffer IS the "will serve the
	// built-in default" state, so the built-in label should show
	// right away rather than waiting for the Save round-trip.
	function resetMaintenanceToDefault(): void {
		maintenanceHtml = '';
		maintenanceIsDefault = true;
		// v2.18.0 — reset clears the global message too, so "Reset to
		// default" returns the maintenance surface to a fully pristine
		// state (built-in page + no custom message). Still buffer-only;
		// nothing persists until Save.
		maintenanceMessage = '';
	}

	// --- Helpers -----------------------------------------

	function codeHasContent(code: number): boolean {
		return Boolean(editPages[code]?.trim());
	}

	function formatDate(iso: string): string {
		const d = new Date(iso);
		const locale = language.current === 'fr' ? 'fr-FR' : 'en-US';
		return d.toLocaleDateString(locale, {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}
</script>

<svelte:head>
	<title>{language.current && t('errorPages.headTitle')}</title>
</svelte:head>

<PageHeader
	eyebrow={language.current && t('errorPages.eyebrow')}
	title={language.current && (section === 'maintenance'
		? t('errorPages.tabMaintenance')
		: view === 'list'
			? t('errorPages.titleList')
			: editingBuiltin
				? t('errorPages.titleBuiltinPreview')
				: editingId
					? t('errorPages.titleEdit')
					: t('errorPages.titleNew'))}
	subtitle={language.current && (section === 'maintenance'
		? t('errorPages.maintenance.subtitle')
		: t('errorPages.subtitle'))}
>
	{#snippet actions()}
		{#if section === 'maintenance'}
			<Button
				variant="secondary"
				onclick={resetMaintenanceToDefault}
				disabled={maintenanceSaving || maintenanceLoading}
			>
				{language.current && t('errorPages.maintenance.btnResetToDefault')}
			</Button>
			<Button
				variant="primary"
				onclick={() => void saveMaintenancePage()}
				disabled={maintenanceSaving || maintenanceLoading}
				loading={maintenanceSaving}
			>
				{language.current && (maintenanceSaving ? t('errorPages.btnSaving') : t('errorPages.btnSave'))}
			</Button>
		{:else if view === 'list'}
			<Button variant="primary" onclick={startCreate}>{language.current && t('errorPages.btnNew')}</Button>
		{:else if editingBuiltin}
			<!-- Read-only mode : no Save. Operator returns to
			     list or duplicates to customise. -->
			<Button variant="secondary" onclick={cancelEdit}>{language.current && t('errorPages.btnBack')}</Button>
			<Button
				variant="primary"
				onclick={() => {
					// Materialise a synthetic ErrorTemplate from the
					// current edit buffer to feed the duplicate flow.
					// Same content as what was loaded ; the duplicate
					// will lift it to a real editable template.
					const pages: Record<string, string> = {};
					for (const [k, v] of Object.entries(editPages)) {
						if (v) pages[String(k)] = v;
					}
					void duplicateTemplate({
						id: BUILTIN_TEMPLATE_ID,
						name: editName,
						description: editDescription,
						pages,
						createdAt: '',
						updatedAt: '',
						isBuiltin: true
					});
				}}
			>
				{language.current && t('errorPages.btnDuplicateToCustomise')}
			</Button>
		{:else}
			<Button variant="secondary" onclick={cancelEdit} disabled={saving}>{language.current && t('errorPages.btnCancel')}</Button>
			<Button
				variant="primary"
				onclick={() => void saveTemplate()}
				disabled={saving}
				loading={saving}
			>
				{language.current && (saving ? t('errorPages.btnSaving') : t('errorPages.btnSave'))}
			</Button>
		{/if}
	{/snippet}
</PageHeader>

<!-- Task 10 — top-level section tabs (Templates / Maintenance).
     Only shown alongside the list view ; hidden while editing a
     template so the existing editor's own tabs (status codes)
     aren't visually competing with a second tab row. -->
{#if section === 'templates' && view === 'edit'}
	<!-- editor in progress : no top tabs, matches pre-Task-10 layout -->
{:else}
	<div class="card top-tabs-card">
		<div class="top-tabs" role="tablist" aria-label={language.current && t('errorPages.tabsAriaLabelTop')}>
			<button
				role="tab"
				aria-selected={section === 'templates'}
				class="top-tab"
				class:active={section === 'templates'}
				onclick={() => selectSection('templates')}
			>
				{language.current && t('errorPages.tabTemplates')}
			</button>
			<button
				role="tab"
				aria-selected={section === 'maintenance'}
				class="top-tab"
				class:active={section === 'maintenance'}
				onclick={() => selectSection('maintenance')}
			>
				{language.current && t('errorPages.tabMaintenance')}
			</button>
		</div>
	</div>
{/if}

{#if section === 'maintenance'}
	<!-- Task 10 — global maintenance page editor. One buffer
	     (no per-status-code tabs, unlike the templates editor
	     below), same HtmlEditor.svelte component + an iframe
	     preview for visual parity with the templates editor. -->
	<div class="editor-grid">
		{#if maintenanceLoading}
			<div class="card"><div class="loading-wrap"><Spinner /></div></div>
		{:else if maintenanceLoadError}
			<div class="card empty-state">
				<p class="error">{maintenanceLoadError}</p>
				<Button variant="secondary" onclick={() => void loadMaintenancePage()}>
					{language.current && t('errorPages.btnRetry')}
				</Button>
			</div>
		{:else}
			<!-- v2.18.0 — global maintenance message. Plain text
			     substituted into the 503 body via
			     {arenet.maintenance.message} (built-in default page +
			     any custom page). Placed ABOVE the HTML editor so it
			     reads as the primary, no-HTML-needed knob; the editor
			     below is the advanced surface. -->
			<div class="card message-card">
				<label class="message-label" for="maintenance-message">
					{language.current && t('errorPages.maintenance.messageLabel')}
				</label>
				<textarea
					id="maintenance-message"
					class="message-input"
					rows="3"
					bind:value={maintenanceMessage}
					placeholder={t('errorPages.maintenance.messagePlaceholder')}
				></textarea>
				<p class="vars-help">
					{language.current && t('errorPages.maintenance.messageHelp')}
				</p>
			</div>
			<div class="card editor-card">
				<div class="editor-pane">
					<div class="pane-label">
						{language.current && t('errorPages.maintenance.editorPaneLabel')}
						{#if maintenanceIsDefault}
							<!-- v2.17.1 Item E — labels the buffer as the
							     built-in default (mirrors the templates
							     tab's tpl.isBuiltin "Built-in" badge) so
							     the operator sees a real starting point
							     instead of an unexplained pre-filled
							     editor. -->
							<span
								class="builtin-badge"
								title={language.current && t('errorPages.maintenance.builtinTooltip')}
							>
								{language.current && t('errorPages.maintenance.builtinBadge')}
							</span>
						{/if}
					</div>
					<HtmlEditor
						bind:this={maintenanceEditorRef}
						bind:value={maintenanceHtml}
						label={language.current && t('errorPages.maintenance.editorAriaLabel')}
						placeholder={t('errorPages.maintenance.editorPlaceholder')}
						minHeight={360}
					/>
				</div>
				<div class="preview-pane">
					<div class="pane-label">{language.current && t('errorPages.maintenance.previewPaneLabel')}</div>
					<iframe
						title={language.current && t('errorPages.maintenance.previewPaneLabel')}
						sandbox=""
						srcdoc={maintenancePreview(maintenanceHtml)}
						class="preview-frame"
					></iframe>
				</div>
			</div>
			<div class="card vars-card">
				<!-- v2.18.1 — placeholder reference for the maintenance page.
				     Mirrors the templates editor's variable palette. -->
				<div class="pane-label">{language.current && t('errorPages.maintenance.placeholdersTitle')}</div>
				<div class="vars-grid">
					{#each maintenancePlaceholders as ph (ph.token)}
						<button
							type="button"
							class="var-btn"
							title={language.current && ph.desc}
							onclick={() => maintenanceEditorRef?.insertAtCursor(ph.token)}
						>
							<code>{ph.token}</code>
							<span class="var-label">{language.current && ph.desc}</span>
						</button>
					{/each}
				</div>
				<p class="vars-help">
					{language.current && t('errorPages.maintenance.helpRetryAfter')}
				</p>
				<p class="vars-help">
					{language.current && t('errorPages.maintenance.helpEmpty')}
				</p>
			</div>
		{/if}
	</div>
{:else if view === 'list'}
	<div class="card">
		{#if loading}
			<div class="loading-wrap"><Spinner /></div>
		{:else if loadError}
			<div class="empty-state">
				<p class="error">{loadError}</p>
				<Button variant="secondary" onclick={() => void loadTemplates()}>{language.current && t('errorPages.btnRetry')}</Button>
			</div>
		{:else if templates.length === 0}
			<div class="empty-state">
				<h3>{language.current && t('errorPages.emptyTitle')}</h3>
				<p>
					{language.current && t('errorPages.emptyBody')}
				</p>
				<Button variant="primary" onclick={startCreate}>{language.current && t('errorPages.btnCreateFirst')}</Button>
			</div>
		{:else}
			<table class="tpl-table">
				<thead>
					<tr>
						<th>{language.current && t('errorPages.colName')}</th>
						<th>{language.current && t('errorPages.colDescription')}</th>
						<th class="num">{language.current && t('errorPages.colCodesConfigured')}</th>
						<th>{language.current && t('errorPages.colUpdated')}</th>
						<th class="actions">{language.current && t('errorPages.colActions')}</th>
					</tr>
				</thead>
				<tbody>
					{#each templates as tpl (tpl.id)}
						<tr class:builtin-row={tpl.isBuiltin}>
							<td>
								<strong>{tpl.name}</strong>
								{#if tpl.isBuiltin}
									<span class="builtin-badge" title={language.current && t('errorPages.builtinTooltip')}>
										{language.current && t('errorPages.builtinBadge')}
									</span>
								{/if}
							</td>
							<td class="dim">{tpl.description || '—'}</td>
							<td class="num mono">{Object.keys(tpl.pages).length} / 8</td>
							<td class="dim">
								{tpl.isBuiltin ? '—' : formatDate(tpl.updatedAt)}
							</td>
							<td class="actions">
								{#if tpl.isBuiltin}
									<!-- Read-only : Inspect goes to the editor in
									     read-only mode ; Duplicate creates an
									     editable copy. No Modifier / Supprimer. -->
									<Button variant="secondary" size="sm" onclick={() => startEdit(tpl)}>
										{language.current && t('errorPages.btnPreview')}
									</Button>
									<Button
										variant="primary"
										size="sm"
										onclick={() => void duplicateTemplate(tpl)}
										title={language.current && t('errorPages.btnDuplicateBuiltinTooltip')}
									>
										{language.current && t('errorPages.btnDuplicate')}
									</Button>
								{:else}
									<Button variant="secondary" size="sm" onclick={() => startEdit(tpl)}>
										{language.current && t('errorPages.btnEdit')}
									</Button>
									<Button
										variant="secondary"
										size="sm"
										onclick={() => void duplicateTemplate(tpl)}
										title={language.current && t('errorPages.btnDuplicateTooltip')}
									>
										{language.current && t('errorPages.btnDuplicate')}
									</Button>
									<Button variant="danger" size="sm" onclick={() => askDelete(tpl)}>
										{language.current && t('errorPages.btnDelete')}
									</Button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
{:else}
	<!-- Editor view -->
	<div class="editor-grid">
		{#if editingBuiltin}
			<!-- Step R Phase 2.1 — read-only banner. Makes
			     the inputs-disabled state operator-obvious so
			     the absence of a Save button isn't perceived
			     as a UI bug. -->
			<div class="card builtin-banner">
				<strong>{language.current && t('errorPages.readOnlyBannerStrong')}</strong>
				{language.current && t('errorPages.readOnlyBannerBody')}
			</div>
		{/if}
		<!-- Top : name + description -->
		<div class="card meta-card">
			<label>
				<span class="meta-label">{language.current && t('errorPages.metaNameLabel')}</span>
				<input
					type="text"
					bind:value={editName}
					placeholder={language.current && t('errorPages.metaNamePlaceholder')}
					class="meta-input"
					maxlength="100"
					readonly={editingBuiltin}
				/>
			</label>
			<label>
				<span class="meta-label">{language.current && t('errorPages.metaDescriptionLabel')}</span>
				<input
					type="text"
					bind:value={editDescription}
					placeholder={language.current && t('errorPages.metaDescriptionPlaceholder')}
					class="meta-input"
					maxlength="500"
					readonly={editingBuiltin}
				/>
			</label>
			<!--
				v2.9.10 Bug 1 — checkbox "catch-all default".
				When checked + saved, the 404 body of THIS template
				becomes the body served by Arenet's catch-all route
				(requests for a host not configured on any route).
				Storage enforces mutual exclusion: setting it true
				here auto-clears the flag on any other template.
				Hidden in the read-only builtin view (it's a real-
				template-only concern).
			-->
			{#if !editingBuiltin}
				<!-- v2.51 — TWO independent roles, and they are listed
				     together so the difference is visible at the moment
				     of choosing. An operator flagged the catch-all one
				     expecting it to cover their routes: "default" read as
				     global. It never did — a route with no template gets
				     Arenet's built-in pages. The route default below is
				     what they wanted. -->
				<label class="catchall-toggle">
					<input
						type="checkbox"
						bind:checked={editIsRouteDefault}
						data-testid="tmpl-route-default"
					/>
					<span>
						<span class="meta-label">{language.current && t('errorPages.routeDefaultToggleLabel')}</span>
						<span class="catchall-hint">
							{language.current && t('errorPages.routeDefaultHint')}
						</span>
					</span>
				</label>
				<label class="catchall-toggle">
					<input
						type="checkbox"
						bind:checked={editIsCatchallDefault}
						data-testid="tmpl-catchall-default"
					/>
					<span>
						<span class="meta-label">{language.current && t('errorPages.catchallToggleLabel')}</span>
						<span class="catchall-hint">
							{language.current && t('errorPages.catchallHint')}
						</span>
					</span>
				</label>
			{/if}
		</div>

		<!-- Status code tabs -->
		<div class="card tabs-card">
			<div class="code-tabs" role="tablist" aria-label={language.current && t('errorPages.tabsAriaLabel')}>
				{#each SUPPORTED_ERROR_STATUS_CODES as code (code)}
					<button
						role="tab"
						aria-selected={activeCode === code}
						class="code-tab"
						class:active={activeCode === code}
						class:filled={codeHasContent(code)}
						onclick={() => (activeCode = code)}
					>
						{code}
						{#if codeHasContent(code)}<span class="dot">●</span>{/if}
					</button>
				{/each}
			</div>
		</div>

		<!-- Main editor + preview + variables -->
		<div class="card editor-card">
			<div class="editor-pane">
				<div class="pane-label">{language.current && t('errorPages.editorPaneLabel', { code: activeCode })}</div>
				<HtmlEditor
					bind:this={editorRef}
					bind:value={activeBuffer}
					label={language.current && t('errorPages.editorAriaLabel', { code: activeCode })}
					placeholder={t('errorPages.editorPlaceholder')}
					minHeight={360}
					readonly={editingBuiltin}
				/>
			</div>
			<div class="preview-pane">
				<div class="pane-label">
					{language.current && t('errorPages.previewPaneLabel')}
					{#if previewLoading}<span class="dim">{language.current && t('errorPages.previewLoading')}</span>{/if}
				</div>
				{#if previewError}
					<div class="preview-error">{previewError}</div>
				{:else}
					<iframe
						title={language.current && t('errorPages.previewAlt')}
						sandbox=""
						srcdoc={previewHtml}
						class="preview-frame"
					></iframe>
				{/if}
			</div>
		</div>

		<!-- Variables panel -->
		<div class="card vars-card">
			<details open>
				<summary>
					{language.current && t('errorPages.varsSummary')}
					{#if !editingBuiltin}{language.current && t('errorPages.varsSummarySuffix')}{/if}
				</summary>
				<div class="vars-grid">
					{#each ERROR_PAGE_PLACEHOLDERS as p (p.token)}
						<button
							class="var-btn"
							title={language.current && (editingBuiltin
								? t('errorPages.varsExampleReadOnlyTooltip', { ex: p.example })
								: t('errorPages.varsExampleTooltip', { ex: p.example }))}
							onclick={() => insertPlaceholder(p.token)}
							disabled={editingBuiltin}
						>
							<code>{p.token}</code>
							<span class="var-label">{p.label}</span>
						</button>
					{/each}
				</div>
				<p class="vars-help">
					{language.current && t('errorPages.varsHelp')}
				</p>
			</details>
		</div>
	</div>
{/if}

<!-- Delete confirmation -->
{#if deleteTarget}
	<div class="modal-backdrop" onclick={() => (deleteTarget = null)} role="presentation">
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<div
			class="modal"
			role="dialog"
			aria-modal="true"
			aria-labelledby="delete-modal-title"
			tabindex="-1"
			onclick={(e) => e.stopPropagation()}
		>
			<h3 id="delete-modal-title">{language.current && t('errorPages.deleteModalTitle')}</h3>
			<p>
				{language.current && t('errorPages.deleteModalBody', { name: deleteTarget.name })}
			</p>
			<div class="modal-actions">
				<Button
					variant="secondary"
					onclick={() => (deleteTarget = null)}
					disabled={deleting}
				>
					{language.current && t('errorPages.btnCancel')}
				</Button>
				<Button
					variant="danger"
					onclick={() => void confirmDelete()}
					disabled={deleting}
					loading={deleting}
				>
					{language.current && (deleting ? t('errorPages.btnDeleting') : t('errorPages.btnDelete'))}
				</Button>
			</div>
		</div>
	</div>
{/if}

<!-- Cancel with unsaved edits asks first. -->
<ConfirmDialog
	bind:open={confirmDiscardOpen}
	title={language.current && t('errorPages.discardTitle')}
	message={language.current && t('errorPages.discardMessage')}
	confirmLabel={language.current && t('errorPages.discardConfirm')}
	cancelLabel={language.current && t('errorPages.discardCancel')}
	confirmVariant="danger"
	onConfirm={leaveEdit}
/>

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 16px;
	}

	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 48px;
	}
	.empty-state {
		text-align: center;
		padding: 48px 24px;
		color: var(--fg-dim);
	}
	.empty-state h3 {
		color: var(--fg);
		font-size: 16px;
		margin: 0 0 8px;
	}
	.empty-state p {
		margin: 0 auto 16px;
		max-width: 520px;
		font-size: 13px;
	}
	.error { color: var(--status-down); }

	/* List view */
	/* Step R Phase 2.1 — builtin row + badge + read-only banner. */
	.tpl-table .builtin-row {
		background: color-mix(in oklch, var(--accent-cyan) 3%, transparent);
	}
	.builtin-badge {
		display: inline-block;
		margin-left: 8px;
		padding: 1px 7px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--accent-cyan) 16%, transparent);
		color: var(--accent-cyan);
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		vertical-align: middle;
	}
	.builtin-banner {
		padding: 10px 14px;
		font-size: 12.5px;
		color: var(--fg);
		background: color-mix(in oklch, var(--accent-cyan) 8%, transparent);
		border-left: 3px solid var(--accent-cyan);
	}
	.builtin-banner strong {
		color: var(--accent-cyan);
	}

	.tpl-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 13px;
	}
	.tpl-table th {
		text-align: left;
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--fg-dim);
		padding: 8px 12px;
		border-bottom: 1px solid var(--border);
	}
	.tpl-table th.num,
	.tpl-table td.num { text-align: right; }
	.tpl-table th.actions,
	.tpl-table td.actions { text-align: right; }
	.tpl-table td {
		padding: 10px 12px;
		border-bottom: 1px solid var(--border);
	}
	.tpl-table tr:last-child td { border-bottom: none; }
	.tpl-table .dim { color: var(--fg-dim); }
	.tpl-table .mono { font-family: var(--font-mono); font-size: 11.5px; }
	.tpl-table .actions {
		white-space: nowrap;
		display: flex;
		gap: 6px;
		justify-content: flex-end;
	}

	/* Editor view */
	.editor-grid {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.meta-card {
		display: flex;
		gap: 16px;
		flex-wrap: wrap;
	}
	.meta-card label {
		display: flex;
		flex-direction: column;
		gap: 4px;
		flex: 1;
		min-width: 240px;
	}
	.meta-label {
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.05em;
		text-transform: uppercase;
		color: var(--fg-dim);
	}
	.meta-input {
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		color: var(--fg);
		padding: 8px 12px;
		font-size: 13px;
		font-family: inherit;
		outline: none;
	}
	.meta-input:focus { border-color: var(--accent-cyan); }

	/* v2.9.10 Bug 1 — catchall default checkbox row. Spans the
	   full meta-card row (flex-basis 100%) so the long hint text
	   has room to breathe under the name/description pair. */
	.catchall-toggle {
		flex: 1 0 100%;
		flex-direction: row !important;
		align-items: flex-start !important;
		gap: 10px !important;
		min-width: 0 !important;
		padding: 10px 12px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		cursor: pointer;
	}
	.catchall-toggle input[type="checkbox"] {
		margin-top: 3px;
		accent-color: var(--accent-cyan);
		cursor: pointer;
		flex-shrink: 0;
	}
	.catchall-toggle .catchall-hint {
		display: block;
		font-size: 11.5px;
		color: var(--fg-muted);
		margin-top: 4px;
		line-height: 1.4;
		text-transform: none;
		letter-spacing: 0;
		font-family: inherit;
	}

	/* Task 10 — top-level section tabs (Templates / Maintenance) */
	.top-tabs-card { padding: 8px; margin-bottom: 12px; }
	.top-tabs {
		display: inline-flex;
		gap: 2px;
		padding: 2px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 999px;
	}
	.top-tab {
		padding: 6px 16px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-size: 13px;
		font-weight: 500;
	}
	.top-tab:hover { color: var(--fg); }
	.top-tab.active {
		background: var(--surface-hi);
		color: var(--fg);
		box-shadow: inset 0 0 0 1px var(--border-hi);
	}

	/* Code tabs */
	.tabs-card { padding: 8px; }
	.code-tabs {
		display: inline-flex;
		gap: 2px;
		padding: 2px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 999px;
		font-family: var(--font-mono);
	}
	.code-tab {
		padding: 6px 14px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-size: 12px;
		font-weight: 500;
		display: inline-flex;
		align-items: center;
		gap: 4px;
	}
	.code-tab:hover { color: var(--fg); }
	.code-tab.active {
		background: var(--surface-hi);
		color: var(--fg);
		box-shadow: inset 0 0 0 1px var(--border-hi);
	}
	.code-tab.filled .dot { color: var(--accent-cyan); font-size: 8px; }

	/* Editor + preview side by side */
	.editor-card {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		padding: 12px;
	}
	@media (max-width: 1200px) {
		.editor-card { grid-template-columns: 1fr; }
	}
	.editor-pane,
	.preview-pane {
		display: flex;
		flex-direction: column;
		gap: 6px;
		min-height: 0;
	}
	.pane-label {
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--fg-dim);
		display: flex;
		gap: 8px;
		align-items: baseline;
	}
	.pane-label .dim { font-size: 11px; }
	.preview-frame {
		width: 100%;
		min-height: 380px;
		background: white;
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}
	.preview-error {
		padding: 16px;
		color: var(--status-down);
		font-size: 13px;
		border: 1px dashed var(--status-down);
		border-radius: var(--radius);
	}

	/* Variables panel */
	.vars-card details > summary {
		cursor: pointer;
		font-family: var(--font-mono);
		font-size: 11.5px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--fg-dim);
		list-style: none;
	}
	.vars-card details > summary::before { content: '▸ '; }
	.vars-card details[open] > summary::before { content: '▾ '; }
	.vars-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
		gap: 6px;
		margin-top: 12px;
	}
	.var-btn {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		padding: 8px 10px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		cursor: pointer;
		text-align: left;
		color: var(--fg);
		font-family: inherit;
	}
	.var-btn:hover {
		border-color: var(--accent-cyan);
		background: color-mix(in oklch, var(--accent-cyan) 4%, transparent);
	}
	.var-btn code {
		font-family: var(--font-mono);
		font-size: 11.5px;
		color: var(--accent-cyan);
	}
	.var-label {
		font-size: 11px;
		color: var(--fg-dim);
	}
	.vars-help {
		margin-top: 12px;
		color: var(--fg-muted);
		font-size: 12px;
		font-style: italic;
	}

	/* v2.18.0 — global maintenance message field (above the editor) */
	.message-card {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.message-label {
		font-family: var(--font-mono);
		font-size: 11.5px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--fg-dim);
	}
	.message-input {
		width: 100%;
		box-sizing: border-box;
		resize: vertical;
		padding: 10px 12px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		color: var(--fg);
		font-family: inherit;
		font-size: 13px;
		line-height: 1.5;
	}
	.message-input:focus {
		outline: none;
		border-color: var(--accent-cyan);
		box-shadow: 0 0 0 1px var(--accent-cyan);
	}


	/* Modal */
	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}
	.modal {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 24px;
		max-width: 480px;
		width: 90%;
	}
	.modal h3 {
		font-size: 16px;
		margin: 0 0 12px;
		color: var(--fg);
	}
	.modal p {
		font-size: 13px;
		color: var(--fg-dim);
		margin: 0 0 20px;
	}
	.modal-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}
</style>
