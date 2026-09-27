// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step R Phase 2 — typed wrappers for the error-templates CRUD
// endpoints landed in Phase 1 backend (commit f51167c) :
//   - GET    /api/v1/error-templates           (viewer)
//   - GET    /api/v1/error-templates/{id}      (viewer)
//   - GET    /api/v1/error-templates/{id}/preview?statusCode=X
//   - POST   /api/v1/error-templates           (admin)
//   - PUT    /api/v1/error-templates/{id}      (admin)
//   - DELETE /api/v1/error-templates/{id}      (admin)
//
// Backend mirror : internal/api/error_templates.go.

import { request } from './client';

/**
 * The 8 HTTP status codes operators may customise. Locked at Step R
 * Phase 1 ; the storage layer rejects out-of-set codes. Used by the
 * page-side enumeration of editor tabs.
 */
export const SUPPORTED_ERROR_STATUS_CODES = [
	401, 403, 404, 429, 500, 502, 503, 504
] as const;

export type SupportedErrorStatusCode = (typeof SUPPORTED_ERROR_STATUS_CODES)[number];

/**
 * Wire shape of an error-page template. Fields map 1-to-1 to the
 * backend errorTemplateResponse in internal/api/error_templates.go
 * with camelCase JSON tags.
 *
 * `pages` is a sparse map : codes absent from the map fall back to
 * the built-in Arenet default at caddymgr emit time (Phase 1 3-layer
 * resolution).
 */
export interface ErrorTemplate {
	id: string;
	name: string;
	description?: string;
	pages: Record<string, string>;
	createdAt: string;
	updatedAt: string;
	/**
	 * Step R Phase 2.1 — true on the single virtual entry
	 * ("arenet-default") synthesised by the backend list
	 * handler from the caddymgr-owned arenetDefaultErrorPages
	 * map. The list view renders a "Built-in" badge + hides
	 * Edit/Delete actions + shows a Duplicate button instead.
	 * Real DB templates omit this field (JSON omitempty), so
	 * the absence-by-default reads as false on the wire.
	 */
	isBuiltin?: boolean;
	/**
	 * v2.9.10 Bug 1 — when true, this template's pages[404] body
	 * is served by Arenet's catch-all route (requests for hosts
	 * not configured on any route). Storage enforces mutual
	 * exclusion: at most one template carries the flag at any time.
	 * Toggling it on Template B clears it on Template A in the same
	 * write transaction. Absence-by-default (omitempty) reads as
	 * false.
	 */
	isCatchallDefault?: boolean;
	/**
	 * Default for every ROUTE that has not chosen a template (v2.51).
	 *
	 * Separate from isCatchallDefault, which only governs the body for a
	 * host matching no route at all — an operator read that flag as
	 * meaning this one and was surprised. It sits below the route's own
	 * template in the resolution order, so an explicit choice still wins.
	 */
	isRouteDefault?: boolean;
}

/**
 * Step R Phase 2.1 — stable ID under which the backend
 * surfaces the virtual builtin. Frontend gates a few
 * action paths (no save / no delete / duplicate flow)
 * against this exact string.
 */
export const BUILTIN_TEMPLATE_ID = 'arenet-default';

/**
 * Wire shape accepted by POST + PUT. Same fields as ErrorTemplate
 * minus the server-generated id/createdAt/updatedAt.
 */
export interface ErrorTemplateRequest {
	name: string;
	description?: string;
	pages: Record<string, string>;
	/**
	 * v2.9.10 Bug 1 — optional flag on create/update payloads.
	 * The backend storage layer clears the flag on every other
	 * template in the same write transaction when set true.
	 */
	isCatchallDefault?: boolean;
	/**
	 * Default for every ROUTE that has not chosen a template (v2.51).
	 *
	 * Separate from isCatchallDefault, which only governs the body for a
	 * host matching no route at all — an operator read that flag as
	 * meaning this one and was surprised. It sits below the route's own
	 * template in the resolution order, so an explicit choice still wins.
	 */
	isRouteDefault?: boolean;
}

/**
 * Supported Caddy runtime placeholders that operators can use in
 * template bodies. Resolved at serve time by the static_response
 * handler ; preview at API time substitutes fixture values so the
 * editor's preview pane matches what'll render in prod.
 *
 * Documented in internal/caddymgr/error_pages.go's package-level
 * comment block (Phase 1.1 docs FIX 2). Mirrored here so the
 * Variables panel in the editor can render the list + click-to-
 * insert into the active textarea/CodeMirror buffer.
 *
 * Order is operator-facing scan priority (most-useful first).
 */
export interface PlaceholderDef {
	token: string;
	label: string;
	example: string;
}

export const ERROR_PAGE_PLACEHOLDERS: PlaceholderDef[] = [
	// Error context (set by the server's WithError shallow-copy
	// at caddy/v2 server.go:765-787 before the error route runs).
	{
		token: '{http.error.status_code}',
		label: 'HTTP status code',
		example: '403'
	},
	{
		token: '{http.error.status_text}',
		label: 'Status text (English)',
		example: 'Forbidden'
	},
	{
		token: '{http.error.id}',
		label: 'Per-error UUID (Caddy-generated)',
		example: 'a1b2c3d4'
	},
	{
		token: '{http.error.message}',
		label: 'Error message string',
		example: 'access denied'
	},
	// Upstream-error context (Phase 1.1 FIX 3 path).
	{
		token: '{http.reverse_proxy.status_code}',
		label: 'Upstream status (when proxy 4xx/5xx caught)',
		example: '502'
	},
	// Request context (survives into the error pipeline because
	// the Replacer is reused per server.go:765-772).
	{
		token: '{http.request.method}',
		label: 'Request method (GET, POST, …)',
		example: 'GET'
	},
	{
		token: '{http.request.host}',
		label: 'Host header (route primary host)',
		example: 'api.example.com'
	},
	{
		token: '{http.request.uri}',
		label: 'Full request URI with query',
		example: '/items?id=42'
	},
	{
		token: '{http.request.uri.path}',
		label: 'Request path only (no query)',
		example: '/items'
	},
	{
		token: '{http.request.uuid}',
		label: 'Per-request UUID (forensic ID)',
		example: '00000000-0000-4000-8000-000000000000'
	},
	{
		token: '{http.request.remote.host}',
		label: 'Client IP (or proxy IP if behind LB)',
		example: '203.0.113.42'
	},
	// Global Caddy placeholders (verified
	// caddy/v2/replacer.go:387-416).
	{
		token: '{time.now.year}',
		label: 'Current year (for © copyright)',
		example: '2026'
	},
	{
		token: '{system.hostname}',
		label: 'Server hostname (where Arenet runs)',
		example: 'arenet-prod-01'
	}
];

/**
 * API client surface for error-page templates. Symmetrical with the
 * alertingApi shape (lib/api/alerting.ts) so the page can mirror the
 * existing RulesTab pattern without inventing a new style.
 */
export const errorTemplatesApi = {
	list(): Promise<ErrorTemplate[]> {
		return request<ErrorTemplate[]>('GET', '/error-templates');
	},
	get(id: string): Promise<ErrorTemplate> {
		return request<ErrorTemplate>('GET', `/error-templates/${encodeURIComponent(id)}`);
	},
	create(req: ErrorTemplateRequest): Promise<ErrorTemplate> {
		return request<ErrorTemplate>('POST', '/error-templates', req);
	},
	update(id: string, req: ErrorTemplateRequest): Promise<ErrorTemplate> {
		return request<ErrorTemplate>(
			'PUT',
			`/error-templates/${encodeURIComponent(id)}`,
			req
		);
	},
	delete(id: string): Promise<void> {
		return request<void>('DELETE', `/error-templates/${encodeURIComponent(id)}`);
	},
	/**
	 * Preview a single (template, statusCode) cell with mock
	 * placeholder values substituted server-side. Returns the
	 * raw rendered HTML body — the consumer iframe-sandboxes
	 * it for safe display.
	 *
	 * Uses fetch directly (NOT the request() helper) because
	 * the response Content-Type is text/html, not the JSON
	 * envelope the shared helper assumes. The 401/403/404/
	 * error envelopes are still JSON though, so we feature-
	 * detect via Content-Type and unwrap to ApiError to match
	 * the rest of the client surface.
	 */
	async preview(id: string, statusCode: number): Promise<string> {
		const url = `/api/v1/error-templates/${encodeURIComponent(id)}/preview?statusCode=${statusCode}`;
		const res = await fetch(url, { credentials: 'include' });
		if (!res.ok) {
			const errJSON = await res.json().catch(() => ({}));
			const msg =
				typeof (errJSON as { error?: unknown }).error === 'string'
					? (errJSON as { error: string }).error
					: `HTTP ${res.status}`;
			throw new Error(msg);
		}
		return await res.text();
	},

	// Task 10 — global maintenance page GET/PUT. Backend mirror :
	// internal/api/maintenance_page.go (Task 7). Single global HTML
	// singleton served on maintenance-mode 503s for any route ; empty
	// HTML means "serve the branded default" (backend doc comment).
	//
	// v2.17.1 Item E — the response shape grew an `isDefault` flag.
	// GET now always returns non-empty `html` : when the operator has
	// never customized the page, the backend serves the branded
	// built-in default HTML with isDefault=true (instead of an empty
	// string), so the editor has a real starting point rather than a
	// blank buffer. PUT echoes the same shape (isDefault=true again
	// after a "Reset to default" save, since that persists an empty
	// string server-side).
	// v2.18.0 — the shape grew a `message` field: the global maintenance
	// message rendered by the built-in default page (and any custom page)
	// via {arenet.maintenance.message}. Plain text, independent of the
	// HTML buffer / isDefault flag.
	getMaintenancePage(): Promise<{ html: string; isDefault: boolean; message: string }> {
		return request<{ html: string; isDefault: boolean; message: string }>(
			'GET',
			'/settings/maintenance-page'
		);
	},
	putMaintenancePage(
		html: string,
		message: string
	): Promise<{ html: string; isDefault: boolean; message: string }> {
		return request<{ html: string; isDefault: boolean; message: string }>(
			'PUT',
			'/settings/maintenance-page',
			{ html, message }
		);
	}
};
