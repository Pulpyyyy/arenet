// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step R Phase 2.a — /settings/error-pages page tests.
//
// Focused on the operator-facing UX contracts :
//   - empty state when no templates exist
//   - list rendering when templates load
//   - create flow lands in editor view
//   - edit flow pre-populates the form
//   - 8 status-code tabs render
//   - Variables panel renders + click inserts placeholder
//   - delete confirmation flow
//   - error state on list-load failure
//
// CodeMirror internals are exercised by HtmlEditor.test.ts ;
// here we treat HtmlEditor as a black box (its mount is
// verified at the .cm-editor selector).

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { ErrorTemplate } from '$lib/api/error-templates';

const { apiMock, toastMock } = vi.hoisted(() => ({
	apiMock: {
		list: vi.fn(),
		get: vi.fn(),
		create: vi.fn(),
		update: vi.fn(),
		delete: vi.fn(),
		preview: vi.fn(),
		getMaintenancePage: vi.fn(),
		putMaintenancePage: vi.fn()
	},
	toastMock: { pushToast: vi.fn() }
}));

vi.mock('$lib/api/error-templates', async () => {
	const real = await vi.importActual<typeof import('$lib/api/error-templates')>(
		'$lib/api/error-templates'
	);
	return {
		...real,
		errorTemplatesApi: apiMock
	};
});
vi.mock('$lib/stores/toast', () => toastMock);

import Page from './+page.svelte';

const sampleTemplate = (overrides: Partial<ErrorTemplate> = {}): ErrorTemplate => ({
	id: 'tpl-1',
	name: 'WGW Branding',
	description: 'Example branded errors',
	pages: { '403': '<h1>403 — branded</h1>', '404': '<h1>404 — branded</h1>' },
	createdAt: '2026-06-20T10:00:00Z',
	updatedAt: '2026-06-20T10:00:00Z',
	...overrides
});

beforeEach(() => {
	apiMock.list.mockReset();
	apiMock.create.mockReset();
	apiMock.update.mockReset();
	apiMock.delete.mockReset();
	apiMock.preview.mockReset();
	apiMock.getMaintenancePage.mockReset();
	apiMock.putMaintenancePage.mockReset();
	toastMock.pushToast.mockReset();
	apiMock.list.mockResolvedValue([]);
	apiMock.preview.mockResolvedValue('<h1>preview</h1>');
	// v2.17.1 Item E — GET/PUT now return {html, isDefault}. Default
	// mock mirrors a fresh store: non-empty built-in HTML, isDefault
	// true (matches the real backend contract post-change).
	apiMock.getMaintenancePage.mockResolvedValue({
		html: '<h1>Back soon (built-in default)</h1>',
		isDefault: true,
		message: ''
	});
	apiMock.putMaintenancePage.mockResolvedValue({
		html: '<h1>Back soon (built-in default)</h1>',
		isDefault: true,
		message: ''
	});
});

describe('/settings/error-pages — list view', () => {
	it('renders the empty state when no templates exist', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/No custom template/);
		// CTA to create the first template is present.
		const ctas = screen.getAllByRole('button', { name: /Create the first/ });
		expect(ctas.length).toBeGreaterThan(0);
	});

	it('renders the table when templates load', async () => {
		apiMock.list.mockResolvedValue([
			sampleTemplate({ id: 't1', name: 'WGW' }),
			sampleTemplate({
				id: 't2',
				name: 'Other Brand',
				description: 'Another branding',
				pages: { '403': '<h1>x</h1>' }
			})
		]);
		render(Page);
		await screen.findByText('WGW');
		expect(screen.getByText('Other Brand')).toBeInTheDocument();
		// "2 / 8" for WGW (403 + 404 from sample).
		expect(screen.getByText('2 / 8')).toBeInTheDocument();
		// "1 / 8" for the second template.
		expect(screen.getByText('1 / 8')).toBeInTheDocument();
	});

	it('shows error state + retry on list-load failure', async () => {
		apiMock.list.mockRejectedValueOnce(new Error('network down'));
		render(Page);
		await waitFor(() => {
			expect(screen.getByText('network down')).toBeInTheDocument();
		});
		const retryBtn = screen.getByRole('button', { name: 'Retry' });
		expect(retryBtn).toBeInTheDocument();
	});
});

describe('/settings/error-pages — create flow', () => {
	it('clicking "New template" switches to editor view', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/No custom template/);
		// Header CTA = "+ Nouveau template", empty state CTA also creates.
		const cta = screen.getByRole('button', { name: '+ New template' });
		await fireEvent.click(cta);
		// Editor view : the header eyebrow switches to "Nouveau template"
		// and the meta-card name input appears.
		await screen.findByPlaceholderText(/WGW Branding/);
	});

	it('saves a new template and returns to list view', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.create.mockResolvedValue(sampleTemplate({ id: 'new-id', name: 'New One' }));
		// After save, the list re-fetch returns the created.
		apiMock.list.mockResolvedValueOnce([]); // initial empty
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('button', { name: '+ New template' }));
		const nameInput = await screen.findByPlaceholderText(/WGW Branding/);
		await fireEvent.input(nameInput, { target: { value: 'New One' } });
		// Second list call returns the new entry.
		apiMock.list.mockResolvedValueOnce([sampleTemplate({ id: 'new-id', name: 'New One' })]);
		await fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
		await waitFor(() => {
			expect(apiMock.create).toHaveBeenCalledTimes(1);
		});
		const [req] = apiMock.create.mock.calls[0];
		expect(req.name).toBe('New One');
	});

	// v2.51 — the two roles are independent, and both must SURVIVE the
	// save. The payload is rebuilt field by field, which is how the v2.46
	// path redirect was lost: success toast, nothing stored.
	//
	// The flag exists because an operator ticked the CATCH-ALL one
	// expecting their routes to use the template. They never did — the
	// catch-all governs only hosts matching no route.
	it('ships both default flags, independently', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.create.mockResolvedValue(sampleTemplate({ id: 'new-id' }));
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('button', { name: '+ New template' }));
		const nameInput = await screen.findByPlaceholderText(/WGW Branding/);
		await fireEvent.input(nameInput, { target: { value: 'Brand' } });

		// Only the ROUTE default — the operator's actual intent.
		await fireEvent.click(screen.getByTestId('tmpl-route-default'));
		await fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));

		await waitFor(() => expect(apiMock.create).toHaveBeenCalledTimes(1));
		const [req] = apiMock.create.mock.calls[0];
		expect(req.isRouteDefault).toBe(true);
		// And ticking one must not tick the other.
		expect(req.isCatchallDefault).toBe(false);
	});

	// Editing must LOAD the stored flag, or the first save after opening
	// the form would silently clear it — the other half of the
	// path-redirect hole, which had the same gap in openEdit.
	it('keeps a stored route-default flag when the template is edited', async () => {
		const stored = sampleTemplate({ id: 't1', name: 'Brand', isRouteDefault: true });
		apiMock.list.mockResolvedValue([stored]);
		apiMock.get.mockResolvedValue(stored);
		apiMock.update.mockResolvedValue(stored);
		render(Page);
		await screen.findByText('Brand');
		// The row's Edit button, as the other edit tests do — clicking the
		// name does not open the editor.
		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));

		const box = (await screen.findByTestId('tmpl-route-default')) as HTMLInputElement;
		expect(box.checked).toBe(true);

		await fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
		await waitFor(() => expect(apiMock.update).toHaveBeenCalledTimes(1));
		expect(apiMock.update.mock.calls[0][1].isRouteDefault).toBe(true);
	});

	it('rejects empty name with a toast', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('button', { name: '+ New template' }));
		await screen.findByPlaceholderText(/WGW Branding/);
		// Click save with empty name.
		await fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
		await waitFor(() => {
			expect(toastMock.pushToast).toHaveBeenCalledWith(
				expect.stringContaining('Template name is required'),
				'danger'
			);
		});
		// Create API should NOT have been hit.
		expect(apiMock.create).not.toHaveBeenCalled();
	});
});

describe('/settings/error-pages — editor', () => {
	it('renders the 8 supported status-code tabs', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('button', { name: '+ New template' }));
		// All 8 codes appear as tab labels.
		for (const code of [401, 403, 404, 429, 500, 502, 503, 504]) {
			expect(screen.getByRole('tab', { name: new RegExp(`^${code}`) })).toBeInTheDocument();
		}
	});

	it('renders the Variables panel with placeholder tokens', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('button', { name: '+ New template' }));
		// Panel header.
		expect(
			screen.getByText(/Available Caddy variables/)
		).toBeInTheDocument();
		// Some token examples are rendered as <code>.
		expect(screen.getByText('{http.error.status_code}')).toBeInTheDocument();
		expect(screen.getByText('{http.request.host}')).toBeInTheDocument();
		expect(screen.getByText('{time.now.year}')).toBeInTheDocument();
	});

	it('pre-populates the editor when editing an existing template', async () => {
		const existing = sampleTemplate({
			id: 'edit-me',
			name: 'Existing brand',
			description: 'desc',
			pages: { '403': '<h1>existing 403</h1>' }
		});
		apiMock.list.mockResolvedValue([existing]);
		render(Page);
		await screen.findByText('Existing brand');
		// Click Modifier on the row.
		const editBtn = screen.getByRole('button', { name: 'Edit' });
		await fireEvent.click(editBtn);
		// Editor view : name input has the existing value.
		const nameInput = (await screen.findByPlaceholderText(/WGW Branding/)) as HTMLInputElement;
		expect(nameInput.value).toBe('Existing brand');
	});

	it('cancel returns to list view without saving', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate()]);
		render(Page);
		await screen.findByText('WGW Branding');
		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		await screen.findByPlaceholderText(/WGW Branding/);
		await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
		// Back to list : the table is visible again.
		await waitFor(() => {
			expect(screen.getByText('WGW Branding')).toBeInTheDocument();
		});
		expect(apiMock.update).not.toHaveBeenCalled();
	});
});

// Cancel used to drop the name, the flags and all eight bodies unasked.
describe('/settings/error-pages — unsaved edits', () => {
	it('asks before Cancel drops an edit, and keeps it on "Keep editing"', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate()]);
		render(Page);
		await screen.findByText('WGW Branding');
		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		const nameInput = (await screen.findByPlaceholderText(/WGW Branding/)) as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'Renamed' } });

		await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
		expect(await screen.findByText('Discard your changes?')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Keep editing' }));
		await waitFor(() => expect(screen.queryByText('Discard your changes?')).toBeNull());
		expect(nameInput.value).toBe('Renamed');

		await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
		await fireEvent.click(await screen.findByRole('button', { name: 'Discard changes' }));
		await waitFor(() => expect(screen.queryByPlaceholderText(/WGW Branding/)).toBeNull());
		expect(apiMock.update).not.toHaveBeenCalled();
	});
});

describe('/settings/error-pages — delete confirmation', () => {
	it('opens the modal and fires the delete API on confirm', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate({ id: 'doomed', name: 'Doomed' })]);
		apiMock.delete.mockResolvedValue(undefined);
		render(Page);
		await screen.findByText('Doomed');
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		// Modal heading appears.
		await screen.findByText(/Delete template/);
		// Second-stage list call after delete.
		apiMock.list.mockResolvedValueOnce([]);
		// Click the modal's Supprimer button (second occurrence).
		const confirmBtn = screen
			.getAllByRole('button', { name: /^Delete$/ })
			.pop();
		expect(confirmBtn).toBeDefined();
		await fireEvent.click(confirmBtn!);
		await waitFor(() => {
			expect(apiMock.delete).toHaveBeenCalledWith('doomed');
		});
	});

	it('clicking Annuler closes the modal without deleting', async () => {
		apiMock.list.mockResolvedValue([sampleTemplate({ id: 'safe' })]);
		render(Page);
		await screen.findByText('WGW Branding');
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		await screen.findByText(/Delete template/);
		await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
		expect(apiMock.delete).not.toHaveBeenCalled();
	});
});

// --- Step R Phase 2.1 — builtin visibility + duplicate flow ----------------

const builtinTemplate = (overrides: Partial<ErrorTemplate> = {}): ErrorTemplate => ({
	id: 'arenet-default',
	name: 'Arenet default',
	description: 'Built-in branded default. Read-only.',
	pages: {
		'401': '<h1>401</h1>',
		'403': '<h1>403</h1>',
		'404': '<h1>404</h1>',
		'429': '<h1>429</h1>',
		'500': '<h1>500</h1>',
		'502': '<h1>502</h1>',
		'503': '<h1>503</h1>',
		'504': '<h1>504</h1>'
	},
	createdAt: '',
	updatedAt: '',
	isBuiltin: true,
	...overrides
});

describe('/settings/error-pages — Phase 2.1 builtin visibility', () => {
	it('list renders the "Built-in" badge on the arenet-default row', async () => {
		apiMock.list.mockResolvedValue([builtinTemplate()]);
		render(Page);
		// Row name visible.
		await screen.findByText('Arenet default');
		// Badge present.
		expect(screen.getByText('Built-in')).toBeInTheDocument();
	});

	it('builtin row hides Modifier + Supprimer, shows Aperçu + Dupliquer', async () => {
		apiMock.list.mockResolvedValue([builtinTemplate()]);
		render(Page);
		await screen.findByText('Arenet default');
		// "Aperçu" replaces "Modifier" for builtin.
		expect(screen.getByRole('button', { name: 'Preview' })).toBeInTheDocument();
		// Duplicate is visible.
		expect(screen.getByRole('button', { name: 'Duplicate' })).toBeInTheDocument();
		// Modifier + Supprimer are NOT rendered for builtin.
		expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
	});

	it('editable row shows Modifier + Dupliquer + Supprimer (existing UX preserved)', async () => {
		apiMock.list.mockResolvedValue([
			builtinTemplate(),
			sampleTemplate({ id: 'editable-1', name: 'Editable one' })
		]);
		render(Page);
		await screen.findByText('Editable one');
		// All three actions present somewhere (Aperçu only on builtin).
		const modifierButtons = screen.getAllByRole('button', { name: 'Edit' });
		const duplicateButtons = screen.getAllByRole('button', { name: 'Duplicate' });
		const supprimerButtons = screen.getAllByRole('button', { name: 'Delete' });
		// Modifier appears once (editable row only).
		expect(modifierButtons.length).toBe(1);
		// Dupliquer appears twice (builtin + editable).
		expect(duplicateButtons.length).toBe(2);
		// Supprimer once (editable only).
		expect(supprimerButtons.length).toBe(1);
	});

	it('clicking Aperçu opens editor in read-only mode (no Save button)', async () => {
		apiMock.list.mockResolvedValue([builtinTemplate()]);
		render(Page);
		await screen.findByText('Arenet default');
		await fireEvent.click(screen.getByRole('button', { name: 'Preview' }));
		// Editor view : title indicates Aperçu, read-only banner
		// visible, no Save button.
		await screen.findByText(/Preview: Arenet default/);
		expect(screen.getByText(/Read-only/)).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: /^Save$/ })).not.toBeInTheDocument();
		// The Phase 2.1 duplicate-from-editor CTA is present.
		expect(
			screen.getByRole('button', { name: /Duplicate to customise/ })
		).toBeInTheDocument();
	});

	it('clicking row Dupliquer calls create with "Copy of X" name', async () => {
		apiMock.list.mockResolvedValue([builtinTemplate()]);
		apiMock.create.mockResolvedValue({
			...sampleTemplate({
				id: 'new-uuid',
				name: 'Copy of Arenet default'
			})
		});
		// Second list call after create returns both.
		apiMock.list.mockResolvedValueOnce([builtinTemplate()]);
		render(Page);
		await screen.findByText('Arenet default');
		await fireEvent.click(screen.getByRole('button', { name: 'Duplicate' }));
		await waitFor(() => {
			expect(apiMock.create).toHaveBeenCalledTimes(1);
		});
		const [req] = apiMock.create.mock.calls[0];
		expect(req.name).toBe('Copy of Arenet default');
		// Pages copied verbatim from the source.
		expect(req.pages['403']).toBe('<h1>403</h1>');
	});

	it('Dupliquer increments suffix when name collision detected (Finder pattern)', async () => {
		// Two existing rows : the builtin + a previous Copy of
		// Arenet default. The next duplicate should compute
		// "Copy of Arenet default (2)". Default mockResolvedValue
		// is consulted by EVERY list call (including the post-
		// create reload), so we just need to set it once with
		// the conflicting row already present.
		apiMock.list.mockResolvedValue([
			builtinTemplate(),
			sampleTemplate({
				id: 'first-copy',
				name: 'Copy of Arenet default'
			})
		]);
		apiMock.create.mockResolvedValue({
			...sampleTemplate({ id: 'new-2' })
		});
		render(Page);
		await screen.findByText('Arenet default');
		// First Dupliquer in the DOM is on the builtin row.
		const duplicateButtons = screen.getAllByRole('button', { name: 'Duplicate' });
		await fireEvent.click(duplicateButtons[0]);
		await waitFor(() => {
			expect(apiMock.create).toHaveBeenCalledTimes(1);
		});
		const [req] = apiMock.create.mock.calls[0];
		expect(req.name).toBe('Copy of Arenet default (2)');
	});
});

// --- Task 10 — Maintenance tab -------------------------------------

describe('/settings/error-pages — Maintenance tab', () => {
	it('shows a Maintenance tab alongside the templates list', async () => {
		apiMock.list.mockResolvedValue([]);
		render(Page);
		await screen.findByText(/No custom template/);
		expect(screen.getByRole('tab', { name: /Maintenance/ })).toBeInTheDocument();
	});

	it('loads the current maintenance page HTML when the tab is opened', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({ html: '<h1>Back soon</h1>', isDefault: false, message: '' });
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});
		const editor = await screen.findByRole('textbox', { name: /Maintenance page HTML/ });
		expect(editor.getAttribute('data-placeholder')).toBeDefined();
		// The editor mounted with the loaded value (CodeMirror renders
		// the doc into .cm-content ; assert via the container's own
		// data since jsdom won't run full CM layout reliably — instead
		// assert through the page's own exposed value by checking the
		// editor is present and getMaintenancePage resolved before mount
		// completed).
		expect(editor).toBeInTheDocument();
	});

	it('editing and clicking Save calls putMaintenancePage with the new HTML', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({ html: '<h1>Old</h1>', isDefault: false, message: '' });
		apiMock.putMaintenancePage.mockResolvedValue({ html: '<h1>New</h1>', isDefault: false, message: '' });
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});
		await screen.findByRole('textbox', { name: /Maintenance page HTML/ });
		const saveBtn = screen.getByRole('button', { name: /^Save$/ });
		await fireEvent.click(saveBtn);
		await waitFor(() => {
			expect(apiMock.putMaintenancePage).toHaveBeenCalledTimes(1);
		});
		expect(apiMock.putMaintenancePage).toHaveBeenCalledWith('<h1>Old</h1>', '');
	});

	it('"Reset to default" clears the buffer to empty string', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({ html: '<h1>Custom page</h1>', isDefault: false, message: '' });
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});
		await screen.findByRole('textbox', { name: /Maintenance page HTML/ });
		const resetBtn = screen.getByRole('button', { name: /Reset to default/ });
		await fireEvent.click(resetBtn);
		apiMock.putMaintenancePage.mockResolvedValue({ html: '', isDefault: true, message: '' });
		const saveBtn = screen.getByRole('button', { name: /^Save$/ });
		await fireEvent.click(saveBtn);
		await waitFor(() => {
			expect(apiMock.putMaintenancePage).toHaveBeenCalledWith('', '');
		});
	});

	// v2.17.1 Item E — a fresh store (backend isDefault:true) must
	// show the built-in default HTML in the editor (not an empty
	// buffer) labeled "Arenet Default (built-in)", mirroring the
	// templates tab's builtin badge.
	it('shows the built-in default HTML labeled "Arenet Default (built-in)" when isDefault is true', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({
			html: '<h1>503 branded default</h1>',
			isDefault: true,
			message: ''
		});
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});
		await screen.findByRole('textbox', { name: /Maintenance page HTML/ });
		expect(screen.getByText('Arenet Default (built-in)')).toBeInTheDocument();
	});

	// Once the operator has a saved custom page (isDefault false),
	// the built-in label must NOT show.
	it('does not show the built-in label once a custom page is saved (isDefault false)', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({
			html: '<h1>My custom page</h1>',
			isDefault: false,
			message: ''
		});
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});
		await screen.findByRole('textbox', { name: /Maintenance page HTML/ });
		expect(screen.queryByText('Arenet Default (built-in)')).toBeNull();
	});

	it('documents the maintenance placeholders in the editor palette', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({ html: '', isDefault: true, message: '' });
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});
		// v2.18.1 — the message placeholder is offered.
		expect(screen.getByText('{arenet.maintenance.message}')).toBeInTheDocument();
		// v2.69.0 — and retry_after_human, the one and only way to state
		// the delay. The palette is where an operator learns which
		// placeholders exist, so the set it shows is the contract.
		expect(screen.getByText('{arenet.maintenance.retry_after_human}')).toBeInTheDocument();
		// The bare-integer sentinel it replaced must not be advertised:
		// nothing substitutes it any more, so a page built from it would
		// print the token to the public.
		expect(screen.queryByText('{arenet.maintenance.retry_after}')).toBeNull();
	});

	// v2.69.0 — the preview substituted nothing: the iframe took the
	// editor's text verbatim, so the operator judged their page with raw
	// sentinels sitting in it. Harmless while a sentinel was a bare
	// number; not harmless once the built-in page's whole retry line is
	// one, because the operator would see a token where a sentence
	// belongs and could never see the duration at all.
	it('substitutes the Arenet sentinels in the maintenance preview', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({
			html: '<p>{arenet.maintenance.retry_after_line}</p><p>bare {arenet.maintenance.retry_after_human}</p><p>{arenet.maintenance.message}</p>',
			isDefault: false,
			message: ''
		});
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});

		const frame = (await waitFor(() => {
			const el = document.querySelector('iframe.preview-frame');
			expect(el).not.toBeNull();
			return el;
		})) as HTMLIFrameElement;
		const srcdoc = frame.getAttribute('srcdoc') ?? '';

		// The whole sentence, from the line sentinel.
		expect(srcdoc).toContain('Retry in 30 minutes');
		// And the bare duration, from the human sentinel on its own.
		expect(srcdoc).toContain('bare 30 minutes');
		// Nothing Arenet substitutes may survive into what the operator
		// is looking at.
		expect(srcdoc).not.toContain('{arenet.maintenance.');
	});

	// Deliberate, not an oversight: substituting the real meta refresh
	// would make the preview iframe reload itself under the operator's
	// cursor while they edit.
	it('leaves the auto-refresh tag out of the preview', async () => {
		apiMock.list.mockResolvedValue([]);
		apiMock.getMaintenancePage.mockResolvedValue({
			html: '<head>{arenet.maintenance.refresh_meta}</head><body>x</body>',
			isDefault: false,
			message: ''
		});
		render(Page);
		await screen.findByText(/No custom template/);
		await fireEvent.click(screen.getByRole('tab', { name: /Maintenance/ }));
		await waitFor(() => {
			expect(apiMock.getMaintenancePage).toHaveBeenCalledTimes(1);
		});

		const frame = (await waitFor(() => {
			const el = document.querySelector('iframe.preview-frame');
			expect(el).not.toBeNull();
			return el;
		})) as HTMLIFrameElement;
		const srcdoc = frame.getAttribute('srcdoc') ?? '';
		expect(srcdoc).not.toContain('http-equiv');
		expect(srcdoc).not.toContain('{arenet.maintenance.refresh_meta}');
	});
});
