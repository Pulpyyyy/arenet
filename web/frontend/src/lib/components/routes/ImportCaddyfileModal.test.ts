// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.40 — Caddyfile import modal: analyse, pick, conflicts, import.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { CaddyfilePreview } from '$lib/api/types';

const { clientMock, toastMock } = vi.hoisted(() => ({
	clientMock: { previewCaddyfileImport: vi.fn(), importCaddyfile: vi.fn() },
	toastMock: { pushToast: vi.fn() }
}));
vi.mock('$lib/api/client', () => clientMock);
vi.mock('$lib/stores/toast', () => toastMock);

import ImportCaddyfileModal from './ImportCaddyfileModal.svelte';

const CADDYFILE = 'app.example.com {\n\treverse_proxy 10.0.0.10:8080\n}\n';

const PREVIEW: CaddyfilePreview = {
	globalWarnings: [{ line: 1, text: 'global options block ignored' }],
	candidates: [
		{
			host: 'app.example.com',
			aliases: ['www.app.example.com'],
			importable: true,
			conflict: false,
			warnings: [{ line: 7, text: 'directive "php_fastcgi" not imported' }],
			route: {
				host: 'app.example.com',
				aliases: ['www.app.example.com'],
				upstreams: [{ url: 'http://10.0.0.10:8080', weight: 1 }],
				lbPolicy: 'round_robin',
				tlsEnabled: true,
				acmeChallenge: 'http-01',
				insecureSkipVerify: false,
				pathRules: [{ pathPrefix: '/api', upstreams: [{ url: 'http://10.0.0.20:9000', weight: 1 }] }]
			}
		},
		{
			host: 'taken.example.com',
			aliases: [],
			importable: true,
			conflict: true,
			warnings: [],
			route: {
				host: 'taken.example.com',
				aliases: [],
				upstreams: [{ url: 'http://10.0.0.11:8080', weight: 1 }],
				lbPolicy: 'round_robin',
				tlsEnabled: true,
				acmeChallenge: 'http-01',
				insecureSkipVerify: false
			}
		},
		{
			host: 'static.example.com',
			aliases: [],
			importable: false,
			reason: 'no reverse_proxy in this block: nothing to proxy',
			conflict: false,
			warnings: []
		}
	]
};

beforeEach(() => {
	clientMock.previewCaddyfileImport.mockReset();
	clientMock.importCaddyfile.mockReset();
	toastMock.pushToast.mockReset();
	clientMock.previewCaddyfileImport.mockResolvedValue(PREVIEW);
	clientMock.importCaddyfile.mockResolvedValue({ created: ['app.example.com'], replaced: [], skipped: [], warnings: [] });
});

async function analyse() {
	render(ImportCaddyfileModal, { props: { open: true, onClose: vi.fn() } });
	await fireEvent.input(screen.getByTestId('import-text'), { target: { value: CADDYFILE } });
	await fireEvent.click(screen.getByTestId('import-analyse'));
	await waitFor(() => expect(screen.getAllByTestId('import-candidate')).toHaveLength(3));
}

describe('ImportCaddyfileModal', () => {
	it('analyses, lists the blocks and preselects only the importable ones without conflict', async () => {
		await analyse();
		expect(clientMock.previewCaddyfileImport).toHaveBeenCalledWith(CADDYFILE);
		expect(screen.getByTestId('import-global-warnings').textContent).toContain('global options');

		expect((screen.getByTestId('import-pick-app.example.com') as HTMLInputElement).checked).toBe(true);
		expect((screen.getByTestId('import-pick-taken.example.com') as HTMLInputElement).checked).toBe(false);
		const notImportable = screen.getByTestId('import-pick-static.example.com') as HTMLInputElement;
		expect(notImportable.disabled).toBe(true);
		expect(screen.getAllByTestId("import-candidate")[0].textContent).toContain("php_fastcgi");
		expect(screen.getAllByTestId('import-conflict')).toHaveLength(1);
	});

	it('imports the picked hosts and reports them, with replace only when ticked', async () => {
		await analyse();
		await fireEvent.click(screen.getByTestId('import-pick-taken.example.com'));
		await fireEvent.click(screen.getByTestId('import-replace-taken.example.com'));
		await fireEvent.click(screen.getByTestId('import-run'));

		await waitFor(() => expect(clientMock.importCaddyfile).toHaveBeenCalled());
		expect(clientMock.importCaddyfile).toHaveBeenCalledWith(
			CADDYFILE,
			['app.example.com', 'taken.example.com'],
			['taken.example.com']
		);
		expect(toastMock.pushToast).toHaveBeenCalledWith(expect.stringContaining('1'), 'success');
	});

	it('reports what the server left out', async () => {
		clientMock.importCaddyfile.mockResolvedValue({
			created: [],
			replaced: [],
			skipped: [{ host: 'app.example.com', reason: 'a route already serves this host' }],
			warnings: []
		});
		await analyse();
		await fireEvent.click(screen.getByTestId('import-run'));
		await waitFor(() => expect(toastMock.pushToast).toHaveBeenCalledTimes(2));
		expect(toastMock.pushToast.mock.calls[1][0]).toContain('already serves');
	});

	// The box sat alone in its label: "checkbox, checked", with no word
	// of which site block it takes.
	it('names each pick box after its host', async () => {
		await analyse();
		expect(screen.getByRole('checkbox', { name: 'Import app.example.com' })).toBe(
			screen.getByTestId('import-pick-app.example.com')
		);
		expect(screen.getByRole('checkbox', { name: 'Import taken.example.com' })).toBeInTheDocument();
		expect(screen.getByLabelText('Import static.example.com')).toBeDisabled();
	});

	it('selects every importable block, or none, in one click', async () => {
		await analyse();
		const pick = (host: string) => screen.getByTestId(`import-pick-${host}`) as HTMLInputElement;
		expect(screen.getByTestId('import-select-bar').textContent).toContain('1 of 2 selected');

		await fireEvent.click(screen.getByRole('button', { name: 'Select all' }));
		expect(pick('app.example.com').checked).toBe(true);
		expect(pick('taken.example.com').checked).toBe(true);
		// A block that cannot be imported is never picked.
		expect(pick('static.example.com').checked).toBe(false);
		expect(screen.getByTestId('import-select-bar').textContent).toContain('2 of 2 selected');
		expect(screen.getByTestId('import-run').textContent).toContain('2');

		await fireEvent.click(screen.getByRole('button', { name: 'Select none' }));
		expect(pick('app.example.com').checked).toBe(false);
		expect(pick('taken.example.com').checked).toBe(false);
		expect((screen.getByTestId('import-run') as HTMLButtonElement).disabled).toBe(true);
	});

	it('shows the server error when the Caddyfile is invalid', async () => {
		clientMock.previewCaddyfileImport.mockRejectedValue(new Error('this is not a valid Caddyfile'));
		render(ImportCaddyfileModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('import-text'), { target: { value: 'broken {' } });
		await fireEvent.click(screen.getByTestId('import-analyse'));
		await waitFor(() => expect(screen.getByTestId('import-error')).toBeInTheDocument());
		expect(screen.queryAllByTestId('import-candidate')).toHaveLength(0);
	});
});
