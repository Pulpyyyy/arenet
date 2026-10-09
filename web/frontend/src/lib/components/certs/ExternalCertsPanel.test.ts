// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.19.0 external-certs SOCLE (Task 7) — component tests for
// ExternalCertsPanel. Pins:
//   1. The list renders one row per cert in the backend-given order
//      (soonest-first / notAfter ascending) — NO client re-sort.
//   2. Each row carries an expiry badge whose severity tracks the
//      days-to-notAfter thresholds (< 7d red, < 30d amber, else green).
//   3. The delete confirm dialog surfaces the "does NOT revoke with the
//      issuing CA" copy (i18n key referenced here; Task 9 fills the
//      value, so this test keys on the notice element + its i18n key).
//   4. On upload, warnings from the response render as an inline notice.
//   5. A 409 delete opens the blocked dialog with the blocking routes.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { ExternalCertificate } from '$lib/api/external-certs';
import { ApiError } from '$lib/api/types';

const { toastMock, apiMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		externalCertsApi: {
			list: vi.fn(),
			get: vi.fn(),
			upload: vi.fn(),
			update: vi.fn(),
			remove: vi.fn(),
			generateCSR: vi.fn(),
			csrDownloadUrl: vi.fn((id: string) => `/api/v1/certificates/external/${id}/csr`)
		}
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/external-certs', () => apiMock);

import Panel from './ExternalCertsPanel.svelte';

const NOW = new Date('2026-06-05T12:00:00Z');

// Header-shaped PEM fixtures: the wrong-content checks only read the
// BEGIN lines, so the bodies needn't be real DER.
const PEM_CERT = '-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----';
const PEM_KEY = '-----BEGIN PRIVATE KEY-----\nMIIEfake\n-----END PRIVATE KEY-----';

function daysFromNow(days: number): string {
	return new Date(NOW.getTime() + days * 86_400_000).toISOString();
}

function extCert(over: Partial<ExternalCertificate>): ExternalCertificate {
	return {
		id: 'id-' + (over.name ?? 'x'),
		name: 'cert',
		description: '',
		certPEM: 'CERT',
		chainPEM: '',
		keyPEM: '',
		issuer: 'DigiCert Inc',
		subject: 'CN=example.com',
		serialNumber: '0A',
		keyAlgorithm: 'RSA',
		signatureAlgorithm: 'SHA256-RSA',
		notBefore: daysFromNow(-30),
		notAfter: daysFromNow(60),
		dnsNames: ['example.com'],
		createdAt: daysFromNow(-30),
		updatedAt: daysFromNow(-30),
		warnings: [],
		...over
	};
}

beforeEach(() => {
	vi.useFakeTimers({ toFake: ['Date'] });
	vi.setSystemTime(NOW);
	toastMock.pushToast.mockReset();
	apiMock.externalCertsApi.list.mockReset();
	apiMock.externalCertsApi.upload.mockReset();
	apiMock.externalCertsApi.update.mockReset();
	apiMock.externalCertsApi.remove.mockReset();
	apiMock.externalCertsApi.generateCSR.mockReset();
	apiMock.externalCertsApi.list.mockResolvedValue([]);
});

afterEach(() => {
	vi.useRealTimers();
});

describe('ExternalCertsPanel — list', () => {
	it('renders one row per cert, preserving the backend soonest-first order', async () => {
		// Backend returns already sorted by notAfter ascending. We pass
		// them in that order and assert the DOM preserves it verbatim.
		const soonest = extCert({ name: 'soonest', notAfter: daysFromNow(3) });
		const middle = extCert({ name: 'middle', notAfter: daysFromNow(20) });
		const latest = extCert({ name: 'latest', notAfter: daysFromNow(200) });
		apiMock.externalCertsApi.list.mockResolvedValue([soonest, middle, latest]);

		render(Panel);
		await screen.findByTestId('external-certs-table');
		const rows = screen.getAllByTestId('external-cert-row');
		expect(rows).toHaveLength(3);
		expect(rows.map((r) => r.dataset.id)).toEqual([soonest.id, middle.id, latest.id]);
	});

	it('renders an expiry badge whose severity tracks the thresholds', async () => {
		const danger = extCert({ name: 'danger', notAfter: daysFromNow(3) }); // < 7d
		const warn = extCert({ name: 'warn', notAfter: daysFromNow(20) }); // < 30d
		const ok = extCert({ name: 'ok', notAfter: daysFromNow(200) }); // healthy
		apiMock.externalCertsApi.list.mockResolvedValue([danger, warn, ok]);

		render(Panel);
		await screen.findByTestId('external-certs-table');
		const rows = screen.getAllByTestId('external-cert-row');

		const badgeVariant = (row: HTMLElement) =>
			row.querySelector('.badge')?.getAttribute('data-variant');

		const byId = (id: string) => rows.find((r) => r.dataset.id === id)!;
		expect(badgeVariant(byId(danger.id))).toBe('status-down');
		expect(badgeVariant(byId(warn.id))).toBe('status-warn');
		expect(badgeVariant(byId(ok.id))).toBe('status-up');
	});

	it('shows the empty state when there are no external certs', async () => {
		apiMock.externalCertsApi.list.mockResolvedValue([]);
		render(Panel);
		expect(await screen.findByTestId('external-certs-empty')).toBeInTheDocument();
	});
});

describe('ExternalCertsPanel — delete dialog', () => {
	it('opens a confirm dialog carrying the "does NOT revoke" notice', async () => {
		const cert = extCert({ name: 'to-delete' });
		apiMock.externalCertsApi.list.mockResolvedValue([cert]);

		render(Panel);
		await userEvent.click(await screen.findByTestId(`external-cert-delete-${cert.id}`));

		// The revoke notice element is present and carries the "does NOT
		// revoke with the issuing CA" copy owned by the i18n key
		// certificates.external.delete.confirm.revokeNotice (Task 9).
		const notice = await screen.findByTestId('external-cert-revoke-notice');
		expect(notice).toBeInTheDocument();
		expect(notice.textContent ?? '').toContain('does NOT revoke');
		// The confirm button is wired.
		expect(screen.getByTestId('external-cert-delete-confirm')).toBeInTheDocument();
	});

	it('calls remove() and refreshes the list on confirm', async () => {
		const cert = extCert({ name: 'gone' });
		apiMock.externalCertsApi.list.mockResolvedValueOnce([cert]).mockResolvedValueOnce([]);
		apiMock.externalCertsApi.remove.mockResolvedValue(undefined);

		render(Panel);
		await userEvent.click(await screen.findByTestId(`external-cert-delete-${cert.id}`));
		await userEvent.click(await screen.findByTestId('external-cert-delete-confirm'));

		expect(apiMock.externalCertsApi.remove).toHaveBeenCalledWith(cert.id);
		await tick();
		expect(screen.queryByTestId(`external-cert-delete-${cert.id}`)).not.toBeInTheDocument();
	});

	it('opens the blocked dialog listing routes on a 409', async () => {
		const cert = extCert({ name: 'used' });
		apiMock.externalCertsApi.list.mockResolvedValue([cert]);
		apiMock.externalCertsApi.remove.mockRejectedValue(
			Object.assign(new Error('in use'), {
				status: 409,
				blockingRoutes: ['app.example.com']
			})
		);

		render(Panel);
		await userEvent.click(await screen.findByTestId(`external-cert-delete-${cert.id}`));
		await userEvent.click(await screen.findByTestId('external-cert-delete-confirm'));

		// The blocked dialog mounts (its body copy + the {routes}
		// interpolation are owned by the i18n key
		// certificates.external.delete.blocked.text, which Task 9 fills;
		// until then t() returns the raw key without interpolating, so we
		// assert the dialog element is present rather than the route text).
		const blocked = await screen.findByTestId('external-cert-blocked-text');
		expect(blocked).toBeInTheDocument();
		// The blocked path must NOT emit a success toast.
		expect(toastMock.pushToast).not.toHaveBeenCalledWith(expect.anything(), 'success');
		// The delete row is still present — nothing was removed.
		expect(screen.getByTestId(`external-cert-delete-${cert.id}`)).toBeInTheDocument();
	});
});

describe('ExternalCertsPanel — upload', () => {
	it('renders response warnings as an inline notice after a successful upload', async () => {
		apiMock.externalCertsApi.list.mockResolvedValue([]);
		apiMock.externalCertsApi.upload.mockResolvedValue(
			extCert({
				name: 'uploaded',
				warnings: [{ code: 'expires_soon', message: 'This certificate expires soon.' }]
			})
		);

		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		await userEvent.type(screen.getByTestId('external-cert-name'), 'uploaded');
		await userEvent.type(screen.getByTestId('external-cert-cert-pem'), 'CERTPEM');
		await userEvent.type(screen.getByTestId('external-cert-key-pem'), 'KEYPEM');
		await userEvent.click(screen.getByTestId('external-cert-upload-btn'));

		const notice = await screen.findByTestId('external-cert-warnings');
		expect(notice.textContent ?? '').toContain('This certificate expires soon.');
		expect(apiMock.externalCertsApi.upload).toHaveBeenCalledWith(
			expect.objectContaining({ name: 'uploaded', certPEM: 'CERTPEM', keyPEM: 'KEYPEM' })
		);
	});

	it('renders a friendly message (not the raw backend code) when the chain is specified twice', async () => {
		apiMock.externalCertsApi.list.mockResolvedValue([]);
		apiMock.externalCertsApi.upload.mockRejectedValue(
			new ApiError(
				'chain_specified_twice: the Certificate field already contains a chain (2 certificates) and the Chain field is also filled — put the chain in only one place',
				400
			)
		);

		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		await userEvent.type(screen.getByTestId('external-cert-name'), 'dup-chain');
		await userEvent.type(screen.getByTestId('external-cert-cert-pem'), 'FULLCHAINPEM');
		await userEvent.type(screen.getByTestId('external-cert-chain-pem'), 'CHAINPEM');
		await userEvent.type(screen.getByTestId('external-cert-key-pem'), 'KEYPEM');
		await userEvent.click(screen.getByTestId('external-cert-upload-btn'));

		const bottomError = await screen.findByTestId('external-cert-upload-error');
		expect(bottomError.textContent ?? '').not.toContain('chain_specified_twice:');
		expect(bottomError.textContent ?? '').toContain('chain is specified twice');

		// Fix B: the same friendly message ALSO renders inline, next to
		// the Chain field.
		const inlineError = await screen.findByTestId('external-cert-chain-error-inline');
		expect(inlineError.textContent ?? '').not.toContain('chain_specified_twice:');
		expect(inlineError.textContent ?? '').toContain('chain is specified twice');
	});

	it('fills a PEM field from a picked file', async () => {
		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		const file = new File([`${PEM_CERT}\n`], 'cert.pem', { type: 'application/x-pem-file' });
		await fireEvent.change(screen.getByTestId('external-cert-cert-file-input'), {
			target: { files: [file] }
		});

		const field = screen.getByTestId('external-cert-cert-pem') as HTMLTextAreaElement;
		await waitFor(() => expect(field.value).toBe(PEM_CERT));
		// The visible trigger names the field it fills.
		expect(screen.getByTestId('external-cert-cert-file').getAttribute('aria-label')).toBe(
			'Load Certificate (PEM) from a file'
		);
	});

	it('refuses a picked file that is not PEM text', async () => {
		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		const file = new File(['0\u0082binary'], 'cert.cer');
		await fireEvent.change(screen.getByTestId('external-cert-cert-file-input'), {
			target: { files: [file] }
		});

		const err = await screen.findByTestId('external-cert-cert-file-error');
		expect(err.textContent ?? '').toMatch(/cert\.cer is not PEM text/);
		expect((screen.getByTestId('external-cert-cert-pem') as HTMLTextAreaElement).value).toBe('');
	});

	it('flags a private key pasted in the Certificate field and blocks the upload', async () => {
		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		await fireEvent.input(screen.getByTestId('external-cert-name'), {
			target: { value: 'swapped' }
		});
		await fireEvent.input(screen.getByTestId('external-cert-cert-pem'), {
			target: { value: PEM_KEY }
		});
		await fireEvent.input(screen.getByTestId('external-cert-key-pem'), {
			target: { value: PEM_CERT }
		});

		expect(screen.getByTestId('external-cert-cert-issue').textContent ?? '').toMatch(
			/contains a private key/
		);
		expect(screen.getByTestId('external-cert-key-issue').textContent ?? '').toMatch(
			/contains a certificate, not a private key/
		);
		expect(screen.getByTestId('external-cert-cert-pem')).toHaveAttribute('aria-invalid', 'true');
		expect(screen.getByTestId('external-cert-upload-btn')).toBeDisabled();
		expect(apiMock.externalCertsApi.upload).not.toHaveBeenCalled();
	});

	it('flags a fullchain in the Certificate field when the Chain field is also filled', async () => {
		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		await fireEvent.input(screen.getByTestId('external-cert-cert-pem'), {
			target: { value: `${PEM_CERT}\n${PEM_CERT}` }
		});
		expect(screen.queryByTestId('external-cert-cert-issue')).not.toBeInTheDocument();

		await fireEvent.input(screen.getByTestId('external-cert-chain-pem'), {
			target: { value: PEM_CERT }
		});
		expect(screen.getByTestId('external-cert-cert-issue').textContent ?? '').toMatch(
			/full chain and the Chain field is filled too/
		);
	});

	it('translates a backend code on the cert-only re-import', async () => {
		const pending = extCert({
			name: 'Reimport',
			status: 'pending_csr',
			createdAt: daysFromNow(0),
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValue([pending]);
		apiMock.externalCertsApi.update.mockRejectedValue(
			new ApiError('key_does_not_match_cert: tls: private key does not match public key', 400)
		);

		render(Panel);
		await screen.findByTestId('external-certs-empty');
		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));
		await userEvent.click(await screen.findByTestId(`external-cert-reimport-${pending.id}`));
		await fireEvent.input(await screen.findByTestId('external-cert-reimport-cert-pem'), {
			target: { value: PEM_CERT }
		});
		await userEvent.click(screen.getByTestId('external-cert-reimport-submit'));

		const err = await screen.findByTestId('external-cert-reimport-error');
		expect(err.textContent ?? '').not.toContain('key_does_not_match_cert');
		expect(err.textContent ?? '').toMatch(/does not match the certificate/);
	});
});

describe('ExternalCertsPanel — row labelling', () => {
	it('names the certificate in each delete button aria-label', async () => {
		const cert = extCert({ name: 'corp-wildcard' });
		apiMock.externalCertsApi.list.mockResolvedValue([cert]);
		render(Panel);
		const btn = await screen.findByTestId(`external-cert-delete-${cert.id}`);
		expect(btn.getAttribute('aria-label')).toBe('Delete certificate "corp-wildcard"');
	});

	it('names the pending CSR in its delete button aria-label', async () => {
		const pending = extCert({
			name: 'csr-1',
			status: 'pending_csr',
			createdAt: daysFromNow(0),
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValue([pending]);
		render(Panel);
		await screen.findByTestId('external-certs-empty');
		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));
		const btn = await screen.findByTestId(`external-cert-pending-delete-${pending.id}`);
		expect(btn.getAttribute('aria-label')).toBe('Delete pending CSR "csr-1"');
	});

	it('shows the absolute expiry date and says renewal is manual', async () => {
		const cert = extCert({ name: 'manual', notAfter: daysFromNow(60) });
		apiMock.externalCertsApi.list.mockResolvedValue([cert]);
		render(Panel);
		await screen.findByTestId('external-certs-table');
		const hint = screen.getByTestId('external-cert-expiry-hint');
		const expected = new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(
			new Date(cert.notAfter)
		);
		expect(hint.textContent ?? '').toContain(expected);
		expect(hint.textContent ?? '').toMatch(/manual renewal/);
	});
});

// v2.20.0 CSR generation (Task 10) — Pending CSR tab. The pending
// signal is EXCLUSIVELY `status === 'pending_csr'`; `csrSubject`
// truthiness/presence must never be consulted (Go's `omitempty` is a
// no-op on struct-typed fields, so an ACTIVE row can carry a non-nil,
// empty-looking `csrSubject: {}` on the wire — see the CROSS-TASK RULE
// doc comment on ExternalCertificate.status in api/types.ts).
describe('ExternalCertsPanel — Active / Pending CSR tabs', () => {
	it('splits active and pending_csr rows into tabs', async () => {
		const active = extCert({ name: 'Active', status: '', notAfter: daysFromNow(60) });
		const pending = extCert({
			name: 'Pending',
			status: 'pending_csr',
			createdAt: daysFromNow(-1),
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValue([active, pending]);

		render(Panel);
		await screen.findByTestId('external-certs-table');

		// Active tab (default) shows only the active row.
		expect(screen.getByText('Active')).toBeTruthy();
		expect(screen.queryByText('Pending')).not.toBeInTheDocument();

		const pendingTab = screen.getByTestId('external-certs-tab-pending');
		expect(pendingTab.getAttribute('role')).toBe('tab');
		await userEvent.click(pendingTab);

		expect(screen.getByText('Pending')).toBeTruthy();
		expect(screen.queryByTestId('external-certs-table')).not.toBeInTheDocument();
	});

	it('treats a legacy row with no status field as Active, not Pending', async () => {
		const legacy = extCert({ name: 'Legacy' });
		delete (legacy as { status?: string }).status;
		apiMock.externalCertsApi.list.mockResolvedValue([legacy]);

		render(Panel);
		await screen.findByTestId('external-certs-table');

		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));
		expect(screen.queryByText('Legacy')).not.toBeInTheDocument();

		await userEvent.click(screen.getByTestId('external-certs-tab-active'));
		expect(screen.getByText('Legacy')).toBeTruthy();
	});

	it('treats an active row with an empty-looking csrSubject {} as Active, not Pending (the whole cross-task risk)', async () => {
		// Go `omitempty` is a no-op on struct-typed fields, so an active
		// row re-saved after the CSR feature shipped can carry
		// `csrSubject: {}` on the wire even though status === ''. The
		// panel MUST key off status alone.
		const activeWithEmptyCsrSubject = extCert({
			name: 'ActiveWithGhostSubject',
			status: '',
			csrSubject: {} as never
		});
		apiMock.externalCertsApi.list.mockResolvedValue([activeWithEmptyCsrSubject]);

		render(Panel);
		await screen.findByTestId('external-certs-table');

		expect(screen.getByText('ActiveWithGhostSubject')).toBeTruthy();

		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));
		expect(screen.queryByText('ActiveWithGhostSubject')).not.toBeInTheDocument();
	});

	it('renders an age badge on a pending row derived from createdAt', async () => {
		const pending = extCert({
			name: 'FreshCSR',
			status: 'pending_csr',
			createdAt: daysFromNow(0), // recent
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValue([pending]);

		render(Panel);
		await screen.findByTestId('external-certs-empty');
		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));

		const row = await screen.findByTestId(`external-cert-pending-row-${pending.id}`);
		const ageCell = row.querySelector('[data-age]');
		expect(ageCell).toBeTruthy();
		expect(ageCell?.getAttribute('data-age')).toBe('recent');
		expect(ageCell?.querySelector('.badge')).toBeTruthy();
	});

	it('offers a CSR download link pointed at csrDownloadUrl(id)', async () => {
		const pending = extCert({
			name: 'DownloadMe',
			status: 'pending_csr',
			createdAt: daysFromNow(0),
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValue([pending]);

		render(Panel);
		await screen.findByTestId('external-certs-empty');
		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));

		const link = await screen.findByTestId(`external-cert-csr-download-${pending.id}`);
		expect(link.getAttribute('href')).toBe(apiMock.externalCertsApi.csrDownloadUrl(pending.id));
	});

	it('deletes a pending row via remove() and refreshes the list', async () => {
		const pending = extCert({
			name: 'ToDelete',
			status: 'pending_csr',
			createdAt: daysFromNow(0),
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValueOnce([pending]).mockResolvedValueOnce([]);
		apiMock.externalCertsApi.remove.mockResolvedValue(undefined);

		render(Panel);
		await screen.findByTestId('external-certs-empty');
		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));

		await userEvent.click(await screen.findByTestId(`external-cert-pending-delete-${pending.id}`));
		await userEvent.click(await screen.findByTestId('external-cert-delete-confirm'));

		expect(apiMock.externalCertsApi.remove).toHaveBeenCalledWith(pending.id);
	});

	it('renders response warnings as an inline notice after a successful cert-only re-import', async () => {
		// Task 10 fix: confirmReimport must surface updated.warnings the
		// same way the upload path surfaces created.warnings — it must
		// NOT silently drop them.
		const pending = extCert({
			name: 'ReimportMe',
			status: 'pending_csr',
			createdAt: daysFromNow(0),
			csrSubject: { commonName: 'app.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.list.mockResolvedValue([pending]);
		apiMock.externalCertsApi.update.mockResolvedValue(
			extCert({
				name: 'ReimportMe',
				status: '',
				warnings: [
					{ code: 'subject_cn_rewritten', message: 'The CA rewrote the subject CN.' },
					{ code: 'sans_missing', message: 'A requested SAN is missing from the issued cert.' }
				]
			})
		);

		render(Panel);
		await screen.findByTestId('external-certs-empty');
		await userEvent.click(screen.getByTestId('external-certs-tab-pending'));

		await userEvent.click(await screen.findByTestId(`external-cert-reimport-${pending.id}`));
		await userEvent.type(
			await screen.findByTestId('external-cert-reimport-cert-pem'),
			'SIGNEDCERTPEM'
		);
		await userEvent.click(screen.getByTestId('external-cert-reimport-submit'));

		const notice = await screen.findByTestId('external-cert-reimport-warnings');
		expect(notice.textContent ?? '').toContain('The CA rewrote the subject CN.');
		expect(notice.textContent ?? '').toContain('A requested SAN is missing from the issued cert.');
		expect(apiMock.externalCertsApi.update).toHaveBeenCalledWith(
			pending.id,
			expect.objectContaining({ certPEM: 'SIGNEDCERTPEM', keyPEM: '' })
		);
	});

	it('shows a "Generate CSR" button that opens GenerateCSRForm; on success refreshes and switches to Pending', async () => {
		apiMock.externalCertsApi.list.mockResolvedValue([]);
		const created = extCert({
			name: 'NewlyGenerated',
			status: 'pending_csr',
			createdAt: daysFromNow(0),
			csrSubject: { commonName: 'new.corp.local', keyAlgorithm: 'rsa_4096' }
		});
		apiMock.externalCertsApi.generateCSR.mockResolvedValue(created);
		apiMock.externalCertsApi.list.mockResolvedValueOnce([]).mockResolvedValue([created]);

		render(Panel);
		await screen.findByTestId('external-certs-empty');

		await userEvent.click(await screen.findByTestId('external-cert-generate-csr-btn'));
		const form = await screen.findByTestId('generate-csr-form');
		expect(form).toBeInTheDocument();

		await userEvent.type(await screen.findByTestId('csr-common-name'), 'new.corp.local');
		await userEvent.click(screen.getByTestId('csr-generate-btn'));

		// Refreshed + switched to the Pending tab, where the new row shows.
		expect(await screen.findByText('NewlyGenerated')).toBeTruthy();
		expect(apiMock.externalCertsApi.list).toHaveBeenCalled();
	});
});
