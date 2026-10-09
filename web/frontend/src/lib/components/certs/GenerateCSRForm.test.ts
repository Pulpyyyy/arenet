// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.20.0 CSR generation (Task 9) — component tests for
// GenerateCSRForm. Pins:
//   1. Client-side guard: submitting with an empty Common Name never
//      calls externalCertsApi.generateCSR (the backend requires a
//      non-empty CN; we fail fast in the browser instead of round
//      tripping a 400).
//   2. Submitting with a Common Name calls generateCSR with the
//      default key algorithm 'rsa_4096' (selected on mount, per the
//      brief) inside csrSubject.
//
// The `certs.externalCerts.generate.*` i18n keys this component
// renders are added in Task 11, not here. Until then t() returns the
// raw dotted key (see src/lib/i18n/index.ts's documented fallback
// chain), so English-copy-based selectors like getByLabelText(/common
// name/i) would not resolve. Following the same precedent as
// ExternalCertsPanel.test.ts's revokeNotice assertion (Task 7: "t()
// returns the raw key... Task 9 hasn't filled the values yet" — here
// Task 11), we select elements by data-testid / role + the real
// for/id label wiring instead of resolved English text. The label
// association itself (for/id, aria-required) is still exercised —
// only the *text-content* assertion is deferred.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import GenerateCSRForm from './GenerateCSRForm.svelte';
import { externalCertsApi } from '$lib/api/external-certs';
import { ApiError } from '$lib/api/types';

beforeEach(() => {
	vi.restoreAllMocks();
});

describe('GenerateCSRForm', () => {
	it('rejects submit with empty CN', async () => {
		const spy = vi.spyOn(externalCertsApi, 'generateCSR');
		const { getByTestId } = render(GenerateCSRForm);

		await fireEvent.click(getByTestId('csr-generate-btn'));

		expect(spy).not.toHaveBeenCalled();
	});

	it('submits with CN + default RSA algorithm', async () => {
		const spy = vi
			.spyOn(externalCertsApi, 'generateCSR')
			.mockResolvedValue({ id: 'c1', status: 'pending_csr', csrPEM: 'x' } as never);
		const { getByTestId } = render(GenerateCSRForm);

		const cn = getByTestId('csr-common-name') as HTMLInputElement;
		// The label is wired via for/id — assert the association holds,
		// not the (not-yet-i18n'd) label text.
		expect(cn.labels?.[0]).toBeTruthy();

		await fireEvent.input(cn, { target: { value: 'app.corp.local' } });
		await fireEvent.click(getByTestId('csr-generate-btn'));

		expect(spy).toHaveBeenCalled();
		expect(spy.mock.calls[0][0].csrSubject.commonName).toBe('app.corp.local');
		expect(spy.mock.calls[0][0].csrSubject.keyAlgorithm).toBe('rsa_4096');
	});

	it('shows a translated message, not the raw code, when the backend refuses the CSR', async () => {
		// internal/storage/csr.go:41 — the API relays the bare code.
		vi.spyOn(externalCertsApi, 'generateCSR').mockRejectedValue(
			new ApiError('invalid_country', 400)
		);
		const { getByTestId, findByTestId } = render(GenerateCSRForm);

		await fireEvent.input(getByTestId('csr-common-name'), {
			target: { value: 'app.corp.local' }
		});
		await fireEvent.click(getByTestId('csr-generate-btn'));

		const err = await findByTestId('csr-submit-error');
		expect(err.textContent ?? '').not.toContain('invalid_country');
		expect(err.textContent ?? '').toMatch(/two-letter/i);
	});
});
