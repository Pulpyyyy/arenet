// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { ApiError } from '$lib/api/types';
import { resolveCertError, resolveManagedDomainError } from './cert-errors';

describe('resolveCertError', () => {
	it('maps a "code: detail" upload refusal to its translated message', () => {
		const r = resolveCertError(
			new ApiError('key_does_not_match_cert: tls: private key does not match public key', 400)
		);
		expect(r.code).toBe('key_does_not_match_cert');
		expect(r.message).toMatch(/does not match the certificate/);
	});

	it('maps a bare CSR code (internal/storage/csr.go:40-42)', () => {
		const r = resolveCertError(new ApiError('invalid_key_algorithm', 400));
		expect(r.code).toBe('invalid_key_algorithm');
		expect(r.message).toMatch(/Unknown key algorithm/);
	});

	it('falls back to the raw message for an unknown error', () => {
		const r = resolveCertError(new Error('failed to save external certificate'));
		expect(r).toEqual({ message: 'failed to save external certificate', code: null });
	});
});

describe('resolveManagedDomainError', () => {
	it('maps the duplicate-apex conflict', () => {
		expect(
			resolveManagedDomainError(new ApiError('managed domain example.com already exists', 409))
		).toBe('A wildcard policy for example.com already exists.');
	});

	it('maps both overlap conflicts with the apexes involved', () => {
		expect(
			resolveManagedDomainError(
				new ApiError(
					'managed domain example.com would cover existing managed domain app.example.com',
					409
				)
			)
		).toMatch(/example\.com would cover the existing policy for app\.example\.com/);
		expect(
			resolveManagedDomainError(
				new ApiError(
					'managed domain app.example.com is already covered by existing managed domain example.com',
					409
				)
			)
		).toMatch(/app\.example\.com is already covered by the policy for example\.com/);
	});

	it('maps the coded invalid_provider_id refusal', () => {
		expect(
			resolveManagedDomainError(
				new ApiError('providerId does not reference a configured DNS provider', 400, undefined, undefined, 'invalid_provider_id')
			)
		).toMatch(/no longer exists/);
	});

	it('keeps the reload detail', () => {
		expect(
			resolveManagedDomainError(new ApiError('caddy reload failed: boom', 500))
		).toMatch(/Caddy reload failed\): boom$/);
	});

	it('falls back to the server sentence for anything else', () => {
		expect(resolveManagedDomainError(new ApiError('apex already declared', 409))).toBe(
			'apex already declared'
		);
	});
});
