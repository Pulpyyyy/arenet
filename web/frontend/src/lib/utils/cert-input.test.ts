// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { isValidApex, normalizeApexInput, pemBlockTypes, pemFieldIssue } from './cert-input';

const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
const KEY = '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----';
const EC_KEY = '-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----';
const CSR = '-----BEGIN CERTIFICATE REQUEST-----\nMIIC\n-----END CERTIFICATE REQUEST-----';

describe('normalizeApexInput', () => {
	it.each([
		['example.com', 'example.com'],
		['  Example.COM  ', 'example.com'],
		['*.example.com', 'example.com'],
		['example.com.', 'example.com'],
		['https://example.com/', 'example.com'],
		['https://*.example.com/path?q=1#x', 'example.com'],
		['example.com:8443', 'example.com'],
		['lan', 'lan']
	])('%j → %j', (raw, want) => {
		expect(normalizeApexInput(raw)).toBe(want);
	});
});

describe('isValidApex', () => {
	it('accepts what the backend apex grammar accepts', () => {
		expect(isValidApex('example.com')).toBe(true);
		expect(isValidApex('home.lan')).toBe(true);
		// Single-label homelab apex (managed_domain.go:75-80).
		expect(isValidApex('lan')).toBe(true);
	});

	it('rejects what the backend would refuse', () => {
		expect(isValidApex('')).toBe(false);
		expect(isValidApex('exa mple.com')).toBe(false);
		expect(isValidApex('-example.com')).toBe(false);
		expect(isValidApex('example..com')).toBe(false);
		expect(isValidApex('*.example.com')).toBe(false);
	});
});

describe('pemFieldIssue', () => {
	it('lists BEGIN block types', () => {
		expect(pemBlockTypes(`${CERT}\n${KEY}`)).toEqual(['CERTIFICATE', 'PRIVATE KEY']);
	});

	it('flags nothing for headerless text (left to the backend)', () => {
		expect(pemFieldIssue('cert', 'CERTPEM')).toBeNull();
		expect(pemFieldIssue('key', 'KEYPEM')).toBeNull();
	});

	it('accepts the right content in each field', () => {
		expect(pemFieldIssue('cert', CERT)).toBeNull();
		expect(pemFieldIssue('chain', CERT)).toBeNull();
		expect(pemFieldIssue('key', KEY)).toBeNull();
		expect(pemFieldIssue('key', EC_KEY)).toBeNull();
	});

	it('accepts a fullchain in the cert field when the Chain field is empty', () => {
		expect(pemFieldIssue('cert', `${CERT}\n${CERT}`, { chain: '' })).toBeNull();
	});

	it('flags a fullchain in the cert field when the Chain field is filled', () => {
		expect(pemFieldIssue('cert', `${CERT}\n${CERT}`, { chain: CERT })).toBe('chainTwice');
	});

	it('flags a private key in the cert or chain field', () => {
		expect(pemFieldIssue('cert', KEY)).toBe('keyInCert');
		expect(pemFieldIssue('cert', `${CERT}\n${EC_KEY}`)).toBe('keyInCert');
		expect(pemFieldIssue('chain', KEY)).toBe('keyInChain');
	});

	it('flags a CSR in the cert field', () => {
		expect(pemFieldIssue('cert', CSR)).toBe('csrInCert');
	});

	it('flags a certificate in the key field', () => {
		expect(pemFieldIssue('key', CERT)).toBe('certInKey');
	});
});
