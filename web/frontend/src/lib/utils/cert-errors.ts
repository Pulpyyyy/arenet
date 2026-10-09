// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Friendly, translated messages for the refusals the /certs forms can
// get back from the backend. The external-certificate and CSR
// endpoints answer a 400 with "code: technical detail" (or the bare
// code) in the `error` field; the managed-domain endpoint answers with
// English sentences. Anything unrecognised falls back to the server's
// own message so an unknown error is never hidden.

import { ApiError } from '$lib/api/types';
import { serverErrorMessage } from '$lib/api/server-errors';
import { t } from '$lib/i18n';

// Leading codes of the external-certificate and CSR refusals:
//   - upload / re-import: internal/api/external_certs.go:125,129 and
//     internal/storage/external_cert_parse.go:89,110,114,117,121
//   - CSR generation: internal/storage/csr.go:40-42 (surfaced verbatim
//     by internal/api/external_certs.go:374)
const CERT_ERROR_CODE_KEYS: Record<string, string> = {
	chain_specified_twice: 'certificates.external.upload.errors.chainSpecifiedTwice',
	key_does_not_match_cert: 'certificates.external.upload.errors.keyDoesNotMatchCert',
	invalid_cert_pem: 'certificates.external.upload.errors.invalidCertPem',
	invalid_chain_pem: 'certificates.external.upload.errors.invalidChainPem',
	cert_required: 'certificates.external.upload.errors.certRequired',
	key_required: 'certificates.external.upload.errors.keyRequired',
	cn_required: 'certs.externalCerts.generate.errors.cnRequired',
	invalid_country: 'certs.externalCerts.generate.errors.invalidCountry',
	invalid_key_algorithm: 'certs.externalCerts.generate.errors.invalidKeyAlgorithm'
};

function rawMessage(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

/**
 * Resolves an external-certificate or CSR refusal to a translated
 * message. `code` is the recognised backend code (null when the
 * message was not one), so callers can also place the message next to
 * the field it concerns.
 */
export function resolveCertError(err: unknown): { message: string; code: string | null } {
	const raw = rawMessage(err);
	const sep = raw.indexOf(': ');
	const code = sep === -1 ? raw : raw.slice(0, sep);
	const key = CERT_ERROR_CODE_KEYS[code];
	if (key) return { message: t(key), code };
	return { message: raw, code: null };
}

// Sentences written by internal/api/managed_domain.go:199,207,214,245
// and the storage validator (internal/storage/managed_domain.go:107-124,
// relayed at managed_domain.go:232).
const MD_EXISTS_RE = /^managed domain (\S+) already exists$/;
const MD_WOULD_COVER_RE = /^managed domain (\S+) would cover existing managed domain (\S+)$/;
const MD_COVERED_RE = /^managed domain (\S+) is already covered by existing managed domain (\S+)$/;
const MD_RELOAD_PREFIX = 'caddy reload failed: ';
const MD_INVALID_APEX_PREFIX = 'managed_domain: apex';

/**
 * Resolves a wildcard-policy (managed domain) creation refusal to a
 * translated message: the coded invalid_provider_id refusal
 * (managed_domain.go:173) and the known sentences get the wizard's own
 * keys; anything else goes through the shared errors.server catalogue,
 * which falls back to the server's sentence.
 */
export function resolveManagedDomainError(err: unknown): string {
	if (err instanceof ApiError && err.code === 'invalid_provider_id') {
		return t('certs.wildcardWizard.errors.providerGone');
	}
	const raw = rawMessage(err);
	let m = MD_EXISTS_RE.exec(raw);
	if (m) return t('certs.wildcardWizard.errors.alreadyExists', { apex: m[1] });
	m = MD_WOULD_COVER_RE.exec(raw);
	if (m) return t('certs.wildcardWizard.errors.wouldCover', { apex: m[1], existing: m[2] });
	m = MD_COVERED_RE.exec(raw);
	if (m) return t('certs.wildcardWizard.errors.alreadyCovered', { apex: m[1], existing: m[2] });
	if (raw.startsWith(MD_RELOAD_PREFIX)) {
		return t('certs.wildcardWizard.errors.reloadFailed', {
			detail: raw.slice(MD_RELOAD_PREFIX.length)
		});
	}
	if (raw.startsWith(MD_INVALID_APEX_PREFIX)) {
		return t('certs.wildcardWizard.errors.invalidApex');
	}
	return serverErrorMessage(err);
}
