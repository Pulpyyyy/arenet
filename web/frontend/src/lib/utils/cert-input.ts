// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Input helpers for the /certs forms: the wildcard wizard's apex field
// and the external-certificate PEM fields. Plain .ts so the rules are
// unit-testable without rendering a component.

// Mirrors managedDomainApexRE (internal/storage/managed_domain.go:85-87)
// so the wizard accepts exactly what the backend's storage validator
// accepts — single-label homelab apexes ("lan") included.
const APEX_RE =
	/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
const PORT_RE = /:\d+$/;

/**
 * Turns whatever the operator typed or pasted into the bare apex the
 * backend stores: trims, drops a URL scheme, path/query/fragment and
 * port, a leading wildcard ("*.") and trailing dots, then lowercases
 * (the backend's NormalizeApex lowercases too). Never throws; the
 * result may still be invalid — check it with isValidApex.
 */
export function normalizeApexInput(raw: string): string {
	let v = raw.trim().replace(SCHEME_RE, '');
	const cut = v.search(/[/?#]/);
	if (cut !== -1) v = v.slice(0, cut);
	v = v.replace(PORT_RE, '');
	while (v.startsWith('*.')) v = v.slice(2);
	v = v.replace(/\.+$/, '');
	return v.toLowerCase();
}

/** Reports whether a normalised apex looks like a domain name. */
export function isValidApex(apex: string): boolean {
	return APEX_RE.test(apex);
}

/** The PEM fields of the external-certificate forms. */
export type PemField = 'cert' | 'chain' | 'key';

/** A wrong-content problem detected in a PEM field before upload. */
export type PemIssue = 'keyInCert' | 'csrInCert' | 'keyInChain' | 'certInKey' | 'chainTwice';

/** Lists the PEM block types ("CERTIFICATE", "PRIVATE KEY", …) in text. */
export function pemBlockTypes(text: string): string[] {
	const types: string[] = [];
	for (const m of text.matchAll(/-----BEGIN ([A-Z0-9 ]+)-----/g)) {
		types.push(m[1]);
	}
	return types;
}

function isPrivateKeyType(type: string): boolean {
	return type === 'PRIVATE KEY' || type.endsWith(' PRIVATE KEY');
}

/**
 * Flags content pasted into the wrong PEM field, from the BEGIN
 * headers only (no parsing — the backend stays the authority on
 * validity). A field without any BEGIN header is not flagged here;
 * the backend's invalid_*_pem codes cover it.
 *
 * `otherFields` gives the cross-field context: a full chain (several
 * CERTIFICATE blocks) in the cert field is fine on its own — the
 * backend splits it — but rejected as chain_specified_twice when the
 * Chain field is also filled (internal/storage/external_cert_parse.go:87-91).
 */
export function pemFieldIssue(
	field: PemField,
	text: string,
	otherFields: { chain?: string } = {}
): PemIssue | null {
	const types = pemBlockTypes(text);
	if (types.length === 0) return null;
	const certCount = types.filter((t) => t === 'CERTIFICATE').length;
	const hasKey = types.some(isPrivateKeyType);
	switch (field) {
		case 'cert':
			if (hasKey) return 'keyInCert';
			if (certCount === 0 && types.includes('CERTIFICATE REQUEST')) return 'csrInCert';
			if (certCount > 1 && (otherFields.chain ?? '').trim() !== '') return 'chainTwice';
			return null;
		case 'chain':
			return hasKey ? 'keyInChain' : null;
		case 'key':
			return !hasKey && certCount > 0 ? 'certInKey' : null;
	}
}
