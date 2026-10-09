// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Z.5.3 — /logs SOURCE IP cell formatter.
//
// Combines the raw IP with a backend-resolved country code
// (POST /api/v1/geo/lookup-batch) to produce the operator-
// facing label seen in the SOURCE IP column :
//
//   "82.65.x.x · FR"   public IP, MMDB hit
//   "192.168.1.x · LAN" RFC1918 (LAN sentinel)
//   "203.0.113.x · ?"   public IP, MMDB miss / degraded
//   "82.65.x.x"         country lookup not yet resolved (no suffix yet)
//
// IP masking : the last octet (or last 2 IPv6 groups) is
// elided to keep the SOURCE IP column compact AND so casual
// shoulder-surfing of an operator's screen doesn't expose
// full source IPs. Forensic ops still see the full IP in
// the row's title tooltip — that's a separate decision the
// operator owns.

/**
 * Resolve a raw IP + optional country code to its visible
 * label. `country` is the value returned by the lookup-
 * batch endpoint (empty string when the backend didn't
 * find a record or the lookup is degraded ; "LAN" for
 * RFC1918 / loopback / link-local).
 *
 * `country === undefined` means the frontend hasn't called
 * the lookup yet — the IP renders without a suffix so the
 * row appears immediately and the country materializes on
 * the next poll cycle.
 */
export function formatSourceIP(ip: string, country?: string): string {
	if (!ip) return '—';
	const masked = maskIP(ip);
	if (country === undefined) {
		// Lookup not yet resolved — render plain. Avoids
		// flashing a "?" suffix that resolves to "FR" 50ms
		// later.
		return masked;
	}
	if (country === '') {
		// Backend answered but had no record (MMDB miss or
		// degraded). Honest "?" tells the operator "we
		// asked, we don't know".
		return `${masked} · ?`;
	}
	return `${masked} · ${country}`;
}

/**
 * Mask the trailing octet (IPv4) or trailing IPv6 groups
 * so the SOURCE IP column stays compact and doesn't
 * shoulder-surf-expose the full source IP. Exposed
 * separately so unit tests can pin the exact masking shape.
 */
export function maskIP(ip: string): string {
	// IPv4 detection : 3 dots.
	const dotParts = ip.split('.');
	if (dotParts.length === 4) {
		return `${dotParts[0]}.${dotParts[1]}.${dotParts[2]}.x`;
	}
	// IPv6 : keep first 4 groups, mask the rest.
	if (ip.includes(':')) {
		const groups = ip.split(':');
		if (groups.length >= 4) {
			return `${groups[0]}:${groups[1]}:${groups[2]}:${groups[3]}::x`;
		}
	}
	// Unknown shape — return as-is so the operator sees
	// the raw value and a regression is visible.
	return ip;
}

/**
 * True when `ip` is a complete IPv4 or IPv6 address, i.e. a row
 * value worth banning or copying. Rejects the placeholders the
 * /logs mappers emit for rows without a real source ("?",
 * "(interne)", "").
 */
export function isFullIP(ip: string): boolean {
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
		return ip.split('.').every((octet) => Number(octet) <= 255);
	}
	return ip.includes(':') && /^[0-9a-fA-F:.]+$/.test(ip);
}
