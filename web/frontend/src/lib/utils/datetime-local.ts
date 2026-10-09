// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Conversion from an <input type="datetime-local"> value to the
// RFC 3339 instant the API filters expect.
//
// A datetime-local value carries no offset ("2026-05-01T14:30"); the
// operator typed it in their own wall-clock time, so it is read as
// local time and sent as UTC.

// YYYY-MM-DDTHH:mm, optionally :ss and .sss — the shapes a
// datetime-local input can hold. Anything else (a half-typed value,
// pasted garbage) is rejected here rather than sent to the server.
const LOCAL_DATETIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/;

/**
 * Convert a datetime-local value to an ISO 8601 UTC string.
 *
 * Returns '' for an empty input (no filter) and null for a value that
 * is not a complete, real date-time (invalid: do not apply).
 */
export function localInputToIso(value: string): string | null {
	const trimmed = value.trim();
	if (trimmed === '') return '';
	if (!LOCAL_DATETIME_RE.test(trimmed)) return null;
	// ECMAScript parses an offset-less date-time form as local time.
	const date = new Date(trimmed);
	if (Number.isNaN(date.getTime())) return null;
	return date.toISOString();
}
