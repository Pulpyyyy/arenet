// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// Text ⇄ nanoseconds for the Security Automation rule durations
// (window, ban duration, cooldown). The wire carries Go
// time.Duration values, i.e. integer nanoseconds
// (internal/automation/rules.go, Rule.Window / Duration / Cooldown):
// the backend parses no duration text, so the units below are a UI
// convenience — whatever they produce reaches the server as a plain
// nanosecond count.
//
// Unlike ./duration.ts (Retry-After, whole seconds, number + unit
// picker), these fields are free text, so a parse can fail and the
// caller must be told: humanToNs returns null, never a stand-in 0.

const NS_PER_SECOND = 1e9;

// Seconds per accepted suffix. No suffix means seconds, as it always
// has. "min" is accepted beside "m" because operators type it.
const SECONDS_PER_SUFFIX: Record<string, number> = {
	'': 1,
	s: 1,
	m: 60,
	min: 60,
	h: 3600,
	d: 86400
};

// A whole number, optional spaces, an optional suffix. No decimals:
// the ban duration reaches CrowdSec in whole seconds
// (internal/automation/trigger.go, DurationSeconds) and "1.5h" is
// written "90m" just as well.
const DURATION_PATTERN = /^(\d+)\s*(s|min|m|h|d)?$/;

// time.Duration is an int64: a JSON number at or past 2^63 fails to
// decode server-side, so it is refused here rather than as a 400.
const MAX_DURATION_NS_EXCLUSIVE = 2 ** 63;

/**
 * Renders a nanosecond duration as the largest whole unit that divides
 * it ("60s" → "1m", 4 h → "4h", 7 days → "7d"). Zero or negative shows
 * as "0s"; sub-second remainders are dropped.
 */
export function nsToHuman(ns: number): string {
	if (!Number.isFinite(ns) || ns <= 0) return '0s';
	const s = Math.floor(ns / NS_PER_SECOND);
	if (s % 86400 === 0) return `${s / 86400}d`;
	if (s % 3600 === 0) return `${s / 3600}h`;
	if (s % 60 === 0) return `${s / 60}m`;
	return `${s}s`;
}

/**
 * Parses operator text ("30s", "5m", "5min", "2h", "1d", or a bare
 * number of seconds) into nanoseconds. Returns null for anything it
 * cannot read — blank, decimals, unknown units, negative values, or a
 * value too large for the backend — so the caller can refuse it
 * instead of saving 0.
 */
export function humanToNs(input: string): number | null {
	const m = input.trim().match(DURATION_PATTERN);
	if (!m) return null;
	const ns = Number(m[1]) * SECONDS_PER_SUFFIX[m[2] ?? ''] * NS_PER_SECOND;
	if (!Number.isFinite(ns) || ns >= MAX_DURATION_NS_EXCLUSIVE) return null;
	return ns;
}
