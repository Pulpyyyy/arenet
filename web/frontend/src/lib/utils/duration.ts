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

// Human-friendly duration ⇄ seconds conversion for the route
// Maintenance section's Retry-After input (v2.18.0). Storage and the
// HTTP Retry-After header stay in SECONDS (RFC 9110); only the UI
// presents a number + unit. Operators pick "5 minutes" instead of
// typing "300".

export type DurationUnit = 'seconds' | 'minutes' | 'hours' | 'days';

// Seconds per unit. Package-level constant so there are no magic
// numbers at the call sites (and so the unit list is defined once).
export const DURATION_UNIT_FACTORS: Record<DurationUnit, number> = {
	seconds: 1,
	minutes: 60,
	hours: 3600,
	days: 86400
};

// Largest-first so secondsToParts prefers days over hours over minutes.
const UNITS_LARGEST_FIRST: DurationUnit[] = ['days', 'hours', 'minutes', 'seconds'];

export interface DurationParts {
	value: number;
	unit: DurationUnit;
}

// secondsToParts renders a stored seconds count as the largest whole
// unit that divides it evenly, so a round value shows as a round value
// (300 → 5 minutes, 3600 → 1 hour, 90 → 90 seconds). Negatives and
// non-finite inputs clamp to 0 seconds.
export function secondsToParts(seconds: number): DurationParts {
	if (!Number.isFinite(seconds) || seconds <= 0) {
		return { value: 0, unit: 'seconds' };
	}
	const whole = Math.floor(seconds);
	for (const unit of UNITS_LARGEST_FIRST) {
		const factor = DURATION_UNIT_FACTORS[unit];
		if (whole % factor === 0) {
			return { value: whole / factor, unit };
		}
	}
	// Unreachable (seconds factor is 1, divides everything), but keep
	// the function total.
	return { value: whole, unit: 'seconds' };
}

// partsToSeconds converts a UI (value, unit) pair back to the seconds
// stored on the wire. NaN / negative value clamps to 0 (matching the
// pre-v2.18.0 blank-input behavior).
export function partsToSeconds(value: number, unit: DurationUnit): number {
	if (!Number.isFinite(value) || value < 0) {
		return 0;
	}
	return Math.floor(value) * DURATION_UNIT_FACTORS[unit];
}

// formatCountdown renders a remaining wait as m:ss (900 → "15:00",
// 45 → "0:45"), for a countdown that ticks every second, where words
// would reflow on every tick. Negatives and non-finite inputs show
// "0:00"; fractions round up, so a wait never shows 0:00 early.
export function formatCountdown(seconds: number): string {
	const whole = Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : 0;
	const minutes = Math.floor(whole / DURATION_UNIT_FACTORS.minutes);
	const rest = whole % DURATION_UNIT_FACTORS.minutes;
	return `${minutes}:${String(rest).padStart(2, '0')}`;
}
