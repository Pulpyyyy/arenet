// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Keyboard stepping shared by the timeline charts and the activity
// histogram. A focused chart reads one point at a time: Left and Right
// move the tooltip, Home and End jump to the ends, Escape hides it.
// The first arrow press lands on the end it points away from, so Left
// starts on the most recent point, which is usually the one wanted.

/**
 * chartKeyStep returns the position the tooltip moves to for `key`,
 * given the current position (null when no tooltip is shown) and the
 * number of positions. It returns null to hide the tooltip, and
 * undefined when the key is not one the chart handles, so the caller
 * leaves the event alone (Tab, page scrolling, a dialog's Escape).
 */
export function chartKeyStep(
	key: string,
	current: number | null,
	count: number
): number | null | undefined {
	if (key === 'Escape') return current === null ? undefined : null;
	if (count <= 0) return undefined;
	const last = count - 1;
	switch (key) {
		case 'ArrowRight':
			return current === null ? 0 : Math.min(last, current + 1);
		case 'ArrowLeft':
			return current === null ? last : Math.max(0, current - 1);
		case 'Home':
			return 0;
		case 'End':
			return last;
		default:
			return undefined;
	}
}
