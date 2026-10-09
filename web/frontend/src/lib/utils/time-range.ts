// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The windows the shared TimeRange control can offer. Kept in a plain
// module so the component's `generics` constraint and its callers can
// both import the type.

/** Every window TimeRange knows how to label, in display order. */
export const TIME_RANGES = ['1h', '24h', '7d', '30d'] as const;

/** One selectable time window. */
export type TimeRangeValue = (typeof TIME_RANGES)[number];
