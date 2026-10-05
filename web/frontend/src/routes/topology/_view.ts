// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The Proxy / Redirects split, as a module rather than a function
// inside +page.svelte.
//
// It lived in the page until v2.62.1, which meant its test could not
// import it and restated the partition instead — a copy of the code
// under test, which cannot fail when the page stops CALLING it. That is
// exactly what happened: the partition was correct in both places while
// one of the page's four rebuild paths passed the unfiltered list, and
// the proxy view showed every node. The test passed throughout.
//
// So it lives here, imported by the page and by its test, and the test
// has nothing left to mirror.

import type { TopologyRoute } from './_types';

/** Which half of the canvas the operator is looking at. */
export type TopoView = 'proxy' | 'redirect';

/**
 * Split the route list for the selected view.
 *
 * Total and disjoint: every route lands in exactly one view, keyed on
 * `redirectTarget` and nothing else. A route either has a redirect
 * destination or it proxies; there is no third state and no route
 * belongs to both.
 *
 * Takes `routes` as a parameter rather than reading reactive state, so
 * a caller inside `untrack()` cannot be handed a stale partition —
 * the v2.61.1 bug, where nodes vanished on a switch and reappeared two
 * seconds later with the next WebSocket frame.
 */
export function filterForView(all: TopologyRoute[], view: TopoView): TopologyRoute[] {
	return view === 'redirect'
		? all.filter((r) => !!r.redirectTarget)
		: all.filter((r) => !r.redirectTarget);
}
