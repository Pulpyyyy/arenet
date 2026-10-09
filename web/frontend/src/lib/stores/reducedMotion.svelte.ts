// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// "prefers-reduced-motion: reduce", read per component.
//
// app.css zeroes CSS animation and transition durations under that
// query, and that is all it can do: SMIL (<animate*>) and
// requestAnimationFrame loops are invisible to CSS, so the topology
// particles kept travelling for people who had asked for stillness.
// A component that animates outside CSS asks this helper instead.
//
// Why not `prefersReducedMotion` from 'svelte/motion' (used by the
// settings page): it is a module-level singleton that reads
// window.matchMedia once, when the module first loads. That is fine
// at runtime but cannot be flipped by a test, so the reduced path of
// a component using it could never be exercised. Reading matchMedia
// at component init keeps the same live behaviour (the change
// listener follows an OS toggle) and lets a test install its own
// matchMedia before render. Same shape as WorldMap.svelte's watcher.

/** The media query a reduced-motion preference is expressed in. */
export const REDUCED_MOTION_QUERY = '(prefers-reduced-motion: reduce)';

/** Live view of the operator's reduced-motion preference. */
export interface ReducedMotion {
	/** True when the OS / browser asks for reduced motion. */
	readonly current: boolean;
}

/**
 * Watch the reduced-motion preference for the calling component.
 *
 * Must be called during component initialisation (it registers an
 * $effect for the change listener, removed on destroy). The initial
 * value is read synchronously so the first render is already the
 * right one — no particle flashes before the preference applies.
 */
export function watchReducedMotion(): ReducedMotion {
	const mq =
		typeof window !== 'undefined' && typeof window.matchMedia === 'function'
			? window.matchMedia(REDUCED_MOTION_QUERY)
			: null;
	let current = $state(mq?.matches === true);

	$effect(() => {
		if (!mq || typeof mq.addEventListener !== 'function') return;
		const listener = (e: MediaQueryListEvent) => {
			current = e.matches;
		};
		mq.addEventListener('change', listener);
		return () => mq.removeEventListener('change', listener);
	});

	return {
		get current() {
			return current;
		}
	};
}
