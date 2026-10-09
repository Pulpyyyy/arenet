// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Vitest global setup. Stubs $app/navigation (provided by SvelteKit at
// runtime but absent from the test resolver), wires testing-library's
// jest-dom matchers (Chunk 7 §11.1), and provides a minimal jsdom
// shim for window.matchMedia (used by Svelte 5's prefersReducedMotion
// MediaQuery rune in Settings + TopologySvg).

import { vi } from 'vitest';
import '@testing-library/jest-dom/vitest';

// Stub $app/navigation: goto is a no-op spy that tests can read to
// verify redirect behavior of the 401 interceptor (spec §6.4).
// afterNavigate never fires on its own here; a test that needs a
// navigation reads the registered callback off the spy and calls it.
vi.mock('$app/navigation', () => ({
	goto: vi.fn(() => Promise.resolve()),
	// lib/utils/navigation-guard registers here; a no-op keeps pages
	// that use it renderable. Its own test mocks it to drive it.
	beforeNavigate: vi.fn(),
	afterNavigate: vi.fn()
}));

// jsdom doesn't ship window.matchMedia. Svelte 5's
// `svelte/motion#prefersReducedMotion` constructs a MediaQuery at
// module load time, so any test that imports a file touching the
// motion module would crash without this shim. Default to "no
// preference" (matches=false) so tests run the animated paths
// unless a test overrides this for its own scope.
if (typeof window !== 'undefined' && !window.matchMedia) {
	window.matchMedia = vi.fn().mockImplementation((query: string) => ({
		matches: false,
		media: query,
		onchange: null,
		addListener: vi.fn(), // deprecated but referenced by some libs
		removeListener: vi.fn(), // deprecated
		addEventListener: vi.fn(),
		removeEventListener: vi.fn(),
		dispatchEvent: vi.fn()
	}));
}

// Auto-cleanup is wired by the svelteTesting() Vitest plugin
// (see vitest.config.ts). No explicit afterEach(cleanup) needed.

// jsdom doesn't implement Web Animations API (element.animate).
// svelte/transition (fade, fly, slide) calls element.animate on the
// transitioned node — any component test that mounts a Svelte
// transition (Sidebar footer fade, Modal fly, etc.) would crash with
// "TypeError: element.animate is not a function".
//
// Stub returns a minimal Animation-like object so Svelte's transition
// glue can proceed: finished promise resolves immediately (no
// animation actually plays), and cancel/finish are no-ops. Tests
// assert on rendered DOM, not on animation frames.
// jsdom doesn't ship ResizeObserver. TimelineChart (and any
// future chart component that relies on the WHATWG resize-
// observer-pattern for responsive sizing) instantiates one
// on mount via `new ResizeObserver(...)` — without this shim
// the dashboard test would surface a ReferenceError as an
// unhandled exception, failing CI even though the test
// assertions themselves passed.
//
// The shim is a no-op factory: observe / unobserve /
// disconnect are stubs, no callback is ever invoked. Tests
// don't measure layout, so a "size never changes" answer is
// honest. Matches the pattern used by Vitest / Jest jsdom
// projects across the ecosystem (e.g. testing-library docs'
// `ResizeObserver mock` recipe).
if (typeof globalThis.ResizeObserver === 'undefined') {
	globalThis.ResizeObserver = class ResizeObserver {
		observe() {}
		unobserve() {}
		disconnect() {}
	} as unknown as typeof ResizeObserver;
}

if (
	typeof Element !== 'undefined' &&
	typeof Element.prototype.animate === 'undefined'
) {
	Element.prototype.animate = (() => ({
		cancel: () => {},
		finish: () => {},
		finished: Promise.resolve() as unknown as Promise<Animation>,
		onfinish: null,
		oncancel: null,
		addEventListener: () => {},
		removeEventListener: () => {},
		dispatchEvent: () => true,
		currentTime: 0,
		startTime: 0,
		playbackRate: 1,
		playState: 'finished' as const,
		pending: false,
		ready: Promise.resolve() as unknown as Promise<Animation>,
		effect: null,
		timeline: null,
		id: '',
		replaceState: 'active' as const,
		play: () => {},
		pause: () => {},
		reverse: () => {},
		updatePlaybackRate: () => {},
		persist: () => {},
		commitStyles: () => {}
	})) as unknown as typeof Element.prototype.animate;
}
