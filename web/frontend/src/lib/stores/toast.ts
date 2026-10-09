// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { get, writable } from 'svelte/store';

export type ToastVariant = 'success' | 'danger' | 'info';

export interface ToastEntry {
	id: number;
	message: string;
	variant: ToastVariant;
}

// Reading-time model for info/success toasts (WCAG 2.2.1 Timing
// Adjustable). A fixed 4 s used to apply to every toast, which a
// two-line message cannot be read in. The budget is now a floor plus
// a per-character allowance, capped so a very long message still
// leaves eventually; the hover/focus pause below covers anyone who
// needs longer than the cap.
//
// Danger toasts never auto-dismiss: an error the operator did not get
// to read is an error they cannot act on. They stay until closed.
const TOAST_BASE_MS = 2000;
const TOAST_MS_PER_CHAR = 60;
const TOAST_MIN_MS = 5000;
const TOAST_MAX_MS = 15000;

/** Auto-dismiss countdown of one live toast. `handle` is null while
 *  the countdown is paused (hovered or focused). */
interface ToastTimer {
	remainingMs: number;
	startedAt: number;
	handle: ReturnType<typeof setTimeout> | null;
}

let nextId = 1;
const timers = new Map<number, ToastTimer>();

export const toasts = writable<ToastEntry[]>([]);

/**
 * Default lifetime of a toast, in ms, or null when it must stay until
 * dismissed. Danger is sticky; info/success scale with message length
 * between TOAST_MIN_MS and TOAST_MAX_MS.
 */
export function defaultToastTtl(message: string, variant: ToastVariant): number | null {
	if (variant === 'danger') return null;
	const budget = TOAST_BASE_MS + message.length * TOAST_MS_PER_CHAR;
	return Math.min(TOAST_MAX_MS, Math.max(TOAST_MIN_MS, budget));
}

function arm(id: number, timer: ToastTimer): void {
	timer.startedAt = Date.now();
	timer.handle = setTimeout(() => dismissToast(id), timer.remainingMs);
}

/**
 * Push a toast onto the queue. Without ttlMs the lifetime comes from
 * defaultToastTtl (danger stays until dismissed); an explicit ttlMs
 * always wins, whatever the variant. The countdown pauses while the
 * toast is hovered or focused (see pauseToast / resumeToast). A sticky
 * toast identical to one already on screen is not pushed again.
 */
export function pushToast(message: string, variant: ToastVariant = 'info', ttlMs?: number): void {
	const ttl = ttlMs ?? defaultToastTtl(message, variant);
	// A sticky toast never leaves on its own, so a repeated failure
	// (a poll hitting 429 every few seconds) would stack copies of the
	// same error until the operator closed each one. One copy is enough.
	if (ttl === null && get(toasts).some((t) => t.message === message && t.variant === variant)) {
		return;
	}
	const id = nextId++;
	toasts.update((list) => [...list, { id, message, variant }]);
	if (ttl === null) return;
	const timer: ToastTimer = { remainingMs: ttl, startedAt: 0, handle: null };
	timers.set(id, timer);
	arm(id, timer);
}

/**
 * Stop a toast's countdown, keeping the time it had left. No-op for a
 * sticky toast, an unknown id, or one already paused.
 */
export function pauseToast(id: number): void {
	const timer = timers.get(id);
	if (!timer || timer.handle === null) return;
	clearTimeout(timer.handle);
	timer.handle = null;
	timer.remainingMs = Math.max(0, timer.remainingMs - (Date.now() - timer.startedAt));
}

/**
 * Restart a paused toast's countdown with the time it had left. No-op
 * for a sticky toast, an unknown id, or one that is already running.
 */
export function resumeToast(id: number): void {
	const timer = timers.get(id);
	if (!timer || timer.handle !== null) return;
	arm(id, timer);
}

/** Remove a toast from the queue immediately. Safe to call on unknown ids. */
export function dismissToast(id: number): void {
	const timer = timers.get(id);
	if (timer && timer.handle !== null) clearTimeout(timer.handle);
	timers.delete(id);
	toasts.update((list) => list.filter((t) => t.id !== id));
}
