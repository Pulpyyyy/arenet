// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Toast store timing (WCAG 2.2.1): danger stays until dismissed,
// info/success live long enough to read, the countdown pauses while
// the toast is hovered or focused, and an explicit ttl still wins.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';
import {
	toasts,
	pushToast,
	dismissToast,
	pauseToast,
	resumeToast,
	defaultToastTtl
} from './toast';

function messages(): string[] {
	return get(toasts).map((entry) => entry.message);
}

function idOf(message: string): number {
	const entry = get(toasts).find((t) => t.message === message);
	if (!entry) throw new Error(`no toast "${message}"`);
	return entry.id;
}

beforeEach(() => {
	vi.useFakeTimers();
});

afterEach(() => {
	for (const entry of get(toasts)) dismissToast(entry.id);
	vi.useRealTimers();
});

describe('toast lifetime', () => {
	it('never auto-dismisses a danger toast', () => {
		pushToast('Save failed: disk full', 'danger');
		vi.advanceTimersByTime(60 * 60 * 1000);
		expect(messages()).toEqual(['Save failed: disk full']);
		expect(vi.getTimerCount()).toBe(0);
	});

	it('keeps a short info toast at least 5 s', () => {
		pushToast('Saved', 'success');
		vi.advanceTimersByTime(4999);
		expect(messages()).toEqual(['Saved']);
		vi.advanceTimersByTime(1);
		expect(messages()).toEqual([]);
	});

	it('gives a longer message a longer lifetime, up to a cap', () => {
		const long = 'x'.repeat(200); // 2 s + 200 × 60 ms = 14 s
		expect(defaultToastTtl(long, 'info')).toBe(14000);
		expect(defaultToastTtl('x'.repeat(5000), 'info')).toBe(15000);
		expect(defaultToastTtl('anything', 'danger')).toBeNull();

		pushToast(long, 'info');
		vi.advanceTimersByTime(13999);
		expect(messages()).toEqual([long]);
		vi.advanceTimersByTime(1);
		expect(messages()).toEqual([]);
	});

	it('honours an explicit ttl, for danger too', () => {
		pushToast('Checking…', 'info', 12000);
		pushToast('Rate limited', 'danger', 3000);
		vi.advanceTimersByTime(3000);
		expect(messages()).toEqual(['Checking…']);
		vi.advanceTimersByTime(9000);
		expect(messages()).toEqual([]);
	});

	it('does not stack a second copy of a sticky toast already on screen', () => {
		pushToast('rate limited', 'danger');
		pushToast('rate limited', 'danger');
		expect(messages()).toEqual(['rate limited']);
		// Timed toasts are not deduplicated: each one leaves on its own.
		pushToast('Saved', 'success');
		pushToast('Saved', 'success');
		expect(messages()).toEqual(['rate limited', 'Saved', 'Saved']);
	});
});

describe('pause / resume', () => {
	it('stops the countdown while paused and resumes with the time left', () => {
		pushToast('Saved', 'success'); // 5 s
		const id = idOf('Saved');
		vi.advanceTimersByTime(3000);
		pauseToast(id);
		vi.advanceTimersByTime(60000);
		expect(messages()).toEqual(['Saved']);

		resumeToast(id);
		vi.advanceTimersByTime(1999);
		expect(messages()).toEqual(['Saved']);
		vi.advanceTimersByTime(1);
		expect(messages()).toEqual([]);
	});

	it('is idempotent: a double pause or resume does not change the time left', () => {
		pushToast('Saved', 'success'); // 5 s
		const id = idOf('Saved');
		vi.advanceTimersByTime(1000);
		pauseToast(id);
		vi.advanceTimersByTime(1000);
		pauseToast(id);
		resumeToast(id);
		resumeToast(id);
		expect(vi.getTimerCount()).toBe(1);
		vi.advanceTimersByTime(3999);
		expect(messages()).toEqual(['Saved']);
		vi.advanceTimersByTime(1);
		expect(messages()).toEqual([]);
	});

	it('is a no-op on a sticky toast and on unknown ids', () => {
		pushToast('Boom', 'danger');
		const id = idOf('Boom');
		pauseToast(id);
		resumeToast(id);
		pauseToast(9999);
		resumeToast(9999);
		expect(vi.getTimerCount()).toBe(0);
		expect(messages()).toEqual(['Boom']);
	});
});

describe('dismissToast', () => {
	it('removes the toast and cancels its pending timer', () => {
		pushToast('Saved', 'success');
		expect(vi.getTimerCount()).toBe(1);
		dismissToast(idOf('Saved'));
		expect(messages()).toEqual([]);
		expect(vi.getTimerCount()).toBe(0);
	});

	it('is safe on unknown ids', () => {
		expect(() => dismissToast(424242)).not.toThrow();
	});
});
