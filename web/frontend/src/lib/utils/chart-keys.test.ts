// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { chartKeyStep } from './chart-keys';

describe('chartKeyStep', () => {
	it('starts Right on the first point and Left on the last', () => {
		expect(chartKeyStep('ArrowRight', null, 5)).toBe(0);
		expect(chartKeyStep('ArrowLeft', null, 5)).toBe(4);
	});

	it('steps one point and stops at the ends', () => {
		expect(chartKeyStep('ArrowRight', 2, 5)).toBe(3);
		expect(chartKeyStep('ArrowLeft', 2, 5)).toBe(1);
		expect(chartKeyStep('ArrowRight', 4, 5)).toBe(4);
		expect(chartKeyStep('ArrowLeft', 0, 5)).toBe(0);
	});

	it('jumps to the ends with Home and End', () => {
		expect(chartKeyStep('Home', 3, 5)).toBe(0);
		expect(chartKeyStep('End', null, 5)).toBe(4);
	});

	it('hides with Escape, and ignores Escape when nothing is shown', () => {
		expect(chartKeyStep('Escape', 2, 5)).toBeNull();
		expect(chartKeyStep('Escape', null, 5)).toBeUndefined();
	});

	it('leaves other keys and empty charts alone', () => {
		expect(chartKeyStep('Tab', 2, 5)).toBeUndefined();
		expect(chartKeyStep('ArrowUp', 2, 5)).toBeUndefined();
		expect(chartKeyStep('ArrowRight', null, 0)).toBeUndefined();
	});
});
