// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The spinner turns through CSS, so reduced motion can stop it.
//
// It used an SMIL <animateTransform>, which no stylesheet reaches: the
// global prefers-reduced-motion rule in app.css zeroes CSS animation
// durations and left the SMIL rotation running. jsdom does not apply
// media queries, so what is pinned here is the mechanism — no SMIL
// element, and the rotation carried by the class the stylesheet
// animates (and stops under the preference).

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import Spinner from './Spinner.svelte';

describe('Spinner', () => {
	it('carries no SMIL animation', () => {
		const { container } = render(Spinner);
		// getElementsByTagName matches the camelCase SVG name in
		// either namespace.
		expect(container.getElementsByTagName('animateTransform').length).toBe(0);
		expect(container.getElementsByTagName('animate').length).toBe(0);
	});

	it('rotates through the CSS-animated class', () => {
		render(Spinner);
		expect(screen.getByRole('status').classList.contains('spinner')).toBe(true);
	});

	it('still announces itself as a loading status', () => {
		render(Spinner, { props: { size: 'sm', color: 'current' } });
		expect(screen.getByRole('status')).toHaveAttribute('aria-label', 'Loading');
	});
});
