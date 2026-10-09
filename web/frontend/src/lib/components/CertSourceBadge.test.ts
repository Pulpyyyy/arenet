// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 2 (2026-06-17) — CertSourceBadge contract tests.
//
// Pins the operator-visible contract :
//   - managed-domain → "Covered by *.<apex>" badge + RFC 6125
//     tooltip + data-cert-kind="managed-domain" for CSS hooks.
//   - per-route-acme → "Dedicated cert (...)" badge + DNS-01/HTTP-01
//     tooltip distinction.
//   - per-route-internal → "Internal cert" badge.
//   - none / undefined / empty source → NOTHING rendered (the
//     legacy inline check at routes table line 1620 already
//     guards with `{#if r.tlsEnabled}`, so a non-TLS route never
//     reaches this component; defensive zero-render covers the
//     no-cert edge case anyway).

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import CertSourceBadge from './CertSourceBadge.svelte';

describe('CertSourceBadge', () => {
	it('renders nothing when source is undefined', () => {
		const { container } = render(CertSourceBadge, { props: { source: undefined } });
		expect(container.querySelector('span')).toBeNull();
	});

	it('renders nothing when source is empty string', () => {
		const { container } = render(CertSourceBadge, { props: { source: '' } });
		expect(container.querySelector('span')).toBeNull();
	});

	it('renders "Covered by *.<apex>" for managed-domain', () => {
		render(CertSourceBadge, {
			props: { source: 'managed-domain:example.com' }
		});
		expect(screen.getByText('Covered by *.example.com')).toBeInTheDocument();
	});

	it('carries the RFC 6125 explanation in the tooltip for managed-domain', () => {
		const { container } = render(CertSourceBadge, {
			props: { source: 'managed-domain:example.com' }
		});
		const wrapper = container.querySelector('[data-cert-kind="managed-domain"]');
		expect(wrapper).not.toBeNull();
		const tooltip = wrapper?.getAttribute('title') ?? '';
		expect(tooltip).toContain('*.example.com');
		expect(tooltip).toContain('RFC 6125');
	});

	it('renders "Dedicated cert (DNS-01)" for per-route-acme:dns-01', () => {
		render(CertSourceBadge, { props: { source: 'per-route-acme:dns-01' } });
		expect(screen.getByText('Dedicated cert (DNS-01)')).toBeInTheDocument();
	});

	it('renders "Dedicated cert (HTTP-01)" for per-route-acme:http-01', () => {
		render(CertSourceBadge, { props: { source: 'per-route-acme:http-01' } });
		expect(screen.getByText('Dedicated cert (HTTP-01)')).toBeInTheDocument();
	});

	it('renders "Internal cert" for per-route-internal', () => {
		render(CertSourceBadge, { props: { source: 'per-route-internal' } });
		expect(screen.getByText('Internal cert')).toBeInTheDocument();
	});

	it('surfaces the apex even with a nested-MD apex (operator-visible verbatim)', () => {
		// Critical when multiple MDs are configured. The pre-
		// Sujet-2 inline check hid the apex in the title
		// attribute, forcing the operator to hover every row to
		// discover which wildcard served a given route. The new
		// badge surfaces it directly so the multi-MD operator can
		// scan the column.
		render(CertSourceBadge, {
			props: { source: 'managed-domain:staging.example.com' }
		});
		expect(screen.getByText('Covered by *.staging.example.com')).toBeInTheDocument();
	});

	it('degrades to no-render on unknown wire shape (forward-compat)', () => {
		const { container } = render(CertSourceBadge, {
			props: { source: 'quantum-quic:v3' }
		});
		expect(container.querySelector('span')).toBeNull();
	});
});
