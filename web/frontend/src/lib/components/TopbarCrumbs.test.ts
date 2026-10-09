// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The topbar crumb names the page. Before: pages missing from its map
// showed their raw slug ("tcp-services", "api-docs"), and a per-route
// page showed the route's UUID. Each case below is one of those.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mutable so each test sets the path before render. Hoisted because
// vi.mock factories run before top-level consts.
const { pageMock } = vi.hoisted(() => ({
	pageMock: { url: new URL('http://localhost/dashboard') }
}));
vi.mock('$app/state', () => ({ page: pageMock }));

import { render } from '@testing-library/svelte';
import Topbar from './Topbar.svelte';
import { language } from '$lib/stores/language.svelte';

const ROUTE_ID = 'f2aa08ff-8c86-4ede-8bc1-96670b1342a5';

function crumbAt(path: string): string {
	pageMock.url = new URL('http://localhost' + path);
	const { container } = render(Topbar);
	return container.querySelector('.crumbs b')?.textContent?.trim() ?? '';
}

describe('Topbar crumb', () => {
	beforeEach(() => {
		language.current = 'en';
	});
	afterEach(() => {
		language.current = 'en';
	});

	it.each([
		['/dashboard', 'Dashboard'],
		['/security', 'Threats'],
		['/tcp-services', 'TCP / UDP services'],
		['/alerting', 'Alerting'],
		['/api-docs', 'API docs'],
		['/settings/error-pages', 'Error pages'],
		['/admin/users', 'Users']
	])('names %s "%s"', (path, label) => {
		expect(crumbAt(path)).toBe(label);
	});

	it('shows "Route" instead of the id on a per-route page', () => {
		expect(crumbAt(`/security/${ROUTE_ID}`)).toBe('Threats · Route');
		expect(crumbAt(`/observability/${ROUTE_ID}`)).toBe('Metrics · Route');
	});

	it('treats a long hex segment as an id too', () => {
		expect(crumbAt('/security/0123456789abcdef0123')).toBe('Threats · Route');
	});

	it('keeps a short, readable segment as is', () => {
		expect(crumbAt('/security/decisions')).toBe('Threats · decisions');
	});

	it('follows the language', () => {
		language.current = 'fr';
		expect(crumbAt('/security')).toBe('Menaces');
		expect(crumbAt(`/observability/${ROUTE_ID}`)).toBe('Métriques · Route');
	});
});
