// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// WafEventList — "Ban…" row action: admin-only, opens BanIPModal
// pre-filled with the event's source IP. (The "Exclude…" action is
// covered in WafExcludeDialog.test.ts.)

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { WafEvent } from '$lib/api/types';

const { toastMock, securityMock, clientMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: { createManualBan: vi.fn() },
	clientMock: { addWafExclusion: vi.fn() }
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);
vi.mock('$lib/api/client', () => clientMock);

import WafEventList from './WafEventList.svelte';
import { auth } from '$lib/stores/auth.svelte';

const SRC_IP = '203.0.113.9';

function makeEvent(overrides: Partial<WafEvent> = {}): WafEvent {
	return {
		id: 1,
		ts: new Date().toISOString(),
		routeId: 'route-1',
		ruleId: '942100',
		category: 'SQLi',
		severity: 2,
		srcIp: SRC_IP,
		requestMethod: '',
		requestPath: '/api/save?content=x',
		payloadSample: "1' OR '1'='1",
		action: 'BLOCK',
		statusCode: 403,
		matchedVar: 'ARGS:content',
		...overrides
	};
}

function asRole(role: 'admin' | 'viewer'): void {
	auth.user = {
		username: role,
		displayName: role,
		role,
		mfa: 'none',
		passwordCompromised: false
	} as never;
}

beforeEach(() => {
	auth.user = null;
	securityMock.createManualBan.mockReset();
});

afterEach(() => {
	auth.user = null;
});

describe('WafEventList — Ban… button', () => {
	it('is hidden for viewers', () => {
		asRole('viewer');
		render(WafEventList, { props: { events: [makeEvent()] } });
		expect(screen.queryByTestId('waf-ban-open')).toBeNull();
	});

	it('opens BanIPModal pre-filled with the source IP for admins', async () => {
		asRole('admin');
		render(WafEventList, { props: { events: [makeEvent()] } });
		await fireEvent.click(screen.getByTestId('waf-ban-open'));
		expect(await screen.findByRole('dialog', { name: /Ban an IP/i })).toBeInTheDocument();
		await waitFor(() => expect(screen.getByTestId('ban-input-value')).toHaveValue(SRC_IP));
	});

	it('shows on rules that cannot be excluded too (the ban is about the IP)', () => {
		asRole('admin');
		render(WafEventList, { props: { events: [makeEvent({ ruleId: '949110' })] } });
		expect(screen.queryByTestId('waf-exclude-open')).toBeNull();
		expect(screen.getByTestId('waf-ban-open')).toBeInTheDocument();
	});
});
