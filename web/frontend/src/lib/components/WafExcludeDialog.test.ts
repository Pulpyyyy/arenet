// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.36 — "Exclude…" on a WAF event: dialog, event list button,
// route-form editor, helpers.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { ApiError, type WafEvent, type WafTargetedExclusion } from '$lib/api/types';

const { toastMock, clientMock, securityMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	clientMock: { addWafExclusion: vi.fn() },
	securityMock: { fetchEvents: vi.fn(), fetchEventsByRule: vi.fn(), createManualBan: vi.fn() }
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/client', () => clientMock);
vi.mock('$lib/api/security', () => securityMock);

import WafExcludeDialog from './WafExcludeDialog.svelte';
import WafEventList from './WafEventList.svelte';
import WafTargetedExclusionsEditor from './routes/WafTargetedExclusionsEditor.svelte';
import { auth } from '$lib/stores/auth.svelte';
import {
	eventExclusionPath,
	isExcludableRule,
	parseWafTarget,
	summariseRuleEvidence
} from '$lib/utils/waf-exclusion';

const HOUR_MS = 60 * 60 * 1000;

function makeEvent(overrides: Partial<WafEvent> = {}): WafEvent {
	return {
		id: 1,
		ts: new Date().toISOString(),
		routeId: 'route-1',
		ruleId: '942100',
		category: 'SQLi',
		severity: 2,
		srcIp: '203.0.113.9',
		requestMethod: '',
		requestPath: '/api/save?content=x',
		payloadSample: "1' OR '1'='1",
		action: 'BLOCK',
		statusCode: 403,
		matchedVar: 'ARGS:content',
		...overrides
	};
}

function asAdmin(): void {
	auth.user = {
		username: 'admin',
		displayName: 'Admin',
		role: 'admin',
		mfa: 'none',
		passwordCompromised: false
	} as never;
}

beforeEach(() => {
	toastMock.pushToast.mockReset();
	clientMock.addWafExclusion.mockReset();
	securityMock.fetchEvents.mockReset();
	securityMock.fetchEventsByRule.mockReset();
	securityMock.fetchEvents.mockResolvedValue({ events: [] });
	securityMock.fetchEventsByRule.mockResolvedValue({ rows: [] });
	auth.user = null;
});

describe('waf-exclusion helpers', () => {
	it('refuses Arenet and blocking-evaluation rules', () => {
		expect(isExcludableRule('942100')).toBe(true);
		expect(isExcludableRule('100001')).toBe(false);
		expect(isExcludableRule('949110')).toBe(false);
		expect(isExcludableRule('959100')).toBe(false);
		expect(isExcludableRule('980170')).toBe(false);
		expect(isExcludableRule('901001')).toBe(false);
		expect(isExcludableRule('abc')).toBe(false);
	});

	it('parses usable targets only', () => {
		expect(parseWafTarget('ARGS:content')).toEqual({ variable: 'ARGS', key: 'content' });
		expect(parseWafTarget('request_headers:User-Agent')).toEqual({
			variable: 'REQUEST_HEADERS',
			key: 'User-Agent'
		});
		expect(parseWafTarget('')).toBeNull();
		expect(parseWafTarget(undefined)).toBeNull();
		expect(parseWafTarget('REQUEST_FILENAME:x')).toBeNull();
		expect(parseWafTarget('ARGS:a,b')).toBeNull();
		expect(parseWafTarget('ARGS:/re/')).toBeNull();
	});

	it('derives the decoded path without the query string', () => {
		expect(eventExclusionPath('/api/save?content=x')).toBe('/api/save');
		expect(eventExclusionPath('/caf%C3%A9/x')).toBe('/café/x');
		expect(eventExclusionPath('/a%20b')).toBe('');
		expect(eventExclusionPath('/bad%E0')).toBe('');
		expect(eventExclusionPath('')).toBe('');
	});

	it('counts distinct source IPs of the rule inside the window only', () => {
		const now = Date.now();
		const recent = new Date(now - HOUR_MS).toISOString();
		const old = new Date(now - 48 * HOUR_MS).toISOString();
		const events = [
			{ ruleId: '942100', ts: recent, srcIp: '198.51.100.1' },
			{ ruleId: '942100', ts: recent, srcIp: '198.51.100.1' },
			{ ruleId: '942100', ts: recent, srcIp: '' },
			{ ruleId: '942100', ts: old, srcIp: '198.51.100.2' },
			{ ruleId: '941100', ts: recent, srcIp: '198.51.100.3' },
			{ ruleId: '942100', ts: 'garbage', srcIp: '198.51.100.4' }
		];
		expect(summariseRuleEvidence('942100', 7, events, now - 24 * HOUR_MS)).toEqual({
			hits: 7,
			sampled: 3,
			distinctIps: 1
		});
	});
});

describe('WafExcludeDialog', () => {
	it('creates a targeted exclusion limited to the event path by default', async () => {
		clientMock.addWafExclusion.mockResolvedValue({});
		const onClose = vi.fn();
		const onSuccess = vi.fn();
		render(WafExcludeDialog, {
			props: { open: true, event: makeEvent(), host: 'app.example.com', onClose, onSuccess }
		});
		expect(screen.getByTestId('waf-exclude-intro').textContent).toContain('content');
		expect((screen.getByTestId('waf-exclude-path') as HTMLInputElement).value).toBe('/api/save');

		await fireEvent.click(screen.getByTestId('waf-exclude-submit'));
		await waitFor(() => expect(onClose).toHaveBeenCalled());
		expect(clientMock.addWafExclusion).toHaveBeenCalledWith('route-1', {
			ruleId: 942100,
			target: 'ARGS:content',
			path: '/api/save'
		});
		expect(onSuccess).toHaveBeenCalled();
		expect(toastMock.pushToast).toHaveBeenCalledWith(expect.stringContaining('app.example.com'), 'success');
	});

	it('sends the prefix flag, or no path when unchecked', async () => {
		clientMock.addWafExclusion.mockResolvedValue({});
		const { unmount } = render(WafExcludeDialog, {
			props: { open: true, event: makeEvent(), onClose: vi.fn() }
		});
		await fireEvent.click(screen.getByTestId('waf-exclude-prefix'));
		await fireEvent.click(screen.getByTestId('waf-exclude-submit'));
		await waitFor(() => expect(clientMock.addWafExclusion).toHaveBeenCalledTimes(1));
		expect(clientMock.addWafExclusion.mock.calls[0][1]).toEqual({
			ruleId: 942100,
			target: 'ARGS:content',
			path: '/api/save',
			pathPrefix: true
		});
		unmount();

		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose: vi.fn() } });
		await fireEvent.click(screen.getByTestId('waf-exclude-only-path'));
		expect(screen.queryByTestId('waf-exclude-path')).toBeNull();
		await fireEvent.click(screen.getByTestId('waf-exclude-submit'));
		await waitFor(() => expect(clientMock.addWafExclusion).toHaveBeenCalledTimes(2));
		expect(clientMock.addWafExclusion.mock.calls[1][1]).toEqual({ ruleId: 942100, target: 'ARGS:content' });
	});

	it('blocks an invalid edited path', async () => {
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('waf-exclude-path'), { target: { value: 'no-slash' } });
		expect((screen.getByTestId('waf-exclude-submit') as HTMLButtonElement).disabled).toBe(true);
	});

	it('falls back to the whole route only after an explicit acknowledgement', async () => {
		clientMock.addWafExclusion.mockResolvedValue({});
		const onClose = vi.fn();
		render(WafExcludeDialog, {
			props: { open: true, event: makeEvent({ matchedVar: '' }), host: 'app.example.com', onClose }
		});
		expect(screen.getByTestId('waf-exclude-whole-route').textContent).toContain('app.example.com');
		expect(screen.queryByTestId('waf-exclude-path')).toBeNull();

		const submit = screen.getByTestId('waf-exclude-submit') as HTMLButtonElement;
		expect(submit.className).toContain('bg-down');
		expect(submit.disabled).toBe(true);
		await fireEvent.click(submit);
		expect(clientMock.addWafExclusion).not.toHaveBeenCalled();

		const ack = screen.getByTestId('waf-exclude-whole-route-ack') as HTMLInputElement;
		expect(ack.checked).toBe(false);
		expect(ack.closest('label')?.textContent).toContain('942100');
		await fireEvent.click(ack);
		expect(submit.disabled).toBe(false);
		await fireEvent.click(submit);
		await waitFor(() => expect(onClose).toHaveBeenCalled());
		expect(clientMock.addWafExclusion).toHaveBeenCalledWith('route-1', { ruleId: 942100 });
	});

	it('keeps the primary variant and no acknowledgement for a targeted exclusion', () => {
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose: vi.fn() } });
		const submit = screen.getByTestId('waf-exclude-submit') as HTMLButtonElement;
		expect(submit.className).toContain('bg-cyan');
		expect(submit.className).not.toContain('bg-down');
		expect(submit.disabled).toBe(false);
		expect(screen.queryByTestId('waf-exclude-whole-route-ack')).toBeNull();
	});

	it('shows the evidence the event carries', () => {
		render(WafExcludeDialog, {
			props: { open: true, event: makeEvent({ requestMethod: 'POST' }), onClose: vi.fn() }
		});
		expect(screen.getByTestId('waf-exclude-evidence')).toBeInTheDocument();
		expect(screen.getByTestId('waf-exclude-evidence-payload').textContent).toBe("1' OR '1'='1");
		expect(screen.getByTestId('waf-exclude-evidence-ip').textContent).toBe('203.0.113.9');
		expect(screen.getByTestId('waf-exclude-evidence-field').textContent).toContain('ARGS:content');
		expect(screen.getByTestId('waf-exclude-evidence-request').textContent).toBe('POST /api/save?content=x');
	});

	it('shows hits and distinct source IPs over 24h when the counts are complete', async () => {
		const ts = new Date(Date.now() - HOUR_MS).toISOString();
		securityMock.fetchEventsByRule.mockResolvedValue({
			rows: [
				{ ruleId: '942100', category: 'SQLi', count: 3, lastSeen: ts },
				{ ruleId: '942200', category: 'SQLi', count: 40, lastSeen: ts }
			]
		});
		securityMock.fetchEvents.mockResolvedValue({
			events: [
				makeEvent({ id: 1, ts }),
				makeEvent({ id: 2, ts }),
				makeEvent({ id: 3, ts }),
				makeEvent({ id: 4, ts, ruleId: '942200', srcIp: '198.51.100.7' })
			]
		});
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose: vi.fn() } });
		await waitFor(() =>
			expect(screen.getByTestId('waf-exclude-evidence-counts').textContent).toContain('3 hits from 1 IP')
		);
		expect(securityMock.fetchEventsByRule).toHaveBeenCalledWith({ route: 'route-1', window: '24h' });
		expect(securityMock.fetchEvents).toHaveBeenCalledWith({ route: 'route-1', category: 'SQLi', limit: 100 });
	});

	it('says the IP count covers only the most recent hits when the sample is short', async () => {
		const ts = new Date(Date.now() - HOUR_MS).toISOString();
		securityMock.fetchEventsByRule.mockResolvedValue({
			rows: [{ ruleId: '942100', category: 'SQLi', count: 12, lastSeen: ts }]
		});
		securityMock.fetchEvents.mockResolvedValue({
			events: [makeEvent({ id: 1, ts, srcIp: '198.51.100.1' }), makeEvent({ id: 2, ts, srcIp: '198.51.100.2' })]
		});
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose: vi.fn() } });
		await waitFor(() =>
			expect(screen.getByTestId('waf-exclude-evidence-counts').textContent).toContain('12 hits')
		);
		expect(screen.getByTestId('waf-exclude-evidence-counts').textContent).toContain(
			'the 2 most recent come from 2 IPs'
		);
	});

	it('says the counts are unavailable when the API fails', async () => {
		securityMock.fetchEventsByRule.mockRejectedValue(new ApiError('down', 503));
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose: vi.fn() } });
		await waitFor(() =>
			expect(screen.getByTestId('waf-exclude-evidence-counts').textContent).toContain('unavailable')
		);
		// The event's own evidence stays on screen.
		expect(screen.getByTestId('waf-exclude-evidence-ip').textContent).toBe('203.0.113.9');
	});

	it('treats 409 as "already exists" and closes', async () => {
		clientMock.addWafExclusion.mockRejectedValue(new ApiError('exists', 409));
		const onClose = vi.fn();
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose } });
		await fireEvent.click(screen.getByTestId('waf-exclude-submit'));
		await waitFor(() => expect(onClose).toHaveBeenCalled());
		expect(toastMock.pushToast).toHaveBeenCalledWith(expect.any(String), 'info');
	});

	it('keeps the dialog open with the server error otherwise', async () => {
		clientMock.addWafExclusion.mockRejectedValue(new ApiError('rule ID 949110 is protected', 400));
		const onClose = vi.fn();
		render(WafExcludeDialog, { props: { open: true, event: makeEvent(), onClose } });
		await fireEvent.click(screen.getByTestId('waf-exclude-submit'));
		await waitFor(() => expect(screen.getByTestId('waf-exclude-error')).toBeInTheDocument());
		expect(screen.getByTestId('waf-exclude-error').textContent).toContain('949110');
		expect(onClose).not.toHaveBeenCalled();
	});
});

describe('WafEventList — Exclude button', () => {
	it('is hidden for non-admins', () => {
		render(WafEventList, { props: { events: [makeEvent()] } });
		expect(screen.queryByTestId('waf-exclude-open')).toBeNull();
	});

	it('shows for admins on excludable rules only and opens the dialog', async () => {
		asAdmin();
		render(WafEventList, {
			props: {
				events: [makeEvent(), makeEvent({ id: 2, ruleId: '949110' }), makeEvent({ id: 3, ruleId: '100001' })],
				hostByRouteId: { 'route-1': 'app.example.com' }
			}
		});
		const buttons = screen.getAllByTestId('waf-exclude-open');
		expect(buttons).toHaveLength(1);
		await fireEvent.click(buttons[0]);
		expect(screen.getByTestId('waf-exclude-dialog')).toBeInTheDocument();
	});
});

describe('WafTargetedExclusionsEditor', () => {
	it('lists, adds and removes exclusions', async () => {
		let value: WafTargetedExclusion[] = [{ ruleId: 942100, target: 'ARGS:content', path: '/api', pathPrefix: true }];
		const { rerender } = render(WafTargetedExclusionsEditor, {
			props: {
				get value() {
					return value;
				},
				set value(v) {
					value = v;
				}
			}
		});
		expect(screen.getAllByTestId('waf-targeted-row')).toHaveLength(1);

		await fireEvent.input(screen.getByTestId('waf-targeted-rule'), { target: { value: '941100' } });
		await fireEvent.change(screen.getByTestId('waf-targeted-kind'), { target: { value: 'REQUEST_HEADERS' } });
		await fireEvent.input(screen.getByTestId('waf-targeted-name'), { target: { value: 'referer' } });
		await fireEvent.click(screen.getByTestId('waf-targeted-add'));
		expect(value).toEqual([
			{ ruleId: 942100, target: 'ARGS:content', path: '/api', pathPrefix: true },
			{ ruleId: 941100, target: 'REQUEST_HEADERS:referer' }
		]);
		await rerender({});
		await fireEvent.click(screen.getAllByTestId('waf-targeted-remove')[0]);
		expect(value).toEqual([{ ruleId: 941100, target: 'REQUEST_HEADERS:referer' }]);
	});

	it('rejects a protected rule, a bad name and a bad path', async () => {
		let value: WafTargetedExclusion[] = [];
		render(WafTargetedExclusionsEditor, {
			props: {
				get value() {
					return value;
				},
				set value(v) {
					value = v;
				}
			}
		});
		const add = async (rule: string, name: string, path = '') => {
			await fireEvent.input(screen.getByTestId('waf-targeted-rule'), { target: { value: rule } });
			await fireEvent.input(screen.getByTestId('waf-targeted-name'), { target: { value: name } });
			await fireEvent.input(screen.getByTestId('waf-targeted-path'), { target: { value: path } });
			await fireEvent.click(screen.getByTestId('waf-targeted-add'));
		};
		await add('949110', 'a');
		expect(screen.getByTestId('waf-targeted-error')).toBeInTheDocument();
		await add('942100', 'a,b');
		expect(screen.getByTestId('waf-targeted-error')).toBeInTheDocument();
		await add('942100', 'a', 'relative');
		expect(screen.getByTestId('waf-targeted-error')).toBeInTheDocument();
		expect(value).toEqual([]);
	});
});
