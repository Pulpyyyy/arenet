// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// AL.4.b.3 — RuleModal behaviour tests. Mirrors the
// AL.4.b.2 ChannelModal test layout. Focus on the dynamic
// source/eval form switching + the channel multi-select +
// validation rejects + valid submit payload shape.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type {
	AlertChannel,
	AlertRule,
	AlertRuleRequest,
	AlertRuleTestResponse
} from '$lib/api/alerting';

const createMock = vi.fn();
const updateMock = vi.fn();
const testMock = vi.fn();
const listChannelsMock = vi.fn();
const listRulesMock = vi.fn();

vi.mock('$lib/api/alerting', async () => {
	const real = await vi.importActual<typeof import('$lib/api/alerting')>('$lib/api/alerting');
	return {
		...real,
		alertingApi: {
			...real.alertingApi,
			createRule: (r: AlertRuleRequest) => createMock(r),
			updateRule: (id: string, r: AlertRuleRequest) => updateMock(id, r),
			testRule: (id: string): Promise<AlertRuleTestResponse> => testMock(id),
			listChannels: (): Promise<AlertChannel[]> => listChannelsMock(),
			listRules: (): Promise<AlertRule[]> => listRulesMock()
		}
	};
});

const listRoutesMock = vi.fn();
vi.mock('$lib/api/client', async () => {
	const real = await vi.importActual<typeof import('$lib/api/client')>('$lib/api/client');
	return {
		...real,
		listRoutes: () => listRoutesMock()
	};
});

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (m: string, v?: string) => pushToastMock(m, v)
}));

beforeEach(() => {
	createMock.mockReset();
	updateMock.mockReset();
	testMock.mockReset();
	listChannelsMock.mockReset();
	listRulesMock.mockReset();
	listRoutesMock.mockReset();
	pushToastMock.mockReset();
	// Default seeds: 2 enabled channels, no routes (cert
	// path is fine without), no rules.
	listChannelsMock.mockResolvedValue([
		{
			id: 'ch-1',
			name: 'ops-webhook',
			kind: 'webhook',
			enabled: true,
			minSeverity: 0,
			config: { url: 'http://x', method: 'POST', timeoutSeconds: 5 },
			createdAt: '',
			updatedAt: ''
		},
		{
			id: 'ch-2',
			name: 'ops-email',
			kind: 'email',
			enabled: true,
			minSeverity: 0,
			config: {
				smtpHost: 'x',
				smtpPort: 587,
				smtpUsername: '',
				smtpPassword: '',
				from: 'a@b',
				to: ['c@d'],
				useTLS: false,
				useStartTLS: true
			},
			createdAt: '',
			updatedAt: ''
		}
	] satisfies AlertChannel[]);
	listRulesMock.mockResolvedValue([]);
	listRoutesMock.mockResolvedValue([]);
});

function thresholdRule(): AlertRule {
	return {
		id: 'rule-1',
		name: 'block-rate',
		enabled: true,
		kind: 'threshold',
		severity: 1,
		category: 'waf',
		source: 'waf_event_rate',
		sourceParams: { windowSecs: 300, action: 'BLOCK' },
		evalParams: { operator: '>', value: 50 },
		channels: ['ch-1'],
		cooldownSecs: 300,
		createdAt: '2026-06-16T10:00:00Z',
		updatedAt: '2026-06-16T10:00:00Z'
	};
}

describe('RuleModal', () => {
	it('shows the waf_event_rate sub-form by default (create mode)', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		// waf_event_rate exposes a window/action/route trio.
		expect(screen.getByLabelText(/Window/i)).toBeTruthy();
		expect(screen.getByLabelText(/Action/i)).toBeTruthy();
		// cert_expiry-only label must NOT be present.
		expect(screen.queryByLabelText(/Host/i)).toBeNull();
	});

	it('swaps to cert_expiry sub-form when source = cert_expiry', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'cert_expiry' } });

		expect(screen.getByLabelText(/Host/i)).toBeTruthy();
		// waf_event_rate fields gone.
		expect(screen.queryByLabelText(/Window/i)).toBeNull();
	});

	it('swaps to system_health sub-form when source = system_health', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'system_health' } });

		expect(screen.getByLabelText(/Component/i)).toBeTruthy();
		expect(screen.queryByLabelText(/Window/i)).toBeNull();
		expect(screen.queryByLabelText(/Host/i)).toBeNull();
	});

	// v2.54 — asked by the operator: "BoltDB is still in the list, didn't
	// you say you'd put db?". The label IS "BoltDB" and the value IS "db",
	// so that part is right. What was not: the editor once offered the
	// value "boltdb", the evaluator was taught to accept both in v2.52, but
	// the editor was not — so reopening one of those older rules bound
	// "boltdb" to a <select> with no such option and showed the wrong
	// component for a rule that works.
	it('shows BoltDB as the label for the db component', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.change(screen.getByLabelText(/^Source$/i), {
			target: { value: 'system_health' }
		});

		const select = screen.getByLabelText(/Component/i) as HTMLSelectElement;
		const db = Array.from(select.options).find((o) => o.value === 'db');
		expect(db, 'no option carries the value the health report publishes').toBeTruthy();
		expect(db?.textContent?.trim()).toBe('BoltDB');
		// And the name that never matched the report must not be offered.
		expect(Array.from(select.options).map((o) => o.value)).not.toContain('boltdb');
	});

	it('resolves a legacy boltdb component to db when editing an older rule', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				rule: {
					...thresholdRule(),
					source: 'system_health',
					sourceParams: { component: 'boltdb' }
				},
				onClose: () => {},
				onSaved: () => {}
			}
		});

		const select = screen.getByLabelText(/Component/i) as HTMLSelectElement;
		expect(select.value, 'an older rule shows no component at all').toBe('db');
	});

	it('lists cert_renewal_failed as a selectable Source option (hotfix Cert.A.2)', async () => {
		// Regression guard for the Cert.A backend ship that
		// left the frontend dropdown hardcoded — operators saw
		// the source registered in journalctl but couldn't
		// wire a rule via UI.
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		const opts = Array.from(sourceSelect.options).map((o) => o.value);
		expect(opts).toContain('cert_renewal_failed');
	});

	it('lists update_available as a selectable Source option (v2.12.5)', async () => {
		// Same class of bug as cert_renewal_failed above: v2.12.3
		// registered the update_available backend source but the
		// dropdown stayed hardcoded, so operators couldn't wire an
		// "update available" alert rule via the UI.
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		const opts = Array.from(sourceSelect.options).map((o) => o.value);
		expect(opts).toContain('update_available');
	});

	it('update_available is a state source with no source-specific params', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'update_available' } });

		// No per-source sub-form fields (unlike waf/cert/system_health).
		expect(screen.queryByLabelText(/Window/i)).toBeNull();
		expect(screen.queryByLabelText(/Host/i)).toBeNull();
		expect(screen.queryByLabelText(/Component/i)).toBeNull();
		// It is a state rule → the state "expected" field is present.
		expect(screen.getByLabelText(/Expected/i)).toBeTruthy();
	});

	it('swaps to cert_renewal_failed sub-form when source = cert_renewal_failed', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'cert_renewal_failed' } });

		// Sub-form's own inputs are present.
		expect(screen.getByLabelText(/Domain/i)).toBeTruthy();
		expect(screen.getByLabelText(/Failure window/i)).toBeTruthy();
		// Other sub-forms gone.
		expect(screen.queryByLabelText(/^Hôte/i)).toBeNull();
		expect(screen.queryByLabelText(/Component/i)).toBeNull();
	});

	it('cert_manual_expiring sends no host source param (backend ignores it)', async () => {
		// The backend CertManualExpiringParams struct has only
		// thresholdDays (carried in eval params), no host. The old
		// buildSourceParams put p.host in here, which the backend
		// silently dropped — assert we no longer send it.
		createMock.mockResolvedValue(thresholdRule());
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		// First pick cert_expiry and fill its Host field so the shared
		// certHost state carries a value. The old buggy code leaked this
		// stale value into cert_manual_expiring's source params.
		await fireEvent.change(sourceSelect, { target: { value: 'cert_expiry' } });
		await fireEvent.input(screen.getByLabelText(/Host/i), {
			target: { value: 'stale.example.com' }
		});
		await fireEvent.change(sourceSelect, { target: { value: 'cert_manual_expiring' } });

		await fireEvent.input(screen.getByLabelText(/^Name \(slug\)$/i), {
			target: { value: 'manual-cert-expiring' }
		});
		const opsWh = screen.getByText('ops-webhook').previousElementSibling as HTMLInputElement;
		await fireEvent.click(opsWh);
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(createMock).toHaveBeenCalledTimes(1);
		});
		const [req] = createMock.mock.calls[0];
		expect(req.source).toBe('cert_manual_expiring');
		// The bug: p.host was set for this source. It must be absent.
		expect(req.sourceParams).not.toHaveProperty('host');
	});

	// v2.52 — cert_manual_expiring had NO form branch, so thresholdDays
	// never left the backend default of 30 and the operator could not
	// change it. Worse, the code comment claimed the value travelled in
	// the threshold eval params; it does not — eval `value` is compared
	// against the COUNT of matching certificates.
	it('sends an editable thresholdDays for cert_manual_expiring', async () => {
		createMock.mockResolvedValue(thresholdRule());
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});
		await waitFor(() => expect(screen.getByText('ops-webhook')).toBeTruthy());

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'cert_manual_expiring' } });

		// The form must exist at all — it did not before.
		const days = screen.getByTestId('cert-manual-days') as HTMLInputElement;
		await fireEvent.input(days, { target: { value: '45' } });

		await fireEvent.input(screen.getByLabelText(/^Name \(slug\)$/i), {
			target: { value: 'manual-45' }
		});
		const opsWh = screen.getByText('ops-webhook').previousElementSibling as HTMLInputElement;
		await fireEvent.click(opsWh);
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => expect(createMock).toHaveBeenCalledTimes(1));
		expect(createMock.mock.calls[0][0].sourceParams.thresholdDays).toBe(45);
	});

	// And the stored value must come back when editing, or the first save
	// after opening the form would silently reset it to 30.
	it('loads a stored thresholdDays when editing', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				rule: {
					...thresholdRule(),
					source: 'cert_manual_expiring',
					sourceParams: { thresholdDays: 60 }
				},
				onClose: () => {},
				onSaved: () => {}
			}
		});

		const days = (await screen.findByTestId('cert-manual-days')) as HTMLInputElement;
		expect(days.value).toBe('60');
	});

	it('swaps to State eval form when kind=state', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const stateRadio = screen.getByLabelText(/State \(string\)/i) as HTMLInputElement;
		await fireEvent.click(stateRadio);

		expect(screen.getByLabelText(/Expected value/i)).toBeTruthy();
		expect(screen.queryByLabelText(/Operator/i)).toBeNull();
	});

	it('disables the kind selector in edit mode', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: thresholdRule(), onClose: () => {}, onSaved: () => {} }
		});

		const threshRadio = screen.getByLabelText(/Threshold \(numeric\)/i) as HTMLInputElement;
		const stateRadio = screen.getByLabelText(/State \(string\)/i) as HTMLInputElement;
		expect(threshRadio.disabled).toBe(true);
		expect(stateRadio.disabled).toBe(true);
	});

	it('blocks submit when no channels are selected', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		// Wait for channels to load so the multi-select is rendered.
		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});

		// Fill required scalar fields.
		await fireEvent.input(screen.getByLabelText(/^Name \(slug\)$/i), {
			target: { value: 'no-channels' }
		});
		// Don't tick any channel checkbox.
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(screen.getByText(/at least one channel/i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
	});

	it('blocks submit when name does not match the slug regex', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.input(screen.getByLabelText(/^Name \(slug\)$/i), {
			target: { value: 'Block Rate High!' } // spaces + caps + bang
		});
		// Tick a channel so the only invariant left is the name.
		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});
		const opsWh = screen.getByText('ops-webhook').previousElementSibling as HTMLInputElement;
		await fireEvent.click(opsWh);
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(screen.getByText(/lowercase.*alphanumeric.*dashes/i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
	});

	it('submits a valid threshold rule with the expected payload', async () => {
		createMock.mockResolvedValue(thresholdRule());
		const Modal = (await import('./RuleModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved }
		});

		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});

		await fireEvent.input(screen.getByLabelText(/^Name \(slug\)$/i), {
			target: { value: 'block-rate' }
		});
		const opsWh = screen.getByText('ops-webhook').previousElementSibling as HTMLInputElement;
		await fireEvent.click(opsWh);
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(createMock).toHaveBeenCalledTimes(1);
		});
		const [req] = createMock.mock.calls[0];
		expect(req.name).toBe('block-rate');
		expect(req.kind).toBe('threshold');
		expect(req.source).toBe('waf_event_rate');
		expect(req.channels).toEqual(['ch-1']);
		// Eval params shape: threshold ⇒ {operator, value}.
		expect(req.evalParams.operator).toBe('>');
		expect(typeof req.evalParams.value).toBe('number');
		// Source params shape: waf_event_rate ⇒ at least
		// windowSecs (defaults to 300).
		expect(req.sourceParams.windowSecs).toBeGreaterThanOrEqual(60);
		expect(onSaved).toHaveBeenCalledTimes(1);
	});

	it('pre-populates the edit form from an existing rule', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: thresholdRule(), onClose: () => {}, onSaved: () => {} }
		});

		const nameInput = screen.getByLabelText(/^Name \(slug\)$/i) as HTMLInputElement;
		expect(nameInput.value).toBe('block-rate');

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		expect(sourceSelect.value).toBe('waf_event_rate');

		const opSelect = screen.getByLabelText(/Operator/i) as HTMLSelectElement;
		expect(opSelect.value).toBe('>');

		const valueInput = screen.getByLabelText(/Threshold value/i) as HTMLInputElement;
		expect(Number(valueInput.value)).toBe(50);

		// The pre-populated channel checkbox is ticked.
		await waitFor(() => {
			const opsWhText = screen.getByText('ops-webhook');
			const checkbox = opsWhText.previousElementSibling as HTMLInputElement;
			expect(checkbox.checked).toBe(true);
		});
	});
});
