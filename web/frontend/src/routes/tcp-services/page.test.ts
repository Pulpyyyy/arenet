// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.42 — TCP / UDP services page.
//
// What is pinned is what the operator relies on: the list says what
// guards each relay, the two pairings the API refuses are surfaced
// before Save,
// and the PROXY-protocol block says what to configure on the far
// side — the silent failure mode of this feature.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { tick } from 'svelte';
import { ApiError } from '$lib/api/types';

const { api } = vi.hoisted(() => ({
	api: {
		listTCPServices: vi.fn(),
		tcpServicesMetrics: vi.fn(),
		createTCPService: vi.fn(),
		updateTCPService: vi.fn(),
		deleteTCPService: vi.fn(),
		testTCPService: vi.fn()
	}
}));

vi.mock('$lib/api/tcp-services', async (importOriginal) => ({
	...((await importOriginal()) as Record<string, unknown>),
	listTCPServices: (...a: unknown[]) => api.listTCPServices(...a),
	tcpServicesMetrics: (...a: unknown[]) => api.tcpServicesMetrics(...a),
	createTCPService: (...a: unknown[]) => api.createTCPService(...a),
	updateTCPService: (...a: unknown[]) => api.updateTCPService(...a),
	deleteTCPService: (...a: unknown[]) => api.deleteTCPService(...a),
	testTCPService: (...a: unknown[]) => api.testTCPService(...a)
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import Page from './+page.svelte';

function service(over: Record<string, unknown> = {}) {
	return {
		id: 'svc1',
		name: 'stalwart-imaps',
		listenPort: 993,
		protocol: 'tcp',
		upstreams: [{ host: '10.20.0.5', port: 993 }],
		proxyProtocol: 'v2',
		crowdSecEnabled: true,
		createdAt: '2026-09-24T10:00:00Z',
		updatedAt: '2026-09-24T10:00:00Z',
		...over
	};
}

beforeEach(() => {
	Object.values(api).forEach((fn) => fn.mockReset());
	api.listTCPServices.mockResolvedValue([]);
	api.tcpServicesMetrics.mockResolvedValue({});
});

describe('/tcp-services — list', () => {
	it('explains what a relay is when there is none', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		const text = screen.getByTestId('tcp-empty').textContent ?? '';
		expect(text).toMatch(/WAF/);
		expect(text).toMatch(/end to end/i);
	});

	it('shows what guards each relay', async () => {
		api.listTCPServices.mockResolvedValue([
			service(),
			service({
				id: 'svc2',
				name: 'wireguard',
				protocol: 'udp',
				listenPort: 51820,
				crowdSecEnabled: false,
				ipFilter: { mode: 'allow', cidrs: ['192.168.1.0/24'] }
			})
		]);
		render(Page);

		const row = await screen.findByTestId('tcp-row-svc1');
		expect(row.textContent).toContain('tcp/0.0.0.0:993');
		expect(row.textContent).toContain('proxy v2');
		expect(row.textContent).toContain('crowdsec');

		const udp = screen.getByTestId('tcp-row-svc2');
		expect(udp.textContent).toContain('udp/0.0.0.0:51820');
		expect(udp.textContent).toMatch(/ip\s*:\s*1/);
	});
});

describe('/tcp-services — the two refusals, before Save', () => {
	it('warns about PROXY v1 over UDP and about an active check over UDP', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		await userEvent.click(screen.getByTestId('tcp-protocol-udp'));
		await userEvent.click(screen.getByTestId('tcp-proxy-v1'));
		await tick();
		expect(screen.getByTestId('tcp-udp-v1-warning').textContent).toMatch(/v2/);

		// The health-check switch is disabled over UDP rather than
		// letting the operator arm something the API will refuse.
		expect((screen.getByTestId('tcp-healthcheck') as HTMLInputElement).disabled).toBe(true);
	});
});

describe('/tcp-services — the PROXY protocol pairing', () => {
	it('says what to configure on the backend, and tests it', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.testTCPService.mockResolvedValue({
			backends: [{ backend: '10.20.0.5:993', ok: true, elapsedMs: 3 }],
			proxyProtocolNote: 'On Stalwart, that is proxyTrustedNetworks.'
		});
		render(Page);

		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();

		const callout = screen.getByTestId('tcp-proxy-callout').textContent ?? '';
		expect(callout).toMatch(/proxyTrustedNetworks/);
		expect(callout).toMatch(/silently/i);

		await userEvent.click(screen.getByText('Test the backends'));
		await waitFor(() => expect(screen.getByTestId('tcp-test-result')).toBeInTheDocument());
		expect(screen.getByTestId('tcp-test-result').textContent).toContain('10.20.0.5:993');
	});

	it('disappears when no header is sent', async () => {
		api.listTCPServices.mockResolvedValue([service({ proxyProtocol: '' })]);
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
		expect(screen.queryByTestId('tcp-proxy-callout')).toBeNull();
	});
});

describe('/tcp-services — saving', () => {
	it('ships what the form holds', async () => {
		api.createTCPService.mockResolvedValue(service());
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		// v2.44.1 — typed in full: the presets are gone, so this is
		// now the only way an operator fills the form, and the test
		// exercises exactly that path.
		await userEvent.type(document.getElementById('tcp-name') as HTMLInputElement, 'imaps');
		await userEvent.type(document.getElementById('tcp-listen-port') as HTMLInputElement, '993');
		await userEvent.type(document.getElementById('tcp-backend-host') as HTMLInputElement, '10.20.0.5');
		await userEvent.type(document.getElementById('tcp-backend-port') as HTMLInputElement, '993');
		await tick();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.createTCPService).toHaveBeenCalledTimes(1));
		const payload = api.createTCPService.mock.calls[0][0];
		expect(payload).toMatchObject({
			name: 'imaps',
			protocol: 'tcp',
			listenPort: 993,
			proxyProtocol: 'v2',
			crowdSecEnabled: true
		});
		expect(payload.upstreams[0]).toMatchObject({ host: '10.20.0.5', port: 993 });
	});

	// v2.49 — the accepted protocol must SURVIVE the save.
	//
	// buildPayload() rebuilds every field by hand, which is exactly how
	// the v2.46 path redirect was lost: the operator saw a success toast,
	// the log said "config is unchanged", and nothing had been stored.
	// Three places have to agree — buildPayload, resetForm and openEdit —
	// and this covers the first two.
	it('ships the accepted protocol, and does not drop it', async () => {
		api.createTCPService.mockResolvedValue(service());
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		await userEvent.type(document.getElementById('tcp-name') as HTMLInputElement, 'imaps');
		await userEvent.type(document.getElementById('tcp-listen-port') as HTMLInputElement, '993');
		await userEvent.type(document.getElementById('tcp-backend-host') as HTMLInputElement, '10.20.0.5');
		await userEvent.type(document.getElementById('tcp-backend-port') as HTMLInputElement, '993');
		await userEvent.selectOptions(screen.getByTestId('tcp-accept-protocol'), 'tls');
		await tick();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.createTCPService).toHaveBeenCalledTimes(1));
		expect(api.createTCPService.mock.calls[0][0].acceptProtocol).toBe('tls');
	});

	// Left at "anything", nothing is sent: an existing relay must keep
	// emitting the config it emitted before v2.49.
	it('sends no protocol when the operator did not choose one', async () => {
		api.createTCPService.mockResolvedValue(service());
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		await userEvent.type(document.getElementById('tcp-name') as HTMLInputElement, 'imaps');
		await userEvent.type(document.getElementById('tcp-listen-port') as HTMLInputElement, '993');
		await userEvent.type(document.getElementById('tcp-backend-host') as HTMLInputElement, '10.20.0.5');
		await userEvent.type(document.getElementById('tcp-backend-port') as HTMLInputElement, '993');
		await tick();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.createTCPService).toHaveBeenCalledTimes(1));
		expect(api.createTCPService.mock.calls[0][0].acceptProtocol).toBeUndefined();
	});

	// Editing an existing relay must LOAD the stored value, or the first
	// save after opening the form would silently clear it — the other
	// half of the path-redirect bug, which had the same hole in openEdit.
	it('keeps the stored protocol when an existing service is edited', async () => {
		api.listTCPServices.mockResolvedValue([service({ acceptProtocol: 'ssh' })]);
		api.updateTCPService.mockResolvedValue(service({ acceptProtocol: 'ssh' }));
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-row-svc1')).toBeInTheDocument());
		await userEvent.click(screen.getByTestId('tcp-row-svc1'));
		await tick();

		expect((screen.getByTestId('tcp-accept-protocol') as HTMLSelectElement).value).toBe('ssh');

		await userEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(api.updateTCPService).toHaveBeenCalledTimes(1));
		expect(api.updateTCPService.mock.calls[0][1].acceptProtocol).toBe('ssh');
	});

	// The API replaces the whole service on update, and the form shows one
	// backend, an allow list and a health-check switch. Renaming a relay
	// used to delete its other backends, its deny list and its check
	// timing — with a success toast.
	function richService() {
		return service({
			upstreams: [
				{ host: '10.20.0.5', port: 993, maxConnections: 50 },
				{ host: '10.20.0.6', port: 993 },
				{ host: '10.20.0.7', port: 993 }
			],
			lbPolicy: 'least_conn',
			ipFilter: { mode: 'deny', cidrs: ['203.0.113.0/24'] },
			healthCheck: { enabled: true, interval: '10s', timeout: '2s' }
		});
	}

	it('keeps what the form cannot show when only the name changes', async () => {
		api.listTCPServices.mockResolvedValue([richService()]);
		api.updateTCPService.mockResolvedValue(richService());
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();

		const name = document.getElementById('tcp-name') as HTMLInputElement;
		await userEvent.clear(name);
		await userEvent.type(name, 'imaps-renamed');
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.updateTCPService).toHaveBeenCalledTimes(1));
		const payload = api.updateTCPService.mock.calls[0][1];
		expect(payload.name).toBe('imaps-renamed');
		expect(payload.upstreams).toEqual([
			{ host: '10.20.0.5', port: 993, maxConnections: 50 },
			{ host: '10.20.0.6', port: 993 },
			{ host: '10.20.0.7', port: 993 }
		]);
		expect(payload.lbPolicy).toBe('least_conn');
		expect(payload.ipFilter).toEqual({ mode: 'deny', cidrs: ['203.0.113.0/24'] });
		expect(payload.healthCheck).toEqual({ enabled: true, interval: '10s', timeout: '2s' });
	});

	// Switching Restrict on is an explicit choice of an allow list, and
	// it must start empty: the deny list loaded into the "allowed ranges"
	// box would have inverted the gate.
	it('replaces the deny list by an allow list only when Restrict is switched on', async () => {
		api.listTCPServices.mockResolvedValue([richService()]);
		api.updateTCPService.mockResolvedValue(richService());
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();

		await userEvent.click(screen.getByTestId('tcp-restrict'));
		await tick();
		const cidrs = document.getElementById('tcp-cidrs') as HTMLTextAreaElement;
		expect(cidrs.value).toBe('');
		await userEvent.type(cidrs, '192.168.1.0/24');
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.updateTCPService).toHaveBeenCalledTimes(1));
		const payload = api.updateTCPService.mock.calls[0][1];
		expect(payload.ipFilter).toEqual({ mode: 'allow', cidrs: ['192.168.1.0/24'] });
		// The rest is still carried over.
		expect(payload.upstreams).toHaveLength(3);
	});

	it('says what it keeps without showing it, and only when there is something', async () => {
		api.listTCPServices.mockResolvedValue([
			richService(),
			service({ id: 'svc2', name: 'plain', listenPort: 2222 })
		]);
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();

		const note = screen.getByTestId('tcp-hidden-kept').textContent ?? '';
		expect(note).toMatch(/kept on save/i);
		expect(note).toContain('2 more backend');
		expect(note).toMatch(/deny filter/);
		expect(note).toMatch(/health-check timing/);

		// Once Restrict is on the deny list is no longer kept, so the
		// note stops promising it.
		await userEvent.click(screen.getByTestId('tcp-restrict'));
		await tick();
		expect(screen.getByTestId('tcp-hidden-kept').textContent).not.toMatch(/deny filter/);

		// Restrict is an unsaved edit: leaving the row asks first.
		await userEvent.click(screen.getByTestId('tcp-row-svc2'));
		await userEvent.click(await screen.findByText('Discard changes'));
		await tick();
		expect(screen.queryByTestId('tcp-hidden-kept')).toBeNull();
	});

	it('gives no health check to a service that never had one', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.updateTCPService.mockResolvedValue(service());
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.updateTCPService).toHaveBeenCalledTimes(1));
		const payload = api.updateTCPService.mock.calls[0][1];
		expect(payload.healthCheck).toBeUndefined();
		expect(payload.ipFilter).toBeUndefined();
		expect(payload.upstreams).toEqual([{ host: '10.20.0.5', port: 993 }]);
	});

	// Switching to UDP must clear a TCP-only protocol rather than submit
	// a pair the API refuses with a 400 the operator cannot interpret.
	it('clears a TCP-only protocol when the transport becomes UDP', async () => {
		api.createTCPService.mockResolvedValue(service());
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		await userEvent.selectOptions(screen.getByTestId('tcp-accept-protocol'), 'tls');
		await tick();
		expect((screen.getByTestId('tcp-accept-protocol') as HTMLSelectElement).value).toBe('tls');

		await userEvent.click(screen.getByText('UDP'));
		await tick();
		expect((screen.getByTestId('tcp-accept-protocol') as HTMLSelectElement).value).toBe('');
		// And the offer itself follows the transport.
		const options = Array.from(
			(screen.getByTestId('tcp-accept-protocol') as HTMLSelectElement).options
		).map((o) => o.value);
		expect(options).toContain('wireguard');
		expect(options).not.toContain('tls');
	});

	// The form now checks its fields first, so it is filled: an empty
	// one never reaches the API. A refusal that names no field still
	// lands in the block at the bottom.
	it('surfaces what the server refused', async () => {
		api.createTCPService.mockRejectedValue(new Error('caddy reload failed: listener exploded'));
		await openNewForm();
		await fillValidForm();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(screen.getByTestId('tcp-form-error')).toBeInTheDocument());
		expect(screen.getByTestId('tcp-form-error').textContent).toContain('listener exploded');
	});
});

async function openNewForm() {
	render(Page);
	await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
	await userEvent.click(screen.getAllByText('+ New service')[0]);
	await tick();
}

function field(id: string): HTMLInputElement {
	return document.getElementById(id) as HTMLInputElement;
}

async function fillValidForm() {
	await userEvent.type(field('tcp-name'), 'imaps');
	await userEvent.type(field('tcp-listen-port'), '993');
	await userEvent.type(field('tcp-backend-host'), '10.20.0.5');
	await userEvent.type(field('tcp-backend-port'), '993');
	await tick();
}

// The form used to send whatever it held — an empty port went out as
// 0 — and every refusal came back as one sentence at the bottom, far
// from the field to fix.
describe('/tcp-services — the form checks its fields before sending', () => {
	it('sends nothing while required fields are empty, and says so next to each', async () => {
		await openNewForm();
		await userEvent.click(screen.getByText('Save'));

		for (const id of ['tcp-name', 'tcp-listen-port', 'tcp-backend-host', 'tcp-backend-port']) {
			const err = await screen.findByTestId(`${id}-err`);
			expect(err.textContent?.trim()).not.toBe('');
			expect(field(id).getAttribute('aria-invalid')).toBe('true');
			expect(field(id).getAttribute('aria-describedby')).toBe(err.id);
		}
		expect(screen.getByTestId('tcp-name-err').textContent).toMatch(/name/i);
		expect(screen.getByTestId('tcp-listen-port-err').textContent).toMatch(/port/i);
		// The interface may stay empty: it means "all".
		expect(screen.queryByTestId('tcp-listen-addr-err')).toBeNull();
		expect(field('tcp-listen-addr').getAttribute('aria-invalid')).toBeNull();
		// Errors that belong to a field are not repeated at the bottom.
		expect(screen.queryByTestId('tcp-form-error')).toBeNull();
		// The first field in error is where the operator lands.
		await waitFor(() => expect(document.activeElement).toBe(field('tcp-name')));
		expect(api.createTCPService).not.toHaveBeenCalled();
	});

	it('refuses a port out of range, then saves once it is fixed', async () => {
		api.createTCPService.mockResolvedValue(service());
		await openNewForm();
		await userEvent.type(field('tcp-name'), 'imaps');
		await userEvent.type(field('tcp-listen-port'), '70000');
		await userEvent.type(field('tcp-backend-host'), '10.20.0.5');
		await userEvent.type(field('tcp-backend-port'), '993');
		await tick();
		await userEvent.click(screen.getByText('Save'));

		const err = await screen.findByTestId('tcp-listen-port-err');
		expect(err.textContent).toMatch(/1 to 65535/);
		expect(screen.queryByTestId('tcp-name-err')).toBeNull();
		expect(screen.queryByTestId('tcp-backend-port-err')).toBeNull();
		await waitFor(() => expect(document.activeElement).toBe(field('tcp-listen-port')));
		expect(api.createTCPService).not.toHaveBeenCalled();

		// Editing the field clears its message; a valid value goes out.
		await userEvent.clear(field('tcp-listen-port'));
		await userEvent.type(field('tcp-listen-port'), '993');
		await tick();
		expect(screen.queryByTestId('tcp-listen-port-err')).toBeNull();
		expect(field('tcp-listen-port').getAttribute('aria-invalid')).toBeNull();

		await userEvent.click(screen.getByText('Save'));
		await waitFor(() => expect(api.createTCPService).toHaveBeenCalledTimes(1));
		expect(api.createTCPService.mock.calls[0][0]).toMatchObject({ name: 'imaps', listenPort: 993 });
	});

	it('saves a valid form without complaint', async () => {
		api.createTCPService.mockResolvedValue(service());
		await openNewForm();
		await fillValidForm();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.createTCPService).toHaveBeenCalledTimes(1));
		expect(document.querySelector('[aria-invalid="true"]')).toBeNull();
	});

	// The server knows things the form cannot: whether the port is free
	// on this host, whether another relay already holds it.
	it('puts a refusal about the listening port next to that port', async () => {
		api.createTCPService.mockRejectedValue(
			new ApiError(
				'cannot listen on 0.0.0.0:993: address already in use',
				400,
				'validation',
				undefined,
				'listen_port_taken',
				{ addr: '0.0.0.0:993' }
			)
		);
		await openNewForm();
		await fillValidForm();
		await userEvent.click(screen.getByText('Save'));

		const err = await screen.findByTestId('tcp-listen-port-err');
		// Translated from the code, not the server's English.
		expect(err.textContent).toMatch(/something else on this host already holds it/);
		expect(err.textContent).toContain('0.0.0.0:993');
		expect(field('tcp-listen-port').getAttribute('aria-invalid')).toBe('true');
		expect(screen.queryByTestId('tcp-form-error')).toBeNull();
		await waitFor(() => expect(document.activeElement).toBe(field('tcp-listen-port')));
	});

	it('maps a port conflict with another relay to the listening port', async () => {
		api.createTCPService.mockRejectedValue(
			new ApiError('tcp service "imaps": port 443 is used by Arenet HTTPS routes', 400)
		);
		await openNewForm();
		await fillValidForm();
		await userEvent.click(screen.getByText('Save'));

		const err = await screen.findByTestId('tcp-listen-port-err');
		expect(err.textContent).toContain('Arenet HTTPS routes');
		expect(screen.queryByTestId('tcp-form-error')).toBeNull();
	});
});

// v2.42 — the counters. Layer-4 traffic crosses no HTTP chain, so
// this column is the only place an operator can see that a relay is
// carrying anything at all.
describe('/tcp-services — traffic', () => {
	it('shows connections, open ones, failures and bytes', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.tcpServicesMetrics.mockResolvedValue({
			svc1: { connections: 42, active: 3, bytesIn: 2048, bytesOut: 5_242_880, errors: 2 }
		});
		render(Page);

		const cell = await screen.findByTestId('tcp-traffic-svc1');
		const text = cell.textContent ?? '';
		expect(text).toContain('42');
		expect(text).toContain('3');
		expect(text).toContain('2');
		// Decimal units (lib/utils/format.ts): 2048 B → 2 kB, 5 MiB → 5.2 MB.
		expect(text).toMatch(/2\skB/);
		expect(text).toMatch(/5\.2\sMB/);
	});

	it('shows a dash for a service that has carried nothing yet', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.tcpServicesMetrics.mockResolvedValue({});
		render(Page);
		expect((await screen.findByTestId('tcp-traffic-svc1')).textContent).toContain('—');
	});

	it('still lists the services when the counters cannot be read', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.tcpServicesMetrics.mockRejectedValue(new Error('nope'));
		render(Page);
		expect(await screen.findByTestId('tcp-row-svc1')).toBeInTheDocument();
	});
});

// --- v2.42.1 — the empty state takes the page --------------------
//
// It used to be squeezed into the left column of the split layout,
// which only exists to leave room for a list that is not there yet.

describe('/tcp-services — empty state layout', () => {
	it('is full width and carries the diagram when nothing is configured', async () => {
		render(Page);
		const empty = await screen.findByTestId('tcp-empty');
		// Not inside the two-column grid.
		// v2.48 — the marker moved from the old fixed xl:grid-cols
		// class to .split, so the previous assertion would now pass
		// by looking for something that exists nowhere.
		expect(empty.closest('.split')).toBeNull();
		// The diagram explains what the sentence says.
		const diagram = empty.querySelector('[role="img"]');
		expect(diagram).not.toBeNull();
		const described = diagram?.getAttribute('aria-label') ?? '';
		expect(described).toMatch(/without reading/i);
		expect(described).toMatch(/client IP/i);
		// v2.42.2 — one row. The HTTP route drawn above for contrast
		// only made the row that matters harder to read.
		expect(diagram?.querySelectorAll('.node').length).toBe(3);
		expect(described).not.toMatch(/inspect/i);
	});

	it('steps aside once the form is open, so the form is not pushed off screen', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		expect(screen.queryByTestId('tcp-empty')).toBeNull();
		expect(screen.getByTestId('tcp-form')).toBeInTheDocument();
		// A compact reminder stays where the list will be.
		expect(screen.getByTestId('tcp-empty-compact')).toBeInTheDocument();
	});
});

// --- v2.43 — the test proves the pairing, the list moves on its own
//
// Two things the page could not do before. The test button opened a
// connection and closed it, which said nothing about the PROXY
// pairing — the failure that actually breaks relays, and the one the
// operator hit in production. And the traffic column only moved on a
// manual reload, which for a feature whose traffic appears nowhere
// else in the UI turned a live view into a snapshot.

describe('/tcp-services — the PROXY verdict', () => {
	it('shows that the backend did not refuse the header', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.testTCPService.mockResolvedValue({
			backends: [
				{ backend: '10.20.0.5:993', ok: true, elapsedMs: 3, proxyProtocol: 'not-refused' }
			],
			proxyProtocolNote: 'On Stalwart, that is proxyTrustedNetworks.'
		});
		render(Page);

		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
		await userEvent.click(screen.getByText('Test the backends'));

		await waitFor(() => expect(screen.getByTestId('tcp-test-result')).toBeInTheDocument());
		const text = screen.getByTestId('tcp-test-result').textContent ?? '';
		expect(text).toMatch(/not refused/i);
		// The wording must not overclaim: one connection cannot prove
		// the far side parsed the header, only that it did not hang up.
		expect(text).not.toMatch(/accepted/i);
	});

	it('names the refusal when the backend hangs up', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.testTCPService.mockResolvedValue({
			backends: [{ backend: '10.20.0.5:993', ok: true, elapsedMs: 2, proxyProtocol: 'refused' }]
		});
		render(Page);

		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
		await userEvent.click(screen.getByText('Test the backends'));

		await waitFor(() => expect(screen.getByTestId('tcp-test-result')).toBeInTheDocument());
		const text = screen.getByTestId('tcp-test-result').textContent ?? '';
		// The dial succeeded, so the row is not an error — the verdict
		// on the header is the separate, useful part.
		expect(text).toContain('10.20.0.5:993');
		expect(text).toMatch(/refused/i);
		expect(text).toMatch(/not expecting it/i);
	});

	it('reports a UDP backend as untestable rather than broken', async () => {
		api.listTCPServices.mockResolvedValue([
			service({ protocol: 'udp', listenPort: 51820, name: 'wireguard' })
		]);
		api.testTCPService.mockResolvedValue({
			backends: [
				{
					backend: '10.20.0.9:51820',
					ok: false,
					skipped: true,
					elapsedMs: 0,
					error: 'UDP is connectionless: there is no handshake to attempt.'
				}
			]
		});
		render(Page);

		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
		await userEvent.click(screen.getByText('Test the backends'));

		await waitFor(() => expect(screen.getByTestId('tcp-test-result')).toBeInTheDocument());
		const text = screen.getByTestId('tcp-test-result').textContent ?? '';
		expect(text).toMatch(/not testable/i);
		expect(text).toMatch(/connectionless/i);
		// Not a failure: the cross would read as "your relay is broken".
		expect(text).not.toContain('✕');
	});
});

describe('/tcp-services — live counters', () => {
	it('refreshes the traffic column without a reload', async () => {
		vi.useFakeTimers();
		try {
			api.listTCPServices.mockResolvedValue([service()]);
			api.tcpServicesMetrics.mockResolvedValue({
				svc1: { connections: 1, active: 1, bytesIn: 100, bytesOut: 200, errors: 0 }
			});
			render(Page);
			await vi.waitFor(() => expect(screen.getByTestId('tcp-traffic-svc1')).toBeInTheDocument());
			expect(screen.getByTestId('tcp-traffic-svc1').textContent).toContain('100');

			// The session carries on: the counters must move on their
			// own, which is the whole point for a long-lived relay.
			api.tcpServicesMetrics.mockResolvedValue({
				svc1: { connections: 1, active: 1, bytesIn: 4096, bytesOut: 200, errors: 0 }
			});
			await vi.advanceTimersByTimeAsync(5000);
			await vi.waitFor(() =>
				expect(screen.getByTestId('tcp-traffic-svc1').textContent).toMatch(/4\.1\skB/)
			);
		} finally {
			vi.useRealTimers();
		}
	});

	it('keeps the last good values when a tick fails', async () => {
		vi.useFakeTimers();
		try {
			api.listTCPServices.mockResolvedValue([service()]);
			api.tcpServicesMetrics.mockResolvedValue({
				svc1: { connections: 7, active: 0, bytesIn: 100, bytesOut: 200, errors: 0 }
			});
			render(Page);
			await vi.waitFor(() => expect(screen.getByTestId('tcp-row-svc1')).toBeInTheDocument());

			api.listTCPServices.mockRejectedValue(new Error('network down'));
			api.tcpServicesMetrics.mockRejectedValue(new Error('network down'));
			await vi.advanceTimersByTimeAsync(5000);

			// A failed poll must not blank the page the operator is
			// looking at, nor raise an error banner over stale-but-true
			// numbers.
			expect(screen.getByTestId('tcp-row-svc1')).toBeInTheDocument();
			expect(screen.getByTestId('tcp-traffic-svc1').textContent).toContain('7');
		} finally {
			vi.useRealTimers();
		}
	});
});

// --- v2.48 — the table owns the page until something is selected --
//
// The split was fixed at two columns, so the list sat squeezed into
// half the width even with nothing open beside it: every column
// truncated for a panel that was not there.

describe('/tcp-services — the split only opens on demand', () => {
	it('is one column until a service is selected', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		render(Page);

		const row = await screen.findByTestId('tcp-row-svc1');
		const split = row.closest('.split');
		expect(split).not.toBeNull();
		expect(split?.classList.contains('split-open')).toBe(false);

		await userEvent.click(row);
		await tick();
		expect(split?.classList.contains('split-open')).toBe(true);
	});
});

// Cancel, another row, Add and leaving the page all dropped an edit
// unasked. They now go through one discard question.
describe('/tcp-services — unsaved changes', () => {
	async function openService() {
		api.listTCPServices.mockResolvedValue([service()]);
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
	}
	const nameInput = () => document.getElementById('tcp-name') as HTMLInputElement | null;

	it('closes without asking when nothing changed', async () => {
		await openService();
		await userEvent.click(screen.getByText('Cancel'));
		await tick();
		expect(screen.queryByText('Discard your changes?')).toBeNull();
		expect(nameInput()).toBeNull();
	});

	it('asks before Cancel drops an edit, and keeps it on "Keep editing"', async () => {
		await openService();
		await userEvent.type(nameInput()!, '-2');
		await userEvent.click(screen.getByText('Cancel'));
		await tick();
		expect(await screen.findByText('Discard your changes?')).toBeInTheDocument();

		await userEvent.click(screen.getByText('Keep editing'));
		await tick();
		expect(nameInput()?.value).toBe('stalwart-imaps-2');

		await userEvent.click(screen.getByText('Cancel'));
		await userEvent.click(await screen.findByText('Discard changes'));
		await waitFor(() => expect(nameInput()).toBeNull());
	});
});

