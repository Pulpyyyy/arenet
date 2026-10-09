// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// OperationView "Try it": a changing request must never go out on a
// double-click. "Send" used to turn into "Yes, send it" in the same
// spot, so the second click of a double-click fired a real write
// against the live configuration.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';

const { clientMock } = vi.hoisted(() => ({
	clientMock: { rawRequest: vi.fn() }
}));
vi.mock('$lib/api/client', () => clientMock);

import OperationView from './OperationView.svelte';
import { listOperations, type Operation } from '$lib/utils/openapi';

/** Mirrors CONFIRM_GUARD_MS in OperationView.svelte. */
const GUARD_MS = 1000;

const DOC = {
	openapi: '3.1.0',
	info: { title: 'Arenet admin API', version: 'v2.39.0' },
	servers: [{ url: '/api/v1' }],
	tags: [{ name: 'Routes' }],
	paths: {
		'/routes': {
			get: { summary: 'List routes', tags: ['Routes'], responses: { '200': { description: 'OK' } } },
			post: {
				summary: 'Create a route',
				tags: ['Routes'],
				requestBody: {
					content: { 'application/json': { schema: { type: 'object', properties: { host: { type: 'string', example: 'a.example.com' } } } } }
				},
				responses: { '201': { description: 'Created' } }
			}
		},
		'/routes/{id}': {
			parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
			delete: { summary: 'Delete a route', tags: ['Routes'], responses: { '204': { description: 'Deleted' } } }
		}
	}
};

function opFor(key: string): Operation {
	const op = listOperations(DOC).find((o) => o.key === key);
	if (!op) throw new Error(`no operation ${key}`);
	return op;
}

/** Renders the DELETE operation with its path parameter filled. */
async function renderDelete(): Promise<void> {
	render(OperationView, { doc: DOC, op: opFor('delete /routes/{id}') });
	await fireEvent.click(screen.getByTestId('api-try-open'));
	await fireEvent.input(screen.getByTestId('api-param-id'), { target: { value: 'r1' } });
}

beforeEach(() => {
	clientMock.rawRequest.mockReset();
	clientMock.rawRequest.mockResolvedValue({ status: 204, body: '', contentType: '' });
	vi.useFakeTimers();
});

afterEach(() => {
	vi.useRealTimers();
});

describe('OperationView — Try it', () => {
	it('does not send a DELETE on a double-click of Send', async () => {
		await renderDelete();
		const send = screen.getByTestId('api-send');

		// Two quick clicks on the same spot, then the browser's dblclick.
		await fireEvent.click(send);
		await fireEvent.click(send);
		await fireEvent.dblClick(send);
		expect(clientMock.rawRequest).not.toHaveBeenCalled();

		// Send stays where it was and is now inert; the confirm control
		// is a different element, held back by the guard.
		expect((send as HTMLButtonElement).disabled).toBe(true);
		const confirm = screen.getByTestId('api-confirm-send') as HTMLButtonElement;
		expect(confirm).not.toBe(send);
		expect(confirm.disabled).toBe(true);
		expect(screen.getByTestId('api-confirm-countdown')).toBeInTheDocument();

		// Even a click that reaches it during the guard does nothing.
		await fireEvent.click(confirm);
		expect(clientMock.rawRequest).not.toHaveBeenCalled();
	});

	it('names the request and marks a DELETE as dangerous', async () => {
		await renderDelete();
		await fireEvent.click(screen.getByTestId('api-send'));
		expect(screen.getByTestId('api-confirm').textContent).toContain('DELETE /api/v1/routes/r1');
		expect(screen.getByTestId('api-confirm-panel').classList.contains('danger')).toBe(true);
		expect(screen.getByTestId('api-confirm-send').classList.contains('danger')).toBe(true);
		// Focus lands on Cancel, so a repeated Enter cancels instead.
		await tick();
		expect(document.activeElement).toBe(screen.getByTestId('api-confirm-cancel'));
	});

	it('sends the DELETE once the guard delay has passed', async () => {
		await renderDelete();
		await fireEvent.click(screen.getByTestId('api-send'));
		await vi.advanceTimersByTimeAsync(GUARD_MS);

		const confirm = screen.getByTestId('api-confirm-send') as HTMLButtonElement;
		expect(confirm.disabled).toBe(false);
		expect(screen.queryByTestId('api-confirm-countdown')).toBeNull();

		await fireEvent.click(confirm);
		expect(clientMock.rawRequest).toHaveBeenCalledTimes(1);
		expect(clientMock.rawRequest).toHaveBeenCalledWith('delete', '/api/v1/routes/r1', undefined);
		expect(screen.queryByTestId('api-confirm-panel')).toBeNull();
	});

	it('returns to the initial state on Escape and on Cancel', async () => {
		await renderDelete();
		const send = screen.getByTestId('api-send') as HTMLButtonElement;

		await fireEvent.click(send);
		await fireEvent.keyDown(window, { key: 'Escape' });
		expect(screen.queryByTestId('api-confirm-panel')).toBeNull();
		expect(send.disabled).toBe(false);

		await fireEvent.click(send);
		await fireEvent.click(screen.getByTestId('api-confirm-cancel'));
		expect(screen.queryByTestId('api-confirm-panel')).toBeNull();
		expect(send.disabled).toBe(false);

		// Re-opening restarts the guard rather than inheriting a spent one.
		await vi.advanceTimersByTimeAsync(GUARD_MS);
		await fireEvent.click(send);
		expect((screen.getByTestId('api-confirm-send') as HTMLButtonElement).disabled).toBe(true);
		expect(clientMock.rawRequest).not.toHaveBeenCalled();
	});

	it('warns about a POST without the DELETE styling', async () => {
		render(OperationView, { doc: DOC, op: opFor('post /routes') });
		await fireEvent.click(screen.getByTestId('api-try-open'));
		await fireEvent.click(screen.getByTestId('api-send'));
		expect(screen.getByTestId('api-confirm').textContent).toContain('POST /api/v1/routes');
		expect(screen.getByTestId('api-confirm-panel').classList.contains('danger')).toBe(false);
		expect(clientMock.rawRequest).not.toHaveBeenCalled();
	});

	it('sends a GET directly, without confirmation', async () => {
		render(OperationView, { doc: DOC, op: opFor('get /routes') });
		await fireEvent.click(screen.getByTestId('api-try-open'));
		await fireEvent.click(screen.getByTestId('api-send'));
		expect(screen.queryByTestId('api-confirm-panel')).toBeNull();
		expect(clientMock.rawRequest).toHaveBeenCalledTimes(1);
		expect(clientMock.rawRequest).toHaveBeenCalledWith('get', '/api/v1/routes', undefined);
	});
});
