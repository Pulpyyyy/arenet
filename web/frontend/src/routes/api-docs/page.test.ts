// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.39 — API docs viewer: helpers + page (list, search, detail,
// "Try it" with confirmation for changing methods).

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';

const { clientMock } = vi.hoisted(() => ({
	clientMock: { getOpenAPI: vi.fn(), rawRequest: vi.fn() }
}));
vi.mock('$lib/api/client', () => clientMock);

import Page from './+page.svelte';
import { fillPath, groupByTag, listOperations, matches, resolve, sampleFromSchema } from '$lib/utils/openapi';

const DOC = {
	openapi: '3.1.0',
	info: { title: 'Arenet admin API', version: 'v2.39.0', description: 'Intro text.' },
	servers: [{ url: '/api/v1' }],
	tags: [{ name: 'Routes' }, { name: 'System' }],
	paths: {
		'/routes': {
			get: { summary: 'List routes', tags: ['Routes'], 'x-arenet-role': 'viewer', responses: { '200': { description: 'OK' } } },
			post: {
				summary: 'Create a route',
				tags: ['Routes'],
				'x-arenet-role': 'admin',
				requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/RouteRequest' } } } },
				responses: { '201': { description: 'Created' }, '400': { $ref: '#/components/responses/BadRequest' } }
			}
		},
		'/routes/{id}': {
			parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
			get: { summary: 'Get a route', tags: ['Routes'], 'x-arenet-role': 'viewer', responses: { '200': { description: 'OK' } } }
		},
		'/healthz': {
			servers: [{ url: '/' }],
			get: { summary: 'Liveness', tags: ['System'], 'x-arenet-role': 'public', security: [], responses: { '200': { description: 'OK' } } }
		}
	},
	components: {
		schemas: {
			RouteRequest: {
				type: 'object',
				required: ['host'],
				properties: {
					host: { type: 'string', example: 'app.example.com' },
					wafMode: { type: 'string', enum: ['off', 'detect', 'block'] },
					id: { type: 'string', readOnly: true },
					upstreams: { type: 'array', items: { $ref: '#/components/schemas/Upstream' } }
				}
			},
			Upstream: { type: 'object', properties: { url: { type: 'string' }, weight: { type: 'integer', minimum: 1 } } }
		},
		responses: { BadRequest: { description: 'Invalid input.' } }
	}
};

beforeEach(() => {
	clientMock.getOpenAPI.mockReset();
	clientMock.rawRequest.mockReset();
	clientMock.getOpenAPI.mockResolvedValue(DOC);
	window.history.replaceState(null, '', '/api-docs');
});

afterEach(() => {
	vi.useRealTimers();
});

// v2.55 — the tag groups fold, so an operation link is hidden until its
// group is opened. getAllByTestId still finds hidden nodes, which is why
// the tests below open the group first: clicking a node a real user cannot
// see would pass while proving nothing.
async function openGroup(index = 0): Promise<void> {
	await fireEvent.click(screen.getAllByTestId('api-tag-toggle')[index]);
}

describe('openapi helpers', () => {
	it('lists operations by tag with full paths', () => {
		const ops = listOperations(DOC);
		expect(ops.map((o) => `${o.method} ${o.fullPath}`)).toEqual([
			'get /api/v1/routes',
			'post /api/v1/routes',
			'get /api/v1/routes/{id}',
			'get /healthz'
		]);
		expect(ops[2].parameters[0].name).toBe('id');
		expect(ops[1].responses['400'].description).toBe('Invalid input.');
		expect(groupByTag(ops).map((g) => g.tag)).toEqual(['Routes', 'System']);
		expect(matches(ops[1], 'create')).toBe(true);
		expect(matches(ops[1], 'healthz')).toBe(false);
	});

	it('builds examples from schemas, skipping read-only fields', () => {
		const sample = sampleFromSchema(DOC, { $ref: '#/components/schemas/RouteRequest' });
		expect(sample).toEqual({ host: 'app.example.com', wafMode: 'off', upstreams: [{ url: '', weight: 1 }] });
		expect(resolve(DOC, { $ref: '#/components/schemas/Upstream' }).type).toBe('object');
		expect(fillPath('/api/v1/routes/{id}', { id: 'a b' })).toBe('/api/v1/routes/a%20b');
	});
});

describe('/api-docs page', () => {
	it('shows the intro, filters, and opens an operation', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('api-intro')).toBeInTheDocument());
		expect(screen.getAllByTestId('api-op-link')).toHaveLength(4);

		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: 'health' } });
		expect(screen.getAllByTestId('api-op-link')).toHaveLength(1);
		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: '' } });

		await openGroup();
		await fireEvent.click(screen.getAllByTestId('api-op-link')[1]);
		const op = screen.getByTestId('api-op');
		expect(op.textContent).toContain('/api/v1/routes');
		expect(op.textContent).toContain('Create a route');
		expect(op.textContent).toContain('host');
		expect(op.textContent).toContain('wafMode');
	});

	it('asks for confirmation before sending a changing request', async () => {
		clientMock.rawRequest.mockResolvedValue({ status: 201, body: '{"id":"r1"}', contentType: 'application/json' });
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-op-link')).toHaveLength(4));
		await openGroup();
		await fireEvent.click(screen.getAllByTestId('api-op-link')[1]);
		await fireEvent.click(screen.getByTestId('api-try-open'));
		expect((screen.getByTestId('api-body') as HTMLTextAreaElement).value).toContain('app.example.com');

		// The confirm button is held back for a moment; fake only the
		// timers from here on, once the document has loaded.
		vi.useFakeTimers();
		await fireEvent.click(screen.getByTestId('api-send'));
		expect(screen.getByTestId('api-confirm')).toBeInTheDocument();
		expect(clientMock.rawRequest).not.toHaveBeenCalled();

		// A second click on Send (a double-click) does not send.
		await fireEvent.click(screen.getByTestId('api-send'));
		expect(clientMock.rawRequest).not.toHaveBeenCalled();

		await vi.advanceTimersByTimeAsync(1000);
		await fireEvent.click(screen.getByTestId('api-confirm-send'));
		vi.useRealTimers();
		await waitFor(() => expect(screen.getByTestId('api-result')).toBeInTheDocument());
		expect(clientMock.rawRequest).toHaveBeenCalledWith('post', '/api/v1/routes', expect.stringContaining('app.example.com'));
		expect(screen.getByTestId('api-result').textContent).toContain('201');
	});

	// v2.55 — the fold.
	//
	// The sidebar rendered all 15 tag groups expanded, so the real document
	// put 159 operations in one column. The operator's report was that every
	// request sat one behind the other and read as odd.
	it('folds every group until one is asked for', async () => {
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-tag-toggle')).toHaveLength(2));

		// In the document, but not something anyone can see or tab to.
		for (const link of screen.getAllByTestId('api-op-link')) {
			expect(link).not.toBeVisible();
		}
		for (const toggle of screen.getAllByTestId('api-tag-toggle')) {
			expect(toggle.getAttribute('aria-expanded')).toBe('false');
		}
	});

	it('opens and closes the group that was clicked, and only that one', async () => {
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-tag-toggle')).toHaveLength(2));
		const [routes, system] = screen.getAllByTestId('api-tag-toggle');

		await fireEvent.click(routes);
		expect(routes.getAttribute('aria-expanded')).toBe('true');
		expect(system.getAttribute('aria-expanded')).toBe('false');
		// Routes owns the first three operations, System the fourth.
		expect(screen.getAllByTestId('api-op-link')[0]).toBeVisible();
		expect(screen.getAllByTestId('api-op-link')[3]).not.toBeVisible();

		await fireEvent.click(routes);
		expect(routes.getAttribute('aria-expanded')).toBe('false');
		expect(screen.getAllByTestId('api-op-link')[0]).not.toBeVisible();
	});

	// Filtering to results nobody can see would be worse than not filtering.
	it('shows the matches of a search without being asked', async () => {
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-tag-toggle')).toHaveLength(2));

		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: 'health' } });
		const links = screen.getAllByTestId('api-op-link');
		expect(links).toHaveLength(1);
		expect(links[0], 'a search that hides its own results').toBeVisible();
	});

	// After a search is cleared, the operation on screen must still be
	// reachable in the list — otherwise the sidebar disagrees with the panel.
	it('keeps the selected operation visible once the search is cleared', async () => {
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-tag-toggle')).toHaveLength(2));

		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: 'health' } });
		await fireEvent.click(screen.getAllByTestId('api-op-link')[0]);
		await fireEvent.input(screen.getByTestId('api-search'), { target: { value: '' } });

		const toggles = screen.getAllByTestId('api-tag-toggle');
		expect(toggles[1].getAttribute('aria-expanded'), 'System holds the selection').toBe('true');
		expect(toggles[0].getAttribute('aria-expanded')).toBe('false');
		expect(screen.getAllByTestId('api-op-link')[3]).toBeVisible();
	});

	// The selected operation lives in the hash: linkable, survives a reload.
	it('opens the operation named by the hash', async () => {
		window.history.replaceState(null, '', '/api-docs#get/routes/{id}');
		render(Page);
		await waitFor(() => expect(screen.getByTestId('api-op').textContent).toContain('Get a route'));
		// Its group is open and its link marked as the current one.
		const link = screen.getAllByTestId('api-op-link')[2];
		expect(link).toBeVisible();
		expect(link.getAttribute('aria-current')).toBe('true');
	});

	it('writes the selection to the hash and marks only the active link', async () => {
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-op-link')).toHaveLength(4));
		await openGroup();
		const links = screen.getAllByTestId('api-op-link');
		for (const l of links) expect(l.hasAttribute('aria-current')).toBe(false);

		await fireEvent.click(links[1]);
		expect(window.location.hash).toBe('#post/routes');
		expect(links[1].getAttribute('aria-current')).toBe('true');
		expect(links[0].hasAttribute('aria-current')).toBe(false);

		await fireEvent.click(links[0]);
		expect(window.location.hash).toBe('#get/routes');
		expect(links[0].getAttribute('aria-current')).toBe('true');
		expect(links[1].hasAttribute('aria-current')).toBe(false);
	});

	it('ignores a hash that names no operation', async () => {
		window.history.replaceState(null, '', '/api-docs#delete/nope');
		render(Page);
		await waitFor(() => expect(screen.getByTestId('api-intro')).toBeInTheDocument());
		expect(screen.queryByTestId('api-op')).toBeNull();
	});

	it('does not nest a second main landmark', async () => {
		const { container } = render(Page);
		await waitFor(() => expect(screen.getByTestId('api-intro')).toBeInTheDocument());
		expect(container.querySelector('main')).toBeNull();
	});

	it('counts the operations in each group', async () => {
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-tag-toggle')).toHaveLength(2));
		const [routes, system] = screen.getAllByTestId('api-tag-toggle');
		expect(routes.textContent).toContain('3');
		expect(system.textContent).toContain('1');
	});

	it('sends a GET directly once the path parameters are filled', async () => {
		clientMock.rawRequest.mockResolvedValue({ status: 404, body: '{"error":"route not found"}', contentType: 'application/json' });
		render(Page);
		await waitFor(() => expect(screen.getAllByTestId('api-op-link')).toHaveLength(4));
		await openGroup();
		await fireEvent.click(screen.getAllByTestId('api-op-link')[2]);
		await fireEvent.click(screen.getByTestId('api-try-open'));
		expect((screen.getByTestId('api-send') as HTMLButtonElement).disabled).toBe(true);
		await fireEvent.input(screen.getByTestId('api-param-id'), { target: { value: 'r1' } });
		await fireEvent.click(screen.getByTestId('api-send'));
		await waitFor(() => expect(screen.getByTestId('api-result')).toBeInTheDocument());
		expect(clientMock.rawRequest).toHaveBeenCalledWith('get', '/api/v1/routes/r1', undefined);
		expect(screen.getByTestId('api-result').textContent).toContain('route not found');
	});
});
