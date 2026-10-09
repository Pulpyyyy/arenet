// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.a — AliasNode visual contract pin.
//
// Tests the operator-visible invariants on the rendered DOM:
//   - host string is surfaced
//   - reqPerSec formatted per the rate-label policy
//   - idle state toggles the .idle class + the "—" rate label
//   - hover tooltip on the meta row carries the precise numbers
//   - host element has a title attribute for ellipsis tooltip
//
// AliasNode includes a SvelteFlow <Handle> which requires
// SvelteFlow's per-node context (set by the SvelteFlow internals
// when it mounts a registered node type). That context can't be
// faked from outside the framework, so we mock @xyflow/svelte at
// the module boundary: Handle becomes a no-op stub, the rest of
// the API (Position enum, type imports) flows through.
//
// Props pass through `{props: {…}}` because AliasNodeData.kind
// collides with Svelte component option names. NodeProps requires
// id/type/dragging/selected/etc — we satisfy the type with a
// minimal helper that produces a complete-enough shape, cast to
// `any` to bypass the union arithmetic svelte-check does on the
// generic `Node<T>` constraint.

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import type { AliasNodeData } from '../../_types';

vi.mock('@xyflow/svelte', async () => {
	const actual = await vi.importActual<typeof import('@xyflow/svelte')>('@xyflow/svelte');
	const HandleStub = (await import('./HandleStub.test.svelte')).default;
	return {
		...actual,
		Handle: HandleStub
	};
});

const AliasNode = (await import('./AliasNode.svelte')).default;

function makeData(overrides: Partial<AliasNodeData> = {}): AliasNodeData {
	return {
		kind: 'alias',
		host: 'alt.example.com',
		reqPerSec: 0,
		p99LatencyMs: 0,
		errorRate5xx: 0,
		parentRouteId: 'r-1',
		isIdle: true,
		...overrides
	};
}

// nodeProps satisfies NodeProps' wide surface so svelte-check
// passes. Cast at the boundary keeps the assertion test body
// readable; the runtime contract is the `data` field only.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function nodeProps(data: AliasNodeData): any {
	return {
		id: 'test-alias-node',
		type: 'alias',
		data,
		dragging: false,
		selected: false,
		isConnectable: false,
		positionAbsoluteX: 0,
		positionAbsoluteY: 0,
		width: 140,
		height: 40,
		zIndex: 0
	};
}

describe('AliasNode', () => {
	it('renders the alias host string (no badge — Phase 3.d removed it)', () => {
		// Phase 3.d (2026-06-17): the "ALIAS" badge in front of
		// the hostname was removed. RouteGroupNode container
		// already binds the card to its route visually; the
		// badge was redundant and crowded the host label on the
		// new narrower 170 px width.
		const { container } = render(AliasNode, {
			props: nodeProps(makeData({ host: 'sonarr.example.com', reqPerSec: 0.94, isIdle: false }))
		});
		expect(screen.getByText('sonarr.example.com')).toBeInTheDocument();
		expect(container.querySelector('.kind-tag')).toBeNull();
		// The literal string "alias" must not appear as a
		// standalone label anywhere on the card. (We allow it
		// to appear *within* a hostname like "alias.foo.com",
		// hence the exact match via byText.)
		expect(screen.queryByText('alias')).toBeNull();
	});

	it('formats reqPerSec with two decimals when < 10 r/s', () => {
		render(AliasNode, {
			props: nodeProps(makeData({ host: 'mid.example.com', reqPerSec: 5.482, isIdle: false }))
		});
		expect(screen.getByText('5.48 r/s')).toBeInTheDocument();
	});

	it('formats reqPerSec as integer when >= 10 r/s', () => {
		render(AliasNode, {
			props: nodeProps(makeData({ host: 'busy.example.com', reqPerSec: 137.6, isIdle: false }))
		});
		expect(screen.getByText('138 r/s')).toBeInTheDocument();
	});

	it('renders the "—" rate label and applies the .idle CSS class when isIdle is true', () => {
		const { container } = render(AliasNode, {
			props: nodeProps(makeData({ host: 'idle.example.com', reqPerSec: 0, isIdle: true }))
		});
		expect(screen.getByText('—')).toBeInTheDocument();
		const card = container.querySelector('.alias-node');
		expect(card).not.toBeNull();
		expect(card?.classList.contains('idle')).toBe(true);
	});

	it('omits the .idle class when isIdle is false', () => {
		const { container } = render(AliasNode, {
			props: nodeProps(makeData({ host: 'busy.example.com', reqPerSec: 12.0, isIdle: false }))
		});
		const card = container.querySelector('.alias-node');
		expect(card?.classList.contains('idle')).toBe(false);
	});

	it('surfaces precise reqPerSec, p99, 5xx in the meta hover tooltip', () => {
		const { container } = render(AliasNode, {
			props: nodeProps(makeData({
				host: 'precise.example.com',
				reqPerSec: 1.235,
				p99LatencyMs: 42,
				errorRate5xx: 0.5,
				isIdle: false
			}))
		});
		const meta = container.querySelector('.meta');
		expect(meta).not.toBeNull();
		const title = meta?.getAttribute('title') ?? '';
		expect(title).toContain('1.235 req/s windowed');
		expect(title).toContain('p99 42 ms');
		expect(title).toContain('0.50% 5xx');
		expect(title).not.toContain('idle');
	});

	it('appends "alias idle for 60 s" to the tooltip on idle', () => {
		const { container } = render(AliasNode, {
			props: nodeProps(makeData({ host: 'idle.example.com', reqPerSec: 0, isIdle: true }))
		});
		const meta = container.querySelector('.meta');
		expect(meta?.getAttribute('title') ?? '').toContain('alias idle for 60 s');
	});

	it('host element carries a title attribute equal to the host (for ellipsis tooltip)', () => {
		const { container } = render(AliasNode, {
			props: nodeProps(makeData({ host: 'a-very-very-long-alias-name.example.com', isIdle: false }))
		});
		const host = container.querySelector('.host');
		expect(host?.getAttribute('title')).toBe('a-very-very-long-alias-name.example.com');
	});
});
