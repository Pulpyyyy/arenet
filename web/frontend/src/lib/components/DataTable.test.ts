// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// DataTable component tests (Step F Chunk 7.2, spec §11.3 — 3 tests).
// Behavior-based per §11.2.
//
// DataTable is `generics="T extends { id: string }"`. The row + expanded
// snippets receive the item as parameter, so createRawSnippet's render
// callback takes the typed parameter and returns the markup string.
// testing-library handles the HTML strings; we read the rendered <td>
// content as the assertion surface.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet, type Snippet } from 'svelte';
import DataTable from './DataTable.svelte';

interface Item {
	id: string;
	label: string;
}

const items: Item[] = [
	{ id: 'r1', label: 'route one' },
	{ id: 'r2', label: 'route two' }
];

// Snippets that read the row item parameter. The double cast widens
// the snippet's parameter type from Item to the generic `{id: string}`
// that svelte-check infers from the DataTable's generic signature in
// a non-TSX context. The runtime contract is intact (Svelte calls
// the snippet with the actual Item at render time).
function rowSnippet(): Snippet<[{ id: string }]> {
	return createRawSnippet((getItem: () => Item) => ({
		render: () => {
			const item = getItem();
			return `<td class="px-4 py-3">${item.label}</td>`;
		}
	})) as unknown as Snippet<[{ id: string }]>;
}

function expandedSnippet(): Snippet<[{ id: string }]> {
	return createRawSnippet((getItem: () => Item) => ({
		render: () => {
			const item = getItem();
			return `<div data-testid="expanded-${item.id}">expanded: ${item.label}</div>`;
		}
	})) as unknown as Snippet<[{ id: string }]>;
}

describe('DataTable', () => {
	it('renders all headers + a row per item', () => {
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet()
		});

		// Headers in <th>.
		expect(screen.getByRole('columnheader', { name: 'Label' })).toBeInTheDocument();
		// One <td> per item via the row snippet.
		expect(screen.getByText('route one')).toBeInTheDocument();
		expect(screen.getByText('route two')).toBeInTheDocument();
	});

	it('reveals the expanded snippet when a row is clicked, then collapses on second click', async () => {
		const user = userEvent.setup();
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		// Pre-click: expanded panel is not rendered (activeId === null,
		// the `{#if expanded && open}` branch is false).
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();

		// Mouse convenience: a click anywhere on the row toggles it.
		const firstRow = container.querySelectorAll('tr.data-row')[0] as HTMLElement;
		await user.click(screen.getByText('route one'));
		expect(screen.getByTestId('expanded-r1')).toBeInTheDocument();

		// Second click on the same row collapses it (activeId returns
		// to null per the toggle() logic).
		await user.click(firstRow);
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();
	});

	it('keeps rows as plain table rows and exposes a disclosure button per row', async () => {
		const user = userEvent.setup();
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet(),
			rowLabel: ((item: Item) => item.label) as unknown as (item: { id: string }) => string
		});

		// The <tr> is not hijacked into a button: screen readers keep
		// the row/cell structure.
		for (const r of container.querySelectorAll('tr.data-row')) {
			expect(r.getAttribute('role')).toBeNull();
			expect(r.getAttribute('tabindex')).toBeNull();
			expect(r.getAttribute('aria-expanded')).toBeNull();
		}
		expect(screen.getAllByRole('row').length).toBeGreaterThan(items.length);

		// One real button per row, named after the row via rowLabel.
		const toggle = screen.getByRole('button', { name: 'Details for route one' });
		expect(toggle).toHaveAttribute('aria-expanded', 'false');
		expect(toggle).not.toHaveAttribute('aria-controls');

		// Keyboard path: Tab reaches the button, Enter opens it.
		await user.tab();
		expect(toggle).toHaveFocus();
		await user.keyboard('{Enter}');
		expect(toggle).toHaveAttribute('aria-expanded', 'true');
		const panel = screen.getByTestId('expanded-r1');
		const controlsId = toggle.getAttribute('aria-controls');
		expect(controlsId).toBeTruthy();
		expect(document.getElementById(controlsId as string)).toContainElement(panel);

		// Space closes it again (native <button> activation).
		await user.keyboard(' ');
		expect(toggle).toHaveAttribute('aria-expanded', 'false');
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();
	});

	it('leaves clicks on controls inside a row to those controls', async () => {
		const user = userEvent.setup();
		const withControl = createRawSnippet((getItem: () => Item) => ({
			render: () => {
				const item = getItem();
				return `<td><button type="button">filter ${item.label}</button></td>`;
			}
		})) as unknown as Snippet<[{ id: string }]>;
		render(DataTable, {
			headers: ['Label'],
			items,
			row: withControl,
			expanded: expandedSnippet()
		});

		await user.click(screen.getByRole('button', { name: 'filter route one' }));
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();
	});

	it('shows a fallback empty-state message when items is empty', () => {
		render(DataTable, {
			headers: ['Label'],
			items: [] as Item[],
			row: rowSnippet()
		});

		// DataTable renders a single fallback row with "No items." text
		// inside a colspan'd <td>. Asserting on the text is enough; the
		// surrounding markup is a defensive scaffold.
		expect(screen.getByText('No items.')).toBeInTheDocument();
	});

	it('drops row interactivity when interactive=false (Step G G.3)', () => {
		// Sessions table use case: caller passes no expanded snippet and
		// wants read-only rows: no cursor-pointer, no hover-rail, and no
		// disclosure button (smoke doc Step F §5 dette #1).
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			interactive: false
		});

		// No disclosure buttons and no extra header column.
		expect(screen.queryAllByRole('button')).toHaveLength(0);
		expect(screen.getAllByRole('columnheader')).toHaveLength(1);

		// Rows render without the .interactive class that drives cursor
		// + hover-rail in CSS.
		const rows = container.querySelectorAll('tr.data-row');
		expect(rows).toHaveLength(items.length);
		for (const r of rows) {
			expect(r.getAttribute('tabindex')).toBeNull();
			expect(r.getAttribute('role')).toBeNull();
			expect(r.classList.contains('interactive')).toBe(false);
		}
	});

	it('defaults to interactive=true (rétrocompat Audit)', () => {
		// Without an explicit interactive prop, rows stay click-to-expand
		// (.interactive class) and each gets a disclosure button, with a
		// leading header cell so the columns stay aligned.
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		const rows = container.querySelectorAll('tr.data-row');
		expect(rows).toHaveLength(items.length);
		for (const r of rows) {
			expect(r.classList.contains('interactive')).toBe(true);
			expect(r.querySelectorAll('button[aria-expanded]')).toHaveLength(1);
		}
		expect(screen.getAllByRole('columnheader')).toHaveLength(2);
		expect(screen.getAllByRole('button', { name: 'Row details' })).toHaveLength(items.length);
	});
});
