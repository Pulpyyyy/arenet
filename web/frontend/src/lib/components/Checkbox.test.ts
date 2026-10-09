// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Checkbox keyboard focus. The real <input> is opacity-0 and the
// visible box is a painted sibling, so the focus ring has to live on
// the painted box, keyed on the input's :focus-visible through
// Tailwind's `peer` / `peer-focus-visible:` pair. jsdom computes no
// :focus-visible and no Tailwind CSS, so this pins the structure the
// selector relies on: the input is the peer, the box is a LATER
// sibling of it (`peer-*` compiles to `.peer:focus-visible ~ .x`), and
// the box carries the focus classes.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Checkbox from './Checkbox.svelte';

const FOCUS_CLASSES = [
	'peer-focus-visible:outline',
	'peer-focus-visible:outline-2',
	'peer-focus-visible:outline-offset-2',
	'peer-focus-visible:outline-cyan'
];

function paintedBox(input: HTMLElement): HTMLElement {
	const box = input.nextElementSibling;
	if (!(box instanceof HTMLElement)) throw new Error('painted box not found after the input');
	return box;
}

describe('Checkbox — keyboard focus', () => {
	it('is reachable by Tab and toggles with Space', async () => {
		const user = userEvent.setup();
		render(Checkbox, { label: 'Enable WAF' });
		const input = screen.getByRole('checkbox', { name: 'Enable WAF' });

		await user.tab();
		expect(input).toHaveFocus();
		await user.keyboard(' ');
		expect(input).toBeChecked();
	});

	it('paints a focus ring on the visible box when the input has :focus-visible', async () => {
		const user = userEvent.setup();
		render(Checkbox, { label: 'Enable WAF' });
		const input = screen.getByRole('checkbox', { name: 'Enable WAF' });
		const box = paintedBox(input);

		expect(input).toHaveClass('peer');
		for (const cls of FOCUS_CLASSES) expect(box).toHaveClass(cls);
		// The box must come after the input in the same parent, or the
		// `~` combinator behind peer-focus-visible matches nothing.
		expect(box.parentElement).toBe(input.parentElement);
		expect(input.compareDocumentPosition(box) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

		await user.tab();
		expect(input).toHaveFocus();
		// Checking it swaps the fill classes; the focus classes stay.
		await user.keyboard(' ');
		for (const cls of FOCUS_CLASSES) expect(box).toHaveClass(cls);
	});
});
