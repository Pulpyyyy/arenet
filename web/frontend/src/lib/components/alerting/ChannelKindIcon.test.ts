// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';

import ChannelKindIcon from './ChannelKindIcon.svelte';
import { ALERT_CHANNEL_KINDS } from '$lib/api/alerting';

// v2.54 — the reported gap: Discord had no icon.
//
// The old kindIcon() was a switch over emoji with a "•" default, and
// Discord was never added to it, so the newest channel kind was the one
// that looked unfinished. The test that matters is therefore not "discord
// has an icon" but "no kind falls through to the default" — that is the
// shape of the bug, and it will catch the next kind too.

function paths(container: HTMLElement): string[] {
	return Array.from(container.querySelectorAll('svg path, svg rect, svg circle')).map(
		(el) => el.getAttribute('d') ?? el.tagName.toLowerCase()
	);
}

describe('ChannelKindIcon', () => {
	it('gives every supported channel kind its own mark', () => {
		const seen = new Map<string, string>();

		for (const kind of ALERT_CHANNEL_KINDS) {
			const { container } = render(ChannelKindIcon, { props: { kind } });
			const drawn = paths(container).join('|');

			expect(drawn, `kind "${kind}" drew nothing`).not.toBe('');
			// The fallback is a lone circle. A supported kind reaching it is
			// exactly the Discord bug.
			expect(drawn, `kind "${kind}" fell through to the fallback bullet`).not.toBe('circle');

			for (const [other, otherDrawn] of seen) {
				expect(drawn, `"${kind}" and "${other}" share the same mark`).not.toBe(otherDrawn);
			}
			seen.set(kind, drawn);
		}

		expect(seen.size).toBe(ALERT_CHANNEL_KINDS.length);
	});

	it('draws the Discord brand mark, not an approximation', () => {
		const { container } = render(ChannelKindIcon, { props: { kind: 'discord' } });
		const svg = container.querySelector('svg');

		expect(svg?.getAttribute('fill')).toBe('currentColor');
		// The brand mark's first curve. Checked because a truncated or
		// hand-retyped path renders as visible nonsense rather than failing.
		expect(container.querySelector('path')?.getAttribute('d')).toMatch(/^M20\.317 4\.3698/);
	});

	it('still marks an unknown kind, so the column is never blank', () => {
		const { container } = render(ChannelKindIcon, { props: { kind: 'carrier-pigeon' } });
		expect(container.querySelector('svg circle')).toBeTruthy();
	});

	it('honours the size it is given', () => {
		const { container } = render(ChannelKindIcon, { props: { kind: 'email', size: 24 } });
		expect(container.querySelector('svg')?.getAttribute('width')).toBe('24');
	});
});
