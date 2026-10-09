// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.41 — the shared empty-state surface. Half the pages had a real
// explanatory empty state and half had a one-liner or nothing; this
// is the one shape they now share.

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import EmptyState from './EmptyState.svelte';

describe('EmptyState', () => {
	it('states what is empty and why', () => {
		render(EmptyState, {
			props: { title: 'Nothing recorded yet', body: 'Changes land here.', testid: 'es' }
		});
		expect(screen.getByText('Nothing recorded yet')).toBeInTheDocument();
		expect(screen.getByText('Changes land here.')).toBeInTheDocument();
		expect(screen.getByTestId('es').getAttribute('data-tone')).toBe('neutral');
	});

	it('offers a way out as a link', () => {
		render(EmptyState, {
			props: { title: 'Nothing to draw', actionLabel: 'Create a route', actionHref: '/routes' }
		});
		const link = screen.getByText('Create a route') as HTMLAnchorElement;
		expect(link.tagName).toBe('A');
		expect(link.getAttribute('href')).toBe('/routes');
	});

	it('offers a way out as an action', async () => {
		const onAction = vi.fn();
		render(EmptyState, {
			props: { title: 'No match', tone: 'filter', actionLabel: 'Clear the filters', onAction }
		});
		await fireEvent.click(screen.getByText('Clear the filters'));
		expect(onAction).toHaveBeenCalledTimes(1);
	});

	it('offers a second way out beside the first', async () => {
		const onAction = vi.fn();
		const onSecondaryAction = vi.fn();
		render(EmptyState, {
			props: {
				title: 'No routes yet',
				actionLabel: 'Add a route',
				onAction,
				secondaryActionLabel: 'Import a Caddyfile',
				onSecondaryAction
			}
		});
		await fireEvent.click(screen.getByRole('button', { name: 'Import a Caddyfile' }));
		expect(onSecondaryAction).toHaveBeenCalledTimes(1);
		expect(onAction).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByRole('button', { name: 'Add a route' }));
		expect(onAction).toHaveBeenCalledTimes(1);
	});

	it('renders no action when only a label is given', () => {
		render(EmptyState, { props: { title: 'No match', actionLabel: 'Clear' } });
		expect(screen.queryByText('Clear')).toBeNull();
	});
});
