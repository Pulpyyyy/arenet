// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Users-page Phase 1 refactor — vitest coverage for the
// /utilisateurs rewrite (commit 2). Pins:
//   - KPI counts derive correctly from a multi-user fixture
//   - Filters (search + role + source) narrow as expected
//   - Online/Actif/Hors-ligne render from lastActivityAt +
//     activeSessionCount thresholds
//   - BREAK-GLASS badge only shows on local admins when
//     OIDC is currently active
//   - Delete confirm dialog → API call → row removed
//   - Self-row Delete button hidden (UX guard)

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { settingsMock, authMock, toastMock, authStoreMock } = vi.hoisted(() => ({
	settingsMock: {
		listAdminUsers: vi.fn(),
		updateUserRole: vi.fn(),
		deleteAdminUser: vi.fn(),
		getOIDCConfig: vi.fn(),
		rotateServiceAccountToken: vi.fn()
	},
	authMock: {
		oidcStatus: vi.fn()
	},
	toastMock: { pushToast: vi.fn() },
	authStoreMock: {
		state: 'authenticated' as 'authenticated' | 'unauthenticated',
		user: { id: 'self-id', role: 'admin' as 'admin' | 'viewer' }
	}
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/toast', () => ({ pushToast: toastMock.pushToast }));
vi.mock('$lib/stores/auth.svelte', () => ({ auth: authStoreMock }));
vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		listAdminUsers: (...a: unknown[]) => settingsMock.listAdminUsers(...a),
		updateUserRole: (...a: unknown[]) => settingsMock.updateUserRole(...a),
		deleteAdminUser: (...a: unknown[]) => settingsMock.deleteAdminUser(...a),
		getOIDCConfig: (...a: unknown[]) => settingsMock.getOIDCConfig(...a),
		rotateServiceAccountToken: (...a: unknown[]) => settingsMock.rotateServiceAccountToken(...a)
	}
}));
vi.mock('$lib/api/auth', () => ({
	authApi: {
		oidcStatus: (...a: unknown[]) => authMock.oidcStatus(...a)
	}
}));

import Page from './+page.svelte';
import type { AdminUser } from '$lib/api/types';

function user(over: Partial<AdminUser> = {}): AdminUser {
	return {
		id: 'u-' + Math.random().toString(36).slice(2, 8),
		username: 'alice',
		displayName: 'Alice',
		email: 'alice@example.test',
		authSource: 'local',
		oidcLinked: false,
		role: 'admin',
		createdAt: '2026-01-01T00:00:00Z',
		updatedAt: '2026-06-01T00:00:00Z',
		activeSessionCount: 0,
		...over
	};
}

const now = Date.now();
function isoMinutesAgo(min: number): string {
	return new Date(now - min * 60_000).toISOString();
}

beforeEach(() => {
	settingsMock.listAdminUsers.mockReset();
	settingsMock.updateUserRole.mockReset();
	settingsMock.deleteAdminUser.mockReset();
	settingsMock.getOIDCConfig.mockReset();
	settingsMock.rotateServiceAccountToken.mockReset();
	authMock.oidcStatus.mockReset();
	toastMock.pushToast.mockReset();
	authStoreMock.state = 'authenticated';
	authStoreMock.user = { id: 'self-id', role: 'admin' };

	settingsMock.getOIDCConfig.mockResolvedValue({
		enabled: false,
		configured: false,
		issuerUrl: '',
		clientId: '',
		clientSecret: '',
		clientSecretSet: false,
		scopes: [],
		redirectUrl: '',
		acceptUnverifiedEmail: false,
		kind: '',
		allowedIdentities: []
	});
	authMock.oidcStatus.mockResolvedValue({ enabled: false });
});

describe('/utilisateurs — KPI strip', () => {
	it('derives total / admins / sso / local counts from users[]', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' }),
			user({ id: 'u2', role: 'admin', authSource: 'oidc' }),
			user({ id: 'u3', role: 'viewer', authSource: 'oidc' }),
			user({ id: 'u4', role: 'viewer', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const strip = screen.getByTestId('users-kpi-strip');
		// Total = 4, Admins = 2, OIDC = 3, Local = 1.
		expect(strip.textContent).toContain('4');
		expect(strip.textContent).toContain('2');
		expect(strip.textContent).toContain('3');
		expect(strip.textContent).toContain('1');
	});
});

describe('/utilisateurs — filters', () => {
	it('search matches username, email, and role substring', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({
				id: 'u1',
				username: 'alice',
				displayName: 'Alice',
				email: 'alice@x.test',
				role: 'admin'
			}),
			user({
				id: 'u2',
				username: 'bob',
				displayName: 'Bob',
				email: 'bob@x.test',
				role: 'viewer'
			})
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1')).toBeTruthy();
		expect(screen.getByTestId('user-row-u2')).toBeTruthy();

		const search = screen.getByLabelText('Filter users');
		await userEvent.type(search, 'alice');
		await tick();

		expect(screen.getByTestId('user-row-u1')).toBeTruthy();
		expect(screen.queryByTestId('user-row-u2')).toBeNull();
	});

	it('role chips narrow to admins / viewers', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin' }),
			user({ id: 'u2', role: 'viewer' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const roleFilter = screen.getByTestId('role-filter');
		await userEvent.click(roleFilter.querySelector('button:nth-child(2)') as HTMLElement);
		await tick();

		expect(screen.getByTestId('user-row-u1')).toBeTruthy();
		expect(screen.queryByTestId('user-row-u2')).toBeNull();
	});

	it('role chips say which one is pressed', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin' }),
			user({ id: 'u2', role: 'viewer' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const chips = Array.from(
			screen.getByTestId('role-filter').querySelectorAll('button')
		);
		expect(chips.map((c) => c.getAttribute('aria-pressed'))).toEqual([
			'true',
			'false',
			'false'
		]);

		await userEvent.click(chips[1]);
		await tick();

		expect(chips.map((c) => c.getAttribute('aria-pressed'))).toEqual([
			'false',
			'true',
			'false'
		]);
	});

	it('source chips narrow to local / oidc', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', authSource: 'local' }),
			user({ id: 'u2', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const sourceFilter = screen.getByTestId('source-filter');
		await userEvent.click(sourceFilter.querySelector('button:nth-child(3)') as HTMLElement);
		await tick();

		expect(screen.queryByTestId('user-row-u1')).toBeNull();
		expect(screen.getByTestId('user-row-u2')).toBeTruthy();
	});
});

describe('/utilisateurs — activity indicator', () => {
	it('renders En ligne when lastActivityAt is recent + sessions exist', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({
				id: 'u1',
				activeSessionCount: 1,
				lastActivityAt: isoMinutesAgo(2)
			})
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const row = screen.getByTestId('user-row-u1');
		expect(row.textContent).toContain('Online');
	});

	it('renders Actif when activity is between 5 and 60 min', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({
				id: 'u1',
				activeSessionCount: 1,
				lastActivityAt: isoMinutesAgo(30)
			})
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1').textContent).toContain('Active');
	});

	it('renders Hors-ligne when no active session', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', activeSessionCount: 0 })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1').textContent).toContain('Offline');
	});
});

describe('/utilisateurs — break-glass badge', () => {
	it('renders BREAK-GLASS on local admin when OIDC is enabled', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('break-glass-badge-u1')).toBeTruthy();
	});

	it('does NOT render BREAK-GLASS when OIDC is disabled', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: false });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('break-glass-badge-u1')).toBeNull();
	});

	it('does NOT render BREAK-GLASS on OIDC admins', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('break-glass-badge-u1')).toBeNull();
	});

	it('does NOT render BREAK-GLASS on viewers', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'viewer', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('break-glass-badge-u1')).toBeNull();
	});
});

describe('/utilisateurs — self-row VOUS badge', () => {
	// Follow-up to 8a1b459 — operator smoke surfaced that
	// without a "VOUS" marker on the acting user's row,
	// admins lose track of which row is theirs when scanning
	// the list. The badge is inline next to the name and
	// uses the same status-info variant as the OIDC source
	// badge so the palette stays consistent.
	it('renders VOUS badge only on the row matching the current user id', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'self-id', username: 'me', displayName: 'Me' }),
			user({ id: 'other-id', username: 'other', displayName: 'Other' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('self-badge-self-id')).toBeTruthy();
		expect(screen.queryByTestId('self-badge-other-id')).toBeNull();
	});
});

describe('/utilisateurs — delete flow', () => {
	it('hides Delete button on self row', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'self-id', username: 'me' }),
			user({ id: 'other-id', username: 'other' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('delete-btn-self-id')).toBeNull();
		expect(screen.getByTestId('delete-btn-other-id')).toBeTruthy();
	});

	it('confirm dialog → API → row removed', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', username: 'alice' }),
			user({ id: 'u2', username: 'bob' })
		]);
		settingsMock.deleteAdminUser.mockResolvedValue(undefined);
		render(Page);
		await tick();
		await tick();
		await tick();

		await userEvent.click(screen.getByTestId('delete-btn-u1'));
		await tick();

		// ConfirmDialog renders a "Delete" confirm button.
		const confirmBtn = screen
			.getAllByRole('button', { name: /^Delete$/ })
			.find((b) => !b.dataset.testid?.startsWith('delete-btn-'));
		expect(confirmBtn).toBeTruthy();
		await userEvent.click(confirmBtn!);
		await tick();
		await tick();

		expect(settingsMock.deleteAdminUser).toHaveBeenCalledWith('u1');
		expect(screen.queryByTestId('user-row-u1')).toBeNull();
		expect(screen.getByTestId('user-row-u2')).toBeTruthy();
	});
});

// --- Role changes: never your own, never the last admin -----------
//
// Demoting yourself, or the last admin, locks the instance out of its
// own administration; the page does not offer either.

describe('/utilisateurs — role change guards', () => {
	async function renderWith(list: AdminUser[]): Promise<void> {
		settingsMock.listAdminUsers.mockResolvedValue(list);
		render(Page);
		await tick();
		await tick();
		await tick();
	}

	it('offers no role button on your own row, and says why', async () => {
		await renderWith([
			user({ id: 'self-id', username: 'me', role: 'admin', authSource: 'local' }),
			user({ id: 'other-id', username: 'other', role: 'admin', authSource: 'local' })
		]);

		expect(screen.queryByTestId('role-btn-self-id')).toBeNull();
		const hint = screen.getByTestId('role-self-hint-self-id');
		expect(hint.getAttribute('title')).toMatch(/your own role/i);
		// Two local admins: the other one can be demoted.
		expect((screen.getByTestId('role-btn-other-id') as HTMLButtonElement).disabled).toBe(false);
	});

	it('disables Demote on the last admin, with the reason', async () => {
		await renderWith([
			user({ id: 'u1', username: 'alice', role: 'admin', authSource: 'local' }),
			user({ id: 'u2', username: 'bob', role: 'viewer', authSource: 'local' }),
			// A service admin cannot sign in here: it does not count.
			user({ id: 'svc-1', username: 'ci', role: 'admin', authSource: 'service' })
		]);

		const demote = screen.getByTestId('role-btn-u1') as HTMLButtonElement;
		expect(demote.disabled).toBe(true);
		expect(demote.getAttribute('aria-describedby')).toBe('role-lock-u1');
		expect(screen.getByTestId('role-lock-hint-u1').textContent).toMatch(/last admin/i);

		await fireEvent.click(demote);
		expect(screen.queryByRole('dialog')).toBeNull();
		expect(settingsMock.updateUserRole).not.toHaveBeenCalled();

		// Promoting a viewer stays possible.
		expect((screen.getByTestId('role-btn-u2') as HTMLButtonElement).disabled).toBe(false);
	});

	it('disables Demote on the last local admin, not on an SSO admin', async () => {
		await renderWith([
			user({ id: 'u1', username: 'alice', role: 'admin', authSource: 'local' }),
			user({ id: 'u2', username: 'bob', role: 'admin', authSource: 'oidc' })
		]);

		expect((screen.getByTestId('role-btn-u1') as HTMLButtonElement).disabled).toBe(true);
		expect(screen.getByTestId('role-lock-hint-u1').textContent).toMatch(/last local admin/i);
		expect((screen.getByTestId('role-btn-u2') as HTMLButtonElement).disabled).toBe(false);
		expect(screen.queryByTestId('role-lock-hint-u2')).toBeNull();
	});
});

describe('/utilisateurs — Phase 2 visual polish', () => {
	it('renders the friendly provider label on the SOURCE column instead of "OIDC"', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true, kind: 'authentik' });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const sourceBadge = screen.getByTestId('source-badge-u1');
		expect(sourceBadge.textContent).toContain('GoAuthentik');
		// Bare "OIDC" must NOT be the badge text — that was the
		// pre-polish placeholder the operator called out.
		expect(sourceBadge.textContent?.trim()).not.toBe('OIDC');
	});

	it('renders "Local" badge unchanged for local accounts', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true, kind: 'authentik' });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('user-row-u1').textContent).toContain('Local');
		expect(screen.queryByTestId('source-badge-u1')).toBeNull();
	});

	it('renders "promu" label next to Admin badge when role=admin && source=oidc', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true, kind: 'authentik' });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('promoted-label-u1').textContent?.trim()).toBe('promoted');
	});

	it('does NOT render "promu" on local admins (break-glass) or OIDC viewers', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true, kind: 'authentik' });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', role: 'admin', authSource: 'local' }),
			user({ id: 'u2', role: 'viewer', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('promoted-label-u1')).toBeNull();
		expect(screen.queryByTestId('promoted-label-u2')).toBeNull();
	});

	it('renders the globe glyph alongside the OIDC provider label', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true, kind: 'authentik' });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', authSource: 'oidc' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('source-globe-u1')).toBeTruthy();
		// Local rows must NOT carry the globe — it's the "external
		// identity" affordance, meaningless for local accounts.
	});

	it('does NOT render the globe glyph on local accounts', async () => {
		authMock.oidcStatus.mockResolvedValue({ enabled: true, kind: 'authentik' });
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', authSource: 'local' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.queryByTestId('source-globe-u1')).toBeNull();
	});

	it('renders action buttons in order: Supprimer then Rétrograder/Promouvoir', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', username: 'other', role: 'admin' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const row = screen.getByTestId('user-row-u1');
		const deleteBtn = screen.getByTestId('delete-btn-u1');
		const roleBtn = screen.getByTestId('role-btn-u1');

		// Both buttons live in the same actions cell; we assert
		// document-order: delete first (left), role second (right).
		// Node.compareDocumentPosition returns FOLLOWING (4) when
		// roleBtn comes after deleteBtn in the DOM.
		expect(row.contains(deleteBtn)).toBe(true);
		expect(row.contains(roleBtn)).toBe(true);
		expect(deleteBtn.compareDocumentPosition(roleBtn) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
	});

	it('renders the SERVICE suffix on service-account source cell', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'svc-1', username: 'ci-deploy', authSource: 'service', role: 'viewer' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('service-suffix-svc-1')).toBeTruthy();
		expect(screen.getByTestId('service-suffix-svc-1').textContent?.trim()).toBe('SERVICE');
		// And NO globe (that's the OIDC marker, not service).
		expect(screen.queryByTestId('source-globe-svc-1')).toBeNull();
	});

	it('renders Rotation + Supprimer actions on service-account rows', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'svc-1', username: 'ci-deploy', authSource: 'service', role: 'viewer' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('rotate-btn-svc-1')).toBeTruthy();
		expect(screen.getByTestId('delete-btn-svc-1')).toBeTruthy();
		// Service accounts can't be promoted/demoted — no role
		// button on these rows.
		expect(screen.queryByTestId('role-btn-svc-1')).toBeNull();
	});

	it('renders the "+ Créer un service account" CTA above the table', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		expect(screen.getByTestId('create-svc-button')).toBeTruthy();
	});

	it('renders the activity state with a StatusDot + label (not a Badge)', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', activeSessionCount: 1, lastActivityAt: isoMinutesAgo(2) })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();

		const cell = screen.getByTestId('activity-state-u1');
		expect(cell.textContent).toContain('Online');
		// StatusDot renders a span with aria-label="Status: up" for
		// the online state — assert the dot is there.
		const dot = cell.querySelector('[aria-label^="Status:"]');
		expect(dot).not.toBeNull();
	});
});

// --- Token rotation: confirm, then a show-once reveal -------------
//
// Rotating revokes the current token at once, so the new one is the
// only working credential: the reveal must not be dismissible, and
// a refused copy (plain HTTP) must still leave a way out.

describe('/utilisateurs — token rotation', () => {
	async function openRotation(): Promise<void> {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'svc-1', username: 'ci-deploy', authSource: 'service', role: 'viewer' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();
		await fireEvent.click(screen.getByTestId('rotate-btn-svc-1'));
	}

	async function rotate(): Promise<void> {
		settingsMock.rotateServiceAccountToken.mockResolvedValue({
			token: 'arn_newtokennewtoken',
			tokenId: 'tok-2'
		});
		await openRotation();
		await fireEvent.click(screen.getByTestId('rotate-confirm-btn'));
		await waitFor(() => expect(screen.getByTestId('rotate-revealed-token')).toBeInTheDocument());
	}

	afterEach(() => {
		delete (navigator as unknown as Record<string, unknown>).clipboard;
		delete (document as unknown as Record<string, unknown>).execCommand;
	});

	it('asks in a labelled dialog, with a danger confirm button', async () => {
		await openRotation();

		expect(screen.getByRole('dialog', { name: /ci-deploy/ })).toBeInTheDocument();
		expect(screen.getByTestId('rotate-confirm-btn').className).toContain('bg-down');
		expect(settingsMock.rotateServiceAccountToken).not.toHaveBeenCalled();
	});

	it('keeps the new token on Escape until it is saved', async () => {
		await rotate();
		expect(settingsMock.rotateServiceAccountToken).toHaveBeenCalledWith('svc-1');

		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(screen.getByTestId('rotate-revealed-token').textContent).toBe('arn_newtokennewtoken');

		const close = screen.getByTestId('rotate-close-btn') as HTMLButtonElement;
		expect(close.disabled).toBe(true);
		await fireEvent.click(screen.getByTestId('rotate-saved-checkbox'));
		expect(close.disabled).toBe(false);
	});

	it('says so in the dialog when the copy fails', async () => {
		await rotate();
		Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
		Object.defineProperty(document, 'execCommand', { value: () => false, configurable: true });

		await fireEvent.click(screen.getByTestId('rotate-copy-btn'));

		expect(await screen.findByTestId('rotate-copy-failed')).toBeInTheDocument();
		expect((screen.getByTestId('rotate-close-btn') as HTMLButtonElement).disabled).toBe(true);
	});
});

// --- v2.41 — the empty state is a way out, not a dead end -------

describe('/utilisateurs — empty state', () => {
	it('explains an over-narrow filter and clears it on demand', async () => {
		settingsMock.listAdminUsers.mockResolvedValue([
			user({ id: 'u1', username: 'alice', role: 'admin' })
		]);
		render(Page);
		await tick();
		await tick();
		await tick();
		expect(screen.getByTestId('user-row-u1')).toBeInTheDocument();

		const search = screen.getByLabelText('Filter users');
		await userEvent.type(search, 'zzzzz');
		await tick();
		expect(screen.getByTestId('users-empty')).toBeInTheDocument();
		expect(screen.getByTestId('users-empty').textContent ?? '').toMatch(/filter/i);

		await userEvent.click(screen.getByText('Clear the filters'));
		await tick();
		expect(screen.getByTestId('user-row-u1')).toBeInTheDocument();
		expect((search as HTMLInputElement).value).toBe('');
	});
});
