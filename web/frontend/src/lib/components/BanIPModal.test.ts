// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step CS.3 Commit D — BanIPModal tests.
//
// Validates form state machine, validation, submit flow,
// error UX, and form reset on re-open. Backend wire shape
// is mocked; lib/api/security.ts createManualBan is the
// seam.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { ManualBanResponse } from '$lib/api/types';
import { ApiError } from '$lib/api/types';

const { toastMock, securityMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	securityMock: {
		createManualBan: vi.fn()
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/security', () => securityMock);

beforeEach(() => {
	toastMock.pushToast.mockReset();
	securityMock.createManualBan.mockReset();
});

import BanIPModal from './BanIPModal.svelte';

function happyResponse(value: string): ManualBanResponse {
	return {
		scenario: `manual:admin|smoke`,
		scope: value.includes('/') ? 'Range' : 'Ip',
		value,
		type: 'ban',
		duration: '24h',
		origin: 'manual',
		expiresAt: new Date(Date.now() + 86400_000).toISOString()
	};
}

describe('BanIPModal — mount + form', () => {
	it('does not render any dialog when open=false', () => {
		render(BanIPModal, {
			props: { open: false, onClose: vi.fn() }
		});
		expect(screen.queryByRole('dialog')).toBeNull();
	});

	it('renders the form with default values when open=true', () => {
		render(BanIPModal, {
			props: { open: true, onClose: vi.fn() }
		});
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		// Default duration is "24h".
		const dur = screen.getByTestId('ban-input-duration') as HTMLSelectElement;
		expect(dur.value).toBe('24h');
		const type = screen.getByTestId('ban-input-type') as HTMLSelectElement;
		expect(type.value).toBe('ban');
	});

	it('reveals the custom duration field only when "custom" is selected', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		expect(screen.queryByTestId('ban-input-custom-duration')).toBeNull();

		const dur = screen.getByTestId('ban-input-duration') as HTMLSelectElement;
		await fireEvent.change(dur, { target: { value: 'custom' } });
		expect(screen.getByTestId('ban-input-custom-duration')).toBeInTheDocument();
	});
});

describe('BanIPModal — mask warning (info-only, non-blocking)', () => {
	it('shows a wide-range warning for IPv4 mask ≥ /16', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '10.0.0.0/16' }
		});
		await waitFor(() => {
			const warn = screen.getByTestId('ban-mask-warn');
			expect(warn.textContent ?? '').toMatch(/You are about to ban/i);
			expect(warn.textContent ?? '').toMatch(/65\.5|65,5|10\^/);
		});
	});

	it('does NOT warn for a /24', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '10.0.0.0/24' }
		});
		// Wait a microtask so the $derived runs.
		await new Promise((r) => setTimeout(r, 0));
		expect(screen.queryByTestId('ban-mask-warn')).toBeNull();
	});

	it('warns for IPv6 mask ≥ /48', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '2001:db8::/48' }
		});
		await waitFor(() => {
			expect(screen.getByTestId('ban-mask-warn')).toBeInTheDocument();
		});
	});

	it('does NOT warn for IPv6 mask /64', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '2001:db8::/64' }
		});
		await new Promise((r) => setTimeout(r, 0));
		expect(screen.queryByTestId('ban-mask-warn')).toBeNull();
	});

	it('does NOT warn for a bare IP', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.42' }
		});
		await new Promise((r) => setTimeout(r, 0));
		expect(screen.queryByTestId('ban-mask-warn')).toBeNull();
	});
});

describe('BanIPModal — client validation', () => {
	it('shows inline error and does NOT call backend when value is empty', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		// Default reason is also empty. Click submit directly.
		await fireEvent.click(screen.getByTestId('ban-submit'));
		await waitFor(() => {
			expect(screen.getByTestId('ban-error').textContent ?? '').toMatch(/IP/i);
		});
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});

	it('shows inline error when reason is empty', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.42' }
		});
		await fireEvent.click(screen.getByTestId('ban-submit'));
		await waitFor(() => {
			expect(screen.getByTestId('ban-error').textContent ?? '').toMatch(/Reason is required/i);
		});
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});

	it('shows inline error when reason exceeds 256 chars', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.42' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'x'.repeat(257) }
		});
		await fireEvent.click(screen.getByTestId('ban-submit'));
		await waitFor(() => {
			expect(screen.getByTestId('ban-error').textContent ?? '').toMatch(/exceeds 256/i);
		});
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});

	it('shows inline error when custom duration is empty but selected', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn() } });
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.42' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'r' }
		});
		const dur = screen.getByTestId('ban-input-duration') as HTMLSelectElement;
		await fireEvent.change(dur, { target: { value: 'custom' } });
		// Custom field left empty.
		await fireEvent.click(screen.getByTestId('ban-submit'));
		await waitFor(() => {
			expect(screen.getByTestId('ban-error').textContent ?? '').toMatch(/Duration is required/i);
		});
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});
});

describe('BanIPModal — submit flow', () => {
	it('POSTs trimmed values + closes + toast + onSuccess on 201', async () => {
		securityMock.createManualBan.mockResolvedValue(happyResponse('203.0.113.42'));
		const onClose = vi.fn();
		const onSuccess = vi.fn();
		render(BanIPModal, {
			props: { open: true, onClose, onSuccess }
		});

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '  203.0.113.42  ' } // padding to verify trim
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: '  smoke test  ' }
		});
		await fireEvent.click(screen.getByTestId('ban-submit'));

		await waitFor(() => {
			expect(securityMock.createManualBan).toHaveBeenCalledWith({
				value: '203.0.113.42',
				duration: '24h',
				type: 'ban',
				reason: 'smoke test'
			});
		});
		await waitFor(() => {
			expect(toastMock.pushToast).toHaveBeenCalledWith(
				expect.stringMatching(/203\.0\.113\.42/),
				'success'
			);
		});
		expect(onClose).toHaveBeenCalledTimes(1);
		expect(onSuccess).toHaveBeenCalledTimes(1);
	});

	it('sends the custom duration string verbatim when "custom" is selected', async () => {
		securityMock.createManualBan.mockResolvedValue(happyResponse('203.0.113.42'));
		render(BanIPModal, {
			props: { open: true, onClose: vi.fn(), onSuccess: vi.fn() }
		});

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.42' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'r' }
		});
		const dur = screen.getByTestId('ban-input-duration') as HTMLSelectElement;
		await fireEvent.change(dur, { target: { value: 'custom' } });
		await fireEvent.input(screen.getByTestId('ban-input-custom-duration'), {
			target: { value: '1h30m' }
		});

		await fireEvent.click(screen.getByTestId('ban-submit'));

		await waitFor(() => {
			expect(securityMock.createManualBan).toHaveBeenCalledWith(
				expect.objectContaining({ duration: '1h30m' })
			);
		});
	});
});

describe('BanIPModal — error UX', () => {
	it('shows inline backend error on 400 + dialog stays open + no toast', async () => {
		securityMock.createManualBan.mockRejectedValue(
			new ApiError('invalid IP "not-an-ip" (expected IPv4, IPv6, or CIDR)', 400)
		);
		const onClose = vi.fn();
		render(BanIPModal, { props: { open: true, onClose, onSuccess: vi.fn() } });

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: 'not-an-ip' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'r' }
		});
		await fireEvent.click(screen.getByTestId('ban-submit'));

		await waitFor(() => {
			expect(screen.getByTestId('ban-error').textContent ?? '').toMatch(/invalid IP/i);
		});
		expect(onClose).not.toHaveBeenCalled();
		expect(toastMock.pushToast).not.toHaveBeenCalled();
	});

	it('shows the "Security Automation not configured" CTA on 412', async () => {
		securityMock.createManualBan.mockRejectedValue(
			new ApiError('security automation not configured', 412)
		);
		const onClose = vi.fn();
		render(BanIPModal, { props: { open: true, onClose, onSuccess: vi.fn() } });

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '1.1.1.1' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'r' }
		});
		await fireEvent.click(screen.getByTestId('ban-submit'));

		await waitFor(() => {
			const cta = screen.getByTestId('ban-not-configured');
			expect(cta.textContent ?? '').toMatch(/Security Automation/i);
		});
		// CTA scrolls directly to the Security Automation
		// section (#R-CS2C-anchor-link — pre-fix landed at
		// top-of-page and forced the operator to scroll).
		const link = screen.getByRole('link', { name: /Security Automation/i });
		expect(link).toHaveAttribute('href', '/settings#security-automation');
		expect(onClose).not.toHaveBeenCalled();
	});

	it('shows the "LAPI unreachable" banner + Retry on 502 + retry works', async () => {
		securityMock.createManualBan
			.mockRejectedValueOnce(new ApiError('connection refused', 502))
			.mockResolvedValueOnce(happyResponse('1.1.1.1'));
		const onClose = vi.fn();
		const onSuccess = vi.fn();
		render(BanIPModal, { props: { open: true, onClose, onSuccess } });

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '1.1.1.1' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'r' }
		});
		await fireEvent.click(screen.getByTestId('ban-submit'));

		await waitFor(() => {
			expect(screen.getByTestId('ban-unreachable')).toBeInTheDocument();
		});
		expect(onClose).not.toHaveBeenCalled();

		// Retry button.
		await fireEvent.click(screen.getByRole('button', { name: /Retry/i }));
		await waitFor(() => {
			expect(securityMock.createManualBan).toHaveBeenCalledTimes(2);
		});
		await waitFor(() => {
			expect(onSuccess).toHaveBeenCalledTimes(1);
			expect(onClose).toHaveBeenCalledTimes(1);
		});
	});
});

describe('BanIPModal — range confirmation', () => {
	async function fill(value: string): Promise<void> {
		await fireEvent.input(screen.getByTestId('ban-input-value'), { target: { value } });
		await fireEvent.input(screen.getByTestId('ban-input-reason'), { target: { value: 'r' } });
	}

	it('a /16 needs a second, deliberate click', async () => {
		securityMock.createManualBan.mockResolvedValue(happyResponse('203.0.0.0/16'));
		const onSuccess = vi.fn();
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess } });
		await fill('203.0.0.0/16');

		await fireEvent.click(screen.getByTestId('ban-submit'));
		const block = await screen.findByTestId('ban-confirm-range');
		expect(block.textContent ?? '').toMatch(/203\.0\.0\.0\/16 covers/);
		expect(screen.getByTestId('ban-submit').textContent ?? '').toMatch(/Confirm ban/);
		expect(securityMock.createManualBan).not.toHaveBeenCalled();

		await fireEvent.click(screen.getByTestId('ban-submit'));
		await waitFor(() => {
			expect(securityMock.createManualBan).toHaveBeenCalledWith(
				expect.objectContaining({ value: '203.0.0.0/16' })
			);
		});
		await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
	});

	it('a private /24 needs confirmation and names the block it touches', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess: vi.fn() } });
		await fill('192.168.1.0/24');

		await fireEvent.click(screen.getByTestId('ban-submit'));
		const block = await screen.findByTestId('ban-confirm-range');
		expect(block.textContent ?? '').toMatch(/192\.168\.0\.0\/16/);
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});

	it('a loopback address needs confirmation', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess: vi.fn() } });
		await fill('127.0.0.1');

		await fireEvent.click(screen.getByTestId('ban-submit'));
		await screen.findByTestId('ban-confirm-range');
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});

	it('a public /24 goes straight through', async () => {
		securityMock.createManualBan.mockResolvedValue(happyResponse('203.0.113.0/24'));
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess: vi.fn() } });
		await fill('203.0.113.0/24');

		await fireEvent.click(screen.getByTestId('ban-submit'));
		await waitFor(() => expect(securityMock.createManualBan).toHaveBeenCalledTimes(1));
		expect(screen.queryByTestId('ban-confirm-range')).toBeNull();
	});

	it('editing the value disarms the confirmation', async () => {
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess: vi.fn() } });
		await fill('10.0.0.0/16');
		await fireEvent.click(screen.getByTestId('ban-submit'));
		await screen.findByTestId('ban-confirm-range');

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '10.1.0.0/16' }
		});
		await waitFor(() => expect(screen.queryByTestId('ban-confirm-range')).toBeNull());

		// The next click re-arms for the new value; still nothing sent.
		await fireEvent.click(screen.getByTestId('ban-submit'));
		await screen.findByTestId('ban-confirm-range');
		expect(securityMock.createManualBan).not.toHaveBeenCalled();
	});
});

describe('BanIPModal — self-ban (409 crowdsec_self_ban)', () => {
	function selfBanError(): ApiError {
		return new ApiError(
			'203.0.113.7 covers your own client IP 203.0.113.7',
			409,
			undefined,
			undefined,
			'crowdsec_self_ban',
			{ value: '203.0.113.7', clientIp: '203.0.113.7' }
		);
	}

	async function submitOwnIP(): Promise<void> {
		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.7' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), { target: { value: 'r' } });
		await fireEvent.click(screen.getByTestId('ban-submit'));
	}

	it('explains the refusal and keeps the dialog open', async () => {
		securityMock.createManualBan.mockRejectedValue(selfBanError());
		const onClose = vi.fn();
		render(BanIPModal, { props: { open: true, onClose, onSuccess: vi.fn() } });
		await submitOwnIP();

		const block = await screen.findByTestId('ban-self-ban');
		expect(block.textContent ?? '').toMatch(/This would ban you/);
		expect(block.textContent ?? '').toMatch(/your own address \(203\.0\.113\.7/);
		expect(onClose).not.toHaveBeenCalled();
		expect(toastMock.pushToast).not.toHaveBeenCalled();
	});

	it('offers the override only after the acknowledgement is ticked', async () => {
		securityMock.createManualBan
			.mockRejectedValueOnce(selfBanError())
			.mockResolvedValueOnce(happyResponse('203.0.113.7'));
		const onSuccess = vi.fn();
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess } });
		await submitOwnIP();

		const override = await screen.findByTestId('ban-self-ban-confirm');
		expect(override).toBeDisabled();
		// The first attempt did not carry the override.
		expect(securityMock.createManualBan.mock.calls[0][0]).not.toHaveProperty('confirmSelfBan');

		await fireEvent.click(screen.getByTestId('ban-self-ban-ack'));
		await waitFor(() => expect(screen.getByTestId('ban-self-ban-confirm')).toBeEnabled());
		await fireEvent.click(screen.getByTestId('ban-self-ban-confirm'));

		await waitFor(() => {
			expect(securityMock.createManualBan).toHaveBeenCalledTimes(2);
		});
		expect(securityMock.createManualBan.mock.calls[1][0]).toEqual(
			expect.objectContaining({ value: '203.0.113.7', confirmSelfBan: true })
		);
		await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
	});

	it('drops the override when the value is edited', async () => {
		securityMock.createManualBan.mockRejectedValue(selfBanError());
		render(BanIPModal, { props: { open: true, onClose: vi.fn(), onSuccess: vi.fn() } });
		await submitOwnIP();
		await screen.findByTestId('ban-self-ban');

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '203.0.113.8' }
		});
		await waitFor(() => expect(screen.queryByTestId('ban-self-ban')).toBeNull());
		expect(screen.queryByTestId('ban-self-ban-confirm')).toBeNull();
	});
});

describe('BanIPModal — form reset on re-open', () => {
	it('clears the form when the parent reopens the modal after a close', async () => {
		const onClose = vi.fn();
		const { rerender } = render(BanIPModal, {
			props: { open: true, onClose, onSuccess: vi.fn() }
		});

		await fireEvent.input(screen.getByTestId('ban-input-value'), {
			target: { value: '1.1.1.1' }
		});
		await fireEvent.input(screen.getByTestId('ban-input-reason'), {
			target: { value: 'stale-typo' }
		});

		// Close.
		await rerender({ open: false, onClose, onSuccess: vi.fn() });
		// Re-open.
		await rerender({ open: true, onClose, onSuccess: vi.fn() });

		await waitFor(() => {
			expect(screen.getByRole('dialog')).toBeInTheDocument();
		});
		const valueInput = screen.getByTestId('ban-input-value') as HTMLInputElement;
		const reasonInput = screen.getByTestId('ban-input-reason') as HTMLInputElement;
		expect(valueInput.value).toBe('');
		expect(reasonInput.value).toBe('');
	});
});
