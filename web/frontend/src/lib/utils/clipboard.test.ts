// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// copyText must still copy on a plain-HTTP console, where
// navigator.clipboard does not exist — the homelab default — and must
// say so honestly when nothing worked.

import { describe, it, expect, vi, afterEach } from 'vitest';
import { copyText } from './clipboard';

function setClipboard(value: unknown) {
	Object.defineProperty(navigator, 'clipboard', { value, configurable: true, writable: true });
}

function setExecCommand(impl: (command: string) => boolean) {
	const spy = vi.fn(impl);
	Object.defineProperty(document, 'execCommand', { value: spy, configurable: true, writable: true });
	return spy;
}

afterEach(() => {
	// Own properties shadow whatever jsdom ships on the prototypes.
	delete (navigator as unknown as Record<string, unknown>).clipboard;
	delete (document as unknown as Record<string, unknown>).execCommand;
	window.getSelection()?.removeAllRanges();
	document.body.innerHTML = '';
});

describe('copyText', () => {
	it('uses the Clipboard API when it is there', async () => {
		const writeText = vi.fn().mockResolvedValue(undefined);
		setClipboard({ writeText });
		const exec = setExecCommand(() => true);

		await expect(copyText('s3cret')).resolves.toBe(true);
		expect(writeText).toHaveBeenCalledWith('s3cret');
		expect(exec).not.toHaveBeenCalled();
	});

	it('falls back to execCommand when navigator.clipboard is undefined (plain HTTP)', async () => {
		setClipboard(undefined);
		let copiedValue = '';
		const exec = setExecCommand(() => {
			// What the browser would copy: the selected textarea's value.
			copiedValue = (document.activeElement as HTMLTextAreaElement).value;
			return true;
		});

		await expect(copyText('s3cret')).resolves.toBe(true);
		expect(exec).toHaveBeenCalledWith('copy');
		expect(copiedValue).toBe('s3cret');
		// The helper textarea does not linger in the page.
		expect(document.querySelector('textarea')).toBeNull();
	});

	it('falls back to execCommand when the Clipboard API refuses', async () => {
		setClipboard({ writeText: vi.fn().mockRejectedValue(new Error('NotAllowedError')) });
		const exec = setExecCommand(() => true);

		await expect(copyText('s3cret')).resolves.toBe(true);
		expect(exec).toHaveBeenCalledWith('copy');
	});

	it('gives focus back to the element that had it', async () => {
		setClipboard(undefined);
		setExecCommand(() => true);
		const button = document.createElement('button');
		document.body.appendChild(button);
		button.focus();

		await copyText('s3cret');
		expect(document.activeElement).toBe(button);
	});

	it('reports failure and selects the shown text for a manual copy', async () => {
		setClipboard(undefined);
		setExecCommand(() => false);
		const shown = document.createElement('pre');
		shown.textContent = 's3cret';
		document.body.appendChild(shown);

		await expect(copyText('s3cret', shown)).resolves.toBe(false);
		const selection = window.getSelection();
		expect(selection?.rangeCount).toBe(1);
		expect(selection?.getRangeAt(0).toString()).toBe('s3cret');
	});

	it('reports failure when execCommand is missing too', async () => {
		setClipboard(undefined);
		Object.defineProperty(document, 'execCommand', { value: undefined, configurable: true, writable: true });

		await expect(copyText('s3cret')).resolves.toBe(false);
	});
});
