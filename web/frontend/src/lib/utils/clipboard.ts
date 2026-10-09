// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Copying that still works where the console is served over plain
// HTTP — the common homelab case. `navigator.clipboard` only exists in
// a secure context, so there it is undefined and the old
// execCommand('copy') path is the only one left.

/**
 * Copies `text`, trying the async Clipboard API first and falling back
 * to a hidden textarea + `document.execCommand('copy')` when the API is
 * missing or refuses. Resolves to whether either path reported success.
 *
 * When both fail and `selectOnFailure` is given, its text is selected so
 * the operator only has to press Ctrl+C.
 */
export async function copyText(text: string, selectOnFailure?: HTMLElement | null): Promise<boolean> {
	try {
		if (navigator.clipboard?.writeText) {
			await navigator.clipboard.writeText(text);
			return true;
		}
	} catch {
		// Permission refused, or a browser that ships the API but blocks
		// it here: the legacy path below may still work.
	}
	if (legacyCopy(text)) return true;
	if (selectOnFailure) selectContents(selectOnFailure);
	return false;
}

function legacyCopy(text: string): boolean {
	if (typeof document.execCommand !== 'function') return false;
	const previousFocus = document.activeElement as HTMLElement | null;
	const area = document.createElement('textarea');
	area.value = text;
	area.setAttribute('readonly', '');
	// Off-screen but still selectable; fixed so the page does not jump.
	area.style.position = 'fixed';
	area.style.top = '0';
	area.style.left = '0';
	area.style.opacity = '0';
	document.body.appendChild(area);
	try {
		// execCommand copies the active selection, which needs focus.
		area.focus();
		area.select();
		return document.execCommand('copy');
	} catch {
		return false;
	} finally {
		area.remove();
		// Focus left for the textarea; inside a modal it must come back
		// to the button that was pressed.
		previousFocus?.focus();
	}
}

/** Selects every character inside `el`, for a manual Ctrl+C. */
function selectContents(el: HTMLElement): void {
	const selection = window.getSelection();
	if (!selection) return;
	const range = document.createRange();
	range.selectNodeContents(el);
	selection.removeAllRanges();
	selection.addRange(range);
}
