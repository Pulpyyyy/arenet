<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PemFileButton — "Load from file…" next to a PEM textarea.

  CAs hand certificates and keys out as files (.pem / .crt / .cer /
  .key); copying them into a textarea by hand is where the BEGIN line
  or the last dashes get lost. This reads the picked file as text and
  hands it to `onLoad`, which fills the field. The file never leaves the
  browser until the operator submits the form.

  A file without any "-----BEGIN " line is refused with a hint: a
  binary DER .cer read as text would only produce garbage in the field.
-->
<script lang="ts">
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	// A PEM certificate, chain or key is a few KiB. Anything past this
	// is not one, and dumping it into a textarea would freeze the page.
	const MAX_PEM_FILE_BYTES = 1_048_576;
	const PEM_ACCEPT = '.pem,.crt,.cer,.key';
	const PEM_BEGIN_MARKER = '-----BEGIN ';

	interface Props {
		/** Visible label of the field the file fills (for the aria-label). */
		fieldLabel: string;
		/** Receives the file's text once read and checked. */
		onLoad: (text: string) => void;
		disabled?: boolean;
		/** data-testid of the button; the hidden input gets `<testId>-input`. */
		testId: string;
	}

	let { fieldLabel, onLoad, disabled = false, testId }: Props = $props();

	let input = $state<HTMLInputElement | null>(null);
	let error = $state<string | null>(null);

	async function handleChange(e: Event): Promise<void> {
		const el = e.currentTarget as HTMLInputElement;
		const file = el.files && el.files.length > 0 ? el.files[0] : null;
		if (!file) return;
		error = null;
		try {
			if (file.size > MAX_PEM_FILE_BYTES) {
				error = t('certificates.external.upload.file.tooLarge', { name: file.name });
				return;
			}
			let text: string;
			try {
				text = await file.text();
			} catch {
				error = t('certificates.external.upload.file.readFailed', { name: file.name });
				return;
			}
			if (!text.includes(PEM_BEGIN_MARKER)) {
				error = t('certificates.external.upload.file.notPem', { name: file.name });
				return;
			}
			onLoad(text.trim());
		} finally {
			// Clear the selection so picking the same file again (after
			// editing the field) still fires a change event.
			el.value = '';
		}
	}
</script>

<div class="pem-file">
	<input
		bind:this={input}
		type="file"
		accept={PEM_ACCEPT}
		class="visually-hidden"
		tabindex="-1"
		aria-hidden="true"
		{disabled}
		data-testid={`${testId}-input`}
		onchange={(e) => void handleChange(e)}
	/>
	<button
		type="button"
		class="pem-file-btn"
		{disabled}
		aria-label={language.current &&
			t('certificates.external.upload.file.buttonAria', { field: fieldLabel })}
		data-testid={testId}
		onclick={() => input?.click()}
	>
		{language.current && t('certificates.external.upload.file.button')}
	</button>
	{#if error}
		<span class="pem-file-error" role="alert" data-testid={`${testId}-error`}>{error}</span>
	{/if}
</div>

<style>
	.pem-file {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: 8px;
		margin-top: 6px;
	}
	.pem-file-btn {
		appearance: none;
		background: transparent;
		border: 1px solid var(--border);
		color: var(--fg-muted);
		font-size: 11px;
		font-family: inherit;
		padding: 4px 10px;
		border-radius: var(--radius-sm);
		cursor: pointer;
	}
	.pem-file-btn:hover:not(:disabled) {
		color: var(--accent);
		border-color: var(--accent);
	}
	.pem-file-btn:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}
	.pem-file-btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.pem-file-error {
		color: var(--status-down);
		font-size: 11.5px;
	}
	.visually-hidden {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip: rect(0, 0, 0, 0);
		white-space: nowrap;
		border: 0;
	}
</style>
