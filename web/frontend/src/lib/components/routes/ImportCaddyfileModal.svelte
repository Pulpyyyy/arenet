<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ImportCaddyfileModal (v2.40) — the "Import a Caddyfile" button of the
  Routes page. Two steps: paste or drop the file and analyse it (the
  server parses it with Caddy's own parser and writes nothing), then
  pick the site blocks to create. Each row shows what would be imported,
  what could not be translated (with its line) and whether a route
  already serves that host — in which case it is skipped unless
  "replace" is ticked.
-->
<script lang="ts">
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { importCaddyfile, previewCaddyfileImport } from '$lib/api/client';
	import type { CaddyfileCandidate, CaddyfilePreview } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	interface Props {
		open: boolean;
		onClose: () => void;
		/** Called after a successful import so the page reloads its list. */
		onImported?: () => void;
	}

	let { open, onClose, onImported }: Props = $props();

	let text = $state('');
	let preview = $state<CaddyfilePreview | null>(null);
	let selected = $state<Record<string, boolean>>({});
	let replace = $state<Record<string, boolean>>({});
	let analysing = $state(false);
	let importing = $state(false);
	let error = $state<string | null>(null);

	// Reset on every open.
	let wasOpen = false;
	$effect(() => {
		if (open && !wasOpen) {
			text = '';
			preview = null;
			selected = {};
			replace = {};
			error = null;
		}
		wasOpen = open;
	});

	const chosen = $derived(
		(preview?.candidates ?? []).filter((c) => c.importable && selected[c.host])
	);

	// A Caddyfile with thirty site blocks meant thirty clicks to take
	// or leave them all. "All" ticks every importable block — a
	// conflicting one is ticked too, and still skipped by the server
	// unless its own "replace" box is ticked as well.
	const importableCount = $derived((preview?.candidates ?? []).filter((c) => c.importable).length);

	function selectAll(on: boolean): void {
		const next: Record<string, boolean> = {};
		for (const c of preview?.candidates ?? []) next[c.host] = on && c.importable;
		selected = next;
		if (!on) replace = {};
	}

	async function analyse(): Promise<void> {
		if (text.trim() === '') return;
		analysing = true;
		error = null;
		try {
			preview = await previewCaddyfileImport(text);
			const next: Record<string, boolean> = {};
			for (const c of preview.candidates) next[c.host] = c.importable && !c.conflict;
			selected = next;
			replace = {};
		} catch (err) {
			preview = null;
			error = err instanceof Error ? err.message : String(err);
		} finally {
			analysing = false;
		}
	}

	async function onFile(event: Event): Promise<void> {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		if (!file) return;
		text = await file.text();
		await analyse();
	}

	async function runImport(): Promise<void> {
		if (chosen.length === 0) return;
		importing = true;
		error = null;
		try {
			const hosts = chosen.map((c) => c.host);
			const res = await importCaddyfile(
				text,
				hosts,
				hosts.filter((h) => replace[h])
			);
			const count = res.created.length + res.replaced.length;
			pushToast(t('importCaddyfile.toastDone', { count }), count > 0 ? 'success' : 'info');
			if (res.skipped.length > 0) {
				pushToast(
					t('importCaddyfile.toastSkipped', {
						list: res.skipped.map((s) => `${s.host} (${s.reason})`).join(', ')
					}),
					'info',
					12000
				);
			}
			onImported?.();
			onClose();
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			importing = false;
		}
	}

	function summary(c: CaddyfileCandidate): string {
		const r = c.route;
		if (!r) return '';
		const parts = [r.upstreams.map((u) => u.url).join(', ')];
		if (r.pathRules && r.pathRules.length > 0) {
			parts.push(t('importCaddyfile.pathRules', { count: r.pathRules.length }));
		}
		return parts.filter(Boolean).join(' · ');
	}
</script>

<Modal {open} title={language.current && t('importCaddyfile.title')} onClose={() => (importing ? undefined : onClose())} width="xl">
	{#snippet children()}
		<div class="import" data-testid="import-caddyfile">
			{#if !preview}
				<p class="hint">{language.current && t('importCaddyfile.hint')}</p>
				<textarea
					bind:value={text}
					rows="12"
					spellcheck="false"
					placeholder={language.current && t('importCaddyfile.placeholder')}
					aria-label={language.current && t('importCaddyfile.title')}
					data-testid="import-text"
					class="bg-surface border border-border-default rounded-md px-2 py-2 text-xs text-primary font-mono"
				></textarea>
				<div class="row">
					<input
						type="file"
						accept=".caddyfile,.conf,.txt,text/plain"
						onchange={(e) => void onFile(e)}
						aria-label={language.current && t('importCaddyfile.file')}
						data-testid="import-file"
						class="text-xs text-secondary"
					/>
				</div>
			{:else}
				{#if preview.globalWarnings.length > 0}
					<ul class="warnings" data-testid="import-global-warnings">
						{#each preview.globalWarnings as w, i (i)}
							<li>{#if w.line > 0}<span class="mono">{language.current && t('importCaddyfile.line', { line: w.line })}</span>{/if} {w.text}</li>
						{/each}
					</ul>
				{/if}
				{#if importableCount > 1}
					<div class="row" data-testid="import-select-bar">
						<span class="sub">
							{language.current && t('importCaddyfile.selectedCount', { count: chosen.length, total: importableCount })}
						</span>
						<Button variant="ghost" size="sm" type="button" onclick={() => selectAll(true)} data-testid="import-select-all">
							{language.current && t('importCaddyfile.selectAll')}
						</Button>
						<Button variant="ghost" size="sm" type="button" onclick={() => selectAll(false)} data-testid="import-select-none">
							{language.current && t('importCaddyfile.selectNone')}
						</Button>
					</div>
				{/if}
				<ul class="rows">
					{#each preview.candidates as c (c.host)}
						<li class="row-item" class:disabled={!c.importable} data-testid="import-candidate">
							<label class="pick">
								<!-- The box sat alone in its label, so a screen
								     reader announced "checkbox, checked" with no
								     word of which site block it takes. -->
								<input
									type="checkbox"
									bind:checked={selected[c.host]}
									disabled={!c.importable}
									aria-label={language.current && t('importCaddyfile.pickLabel', { host: c.host })}
									data-testid="import-pick-{c.host}"
								/>
							</label>
							<div class="info">
								<span class="host">
									{c.host}
									{#if c.aliases.length > 0}<span class="aliases">+ {c.aliases.join(', ')}</span>{/if}
									{#if c.route && !c.route.tlsEnabled}<span class="badge">HTTP</span>{/if}
									{#if c.conflict}<span class="badge warn" data-testid="import-conflict">{language.current && t('importCaddyfile.conflict')}</span>{/if}
								</span>
								{#if c.importable}
									<span class="sub mono">{summary(c)}</span>
								{:else}
									<span class="sub error-text">{c.reason}</span>
								{/if}
								{#if c.conflict && selected[c.host]}
									<label class="replace">
										<input type="checkbox" bind:checked={replace[c.host]} data-testid="import-replace-{c.host}" />
										{language.current && t('importCaddyfile.replace')}
									</label>
								{/if}
								{#if c.warnings.length > 0}
									<details>
										<summary>{language.current && t('importCaddyfile.warnings', { count: c.warnings.length })}</summary>
										<ul class="warnings">
											{#each c.warnings as w, i (i)}
												<li><span class="mono">{language.current && t('importCaddyfile.line', { line: w.line })}</span> {w.text}</li>
											{/each}
										</ul>
									</details>
								{/if}
							</div>
						</li>
					{/each}
				</ul>
			{/if}
			{#if error}
				<p class="error-text" role="alert" data-testid="import-error">{error}</p>
			{/if}
		</div>
	{/snippet}

	{#snippet footer()}
		<Button variant="ghost" type="button" onclick={onClose} disabled={importing}>
			{language.current && t('importCaddyfile.cancel')}
		</Button>
		{#if !preview}
			<Button
				type="button"
				onclick={() => void analyse()}
				disabled={analysing || text.trim() === ''}
				loading={analysing}
				data-testid="import-analyse"
			>
				{language.current && t('importCaddyfile.analyse')}
			</Button>
		{:else}
			<Button variant="ghost" type="button" onclick={() => (preview = null)} disabled={importing}>
				{language.current && t('importCaddyfile.back')}
			</Button>
			<Button
				type="button"
				onclick={() => void runImport()}
				disabled={importing || chosen.length === 0}
				loading={importing}
				data-testid="import-run"
			>
				{language.current && t('importCaddyfile.import', { count: chosen.length })}
			</Button>
		{/if}
	{/snippet}
</Modal>

<style>
	.import {
		display: flex;
		flex-direction: column;
		gap: 10px;
		max-height: 60vh;
		overflow: auto;
	}
	.hint {
		margin: 0;
		font-size: 13px;
		color: var(--text-secondary);
		max-width: 75ch;
	}
	.row {
		display: flex;
		gap: 8px;
		align-items: center;
	}
	.rows {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--border-subtle);
		border-radius: 6px;
	}
	.row-item {
		display: flex;
		gap: 10px;
		padding: 8px 10px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.row-item:last-child {
		border-bottom: none;
	}
	.row-item.disabled {
		opacity: 0.6;
	}
	.info {
		display: flex;
		flex-direction: column;
		gap: 3px;
		min-width: 0;
	}
	.host {
		font-size: 14px;
		color: var(--text-primary);
		font-weight: 600;
	}
	.aliases {
		margin-left: 6px;
		font-size: 12px;
		font-weight: 400;
		color: var(--text-muted);
	}
	.badge {
		margin-left: 6px;
		font-size: 10px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: 1px 5px;
		border-radius: 4px;
		border: 1px solid var(--border-subtle);
		color: var(--text-muted);
	}
	.badge.warn {
		color: var(--status-warn-fg);
		border-color: var(--status-warn);
	}
	.sub {
		font-size: 12px;
		color: var(--text-secondary);
		word-break: break-all;
	}
	.replace {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		font-size: 12px;
		color: var(--status-warn-fg);
	}
	details summary {
		cursor: pointer;
		font-size: 12px;
		color: var(--text-muted);
	}
	.warnings {
		list-style: none;
		margin: 4px 0 0 0;
		padding: 0 0 0 10px;
		border-left: 2px solid var(--border-subtle);
		font-size: 12px;
		color: var(--text-secondary);
	}
	.warnings li {
		padding: 1px 0;
	}
	.mono {
		font-family: var(--font-mono, monospace);
		color: var(--text-muted);
	}
	.error-text {
		margin: 0;
		font-size: 12px;
		color: var(--status-down);
	}
</style>
