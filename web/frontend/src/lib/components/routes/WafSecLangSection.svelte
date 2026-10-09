<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WafSecLangSection (v2.38) — "SecLang (advanced)" in the route form's
  WAF section, collapsed unless the route already has SecLang:
  - the editor (highlighting, completion, live server check with the
    problems on their line — debounced);
  - commented templates, inserted with the next free rule ID;
  - the request tester: a sample request runs through a WAF built
    like the route's, using the unsaved draft (no traffic).
  Saved with the route; the server re-checks on save.
-->
<script lang="ts">
	import SecLangEditor from './SecLangEditor.svelte';
	import { testRouteWaf, validateSecLang } from '$lib/api/client';
	import type { SecLangError, WafTestResponse } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { SECLANG_TEMPLATE_KEYS, secLangTemplate, type SecLangTemplateKey } from '$lib/utils/seclang-templates';

	interface Props {
		value: string;
		/** Saved route id; the tester needs one. */
		routeId?: string | null;
		wafMode?: string;
		/** Problems from a refused save, shown until the next check. */
		saveErrors?: SecLangError[];
	}

	let { value = $bindable(''), routeId = null, wafMode = 'detect', saveErrors = [] }: Props = $props();

	const CHECK_DEBOUNCE_MS = 600;

	let editor: SecLangEditor | undefined = $state();
	let errors = $state<SecLangError[]>([]);
	let checked = $state(false);
	let checking = $state(false);
	let template = $state<SecLangTemplateKey>('jsonOnly');

	$effect(() => {
		if (saveErrors.length > 0) errors = saveErrors;
	});

	// Live check, debounced.
	let timer: ReturnType<typeof setTimeout> | undefined;
	$effect(() => {
		const text = value;
		clearTimeout(timer);
		if (text.trim() === '') {
			errors = [];
			checked = false;
			return;
		}
		timer = setTimeout(async () => {
			checking = true;
			try {
				const res = await validateSecLang(text);
				if (text === value) {
					errors = res.errors;
					checked = true;
				}
			} catch {
				// Network hiccup: keep the previous state; the save re-checks.
			} finally {
				checking = false;
			}
		}, CHECK_DEBOUNCE_MS);
		return () => clearTimeout(timer);
	});

	async function insertTemplate(): Promise<void> {
		let next = 130000;
		try {
			next = (await validateSecLang(value)).nextId;
		} catch {
			// keep the default; the check will flag a clash
		}
		const text = secLangTemplate(template, language.current, next);
		const prefix = value.trim() === '' ? '' : value.endsWith('\n') ? '\n' : '\n\n';
		editor?.insertAtCursor(prefix + text);
	}

	// --- Tester ---------------------------------------------------------
	let testMethod = $state('GET');
	let testPath = $state('/');
	let testHeaders = $state('User-Agent: Mozilla/5.0\nAccept: text/html');
	let testBody = $state('');
	let testing = $state(false);
	let testError = $state<string | null>(null);
	let result = $state<WafTestResponse | null>(null);

	function parseHeaders(text: string): { name: string; value: string }[] {
		return text
			.split('\n')
			.map((l) => l.trim())
			.filter((l) => l.includes(':'))
			.map((l) => {
				const i = l.indexOf(':');
				return { name: l.slice(0, i).trim(), value: l.slice(i + 1).trim() };
			});
	}

	async function runTest(): Promise<void> {
		if (!routeId) return;
		testing = true;
		testError = null;
		try {
			result = await testRouteWaf(routeId, {
				method: testMethod,
				path: testPath.trim() || '/',
				headers: parseHeaders(testHeaders),
				body: testBody,
				seclang: value
			});
		} catch (err) {
			result = null;
			testError = err instanceof Error ? err.message : String(err);
		} finally {
			testing = false;
		}
	}

	const blockerMsg = $derived(result?.blocked ? (result.matches.find((m) => m.id === result!.blockedBy)?.msg ?? '') : '');
</script>

<details class="seclang" open={value.trim() !== ''} data-testid="waf-seclang-section">
	<summary class="text-sm font-medium text-secondary">{language.current && t('wafSecLang.title')}</summary>
	<p class="text-xs text-muted max-w-prose">{language.current && t('wafSecLang.hint')}</p>

	<div class="toolbar">
		<label class="text-xs text-secondary" for="seclang-template">{language.current && t('wafSecLang.templateLabel')}</label>
		<select
			id="seclang-template"
			bind:value={template}
			data-testid="seclang-template"
			class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
		>
			{#each SECLANG_TEMPLATE_KEYS as key (key)}
				<option value={key}>{language.current && t(`wafSecLang.templates.${key}`)}</option>
			{/each}
		</select>
		<button type="button" class="btn" onclick={() => void insertTemplate()} data-testid="seclang-insert-template">
			{language.current && t('wafSecLang.insert')}
		</button>
	</div>

	<SecLangEditor bind:this={editor} bind:value label={language.current && t('wafSecLang.editorLabel')} {errors} />

	<p class="status text-xs" data-testid="seclang-status" aria-live="polite">
		{#if checking}
			<span class="text-muted">{language.current && t('wafSecLang.checking')}</span>
		{:else if errors.length > 0}
			<span class="text-down">{language.current && t('wafSecLang.problems', { count: errors.length })}</span>
		{:else if checked}
			<span class="text-up">{language.current && t('wafSecLang.valid')}</span>
		{/if}
	</p>
	{#if errors.length > 0}
		<ul class="problems" data-testid="seclang-problems">
			{#each errors as e, i (i)}
				<li class="text-xs"><span class="mono">{language.current && t('wafSecLang.line', { line: e.line })}</span> {e.message}</li>
			{/each}
		</ul>
	{/if}

	<div class="tester" data-testid="waf-tester">
		<span class="text-xs font-medium text-secondary">{language.current && t('wafSecLang.tester.title')}</span>
		{#if !routeId}
			<p class="text-xs text-muted">{language.current && t('wafSecLang.tester.saveFirst')}</p>
		{:else}
			<div class="tester-row">
				<select
					bind:value={testMethod}
					aria-label={language.current && t('wafSecLang.tester.method')}
					data-testid="tester-method"
					class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
				>
					{#each ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as m (m)}
						<option value={m}>{m}</option>
					{/each}
				</select>
				<input
					type="text"
					bind:value={testPath}
					aria-label={language.current && t('wafSecLang.tester.path')}
					placeholder="/api/save?q=1"
					data-testid="tester-path"
					class="grow bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
				/>
				<button type="button" class="btn primary" onclick={() => void runTest()} disabled={testing} data-testid="tester-run">
					{language.current && t('wafSecLang.tester.run')}
				</button>
			</div>
			<div class="tester-row">
				<textarea
					bind:value={testHeaders}
					rows="3"
					aria-label={language.current && t('wafSecLang.tester.headers')}
					placeholder={language.current && t('wafSecLang.tester.headers')}
					data-testid="tester-headers"
					class="grow bg-surface border border-border-default rounded-md px-2 py-1 text-xs text-primary font-mono"
				></textarea>
				<textarea
					bind:value={testBody}
					rows="3"
					aria-label={language.current && t('wafSecLang.tester.body')}
					placeholder={language.current && t('wafSecLang.tester.body')}
					data-testid="tester-body"
					class="grow bg-surface border border-border-default rounded-md px-2 py-1 text-xs text-primary font-mono"
				></textarea>
			</div>
			{#if testError}
				<p class="text-xs text-down" role="alert" data-testid="tester-error">{testError}</p>
			{/if}
			{#if result}
				<div class="result" class:blocked={result.blocked} data-testid="tester-result">
					<strong>
						{#if result.blocked}
							{language.current &&
								t('wafSecLang.tester.blocked', { status: result.status ?? 403, rule: result.blockedBy ?? 0, msg: blockerMsg })}
						{:else}
							{language.current && t('wafSecLang.tester.accepted')}
						{/if}
					</strong>
					{#if result.blocked && result.mode !== 'block'}
						<span class="text-xs text-warn">{language.current && t(`wafSecLang.tester.mode.${result.mode}`)}</span>
					{/if}
					{#if result.matches.length > 0}
						<ul>
							{#each result.matches as m (m.id)}
								<li class="text-xs"><span class="mono">{m.id}</span> {m.msg}{#if m.data}<span class="text-muted"> — {m.data}</span>{/if}</li>
							{/each}
						</ul>
					{:else}
						<p class="text-xs text-muted">{language.current && t('wafSecLang.tester.noMatch')}</p>
					{/if}
				</div>
			{/if}
		{/if}
	</div>
	{#if wafMode === 'off'}
		<p class="text-xs text-warn">{language.current && t('wafRules.wafOff')}</p>
	{/if}
</details>

<style>
	.seclang {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.seclang > :global(*) + :global(*) {
		margin-top: 8px;
	}
	summary {
		cursor: pointer;
	}
	.toolbar,
	.tester-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 6px;
	}
	.grow {
		flex: 1;
		min-width: 160px;
	}
	.btn {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle);
		padding: 2px 10px;
		border-radius: 4px;
		font-size: 12px;
		cursor: pointer;
		white-space: nowrap;
	}
	.btn:hover,
	.btn.primary {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
	}
	.btn:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.status {
		margin: 0;
		min-height: 1em;
	}
	.problems {
		margin: 0;
		padding-left: 1rem;
		color: var(--status-down);
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.tester {
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 10px;
		border: 1px solid var(--border-subtle);
		border-radius: 6px;
	}
	.result {
		padding: 8px 10px;
		border-radius: 4px;
		border-left: 3px solid var(--status-up);
		background: var(--bg-surface);
		font-size: 13px;
	}
	.result.blocked {
		border-left-color: var(--status-down);
	}
	.result ul {
		margin: 6px 0 0 0;
		padding-left: 1rem;
	}
</style>
