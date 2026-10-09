<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WafTargetedExclusionsEditor (v2.36) — the "Targeted exclusions"
  list of the route form's WAF section. One readable line per
  exclusion ("Rule 942100 ignores the parameter “content” on
  /api/save"), a remove button, and a small form to add one by
  hand. Most exclusions are created from a WAF event instead
  (WafExcludeDialog). The server validates and canonicalises on
  save; the checks here only give early feedback.
-->
<script lang="ts">
	import type { WafTargetedExclusion } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		WAF_TARGET_VARIABLES,
		isExcludableRule,
		isValidExclusionPath,
		isValidTargetKey,
		parseWafTarget
	} from '$lib/utils/waf-exclusion';

	interface Props {
		value: WafTargetedExclusion[];
		/** The CRS is disabled on the route: exclusions are inert. */
		crsDisabled?: boolean;
	}

	let { value = $bindable(), crsDisabled = false }: Props = $props();

	let ruleInput = $state('');
	let kind = $state<string>('ARGS');
	let name = $state('');
	let path = $state('');
	let prefix = $state(false);
	let error = $state<string | null>(null);

	function describe(e: WafTargetedExclusion): string {
		const target = parseWafTarget(e.target);
		const kindLabel = target ? t(`wafExclude.kind.${target.variable}`) : e.target;
		return t('wafExclude.editor.rowSentence', {
			rule: e.ruleId,
			kind: kindLabel,
			name: target?.key ?? e.target
		});
	}

	function scope(e: WafTargetedExclusion): string {
		if (!e.path) return t('wafExclude.editor.rowAllPaths');
		return t(e.pathPrefix ? 'wafExclude.editor.rowPathPrefix' : 'wafExclude.editor.rowPath', { path: e.path });
	}

	function remove(index: number): void {
		value = value.filter((_, i) => i !== index);
	}

	function add(): void {
		error = null;
		const ruleId = Number(ruleInput.trim());
		if (!isExcludableRule(ruleId)) {
			error = t('wafExclude.editor.errRule');
			return;
		}
		const key = name.trim();
		if (!isValidTargetKey(key)) {
			error = t('wafExclude.editor.errName');
			return;
		}
		const p = path.trim();
		if (p !== '' && !isValidExclusionPath(p)) {
			error = t('wafExclude.editor.errPath');
			return;
		}
		const next: WafTargetedExclusion = { ruleId, target: `${kind}:${key}` };
		if (p !== '') {
			next.path = p;
			if (prefix) next.pathPrefix = true;
		}
		const same = (e: WafTargetedExclusion) =>
			e.ruleId === next.ruleId &&
			e.target.toLowerCase() === next.target.toLowerCase() &&
			(e.path ?? '') === (next.path ?? '') &&
			!!e.pathPrefix === !!next.pathPrefix;
		if (value.some(same)) {
			error = t('wafExclude.editor.errDuplicate');
			return;
		}
		value = [...value, next];
		ruleInput = '';
		name = '';
		path = '';
		prefix = false;
	}
</script>

<div data-testid="waf-targeted-editor">
	<span class="text-sm font-medium text-secondary block mb-1">
		{language.current && t('wafExclude.editor.title')}
	</span>
	<p class="text-xs text-muted mb-2 max-w-prose">{language.current && t('wafExclude.editor.hint')}</p>

	{#if value.length === 0}
		<p class="text-xs text-muted italic" data-testid="waf-targeted-empty">
			{language.current && t('wafExclude.editor.empty')}
		</p>
	{:else}
		<ul class="rows" class:inert={crsDisabled}>
			{#each value as e, i (e.ruleId + e.target + (e.path ?? '') + (e.pathPrefix ? '/*' : ''))}
				<li class="row" data-testid="waf-targeted-row">
					<span class="text-sm text-primary">
						{language.current && describe(e)}
						<span class="text-muted">{language.current && scope(e)}</span>
					</span>
					<button
						type="button"
						class="remove"
						onclick={() => remove(i)}
						aria-label={language.current &&
							t('wafExclude.editor.removeAria', { rule: e.ruleId, name: e.target })}
						data-testid="waf-targeted-remove"
					>
						{language.current && t('wafExclude.editor.remove')}
					</button>
				</li>
			{/each}
		</ul>
	{/if}

	<div class="add-grid mt-2">
		<label class="field">
			<span>{language.current && t('wafExclude.editor.ruleLabel')}</span>
			<input
				type="text"
				inputmode="numeric"
				placeholder="942100"
				bind:value={ruleInput}
				data-testid="waf-targeted-rule"
				class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
			/>
		</label>
		<label class="field">
			<span>{language.current && t('wafExclude.editor.kindLabel')}</span>
			<select
				bind:value={kind}
				data-testid="waf-targeted-kind"
				class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
			>
				{#each WAF_TARGET_VARIABLES as v (v)}
					<option value={v}>{language.current && t(`wafExclude.kind.${v}`)} ({v})</option>
				{/each}
			</select>
		</label>
		<label class="field">
			<span>{language.current && t('wafExclude.editor.nameLabel')}</span>
			<input
				type="text"
				placeholder="content"
				bind:value={name}
				data-testid="waf-targeted-name"
				class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
			/>
		</label>
		<label class="field">
			<span>{language.current && t('wafExclude.editor.pathLabel')}</span>
			<input
				type="text"
				placeholder="/api/save"
				bind:value={path}
				data-testid="waf-targeted-path"
				class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
			/>
		</label>
		<label class="prefix text-xs text-secondary">
			<input type="checkbox" bind:checked={prefix} disabled={path.trim() === ''} data-testid="waf-targeted-prefix" />
			{language.current && t('wafExclude.editor.prefixLabel')}
		</label>
		<button
			type="button"
			class="add-btn"
			onclick={add}
			data-testid="waf-targeted-add"
		>
			{language.current && t('wafExclude.editor.add')}
		</button>
	</div>
	{#if error}
		<p class="text-xs text-down mt-1" role="alert" data-testid="waf-targeted-error">{error}</p>
	{/if}
	{#if crsDisabled}
		<p class="text-xs text-warn mt-1">
			{language.current && t('routes.form.wafExcludeRulesCRSDisabledWarning')}
		</p>
	{/if}
</div>

<style>
	.rows {
		list-style: none;
		margin: 0;
		padding: 0;
		border: 1px solid var(--border-subtle);
		border-radius: 6px;
	}
	.rows.inert {
		opacity: 0.6;
	}
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 6px 10px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.row:last-child {
		border-bottom: none;
	}
	.remove,
	.add-btn {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle);
		padding: 2px 10px;
		border-radius: 4px;
		font-size: 12px;
		cursor: pointer;
		white-space: nowrap;
	}
	.remove:hover {
		color: var(--status-down);
		border-color: var(--status-down);
	}
	.add-btn:hover {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
	}
	.remove:focus-visible,
	.add-btn:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.add-grid {
		display: grid;
		grid-template-columns: 110px minmax(150px, 1fr) minmax(120px, 1fr) minmax(120px, 1fr) auto auto;
		gap: 8px;
		align-items: end;
	}
	@media (max-width: 720px) {
		.add-grid {
			grid-template-columns: 1fr 1fr;
		}
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}
	.field span {
		font-size: 11px;
		color: var(--text-secondary);
	}
	.prefix {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		padding-bottom: 6px;
		white-space: nowrap;
	}
</style>
