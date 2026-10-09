<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  WafCustomRulesEditor (v2.37) — "Custom rules" of the route form's
  WAF section. Each rule is shown as one sentence ("Block when the
  method is POST and the path begins with /login"), with an on/off
  switch, edit and delete. The inline editor builds a rule from
  criteria (path, method, User-Agent, header) that must ALL match;
  each criterion accepts several values (any of them). Presets
  prefill the editor. Rules are saved with the route; the server
  validates and allocates the rule IDs.
-->
<script lang="ts">
	import type { WafCustomRule, WafRuleCondition } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		FIELDS,
		MAX_CONDITIONS,
		OPERATORS_BY_FIELD,
		describeRule,
		newCondition,
		parseValues,
		preset,
		ruleError,
		takesValues,
		type PresetKey
	} from '$lib/utils/waf-custom-rule';

	interface Props {
		value: WafCustomRule[];
		/** Route WAF mode; rules do nothing when "off". */
		wafMode?: string;
		/** v2.38 — "→ SecLang": convert rule `index` (parent handles it). */
		onConvert?: (index: number) => void;
		/**
		 * Out: a rule is open in the editor and not yet confirmed with
		 * OK. The draft is not in `value` until then, so the parent
		 * treats it as unsaved work and refuses to save over it.
		 */
		editing?: boolean;
	}

	let {
		value = $bindable(),
		wafMode = 'detect',
		onConvert,
		editing = $bindable(false)
	}: Props = $props();

	// Editor state: index of the rule being edited (-1 = new rule),
	// the draft, and one textarea string per condition.
	interface Draft {
		index: number;
		id: number;
		name: string;
		disabled: boolean;
		conditions: WafRuleCondition[];
		valuesText: string[];
	}
	let draft = $state<Draft | null>(null);
	let error = $state<string | null>(null);

	$effect(() => {
		editing = draft !== null;
	});

	function open(rule: WafCustomRule, index: number): void {
		const conditions = rule.conditions.map((c) => ({ ...c, values: [...(c.values ?? [])] }));
		draft = {
			index,
			id: rule.id,
			name: rule.name,
			disabled: !!rule.disabled,
			conditions,
			valuesText: conditions.map((c) => (c.values ?? []).join('\n'))
		};
		error = null;
	}

	function addRule(): void {
		open({ id: 0, name: '', conditions: [newCondition('path')] }, -1);
	}

	function addPreset(key: PresetKey): void {
		open(preset(key), -1);
	}

	function draftRule(d: Draft): WafCustomRule {
		const conditions = d.conditions.map((c, i) => {
			const out: WafRuleCondition = { field: c.field, operator: c.operator };
			if (c.field === 'header') out.header = (c.header ?? '').trim();
			if (takesValues(c.operator)) out.values = parseValues(d.valuesText[i], c.field);
			return out;
		});
		const rule: WafCustomRule = { id: d.id, name: d.name.trim(), conditions };
		if (d.disabled) rule.disabled = true;
		return rule;
	}

	const preview = $derived(draft ? describeRule(draftRule(draft)) : '');

	function commit(): void {
		if (!draft) return;
		const rule = draftRule(draft);
		const key = ruleError(rule);
		if (key) {
			error = t(key);
			return;
		}
		value = draft.index < 0 ? [...value, rule] : value.map((r, i) => (i === draft!.index ? rule : r));
		draft = null;
	}

	function setField(i: number, field: WafRuleCondition['field']): void {
		if (!draft) return;
		draft.conditions[i] = newCondition(field);
		draft.valuesText[i] = '';
	}

	function addCondition(): void {
		if (!draft || draft.conditions.length >= MAX_CONDITIONS) return;
		draft.conditions.push(newCondition('path'));
		draft.valuesText.push('');
	}

	function removeCondition(i: number): void {
		if (!draft) return;
		draft.conditions.splice(i, 1);
		draft.valuesText.splice(i, 1);
	}

	function toggle(index: number): void {
		value = value.map((r, i) => (i === index ? { ...r, disabled: !r.disabled || undefined } : r));
	}

	function remove(index: number): void {
		value = value.filter((_, i) => i !== index);
		if (draft && draft.index === index) draft = null;
	}
</script>

<div data-testid="waf-rules-editor">
	<span class="text-sm font-medium text-secondary block mb-1">
		{language.current && t('wafRules.title')}
	</span>
	<p class="text-xs text-muted mb-2 max-w-prose">{language.current && t('wafRules.hint')}</p>
	{#if wafMode === 'off'}
		<p class="text-xs text-status-warn mb-2" data-testid="waf-rules-off">{language.current && t('wafRules.wafOff')}</p>
	{/if}

	{#if value.length === 0}
		<p class="text-xs text-muted italic" data-testid="waf-rules-empty">{language.current && t('wafRules.empty')}</p>
	{:else}
		<ul class="rules">
			{#each value as rule, i (rule.id || `new-${i}`)}
				<li class="rule" class:off={rule.disabled} data-testid="waf-rule-row">
					<label class="switch" title={language.current && t('wafRules.enabledAria', { name: rule.name })}>
						<input
							type="checkbox"
							checked={!rule.disabled}
							onchange={() => toggle(i)}
							aria-label={language.current && t('wafRules.enabledAria', { name: rule.name })}
							data-testid="waf-rule-toggle"
						/>
					</label>
					<div class="rule-text">
						<span class="text-sm text-primary font-medium">
							{rule.name}
							{#if rule.disabled}<span class="badge">{language.current && t('wafRules.disabledBadge')}</span>{/if}
						</span>
						<span class="text-xs text-secondary" data-testid="waf-rule-sentence">
							{language.current && describeRule(rule)}
						</span>
					</div>
					<div class="rule-actions">
						<button
							type="button"
							class="btn"
							onclick={() => open(rule, i)}
							aria-label={language.current && t('wafRules.editAria', { name: rule.name })}
							data-testid="waf-rule-edit">{language.current && t('wafRules.edit')}</button
						>
						{#if onConvert}
							<button
								type="button"
								class="btn"
								onclick={() => onConvert(i)}
								aria-label={language.current && t('wafSecLang.convertAria', { name: rule.name })}
								data-testid="waf-rule-convert">{language.current && t('wafSecLang.convert')}</button
							>
						{/if}
						<button
							type="button"
							class="btn danger"
							onclick={() => remove(i)}
							aria-label={language.current && t('wafRules.deleteAria', { name: rule.name })}
							data-testid="waf-rule-delete">{language.current && t('wafRules.delete')}</button
						>
					</div>
				</li>
			{/each}
		</ul>
	{/if}

	{#if draft}
		<div class="editor" data-testid="waf-rule-draft">
			<label class="field">
				<span>{language.current && t('wafRules.nameLabel')}</span>
				<input
					type="text"
					bind:value={draft.name}
					placeholder={language.current && t('wafRules.namePlaceholder')}
					maxlength="64"
					data-testid="waf-rule-name"
					class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
				/>
			</label>
			<span class="text-xs font-medium text-secondary">{language.current && t('wafRules.conditionsLabel')}</span>
			{#each draft.conditions as c, i (i)}
				<div class="condition" data-testid="waf-rule-condition">
					<select
						value={c.field}
						onchange={(e) => setField(i, (e.currentTarget as HTMLSelectElement).value as WafRuleCondition['field'])}
						aria-label={language.current && t('wafRules.fieldLabel')}
						data-testid="waf-rule-field"
						class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
					>
						{#each FIELDS as f (f)}
							<option value={f}>{language.current && t(`wafRules.fields.${f}`)}</option>
						{/each}
					</select>
					{#if c.field === 'header'}
						<input
							type="text"
							bind:value={c.header}
							placeholder="X-Api-Key"
							aria-label={language.current && t('wafRules.headerLabel')}
							data-testid="waf-rule-header"
							class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
						/>
					{/if}
					<select
						bind:value={c.operator}
						aria-label={language.current && t('wafRules.operatorLabel')}
						data-testid="waf-rule-operator"
						class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
					>
						{#each OPERATORS_BY_FIELD[c.field] as op (op)}
							<option value={op}>{language.current && t(`wafRules.operators.${op}`)}</option>
						{/each}
					</select>
					{#if takesValues(c.operator)}
						<textarea
							bind:value={draft.valuesText[i]}
							rows="2"
							aria-label={language.current && t('wafRules.valuesLabel')}
							placeholder={language.current && t('wafRules.valuesLabel')}
							data-testid="waf-rule-values"
							class="values bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
						></textarea>
					{/if}
					{#if draft.conditions.length > 1}
						<button
							type="button"
							class="btn"
							onclick={() => removeCondition(i)}
							aria-label={language.current && t('wafRules.removeCondition')}
							data-testid="waf-rule-remove-condition">×</button
						>
					{/if}
				</div>
			{/each}
			{#if draft.conditions.length < MAX_CONDITIONS}
				<button type="button" class="link" onclick={addCondition} data-testid="waf-rule-add-condition">
					{language.current && t('wafRules.addCondition')}
				</button>
			{/if}
			<p class="preview text-sm" data-testid="waf-rule-preview">
				<span class="text-muted">{language.current && t('wafRules.preview')} :</span>
				{language.current && preview}
			</p>
			{#if error}
				<p class="text-xs text-status-down" role="alert" data-testid="waf-rule-error">{error}</p>
			{/if}
			<div class="editor-actions">
				<button type="button" class="btn" onclick={() => (draft = null)} data-testid="waf-rule-cancel">
					{language.current && t('wafRules.cancel')}
				</button>
				<button type="button" class="btn primary" onclick={commit} data-testid="waf-rule-ok">
					{language.current && t('wafRules.saveRule')}
				</button>
			</div>
		</div>
	{:else}
		<div class="add-row">
			<button type="button" class="btn" onclick={addRule} data-testid="waf-rule-add">
				{language.current && t('wafRules.add')}
			</button>
			<span class="text-xs text-muted">{language.current && t('wafRules.presetsLabel')}</span>
			{#each ['sensitiveFiles', 'scanners', 'methods'] as const as key (key)}
				<button type="button" class="chip" onclick={() => addPreset(key)} data-testid="waf-rule-preset-{key}">
					{language.current && t(`wafRules.presets.${key}`)}
				</button>
			{/each}
		</div>
	{/if}
</div>

<style>
	.rules {
		list-style: none;
		margin: 0 0 8px 0;
		padding: 0;
		border: 1px solid var(--border-subtle);
		border-radius: 6px;
	}
	.rule {
		display: flex;
		align-items: center;
		gap: 10px;
		padding: 8px 10px;
		border-bottom: 1px solid var(--border-subtle);
	}
	.rule:last-child {
		border-bottom: none;
	}
	.rule.off .rule-text {
		opacity: 0.55;
	}
	.rule-text {
		display: flex;
		flex-direction: column;
		gap: 2px;
		flex: 1;
		min-width: 0;
	}
	.rule-actions {
		display: flex;
		gap: 6px;
	}
	.badge {
		margin-left: 6px;
		font-size: 11px;
		font-weight: 400;
		color: var(--text-muted);
		border: 1px solid var(--border-subtle);
		border-radius: 4px;
		padding: 0 4px;
	}
	.btn,
	.chip {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle);
		padding: 2px 10px;
		border-radius: 4px;
		font-size: 12px;
		cursor: pointer;
		white-space: nowrap;
	}
	.chip {
		border-radius: 999px;
	}
	.btn:hover,
	.chip:hover {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
	}
	.btn.danger:hover {
		color: var(--status-down);
		border-color: var(--status-down);
	}
	.btn.primary {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
	}
	.btn:focus-visible,
	.chip:focus-visible,
	.link:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.add-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 6px;
		margin-top: 4px;
	}
	.editor {
		display: flex;
		flex-direction: column;
		gap: 8px;
		padding: 10px;
		margin-top: 4px;
		border: 1px solid var(--border-default, var(--border-subtle));
		border-radius: 6px;
		background: var(--bg-surface);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.field span {
		font-size: 11px;
		color: var(--text-secondary);
	}
	.condition {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		gap: 6px;
	}
	.values {
		flex: 1;
		min-width: 180px;
	}
	.link {
		align-self: flex-start;
		background: none;
		border: none;
		padding: 0;
		font-size: 12px;
		color: var(--accent-cyan);
		cursor: pointer;
	}
	.preview {
		margin: 0;
		color: var(--text-primary);
	}
	.editor-actions {
		display: flex;
		justify-content: flex-end;
		gap: 6px;
	}
</style>
