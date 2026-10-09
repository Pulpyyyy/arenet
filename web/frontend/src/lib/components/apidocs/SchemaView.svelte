<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  SchemaView (v2.39) — one JSON schema as a readable tree: property
  name, type, required / read-only / write-only markers, enum values,
  description; objects and arrays expand (collapsed past the first
  level). Recursive; cycles stop at a fixed depth.
-->
<script lang="ts">
	import SchemaView from './SchemaView.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { refName, resolve, schemaType, type OpenAPIDoc, type Schema } from '$lib/utils/openapi';

	interface Props {
		doc: OpenAPIDoc;
		schema: Schema;
		depth?: number;
	}

	let { doc, schema, depth = 0 }: Props = $props();

	const MAX_DEPTH = 8;

	const node = $derived(resolve(doc, schema) ?? {});
	const name = $derived(refName(schema));
	const type = $derived(schemaType(node));
	const itemSchema = $derived(type === 'array' ? node.items : undefined);
	const properties = $derived(Object.entries<Schema>(node.properties ?? {}));
	const required = $derived(new Set<string>(node.required ?? []));
	const variants = $derived<Schema[]>(node.oneOf ?? node.anyOf ?? []);

	function label(s: Schema): string {
		const r = resolve(doc, s) ?? {};
		const n = refName(s);
		const ty = schemaType(r);
		if (ty === 'array') {
			const inner = refName(r.items) || schemaType(resolve(doc, r.items));
			return `${inner || 'any'}[]`;
		}
		const nullable = Array.isArray(r.type) && r.type.includes('null') ? ' | null' : '';
		return (n || ty || 'any') + (r.format ? ` (${r.format})` : '') + nullable;
	}
</script>

{#if depth === 0 && name}
	<p class="schema-name">{name}</p>
{/if}
{#if node.description && depth === 0}
	<p class="desc">{node.description}</p>
{/if}

{#if depth >= MAX_DEPTH}
	<span class="muted">…</span>
{:else if properties.length > 0}
	<ul class="props">
		{#each properties as [key, sub] (key)}
			{@const r = resolve(doc, sub) ?? {}}
			{@const expandable = schemaType(r) === 'object' || (schemaType(r) === 'array' && schemaType(resolve(doc, r.items)) === 'object')}
			<li>
				{#if expandable}
					<details open={depth === 0}>
						<summary>
							<span class="key">{key}</span>
							<span class="type">{label(sub)}</span>
							{#if required.has(key)}<span class="flag req">{language.current && t('apiDocs.required')}</span>{/if}
							{#if r.readOnly}<span class="flag">{language.current && t('apiDocs.readOnly')}</span>{/if}
							{#if r.writeOnly}<span class="flag">{language.current && t('apiDocs.writeOnly')}</span>{/if}
						</summary>
						{#if r.description}<p class="desc">{r.description}</p>{/if}
						<SchemaView {doc} schema={schemaType(r) === 'array' ? r.items : sub} depth={depth + 1} />
					</details>
				{:else}
					<span class="key">{key}</span>
					<span class="type">{label(sub)}</span>
					{#if required.has(key)}<span class="flag req">{language.current && t('apiDocs.required')}</span>{/if}
					{#if r.readOnly}<span class="flag">{language.current && t('apiDocs.readOnly')}</span>{/if}
					{#if r.writeOnly}<span class="flag">{language.current && t('apiDocs.writeOnly')}</span>{/if}
					{#if Array.isArray(r.enum)}<span class="enum">{r.enum.map((v: unknown) => JSON.stringify(v)).join(' | ')}</span>{/if}
					{#if r.description}<p class="desc">{r.description}</p>{/if}
				{/if}
			</li>
		{/each}
	</ul>
{:else if itemSchema}
	<p class="type">{label(schema)}</p>
	{#if schemaType(resolve(doc, itemSchema)) === 'object'}
		<SchemaView {doc} schema={itemSchema} depth={depth + 1} />
	{/if}
{:else if variants.length > 0}
	<p class="muted">{language.current && t('apiDocs.oneOf')}</p>
	<ul class="props">
		{#each variants as v, i (i)}
			<li><SchemaView {doc} schema={v} depth={depth + 1} /></li>
		{/each}
	</ul>
{:else}
	<p class="type">
		{label(schema)}
		{#if Array.isArray(node.enum)}<span class="enum">{node.enum.map((v: unknown) => JSON.stringify(v)).join(' | ')}</span>{/if}
	</p>
{/if}

<style>
	.schema-name {
		margin: 0 0 4px 0;
		font-family: var(--font-mono, monospace);
		font-size: 12px;
		color: var(--accent-cyan);
	}
	.props {
		list-style: none;
		margin: 0;
		padding-left: 14px;
		border-left: 1px solid var(--border-subtle);
	}
	.props > li {
		padding: 3px 0;
		font-size: 13px;
	}
	summary {
		cursor: pointer;
	}
	.key {
		font-family: var(--font-mono, monospace);
		color: var(--text-primary);
		font-weight: 600;
	}
	.type {
		margin: 0 0 0 6px;
		font-family: var(--font-mono, monospace);
		font-size: 12px;
		color: var(--text-secondary);
	}
	p.type {
		margin: 0;
	}
	.flag {
		margin-left: 6px;
		font-size: 10px;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-muted);
	}
	.flag.req {
		color: var(--status-warn-fg);
	}
	.enum {
		margin-left: 6px;
		font-family: var(--font-mono, monospace);
		font-size: 11px;
		color: var(--status-up);
	}
	.desc {
		margin: 2px 0 0 0;
		font-size: 12px;
		color: var(--text-muted);
		white-space: pre-line;
	}
	.muted {
		margin: 0;
		font-size: 12px;
		color: var(--text-muted);
	}
</style>
