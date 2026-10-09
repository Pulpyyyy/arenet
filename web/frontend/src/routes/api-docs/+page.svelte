<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  /api-docs (v2.39) — in-app viewer of Arenet's OpenAPI document
  (GET /api/v1/openapi.json): operations by tag with a search on the
  left, the selected operation on the right (OperationView), a link to
  download the JSON. Written in Svelte on purpose: the usual viewers
  (Swagger UI, Redoc, Scalar) bundle React or Vue. The selected
  operation is kept in the URL hash (#post/routes) so it can be linked.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import OperationView from '$lib/components/apidocs/OperationView.svelte';
	import { getOpenAPI } from '$lib/api/client';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { groupByTag, listOperations, matches, type OpenAPIDoc, type Operation } from '$lib/utils/openapi';

	let doc = $state<OpenAPIDoc | null>(null);
	let loadError = $state<string | null>(null);
	let query = $state('');
	let selectedKey = $state<string | null>(null);

	const ops = $derived<Operation[]>(doc ? listOperations(doc) : []);
	const groups = $derived(groupByTag(ops.filter((o) => matches(o, query))));
	const selected = $derived(ops.find((o) => o.key === selectedKey) ?? null);
	const intro = $derived<string>(doc?.info?.description ?? '');

	// v2.55 — the tag groups fold.
	//
	// Every group used to render expanded, so the sidebar was 15 headings
	// and 159 operations in one column — the operator's words were that all
	// the requests sat one behind the other and it looked odd. Folded, the
	// same list opens as 15 rows you can aim at.
	//
	// Deliberately a button plus `hidden` rather than <details open={…}>:
	// RouteSection documents what happens when a reactive value drives the
	// native open attribute — the element snaps shut under the cursor on any
	// parent re-render. Here the state below is the only source of truth.
	//
	// `hidden` rather than {#if} so the operations stay in the document:
	// nothing has to be rebuilt when a group opens, and the attribute already
	// takes them out of both the accessibility tree and the tab order.
	let openTags = $state<Record<string, boolean>>({});

	const searching = $derived(query.trim() !== '');
	const selectedTag = $derived(selected?.tag ?? null);

	/**
	 * Whether a tag group shows its operations.
	 *
	 * A search opens every group that still has matches — filtering to
	 * results nobody can see would be worse than not filtering. Otherwise
	 * an explicit toggle wins, and with none, the group holding the current
	 * operation is the one open.
	 */
	function groupOpen(tag: string): boolean {
		if (searching) return true;
		const explicit = openTags[tag];
		if (explicit !== undefined) return explicit;
		return tag === selectedTag;
	}

	function toggleTag(tag: string): void {
		openTags = { ...openTags, [tag]: !groupOpen(tag) };
	}

	/** Stable DOM id for a tag, so the toggle can own aria-controls. */
	function tagId(tag: string): string {
		return 'api-tag-' + tag.toLowerCase().replace(/[^a-z0-9]+/g, '-');
	}

	// The selected operation lives in the URL hash ("#post/routes") so an
	// operation can be linked to and survives a reload. replaceState, not
	// a hash assignment: assigning location.hash would make the browser
	// scroll to a fragment that is not an element id.

	/** Hash fragment (without "#") naming an operation. */
	function hashFor(o: Operation): string {
		return o.method + o.path;
	}

	/** The key of the operation the current hash names, or null. */
	function keyFromHash(): string | null {
		const raw = window.location.hash.slice(1);
		if (!raw) return null;
		let wanted = raw;
		try {
			wanted = decodeURIComponent(raw);
		} catch {
			// Malformed escape: compare the raw text.
		}
		return ops.find((o) => hashFor(o) === wanted)?.key ?? null;
	}

	function selectOp(o: Operation): void {
		selectedKey = o.key;
		const url = new URL(window.location.href);
		url.hash = hashFor(o);
		window.history.replaceState(window.history.state, '', url.toString());
	}

	async function load(): Promise<void> {
		try {
			doc = await getOpenAPI();
			selectedKey = keyFromHash();
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		}
	}

	onMount(() => {
		void load();
		// A hash typed in the address bar, or a link to another operation.
		const onHash = (): void => {
			if (doc) selectedKey = keyFromHash();
		};
		window.addEventListener('hashchange', onHash);
		return () => window.removeEventListener('hashchange', onHash);
	});

	function download(): void {
		if (!doc) return;
		const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
		const a = document.createElement('a');
		a.href = URL.createObjectURL(blob);
		a.download = 'arenet-openapi.json';
		a.click();
		URL.revokeObjectURL(a.href);
	}
</script>

<PageHeader
	title={language.current && t('pageTitles.apiDocs')}
	subtitle={doc ? `OpenAPI ${doc.openapi} · ${doc.info?.version ?? ''} · ${ops.length} ${language.current && t('apiDocs.operations')}` : ''}
/>

{#if loadError}
	<p class="error" role="alert">{loadError}</p>
{:else if !doc}
	<div class="loading"><Spinner /></div>
{:else}
	<div class="layout">
		<nav class="nav" aria-label={language.current && t('apiDocs.navLabel')}>
			<input
				type="search"
				bind:value={query}
				placeholder={language.current && t('apiDocs.search')}
				aria-label={language.current && t('apiDocs.search')}
				data-testid="api-search"
				class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary"
			/>
			<button type="button" class="link" onclick={download} data-testid="api-download">
				{language.current && t('apiDocs.download')}
			</button>
			{#each groups as g (g.tag)}
				<button
					type="button"
					class="tag"
					aria-expanded={groupOpen(g.tag)}
					aria-controls={tagId(g.tag)}
					onclick={() => toggleTag(g.tag)}
					data-testid="api-tag-toggle"
				>
					<span class="caret" class:open={groupOpen(g.tag)} aria-hidden="true">▸</span>
					<span class="tag-name">{g.tag}</span>
					<span class="tag-count">{g.ops.length}</span>
				</button>
				<ul id={tagId(g.tag)} hidden={!groupOpen(g.tag)}>
					{#each g.ops as o (o.key)}
						<li>
							<button
								type="button"
								class="op-link"
								class:active={o.key === selectedKey}
								aria-current={o.key === selectedKey ? 'true' : undefined}
								onclick={() => selectOp(o)}
								data-testid="api-op-link"
							>
								<span class="m m-{o.method}">{o.method.toUpperCase()}</span>
								<span class="p">{o.path}</span>
							</button>
						</li>
					{/each}
				</ul>
			{:else}
				<p class="muted">{language.current && t('apiDocs.noMatch')}</p>
			{/each}
		</nav>
		<!-- A section, not a <main>: the layout already provides the page's
		     single main landmark. -->
		<section class="detail">
			{#if selected}
				<OperationView {doc} op={selected} />
			{:else}
				<div class="intro" data-testid="api-intro">
					<h2>{doc.info?.title}</h2>
					<p>{intro}</p>
				</div>
			{/if}
		</section>
	</div>
{/if}

<style>
	.layout {
		display: grid;
		grid-template-columns: minmax(240px, 340px) 1fr;
		gap: 16px;
		align-items: start;
	}
	@media (max-width: 860px) {
		.layout {
			grid-template-columns: 1fr;
		}
	}
	.nav {
		position: sticky;
		top: 12px;
		max-height: calc(100vh - 140px);
		overflow: auto;
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 10px;
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		background: var(--bg-surface);
	}
	.nav ul {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.tag {
		display: flex;
		align-items: center;
		gap: 6px;
		width: 100%;
		margin: 8px 0 2px 0;
		padding: 3px 6px;
		border: none;
		border-radius: 4px;
		background: none;
		text-align: left;
		cursor: pointer;
		font-size: 11px;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--text-muted);
	}
	.tag:hover {
		background: var(--bg-hover);
		color: var(--text-secondary);
	}
	.tag:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
	.caret {
		flex: none;
		font-size: 9px;
		transition: transform 0.15s ease;
	}
	.caret.open {
		transform: rotate(90deg);
	}
	.tag-name {
		flex: 1;
		min-width: 0;
	}
	.tag-count {
		flex: none;
		font-variant-numeric: tabular-nums;
		font-weight: 500;
		letter-spacing: 0;
		color: var(--text-muted);
	}
	@media (prefers-reduced-motion: reduce) {
		.caret {
			transition: none;
		}
	}
	.op-link {
		display: flex;
		align-items: baseline;
		gap: 6px;
		width: 100%;
		padding: 3px 6px;
		border: none;
		border-radius: 4px;
		background: none;
		text-align: left;
		cursor: pointer;
		color: var(--text-secondary);
	}
	.op-link:hover,
	.op-link.active {
		background: var(--bg-hover);
		color: var(--text-primary);
	}
	.op-link:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -2px;
	}
	.m {
		flex: none;
		width: 46px;
		font-family: var(--font-mono, monospace);
		font-size: 10px;
		font-weight: 700;
		color: var(--text-muted);
	}
	.m-get {
		color: var(--accent-cyan);
	}
	.m-post {
		color: var(--status-up);
	}
	.m-put,
	.m-patch {
		color: var(--status-warn);
	}
	.m-delete {
		color: var(--status-down);
	}
	.p {
		font-family: var(--font-mono, monospace);
		font-size: 12px;
		word-break: break-all;
	}
	.detail {
		min-width: 0;
		padding: 16px;
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		background: var(--bg-surface);
	}
	.intro h2 {
		margin: 0 0 8px 0;
		font-size: 18px;
		color: var(--text-primary);
	}
	.intro p {
		margin: 0;
		white-space: pre-line;
		font-size: 13px;
		color: var(--text-secondary);
		max-width: 80ch;
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
	.muted {
		color: var(--text-muted);
		font-size: 12px;
	}
	.error {
		color: var(--status-down);
	}
	.loading {
		display: flex;
		justify-content: center;
		padding: 40px;
	}
</style>
