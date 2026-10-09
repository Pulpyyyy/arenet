<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  OperationView (v2.39) — one API operation: method + path, role,
  description, parameters, request body (schema + example), responses,
  and "Try it": fills the parameters, sends the call with the current
  session and shows the raw status + body. A changing method
  (POST/PUT/PATCH/DELETE) asks for confirmation first — it acts on
  the real configuration.

  The confirmation must not be reachable by a double-click: "Send"
  used to turn into "Yes, send it" in the same spot, so the second
  click of a double-click fired a real write. Now "Send" stays put and
  is disabled, the confirm button appears in a separate panel below,
  after Cancel, and stays disabled for CONFIRM_GUARD_MS with a visible
  countdown. Focus lands on Cancel, so a repeated Enter cancels too.
  Escape or Cancel returns to the initial state.
-->
<script lang="ts">
	import { onDestroy, tick } from 'svelte';
	import SchemaView from './SchemaView.svelte';
	import { rawRequest, type RawResponse } from '$lib/api/client';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		explicitExample,
		fillPath,
		isMutating,
		jsonSchema,
		sampleFromSchema,
		type OpenAPIDoc,
		type Operation
	} from '$lib/utils/openapi';

	interface Props {
		doc: OpenAPIDoc;
		op: Operation;
	}

	let { doc, op }: Props = $props();

	const requestSchema = $derived(jsonSchema(doc, op.requestBody));
	const requestExample = $derived.by(() => {
		if (!op.requestBody) return undefined;
		const ex = explicitExample(op.requestBody);
		return ex !== undefined ? ex : requestSchema ? sampleFromSchema(doc, requestSchema) : undefined;
	});
	const pathParams = $derived(op.parameters.filter((p) => p.in === 'path'));
	const queryParams = $derived(op.parameters.filter((p) => p.in === 'query'));

	// --- Try it -----------------------------------------------------------

	/** How long the confirm button stays disabled after it appears —
	 *  longer than any double-click interval. */
	const CONFIRM_GUARD_MS = 1000;
	/** Countdown refresh step. */
	const GUARD_TICK_MS = 100;
	const MS_PER_SECOND = 1000;

	let open = $state(false);
	let values = $state<Record<string, string>>({});
	let body = $state('');
	let sending = $state(false);
	let confirming = $state(false);
	/** Milliseconds before the confirm button accepts a click. */
	let guardLeft = $state(0);
	let response = $state<RawResponse | null>(null);
	let sendError = $state<string | null>(null);
	let sendBtn = $state<HTMLButtonElement | null>(null);
	let cancelBtn = $state<HTMLButtonElement | null>(null);
	let guardTimer: ReturnType<typeof setInterval> | null = null;

	const isDelete = $derived(op.method === 'delete');
	const guardSeconds = $derived(Math.ceil(guardLeft / MS_PER_SECOND));

	function stopGuard(): void {
		if (guardTimer !== null) {
			clearInterval(guardTimer);
			guardTimer = null;
		}
	}

	function startGuard(): void {
		stopGuard();
		guardLeft = CONFIRM_GUARD_MS;
		guardTimer = setInterval(() => {
			guardLeft = Math.max(0, guardLeft - GUARD_TICK_MS);
			if (guardLeft === 0) stopGuard();
		}, GUARD_TICK_MS);
	}

	onDestroy(stopGuard);

	// Reset the form when another operation is shown.
	let lastKey = '';
	$effect(() => {
		if (op.key === lastKey) return;
		lastKey = op.key;
		open = false;
		values = {};
		body = requestExample !== undefined ? JSON.stringify(requestExample, null, 2) : '';
		response = null;
		sendError = null;
		confirming = false;
		stopGuard();
		guardLeft = 0;
	});

	const url = $derived.by(() => {
		const path = fillPath(op.fullPath, values);
		const qs = queryParams
			.filter((p) => (values[p.name] ?? '').trim() !== '')
			.map((p) => `${encodeURIComponent(p.name)}=${encodeURIComponent(values[p.name].trim())}`)
			.join('&');
		return qs ? `${path}?${qs}` : path;
	});
	const missingPath = $derived(pathParams.some((p) => (values[p.name] ?? '').trim() === ''));

	/** "Send": a GET goes out at once; a changing method opens the
	 *  confirmation instead. */
	function requestSend(): void {
		if (missingPath || sending || confirming) return;
		if (isMutating(op.method)) {
			confirming = true;
			startGuard();
			void tick().then(() => cancelBtn?.focus());
			return;
		}
		void send();
	}

	/** The confirm button: refused while the guard is still running. */
	function confirmSend(): void {
		if (!confirming || guardLeft > 0) return;
		void send();
	}

	/** Cancel / Escape: back to the initial state. */
	function cancelConfirm(): void {
		if (!confirming) return;
		confirming = false;
		stopGuard();
		guardLeft = 0;
		void tick().then(() => sendBtn?.focus());
	}

	function onWindowKeydown(e: KeyboardEvent): void {
		if (confirming && e.key === 'Escape') {
			e.preventDefault();
			cancelConfirm();
		}
	}

	async function send(): Promise<void> {
		if (missingPath) return;
		confirming = false;
		stopGuard();
		guardLeft = 0;
		sending = true;
		sendError = null;
		try {
			response = await rawRequest(op.method, url, op.requestBody ? body : undefined);
		} catch (err) {
			response = null;
			sendError = err instanceof Error ? err.message : String(err);
		} finally {
			sending = false;
		}
	}

	const prettyBody = $derived.by(() => {
		if (!response) return '';
		try {
			return JSON.stringify(JSON.parse(response.body), null, 2);
		} catch {
			return response.body;
		}
	});

	function responseSchema(code: string) {
		return jsonSchema(doc, op.responses[code]);
	}
</script>

<svelte:window onkeydown={onWindowKeydown} />

<article class="op" data-testid="api-op">
	<header>
		<span class="method method-{op.method}">{op.method.toUpperCase()}</span>
		<code class="path">{op.fullPath}</code>
		<span class="role role-{op.role}" title={language.current && t('apiDocs.roleTitle')}>
			{language.current && t(`apiDocs.roles.${op.role || 'viewer'}`)}
		</span>
	</header>
	<h2>{op.summary}</h2>
	{#if op.description}<p class="description">{op.description}</p>{/if}

	{#if op.parameters.length > 0}
		<h3>{language.current && t('apiDocs.parameters')}</h3>
		<table class="params">
			<tbody>
				{#each op.parameters as p (p.in + p.name)}
					<tr>
						<td><code>{p.name}</code>{#if p.required}<span class="req">*</span>{/if}</td>
						<td class="muted">{p.in}</td>
						<td class="muted">{p.schema?.type ?? ''}</td>
						<td>{p.description ?? ''}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}

	{#if requestSchema}
		<h3>{language.current && t('apiDocs.requestBody')}</h3>
		<SchemaView {doc} schema={requestSchema} />
		{#if requestExample !== undefined}
			<details class="example">
				<summary>{language.current && t('apiDocs.example')}</summary>
				<pre>{JSON.stringify(requestExample, null, 2)}</pre>
			</details>
		{/if}
	{/if}

	<h3>{language.current && t('apiDocs.responses')}</h3>
	{#each Object.keys(op.responses) as code (code)}
		{@const rs = responseSchema(code)}
		<details class="response" open={code.startsWith('2') && !!rs}>
			<summary>
				<span class="status status-{code[0]}">{code}</span>
				{op.responses[code]?.description ?? ''}
			</summary>
			{#if rs}<SchemaView {doc} schema={rs} />{/if}
		</details>
	{/each}

	<section class="try" data-testid="api-try">
		{#if !open}
			<button type="button" class="btn" onclick={() => (open = true)} data-testid="api-try-open">
				{language.current && t('apiDocs.tryIt')}
			</button>
		{:else}
			<h3>{language.current && t('apiDocs.tryIt')}</h3>
			{#each [...pathParams, ...queryParams] as p (p.in + p.name)}
				<label class="field">
					<span><code>{p.name}</code> <span class="muted">({p.in}){#if p.required} *{/if}</span></span>
					<input
						type="text"
						bind:value={values[p.name]}
						data-testid="api-param-{p.name}"
						class="bg-surface border border-border-default rounded-md px-2 py-1 text-sm text-primary font-mono"
					/>
				</label>
			{/each}
			{#if op.requestBody}
				<label class="field">
					<span>{language.current && t('apiDocs.body')}</span>
					<textarea
						bind:value={body}
						rows="8"
						spellcheck="false"
						data-testid="api-body"
						class="bg-surface border border-border-default rounded-md px-2 py-1 text-xs text-primary font-mono"
					></textarea>
				</label>
			{/if}
			<p class="url"><code>{op.method.toUpperCase()} {url}</code></p>
			<div class="actions">
				<button
					type="button"
					class="btn primary"
					bind:this={sendBtn}
					onclick={requestSend}
					disabled={sending || missingPath || confirming}
					data-testid="api-send"
				>
					{language.current && t('apiDocs.send')}
				</button>
			</div>
			{#if confirming}
				<!-- Below "Send", confirm after Cancel: never under the cursor
				     that just clicked "Send". -->
				<div
					class="confirm"
					class:danger={isDelete}
					role="group"
					aria-labelledby="api-confirm-msg"
					data-testid="api-confirm-panel"
				>
					<p class="confirm-msg" id="api-confirm-msg" role="alert" data-testid="api-confirm">
						{language.current &&
							t(isDelete ? 'apiDocs.confirmDelete' : 'apiDocs.confirmMutating', {
								request: `${op.method.toUpperCase()} ${url}`
							})}
					</p>
					<div class="actions">
						<button
							type="button"
							class="btn"
							bind:this={cancelBtn}
							onclick={cancelConfirm}
							data-testid="api-confirm-cancel"
						>
							{language.current && t('apiDocs.cancel')}
						</button>
						<button
							type="button"
							class="btn confirm-btn"
							class:danger={isDelete}
							onclick={confirmSend}
							disabled={guardLeft > 0}
							data-testid="api-confirm-send"
						>
							{language.current && t(isDelete ? 'apiDocs.confirmDeleteSend' : 'apiDocs.confirmSend')}
							{#if guardLeft > 0}
								<span class="countdown" data-testid="api-confirm-countdown">
									{language.current && t('apiDocs.countdown', { seconds: guardSeconds })}
								</span>
							{/if}
						</button>
					</div>
				</div>
			{/if}
			{#if sendError}<p class="error" role="alert">{sendError}</p>{/if}
			{#if response}
				<div class="result" data-testid="api-result">
					<span class="status status-{String(response.status)[0]}">{response.status}</span>
					<pre>{prettyBody}</pre>
				</div>
			{/if}
		{/if}
	</section>
</article>

<style>
	.op {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	header {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		gap: 8px;
	}
	.method {
		font-family: var(--font-mono, monospace);
		font-size: 12px;
		font-weight: 700;
		padding: 2px 8px;
		border-radius: 4px;
		color: var(--bg-base);
		background: var(--text-muted);
	}
	.method-get {
		background: var(--accent-cyan);
	}
	.method-post {
		background: var(--status-up);
	}
	.method-put,
	.method-patch {
		background: var(--status-warn);
	}
	.method-delete {
		background: var(--status-down);
	}
	.path {
		font-size: 14px;
		color: var(--text-primary);
		word-break: break-all;
	}
	.role {
		font-size: 11px;
		padding: 1px 6px;
		border-radius: 999px;
		border: 1px solid var(--border-subtle);
		color: var(--text-secondary);
	}
	.role-admin {
		color: var(--status-warn);
		border-color: var(--status-warn);
	}
	h2 {
		margin: 4px 0 0 0;
		font-size: 18px;
		color: var(--text-primary);
	}
	h3 {
		margin: 12px 0 4px 0;
		font-size: 13px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--text-secondary);
	}
	.description {
		margin: 0;
		font-size: 13px;
		color: var(--text-secondary);
		white-space: pre-line;
		max-width: 75ch;
	}
	.params {
		border-collapse: collapse;
		font-size: 13px;
	}
	.params td {
		padding: 3px 10px 3px 0;
		vertical-align: top;
	}
	.req {
		color: var(--status-warn);
	}
	.muted {
		color: var(--text-muted);
	}
	pre {
		margin: 4px 0 0 0;
		padding: 8px 10px;
		max-height: 360px;
		overflow: auto;
		font-size: 12px;
		background: var(--bg-base);
		border: 1px solid var(--border-subtle);
		border-radius: 4px;
		color: var(--text-primary);
	}
	.response summary,
	.example summary {
		cursor: pointer;
		font-size: 13px;
		color: var(--text-secondary);
	}
	.status {
		display: inline-block;
		min-width: 36px;
		font-family: var(--font-mono, monospace);
		font-weight: 700;
		color: var(--text-secondary);
	}
	.status-2 {
		color: var(--status-up);
	}
	.status-4 {
		color: var(--status-warn);
	}
	.status-5 {
		color: var(--status-down);
	}
	.try {
		margin-top: 12px;
		padding-top: 10px;
		border-top: 1px solid var(--border-subtle);
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: 2px;
		font-size: 12px;
		color: var(--text-secondary);
	}
	.url {
		margin: 0;
		font-size: 12px;
		word-break: break-all;
	}
	.actions {
		display: flex;
		gap: 6px;
	}
	.btn {
		align-self: flex-start;
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle);
		padding: 3px 12px;
		border-radius: 4px;
		font-size: 13px;
		cursor: pointer;
	}
	.btn.primary,
	.btn:hover {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
	}
	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}
	.btn:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.confirm {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 4px;
		padding: 10px 12px;
		border: 1px solid var(--status-warn);
		border-left-width: 4px;
		border-radius: 4px;
		background: var(--bg-base);
	}
	.confirm.danger {
		border-color: var(--status-down);
	}
	.confirm-msg {
		margin: 0;
		font-size: 13px;
		color: var(--status-warn);
		overflow-wrap: anywhere;
	}
	.confirm.danger .confirm-msg {
		color: var(--status-down);
		font-weight: 600;
	}
	.btn.confirm-btn,
	.btn.confirm-btn:hover {
		color: var(--status-warn);
		border-color: var(--status-warn);
	}
	.btn.confirm-btn.danger,
	.btn.confirm-btn.danger:hover {
		color: var(--bg-base);
		background: var(--status-down);
		border-color: var(--status-down);
		font-weight: 600;
	}
	.countdown {
		font-variant-numeric: tabular-nums;
	}
	.error {
		margin: 0;
		font-size: 12px;
		color: var(--status-down);
	}
</style>
