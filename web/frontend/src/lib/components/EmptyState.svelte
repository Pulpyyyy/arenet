<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  EmptyState (v2.41) — the "there is nothing here" surface.

  Half the pages had a real explanatory empty state with a way out
  (routes, certs, error pages) and half had a one-line "no data" or
  nothing at all (users, audit, logs, topology, map). An operator who
  lands on an empty page needs the same three things everywhere: what
  is empty, why it might be, and what to do next.

  `title` says what is empty, `body` says why (and, when a filter is
  the cause, that the filter is the cause), and the optional action —
  a link or a callback — is the way out. The `tone` only shades the
  mark: 'neutral' for an empty collection, 'filter' for "your filter
  matched nothing", 'warn' for a degraded subsystem.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';
	import Button from './Button.svelte';

	interface Props {
		title: string;
		body?: string;
		/** Label of the way out; nothing is rendered without it. */
		actionLabel?: string;
		/** Link target. Takes precedence over onAction. */
		actionHref?: string;
		onAction?: () => void;
		/** A second way out, shown beside the first in a quieter style
		 *  (Routes: "Add a route" or "Import a Caddyfile"). Rendered only
		 *  with both a label and a callback. */
		secondaryActionLabel?: string;
		onSecondaryAction?: () => void;
		tone?: 'neutral' | 'filter' | 'warn';
		testid?: string;
		/** Extra content under the body (a second link, a hint). */
		children?: Snippet;
	}

	let {
		title,
		body = '',
		actionLabel = '',
		actionHref = '',
		onAction,
		secondaryActionLabel = '',
		onSecondaryAction,
		tone = 'neutral',
		testid,
		children
	}: Props = $props();

	const MARKS: Record<'neutral' | 'filter' | 'warn', string> = {
		neutral: '◉',
		filter: '⌕',
		warn: '!'
	};
</script>

<div class="empty-state" data-tone={tone} data-testid={testid}>
	<div class="mark" aria-hidden="true">{MARKS[tone]}</div>
	<h3 class="title">{title}</h3>
	{#if body}
		<p class="body">{body}</p>
	{/if}
	{#if children}
		<div class="extra">{@render children()}</div>
	{/if}
	{#snippet primary()}
		{#if actionLabel}
			{#if actionHref}
				<a class="action" href={actionHref}>{actionLabel}</a>
			{:else if onAction}
				<Button onclick={onAction}>{actionLabel}</Button>
			{/if}
		{/if}
	{/snippet}
	{#if secondaryActionLabel && onSecondaryAction}
		<div class="actions">
			{@render primary()}
			<Button variant="secondary" onclick={onSecondaryAction}>{secondaryActionLabel}</Button>
		</div>
	{:else}
		{@render primary()}
	{/if}
</div>

<style>
	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: 10px;
		padding: 48px 20px;
	}
	.mark {
		font-size: 40px;
		line-height: 1;
		color: var(--text-muted);
	}
	.empty-state[data-tone='warn'] .mark {
		color: var(--status-warn);
	}
	.title {
		margin: 0;
		font-size: 15px;
		font-weight: 600;
		color: var(--text-primary);
	}
	.body,
	.extra {
		margin: 0;
		max-width: 52ch;
		font-size: 13px;
		line-height: 1.6;
		color: var(--text-secondary);
	}
	.actions {
		margin-top: 4px;
		display: flex;
		flex-wrap: wrap;
		justify-content: center;
		gap: 8px;
	}
	.action {
		margin-top: 4px;
		display: inline-flex;
		align-items: center;
		gap: 8px;
		padding: 6px 14px;
		border-radius: var(--radius-md, 8px);
		font-size: 13px;
		font-weight: 500;
		text-decoration: none;
		color: var(--text-primary);
		background: var(--bg-elevated);
		border: 1px solid var(--border-default);
	}
	.action:hover {
		background: var(--bg-hover);
	}
</style>
