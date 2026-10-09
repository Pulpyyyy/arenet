<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step M.3 — Recent WAF events table.

Reused by /security (limit=20, no filter) AND
/security/[routeId] (limit=20, route-scoped, M.4).

Columns:
  - ts           (relative: "12s ago" / "3m ago" / absolute past 1h)
  - route        (link to /security/<routeId>; falls back to UUID
                  if the host isn't supplied in props)
  - category     (coloured badge, same palette as CategoryDistribution)
  - ruleId       (mono, narrow column)
  - srcIp        (mono)
  - payload      (truncated; full sample available on hover via title)

Empty state: italic "no events" message inside a card-sized
panel — same shape as the TimelineChart's empty state so the
dashboard feels coherent.

Compact mode (prop): drops the route column. Used by the
drill-down page where every row already belongs to the
selected route.
-->

<script lang="ts">
	import type { OwaspCategory, WafEvent } from '$lib/api/types';
	import WafExcludeDialog from '$lib/components/WafExcludeDialog.svelte';
	import BanIPModal from '$lib/components/BanIPModal.svelte';
	import { auth } from '$lib/stores/auth.svelte';
	import { isFullIP } from '$lib/utils/ipClass';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { isExcludableRule } from '$lib/utils/waf-exclusion';

	interface Props {
		events: WafEvent[];
		/**
		 * Optional map of routeId → host string so the route
		 * cell can show the friendly host instead of the bare
		 * UUID. When the routeId isn't in the map, falls back
		 * to a truncated UUID.
		 */
		hostByRouteId?: Record<string, string>;
		/**
		 * Compact mode = drop the route column. Drill-down
		 * page sets this true (every row is the same route).
		 */
		compact?: boolean;
		/**
		 * v2.36 — host shown in the "Exclude…" dialog when the
		 * map has no entry (drill-down page: one route).
		 */
		host?: string;
		/** v2.36 — called after an exclusion was added. */
		onExcluded?: () => void;
	}
	let { events, hostByRouteId = {}, compact = false, host = '', onExcluded }: Props = $props();

	// v2.36 — "Exclude…" on a row (admins only; the backend is the
	// authoritative gate). Protected / Arenet rules get no button.
	const isAdmin = $derived(auth.user?.role === 'admin');
	let excludeEvent = $state<WafEvent | null>(null);
	// "Ban…" on a row: the source IP handed to BanIPModal (admins
	// only, like the CrowdSec panel's ban button).
	let banIP = $state<string | null>(null);

	// Category badge colours mirror CategoryDistribution.
	// Phase Y — colour mapping moved to lib/utils/waf-category
	// (single source of truth across CategoryDistribution +
	// WafEventList + MixedEventList + /waf + /security/[routeId]).
	import { categoryMeta } from '$lib/utils/waf-category';

	// Relative time formatting: "Ns ago" up to a minute, "Nm
	// ago" up to an hour, then HH:MM. Pure function — no
	// re-renders on tick (caller controls refresh cadence).
	function relativeTs(iso: string): string {
		const then = new Date(iso).getTime();
		const now = Date.now();
		const secs = Math.max(0, Math.floor((now - then) / 1000));
		if (secs < 60) return `${secs}s ago`;
		const mins = Math.floor(secs / 60);
		if (mins < 60) return `${mins}m ago`;
		const d = new Date(iso);
		const hh = String(d.getHours()).padStart(2, '0');
		const mm = String(d.getMinutes()).padStart(2, '0');
		return `${hh}:${mm}`;
	}

	// Short host display: prefer the friendly host from the
	// caller, fall back to a UUID prefix. The cell always
	// links to /security/<routeId>.
	function hostFor(routeId: string): string {
		return hostByRouteId[routeId] ?? routeId.slice(0, 8) + '…';
	}

	// Truncate payload to 60 chars for the table cell; full
	// text in the title= tooltip.
	function payloadPreview(s: string): string {
		if (s.length <= 60) return s;
		return s.slice(0, 60) + '…';
	}
</script>

{#if events.length === 0}
	<div class="empty">no WAF events in window</div>
{:else}
	<table>
		<thead>
			<tr>
				<th>Time</th>
				{#if !compact}
					<th>Route</th>
				{/if}
				<th>Category</th>
				<th>Rule</th>
				<th>Source IP</th>
				<th>Payload</th>
				{#if isAdmin}
					<th><span class="sr-only">{language.current && t('wafExclude.action')}</span></th>
				{/if}
			</tr>
		</thead>
		<tbody>
			{#each events as e (e.id)}
				<tr>
					<td class="ts" title={e.ts}>{relativeTs(e.ts)}</td>
					{#if !compact}
						<td class="route">
							<a href="/security/{e.routeId}">{hostFor(e.routeId)}</a>
						</td>
					{/if}
					<td>
						<span class="badge" style:background={categoryMeta(e.category).color}>
							{e.category}
						</span>
					</td>
					<td class="mono" title={e.ruleName ?? ''}>
						{e.ruleId}
						{#if e.ruleName}
							<span class="rule-name">{e.ruleName}</span>
						{/if}
					</td>
					<td class="mono">{e.srcIp}</td>
					<td class="payload mono" title={e.payloadSample || '(empty)'}>
						{payloadPreview(e.payloadSample) || '—'}
					</td>
					{#if isAdmin}
						<td class="actions">
							{#if isExcludableRule(e.ruleId)}
								<button
									type="button"
									class="exclude-btn"
									onclick={() => (excludeEvent = e)}
									aria-label={language.current && t('wafExclude.actionAria', { rule: e.ruleId })}
									data-testid="waf-exclude-open"
								>
									{language.current && t('wafExclude.action')}
								</button>
							{/if}
							{#if isFullIP(e.srcIp)}
								<button
									type="button"
									class="exclude-btn"
									onclick={() => (banIP = e.srcIp)}
									aria-label={language.current && t('banIp.rowActionAria', { ip: e.srcIp })}
									data-testid="waf-ban-open"
								>
									{language.current && t('banIp.rowAction')}
								</button>
							{/if}
						</td>
					{/if}
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<WafExcludeDialog
	open={excludeEvent !== null}
	event={excludeEvent}
	host={excludeEvent ? (hostByRouteId[excludeEvent.routeId] ?? host) : ''}
	onClose={() => (excludeEvent = null)}
	onSuccess={() => onExcluded?.()}
/>

{#if isAdmin}
	<BanIPModal open={banIP !== null} initialValue={banIP ?? ''} onClose={() => (banIP = null)} />
{/if}

<style>
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm, 13px);
	}
	th,
	td {
		padding: 0.4rem 0.6rem;
		text-align: left;
		border-bottom: 1px solid var(--border-subtle, var(--bg-hover));
		vertical-align: top;
	}
	th {
		color: var(--text-secondary);
		font-weight: 500;
		font-size: var(--text-xs, 11px);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.ts {
		font-family: var(--font-mono, monospace);
		color: var(--text-secondary);
		white-space: nowrap;
	}
	.route a {
		color: var(--text-primary);
		text-decoration: none;
		border-bottom: 1px dashed var(--text-muted);
	}
	.route a:hover {
		color: var(--accent-cyan);
		border-bottom-color: var(--accent-cyan);
	}
	.mono {
		font-family: var(--font-mono, monospace);
	}
	.payload {
		color: var(--text-secondary);
		word-break: break-all;
	}
	.badge {
		display: inline-block;
		padding: 0.1rem 0.45rem;
		border-radius: 3px;
		color: var(--text-on-color, #ffffff);
		font-size: var(--text-xs, 11px);
		font-weight: 600;
		letter-spacing: 0.04em;
	}
	.rule-name {
		display: block;
		font-family: var(--font-body, inherit);
		color: var(--text-secondary);
		font-size: var(--text-xs, 11px);
	}
	.actions {
		text-align: right;
		white-space: nowrap;
	}
	.exclude-btn {
		background: var(--bg-surface);
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle, var(--bg-hover));
		padding: 0.15rem 0.5rem;
		border-radius: 4px;
		font-size: var(--text-xs, 11px);
		cursor: pointer;
	}
	.exclude-btn + .exclude-btn {
		margin-left: 0.3rem;
	}
	.exclude-btn:hover {
		color: var(--accent-cyan);
		border-color: var(--accent-cyan);
	}
	.exclude-btn:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 1px;
	}
	.sr-only {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip: rect(0 0 0 0);
		white-space: nowrap;
	}
	.empty {
		padding: 1rem;
		text-align: center;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm, 13px);
	}
</style>
