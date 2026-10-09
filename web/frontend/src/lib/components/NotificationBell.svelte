<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Sidebar notification entry (bell + label + unread count) with a
  popover listing the most recent alert events plus a synthetic
  update item. Reads notificationsStore; unread via localStorage.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { notificationsStore, SYNTHETIC_UPDATE_ID } from '$lib/stores/notifications.svelte';
	import { notificationHref } from '$lib/utils/notification-href';
	import { relativeTime } from '$lib/utils/audit-format';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import type { AlertEvent } from '$lib/api/alerting';

	// Background refresh cadence (spec §1). Keeps the unread badge
	// current — including a newly-available update — without the
	// operator having to reload the page or open the panel.
	const POLL_INTERVAL_MS = 60_000;

	let open = $state(false);
	let triggerEl = $state<HTMLButtonElement | null>(null);
	let panelEl = $state<HTMLDivElement | null>(null);
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	const count = $derived(notificationsStore.unreadCount);
	const badge = $derived(count > 99 ? '99+' : String(count));
	// The aria-label replaces the button's content as its name, so the
	// badge is never read out: the count has to be in the label. The
	// real number, not the 99+ cap. Two keys for singular / plural.
	const triggerLabel = $derived(
		language.current &&
			(() => {
				const action = t(open ? 'notifications.ariaClose' : 'notifications.ariaOpen');
				if (count === 0) return action;
				const key = count === 1 ? 'notifications.ariaUnreadOne' : 'notifications.ariaUnreadMany';
				return t(key, { action, count });
			})()
	);

	function subjectOf(ev: AlertEvent): string {
		if (ev.eventId === SYNTHETIC_UPDATE_ID) {
			const version = (ev.context?.version as string) ?? '';
			return (language.current && t('notifications.updateAvailable', { version })) as string;
		}
		return ev.subject;
	}

	function isUnread(ev: AlertEvent): boolean {
		return ev.timestamp > notificationsStore.lastSeen;
	}

	async function toggle(): Promise<void> {
		open = !open;
		if (open) await notificationsStore.load();
	}
	function close(): void {
		open = false;
		triggerEl?.focus();
	}
	function markRead(): void {
		notificationsStore.markAllRead();
	}
	// Navigate to an internal route then close. Using goto() rather than
	// relying on the <a>'s default click means closing the panel (which
	// unmounts the link) can't race the navigation. External links keep
	// their native <a target=_blank> behavior.
	function goInternal(e: MouseEvent, href: string): void {
		e.preventDefault();
		open = false;
		void goto(href);
	}

	function onKey(e: KeyboardEvent): void {
		if (e.key === 'Escape' && open) close();
	}
	function onClickOutside(e: MouseEvent): void {
		if (!open) return;
		const target = e.target as Node;
		if (panelEl?.contains(target) || triggerEl?.contains(target)) return;
		open = false;
	}

	onMount(() => {
		notificationsStore.load();
		pollTimer = setInterval(() => notificationsStore.load(), POLL_INTERVAL_MS);
		document.addEventListener('keydown', onKey);
		document.addEventListener('click', onClickOutside, true);
	});
	onDestroy(() => {
		if (pollTimer !== null) clearInterval(pollTimer);
		if (typeof document === 'undefined') return;
		document.removeEventListener('keydown', onKey);
		document.removeEventListener('click', onClickOutside, true);
	});
</script>

<div class="notif-wrap">
	<button
		bind:this={triggerEl}
		type="button"
		class="notif-trigger"
		data-testid="notif-trigger"
		aria-haspopup="dialog"
		aria-expanded={open}
		aria-label={triggerLabel}
		onclick={toggle}
	>
		<span class="bell" aria-hidden="true">
			<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" stroke-linecap="round" stroke-linejoin="round" />
				<path d="M13.73 21a2 2 0 0 1-3.46 0" stroke-linecap="round" stroke-linejoin="round" />
			</svg>
		</span>
		<span class="label">{language.current && t('notifications.label')}</span>
		{#if count > 0}
			<span class="count" data-testid="notif-count">{badge}</span>
		{/if}
	</button>

	{#if open}
		<div class="panel" bind:this={panelEl} role="dialog" aria-label={language.current && t('notifications.title')}>
			<div class="panel-head">
				<b>{language.current && t('notifications.title')}</b>
				<button
					type="button"
					class="markread"
					data-testid="notif-markread"
					disabled={count === 0}
					onclick={markRead}
				>{language.current && t('notifications.markAllRead')}</button>
			</div>

			{#if notificationsStore.loading && notificationsStore.recent.length === 0}
				<div class="panel-msg">{language.current && t('common.loading')}</div>
			{:else if notificationsStore.loadError}
				<div class="panel-msg error">{language.current && t('notifications.loadError')}</div>
			{:else if notificationsStore.recent.length === 0}
				<div class="panel-empty">
					<p>{language.current && t('notifications.empty')}</p>
					<a href="/alerting" onclick={(e) => goInternal(e, '/alerting')}>{language.current && t('notifications.emptyCta')}</a>
				</div>
			{:else}
				<ul class="panel-list">
					{#each notificationsStore.recent as ev (ev.eventId)}
						{@const dest = notificationHref(ev)}
						<li class:unread={isUnread(ev)}>
							<a
								href={dest.href}
								target={dest.external ? '_blank' : undefined}
								rel={dest.external ? 'noopener noreferrer' : undefined}
								onclick={dest.external ? close : (e) => goInternal(e, dest.href)}
							>
								<span class="subject">{subjectOf(ev)}</span>
								<span class="meta">{language.current && relativeTime(ev.timestamp)}</span>
							</a>
						</li>
					{/each}
				</ul>
				<div class="panel-foot">
					<a href="/alerting#history" onclick={(e) => goInternal(e, '/alerting#history')}>{language.current && t('notifications.viewAll')}</a>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.notif-wrap { position: relative; }
	.notif-trigger {
		display: flex; align-items: center; gap: 10px; width: 100%;
		padding: 8px 16px; font-size: 13px; color: var(--fg-muted);
		background: none; border: none; cursor: pointer; text-align: left;
	}
	.notif-trigger:hover { color: var(--fg); }
	.bell { position: relative; display: inline-flex; }
	.label { flex: 1; }
	.count {
		background: var(--danger, #d9534f); color: #fff; font-size: 10.5px;
		font-weight: 700; border-radius: 20px; padding: 1px 7px; min-width: 16px;
		text-align: center;
	}
	.panel {
		position: absolute; bottom: 100%; left: 8px; width: 300px;
		background: var(--bg-elevated, #12161d); border: 1px solid var(--border);
		border-radius: 10px; margin-bottom: 8px; z-index: 20; overflow: hidden;
	}
	.panel-head {
		display: flex; align-items: center; justify-content: space-between;
		padding: 10px 14px; border-bottom: 1px solid var(--border);
	}
	.panel-head b { color: var(--fg); font-size: 13.5px; }
	.markread { background: none; border: none; color: var(--accent); font-size: 11px; cursor: pointer; }
	.markread:disabled { color: var(--fg-muted); cursor: default; }
	.panel-list { list-style: none; margin: 0; padding: 0; max-height: 320px; overflow-y: auto; }
	.panel-list li a {
		display: flex; flex-direction: column; gap: 2px; padding: 10px 14px;
		border-bottom: 1px solid var(--border-subtle, #1c222c); text-decoration: none; color: var(--fg-muted);
	}
	.panel-list li.unread a { color: var(--fg); border-left: 2px solid var(--accent); }
	.subject { font-size: 12.5px; color: var(--fg); }
	.meta { font-size: 11px; color: var(--fg-muted); }
	.panel-empty { padding: 18px 14px; text-align: center; font-size: 12.5px; color: var(--fg-muted); }
	.panel-empty a, .panel-foot a { color: var(--accent); font-size: 11.5px; text-decoration: none; }
	.panel-foot { padding: 10px 14px; border-top: 1px solid var(--border); text-align: center; }
	.panel-msg { padding: 14px; font-size: 12px; color: var(--fg-muted); text-align: center; }
	.panel-msg.error { color: var(--danger, #d9534f); }
</style>
