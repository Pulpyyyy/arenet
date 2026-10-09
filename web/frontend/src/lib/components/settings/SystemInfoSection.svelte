<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.45 — the host under Arenet, live.

  The Settings → System tab said how Arenet was and nothing about the
  machine it runs on, so an operator watching a relay slow down had no
  way to tell from Arenet whether the host was out of memory, out of
  CPU or out of disk.

  Two things this panel is careful about.

  It never shows a figure without saying where it came from. In a
  container /proc reports the HOST, so a 512 MiB container would
  otherwise display the host's 64 GiB — literally correct, and useless
  to whoever is working out why Arenet keeps being OOM-killed. When a
  cgroup limit exists it is the one shown, badged "container", with the
  machine's own core count kept beside it so a quota reads as the
  restriction it is rather than as a smaller machine.

  And it leaves a figure blank rather than inventing it. CPU usage is a
  rate: the first reading after a restart has no baseline, so it shows
  a dash until the second tick.
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import { getSystemInfo, type SystemInfo } from '$lib/api/system';
	import { formatBytes } from '$lib/utils/format';

	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	let info = $state<SystemInfo | null>(null);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	// Live, like the layer-4 counters: a supervision panel that only
	// moves when you reload is a screenshot. Same cadence, and the
	// same reason the idle lock is safe — the API client tags a call
	// as background whenever the operator has not interacted since the
	// last reset, and a background call does not push the lock out.
	const REFRESH_MS = 5000;
	let pollId: ReturnType<typeof setInterval> | null = null;

	async function load(first = false) {
		try {
			info = await getSystemInfo();
			loadError = null;
		} catch (err) {
			// Only the first failure is worth showing: a tick that
			// fails leaves the previous reading on screen rather than
			// blanking a panel the operator is watching.
			if (first) loadError = err instanceof Error ? err.message : String(err);
		} finally {
			if (first) loading = false;
		}
	}

	onMount(() => {
		void load(true);
		pollId = setInterval(() => {
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
			void load();
		}, REFRESH_MS);
	});

	onDestroy(() => {
		if (pollId !== null) clearInterval(pollId);
	});

	// A missing or zero reading is "not reported", not an empty host.
	function sizeOrDash(n?: number): string {
		return n ? formatBytes(n) : '—';
	}

	function formatUptime(seconds?: number): string {
		if (!seconds) return '—';
		const d = Math.floor(seconds / 86400);
		const h = Math.floor((seconds % 86400) / 3600);
		const m = Math.floor((seconds % 3600) / 60);
		if (d > 0) return tl('system.uptimeDays', { days: d, hours: h });
		if (h > 0) return tl('system.uptimeHours', { hours: h, minutes: m });
		return tl('system.uptimeMinutes', { minutes: m });
	}

	function percent(used?: number, total?: number): number | null {
		if (!used || !total) return null;
		return Math.min(100, Math.round((used / total) * 100));
	}

	const memoryPct = $derived(percent(info?.memory.usedBytes, info?.memory.totalBytes));
	const diskPct = $derived(percent(info?.disk.usedBytes, info?.disk.totalBytes));
	const cpuPct = $derived(info?.cpu.usagePercent != null ? Math.round(info.cpu.usagePercent) : null);

	// A bar turns amber then red as it fills. The thresholds are the
	// ones an operator acts on: 75% is "watch it", 90% is "do
	// something today".
	function tone(pct: number | null): string {
		if (pct === null) return 'bg-border-default';
		if (pct >= 90) return 'bg-down';
		if (pct >= 75) return 'bg-warn';
		return 'bg-up';
	}
</script>

<Card padding="p-6">
	<header class="border-b border-border-subtle pb-3 mb-4 flex items-center gap-3 flex-wrap">
		<h2 class="text-xl font-semibold">{tl('system.title')}</h2>
		{#if info?.host.containerised}
			<!-- Named up front: it changes how every figure below must
			     be read. -->
			<Badge variant="status-info">{tl('system.container')}</Badge>
		{/if}
	</header>

	{#if loading}
		<Spinner />
	{:else if loadError}
		<p class="text-sm text-down" data-testid="system-info-error">{loadError}</p>
	{:else if info}
		{#if info.unsupported}
			<p class="text-sm text-muted mb-4" data-testid="system-info-unsupported">
				{info.unsupported}
			</p>
		{/if}

		<div class="grid gap-4 sm:grid-cols-3" data-testid="system-info">
			<!-- CPU -->
			<div class="rounded-md border border-border-subtle bg-surface p-3">
				<div class="flex items-baseline justify-between mb-1">
					<span class="text-sm text-secondary">{tl('system.cpu')}</span>
					<span class="font-mono text-lg text-primary" data-testid="system-cpu-usage"
						>{cpuPct === null ? '—' : `${cpuPct}%`}</span
					>
				</div>
				<div class="h-1.5 rounded-full bg-border-subtle overflow-hidden mb-2">
					<div class="h-full {tone(cpuPct)}" style="width: {cpuPct ?? 0}%"></div>
				</div>
				<div class="text-xs text-muted" data-testid="system-cpu-cores">
					{#if info.cpu.source === 'container' && info.cpu.hostCores}
						{tl('system.coresLimited', {
							cores: info.cpu.cores ?? 0,
							hostCores: info.cpu.hostCores
						})}
					{:else}
						{tl('system.cores', { cores: info.cpu.cores ?? 0 })}
					{/if}
				</div>
				<div class="text-xs text-muted">
					{tl('system.load')}
					<span class="font-mono"
						>{info.cpu.load1 ?? 0} · {info.cpu.load5 ?? 0} · {info.cpu.load15 ?? 0}</span
					>
				</div>
				{#if info.cpu.model}
					<div class="text-xs text-muted mt-1 truncate" title={info.cpu.model}>
						{info.cpu.model}
					</div>
				{/if}
			</div>

			<!-- Memory -->
			<div class="rounded-md border border-border-subtle bg-surface p-3">
				<div class="flex items-baseline justify-between mb-1">
					<span class="text-sm text-secondary">{tl('system.memory')}</span>
					<span class="font-mono text-lg text-primary" data-testid="system-memory-usage"
						>{memoryPct === null ? '—' : `${memoryPct}%`}</span
					>
				</div>
				<div class="h-1.5 rounded-full bg-border-subtle overflow-hidden mb-2">
					<div class="h-full {tone(memoryPct)}" style="width: {memoryPct ?? 0}%"></div>
				</div>
				<div class="text-xs text-muted" data-testid="system-memory-detail">
					{tl('system.usedOfTotal', {
						used: sizeOrDash(info.memory.usedBytes),
						total: sizeOrDash(info.memory.totalBytes)
					})}
				</div>
				<!-- Which ceiling this is: the container's, or the
				     machine's. Without it the number can mislead. -->
				<div class="text-xs text-muted" data-testid="system-memory-source">
					{info.memory.source === 'container'
						? tl('system.sourceContainer')
						: tl('system.sourceHost')}
				</div>
			</div>

			<!-- Disk -->
			<div class="rounded-md border border-border-subtle bg-surface p-3">
				<div class="flex items-baseline justify-between mb-1">
					<span class="text-sm text-secondary">{tl('system.disk')}</span>
					<span class="font-mono text-lg text-primary" data-testid="system-disk-usage"
						>{diskPct === null ? '—' : `${diskPct}%`}</span
					>
				</div>
				<div class="h-1.5 rounded-full bg-border-subtle overflow-hidden mb-2">
					<div class="h-full {tone(diskPct)}" style="width: {diskPct ?? 0}%"></div>
				</div>
				<div class="text-xs text-muted">
					{tl('system.freeOfTotal', {
						free: sizeOrDash(info.disk.availableBytes),
						total: sizeOrDash(info.disk.totalBytes)
					})}
				</div>
				<!-- The data directory, not "/": the database, the
				     backups and the logs all live there. -->
				<div class="text-xs text-muted truncate" title={info.disk.path ?? ''}>
					{info.disk.path ?? '—'}
				</div>
			</div>
		</div>

		<dl class="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm mt-5">
			<dt class="text-secondary">{tl('system.hostname')}</dt>
			<dd class="text-primary font-mono" data-testid="system-hostname">
				{info.host.hostname || '—'}
			</dd>
			<dt class="text-secondary">{tl('system.os')}</dt>
			<dd class="text-primary">{info.host.os || '—'}</dd>
			<dt class="text-secondary">{tl('system.kernel')}</dt>
			<dd class="text-primary font-mono">{info.host.kernel || '—'} · {info.host.arch || '—'}</dd>
			<dt class="text-secondary">{tl('system.hostUptime')}</dt>
			<dd class="text-primary">{formatUptime(info.host.uptimeSeconds)}</dd>

			<dt class="text-secondary pt-2 border-t border-border-subtle">{tl('system.arenetUptime')}</dt>
			<dd class="text-primary pt-2 border-t border-border-subtle">
				{formatUptime(info.process.uptimeSeconds)}
			</dd>
			<dt class="text-secondary">{tl('system.arenetMemory')}</dt>
			<dd class="text-primary font-mono" data-testid="system-process-memory">
				{sizeOrDash(info.process.residentBytes || info.process.heapBytes)}
			</dd>
			<dt class="text-secondary">{tl('system.goroutines')}</dt>
			<dd class="text-primary font-mono">{info.process.goroutines ?? '—'}</dd>
		</dl>
	{/if}
</Card>
