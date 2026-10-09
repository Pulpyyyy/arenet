<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  v2.42 — TCP / UDP services (layer 4).

  The form is deliberately flat: a relay is four things, and folding
  four things behind collapsible sections would add clicks to hide
  what already fits on screen — the opposite mistake to the one the
  route form had. Consistency with the rest of Arenet comes from the
  components (segmented control, switch rows, posture chips), not
  from the presence of sections.

  Two elements are load-bearing and sit next to each other on
  purpose: the PROXY-protocol block, which prints the exact address
  to trust on the backend, and the "test the backends" button. A
  mismatched PROXY setting breaks connections *silently*, so the
  operator needs to be told what to configure and given a way to
  check before they trust the relay.
-->
<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import ModeSelector from '$lib/components/form/ModeSelector.svelte';
	import SwitchRow from '$lib/components/form/SwitchRow.svelte';
	import PostureSentence from '$lib/components/form/PostureSentence.svelte';
	import { serverErrorMessage } from '$lib/api/server-errors';
	import { guardNavigation } from '$lib/utils/navigation-guard';
	import { pushToast } from '$lib/stores/toast';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		listTCPServices,
		createTCPService,
		updateTCPService,
		deleteTCPService,
		testTCPService,
		type TCPService,
		type TCPServiceRequest,
		acceptProtocolsFor,
		REFUSAL_CAUSES,
		type RefusalCause,
		type TCPServiceTestResult,
		tcpServicesMetrics,
		type TCPServiceProtocol,
		type ProxyProtocolVersion,
		type TCPServiceCounters
	} from '$lib/api/tcp-services';
	import TCPFlowDiagram from '$lib/components/tcp/TCPFlowDiagram.svelte';

	function tl(key: string, params?: Record<string, string | number>): string {
		void language.current;
		return t(key, params);
	}

	let services = $state<TCPService[]>([]);
	// v2.42 — the counters. A relay whose traffic nobody can see is a
	// relay nobody watches, so the list carries them next to the name
	// rather than hiding them behind a click.
	let counters = $state<Record<string, TCPServiceCounters>>({});
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	let formOpen = $state(false);
	let editingId = $state<string | null>(null);
	let saving = $state(false);
	let formError = $state<string | null>(null);
	let testResult = $state<TCPServiceTestResult | null>(null);
	let testing = $state(false);
	let confirmDeleteOpen = $state(false);

	// --- form state ---------------------------------------------
	let fName = $state('');
	let fProtocol = $state<TCPServiceProtocol>('tcp');
	let fAcceptProtocol = $state('');
	let fListenAddr = $state('');
	let fListenPort = $state<number | null>(null);
	let fBackendHost = $state('');
	let fBackendPort = $state<number | null>(null);
	let fProxyProtocol = $state<ProxyProtocolVersion>('v2');
	let fCrowdSec = $state(true);
	let fRestrict = $state(false);
	let fCIDRs = $state('');
	let fHealthCheck = $state(false);
	let fDisabled = $state(false);

	// Unsaved changes: the form is snapshotted when it opens, and
	// anything different afterwards is unsaved work. Cancel, picking
	// another row, Add, and leaving the page all dropped it unasked.
	let formSnapshot = $state('');
	function formState(): string {
		return JSON.stringify([
			fName,
			fProtocol,
			fAcceptProtocol,
			fListenAddr,
			fListenPort,
			fBackendHost,
			fBackendPort,
			fProxyProtocol,
			fCrowdSec,
			fRestrict,
			fCIDRs,
			fHealthCheck,
			fDisabled
		]);
	}
	const formDirty = $derived(formOpen && formSnapshot !== '' && formState() !== formSnapshot);

	let confirmDiscardOpen = $state(false);
	let pendingAfterDiscard: (() => void) | null = null;
	function guardUnsaved(action: () => void): void {
		if (formDirty) {
			pendingAfterDiscard = action;
			confirmDiscardOpen = true;
			return;
		}
		action();
	}
	function onConfirmDiscard(): void {
		confirmDiscardOpen = false;
		const action = pendingAfterDiscard;
		pendingAfterDiscard = null;
		action?.();
	}
	// ConfirmDialog's cancel only flips `open`: drop what was armed.
	$effect(() => {
		if (!confirmDiscardOpen) pendingAfterDiscard = null;
	});
	// closeForm() makes formDirty false, so the resumed navigation passes.
	guardNavigation(
		() => formDirty,
		(proceed) =>
			guardUnsaved(() => {
				closeForm();
				proceed();
			})
	);

	const protocolOptions = $derived([
		{ value: 'tcp' as const, label: 'TCP', hint: tl('tcpServices.form.protocolTCPHint'), tone: 'neutral' as const },
		{ value: 'udp' as const, label: 'UDP', hint: tl('tcpServices.form.protocolUDPHint'), tone: 'neutral' as const }
	]);

	// Cause -> i18n key. Named rather than interpolated at the call site
	// so the mapping is in one place and a missing translation shows up
	// as one obvious key instead of a computed string nobody greps for.
	function refusedLabelKey(cause: RefusalCause): string {
		return `tcpServices.refused${cause[0].toUpperCase()}${cause.slice(1)}`;
	}

	// The protocols valid for the chosen transport, plus "anything".
	const acceptProtocolChoices = $derived(acceptProtocolsFor(fProtocol));

	// Switching transport can invalidate the chosen protocol — tls means
	// nothing on a UDP relay. Clearing it here keeps the form from
	// submitting a pair the API refuses, which the operator would read as
	// an unexplained 400.
	$effect(() => {
		if (fAcceptProtocol && !acceptProtocolChoices.includes(fAcceptProtocol)) {
			fAcceptProtocol = '';
		}
	});

	const proxyOptions = $derived([
		{ value: '' as const, label: tl('tcpServices.form.proxyNone'), hint: tl('tcpServices.form.proxyNoneHint'), tone: 'neutral' as const },
		{ value: 'v1' as const, label: 'v1', hint: tl('tcpServices.form.proxyV1Hint'), tone: 'neutral' as const },
		{ value: 'v2' as const, label: 'v2', hint: tl('tcpServices.form.proxyV2Hint'), tone: 'allow' as const }
	]);

	// The two pairings the API refuses, surfaced before the operator
	// presses Save rather than as a 400 afterwards.
	const udpWithV1 = $derived(fProtocol === 'udp' && fProxyProtocol === 'v1');
	const udpWithHealthCheck = $derived(fProtocol === 'udp' && fHealthCheck);

	const relaySentence = $derived(
		fListenPort && fBackendHost && fBackendPort
			? tl('tcpServices.form.relaySentence', {
					protocol: fProtocol.toUpperCase(),
					listen: `${fListenAddr || '0.0.0.0'}:${fListenPort}`,
					backend: `${fBackendHost}:${fBackendPort}`
				})
			: ''
	);

	async function load() {
		loading = true;
		loadError = null;
		try {
			services = await listTCPServices();
			// Counters are a nicety: a failure here must not hide the
			// services themselves.
			counters = await tcpServicesMetrics().catch(() => ({}));
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	}

	// v2.43 — the counters move on their own.
	//
	// Layer-4 traffic appears nowhere else in the UI, so this column
	// is the only way to see that a relay is carrying anything; having
	// to reload the page to find out turned a live view into a
	// snapshot. A tick keeps the last good data on failure and never
	// raises the spinner — a row that blinks every five seconds is
	// worse than a stale number.
	//
	// The idle lock is not at risk: the API client tags a request as
	// background whenever the operator has not interacted since the
	// last reset, and a background request does not push the lock out.
	const REFRESH_MS = 5000;
	let pollId: ReturnType<typeof setInterval> | null = null;

	async function refresh() {
		try {
			const [list, metrics] = await Promise.all([
				listTCPServices(),
				tcpServicesMetrics().catch(() => counters)
			]);
			services = list;
			counters = metrics;
			loadError = null;
		} catch {
			// A tick that fails changes nothing on screen: the previous
			// values stay, and the next tick will correct them.
		}
	}

	function startPolling(): void {
		if (pollId !== null) return;
		pollId = setInterval(() => {
			if (typeof document !== 'undefined' && document.visibilityState !== 'visible') return;
			void refresh();
		}, REFRESH_MS);
	}

	function stopPolling(): void {
		if (pollId !== null) {
			clearInterval(pollId);
			pollId = null;
		}
	}

	onMount(() => {
		void load();
		startPolling();
	});

	onDestroy(stopPolling);

	function resetForm() {
		fName = '';
		fProtocol = 'tcp';
		fAcceptProtocol = '';
		fListenAddr = '';
		fListenPort = null;
		fBackendHost = '';
		fBackendPort = null;
		fProxyProtocol = 'v2';
		fCrowdSec = true;
		fRestrict = false;
		fCIDRs = '';
		fHealthCheck = false;
		fDisabled = false;
		formError = null;
		testResult = null;
	}

	function openCreate() {
		resetForm();
		editingId = null;
		formOpen = true;
		formSnapshot = formState();
	}

	function closeForm() {
		formOpen = false;
	}

	function openEdit(svc: TCPService) {
		resetForm();
		editingId = svc.id;
		fName = svc.name;
		fProtocol = svc.protocol ?? 'tcp';
		fAcceptProtocol = svc.acceptProtocol ?? '';
		fListenAddr = svc.listenAddr ?? '';
		fListenPort = svc.listenPort;
		fBackendHost = svc.upstreams[0]?.host ?? '';
		fBackendPort = svc.upstreams[0]?.port ?? null;
		fProxyProtocol = svc.proxyProtocol ?? '';
		fCrowdSec = svc.crowdSecEnabled ?? false;
		fRestrict = svc.ipFilter?.mode === 'allow';
		fCIDRs = (svc.ipFilter?.cidrs ?? []).join(', ');
		fHealthCheck = svc.healthCheck?.enabled ?? false;
		fDisabled = svc.disabled ?? false;
		formOpen = true;
		formSnapshot = formState();
	}

	function buildPayload(): TCPServiceRequest {
		const cidrs = fCIDRs
			.split(/[,\n]/)
			.map((c) => c.trim())
			.filter((c) => c !== '');
		return {
			name: fName.trim(),
			protocol: fProtocol,
			// Every field of this payload is rebuilt by hand, so a new
			// one that is not listed here is silently dropped on save
			// with a success toast — that is how the v2.46 path
			// redirect was lost. See the buildPayload test.
			acceptProtocol: fAcceptProtocol || undefined,
			listenAddr: fListenAddr.trim(),
			listenPort: fListenPort ?? 0,
			upstreams: [{ host: fBackendHost.trim(), port: fBackendPort ?? 0 }],
			proxyProtocol: fProxyProtocol,
			crowdSecEnabled: fCrowdSec,
			ipFilter: fRestrict ? { mode: 'allow', cidrs } : undefined,
			healthCheck: fHealthCheck ? { enabled: true } : undefined,
			disabled: fDisabled
		};
	}

	async function save() {
		saving = true;
		formError = null;
		try {
			if (editingId) {
				await updateTCPService(editingId, buildPayload());
			} else {
				await createTCPService(buildPayload());
			}
			pushToast(tl('tcpServices.saved'), 'success');
			formOpen = false;
			await load();
		} catch (err) {
			formError = serverErrorMessage(err);
		} finally {
			saving = false;
		}
	}

	async function runTest() {
		if (!editingId) return;
		testing = true;
		testResult = null;
		try {
			testResult = await testTCPService(editingId);
		} catch (err) {
			formError = serverErrorMessage(err);
		} finally {
			testing = false;
		}
	}

	async function confirmDelete() {
		if (!editingId) return;
		try {
			await deleteTCPService(editingId);
			pushToast(tl('tcpServices.deleted'), 'success');
			confirmDeleteOpen = false;
			formOpen = false;
			await load();
		} catch (err) {
			formError = serverErrorMessage(err);
			confirmDeleteOpen = false;
		}
	}

	// Bytes in a shape an operator reads at a glance rather than
	// counting digits.
	function formatBytes(n: number): string {
		if (n < 1024) return `${n} B`;
		const units = ['kB', 'MB', 'GB', 'TB'];
		let value = n / 1024;
		let unit = 0;
		while (value >= 1024 && unit < units.length - 1) {
			value /= 1024;
			unit++;
		}
		return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
	}

	function listenOf(svc: TCPService): string {
		return `${svc.protocol === 'udp' ? 'udp' : 'tcp'}/${svc.listenAddr || '0.0.0.0'}:${svc.listenPort}`;
	}
</script>

<svelte:head>
	<title>{language.current && t('tcpServices.headTitle')}</title>
</svelte:head>

<PageHeader
	eyebrow={tl('tcpServices.eyebrow')}
	title={tl('tcpServices.title')}
	subtitle={tl('tcpServices.subtitle')}
>
	{#snippet actions()}
		<Button onclick={() => guardUnsaved(openCreate)}>{tl('tcpServices.addButton')}</Button>
	{/snippet}
</PageHeader>

{#if loading}
	<div class="flex justify-center mt-12"><Spinner size="lg" /></div>
{:else if loadError}
	<div class="rounded-md border border-border-subtle bg-elevated p-4 text-sm text-down" data-testid="tcp-load-error">
		{loadError}
	</div>
{:else}
	<!-- v2.42.1 — with nothing configured there is no list to sit
	     beside, so the empty state takes the whole width instead of
	     being squeezed into the column a future list would occupy.
	     It also gets the diagram: the sentence says a relay forwards
	     bytes without reading them, the drawing shows what that
	     means next to an HTTP route. -->
	{#if services.length === 0 && !formOpen}
		<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden mt-6">
			<EmptyState
				testid="tcp-empty"
				title={tl('tcpServices.emptyTitle')}
				body={tl('tcpServices.emptyBody')}
				actionLabel={tl('tcpServices.addButton')}
				onAction={() => guardUnsaved(openCreate)}
			>
				<TCPFlowDiagram
					labels={{
						client: tl('tcpServices.diagram.client'),
						service: tl('tcpServices.diagram.service'),
						backend: tl('tcpServices.diagram.backend'),
						serviceNote: tl('tcpServices.diagram.serviceNote'),
						proxyNote: tl('tcpServices.diagram.proxyNote')
					}}
				/>
			</EmptyState>
		</div>
	{:else}
	<div class="split mt-6" class:split-open={formOpen} style="--split-open-cols: 1.2fr 1fr">
		<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden">
			{#if services.length === 0}
				<EmptyState
					testid="tcp-empty-compact"
					title={tl('tcpServices.emptyTitle')}
					body={tl('tcpServices.emptyBody')}
				/>
			{:else}
				<table class="w-full text-sm">
					<thead>
						<tr class="text-left text-xs uppercase tracking-wide text-muted">
							<th class="px-4 py-3 font-medium">{tl('tcpServices.colName')}</th>
							<th class="px-4 py-3 font-medium">{tl('tcpServices.colListen')}</th>
							<th class="px-4 py-3 font-medium">{tl('tcpServices.colBackend')}</th>
							<th class="px-4 py-3 font-medium">{tl('tcpServices.colGuards')}</th>
							<th class="px-4 py-3 font-medium">{tl('tcpServices.colTraffic')}</th>
							<th class="px-4 py-3 font-medium" title={tl('tcpServices.refusedTooltip')}
								>{tl('tcpServices.colRefused')}</th
							>
						</tr>
					</thead>
					<tbody>
						{#each services as svc (svc.id)}
							<tr
								class="border-t border-border-subtle cursor-pointer hover:bg-hover"
								class:opacity-50={svc.disabled}
								data-testid="tcp-row-{svc.id}"
								onclick={() => guardUnsaved(() => openEdit(svc))}
								onkeydown={(e) => {
									if (e.key === 'Enter' || e.key === ' ') {
										e.preventDefault();
										guardUnsaved(() => openEdit(svc));
									}
								}}
								tabindex="0"
								role="button"
							>
								<td class="px-4 py-3 font-mono">{svc.name}</td>
								<td class="px-4 py-3 font-mono text-secondary">{listenOf(svc)}</td>
								<td class="px-4 py-3 font-mono text-secondary">
									{svc.upstreams[0]?.host}:{svc.upstreams[0]?.port}{svc.upstreams.length > 1
										? ` (+${svc.upstreams.length - 1})`
										: ''}
								</td>
								<td class="px-4 py-3">
									<div class="flex flex-wrap gap-1">
										{#if svc.proxyProtocol}
											<Badge variant="status-up">proxy {svc.proxyProtocol}</Badge>
										{/if}
										{#if svc.crowdSecEnabled}
											<Badge variant="status-down">crowdsec</Badge>
										{/if}
										{#if svc.ipFilter?.mode === 'allow'}
											<Badge variant="status-up"
												>{tl('tcpServices.badgeIPAllow', { count: svc.ipFilter.cidrs?.length ?? 0 })}</Badge
											>
										{:else if svc.ipFilter?.mode === 'deny'}
											<Badge variant="status-down"
												>{tl('tcpServices.badgeIPDeny', { count: svc.ipFilter.cidrs?.length ?? 0 })}</Badge
											>
										{/if}
										{#if svc.disabled}
											<Badge variant="neutral">{tl('tcpServices.badgeDisabled')}</Badge>
										{/if}
									</div>
								</td>
								<td class="px-4 py-3 font-mono text-xs text-secondary" data-testid="tcp-traffic-{svc.id}">
									{#if counters[svc.id]}
										{@const c = counters[svc.id]}
										<span class="text-primary">{c.connections}</span>
										{tl('tcpServices.connShort')}
										{#if c.active > 0}
											<span class="text-up">· {c.active} {tl('tcpServices.activeShort')}</span>
										{/if}
										{#if c.errors > 0}
											<span class="text-down">· {c.errors} {tl('tcpServices.errShort')}</span>
										{/if}
										<div class="text-muted">{formatBytes(c.bytesIn)} ↓ · {formatBytes(c.bytesOut)} ↑</div>
									{:else}
										<span class="text-muted">—</span>
									{/if}
								</td>
								<!--
								  v2.49 — refusals, per cause.
								  Until now a connection closed by CrowdSec, the source
								  filter or (new) the protocol gate incremented nothing
								  anywhere: the metrics handler lives in the relay chain,
								  which a refused connection never reaches. The operator
								  could not tell a relay that was protecting them from one
								  whose protection was off. Hence a column, not a tooltip.
								-->
								<td class="px-4 py-3 font-mono text-xs" data-testid="tcp-refused-{svc.id}">
									{#if counters[svc.id]}
										{@const refused = counters[svc.id].refused ?? {}}
										{#if Object.keys(refused).length > 0}
											<div class="flex flex-col gap-0.5">
												{#each REFUSAL_CAUSES as cause (cause)}
													{#if refused[cause]}
														<span class="text-down"
															>{refused[cause]}
															<span class="text-muted">{tl(refusedLabelKey(cause))}</span></span
														>
													{/if}
												{/each}
											</div>
										{:else}
											<span class="text-muted">{tl('tcpServices.refusedNone')}</span>
										{/if}
									{:else}
										<span class="text-muted">—</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		{#if formOpen}
			<div class="rounded-lg border border-border-subtle bg-elevated" data-testid="tcp-form">
				<div class="px-5 py-4 border-b border-border-subtle">
					<h3 class="text-base font-semibold text-primary">
						{editingId ? tl('tcpServices.form.titleEdit') : tl('tcpServices.form.titleNew')}
					</h3>
				</div>

				<form
					class="flex flex-col gap-4 p-5"
					onsubmit={(e) => {
						e.preventDefault();
						save();
					}}
				>

					<div class="grid gap-3 sm:grid-cols-2">
						<div>
							<label for="tcp-name" class="text-sm font-medium text-secondary block mb-1"
								>{tl('tcpServices.form.name')}</label
							>
							<input
								id="tcp-name"
								bind:value={fName}
								class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
							/>
						</div>
						<div>
							<label for="tcp-listen-port" class="text-sm font-medium text-secondary block mb-1"
								>{tl('tcpServices.form.listenPort')}</label
							>
							<input
								id="tcp-listen-port"
								type="number"
								min="1"
								max="65535"
								bind:value={fListenPort}
								class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
							/>
						</div>
						<div>
							<label for="tcp-listen-addr" class="text-sm font-medium text-secondary block mb-1"
								>{tl('tcpServices.form.listenAddr')}</label
							>
							<input
								id="tcp-listen-addr"
								bind:value={fListenAddr}
								placeholder="0.0.0.0"
								class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
							/>
						</div>
						<div class="grid grid-cols-[1fr_90px] gap-2">
							<div>
								<label for="tcp-backend-host" class="text-sm font-medium text-secondary block mb-1"
									>{tl('tcpServices.form.backend')}</label
								>
								<input
									id="tcp-backend-host"
									bind:value={fBackendHost}
									placeholder="10.20.0.5"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>
							<div>
								<label for="tcp-backend-port" class="text-sm font-medium text-secondary block mb-1"
									>{tl('tcpServices.form.port')}</label
								>
								<input
									id="tcp-backend-port"
									type="number"
									min="1"
									max="65535"
									bind:value={fBackendPort}
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
								/>
							</div>
						</div>
					</div>

					<div class="flex flex-col gap-2">
						<span class="text-sm font-medium text-secondary">{tl('tcpServices.form.protocol')}</span>
						<ModeSelector id="tcp-protocol" bind:value={fProtocol} options={protocolOptions} ariaLabel={tl('tcpServices.form.protocol')} />
					</div>

					<div class="flex flex-col gap-2">
						<span class="text-sm font-medium text-secondary"
							>{tl('tcpServices.form.acceptProtocol')}</span
						>
						<select
							id="tcp-accept-protocol"
							bind:value={fAcceptProtocol}
							aria-label={tl('tcpServices.form.acceptProtocol')}
							data-testid="tcp-accept-protocol"
							class="h-9 rounded-md border border-border-subtle bg-surface px-2 text-sm text-primary"
						>
							<option value="">{tl('tcpServices.form.acceptProtocolAny')}</option>
							{#each acceptProtocolChoices as proto (proto)}
								<option value={proto}>{proto}</option>
							{/each}
						</select>
						<span class="text-xs text-muted">{tl('tcpServices.form.acceptProtocolHint')}</span>
					</div>

					{#if relaySentence}
						<PostureSentence posture="allow" testid="tcp-relay-sentence">{relaySentence}</PostureSentence>
					{/if}

					<div class="flex flex-col gap-2">
						<span class="text-sm font-medium text-secondary"
							>{tl('tcpServices.form.proxyProtocol')}</span
						>
						<ModeSelector id="tcp-proxy" bind:value={fProxyProtocol} options={proxyOptions} ariaLabel={tl('tcpServices.form.proxyProtocol')} />
						{#if fProxyProtocol}
							<div
								class="rounded-md border border-border-subtle border-l-[3px] border-l-warn bg-surface p-3 text-xs text-secondary leading-relaxed"
								data-testid="tcp-proxy-callout"
							>
								{tl('tcpServices.form.proxyCallout')}
							</div>
						{/if}
						{#if udpWithV1}
							<p class="text-xs text-down" data-testid="tcp-udp-v1-warning">
								{tl('tcpServices.form.udpV1Refused')}
							</p>
						{/if}
					</div>

					<SwitchRow
						checked={fCrowdSec}
						onchange={(v) => (fCrowdSec = v)}
						label={tl('tcpServices.form.crowdsec')}
						helper={tl('tcpServices.form.crowdsecHelper')}
						testid="tcp-crowdsec"
					/>

					<SwitchRow
						checked={fRestrict}
						onchange={(v) => (fRestrict = v)}
						label={tl('tcpServices.form.restrict')}
						helper={tl('tcpServices.form.restrictHelper')}
						testid="tcp-restrict"
					/>
					{#if fRestrict}
						<div>
							<label for="tcp-cidrs" class="text-sm font-medium text-secondary block mb-1"
								>{tl('tcpServices.form.cidrs')}</label
							>
							<textarea
								id="tcp-cidrs"
								rows="2"
								bind:value={fCIDRs}
								placeholder="192.168.1.0/24, 10.0.0.0/8"
								class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary font-mono"
							></textarea>
						</div>
					{/if}

					<SwitchRow
						checked={fHealthCheck}
						onchange={(v) => (fHealthCheck = v)}
						label={tl('tcpServices.form.healthCheck')}
						helper={tl('tcpServices.form.healthCheckHelper')}
						disabled={fProtocol === 'udp'}
						testid="tcp-healthcheck"
					/>
					{#if udpWithHealthCheck}
						<p class="text-xs text-down" data-testid="tcp-udp-hc-warning">
							{tl('tcpServices.form.udpHealthCheckRefused')}
						</p>
					{/if}

					<SwitchRow
						checked={fDisabled}
						onchange={(v) => (fDisabled = v)}
						label={tl('tcpServices.form.disabled')}
						helper={tl('tcpServices.form.disabledHelper')}
						testid="tcp-disabled"
					/>

					<p class="text-xs text-muted" data-testid="tcp-not-applicable">
						{tl('tcpServices.form.notApplicable')}
					</p>

					{#if editingId}
						<div class="flex items-center gap-2">
							<Button variant="secondary" size="sm" onclick={runTest} loading={testing} type="button"
								>{tl('tcpServices.form.testButton')}</Button
							>
						</div>
						{#if testResult}
							<div class="rounded-md border border-border-subtle bg-surface p-3 text-xs" data-testid="tcp-test-result">
								{#each testResult.backends as b (b.backend)}
									<div class="flex flex-wrap items-center gap-2 py-0.5">
										{#if b.skipped}
											<span class="text-muted">–</span>
										{:else}
											<span class:text-up={b.ok} class:text-down={!b.ok}>{b.ok ? '✓' : '✕'}</span>
										{/if}
										<span class="font-mono text-primary">{b.backend}</span>
										{#if b.skipped}
											<span class="text-muted">{tl('tcpServices.form.testSkipped')}</span>
										{:else}
											<span class="text-muted">{b.ok ? `${b.elapsedMs} ms` : b.error}</span>
										{/if}
										<!-- v2.43 — the verdict on the pairing, which is the
										     question a dial never answered. -->
										{#if b.proxyProtocol === 'not-refused'}
											<Badge variant="status-up">{tl('tcpServices.form.testProxyNotRefused')}</Badge>
										{:else if b.proxyProtocol === 'refused'}
											<Badge variant="status-down">{tl('tcpServices.form.testProxyRefused')}</Badge>
										{/if}
									</div>
									{#if b.skipped && (b.errorCode || b.error)}
										<!-- v2.46 — translated when the code is known,
										     the server's sentence otherwise. -->
										<p class="text-muted pb-1 pl-5">
											{b.errorCode
												? tl(`tcpServices.form.${b.errorCode}`)
												: b.error}
										</p>
									{/if}
								{/each}
								{#if testResult.backends.some((b) => b.proxyProtocol)}
									<p class="text-muted mt-2">{tl('tcpServices.form.testProxyExplain')}</p>
								{/if}
								{#if testResult.proxyProtocolVersion}
									<p class="text-muted mt-2">
										{tl('tcpServices.form.proxyNote', {
											version: testResult.proxyProtocolVersion
										})}
									</p>
								{:else if testResult.proxyProtocolNote}
									<p class="text-muted mt-2">{testResult.proxyProtocolNote}</p>
								{/if}
							</div>
						{/if}
					{/if}

					{#if formError}
						<p class="text-sm text-down" data-testid="tcp-form-error">{formError}</p>
					{/if}

					<div class="flex items-center justify-between border-t border-border-subtle pt-4">
						{#if editingId}
							<Button variant="ghost" type="button" onclick={() => (confirmDeleteOpen = true)}
								>{tl('tcpServices.form.delete')}</Button
							>
						{:else}
							<span></span>
						{/if}
						<div class="flex gap-2">
							<Button variant="ghost" type="button" onclick={() => guardUnsaved(closeForm)}
								>{tl('tcpServices.form.cancel')}</Button
							>
							<Button type="submit" loading={saving}>{tl('tcpServices.form.save')}</Button>
						</div>
					</div>
				</form>
			</div>
		{/if}
	</div>
	{/if}
{/if}

<ConfirmDialog
	bind:open={confirmDiscardOpen}
	title={tl('tcpServices.discardDialog.title')}
	message={tl('tcpServices.discardDialog.message')}
	confirmLabel={tl('tcpServices.discardDialog.confirmLabel')}
	cancelLabel={tl('tcpServices.discardDialog.cancelLabel')}
	confirmVariant="danger"
	onConfirm={onConfirmDiscard}
/>

<ConfirmDialog
	bind:open={confirmDeleteOpen}
	title={tl('tcpServices.deleteDialog.title')}
	message={tl('tcpServices.deleteDialog.message')}
	confirmLabel={tl('tcpServices.deleteDialog.confirm')}
	cancelLabel={tl('tcpServices.deleteDialog.cancel')}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>

<style>
	/* v2.48 — the table owns the page until something is selected.
	   
	   The split was fixed at two columns, so the list sat squeezed
	   into 55% of the width even with nothing open beside it — every
	   column truncated for a panel that was not there.
	   
	   Both tracks always exist; the second animates between 0fr and
	   1fr. That is what makes the transition possible at all:
	   grid-template-columns interpolates when the two sides have the
	   same structure, which swapping between one and two tracks does
	   not. The collapsed track needs overflow hidden and min-width 0
	   or its content refuses to shrink below its intrinsic size and
	   the animation fights itself. */
	.split {
		display: grid;
		grid-template-columns: 1fr;
		gap: 1rem;
		align-items: start;
	}
	@media (min-width: 1280px) {
		.split {
			grid-template-columns: 1fr 0fr;
			transition: grid-template-columns 260ms ease;
		}
		.split.split-open {
			grid-template-columns: var(--split-open-cols, 1.3fr 1fr);
		}
		.split > * {
			min-width: 0;
			overflow: hidden;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.split {
			transition: none;
		}
	}
</style>
