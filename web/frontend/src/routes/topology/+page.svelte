<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topology v2 — Phase 2.

  Phase 1 shipped the canvas + sidebar + view toggle against a
  static mock. Phase 2 replaces the mock import with a live data
  feed: fetchSnapshot on mount, then connectLiveStream subscribes
  to the WS push at /api/v1/topology/stream (default 2 s emit
  cadence, configurable via ARENET_TOPOLOGY_TICK_MS on the
  server).

  States:
    - loading       initial fetch in flight (centered spinner)
    - error         fetch failed (message + manual retry button)
    - connected     snapshot loaded, WS open or reconnecting
                    (canvas + sidebar render normally)

  The view toggle swaps between protocol and service-to-backend
  layouts; both consume the same `routes` state. WS ticks rebuild
  the graph in place — Svelte Flow keeps drag positions because
  the layout builders emit stable, deterministic node ids per
  route. Reconnect attempts run silently in the background with
  the backoff schedule documented in _api.ts; while disconnected the
  canvas is dimmed, its particles stop, and the toolbar indicator
  (role="status") gives the time of the last update.
-->
<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { SvelteFlow, Background, Controls, ControlButton, useSvelteFlow, type NodeTypes, type EdgeTypes, type Node, type Edge } from '@xyflow/svelte';
	import '@xyflow/svelte/dist/style.css';

	import { buildTopologyGraph } from './_layout';
	import { collapsedRoutes } from './_collapsed.svelte';
	import type { TopologyRoute } from './_types';
	import { fetchSnapshot, connectLiveStream, TopologyFetchError } from './_api';
	import { filterForView, type TopoView } from './_view';

	// Custom node components — one per `kind` emitted by the layout builder.
	import FQDNNode from './_components/nodes/FQDNNode.svelte';
	import AliasNode from './_components/nodes/AliasNode.svelte';
	import RouteGroupNode from './_components/nodes/RouteGroupNode.svelte';
	import CaddyHubNode from './_components/nodes/CaddyHubNode.svelte';
	import BackendClusterNode from './_components/nodes/BackendClusterNode.svelte';
	import UpstreamNode from './_components/nodes/UpstreamNode.svelte';
	import PathSectionHeaderNode from './_components/nodes/PathSectionHeaderNode.svelte';
	import AnimatedFlowEdge from './_components/edges/AnimatedFlowEdge.svelte';
	import FlowApiBridge from './_components/FlowApiBridge.svelte';

	// Page-level UI
	import TopologySidebar from './_components/TopologySidebar.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Button from '$lib/components/Button.svelte';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';

	type FlowApi = ReturnType<typeof useSvelteFlow<Node, Edge>>;

	// Phase 3.c: 'route-group' must come FIRST so SvelteFlow's
	// component lookup matches the order we emit nodes in. The
	// container needs to render BEHIND the FQDN + alias cards;
	// _layout.ts enforces array order (route-group emitted first
	// per route).
	const nodeTypes: NodeTypes = {
		'route-group': RouteGroupNode,
		fqdn: FQDNNode,
		alias: AliasNode,
		caddy: CaddyHubNode,
		'backend-cluster': BackendClusterNode,
		upstream: UpstreamNode,
		'path-section-header': PathSectionHeaderNode,
	};

	const edgeTypes: EdgeTypes = {
		'animated-flow': AnimatedFlowEdge,
	};

	// Graph state. routes is the live data; nodes/edges are the
	// builder output. C6b-i collapsed the two-view design into a
	// single buildTopologyGraph call — no view toggle, no second
	// canvas mode.
	let routes = $state<TopologyRoute[]>([]);

	// v2.61 — the canvas splits by what a route DOES, because mixing
	// the two made both harder to read: proxying routes carry a
	// backend pool worth watching, redirecting routes carry a
	// destination and nothing to watch. An instance with many
	// redirects drowned its own backends.
	//
	// 'proxy' is the default: it is the half with health, traffic and
	// latency — the half an operator opens this page to look at.
	// TopoView / filterForView live in ./_view so the test can import
	// the real thing instead of restating it — see the module comment.
	let topoView = $state<TopoView>('proxy');

	// The counts on the selector labels. Read from the TEMPLATE, where
	// a derived is exactly right.
	const proxyRoutes = $derived(routes.filter((r) => !r.redirectTarget));
	const redirectRoutes = $derived(routes.filter((r) => !!r.redirectTarget));

	// v2.61.1 — a PLAIN function, not a $derived, because the graph
	// rebuild happens inside untrack() and reading a derived in there
	// is the bug this replaces: untrack suppresses the machinery that
	// marks a derived dirty, so the effect could be handed the
	// PREVIOUS view's list. The symptom was nodes vanishing on a view
	// switch and reappearing ~2s later when the next WebSocket frame
	// rebuilt with the correct set.
	//
	// Taking `routes` as a parameter also keeps the effect from
	// registering it as a dependency, which is what the untrack was
	// there to prevent in the first place: the WS handler owns the
	// per-frame rebuild, and an effect that also fired on every frame
	// would rebuild the graph twice a tick.
	let nodes = $state.raw([] as ReturnType<typeof buildTopologyGraph>['nodes']);
	let edges = $state.raw([] as ReturnType<typeof buildTopologyGraph>['edges']);

	// Page-status state. 'loading' shows the centered spinner;
	// 'error' shows the error panel + retry button; 'connected'
	// shows the canvas.
	type PageStatus = 'loading' | 'error' | 'connected';
	let pageStatus = $state<PageStatus>('loading');
	let pageError = $state<string>('');

	// Live indicator — 'connecting' until the first frame arrives,
	// 'live' while frames do, 'reconnecting' after the stream dropped.
	//
	// It used to START as 'reconnecting', so every page load said
	// "reconnecting" for the moment before the first frame: a claim
	// that something had broken when nothing had connected yet.
	type LiveStatus = 'connecting' | 'live' | 'reconnecting';
	let liveStatus = $state<LiveStatus>('connecting');

	// When the data on the canvas was last refreshed (client clock,
	// ms) — the snapshot, then each live frame. Shown once the stream
	// drops, so the operator knows how old the picture is.
	let lastUpdateMs = $state<number | null>(null);

	// A dropped stream used to change one toolbar dot and nothing
	// else: the particles kept flowing at the last rates and the
	// graph looked live. While stale the canvas is dimmed and the
	// particles hidden (see .canvas-frame.is-stale), and the
	// indicator states the time of the last update.
	const isStale = $derived(liveStatus === 'reconnecting');

	function formatClock(ms: number, lang: string): string {
		return new Intl.DateTimeFormat(lang, {
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit'
		}).format(new Date(ms));
	}

	const liveLabel = $derived.by(() => {
		const lang = language.current;
		if (liveStatus === 'live') return t('topology.liveLive');
		if (liveStatus === 'connecting') return t('topology.liveConnecting');
		if (lastUpdateMs === null) return t('topology.liveReconnecting');
		return `${t('topology.liveReconnecting')} · ${t('topology.liveLastUpdate', {
			time: formatClock(lastUpdateMs, lang)
		})}`;
	});

	let closeStream: (() => void) | null = null;

	// Flow API captured from inside <SvelteFlow> via FlowApiBridge.
	// Null until the bridge mounts (first frame after <SvelteFlow>
	// renders). rebuildGraph's tick path requires it for the
	// updateNodeData / updateEdge calls — if it's still null on a
	// tick (extremely brief window during initial mount) we fall
	// back to the array-reassignment path, which works but remounts.
	let flowApi: FlowApi | null = null;

	// Live-tick reconciliation.
	//
	// Three invariants matter on every WS tick:
	//   1. User-dragged node positions must survive the rebuild
	//      (F1 — operator browser feedback 2026-06-03).
	//   2. Custom edge components (AnimatedFlowEdge) must NOT
	//      remount, so their SMIL <animateMotion> animations
	//      don't snap back to t=0 every tick (C4 — sawtooth
	//      jitter, 2026-06-03).
	//   3. Custom node components (UpstreamNode etc.) must
	//      observe live data updates — not just remain mounted.
	//      Regression B (2026-06-03): the earlier in-place
	//      `prev.data = fresh.data` mutation kept the wrapper
	//      mounted (good for SMIL continuity) but didn't cross
	//      the reactivity boundary into children that destructured
	//      `data` via $props(), so per-upstream req/s went stale.
	//
	// Solution: use Svelte Flow's first-class updateNodeData /
	// updateEdge APIs for ids present in both old and new graphs.
	// These mutate the internal store in a way the framework
	// observes AND propagate the new data into the rendered child
	// component without unmounting it. The same call also keeps
	// edge identity stable, so AnimatedFlowEdge's SMIL continues
	// uninterrupted.
	//
	// For ids that appear or disappear, we still need an array
	// reassignment (the API doesn't have a single add/remove
	// primitive that preserves the others' identity in one call),
	// so we do a partial reassignment only when the id set
	// actually changes between ticks.
	//
	// C6b-i dropped the view-mode argument: with no Vue protocole,
	// there's nothing to switch between. The function now only
	// distinguishes "first build" (full reassignment, no prior
	// state) from "tick" (in-place data updates via the flow API).
	// `view` travels as a parameter rather than being read from state
	// inside the body. The body runs under untrack() — see the effect
	// below — and a state read there can hand back the PREVIOUS value,
	// which is exactly the v2.61.1 bug where nodes vanished on a
	// switch and came back with the next WebSocket frame.
	function rebuildGraph(routesIn: TopologyRoute[], view: TopoView): void {
		// v2.48 — fold the alias stacks on arrival, once. A route
		// with no alias has nothing to fold, so seeding only the
		// ones that do keeps the chevron meaningful everywhere it
		// appears.
		collapsedRoutes.seedCollapsed(
			routesIn.filter((r) => (r.aliases?.length ?? 0) > 0).map((r) => r.id)
		);

		// Phase 3.e — thread the page-local collapsed set into
		// the layout builder. The builder is pure; the set
		// arrives as a read-only snapshot of the store's current
		// value.
		const graph = buildTopologyGraph(routesIn, collapsedRoutes.collapsed, {
			// The Caddy hub is the literal truth for a proxied route and
			// a hop that carries nothing for a redirect, so the
			// Redirects view wires hosts straight to their destination.
			hideHub: view === 'redirect'
		});

		// First call: reassign the full arrays. No existing state
		// to reconcile against. The builder's positions are the
		// truth.
		if (nodes.length === 0 || flowApi === null) {
			nodes = graph.nodes;
			edges = graph.edges;
			return;
		}

		// Compare id sets. If add or remove happened, fall back to
		// array reassignment with position preservation (the F1
		// pattern from before the API rewrite). The data update
		// for surviving nodes still goes through updateNodeData
		// so child components react.
		const prevNodeIds = new Set<string>();
		for (const n of nodes) prevNodeIds.add(n.id);
		const nextNodeIds = new Set<string>();
		for (const n of graph.nodes) nextNodeIds.add(n.id);
		const prevEdgeIds = new Set<string>();
		for (const e of edges) prevEdgeIds.add(e.id);
		const nextEdgeIds = new Set<string>();
		for (const e of graph.edges) nextEdgeIds.add(e.id);

		const idsetEqual = (a: Set<string>, b: Set<string>): boolean => {
			if (a.size !== b.size) return false;
			for (const x of a) if (!b.has(x)) return false;
			return true;
		};

		const nodesIdsetEqual = idsetEqual(prevNodeIds, nextNodeIds);
		const edgesIdsetEqual = idsetEqual(prevEdgeIds, nextEdgeIds);

		if (nodesIdsetEqual && edgesIdsetEqual) {
			// Fast path: same id sets. Push data changes through
			// Svelte Flow's first-class APIs so children re-render
			// without the wrapper being unmounted.
			for (const fresh of graph.nodes) {
				flowApi.updateNodeData(fresh.id, fresh.data, { replace: true });
			}
			for (const fresh of graph.edges) {
				flowApi.updateEdge(fresh.id, { data: fresh.data });
			}
			return;
		}

		// Mixed: some ids added, some removed. Preserve drag
		// positions for ids that survived; emit fresh entries for
		// new ones; drop removed ones implicitly via the new
		// array. New entries land via array reassignment (Svelte
		// Flow handles their initial mount); survivors update via
		// updateNodeData *after* the reassignment to ensure their
		// child components see the new data prop too.
		const prevPositionsById = new Map<string, { x: number; y: number }>();
		for (const n of nodes) {
			if (n.position) prevPositionsById.set(n.id, { x: n.position.x, y: n.position.y });
		}
		const nextNodes = graph.nodes.map((fresh) => {
			const savedPos = prevPositionsById.get(fresh.id);
			if (savedPos) {
				return { ...fresh, position: savedPos };
			}
			return fresh;
		});
		nodes = nextNodes;
		edges = graph.edges;

		// Reactivity flush then data push for survivors. Without
		// this, ids that survived the membership change would
		// receive their fresh data via the array reassignment AND
		// the child render would unmount-remount because the
		// reassignment replaced the node object refs. The
		// updateNodeData call is idempotent — pushing the same
		// data we just put in the array — but it nudges the
		// framework into the no-remount data-only update path.
		for (const fresh of graph.nodes) {
			if (prevNodeIds.has(fresh.id)) {
				flowApi.updateNodeData(fresh.id, fresh.data, { replace: true });
			}
		}
	}

	async function loadInitial(): Promise<void> {
		pageStatus = 'loading';
		pageError = '';
		try {
			const snap = await fetchSnapshot();
			routes = snap.routes;
			rebuildGraph(filterForView(snap.routes, topoView), topoView);
			lastUpdateMs = Date.now();
			pageStatus = 'connected';
			// Now that we have the initial graph, open the live
			// stream. The WS handler's initial-emit-on-connect
			// means the FIRST tick arrives ~immediately and we'll
			// flip liveStatus to 'live' in the onTick callback.
			openStream();
		} catch (err) {
			const msg =
				err instanceof TopologyFetchError
					? err.message
					: err instanceof Error
						? err.message
						: String(err);
			pageError = msg;
			pageStatus = 'error';
		}
	}

	function openStream(): void {
		// Idempotent — if the page reloads or the user clicks
		// Retry mid-stream, close the previous handle first.
		if (closeStream !== null) {
			closeStream();
			closeStream = null;
		}
		closeStream = connectLiveStream(
			(nextRoutes) => {
				routes = nextRoutes;
				// THE view filter belongs here too. `routes` keeps the
				// full list — the sidebar and the selector counts need
				// it — but the graph only ever shows one view.
				//
				// This site was the one of four that passed the raw
				// list, so every frame (2 s by default) rebuilt the
				// canvas with every node and undid the operator's
				// choice. The comment above filterForView already
				// claimed "the WS handler owns the per-frame rebuild";
				// it did, and it was the handler that forgot to filter.
				rebuildGraph(filterForView(nextRoutes, topoView), topoView);
				lastUpdateMs = Date.now();
				liveStatus = 'live';
			},
			() => {
				// onDisconnect — the stream client is mid-reconnect.
				// We don't reset routes; the canvas keeps showing
				// the last-known state until the next successful
				// tick, dimmed and without particles, and the
				// indicator says when that state dates from.
				liveStatus = 'reconnecting';
			}
		);
	}

	onMount(() => {
		void loadInitial();
		return () => {
			if (closeStream !== null) {
				closeStream();
				closeStream = null;
			}
		};
	});

	// Phase 3.e — collapsed-set reactivity. When the operator
	// clicks a chevron, collapsedRoutes.collapsed updates and
	// this effect re-runs rebuildGraph against the current
	// routes snapshot.
	//
	// HOTFIX (2026-06-17, post-3.e ship) :
	// effect_update_depth_exceeded — the initial implementation
	// invoked rebuildGraph inline, which Svelte traced as part of
	// this effect's reactive graph. rebuildGraph both READS
	// `nodes` / `edges` (for diffing) and WRITES them (for first-
	// build + mixed-id-set paths). The write triggers the same
	// effect to re-run, which writes again, infinite loop.
	//
	// Fix : isolate the rebuildGraph call inside untrack() so its
	// internal $state reads and writes are NOT registered as
	// dependencies of THIS effect. The effect's dependency surface
	// is now exactly what we intend :
	//   - collapsedRoutes.collapsed (the only trigger)
	//   - pageStatus (the gate)
	// Everything else (routes, nodes, edges) is touched only
	// inside the untracked region.
	//
	// `routes` is still read INSIDE untrack so we pin the
	// snapshot at effect-fire time — if the operator clicks the
	// chevron mid-WS-tick, we rebuild against the freshest
	// routes the WS handler has assigned.
	$effect(() => {
		// Tracked deps : the trigger and the gate.
		void collapsedRoutes.collapsed;
		// v2.61 — the view selector is a tracked dep, so switching
		// Proxy ↔ Redirections redraws immediately instead of waiting
		// for the next WebSocket frame. Captured into a local BEFORE
		// the untrack: v2.61.1 learned that reading reactive state
		// inside untrack can hand back a stale value.
		const view = topoView;
		if (pageStatus !== 'connected') return;
		// Untracked body : rebuildGraph reads and writes nodes /
		// edges; isolating it here keeps those out of the effect's
		// reactive graph, and keeps `routes` from becoming a
		// dependency that would duplicate the WS handler's rebuild.
		untrack(() => {
			rebuildGraph(filterForView(routes, view), view);
		});
	});

	// HOTFIX (2026-06-17 #4) — drag-sync handler.
	//
	// When the operator drags the primary FQDN of a route with
	// aliases, the RouteGroupNode container + every alias of the
	// same route must move by the same delta so the route-row
	// stays visually cohesive. The pre-hotfix parent/child wire
	// (HF3, 1bcd128) achieved this via SvelteFlow's native
	// parent/child contract, but forced draggable:false on the
	// FQDN — the operator could no longer use the primary card
	// as the drag affordance, only the surrounding blue chrome.
	//
	// This handler restores the natural affordance : FQDN is
	// draggable, container + aliases follow. SvelteFlow fires
	// onnodedrag throughout the drag gesture; we apply the same
	// delta to the matching route-group + aliases via the flow
	// API's updateNode call, which doesn't remount the children
	// (preserves SMIL particle continuity on edges, mirror of
	// the rebuildGraph fast path).
	//
	// Delta computation : SvelteFlow gives us the FQDN's NEW
	// absolute position. We compare against the previous
	// position cached in lastDragPosByNode and apply the delta
	// to the related nodes. On dragstart we seed the cache;
	// on dragstop we clear the entry. Cache is keyed by FQDN
	// node id, so concurrent drags of different rows are
	// independent.
	const lastDragPosByNode = new Map<string, { x: number; y: number }>();

	function handleNodeDragStart({ targetNode }: { targetNode: Node | null }) {
		// Only care about FQDN drags — that's the only node type
		// with the default `draggable: true` on alias-routes
		// (container is draggable:false, aliases are
		// draggable:false). Defensive id-pattern check covers
		// the no-target case (rare but possible per SvelteFlow's
		// type).
		if (!targetNode || !targetNode.id.startsWith('fqdn-')) return;
		lastDragPosByNode.set(targetNode.id, {
			x: targetNode.position.x,
			y: targetNode.position.y,
		});
	}

	function handleNodeDrag({ targetNode }: { targetNode: Node | null }) {
		if (!targetNode || !targetNode.id.startsWith('fqdn-')) return;
		if (flowApi === null) return;
		const prev = lastDragPosByNode.get(targetNode.id);
		if (!prev) return;
		const dx = targetNode.position.x - prev.x;
		const dy = targetNode.position.y - prev.y;
		if (dx === 0 && dy === 0) return;
		lastDragPosByNode.set(targetNode.id, {
			x: targetNode.position.x,
			y: targetNode.position.y,
		});

		// Resolve the route ID from the FQDN node id (format:
		// "fqdn-{routeId}"). Apply the delta to the matching
		// route-group + every alias of the same route.
		// updateNode is SvelteFlow's first-class position-mutate
		// API — preserves node identity (no remount), same path
		// used by the live-tick reconciler in rebuildGraph.
		const routeId = targetNode.id.slice('fqdn-'.length);
		const targets: string[] = [`route-group-${routeId}`];
		for (const n of nodes) {
			if (n.id.startsWith(`alias-${routeId}-`)) targets.push(n.id);
		}
		for (const targetId of targets) {
			flowApi.updateNode(targetId, (n) => ({
				position: { x: n.position.x + dx, y: n.position.y + dy },
			}));
		}
	}

	function handleNodeDragStop({ targetNode }: { targetNode: Node | null }) {
		if (!targetNode) return;
		lastDragPosByNode.delete(targetNode.id);
	}

	// v2.48 — put the graph back where the builder wanted it.
	//
	// Nodes are draggable, and there was no way back: an operator who
	// pulled things apart to read a busy corner had to reload the page
	// to recover the layout. This rebuilds positions from the builder,
	// which is the same pure function that produced them in the first
	// place, then re-frames the view.
	//
	// Deliberately NOT automatic on a poll tick: a tick that snapped
	// dragged nodes back would make the graph unusable while reading
	// it. This is a button because it has to be a decision.
	function relayout(): void {
		const graph = buildTopologyGraph(filterForView(routes, topoView), collapsedRoutes.collapsed, {
			hideHub: topoView === 'redirect'
		});
		nodes = graph.nodes;
		edges = graph.edges;
		lastDragPosByNode.clear();
		// Let the reassignment render before framing it.
		queueMicrotask(() => flowApi?.fitView?.());
	}
</script>

<svelte:head>
	<title>{language.current && t('topology.headTitle')}</title>
</svelte:head>

<div class="topo-page">
	<!-- v2.41 — was a hand-rolled copy of PageHeader (whose own doc
	     comment already listed this page as a consumer). The wrapper
	     keeps the flex sizing the page layout depends on. -->
	<div class="topo-header">
		<PageHeader
			eyebrow={language.current && t('topology.eyebrow')}
			title={language.current && t('topology.title')}
			subtitle={language.current && t('topology.lede')}
		/>
		<!-- v2.61 — the view selector. Counts are on the labels because
		     the useful question before switching is "is there anything
		     over there", and a tab that turns out to be empty is a
		     wasted click. -->
		<div class="topo-views" role="group" aria-label={language.current && t('topology.viewAriaLabel')}>
			<button
				type="button"
				data-testid="topo-view-proxy"
				class="topo-view-btn"
				class:is-active={topoView === 'proxy'}
				aria-pressed={topoView === 'proxy'}
				onclick={() => (topoView = 'proxy')}
			>{language.current && t('topology.viewProxy')} ({proxyRoutes.length})</button>
			<button
				type="button"
				data-testid="topo-view-redirect"
				class="topo-view-btn"
				class:is-active={topoView === 'redirect'}
				aria-pressed={topoView === 'redirect'}
				onclick={() => (topoView = 'redirect')}
			>{language.current && t('topology.viewRedirect')} ({redirectRoutes.length})</button>
		</div>
	</div>

	{#if pageStatus === 'loading'}
		<div class="topo-state-wrap">
			<Spinner size="lg" />
			<p class="state-text">{language.current && t('topology.loadingState')}</p>
		</div>
	{:else if pageStatus === 'error'}
		<div class="topo-state-wrap">
			<div class="error-box">
				<div class="error-title">{language.current && t('topology.errorTitle')}</div>
				<div class="error-msg">{pageError}</div>
				<Button variant="secondary" size="sm" onclick={() => void loadInitial()}>
					{language.current && t('topology.errorRetry')}
				</Button>
			</div>
		</div>
	{:else if routes.length === 0}
		<!-- v2.41 — the page had no empty state at all: a fresh
		     install showed an empty canvas with no explanation. -->
		<div class="topo-state-wrap">
			<EmptyState
				testid="topology-empty"
				title={language.current && t('topology.emptyTitle')}
				body={language.current && t('topology.emptyBody')}
				actionLabel={language.current && t('topology.emptyAction')}
				actionHref="/routes"
			/>
		</div>
	{:else}
		<div class="topo-content">
			<div class="topo-canvas-wrap">
				<div class="canvas-toolbar">
					<div
						class="live-indicator"
						class:reconnecting={liveStatus === 'reconnecting'}
						class:connecting={liveStatus === 'connecting'}
						role="status"
						data-testid="topology-live-status"
						data-live-status={liveStatus}
					>
						<span class="dot" aria-hidden="true"></span>
						<span class="label">{liveLabel}</span>
					</div>
				</div>
				<div class="canvas-frame" class:is-stale={isStale} data-stale={isStale}>
					<SvelteFlow
						bind:nodes
						bind:edges
						{nodeTypes}
						{edgeTypes}
						fitView
						nodesDraggable
						nodesConnectable={false}
						elementsSelectable
						onnodedragstart={handleNodeDragStart}
						onnodedrag={handleNodeDrag}
						onnodedragstop={handleNodeDragStop}
						proOptions={{ hideAttribution: true }}
					>
						<Background />
						<Controls>
							<ControlButton
								onclick={relayout}
								title={language.current && t('topology.relayout')}
								aria-label={language.current && t('topology.relayout')}
								data-testid="topology-relayout"
							>
								<!-- Four corners drawing inwards: "put this back
								     in order", distinct from the fit-view icon
								     just above it, which only re-frames. -->
								<svg viewBox="0 0 24 24" width="14" height="14" fill="none"
									stroke="currentColor" stroke-width="2" stroke-linecap="round">
									<path d="M3 9V5a2 2 0 0 1 2-2h4" />
									<path d="M21 9V5a2 2 0 0 0-2-2h-4" />
									<path d="M3 15v4a2 2 0 0 0 2 2h4" />
									<path d="M21 15v4a2 2 0 0 1-2 2h-4" />
									<rect x="9" y="9" width="6" height="6" rx="1" />
								</svg>
							</ControlButton>
						</Controls>
						<FlowApiBridge onReady={(api) => (flowApi = api)} />
					</SvelteFlow>
				</div>
			</div>

			<!-- The sidebar follows the selector. Top flows ranking proxy
			     routes while the canvas showed only redirects made the
			     filter look half-applied; the panel answers "what is busy
			     in what I am looking at", not "what is busy overall". -->
			<TopologySidebar routes={filterForView(routes, topoView)} />
		</div>
	{/if}
</div>

<style>
	.topo-page {
		display: flex;
		flex-direction: column;
		height: 100%;
		min-height: 0;
		padding: 24px;
		gap: 18px;
		box-sizing: border-box;
	}

	.topo-header {
		flex: 0 0 auto;
	}

	/* v2.68 — viewport-fit chain, same shape as /logs (see the
	   Z.5.7 comment there, which this deliberately mirrors rather
	   than inventing a second pattern).

	   .topo-page already asked for `height: 100%`, but the shell
	   above it is `min-height: 100vh` — a minimum, not a height —
	   so the percentage resolved against an auto-height parent and
	   behaved like `auto`. The page then grew to its tallest column,
	   which is the sidebar: the canvas kept its aspect, the panels
	   ran past the fold, and the operator had to scroll the DOCUMENT
	   to reach the Top flows rows. The sidebar's own `overflow-y:
	   auto` never engaged because nothing ever constrained it.

	   :has() scopes all three overrides to this route, so every other
	   page keeps its natural page scroll. On a browser without :has()
	   the rules are ignored and the page degrades to exactly the
	   behaviour it has today. */
	:global(.app-shell:has(.topo-page)) {
		height: 100vh;
		height: 100dvh;
		min-height: 0;
		overflow: hidden;
	}
	:global(.app-col:has(.topo-page)) {
		min-height: 0;
		overflow: hidden;
	}
	/* box-sizing is load-bearing: .app-main carries padding: 22px
	   globally and there is no universal reset, so without it the
	   padding would push the content past the bounded parent and put
	   the scrollbar straight back. */
	:global(.app-main:has(.topo-page)) {
		box-sizing: border-box;
		flex: 1;
		min-height: 0;
		overflow: hidden;
		display: flex;
		flex-direction: column;
	}

	/* Below ~900px the canvas and a 280px sidebar side by side leave
	   neither anything to work with, and pinning that to the viewport
	   would make both unusable. Let the page scroll instead. */
	@media (max-width: 900px) {
		:global(.app-main:has(.topo-page)) {
			height: auto;
			overflow: visible;
		}
		.topo-page {
			height: auto;
		}
		.topo-content {
			flex-wrap: wrap;
		}
		.topo-canvas-wrap {
			flex: 1 1 100%;
			min-height: 420px;
		}
	}


	.topo-content {
		flex: 1 1 auto;
		min-height: 0;
		display: flex;
		gap: 14px;
	}

	.topo-canvas-wrap {
		flex: 1 1 auto;
		min-width: 0;
		border: 1px solid var(--border, oklch(28% 0.009 250));
		border-radius: 8px;
		overflow: hidden;
		background: var(--bg, oklch(15% 0.005 250));
		display: flex;
		flex-direction: column;
	}

	/* Slimmer toolbar than pre-C6b-i — it only carries the live
	   indicator now that the view toggle is gone. Right-aligned so
	   the indicator sits in its natural spot without needing the
	   previous absolute-positioning hack. */
	.canvas-toolbar {
		flex: 0 0 auto;
		display: flex;
		justify-content: flex-end;
		align-items: center;
		padding: 6px 12px;
		border-bottom: 1px solid var(--border, oklch(28% 0.009 250));
		background: var(--surface-2, oklch(22% 0.007 250));
	}

	.canvas-frame {
		flex: 1 1 auto;
		min-height: 0;
		position: relative;
	}

	/* Loading / error states use the same outer wrap so the
	   page layout doesn't jump between states. */
	.topo-state-wrap {
		flex: 1 1 auto;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 14px;
		min-height: 0;
	}

	.state-text {
		color: var(--fg-muted, oklch(68% 0.012 250));
		font-size: 13px;
		margin: 0;
	}

	.error-box {
		max-width: 480px;
		padding: 20px 24px;
		background: var(--surface, oklch(19% 0.006 250));
		border: 1px solid color-mix(in oklch, var(--status-down) 40%, transparent);
		border-radius: 8px;
		text-align: center;
	}

	.error-title {
		font-size: 14px;
		font-weight: 600;
		color: var(--status-down);
		margin-bottom: 6px;
	}

	.error-msg {
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 12px;
		color: var(--fg-muted, oklch(68% 0.012 250));
		margin-bottom: 14px;
		word-break: break-word;
	}


	/* Live indicator — small pill. Used to be absolute-positioned
	   to coexist with a centered ViewToggle; C6b-i dropped the
	   toggle, so the indicator now flows naturally inside the
	   flex-end toolbar. */
	.live-indicator {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-family: var(--font-mono, ui-monospace, monospace);
		font-size: 10.5px;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: var(--status-up);
		padding: 4px 10px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--status-up) 14%, transparent);
	}

	.live-indicator.reconnecting {
		color: var(--status-warn);
		background: color-mix(in oklch, var(--status-warn) 14%, transparent);
	}

	.live-indicator .dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: currentColor;
		box-shadow: 0 0 6px currentColor;
	}

	.live-indicator.reconnecting .dot {
		box-shadow: none;
	}

	/* Not yet live, not broken either: neutral, no glow. */
	.live-indicator.connecting {
		color: var(--text-secondary);
		background: color-mix(in oklch, var(--text-secondary) 12%, transparent);
	}

	.live-indicator.connecting .dot {
		box-shadow: none;
	}

	/* Stale canvas — the stream dropped. The last-known graph stays
	   readable (and draggable) but visibly is not live: dimmed,
	   desaturated, and without the particles that would otherwise
	   keep flowing at the last rates. The controls sit outside the
	   viewport and stay at full strength. */
	.canvas-frame :global(.svelte-flow__viewport) {
		transition: opacity 0.3s ease, filter 0.3s ease;
	}

	.canvas-frame.is-stale :global(.svelte-flow__viewport) {
		opacity: 0.45;
		filter: grayscale(0.7);
	}

	.canvas-frame.is-stale :global(circle.particle) {
		display: none;
	}

	/* Phase 3.c (2026-06-17): override SvelteFlow Controls palette.
	   Defaults are white-on-white in light themes — invisible on our
	   dark canvas background. The package exposes per-component CSS
	   vars; scoping them to .canvas-frame keeps the override local
	   and lets a future light-theme toggle reset without touching
	   this rule. Foreground/border use the design-token palette so
	   the buttons match the rest of the canvas chrome. */
	.topo-views {
		display: inline-flex;
		gap: 2px;
		padding: 2px;
		border-radius: var(--radius-full);
		background: var(--bg-surface);
		border: 1px solid var(--border-default);
	}
	.topo-view-btn {
		border: 0;
		background: transparent;
		color: var(--text-secondary);
		font-size: var(--text-xs);
		padding: 4px 12px;
		border-radius: var(--radius-full);
		cursor: pointer;
		transition: background var(--motion-fast), color var(--motion-fast);
	}
	.topo-view-btn:hover {
		color: var(--text-primary);
	}
	.topo-view-btn.is-active {
		background: var(--bg-hover);
		color: var(--text-primary);
	}

	.canvas-frame :global(.svelte-flow__controls) {
		--xy-controls-button-background-color: var(--surface, oklch(19% 0.006 250));
		--xy-controls-button-background-color-hover: var(--surface-2, oklch(22% 0.007 250));
		--xy-controls-button-color: var(--fg, oklch(96% 0.005 250));
		--xy-controls-button-color-hover: var(--accent, oklch(68% 0.21 255));
		--xy-controls-button-border-color: var(--border, oklch(28% 0.009 250));
		--xy-controls-box-shadow: 0 2px 6px rgb(0 0 0 / 0.4);
		border-radius: 6px;
		overflow: hidden;
	}
</style>
