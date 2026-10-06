<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Test-only stub for SvelteFlow's <Handle> that leaves a TRACE.

  HandleStub.test.svelte renders nothing, which is right for tests
  whose surface is the card body around the handle. It cannot be used
  to prove a handle was rendered at all — and that is exactly the
  contract BackendClusterNode needs pinned: with no upstream children
  the cluster is an edge endpoint, and Svelte Flow anchors an edge on a
  handle or silently draws no edge.

  So this one renders a marker carrying the type and position, and the
  test asserts on it.
-->
<script lang="ts">
	const props: Record<string, unknown> = $props();
</script>

<div
	data-testid="flow-handle"
	data-handle-type={String(props.type ?? '')}
	data-handle-position={String(props.position ?? '')}
></div>
