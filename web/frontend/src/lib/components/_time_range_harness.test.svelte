<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Test harness for TimeRange.test.ts: binds `value` both ways so the
  test can observe a selection reaching the parent, and a parent write
  reaching the control. Not a test file itself (vitest only collects
  *.test.ts).
-->
<script lang="ts">
	import TimeRange from './TimeRange.svelte';
	import type { TimeRangeValue } from '$lib/utils/time-range';

	let value = $state<TimeRangeValue>('24h');
</script>

<TimeRange bind:value ariaLabel="Harness range" />
<output data-testid="bound">{value}</output>
<button type="button" data-testid="set-7d" onclick={() => (value = '7d')}>7d</button>
