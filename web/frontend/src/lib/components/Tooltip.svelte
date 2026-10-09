<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Tooltip (Step F §5.1 — new in Chunk 3.1).

  Renders a small floating label anchored to the trigger element
  the caller wraps. Show/hide is driven by hover + focus on the
  trigger; the tooltip itself is non-interactive (pointer-events:
  none) so it never blocks clicks.

  Positioning is CSS-only via absolute positioning around the
  wrapper, no floating-ui dependency. The wrapper is
  `display: inline-block` so trigger sizing isn't disturbed.
  Side: 'top' | 'bottom' | 'left' | 'right' — defaults to 'top'.

  Reduced-motion is respected by the global @media block in
  app.css (the bubble's fade-in animation duration collapses to 0).

  Accessibility (WCAG 1.3.1 / 4.1.2 / 1.4.13):

    - aria-describedby goes on the FOCUSABLE trigger, not on the
      wrapper: on mount the component looks for the first focusable
      element inside `children` (button, link, input, [tabindex]…)
      and adds the bubble's id to that element's aria-describedby
      (merged with any ids the caller already set; removed again on
      unmount). Callers therefore just wrap a focusable element —
      no id plumbing needed.
    - When `children` holds nothing focusable (e.g. a Badge), the
      wrapper itself becomes the trigger: it gets tabindex="0" and
      the aria-describedby, so keyboard and screen-reader users can
      still reach the text.
    - The bubble stays in the DOM (hidden while closed) so the
      description resolves the moment focus lands, not one render
      later.
    - Escape dismisses the open tooltip, whether it was opened by
      hover or by focus, without moving the pointer or the focus.

  Public API (add-only per §1.3):

    label   — string (required)
    side    — 'top' | 'bottom' | 'left' | 'right' (default 'top')
    children — Snippet (the trigger element)
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	type Side = 'top' | 'bottom' | 'left' | 'right';

	interface Props {
		label: string;
		side?: Side;
		children?: Snippet;
	}

	let { label, side = 'top', children }: Props = $props();

	/** Elements that take keyboard focus on their own. */
	const FOCUSABLE_SELECTOR = [
		'a[href]',
		'button:not([disabled])',
		'input:not([disabled]):not([type="hidden"])',
		'select:not([disabled])',
		'textarea:not([disabled])',
		'summary',
		'[contenteditable="true"]',
		'[tabindex]:not([tabindex="-1"])'
	].join(', ');

	let open = $state(false);
	/** True when `children` has no focusable element: the wrapper is the trigger. */
	let wrapperIsTrigger = $state(false);
	let wrapper: HTMLSpanElement | undefined = $state();
	const id = `tt-${Math.random().toString(36).slice(2, 9)}`;

	$effect(() => {
		if (!wrapper) return;
		const trigger = wrapper.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
		if (!trigger) {
			wrapperIsTrigger = true;
			return;
		}
		wrapperIsTrigger = false;
		const existing = (trigger.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean);
		if (!existing.includes(id)) {
			trigger.setAttribute('aria-describedby', [...existing, id].join(' '));
		}
		return () => {
			const rest = (trigger.getAttribute('aria-describedby') ?? '')
				.split(/\s+/)
				.filter((token) => token && token !== id);
			if (rest.length > 0) {
				trigger.setAttribute('aria-describedby', rest.join(' '));
			} else {
				trigger.removeAttribute('aria-describedby');
			}
		};
	});

	function onWindowKeydown(event: KeyboardEvent): void {
		if (open && event.key === 'Escape') {
			open = false;
		}
	}
</script>

<svelte:window onkeydown={onWindowKeydown} />

<!-- svelte-ignore a11y_no_static_element_interactions, a11y_no_noninteractive_tabindex —
     the wrapper is a positioning container; the interactive surface
     is normally the focusable child passed via children, which gets
     the aria-describedby. Only when that child is not focusable does
     the wrapper take a tabindex so the description stays reachable
     from the keyboard. mouseenter/leave drive hover, focusin/out
     drive keyboard nav. -->
<span
	class="tt-wrapper"
	bind:this={wrapper}
	onmouseenter={() => (open = true)}
	onmouseleave={() => (open = false)}
	onfocusin={() => (open = true)}
	onfocusout={() => (open = false)}
	tabindex={wrapperIsTrigger ? 0 : undefined}
	aria-describedby={wrapperIsTrigger ? id : undefined}
>
	{@render children?.()}
	<span class="tt-bubble tt-{side}" {id} role="tooltip" hidden={!open}>
		{label}
	</span>
</span>

<style>
	.tt-wrapper {
		position: relative;
		display: inline-block;
	}
	.tt-bubble {
		position: absolute;
		z-index: 50;
		padding: var(--space-1) var(--space-2);
		background: var(--bg-surface);
		color: var(--text-primary);
		border: 1px solid var(--border-default);
		border-radius: var(--radius-sm);
		font-size: var(--text-xs);
		font-weight: 500;
		white-space: nowrap;
		box-shadow: var(--shadow-md);
		pointer-events: none;
		line-height: 1.3;
		/* Fades in each time `hidden` is lifted (display: none → box
		   restarts the animation). Reduced motion collapses it via
		   the global block in app.css. */
		animation: tt-fade-in 100ms ease-out;
	}
	@keyframes tt-fade-in {
		from {
			opacity: 0;
		}
		to {
			opacity: 1;
		}
	}
	.tt-top {
		bottom: calc(100% + var(--space-1));
		left: 50%;
		transform: translateX(-50%);
	}
	.tt-bottom {
		top: calc(100% + var(--space-1));
		left: 50%;
		transform: translateX(-50%);
	}
	.tt-left {
		right: calc(100% + var(--space-1));
		top: 50%;
		transform: translateY(-50%);
	}
	.tt-right {
		left: calc(100% + var(--space-1));
		top: 50%;
		transform: translateY(-50%);
	}
</style>
