<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script module lang="ts">
	// Open modals, oldest first. Every open Modal listens on `document`,
	// so without this a ConfirmDialog opened over a form would close
	// both on one Escape. Only the last entry handles keys.
	const openStack: symbol[] = [];
</script>

<script lang="ts">
	import type { Snippet } from 'svelte';
	import { fade, fly } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';

	// AL.4.b.2 — `width` is a new additive prop. Default
	// 'md' preserves the pre-extension layout exactly so
	// every existing caller (ConfirmDialog, ChangePassword,
	// CreateServiceAccount, BanIP, WildcardApexWizard,
	// certs/routes inline modals) renders unchanged. Larger
	// values are for forms with many fields (AL.4.b.2
	// ChannelModal, AL.4.b.3 RuleModal).
	type Width = 'sm' | 'md' | 'lg' | 'xl';

	interface Props {
		open?: boolean;
		title: string;
		onClose: () => void;
		children?: Snippet;
		footer?: Snippet;
		width?: Width;
		/**
		 * False makes Escape and backdrop clicks do nothing, so only the
		 * dialog's own buttons can close it — for content that is lost
		 * on close, like a secret shown once.
		 */
		dismissible?: boolean;
	}

	let {
		open = false,
		title,
		onClose,
		children,
		footer,
		width = 'md',
		dismissible = true
	}: Props = $props();

	// Tailwind class per width token. Kept as a static map
	// so the Tailwind purger sees every literal at build
	// time (a dynamic interpolation `max-w-${width}` would
	// be purged unless every variant is also listed in the
	// safelist).
	const widthClass: Record<Width, string> = {
		sm: 'max-w-sm',
		md: 'max-w-md',
		lg: 'max-w-2xl',
		xl: 'max-w-4xl'
	};

	let dialog: HTMLDivElement | undefined = $state(undefined);
	const titleId = `modal-title-${Math.random().toString(36).slice(2, 9)}`;
	const stackToken = Symbol('modal');

	function isTopmost(): boolean {
		return openStack[openStack.length - 1] === stackToken;
	}

	/**
	 * Returns the focusable descendants of the dialog, in tab order.
	 * Used by the trap logic to wrap Tab/Shift+Tab inside the modal.
	 */
	function focusable(): HTMLElement[] {
		if (!dialog) return [];
		const selector =
			'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
		return Array.from(dialog.querySelectorAll<HTMLElement>(selector));
	}

	function onKeydown(event: KeyboardEvent) {
		// A modal underneath another one must neither close nor trap Tab.
		if (!isTopmost()) return;
		if (event.key === 'Escape') {
			event.preventDefault();
			if (dismissible) onClose();
			return;
		}
		if (event.key !== 'Tab') return;
		const items = focusable();
		if (items.length === 0) {
			event.preventDefault();
			return;
		}
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		if (event.shiftKey && active === first) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && active === last) {
			event.preventDefault();
			first.focus();
		}
	}

	$effect(() => {
		if (!open) return;
		openStack.push(stackToken);
		document.addEventListener('keydown', onKeydown);
		const previouslyFocused = document.activeElement as HTMLElement | null;
		// Move focus into the dialog after Svelte mounts the markup.
		queueMicrotask(() => {
			const items = focusable();
			(items[0] ?? dialog)?.focus();
		});
		return () => {
			// By identity, not pop(): modals do not always close in the
			// order they opened.
			const index = openStack.indexOf(stackToken);
			if (index !== -1) openStack.splice(index, 1);
			document.removeEventListener('keydown', onKeydown);
			previouslyFocused?.focus();
		};
	});
</script>

{#if open}
	<!-- Backdrop: fade in/out via svelte/transition (Chunk 3.0 lib
	     decision). Background uses --overlay-modal (rgba 0.8) so theme
	     switches don't change the dim level. -->
	<div
		role="presentation"
		class="modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4"
		onclick={(e) => {
			if (dismissible && e.target === e.currentTarget) onClose();
		}}
		onkeydown={() => {
			/* keydown is handled at document level via $effect; this stub keeps
			   svelte/a11y happy on the click handler. */
		}}
		transition:fade={{ duration: 200, easing: cubicOut }}
	>
		<!-- Dialog: fly + fade per spec §10.2 (slide-up + fade with
		     --motion-slow 400ms). Both directions (in/out) are now
		     animated — pre-Chunk-3 only the entry was.
		     Capped to the viewport minus the backdrop's p-4, with only the
		     body scrolling: a long form used to overflow the centred box
		     and clip its own header and Save footer out of reach. -->
		<div
			bind:this={dialog}
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			tabindex="-1"
			class="bg-elevated border border-border-default rounded-lg shadow-lg w-full {widthClass[width]} max-h-[calc(100dvh-2rem)] flex flex-col focus:outline-none"
			transition:fly={{ y: 20, duration: 400, easing: cubicOut }}
		>
			<header class="shrink-0 px-5 py-4 border-b border-border-subtle">
				<h2 id={titleId} class="text-lg font-semibold">{title}</h2>
			</header>
			<div class="min-h-0 overflow-y-auto px-5 py-4">
				{@render children?.()}
			</div>
			{#if footer}
				<footer class="shrink-0 px-5 py-3 border-t border-border-subtle flex justify-end gap-2">
					{@render footer()}
				</footer>
			{/if}
		</div>
	</div>
{/if}

<style>
	.modal-backdrop {
		background-color: var(--overlay-modal);
		backdrop-filter: blur(4px);
	}
</style>
