<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R Phase 2.a — CodeMirror 6 HTML editor wrap.

  Used by /settings/error-pages to edit operator-supplied HTML
  bodies for the 8 error-page status codes. Could be reused by
  any future surface that wants an HTML editor (Step BB custom
  landing pages ?), so the component stays narrow : it owns the
  CodeMirror instance lifecycle + bind:value + imperative
  insertAtCursor for the Variables panel click-to-insert ; it
  does NOT know about Caddy placeholders or status codes.

  Design choices :
  - Static import : CodeMirror packages land in the consuming
    page's bundle (~60 KB minified+gzipped). The page itself
    is admin-only, low-volume — the bundle cost is invisible.
    Lazy-load was considered but rejected (200ms cold-cache
    loading state would feel janky on first edit ; see R.2.0
    audit decision).
  - Editor cleanup on unmount : CodeMirror's EditorView.destroy()
    releases the DOM + listeners. Without this Svelte 5 HMR
    would leak instances across reloads.
  - bind:value Svelte 5 pattern : the prop is reactive both
    ways. Consumer mutation reflows the editor doc ; user typing
    fires onUpdate that writes back to the bound parent state.
  - insertAtCursor : exposed via $bindable so the consumer can
    do `let editor = $bindable()` and call editor.insertAtCursor()
    on Variables panel clicks.
-->

<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Compartment, EditorState, type Extension } from '@codemirror/state';
	import { EditorView, keymap, lineNumbers, drawSelection } from '@codemirror/view';
	import { html } from '@codemirror/lang-html';
	import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';

	interface Props {
		/** Two-way bound HTML buffer. */
		value: string;
		/** Operator-facing label (aria-label on the wrapping div). */
		label: string;
		/** Optional placeholder text rendered when value is empty. */
		placeholder?: string;
		/** Optional min-height in px. Default 320. */
		minHeight?: number;
		/**
		 * Step R Phase 2.1 — when true, the editor disallows
		 * edits via Caddymgr EditorView.editable.of(false).
		 * The doc is still visible + scrollable, but typing,
		 * pasting, and IME composition are blocked. Used by
		 * /settings/error-pages when the operator opens the
		 * virtual builtin (no save path, only Duplicate-to-
		 * customise).
		 */
		readonly?: boolean;
	}

	let {
		value = $bindable(''),
		label,
		placeholder = '',
		minHeight = 320,
		readonly = false
	}: Props = $props();

	let containerEl: HTMLDivElement | undefined = $state();
	let view: EditorView | undefined;

	// Track whether the next value change came FROM the editor
	// itself so we don't recurse : editor.dispatch fires our
	// update listener → write back to `value` → $effect sees
	// value change → push back into editor → ... infinite loop.
	// The flag suppresses the push-back side of one cycle.
	let updatingFromEditor = false;

	// The read-only gate lives in a Compartment so a `readonly` change
	// after mount is applied in place. The page flips it on the same
	// editor when "Duplicate to customise" turns the built-in preview
	// into the editable copy; a mount-time-only gate left that copy
	// read-only.
	const readonlyGate = new Compartment();
	let appliedReadonly = false;
	function readonlyExtensions(ro: boolean): Extension {
		return [EditorView.editable.of(!ro), EditorState.readOnly.of(ro)];
	}

	onMount(() => {
		if (!containerEl) return;
		appliedReadonly = readonly;
		const state = EditorState.create({
			doc: value,
			extensions: [
				lineNumbers(),
				history(),
				drawSelection(),
				html(),
				keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
				EditorView.lineWrapping,
				// Phase 2.1 — read-only gate. EditorView.editable
				// drives the contenteditable attribute on .cm-content;
				// EditorState.readOnly blocks commands that edit.
				// Reconfigured by the $effect below.
				readonlyGate.of(readonlyExtensions(appliedReadonly)),
				EditorView.theme({
					'&': { height: '100%', minHeight: `${minHeight}px` },
					'.cm-scroller': {
						fontFamily: 'var(--font-mono)',
						fontSize: '13px'
					},
					'.cm-content': { padding: '8px 0' },
					'.cm-gutters': {
						backgroundColor: 'var(--bg-base)',
						borderRight: '1px solid var(--border-subtle)',
						color: 'var(--text-secondary)'
					}
				}),
				EditorView.updateListener.of((u) => {
					if (!u.docChanged) return;
					updatingFromEditor = true;
					value = u.state.doc.toString();
					// Reset on next tick so the $effect re-sync
					// path stays open for parent-driven updates
					// (e.g. switching tabs in the editor page
					// loads a different status code's body).
					queueMicrotask(() => {
						updatingFromEditor = false;
					});
				})
			]
		});
		view = new EditorView({
			state,
			parent: containerEl
		});
	});

	onDestroy(() => {
		view?.destroy();
		view = undefined;
	});

	// Sync parent-driven `value` change back into the editor
	// doc. Skipped when the change originated from the editor
	// itself (see updatingFromEditor flag). Without this branch,
	// a parent-side reset (e.g. "Cancel" button restores the
	// original buffer) wouldn't reach the editor.
	$effect(() => {
		if (!view || updatingFromEditor) return;
		const current = view.state.doc.toString();
		if (current === value) return;
		view.dispatch({
			changes: { from: 0, to: current.length, insert: value }
		});
	});

	// Apply a post-mount `readonly` change. `readonly` is read before the
	// guard so the effect tracks it even when it first runs unmounted.
	$effect(() => {
		const ro = readonly;
		if (!view || ro === appliedReadonly) return;
		appliedReadonly = ro;
		view.dispatch({ effects: readonlyGate.reconfigure(readonlyExtensions(ro)) });
	});

	/**
	 * Insert text at the current cursor position. Exposed for
	 * the Variables panel's click-to-insert affordance. If no
	 * cursor is set (editor never focused), inserts at the end
	 * of the document.
	 *
	 * Returns silently if the editor isn't mounted yet (the
	 * variables panel may pre-render before onMount).
	 */
	export function insertAtCursor(text: string): void {
		if (!view) return;
		const { from, to } = view.state.selection.main;
		view.dispatch({
			changes: { from, to, insert: text },
			selection: { anchor: from + text.length }
		});
		view.focus();
	}

	/**
	 * Focus the editor. Exposed so the consuming page can
	 * focus after switching tabs (better UX than requiring
	 * a click).
	 */
	export function focus(): void {
		view?.focus();
	}
</script>

<div
	class="html-editor"
	bind:this={containerEl}
	role="textbox"
	aria-label={label}
	aria-multiline="true"
	data-placeholder={placeholder}
></div>

<style>
	.html-editor {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius);
		background: var(--bg-base);
		overflow: hidden;
		min-height: 0;
		display: flex;
		flex-direction: column;
	}
	.html-editor :global(.cm-editor) {
		flex: 1;
		min-height: 0;
		outline: none;
	}
	.html-editor :global(.cm-editor.cm-focused) {
		outline: none;
		box-shadow: inset 0 0 0 1px var(--accent-cyan);
	}
	.html-editor :global(.cm-content) {
		caret-color: var(--accent-cyan);
		color: var(--text-primary);
	}
</style>
