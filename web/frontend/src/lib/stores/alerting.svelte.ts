// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// AL.4.b.1 — Alerting page state stores. Svelte 5 runes.
//
// alertEventsStore drives the History tab; ships in full
// here. channelsStore + rulesStore are stubbed so the
// stub tabs can import them without TypeScript errors —
// they get fleshed out in AL.4.b.2 / .3 (full CRUD,
// optimistic updates, /test integration).

import {
	alertingApi,
	type AlertChannel,
	type AlertEvent,
	type AlertEventsFilter,
	type AlertRule
} from '$lib/api/alerting';
import { ApiError } from '$lib/api/types';
import { t } from '$lib/i18n';

// --- alertEventsStore --------------------------------------

interface AlertEventsState {
	events: AlertEvent[];
	nextCursor: string;
	loading: boolean;
	loadMoreLoading: boolean;
	loadError: string;
	degraded: boolean;
}

function createAlertEventsStore() {
	const state = $state<AlertEventsState>({
		events: [],
		nextCursor: '',
		loading: false,
		loadMoreLoading: false,
		loadError: '',
		degraded: false
	});

	async function load(filter: AlertEventsFilter, reset: boolean): Promise<void> {
		if (reset) {
			state.loading = true;
		} else {
			state.loadMoreLoading = true;
		}
		state.loadError = '';
		const req: AlertEventsFilter = { ...filter };
		if (!reset && state.nextCursor) req.cursor = state.nextCursor;
		try {
			const res = await alertingApi.listAlertEvents(req);
			state.events = reset ? res.events : [...state.events, ...res.events];
			state.nextCursor = res.nextCursor;
			state.degraded = res.degraded ?? false;
		} catch (err) {
			if (reset) {
				state.loadError =
					err instanceof ApiError ? err.message : t('alerting.loadEventsFailed');
				state.events = [];
			}
			// On loadMore failure we keep the existing list and
			// surface a transient error; the History tab toast-
			// pushes for non-reset failures.
			throw err;
		} finally {
			state.loading = false;
			state.loadMoreLoading = false;
		}
	}

	return {
		get state() {
			return state;
		},
		load
	};
}

export const alertEventsStore = createAlertEventsStore();

// --- channelsStore -----------------------------------------
//
// Full CRUD wired in AL.4.b.2. Each mutation hits the
// backend then re-loads the list — simpler than tracking
// optimistic state for the modest channel counts a homelab
// runs (operator typically has 1-3 channels). The /test
// endpoint returns immediately with the per-channel
// outcome; channelsStore does not refresh after a test
// because the LastSentAt/LastError fields on the channel
// row update server-side via MarkAlertChannelSendResult,
// so a follow-up load() picks them up the next time the
// table refreshes.

interface ChannelsState {
	channels: AlertChannel[];
	loading: boolean;
	loadError: string;
}

function createChannelsStore() {
	const state = $state<ChannelsState>({
		channels: [],
		loading: false,
		loadError: ''
	});

	async function load(): Promise<void> {
		state.loading = true;
		state.loadError = '';
		try {
			state.channels = await alertingApi.listChannels();
		} catch (err) {
			state.loadError =
				err instanceof ApiError ? err.message : t('alerting.loadChannelsFailed');
		} finally {
			state.loading = false;
		}
	}

	async function create(req: Parameters<typeof alertingApi.createChannel>[0]): Promise<AlertChannel> {
		const created = await alertingApi.createChannel(req);
		// Append optimistically so the new row appears
		// immediately; a subsequent load() refresh would
		// also include it. The list is small enough that
		// either path is correct — append avoids the
		// round-trip blink.
		state.channels = [...state.channels, created];
		return created;
	}

	async function update(
		id: string,
		req: Parameters<typeof alertingApi.updateChannel>[1]
	): Promise<AlertChannel> {
		const updated = await alertingApi.updateChannel(id, req);
		state.channels = state.channels.map((c) => (c.id === id ? updated : c));
		return updated;
	}

	async function remove(id: string): Promise<void> {
		await alertingApi.deleteChannel(id);
		state.channels = state.channels.filter((c) => c.id !== id);
	}

	async function test(id: string) {
		// Surfaces the per-call outcome to the caller (the
		// ChannelsTab toast + inline status); does NOT
		// mutate the store. A subsequent load() picks up the
		// updated LastSentAt/LastError on the row.
		return alertingApi.testChannel(id);
	}

	return {
		get state() {
			return state;
		},
		load,
		create,
		update,
		remove,
		test
	};
}

export const channelsStore = createChannelsStore();

// --- rulesStore --------------------------------------------
//
// Full CRUD wired in AL.4.b.3 (mirrors the AL.4.b.2
// channelsStore). create/update/delete update the local
// list immediately so the table doesn't blink during the
// round-trip; the RulesTab also reloads after each
// successful mutation to pick up server-side timestamps
// (LastEvalAt, LastFiredAt) that the watcher writes.

interface RulesState {
	rules: AlertRule[];
	loading: boolean;
	loadError: string;
}

function createRulesStore() {
	const state = $state<RulesState>({
		rules: [],
		loading: false,
		loadError: ''
	});

	async function load(): Promise<void> {
		state.loading = true;
		state.loadError = '';
		try {
			state.rules = await alertingApi.listRules();
		} catch (err) {
			state.loadError =
				err instanceof ApiError ? err.message : t('alerting.loadRulesFailed');
		} finally {
			state.loading = false;
		}
	}

	async function create(req: Parameters<typeof alertingApi.createRule>[0]): Promise<AlertRule> {
		const created = await alertingApi.createRule(req);
		state.rules = [...state.rules, created];
		return created;
	}

	async function update(
		id: string,
		req: Parameters<typeof alertingApi.updateRule>[1]
	): Promise<AlertRule> {
		const updated = await alertingApi.updateRule(id, req);
		state.rules = state.rules.map((r) => (r.id === id ? updated : r));
		return updated;
	}

	async function remove(id: string): Promise<void> {
		await alertingApi.deleteRule(id);
		state.rules = state.rules.filter((r) => r.id !== id);
	}

	async function test(id: string) {
		// Pass-through; LastFiredAt updates server-side
		// (the dispatcher + watcher write back), picked up
		// on next load(). Returns the per-channel
		// fired/skipped/errors result for the toast.
		return alertingApi.testRule(id);
	}

	return {
		get state() {
			return state;
		},
		load,
		create,
		update,
		remove,
		test
	};
}

export const rulesStore = createRulesStore();
