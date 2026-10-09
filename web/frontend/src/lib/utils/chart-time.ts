// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Axis and tooltip labels for the timeline charts. A hand-rolled
// "MM-DD" read month-first in every language, which a French reader
// takes for day-first; Intl orders day and month for the app language
// ("05/10" in French, "10/05" in English for 5 October). The clock is
// pinned to 24 hours so an English axis does not grow an AM/PM suffix
// and three ticks still fit under a narrow chart.

import { language } from '$lib/stores/language.svelte';

/** chartDay renders the local day and month of `d`, both two-digit. */
export function chartDay(d: Date, locale: string = language.current): string {
	return new Intl.DateTimeFormat(locale, { day: '2-digit', month: '2-digit' }).format(d);
}

/** chartClock renders the local 24-hour time of `d` ("14:05"). */
export function chartClock(d: Date, locale: string = language.current): string {
	return new Intl.DateTimeFormat(locale, {
		hour: '2-digit',
		minute: '2-digit',
		hourCycle: 'h23'
	}).format(d);
}

/** chartDayTime joins both: "05/10 14:05" in French. */
export function chartDayTime(d: Date, locale: string = language.current): string {
	return `${chartDay(d, locale)} ${chartClock(d, locale)}`;
}
