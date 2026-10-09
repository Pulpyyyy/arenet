// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// The count series (req_per_sec, four_xx_rate, five_xx_rate) are not
// rates despite their names: each point is the COUNT seen in one
// bucket (internal/api/metrics_handlers.go pickMetricValue), and a
// bucket is a minute on the 24h window and an hour on the 30d one.
// The dashboard labelled them "Req/s"; the route page "/ minute" on
// both windows. The unit is the bucket, read from the response's
// bucketSizeSeconds.

const MINUTE = 60;
const HOUR = 3600;

/** The bucket as a unit suffix: "min", "h", "5 min", "30 s". */
export function bucketUnit(seconds: number): string {
	if (seconds >= HOUR && seconds % HOUR === 0) {
		return seconds === HOUR ? 'h' : `${seconds / HOUR} h`;
	}
	if (seconds >= MINUTE && seconds % MINUTE === 0) {
		return seconds === MINUTE ? 'min' : `${seconds / MINUTE} min`;
	}
	return `${seconds} s`;
}
