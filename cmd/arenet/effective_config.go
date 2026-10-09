// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package main

import (
	"os"
	"regexp"
	"time"
)

// zeroTailRe matches a trailing "0s", or a trailing "0m0s"/"0m", as
// WHOLE components (a leading non-digit boundary ensures we don't chop
// the "0m" out of "30m"). Applied once, it turns 12h0m0s → 12h,
// 1h30m0s → 1h30m, 90m0s → 90m.
var zeroTailRe = regexp.MustCompile(`(\D)(0m)?0s$`)

// humanizeDuration renders a duration without the trailing zero
// components that time.Duration.String() emits, so the boot log echoes
// ~what the operator typed.
func humanizeDuration(d time.Duration) string {
	return zeroTailRe.ReplaceAllString(d.String(), "$1")
}

// effectiveConfigLogAttrs builds the slog key/value attrs for the
// one-line "effective config" boot log (v2.12.3). It reports the
// EFFECTIVE value of the operator-facing knobs — the value that was
// actually applied, whether it came from an env var / .env file or the
// built-in default — so an operator can confirm at a glance that their
// override was picked up.
//
// Secret-bearing vars (API keys) are reported as "set"/"unset" only —
// never their value. Presence-only env vars (contact email, trusted
// proxies) are likewise "set"/"unset" since the value isn't needed to
// confirm it was read.
func effectiveConfigLogAttrs(
	adminBind, dataDir, httpPort, httpsPort string,
	updateEnabled bool,
	updateInterval string,
) []any {
	updateCheck := "disabled"
	if updateEnabled {
		updateCheck = "enabled"
	}
	attrs := []any{
		"admin_bind", adminBind,
		"data_dir", dataDir,
		"http", httpPort,
		"https", httpsPort,
		"update_check", updateCheck,
		"update_interval", updateInterval,
		"acme_email", setUnset("ARENET_ACME_EMAIL"),
		"trusted_proxies", setUnset("ARENET_TRUSTED_PROXIES"),
		"admin_allowed_cidrs", setUnset("ARENET_ADMIN_ALLOWED_CIDRS"),
		"crowdsec_api_url", setUnset("ARENET_CROWDSEC_API_URL"),
		"crowdsec_api_key", setUnset("ARENET_CROWDSEC_API_KEY"),
		"geoip_mmdb", setUnset("ARENET_GEOIP_MMDB"),
		"geoip_asn_mmdb", setUnset("ARENET_GEOIP_ASN_MMDB"),
		"secret_key_file", setUnset(envSecretKeyFile),
	}
	return attrs
}

// setUnset returns "set" when the env var is present and non-empty,
// "unset" otherwise. Used for secret / presence-only vars so the log
// confirms the var was read without ever printing its value.
func setUnset(envKey string) string {
	if os.Getenv(envKey) != "" {
		return "set"
	}
	return "unset"
}
