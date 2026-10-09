// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Step J.1: one backend in a Route's upstream pool. Replaces the
 * pre-J.1 single upstreamUrl string. Weight defaults to 1 and is
 * only consulted by the weighted_round_robin LB policy; other
 * policies ignore it.
 */
export interface Upstream {
	url: string;
	weight: number;
}

/**
 * Step J.1: load-balancing selection policy enum. Must match the
 * six storage.LBPolicy* constants on the backend exactly; drift
 * would be caught by the route create / update returning a 400.
 */
export type LBPolicy =
	| 'round_robin'
	| 'weighted_round_robin'
	| 'least_conn'
	| 'ip_hash'
	| 'random'
	| 'first';

/**
 * Step J.2: per-route active health check. Mirrors storage.HealthCheck
 * (9 fields). When Enabled is false the other eight fields are inert
 * — the server emits no Caddy `health_checks` block.
 *
 * The five defaultable fields (method, interval, timeout, passes,
 * fails) are materialised by the server before validation. URI is
 * the one field operators must always supply when Enabled is true.
 *
 * Wire semantics on PUT (J.2 decision): the block is preserve-or-
 * replace, never partial. Send the complete 9-field block (full
 * replacement) OR omit the block entirely (preserve previous);
 * never a partial block, because every omitted sub-field resets to
 * its server-side default. See docs/backlog-step-j.md "J.3 frontend
 * — health-check is preserve-or-replace, never partial".
 */
export interface HealthCheck {
	enabled: boolean;
	uri: string;
	method: 'GET' | 'HEAD' | '';
	interval: string;
	timeout: string;
	/**
	 * 0 accepts any 2xx. 1-5 is Caddy's status-class shorthand, so 3
	 * accepts every 3xx — what an app that redirects to a login page
	 * needs. Anything else is a literal status in 100..599.
	 */
	expectStatus: number;
	expectBody: string;
	passes: number;
	fails: number;
	/**
	 * v2.55 — the Host the probe sends. Empty means the route's own
	 * host, which is what the real traffic carries.
	 *
	 * Caddy builds the probe from the upstream's dial address, so
	 * before v2.55 it asked `Host: 10.0.0.2:80`. A backend that routes
	 * on Host answered 404 and every upstream went down while serving
	 * its route perfectly.
	 */
	hostHeader?: string;
	/** Extra probe headers, e.g. an Authorization the endpoint wants. */
	headers?: Record<string, string>;
}

/** v2.35 — post-apply probe of a create / update / enable. */
export interface RouteCheck {
	status: 'ok' | 'failed' | 'pending_certificate' | 'skipped';
	host?: string;
	httpStatus?: number;
	detail?: string;
}

/**
 * v2.44 — the route-level redirect state.
 *
 * Present only when the route redirects instead of proxying. The
 * target must be on a DIFFERENT host: a target on this route's own
 * host matches the redirect that produced it, and the server refuses
 * it at save. Sending "/" somewhere else on the same host is the path
 * rule's job, not this one.
 */
export interface RedirectConfig {
	/** Absolute URL, scheme + host. No path when preservePath is on. */
	target: string;
	/** 301 or 302. Omitted means 301. */
	statusCode?: number;
	/** Appends the visitor's own path AND query to the target. */
	preservePath?: boolean;
}

export interface Route {
	id: string;
	host: string;
	/** Present on create / update / enable responses only (v2.35). */
	check?: RouteCheck;
	/**
	 * Step J.1: pool of backends. Always non-empty (the backend's
	 * storage.validate() guarantees it). A migrated pre-J.1 route
	 * carries a one-element pool with the legacy URL at index 0.
	 */
	upstreams: Upstream[];
	/**
	 * Step J.1: LB selection policy. Always one of the six LBPolicy
	 * enum values on a stored route.
	 */
	lbPolicy: LBPolicy;
	tlsEnabled: boolean;
	/**
	 * Step I.1 (wired by I.2): when true and tlsEnabled is also true,
	 * HTTP requests on :80 are 301-redirected to https://. Ignored when
	 * tlsEnabled is false.
	 */
	redirectToHttps: boolean;
	/**
	 * Step I.3: additional hostnames served by the same upstream + same
	 * TLS cert (multi-SAN). The server normalizes the wire shape to an
	 * empty array (never null), so callers can read .length without a
	 * null check.
	 */
	aliases: string[];
	/**
	 * Step K.1 — per-route auth mode. Replaces the Step I.5 flat
	 * basicAuthEnabled boolean with a three-valued radio enum:
	 *   - "none":        no auth gate on the route.
	 *   - "basic":       Step I.5 HTTP Basic Auth, preserved.
	 *   - "forward_auth": delegated to an external IdP via Caddy
	 *                    forward_auth (Authelia / Authentik /
	 *                    Keycloak / generic).
	 * Mutually exclusive (§1.3 decision 2). The server normalises
	 * the storage zero value "" to "none" so the wire always
	 * carries an explicit enum value.
	 */
	authMode: RouteAuthMode;
	/**
	 * Step K.1 — Basic Auth response sub-shape (replaces the flat
	 * Step I.5 basicAuthEnabled / basicAuthUsername /
	 * basicAuthPasswordSet triplet). Active only when authMode ==
	 * "basic". The plaintext password and the argon2id hash are
	 * NEVER on the wire response; passwordSet tells the UI whether
	 * a hash exists so it can render the "••• set" placeholder on
	 * Edit.
	 */
	basicAuth: BasicAuthResponse;
	/**
	 * Step K.1 — Forward-auth response sub-shape. Active only when
	 * authMode == "forward_auth". Carries the reference to the
	 * instance-level provider (configured via Settings).
	 */
	forwardAuth: ForwardAuthResponse;
	/**
	 * Step I.6 — custom headers applied to the proxied request /
	 * response. Map of name → value (single value per name in v1.0).
	 * Server normalizes nil → empty object on the wire, so callers
	 * iterate Object.keys without a null check.
	 */
	requestHeaders: Record<string, string>;
	responseHeaders: Record<string, string>;
	/**
	 * Step I.4 — WAF mode. Replaces the pre-I.4 wafEnabled bool with
	 * a three-valued enum:
	 *   - "off":    no WAF inspection.
	 *   - "detect": Coraza/OWASP CRS inspects and logs matches but
	 *               lets traffic through (FortiWeb-style safe-shadow,
	 *               the recommended starting point).
	 *   - "block":  Coraza returns 403 on match.
	 */
	wafMode: 'off' | 'detect' | 'block';
	/**
	 * Step J.2 — active health check. Always present on a stored
	 * route (storage.HealthCheck has no omitempty); a route created
	 * pre-J.2 reads back with the zero-value HealthCheck (Enabled
	 * false, every sub-field at zero).
	 */
	healthCheck: HealthCheck;
	/**
	 * Step J.4 — ACME challenge type. The backend normalises the
	 * pre-J.4 storage zero value "" to "http-01" before serialising,
	 * so callers always see one of the enum values on the wire.
	 * Step O.1 adds "inherited" for routes covered by a managed-
	 * domain wildcard; the frontend hides the ACME selector and
	 * shows an inheritance badge instead.
	 */
	acmeChallenge: ACMEChallenge;
	/**
	 * Step O.1 — per-route opt-out from a covering managed-domain
	 * wildcard (spec D1.B). When true on a covered route, the route
	 * emits its own per-route ACME cert alongside the wildcard.
	 * Omitted on the wire for pre-O routes (`omitempty` on the Go
	 * side); default false.
	 */
	useDedicatedCert?: boolean;
	/**
	 * Step O.3 — derived field telling the operator which TLS policy
	 * actually serves this route's cert (spec AC #4). One of:
	 *   - "managed-domain:<apex>"
	 *   - "per-route-acme:dns-01"
	 *   - "per-route-acme:http-01"
	 *   - "per-route-internal"
	 * Empty / omitted for routes without TLS (the dashboard hides
	 * the badge in that case).
	 */
	effectiveCertSource?: string;
	/**
	 * Critique 11 Pack A (2026-06-05) — derived per-route health
	 * rollup the Routes API computes from the Stage B HC tracker.
	 *   "healthy"        — HC enabled AND every upstream healthy
	 *   "degraded"       — HC enabled, at least one unhealthy upstream
	 *   "down"           — HC enabled AND every upstream unhealthy
	 *   "unknown"        — HC enabled, warm-up window with no
	 *                      unhealthy signal yet
	 *   "not_monitored"  — HC disabled (operator deliberately chose
	 *                      not to monitor ; distinct from warm-up
	 *                      "unknown" so the UI can render a clear
	 *                      "HC inactif" label vs the ambiguous
	 *                      "still observing" gray badge)
	 * Always present on a route response. See the backend
	 * `computeRouteAggregateHealth` docstring for the full
	 * precedence table.
	 */
	aggregateStatus:
		| 'healthy'
		| 'degraded'
		| 'down'
		| 'unknown'
		| 'not_monitored'
		/**
		 * v2.59 — the route proxies nothing, so it has no health to
		 * report. Today that is a redirecting route: it answers from
		 * Caddy itself, carries no upstream, and nothing will ever
		 * probe anything. It used to arrive as 'unknown', which the
		 * list renders as a warm-up window — one that can never
		 * close on a route with neither HC nor backend.
		 */
		| 'not_applicable';
	/**
	 * Step W — per-route country-block gate state.
	 * Always present (storage zero-value reads back as
	 * `{mode: 'off', countryList: [], statusCode: 0}` via
	 * the W.2 toResponse normalisation). Frontend renders
	 * the "Pays bloqués" form section + shows a badge in
	 * the route row when mode != 'off'.
	 */
	countryBlock: CountryBlock;
	/**
	 * Step #R-PROXMOX-HTTPS-LOOP — when true and the upstream
	 * pool uses `https://`, the embedded Caddy emits
	 * `transport.tls.insecure_skip_verify=true` so it accepts
	 * self-signed / IP-SAN-mismatched upstream certs (Proxmox,
	 * Synology DSM, ESXi, UniFi). Always present on a stored
	 * route (zero-value false = strict cert validation against
	 * the host trust store). On HTTP-only pools the field is
	 * meaningless — the backend silently normalises it to false
	 * on create/update with a warn-log (no `transport.tls`
	 * block ever emitted for an http pool).
	 */
	insecureSkipVerify: boolean;
	/**
	 * v2.60 — the name Caddy presents in SNI and verifies the
	 * backend certificate against. '' means Caddy's default (both
	 * derived from the upstream address). Always present on a
	 * route response so a GET→PUT roundtrip carries it back.
	 */
	upstreamTlsServerName: string;
	/**
	 * Phase 4.5 (#R-WAF-BUFFER-OOM-ON-LARGE-UPLOADS) — when
	 * true, the route bypasses the two RAM-buffering surfaces
	 * that explode on big request bodies (Docker registry
	 * pushes, file servers, backups):
	 *
	 *   1. WAF body inspection — the arenet_waf handler skips
	 *      ReadRequestBodyFrom so Coraza never stages the
	 *      upload in memory. Headers, URI, and response phases
	 *      stay live; only the body is unscanned.
	 *   2. Caddy reverse_proxy buffering — caddymgr emits
	 *      `flush_interval: -1` so bytes stream through
	 *      end-to-end.
	 *
	 * Always present (storage zero-value reads back as false
	 * via the API response normalisation). The frontend toggle
	 * lives in the route's WAF settings block — coupling the
	 * affordance with the security knob it modulates is the
	 * clearer mental model than burying it under "advanced TLS".
	 *
	 * Independent of wafMode: any combination is operator-valid.
	 * The common shape is {wafMode: 'block', uploadStreamingMode:
	 * true} for binary-upload routes (headers blocked, body
	 * left alone — body inspection on opaque streams is high
	 * false-positive and zero security signal).
	 */
	uploadStreamingMode: boolean;
	/**
	 * Step X.1 — per-route opt-out from the OWASP CRS load. When
	 * true, the route's arenet_waf handler runs with NO @-Includes
	 * (no @coraza.conf-recommended, no @crs-setup, no
	 * @owasp_crs/*.conf), so Coraza loads zero rules even when the
	 * mode is detect or block. The handler is still wired — the
	 * event sink + audit log + dashboard counter all stay alive —
	 * so flipping the flag back to false re-engages the full CRS
	 * without any storage migration.
	 *
	 * Use case : trusted internal API on the LAN where the operator
	 * wants the WAF infrastructure observable + cheap (per-request
	 * cost ~ Coraza dispatch, no rule evaluation) but doesn't need
	 * the ~10 ms latency + ~50 MB RAM of the full CRS rule set.
	 *
	 * Default false (CRS loaded). Always present (storage
	 * zero-value reads back as false via the response shape). The
	 * frontend toggle lives in the WAF settings block alongside
	 * uploadStreamingMode + wafMode. ADR D2 (inverted polarity)
	 * explains why the field defaults to "not disabled" rather
	 * than the positive "loaded": zero-value alignment with
	 * pre-X.1 stored rows.
	 */
	wafDisableCRS: boolean;
	/**
	 * Step X Option (c) — per-route OWASP CRS rule-ID
	 * exclusion list. Always present (zero-length [] when
	 * the operator has configured no exclusions) so a
	 * GET → PUT round-trip echoes the field verbatim
	 * without triggering the preserve-on-omit semantic on
	 * the put side. Server-side canonical : ascending
	 * sort + dedup.
	 *
	 * Use case : surgical false-positive fix. Operator sees
	 * rule 942100 trip on a legitimate POST in
	 * /security/<routeId>, copies the ID into this list,
	 * the route stops blocking that specific rule while
	 * the rest of the CRS stays active.
	 */
	wafExcludeRules: number[];
	/**
	 * Step X Option (e) (2026-06-22) — per-route CRS tag
	 * exclusion list. Always present (zero-length array
	 * when no exclusions configured) so a GET→PUT
	 * roundtrip doesn't trip the preserve-on-omit
	 * semantic. Server-side canonical : lowercase + dedup
	 * + ascending sort. Operator-friendly sibling of
	 * wafExcludeRules — instead of pinning 15 rule IDs
	 * one by one, exclude the tag family they share (e.g.
	 * "attack-protocol" covers every CRS rule with that
	 * tag, including future rules added in CRS updates).
	 */
	wafExcludeTags: string[];
	/**
	 * v2.36 — targeted exclusions: one CRS rule stops inspecting one
	 * field (optionally on one path). Always present ([] when none).
	 */
	wafTargetedExclusions: WafTargetedExclusion[];
	/** v2.37 — guided rules. Always present ([] when none). */
	wafCustomRules: WafCustomRule[];
	/** v2.38 — expert SecLang ("" when none). */
	wafSecLang: string;
	/**
	 * Step Q (2026-06-18) — per-route rate-limit config.
	 * null when no rate limit configured ; non-null
	 * carries the operator-supplied (events, window, key)
	 * tuple. Default null. The /routes form's toggle reads
	 * the null as "off" and seeds defaults when flipped on.
	 */
	rateLimit: RouteRateLimit | null;
	/**
	 * Step R Phase 1 — UUID of an attached ErrorPageTemplate,
	 * or empty string when none. The built-in Arenet branded
	 * default applies for every code when this is empty.
	 * Response shape uses omitempty so an empty value may
	 * arrive as undefined instead of "".
	 */
	errorPageTemplateId?: string;
	/**
	 * Step R Phase 1 — per-route HTML body overrides keyed
	 * by HTTP status code. Highest precedence in the 3-layer
	 * resolution (override → template → default). May be
	 * undefined when the route has no overrides.
	 */
	errorPageOverrides?: Record<number, string>;
	/**
	 * Count of upstreams the HC tracker has observed as healthy.
	 * Zero on routes without HC configured (the C13 gate doesn't
	 * peek at tracker state). Used by the Routes table to render
	 * "N/M sains" when the pool has multiple upstreams.
	 */
	healthyUpstreamCount: number;
	totalUpstreamCount: number;
	createdAt: string;
	updatedAt: string;
	/**
	 * v2.14.3 — route disable/enable. When true, the route is
	 * excluded from the emitted Caddy config (serves no traffic,
	 * config preserved). Always present on a stored route
	 * (storage zero-value reads back as false).
	 */
	disabled?: boolean;
	/**
	 * Task 8/9 — route maintenance mode. When present (non-null),
	 * the route is in maintenance: Caddy keeps the route emitted
	 * (the host/TLS server stays alive — unlike `disabled`, a
	 * maintenance route does NOT drop the last-active-HTTPS :443
	 * server) but responses are replaced with a maintenance page,
	 * except for the configured bypass IPs/CIDRs. Absent/undefined
	 * when the route is not in maintenance. Mutually exclusive
	 * with `disabled` in the UI's 3-state model (RouteStateControl):
	 * disabled takes precedence when both happen to be set.
	 */
	maintenanceConfig?: MaintenanceConfig;
	/** v2.44 — present only when the route redirects. */
	redirectConfig?: RedirectConfig;
	/**
	 * v2.19.0 external-certs SOCLE — cert provider selector.
	 *   - "" / "acme"  → ACME-issued cert (managed-domain wildcard,
	 *                    per-route http-01/dns-01; the default).
	 *   - "internal"   → Caddy internal self-signed CA.
	 *   - "manual"     → an operator-uploaded external cert,
	 *                    referenced by `cert_id`.
	 *
	 * WIRE NAME IS snake_case (`cert_source`) — the sole exception to
	 * the otherwise-camelCase route wire shape. The API client does
	 * no case transformation (res.json() cast straight to the type),
	 * so the TS property MUST be `cert_source` to round-trip; a
	 * camelCased `certSource` would ship an unknown field and the
	 * backend's DisallowUnknownFields decoder would 400. omitempty on
	 * the Go side means a pre-v2.19.0 route reads back with the field
	 * absent (undefined), which the form treats as "acme".
	 */
	cert_source?: string;
	/**
	 * v2.19.0 external-certs SOCLE — ExternalCertificate.id the route
	 * serves when `cert_source === 'manual'`. Empty / absent for any
	 * other source. snake_case on the wire for the same reason as
	 * `cert_source` above.
	 */
	cert_id?: string;
	/**
	 * path-based-rules Task 1-6 — per-route IP allow/deny gate.
	 * Always present on a stored route (storage zero-value reads
	 * back as `{mode: '', cidrs: [], statusCode: 0}`), mirroring
	 * countryBlock's always-present contract. mode:
	 *   - ""     → not yet configured (treated the same as "off").
	 *   - "off"  → gate disabled, all traffic passes through.
	 *   - "allow" → only listed CIDRs/IPs may pass.
	 *   - "deny"  → listed CIDRs/IPs are blocked, everyone else passes.
	 */
	ipFilter?: IPFilter;
	/**
	 * path-based-rules Task 1-6 — per-path sub-rules (basic auth
	 * and/or IP filter scoped to a path prefix under this route).
	 * Always present on a stored route as an array (possibly empty).
	 */
	pathRules?: PathRule[];
}

/**
 * Task 8/9 — per-route maintenance-mode configuration. Mirrors the
 * backend's wire shape for `Route.maintenanceConfig` /
 * `RouteRequest.maintenanceConfig`.
 */
export interface MaintenanceConfig {
	/**
	 * Value sent in the `Retry-After` header of the maintenance
	 * response, in seconds. Operator-facing hint for how long the
	 * client should wait before retrying.
	 */
	retryAfterSeconds: number;
	/**
	 * IPs/CIDRs allowed to bypass the maintenance page and reach
	 * the real upstream — lets the operator keep testing the
	 * backend while the public-facing route serves the
	 * maintenance page to everyone else. Always a definite array
	 * (possibly empty) on the wire.
	 */
	bypassIps: string[];
	/**
	 * Per-route maintenance message rendered via the
	 * `{arenet.maintenance.message}` placeholder (v2.18.1). When empty,
	 * the emission falls back to the global message
	 * (Settings → Error Pages → Maintenance). Plain text — HTML-escaped
	 * at serve time.
	 */
	message?: string;
}

/**
 * Step J.4 — per-route ACME challenge type. "http-01" is the
 * default (and the pre-J.4 behaviour). "dns-01" is required for
 * wildcard hosts and depends on a configured DNS provider in
 * Settings. Step O.1 adds "inherited" for routes covered by a
 * managed-domain wildcard.
 */
export type ACMEChallenge = 'http-01' | 'dns-01' | 'inherited';

/**
 * Step K.1 — per-route auth mode enum. See Route.authMode for
 * the per-value semantics.
 */
export type RouteAuthMode = 'none' | 'basic' | 'forward_auth';

/**
 * Step K.1 — Basic Auth response shape. Surfaces username +
 * passwordSet flag; the hash and plaintext are never on the wire.
 */
export interface BasicAuthResponse {
	username: string;
	passwordSet: boolean;
}

/**
 * Step K.1 — Forward-auth response shape. Carries only the
 * provider reference; the provider configuration itself is
 * GET'd via the Settings endpoint.
 */
export interface ForwardAuthResponse {
	providerName: string;
}

/**
 * Step K.1 — Basic Auth request shape. password is the PLAIN
 * text on the wire (write-only): leave empty on Edit to keep
 * the existing hash; provide a fresh value to rotate.
 */
export interface BasicAuthRequest {
	username: string;
	password: string;
}

/**
 * Step K.1 — Forward-auth request shape. Mirrors the response
 * shape — only the provider reference.
 */
export interface ForwardAuthRequest {
	providerName: string;
}

/**
 * Step K.1 — instance-level forward-auth provider as returned by
 * the Settings API. The client_secret is always blanked on the
 * wire; clientSecretSet flags the UI to render the "••• set"
 * placeholder. Mirrors the J.4 DNS-provider redaction shape.
 */
export interface ForwardAuthProvider {
	name: string;
	kind: ForwardAuthProviderKind;
	verifyUrl: string;
	authRequestUri: string;
	copyHeaders: string[];
	clientSecret: string; // always "" on the wire (redacted)
	clientSecretSet: boolean;
	/**
	 * Step K.4 — optional path prefix served by the IdP itself
	 * on the application's external host. Non-empty makes the
	 * generator emit a passthrough route bypassing the
	 * forward_auth gate for that subtree (required for the
	 * Authentik embedded outpost pattern + oauth2-proxy).
	 * Empty = legacy K.1 behaviour.
	 */
	authPassthroughPrefix: string;
	/**
	 * Step K.4 parity fix — when true, the forward_auth sub-
	 * request's Host header is rewritten to the verify URL's
	 * host. Required for IdPs that route apps by Host
	 * (Authentik embedded outpost). Default false = canonical
	 * Caddy expansion (client Host propagated).
	 */
	rewriteVerifyHost: boolean;
	createdAt: string;
	updatedAt: string;
}

/**
 * Step K.1 — wire shape for POST / PUT
 * /api/v1/settings/forward-auth/providers. The clientSecret is
 * write-only; empty on PUT preserves the previously stored
 * value (Step J.4 preserve-on-edit pattern).
 */
export interface ForwardAuthProviderRequest {
	name: string;
	kind: ForwardAuthProviderKind;
	verifyUrl: string;
	authRequestUri: string;
	copyHeaders: string[];
	clientSecret: string;
	authPassthroughPrefix?: string;
	rewriteVerifyHost?: boolean;
}

/**
 * Step K.1 — supported forward-auth provider kinds. Drives UI
 * presets (default verify URL, default copy-headers list);
 * server stores the enum as-is.
 */
export type ForwardAuthProviderKind = 'authelia' | 'authentik' | 'keycloak' | 'generic';

export const FORWARD_AUTH_PROVIDER_KINDS: readonly ForwardAuthProviderKind[] = [
	'authelia',
	'authentik',
	'keycloak',
	'generic'
] as const;

export interface RouteRequest {
	host: string;
	/**
	 * Step J.1: pool of backends. Repeater on the form; at least one
	 * entry; per-element URL + weight. Server materialises Weight=0
	 * → 1 before validation, so an omitted weight is fine.
	 */
	upstreams: Upstream[];
	/**
	 * Step J.1: LB selection policy. Empty string on POST means
	 * "give me the default round_robin"; empty on PUT preserves the
	 * previously stored value (same UX as wafMode). The form sends
	 * the explicit value when the LB selector is visible (pool size
	 * ≥ 2), otherwise sends "" so the backend default applies.
	 */
	lbPolicy: LBPolicy | '';
	tlsEnabled: boolean;
	redirectToHttps: boolean;
	aliases: string[];
	/**
	 * Step K.1 — per-route auth mode. Empty string on POST is
	 * normalised to "none" by the server; empty on PUT preserves
	 * the previously stored value (same UX as wafMode).
	 */
	authMode: RouteAuthMode | '';
	/**
	 * Step K.1 — Basic Auth request shape. Active only when
	 * authMode == "basic". password is write-only (empty on Edit
	 * keeps the existing hash; new value rotates). When authMode
	 * != "basic", set username/password to "" (the server
	 * enforces this mutual exclusion at the validation layer).
	 */
	basicAuth: BasicAuthRequest;
	/**
	 * Step K.1 — Forward-auth request shape. Active only when
	 * authMode == "forward_auth". When authMode != "forward_auth",
	 * providerName must be "" (mutual exclusion).
	 */
	forwardAuth: ForwardAuthRequest;
	requestHeaders: Record<string, string>;
	responseHeaders: Record<string, string>;
	/**
	 * Step I.4 — WAF mode. On POST, empty string is normalized to
	 * "detect" by the server. On PUT, empty string preserves the
	 * previously stored value (mirrors the I.5 password preserve UX).
	 */
	wafMode: 'off' | 'detect' | 'block' | '';
	/**
	 * Step J.2 — active health check. OPTIONAL field with
	 * preserve-or-replace semantics on PUT (J.2 decision):
	 *   - omitted (undefined)         → preserve previously stored
	 *     HealthCheck verbatim. The form uses this when the user did
	 *     not touch the HC sub-form.
	 *   - present with all 9 fields   → full replacement. The server
	 *     materialises the five defaultable fields if blank.
	 *
	 * Never ship a partial block: every omitted sub-field of a
	 * present block resets to its server-side default. See
	 * docs/backlog-step-j.md.
	 */
	healthCheck?: HealthCheck;
	/**
	 * Step J.4 — ACME challenge type. Empty string on POST/PUT is
	 * normalised by the backend to "http-01" (no preserve-on-omit
	 * semantic — the value carries no secret and is naturally
	 * supplied on every form submit). The backend (O.3) may
	 * rewrite the value to "inherited" if the host is covered by
	 * a managed domain AND useDedicatedCert is false; the
	 * frontend doesn't send "inherited" directly.
	 */
	acmeChallenge: ACMEChallenge | '';
	/**
	 * Step O.1 — opt-out from a covering managed-domain wildcard
	 * (spec D1.B). Default false. Omitting the field on the wire
	 * is equivalent to false. When true on a route whose host is
	 * covered by a managed domain, the route emits its own
	 * per-route ACME cert alongside the wildcard. Sending true on
	 * an uncovered route is rejected by the backend with 400.
	 */
	useDedicatedCert?: boolean;
	/**
	 * Step W — per-route country-block gate. OPTIONAL with
	 * preserve-or-replace semantics on PUT (same shape as
	 * healthCheck):
	 *   - omitted (undefined) → preserve previously stored
	 *     CountryBlock verbatim. The form uses this when the
	 *     user did not touch the CountryBlock sub-form.
	 *   - present → full replacement. The server validates
	 *     the §D2 footgun (mode=allow + empty list rejected).
	 *
	 * On POST omission, the server creates the route with
	 * `{mode: 'off'}` (the canonical disabled default).
	 */
	countryBlock?: CountryBlockRequest;
	/**
	 * Step #R-PROXMOX-HTTPS-LOOP — opt-out from upstream TLS
	 * cert verification on https pools. OPTIONAL with the same
	 * preserve-on-omit semantic as `healthCheck` / `countryBlock`:
	 *   - omitted (undefined) on POST → strict default (false).
	 *   - omitted (undefined) on PUT  → preserve previously
	 *                                   stored value.
	 *   - present (true | false)      → full replacement.
	 *
	 * HTTP-only pools silently normalise to false on the backend
	 * (with a warn-log). The form mirrors this by resetting
	 * formData.insecureSkipVerify=false on a https→http scheme
	 * transition, so the on-screen state and the storage state
	 * never diverge.
	 */
	insecureSkipVerify?: boolean;
	/**
	 * v2.60 — absent preserves the stored name on PUT; an
	 * explicit '' clears it. Normalised away by the server on an
	 * http-only pool.
	 */
	upstreamTlsServerName?: string;
	/**
	 * Phase 4.5 — uploadStreamingMode toggle on the wire.
	 * Same preserve-on-omit semantic as insecureSkipVerify:
	 *   - omitted on POST → strict default (false)
	 *   - omitted on PUT  → preserve previously stored value
	 *   - present (true | false) → full replacement
	 */
	uploadStreamingMode?: boolean;
	/**
	 * Step X.1 — wafDisableCRS toggle on the wire. Mirror of
	 * uploadStreamingMode's preserve-on-omit shape (the backend
	 * routeRequest uses *bool with the exact same semantic).
	 *   - omitted on POST → default false (CRS loaded — pre-X.1
	 *                       byte-equivalent runtime).
	 *   - omitted on PUT  → preserve previously stored value.
	 *   - present (true | false) → full replacement.
	 */
	wafDisableCRS?: boolean;
	/**
	 * Step X Option (c) — wafExcludeRules on the wire. Preserve-
	 * on-omit on PUT (matching the *[]int backend shape), full-
	 * replace on supply. Sending [] explicitly clears every
	 * previously-stored exclusion. Server-side : each ID is
	 * validated 6-digit (range 100000..999999), Arenet-reserved
	 * range 100000..199999 rejected ; the stored slice is the
	 * canonical sorted + deduped form.
	 */
	wafExcludeRules?: number[];
	/**
	 * Step X Option (e) — wafExcludeTags on the wire. Same
	 * preserve-on-omit + full-replace semantic as
	 * wafExcludeRules. Server-side canonicalisation : lowercase
	 * + dedup + ascending sort ; rejects characters that would
	 * smuggle ctl: actions into the SecAction directive line
	 * (comma, whitespace, double-quote).
	 */
	wafExcludeTags?: string[];
	/** v2.36 — targeted exclusions; omit = keep, [] = clear. */
	wafTargetedExclusions?: WafTargetedExclusion[];
	/** v2.37 — guided rules; omit = keep, [] = clear. */
	wafCustomRules?: WafCustomRule[];
	/** v2.38 — expert SecLang; omit = keep, "" = clear. */
	wafSecLang?: string;
	/**
	 * Step Q (2026-06-18) — per-route rate limit on the wire.
	 * Preserve-on-omit on PUT (omit → keep stored value),
	 * full-replace when supplied. Server-side validation :
	 * events >= 1, window parses via time.ParseDuration AND
	 * is strictly positive ; key defaults to {http.request.
	 * remote.host} at emit time when empty.
	 */
	rateLimit?: RouteRateLimit;
	/**
	 * v2.9.13 Phase Q.2 — sentinel that explicitly removes a
	 * previously-stored rate-limit on PUT (or no-op on POST).
	 * When true, the backend handler sets RateLimit=nil and
	 * ignores any rateLimit body present in the same payload.
	 * When false / absent (default), the legacy preserve-on-omit
	 * semantic applies — every existing client that doesn't
	 * know about this field keeps the same observable behaviour.
	 *
	 * Set true by the frontend when the operator un-ticks the
	 * rate-limit toggle and saves: the UI form's rateLimit slot
	 * is null, so the payload would otherwise omit the field
	 * and the backend would preserve the previously-stored
	 * value (operator-reported 2026-06-26 bug closure).
	 */
	clearRateLimit?: boolean;
	/**
	 * Step R Phase 1 — UUID of an ErrorPageTemplate this
	 * route opts into. Empty string / absent → built-in
	 * Arenet branded default applies for every code.
	 */
	errorPageTemplateId?: string;
	/**
	 * Step R Phase 1 — per-route HTML body overrides keyed
	 * by HTTP status code. Highest precedence in the 3-layer
	 * resolution (override → template → default). Allowed
	 * keys : 401, 403, 404, 429, 500, 502, 503, 504.
	 */
	errorPageOverrides?: Record<number, string>;
	/**
	 * v2.14.3 — route disable/enable flag. The route form
	 * sends this on every POST/PUT (create/update); when
	 * omitted on the wire, defaults to false (enabled). A
	 * dedicated toggle endpoint (POST /routes/{id}/disable|enable)
	 * also exists for row-level state changes without a full-body PUT.
	 */
	disabled?: boolean;
	/**
	 * Task 8/9 — route maintenance-mode config. The form ships
	 * this full-replacement on every POST/PUT alongside the rest
	 * of the maintenance-section fields; omitted means "not in
	 * maintenance" (mirrors the row-level dedicated endpoints
	 * POST /routes/{id}/maintenance and .../maintenance/off, which
	 * exist for changing state without a full-body PUT).
	 */
	maintenanceConfig?: MaintenanceConfig;
	/**
	 * v2.44 — the redirect state, shipped full-replacement like the
	 * maintenance block above. Omitted means "not redirecting", and
	 * the server clears a stored redirect when a PUT explicitly
	 * re-enables the route without carrying one.
	 */
	redirectConfig?: RedirectConfig;
	/**
	 * v2.19.0 external-certs SOCLE — cert provider on the wire.
	 * The route form ships this full-replacement on every POST/PUT
	 * ("" / "acme" / "internal" / "manual"). snake_case wire name
	 * (see Route.cert_source) — the backend routeRequest decodes
	 * `cert_source` and rejects unknown fields, so this MUST stay
	 * snake_case to avoid a 400.
	 */
	cert_source?: string;
	/**
	 * v2.19.0 external-certs SOCLE — referenced external cert id.
	 * Shipped only when `cert_source === 'manual'` (mirrors the
	 * acmeChallenge-only-under-tls discipline: don't synthesize a
	 * manual reference on a non-manual route). snake_case wire name.
	 */
	cert_id?: string;
	/**
	 * path-based-rules Task 1-6 — per-route IP allow/deny gate on
	 * the wire. Optional; the form ships this full-replacement on
	 * every POST/PUT alongside the rest of the security-section
	 * fields (same discipline as maintenanceConfig — no preserve-
	 * on-omit ambiguity to reason about at the frontend layer).
	 */
	ipFilter?: IPFilter;
	/**
	 * path-based-rules Task 1-6 — per-path sub-rules on the wire.
	 * Optional; full-replacement array when supplied.
	 */
	pathRules?: PathRule[];
}

/**
 * path-based-rules — API wire is camelCase (matches the backend
 * routeRequest mirror types). Shared by Route.ipFilter,
 * RouteRequest.ipFilter, and PathRule.ipFilter.
 */
export interface IPFilter {
	mode: '' | 'off' | 'allow' | 'deny';
	cidrs?: string[];
	statusCode?: number;
}

/**
 * path-based-rules — a single path-scoped sub-rule: optional basic
 * auth and/or IP filter, both scoped to requests whose path starts
 * with `pathPrefix`. camelCase wire, mirrors the backend routeRequest
 * PathRule mirror type.
 *
 * basicAuth.password (Task 8) is a PLAIN password on the request
 * side — mirrors route-level basicAuth.password — hashed
 * server-side via auth.HashRoutePassword. The response side never
 * echoes it back (always blanked), so the type keeps it optional
 * rather than splitting request/response shapes.
 */
export interface PathRule {
	pathPrefix: string;
	basicAuth?: { username: string; password?: string };
	ipFilter?: IPFilter;
	/** Per-path upstream routing (v2.23.0). Empty/absent = inherit the
	 *  route's pool. */
	upstreams?: Upstream[];
	lbPolicy?: LBPolicy;
	healthCheck?: HealthCheck;
	/** Per-path TLS skip-verify (v2.23.1). Autonomous — does not inherit the
	 *  route's posture. Only meaningful when the path pool is https. */
	insecureSkipVerify?: boolean;
	/**
	 * v2.60 — this path pool's own TLS server name. Autonomous:
	 * it is never inherited from the route, because a pool that
	 * dials a different address has a different certificate.
	 */
	upstreamTlsServerName?: string;
	/**
	 * v2.44 — match the WHOLE path instead of the sub-tree. Required
	 * for a "/" rule, whose prefix form also matches the redirect's
	 * own target and would loop the browser.
	 */
	matchExact?: boolean;
	/**
	 * v2.44 — answer a redirect for this path instead of proxying it.
	 * The rest of the route keeps being proxied.
	 */
	redirect?: { target: string; statusCode?: number };
	/**
	 * v2.56 — throttles THIS path in ADDITION to the route's own limit,
	 * with its own counters.
	 *
	 * Reason to exist: a login or session endpoint wants a much tighter
	 * limit than the site around it, and raising the route's limit to
	 * protect one path would throttle every asset on the page to slow
	 * down one form.
	 *
	 * Runs before the path's basic auth, so the requests it counts are
	 * the ones that have not authenticated yet.
	 */
	rateLimit?: RouteRateLimit;
	/**
	 * v2.57 — sends THIS path through an identity provider, in ADDITION
	 * to whatever gate the route already has.
	 *
	 * Reason to exist: a path with no authentication of its own — an
	 * exposed metrics endpoint, a debug console, an admin UI with
	 * nothing in front of it. Basic auth was the only per-path identity
	 * gate, and a shared password is a poor answer for an operator who
	 * already runs an IdP.
	 *
	 * Mutually exclusive with this rule's `basicAuth`: one identity gate
	 * per path, not two. The API refuses both with a 400.
	 */
	forwardAuth?: { providerName: string };
	/**
	 * v2.58 — exempt THIS path from the route's own authentication.
	 *
	 * The only thing a path rule subtracts rather than adds. For an
	 * application that needs both at once: an editor behind an IdP, and
	 * webhook / form / OAuth-callback paths reachable by services that will
	 * never hold a session.
	 *
	 * Everything else the route carries still applies — WAF, CrowdSec,
	 * country block, IP filter, rate limit — and the emitted config strips
	 * the identity headers on the exempted path so a client cannot forge
	 * one.
	 */
	disableRouteAuth?: boolean;
}

/**
 * Step Q — per-route rate limit shape, shared by request +
 * response sides. Wire convention :
 *   - events : maximum requests per window (>= 1).
 *   - window : Go-time-parseable duration string ("30s",
 *     "1m", "5m", "1h"). Stored verbatim ; the caddymgr
 *     emit parses via time.ParseDuration.
 *   - key    : Caddy placeholder string used as the
 *     rate-limit zone key. Default at emit time :
 *     "{http.request.remote.host}" (raw socket peer IP,
 *     no X-Forwarded-For trust). Operator can override
 *     to "{http.request.header.X-Forwarded-For}" or
 *     similar when behind a trusted reverse proxy.
 */
export interface RouteRateLimit {
	events: number;
	window: string;
	key?: string;
}

/**
 * Step #R-PROXMOX-HTTPS-LOOP commit 3 — POST
 * /api/v1/routes/test-upstream request shape. One URL per
 * call; the frontend parallelises pool > 1 via Promise.all.
 * `insecureSkipVerify` mirrors the route-level toggle so
 * the probe runs with the same TLS posture the saved route
 * will use.
 */
/**
 * v2.56 — run the active health check with the settings currently in the
 * form, before saving.
 *
 * A misconfigured check used to surface only as a post-save 503 and an
 * undone change, which protected the site and explained nothing. The
 * reported case: a probe against Ghost with no X-Forwarded-Proto, so Ghost
 * answered 301 and the expected 200 never arrived.
 */
export interface TestHealthCheckRequest {
	/** The pool as currently typed, not what is stored. */
	upstreams: Upstream[];
	healthCheck: HealthCheck;
	/** The route's primary host, used as the probe Host unless overridden. */
	routeHost?: string;
	insecureSkipVerify?: boolean;
	/**
	 * v2.60.1 — mirrors the route field so the probe verifies the
	 * certificate against the same name the emitted config does.
	 * Without it Go uses the dial address, and an IP-addressed pool
	 * always failed the probe while the real proxy worked.
	 */
	upstreamTlsServerName?: string;
	/** v2.56.2 — recorded in the audit row's structured target. */
	routeId?: string;
}

/** What the probe sent, so the operator sees the request rather than infers it. */
export interface TestHealthCheckSent {
	method: string;
	url: string;
	host: string;
	headers?: Record<string, string>;
}

/** What came back. Absent when nothing did. */
export interface TestHealthCheckGot {
	statusCode: number;
	durationMs: number;
	/** Redirect target, when there is one. */
	location?: string;
	bodyExcerpt?: string;
	bodyTruncated: boolean;
	/**
	 * Whether expectBody matched. Absent when no expression was configured,
	 * so "no regex" is distinguishable from "did not match".
	 */
	bodyMatched?: boolean;
}

export interface TestHealthCheckResult {
	/** The dial address probed. */
	upstream: string;
	healthy: boolean;
	/** The precise cause when it failed. */
	reason?: string;
	sent: TestHealthCheckSent;
	got?: TestHealthCheckGot;
	/** Attached to an observed redirect; names X-Forwarded-Proto when relevant. */
	hint?: string;
}

export interface TestHealthCheckResponse {
	results: TestHealthCheckResult[];
}

export interface TestUpstreamRequest {
	url: string;
	insecureSkipVerify?: boolean;
	/**
	 * v2.60.1 — mirrors the route field so the probe verifies the
	 * certificate against the same name the emitted config does.
	 * Without it Go uses the dial address, and an IP-addressed pool
	 * always failed the probe while the real proxy worked.
	 */
	upstreamTlsServerName?: string;
	/**
	 * v2.55 — the Host to probe with, so the test asks the question a
	 * visitor asks. Without it the probe carried the upstream address
	 * and a Host-routing backend answered 404 for a healthy service.
	 */
	hostHeader?: string;
	/**
	 * v2.56.2 — the route the probe was launched from, recorded in the
	 * audit row's structured target. Absent in create mode: there is no
	 * route yet.
	 */
	routeId?: string;
}

/**
 * Step #R-PROXMOX-HTTPS-LOOP commit 3 — leaf TLS cert
 * summary returned for every https probe (success AND
 * cert-error). Empty on http probes.
 */
export interface TestUpstreamCertInfo {
	commonName?: string;
	issuer?: string;
	/**
	 * `selfSigned` is the clearer-than-DN-comparison flag —
	 * true when the cert's subject == issuer (canonical
	 * x509 self-signed shape, e.g. homelab Proxmox).
	 */
	selfSigned: boolean;
}

/**
 * Step #R-PROXMOX-HTTPS-LOOP commit 3 — response shape
 * rendered by the per-row result chip.
 *
 *   reachable=true  → handshake + status code returned
 *                     (any code, including 401/403/404 —
 *                     "the service answered").
 *   reachable=false → DNS / TCP / TLS / timeout failure.
 *                     `error` carries operator-readable
 *                     text; `cert` may still be populated
 *                     on TLS verification errors.
 */
export interface TestUpstreamResponse {
	reachable: boolean;
	statusCode?: number;
	latencyMs?: number;
	tlsHandshakeMs?: number;
	cert?: TestUpstreamCertInfo;
	serverHeader?: string;
	bodyPreview?: string;
	error?: string;
}

/**
 * Step W — per-route country-block configuration on the
 * response side. Mirrors W.2 `countryBlockResp` shape with
 * normalised `mode` (zero-value reads back as "off").
 * `statusCode` 0 means "use the env-default" — the form
 * surfaces it as such; per-route override is a future
 * extension W ships preemptively so the schema is stable.
 */
export interface CountryBlock {
	mode: 'off' | 'allow' | 'deny';
	countryList: string[];
	/** v2.27 — MaxMind continent codes (EU, AS, AF, NA, SA, OC, AN). */
	continents: string[];
	/** v2.28 — autonomous system numbers (GeoLite2-ASN). */
	asns: number[];
	/** v2.27 — countries (v2.28: and ASes) a deny gate always lets through. */
	exceptions: CountryBlockExceptions;
	statusCode: number;
}

/** v2.27 — deny-mode exceptions (always-allowed sources). */
export interface CountryBlockExceptions {
	countries: string[];
	/** v2.28 — AS numbers always allowed. */
	asns: number[];
}

/**
 * Step W — per-route country-block configuration on the
 * request side. Mirrors CountryBlock — only difference is
 * statusCode=0 sentinel (clients send 0 when they want the
 * env default, the explicit 403/451/444 when they want a
 * per-route override).
 */
export interface CountryBlockRequest {
	mode: 'off' | 'allow' | 'deny';
	countryList: string[];
	/** v2.27 — optional; omitted or [] = no continent rule. */
	continents?: string[];
	/** v2.28 — optional; omitted or [] = no ASN rule. */
	asns?: number[];
	/** v2.27 — only valid with mode 'deny' (the API rejects otherwise). */
	exceptions?: CountryBlockExceptions;
	statusCode: number;
}

/**
 * v2.12 — multi-config DNS provider view (no secrets on the wire).
 * The backend returns one row per configured provider; `configured`
 * reflects whether every required credential is present, and `usedBy`
 * lists the wildcard apexes currently bound to this provider (drives
 * the 409 `provider_in_use` guard on delete).
 *
 * v2.26 — multi-type: `fields` carries the NON-secret credential values
 * (e.g. OVH endpoint, Route53 region) and `secretsSet` one flag per
 * secret field of the type. `endpoint` is the legacy OVH wire field
 * (empty for other types).
 */
export interface DNSProvider {
	id: string;
	label: string;
	type: string;
	endpoint: string;
	configured: boolean;
	fields: Record<string, string>;
	secretsSet: Record<string, boolean>;
	usedBy: string[];
}

/**
 * v2.26 — wire shape for POST/PUT /api/v1/settings/dns-providers[/{id}].
 * `credentials` is keyed by the registry field keys of `type`. On edit,
 * an absent secret keeps the stored value (preserve-on-edit); an absent
 * non-secret field is cleared. The backend still accepts the pre-v2.26
 * OVH camelCase fields, which the UI no longer sends.
 */
export interface DNSProviderRequest {
	label: string;
	type: string;
	credentials: Record<string, string>;
}

/** v2.26 — one credential field of a provider type (registry). */
export interface DNSProviderField {
	key: string;
	/** English default label; the UI translates by type + key. */
	label: string;
	secret: boolean;
	required: boolean;
	enum?: string[];
	default?: string;
}

/** v2.26 — GET /settings/dns-providers/types entry. */
export interface DNSProviderType {
	type: string;
	label: string;
	docsUrl: string;
	fields: DNSProviderField[];
}

/** v2.26 — POST /settings/dns-providers/{id}/test response. */
export interface DNSProviderTestResult {
	ok: boolean;
	zone: string;
	records: number;
	error?: string;
}

/**
 * Step O.1 — managed-domain declaration. One row per apex; the
 * caddymgr emits ONE wildcard TLS policy covering every route
 * whose host is `<single-label>.<apex>` (plus the bare apex
 * when `includeApex` is true, per spec D2.C).
 *
 * v2.12 — `providerId` references a row in the multi-config DNS
 * provider collection (DNSProvider.id); the pre-v2.12 `provider`
 * enum was removed when the singleton OVH config became a
 * collection.
 */
export interface ManagedDomain {
	apex: string;
	includeApex: boolean;
	providerId: string;
}

/**
 * Step O.1 — POST /api/v1/settings/managed-domains body shape.
 * `includeApex` is optional on the wire (the backend defaults
 * to `true` per spec D2.C when the field is omitted);
 * `providerId` references a row in the DNS provider collection
 * (v2.12) — the backend picks the sole provider when omitted and
 * exactly one is configured.
 */
export interface ManagedDomainRequest {
	apex: string;
	includeApex?: boolean;
	providerId?: string;
}

/**
 * Step O.3 — GET /api/v1/settings/managed-domains envelope.
 * Wrapping in `{ domains: [] }` rather than returning a bare
 * array leaves room for future top-level fields (e.g. a
 * `disabled` flag for AC #13 carry-forward) without breaking
 * the wire contract.
 */
export interface ManagedDomainsListResponse {
	domains: ManagedDomain[];
}

/**
 * Step T T.1 — runtime status enum surfaced by GET /api/certificates.
 * Mirrors internal/certinfo/types.go Status. Locked vocabulary per
 * spec §2 AC #2; the frontend renders one badge variant per value
 * (see web/frontend/src/lib/utils/certificate-format.ts).
 */
export type CertificateStatus =
	| 'VALID'
	| 'RENEWAL_PENDING'
	| 'EXPIRED'
	| 'OBTAIN_FAILED'
	| 'UNKNOWN';

/**
 * Step T T.1 — cert provenance classification. Drives the
 * "<source> · <challenge>" sub-line under the DOMAINE column of
 * the Domaines table. Mirrors internal/certinfo/types.go Source.
 */
export type CertificateSource = 'wildcard' | 'apex' | 'specific';

/**
 * Step T T.1 — GET /api/certificates row shape. Field-by-field
 * mirror of internal/certinfo.CertRuntimeInfo (JSON tags pinned
 * in internal/certinfo/types.go).
 *
 * notBefore / notAfter / lastErrorAt are RFC3339 strings on the
 * wire (Go time.Time JSON encoding). lastError and lastErrorAt
 * are present only when status === 'OBTAIN_FAILED' AND the
 * failure happened within the 24h freshness window enforced
 * server-side; otherwise both fields are omitted.
 */
export interface Certificate {
	domain: string;
	/**
	 * Subject Alternative Names. Pre-hotfix the backend could
	 * marshal this as JSON `null` for OBTAIN_FAILED entries that
	 * never reached the cert_obtained code path (Go nil-slice
	 * gotcha — see internal/certinfo/tracker.go snapshot()). The
	 * backend now coerces nil to [], but the type stays nullable
	 * so older Arenet builds + any future regression are absorbed
	 * by frontend readers via `cert.sanList ?? []`.
	 */
	sanList: string[] | null;
	issuer: string;
	notBefore: string;
	notAfter: string;
	status: CertificateStatus;
	source: CertificateSource;
	lastError?: string;
	lastErrorAt?: string;
}

/**
 * Task 5 — DELETE /api/v1/certificates/{domain} success response
 * shape (internal/api/certificates_delete.go). `deleted` is the
 * count of on-disk cert files removed across all issuers (0 for a
 * "ghost" tracker entry with nothing on disk — still a 200, the
 * delete is idempotent).
 */
export interface CertificateDeleteResult {
	domain: string;
	deleted: number;
}

/**
 * Step O.3 — DELETE /api/v1/settings/managed-domains/{apex}
 * response shape. The `mutatedRoutes` count tells the frontend
 * how many covered routes had their ACMEChallenge reverted, so
 * the post-action toast can surface "N routes reverted to
 * <revertTo>" honestly. Mirrors the audit event's message.
 */
export interface ManagedDomainDeleteResponse {
	mutatedRoutes: number;
}

/**
 * v2.19.0 external-certs SOCLE — a non-blocking advisory the backend
 * attaches to an uploaded certificate at parse time (e.g. "expires
 * soon", "self-signed", "chain does not verify"). Surfaced verbatim
 * on the upload response so the operator sees why a cert may not be
 * ideal without the upload being rejected. `code` is a stable machine
 * token; `message` is the human-readable text.
 */
export interface CertWarning {
	code: string;
	message: string;
}

/**
 * v2.19.0 external-certs SOCLE — wire shape of a bring-your-own
 * certificate stored by Arenet (as opposed to an ACME-issued one).
 * Field-by-field mirror of the backend externalCertResponse
 * (internal/api/external_certs.go).
 *
 * `keyPEM` is ALWAYS redacted to "" on every read path (list + get +
 * the upload response echo) — the private key never leaves the
 * backend after upload. The field is kept in the type so the shape
 * matches the wire, but readers must never rely on it carrying key
 * material.
 *
 * The x509 metadata (issuer/subject/serialNumber/keyAlgorithm/
 * signatureAlgorithm/notBefore/notAfter/dnsNames) is parsed
 * server-side from certPEM at upload time and persisted, so the
 * frontend never parses PEM itself.
 */
export interface ExternalCertificate {
	id: string;
	name: string;
	description?: string;
	certPEM: string;
	chainPEM: string;
	/** Always "" on the wire — private key is redacted on every read. */
	keyPEM: string;
	issuer: string;
	subject: string;
	serialNumber: string;
	keyAlgorithm: string;
	signatureAlgorithm: string;
	notBefore: string;
	notAfter: string;
	dnsNames: string[];
	createdAt: string;
	updatedAt: string;
	/** Non-blocking advisories attached at parse time (may be empty). */
	warnings: CertWarning[];
	/**
	 * v2.20.0 CSR generation — lifecycle state of this row.
	 *   - "" / undefined → an ordinary uploaded/imported certificate.
	 *   - "pending_csr"  → an Arenet-generated keypair awaiting the
	 *     signed cert to be re-imported (PUT) before it can serve
	 *     traffic. certPEM/chainPEM are empty in this state; csrPEM
	 *     carries the CSR to hand to the CA.
	 *
	 * CROSS-TASK RULE: `csrSubject` can serialize as a non-empty-looking
	 * object even on a non-pending row (Go `omitempty` is a no-op on
	 * struct types) — never infer "is this pending?" from `csrSubject`
	 * truthiness or key presence. `status === 'pending_csr'` is the
	 * only authoritative signal.
	 */
	status?: '' | 'pending_csr';
	/**
	 * v2.20.0 CSR generation — the PEM-encoded PKCS#10 CSR generated
	 * server-side alongside the private key. Present when status ===
	 * 'pending_csr'; the private key itself is never on the wire (see
	 * keyPEM). Also downloadable standalone via
	 * externalCertsApi.csrDownloadUrl(id).
	 */
	csrPEM?: string;
	/**
	 * v2.20.0 CSR generation — the subject fields the CSR was
	 * generated with. See the CROSS-TASK RULE on `status` above: may
	 * be present (possibly empty-ish) even when status !== 'pending_csr'.
	 */
	csrSubject?: CSRSubject;
}

/**
 * v2.20.0 CSR generation — the operator-supplied subject fields for a
 * server-generated CSR. Mirrors the backend's CSRSubject shape
 * (internal/api/external_certs.go createExternalCertCSR). `commonName`
 * and `keyAlgorithm` are required; the rest are optional DN components.
 */
export interface CSRSubject {
	commonName: string;
	sans?: string[];
	organization?: string;
	orgUnit?: string;
	country?: string;
	locality?: string;
	state?: string;
	keyAlgorithm: 'rsa_4096' | 'ecdsa_p256';
}

/**
 * v2.20.0 CSR generation — POST /api/v1/certificates/external/csr
 * request body. Generates a keypair + CSR server-side and stores a
 * `pending_csr` row; the private key never leaves the backend.
 */
export interface GenerateCSRRequest {
	name: string;
	description?: string;
	csrSubject: CSRSubject;
}

/**
 * v2.19.0 external-certs SOCLE — POST /api/v1/certificates/external
 * request body. `chainPEM` is optional (a leaf cert may already be
 * self-contained or the operator may omit intermediates); the backend
 * validates certPEM + keyPEM form a matching pair.
 */
export interface ExternalCertUploadRequest {
	name: string;
	description?: string;
	certPEM: string;
	keyPEM: string;
	chainPEM?: string;
}

/**
 * Step O.3 — `revertTo` query parameter value space for
 * DELETE (AC #21). The operator picks at delete time:
 *   - "" → covered routes revert to "" (project default, J-era
 *     fallback → HTTP-01 on next reload).
 *   - "http-01" → explicit per-route HTTP-01 (same effect as
 *     "" but the audit + route detail surface a deliberate
 *     choice).
 *   - "dns-01" → explicit per-route DNS-01 (requires the DNS
 *     provider to remain configured; otherwise the route
 *     serves internal-CA until provider returns).
 */
export type ManagedDomainRevertTo = '' | 'http-01' | 'dns-01';

/**
 * Step P.3 — auto-classify Source enum (mirror of
 * automation.Source in Go). Nine categories: 6 WAF + 2
 * throttle + auth-burst. The frontend renders one Rule row
 * per Source under the Security Automation Card.
 */
export type AutomationSource =
	| 'waf-sqli'
	| 'waf-xss'
	| 'waf-rce'
	| 'waf-lfi'
	| 'waf-protocol'
	| 'waf-other'
	| 'throttle-tier1'
	| 'throttle-tier2'
	| 'auth-burst';

/**
 * Step P.3 — per-Source rule. Mirrors automation.Rule's JSON
 * tags. Threshold / Window / Duration / Cooldown values are
 * inert when Enabled is false (the backend's Validate skips
 * non-enabled rules so a disabled-by-default operator can
 * leave the inputs blank without errors).
 *
 * Durations are nanoseconds on the wire (Go's
 * time.Duration MarshalJSON default). The Settings UI
 * presents human-friendly forms ("60s", "4h") that we
 * convert on submit.
 */
export interface AutomationRule {
	enabled: boolean;
	threshold: number;
	window_ns: number;
	duration_ns: number;
	cooldown_ns: number;
}

/**
 * Step P.3 — the operator-facing rule set. One Rule per
 * Source; the backend's DefaultRuleSet pre-populates every
 * Source on a fresh install, so the map is always full.
 */
export interface AutomationRuleSet {
	rules: Record<AutomationSource, AutomationRule>;
}

/**
 * Step P.3 — GET /api/v1/settings/automation response shape.
 * Rules + credentials in one round-trip so the Settings UI
 * renders the full section state without a second request.
 * Password is ALWAYS redacted (configured flag is the single
 * source of truth for "is the writer wired").
 */
export interface AutomationResponse {
	rules: AutomationRuleSet;
	credentials: AutomationCredentialsView;
}

export interface AutomationCredentialsView {
	lapiUrl: string;
	machineId: string;
	configured: boolean;
}

/**
 * Step P.3 — PUT /api/v1/settings/automation/credentials body.
 * Empty password triggers the preserve-on-edit path (J.4
 * pattern); non-empty overwrites. All-blank fields erase the
 * row + ClearCredentials on the running engine.
 */
export interface AutomationCredentialsRequest {
	lapiUrl: string;
	machineId: string;
	password: string;
}

/**
 * Step P.3 — PUT /api/v1/settings/automation/rules envelope.
 * The single `rules` key mirrors the GET response shape so
 * the same body can be round-tripped without surgery.
 */
export interface AutomationRulesRequest {
	rules: AutomationRuleSet;
}

/**
 * Step P.3 — all known Source values, in the same order the
 * Go AllSources() emits. UI lists rules in this order so the
 * operator-facing layout is deterministic.
 */
export const AUTOMATION_SOURCES: readonly AutomationSource[] = [
	'waf-sqli',
	'waf-xss',
	'waf-rce',
	'waf-lfi',
	'waf-protocol',
	'waf-other',
	'throttle-tier1',
	'throttle-tier2',
	'auth-burst'
] as const;

/**
 * Step P.3 — operator-friendly Source labels for the
 * Settings UI. Keep concise (column header width); the
 * Tooltip / aria-label can carry the longer description.
 */
export const AUTOMATION_SOURCE_LABELS: Record<AutomationSource, string> = {
	'waf-sqli': 'WAF · SQLi',
	'waf-xss': 'WAF · XSS',
	'waf-rce': 'WAF · RCE',
	'waf-lfi': 'WAF · LFI',
	'waf-protocol': 'WAF · Protocol',
	'waf-other': 'WAF · Other',
	'throttle-tier1': 'Throttle · Tier 1',
	'throttle-tier2': 'Throttle · Tier 2',
	'auth-burst': 'Auth · Burst'
};

/**
 * Step P.4 — provenance helper. Returns true iff a CrowdSec
 * decision's scenario was emitted by Arenet's auto-classify
 * loop (D3.3.A prefix convention). Used by the CrowdSec
 * drill-down panel (/security?tab=crowdsec, CS.3) and
 * MixedEventList to render the "auto" badge.
 */
export function isArenetAutoScenario(scenario: string): boolean {
	return scenario.startsWith('arenet/');
}

/**
 * Step K.2 — OIDC SSO configuration as returned by GET
 * /api/v1/settings/oidc. The clientSecret is always blanked on the
 * wire (server-side redaction, mirrors the J.4 DNS-provider and
 * K.1 forward-auth pattern). clientSecretSet flags the UI to
 * render the "••• set" placeholder on Edit.
 */
export interface OIDCConfig {
	enabled: boolean;
	issuerUrl: string;
	clientId: string;
	clientSecret: string; // always "" on the wire (redacted)
	clientSecretSet: boolean;
	scopes: string[];
	redirectUrl: string;
	/**
     * Step #S-17 — opt-in: relax the §1.6 Δ7 guard (email_verified
     * required on Pass 2 bootstrap) for IdPs that don't emit
     * email_verified=true by default (Authentik admin-created
     * accounts being the typical case). Always emitted by the
     * server (default false). Required field on this response
     * shape so the GUI checkbox can reflect the current state.
     */
    acceptUnverifiedEmail: boolean;	
	/**
	 * Provider kind (optional) — drives the SSO button logo on
	 * the login page. Empty = "generic" fallback. Mirrors the
	 * ForwardAuthProviderKind enum.
	 */
	kind: OIDCProviderKind;
	allowedIdentities: OIDCAllowedIdentity[];
	configured: boolean;
}

export type OIDCProviderKind = '' | 'authentik' | 'keycloak' | 'authelia' | 'generic';

export const OIDC_PROVIDER_KINDS: readonly OIDCProviderKind[] = [
	'',
	'authentik',
	'keycloak',
	'authelia',
	'generic'
] as const;

/**
 * Step K.2 — wire shape for PUT /api/v1/settings/oidc. clientSecret
 * is write-only; empty preserves the previously stored value
 * (Step J.4 preserve-on-edit pattern). The allowlist is NOT
 * mutated by this endpoint — use the /allowlist sub-endpoints.
 */
export interface OIDCConfigRequest {
	enabled: boolean;
	issuerUrl: string;
	clientId: string;
	clientSecret: string;
	scopes: string[];
	redirectUrl: string;
    /**
     * Step #S-17 — opt-in: see OIDCConfig.acceptUnverifiedEmail.
     * Optional on the request shape (the backend defaults to
     * false when omitted, matching the OIDCConfig zero value).
     */
    acceptUnverifiedEmail?: boolean;	
	kind?: OIDCProviderKind;
}

/**
 * Phase 2 Users-page refactor — response shape of POST /settings
 * /oidc/test. The "Tester la connexion" button in the
 * OIDCConfigSummary sidebar drives this. Always HTTP 200; the
 * `reachable` flag distinguishes success from probe failure.
 * `missingScopes` is populated only when `scopesMatch` is false,
 * giving the toast an actionable "missing: groups, email" message.
 */
export interface OIDCTestResult {
	reachable: boolean;
	issuer?: string;
	supportedScopes?: string[];
	scopesMatch: boolean;
	missingScopes?: string[];
	latencyMs: number;
	error?: string;
}

/**
 * Step K.2 — one allowlisted identity. Sub is empty until the
 * user's first successful login canonicalises the entry (§5.2);
 * firstLoginAt is the timestamp of that canonicalisation. The UI
 * uses the empty-Sub state to render a "pending" badge.
 */
export interface OIDCAllowedIdentity {
	email: string;
	displayName: string;
	sub: string;
	addedAt: string;
	firstLoginAt?: string;
}

/**
 * Step K.2 — POST /api/v1/settings/oidc/allowlist body. Server
 * lower-cases the email and rejects duplicates.
 *
 * Spec-1 — optional pre-filled `sub`. Non-empty installs the
 * entry as already-canonicalised, bypassing the email-bootstrap
 * path (Δ7 guard not invoked). Required for IdPs that don't
 * emit `email_verified=true` (Authentik admin-created accounts).
 * Empty (default) keeps the pending behaviour: first login goes
 * through the email-bootstrap Pass 2 with the email_verified
 * guard.
 */
export interface OIDCAllowlistAddRequest {
	email: string;
	displayName: string;
	sub?: string;
}

/**
 * Step K.2 — anonymous status endpoint shape (GET /api/v1/auth/
 * oidc/status). The login page reads this to decide whether to
 * render the "Continue with SSO" button. NEVER carries operational
 * details (no issuer URL, no allowlist).
 */
export interface OIDCStatus {
	enabled: boolean;
	/**
	 * Provider kind (optional, may be absent in JSON when empty/
	 * disabled). The login page uses it to pick the right SSO
	 * button logo via SSOProviderLogo. Absent → "generic".
	 */
	kind?: OIDCProviderKind;
}

/**
 * Step K.2 — admin user list entry as returned by GET
 * /api/v1/admin/users. The wire surface OMITS PasswordHash and
 * surfaces OIDCSub only as a boolean (oidcLinked); the raw sub is
 * operational metadata for the storage layer only.
 */
export interface AdminUser {
	id: string;
	username: string;
	displayName: string;
	/**
	 * Email — required on new local accounts (setup flow);
	 * captured best-effort from the OIDC `email` claim on
	 * every login for OIDC users. Empty for legacy local
	 * users that pre-date the users-page Phase 1 refactor.
	 * Frontend renders "—" in the empty case.
	 */
	email?: string;
	authSource: 'local' | 'oidc' | 'service';
	oidcLinked: boolean;
	role: UserRole;
	createdAt: string;
	updatedAt: string;
	lastLoginAt?: string;
	/**
	 * RFC3339 timestamp of the user's most-recent session
	 * activity (the freshest `Touch` across their live
	 * sessions). Absent when the user has no live session
	 * (the frontend then renders the row as "offline").
	 */
	lastActivityAt?: string;
	/**
	 * Count of non-expired sessions for the user. Zero
	 * means "no live session"; > 0 powers the
	 * online/active indicator together with
	 * lastActivityAt's recency.
	 */
	activeSessionCount: number;
}

/**
 * Step K.2 — admin role enum. "admin" has full CRUD on routes /
 * settings / users; "viewer" has read-only access to the admin UI.
 * Mutually exclusive. The server enforces a last-LOCAL-admin
 * guard against demoting the only break-glass channel.
 */
export type UserRole = 'viewer' | 'admin';

/**
 * Phase 4 — POST /admin/users/service-accounts body. ExpiresAt
 * is optional: omitted → no-expiry (homelab set-and-forget).
 */
export interface CreateServiceAccountRequest {
	name: string;
	role: UserRole;
	expiresAt?: string; // ISO timestamp, must be in the future
}

/**
 * Phase 4 — response shape for POST
 * /admin/users/service-accounts. The `token` field carries the
 * plain Bearer string — shown ONCE by the create modal and
 * never recoverable. Storing it client-side past the modal
 * lifecycle is a deliberate non-feature (an operator wanting
 * a fresh copy rotates).
 */
/**
 * v2.48 — creating a local account.
 *
 * `password` is optional: empty means "generate one", which is the
 * default because an operator asked to invent a password for somebody
 * else reaches for something memorable, and nobody needs to remember
 * this one — it is shown once and the account must change it.
 */
export interface CreateAdminUserRequest {
	username: string;
	displayName: string;
	email: string;
	role: UserRole;
	password?: string;
}

export interface CreateAdminUserResponse {
	user: AdminUser;
	/**
	 * Present ONLY when Arenet generated it, and only here. When the
	 * admin typed one they already have it, and echoing it back would
	 * put it somewhere it does not need to be.
	 */
	generatedPassword?: string;
}

export interface CreateServiceAccountResponse {
	user: AdminUser;
	token: string;
	tokenId: string;
	expiresAt?: string;
}

/**
 * Phase 4 — POST .../rotate-token body. Optional expiry
 * override for the new token (the old one is revoked
 * atomically).
 */
export interface RotateServiceAccountTokenRequest {
	expiresAt?: string;
}

export interface RotateServiceAccountTokenResponse {
	token: string;
	tokenId: string;
	expiresAt?: string;
}

/**
 * Step K.2 — POST /api/v1/admin/users/{id}/role body. Empty role
 * or values outside the UserRole enum return a 400 from the
 * server.
 */
export interface UpdateUserRoleRequest {
	role: UserRole;
}

/**
 * Discriminated kind of an ApiError so the UI can decide presentation:
 *   - validation: inline near the offending field (4xx other than auth/rate)
 *   - system:     toast or full-page error (network, 5xx)
 *   - auth:       401 — caller redirected to /login by the interceptor
 *   - forbidden:  403 — session locked (lock screen overlay)
 *   - rate_limited: 429 — caller shown a toast by the interceptor
 *
 * Step D adds the auth/forbidden/rate_limited kinds (spec §6.4); Step C
 * shipped only validation/system.
 */
export type ErrorKind = 'validation' | 'system' | 'auth' | 'forbidden' | 'rate_limited';

/**
 * The HTTP access log setting (v2.50).
 *
 * It exists so CrowdSec has something to parse: Arenet emitted no access
 * log at all before this, so an agent beside it enforced the community
 * blocklist and detected nothing local — with nothing saying so.
 *
 * Off by default, because the file records every visitor's IP and every
 * URL they asked for.
 */
export interface AccessLogRequest {
	enabled: boolean;
	/** Absolute path, or empty for the per-install default. */
	path?: string;
	/** Size at which a file rotates. 0 means unset, not unlimited. */
	rollSizeMB?: number;
	/** Rotated files kept. 0 means unset, not unlimited. */
	rollKeep?: number;
	/** gzip rotated files. */
	compress?: boolean;
	/**
	 * v2.56 — query-parameter names whose VALUE is masked in the logged
	 * URI. Matched case-insensitively; the request forwarded upstream is
	 * untouched, the substitution happens in Caddy's log encoder.
	 *
	 * Reported case: Vaultwarden puts the user's access token in the URI,
	 * so turning the log on wrote a live credential to a file CrowdSec
	 * also reads.
	 *
	 * Omitted means "keep the server's defaults". An explicit empty array
	 * turns redaction off and is stored as such.
	 */
	redactQueryParams?: string[];
}

export interface AccessLogSettings extends AccessLogRequest {
	/**
	 * The file that will actually be written, per-install default
	 * applied — /var/log/arenet/access.log under systemd, inside the
	 * data volume in a container. This is what CrowdSec acquisition
	 * points at, NOT `path`.
	 */
	resolvedPath: string;
	/** Worst case on disk before compression. */
	ceilingMB: number;
}

export class ApiError extends Error {
	status: number;
	kind: ErrorKind;
	retryAfterSeconds?: number;
	// Optional machine-readable code from the response body
	// (e.g. "oidc_unlock_unsupported"). Step #S-24 — first
	// consumer is LockScreen, which redirects OIDC users to a
	// fresh SSO sign-in when password-based unlock is rejected.
	code?: string;
	// Optional structured parameters accompanying `code` (e.g. the
	// 409 `provider_in_use` body carries `params.wildcards: []`, the
	// 400 `invalid_provider_id` body carries `params.providerId`).
	// Consumers render these into translated messages.
	params?: Record<string, unknown>;

	constructor(
		message: string,
		status: number,
		kind?: ErrorKind,
		retryAfterSeconds?: number,
		code?: string,
		params?: Record<string, unknown>
	) {
		super(message);
		this.status = status;
		if (kind !== undefined) {
			this.kind = kind;
		} else {
			// Step C compat: derive kind from status when caller omits it.
			this.kind = status === 400 || status === 409 ? 'validation' : 'system';
		}
		this.retryAfterSeconds = retryAfterSeconds;
		this.code = code;
		this.params = params;
	}
}

// --- Step L observability types ---------------------------------------------

// The five metrics the timeseries endpoint accepts. Mirrors the
// Go-side `metricName` enum in internal/api/metrics_handlers.go.
// `waf_block_rate` was added in Step M.2 — it's a count metric
// (gap-fill = 0 for missing buckets, not null).
export type MetricName =
	| 'req_per_sec'
	| 'four_xx_rate'
	| 'five_xx_rate'
	| 'p95_latency_ms'
	| 'waf_block_rate'
	// Step Q.3 — rate-limit (throttle) blocks per minute.
	// Reads bucket.ThrottleBlockCount; spec §3.5 stores under
	// the sentinel route_id "_throttle", so the dashboard
	// passes route="_throttle" for the global series.
	| 'throttle_block_rate'
	// Step Q.3 — auth-failure rate. Server-side detour via
	// the audit log (D4.B: single source of truth, no bucket
	// counter). route="all" returns the system-wide series;
	// route=<uuid> returns all-zero (AC #10 — neither signal
	// is per-route).
	| 'auth_failure_rate'
	// Step N.3 — CrowdSec decision rate. Reads
	// bucket.CrowdSecDecisionCount via the QueryAggregated
	// SUM path on route="all" (which includes the sentinel
	// "_crowdsec" row — same trick as throttle). route=<uuid>
	// returns all-zero (mirror of throttle).
	| 'crowdsec_decision_rate'
	// Step Z.3 — HTTP rate-limit (429) rate. Reads
	// bucket.RateLimitCount. Unlike throttle_block_rate,
	// THIS metric is per-route (the Z.1 sink resolves the
	// upstream zone "route-<UUID>" to the route UUID and
	// bumps the bucket under that real ID). Powers the
	// /security/[routeId] chart panel.
	| 'rate_limit_rate'
	// Schema v15 — computed from the stored distributions, so these
	// two honour the quantile parameter. Total runs to the last byte
	// and therefore carries the visitor's download time; TTFB stops
	// when the response committed. Read apart, the gap between them
	// says whether a slow route is the backend or the bandwidth.
	| 'total_ms'
	| 'ttfb_ms'
	// A plain sum; the quantile does not apply.
	| 'bytes_out';

export type MetricWindow = '24h' | '30d';

/**
 * Which quantile the latency series report.
 *
 * Three values, not a free dial. Each is a decision an operator makes
 * — the typical, the slow tail, the worst of it — and a free-form
 * value invites asking for p99.99 of a window holding a few hundred
 * requests, which the server then suppresses, leaving an empty chart
 * and no explanation.
 *
 * Applies to `total_ms` and `ttfb_ms` only. Counts and sums ignore it,
 * and `p95_latency_ms` is fixed at p95 because its name says so.
 */
export type MetricQuantile = 'p50' | 'p95' | 'p99';

// One point on the timeline. `value` is `number | null` — null
// marks a missing-data gap that the chart MUST NOT connect
// across (AC #5: a null p95 must render as a break in the
// line, never as 0 ms which would draw a fake latency dip).
//
// Tied at the type level so a downstream consumer cannot
// accidentally `value: 0` a null point — TypeScript narrows
// `value` only after a `!== null` check.
export interface TimeseriesPoint {
	ts: string;
	value: number | null;
}

export interface TimeseriesResponse {
	routeId: string;
	metric: MetricName;
	window: MetricWindow;
	bucketSizeSeconds: number;
	// AC #13: when the observability subsystem failed at boot,
	// the API returns disabled=true + an empty points array.
	// The dashboard renders an "unavailable" empty state, not
	// an error toast.
	disabled?: boolean;
	points: TimeseriesPoint[];
}

export interface SummaryRoute {
	routeId: string;
	host: string;
	// #R-WAF-METRICS-WINDOW-1MIN-PROJECTION — the PerMin
	// suffix was dropped when the window widened to 24h.
	// The fields name what they count over the configured
	// window (see SummaryResponse.windowSeconds — currently
	// 86400). The frontend reads the values raw; the
	// historic ×60 / ×60×24 projections were removed in the
	// same commit because they no longer apply (the values
	// are absolute counts, not rates).
	//
	// Independence (AC #3): a WAF block does NOT inflate
	// the 4xx count; detect / block counters are
	// independent of each other AND of the 4xx / 5xx
	// fields.
	reqs: number;
	fourxx: number;
	fivexx: number;
	wafBlocked: number;
	wafDetected: number;
}

/**
 * Wire shape of GET /metrics/route-summary?route=<id> — the
 * 24h traffic aggregate for ONE route.
 *
 * Why not read `SummaryResponse.topRoutes`: that list is
 * truncated server-side to the five busiest routes
 * (metrics_handlers.go, `top = top[:5]`). A per-route surface
 * fed from it would show real numbers for five routes and
 * silent zeros for every other one.
 *
 * The window is the same one `SummaryResponse` aggregates over
 * (`windowSeconds`, 86400), computed from the same boundaries,
 * so the route panel and the dashboard can never disagree
 * about what "last 24 hours" means.
 */
export interface RouteSummaryResponse {
	routeId: string;
	generatedAt: string;
	windowSeconds: number;
	/** True when the observability subsystem failed at boot: the
	 *  counters below are all zero and mean "unknown", not "none". */
	disabled?: boolean;
	reqs: number;
	/** Independent of `fivexx` — never collapsed into one
	 *  "errors" number (AC #6). */
	fourxx: number;
	fivexx: number;
	/** Request-weighted mean of the hourly p95 samples, the same
	 *  statistic as `SummaryResponse.globalP95LatencyMs`. NOT a
	 *  true 24h p95 — that cannot be recovered from
	 *  pre-aggregated percentiles. null when the route served no
	 *  traffic with a recorded latency: render "—", never 0 ms,
	 *  which would read as "instant". */
	/**
	 * LEGACY, kept so pre-v15 readers keep working. A request-weighted
	 * mean of the per-hour p95 values — which is a mean of percentiles,
	 * and therefore still not a percentile however correct each hour
	 * is. Prefer `totalMs`.
	 */
	p95LatencyMs: number | null;

	/**
	 * p95 of TOTAL request duration, computed from the window's stored
	 * distribution (schema v15). Runs to the last byte, so it carries
	 * the visitor's download speed as well as the server's.
	 */
	totalMs: number | null;

	/**
	 * p95 of time-to-first-byte: how long the upstream took to START
	 * answering. Excludes body transfer, so a slow client cannot
	 * inflate it.
	 *
	 * Null independently of `totalMs` — a route serving mostly
	 * WebSocket upgrades has requests but few committed responses to
	 * time, and TTFB is gated on its own population.
	 */
	ttfbMs: number | null;

	/**
	 * Observations behind the quantiles, always present.
	 *
	 * Below 20 the quantiles above are null, because at nineteen
	 * samples ceil(0.95 × n) === n and a "p95" is simply the slowest
	 * request. Surfaced so the absence is explicable rather than a
	 * blank the operator has to guess at.
	 */
	samples: number;

	/** Response body bytes served over the window. */
	bytesOut: number;

	/**
	 * Requests whose connection was taken over (a WebSocket upgrade).
	 * Their timing and bytes are unobservable by construction, so they
	 * are counted apart rather than reading as instant empty
	 * responses.
	 */
	hijacked: number;

	/**
	 * True when some rows in the window carry no distribution, which
	 * happens across the schema v15 upgrade boundary. Those rows
	 * cannot be back-filled, so the quantiles describe only part of
	 * the window.
	 */
	partialHistogram?: boolean;
}

export interface SummaryResponse {
	generatedAt: string;
	/**
	 * Width of the window every Total* field aggregates over,
	 * in seconds. Post-#R-WAF-METRICS-WINDOW-1MIN-PROJECTION
	 * = 86400 (24h). Consumers that want a different window
	 * length should read this rather than assume — a future
	 * user-selectable window is the natural follow-on.
	 */
	windowSeconds: number;
	disabled?: boolean;
	/**
	 * Total requests across all routes over the configured
	 * window. Sourced from bucket_1h SUM over 24 rows
	 * (post-fix). Pre-fix this was a per-minute value the
	 * frontend multiplied by 60; post-fix it's the absolute
	 * count and the consumer reads it raw.
	 */
	totalReq: number;
	totalFourXx: number;
	totalFiveXx: number;
	/**
	 * Step M.2 — system-wide WAF blocks counter. Independent
	 * of the L 4xx/5xx totals (AC #3 reciprocal). Sourced
	 * from waf_block_count summed over the window.
	 */
	totalWafBlocked: number;
	/**
	 * #R-DASHBOARD-WAF-COUNTERS-ZERO — system-wide WAF
	 * detect-mode events counter. Sibling to totalWafBlocked:
	 * the two are populated from distinct bucket columns
	 * (waf_block_count vs waf_detect_count). On a homelab
	 * with every route in the recommended wafMode=detect
	 * default, this is the counter that has activity — the
	 * BLOCK counter stays at zero.
	 */
	totalWafDetected: number;
	/**
	 * Step Q.3 — rate-limit (throttle) blocks counted by
	 * the auth handler over the window. AC #15: independent
	 * of totalWafBlocked and the L 4xx/5xx totals.
	 */
	totalThrottle: number;
	/**
	 * Step Z.2 — per-route HTTP rate-limit (429) events over
	 * the window, sourced from the rate_limit_event table.
	 * Distinct from totalThrottle (auth-failure throttle is a
	 * different signal). AC #15 carries forward : independent
	 * of every other counter.
	 */
	totalRateLimitExceeded: number;
	/** Step Q.3 — authentication-failure audit events count. */
	totalAuthFailures: number;
	/**
	 * Step Q.3 / N.3 — server-side union of distinct source
	 * IPs across WAF + throttle + audit auth-failure +
	 * crowdsec events over the window. An IP that hit
	 * multiple sources counts ONCE.
	 */
	attackerIpsUnique: number;
	/**
	 * Step N.3 — total CrowdSec decisions captured by the
	 * parallel StreamBouncer consumer over the window
	 * (dedupe-before-bump per N spec D4.A). AC #N.24:
	 * independent of every other counter.
	 */
	totalCrowdSecDecisions: number;
	// Step N.3 — count of distinct decision `value` strings
	// (IP / CIDR / country / AS) in the just-closed minute.
	// Includes non-IP scopes intentionally; the dashboard's
	// "Active CrowdSec attackers" card surfaces this number.
	activeCrowdSecIpsUnique: number;
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — semantics tightened:
	// this map now only counts events with action=BLOCK
	// over the just-closed minute. Pre-fix it silently
	// aggregated both BLOCK and DETECT populations under a
	// name that claimed blocks-only — the immediate bug
	// the workstream resolves. The sibling
	// `wafDetectsByCategory` carries the DETECT population.
	wafBlocksByCategory: Record<string, number>;
	// #R-DASHBOARD-WAF-COUNTERS-ZERO — sibling of
	// wafBlocksByCategory; the action=DETECT population
	// per OWASP CRS category over the just-closed minute.
	// Operators wanting a combined attack-volume view sum
	// the two maps client-side.
	wafDetectsByCategory: Record<string, number>;
	// Null when no traffic landed in the window — same
	// no-fake-dip rule as TimeseriesPoint.value.
	globalP95LatencyMs: number | null;
	activeRouteCount: number;
	topRoutes: SummaryRoute[];
	// Step M.2 amendment — single most-attacked route over the
	// window, ranked by wafBlockedPerMin across ALL routes
	// (NOT filtered to topRoutes). null when no WAF activity.
	// Spec §1.3 D8 — the M.3 dashboard headline reads from
	// this field so a targeted attack on a low-traffic admin
	// surface stays visible.
	topAttackedRoute: SummaryRoute | null;
}

// --- Step M security types --------------------------------------------------

// OWASP category strings emitted by the WAF event sink.
// Mirrors internal/waf/event.go OwaspCategory enum.
// `OTHER` is the catch-all for rules that don't match any
// known CRS range.
// Phase Y (2026-06-18) — 25-category taxonomy mirror of
// internal/waf/event.go OwaspCategory const block. Each value
// here MUST exist in the Go enum for the SQLite waf_event
// table to deserialize correctly (the frontend ingests
// category strings verbatim from the wire).
//
// Pre-Y categories (kept for storage backward compat — old
// rows reference them as strings) : SQLi, XSS, RCE, LFI,
// PROTOCOL, OTHER. The Phase Y CategoryForRule refactor no
// longer EMITS the over-aggregating RCE/LFI/PROTOCOL strings
// for new events, but the union must include them so the
// frontend can render historical rows without crashing.
export type OwaspCategory =
	// Pre-Y (kept for storage compat)
	| 'SQLi'
	| 'XSS'
	| 'RCE'
	| 'LFI'
	| 'PROTOCOL'
	| 'OTHER'
	// Phase Y precise per-file categories
	| 'INIT'
	| 'COMMON_EXCEPT'
	| 'METHOD'
	| 'SCANNER'
	| 'PROTOCOL_ATK'
	| 'MULTIPART'
	| 'RFI'
	| 'PHP'
	| 'GENERIC'
	| 'SESSION'
	| 'JAVA'
	| 'ANOMALY_REQ'
	| 'ANOMALY_RESP'
	| 'CORRELATION'
	| 'DATA_LEAK'
	| 'DATA_LEAK_SQL'
	| 'DATA_LEAK_JAVA'
	| 'DATA_LEAK_PHP'
	| 'DATA_LEAK_IIS'
	| 'WEBSHELL'
	// v2.37 — the route's guided rules (120000-129999)
	| 'CUSTOM';

// All categories in dashboard-display order. Frontend uses
// this to render the CategoryDistribution strip with stable
// left-to-right ordering even when a category has 0 events.
//
// Phase Y — grouped in operator-meaningful families (request
// attacks first, then protocol/behaviour, aggregators, data-
// leak, infrastructure). The /waf page may further group
// into collapsible sections on render.
export const ALL_OWASP_CATEGORIES: readonly OwaspCategory[] = [
	// Request attacks
	'SQLi',
	'XSS',
	'RCE',
	'PHP',
	'JAVA',
	'GENERIC',
	'LFI',
	'RFI',
	// Protocol / behaviour
	'METHOD',
	'PROTOCOL',
	'PROTOCOL_ATK',
	'MULTIPART',
	'SCANNER',
	'SESSION',
	// Aggregators
	'ANOMALY_REQ',
	'ANOMALY_RESP',
	'CORRELATION',
	// Response-side / data leak
	'DATA_LEAK',
	'DATA_LEAK_SQL',
	'DATA_LEAK_JAVA',
	'DATA_LEAK_PHP',
	'DATA_LEAK_IIS',
	'WEBSHELL',
	// Infrastructure / catch-all
	'INIT',
	'COMMON_EXCEPT',
	'CUSTOM',
	'OTHER'
];

// One WAF event row as returned by GET /api/v1/security/events.
// Field shapes mirror observability.WafEvent via the M.2 wire
// type — see internal/api/security_handlers.go for the source
// of truth.
export interface WafEvent {
	id: number;
	ts: string;
	routeId: string;
	ruleId: string;
	category: OwaspCategory;
	severity: number;
	srcIp: string;
	requestMethod: string;
	requestPath: string;
	payloadSample: string;
	// W.bugfix Fix #1 — mode-aware label fields. "BLOCK" =
	// the WAF returned statusCode (403 today); "DETECT" =
	// the rule fired but the request passed to the upstream
	// (statusCode is 0; UI renders "—"). Pre-fix rows persisted
	// in the legacy schema are backfilled to ("BLOCK", 403).
	action: 'BLOCK' | 'DETECT';
	statusCode: number;
	/**
	 * v2.36 — "VARIABLE:key" of the field that triggered the rule
	 * (e.g. "ARGS:content"); empty for older events or keyless
	 * variables. Absent on pre-v2.36 servers.
	 */
	matchedVar?: string;
	/** v2.37 — name of the route's guided rule (custom range only). */
	ruleName?: string;
}

/** v2.37 — one criterion of a guided WAF rule; `values` are alternatives. */
export interface WafRuleCondition {
	field: 'path' | 'method' | 'user_agent' | 'header';
	header?: string;
	operator: 'is' | 'is_not' | 'begins_with' | 'contains' | 'missing' | 'present' | 'absent';
	values?: string[];
}

/**
 * v2.37 — guided WAF rule of a route: blocks (403 in block mode,
 * logged in detect mode) when every condition matches. `id` 0 = new.
 */
export interface WafCustomRule {
	id: number;
	name: string;
	disabled?: boolean;
	conditions: WafRuleCondition[];
}

/**
 * v2.36 — targeted WAF exclusion: rule `ruleId` no longer inspects
 * `target` ("VARIABLE:key"), on `path` only when set (and below it
 * when `pathPrefix`).
 */
export interface WafTargetedExclusion {
	ruleId: number;
	target: string;
	path?: string;
	pathPrefix?: boolean;
}

/** v2.40 — one thing the Caddyfile import could not translate. */
export interface CaddyfileWarning {
	line: number;
	text: string;
}

/** v2.40 — the route the import would create (subset of Route). */
export interface CaddyfileRoute {
	host: string;
	aliases: string[];
	upstreams: Upstream[];
	lbPolicy: string;
	tlsEnabled: boolean;
	acmeChallenge: string;
	insecureSkipVerify: boolean;
	requestHeaders?: Record<string, string>;
	responseHeaders?: Record<string, string>;
	healthCheck?: HealthCheck;
	pathRules?: PathRule[];
}

/** v2.40 — one site block of the previewed Caddyfile. */
export interface CaddyfileCandidate {
	host: string;
	aliases: string[];
	route?: CaddyfileRoute;
	importable: boolean;
	reason?: string;
	conflict: boolean;
	warnings: CaddyfileWarning[];
}

/** v2.40 — POST /routes/import/caddyfile/preview response. */
export interface CaddyfilePreview {
	globalWarnings: CaddyfileWarning[];
	candidates: CaddyfileCandidate[];
}

/** v2.40 — POST /routes/import/caddyfile response. */
export interface CaddyfileImportResult {
	created: string[];
	replaced: string[];
	skipped: { host: string; reason: string }[];
	warnings: CaddyfileWarning[];
}

/** v2.38 — one SecLang problem, 1-based line. */
export interface SecLangError {
	line: number;
	message: string;
}

/** v2.38 — POST /waf/seclang/validate response. */
export interface SecLangValidateResponse {
	errors: SecLangError[];
	nextId: number;
}

/** v2.38 — sample request for POST /routes/{id}/waf-test. */
export interface WafTestRequest {
	method: string;
	path: string;
	headers: { name: string; value: string }[];
	body: string;
	/** Unsaved SecLang draft; omitted = the stored one. */
	seclang?: string;
}

/** v2.38 — WAF tester result (engine On: "would it be blocked"). */
export interface WafTestResponse {
	blocked: boolean;
	status?: number;
	blockedBy?: number;
	matches: { id: number; msg: string; severity: string; data?: string }[];
	mode: 'off' | 'detect' | 'block';
}

/** v2.36 — body of POST /routes/{id}/waf-exclusions (no target = whole route). */
export interface AddWafExclusionRequest {
	ruleId: number;
	target?: string;
	path?: string;
	pathPrefix?: boolean;
}

export interface WafEventsResponse {
	disabled?: boolean;
	events: WafEvent[];
}

// One row of the per-rule aggregate returned by
// GET /api/v1/security/events/by-rule (M.2 amendment #2).
// Used by the M.4 drill-down's per-rule breakdown table.
// `lastSeen` is the most-recent event ts for the (ruleId,
// category) tuple over the window.
export interface WafEventRuleAggregate {
	ruleId: string;
	category: OwaspCategory;
	count: number;
	lastSeen: string;
}

export interface WafEventsByRuleResponse {
	disabled?: boolean;
	rows: WafEventRuleAggregate[];
}

// --- Step Q security types --------------------------------------------------

/**
 * One rate-limit (throttle) block event as returned by
 * GET /api/v1/security/throttle-events. Mirrors the Go
 * wire type securityThrottleEvent in
 * internal/api/security_handlers.go.
 *
 * Tier is 1 (5 fails / 5 min → 15 min block) or 2 (10 fails
 * / 1 h → 1 h block) per spec D1.A. BlockDurationSeconds is
 * the original duration assigned when the block fired —
 * preserved verbatim so the UI can format "blocked for X"
 * without rounding the live `blockedUntil` countdown.
 *
 * AttemptedUsername is captured-verbatim per spec D8.A:
 * parity with the existing audit log's exposure. The
 * dashboard renders it as the "user attempted" hint so an
 * operator under credential-stuffing sees which usernames
 * the attacker is spraying.
 */
export interface ThrottleEvent {
	id: number;
	ts: string;
	tier: 1 | 2;
	srcIp: string;
	attemptedUsername: string;
	blockedUntil: string;
	blockDurationSeconds: number;
}

export interface ThrottleEventsResponse {
	disabled?: boolean;
	events: ThrottleEvent[];
}

/**
 * One audit-derived auth-failure event as returned in the
 * `recent` slice of GET /api/v1/security/auth-failures.
 * Action is one of the four audit constants the backend
 * surfaces via audit.AuthFailureActions(): login_failure,
 * unlock_failure, oidc_login_rejected, oidc_callback_invalid.
 *
 * username + srcIp + message may be empty strings (the audit
 * record may have been written without them — e.g. the IP
 * extractor failed, spec §8.5). Frontend renders "—" in
 * that case rather than blanking the row.
 */
export type AuthFailureAction =
	| 'login_failure'
	| 'unlock_failure'
	| 'oidc_login_rejected'
	| 'oidc_callback_invalid';

export interface AuthFailureRecentEvent {
	ts: string;
	action: AuthFailureAction;
	username: string;
	srcIp: string;
	message: string;
}

/**
 * GET /api/v1/security/auth-failures response.
 *
 * `timeseries` is the per-minute count over the window
 * (1440 buckets for 24h), gap-filled with 0. Same wire
 * shape as the L metrics timeseries minus the
 * disabled/null cells — auth-failures is a count metric.
 *
 * `recent` is the head-of-feed for the mixed-events widget,
 * ts-descending, capped at 100 server-side.
 *
 * `partial: true` is set when the audit-bucket scan hit its
 * 200-row internal cap before reaching the window's `from`
 * boundary. Operator hint that earlier matching events
 * exist but were not surfaced — rare in practice (spec D4
 * volume), exposed for honesty.
 */
export interface AuthFailureTimeseriesPoint {
	ts: string;
	value: number;
}

export interface AuthFailuresResponse {
	disabled?: boolean;
	window: MetricWindow;
	timeseries: AuthFailureTimeseriesPoint[];
	recent: AuthFailureRecentEvent[];
	partial?: boolean;
}

/**
 * GET /api/v1/security/attackers-summary response.
 *
 * `uniqueIps` is the server-side union count across WAF,
 * throttle, and audit auth-failure source-IP sets over the
 * window. An IP that hit multiple sources counts ONCE.
 *
 * `byBucketSource` is the per-source pre-union breakdown —
 * the dashboard's "by source" widget. SUM(byBucketSource)
 * ≥ uniqueIps (equal when no overlap).
 *
 * Four-state disabled / partial contract (Step N.3 extended
 * the original Q.3 three-state to four):
 *   - All four backend readers nil → disabled=true, empty
 *     bodies.
 *   - At least one nil but not all → partial=true, the
 *     union reflects the readers that DID respond.
 *   - All four present → neither flag set.
 *
 * The frontend uses `partial` to drive an "incomplete data"
 * affordance — same convention as
 * AuthFailuresResponse.partial.
 */
export interface AttackersByBucketSource {
	waf: number;
	throttle: number;
	audit: number;
	// Step N.3 — 4th source: distinct CrowdSec decision
	// `value` strings (IP / CIDR / country / AS). Includes
	// non-IP scopes intentionally — a Range-scoped community
	// blocklist entry is just as much an attacker indicator
	// as a single IP.
	crowdsec: number;
}

export interface AttackersSummaryResponse {
	disabled?: boolean;
	partial?: boolean;
	window: MetricWindow;
	uniqueIps: number;
	byBucketSource: AttackersByBucketSource;
}

// --- Step N CrowdSec types --------------------------------------------------

/**
 * LAPI decision scope. Strings are free-form on the wire
 * (the LAPI vocabulary is operator-controlled; new scopes
 * could appear via custom community scenarios), but the
 * documented values are the four below.
 */
export type DecisionScope = 'ip' | 'range' | 'country' | 'as';

/**
 * LAPI decision action type. The bouncer translates these
 * to HTTP responses:
 *   - `ban`: 403 (default).
 *   - `captcha`: 403 (no captcha challenge implemented in
 *     caddy-crowdsec-bouncer v0.12.1; functionally a ban —
 *     upstream issue #46).
 *   - `throttle`: 429 + Retry-After header.
 *
 * Free-form string on the wire for forward-compat with
 * future LAPI extensions.
 */
export type DecisionType = 'ban' | 'captcha' | 'throttle';

/**
 * One CrowdSec LAPI decision row, mirror of
 * observability.DecisionEvent (storage) + N spec D5.B
 * operator-facing subset.
 *
 * UUID is LAPI's stable cross-instance identifier (drift-
 * safe across CrowdSec restarts; the LAPI server-local `id`
 * was intentionally dropped at the storage layer for
 * stability — see N spec §1.3 D5.B).
 *
 * Scope + Value together describe WHAT the decision targets:
 *   - "ip" + "1.2.3.4"            → single IP.
 *   - "range" + "185.142.86.0/24" → CIDR (community blocklist).
 *   - "country" + "RU"            → all IPs from a country.
 *   - "as" + "AS12345"            → all IPs from an AS.
 *
 * ExpiresAt is the absolute moment the decision becomes
 * inactive. The retention layer (server-side) prunes rows
 * 30d after ExpiresAt per N spec D8.A.
 */
export interface Decision {
	id: number;
	uuid: string;
	ts: string;
	scope: string;
	value: string;
	type: string;
	scenario: string;
	expiresAt: string;
	durationSeconds: number;
}

export interface DecisionsResponse {
	disabled?: boolean;
	events: Decision[];
}

/**
 * Step CS.2.A — Live LAPI decision wire shape returned by
 * GET /api/v1/security/crowdsec/decisions. Distinct from
 * `Decision` (above) which models the local-mirror schema
 * stored in metrics.db decision_event. The shapes intentionally
 * diverge because LAPI exposes more fields per response
 * (`origin`, raw `duration` string) than the mirror persists
 * (the mirror was optimized for time-series query, not for
 * forensic field-richness).
 */
export interface LAPIDecision {
	id: number;
	duration: string;
	origin: string;
	scenario: string;
	scope: string;
	type: string;
	value: string;
	expiresAt?: string;
}

export interface LAPIDecisionsMeta {
	total: number;
	totalByOrigin: Record<string, number>;
	limit: number;
	offset: number;
}

export interface LAPIDecisionsResponse {
	decisions: LAPIDecision[];
	meta: LAPIDecisionsMeta;
}

/**
 * Step CS.2.C — per-scenario aggregate returned by GET
 * /api/v1/security/crowdsec/scenarios. The backend reads
 * LAPI /v1/alerts (JWT auth via Security Automation creds)
 * and aggregates by scenario name. See
 * docs/setup/crowdsec.md §"Why Scenarios tab needs Security
 * Automation" for the credential coupling rationale.
 */
export interface ScenarioAggregate {
	name: string;
	alerts24h: number;
	lastSeen?: string;
	sampleScope?: string;
	sampleValue?: string;
}

export interface ScenariosMeta {
	totalAlerts: number;
	windowHours: number;
}

export interface ScenariosResponse {
	scenarios: ScenarioAggregate[];
	meta: ScenariosMeta;
}

// --- Step U cert event types --------------------------------------------------

/**
 * Level of a cert lifecycle event in the Activity log.
 * Matches the backend's CertEventLevel.String() output
 * (internal/observability/cert_event.go). INFO covers
 * cert_obtained; ERROR covers cert_failed + cert_ocsp_revoked
 * (the latter is a security-relevant signal per Step U spec
 * §3.6).
 */
export type CertEventLevel = 'INFO' | 'ERROR';

/**
 * Event type lineage from certmagic. The frontend renders
 * each as a different row variant in the Activity log table.
 * Matches CertEventType.String() output verbatim so an
 * operator searching the table textbox for "cert_failed"
 * matches the typed token. cert_obtaining is NOT persisted
 * per spec §3.3 — it never appears in the wire shape.
 */
export type CertEventType = 'cert_obtained' | 'cert_failed' | 'cert_ocsp_revoked';

/**
 * One cert lifecycle event row as returned by
 * GET /api/v1/observability/cert-events. Field shapes mirror
 * observability.CertEvent via the U.3 wire type
 * certEventResponseItem in
 * internal/api/cert_events_handler.go (the camelCase JSON
 * tags map 1-to-1 to the snake_case columns in cert_event).
 *
 * Empty-string defaults match the U.1 schema NOT NULL
 * DEFAULT '' constraints: a producer that omits issuer (e.g.
 * a cert_failed row) sends "" not null. The Activity log
 * mapper treats empty strings as "no data" rather than
 * rendering blank pills.
 *
 * Per the U.3 handler's omitempty discipline, only Timestamp,
 * Level, EventType, and Domain are guaranteed present on
 * every row; the other fields may be absent (omitempty) when
 * empty. TypeScript declares them as required for clarity
 * but the runtime tolerates missing fields (treated as "").
 */
export interface CertEvent {
	timestamp: string;
	level: CertEventLevel;
	eventType: CertEventType;
	domain: string;
	issuer: string;
	challenge: '' | 'DNS-01' | 'HTTP-01';
	renewal: boolean;
	error: string;
	details: string;
}

/**
 * Wire shape of GET /api/v1/observability/cert-events.
 *
 * `total` is the count of rows matching the filter ignoring
 * limit (CountCertEvents in the U.3 backend) — lets the UI
 * surface "showing N of M".
 *
 * `hasMore` is true iff total > events.length — pagination
 * hint for a future load-more affordance; U.5 doesn't
 * implement load-more, but the frontend type carries the
 * field so a future increment can wire it without a
 * type-level migration.
 *
 * `degraded` is omitted on the happy path (omitempty); true
 * when the backend reader was nil (boot failure or missed
 * wire-up). Mirrors the `disabled?` field on WAF / throttle
 * / decision responses for operator mental-model uniformity.
 * AC #13 degraded-mode contract carried forward from Step T.
 */
export interface CertEventsResponse {
	events: CertEvent[];
	total: number;
	hasMore: boolean;
	degraded?: boolean;
}

/**
 * Phase 5 — one row of the cert event aggregation. Mirrors
 * the internal/api/cert_events_handler.go certEventsAggregateBucketResp
 * wire shape. bucketStart is the inclusive RFC 3339 timestamp at
 * the start of the interval; the three counters split
 * cert_obtained rows by the renewal boolean (issued = fresh,
 * renewed = post-first-issuance) and fold cert_failed rows into
 * failed. cert_ocsp_revoked is excluded from this aggregate by
 * design — Phase 5 ships the three common lifecycle outcomes.
 */
export interface CertEventBucket {
	bucketStart: string;
	issued: number;
	renewed: number;
	failed: number;
	// Index signature so the MultiSeriesTimelineChart's
	// DataRow shape (`[key: string]: unknown`) accepts this
	// type directly. Counter fields are typed concretely
	// above; the indexer is the structural slot the chart
	// reads via row[seriesKey]. Adding new bucket fields in
	// future migrations stays type-safe because the explicit
	// field declarations take precedence over the indexer.
	[key: string]: string | number;
}

/**
 * Phase 5 — wire shape of
 * GET /api/v1/observability/cert-events/aggregate.
 *
 * Buckets is always present and always has one entry per
 * interval in the window (empty buckets carry zero counts) —
 * the frontend chart renders a continuous timeline without
 * gap-fill.
 *
 * `degraded` follows the same AC #13 contract as
 * CertEventsResponse.
 */
export interface CertEventsAggregateResponse {
	buckets: CertEventBucket[];
	degraded?: boolean;
}

/**
 * Step W.5 — country-block events.
 *
 * Wire shape of GET /api/v1/observability/country-block-events.
 * Field-for-field mirror of
 * internal/observability.CountryBlockEvent (W.4 schema v8)
 * with camelCase JSON tags + RFC 3339 ts.
 *
 * Mode is "allow" or "deny" — the route's enforcement mode
 * at the moment the block fired. Reason is W.1's matcher
 * kebab-case enum ("allow-miss" / "deny-match" / etc.) so
 * the activity-log tooltip can render the "why blocked"
 * hint without parsing free text.
 *
 * Host + ASN are NOT in the persisted row (W.4 deferred);
 * the activity log resolves RouteID → host via the
 * existing /routes API, and renders ASN as "—".
 */
export interface CountryBlockEvent {
	id: number;
	ts: string;
	routeId: string;
	srcIp: string;
	country: string;
	mode: 'allow' | 'deny';
	statusCode: number;
	reason: string;
}

export interface CountryBlockEventsResponse {
	events: CountryBlockEvent[];
	total: number;
	hasMore: boolean;
	degraded?: boolean;
}

/**
 * Step Z.1 — rate-limit (429) events.
 *
 * Wire shape of GET /api/v1/security/rate-limit-events.
 * Field-for-field mirror of
 * internal/observability.RateLimitEvent (Z.1 schema v11)
 * with camelCase JSON tags + RFC 3339 ts.
 *
 * Captured by the Z.1 events.handlers.arenet_ratelimit_sink
 * Caddy module subscribed to upstream mholt/caddy-ratelimit's
 * "rate_limit_exceeded" emit. RouteID extracted from the
 * "route-<UUID>" zone convention ; operator-hand-crafted
 * Caddy configs that bypass Arenet's emit path land with
 * RouteID="" and the raw zone preserved for forensic value.
 *
 * WaitMs is the milliseconds the upstream handler told the
 * client to wait before retrying (Retry-After).
 */
export interface RateLimitEvent {
	id: number;
	ts: string;
	routeId: string;
	zone: string;
	remoteIp: string;
	waitMs: number;
}

export interface RateLimitEventsResponse {
	events: RateLimitEvent[];
	total: number;
	hasMore: boolean;
	degraded?: boolean;
}

/**
 * Step V — geographic threat map.
 *
 * Wire shape of GET /api/v1/observability/server-position
 * (spec §5.1). Locked to the V.4 backend handler in
 * internal/api/server_position_handler.go's
 * serverPositionResponse — camelCase JSON tags map to the
 * snake_case storage columns 1-to-1.
 *
 * `mode` is "auto" when the V.1 ipify-then-GeoIP path
 * produced the position, "manual" when the operator
 * persisted an override via PUT.
 *
 * `degraded` is true when no GeoIP MMDB is loaded AND no
 * manual override exists. In that case `lat`, `lon`, `city`,
 * `country`, `sourceIp`, `detectedAt` collapse to their
 * zero values per the spec §5.1 degraded shape — the
 * frontend renders a banner + falls back to a world-
 * centered Mercator.
 *
 * `sourceIp` and `detectedAt` are omitted by the backend
 * (omitempty) on the manual override path. Declared
 * optional on the wire so the typecheck doesn't require
 * the frontend to assert non-emptiness it can never
 * guarantee.
 */
export interface ServerPosition {
	lat: number;
	lon: number;
	city: string;
	country: string;
	mode: 'auto' | 'manual';
	sourceIp?: string;
	detectedAt?: string;
	degraded?: boolean;
}

/**
 * Step V — GeoEvent wire shape (spec §5.6). Locked enum on
 * `category`: 5 values, no `cert` — cert events live in the
 * Activity log via Step U, NOT in the geo map (the V.2
 * decision honored §5.6 line 515's locked enum over §6
 * AC #2's mention of cert enrichment).
 *
 * `sourceLat` / `sourceLon` are 0 when the GeoIP lookup is
 * degraded (no MMDB) or when the source IP is RFC1918 (LAN
 * sources render at the Arenet position with an `(LAN)`
 * label per spec §3.8). `sourceCountry` is `"UNK"` in the
 * degraded case.
 *
 * `isLan` is true for RFC1918 / loopback / link-local
 * addresses. The frontend uses this flag to render the
 * Arenet-centered loop arc instead of a real source-to-
 * Arenet arc.
 *
 * `statusCode` / `routeId` / `details` are operator-facing
 * tooltip metadata; populated when known, empty otherwise.
 */
// Step W.5 — country_block is the 6th GeoEvent category
// (W.4 backend addition). Per-route operator-declared
// country gate, rendered as gray slate arcs on the map
// to signal "policy enforcement, not threat" per spec §D6.
export type GeoEventCategory =
	| 'normal'
	| 'throttle'
	| 'waf'
	| 'crowdsec'
	| 'auth'
	| 'country_block';

export interface GeoEvent {
	timestamp: string;
	category: GeoEventCategory;
	sourceIp: string;
	sourceLat: number;
	sourceLon: number;
	sourceCountry: string;
	sourceCity: string;
	isLan: boolean;
	statusCode?: number;
	routeId?: string;
	details: string;
}

/**
 * Wire shape of GET /api/v1/observability/geo-events (V.3
 * replay endpoint, spec §5.4). `total` is the ring buffer's
 * current size — events do NOT persist across restart
 * (in-memory N=500 per spec §3.5).
 *
 * `degraded` is true when the GeoIP lookup is degraded —
 * events still flow but with empty country/lat/lon.
 */
export interface GeoEventsResponse {
	events: GeoEvent[];
	total: number;
	degraded?: boolean;
}

/**
 * Step CS.1 — wire shape returned by GET
 * /api/v1/settings/crowdsec. `apiKey` is always blanked on
 * the wire (server-side redaction, mirrors the K.2 OIDC and
 * J.4 DNS-provider pattern). `configured` is the single
 * status flag the UI binds to.
 */
export interface CrowdSecSettings {
	lapiUrl: string;
	apiKey: string; // always "" on the wire (redacted)
	bouncerName: string;
	timeoutSeconds: number;
	configured: boolean;
	updatedAt?: string;
	/**
	 * Set on a save that MOVED the LAPI address (v2.51).
	 *
	 * Arenet reloads Caddy and the bouncer is re-provisioned with the new
	 * URL, but its streaming client keeps dialling the previous one until
	 * the process restarts — it logs the new address while using the old.
	 *
	 * The bouncer fails open, so until the restart Arenet blocks nothing
	 * at all and nothing else on screen says so. The UI must not let this
	 * pass quietly.
	 */
	restartRequired?: boolean;
}

/**
 * Step CS.1 — wire shape for PUT /api/v1/settings/crowdsec.
 * Empty `apiKey` triggers the preserve-on-edit path (stored
 * value is kept). An all-empty PUT clears the configuration
 * (operator's explicit "Disable" path).
 */
export interface CrowdSecSettingsRequest {
	lapiUrl: string;
	apiKey: string;
	bouncerName: string;
	timeoutSeconds: number;
}

/**
 * Step CS.1 — wire shape for POST /api/v1/settings/crowdsec/
 * test. The handler probes LAPI /v1/decisions with the
 * supplied (or stored, when useStored=true) creds.
 */
export interface CrowdSecTestRequest {
	lapiUrl?: string;
	apiKey?: string;
	timeoutSeconds?: number;
	useStored?: boolean;
}

/**
 * Step CS.1 — wire shape returned by POST
 * /api/v1/settings/crowdsec/test. `ok` is the boolean the
 * UI flips a green / red badge on; the optional fields
 * carry diagnostic detail for the operator's
 * troubleshooting flow.
 */
export interface CrowdSecTestResponse {
	ok: boolean;
	statusCode?: number;
	version?: string;
	error?: string;
	effectiveUrl?: string;
}

/**
 * Brick 2 Task 2 — wire shape returned by GET
 * /api/v1/settings/maxmind. `licenseKey` is NEVER echoed by the
 * backend (mirrors the CrowdSec `apiKey` / OIDC `clientSecret`
 * redaction pattern) — there is no license key field on the wire
 * at all, only the `configured` flag the UI binds to render the
 * "•••• already saved" placeholder.
 */
export interface MaxMindConfig {
	accountId: number;
	editionId: string;
	configured: boolean;
}

/**
 * Brick 2 Task 2 — wire shape for PUT /api/v1/settings/maxmind.
 * Empty `licenseKey` triggers the preserve-on-edit path (stored
 * value is kept). `editionId` is optional — blank lets the
 * backend default to "GeoLite2-City".
 */
export interface MaxMindRequest {
	accountId: number;
	licenseKey: string;
	editionId?: string;
}

/**
 * Brick 2 Task 3 — wire shape returned by POST
 * /api/v1/settings/maxmind/test. Always HTTP 200; `reachable`
 * is the boolean the UI flips a green / red badge on.
 */
export interface MaxMindTestResult {
	reachable: boolean;
	error?: string;
}

/**
 * Step CS.3 Commit D — POST /api/v1/security/crowdsec/decisions
 * request body. Mirrors the backend manualBanRequest struct
 * verbatim. Validation duplicates the backend rules so the
 * UI surfaces friendly errors before the network round-trip;
 * the backend remains the authoritative validator.
 */
export interface ManualBanRequest {
	value: string;
	duration: string;
	type: 'ban' | 'captcha' | 'throttle';
	reason: string;
	// Override for the backend self-ban guard (409
	// crowdsec_self_ban). Sent only after the operator's
	// explicit second confirmation; omitted otherwise.
	confirmSelfBan?: boolean;
}

/**
 * 200 response of DELETE /api/v1/security/crowdsec/decisions/{id}
 * (unban). `nbDeleted` is LAPI's count of expired decisions.
 */
export interface CrowdSecDecisionDeleteResponse {
	id: number;
	nbDeleted: number;
}

/**
 * Step CS.3 Commit D — 201 response from the manual ban
 * endpoint. Echoes the canonical scenario string so the UI
 * can optimistically prepend the new row to the table
 * without waiting for the 30s LAPI polling tick.
 */
export interface ManualBanResponse {
	scenario: string;
	scope: 'Ip' | 'Range';
	value: string;
	type: string;
	duration: string;
	origin: 'manual';
	expiresAt: string;
}
