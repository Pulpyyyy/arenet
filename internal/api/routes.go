// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/storage"
)

// NewRouter builds the chi router for the admin API. When dev is true a
// permissive CORS middleware is mounted for http://localhost:5173.
//
// Step D wires the IP extractor near the top (after Recoverer) so
// every downstream handler reads the resolved IP from context. The
// /api/v1/auth/* subtree is then rate-limited per-IP; business
// endpoints under /api/v1 stay unrated (authenticated callers are
// trusted per spec §5.2).
//
// Step E adds the optional ws handler: when non-nil, it is mounted
// at GET /api/v1/ws/topology inside the hard-auth subgroup
// (spec §5.1 + §7.1). Tests that do not exercise the topology
// endpoint pass nil — the route is then simply not registered.
//
// Phase 2 #R-TOPO-v2 — when non-nil, snapshotHandler serves
// GET /api/v1/topology/snapshot and streamHandler serves
// GET /api/v1/topology/stream, both inside the same hard-auth
// subgroup. Viewer + admin both accepted (read-only endpoints).
// Tests that do not exercise these endpoints pass nil.
func NewRouter(h *Handler, dev bool, ipExtractor *auth.IPExtractor, ws *WSTopologyHandler, snapshotHandler *SnapshotHandler, streamHandler *StreamHandler, wsGeoEvents *WSGeoEventsHandler) chi.Router {
	if ipExtractor == nil {
		panic("api.NewRouter: ipExtractor is nil")
	}
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(slogLogger(h.logger))
	r.Use(chimw.Recoverer)
	if dev {
		r.Use(devCORS("http://localhost:5173"))
	}
	r.Use(auth.IPExtractMiddleware(ipExtractor))
	// Source allowlist (ARENET_ADMIN_ALLOWED_CIDRS) — after the IP
	// extractor so it judges the resolved client, before every route
	// so the SPA, the API and the WebSockets are all covered. /healthz
	// stays exempt for the in-container healthcheck.
	if h.adminAllowlist != nil {
		r.Use(auth.SourceAllowlistMiddleware(h.adminAllowlist, h.logger, "/healthz"))
	}

	// /healthz: mounted at the root (NOT /api/v1/...) so the probe
	// path stays stable across API versions. No auth wrapper because
	// orchestrator probes carry no credentials. No audit either —
	// audit is per-handler in Arenet, not a middleware, so /healthz
	// is implicitly silent. Step H.3 — see internal/api/health.go
	// for full design rationale. The middleware stack above does
	// apply (chi enforces "all middlewares before any route"), so
	// probe hits land in the structured log; that is an acceptable
	// trade-off for the homelab single-instance deployment target.
	r.Get("/healthz", h.healthz)

	// Step AL.3a — /system/health for external monitoring
	// stacks (Uptime Kuma, blackbox_exporter, k8s readiness
	// probes). INTENTIONALLY mounted outside the /api/v1
	// auth subtree so a scraper without cookies / Bearer
	// tokens can read it. Response carries zero secrets
	// (status + counts + latency only). See
	// docs/superpowers/decisions/2026-06-15-step-al-
	// decisions.md (D3) for the design context.
	r.Get("/system/health", h.systemHealth)

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			// S.5 smoke finding #5 — rate-limit scoped back to
			// /auth/* only (Step Q's original scope), reverting
			// the Step S.4 lift to /api/v1/*. The broader scope
			// caused Tier 1 (15min block) to fire on legitimate
			// SPA usage: the frontend's /auth/me session check
			// returns 401 when unauthenticated (common: first
			// load, post-logout, expired session), and a handful
			// of failed POST /auth/login attempts (typos during
			// setup) hammer the same bucket. Result: operator
			// locked out of the UI for 15 minutes on a fresh
			// install. Smoke evidence: UI Logs page captured
			// "WARN 429 POST /auth/login · Rate-limit tier 1 ·
			// bloqué 900s · user ?" on first-page-load through
			// the setup wizard, immediately followed by
			// /auth/me 429s blocking the login screen.
			//
			// Reverting to Step Q's scope ships v1.0.0 with a
			// known-good rate-limit behaviour. Broader
			// /api/v1/* DDoS protection deferred to a future
			// focused step with proper endpoint carveouts
			// (exempt GET /auth/me, GET /auth/sessions, GET
			// /auth/heartbeat) + thresholds calibrated against
			// real SPA traffic patterns.
			r.Use(h.rateLimiter.Middleware())

			// No-auth subgroup: /setup, /login + OIDC login flow
			// (the login IS the auth — these endpoints can't
			// require a session). Step K.2 §5.2.
			r.Post("/setup", h.setup)
			r.Get("/setup/status", h.setupStatus)
			r.Post("/login", h.login)
			r.Get("/oidc/login", h.oidcInitiateLogin)
			r.Get("/oidc/callback", h.oidcCallback)
			r.Get("/oidc/status", h.oidcStatus)

			// Soft-auth subgroup: /logout, /me, /unlock.
			r.Group(func(r chi.Router) {
				r.Use(auth.SoftAuthMiddleware(h.sessions, h.users, h.tokenLookup(), h.devMode))
				r.Post("/logout", h.logout)
				r.Get("/me", h.me)
				r.Post("/unlock", h.unlock)
			})

			// Hard-auth subgroup: /heartbeat, /sessions, DELETE /sessions/{id},
			// /me/password, /me/theme, /me/language. All viewer-accessible
			// (the user rotates their OWN password / theme / language, not
			// someone else's). /me/language added in v2.9.11 i18n Phase 1.
			r.Group(func(r chi.Router) {
				r.Use(auth.HardAuthMiddleware(h.sessions, h.users, h.tokenLookup(), h.devMode))
				r.Post("/heartbeat", h.heartbeat)
				r.Get("/sessions", h.listSessions)
				r.Delete("/sessions/{id}", h.deleteSession)
				r.Post("/me/password", h.changePassword)
				r.Post("/me/theme", h.updateTheme)
				r.Post("/me/language", h.updateLanguage)
			})
		})

		// Business endpoints — hard-auth gated per spec §5.2.
		// Step K.2 §1.3 #12: viewer-accessible endpoints
		// (read-only on routes / audit / topology / metrics) sit
		// at this level. The admin-only sub-group below adds the
		// role gate for write endpoints + settings + admin users.
		r.Group(func(r chi.Router) {
			r.Use(auth.HardAuthMiddleware(h.sessions, h.users, h.tokenLookup(), h.devMode))
			// v2.39 — OpenAPI description of this API (any signed-in user).
			r.Get("/openapi.json", h.getOpenAPI)
			r.Get("/routes", h.listRoutes)
			r.Get("/routes/{id}", h.getRoute)
			// v2.42 — TCP (layer 4) services, read side. Same
			// posture as routes: any signed-in user may look.
			// v2.45 — the host Arenet runs on. Viewer scope: it
			// names the machine and its free disk, which is not for
			// an unauthenticated probe, but looking is not changing.
			r.Get("/system/info", h.getSystemInfo)
			r.Get("/tcp-services", h.listTCPServices)
			// Counters live under a fixed path, declared BEFORE the
			// {id} route so chi does not read "metrics" as an id.
			r.Get("/tcp-services/metrics", h.tcpServicesMetrics)
			r.Get("/tcp-services/{id}", h.getTCPService)
			// Step R — custom error pages read-side (viewer-
			// accessible so the RouteForm dropdown can list
			// templates without admin scope ; the preview pane
			// in the /settings/error-pages editor also reads here).
			r.Get("/error-templates", h.listErrorTemplates)
			r.Get("/error-templates/{id}", h.getErrorTemplate)
			r.Get("/error-templates/{id}/preview", h.previewErrorTemplate)
			// Task 7 — global maintenance page read. Viewer-
			// accessible so the /settings/maintenance editor's
			// initial load doesn't require admin scope; the
			// PUT (write) sits in the admin-only sub-group below.
			r.Get("/settings/maintenance-page", h.getMaintenancePage)
			// External certificates read-side (v2.19.0). Viewer-
			// accessible so the RouteForm cert dropdown can list
			// uploaded certs without admin scope; KeyPEM is
			// redacted in every response. POST/PUT/DELETE sit in
			// the admin-only sub-group below.
			r.Get("/certificates/external", h.listExternalCerts)
			r.Get("/certificates/external/{id}", h.getExternalCert)
			r.Get("/certificates/external/{id}/csr", h.downloadExternalCertCSR)
			r.Get("/audit", h.listAudit)
			// Step L L.2 — per-route metrics history.
			// Read-only; viewer-accessible per AC #17. No
			// write surface (there is nothing to write —
			// metrics are produced by the in-process
			// aggregator, never accepted via the API).
			r.Get("/metrics/timeseries", h.metricsTimeseries)
			r.Get("/metrics/summary", h.metricsSummary)
			// Per-route 24h traffic aggregate for the route
			// panel strip. /metrics/summary cannot serve this:
			// its topRoutes list is truncated to five.
			r.Get("/metrics/route-summary", h.metricsRouteSummary)
			// Step M.2 — WAF event log. Read-only,
			// viewer-accessible per AC #12. Same auth shape
			// as /metrics; the data is event-shaped
			// (sparse per-block rows) rather than bucketed
			// timeseries, which is why it gets its own
			// endpoint despite living under the /security/
			// prefix (spec §1.3 D2 carve-out).
			r.Get("/security/events", h.securityEvents)
			// M.2 amendment #2 — per-(rule, category)
			// aggregate over the window. Used by the M.4
			// drill-down's per-rule table; replaces the
			// client-side group-by that silently truncated
			// to the most-recent 100 events on the 30d
			// window.
			r.Get("/security/events/by-rule", h.securityEventsByRule)
			// Step Q.2 — auth-failure timeline derived from
			// the audit log. Single audit-scan projected to
			// per-minute timeseries + recent feed (spec
			// §1.3 D4.B: single source of truth). Same
			// viewer-accessible gate as the other /security
			// endpoints.
			r.Get("/security/auth-failures", h.securityAuthFailures)
			// Step Q.3 — rate-limit (throttle) event log.
			// Pure event-shaped read of the throttle_event
			// table, mirror of /security/events. Optional
			// srcIp / tier filters. Same AC #14 contract.
			r.Get("/security/throttle-events", h.securityThrottleEvents)
			// Step Z.1 — rate-limit (429) event log. Pure
			// event-shaped read of the rate_limit_event
			// table populated by the Z.1 ratelimit.Sink.
			// Optional route / remoteIp / since / until
			// filters. Same hard-auth + AC #13 degraded-
			// mode contract as the security siblings above.
			r.Get("/security/rate-limit-events", h.securityRateLimitEvents)
			// Step Q.3 — attackers summary. Server-side
			// union over WAF + throttle + audit source-IP
			// sets (D6.A). One headline `uniqueIps` stat +
			// a per-source breakdown for the dashboard's
			// "by source" widget.
			r.Get("/security/attackers-summary", h.securityAttackersSummary)
			// Step N.3 — CrowdSec decision event log. Pure
			// event-shaped read of the decision_event table.
			// Optional scope / scenario / srcIp / onlyActive
			// filters. Same AC #15 contract.
			r.Get("/security/decisions", h.securityDecisions)
			// Step U.3 — cert lifecycle event log. Pure
			// event-shaped read of the cert_event table (U.1
			// schema v5, populated by the U.2 sink that
			// subscribes to the certinfo Tracker's AC #18
			// Subscribe seam). Optional limit / since / until /
			// level / search filters per spec §5.1. Endpoint
			// lives under /observability/ rather than /security/
			// because cert events are not security-scoped
			// (lifecycle is the umbrella concept; the §3.4 page
			// rename to "Activity log" reflects that scope
			// widening). Same hard-auth + AC #13 degraded-mode
			// contract as the security siblings above.
			r.Get("/observability/cert-events", h.securityCertEvents)
			// Step AL.4.a — alerting event history (read-
			// only). Reads the alert_event table populated
			// by the AL.4.a dispatcher sink (one row per
			// Dispatch call, regardless of success/failure
			// per-channel). Mirrors the cert-events
			// degraded contract: nil reader → 200 with
			// {events:[], degraded:true}, never 5xx so
			// the History tab renders an empty state.
			// Cursor-based pagination same shape as /audit.
			r.Get("/observability/alert-events", h.listAlertEvents)
			// Phase 5 — cert event aggregation. Bucketed counts
			// (issued / renewed / failed) for the dashboard
			// lifecycle panel + future Phase 6 alerting rule
			// evaluator. Same hard-auth + AC #13 degraded-mode
			// contract as cert-events above.
			r.Get("/observability/cert-events/aggregate", h.aggregateCertEvents)
			// Step W.5 — country-block event log. Reads from
			// the W.4 country_block_event table (schema v8).
			// Mirror of cert-events: pure event-shaped read,
			// optional route/srcIp/country/mode + since/until
			// filters, same hard-auth + AC #13 degraded-mode
			// contract.
			r.Get("/observability/country-block-events", h.securityCountryBlockEvents)
			// Step V.3 — geo events replay endpoint. Returns
			// the in-memory ring buffer (capacity 500 per
			// spec §3.5) for the /map page's initial paint;
			// the WS /ws/geo-events stream below overlays
			// live events on top. Same hard-auth + AC #13
			// degraded-mode contract as cert-events above.
			r.Get("/observability/geo-events", h.securityGeoEvents)
			// Phase Z.5.3 — batch GeoIP lookup. Powers the
			// /logs SOURCE IP column's "82.65.x.x · FR"
			// enrichment without a per-IP round-trip. Cap
			// 256 IPs / request. AC #13 degraded path :
			// empty country codes when MMDB absent.
			r.Post("/geo/lookup-batch", h.geoLookupBatch)
			// Step V.4 — server geographic position (read).
			// Returns the current Mercator-center coordinates
			// + mode (auto|manual) per spec §5.1. Viewer-
			// accessible — the /map page needs to read this
			// at mount time to place its central pin. AC #13
			// degraded shape when no row + no boot
			// auto-detect: 200 + {degraded:true, lat:0,
			// lon:0, ...}.
			r.Get("/observability/server-position", h.getServerPosition)
			// Step O.3 — managed-domain list (read).
			// Viewer-accessible per AC #20 (parallel to
			// the DNS-provider GET — both are config reads
			// the dashboard's SSL section binds to).
			r.Get("/settings/managed-domains", h.listManagedDomains)
			// Step P.3 — auto-classify config (read).
			// Viewer-accessible per AC #20. Returns both
			// the rule set + a credentials-configured
			// boolean so the frontend renders the whole
			// section state in one round-trip.
			r.Get("/settings/automation", h.getAutomation)
			// Step T T.1 — per-domain runtime cert metadata.
			// Viewer-accessible — parallel to
			// /settings/managed-domains above (both read
			// surfaces the Certificates page binds to).
			// Returns []CertRuntimeInfo sorted by NotAfter
			// ascending. Degrades to [] when the tracker
			// singleton is missing (AC #13).
			r.Get("/certificates", h.listCertificates)
			// Step E: live-metrics WebSocket. HardAuthMiddleware
			// rejects the handshake (401 / 403) BEFORE the upgrade,
			// so an unauthorized peer never sees an open WS frame
			// — spec §5.1 + §7.1.
			if ws != nil {
				r.Get("/ws/topology", ws.ServeHTTP)
			}

			// Phase 2 #R-TOPO-v2 — topology snapshot (one-shot
			// read) + stream (WS push). Same hard-auth gate as
			// the rest of this subgroup: viewer + admin both
			// accepted, write surface lives in Phase 2.1.
			//
			// The stream's hard-auth happens BEFORE the WS
			// upgrade (the middleware writes 401/403 and the
			// connection is never upgraded), matching the
			// existing /ws/topology pattern. No in-WS close
			// codes for auth failures.
			if snapshotHandler != nil {
				r.Get("/topology/snapshot", snapshotHandler.ServeHTTP)
			}
			if streamHandler != nil {
				r.Get("/topology/stream", streamHandler.ServeHTTP)
			}

			// Step V.3 — live geo events WebSocket. Mirror of
			// /ws/topology shape. HardAuthMiddleware rejects
			// the handshake (401 / 403) BEFORE the upgrade —
			// spec §5.5. Tests that do not exercise the geo
			// endpoint pass nil.
			if wsGeoEvents != nil {
				r.Get("/ws/geo-events", wsGeoEvents.ServeHTTP)
			}

			// Admin-only sub-group (Step K.2 §1.3 decision 12).
			// Viewer is rejected with 403 "admin role required".
			r.Group(func(r chi.Router) {
				r.Use(auth.RequireAdminMiddleware())
				r.Post("/routes", h.createRoute)
				r.Put("/routes/{id}", h.updateRoute)
				r.Delete("/routes/{id}", h.deleteRoute)
				r.Post("/routes/{id}/disable", h.disableRoute)
				r.Post("/routes/{id}/enable", h.enableRoute)
				r.Post("/routes/{id}/waf-exclusions", h.addWAFExclusion)
				// v2.40 — Caddyfile import (preview writes nothing).
				r.Post("/routes/import/caddyfile/preview", h.previewCaddyfileImport)
				r.Post("/routes/import/caddyfile", h.importCaddyfile)
				r.Post("/routes/{id}/waf-test", h.testRouteWAF)
				// v2.42 — TCP services, write side + the backend
				// dial test. Admin only, audited.
				r.Post("/tcp-services", h.createTCPService)
				r.Put("/tcp-services/{id}", h.updateTCPService)
				r.Delete("/tcp-services/{id}", h.deleteTCPService)
				r.Post("/tcp-services/{id}/test", h.testTCPService)
				r.Post("/waf/seclang/validate", h.validateSecLang)
				r.Post("/waf/seclang/from-guided", h.secLangFromGuided)
				r.Post("/routes/{id}/maintenance", h.enterMaintenance)
				r.Post("/routes/{id}/maintenance/off", h.exitMaintenance)
				r.Delete("/certificates/{domain}", h.deleteCertificate)
				// Step R — custom error pages CRUD (admin-only).
				// GET endpoints are mounted in the viewer-accessible
				// section above so the RouteForm dropdown can list
				// templates without admin scope.
				r.Post("/error-templates", h.createErrorTemplate)
				r.Put("/error-templates/{id}", h.updateErrorTemplate)
				r.Delete("/error-templates/{id}", h.deleteErrorTemplate)
				// Task 7 — global maintenance page write (admin-
				// only). GET is mounted in the viewer-accessible
				// section above, same split as error-templates.
				r.Put("/settings/maintenance-page", h.putMaintenancePage)
				// External certificates write-side (admin-only,
				// v2.19.0). GETs are in the viewer section above,
				// same split as maintenance-page / error-templates.
				r.Post("/certificates/external", h.createExternalCert)
				r.Post("/certificates/external/csr", h.createExternalCertCSR)
				r.Put("/certificates/external/{id}", h.updateExternalCert)
				r.Delete("/certificates/external/{id}", h.deleteExternalCert)
				// Step #R-PROXMOX-HTTPS-LOOP commit 3 — operator-
				// triggered upstream probe (UI button). Per-URL
				// invocation; frontend parallelises pool > 1 via
				// Promise.all. Admin-only via this sub-group's
				// RequireAdminMiddleware (same trust posture as
				// createRoute / updateRoute — see
				// routes_test_upstream.go for the SSRF posture
				// rationale).
				r.Post("/routes/test-upstream", h.testUpstream)
				// v2.56 — run the active health check with the settings
				// currently in the form, before saving. A misconfigured
				// check used to surface only as a post-save 503 and an
				// undone change, which protected the site and explained
				// nothing. Same admin-only posture and same probe dialer
				// as test-upstream above; writes nothing, reloads nothing.
				r.Post("/routes/test-health-check", h.testHealthCheck)
				// v2.11 — DNS provider collection (UUID-keyed,
				// multi-config). Replaces the pre-v2.11 singleton
				// /settings/dns-providers/ovh GET/PUT.
				r.Get("/settings/dns-providers", h.listDNSProviders)
				// v2.26 — provider-type registry (form metadata) and
				// read-only connection test. /types is registered
				// before /{id} for readability; chi matches the static
				// segment first either way.
				r.Get("/settings/dns-providers/types", h.listDNSProviderTypes)
				// v2.28 — ASN search / name resolution for the route
				// form's geo-filtering ASN rules.
				r.Get("/geo/asn", h.searchASN)
				r.Post("/settings/dns-providers/{id}/test", h.testDNSProvider)
				r.Post("/settings/dns-providers", h.createDNSProvider)
				r.Get("/settings/dns-providers/{id}", h.getDNSProvider)
				r.Put("/settings/dns-providers/{id}", h.updateDNSProvider)
				r.Delete("/settings/dns-providers/{id}", h.deleteDNSProvider)
				// v2.12.3 — opt-in update checker. Admin-gated (unlike
				// the public /system/health): carries operator-relevant
				// version state + toggles the opt-in.
				r.Get("/system/version", h.systemVersion)
				r.Post("/system/version/check", h.systemVersionCheck)
				r.Put("/system/version/config", h.systemVersionConfig)
				// Brick 3, Task 5 — opt-in GeoIP database auto-update.
				// Admin-gated, mirroring the update checker above.
				r.Get("/system/geoip/update-config", h.getGeoIPUpdateConfig)
				r.Put("/system/geoip/update-config", h.putGeoIPUpdateConfig)
				r.Post("/system/geoip/update", h.postGeoIPUpdate)
				r.Get("/system/geoip/status", h.getGeoIPStatus)
				// Step K.1 — forward-auth provider CRUD.
				r.Get("/settings/forward-auth/providers", h.listForwardAuthProviders)
				r.Post("/settings/forward-auth/providers", h.createForwardAuthProvider)
				r.Get("/settings/forward-auth/providers/{name}", h.getForwardAuthProvider)
				r.Put("/settings/forward-auth/providers/{name}", h.updateForwardAuthProvider)
				r.Delete("/settings/forward-auth/providers/{name}", h.deleteForwardAuthProvider)
				// Step K.2 — OIDC settings + allowlist + admin
				// users management.
				r.Get("/settings/oidc", h.getOIDCConfig)
				r.Put("/settings/oidc", h.putOIDCConfig)
				// Phase 2 Users-page refactor — operator-triggered
				// discovery probe ({issuer}/.well-known/openid-
				// configuration). Mirrors the routes/test-upstream
				// admin trust posture; uses saved config, no body.
				r.Post("/settings/oidc/test", h.testOIDCConnection)
				r.Get("/settings/oidc/allowlist", h.listOIDCAllowlist)
				r.Post("/settings/oidc/allowlist", h.addOIDCAllowlist)
				r.Delete("/settings/oidc/allowlist/{email}", h.deleteOIDCAllowlist)
				r.Get("/admin/users", h.listAdminUsers)
				// v2.48 — create a local account. Admin only:
				// creating an account is a privilege change, same
				// posture as editing a role or deleting one.
				r.Post("/admin/users", h.createAdminUser)
				r.Post("/admin/users/{id}/role", h.updateUserRole)
				// Users-page Phase 1 refactor — delete an
				// admin user. Last-admin guard fires inside
				// UserStore.Delete; sessions are cascaded
				// inside the handler.
				r.Delete("/admin/users/{id}", h.deleteAdminUser)
				// Phase 4 — service-account lifecycle. Same
				// admin trust posture as the human-user
				// endpoints above; the service account itself
				// authenticates via Bearer token, not via the
				// session cookie that gates THIS request.
				r.Post("/admin/users/service-accounts", h.createServiceAccount)
				r.Post("/admin/users/service-accounts/{id}/rotate-token", h.rotateServiceAccountToken)
				r.Delete("/admin/users/service-accounts/{id}", h.deleteServiceAccount)
				// Step K.3 — backup / restore.
				r.Get("/admin/backup", h.getBackup)
				r.Post("/admin/backup", h.postBackup)
				r.Post("/admin/restore", h.postRestore)
				r.Get("/settings/route-check", h.getRouteCheckConfig)
				r.Put("/settings/route-check", h.putRouteCheckConfig)
				// v2.50 — the HTTP access log CrowdSec parses.
				r.Get("/settings/access-log", h.getAccessLogConfig)
				r.Put("/settings/access-log", h.putAccessLogConfig)
				r.Get("/settings/backup-schedule", h.getBackupSchedule)
				r.Put("/settings/backup-schedule", h.putBackupSchedule)
				r.Post("/admin/backups/run", h.runBackupNow)
				r.Get("/admin/backups", h.listBackups)
				r.Get("/admin/backups/{name}", h.downloadBackup)
				r.Delete("/admin/backups/{name}", h.deleteBackup)
				r.Post("/admin/backups/{name}/restore", h.restoreScheduledBackup)
				// Step O.3 — managed-domain CRUD writes.
				// POST creates + runs the D8.A migration
				// atomically. DELETE supports the AC #21
				// `?revertTo=` query parameter so the
				// operator explicitly picks the post-revert
				// ACMEChallenge value.
				r.Post("/settings/managed-domains", h.createManagedDomain)
				r.Delete("/settings/managed-domains/{apex}", h.deleteManagedDomain)
				// Step P.3 — auto-classify config writes.
				// PUT /rules atomic-swaps the live engine's
				// RuleSet (no restart). PUT /credentials
				// recreates the WatcherClient + swaps the
				// engine's writer pointer atomically (P.2
				// commit-body checklist item #3, recreate-
				// and-swap path).
				r.Put("/settings/automation/rules", h.putAutomationRules)
				r.Put("/settings/automation/credentials", h.putAutomationCredentials)
				// Step CS.3 follow-up — operator-pressed
				// "Reset Security Automation" button. DELETE
				// wipes the watcher row + clears the in-
				// memory writer. Distinct from PUT-all-blank
				// erasure (which emits automation_rule_changed)
				// so /audit traces the deliberate intent via
				// the new automation_reset action. Mirror of
				// CS.2.C f1fe919 (crowdsec_reset).
				r.Delete("/settings/automation/credentials", h.deleteAutomationCredentials)
				// Step V.4 — server geographic position writes.
				// PUT installs a manual override; POST :redetect
				// re-runs the V.1 ipify-then-GeoIP path (useful
				// when the operator's public IP changed). Both
				// admin-gated per spec §5.2 + §5.3. The chi
				// router matches the literal `:redetect`
				// suffix; no path-param interpretation since
				// chi doesn't reserve `:`.
				r.Put("/observability/server-position", h.putServerPosition)
				r.Post("/observability/server-position:redetect", h.redetectServerPosition)
				// Step CS.1 — CrowdSec bouncer settings.
				// GET returns the persisted row (secrets
				// redacted) + fresh-install fallback. PUT
				// persists + hot-reloads the embedded Caddy
				// via the CrowdSecApplier seam. POST /test
				// probes LAPI without mutating state.
				r.Get("/settings/crowdsec", h.getCrowdSecSettings)
				r.Put("/settings/crowdsec", h.putCrowdSecSettings)
				r.Delete("/settings/crowdsec", h.deleteCrowdSecSettings)
				r.Post("/settings/crowdsec/test", h.testCrowdSecConnection)
				// Brick 2 Task 2 — MaxMind GeoIP account
				// credentials. GET returns the persisted row
				// (secret redacted) + fresh-install fallback
				// (configured=false). PUT persists; DELETE
				// wipes. Mirror of the CrowdSec settings
				// endpoints above; the /test connection probe
				// is added in Task 3.
				r.Get("/settings/maxmind", h.getMaxMindSettings)
				r.Put("/settings/maxmind", h.putMaxMindSettings)
				r.Delete("/settings/maxmind", h.deleteMaxMindSettings)
				r.Post("/settings/maxmind/test", h.testMaxMindConnection)
				// Step CS.2.A — Live LAPI decisions proxy.
				// Distinct from /security/decisions (which
				// queries the local mirror in metrics.db) —
				// this one is a real-time pass-through to
				// LAPI's /v1/decisions endpoint. See
				// crowdsec_decisions.go for the two-endpoint
				// rationale.
				r.Get("/security/crowdsec/decisions", h.listCrowdSecDecisions)
				// Step CS.2.C — Scenarios tab via /v1/alerts.
				// Reuses Security Automation (Feature A)
				// machine credentials for the JWT login
				// (LAPI's MachineRoutes require JWT, not
				// the bouncer API key — empirical day-7
				// finding). Cached JWT, singleflight-deduped,
				// retry once on 401. See crowdsec_scenarios.go.
				r.Get("/security/crowdsec/scenarios", h.listCrowdSecScenarios)
				// Step CS.3 Commit C — Bannir une IP.
				// Admin-only manual ban via Security
				// Automation machine creds + JWT (shared
				// lapiWithJWT helper). Encodes
				// scenario = "manual:<username>|<reason>"
				// so the Live LAPI tab's two-line cell can
				// surface the operator's reason inline (per
				// CS.3 Commit B parser). See
				// crowdsec_manual_ban.go for the LAPI Alert
				// payload shape + validation rules.
				r.Post("/security/crowdsec/decisions", h.addManualBan)
				// Step AL.1.b — alerting channel CRUD + /test.
				// Admin-only (channel config carries SMTP
				// passwords + webhook auth headers — secret
				// surface, not viewer-readable). The /test
				// endpoint fires a synthetic event so the
				// operator can verify the channel wires end-
				// to-end without writing a rule first.
				r.Get("/settings/alerting/channels", h.listAlertChannels)
				r.Post("/settings/alerting/channels", h.createAlertChannel)
				r.Get("/settings/alerting/channels/{id}", h.getAlertChannel)
				r.Put("/settings/alerting/channels/{id}", h.updateAlertChannel)
				r.Delete("/settings/alerting/channels/{id}", h.deleteAlertChannel)
				r.Post("/settings/alerting/channels/{id}/test", h.testAlertChannel)
				// Step AL.3b — alerting rule CRUD + /test.
				// Admin-only (same trust posture as
				// channels: rules pick severity + channels
				// + templates; viewer must not mutate). The
				// /test endpoint force-evaluates the rule
				// via the dispatcher, bypassing the
				// cooldown LRU so the operator can re-test
				// a recently-fired rule without waiting
				// out the silence window.
				r.Get("/settings/alerting/rules", h.listAlertRules)
				r.Post("/settings/alerting/rules", h.createAlertRule)
				r.Get("/settings/alerting/rules/{id}", h.getAlertRule)
				r.Put("/settings/alerting/rules/{id}", h.updateAlertRule)
				r.Delete("/settings/alerting/rules/{id}", h.deleteAlertRule)
				r.Post("/settings/alerting/rules/{id}/test", h.testAlertRule)
			})
		})
	})
	return r
}

func (h *Handler) listRoutes(w http.ResponseWriter, r *http.Request) {
	routes, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("list routes", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to list routes")
		return
	}
	// Step O.3 AC #4: fetch managed domains ONCE per list call
	// so the derived effectiveCertSource on every routeResponse
	// is computed off a consistent snapshot. A storage failure
	// here is non-fatal — we proceed with empty mds and the
	// per-route field falls back to the per-route ACME label
	// (no managed-domain inference). Logged so the operator
	// notices via the slog stream.
	mds, mdErr := h.store.ListManagedDomains(r.Context())
	if mdErr != nil {
		h.logger.Warn("list managed domains for effectiveCertSource — continuing without", "err", mdErr)
	}
	out := make([]routeResponse, 0, len(routes))
	for _, rt := range routes {
		resp := toResponse(rt)
		resp.EffectiveCertSource = computeEffectiveCertSource(rt, mds)
		// Critique 11 Pack A: attach the per-route aggregate
		// health rollup derived from the Stage B HC tracker.
		// Nil-tolerant; collapses to "unknown" when the tracker
		// isn't wired (mirrors the no-HC-configured gate).
		resp.AggregateStatus, resp.HealthyUpstreamCount, resp.TotalUpstreamCount =
			computeRouteAggregateHealth(rt, h.hcStatus)
		out = append(out, resp)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) getRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rt, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to get route")
		return
	}
	// Step O.3 AC #4 — same enrichment as listRoutes. Storage
	// failure on the managed-domains fetch is non-fatal.
	mds, mdErr := h.store.ListManagedDomains(r.Context())
	if mdErr != nil {
		h.logger.Warn("list managed domains for effectiveCertSource — continuing without", "err", mdErr)
	}
	resp := toResponse(rt)
	resp.EffectiveCertSource = computeEffectiveCertSource(rt, mds)
	// Critique 11 Pack A — see the comment in listRoutes for the
	// rationale. Same nil-tolerance contract: missing tracker
	// collapses to "unknown".
	resp.AggregateStatus, resp.HealthyUpstreamCount, resp.TotalUpstreamCount =
		computeRouteAggregateHealth(rt, h.hcStatus)
	writeJSON(w, http.StatusOK, resp)
}

// validateAliasesStructural runs the same hostname rule used for the
// primary Host (RFC 1035 grammar + length) on every alias supplied
// by the user. It also enforces the two intra-route invariants from
// Step I.3 S3: no alias may duplicate the primary host, and no
// alias may duplicate another alias in the same request.
//
// Returns the first failure with a user-facing message. The
// duplicate checks here mirror the storage-layer defense in
// storage.Route.validate; the API copy gives a friendlier message
// (with the offending alias quoted) before the storage layer would
// reject it anonymously.
func validateAliasesStructural(host string, aliases []string) error {
	seen := make(map[string]struct{}, len(aliases))
	for _, a := range aliases {
		if a == "" {
			return errors.New("alias must not be empty")
		}
		if err := validateHost(a); err != nil {
			return fmt.Errorf("alias %q: %s", a, err.Error())
		}
		if a == host {
			return fmt.Errorf("alias %q duplicates the primary host", a)
		}
		if _, dup := seen[a]; dup {
			return fmt.Errorf("alias %q duplicates within the same route", a)
		}
		seen[a] = struct{}{}
	}
	return nil
}

// collectAllHostsExcept walks existing routes and returns a map from
// hostname to owning route ID, including every primary Host AND every
// alias. The excludeID, when non-empty, skips the route currently
// being updated (so it doesn't collide with its own existing aliases).
// Used by createRoute and updateRoute to enforce cross-route uniqueness
// across the union of (Host, Aliases) per Step I.3 Q1.
func collectAllHostsExcept(routes []storage.Route, excludeID string) map[string]string {
	owners := make(map[string]string, len(routes))
	for _, rt := range routes {
		if rt.ID == excludeID {
			continue
		}
		for _, h := range rt.AllHosts() {
			owners[h] = rt.ID
		}
	}
	return owners
}

// hostnamesEqual reports whether two hostname slices contain the same
// hosts in the same order. Used by updateRoute to short-circuit the
// uniqueness check when nothing changed (avoids a needless ListRoutes
// + map build on every PUT that flips, say, only WAFEnabled).
func hostnamesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Step I.5 — Basic Auth helpers.

// basicAuthUsernameMaxLen caps the username at a reasonable length.
// 64 chars covers admin usernames + service accounts; longer values
// hint at confused inputs (e.g. an email or a token pasted into the
// wrong field).
const basicAuthUsernameMaxLen = 64

// basicAuthPasswordMaxBytes caps the plaintext password at 64 bytes.
// argon2id doesn't have bcrypt's 72-byte ceiling but a soft cap
// protects against DoS via very long passwords (each hash costs
// ~100 ms; a 1 MB password could lock a goroutine).
const basicAuthPasswordMaxBytes = 64

// validateBasicAuth enforces the per-route Basic Auth invariants
// (Step I.5 rules preserved through K.1 — the nested BasicAuth
// struct of K.1 carries the same Username / Password fields).
// Called ONLY when req.AuthMode == storage.RouteAuthBasic;
// callers MUST guard. existingHash carries the hash already
// stored for this route on PUT — empty on POST. When the user
// picks AuthMode "basic", they must supply a username AND either
// a fresh password (POST, or PUT to rotate) or rely on the
// existing hash (PUT, leaving the password field blank to keep it).
func validateBasicAuth(req routeRequest, existingHash string) error {
	if req.BasicAuth.Username == "" {
		return errors.New("basicAuth.username must not be empty when authMode is \"basic\"")
	}
	if len(req.BasicAuth.Username) > basicAuthUsernameMaxLen {
		return fmt.Errorf("basicAuth.username must not exceed %d characters", basicAuthUsernameMaxLen)
	}
	// RFC 7617: ':' is the Basic Auth separator inside the
	// "user:password" payload — embedding it in the username would
	// break the protocol. Reject early with a clear message.
	if strings.ContainsRune(req.BasicAuth.Username, ':') {
		return errors.New("basicAuth.username must not contain ':' (Basic Auth separator)")
	}
	for _, r := range req.BasicAuth.Username {
		// Reject control / whitespace characters: they make log
		// injection trivial and rarely belong in an admin username.
		if r < 0x21 || r == 0x7F {
			return errors.New("basicAuth.username must not contain whitespace or control characters")
		}
	}
	if req.BasicAuth.Password == "" && existingHash == "" {
		return errors.New("basicAuth.password required when enabling basic auth on a route without an existing password")
	}
	if len(req.BasicAuth.Password) > basicAuthPasswordMaxBytes {
		return fmt.Errorf("basicAuth.password must not exceed %d bytes", basicAuthPasswordMaxBytes)
	}
	return nil
}

// routeForAudit returns a copy of r with the per-route Basic
// Auth password hash blanked. Audit events are persisted under
// the assumption that they hold NO secrets (D3 / spec §1.6 #3);
// the argon2id PHC of a route's Basic Auth must never reach the
// audit bucket. Apply to every storage.Route passed into
// appendAudit's AfterJSON / BeforeJSON since Step I.5 — refactored
// in K.1 to read through the nested BasicAuth struct.
//
// v2.30: also blanks path-rule Basic Auth hashes and redacts the
// values of credential-bearing request / response headers.
func routeForAudit(r storage.Route) storage.Route {
	r.BasicAuth.PasswordHash = ""
	if len(r.PathRules) > 0 {
		rules := slices.Clone(r.PathRules)
		for i := range rules {
			if ba := rules[i].BasicAuth; ba != nil && ba.PasswordHash != "" {
				cp := *ba
				cp.PasswordHash = ""
				rules[i].BasicAuth = &cp
			}
		}
		r.PathRules = rules
	}
	r.RequestHeaders = redactSensitiveHeaders(r.RequestHeaders)
	r.ResponseHeaders = redactSensitiveHeaders(r.ResponseHeaders)
	return r
}

// Step I.6 — Custom request/response headers.

const (
	headerNameMaxLen  = 128
	headerValueMaxLen = 1024
)

// headerNameTokenRE matches an RFC 7230 token: ALPHA / DIGIT plus
// the punctuation set explicitly listed in the grammar. No space,
// no ':', no control character — those are filtered by the regex
// itself (negative match) and made explicit by validateHeaderName's
// error message.
var headerNameTokenRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+\-.^_` + "`" + `|~]+$`)

// reservedHeaderNames lists HTTP header names the user MUST NOT
// override per Step I.6 Q3 / spec §1.6 #2: hop-by-hop fields (RFC
// 7230 §6.1) plus Host and the framing-critical Content-Length /
// Content-Encoding which Caddy's reverse_proxy manages on the
// operator's behalf. Comparison is case-insensitive (HTTP header
// names are case-insensitive); the lookup uses strings.ToLower(name).
var reservedHeaderNames = map[string]struct{}{
	"host":              {},
	"connection":        {},
	"keep-alive":        {},
	"transfer-encoding": {},
	"te":                {},
	"trailer":           {},
	"upgrade":           {},
	"content-length":    {},
	"content-encoding":  {},
}

// validateHeaderName enforces the RFC 7230 token grammar + the
// reserved blacklist + the length cap. Empty name is rejected with
// a separate message (the caller usually catches it earlier when
// building the map, but defense in depth).
func validateHeaderName(name string) error {
	if name == "" {
		return errors.New("header name must not be empty")
	}
	if len(name) > headerNameMaxLen {
		return fmt.Errorf("header name %q exceeds %d characters", name, headerNameMaxLen)
	}
	if !headerNameTokenRE.MatchString(name) {
		return fmt.Errorf("header name %q is not a valid HTTP token (RFC 7230)", name)
	}
	if _, reserved := reservedHeaderNames[strings.ToLower(name)]; reserved {
		return fmt.Errorf("header name %q is reserved (managed by Caddy or required for framing)", name)
	}
	return nil
}

// validateHeaderValue catches HTTP header injection (CR / LF inside
// the value would break the wire framing — see spec §1.6 #2 and
// I.6 audit finding F1) plus NUL and other ASCII control characters
// except HTAB. Visible-ASCII + SP + HTAB are the RFC 7230 field-
// value VCHAR / WSP set. Empty values are ALLOWED (Step I.6
// Ajustement 2: some upstreams check header presence, not value).
func validateHeaderValue(name, value string) error {
	if len(value) > headerValueMaxLen {
		return fmt.Errorf("header %q value exceeds %d characters", name, headerValueMaxLen)
	}
	for i, r := range value {
		if r == '\t' {
			continue
		}
		if r < 0x20 || r == 0x7F {
			return fmt.Errorf("header %q value contains a control character at offset %d (CR/LF/NUL are forbidden)", name, i)
		}
	}
	return nil
}

// Step I.4 — WAF mode validation.

// WAFMode allowed values. Empty string is NOT in this set: empty is a
// per-handler signal ("default to detect on POST" / "preserve on
// PUT") that callers handle before invoking validateWAFMode.
var wafModeValues = map[string]struct{}{
	"off":    {},
	"detect": {},
	"block":  {},
}

// validateWAFMode rejects any value not in the enum {off, detect, block}.
// The empty string is treated as INVALID at this layer; createRoute and
// updateRoute apply the "default to detect" / "preserve previous"
// semantics BEFORE calling this, so by the time validateWAFMode runs the
// caller has either supplied a value or wants it rejected.
func validateWAFMode(mode string) error {
	if _, ok := wafModeValues[mode]; !ok {
		return fmt.Errorf("wafMode %q is invalid (must be one of: off, detect, block)", mode)
	}
	return nil
}

// Step X Option (c) — WAF exclude-rules constants.
//
// The CRS rule-id space is 6-digit per upstream convention
// (every CRS rule file uses a 6-digit `id:` action). Arenet
// reserves the [100000, 199999] sub-range for its own
// internally-generated directives (admin-API exclusion uses
// id:100001, the per-route Option (c) SecAction uses id:200001
// — wait, that's in the 200000 range, NOT reserved). The
// validation here rejects IDs in the reserved sub-range so an
// operator can't accidentally remove an Arenet-internal rule
// that the runtime depends on, OR pile redundant
// ctl:ruleRemoveById entries against IDs that already exist
// in Arenet's own emit.
const (
	wafExcludeRuleMinID            = 100000 // 6-digit lower bound
	wafExcludeRuleMaxID            = 999999 // 6-digit upper bound
	wafExcludeRuleArenetReservedHi = 199999 // [100000, 199999] is Arenet-reserved
)

// Step X Option (e) — WAFExcludeTags canonicalisation knobs.
const (
	// wafExcludeTagMaxLen guards against absurd operator
	// input (a 1 MB tag value would bloat the SecAction
	// directive string + the BoltDB row). CRS tags in
	// practice are <50 chars ; 128 is generous.
	wafExcludeTagMaxLen = 128
	// wafExcludeTagsMaxCount caps the number of tags per
	// route. The SecAction directive line is single-line
	// (comma-separated ctl: actions) — a runaway list
	// would build a kilobyte-scale string Coraza has to
	// parse on every request. 64 entries is two orders of
	// magnitude above any plausible operator config.
	wafExcludeTagsMaxCount = 64
)

// normalizeExcludeTags validates + canonicalises an
// operator-supplied list of CRS tags. Mirror of
// normalizeExcludeRules for the string-tag domain.
//
// Canonicalisation steps :
//
//   - strip surrounding whitespace
//   - reject empty-after-trim entries
//   - reject entries containing characters that would break
//     the SecAction directive line shape : whitespace + ","
//     (the directive uses comma to separate ctl: actions,
//     so an embedded comma would break the parse + smuggle
//     additional actions)
//   - lowercase (CRS tags are conventionally lowercase ; the
//     match is case-sensitive at Coraza ctl.go runtime, so
//     normalising at the API boundary saves the operator
//     from "Attack-SQLi" silently never matching)
//   - dedupe (operator may paste the same tag twice)
//   - sort ascending (stable order = stable emit + audit diff)
//
// Returns ([], nil) for an explicit empty input — same clear-
// exclusions semantics as normalizeExcludeRules.
func normalizeExcludeTags(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{}, nil
	}
	if len(in) > wafExcludeTagsMaxCount {
		return nil, fmt.Errorf(
			"wafExcludeTags: too many tags (%d) ; max %d per route",
			len(in), wafExcludeTagsMaxCount,
		)
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		t := strings.ToLower(strings.TrimSpace(raw))
		if t == "" {
			return nil, fmt.Errorf("wafExcludeTags: empty tag entry")
		}
		if len(t) > wafExcludeTagMaxLen {
			return nil, fmt.Errorf(
				"wafExcludeTags: tag %q exceeds %d chars",
				t, wafExcludeTagMaxLen,
			)
		}
		// Reject characters that would smuggle additional
		// ctl: actions into the SecAction directive line.
		// CRS tag convention is [a-z0-9/_-] — defence in
		// depth against an operator-typed " ", "," or '"' that
		// would corrupt the emit.
		if strings.ContainsAny(t, " ,\t\n\r\"") {
			return nil, fmt.Errorf(
				"wafExcludeTags: tag %q contains whitespace or comma (invalid for SecAction directive)",
				raw,
			)
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// normalizeExcludeRules validates each rule ID in the input
// slice, returns the deduped + ascending-sorted canonical
// form for storage. Returns a 400-ready error on the first
// invalid ID found ; the caller surfaces it verbatim with
// the WAF_EXCLUDE_RULES_INVALID code.
//
// Returns ([], nil) for an explicit empty input — the
// caller wants to clear all exclusions, and the empty slice
// is the correct stored shape (the omitempty json tag on
// storage.Route.WAFExcludeRules drops it from the on-disk
// representation, so an explicit-empty PUT is byte-equal
// to a never-set route after persist + reload).
func normalizeExcludeRules(in []int) ([]int, error) {
	if len(in) == 0 {
		return []int{}, nil
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, id := range in {
		if id < wafExcludeRuleMinID || id > wafExcludeRuleMaxID {
			return nil, fmt.Errorf(
				"wafExcludeRules: rule ID %d is out of range (must be 6-digit, %d..%d)",
				id, wafExcludeRuleMinID, wafExcludeRuleMaxID,
			)
		}
		if id <= wafExcludeRuleArenetReservedHi {
			return nil, fmt.Errorf(
				"wafExcludeRules: rule ID %d is in the Arenet-reserved range (must be > %d)",
				id, wafExcludeRuleArenetReservedHi,
			)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Ints(out)
	return out, nil
}

// Step Q — rate-limit validator + materialiser. The wire-
// side rateLimitReq mirrors storage.RouteRateLimit verbatim
// so the materialise step is field copy + canonicalisation
// (empty Key → default placeholder).
//
// Validation contract :
//   - Events MUST be >= 1 (a zero would block every request ;
//     almost certainly a typo).
//   - Window MUST parse via time.ParseDuration AND be
//     strictly positive (>= 1ms practically ; we don't
//     enforce a floor, the upstream rate-limit module
//     handles fractional-second windows fine).
//   - Key is operator-free-form ; any Caddy placeholder
//     accepted. Empty defaulted to {http.request.remote.host}
//     at caddymgr emit time (single source of truth — keeps
//     this validator focused on the inputs the operator
//     supplied).
//
// Returns (nil, nil) for a nil input ; non-nil input is
// validated and materialised. Errors are operator-friendly
// (surfaced verbatim in the 400 body).
func materialiseRateLimit(req *rateLimitReq) (*storage.RouteRateLimit, error) {
	if req == nil {
		return nil, nil
	}
	if req.Events < 1 {
		return nil, fmt.Errorf("rateLimit.events must be >= 1 (got %d)", req.Events)
	}
	if strings.TrimSpace(req.Window) == "" {
		return nil, fmt.Errorf("rateLimit.window is required (e.g. \"1m\", \"30s\")")
	}
	dur, err := time.ParseDuration(req.Window)
	if err != nil {
		return nil, fmt.Errorf("rateLimit.window invalid : %v (e.g. \"1m\", \"30s\", \"5m\")", err)
	}
	if dur <= 0 {
		return nil, fmt.Errorf("rateLimit.window must be > 0 (got %s)", req.Window)
	}
	return &storage.RouteRateLimit{
		Events: req.Events,
		Window: req.Window,
		Key:    req.Key,
	}, nil
}

// Step W — country-block helpers.

// materialiseCountryBlock converts a wire-side countryBlockReq to a
// countryblock.Config ready for storage. Canonicalises the Mode
// (empty → ModeOff) and uppercases each country code (operators
// often type "fr" out of habit — uppercase it server-side rather
// than rejecting at validation). countryblock.Config.Validate then
// runs the §D2 footgun + enum + duplicate checks.
//
// Returns the materialised Config alongside the validation error;
// the caller surfaces it as a 400.
func materialiseCountryBlock(req countryBlockReq) (countryblock.Config, error) {
	mode := req.Mode
	if mode == "" {
		mode = string(countryblock.ModeOff)
	}
	// Trim ASCII whitespace + uppercase. countryblock.Validate
	// then rejects anything still not a valid code. Done
	// client-side too, but defense in depth.
	cfg := countryblock.Config{
		Mode:        countryblock.Mode(mode),
		CountryList: normaliseCodes(req.CountryList),
		StatusCode:  req.StatusCode,
	}
	// v2.27 — optional lists stay nil when empty so a pre-v2.27
	// config stores (and emits to Caddy) byte-identically.
	if len(req.Continents) > 0 {
		cfg.Continents = normaliseCodes(req.Continents)
	}
	if len(req.ASNs) > 0 {
		cfg.ASNs = req.ASNs
	}
	if req.Exceptions != nil && (len(req.Exceptions.Countries) > 0 || len(req.Exceptions.ASNs) > 0) {
		cfg.Exceptions = &countryblock.Exceptions{}
		if len(req.Exceptions.Countries) > 0 {
			cfg.Exceptions.Countries = normaliseCodes(req.Exceptions.Countries)
		}
		if len(req.Exceptions.ASNs) > 0 {
			cfg.Exceptions.ASNs = req.Exceptions.ASNs
		}
	}
	if err := cfg.Validate(); err != nil {
		return countryblock.Config{}, err
	}
	return cfg, nil
}

// normaliseCodes trims and uppercases each code; never returns nil.
func normaliseCodes(codes []string) []string {
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		out = append(out, strings.ToUpper(strings.TrimSpace(code)))
	}
	return out
}

// validateHeaders walks a request- or response-header map and runs
// validateHeaderName + validateHeaderValue on every entry. The
// direction argument ("request" / "response") is interpolated into
// error messages so the user knows which section to fix. Returns
// the first failure (fail-fast — typing helps when iterating in
// the form).
//
// Note (Step I.6 Ajustement 1): no intra-request duplicate check.
// JSON object key duplicates are last-wins per Go's json.Decode;
// the frontend repeater prevents this in the normal flow but a
// hand-crafted curl could trigger silent merge. Documented in the
// I.6 commit message; Step J may add an ordered-decoder-based
// duplicate check if user feedback warrants it.
func validateHeaders(headers map[string]string, direction string) error {
	for name, value := range headers {
		if err := validateHeaderName(name); err != nil {
			return fmt.Errorf("%s %s", direction, err.Error())
		}
		if err := validateHeaderValue(name, value); err != nil {
			return fmt.Errorf("%s %s", direction, err.Error())
		}
	}
	return nil
}

func (h *Handler) createRoute(w http.ResponseWriter, r *http.Request) {
	var req routeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Surface the decoder's reason — typically either a
		// json.SyntaxError ("invalid character 'x' looking for…")
		// or DisallowUnknownFields' "json: unknown field "xyz"".
		// The latter is the exact symptom that masked the Step
		// #R-PROXMOX-HTTPS-LOOP commit 1 wire-gap (smoke caught
		// "json: unknown field \"insecureSkipVerify\"" silently
		// flattened to "invalid JSON body"). #R-API-PUT-ROUTE-
		// GENERIC-400 tracks the broader sweep across the other
		// ~16 handlers in this package.
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// Step J.1: materialise the per-Upstream default Weight=1 BEFORE
	// pool validation. The storage validate() rule weight >= 1 (the
	// last line of defence) would otherwise reject any pool element
	// the caller submitted without a weight. §1.3 decision 1: weight
	// defaults to 1 and is only consulted by weighted_round_robin.
	for i := range req.Upstreams {
		if req.Upstreams[i].Weight == 0 {
			req.Upstreams[i].Weight = 1
		}
	}
	// A redirecting route proxies nothing: an empty pool is valid for it.
	// See validateUpstreamPoolAllowingEmpty.
	if err := validateUpstreamPoolAllowingEmpty(req.Upstreams, req.RedirectConfig != nil); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// Step J.1: materialise the default LBPolicy on POST. Empty means
	// "give me the default round_robin" (§5.1). updateRoute uses a
	// different rule (preserve previous), hence the per-handler
	// normalisation here.
	if req.LBPolicy == "" {
		req.LBPolicy = storage.LBPolicyRoundRobin
	}
	if err := validateLBPolicy(req.LBPolicy); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	if err := validateAliasesStructural(req.Host, req.Aliases); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// Step K.1: AuthMode default + validation. Empty on POST is
	// normalised to "none" (no per-route auth — the most permissive
	// default, operator opts in to basic / forward_auth explicitly).
	if req.AuthMode == "" {
		req.AuthMode = storage.RouteAuthNone
	}
	if err := validateAuthMode(req.AuthMode); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// Step K.1: per-mode validation + cross-field mutual-exclusion
	// check (§1.3 decision 2). The wire shape allows the operator
	// to populate BasicAuth + ForwardAuth simultaneously by hand-
	// crafted JSON — we reject that even if the AuthMode picks
	// just one of the two, so direct API clients can't smuggle a
	// confused row past the radio-group UI.
	if err := validateAuthFieldsMutex(req); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if req.AuthMode == storage.RouteAuthBasic {
		if err := validateBasicAuth(req, ""); err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.AuthMode == storage.RouteAuthForwardAuth {
		if err := h.validateForwardAuthProvider(r.Context(), req.ForwardAuth.ProviderName); err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := validateHeaders(req.RequestHeaders, "request"); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if err := validateHeaders(req.ResponseHeaders, "response"); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// Step I.4: WAF mode default — POST with empty wafMode means
	// "give me the safe-shadow default" (spec L6). updateRoute
	// applies a different rule (preserve previous), hence the
	// per-handler normalization rather than a centralized one.
	if req.WAFMode == "" {
		req.WAFMode = "detect"
	}
	if err := validateWAFMode(req.WAFMode); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// Step J.4: ACMEChallenge default + validation. Empty string is
	// normalised to "http-01" (the default and the pre-J.4
	// behaviour). validateACMEChallenge then enforces the enum +
	// the "wildcard ⇒ dns-01" cross-rule. The dns-01-requires-a-
	// configured-provider rule needs the store and lives below.
	if req.ACMEChallenge == "" {
		req.ACMEChallenge = storage.ACMEChallengeHTTP01
	}
	// Step O.3: managed-domain coverage reconciliation (spec D1.B
	// + D8.A). Rewrite to "inherited" when the host is covered
	// and the operator didn't opt out; reject when the operator
	// opted out but no managed domain covers the host. The
	// reconciled value flows through validateACMEChallenge
	// (which now accepts "inherited") + the storage write.
	mds, mdErr := h.store.ListManagedDomains(r.Context())
	if mdErr != nil {
		h.logger.Error("list managed domains (route create)", "err", mdErr)
		writeError(w, http.StatusInternalServerError, "failed to load managed domains")
		return
	}
	reconciled, err := reconcileManagedDomainCoverage(req.ACMEChallenge, req.UseDedicatedCert, req.Host, req.Aliases, mds)
	if err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	req.ACMEChallenge = reconciled
	if err := validateACMEChallenge(req.ACMEChallenge, req.Host, req.Aliases); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if req.ACMEChallenge == storage.ACMEChallengeDNS01 {
		configured, err := h.anyDNSProviderConfigured(r.Context())
		if err != nil {
			h.logger.Error("read dns provider", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify dns provider")
			return
		}
		if !configured {
			writeError(w, http.StatusBadRequest,
				"acmeChallenge \"dns-01\" requires a configured DNS provider — see Settings")
			return
		}
	}

	// Step J.2: materialise health-check defaults + uppercase
	// Method, then validate (gated on Enabled). The "block absent
	// vs present" distinction (the *healthCheckReq pointer) is the
	// load-bearing detail of the J.2 wire: nil = no HC block on
	// the request = no probe runs (createRoute treats as
	// zero-value disabled). When non-nil with Enabled=true, the
	// caller meant a real probe — materialise the five defaults
	// (uri is not defaultable) and validate.
	if req.HealthCheck != nil && req.HealthCheck.Enabled {
		hc := materialiseHealthCheck(*req.HealthCheck)
		if err := validateHealthCheck(hc); err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
		req.HealthCheck = &hc
	}

	// Step I.7 hotfix (Finding #5): RedirectToHTTPS is meaningless
	// without TLS. Normalize to false when TLS is off so the stored
	// row never carries a latent redirect that would silently
	// activate if the admin later flips TLS on. Backend is the
	// source of truth — this also covers direct API clients that
	// bypass the frontend, and naturally heals legacy routes the
	// next time they are updated (no separate migration needed).
	if !req.TLSEnabled {
		req.RedirectToHTTPS = false
	}

	// Step W — per-route country-block. nil = "block absent from
	// JSON" → zero-value Off (no gate). Non-nil → materialise +
	// validate; the §D2 footgun (allow + empty list) lands here as
	// a 400 with the countryblock.ErrAllowListEmpty message.
	var newCountryBlock countryblock.Config
	if req.CountryBlock != nil {
		cb, err := materialiseCountryBlock(*req.CountryBlock)
		if err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
		// Spec §D2 deny+empty: legal no-op. Surface a Warn so the
		// operator notices their list became inert (e.g. typo cleared
		// the chip input). Not blocking; this is intentional behavior.
		if cb.Mode == countryblock.ModeDeny && len(cb.CountryList) == 0 && len(cb.Continents) == 0 && len(cb.ASNs) == 0 {
			h.logger.Warn("country-block: deny mode with empty country, continent and ASN lists — no-op",
				"host", req.Host)
		}
		newCountryBlock = cb
	}

	// Step K.1 (was Step I.5): hash the plaintext password BEFORE
	// the uniqueness check + the storage write. Done outside the
	// bbolt transaction so the ~100 ms argon2id cost doesn't hold
	// the single-writer lock. Only computed when AuthMode is
	// "basic"; "none" and "forward_auth" do not carry a password.
	var basicAuthHash string
	if req.AuthMode == storage.RouteAuthBasic {
		hash, hashErr := auth.HashRoutePassword(req.BasicAuth.Password)
		if hashErr != nil {
			h.logger.Error("hash basic auth password", "err", hashErr)
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		basicAuthHash = hash
	}

	// Uniqueness check across the union of (Host ∪ Aliases) per
	// Step I.3 Q1. Caddy dispatches by host match, so any duplicate
	// hostname across two routes would yield non-deterministic
	// routing — reject at the API layer.
	//
	// NOTE: this is not atomic with the subsequent CreateRoute call —
	// two concurrent POSTs with the same host could both pass this
	// loop. Safe under the homelab single-writer assumption codified
	// in spec §3 Q3; revisit when real concurrency is introduced.
	existing, err := h.store.ListRoutes(r.Context())
	if err != nil {
		h.logger.Error("uniqueness list", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
		return
	}
	owners := collectAllHostsExcept(existing, "")
	// Step J.1: map the wire pool to storage.Upstream verbatim.
	// Defaults (Weight=1, LBPolicy=round_robin) have already been
	// materialised above so the storage row carries explicit values.
	storeUpstreams := make([]storage.Upstream, len(req.Upstreams))
	for i, u := range req.Upstreams {
		storeUpstreams[i] = storage.Upstream{URL: u.URL, Weight: u.Weight}
	}
	// Step J.2: map the optional wire HealthCheck to storage. nil
	// pointer or Enabled=false both produce a zero-value
	// storage.HealthCheck (no probe runs).
	var storeHC storage.HealthCheck
	if req.HealthCheck != nil {
		storeHC = storage.HealthCheck{
			Enabled:      req.HealthCheck.Enabled,
			URI:          req.HealthCheck.URI,
			Method:       req.HealthCheck.Method,
			Interval:     req.HealthCheck.Interval,
			Timeout:      req.HealthCheck.Timeout,
			ExpectStatus: req.HealthCheck.ExpectStatus,
			ExpectBody:   req.HealthCheck.ExpectBody,
			Passes:       req.HealthCheck.Passes,
			Fails:        req.HealthCheck.Fails,
			HostHeader:   req.HealthCheck.HostHeader,
			Headers:      req.HealthCheck.Headers,
		}
	}
	// Step #R-PROXMOX-HTTPS-LOOP commit 1b — InsecureSkipVerify
	// on POST: nil pointer means "use the strict default
	// (false)"; non-nil dereferences the operator's choice.
	// Self-heal: if the operator passes true but the upstream
	// pool is http-only, the flag is meaningless and would
	// silently persist as dead config — coerce to false and
	// warn-log (same shape as RedirectToHTTPS self-heal at
	// routes.go:1273-1275). The PoolUsesHTTPS predicate is
	// the single source of truth (validator guarantees the
	// same-scheme invariant; checking upstreams[0] is enough).
	skipVerify := false
	if req.InsecureSkipVerify != nil {
		skipVerify = *req.InsecureSkipVerify
	}
	tempForSchemeCheck := storage.Route{Upstreams: storeUpstreams}
	if skipVerify && !tempForSchemeCheck.PoolUsesHTTPS() {
		h.logger.Warn("insecure_skip_verify ignored on http-only upstream pool; normalising to false",
			"host", req.Host)
		skipVerify = false
	}
	// v2.60 — UpstreamTLSServerName on POST, same shape: absent means
	// "Caddy's default", and a name on an http-only pool is dead
	// config (no transport.tls block is emitted) so it is normalised
	// away with a warning rather than stored where nothing reads it.
	tlsServerName := ""
	if req.UpstreamTLSServerName != nil {
		tlsServerName = strings.TrimSpace(*req.UpstreamTLSServerName)
	}
	if tlsServerName != "" && !tempForSchemeCheck.PoolUsesHTTPS() {
		h.logger.Warn("upstream_tls_server_name ignored on http-only upstream pool; normalising to empty",
			"host", req.Host)
		tlsServerName = ""
	}
	if err := storage.ValidateUpstreamTLSServerName(tlsServerName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Phase 4.5 — UploadStreamingMode on POST: default false,
	// nil-pointer accepted (no preserve-on-omit semantics on
	// create — there's no previous value), non-nil overrides.
	streamingMode := false
	if req.UploadStreamingMode != nil {
		streamingMode = *req.UploadStreamingMode
	}
	// Step X.1 — WAFDisableCRS on POST: same default-false +
	// non-nil-overrides shape as UploadStreamingMode above.
	disableCRS := false
	if req.WAFDisableCRS != nil {
		disableCRS = *req.WAFDisableCRS
	}
	// Step X Option (c) — WAFExcludeRules on POST: nil pointer
	// defaults to no exclusions ; a supplied slice is sanitised
	// (validated, deduped, sorted) by normalizeExcludeRules.
	// Validation errors surface as 400 here so the create
	// rejects malformed rule IDs before the route lands in
	// storage. Same shape as the countryBlock validation path.
	var excludeRules []int
	if req.WAFExcludeRules != nil {
		normalised, validationErr := normalizeExcludeRules(*req.WAFExcludeRules)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		excludeRules = normalised
	}
	// Step X Option (e) — WAFExcludeTags on POST : mirror of the
	// WAFExcludeRules wiring above. nil pointer → no tag
	// exclusions (pre-X(e) byte-equivalent), supplied slice
	// canonicalised via normalizeExcludeTags (lowercase, dedupe,
	// sort, length + count caps, reject characters that would
	// smuggle ctl: actions into the SecAction directive).
	var excludeTags []string
	if req.WAFExcludeTags != nil {
		normalised, validationErr := normalizeExcludeTags(*req.WAFExcludeTags)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		excludeTags = normalised
	}
	var targeted []storage.WAFTargetedExclusion
	if req.WAFTargetedExclusions != nil {
		normalised, validationErr := normalizeTargetedExclusions(*req.WAFTargetedExclusions)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		targeted = normalised
	}
	var customRules []storage.WAFCustomRule
	if req.WAFCustomRules != nil {
		normalised, validationErr := normalizeCustomRules(*req.WAFCustomRules, nil)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		customRules = normalised
	}
	var secLang string
	if req.WAFSecLang != nil {
		normalised, validationErr := normalizeSecLang(*req.WAFSecLang)
		if validationErr != nil {
			writeSecLangError(w, validationErr)
			return
		}
		secLang = normalised
	}
	// Step Q (2026-06-18) — RateLimit on POST : nil pointer
	// = no rate limit (pre-Q byte-equivalent) ; non-nil
	// supplied → validated by materialiseRateLimit which
	// rejects with 400 on bad Events / Window.
	//
	// v2.9.13 Phase Q.2 — ClearRateLimit=true on POST is a
	// no-op-but-valid request: the route is created with
	// RateLimit=nil regardless of what's in req.RateLimit.
	// Accepted (rather than 400'd) for symmetry with the PUT
	// path; a tooling client that always sends clearRateLimit
	// alongside its updates should also work on create.
	var rateLimit *storage.RouteRateLimit
	if req.ClearRateLimit {
		rateLimit = nil
	} else {
		var validationErr error
		rateLimit, validationErr = materialiseRateLimit(req.RateLimit)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
	}
	// Per-path upstream routing: validate each path-rule's OWN upstream
	// pool (URL syntax + LB enum + enabled-HC contents) the same way the
	// route-level pool is validated above — storage.PathRule.Validate()
	// deliberately skips URL syntax and HealthCheck contents (see
	// validatePathRuleUpstreams doc-comment), so the API is the only line
	// of defence against a malformed path-rule upstream reaching Caddy.
	if err := validatePathRuleUpstreams(req.PathRules); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// v1 path-based-rules: nil-safe mapper, hashes each path-rule's
	// plain BasicAuth.Password server-side via auth.HashRoutePassword
	// (same fix as the route-level basicAuthHash above). No
	// "existing" route on create, so there is nothing to preserve a
	// path-rule password hash against.
	pathRules, pathRulesErr := mapPathRuleReqs(req.PathRules, nil)
	if pathRulesErr != nil {
		// Operator input gets a 400 carrying the reason; only a genuine
		// server failure (a password that would not hash) is a 500.
		if errors.Is(pathRulesErr, errPathRuleInvalid) {
			writeError(w, http.StatusBadRequest, pathRulesErr.Error())
			return
		}
		h.logger.Error("hash path-rule basic auth password", "err", pathRulesErr)
		writeError(w, http.StatusInternalServerError, "failed to hash path-rule password")
		return
	}
	newRoute := storage.Route{
		Host:              req.Host,
		Upstreams:         storeUpstreams,
		LBPolicy:          req.LBPolicy,
		TLSEnabled:        req.TLSEnabled,
		RedirectToHTTPS:   req.RedirectToHTTPS,
		Disabled:          req.Disabled != nil && *req.Disabled,
		MaintenanceConfig: req.MaintenanceConfig,
		RedirectConfig:    req.RedirectConfig,
		CertSource:        req.CertSource,
		CertID:            req.CertID,
		Aliases:           req.Aliases,
		AuthMode:          req.AuthMode,
		BasicAuth: storage.BasicAuthRouteConfig{
			Username:     req.BasicAuth.Username,
			PasswordHash: basicAuthHash,
		},
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: req.ForwardAuth.ProviderName,
		},
		RequestHeaders:        req.RequestHeaders,
		ResponseHeaders:       req.ResponseHeaders,
		WAFMode:               req.WAFMode,
		ACMEChallenge:         req.ACMEChallenge,
		UseDedicatedCert:      req.UseDedicatedCert,
		HealthCheck:           storeHC,
		CountryBlock:          newCountryBlock,
		InsecureSkipVerify:    skipVerify,
		UpstreamTLSServerName: tlsServerName,
		UploadStreamingMode:   streamingMode,
		WAFDisableCRS:         disableCRS,
		WAFExcludeRules:       excludeRules,
		WAFExcludeTags:        excludeTags,
		WAFTargetedExclusions: targeted,
		WAFCustomRules:        customRules,
		WAFSecLang:            secLang,
		RateLimit:             rateLimit,
		// Step R — error-page wiring. Both fields are
		// pass-through ; storage.validate() enforces the
		// supported-code allowlist + 1 MiB body cap.
		ErrorPageTemplateID: req.ErrorPageTemplateID,
		ErrorPageOverrides:  req.ErrorPageOverrides,
		// v1 path-based-rules: nil-safe mappers. No "existing"
		// route on create, so there is nothing to preserve a
		// path-rule password hash against.
		IPFilter:  mapIPFilterReq(req.IPFilter),
		PathRules: pathRules,
	}
	// v2.19.0 manual-cert cross-check: a route pinned to an uploaded
	// external cert must reference an existing cert whose SANs cover
	// the host. Rejected with a 400 before the storage write.
	if verr := h.validateManualCertRef(r.Context(), &newRoute); verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}
	// Step K.1: when AuthMode != "basic" / "forward_auth", clear
	// the corresponding sub-struct (storage trusts the API to
	// not persist orphan credentials).
	if newRoute.AuthMode != storage.RouteAuthBasic {
		newRoute.BasicAuth = storage.BasicAuthRouteConfig{}
	}
	if newRoute.AuthMode != storage.RouteAuthForwardAuth {
		newRoute.ForwardAuth = storage.ForwardAuthRouteConfig{}
	}
	for _, h := range newRoute.AllHosts() {
		if ownerID, taken := owners[h]; taken {
			writeError(w, http.StatusConflict, fmt.Sprintf("hostname %q already configured on route %s", h, ownerID))
			return
		}
	}

	// v2.46 — validate before storing, as the update path already
	// does (routes.go ValidateRoute above). Without this a refusal from
	// the storage validator surfaced as a 500 "failed to create route",
	// so an operator creating a route with, say, a self-referencing
	// redirect was told nothing about what was wrong. The same refusal
	// on an edit of that route explained itself.
	if err := storage.ValidateRoute(newRoute); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	created, err := h.store.CreateRoute(r.Context(), newRoute)
	if err != nil {
		h.logger.Error("create route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to create route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after create — rolling back", "err", err, "id", created.ID)
		if delErr := h.store.DeleteRoute(r.Context(), created.ID); delErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", delErr, "id", created.ID)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_created audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). On reload failure the early return above skips
	// this emission.
	//
	// Step I.5 / F1: the storage.Route now carries
	// BasicAuthPasswordHash, an argon2id PHC string that must NEVER
	// reach the audit log (D3 / spec §1.6 #3). routeForAudit clones
	// the route with that field blanked before mustMarshalForAudit
	// serializes it.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteCreated,
		TargetType: "route",
		TargetID:   created.ID,
		AfterJSON:  mustMarshalForAudit(routeForAudit(created)),
	})

	// Step O.3: enrich the response with the derived
	// effectiveCertSource (AC #4). `mds` was fetched earlier in
	// the handler for the reconcile pass — reuse it rather than
	// re-querying.
	resp := toResponse(created)
	resp.EffectiveCertSource = computeEffectiveCertSource(created, mds)
	// v2.35 — post-apply check. A creation is never undone (the
	// service is often started after its route): report only.
	checkCtx, cancelCheck := detachedCheckContext(r.Context())
	defer cancelCheck()
	check := h.checkRoute(checkCtx, created)
	resp.Check = &check
	writeJSON(w, http.StatusCreated, resp)
}

func (h *Handler) updateRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	var req routeRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		// Surface the decoder's reason (see createRoute for
		// rationale; #R-API-PUT-ROUTE-GENERIC-400 sweep).
		writeError(w, http.StatusBadRequest, translateDecodeError(err))
		return
	}
	if err := validateHost(req.Host); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// Step J.1: materialise the per-Upstream default Weight=1 before
	// pool validation. Same rule as createRoute (storage validate()
	// rejects weight < 1).
	for i := range req.Upstreams {
		if req.Upstreams[i].Weight == 0 {
			req.Upstreams[i].Weight = 1
		}
	}
	// A redirecting route proxies nothing: an empty pool is valid for it.
	// See validateUpstreamPoolAllowingEmpty.
	if err := validateUpstreamPoolAllowingEmpty(req.Upstreams, req.RedirectConfig != nil); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if err := validateAliasesStructural(req.Host, req.Aliases); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for update", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	// Step K.1: AuthMode resolution on PUT — same preserve-
	// previous semantics as WAFMode below. Empty means "keep the
	// stored value", explicit value goes through validateAuthMode.
	// A row persisted without AuthMode (a row a code path bypassed
	// the migration on, e.g. test seeds calling storage.CreateRoute
	// directly) reads back as previous.AuthMode == "" — treat as
	// "none" so the preserve path yields a valid state.
	if req.AuthMode == "" {
		req.AuthMode = previous.AuthMode
		if req.AuthMode == "" {
			req.AuthMode = storage.RouteAuthNone
		}
	}
	if err := validateAuthMode(req.AuthMode); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if err := validateAuthFieldsMutex(req); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// Step K.1: per-mode validation. For "basic", validateBasicAuth
	// takes the previous hash into account so toggling-on a route
	// that already has a hash works without re-typing the password
	// (Step I.5 preserve UX preserved through K.1).
	if req.AuthMode == storage.RouteAuthBasic {
		if err := validateBasicAuth(req, previous.BasicAuth.PasswordHash); err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
	}
	if req.AuthMode == storage.RouteAuthForwardAuth {
		if err := h.validateForwardAuthProvider(r.Context(), req.ForwardAuth.ProviderName); err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
	}
	if err := validateHeaders(req.RequestHeaders, "request"); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if err := validateHeaders(req.ResponseHeaders, "response"); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// Step J.1: LBPolicy resolution on PUT — same preserve-previous
	// semantics as WAFMode below. Empty means "keep the stored
	// value", explicit value goes through validateLBPolicy. A row
	// persisted without LBPolicy is a programming-error case (pool
	// migration guarantees it) but we recover to "round_robin" to
	// avoid a 500 if it ever happens.
	if req.LBPolicy == "" {
		req.LBPolicy = previous.LBPolicy
		if req.LBPolicy == "" {
			req.LBPolicy = storage.LBPolicyRoundRobin
		}
	}
	if err := validateLBPolicy(req.LBPolicy); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// Step I.4: WAF mode resolution on PUT (Q6 override). Empty
	// wafMode means "preserve the previously stored value", mirroring
	// the I.5 password preserve UX — admins can flip unrelated
	// fields without re-stating the WAF mode. Explicit value still
	// goes through validateWAFMode to catch typos.
	//
	// Edge case: a route that was persisted without WAFMode (a row
	// that should have been touched by the boot migration but was
	// created by a code path that bypassed it — typically test seed
	// fixtures using storage.CreateRoute directly) reads back as
	// previous.WAFMode == "". Treat that as "off" so the preserve
	// path produces a valid state, equivalent to the L7 mapping
	// (WAFEnabled=false → off).
	if req.WAFMode == "" {
		req.WAFMode = previous.WAFMode
		if req.WAFMode == "" {
			req.WAFMode = "off"
		}
	}
	if err := validateWAFMode(req.WAFMode); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	// Step J.4: ACMEChallenge — same default + validation as on
	// POST. The field carries no secret and the per-route ACME
	// choice is naturally specified on every edit, so we don't use
	// the wafMode-style preserve-previous-on-empty rule; an empty
	// value on PUT means "default", and a pre-J.4 stored row
	// (zero value "") also reads back through toResponse as
	// "http-01" so the frontend submits an explicit value on every
	// round-trip.
	if req.ACMEChallenge == "" {
		req.ACMEChallenge = storage.ACMEChallengeHTTP01
	}
	// Step O.3: managed-domain coverage reconciliation. Same
	// rules as createRoute — see reconcileManagedDomainCoverage
	// for the four-state matrix. The reconciled ACMEChallenge
	// flows through the rest of the handler verbatim, including
	// the storage write below.
	mds, mdErr := h.store.ListManagedDomains(r.Context())
	if mdErr != nil {
		h.logger.Error("list managed domains (route update)", "err", mdErr)
		writeError(w, http.StatusInternalServerError, "failed to load managed domains")
		return
	}
	reconciled, err := reconcileManagedDomainCoverage(req.ACMEChallenge, req.UseDedicatedCert, req.Host, req.Aliases, mds)
	if err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	req.ACMEChallenge = reconciled
	if err := validateACMEChallenge(req.ACMEChallenge, req.Host, req.Aliases); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	if req.ACMEChallenge == storage.ACMEChallengeDNS01 {
		configured, err := h.anyDNSProviderConfigured(r.Context())
		if err != nil {
			h.logger.Error("read dns provider (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify dns provider")
			return
		}
		if !configured {
			writeError(w, http.StatusBadRequest,
				"acmeChallenge \"dns-01\" requires a configured DNS provider — see Settings")
			return
		}
	}

	// Step J.2: HealthCheck resolution on PUT — preserve-or-replace,
	// driven by the wire's nil-vs-present distinction (see
	// healthCheckReq doc-comment on routeRequest).
	//
	//   - req.HealthCheck == nil (block absent from PUT) → preserve
	//     the previously stored HealthCheck verbatim. Matches the
	//     Step I.5 BasicAuth password-blank-preserves-hash pattern
	//     and the Step I.4 WAFMode empty-preserves-mode pattern.
	//     The previous HealthCheck is already validated (storage
	//     accepted it at the original write); no need to
	//     re-materialise or re-validate. Copied straight into
	//     storeHC below at the assembly site.
	//
	//   - req.HealthCheck != nil (block present, any value) → full
	//     replacement (decision #4). When Enabled is true,
	//     materialise the five defaults + uppercase Method then
	//     validate; the stored row carries the explicit values.
	//     When Enabled is false the rest of the block is inert and
	//     the storage row carries a zero HealthCheck (disabled).
	//
	// J.3 form must ship one or the other — never a partial block.
	// See docs/backlog-step-j.md "J.3 frontend — health-check is
	// preserve-or-replace, never partial".
	if req.HealthCheck != nil && req.HealthCheck.Enabled {
		hc := materialiseHealthCheck(*req.HealthCheck)
		if err := validateHealthCheck(hc); err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
		req.HealthCheck = &hc
	}

	// Step I.7 hotfix (Finding #5): RedirectToHTTPS is meaningless
	// without TLS — normalize on PUT too so a route losing its TLS
	// also loses its redirect. Also self-heals legacy rows that
	// were persisted with redirect=true + tls=false before the fix
	// landed (no separate migration needed: any update to such a
	// row clears the latent flag).
	if !req.TLSEnabled {
		req.RedirectToHTTPS = false
	}

	// Step W — per-route country-block on PUT. Same preserve-or-
	// replace semantics as HealthCheck above (driven by the
	// nil-vs-present distinction on the wire pointer):
	//   - nil ptr   → preserve previous stored CountryBlock verbatim.
	//                 Operators editing unrelated fields don't need
	//                 to restate the country list every time.
	//   - non-nil   → full replacement; materialise + validate.
	//                 Empty Mode normalises to "off" (clears the gate).
	var newCountryBlock countryblock.Config
	if req.CountryBlock == nil {
		newCountryBlock = previous.CountryBlock
	} else {
		cb, err := materialiseCountryBlock(*req.CountryBlock)
		if err != nil {
			writeErrorFrom(w, http.StatusBadRequest, err)
			return
		}
		if cb.Mode == countryblock.ModeDeny && len(cb.CountryList) == 0 && len(cb.Continents) == 0 && len(cb.ASNs) == 0 {
			h.logger.Warn("country-block: deny mode with empty country, continent and ASN lists — no-op",
				"host", req.Host, "id", id)
		}
		newCountryBlock = cb
	}

	// v1 path-based-rules Important-finding fix — per-route
	// whole-domain IPFilter on PUT. Same preserve-or-replace
	// semantics as CountryBlock above (driven by the nil-vs-
	// present distinction on the wire pointer):
	//   - nil ptr   → preserve previous stored IPFilter verbatim.
	//                 Operators editing unrelated fields don't
	//                 need to restate the CIDR list every time.
	//   - non-nil   → full replacement via mapIPFilterReq.
	newIPFilter := previous.IPFilter
	if req.IPFilter != nil {
		newIPFilter = mapIPFilterReq(req.IPFilter)
	}

	// Step K.1 password resolution (refactor of the Step I.5 Q5
	// rule under the new AuthMode enum):
	//   - AuthMode != "basic"            → no hash stored, fields cleared.
	//   - new password supplied          → re-hash, replacing whatever
	//                                      was there before (rotation).
	//   - empty password on PUT (basic)  → keep the existing hash. The
	//                                      "edit anything else without
	//                                      re-typing the secret" path.
	var basicAuthHash string
	switch {
	case req.AuthMode != storage.RouteAuthBasic:
		basicAuthHash = ""
	case req.BasicAuth.Password != "":
		hash, hashErr := auth.HashRoutePassword(req.BasicAuth.Password)
		if hashErr != nil {
			h.logger.Error("hash basic auth password (update)", "err", hashErr)
			writeError(w, http.StatusInternalServerError, "failed to hash password")
			return
		}
		basicAuthHash = hash
	default:
		basicAuthHash = previous.BasicAuth.PasswordHash
	}

	// Uniqueness check across (Host ∪ Aliases) when ANY hostname has
	// changed since the stored copy (Step I.3 Q1). The pre-Step-I.3
	// optimization that compared only Host is no longer sufficient —
	// adding a new alias must still trigger the cross-route check.
	// Step J.1: map the wire pool to storage.Upstream verbatim, same
	// as createRoute.
	storeUpstreams := make([]storage.Upstream, len(req.Upstreams))
	for i, u := range req.Upstreams {
		storeUpstreams[i] = storage.Upstream{URL: u.URL, Weight: u.Weight}
	}
	// Step J.2: map the HealthCheck to storage.
	//   - req.HealthCheck == nil  → preserve previous verbatim
	//     (no re-materialise, no re-validate; previous is already
	//     valid by construction).
	//   - req.HealthCheck != nil  → full replacement, mapped from
	//     the materialised+validated value built above.
	var storeHC storage.HealthCheck
	if req.HealthCheck == nil {
		storeHC = previous.HealthCheck
	} else {
		storeHC = storage.HealthCheck{
			Enabled:      req.HealthCheck.Enabled,
			URI:          req.HealthCheck.URI,
			Method:       req.HealthCheck.Method,
			Interval:     req.HealthCheck.Interval,
			Timeout:      req.HealthCheck.Timeout,
			ExpectStatus: req.HealthCheck.ExpectStatus,
			ExpectBody:   req.HealthCheck.ExpectBody,
			Passes:       req.HealthCheck.Passes,
			Fails:        req.HealthCheck.Fails,
			HostHeader:   req.HealthCheck.HostHeader,
			Headers:      req.HealthCheck.Headers,
		}
	}
	// Step #R-PROXMOX-HTTPS-LOOP commit 1b — InsecureSkipVerify
	// on PUT: nil pointer preserves the previously stored
	// value (same UX as HealthCheck / CountryBlock above);
	// non-nil pointer is a full replacement.
	// Self-heal on http-only pools (mirror of createRoute).
	skipVerify := previous.InsecureSkipVerify
	if req.InsecureSkipVerify != nil {
		skipVerify = *req.InsecureSkipVerify
	}
	tempForSchemeCheck := storage.Route{Upstreams: storeUpstreams}
	if skipVerify && !tempForSchemeCheck.PoolUsesHTTPS() {
		h.logger.Warn("insecure_skip_verify ignored on http-only upstream pool; normalising to false",
			"id", id, "host", req.Host)
		skipVerify = false
	}
	// v2.60 — UpstreamTLSServerName on PUT: nil preserves, non-nil
	// replaces (an explicit "" is how an operator removes one), and
	// the http-only self-heal mirrors createRoute.
	tlsServerName := previous.UpstreamTLSServerName
	if req.UpstreamTLSServerName != nil {
		tlsServerName = strings.TrimSpace(*req.UpstreamTLSServerName)
	}
	if tlsServerName != "" && !tempForSchemeCheck.PoolUsesHTTPS() {
		h.logger.Warn("upstream_tls_server_name ignored on http-only upstream pool; normalising to empty",
			"id", id, "host", req.Host)
		tlsServerName = ""
	}
	if err := storage.ValidateUpstreamTLSServerName(tlsServerName); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Phase 4.5 — UploadStreamingMode on PUT: nil pointer
	// preserves the previously stored value (same shape as
	// InsecureSkipVerify above); non-nil pointer is a full
	// replacement.
	streamingMode := previous.UploadStreamingMode
	if req.UploadStreamingMode != nil {
		streamingMode = *req.UploadStreamingMode
	}
	// Step X.1 — WAFDisableCRS on PUT: same preserve-on-nil +
	// replace-on-non-nil shape as UploadStreamingMode above.
	disableCRS := previous.WAFDisableCRS
	if req.WAFDisableCRS != nil {
		disableCRS = *req.WAFDisableCRS
	}
	// Step X Option (c) — WAFExcludeRules on PUT: nil pointer
	// preserves the previously stored slice ; a non-nil
	// pointer (including an empty slice) is a full
	// replacement. Empty slice clears every exclusion. The
	// supplied slice is sanitised via normalizeExcludeRules
	// just like the POST path.
	excludeRules := previous.WAFExcludeRules
	if req.WAFExcludeRules != nil {
		normalised, validationErr := normalizeExcludeRules(*req.WAFExcludeRules)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		excludeRules = normalised
	}
	// Step X Option (e) — WAFExcludeTags on PUT: same preserve-
	// on-nil + replace-on-non-nil contract as WAFExcludeRules
	// above. Empty supplied slice → clear all tag exclusions.
	excludeTags := previous.WAFExcludeTags
	if req.WAFExcludeTags != nil {
		normalised, validationErr := normalizeExcludeTags(*req.WAFExcludeTags)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		excludeTags = normalised
	}
	// v2.36 — WAFTargetedExclusions on PUT: preserve on nil,
	// replace (validated) otherwise.
	targeted := previous.WAFTargetedExclusions
	if req.WAFTargetedExclusions != nil {
		normalised, validationErr := normalizeTargetedExclusions(*req.WAFTargetedExclusions)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		targeted = normalised
	}
	// v2.37 — WAFCustomRules on PUT: preserve on nil, replace
	// (validated, IDs kept or allocated) otherwise.
	customRules := previous.WAFCustomRules
	if req.WAFCustomRules != nil {
		normalised, validationErr := normalizeCustomRules(*req.WAFCustomRules, previous.WAFCustomRules)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		customRules = normalised
	}
	// v2.39 — Disabled / MaintenanceConfig on PUT: preserve when the
	// field is omitted. The UI always ships them; a script sending a
	// partial PUT used to re-enable a disabled route and take one out
	// of maintenance. The dedicated /disable, /enable, /maintenance and
	// /maintenance/off endpoints stay the primary toggles.
	disabled := previous.Disabled
	if req.Disabled != nil {
		disabled = *req.Disabled
	}
	maintenance := previous.MaintenanceConfig
	if req.MaintenanceConfig != nil {
		maintenance = req.MaintenanceConfig
	}
	// The three states are exclusive (routeState): a route explicitly
	// enabled in this PUT leaves maintenance unless the request also
	// carries a maintenance block.
	if req.Disabled != nil && !*req.Disabled && req.MaintenanceConfig == nil {
		maintenance = nil
	}
	// v2.44 — RedirectConfig on PUT, same preserve-or-replace shape
	// as maintenance above.
	redirect := previous.RedirectConfig
	if req.RedirectConfig != nil {
		redirect = req.RedirectConfig
	}
	if req.Disabled != nil && !*req.Disabled && req.RedirectConfig == nil {
		redirect = nil
	}
	// The two replacement states are exclusive: a PUT that sets one
	// clears the other. Without this, a route moved from maintenance
	// to redirect would carry both and storage.Route.Validate would
	// refuse a change the operator made correctly in the form.
	if req.MaintenanceConfig != nil {
		redirect = nil
	}
	if req.RedirectConfig != nil {
		maintenance = nil
	}

	// v2.38 — WAFSecLang on PUT: preserve on nil, replace (checked)
	// otherwise.
	secLang := previous.WAFSecLang
	if req.WAFSecLang != nil {
		normalised, validationErr := normalizeSecLang(*req.WAFSecLang)
		if validationErr != nil {
			writeSecLangError(w, validationErr)
			return
		}
		secLang = normalised
	}
	// Step Q (2026-06-18) — RateLimit on PUT.
	// v2.9.13 Phase Q.2 — clearRateLimit sentinel shipped.
	//
	// Semantic matrix:
	//   ClearRateLimit | RateLimit body | Result
	//   ---------------|----------------|----------
	//   false (default)| absent         | preserve previous (legacy)
	//   false          | present        | replace with body (legacy)
	//   true           | absent         | clear (set to nil) — NEW
	//   true           | present        | clear (sentinel wins) — NEW
	//
	// Pre-v2.9.13 there was no wire-level way to surface the
	// operator's "remove this rate-limit" intent — the UI toggle
	// OFF appeared to succeed but the underlying state persisted
	// (operator-reported 2026-06-26 against the proxmox route).
	// The sentinel closes that footgun without breaking any
	// existing client (defaults to false → legacy semantic).
	rateLimit := previous.RateLimit
	if req.ClearRateLimit {
		// Sentinel wins — any req.RateLimit body is intentionally
		// ignored. Validation of the body is also skipped: the
		// operator's intent was clear, not replace.
		rateLimit = nil
	} else if req.RateLimit != nil {
		next, validationErr := materialiseRateLimit(req.RateLimit)
		if validationErr != nil {
			writeError(w, http.StatusBadRequest, validationErr.Error())
			return
		}
		rateLimit = next
	}
	// Per-path upstream routing: same defence-in-depth validation as
	// createRoute — see validatePathRuleUpstreams doc-comment for why
	// storage.PathRule.Validate() alone is not sufficient.
	if err := validatePathRuleUpstreams(req.PathRules); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}
	// v1 path-based-rules: hashes each path-rule's plain
	// BasicAuth.Password server-side via auth.HashRoutePassword (same
	// fix as the route-level basicAuthHash above). Preserves the
	// previously stored hash for a given PathPrefix when the wire
	// value omits a password — see mapPathRuleReqs doc-comment.
	pathRules, pathRulesErr := mapPathRuleReqs(req.PathRules, previous.PathRules)
	if pathRulesErr != nil {
		// Operator input gets a 400 carrying the reason; only a genuine
		// server failure (a password that would not hash) is a 500.
		if errors.Is(pathRulesErr, errPathRuleInvalid) {
			writeError(w, http.StatusBadRequest, pathRulesErr.Error())
			return
		}
		h.logger.Error("hash path-rule basic auth password", "err", pathRulesErr)
		writeError(w, http.StatusInternalServerError, "failed to hash path-rule password")
		return
	}
	newRoute := storage.Route{
		ID:                id,
		Host:              req.Host,
		Upstreams:         storeUpstreams,
		LBPolicy:          req.LBPolicy,
		TLSEnabled:        req.TLSEnabled,
		RedirectToHTTPS:   req.RedirectToHTTPS,
		Disabled:          disabled,
		MaintenanceConfig: maintenance,
		RedirectConfig:    redirect,
		CertSource:        req.CertSource,
		CertID:            req.CertID,
		Aliases:           req.Aliases,
		AuthMode:          req.AuthMode,
		BasicAuth: storage.BasicAuthRouteConfig{
			Username:     req.BasicAuth.Username,
			PasswordHash: basicAuthHash,
		},
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: req.ForwardAuth.ProviderName,
		},
		RequestHeaders:        req.RequestHeaders,
		ResponseHeaders:       req.ResponseHeaders,
		WAFMode:               req.WAFMode,
		ACMEChallenge:         req.ACMEChallenge,
		UseDedicatedCert:      req.UseDedicatedCert,
		HealthCheck:           storeHC,
		CountryBlock:          newCountryBlock,
		InsecureSkipVerify:    skipVerify,
		UpstreamTLSServerName: tlsServerName,
		UploadStreamingMode:   streamingMode,
		WAFDisableCRS:         disableCRS,
		WAFExcludeRules:       excludeRules,
		WAFExcludeTags:        excludeTags,
		WAFTargetedExclusions: targeted,
		WAFCustomRules:        customRules,
		WAFSecLang:            secLang,
		RateLimit:             rateLimit,
		// Step R — error-page wiring (update path mirrors
		// create). Pass-through both fields ; storage.validate()
		// rejects unsupported codes + oversized bodies.
		ErrorPageTemplateID: req.ErrorPageTemplateID,
		ErrorPageOverrides:  req.ErrorPageOverrides,
		// v1 path-based-rules Important-finding fix: IPFilter on PUT
		// follows the exact same preserve-or-replace contract as
		// CountryBlock / HealthCheck above (driven by the nil-vs-
		// present distinction on the wire pointer):
		//   - nil ptr   → preserve previous stored IPFilter verbatim.
		//                 Operators editing unrelated fields don't
		//                 silently wipe a whole-domain IP allow/deny
		//                 gate.
		//   - non-nil   → full replacement via mapIPFilterReq.
		// PathRules: mapPathRuleReqs preserves each rule's stored
		// password hash when the wire value omits it (see its
		// doc-comment) — same UX as the route-level BasicAuth
		// preserve-on-empty-password pattern above.
		IPFilter:  newIPFilter,
		PathRules: pathRules,
	}
	// v2.19.0 manual-cert cross-check (mirrors createRoute).
	if verr := h.validateManualCertRef(r.Context(), &newRoute); verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}
	if newRoute.AuthMode != storage.RouteAuthBasic {
		newRoute.BasicAuth = storage.BasicAuthRouteConfig{}
	}
	if newRoute.AuthMode != storage.RouteAuthForwardAuth {
		newRoute.ForwardAuth = storage.ForwardAuthRouteConfig{}
	}
	if !hostnamesEqual(newRoute.AllHosts(), previous.AllHosts()) {
		existing, err := h.store.ListRoutes(r.Context())
		if err != nil {
			h.logger.Error("uniqueness list (update)", "err", err)
			writeError(w, http.StatusInternalServerError, "failed to verify uniqueness")
			return
		}
		owners := collectAllHostsExcept(existing, id)
		for _, h := range newRoute.AllHosts() {
			if ownerID, taken := owners[h]; taken {
				writeError(w, http.StatusConflict, fmt.Sprintf("hostname %q already configured on route %s", h, ownerID))
				return
			}
		}
	}

	// Validate BEFORE the store call so a bad-input rejection (e.g. a
	// path-rule with no active protection) surfaces as a 400 with the
	// actual message — mirroring createRoute's pre-store validation.
	// Without this, storage.UpdateRoute's internal validate() failure
	// fell through to the generic 500 branch below (operator-reported:
	// editing a route to leave a dead path-rule — ipFilter mode "off"
	// with a residual CIDR and no basic auth — returned an opaque
	// "failed to update route" 500 instead of an actionable 400).
	if err := storage.ValidateRoute(newRoute); err != nil {
		writeErrorFrom(w, http.StatusBadRequest, err)
		return
	}

	updated, err := h.store.UpdateRoute(r.Context(), newRoute)
	if err != nil {
		h.logger.Error("update route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after update — rolling back", "err", err, "id", id)
		// UpdateRoute is used here (not RestoreRoute) per spec §9: RestoreRoute
		// is reserved for DELETE rollback. Side-effect: UpdatedAt reflects the
		// rollback time, not previous.UpdatedAt. Acceptable under single-writer.
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_updated audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). Step I.5 / F1: strip BasicAuthPasswordHash
	// from both Before and After via routeForAudit — the argon2id PHC
	// is a secret that must never reach the audit log (D3).
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteUpdated,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
	})

	// v2.35 — post-apply check: a change that broke a WORKING route is
	// undone (409); if the previous version fails too, the change stays
	// and the check is reported as a warning.
	checkCtx, cancelCheck := detachedCheckContext(r.Context())
	defer cancelCheck()
	check := h.checkRoute(checkCtx, updated)
	if check.Failed() {
		rolledBack, rbErr := h.rollbackIfItFixes(checkCtx, previous, updated, check)
		if rbErr != nil {
			h.logger.Error("route check: rollback / re-apply failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		if rolledBack {
			h.writeRolledBack(w, r, previous, updated, check)
			return
		}
	}

	// Step O.3: enrich the response with effectiveCertSource
	// (AC #4). `mds` was fetched earlier for the reconcile pass.
	resp := toResponse(updated)
	resp.EffectiveCertSource = computeEffectiveCertSource(updated, mds)
	resp.Check = &check
	writeJSON(w, http.StatusOK, resp)
}

// toggleRouteDisabled is the shared body of the disable/enable
// endpoints. It mirrors updateRoute's reload+rollback+audit contract:
// GetRoute → set Disabled → UpdateRoute → ReloadFromStore → roll back
// on reload failure → appendAudit. Idempotent: setting the same value
// is a no-op success. On /disable it computes lastHttpsRouteAffected.
func (h *Handler) toggleRouteDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	id := chi.URLParam(r, "id")

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for toggle", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	// Compute the hint BEFORE mutation: is this the last active TLS route?
	lastHTTPS := false
	if disabled && previous.TLSEnabled && !previous.Disabled {
		all, lerr := h.store.ListRoutes(r.Context())
		if lerr == nil {
			activeTLS := 0
			for _, rt := range all {
				if rt.TLSEnabled && !rt.Disabled {
					activeTLS++
				}
			}
			lastHTTPS = activeTLS == 1
		}
	}

	next := previous
	next.Disabled = disabled
	// The 3 states (Active / Maintenance / Disabled) are mutually
	// exclusive, so BOTH /disable and /enable establish a non-maintenance
	// state and must clear MaintenanceConfig unconditionally. /disable →
	// Disabled (spec-8). /enable → Active: without clearing, a route that
	// still carries MaintenanceConfig would be derived as 'maintenance'
	// (routeState prioritises MaintenanceConfig once Disabled is false),
	// so /enable would resurrect maintenance instead of going Active. The
	// UI reaches Active-from-maintenance via /maintenance/off, but /enable
	// must be robust to any caller.
	next.MaintenanceConfig = nil
	updated, err := h.store.UpdateRoute(r.Context(), next)
	if err != nil {
		h.logger.Error("toggle route disabled", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after toggle — rolling back", "err", err, "id", id)
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	action := audit.ActionRouteEnabled
	if disabled {
		action = audit.ActionRouteDisabled
	}
	h.appendAudit(r, audit.Event{
		Action:     action,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
	})

	resp := toResponse(updated)
	if !disabled {
		// v2.35 — re-enabling is reported, never undone (like a
		// creation: the backend may come up later).
		checkCtx, cancelCheck := detachedCheckContext(r.Context())
		defer cancelCheck()
		check := h.checkRoute(checkCtx, updated)
		resp.Check = &check
	}
	// Attach the hint on the disable path so the frontend can pre-warn.
	writeJSONWithHint(w, resp, disabled && lastHTTPS)
}

// disableRoute handles POST /routes/{id}/disable. Idempotent: disabling
// an already-disabled route returns 200 without error.
func (h *Handler) disableRoute(w http.ResponseWriter, r *http.Request) {
	h.toggleRouteDisabled(w, r, true)
}

// enableRoute handles POST /routes/{id}/enable. Idempotent: enabling
// an already-enabled route returns 200 without error.
func (h *Handler) enableRoute(w http.ResponseWriter, r *http.Request) {
	h.toggleRouteDisabled(w, r, false)
}

// defaultMaintenanceRetryAfterSeconds is the RetryAfterSeconds applied
// when a route enters maintenance with no prior MaintenanceConfig.
// 300s (5 min) is a conservative default for the 503 Retry-After
// header — long enough to avoid a thundering herd of retries, short
// enough that clients don't need a manual refresh.
const defaultMaintenanceRetryAfterSeconds = 300

// toggleRouteMaintenance is the shared body of the maintenance
// enter/exit endpoints. Mirrors toggleRouteDisabled's contract:
// GetRoute → mutate MaintenanceConfig → UpdateRoute → ReloadFromStore
// → roll back on reload failure → appendAudit. On enter (on=true), an
// existing MaintenanceConfig is preserved as-is (idempotent — calling
// /maintenance again does not reset a previously customised
// RetryAfterSeconds/BypassIPs); absent a prior config, defaults are
// applied (300s retry-after, no bypass IPs). On exit (on=false), the
// config is cleared to nil (clear-on-off) — re-entering maintenance
// later always starts from defaults. Unlike toggleRouteDisabled, this
// does NOT compute a last-HTTPS hint: a route in maintenance stays
// emitted in the Caddy config (it serves a 503 rather than being
// pulled), so its :443 listener is unaffected.
func (h *Handler) toggleRouteMaintenance(w http.ResponseWriter, r *http.Request, on bool) {
	id := chi.URLParam(r, "id")

	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for maintenance toggle", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	next := previous
	if on {
		if previous.MaintenanceConfig != nil {
			next.MaintenanceConfig = previous.MaintenanceConfig
		} else {
			next.MaintenanceConfig = &storage.MaintenanceConfig{RetryAfterSeconds: defaultMaintenanceRetryAfterSeconds}
		}
		// The 3 states are mutually exclusive. Entering maintenance from a
		// disabled route must clear Disabled — otherwise routeState()
		// (Disabled wins over Maintenance) keeps showing it disabled (the
		// maintenance toast lies), and a later /enable resurrects
		// maintenance instead of going Active. Mirror of the /disable side
		// which clears MaintenanceConfig (spec-8).
		next.Disabled = false
	} else {
		next.MaintenanceConfig = nil
	}

	updated, err := h.store.UpdateRoute(r.Context(), next)
	if err != nil {
		h.logger.Error("toggle route maintenance", "err", err, "id", id)
		writeError(w, http.StatusInternalServerError, "failed to update route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after maintenance toggle — rolling back", "err", err, "id", id)
		if _, rbErr := h.store.UpdateRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	action := audit.ActionRouteMaintenanceOff
	if on {
		action = audit.ActionRouteMaintenanceOn
	}
	h.appendAudit(r, audit.Event{
		Action:     action,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
		AfterJSON:  mustMarshalForAudit(routeForAudit(updated)),
	})

	writeJSON(w, http.StatusOK, toResponse(updated))
}

// enterMaintenance handles POST /routes/{id}/maintenance. Idempotent:
// re-entering maintenance on a route already under maintenance
// preserves the existing RetryAfterSeconds/BypassIPs rather than
// resetting to defaults.
func (h *Handler) enterMaintenance(w http.ResponseWriter, r *http.Request) {
	h.toggleRouteMaintenance(w, r, true)
}

// exitMaintenance handles POST /routes/{id}/maintenance/off.
// Idempotent: exiting maintenance on a route not under maintenance
// returns 200 without error. Clear-on-off: the MaintenanceConfig is
// set to nil, so a later /maintenance call starts from defaults.
func (h *Handler) exitMaintenance(w http.ResponseWriter, r *http.Request) {
	h.toggleRouteMaintenance(w, r, false)
}

func (h *Handler) deleteRoute(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	previous, err := h.store.GetRoute(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			writeError(w, http.StatusNotFound, "route not found")
			return
		}
		h.logger.Error("get route for delete", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to load route")
		return
	}

	if err := h.store.DeleteRoute(r.Context(), id); err != nil {
		h.logger.Error("delete route", "err", err)
		writeError(w, http.StatusInternalServerError, "failed to delete route")
		return
	}

	if err := h.caddy.ReloadFromStore(r.Context()); err != nil {
		h.logger.Error("caddy reload after delete — rolling back", "err", err, "id", id)
		if rbErr := h.store.RestoreRoute(r.Context(), previous); rbErr != nil {
			h.logger.Error("rollback failed, DB and Caddy may diverge", "err", rbErr, "id", id)
		}
		writeError(w, http.StatusInternalServerError, "caddy reload failed: "+err.Error())
		return
	}

	// Emit route_deleted audit event AFTER the Caddy reload succeeds
	// (Plan §4.4 / D2). BeforeJSON captures the deleted route's last
	// state; AfterJSON is intentionally nil. Step I.5 / F1: strip
	// BasicAuthPasswordHash via routeForAudit so the deletion record
	// never holds the secret.
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteDeleted,
		TargetType: "route",
		TargetID:   id,
		BeforeJSON: mustMarshalForAudit(routeForAudit(previous)),
	})

	w.WriteHeader(http.StatusNoContent)
}
