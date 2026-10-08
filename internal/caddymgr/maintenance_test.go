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

package caddymgr

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestBuildConfigJSON_MaintenanceRoute is the Task 4 structural gate:
// a route with MaintenanceConfig set must emit a static_response 503
// (with Retry-After + the maintenance body) for everyone except the
// client_ip bypass allow-list.
//
// We deliberately do NOT call caddy.Validate in THIS file: this file
// sorts alphabetically BEFORE manager_test.go (and before
// managed_domain_emission_test.go), so a Validate call here would
// leak Caddy admin-endpoint global state into the alphabetically-
// later TestSyncRegistry_NotCalledOnReloadFailure (manager_test.go)
// and break it — the exact anti-pattern documented at
// managed_domain_emission_test.go:462-478 and manager_test.go:
// 1160-1166. The real caddy.Validate coverage for the maintenance
// shape lives in TestBuildConfigJSON_LoadsCleanly's canonical fixture
// (manager_test.go, route ID "r-maintenance"), which runs safely
// after the sync-registry test in the same file. This file sticks to
// buildConfigJSON + string/structural assertions only.
func TestBuildConfigJSON_MaintenanceRoute(t *testing.T) {
	// NOTE: buildConfigJSON is pure config generation — it emits the
	// arenet_routemetrics handler as a JSON string but never
	// PROVISIONS it, so no metrics.SetRegistry is needed here.
	// Crucially, we must NOT call metrics.SetRegistry: this test
	// sorts alphabetically BEFORE TestSyncRegistry_NotCalledOnReload
	// Failure, which relies on the process-global registry being nil
	// so the arenet_routemetrics Provision fails and its caddy.Load
	// is rejected. Setting the global here would let that Load
	// succeed and break the sync test (a real cross-test poisoning
	// caught during Task 4 implementation).
	routes := []storage.Route{{
		ID: "r1", Host: "maint.example.com", TLSEnabled: true,
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{
			RetryAfterSeconds: 300, BypassIPs: []string{"192.168.1.0/24"},
		},
	}}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	// buildConfigJSON emits via json.MarshalIndent (manager.go:2219),
	// so keys are followed by ": " (space) rather than compact ":".
	// Normalize whitespace before the substring checks so the
	// assertions don't depend on the marshaler's indent style.
	compact := strings.Join(strings.Fields(string(cfgJSON)), "")

	// 1. static_response 503 present.
	if !strings.Contains(compact, `"static_response"`) || !strings.Contains(compact, `"status_code":503`) {
		t.Error("no static_response 503 emitted for maintenance route")
	}
	// 2. Retry-After header present.
	if !strings.Contains(compact, `"Retry-After"`) || !strings.Contains(compact, `"300"`) {
		t.Error("no Retry-After: 300 header emitted")
	}
	// 3. client_ip bypass with the CIDR (NOT remote_ip).
	if !strings.Contains(compact, `"client_ip"`) || !strings.Contains(compact, `192.168.1.0/24`) {
		t.Error("no client_ip bypass with the CIDR")
	}
	if strings.Contains(compact, `"remote_ip"`) {
		t.Error("used remote_ip; want client_ip")
	}
}

// TestBuildConfigJSON_MaintenanceRoute_NoBypass covers the "no bypass
// IPs configured" path: the bypass inner route must be omitted
// entirely (an empty client_ip ranges matcher would be a no-op
// matcher, not "match nobody"), so ALL traffic — including the
// operator's own IP — hits the 503 until BypassIPs is populated.
func TestBuildConfigJSON_MaintenanceRoute_NoBypass(t *testing.T) {
	// See the note in TestBuildConfigJSON_MaintenanceRoute: no
	// metrics.SetRegistry here — buildConfigJSON is pure, and
	// setting the global registry would poison the later
	// TestSyncRegistry_NotCalledOnReloadFailure.
	routes := []storage.Route{{
		ID: "r2", Host: "maint2.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{
			RetryAfterSeconds: 60,
		},
	}}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	compact := strings.Join(strings.Fields(string(cfgJSON)), "")
	if strings.Contains(compact, `"client_ip"`) {
		t.Error("client_ip bypass emitted with no BypassIPs configured; want no bypass route at all")
	}
	if !strings.Contains(compact, `"static_response"`) || !strings.Contains(compact, `"status_code":503`) {
		t.Error("no static_response 503 emitted for maintenance route")
	}
}

// v2.18.0 — buildMaintenanceBody must substitute BOTH the per-route
// retry_after sentinel AND the global message sentinel. The message is
// operator free text: it MUST be HTML-escaped (so it can't inject
// markup into every 503), and its newlines rendered as <br> (so a
// multi-line message from the Settings textarea displays across lines
// rather than collapsing to one). An empty message substitutes to
// nothing (the built-in default's generic line then stands alone).
func TestBuildMaintenanceBody_SubstitutesMessage(t *testing.T) {
	html := `<p class="msg">{arenet.maintenance.message}</p><p>retry {arenet.maintenance.retry_after_human}</p>`
	got := buildMaintenanceBody(html, 300, "Back at 14:00")
	if !strings.Contains(got, "Back at 14:00") {
		t.Errorf("message not substituted; body=%q", got)
	}
	if !strings.Contains(got, "retry 5 minutes") {
		t.Errorf("retry_after_human not substituted; body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.message}") {
		t.Errorf("message sentinel left unsubstituted; body=%q", got)
	}
}

func TestBuildMaintenanceBody_EscapesMessageHTML(t *testing.T) {
	html := `<div>{arenet.maintenance.message}</div>`
	got := buildMaintenanceBody(html, 60, `<script>alert(1)</script> & "quoted"`)
	if strings.Contains(got, "<script>") {
		t.Errorf("message HTML not escaped — raw <script> in body: %q", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag; body=%q", got)
	}
	if !strings.Contains(got, "&amp;") {
		t.Errorf("expected escaped ampersand; body=%q", got)
	}
}

func TestBuildMaintenanceBody_MessageNewlinesToBr(t *testing.T) {
	html := `<div>{arenet.maintenance.message}</div>`
	got := buildMaintenanceBody(html, 60, "line one\nline two")
	if !strings.Contains(got, "line one<br>line two") {
		t.Errorf("newline not rendered as <br>; body=%q", got)
	}
}

// v2.18.1 — per-route message resolution: a route's own
// MaintenanceConfig.Message wins; when empty, the global message
// (opts.MaintenanceMessage) is used. Exercised through buildConfigJSON
// (the real emission path where the resolution lives).
func TestBuildConfigJSON_MaintenanceMessage_PerRouteWinsElseGlobal(t *testing.T) {
	routes := []storage.Route{
		{
			ID: "own", Host: "own.example.com",
			Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			MaintenanceConfig: &storage.MaintenanceConfig{
				RetryAfterSeconds: 60, Message: "ROUTE_OWN_MSG",
			},
		},
		{
			ID: "fallback", Host: "fallback.example.com",
			Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			MaintenanceConfig: &storage.MaintenanceConfig{
				RetryAfterSeconds: 60, // no per-route message
			},
		},
	}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{DevMode: true, MaintenanceMessage: "GLOBAL_MSG"})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	out := string(cfgJSON)
	// The route with its own message shows it; the one without shows the
	// global. Both must be present in the combined config.
	if !strings.Contains(out, "ROUTE_OWN_MSG") {
		t.Error("per-route message not emitted for the route that set one")
	}
	if !strings.Contains(out, "GLOBAL_MSG") {
		t.Error("global fallback message not emitted for the route without its own")
	}
}

// v2.18.1 — the built-in default page auto-refreshes the browser via a
// meta http-equiv tag built from the route's Retry-After. buildMaintenance
// Body substitutes the {arenet.maintenance.refresh_meta} sentinel with a
// <meta http-equiv="refresh" content="N"> when retryAfter > 0, and with
// NOTHING when retryAfter == 0 (content="0" would reload instantly = a
// hammering loop).
func TestBuildMaintenanceBody_RefreshMeta_PositiveRetry(t *testing.T) {
	html := `<head>{arenet.maintenance.refresh_meta}</head>`
	got := buildMaintenanceBody(html, 1800, "")
	if !strings.Contains(got, `<meta http-equiv="refresh" content="1800">`) {
		t.Errorf("expected meta refresh with content=1800; body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.refresh_meta}") {
		t.Errorf("refresh_meta sentinel left unsubstituted; body=%q", got)
	}
}

func TestBuildMaintenanceBody_RefreshMeta_ZeroRetryOmits(t *testing.T) {
	html := `<head>[{arenet.maintenance.refresh_meta}]</head>`
	got := buildMaintenanceBody(html, 0, "")
	if strings.Contains(got, "http-equiv") {
		t.Errorf("retry_after=0 must NOT emit a meta refresh (hammering loop); body=%q", got)
	}
	if !strings.Contains(got, "[]") {
		t.Errorf("zero-retry refresh_meta should substitute to nothing (leaving []); body=%q", got)
	}
}

// A CUSTOM page that does not ASK for auto-refresh must not be given it:
// no refresh_meta sentinel in, no <meta http-equiv> out. Auto-refresh is
// opt-in, not "default page only" — a custom page gets it by writing the
// sentinel itself, which TestBuildMaintenanceBody_RefreshMeta_
// PositiveRetry already covers on an arbitrary body.
//
// The second assertion proves the body really went through substitution
// rather than being returned untouched, which is the only way the first
// one means anything. It used to make that point with the raw
// retry_after sentinel; v2.69.0 removed it, so the humanised one does.
func TestBuildMaintenanceBody_RefreshMeta_CustomPageUntouched(t *testing.T) {
	html := `<head><title>custom</title></head><body>retry {arenet.maintenance.retry_after_human}</body>`
	got := buildMaintenanceBody(html, 1800, "")
	if strings.Contains(got, "http-equiv") {
		t.Errorf("custom page (no sentinel) must not gain an auto meta refresh; body=%q", got)
	}
	if !strings.Contains(got, "retry 30 minutes") {
		t.Errorf("the custom body was not substituted at all; body=%q", got)
	}
}

// v2.18.0 security — the message is operator free text substituted into
// the (placeholder-expanded) 503 body. A message of {env.SECRET} would
// otherwise leak a process-env secret into the public 503. The message
// has no documented placeholders of its own, so dangerous Caddy
// namespaces ({env.*}, {file.*}) must be neutralized.
func TestBuildMaintenanceBody_NeutralizesEnvPlaceholderInMessage(t *testing.T) {
	html := `<div>{arenet.maintenance.message}</div>`
	got := buildMaintenanceBody(html, 60, "leak: {env.ACME_DNS_API_TOKEN} and {file./etc/passwd}")
	if strings.Contains(got, "{env.ACME_DNS_API_TOKEN}") {
		t.Errorf("{env.*} in message survived — secret disclosure: %q", got)
	}
	if strings.Contains(got, "{file./etc/passwd}") {
		t.Errorf("{file.*} in message survived — file disclosure: %q", got)
	}
}

func TestBuildMaintenanceBody_EmptyMessageSubstitutesNothing(t *testing.T) {
	html := `<div>[{arenet.maintenance.message}]</div>`
	got := buildMaintenanceBody(html, 60, "")
	if !strings.Contains(got, "[]") {
		t.Errorf("empty message should substitute to nothing (leaving []); body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.message}") {
		t.Errorf("empty message left the sentinel unsubstituted; body=%q", got)
	}
}

// TestDefaultMaintenancePageHTML_MatchesInternalDefault pins the
// v2.17.1 Item E exported accessor: it must return the exact same
// HTML as the package-private arenetDefaultMaintenancePage used by
// resolveMaintenancePage's empty-stored-HTML fallback, and it must be
// non-empty so internal/api's GET handler has something real to
// surface to the frontend as the built-in default.
func TestDefaultMaintenancePageHTML_MatchesInternalDefault(t *testing.T) {
	got := DefaultMaintenancePageHTML()
	if got == "" {
		t.Fatal("DefaultMaintenancePageHTML() returned empty string")
	}
	if got != arenetDefaultMaintenancePage {
		t.Error("DefaultMaintenancePageHTML() does not match arenetDefaultMaintenancePage")
	}
}

// ---------------------------------------------------------------------
// v2.69.0 — the retry-after line in words.
//
// The operator read the served page and said what it actually says:
// "si on met 86400s ça affiche 86400s, un utilisateur ne sait pas que
// cela est égal à 1 jour". Nothing asserted that line before this —
// grep for "Retry in" across every _test.go came back empty — which is
// also why "Retry in 0s" shipped and sat there.
// ---------------------------------------------------------------------

func TestFormatRetryAfterHuman(t *testing.T) {
	cases := []struct {
		seconds int
		want    string
		why     string
	}{
		{86400, "1 day", "the operator's own value, the whole point of this change"},
		{300, "5 minutes", "the default retry-after (api/routes.go defaultMaintenanceRetryAfterSeconds)"},
		// Cross-language pin. web/frontend/src/routes/settings/error-pages/
		// +page.svelte hardcodes MAINTENANCE_PREVIEW_RETRY_HUMAN = '30
		// minutes' for its editor preview, because the preview cannot call
		// into Go. Reword the formatter and this fails here, in the suite
		// that runs on every push, instead of leaving the operator's
		// preview quietly disagreeing with what gets served.
		{1800, "30 minutes", "pinned by the frontend maintenance preview — update both together"},
		{3600, "1 hour", "exactly one hour is one component, not 60 minutes"},
		{60, "1 minute", "singular at the boundary"},
		{1, "1 second", "singular at the floor"},
		{2, "2 seconds", "plural"},
		{59, "59 seconds", "below a minute stays seconds"},
		{90, "1 minute 30 seconds", "a remainder is stated, not rounded away"},
		{5400, "1 hour 30 minutes", "90 minutes reads as an hour and a half"},
		{172800, "2 days", "plural days"},
		{90061, "1 day 1 hour 1 minute 1 second", "every component, however ugly — it is exact"},
		{0, "", "no Retry-After header, no auto-refresh, so no duration to state"},
		{-1, "", "unreachable through validation; the guard keeps the function total"},
	}
	for _, c := range cases {
		if got := formatRetryAfterHuman(c.seconds); got != c.want {
			t.Errorf("formatRetryAfterHuman(%d) = %q, want %q — %s", c.seconds, got, c.want, c.why)
		}
	}
}

// The rendering must be EXACT, not approximate: whatever words come out,
// parsing them back has to give the stored seconds. Checked by
// reconstruction rather than by a table, so it covers values no table
// would list.
func TestFormatRetryAfterHuman_IsExact(t *testing.T) {
	unitSeconds := map[string]int{
		"second": 1, "seconds": 1,
		"minute": 60, "minutes": 60,
		"hour": 3600, "hours": 3600,
		"day": 86400, "days": 86400,
	}
	for _, seconds := range []int{1, 7, 59, 61, 119, 300, 3599, 3601, 5400, 86399, 86400, 86401, 90061, 1234567} {
		text := formatRetryAfterHuman(seconds)
		fields := strings.Fields(text)
		if len(fields)%2 != 0 {
			t.Fatalf("formatRetryAfterHuman(%d) = %q: not value/unit pairs", seconds, text)
		}
		total := 0
		for i := 0; i < len(fields); i += 2 {
			n, err := strconv.Atoi(fields[i])
			if err != nil {
				t.Fatalf("formatRetryAfterHuman(%d) = %q: %q is not a number", seconds, text, fields[i])
			}
			factor, ok := unitSeconds[fields[i+1]]
			if !ok {
				t.Fatalf("formatRetryAfterHuman(%d) = %q: unknown unit %q", seconds, text, fields[i+1])
			}
			total += n * factor
		}
		if total != seconds {
			t.Errorf("formatRetryAfterHuman(%d) = %q, which parses back to %d", seconds, text, total)
		}
	}
}

func TestFormatRetryAfterHuman_NeverPluralisesOne(t *testing.T) {
	// "1 days" is the classic tell of a formatter nobody read. Every
	// unit, at its own boundary.
	for _, seconds := range []int{1, 60, 3600, 86400} {
		got := formatRetryAfterHuman(seconds)
		if strings.HasPrefix(got, "1 ") && strings.HasSuffix(got, "s") {
			t.Errorf("formatRetryAfterHuman(%d) = %q: singular value with a plural unit", seconds, got)
		}
	}
}

func TestBuildMaintenanceBody_HumanSentinel(t *testing.T) {
	html := `<p>back in {arenet.maintenance.retry_after_human}</p>`
	got := buildMaintenanceBody(html, 86400, "")
	if !strings.Contains(got, "back in 1 day") {
		t.Errorf("retry_after_human not substituted; body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.retry_after_human}") {
		t.Errorf("retry_after_human sentinel left unsubstituted; body=%q", got)
	}
}

// v2.69.0 removed {arenet.maintenance.retry_after}. This pins the
// removal from the other side: the token is now ordinary text, and
// buildMaintenanceBody must not quietly start expanding it again.
//
// The asymmetry matters because of how Caddy serves the body.
// static_response expands it with repl.ReplaceKnown (v2.11.4
// staticresp.go:208), documented as "Unrecognized placeholders will
// remain in the output" (replacer.go:151-157) — so a page still
// carrying the dead token PRINTS it on a public 503 rather than
// dropping it. That is the behaviour a reader needs to know about, and
// the reason maintenance_example_page_test.go keeps the token in its
// mustNotContain list.
func TestBuildMaintenanceBody_DeadRawSentinelIsNotExpanded(t *testing.T) {
	html := `<p>retry {arenet.maintenance.retry_after}</p>`
	got := buildMaintenanceBody(html, 86400, "")
	if got != html {
		t.Errorf("the removed sentinel is being substituted again: %q", got)
	}
}

// TestBuildMaintenanceBody_SentinelsDoNotShadowEachOther pins what
// buildMaintenanceBody's substitution-order comment asserts. Both
// retry-after sentinels close with '}', so neither is a substring of
// the other and the order of the ReplaceAll passes is free. Rename one
// so a brace moves or disappears and one pass starts eating the other's
// token — this is what notices.
func TestBuildMaintenanceBody_SentinelsDoNotShadowEachOther(t *testing.T) {
	if strings.Contains(maintenanceRetryAfterLineSentinel, maintenanceRetryAfterHumanSentinel) {
		t.Errorf("%q is a substring of %q: substitution order now matters",
			maintenanceRetryAfterHumanSentinel, maintenanceRetryAfterLineSentinel)
	}
	if strings.Contains(maintenanceRetryAfterHumanSentinel, maintenanceRetryAfterLineSentinel) {
		t.Errorf("%q is a substring of %q: substitution order now matters",
			maintenanceRetryAfterLineSentinel, maintenanceRetryAfterHumanSentinel)
	}

	// And the behaviour that property protects: both in one body, each
	// rendering its own thing.
	html := maintenanceRetryAfterHumanSentinel + "|" + maintenanceRetryAfterLineSentinel
	got := buildMaintenanceBody(html, 3600, "")
	want := `1 hour|<p class="retry">Retry in 1 hour</p>`
	if got != want {
		t.Errorf("buildMaintenanceBody = %q, want %q", got, want)
	}
}

func TestBuildMaintenanceBody_RetryLine_ZeroOmitsTheWholeParagraph(t *testing.T) {
	// The old page said "Retry in 0s". A humanised value alone would say
	// "Retry in " with a dangling space, which is why the line — prose
	// included — is the substituted unit.
	html := `<div>[` + maintenanceRetryAfterLineSentinel + `]</div>`
	got := buildMaintenanceBody(html, 0, "")
	if got != `<div>[]</div>` {
		t.Errorf("expected the retry line to vanish whole at 0; body=%q", got)
	}
	if strings.Contains(got, "Retry in") {
		t.Errorf("retry prose survived a zero Retry-After; body=%q", got)
	}
}

// The default page is what the operator actually looked at, so assert on
// it directly rather than only on a synthetic body with the sentinel in
// it.
func TestDefaultMaintenancePage_RendersDurationInWords(t *testing.T) {
	got := buildMaintenanceBody(resolveMaintenancePage(""), 86400, "")
	if !strings.Contains(got, "Retry in 1 day") {
		t.Errorf("default page does not state the duration in words; body=%q", got)
	}
	if strings.Contains(got, "86400s") {
		t.Errorf("default page still shows raw seconds to the visitor; body=%q", got)
	}
	// The auto-refresh is what the operator asked to keep, and it needs
	// the integer: a meta refresh cannot parse "1 day".
	if !strings.Contains(got, `<meta http-equiv="refresh" content="86400">`) {
		t.Errorf("auto-refresh lost its raw seconds; body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.") {
		t.Errorf("a sentinel survived into the served default page; body=%q", got)
	}
}

func TestDefaultMaintenancePage_ZeroRetryHasNoRetryLineAndNoRefresh(t *testing.T) {
	got := buildMaintenanceBody(resolveMaintenancePage(""), 0, "")
	if strings.Contains(got, "Retry in") {
		t.Errorf("default page states a retry with no Retry-After set; body=%q", got)
	}
	if strings.Contains(got, "http-equiv=\"refresh\"") {
		t.Errorf("zero Retry-After must not emit a meta refresh (instant-reload loop); body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.") {
		t.Errorf("a sentinel survived into the served default page; body=%q", got)
	}
}

// ---------------------------------------------------------------------
// v2.70.0 — gates G3-G6 of the maintenance-bypass spec.
//
// The operator's report, which is G3: "depuis mon ip l'accès a la route
// avec mon ip en bypass c'est ok mais une prefix/header qui match une
// URI avec forward auth elle tombe en 404 depuis mon ip".
//
// These assert on the emitted JSON as a STRING within the route that
// carries the bypass matcher, because the defect was never about the
// 503 — it was about what sat behind the allow-list.
// ---------------------------------------------------------------------

// maintenanceProbeRoute is the operator's shape: a path rule with its
// own upstream pool, custom headers, and a bypass list.
func maintenanceProbeRoute(bypass []string) storage.Route {
	return storage.Route{
		ID: "r-maint", Host: "app.example.com", TLSEnabled: true,
		Upstreams:       []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:        storage.LBPolicyRoundRobin,
		WAFMode:         "off",
		RequestHeaders:  map[string]string{"X-Probe-Req": "yes"},
		ResponseHeaders: map[string]string{"X-Probe-Resp": "yes"},
		PathRules: []storage.PathRule{{
			PathPrefix: "/admin",
			Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:   storage.LBPolicyRoundRobin,
		}},
		MaintenanceConfig: &storage.MaintenanceConfig{
			RetryAfterSeconds: 86400,
			BypassIPs:         bypass,
		},
	}
}

// httpsRoutesOf returns the emitted arenet_https routes as raw JSON, in
// declaration order — which is load-bearing, since Caddy dispatches in
// that order.
func httpsRoutesOf(t *testing.T, routes []storage.Route) []string {
	t.Helper()
	out, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []json.RawMessage `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("unmarshal emitted config: %v", err)
	}
	srv, ok := cfg.Apps.HTTP.Servers["arenet_https"]
	if !ok {
		t.Fatal("no arenet_https server emitted")
	}
	// Whitespace-normalised, like TestBuildConfigJSON_MaintenanceRoute
	// already does: buildConfigJSON emits via json.MarshalIndent, so a
	// key is followed by ": " and a literal `"status_code":503` matches
	// nothing. Compacting keeps the assertions independent of the
	// marshaller's indent style.
	raw := make([]string, 0, len(srv.Routes))
	for _, r := range srv.Routes {
		raw = append(raw, strings.Join(strings.Fields(string(r)), ""))
	}
	return raw
}

// bypassedRoute returns the single emitted route gated behind the given
// CIDR, failing if there is not exactly one.
func bypassedRoute(t *testing.T, raw []string, cidr string) string {
	t.Helper()
	var found []string
	for _, r := range raw {
		if strings.Contains(r, `"client_ip"`) && strings.Contains(r, cidr) {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly 1 route gated behind %s, got %d", cidr, len(found))
	}
	return found[0]
}

// G3 — the operator's 404. The path rule's own pool must be reachable
// behind the bypass matcher, which is exactly what the pre-v2.70.0
// shape dropped.
func TestMaintenanceBypass_ReachesThePathRulePool(t *testing.T) {
	raw := httpsRoutesOf(t, []storage.Route{maintenanceProbeRoute([]string{"203.0.113.7"})})
	route := bypassedRoute(t, raw, "203.0.113.7")

	if !strings.Contains(route, "127.0.0.1:9001") {
		t.Errorf("the path rule's own upstream pool is not behind the bypass; route=%s", route)
	}
	if !strings.Contains(route, `"path"`) {
		t.Errorf("no path matcher behind the bypass, so every URI hits the root pool; route=%s", route)
	}
	if !strings.Contains(route, "/admin") {
		t.Errorf("the path prefix itself is missing; route=%s", route)
	}
}

// G4 — the headers. Named in the old branch's comment as something it
// discarded, which made it a decision on paper and a defect in use: a
// bypassed operator tested their route without its own headers.
func TestMaintenanceBypass_AppliesTheHeaders(t *testing.T) {
	raw := httpsRoutesOf(t, []storage.Route{maintenanceProbeRoute([]string{"203.0.113.7"})})
	route := bypassedRoute(t, raw, "203.0.113.7")

	for _, want := range []string{"X-Probe-Req", "X-Probe-Resp"} {
		if !strings.Contains(route, want) {
			t.Errorf("%s missing from the bypassed route; route=%s", want, route)
		}
	}
}

// G5 — everyone else still meets the 503, and the ORDER matters: Caddy
// dispatches in declaration order, so a 503 declared before the gated
// route would swallow the bypass and this whole change would be invisible.
func TestMaintenanceBypass_The503FollowsTheGatedRoute(t *testing.T) {
	raw := httpsRoutesOf(t, []storage.Route{maintenanceProbeRoute([]string{"203.0.113.7"})})

	gatedAt, respAt := -1, -1
	for i, r := range raw {
		switch {
		case strings.Contains(r, "203.0.113.7"):
			gatedAt = i
		case strings.Contains(r, `"status_code":503`) && strings.Contains(r, "app.example.com"):
			if respAt == -1 {
				respAt = i
			}
		}
	}
	if gatedAt == -1 {
		t.Fatal("no route gated behind the bypass list")
	}
	if respAt == -1 {
		t.Fatalf("no 503 route for the host; routes=%v", raw)
	}
	if gatedAt > respAt {
		t.Errorf("the 503 (index %d) is declared BEFORE the gated route (index %d): "+
			"Caddy dispatches in order, so the bypass would never match", respAt, gatedAt)
	}
	if !strings.Contains(raw[respAt], `"Retry-After"`) {
		t.Errorf("the 503 lost its Retry-After header; route=%s", raw[respAt])
	}
	// And the 503 must stay a catch-all: gate it too and nobody gets it.
	if strings.Contains(raw[respAt], `"client_ip"`) {
		t.Errorf("the 503 is itself gated behind client_ip, so unbypassed "+
			"clients match nothing; route=%s", raw[respAt])
	}
}

// G6 — security, not cosmetics. With no bypass list, NOTHING may proxy
// this host: a leak here exposes a backend the operator believes is
// closed. Asserted on the upstream dial addresses rather than on a
// handler name, because that is what a leak would actually reach.
func TestMaintenanceBypass_EmptyListProxiesNothing(t *testing.T) {
	raw := httpsRoutesOf(t, []storage.Route{maintenanceProbeRoute(nil)})

	for i, r := range raw {
		for _, upstream := range []string{"127.0.0.1:9000", "127.0.0.1:9001"} {
			if strings.Contains(r, upstream) {
				t.Errorf("route %d reaches upstream %s with an empty bypass list — "+
					"the backend is exposed during maintenance; route=%s", i, upstream, r)
			}
		}
	}
	// The 503 must still be there, or the host would 404 instead.
	var found bool
	for _, r := range raw {
		if strings.Contains(r, `"status_code":503`) && strings.Contains(r, "app.example.com") {
			found = true
		}
	}
	if !found {
		t.Errorf("no 503 emitted for a maintenance route with no bypass; routes=%v", raw)
	}
}

// The window must close on the forward-auth deny exit too (spec D6).
// That path `continue`s early, so it was the one place a post-processing
// step placed at the end of the loop body would have silently skipped —
// leaving a maintenance route with no 503 at all.
func TestMaintenanceBypass_ClosesOnTheForwardAuthDenyExit(t *testing.T) {
	r := maintenanceProbeRoute([]string{"203.0.113.7"})
	r.AuthMode = storage.RouteAuthForwardAuth
	r.ForwardAuth = storage.ForwardAuthRouteConfig{ProviderName: "provider-deleted-since"}

	raw := httpsRoutesOf(t, []storage.Route{r})

	var gated, resp bool
	for _, x := range raw {
		if strings.Contains(x, "203.0.113.7") {
			gated = true
		}
		if strings.Contains(x, `"status_code":503`) && strings.Contains(x, "app.example.com") {
			resp = true
		}
	}
	if !gated {
		t.Error("the deny route was not gated behind the bypass list")
	}
	if !resp {
		t.Error("no 503 emitted: the window was not closed on the deny exit path")
	}
}
