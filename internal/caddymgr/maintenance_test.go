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
	html := `<p class="msg">{arenet.maintenance.message}</p><p>retry {arenet.maintenance.retry_after}s</p>`
	got := buildMaintenanceBody(html, 300, "Back at 14:00")
	if !strings.Contains(got, "Back at 14:00") {
		t.Errorf("message not substituted; body=%q", got)
	}
	if !strings.Contains(got, "retry 300s") {
		t.Errorf("retry_after not substituted; body=%q", got)
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

// A CUSTOM page has no refresh_meta sentinel, so buildMaintenanceBody
// leaves it untouched (auto-refresh is default-page-only per the locked
// decision). The {arenet.maintenance.retry_after} placeholder stays
// available so a custom author can add their own meta refresh.
func TestBuildMaintenanceBody_RefreshMeta_CustomPageUntouched(t *testing.T) {
	html := `<head><title>custom</title></head><body>retry {arenet.maintenance.retry_after}</body>`
	got := buildMaintenanceBody(html, 1800, "")
	if strings.Contains(got, "http-equiv") {
		t.Errorf("custom page (no sentinel) must not gain an auto meta refresh; body=%q", got)
	}
	if !strings.Contains(got, "retry 1800") {
		t.Errorf("retry_after placeholder should still work on custom page; body=%q", got)
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

// Non-regression, and the reason the humanised form is a SECOND
// sentinel rather than a change to the first: a custom page may be
// using the raw value to build its own meta refresh or a
// machine-readable attribute.
func TestBuildMaintenanceBody_RawSentinelStaysRaw(t *testing.T) {
	html := `<meta http-equiv="refresh" content="{arenet.maintenance.retry_after}">`
	got := buildMaintenanceBody(html, 86400, "")
	if !strings.Contains(got, `content="86400"`) {
		t.Errorf("raw retry_after no longer renders the integer; body=%q", got)
	}
	if strings.Contains(got, "1 day") {
		t.Errorf("raw retry_after was humanised; body=%q", got)
	}
}

// TestBuildMaintenanceBody_SentinelsDoNotShadowEachOther pins what
// buildMaintenanceBody's substitution-order comment asserts. The three
// retry-after sentinels all close with '}', so none is a substring of
// another and the order of the ReplaceAll passes is free. Rename one so
// a brace moves or disappears and one pass starts eating another's
// token — this is what notices.
func TestBuildMaintenanceBody_SentinelsDoNotShadowEachOther(t *testing.T) {
	for _, pair := range [][2]string{
		{maintenanceRetryAfterSentinel, maintenanceRetryAfterHumanSentinel},
		{maintenanceRetryAfterSentinel, maintenanceRetryAfterLineSentinel},
		{maintenanceRetryAfterHumanSentinel, maintenanceRetryAfterLineSentinel},
	} {
		if strings.Contains(pair[1], pair[0]) {
			t.Errorf("%q is a substring of %q: substitution order now matters", pair[0], pair[1])
		}
		if strings.Contains(pair[0], pair[1]) {
			t.Errorf("%q is a substring of %q: substitution order now matters", pair[1], pair[0])
		}
	}

	// And the behaviour that property protects: all three in one body,
	// each rendering its own thing.
	html := maintenanceRetryAfterSentinel + "|" + maintenanceRetryAfterHumanSentinel + "|" + maintenanceRetryAfterLineSentinel
	got := buildMaintenanceBody(html, 3600, "")
	want := `3600|1 hour|<p class="retry">Retry in 1 hour</p>`
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
