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
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/metrics"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.56 — sensitive query parameters are masked in the logged URI.
//
// Reported case: Vaultwarden puts the user's access token in the URI
// (/notifications/hub?access_token=eyJ...), so turning the access log on
// wrote a live session credential to a file that CrowdSec also reads.
//
// The tests below exercise the regexp the emitter builds, because that is
// what Caddy will apply — asserting on the emitted JSON alone would prove
// the config looks right, not that a token gets masked.

// applyEmittedFilter compiles the emitted pattern and runs it, the way
// Caddy's RegexpFilter does (ReplaceAllString, filters.go:623).
func applyEmittedFilter(t *testing.T, params []string, uri string) string {
	t.Helper()
	filter := buildURIRedactFilter(params)
	if filter == nil {
		t.Fatalf("no filter emitted for %v", params)
	}
	re, err := regexp.Compile(filter["regexp"].(string))
	if err != nil {
		t.Fatalf("emitted pattern does not compile: %v", err)
	}
	return re.ReplaceAllString(uri, filter["value"].(string))
}

// THE test. The exact URI from the report.
func TestAccessLogRedact_VaultwardenAccessToken(t *testing.T) {
	const uri = "/notifications/hub?access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.thesignature"
	got := applyEmittedFilter(t, storage.DefaultRedactQueryParams(), uri)

	if strings.Contains(got, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("the access token survived into the log line: %q", got)
	}
	if got != "/notifications/hub?access_token=REDACTED" {
		t.Errorf("got %q", got)
	}
}

func TestAccessLogRedact_URIForms(t *testing.T) {
	params := storage.DefaultRedactQueryParams()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single", "/a?token=abc", "/a?token=REDACTED"},
		{"first of several", "/a?access_token=abc&x=1", "/a?access_token=REDACTED&x=1"},
		{"last of several", "/a?x=1&code=abc", "/a?x=1&code=REDACTED"},
		{"middle of several", "/a?x=1&state=abc&y=2", "/a?x=1&state=REDACTED&y=2"},
		{"two sensitive at once", "/a?code=abc&state=def", "/a?code=REDACTED&state=REDACTED"},
		{"uppercase name", "/a?Access_Token=abc", "/a?Access_Token=REDACTED"},
		{"mixed case name", "/a?ApiKey=abc", "/a?ApiKey=REDACTED"},
		{"percent-encoded value", "/a?token=a%2Fb%3Dc&x=1", "/a?token=REDACTED&x=1"},
		{"empty value", "/a?token=&x=1", "/a?token=REDACTED&x=1"},
		{"no query at all", "/a/b/c", "/a/b/c"},
		// Order and encoding are preserved — which is why the emitter
		// does not use Caddy's `query` filter, whose q.Encode() would
		// re-sort these.
		{"order preserved", "/a?z=1&token=abc&a=2", "/a?z=1&token=REDACTED&a=2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := applyEmittedFilter(t, params, tc.in); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// A name that merely ENDS with a sensitive one must survive: the anchor
// is a real parameter boundary, not a substring.
func TestAccessLogRedact_LeavesLookalikesAlone(t *testing.T) {
	params := storage.DefaultRedactQueryParams()
	for _, in := range []string{
		"/a?mytoken=keepme",
		"/a?tokenizer=keepme",
		"/a?monkey=keepme", // ends in "key"
		"/a?foo=bar&page=2",
		"/api?path=../etc/passwd",
	} {
		t.Run(in, func(t *testing.T) {
			if got := applyEmittedFilter(t, params, in); got != in {
				t.Errorf("a non-sensitive URI was rewritten: %q → %q", in, got)
			}
		})
	}
}

// A parameter name carrying regexp metacharacters must be quoted, not
// compiled as a pattern.
func TestAccessLogRedact_QuotesOperatorInput(t *testing.T) {
	got := applyEmittedFilter(t, []string{"a.b"}, "/x?a.b=secret&axb=keepme")
	if strings.Contains(got, "secret") {
		t.Errorf("the named parameter was not masked: %q", got)
	}
	if !strings.Contains(got, "axb=keepme") {
		t.Errorf("an unquoted dot matched a different parameter: %q", got)
	}
}

// An empty list emits no filter, so the encoder stays the bare `json` it
// was before v2.56.
func TestAccessLogRedact_EmptyListLeavesTheEncoderAlone(t *testing.T) {
	if f := buildURIRedactFilter(nil); f != nil {
		t.Errorf("a filter was emitted for an empty list: %v", f)
	}
	cfg := storage.AccessLogConfig{
		Enabled: true, RollSizeMB: 10, RollKeep: 5, RedactQueryParams: []string{},
	}
	logging := buildAccessLogging(cfg, "/tmp/a.log")
	raw, _ := json.Marshal(logging)
	if strings.Contains(string(raw), "filter") {
		t.Errorf("a filter encoder was emitted with no parameters to mask: %s", raw)
	}
	if !strings.Contains(string(raw), `"format":"json"`) {
		t.Errorf("the plain json encoder is gone: %s", raw)
	}
}

// The emitted config has to be something Caddy loads, not something that
// merely looks right — the project's rule for anything Caddy-facing.
func TestAccessLogRedact_LoadsCleanly(t *testing.T) {
	// arenet_routemetrics refuses to provision without a registry, same
	// as the other LoadsCleanly guards in this package.
	metrics.SetRegistry(metrics.NewRegistry())

	cfg := storage.AccessLogConfig{
		Enabled: true, RollSizeMB: 10, RollKeep: 5, Compress: true,
		RedactQueryParams: storage.DefaultRedactQueryParams(),
	}
	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}
	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode: true, AccessLog: cfg, AccessLogPath: "/tmp/arenet-redact-test.log",
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Parsed rather than grepped: buildConfigJSON indents, so a
	// substring like `"format":"filter"` would never match and the test
	// would fail for the wrong reason.
	var full map[string]any
	if err := json.Unmarshal(raw, &full); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	logs := full["logging"].(map[string]any)["logs"].(map[string]any)
	sink := logs["arenet_access"].(map[string]any)
	encoder := sink["encoder"].(map[string]any)
	if encoder["format"] != "filter" {
		t.Fatalf("encoder format = %v; want the filter wrapper", encoder["format"])
	}
	if wrapped := encoder["wrap"].(map[string]any); wrapped["format"] != "json" {
		t.Fatalf("the wrapped encoder is %v; the log must stay JSON", wrapped["format"])
	}
	fields := encoder["fields"].(map[string]any)
	if _, ok := fields["request>uri"]; !ok {
		t.Fatalf("the filter is not attached to request>uri: %v", fields)
	}

	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate with the redaction filter: %v\n%s", err, raw)
	}
}
