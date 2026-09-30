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
	"path/filepath"
	"regexp"
	"strings"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.50 — the HTTP access log, emitted so CrowdSec can parse it.
//
// Arenet used to emit no access log at all: no `logs` on any server, no
// `logging` block. An agent installed beside it therefore enforced the
// community blocklist and detected nothing about this host, with nothing
// saying so. See
// docs/superpowers/specs/2026-09-27-access-log-for-crowdsec-design.md.
//
// The format is Caddy's stock JSON, deliberately unmodified: the
// crowdsecurity/caddy collection already parses it, reading
// request.client_ip, status, request.uri, request.method,
// request.headers, request.host and resp_headers. Inventing an
// Arenet-shaped log would mean shipping and maintaining a parser too.

const (
	// accessLogName is the logger the servers write to, and the suffix
	// Caddy appends to its own access-logger name.
	//
	// The composed name is what `include` has to carry, and it is not a
	// guess: the http app's logger is named "http" (app.go:180), the
	// access logger is that .Named("log.access") (app.go:235), and
	// wrapLogger then .Named(<default_logger_name>) per request
	// (logging.go:106,153). Hence http.log.access.<name>.
	//
	// Getting this wrong is the failure this feature is most exposed to:
	// the config still loads, the file is still created, and not one
	// line ever reaches it. caddy.Validate cannot see the difference,
	// which is why the test drives a real request.
	accessLogName    = "arenet_access"
	accessLogInclude = "http.log.access." + accessLogName
)

// accessLogWriter is the `writer` module block (file output).
type accessLogWriter struct {
	Output   string `json:"output"`
	Filename string `json:"filename"`
	// RollSizeMB is caddy's roll_size_mb — megabytes, and NOT the
	// "roll_size" a Caddyfile accepts. A wrong key here is silently
	// ignored and Caddy substitutes its own 100 MB.
	RollSizeMB int  `json:"roll_size_mb"`
	RollKeep   int  `json:"roll_keep"`
	RollGzip   bool `json:"roll_gzip,omitempty"`
}

// accessLogURIField is the log field the redaction filter rewrites.
// Caddy addresses a nested field with `>`, and the access log's shape is
// {"request":{"uri":"…"}}.
const accessLogURIField = "request>uri"

// redactPlaceholder is what replaces a masked value. Spelled like the
// Cookie header Caddy already redacts, so an operator reading a line
// recognises it without being told.
const accessLogRedactPlaceholder = "REDACTED"

// buildURIRedactFilter returns the `regexp` log filter that masks the
// listed query parameters in the logged URI, or nil when the list is
// empty.
//
// Caddy ships a `query` filter that looks purpose-built for this, and it
// is not used, for two reasons read in its source
// (caddy modules/logging/filters.go):
//
//   - it matches parameter names through a url.Values map lookup (:418),
//     so it is case-SENSITIVE: `?Access_Token=` would slip past;
//   - it rebuilds the query with q.Encode() (:432), which re-orders the
//     parameters alphabetically and re-encodes them, so a line no longer
//     shows the URI the client actually sent.
//
// One case-insensitive regexp does the whole list in a single pass,
// touches only the matched values, and leaves order and encoding alone.
// RegexpFilter applies it with ReplaceAllString (:623), so ${1} carries
// the `name=` prefix through.
//
// Nothing here changes the request forwarded upstream: a log filter runs
// on the encoded log entry, after the response.
func buildURIRedactFilter(params []string) map[string]any {
	if len(params) == 0 {
		return nil
	}
	alternatives := make([]string, 0, len(params))
	for _, name := range params {
		alternatives = append(alternatives, regexp.QuoteMeta(name))
	}
	// `[?&]` anchors on a real parameter boundary so `?xtoken=` is not
	// mistaken for `?token=`. `[^&]*` rather than `+` so `?token=` with
	// an empty value is still rewritten, which keeps the line honest
	// about what the parameter was.
	pattern := `(?i)([?&](?:` + strings.Join(alternatives, "|") + `)=)[^&]*`
	return map[string]any{
		"filter": "regexp",
		"regexp": pattern,
		"value":  "${1}" + accessLogRedactPlaceholder,
	}
}

type accessLogSink struct {
	Writer accessLogWriter `json:"writer"`
	// Encoder is built as a map rather than a struct because it has two
	// shapes: the bare `json` encoder, or that same encoder wrapped in a
	// `filter` one when query parameters are masked.
	//
	// Two Go fields sharing the json tag "encoder" was the first attempt.
	// encoding/json drops BOTH on a same-depth tag conflict, silently, so
	// the sink would have gone out with no encoder at all.
	//
	// The format is always stated explicitly: Caddy otherwise picks
	// console or JSON depending on whether stderr happens to be a
	// terminal (logging.go:735-748), and a log whose format depends on
	// how the service was started is not one a parser can rely on.
	Encoder map[string]any `json:"encoder"`
	Include []string       `json:"include"`
}

// ResolveAccessLogPath returns the file to write to: the operator's
// choice, else the configured default, else one derived from the data
// directory.
//
// The derived form is <dataDir>/logs/access.log rather than
// /var/log/arenet/access.log because the binary cannot know it is under
// systemd — and under ProtectSystem=strict, /var/log is read-only unless
// the unit grants it with LogsDirectory=. The systemd installer sets the
// /var/log path explicitly and adds that directive; every other
// topology keeps the data dir, which is also the Docker volume and so
// the only place a log survives the container being replaced.
func ResolveAccessLogPath(configured, dataDir, operatorChoice string) string {
	if operatorChoice != "" {
		return operatorChoice
	}
	if configured != "" {
		return configured
	}
	return filepath.Join(dataDir, "logs", "access.log")
}

// buildAccessLogging returns the top-level `logging` block, or nil when
// the access log is off — which keeps the emitted config byte-identical
// to pre-v2.50 for every installation that never enables it.
func buildAccessLogging(cfg storage.AccessLogConfig, path string) map[string]any {
	if !cfg.Enabled || path == "" {
		return nil
	}
	sink := accessLogSink{
		Writer: accessLogWriter{
			Output:     "file",
			Filename:   path,
			RollSizeMB: cfg.RollSizeMB,
			RollKeep:   cfg.RollKeep,
			RollGzip:   cfg.Compress,
		},
		Encoder: map[string]any{"format": "json"},
		Include: []string{accessLogInclude},
	}
	// v2.56 — wrap the JSON encoder in a filter when there is something
	// to mask. With no list the encoder stays the bare `json` it was, so
	// the emitted config is unchanged for anyone who clears it.
	if filter := buildURIRedactFilter(cfg.RedactQueryParams); filter != nil {
		sink.Encoder = map[string]any{
			"format": "filter",
			"wrap":   map[string]any{"format": "json"},
			"fields": map[string]any{accessLogURIField: filter},
		}
	}
	return map[string]any{"logs": map[string]any{accessLogName: sink}}
}

// accessLogServerConfig is what a server needs for its requests to reach
// that sink. Returns nil when the log is off, so the server block stays
// exactly as it was.
//
// Both servers get it: a scanner probes port 80 as readily as 443, and
// one file keeps the CrowdSec acquisition to a single entry.
func accessLogServerConfig(cfg storage.AccessLogConfig, path string) map[string]any {
	if !cfg.Enabled || path == "" {
		return nil
	}
	return map[string]any{"default_logger_name": accessLogName}
}
