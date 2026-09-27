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
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"
)

func enabledAccessLog(path string) (storage.AccessLogConfig, string) {
	cfg := storage.DefaultAccessLogConfig()
	cfg.Enabled = true
	return cfg, path
}

// The contract every existing installation depends on: the access log
// off means not one byte of the emitted config changes.
func TestBuildConfigJSON_AccessLogOff_ByteIdentical(t *testing.T) {
	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	before, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Same call but going through the v2.50 fields with the log
	// disabled — and with a path set, which must not surface either.
	after, err := buildConfigJSON(routes, buildOpts{
		DevMode:       true,
		AccessLog:     storage.DefaultAccessLogConfig(),
		AccessLogPath: "/var/log/arenet/access.log",
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("emitted config changed with the access log off:\n--- before\n%s\n--- after\n%s", before, after)
	}
	if bytes.Contains(after, []byte("logging")) {
		t.Fatal("a logging block was emitted with the access log off")
	}
}

// Enabled, the sink and BOTH servers must appear — and the include name
// has to be the one Caddy actually composes.
func TestBuildConfigJSON_AccessLogOn_SinkAndServers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	cfg, _ := enabledAccessLog(path)

	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: true, // so an HTTPS server exists to check too
	}}

	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode: true, AccessLog: cfg, AccessLogPath: path,
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// `logging` is top level, a sibling of apps — not inside the http app.
	logging, _ := got["logging"].(map[string]any)
	if logging == nil {
		t.Fatalf("no top-level logging block:\n%s", raw)
	}
	logs, _ := logging["logs"].(map[string]any)
	sink, _ := logs[accessLogName].(map[string]any)
	if sink == nil {
		t.Fatalf("no %q sink: %v", accessLogName, logs)
	}

	writer, _ := sink["writer"].(map[string]any)
	if writer["output"] != "file" || writer["filename"] != path {
		t.Fatalf("writer: got %v", writer)
	}
	// roll_size_mb, not roll_size: the Caddyfile name is different and a
	// wrong key is ignored, leaving Caddy's own 100 MB default.
	if writer["roll_size_mb"] != float64(storage.AccessLogDefaultRollSizeMB) {
		t.Fatalf("roll_size_mb: got %v", writer["roll_size_mb"])
	}
	if writer["roll_keep"] != float64(storage.AccessLogDefaultRollKeep) {
		t.Fatalf("roll_keep: got %v", writer["roll_keep"])
	}
	if writer["roll_gzip"] != true {
		t.Fatalf("roll_gzip: got %v", writer["roll_gzip"])
	}

	encoder, _ := sink["encoder"].(map[string]any)
	if encoder["format"] != "json" {
		t.Fatalf("the encoder must be pinned to json, got %v", encoder)
	}

	include, _ := sink["include"].([]any)
	if len(include) != 1 || include[0] != accessLogInclude {
		t.Fatalf("include: got %v, want [%s]", include, accessLogInclude)
	}

	// A sink no server writes to would load cleanly and receive nothing.
	apps, _ := got["apps"].(map[string]any)
	httpApp, _ := apps["http"].(map[string]any)
	servers, _ := httpApp["servers"].(map[string]any)
	for _, name := range []string{"arenet_http", "arenet_https"} {
		srv, _ := servers[name].(map[string]any)
		if srv == nil {
			t.Fatalf("%s server missing", name)
		}
		srvLogs, _ := srv["logs"].(map[string]any)
		if srvLogs == nil {
			t.Errorf("%s: no logs block — its requests would reach no sink", name)
			continue
		}
		if srvLogs["default_logger_name"] != accessLogName {
			t.Errorf("%s: default_logger_name = %v", name, srvLogs["default_logger_name"])
		}
	}
}

// The include name is composed from three separate places in Caddy, so
// it is pinned literally: a drift there produces a config that loads,
// creates the file, and never writes a line to it.
func TestAccessLogInclude_ComposedName(t *testing.T) {
	if accessLogInclude != "http.log.access."+accessLogName {
		t.Fatalf("include = %q", accessLogInclude)
	}
	// Named after the http app's logger ("http"), then "log.access"
	// (caddyhttp/app.go:235), then the server's default_logger_name
	// (caddyhttp/logging.go:106,153).
	if accessLogInclude != "http.log.access.arenet_access" {
		t.Fatalf("include = %q, want http.log.access.arenet_access", accessLogInclude)
	}
}

// Path resolution: the operator's choice wins, then the configured
// default, then one derived from the data dir.
func TestResolveAccessLogPath(t *testing.T) {
	cases := []struct {
		name       string
		configured string
		dataDir    string
		choice     string
		want       string
	}{
		{"operator wins over everything", "/var/log/arenet/access.log", "/var/lib/arenet", "/srv/logs/a.log", "/srv/logs/a.log"},
		{"systemd: configured path", "/var/log/arenet/access.log", "/var/lib/arenet", "", "/var/log/arenet/access.log"},
		{"docker and dev: derived from the data dir", "", "/var/lib/arenet", "", "/var/lib/arenet/logs/access.log"},
		{"dev relative data dir", "", "./data", "", filepath.Join("data", "logs", "access.log")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveAccessLogPath(c.configured, c.dataDir, c.choice); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// caddy.Validate has to accept the whole thing, logger included.
//
// It is NOT sufficient on its own — a sink no server feeds validates
// perfectly — which is why the server wiring is asserted above and the
// end-to-end proof (a real request landing in the file, carrying
// request.client_ip) is gate G5 of the smoke procedure.
func TestBuildConfigJSON_LoadsCleanly_WithAccessLog(t *testing.T) {
	metrics.SetRegistry(metrics.NewRegistry())
	t.Cleanup(metrics.ResetForTest)

	path := filepath.Join(t.TempDir(), "access.log")
	cfg, _ := enabledAccessLog(path)

	routes := []storage.Route{{
		ID: "r1", Host: "app.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}

	raw, err := buildConfigJSON(routes, buildOpts{
		DevMode: true, AccessLog: cfg, AccessLogPath: path,
	})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate with the access log on: %v\n%s", err, raw)
	}
}
