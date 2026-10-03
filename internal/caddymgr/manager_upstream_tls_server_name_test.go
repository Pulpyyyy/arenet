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
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.60 — transport.tls.server_name emission, mirroring
// manager_https_upstream_test.go.
//
// The operator-visible contract this pins: a route may dial an IP and
// still verify the backend's certificate against a hostname. Before
// this field the only ways to proxy forum.hacf.fr to its own backend
// were an invisible /etc/hosts pin on the Arenet host or switching
// certificate verification off entirely — and the pin, left out by
// one step, put Arenet in a self-proxy loop in production on
// 2026-10-03.

func TestBuildConfigJSON_UpstreamTLSServerName_EmitsServerName(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-sni",
			Host: "forum.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://194.163.129.255", Weight: 1},
			},
			LBPolicy:              storage.LBPolicyRoundRobin,
			UpstreamTLSServerName: "forum.example.com",
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "forum.example.com")
	transport, has := rp["transport"].(map[string]any)
	if !has {
		t.Fatalf("transport block absent on an https pool\nreverse_proxy=%+v", rp)
	}
	tlsCfg, has := transport["tls"].(map[string]any)
	if !has {
		t.Fatalf("transport.tls absent\ntransport=%+v", transport)
	}
	if got := tlsCfg["server_name"]; got != "forum.example.com" {
		t.Errorf("transport.tls.server_name = %v; want %q\ntls=%+v",
			got, "forum.example.com", tlsCfg)
	}
	// server_name must not drag skip-verify along with it: the whole
	// point is to keep verification ON while dialing an address.
	if _, hasSkip := tlsCfg["insecure_skip_verify"]; hasSkip {
		t.Errorf("transport.tls carries insecure_skip_verify; a server name must not "+
			"weaken verification\ntls=%+v", tlsCfg)
	}
}

func TestBuildConfigJSON_NoUpstreamTLSServerName_EmitsNothingExtra(t *testing.T) {
	// The non-regression rule: a route that does not use the field
	// keeps the byte-identical `"tls": {}` the strict default has
	// always produced. An unconditional server_name key would change
	// every existing https route's config.
	routes := []storage.Route{
		{
			ID:   "r-no-sni",
			Host: "pve.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://192.168.1.60:8006", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "pve.example.com")
	tlsCfg := rp["transport"].(map[string]any)["tls"].(map[string]any)
	if _, has := tlsCfg["server_name"]; has {
		t.Errorf("transport.tls carries server_name on a route that set none; want absent\ntls=%+v", tlsCfg)
	}
	if len(tlsCfg) != 0 {
		t.Errorf("transport.tls = %+v; want {} for a strict route with no server name", tlsCfg)
	}
}

func TestBuildConfigJSON_UpstreamTLSServerName_HTTPPool_EmitsNoTransport(t *testing.T) {
	// A server name on an http-only pool is meaningless — the API
	// normalises it away, but the generator must not emit a transport
	// block for it either, in case a row reaches it some other way.
	routes := []storage.Route{
		{
			ID:   "r-http-sni",
			Host: "plain.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.10:8123", Weight: 1},
			},
			LBPolicy:              storage.LBPolicyRoundRobin,
			UpstreamTLSServerName: "plain.example.com",
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "plain.example.com")
	if _, has := rp["transport"]; has {
		t.Errorf("transport emitted for an http-only pool; want absent\nreverse_proxy=%+v", rp)
	}
}

func TestBuildConfigJSON_UpstreamTLSServerName_CoexistsWithSkipVerify(t *testing.T) {
	// Both at once is a legitimate, if unusual, combination: dial an
	// IP, present a name, and accept a self-signed certificate for it.
	routes := []storage.Route{
		{
			ID:   "r-both",
			Host: "lab.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://10.0.0.40:8443", Weight: 1},
			},
			LBPolicy:              storage.LBPolicyRoundRobin,
			InsecureSkipVerify:    true,
			UpstreamTLSServerName: "lab.internal",
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "lab.example.com")
	tlsCfg := rp["transport"].(map[string]any)["tls"].(map[string]any)
	if v, _ := tlsCfg["insecure_skip_verify"].(bool); !v {
		t.Errorf("insecure_skip_verify = %v; want true", tlsCfg["insecure_skip_verify"])
	}
	if got := tlsCfg["server_name"]; got != "lab.internal" {
		t.Errorf("server_name = %v; want lab.internal", got)
	}
}

func TestBuildConfigJSON_UpstreamTLSServerName_LoadsCleanly(t *testing.T) {
	// The project's standing rule for anything Caddy-facing: the
	// emitted JSON must survive caddy.Validate, not just look right.
	// The metrics registry has to be installed first — the emitted
	// chain starts with arenet_routemetrics, which refuses to
	// provision without one.
	metrics.SetRegistry(metrics.NewRegistry())
	routes := []storage.Route{
		{
			ID:   "r-validate",
			Host: "forum.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://194.163.129.255", Weight: 1},
			},
			LBPolicy:              storage.LBPolicyRoundRobin,
			UpstreamTLSServerName: "forum.example.com",
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate rejected transport.tls.server_name: %v\n%s", err, raw)
	}
}
