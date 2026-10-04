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

package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// v2.62 — the access log names which Arenet gate refused a request.
//
// From a production incident on 2026-10-04: two members were banned by
// CrowdSec and working out why took an afternoon, because a 403 served
// by Arenet's WAF is byte-indistinguishable in the access log from a
// 403 served by the backend. Two diagnostic queries written that day
// reached the wrong conclusion for exactly that reason.

// withCaddyRequestContext builds the context Caddy gives every request:
// a vars map and the extra-log-fields holder (server.go:998).
func withCaddyRequestContext(t *testing.T, r *http.Request) (*http.Request, *caddyhttp.ExtraLogFields) {
	t.Helper()
	extra := new(caddyhttp.ExtraLogFields)
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, make(map[string]any))
	ctx = context.WithValue(ctx, caddyhttp.ExtraLogFieldsCtxKey, extra)
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	return r.WithContext(ctx), extra
}

func TestAppendDenialLogField_WritesTheGatesVerdict(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r, extra := withCaddyRequestContext(t, r)
	caddyhttp.SetVar(r.Context(), DeniedVarKey, "waf")

	got := appendDenialLogField(r)

	if got != "waf" {
		t.Errorf("wrote %q; want \"waf\" — without it an operator cannot tell a WAF 403 "+
			"from the backend's own", got)
	}
	_ = extra
}

func TestAppendDenialLogField_SaysNothingWhenNothingDenied(t *testing.T) {
	// The reason this is written here instead of with Caddy's
	// log_append: that handler adds the field unconditionally
	// (logappend.go:158), so every allowed request would carry
	// arenet_denied="". On an instance serving millions of requests
	// that is noise in a log read by hand.
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r, extra := withCaddyRequestContext(t, r)

	if got := appendDenialLogField(r); got != "" {
		t.Errorf("wrote %q on a request nobody refused; the field must be ABSENT, "+
			"not empty", got)
	}
	_ = extra
}

func TestAppendDenialLogField_SurvivesAMissingHolder(t *testing.T) {
	// Defensive: only reachable if something upstream replaced the
	// request context. Losing a log field must never cost a request,
	// so this must not panic.
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, make(map[string]any))
	r = r.WithContext(ctx)
	caddyhttp.SetVar(r.Context(), DeniedVarKey, "country")

	if got := appendDenialLogField(r); got != "" {
		t.Errorf("wrote %q with no log-field holder in the context; want nothing", got)
	}
}

func TestAppendDenialLogField_IgnoresANonStringVar(t *testing.T) {
	// The var map is map[string]any and nothing stops a future caller
	// putting something else there. A wrong type must mean "no field",
	// not a panic and not a garbled log.
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
	r, extra := withCaddyRequestContext(t, r)
	caddyhttp.SetVar(r.Context(), DeniedVarKey, 403)

	if got := appendDenialLogField(r); got != "" {
		t.Errorf("a non-string var produced %q; want it ignored", got)
	}
	_ = extra
}
