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

// v2.62 — naming Arenet's own refusals in the access log.
//
// The need came out of a production incident on 2026-10-04: two members
// were banned by CrowdSec, and working out why took an afternoon
// because a 403 served by Arenet's WAF is byte-indistinguishable in the
// access log from a 403 served by the backend. Two of the diagnostic
// queries written that day reached the wrong conclusion for exactly
// that reason.
//
// There WAS an accidental tell — Arenet's error-page templates
// reference {http.request.uuid}, which makes Caddy generate the request
// UUID, which then lands in the access log. So "has a uuid" meant
// "Arenet served its own error page". It is not a contract: the error
// templates are operator-editable in the UI, so anyone who customises
// one without carrying that placeholder over silently loses the marker,
// and the CrowdSec whitelist built on it stops working with no sign.
//
// So the marker is explicit now, and it is a LOG FIELD rather than a
// response header. A header would be trivial to set but would tell a
// prober which gate stopped them, which is information that helps them
// tune.
//
// The field is written by internal/metrics' middleware, which is
// already first in every route's chain and already wraps the response.
// A first attempt emitted Caddy's own http.handlers.log_append instead;
// it worked, but it inserted a handler at position 1 and broke fifteen
// chain-order tests, and it wrote the field as an EMPTY value on every
// allowed request (logappend.go:158 adds the field unconditionally).
// Writing it ourselves lets the field be absent when nothing denied.

// DeniedVarKey is the Caddy var each Arenet gate sets when it refuses a
// request, read back by the metrics middleware after next.ServeHTTP
// returns — so one reader at the top of the chain catches whatever any
// gate downstream wrote.
const DeniedVarKey = "arenet_denied"

// DeniedLogField is the key the value appears under in the access log.
// Deliberately prefixed: it sits beside Caddy's own fields, and an
// operator grepping their logs should be able to tell whose field it is.
const DeniedLogField = "arenet_denied"

// Denial reasons. Each is the value one gate writes. Stable strings —
// a CrowdSec whitelist or a log query will be written against them, so
// renaming one silently breaks an operator's configuration.
const (
	// DeniedByWAF — internal/waf, Coraza interruption in block mode.
	DeniedByWAF = "waf"
	// DeniedByCountryBlock — internal/countryblock, geo/ASN gate.
	DeniedByCountryBlock = "country"
)
