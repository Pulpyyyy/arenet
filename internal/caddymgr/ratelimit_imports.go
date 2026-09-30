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

// v2.57 — register http.handlers.rate_limit where the emitter lives.
//
// Until now this blank import existed only in cmd/arenet/main.go. The
// binary was therefore fine, and the test suite could not tell: a
// caddy.Validate over a config carrying a rate_limit handler failed with
// "unknown module", so no test in this package ever validated one. Arenet
// has emitted the route-level rate_limit zone since Step Q without a
// single guard proving its shape loads.
//
// That is the same miss as the layer-4 matchers (see crowdsec_imports.go):
// the emitter references a module ID the test binary does not register, so
// the one check that would catch a wrong key cannot run. A mistyped field
// there is silently ignored by Caddy and the limit simply never applies —
// the failure mode is an unprotected endpoint, with nothing saying so.
//
// Kept in its own file so the dependency direction is one `git grep` away,
// mirroring how coraza-caddy and the CrowdSec bouncer were wired.
//
// Apache 2.0 licensed (one-way compatible with AGPL v3).
import (
	// http.handlers.rate_limit — the sliding-window limiter both the
	// route-level and the per-path limits emit.
	_ "github.com/mholt/caddy-ratelimit"
)
