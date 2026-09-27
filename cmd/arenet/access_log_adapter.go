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

package main

import "github.com/barto95100/arenet/internal/caddymgr"

// accessLogPaths adapts the process configuration to the API's
// AccessLogPathResolver (v2.50).
//
// It exists so the API can answer "where will the log actually be
// written?" without reading process configuration itself, and so both
// the emitter and the API resolve it through the same function — a UI
// that printed one path while Caddy wrote another would be worse than
// printing nothing.
type accessLogPaths struct {
	configured string
	dataDir    string
}

func (a accessLogPaths) ResolveAccessLogPath(operatorChoice string) string {
	return caddymgr.ResolveAccessLogPath(a.configured, a.dataDir, operatorChoice)
}
