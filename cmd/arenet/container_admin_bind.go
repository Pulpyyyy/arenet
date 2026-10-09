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

// Container loopback-admin guard. Up to the Dockerfile fix that moved
// the image defaults from CMD flags to ENV, the image CMD passed
// --admin-port=:8001, which (flag > env) silently shadowed the
// ARENET_ADMIN_BIND=127.0.0.1:8001 that the reference compose shipped.
// Operators copied that compose, so their env still carries the
// loopback value — and now that the env is honoured, the admin binds
// the CONTAINER's loopback. Docker forwards a published port to the
// container's network interface, never to its loopback, so the admin
// becomes unreachable from the host while the in-container healthcheck
// (which probes 127.0.0.1) stays green. This guard turns that silent
// failure into a startup warning naming the fix.

package main

import (
	"errors"
	"io/fs"
	"net"
)

// containerMarkerFiles are the files container runtimes drop at the
// root of every container: /.dockerenv (Docker) and /run/.containerenv
// (Podman). A bare-metal / systemd install has neither.
var containerMarkerFiles = []string{"/.dockerenv", "/run/.containerenv"}

// isLoopbackBind reports whether a host:port listen address binds a
// loopback interface only. An empty host (":8001") binds every
// interface and is NOT loopback; an unparsable address is treated as
// not loopback so the guard never fires on input it doesn't understand.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// runningInContainer reports whether any container marker file exists.
// stat is injected for testability (os.Stat in production).
func runningInContainer(stat func(string) (fs.FileInfo, error)) bool {
	for _, p := range containerMarkerFiles {
		// EACCES still proves the path is there.
		if _, err := stat(p); err == nil || errors.Is(err, fs.ErrPermission) {
			return true
		}
	}
	return false
}

// containerLoopbackAdmin reports whether the admin is about to listen on
// a loopback-only address inside a container, where a published port can
// never reach it.
func containerLoopbackAdmin(adminBind string, stat func(string) (fs.FileInfo, error)) bool {
	return isLoopbackBind(adminBind) && runningInContainer(stat)
}
