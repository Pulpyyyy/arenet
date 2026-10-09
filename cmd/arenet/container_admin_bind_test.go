// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package main

import (
	"io/fs"
	"testing"
)

// fakeStat answers like os.Stat for a fixed set of existing paths and
// returns errFor for every other path.
func fakeStat(existing map[string]bool, errFor error) func(string) (fs.FileInfo, error) {
	return func(p string) (fs.FileInfo, error) {
		if existing[p] {
			return nil, nil
		}
		return nil, errFor
	}
}

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8001", true},
		{"127.1.2.3:8001", true},
		{"localhost:8001", true},
		{"[::1]:8001", true},
		{":8001", false},
		{"0.0.0.0:8001", false},
		{"[::]:8001", false},
		{"192.168.1.10:8001", false},
		{"example.com:8001", false},
		{"not-an-addr", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackBind(c.addr); got != c.want {
			t.Errorf("isLoopbackBind(%q) = %v; want %v", c.addr, got, c.want)
		}
	}
}

func TestRunningInContainer(t *testing.T) {
	cases := []struct {
		name     string
		existing map[string]bool
		errFor   error
		want     bool
	}{
		{"docker marker", map[string]bool{"/.dockerenv": true}, fs.ErrNotExist, true},
		{"podman marker", map[string]bool{"/run/.containerenv": true}, fs.ErrNotExist, true},
		{"no marker", nil, fs.ErrNotExist, false},
		{"marker unreadable still counts", nil, fs.ErrPermission, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := runningInContainer(fakeStat(c.existing, c.errFor)); got != c.want {
				t.Errorf("runningInContainer = %v; want %v", got, c.want)
			}
		})
	}
}

func TestContainerLoopbackAdmin(t *testing.T) {
	inDocker := fakeStat(map[string]bool{"/.dockerenv": true}, fs.ErrNotExist)
	bareMetal := fakeStat(nil, fs.ErrNotExist)

	cases := []struct {
		name string
		bind string
		stat func(string) (fs.FileInfo, error)
		want bool
	}{
		// The upgrade trap: old reference compose env on the new image.
		{"loopback in container", "127.0.0.1:8001", inDocker, true},
		{"image default in container", ":8001", inDocker, false},
		// systemd ships a loopback bind on purpose — never warn there.
		{"loopback on bare metal", "127.0.0.1:8001", bareMetal, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := containerLoopbackAdmin(c.bind, c.stat); got != c.want {
				t.Errorf("containerLoopbackAdmin(%q) = %v; want %v", c.bind, got, c.want)
			}
		})
	}
}
