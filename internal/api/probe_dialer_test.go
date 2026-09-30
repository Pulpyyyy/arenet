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

package api

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// v2.56 — a diagnostic probe must not reach cloud instance metadata.
//
// Both Test buttons fetch a URL the request names, which is correct — the
// operator is testing an address they are about to save. It also means the
// admin API can reach whatever the host can, and 169.254.169.254 hands out
// instance credentials to anything asking from the instance.
//
// Private space and loopback stay allowed: in a homelab the upstream IS a
// private address, and refusing them would break the feature to protect
// against nothing.

func TestProbeTargetBlocked_AllowsWhereUpstreamsLive(t *testing.T) {
	for _, addr := range []string{
		"10.66.0.2",   // the reported setup, over WireGuard
		"10.0.0.1",    // 10/8
		"172.16.5.4",  // 172.16/12
		"192.168.1.9", // 192.168/16
		"127.0.0.1",   // loopback
		"::1",         // loopback, v6
		"93.184.216.34",
	} {
		t.Run(addr, func(t *testing.T) {
			if blocked, why := probeTargetBlocked(net.ParseIP(addr)); blocked {
				t.Errorf("%s was refused (%s); a homelab upstream lives there", addr, why)
			}
		})
	}
}

func TestProbeTargetBlocked_RefusesMetadataAndLinkLocal(t *testing.T) {
	for _, addr := range []string{
		"169.254.169.254", // IMDS on every major provider
		"169.254.0.1",     // the rest of the link-local range
		"169.254.255.254",
		"fd00:ec2::254", // AWS IMDS over IPv6
		"fe80::1",       // link-local, v6
	} {
		t.Run(addr, func(t *testing.T) {
			blocked, why := probeTargetBlocked(net.ParseIP(addr))
			if !blocked {
				t.Errorf("%s was allowed; that is where instance credentials answer", addr)
			}
			if why == "" {
				t.Error("a refusal with no reason is not actionable")
			}
		})
	}
}

func TestProbeTargetBlocked_RefusesAnUnparseableAddress(t *testing.T) {
	if blocked, _ := probeTargetBlocked(nil); !blocked {
		t.Error("an address that could not be parsed was allowed")
	}
}

// The dialer refuses the literal address before connecting.
func TestProbeDialer_RefusesMetadataByIP(t *testing.T) {
	d := newProbeDialer(2 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := d.DialContext(ctx, "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("the dial succeeded; the metadata endpoint must be unreachable from a probe")
	}
	if !errors.Is(err, errBlockedProbeTarget) {
		t.Errorf("err = %v; want it to wrap errBlockedProbeTarget so the caller can explain itself", err)
	}
}

// stubDNS answers every A query with the given address, over UDP.
//
// Needed because the whole point of checking after resolution is the case a
// pre-flight lookup misses: a NAME that resolves to the metadata address.
// Proving that requires controlling what the name resolves to.
func stubDNS(t *testing.T, answer net.IP) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return // listener closed by Cleanup
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(buf[:n]); err != nil || len(msg.Questions) == 0 {
				continue
			}
			q := msg.Questions[0]
			reply := dnsmessage.Message{
				Header: dnsmessage.Header{
					ID:            msg.Header.ID,
					Response:      true,
					Authoritative: true,
				},
				Questions: msg.Questions,
			}
			if q.Type == dnsmessage.TypeA {
				var a [4]byte
				copy(a[:], answer.To4())
				reply.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   1,
					},
					Body: &dnsmessage.AResource{A: a},
				}}
			}
			out, err := reply.Pack()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, from)
		}
	}()

	addr := pc.LocalAddr().String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", addr)
		},
	}
}

// THE test for the post-resolution property: a name that resolves to the
// metadata address is refused. A check on the name alone would have let
// this through, which is the whole reason it lives in Control.
func TestProbeDialer_RefusesMetadataBehindADNSName(t *testing.T) {
	d := newProbeDialer(2 * time.Second)
	d.Resolver = stubDNS(t, net.ParseIP("169.254.169.254"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := d.DialContext(ctx, "tcp", "metadata.invalid:80")
	if err == nil {
		t.Fatal("a name resolving to the metadata address was dialled")
	}
	if !errors.Is(err, errBlockedProbeTarget) {
		t.Errorf("err = %v; want errBlockedProbeTarget — the refusal must be the guard's, not a DNS failure", err)
	}
}

// And the same machinery must still connect to a private address, because
// that is where the upstreams are. Dialled through a name so the resolution
// path is the one exercised.
func TestProbeDialer_ConnectsToAPrivateAddressBehindADNSName(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	d := newProbeDialer(2 * time.Second)
	d.Resolver = stubDNS(t, net.ParseIP("127.0.0.1"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "upstream.invalid:"+port)
	if err != nil {
		t.Fatalf("a private address was refused: %v", err)
	}
	conn.Close()
}
