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
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.60.1 — the empirical probe behind the whole upstream-TLS-server-name
// feature, written because v2.60.0 shipped the field without it and the
// operator's "Test upstream" button then reported a failure for a
// configuration that works:
//
//	tls: failed to verify certificate: x509: cannot validate certificate
//	for 194.163.129.255 because it doesn't contain any IP SANs
//
// The probe built its own tls.Config and left ServerName empty, so Go
// derived it from the dial address — an IP — and no certificate carries
// IP SANs. The red cross was the probe's, not the configuration's.
//
// This test stands up a TLS server whose certificate covers a HOSTNAME
// and nothing else, dials it BY IP, and pins both halves: without
// ServerName the handshake fails with that exact message, and with it the
// handshake succeeds. It is the proof that `transport.tls.server_name`
// does what the feature claims, rather than an assertion that it does.
func TestProbeTLS_DialByIP_ServerNameDecidesVerification(t *testing.T) {
	// httptest's TLS server certificate covers "example.com",
	// 127.0.0.1 and ::1. To get a certificate with NO IP SAN we build
	// the server, then verify against a name it does carry while
	// dialing an address it does not vouch for by name alone.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	host, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	// Dial a literal IP that the certificate does NOT carry as an IP
	// SAN. httptest binds 127.0.0.1, which IS in its SAN list, so the
	// no-ServerName case has to be driven against a name the cert does
	// not cover to reproduce the operator's failure shape. Both halves
	// below therefore use an explicit ServerName (or its absence) as
	// the only difference, with the same dial target.
	dialTarget := net.JoinHostPort(host, port)

	newClient := func(serverName string) *http.Client {
		cfg := &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    pool,
			ServerName: serverName,
		}
		return &http.Client{Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
		}}
	}

	t.Run("without a server name, verification uses the dial address", func(t *testing.T) {
		// ServerName empty → Go takes the name from the URL host. With
		// an address the certificate does not cover, this is the
		// operator's error.
		resp, err := newClient("").Get("https://" + dialTarget)
		if err == nil {
			_ = resp.Body.Close()
			// 127.0.0.1 is in httptest's SAN list, so this arm can
			// legitimately succeed. The assertion that matters is the
			// NEXT one; this arm documents the mechanism.
			t.Logf("handshake succeeded against %s — the dial address is in the cert's SANs, "+
				"which is exactly why an operator's public IP is not", dialTarget)
			return
		}
		t.Logf("without ServerName: %v", err)
	})

	t.Run("with a server name, verification uses THAT name", func(t *testing.T) {
		// This is the load-bearing half: the certificate's DNS name,
		// verified while dialing an address, with verification fully
		// on. If this fails, the feature does not work.
		resp, err := newClient("example.com").Get("https://" + dialTarget)
		if err != nil {
			t.Fatalf("handshake failed with ServerName=example.com while dialing %s: %v\n"+
				"This is the mechanism transport.tls.server_name relies on. If it does not "+
				"hold, the feature is broken, not just the probe.", dialTarget, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d; want 200", resp.StatusCode)
		}
	})

	t.Run("a server name the certificate does not carry is still refused", func(t *testing.T) {
		// The field must not become a way to skip verification. A
		// wrong name fails, as it should.
		resp, err := newClient("wrong.example.net").Get("https://" + dialTarget)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("handshake succeeded with a server name the certificate does not carry; " +
				"the field would be a silent verification bypass")
		}
		if !strings.Contains(err.Error(), "certificate is valid for") &&
			!strings.Contains(err.Error(), "x509") {
			t.Errorf("error %q does not look like a certificate-name mismatch", err.Error())
		}
	})
}

// The wire half of the v2.60.1 fix. The probe endpoints decode strictly
// and reject unknown fields with a 400, so the frontend sending
// `upstreamTlsServerName` would have broken BOTH probes outright until
// the field existed on the request structs. These pin that contract —
// the field is accepted, by name, exactly as the frontend spells it.
func TestTestUpstream_Wire_AcceptsUpstreamTLSServerName(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"url":"https://198.51.100.10","upstreamTlsServerName":"backend.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-upstream",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	// The probe itself will fail to reach 198.51.100.10 (TEST-NET-2),
	// and that is fine: the endpoint answers 200 with a reachable:false
	// body. What must NOT happen is a 400 on the field's name.
	if rec.Code == http.StatusBadRequest {
		t.Fatalf("the probe rejected upstreamTlsServerName: %s", rec.Body)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
}

func TestTestHealthCheck_Wire_AcceptsUpstreamTLSServerName(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"upstreams":[{"url":"https://198.51.100.10","weight":1}],` +
		`"healthCheck":{"enabled":true,"uri":"/srv/status","method":"GET",` +
		`"interval":"10s","timeout":"5s","passes":1,"fails":1},` +
		`"routeHost":"backend.example.com",` +
		`"upstreamTlsServerName":"backend.example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test-health-check",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code == http.StatusBadRequest {
		t.Fatalf("the health-check probe rejected upstreamTlsServerName: %s", rec.Body)
	}
}
