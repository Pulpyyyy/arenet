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

// Package certinfo bridges certmagic's per-cert runtime state into
// AreNET's API surface. T.1 of Step T (spec at docs/superpowers/
// specs/2026-06-04-step-t-certificates-runtime-refactor.md, frozen
// at v1.2.0-step-t-spec, commit 9a34eb1).
//
// Architecture (§1.7 of the spec, locked):
//
//  1. Subscribe to certmagic events through the Caddy events App
//     via an events.handlers.arenet_cert_info module (same shape
//     as internal/caddyhc — see commits 1926f78 + 3b371d8 for the
//     template).
//  2. Maintain an in-memory CertRuntimeInfo cache keyed on
//     certificate primary domain.
//  3. Reconcile from certmagic's on-disk storage at boot so certs
//     obtained BEFORE the events listener registered are still
//     visible immediately.
//
// Forward-compat seam for Step T+1 (ACME events log): the tracker
// exposes Subscribe(handler EventHandler) so a future package can
// fan out on the same events without modifying T's runtime cache.
// AC #18 pins this contract.
//
// EMPIRICAL EVENT NAMES (verified during T.1 recon against
// certmagic v0.25.3 — DO NOT trust inferred names):
//
//   - cert_obtaining (config.go:605, :891) — about to attempt issuance.
//     Payload: {identifier}.
//   - cert_obtained  (config.go:728, :1019) — issuance succeeded.
//     Payload: {renewal bool, identifier, issuer, storage_path,
//     private_key_path, certificate_path, metadata_path, csr_pem}.
//     RENEWAL is detected via renewal=true (no separate
//     "cert_renewed" event exists in v0.25.3).
//   - cert_failed    (config.go:693, :983) — issuance failed.
//     Payload: {renewal bool, identifier, [remaining], issuers,
//     error}.
//   - cached_managed_cert / cached_unmanaged_cert (certificates.go:
//     261, 322, 358, 376, 407) — emitted when a cert is loaded into
//     certmagic's in-memory cache. Payload: {sans, [replacement]}.
//     Used by T.1's reconcile-vs-live diff path to know which certs
//     are actually loaded right now.
//
// EMPIRICAL EVENT ORIGIN (verified against caddyserver/caddy v2.11.4,
// modules/caddytls/tls.go:1003-1006):
//
//	The certmagic emit callback flows through (*caddytls.TLS).onEvent
//	which calls t.events.Emit(t.ctx, eventName, data). The originating
//	Caddy module ID is therefore "tls" (the top-level TLS app, declared
//	at modules/caddytls/tls.go:156), NOT "tls.issuance.acme" or any
//	sub-namespace. The Caddy events App's dispatch loop walks UP the
//	module tree from the origin (caddyevents/app.go:269-313), so the
//	subscription filter MUST select "tls" or a strict ancestor (the
//	empty string for "all events"); a more specific filter would
//	never match. Same shape of trap as Stage B's
//	"http.handlers.reverse_proxy.health_checker" mistake (Bug 1, fixed
//	in commit 3b371d8). The empirical recon paid off — no wrong-filter
//	first-deploy here.
package certinfo

import "time"

// Status is the per-certificate health classification surfaced to
// the frontend. Locked enum vocabulary (§2 AC #2 of the Step T spec).
//
// Satisfies AC #2 + AC #10 (Step T spec v1.2.0-step-t-spec).
// Implemented by 1350777 (T.1).
type Status string

const (
	// StatusValid: cert is current, not in the renewal window
	// (NotAfter > now + renewal-margin).
	StatusValid Status = "VALID"
	// StatusRenewalPending: cert is approaching expiry — within the
	// renewal margin (NotAfter <= now + 30d by default).
	StatusRenewalPending Status = "RENEWAL_PENDING"
	// StatusExpired: NotAfter <= now.
	StatusExpired Status = "EXPIRED"
	// StatusObtainFailed: the most recent cert_obtaining attempt for
	// this domain ended in a cert_failed event within the last 24h
	// (per §3.1 of the spec). When NotAfter is still in the future
	// but an OBTAIN_FAILED record is fresh, the operator sees a hint
	// that automatic renewal is currently failing.
	StatusObtainFailed Status = "OBTAIN_FAILED"
	// StatusUnknown: no information yet — either bootstrap before
	// reconcile completed, or a domain we expect but have neither
	// an on-disk cert nor a recent event for. Steady-state should
	// never show this once reconcile + first events have flowed.
	StatusUnknown Status = "UNKNOWN"
)

// Source describes WHICH cert policy produced this certificate,
// used by the frontend's unified Domaines table to render the
// type sub-line (§1.4 of the spec).
type Source string

const (
	// SourceWildcard: cert is *.apex.tld issued under a managed
	// wildcard apex policy via DNS-01.
	SourceWildcard Source = "wildcard"
	// SourceApex: cert is the bare apex domain (the
	// managed-domain row's includeApex companion).
	SourceApex Source = "apex"
	// SourceSpecific: per-route cert auto-provisioned at route
	// creation (default mode, HTTP-01 or DNS-01).
	SourceSpecific Source = "specific"
)

// CertRuntimeInfo is the wire shape returned by GET /api/certificates
// and the in-memory shape held by the Tracker. Field-by-field mirror
// of the frontend type declared in web/frontend/src/lib/api/types.ts
// (T.4 adds it); JSON tags below are the contract.
//
// Fields populated from the on-disk leaf cert (Domain, SANList,
// Issuer, NotBefore, NotAfter) are seeded at boot by ReconcileFromDisk
// and refreshed on every cert_obtained event (which carries the new
// certificate path). Fields populated from events (LastError,
// LastErrorAt) are volatile — only the current-process lifetime,
// since certmagic doesn't replay history.
//
// Status and Source are derived fields recomputed on every List() call
// based on the persistent fields + the current wall-clock; they are
// NOT stored on disk and not re-fetched from certmagic.
type CertRuntimeInfo struct {
	Domain      string     `json:"domain"`
	SANList     []string   `json:"sanList"`
	Issuer      string     `json:"issuer"`
	NotBefore   time.Time  `json:"notBefore"`
	NotAfter    time.Time  `json:"notAfter"`
	Status      Status     `json:"status"`
	Source      Source     `json:"source"`
	LastError   *string    `json:"lastError,omitempty"`
	LastErrorAt *time.Time `json:"lastErrorAt,omitempty"`
}

// EventKind classifies the events flowing through the tracker's
// Subscribe seam (forward-compat for T+1's ACME events log per
// §1.3 + AC #18 of the spec). Distinct from the on-wire status
// because Subscribe-stream consumers want the raw transition
// signal, not the derived status.
type EventKind string

const (
	// EventCertObtained fires on certmagic's "cert_obtained" event
	// (initial issuance OR successful renewal — disambiguated by
	// the IsRenewal field).
	EventCertObtained EventKind = "cert_obtained"
	// EventCertFailed fires on certmagic's "cert_failed" event.
	EventCertFailed EventKind = "cert_failed"
	// EventCertObtaining fires on certmagic's "cert_obtaining"
	// event (informational — issuance has started; outcome not yet
	// known).
	EventCertObtaining EventKind = "cert_obtaining"
	// EventCertRemoved is synthesized by the tracker (NOT by
	// certmagic — Caddy v2.11.4 / certmagic v0.25.4 have no
	// cert-removal event; verified empirically against the
	// vendored sources). Fires from RemoveDomain, which the
	// DELETE managed-domain API handler calls after a successful
	// caddy reload to purge ghost entries (OBTAIN_FAILED rows
	// for the removed apex). Forward-compat seam for Step T+1's
	// ACME events log so it can record the purge alongside the
	// other lifecycle events.
	EventCertRemoved EventKind = "cert_removed"
	// EventCertOCSPRevoked fires on certmagic's
	// "cert_ocsp_revoked" event (maintain.go:375). Step U.2
	// added this kind — T.1's subscription deliberately did
	// NOT cover OCSP because the tracker had no policy for
	// it; U.2 introduces persistence to the cert_event table
	// (via the AC #18 Subscribe seam) but does NOT change
	// tracker Status because the cert may still serve
	// requests until certmagic replaces it. Spec §3.6 locked
	// decision: this is INCLUDED as level=ERROR because cert
	// revocation is a security-relevant signal (may indicate
	// key compromise).
	EventCertOCSPRevoked EventKind = "cert_ocsp_revoked"
)

// Event is the payload passed to Subscribe handlers. Decoupled from
// the raw caddy.Event so consumers don't have to peek into Caddy's
// untyped map.
type Event struct {
	Kind      EventKind
	Domain    string
	IsRenewal bool      // true when Kind=EventCertObtained AND payload.renewal=true
	Issuer    string    // populated on cert_obtained
	Error     string    // populated on cert_failed (the raw error message)
	At        time.Time // wall-clock at handler dispatch
}

// EventHandler is the seam declared in §1.7 of the spec for Step T+1
// forward-compat. T.1 ships the seam + an internal no-op in the
// tracker; T+1's ACME events log attaches via this interface.
//
// The handler is called synchronously from the Caddy events dispatch
// goroutine via the tracker's internal fan-out. Handlers must NOT
// block — long work goes into the consumer's own goroutine. Failures
// in a Subscribe-attached handler are swallowed (logged but not
// propagated): one consumer's bug must not break the tracker's
// primary state-maintenance role.
type EventHandler interface {
	HandleCertEvent(e Event)
}
