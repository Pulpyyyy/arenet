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

package audit

import "testing"

// TestAllActions_Count guards against accidental drift from D7
// (Step D shipped 15) + Step J.4 (+1 = 16) + Step K.1 (+2 = 18)
// + Step K.2 (+7 = 25) + Step K.3 (+3 = 28) + Step O.3 (+2 = 30)
// + Step P.3 (+2 = 32) + Step V.4 (+2 = 34) + MaxMind (+2 = 36).
// Adding or removing actions without updating the spec / decisions
// doc is a process violation; this test forces the conversation.
func TestAllActions_Count(t *testing.T) {
	const wantCount = 78
	if got := len(AllActions()); got != wantCount {
		t.Fatalf("AllActions count drift: got %d, want %d (D7=15 + J.4=1 + v2.11-dns=2 + K.1=2 + K.2=7 + K.3=3 + O.3=2 + P.3=2 + V.4=2 + CS.1=2 + CS.2=1 + CS.3=1 + crowdsec-unban=1 + CS.3-fu=1 + users-page=1 + Phase4=3 + AL.1.a=3 + AL.3b=3 + R=3 + MaxMind=2 + route-toggle=2 + route-maintenance=2 + cert-delete=1 + external-cert=3 + external-cert-csr=1 + scheduled-backups=2 + route-check=2 + tcp-services=3 + local-users=1 + access-log=1 + probes=3)", got, wantCount)
	}
}

// TestAllActions_NoDuplicates ensures every action string is unique
// within the enum.
func TestAllActions_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool, len(AllActions()))
	for _, a := range AllActions() {
		if seen[a] {
			t.Errorf("duplicate action in AllActions: %q", a)
		}
		seen[a] = true
	}
}

// TestAllActions_ReturnsFreshCopy guards against mutability leakage:
// each call must return an independent slice so callers cannot mutate
// the package-level source of truth.
func TestAllActions_ReturnsFreshCopy(t *testing.T) {
	a := AllActions()
	b := AllActions()
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("AllActions returned empty slice")
	}
	if &a[0] == &b[0] {
		t.Error("AllActions returned same backing array on consecutive calls")
	}
	// Mutate the first copy; the second copy and a subsequent third
	// call must remain intact.
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Error("mutating one copy mutated another")
	}
	c := AllActions()
	if c[0] == "MUTATED" {
		t.Error("mutating a copy mutated the package source")
	}
}

// TestAllActions_ExactSet confirms the exact set: 15 from D7
// + 1 added by Step J.4 (dns_provider_updated) + 2 added by
// Step K.1 (forward_auth_provider_updated /
// forward_auth_provider_deleted). If you add or remove an
// action, this test will fail and force you to amend the
// decision document / spec.
func TestAllActions_ExactSet(t *testing.T) {
	want := map[string]bool{
		"login_success":                 true,
		"login_failure":                 true,
		"logout":                        true,
		"unlock_success":                true,
		"unlock_failure":                true,
		"session_revoked":               true,
		"setup_admin_created":           true,
		"password_changed":              true,
		"route_created":                 true,
		"route_updated":                 true,
		"route_deleted":                 true,
		"route_disabled":                true,
		"route_enabled":                 true,
		"cert_deleted":                  true,
		"route_maintenance_on":          true,
		"route_maintenance_off":         true,
		"audit_viewed":                  true,
		"password_hibp_clean":           true,
		"password_hibp_pending":         true,
		"password_compromised_detected": true,
		"dns_provider_updated":          true,
		// v2.11 multi-config DNS providers (+2).
		"dns_provider_created":          true,
		"dns_provider_deleted":          true,
		"forward_auth_provider_updated": true,
		"forward_auth_provider_deleted": true,
		"oidc_configured":               true,
		"oidc_updated":                  true,
		"oidc_login_rejected":           true,
		"oidc_callback_invalid":         true,
		"login_break_glass":             true,
		"local_admin_password_rotated":  true,
		"user_role_changed":             true,
		"config_exported":               true,
		"config_restored":               true,
		"config_restored_rejected":      true,
		// Step O.3 (+2) — managed-domain CRUD audit events.
		"managed_domain_created": true,
		"managed_domain_deleted": true,
		// Step P.3 (+2) — auto-classify lifecycle audit events.
		"automation_decision_pushed": true,
		"automation_rule_changed":    true,
		// Step V.4 (+2) — server geographic position admin
		// events. Updated emitted by PUT (manual override);
		// Redetected emitted by POST :redetect (re-run V.1
		// auto-detect).
		"server_position_updated":    true,
		"server_position_redetected": true,
		// Step CS.1 (+2) — CrowdSec bouncer config admin
		// events. Configured emitted on first PUT;
		// Updated emitted on subsequent PUTs.
		"crowdsec_configured": true,
		"crowdsec_updated":    true,
		// Step CS.2 follow-up (+1) — operator-pressed
		// Reset button on Settings UI. Distinct from
		// crowdsec_updated to make the deliberate
		// "bouncer disabled" intent visible in /audit.
		"crowdsec_reset": true,
		// Step CS.3 Commit C (+1) — operator-pressed
		// "Bannir une IP" button on the Décisions actives
		// tab. POST creates a manual ban via Security
		// Automation machine creds; encodes
		// "manual:<username>|<reason>" into Decision.scenario.
		"crowdsec_decision_create": true,
		// Unban (+1) — DELETE of one LAPI decision from the
		// Live LAPI table; the counterpart of the manual ban.
		"crowdsec_decision_delete": true,
		// Step CS.3 follow-up (+1) — operator-pressed
		// "Reset Security Automation" button on Settings
		// UI. Mirror of crowdsec_reset: distinct from
		// automation_rule_changed so the deliberate
		// "auto-writer disabled" intent is visible in /audit.
		"automation_reset": true,
		// Users-page Phase 1 refactor (+1) — DELETE
		// /api/v1/admin/users/{id} emits this on success.
		// Last-admin guard rejects before the audit fires.
		"user_deleted": true,
		// Phase 4 (+3) — service-account lifecycle audit
		// events. The plain token is NEVER stored in the
		// audit row; only the metadata (name, role, expiry
		// presence) and the human admin who pressed the
		// button.
		"service_account_created":       true,
		"service_account_token_rotated": true,
		"service_account_deleted":       true,
		// Step AL.1.a (+3) — alerting channel lifecycle.
		// Wired in AL.1.c when the CRUD HTTP handlers
		// land; constants ship now so the audit count
		// test stays stable across the AL.1.b → AL.1.c
		// gap.
		"alert_channel_created": true,
		"alert_channel_updated": true,
		"alert_channel_deleted": true,
		// Step AL.3b (+3) — alerting rule lifecycle.
		// Wired by internal/api/alerting_rules.go CRUD
		// handlers; templates are operator-supplied
		// text/template strings (not secret-bearing) so
		// audit before/after carries the full diff.
		"alert_rule_created": true,
		"alert_rule_updated": true,
		"alert_rule_deleted": true,
		// Step R (+3) — operator-defined HTML error page
		// templates. Body content is operator-typed HTML
		// (not secret-bearing) so audit before/after carries
		// the full diff. Wired by internal/api/error_templates.go
		// CRUD handlers.
		"error_template_created": true,
		"error_template_updated": true,
		"error_template_deleted": true,
		// MaxMind (+2) — GeoIP account credential admin events.
		// ConfigUpdated emitted by PUT /api/v1/settings/maxmind
		// (first write and subsequent updates); ConfigDeleted
		// emitted by DELETE. Mirror of CrowdSec CS.1: license
		// key scrubbed from before/after JSON.
		"maxmind_config_updated": true,
		"maxmind_config_deleted": true,
		// External certificates (+3) — v2.19.0. Operator-uploaded
		// TLS certs served via load_pem. Uploaded on POST, Updated
		// on PUT, Deleted on DELETE. The private key is NEVER in the
		// audit row (only the cert UUID as target_id).
		"external_cert_uploaded":      true,
		"external_cert_updated":       true,
		"external_cert_deleted":       true,
		"external_cert_csr_generated": true,
		"backup_schedule_updated":     true,
		"backup_deleted":              true,
		"route_update_rolled_back":    true,
		"route_check_updated":         true,
		// TCP (layer 4) services (+3) — v2.42. A relay exposes a
		// port on this host, which is as much a change to what the
		// machine answers on the network as an HTTP route is.
		"tcp_service_created": true,
		"tcp_service_updated": true,
		"tcp_service_deleted": true,
		// Creating a local user (+1) — v2.48. An administrator
		// minting an account that can sign in, with a role, is a
		// privilege change; the event names actor, username, role
		// and auth source, and carries no password material.
		"user_created": true,
		// Turning the HTTP access log on or off (+1) — v2.50. It
		// decides whether every visitor's IP and URL is written to
		// disk, so both directions belong in the trail: enabling it
		// starts recording people, disabling it blinds CrowdSec.
		"access_log_updated": true,
		// v2.56 — the diagnostic probes. Creating a route to reach an
		// address is audited; a Test button was not, which made it the
		// quiet way to find out what answers on an internal address.
		// The refusal is recorded too: an attempt at the metadata
		// endpoint is worth more than its absence.
		"probe_upstream":     true,
		"probe_health_check": true,
		"probe_refused":      true,
	}
	for _, a := range AllActions() {
		if !want[a] {
			t.Errorf("unexpected action %q (not in D7)", a)
		}
		delete(want, a)
	}
	for missing := range want {
		t.Errorf("missing action %q from AllActions", missing)
	}
}
