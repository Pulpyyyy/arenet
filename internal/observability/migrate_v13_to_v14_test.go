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

package observability

import (
	"context"
	"strings"
	"testing"
)

// v2.56 — v13→v14 re-redacts the events already stored.
//
// Fixing the pattern protects what is recorded from now on. Events
// written before it may carry a live credential, and a secret in a
// database is not less of a secret for having been written last week.

// insertRawWafEvent writes a row the way a pre-v14 binary did: through
// SQL, bypassing the sink that would have redacted it.
func insertRawWafEvent(t *testing.T, s *Store, path, payload string) int64 {
	t.Helper()
	res, err := s.db.ExecContext(context.Background(), `INSERT INTO waf_event
		(ts, route_id, rule_id, category, severity, src_ip, request_method, request_path, payload_sample, action, status_code)
		VALUES (1790000000, 'r', '942100', 'SQLI', 2, '', 'GET', ?, ?, 'BLOCK', 403)`, path, payload)
	if err != nil {
		t.Fatalf("insert raw waf_event: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func readWafRow(t *testing.T, s *Store, id int64) (string, string) {
	t.Helper()
	var path, payload string
	err := s.db.QueryRowContext(context.Background(),
		`SELECT request_path, payload_sample FROM waf_event WHERE id = ?`, id).Scan(&path, &payload)
	if err != nil {
		t.Fatalf("read back row %d: %v", id, err)
	}
	return path, payload
}

// THE test, on the reported URI.
func TestMigrate_V13ToV14_RedactsStoredAccessToken(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	const leaked = "/notifications/hub?access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.thesignature"
	id := insertRawWafEvent(t, s, leaked, "Cookie: session=abc123")

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if err := migrateV13toV14(ctx, tx); err != nil {
		tx.Rollback()
		t.Fatalf("migrateV13toV14: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	path, payload := readWafRow(t, s, id)
	if strings.Contains(path, "eyJhbGciOiJIUzI1NiJ9") {
		t.Errorf("the stored access token survived the migration: %q", path)
	}
	if !strings.Contains(path, "[REDACTED]") {
		t.Errorf("request_path carries no redaction marker: %q", path)
	}
	if strings.Contains(payload, "abc123") {
		t.Errorf("the stored cookie survived: %q", payload)
	}
}

// Idempotent: running it twice changes nothing the second time, so a
// re-run after a restore is harmless.
func TestMigrate_V13ToV14_Idempotent(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	id := insertRawWafEvent(t, s, "/a?token=leaked", "")
	run := func() {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		if err := migrateV13toV14(ctx, tx); err != nil {
			tx.Rollback()
			t.Fatalf("migrate: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
	run()
	first, _ := readWafRow(t, s, id)
	run()
	second, _ := readWafRow(t, s, id)
	if first != second {
		t.Errorf("not idempotent: %q then %q", first, second)
	}
}

// A row with nothing to hide must come out byte-identical — an attack
// payload is what this store exists to keep.
func TestMigrate_V13ToV14_LeavesCleanRowsAlone(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	const probe = "/api?path=../etc/passwd"
	const payload = "ARGS:path=../etc/passwd"
	id := insertRawWafEvent(t, s, probe, payload)

	tx, _ := s.db.BeginTx(ctx, nil)
	if err := migrateV13toV14(ctx, tx); err != nil {
		tx.Rollback()
		t.Fatalf("migrate: %v", err)
	}
	tx.Commit()

	gotPath, gotPayload := readWafRow(t, s, id)
	if gotPath != probe {
		t.Errorf("an attack payload was rewritten: %q → %q", probe, gotPath)
	}
	if gotPayload != payload {
		t.Errorf("payload rewritten: %q → %q", payload, gotPayload)
	}
}

// An empty table must not error — a fresh install runs this too.
func TestMigrate_V13ToV14_EmptyTable(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	if _, err := s.db.ExecContext(ctx, `DELETE FROM waf_event`); err != nil {
		t.Fatalf("clear: %v", err)
	}
	tx, _ := s.db.BeginTx(ctx, nil)
	if err := migrateV13toV14(ctx, tx); err != nil {
		tx.Rollback()
		t.Fatalf("migrate on an empty table: %v", err)
	}
	tx.Commit()
}
