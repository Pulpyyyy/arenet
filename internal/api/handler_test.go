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
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeReloader records ReloadFromStore calls and can be primed to return an
// error to exercise the rollback paths.
type fakeReloader struct {
	mu      sync.Mutex
	calls   int
	nextErr error
	// onReload, when set, runs on every reload (e.g. to simulate the
	// client connection dying during a Caddy reload).
	onReload func()
}

func (f *fakeReloader) ReloadFromStore(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.onReload != nil {
		f.onReload()
	}
	return f.nextErr
}

func (f *fakeReloader) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeReloader) SetNextErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextErr = err
}

// fakeAuditAppender records Append calls for assertion. Safe for
// concurrent use; mirrors the interface defined in handler.go.
type fakeAuditAppender struct {
	mu      sync.Mutex
	events  []audit.Event
	nextErr error
}

func (f *fakeAuditAppender) Append(ctx context.Context, evt audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, evt)
	return f.nextErr
}

// List returns a copy of the captured events. Pagination is minimal
// (Limit honored, Cursor ignored) — sufficient for handler tests
// that don't exercise cursor behavior. Filter fields ActorUserID,
// Action, TargetType, TargetID are applied; From/To are honored.
func (f *fakeAuditAppender) List(_ context.Context, filter audit.Filter) ([]audit.Event, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Event, 0)
	for _, e := range f.events {
		if filter.ActorUserID != "" && e.ActorUserID != filter.ActorUserID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		if filter.TargetType != "" && e.TargetType != filter.TargetType {
			continue
		}
		if filter.TargetID != "" && e.TargetID != filter.TargetID {
			continue
		}
		if !filter.From.IsZero() && e.Timestamp.Before(filter.From) {
			continue
		}
		if !filter.To.IsZero() && !e.Timestamp.Before(filter.To) {
			continue
		}
		out = append(out, e)
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		out = out[:filter.Limit]
	}
	return out, "", nil
}

func (f *fakeAuditAppender) Events() []audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]audit.Event, len(f.events))
	copy(out, f.events)
	return out
}

func (f *fakeAuditAppender) SetNextErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextErr = err
}

type testEnv struct {
	router     http.Handler
	store      *storage.Store
	caddy      *fakeReloader
	audit      *fakeAuditAppender
	setupToken *SetupTokenHolder
	// handler is the underlying *Handler instance — exposed so
	// tests can call setters like SetUIOrigin without going
	// through the router. Tests that only drive HTTP via the
	// router can ignore it.
	handler *Handler
}

func newTestEnv(t *testing.T, dev bool) *testEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	caddy := &fakeReloader{}
	auditAppender := &fakeAuditAppender{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Step D dependencies. Tests that don't exercise auth flows
	// receive functional but defaulted instances. HIBP is disabled
	// via env var so no network calls are made; the env scope is
	// limited to this t via t.Setenv.
	t.Setenv("ARENET_HIBP_DISABLED", "true")
	userStore := auth.NewUserStore(store.DB())
	sessionStore := auth.NewSessionStore(store.DB())
	hibpClient := auth.NewHIBPClient()
	rateLimiter := auth.NewRateLimiter(logger)
	setupTokenHolder := NewSetupTokenHolder()
	ipExtractor, _ := auth.NewIPExtractor("")

	h := NewHandler(store, caddy, auditAppender, userStore, sessionStore, hibpClient, rateLimiter, setupTokenHolder, dev, logger)
	rawRouter := NewRouter(h, dev, ipExtractor, nil /* ws topology */, nil /* topology snapshot */, nil /* topology stream */, nil /* ws geo events */)

	// Step C tests predate hard-auth gating on /routes; they hit the
	// router without a cookie. To avoid touching every Step C test,
	// we wrap the router: if a request has no arenet_session cookie,
	// we synthesize a freshly-bootstrapped admin session and inject it.
	// Step D auth tests (e.g., TestLogin*, TestSetup_403*) make their
	// own requests directly via the raw router via env.rawRouter or
	// by setting the cookie explicitly.
	autoAuth := newAutoAuthRouter(t, rawRouter, store, sessionStore, userStore)
	return &testEnv{
		router:     autoAuth,
		store:      store,
		caddy:      caddy,
		audit:      auditAppender,
		setupToken: setupTokenHolder,
		handler:    h,
	}
}

// newAutoAuthRouter wraps the raw router so any request lacking the
// arenet_session cookie gets one synthesized. The wrapper bootstraps
// a real admin user + session on first use and reuses the same
// session for subsequent unauthenticated requests within the same
// test. This preserves the Step C contract "every test starts with
// a working router" without forcing every test to bootstrap auth.
func newAutoAuthRouter(t *testing.T, raw http.Handler, store *storage.Store, ss *auth.SessionStore, us *auth.UserStore) http.Handler {
	t.Helper()
	var (
		ready         bool
		sessionCookie string
		mu            sync.Mutex
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Step D auth subtree: do not auto-authenticate; tests there
		// drive their own flow.
		if strings.HasPrefix(r.URL.Path, "/api/v1/auth") {
			raw.ServeHTTP(w, r)
			return
		}
		if _, err := r.Cookie(sessionCookieName); err == nil {
			raw.ServeHTTP(w, r)
			return
		}
		// Lazy bootstrap on first call without cookie.
		mu.Lock()
		if !ready {
			ctx := context.Background()
			u, err := us.Create(ctx, "tester", "Tester", "", "test-password-15c-xx")
			if err != nil {
				mu.Unlock()
				t.Fatalf("autoAuth: bootstrap user: %v", err)
			}
			sess, err := ss.Create(ctx, u.ID, false, "127.0.0.1", "test/1")
			if err != nil {
				mu.Unlock()
				t.Fatalf("autoAuth: bootstrap session: %v", err)
			}
			sessionCookie = sess.ID
			ready = true
		}
		mu.Unlock()
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionCookie})
		raw.ServeHTTP(w, r)
	})
}

func TestListRoutes_Empty(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got []routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if len(got) != 0 {
		t.Errorf("want empty list, got %d items", len(got))
	}
}

func TestListRoutes_Multiple(t *testing.T) {
	env := newTestEnv(t, false)
	ctx := context.Background()
	for _, h := range []string{"a.local", "b.local", "c.local"} {
		if _, err := env.store.CreateRoute(ctx, storage.Route{Host: h, Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin}); err != nil {
			t.Fatalf("seed %s: %v", h, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var got []routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 routes, got %d", len(got))
	}
	hosts := []string{got[0].Host, got[1].Host, got[2].Host}
	want := []string{"a.local", "b.local", "c.local"}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("got hosts=%v want=%v", hosts, want)
			break
		}
	}
}

func TestGetRoute_Found(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{Host: "g.local", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rec.Body)
	}
	if got.ID != created.ID || got.Host != "g.local" {
		t.Errorf("got=%+v", got)
	}
}

func TestGetRoute_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/00000000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "error") {
		t.Errorf("body missing error key: %s", rec.Body)
	}
}

func TestCreateRoute_Success(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"new.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reload calls = %d, want 1", env.caddy.CallCount())
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || got[0].Host != "new.local" {
		t.Errorf("store state: %+v", got)
	}
}

// Step I.1: redirectToHttps is a new wire field added with the
// ACME work. The default zero value (false) keeps the pre-Step-I.1
// behavior; explicit true must round-trip through create → store →
// response.
func TestCreateRoute_AcceptsRedirectToHTTPS(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"redir.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"redirectToHttps":true,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	// Store persists the field.
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || !got[0].RedirectToHTTPS {
		t.Errorf("store RedirectToHTTPS = %v; want true. routes=%+v", got[0].RedirectToHTTPS, got)
	}
	// Response includes the field.
	if !strings.Contains(rec.Body.String(), `"redirectToHttps":true`) {
		t.Errorf("response body missing redirectToHttps=true: %s", rec.Body)
	}
}

// --- Step I.3 — Alias hostnames -------------------------------------------

func TestCreateRoute_AcceptsAliases(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"primary.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":["alt1.local","alt2.local"],"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || len(got[0].Aliases) != 2 {
		t.Fatalf("aliases not persisted: routes=%+v", got)
	}
	if got[0].Aliases[0] != "alt1.local" || got[0].Aliases[1] != "alt2.local" {
		t.Errorf("aliases ordering wrong: %v", got[0].Aliases)
	}
	// Response wire shape: aliases must be present as an array.
	if !strings.Contains(rec.Body.String(), `"aliases":["alt1.local","alt2.local"]`) {
		t.Errorf("response missing aliases array: %s", rec.Body)
	}
}

func TestCreateRoute_RejectsInvalidAlias(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"primary.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":["not a hostname"],"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `not a hostname`) {
		t.Errorf("body should quote the offending alias: %s", rec.Body)
	}
}

func TestCreateRoute_RejectsIntraRouteDuplicate(t *testing.T) {
	env := newTestEnv(t, false)
	// Two identical aliases in the same request — defense-in-depth
	// before storage sees the route.
	body := `{"host":"primary.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":["dup.local","dup.local"],"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `duplicates within the same route`) {
		t.Errorf("body=%s", rec.Body)
	}
}

func TestCreateRoute_RejectsCrossRouteDuplicate(t *testing.T) {
	env := newTestEnv(t, false)
	// Seed an existing route with Host=x.com; a new route trying to
	// claim it as an alias must fail with a 409.
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{Host: "x.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"host":"other.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":["x.local"],"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409", rec.Code, rec.Body)
	}
	// Conflict message names BOTH the host and the owning route ID.
	if !strings.Contains(rec.Body.String(), `x.local`) || !strings.Contains(rec.Body.String(), seeded.ID) {
		t.Errorf("body should cite host + owner: %s", rec.Body)
	}
}

// --- Step I.5 — Basic Auth ------------------------------------------------

// TestCreateRoute_AcceptsBasicAuth_HashesPassword exercises the
// happy path: plaintext password goes IN via the request, the
// route is persisted with an argon2id PHC hash, the response carries
// basicAuth.passwordSet:true but NEVER the hash or plaintext.
func TestCreateRoute_AcceptsBasicAuth_HashesPassword(t *testing.T) {
	env := newTestEnv(t, false)
	plain := "s3cret-pa$$"
	body := `{"host":"auth.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"basic","basicAuth":{"username":"admin","password":"` + plain + `"},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	// Store: hash present, starts with $argon2id$ PHC marker.
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || got[0].BasicAuth.PasswordHash == "" {
		t.Fatalf("hash not persisted: %+v", got)
	}
	if !strings.HasPrefix(got[0].BasicAuth.PasswordHash, "$argon2id$") {
		t.Errorf("hash should be argon2id PHC; got %q", got[0].BasicAuth.PasswordHash)
	}
	// Response: passwordSet flag yes, plain absent, hash absent.
	respBody := rec.Body.String()
	if !strings.Contains(respBody, `"passwordSet":true`) {
		t.Errorf("response missing basicAuthPasswordSet:true: %s", respBody)
	}
	if strings.Contains(respBody, plain) {
		t.Errorf("response leaked plaintext password: %s", respBody)
	}
	if strings.Contains(respBody, "$argon2id$") {
		t.Errorf("response leaked hash PHC: %s", respBody)
	}
}

// TestCreateRoute_RejectsBasicAuthEnabledWithoutPassword catches the
// classic UI mistake of flipping the toggle but forgetting to type
// the credentials. Q6 in the audit.
func TestCreateRoute_RejectsBasicAuthEnabledWithoutPassword(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"auth.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"basic","basicAuth":{"username":"admin","password":""},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "basicAuth.password required") {
		t.Errorf("body=%s; want basicAuth.password-required message", rec.Body)
	}
}

// TestUpdateRoute_EmptyPasswordPreservesHash exercises the "Edit
// anything without re-typing the secret" UX (Q5). Empty password on
// PUT keeps the existing hash verbatim — re-hashing would invalidate
// every cached browser credential on the route.
func TestUpdateRoute_EmptyPasswordPreservesHash(t *testing.T) {
	env := newTestEnv(t, false)
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "auth.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		AuthMode: storage.RouteAuthBasic,
		BasicAuth: storage.BasicAuthRouteConfig{
			Username:     "admin",
			PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$SALTSALTSALTSALT$KEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEYKEY",
		},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	originalHash := seeded.BasicAuth.PasswordHash

	// PUT with basicAuth.password:"" — and a different upstream so we
	// know the update path actually ran. Step K.1 wire shape.
	body := `{"host":"auth.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"basic","basicAuth":{"username":"admin","password":""},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), seeded.ID)
	if got.BasicAuth.PasswordHash != originalHash {
		t.Errorf("hash was rotated despite empty password: before=%q after=%q", originalHash, got.BasicAuth.PasswordHash)
	}
	if got.Upstreams[0].URL != "http://127.0.0.1:9001" {
		t.Errorf("upstream not updated: %v", got)
	}
}

// TestAudit_BasicAuthHashNeverInAuditLog is the explicit F1 mitigation
// guard: when a route with Basic Auth is created / updated / deleted,
// the AfterJSON / BeforeJSON payloads embedded in the audit events
// must NOT contain the argon2id PHC string. Routes are passed through
// routeForAudit() before mustMarshalForAudit, which blanks the hash.
func TestAudit_BasicAuthHashNeverInAuditLog(t *testing.T) {
	env := newTestEnv(t, false)
	plain := "leaky-secret-3000"
	body := `{"host":"audit.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"basic","basicAuth":{"username":"admin","password":"` + plain + `"},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	// Find the route_created event we just emitted and assert the
	// AfterJSON payload contains no argon2id PHC marker.
	events := env.audit.Events()
	if len(events) == 0 {
		t.Fatal("no audit events captured")
	}
	var got *audit.Event
	for i := range events {
		if events[i].Action == audit.ActionRouteCreated {
			got = &events[i]
			break
		}
	}
	if got == nil {
		t.Fatal("route_created event not found")
	}
	if strings.Contains(string(got.AfterJSON), "$argon2id$") {
		t.Errorf("audit AfterJSON LEAKED argon2id PHC hash: %s", got.AfterJSON)
	}
	if strings.Contains(string(got.AfterJSON), plain) {
		t.Errorf("audit AfterJSON LEAKED plaintext password: %s", got.AfterJSON)
	}
}

// --- Step I.6 — Custom headers --------------------------------------------

// TestCreateRoute_AcceptsCustomHeaders exercises the happy path: a
// POST with both request- and response-header maps round-trips into
// storage and back out on the response (the API does NOT redact
// header values, per Q7).
func TestCreateRoute_AcceptsCustomHeaders(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"hdr.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{"X-Real-Foo":"bar"},"responseHeaders":{"X-Custom":"x"},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if got[0].RequestHeaders["X-Real-Foo"] != "bar" {
		t.Errorf("RequestHeaders not persisted: %v", got[0].RequestHeaders)
	}
	if got[0].ResponseHeaders["X-Custom"] != "x" {
		t.Errorf("ResponseHeaders not persisted: %v", got[0].ResponseHeaders)
	}
	if !strings.Contains(rec.Body.String(), `"X-Real-Foo":"bar"`) {
		t.Errorf("response missing request header: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"X-Custom":"x"`) {
		t.Errorf("response missing response header: %s", rec.Body)
	}
}

// TestCreateRoute_RejectsCRLFInHeaderValue is the F1 mitigation
// guard. A CR or LF in a header value would let an attacker inject
// arbitrary additional headers (or even a response body) by
// breaking HTTP framing. The API MUST reject before the value ever
// reaches Caddy's config or BoltDB.
func TestCreateRoute_RejectsCRLFInHeaderValue(t *testing.T) {
	env := newTestEnv(t, false)
	// Embedded \r\n in the header value (escaped as \\r\\n in the
	// JSON string literal so the decoder lands a real CR + LF in
	// the Go string).
	body := `{"host":"injection.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{"X-Injected":"ok\r\nEvil: foo"},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	// Message names the header AND explains the control-character
	// rejection — admin-friendly diagnostic.
	if !strings.Contains(rec.Body.String(), "X-Injected") || !strings.Contains(rec.Body.String(), "control character") {
		t.Errorf("body=%s; want X-Injected + control-character mention", rec.Body)
	}
}

// TestCreateRoute_RejectsInvalidHeaderKey: a key with a space is
// not a valid RFC 7230 token. The reject message identifies the
// offending key.
func TestCreateRoute_RejectsInvalidHeaderKey(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"badkey.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{"Bad Key":"value"},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "Bad Key") || !strings.Contains(rec.Body.String(), "RFC 7230") {
		t.Errorf("body=%s; want Bad Key + RFC 7230 mention", rec.Body)
	}
}

// TestCreateRoute_RejectsReservedHeaderName: a user that tries to
// override Host / Connection / etc. would break the proxying
// machinery. Reject with a clear message.
func TestCreateRoute_RejectsReservedHeaderName(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"reserved.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{"Host":"evil.example.com"},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "reserved") {
		t.Errorf("body=%s; want reserved-header mention", rec.Body)
	}
}

// --- Step I.4 — WAF mode --------------------------------------------------

func TestCreateRoute_AcceptsWAFModeDetect(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"waf-detect.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"detect"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || got[0].WAFMode != "detect" {
		t.Errorf("WAFMode = %v; want detect. routes=%+v", got[0].WAFMode, got)
	}
	if !strings.Contains(rec.Body.String(), `"wafMode":"detect"`) {
		t.Errorf("response missing wafMode:detect: %s", rec.Body)
	}
}

// TestCreateRoute_DefaultsToWAFModeDetect — POST with an empty (or
// absent) wafMode lands the route in "detect" per spec L6 / Q6 override.
// FortiWeb-style safe-shadow default makes the WAF observable before
// it ever blocks legitimate traffic.
func TestCreateRoute_DefaultsToWAFModeDetect(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"waf-default.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 || got[0].WAFMode != "detect" {
		t.Errorf("WAFMode = %v; want detect (default on POST). routes=%+v", got[0].WAFMode, got)
	}
}

// TestCreateRoute_RejectsInvalidWAFMode — anything outside the enum
// {off, detect, block} returns 400.
func TestCreateRoute_RejectsInvalidWAFMode(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"waf-bad.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"loud"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	// JSON-escaped quotes in the body (\"loud\") wouldn't match a
	// literal `"loud"` substring search — assert on the bare value
	// and the enum listing separately, same pattern as the I.3
	// duplicate-host test.
	if !strings.Contains(rec.Body.String(), `loud`) || !strings.Contains(rec.Body.String(), "off, detect, block") {
		t.Errorf("body=%s; want offending value + enum listing", rec.Body)
	}
}

// TestUpdateRoute_EmptyWAFModePreservesPrevious — Q6 override: empty
// wafMode on PUT means "keep the previously stored value", mirroring
// the I.5 password preserve UX.
func TestUpdateRoute_EmptyWAFModePreservesPrevious(t *testing.T) {
	env := newTestEnv(t, false)
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "waf-preserve.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		WAFMode: "block",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// PUT with empty wafMode — and a different upstream so we know
	// the update path actually ran.
	body := `{"host":"waf-preserve.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), seeded.ID)
	if got.WAFMode != "block" {
		t.Errorf("WAFMode lost on PUT: got %q, want %q (preserved)", got.WAFMode, "block")
	}
	if got.Upstreams[0].URL != "http://127.0.0.1:9001" {
		t.Errorf("upstream not updated: %v", got)
	}
}

// --- Step I.7 hotfix (Finding #5) — redirect-without-TLS normalize -------

// TestCreateRoute_NormalizesRedirectWhenTLSOff — a POST with
// tlsEnabled=false + redirectToHttps=true (the bug pattern that
// the frontend defaults made common) MUST land in storage as
// redirect=false. The defense lives at the API layer so direct
// curl callers bypassing the form get the same protection, and
// no latent redirect ever ships to BoltDB.
func TestCreateRoute_NormalizesRedirectWhenTLSOff(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"latent.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":true,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if got[0].RedirectToHTTPS {
		t.Errorf("RedirectToHTTPS persisted as true despite TLSEnabled=false (Finding #5 regression): %+v", got[0])
	}
	// Response wire shape also reflects the normalized value.
	if !strings.Contains(rec.Body.String(), `"redirectToHttps":false`) {
		t.Errorf("response did not echo normalized redirectToHttps:false: %s", rec.Body)
	}
}

// TestUpdateRoute_NormalizesRedirectWhenTLSOff — same invariant
// on PUT, plus the self-heal property: a legacy row persisted
// before the hotfix (redirect=true + tls=false) gets cleaned the
// next time it's updated, even if the PUT payload doesn't touch
// the redirect field explicitly.
func TestUpdateRoute_NormalizesRedirectWhenTLSOff(t *testing.T) {
	env := newTestEnv(t, false)
	// Seed a "legacy" row directly through the store — this
	// bypasses the API-layer normalize and produces the exact
	// pre-hotfix state Finding #5 catches.
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "heal.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		TLSEnabled:      false,
		RedirectToHTTPS: true, // the latent bug we want self-healed
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// PUT touching ONLY the upstream — payload still says
	// redirectToHttps:true (matching the legacy stored value),
	// tls stays false. The normalize at the top of updateRoute
	// must coerce redirect to false on the way out.
	body := `{"host":"heal.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":true,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), seeded.ID)
	if got.RedirectToHTTPS {
		t.Errorf("legacy redirect=true row not self-healed by PUT: %+v", got)
	}
	if got.Upstreams[0].URL != "http://127.0.0.1:9001" {
		t.Errorf("upstream not updated: %v", got)
	}
}

func TestUpdateRoute_AllowsKeepingSameAliases(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "primary.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		Aliases: []string{"alt.local"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// PUT with the exact same (Host + Aliases) must NOT trigger a
	// false-positive duplicate error — the hostnamesEqual short-circuit
	// is the guard against the obvious bug of "comparing to self".
	body := `{"host":"primary.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":["alt.local"],"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (no duplicate on self)", rec.Code, rec.Body)
	}
}

// Step I.1: an update flipping redirectToHttps back to false must
// persist the change (catches the bug of forgetting the field in
// updateRoute's storage.Route construction).
func TestUpdateRoute_PreservesRedirectToHTTPS(t *testing.T) {
	env := newTestEnv(t, false)
	// Seed: a route with redirect on.
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "flip.local", Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		TLSEnabled: true, RedirectToHTTPS: true,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"host":"flip.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"redirectToHttps":false,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, err := env.store.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.RedirectToHTTPS {
		t.Errorf("RedirectToHTTPS not flipped to false; got route = %+v", got)
	}
}

func TestCreateRoute_InvalidJSON(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestCreateRoute_ValidationErrors(t *testing.T) {
	tests := []struct {
		name, body, wantSub string
	}{
		{"empty host", `{"host":"","upstreams":[{"url":"http://x:1","weight":1}],"lbPolicy":"round_robin"}`, "host must not be empty"},
		{"whitespace host", `{"host":"a b","upstreams":[{"url":"http://x:1","weight":1}],"lbPolicy":"round_robin"}`, "must not contain whitespace"},
		{"bad scheme", `{"host":"a.local","upstreams":[{"url":"ftp://x","weight":1}],"lbPolicy":"round_robin"}`, "http or https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, false)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
			}
			if !strings.Contains(rec.Body.String(), tc.wantSub) {
				t.Errorf("body %q missing %q", rec.Body.String(), tc.wantSub)
			}
			if env.caddy.CallCount() != 0 {
				t.Errorf("reload should not have been called")
			}
		})
	}
}

func TestCreateRoute_DuplicateHost(t *testing.T) {
	env := newTestEnv(t, false)
	_, _ = env.store.CreateRoute(context.Background(), storage.Route{Host: "dup.local", Upstreams: []storage.Upstream{{URL: "http://x:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})

	body := `{"host":"dup.local","upstreams":[{"url":"http://x:2","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	// Step I.3: the conflict message now identifies BOTH the conflicting
	// hostname and the owning route ID (the wider check covers aliases too,
	// so the message must disambiguate which host triggered the collision).
	// The body is JSON, so the quotes around dup.local are backslash-
	// escaped — match the substring without the surrounding quotes.
	if !strings.Contains(rec.Body.String(), `dup.local`) || !strings.Contains(rec.Body.String(), `already configured`) {
		t.Errorf("body=%s", rec.Body)
	}
}

func TestCreateRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.SetNextErr(errors.New("simulated reload failure"))

	body := `{"host":"rb.local","upstreams":[{"url":"http://x:1","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 0 {
		t.Errorf("rollback failed: %d routes left", len(got))
	}
}

func TestUpdateRoute_Success(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "u.local", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})

	body := `{"host":"u.local","upstreams":[{"url":"http://u:2","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reload calls = %d", env.caddy.CallCount())
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.Upstreams[0].URL != "http://u:2" || !got.TLSEnabled {
		t.Errorf("not updated: %+v", got)
	}
}

func TestUpdateRoute_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"host":"x.local","upstreams":[{"url":"http://x:1","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/00000000-0000-0000-0000-000000000000", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload should not have been called on 404, got %d", env.caddy.CallCount())
	}
}

func TestUpdateRoute_HostCollision(t *testing.T) {
	env := newTestEnv(t, false)
	_, _ = env.store.CreateRoute(context.Background(), storage.Route{Host: "a.local", Upstreams: []storage.Upstream{{URL: "http://x:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})
	target, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "b.local", Upstreams: []storage.Upstream{{URL: "http://x:2", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})

	// Try to rename b.local → a.local (already taken).
	body := `{"host":"a.local","upstreams":[{"url":"http://x:2","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+target.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d", rec.Code)
	}
	got, _ := env.store.GetRoute(context.Background(), target.ID)
	if got.Host != "b.local" {
		t.Errorf("target was mutated: %+v", got)
	}
}

func TestUpdateRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "rb.local", Upstreams: []storage.Upstream{{URL: "http://old:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})

	env.caddy.SetNextErr(errors.New("simulated"))
	body := `{"host":"rb.local","upstreams":[{"url":"http://new:1","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.Upstreams[0].URL != "http://old:1" {
		t.Errorf("rollback failed: upstream=%q", got.Upstreams[0].URL)
	}
}

func TestDeleteRoute_Success(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "d.local", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reload calls = %d", env.caddy.CallCount())
	}
	if _, err := env.store.GetRoute(context.Background(), created.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestDeleteRoute_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/00000000-0000-0000-0000-000000000000", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload should not have been called on 404, got %d", env.caddy.CallCount())
	}
}

func TestDeleteRoute_ReloadFails_Rollback(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{Host: "rb.local", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin})

	env.caddy.SetNextErr(errors.New("simulated"))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
	got, err := env.store.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("rollback failed, GetRoute err=%v", err)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) || !got.UpdatedAt.Equal(created.UpdatedAt) {
		t.Errorf("RestoreRoute didn't preserve timestamps: got=%v want=%v", got, created)
	}
}

func TestCORS_DevMode_Preflight(t *testing.T) {
	env := newTestEnv(t, true) // dev=true

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/routes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Errorf("Allow-Methods=%q", got)
	}
	// Allow-Credentials must be "true" so the Vite dev server at :5173
	// can send the arenet_session cookie via fetch credentials:'include'.
	// Wildcard origins are incompatible with credentials, hence the
	// explicit allowOrigin in devCORS (verified above).
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials=%q want %q", got, "true")
	}
}

func TestCORS_ProdMode_NoHeader(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty in prod, got %q", got)
	}
}

func TestCORS_DevMode_ActualRequest(t *testing.T) {
	env := newTestEnv(t, true) // dev=true

	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin on GET in dev mode=%q, want http://localhost:5173", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age=%q on actual response, want 3600", got)
	}
	// Allow-Credentials must also be set on simple requests, not just
	// preflight, otherwise the browser rejects the response when fetch
	// uses credentials:'include'.
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials=%q want %q", got, "true")
	}
}

// TestCORS_DevMode_AuthMe_Preflight covers the exact path that surfaced
// the Allow-Credentials regression: the SvelteKit dev server at :5173
// polls /api/v1/auth/me with fetch credentials:'include' on every page
// load to bootstrap auth state. Without Allow-Credentials, the browser
// drops the response.
func TestCORS_DevMode_AuthMe_Preflight(t *testing.T) {
	env := newTestEnv(t, true)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/me", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Allow-Origin=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials=%q want %q", got, "true")
	}
}

// --- Audit emission on /routes mutations (spec §4 + D7 + Plan §4.4) -------
//
// The autoAuth wrapper bootstraps a `tester` user and adds a logout to
// the audit log for any subsequent /auth/logout call. Mutation tests
// below filter env.audit.Events() by Action prefix "route_" so they
// don't accidentally match other events emitted by middleware or by
// other handlers.

// routeEvents returns the subset of recorded audit events whose Action
// is one of route_created / route_updated / route_deleted.
func routeEvents(events []audit.Event) []audit.Event {
	out := make([]audit.Event, 0)
	for _, e := range events {
		switch e.Action {
		case audit.ActionRouteCreated, audit.ActionRouteUpdated, audit.ActionRouteDeleted:
			out = append(out, e)
		}
	}
	return out
}

func TestCreateRoute_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"audit-create.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := routeEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("route audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Action != audit.ActionRouteCreated {
		t.Errorf("Action=%q want %q", ev.Action, audit.ActionRouteCreated)
	}
	if ev.TargetType != "route" {
		t.Errorf("TargetType=%q want %q", ev.TargetType, "route")
	}
	// Read back the stored route to compare TargetID with the persisted id.
	stored, _ := env.store.ListRoutes(context.Background())
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored route, got %d", len(stored))
	}
	if ev.TargetID != stored[0].ID {
		t.Errorf("TargetID=%q want %q", ev.TargetID, stored[0].ID)
	}
	if ev.BeforeJSON != nil {
		t.Errorf("BeforeJSON should be nil on create, got %s", ev.BeforeJSON)
	}
	if len(ev.AfterJSON) == 0 {
		t.Fatalf("AfterJSON should be populated on create")
	}
	if !strings.Contains(string(ev.AfterJSON), "audit-create.local") {
		t.Errorf("AfterJSON missing host: %s", ev.AfterJSON)
	}
}

func TestUpdateRoute_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "audit-update.local", Upstreams: []storage.Upstream{{URL: "http://old:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})

	body := `{"host":"audit-update.local","upstreams":[{"url":"http://new:1","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := routeEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("route audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Action != audit.ActionRouteUpdated {
		t.Errorf("Action=%q want %q", ev.Action, audit.ActionRouteUpdated)
	}
	if ev.TargetID != created.ID {
		t.Errorf("TargetID=%q want %q", ev.TargetID, created.ID)
	}
	if len(ev.BeforeJSON) == 0 || !strings.Contains(string(ev.BeforeJSON), "http://old:1") {
		t.Errorf("BeforeJSON missing previous upstream: %s", ev.BeforeJSON)
	}
	if len(ev.AfterJSON) == 0 || !strings.Contains(string(ev.AfterJSON), "http://new:1") {
		t.Errorf("AfterJSON missing new upstream: %s", ev.AfterJSON)
	}
}

func TestDeleteRoute_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "audit-delete.local", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	events := routeEvents(env.audit.Events())
	if len(events) != 1 {
		t.Fatalf("route audit events = %d, want 1: %+v", len(events), events)
	}
	ev := events[0]
	if ev.Action != audit.ActionRouteDeleted {
		t.Errorf("Action=%q want %q", ev.Action, audit.ActionRouteDeleted)
	}
	if ev.TargetID != created.ID {
		t.Errorf("TargetID=%q want %q", ev.TargetID, created.ID)
	}
	if len(ev.BeforeJSON) == 0 || !strings.Contains(string(ev.BeforeJSON), "audit-delete.local") {
		t.Errorf("BeforeJSON missing deleted host: %s", ev.BeforeJSON)
	}
	if ev.AfterJSON != nil {
		t.Errorf("AfterJSON should be nil on delete, got %s", ev.AfterJSON)
	}
}

// The next three tests guard the D2 / Plan §4.4 invariant: when a
// Caddy reload fails, the storage rollback runs AND no audit event is
// emitted. The structural placement of appendAudit AFTER the reload
// branch is what makes this hold; this test catches any regression
// that moves the emission above the reload check.

func TestCreateRoute_ReloadFails_NoAudit(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.SetNextErr(errors.New("simulated reload failure"))

	body := `{"host":"noaudit-create.local","upstreams":[{"url":"http://x:1","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if events := routeEvents(env.audit.Events()); len(events) != 0 {
		t.Errorf("expected 0 route audit events on reload failure, got %d: %+v", len(events), events)
	}
}

func TestUpdateRoute_ReloadFails_NoAudit(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "noaudit-update.local", Upstreams: []storage.Upstream{{URL: "http://old:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})

	env.caddy.SetNextErr(errors.New("simulated reload failure"))
	body := `{"host":"noaudit-update.local","upstreams":[{"url":"http://new:1","weight":1}],"lbPolicy":"round_robin"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if events := routeEvents(env.audit.Events()); len(events) != 0 {
		t.Errorf("expected 0 route audit events on reload failure, got %d: %+v", len(events), events)
	}
}

func TestDeleteRoute_ReloadFails_NoAudit(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "noaudit-delete.local", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})

	env.caddy.SetNextErr(errors.New("simulated reload failure"))
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/routes/"+created.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if events := routeEvents(env.audit.Events()); len(events) != 0 {
		t.Errorf("expected 0 route audit events on reload failure, got %d: %+v", len(events), events)
	}
}

// --- Step J.1 — Upstream pool + LB policy handler-level invariants --------

// TestCreateRoute_DefaultsWeightWhenOmitted pins the
// materialise-before-validate ordering for Upstream.Weight. A POST
// with the pool element's weight omitted (or 0) must reach storage
// with weight=1, because storage.validate() rejects weight<1 — if
// the API stopped materialising the default, this test would 400.
func TestCreateRoute_DefaultsWeightWhenOmitted(t *testing.T) {
	env := newTestEnv(t, false)

	// JSON literal omits the weight field entirely; Go unmarshal
	// gives Weight=0 to the corresponding upstreamReq, which is the
	// exact zero-value case the API must materialise.
	body := `{"host":"wzero.local","upstreams":[{"url":"http://127.0.0.1:9000"}],"lbPolicy":"round_robin","wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (weight=0 should be materialised to 1)", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route stored, got %d", len(got))
	}
	if got[0].Upstreams[0].Weight != 1 {
		t.Errorf("Upstreams[0].Weight = %d; want 1 (default materialised by API)", got[0].Upstreams[0].Weight)
	}
}

// TestCreateRoute_DefaultsLBPolicyWhenOmitted pins the same
// materialise-before-validate ordering for LBPolicy. A POST with
// "lbPolicy" omitted (or empty) must reach storage with
// "round_robin" (§5.1 default).
func TestCreateRoute_DefaultsLBPolicyWhenOmitted(t *testing.T) {
	env := newTestEnv(t, false)

	// JSON literal omits the lbPolicy field entirely.
	body := `{"host":"lbzero.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (lbPolicy=\"\" should be materialised to round_robin)", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route stored, got %d", len(got))
	}
	if got[0].LBPolicy != storage.LBPolicyRoundRobin {
		t.Errorf("LBPolicy = %q; want %q (default materialised by API)", got[0].LBPolicy, storage.LBPolicyRoundRobin)
	}
}

// TestCreateRoute_RejectsEmptyUpstreamPool — §5.1 rule 1, handler
// level. Empty pool must come back as 400 (not 500, not a storage
// validate panic).
func TestCreateRoute_RejectsEmptyUpstreamPool(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"empty.local","upstreams":[],"lbPolicy":"round_robin","wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "at least one entry") {
		t.Errorf("body %q missing 'at least one entry'", rec.Body.String())
	}
	if env.caddy.CallCount() != 0 {
		t.Errorf("reload should not have been called on 400")
	}
}

// TestCreateRoute_RejectsNegativeWeight — §5.1 rule 3, handler
// level. A negative weight must come back as 400 with the indexed
// error message; weight=0 is materialised to 1 (covered by
// TestCreateRoute_DefaultsWeightWhenOmitted) so it does not hit
// this path.
func TestCreateRoute_RejectsNegativeWeight(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"wneg.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1},{"url":"http://127.0.0.1:9002","weight":-3}],"lbPolicy":"round_robin","wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	// JSON encoder escapes `>` as >, so we assert against the
	// non-special-char prefix (the indexed location + start of
	// message). Catches the regression "weight check not wired"
	// without coupling the test to the JSON-encoded form of >=.
	if !strings.Contains(rec.Body.String(), "upstreams[1].weight must be") {
		t.Errorf("body %q missing the indexed weight error", rec.Body.String())
	}
}

// TestCreateRoute_RejectsUnknownLBPolicy — §5.1 rule 2, handler
// level. An unknown policy value must come back as 400.
func TestCreateRoute_RejectsUnknownLBPolicy(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"badpolicy.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"magic_sauce","wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	// JSON encoder escapes `"` as \", so we assert on the
	// unambiguous middle of the message (no quote chars). Catches
	// the regression "policy enum not wired" without coupling the
	// test to the JSON-encoded form of double quotes.
	if !strings.Contains(rec.Body.String(), `magic_sauce`) || !strings.Contains(rec.Body.String(), `is not a valid policy`) {
		t.Errorf("body %q missing the not-a-valid-policy error", rec.Body.String())
	}
}

// TestUpdateRoute_EmptyLBPolicyPreservesPrevious — anti-silent-
// downgrade. A PUT with "lbPolicy":"" must preserve the previously
// stored non-default policy, mirroring the WAFMode preserve UX so
// an admin who toggles unrelated fields doesn't silently revert the
// policy to round_robin.
func TestUpdateRoute_EmptyLBPolicyPreservesPrevious(t *testing.T) {
	env := newTestEnv(t, false)
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "lb-preserve.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyLeastConn,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// PUT with empty lbPolicy — and a different upstream URL so we
	// know the update path actually ran.
	body := `{"host":"lb-preserve.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), seeded.ID)
	if got.LBPolicy != storage.LBPolicyLeastConn {
		t.Errorf("LBPolicy lost on PUT: got %q, want %q (preserved)", got.LBPolicy, storage.LBPolicyLeastConn)
	}
	if got.Upstreams[0].URL != "http://127.0.0.1:9001" {
		t.Errorf("upstream not updated (so the update path didn't actually run): %v", got)
	}
}

// --- Step J.2 — Active health check handler-level invariants --------------

// TestCreateRoute_DefaultsHealthCheckSubFieldsWhenEnabled pins the
// materialise-before-validate ordering for the five defaultable HC
// sub-fields. A POST with `healthCheck.enabled: true` and only
// `uri` supplied (the other five sub-fields zero) must reach
// storage with Method="GET", Interval="30s", Timeout="5s",
// Passes=1, Fails=1 — because storage.HealthCheck.validate()
// rejects an empty Method, non-positive Passes, etc.; if the API
// stopped materialising the defaults, this test would 400.
func TestCreateRoute_DefaultsHealthCheckSubFieldsWhenEnabled(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"hc-defaults.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","wafMode":"off",` +
		`"healthCheck":{"enabled":true,"uri":"/healthz"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (HC sub-field defaults must be materialised)", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route stored, got %d", len(got))
	}
	hc := got[0].HealthCheck
	if hc.Method != "GET" {
		t.Errorf("HC.Method = %q; want %q (default materialised)", hc.Method, "GET")
	}
	if hc.Interval != "30s" {
		t.Errorf("HC.Interval = %q; want %q (default materialised)", hc.Interval, "30s")
	}
	if hc.Timeout != "5s" {
		t.Errorf("HC.Timeout = %q; want %q (default materialised)", hc.Timeout, "5s")
	}
	if hc.Passes != 1 {
		t.Errorf("HC.Passes = %d; want 1 (default materialised)", hc.Passes)
	}
	if hc.Fails != 1 {
		t.Errorf("HC.Fails = %d; want 1 (default materialised)", hc.Fails)
	}
}

// TestCreateRoute_NormalisesHealthCheckMethod pins the §5.2
// uppercase write-back end-to-end: POST `method:"head"` →
// storage row carries `Method:"HEAD"`. Covers the chain
// API.materialise → storage.validate (strict GET/HEAD) →
// persistence → GET reads back "HEAD". This is the test that
// makes the API-normalise / storage-pure-grid contract
// load-bearing across the boundary.
func TestCreateRoute_NormalisesHealthCheckMethod(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"hc-method.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","wafMode":"off",` +
		`"healthCheck":{"enabled":true,"uri":"/healthz","method":"head"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (lowercase method should be uppercased)", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route stored, got %d", len(got))
	}
	if got[0].HealthCheck.Method != "HEAD" {
		t.Errorf("HC.Method = %q; want %q (API uppercased and persisted)", got[0].HealthCheck.Method, "HEAD")
	}
}

// TestCreateRoute_RejectsHealthCheckEmptyURI — §5.2 non-defaultable
// rule. Enabled=true + uri="" must come back as 400 with the
// camelCase friendly message.
func TestCreateRoute_RejectsHealthCheckEmptyURI(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"hc-uri.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","wafMode":"off",` +
		`"healthCheck":{"enabled":true,"uri":""}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "healthCheck.uri") {
		t.Errorf("body %q missing healthCheck.uri error", rec.Body.String())
	}
}

// TestCreateRoute_RejectsHealthCheckInvalidMethod — Method "POST"
// (non-GET, non-HEAD) must come back as 400. The materialiser
// uppercases first, so "post" and "POST" both reach the validator
// as "POST" and get rejected uniformly.
func TestCreateRoute_RejectsHealthCheckInvalidMethod(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"hc-method-bad.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","wafMode":"off",` +
		`"healthCheck":{"enabled":true,"uri":"/healthz","method":"POST"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "healthCheck.method") {
		t.Errorf("body %q missing healthCheck.method error", rec.Body.String())
	}
}

// TestCreateRoute_RejectsHealthCheckTimeoutNotLessThanInterval —
// §5.2 ordering rule. Timeout >= Interval must come back as 400.
func TestCreateRoute_RejectsHealthCheckTimeoutNotLessThanInterval(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"host":"hc-timeout.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","wafMode":"off",` +
		`"healthCheck":{"enabled":true,"uri":"/healthz","interval":"5s","timeout":"5s"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "timeout") {
		t.Errorf("body %q missing timeout error", rec.Body.String())
	}
}

// TestUpdateRoute_HealthCheckAbsentPreservesPrevious — THE
// load-bearing test for the (b) decision. A PUT without a
// `healthCheck` key on the wire MUST preserve the previously
// stored HC (Enabled=true with non-default custom values), not
// reset it to zero. Mirrors the BasicAuth / WAFMode preserve
// patterns. If a future regression changes
// routeRequest.HealthCheck from *healthCheckReq to value, the
// distinction nil-vs-zero disappears and this test fails.
func TestUpdateRoute_HealthCheckAbsentPreservesPrevious(t *testing.T) {
	env := newTestEnv(t, false)

	// Seed a route with a custom health-check setup directly via
	// storage (bypasses API; lets us seed any HC we want).
	seeded, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "hc-preserve.local",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		HealthCheck: storage.HealthCheck{
			Enabled:  true,
			URI:      "/custom/probe",
			Method:   "HEAD",
			Interval: "45s",
			Timeout:  "7s",
			Passes:   3,
			Fails:    5,
		},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// PUT with NO healthCheck key — only an unrelated change
	// (different upstream) so we know the update path actually ran.
	body := `{"host":"hc-preserve.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+seeded.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), seeded.ID)
	if got.Upstreams[0].URL != "http://127.0.0.1:9001" {
		t.Errorf("upstream not updated (so update path didn't actually run): %v", got)
	}
	// All seven non-default HC fields must be preserved verbatim.
	want := storage.HealthCheck{
		Enabled:  true,
		URI:      "/custom/probe",
		Method:   "HEAD",
		Interval: "45s",
		Timeout:  "7s",
		Passes:   3,
		Fails:    5,
	}
	// reflect.DeepEqual since v2.55: HealthCheck carries a Headers map,
	// so the struct is no longer comparable with ==.
	if !reflect.DeepEqual(got.HealthCheck, want) {
		t.Errorf("HealthCheck silently mutated by PUT without HC block:\ngot:  %+v\nwant: %+v",
			got.HealthCheck, want)
	}
}
