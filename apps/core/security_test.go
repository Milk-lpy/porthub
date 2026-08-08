package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"porthub/internal/auth"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestBearerTokenAuth(t *testing.T) {
	restore := testTokenDB(t)
	defer restore()
	raw := "ph_test_token"
	db.Exec("insert into api_tokens(name,token_hash,prefix,role,created_at,revoked) values(?,?,?,?,datetime('now'),0)", "ci", hashToken(raw), "ph_test", "operator")

	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(actor(r)))
	})
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	res := httptest.NewRecorder()
	handler(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", res.Code)
	}
	if res.Body.String() != "api_token:ph_test" {
		t.Fatalf("unexpected actor %q", res.Body.String())
	}
	var last string
	db.QueryRow("select last_used_at from api_tokens where prefix='ph_test'").Scan(&last)
	if last == "" {
		t.Fatal("last_used_at was not updated")
	}
}

func TestReadonlyBearerTokenCannotMutate(t *testing.T) {
	restore := testTokenDB(t)
	defer restore()
	raw := "ph_readonly_token"
	db.Exec("insert into api_tokens(name,token_hash,prefix,role,created_at,revoked) values(?,?,?,?,datetime('now'),0)", "ro", hashToken(raw), "ph_ro", "readonly")

	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mappings", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	res := httptest.NewRecorder()
	handler(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("unexpected status %d", res.Code)
	}
}

func TestReadonlySessionCannotMutate(t *testing.T) {
	restore := testSessionDB(t)
	defer restore()
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})
	req := httptest.NewRequest(http.MethodPost, "/api/mappings", nil)
	req.AddCookie(&http.Cookie{Name: "ph_session", Value: "sid"})
	req.Header.Set("X-CSRF-Token", "csrf")
	res := httptest.NewRecorder()
	handler(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("unexpected status %d", res.Code)
	}
}

func TestOperatorRBACBoundaries(t *testing.T) {
	restore := testTokenDB(t)
	defer restore()
	raw := "ph_operator_token"
	db.Exec("insert into api_tokens(name,token_hash,prefix,role,created_at,revoked) values(?,?,?,?,datetime('now'),0)", "ops", hashToken(raw), "ph_ops", "operator")
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })

	for _, tc := range []struct {
		path string
		want int
	}{
		{"/api/mappings", http.StatusNoContent},
		{"/api/deploy", http.StatusNoContent},
		{"/api/acl-rules", http.StatusForbidden},
		{"/api/users", http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+raw)
		res := httptest.NewRecorder()
		handler(res, req)
		if res.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.path, res.Code, tc.want)
		}
	}
}

func TestAdminCannotManageUsers(t *testing.T) {
	restore := testTokenDB(t)
	defer restore()
	raw := "ph_admin_token"
	db.Exec("insert into api_tokens(name,token_hash,prefix,role,created_at,revoked) values(?,?,?,?,datetime('now'),0)", "admin", hashToken(raw), "ph_admin", "admin")
	handler := requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+raw)
	res := httptest.NewRecorder()
	handler(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("admin user management should be forbidden, got %d", res.Code)
	}
}

func TestAdminCannotCreateSuperAdminToken(t *testing.T) {
	restore := testTokenDB(t)
	defer restore()
	if _, err := db.Exec(`create table audit(ts text, actor text, action text, detail text)`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/tokens", bytes.NewReader([]byte(`{"name":"bad","role":"super_admin"}`)))
	ctx := context.WithValue(req.Context(), actorKey, "admin-user")
	ctx = context.WithValue(ctx, roleKey, "admin")
	req = req.WithContext(ctx)
	res := httptest.NewRecorder()
	tokens(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("expected admin escalation to be forbidden, got %d %s", res.Code, res.Body.String())
	}
}

func TestSessionStatusRestoresCSRFAndRole(t *testing.T) {
	restore := testSessionDB(t)
	defer restore()
	handler := requireAuth(sessionStatus)
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.AddCookie(&http.Cookie{Name: "ph_session", Value: "sid"})
	res := httptest.NewRecorder()
	handler(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("session restore failed: %d %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"csrf":"csrf"`) || !strings.Contains(res.Body.String(), `"role":"readonly"`) {
		t.Fatalf("unexpected session response: %s", res.Body.String())
	}
}

func TestLoginRateLimit(t *testing.T) {
	restore := testLoginDB(t)
	defer restore()
	loginLimits.Lock()
	loginLimits.entries = map[string]loginAttempt{}
	loginLimits.Unlock()

	for i := 0; i < loginFailureLimit; i++ {
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"Username":"missing","Password":"bad"}`)))
		req.RemoteAddr = "192.0.2.10:12345"
		login(res, req)
		if res.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d got %d", i+1, res.Code)
		}
	}
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"Username":"missing","Password":"bad"}`)))
	req.RemoteAddr = "192.0.2.10:54321"
	login(res, req)
	if res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") == "" {
		t.Fatalf("expected rate limit, got %d headers=%v", res.Code, res.Header())
	}
}

func TestLoginRememberedDeviceAllowsMissingTOTP(t *testing.T) {
	restore := testLoginDB(t)
	defer restore()
	secret := auth.NewTOTPSecret()
	passhash, _ := auth.HashPassword("strong-password-123")
	db.Exec("insert into users(username,passhash,totp,role,must_change) values(?,?,?,?,0)", "admin", passhash, secret, "super_admin")
	code, _ := auth.TOTP(secret, time.Now())

	res := httptest.NewRecorder()
	body := bytes.NewReader([]byte(`{"Username":"admin","Password":"strong-password-123","TOTP":"` + code + `","RememberDevice":true}`))
	login(res, httptest.NewRequest(http.MethodPost, "/api/login", body))
	if res.Code != http.StatusOK {
		t.Fatalf("first login failed: %d %s", res.Code, res.Body.String())
	}
	var trusted *http.Cookie
	for _, c := range res.Result().Cookies() {
		if c.Name == trustedDeviceCookie {
			trusted = c
		}
	}
	if trusted == nil {
		t.Fatal("trusted device cookie was not set")
	}

	res = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"Username":"admin","Password":"strong-password-123"}`)))
	req.AddCookie(trusted)
	login(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("trusted login failed: %d %s", res.Code, res.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["trusted_device"] != true {
		t.Fatalf("trusted_device flag missing: %+v", out)
	}
}

func TestLoginRejectedWhenTrustedDeviceRevoked(t *testing.T) {
	restore := testLoginDB(t)
	defer restore()
	secret := auth.NewTOTPSecret()
	passhash, _ := auth.HashPassword("strong-password-123")
	db.Exec("insert into users(username,passhash,totp,role,must_change) values(?,?,?,?,0)", "admin", passhash, secret, "super_admin")
	raw := "remember-me"
	db.Exec("insert into trusted_devices(username,token_hash,user_agent,created_at,expires_at,revoked) values(?,?,?,?,?,1)", "admin", hashToken(raw), "test", time.Now().Format(time.RFC3339), time.Now().Add(time.Hour).Unix())

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(`{"Username":"admin","Password":"strong-password-123"}`)))
	req.AddCookie(&http.Cookie{Name: trustedDeviceCookie, Value: raw})
	login(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("revoked trusted device should fail, got %d", res.Code)
	}
}

func testTokenDB(t *testing.T) func() {
	t.Helper()
	oldDB := db
	nextDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = nextDB
	if _, err := db.Exec(`create table api_tokens(id integer primary key, name text, token_hash text, prefix text, role text, created_at text, last_used_at text, revoked int)`); err != nil {
		t.Fatal(err)
	}
	return func() {
		db.Close()
		db = oldDB
	}
}

func testSessionDB(t *testing.T) func() {
	t.Helper()
	oldDB := db
	nextDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = nextDB
	for _, stmt := range []string{
		`create table users(id integer primary key, username text unique, passhash text, totp text, role text, must_change int)`,
		`create table sessions(id text primary key, username text, csrf text, expires_at integer)`,
		`insert into users(username,role,must_change) values('reader','readonly',0)`,
		`insert into sessions(id,username,csrf,expires_at) values('sid','reader','csrf',4102444800)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		db.Close()
		db = oldDB
	}
}

func testLoginDB(t *testing.T) func() {
	t.Helper()
	oldDB := db
	nextDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = nextDB
	for _, stmt := range []string{
		`create table users(id integer primary key, username text unique, passhash text, totp text, role text, must_change int)`,
		`create table sessions(id text primary key, username text, csrf text, expires_at integer)`,
		`create table trusted_devices(id integer primary key, username text, token_hash text unique, user_agent text, created_at text, expires_at integer, last_used_at text, revoked int default 0)`,
		`create table audit(ts text, actor text, action text, detail text)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	return func() {
		db.Close()
		db = oldDB
	}
}
