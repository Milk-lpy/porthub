package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestUsersListDoesNotReturnSecrets(t *testing.T) {
	restore := testUsersDB(t)
	defer restore()
	db.Exec("insert into users(username,passhash,totp,role,must_change) values('rootish','hash','secret','super_admin',0)")

	res := httptest.NewRecorder()
	users(res, httptest.NewRequest(http.MethodGet, "/api/users", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", res.Code)
	}
	if bytes.Contains(res.Body.Bytes(), []byte("secret")) || bytes.Contains(res.Body.Bytes(), []byte("hash")) {
		t.Fatalf("users response leaked secret material: %s", res.Body.String())
	}
}

func TestCreateUserReturnsOneTimeCredentials(t *testing.T) {
	restore := testUsersDB(t)
	defer restore()
	body := []byte(`{"username":"operator1","password":"strong-password-123","role":"operator"}`)

	res := httptest.NewRecorder()
	users(res, httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body)))
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status %d body=%s", res.Code, res.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["initial_password"] == "" || out["totp_secret"] == "" {
		t.Fatalf("missing one-time credentials: %+v", out)
	}
}

func TestCannotDeleteLastSuperAdmin(t *testing.T) {
	restore := testUsersDB(t)
	defer restore()
	db.Exec("insert into users(username,passhash,totp,role,must_change) values('only','hash','secret','super_admin',0)")

	res := httptest.NewRecorder()
	users(res, httptest.NewRequest(http.MethodDelete, "/api/users?id=1", nil))
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected rejection, got %d", res.Code)
	}
}

func TestTokenDeleteRevokes(t *testing.T) {
	restore := testUsersDB(t)
	defer restore()
	db.Exec("insert into api_tokens(name,token_hash,prefix,role,created_at,revoked) values('ci','hash','ph_ci','operator',datetime('now'),0)")

	res := httptest.NewRecorder()
	tokens(res, httptest.NewRequest(http.MethodDelete, "/api/tokens?id=1", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status %d", res.Code)
	}
	var revoked int
	db.QueryRow("select revoked from api_tokens where id=1").Scan(&revoked)
	if revoked != 1 {
		t.Fatal("token was not revoked")
	}
}

func testUsersDB(t *testing.T) func() {
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
		`create table audit(ts text, actor text, action text, detail text)`,
		`create table api_tokens(id integer primary key, name text, token_hash text, prefix text, role text, created_at text, last_used_at text, revoked int)`,
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
