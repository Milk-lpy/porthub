package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestPrepareACMEHTTP01DryRun(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	result := prepareACMEHTTP01(certificateItem{
		ID:      1,
		Name:    "NAS",
		Domains: []string{"nas.example.com"},
		Mode:    "acme_http_01",
		Enabled: true,
	}, true)
	if !result.OK || !result.DryRun {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.KeyRef == "" || result.Webroot == "" || len(result.ChallengeRefs) != 1 {
		t.Fatalf("missing prepare paths: %+v", result)
	}
	if _, err := os.Stat(result.KeyRef); err == nil {
		t.Fatal("dry-run should not create private key")
	}
}

func TestPrepareACMEHTTP01WritesProtectedFiles(t *testing.T) {
	restore := testCertPrepareDB(t)
	defer restore()
	cert := certificateItem{
		ID:      7,
		Name:    "NAS",
		Domains: []string{"nas.example.com"},
		Mode:    "acme_http_01",
		Enabled: true,
	}
	result := prepareACMEHTTP01(cert, false)
	if !result.OK {
		t.Fatalf("unexpected blockers: %+v", result.Blockers)
	}
	st, err := os.Stat(result.KeyRef)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("unexpected key mode %o", st.Mode().Perm())
	}
	body, err := os.ReadFile(result.ChallengeRefs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "porthub-http-01-ready\n" {
		t.Fatalf("unexpected challenge body %q", string(body))
	}
	var status, keyRef string
	db.QueryRow("select status,key_ref from certificates where id=7").Scan(&status, &keyRef)
	if status != "prepared" || keyRef != result.KeyRef {
		t.Fatalf("certificate row not updated status=%q key=%q", status, keyRef)
	}
}

func TestPrepareACMEHTTP01BlocksWildcard(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	result := prepareACMEHTTP01(certificateItem{
		ID:      2,
		Name:    "Wildcard",
		Domains: []string{"*.example.com"},
		Mode:    "acme_http_01",
		Enabled: true,
	}, true)
	if result.OK || !containsBlocker(result.Blockers, "wildcard") {
		t.Fatalf("expected wildcard blocker: %+v", result)
	}
}

func testCertPrepareDB(t *testing.T) func() {
	t.Helper()
	oldDB, oldData := db, dataDir
	dataDir = t.TempDir()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`create table certificates(id integer primary key, name text, domains text, issuer text, mode text, status text, expires_at text, key_ref text, dns_provider_id int default 0, enabled int, created_at text, updated_at text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`insert into certificates(id,name,domains,mode,status,enabled) values(7,'NAS','["nas.example.com"]','acme_http_01','draft',1)`); err != nil {
		t.Fatal(err)
	}
	return func() {
		db.Close()
		db, dataDir = oldDB, oldData
	}
}

func TestSafeName(t *testing.T) {
	old := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = old }()
	if got := safeName("*.NAS Example.COM."); got != "nas-example.com" {
		t.Fatalf("unexpected safe name %q", got)
	}
	if got := safeCertFileName(certificateItem{Name: "!!!"}); got != "certificate" {
		t.Fatalf("unexpected fallback %q", got)
	}
	if err := validateUnderDataDir(filepath.Join(dataDir, "..", "bad")); err == nil {
		t.Fatal("expected data dir restriction")
	}
}
