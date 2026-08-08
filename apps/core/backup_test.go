package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestCreateCoreBackupAndList(t *testing.T) {
	restore := testBackupEnv(t)
	defer restore()
	info, err := createCoreBackup()
	if err != nil {
		t.Fatal(err)
	}
	if info.Name == "" || info.Size == 0 {
		t.Fatalf("unexpected backup info: %+v", info)
	}
	items, err := listBackups()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != info.Name {
		t.Fatalf("unexpected backup list: %+v", items)
	}
	if !tarContains(t, info.Path, "core/core.db") || !tarContains(t, info.Path, "core/certs/7-app.key") || !tarContains(t, info.Path, "manifest.json") {
		t.Fatalf("backup missing expected files")
	}
}

func TestBackupRestorePlanIsReadOnly(t *testing.T) {
	restore := testBackupEnv(t)
	defer restore()
	info, err := createCoreBackup()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dataDir, "after-backup.marker")
	if err := os.WriteFile(marker, []byte("must-stay"), 0600); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"` + info.Name + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/backups/restore/plan", bytes.NewReader(body))
	res := httptest.NewRecorder()
	backupRestorePlan(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("restore plan failed: %d %s", res.Code, res.Body.String())
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("restore plan modified data directory: %v", err)
	}
	if bytes.Contains(res.Body.Bytes(), []byte(`"execute":true`)) {
		t.Fatalf("restore plan must not execute: %s", res.Body.String())
	}
}

func TestSafeBackupPathRejectsTraversal(t *testing.T) {
	old := backupDir
	backupDir = t.TempDir()
	defer func() { backupDir = old }()
	if _, err := safeBackupPath("../core.tar.gz"); err == nil {
		t.Fatal("expected traversal rejection")
	}
	if _, err := safeBackupPath("core.txt"); err == nil {
		t.Fatal("expected suffix rejection")
	}
	if path, err := safeBackupPath("core-20260731.tar.gz"); err != nil || filepath.Dir(path) != backupDir {
		t.Fatalf("unexpected safe path %q %v", path, err)
	}
}

func testBackupEnv(t *testing.T) func() {
	t.Helper()
	oldDB, oldData, oldBackup := db, dataDir, backupDir
	root := t.TempDir()
	dataDir = filepath.Join(root, "core")
	backupDir = filepath.Join(root, "backups")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	db, err = sql.Open("sqlite3", filepath.Join(dataDir, "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("create table smoke(id integer primary key, name text); insert into smoke(name) values('ok')"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ed25519.key", "ed25519.pub", "tls.crt", "tls.key"} {
		if err := os.WriteFile(filepath.Join(dataDir, name), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "certs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "certs", "7-app.key"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	return func() {
		db.Close()
		db, dataDir, backupDir = oldDB, oldData, oldBackup
	}
}

func tarContains(t *testing.T, path, name string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			return false
		}
		if h.Name == name {
			return true
		}
	}
}

func TestBackupEmbedsRestoreScript(t *testing.T) {
	restore := testBackupEnv(t)
	defer restore()
	info, err := createCoreBackup()
	if err != nil {
		t.Fatal(err)
	}
	if !info.HasScript {
		t.Fatal("backup should report HasScript=true")
	}
	if !tarContains(t, info.Path, "restore.sh") {
		t.Fatal("backup archive must embed restore.sh")
	}
	// restore.sh must be a shell script with manifest verification.
	f, err := os.Open(info.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatal("restore.sh not found in archive")
		}
		if h.Name != "restore.sh" {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"verifying MANIFEST", "sha256sum", "pre-restore", "usage: sh restore.sh"} {
			if !bytes.Contains(body, []byte(want)) {
				t.Fatalf("restore.sh missing %q", want)
			}
		}
		return
	}
}
