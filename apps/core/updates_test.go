package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"porthub/internal/updater"
	"runtime"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestUpdateStageVerifiesManifestAndArtifact(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	for _, statement := range []string{
		`create table update_events(id integer primary key,ts text,status text,version text,component text,message text)`,
		`create table audit(ts text,actor text,action text,detail text)`,
	} {
		if _, err := testDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	binary := []byte("verified-porthub-core")
	digest := sha256.Sum256(binary)
	manifest, err := updater.Sign(updater.Manifest{
		Version: "1.2.3", PublishedAt: time.Now().UTC(), Notes: "test release",
		Artifacts: []updater.Artifact{{Component: "core", OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://updates.example/core", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(binary))}},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	manifestBody, _ := json.Marshal(manifest)
	temporary := t.TempDir()
	publicKeyPath := filepath.Join(temporary, "update.pub")
	if err := os.WriteFile(publicKeyPath, []byte(base64.StdEncoding.EncodeToString(publicKey)), 0600); err != nil {
		t.Fatal(err)
	}

	oldDB, oldURL, oldKey, oldStage, oldFactory := db, updateManifestURL, updatePublicKeyPath, updateStageDir, updateHTTPClientFactory
	db, updateManifestURL, updatePublicKeyPath, updateStageDir = testDB, "https://updates.example/manifest.json", publicKeyPath, filepath.Join(temporary, "stage")
	updateHTTPClientFactory = func(string) (*http.Client, error) {
		return &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			body := manifestBody
			if strings.HasSuffix(request.URL.Path, "/core") {
				body = binary
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
		})}, nil
	}
	defer func() {
		db, updateManifestURL, updatePublicKeyPath, updateStageDir, updateHTTPClientFactory = oldDB, oldURL, oldKey, oldStage, oldFactory
	}()

	request := httptest.NewRequest(http.MethodPost, "/api/updates/stage", strings.NewReader(`{"component":"core"}`))
	recorder := httptest.NewRecorder()
	updatesStage(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stage failed: %d %s", recorder.Code, recorder.Body.String())
	}
	stagedPath := filepath.Join(updateStageDir, "1.2.3", "core", "porthub-core")
	staged, err := os.ReadFile(stagedPath)
	if err != nil || !bytes.Equal(staged, binary) {
		t.Fatalf("staged artifact mismatch: %v", err)
	}
	info, _ := os.Stat(stagedPath)
	if info.Mode().Perm() != 0750 {
		t.Fatalf("unexpected staged mode: %o", info.Mode().Perm())
	}
	var status string
	if err := db.QueryRow("select status from update_events order by id desc limit 1").Scan(&status); err != nil || status != "staged" {
		t.Fatalf("stage event missing status=%q err=%v", status, err)
	}
}

func TestUpdateCheckRequiresConfiguredTrust(t *testing.T) {
	oldURL, oldKey := updateManifestURL, updatePublicKeyPath
	updateManifestURL, updatePublicKeyPath = "", ""
	defer func() { updateManifestURL, updatePublicKeyPath = oldURL, oldKey }()
	if _, _, err := fetchUpdateManifest(); err == nil {
		t.Fatal("unconfigured update trust accepted")
	}
}
