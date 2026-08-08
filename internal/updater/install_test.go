package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type installFixture struct {
	root      string
	target    string
	staged    string
	oldBinary []byte
	newBinary []byte
}

func newInstallFixture(t *testing.T) installFixture {
	t.Helper()
	root := t.TempDir()
	oldBinary := []byte("old-porthub-core")
	newBinary := []byte("new-porthub-core")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(newBinary)
	manifest, err := Sign(Manifest{
		Version: "1.2.3", PublishedAt: time.Now().UTC(),
		Artifacts: []Artifact{{Component: "core", OS: runtime.GOOS, Arch: runtime.GOARCH, URL: "https://updates.example/core", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(newBinary))}},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	manifestBody, _ := json.Marshal(manifest)
	target := rooted(root, "/opt/porthub/bin/porthub-core")
	staged := rooted(root, "/var/lib/porthub/updates/1.2.3/core/porthub-core")
	for path, body := range map[string][]byte{
		target: oldBinary,
		staged: newBinary,
		rooted(root, "/var/lib/porthub/updates/1.2.3/core/manifest.json"): manifestBody,
		rooted(root, "/etc/porthub/update-signing.pub"):                   []byte(base64.StdEncoding.EncodeToString(publicKey)),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return installFixture{root: root, target: target, staged: staged, oldBinary: oldBinary, newBinary: newBinary}
}

func TestInstallDryRunAndSuccess(t *testing.T) {
	fixture := newInstallFixture(t)
	dryRun, err := Install(InstallOptions{Root: fixture.root, Version: "1.2.3", Component: "core"})
	if err != nil || !dryRun.DryRun {
		t.Fatalf("dry-run failed result=%+v err=%v", dryRun, err)
	}
	if body, _ := os.ReadFile(fixture.target); string(body) != string(fixture.oldBinary) {
		t.Fatal("dry-run changed installed binary")
	}
	restarts := 0
	result, err := Install(InstallOptions{
		Root: fixture.root, Version: "1.2.3", Component: "core", Execute: true,
		Restart: func(string) error { restarts++; return nil }, Healthy: func(string) error { return nil },
		Now: func() time.Time { return time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil || result.DryRun || result.BackupDir == "" || result.RolledBack || restarts != 1 {
		t.Fatalf("install failed result=%+v restarts=%d err=%v", result, restarts, err)
	}
	if body, _ := os.ReadFile(fixture.target); string(body) != string(fixture.newBinary) {
		t.Fatal("new binary not installed")
	}
	if body, _ := os.ReadFile(filepath.Join(result.BackupDir, "porthub-core")); string(body) != string(fixture.oldBinary) {
		t.Fatal("old binary backup missing")
	}
}

func TestInstallHealthFailureRollsBack(t *testing.T) {
	fixture := newInstallFixture(t)
	restarts := 0
	result, err := Install(InstallOptions{
		Root: fixture.root, Version: "1.2.3", Component: "core", Execute: true,
		Restart: func(string) error { restarts++; return nil }, Healthy: func(string) error { return errors.New("not ready") },
	})
	if err == nil || !result.RolledBack || restarts != 2 {
		t.Fatalf("rollback not reported result=%+v restarts=%d err=%v", result, restarts, err)
	}
	if body, _ := os.ReadFile(fixture.target); string(body) != string(fixture.oldBinary) {
		t.Fatal("old binary was not restored")
	}
}

func TestInstallRejectsTamperedStage(t *testing.T) {
	fixture := newInstallFixture(t)
	if err := os.WriteFile(fixture.staged, []byte("tampered"), 0755); err != nil {
		t.Fatal(err)
	}
	restarts := 0
	if _, err := Install(InstallOptions{Root: fixture.root, Version: "1.2.3", Component: "core", Execute: true, Restart: func(string) error { restarts++; return nil }}); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	if restarts != 0 {
		t.Fatal("tampered stage triggered restart")
	}
}
