package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestSignedManifestAndArtifact(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("porthub-test-binary")
	digest := sha256.Sum256(body)
	manifest, err := Sign(Manifest{
		Version: "1.2.3", PublishedAt: time.Now().UTC(),
		Artifacts: []Artifact{{Component: "core", OS: "linux", Arch: "amd64", URL: "https://updates.example/core", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(body))}},
	}, privateKey)
	if err != nil || Verify(manifest, publicKey) != nil {
		t.Fatalf("signed manifest rejected: %v", err)
	}
	artifact, ok := manifest.Find("core", "linux", "amd64")
	if !ok || VerifyArtifact(artifact, body) != nil {
		t.Fatal("matching artifact rejected")
	}
	manifest.Version = "1.2.4"
	if Verify(manifest, publicKey) == nil {
		t.Fatal("tampered manifest accepted")
	}
}

func TestManifestRejectsUnsafeArtifact(t *testing.T) {
	manifest := Manifest{Version: "1.0.0", PublishedAt: time.Now().UTC(), Artifacts: []Artifact{{
		Component: "core", OS: "linux", Arch: "amd64", URL: "http://127.0.0.1/core", SHA256: "0", Size: 1,
	}}}
	if manifest.Validate() == nil {
		t.Fatal("unsafe artifact accepted")
	}
}
