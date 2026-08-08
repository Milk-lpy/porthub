package snapshots

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestCertificateBundleSignatureAndReplay(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	bundle, err := SignCertificateBundle(CertificateBundle{ID: 7, Domains: []string{"app.example"}, Certificate: "certificate", PrivateKey: "private"}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	check := func(nonce string) bool { exists := seen[nonce]; seen[nonce] = true; return exists }
	if err := VerifyCertificateBundle(bundle, publicKey, time.Now(), check); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCertificateBundle(bundle, publicKey, time.Now(), check); err == nil {
		t.Fatal("replayed certificate bundle accepted")
	}
	bundle.Nonce = "changed"
	if err := VerifyCertificateBundle(bundle, publicKey, time.Now(), func(string) bool { return false }); err == nil {
		t.Fatal("tampered certificate bundle accepted")
	}
}
