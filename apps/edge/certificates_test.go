package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"testing"
	"time"
)

func TestApplyCertificateBundleAndSNI(t *testing.T) {
	oldData, oldPub, oldNonces := data, pub, nonces
	data = t.TempDir()
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	pub, nonces = publicKey, map[string]time.Time{}
	defer func() { data, pub, nonces = oldData, oldPub, oldNonces }()

	defaultCert, defaultKey := edgeTestCertificatePair(t, "default.example.test", 1)
	defaultCertPath, defaultKeyPath := filepath.Join(data, "default.crt"), filepath.Join(data, "default.key")
	os.WriteFile(defaultCertPath, defaultCert, 0600)
	os.WriteFile(defaultKeyPath, defaultKey, 0600)
	certificate, key := edgeTestCertificatePair(t, "app.example.test", 2)
	bundle, err := snapshots.SignCertificateBundle(snapshots.CertificateBundle{
		ID: 1, Domains: []string{"app.example.test"}, Certificate: string(certificate), PrivateKey: string(key),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(bundle)
	request := httptest.NewRequest(http.MethodPost, "/api/certificates/apply", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	applyCertificateBundle(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	keys, _ := filepath.Glob(filepath.Join(data, "certs", "1-*.key"))
	if len(keys) != 1 {
		t.Fatalf("managed keys=%v", keys)
	}
	if mode := fileMode(t, keys[0]); mode != 0600 {
		t.Fatalf("key mode=%o", mode)
	}
	store, err := newCertificateStore(defaultCertPath, defaultKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := store.getCertificate(&tls.ClientHelloInfo{ServerName: "app.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(selected.Certificate[0])
	if leaf.SerialNumber.Int64() != 2 {
		t.Fatalf("selected serial=%s", leaf.SerialNumber)
	}

	replay := httptest.NewRecorder()
	applyCertificateBundle(replay, httptest.NewRequest(http.MethodPost, "/api/certificates/apply", bytes.NewReader(body)))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d", replay.Code)
	}
}

func edgeTestCertificatePair(t *testing.T, domain string, serial int64) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
