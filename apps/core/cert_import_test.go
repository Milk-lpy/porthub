package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestValidateImportedCertificate(t *testing.T) {
	certificate, privateKey := testCertificatePair(t, "app.example.test")
	leaf, err := validateImportedCertificate([]string{"app.example.test"}, certificate, privateKey, time.Now())
	if err != nil || leaf.DNSNames[0] != "app.example.test" {
		t.Fatalf("leaf=%+v err=%v", leaf, err)
	}
	if _, err := validateImportedCertificate([]string{"other.example.test"}, certificate, privateKey, time.Now()); err == nil {
		t.Fatal("uncovered domain accepted")
	}
	_, anotherKey := testCertificatePair(t, "app.example.test")
	if _, err := validateImportedCertificate([]string{"app.example.test"}, certificate, anotherKey, time.Now()); err == nil {
		t.Fatal("mismatched private key accepted")
	}
}

func testCertificatePair(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
