package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var agentCACertificate *x509.Certificate
var agentCAPrivateKey *ecdsa.PrivateKey

func ensureAgentCA(data string) {
	certPath := filepath.Join(data, "agent-ca.crt")
	keyPath := filepath.Join(data, "agent-ca.key")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		createAgentCA(certPath, keyPath)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		panic("invalid agent ca")
	}
	agentCACertificate, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		panic(err)
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		panic(err)
	}
	agentCAPrivateKey = parsedKey.(*ecdsa.PrivateKey)
}

func createAgentCA(certPath, keyPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "PortHub Agent CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		panic(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		panic(err)
	}
}
