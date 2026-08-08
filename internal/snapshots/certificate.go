package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

type CertificateBundle struct {
	ID          int       `json:"id"`
	Domains     []string  `json:"domains"`
	Certificate string    `json:"certificate_pem"`
	PrivateKey  string    `json:"private_key_pem"`
	CreatedAt   time.Time `json:"created_at"`
	Nonce       string    `json:"nonce"`
	SHA256      string    `json:"sha256"`
	Signature   string    `json:"signature"`
}

func SignCertificateBundle(bundle CertificateBundle, privateKey ed25519.PrivateKey) (CertificateBundle, error) {
	bundle.CreatedAt = time.Now().UTC()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return bundle, err
	}
	bundle.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	canonical, err := canonicalCertificateBundle(bundle)
	if err != nil {
		return bundle, err
	}
	hash := sha256.Sum256(canonical)
	bundle.SHA256 = hex.EncodeToString(hash[:])
	bundle.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, hash[:]))
	return bundle, nil
}

func VerifyCertificateBundle(bundle CertificateBundle, publicKey ed25519.PublicKey, now time.Time, nonceSeen func(string) bool) error {
	if bundle.ID < 1 || len(bundle.Domains) == 0 || bundle.Certificate == "" || bundle.PrivateKey == "" {
		return errors.New("incomplete certificate bundle")
	}
	if bundle.Nonce == "" {
		return errors.New("certificate bundle replay rejected")
	}
	if bundle.CreatedAt.After(now.Add(time.Minute)) || bundle.CreatedAt.Before(now.Add(-5*time.Minute)) {
		return errors.New("certificate bundle timestamp rejected")
	}
	canonical, err := canonicalCertificateBundle(bundle)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(canonical)
	if hex.EncodeToString(hash[:]) != bundle.SHA256 {
		return errors.New("certificate bundle hash mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil || !ed25519.Verify(publicKey, hash[:], signature) {
		return errors.New("certificate bundle signature invalid")
	}
	// Record/check nonce only after the signature is verified, so invalid
	// payloads cannot burn a legitimate nonce.
	if nonceSeen(bundle.Nonce) {
		return errors.New("certificate bundle replay rejected")
	}
	return nil
}

func canonicalCertificateBundle(bundle CertificateBundle) ([]byte, error) {
	bundle.SHA256 = ""
	bundle.Signature = ""
	return json.Marshal(bundle)
}
