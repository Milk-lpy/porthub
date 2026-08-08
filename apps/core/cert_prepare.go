package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type certificatePrepareRequest struct {
	CertificateID int  `json:"certificate_id"`
	DryRun        bool `json:"dry_run"`
}

type certificatePrepareResult struct {
	OK            bool     `json:"ok"`
	DryRun        bool     `json:"dry_run"`
	CertificateID int      `json:"certificate_id"`
	KeyRef        string   `json:"key_ref,omitempty"`
	Webroot       string   `json:"webroot,omitempty"`
	ChallengeRefs []string `json:"challenge_refs"`
	Steps         []string `json:"steps"`
	Blockers      []string `json:"blockers"`
}

var safeCertNameRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func certificatePrepare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req certificatePrepareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.CertificateID < 1 {
		http.Error(w, "certificate_id required", http.StatusBadRequest)
		return
	}
	cert, err := loadCertificate(req.CertificateID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	result := prepareACMEHTTP01(cert, req.DryRun)
	if !result.OK {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, result)
		return
	}
	audit(actor(r), "certificate_acme_prepare", cert.Name)
	writeJSON(w, result)
}

func prepareACMEHTTP01(cert certificateItem, dryRun bool) certificatePrepareResult {
	result := certificatePrepareResult{OK: true, DryRun: dryRun, CertificateID: cert.ID}
	if !cert.Enabled {
		result.Blockers = append(result.Blockers, "certificate disabled")
	}
	if cert.Mode != "acme_http_01" {
		result.Blockers = append(result.Blockers, "only acme_http_01 preparation is supported")
	}
	if err := validateCertificateItem(cert); err != nil {
		result.Blockers = append(result.Blockers, err.Error())
	}
	for _, domain := range cert.Domains {
		if strings.HasPrefix(domain, "*.") {
			result.Blockers = append(result.Blockers, "wildcard domain requires DNS-01")
			break
		}
	}
	keyRef := strings.TrimSpace(cert.KeyRef)
	if keyRef == "" {
		keyRef = filepath.Join(dataDir, "certs", safeCertFileName(cert)+".key")
	}
	if err := validateCertificateKeyRef(keyRef); err != nil {
		result.Blockers = append(result.Blockers, err.Error())
	}
	webroot := filepath.Join(dataDir, "acme", "http-01", ".well-known", "acme-challenge")
	if err := validateUnderDataDir(webroot); err != nil {
		result.Blockers = append(result.Blockers, err.Error())
	}
	result.KeyRef = keyRef
	result.Webroot = webroot
	for _, domain := range cert.Domains {
		result.ChallengeRefs = append(result.ChallengeRefs, filepath.Join(webroot, "porthub-"+safeName(domain)+".txt"))
	}
	result.Steps = []string{
		"generate protected ECDSA P-256 certificate private key",
		"prepare HTTP-01 challenge webroot",
		"write placeholder challenge files for webroot/proxy verification",
		"update certificate metadata to prepared",
		"next phase: create ACME account/order and replace placeholders with real CA challenge tokens",
	}
	if len(result.Blockers) > 0 {
		result.OK = false
		return result
	}
	if dryRun {
		return result
	}
	if err := writeCertificateKey(keyRef); err != nil && !errors.Is(err, os.ErrExist) {
		result.OK = false
		result.Blockers = append(result.Blockers, err.Error())
		return result
	}
	if err := os.MkdirAll(webroot, 0755); err != nil {
		result.OK = false
		result.Blockers = append(result.Blockers, err.Error())
		return result
	}
	for _, ref := range result.ChallengeRefs {
		if err := os.WriteFile(ref, []byte("porthub-http-01-ready\n"), 0644); err != nil {
			result.OK = false
			result.Blockers = append(result.Blockers, err.Error())
			return result
		}
	}
	now := time.Now().Format(time.RFC3339)
	db.Exec("update certificates set key_ref=?,status=?,updated_at=? where id=?", keyRef, "prepared", now, cert.ID)
	return result
}

func writeCertificateKey(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return os.ErrExist
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	return os.WriteFile(path, body, 0600)
}

func safeCertFileName(cert certificateItem) string {
	if len(cert.Domains) > 0 {
		return safeName(cert.Domains[0])
	}
	return safeName(cert.Name)
}

func safeName(value string) string {
	value = strings.Trim(strings.ToLower(value), ".")
	value = strings.TrimPrefix(value, "*.")
	value = safeCertNameRe.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if value == "" {
		return "certificate"
	}
	return value
}

func validateUnderDataDir(path string) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	base, err := filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if clean == base || strings.HasPrefix(clean, base+string(os.PathSeparator)) {
		return nil
	}
	return errors.New("path must be under Core data directory")
}
