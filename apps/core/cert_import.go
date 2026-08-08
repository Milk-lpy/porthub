package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

type certificateImportRequest struct {
	CertificateID int    `json:"certificate_id"`
	Certificate   string `json:"certificate_pem"`
	PrivateKey    string `json:"private_key_pem"`
	Deploy        bool   `json:"deploy"`
}

func certificateImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var request certificateImportRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid certificate import request", http.StatusBadRequest)
		return
	}
	cert, err := loadCertificate(request.CertificateID)
	if err != nil {
		http.Error(w, "certificate metadata not found", http.StatusNotFound)
		return
	}
	leaf, err := validateImportedCertificate(cert.Domains, []byte(request.Certificate), []byte(request.PrivateKey), time.Now())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	certPath, keyPath := managedCertificatePaths(cert)
	if err := atomicPrivateWrite(certPath, []byte(request.Certificate), 0640); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := atomicPrivateWrite(keyPath, []byte(request.PrivateKey), 0600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	issuer := leaf.Issuer.CommonName
	if issuer == "" {
		issuer = "manual"
	}
	_, err = db.Exec("update certificates set issuer=?,status='issued',expires_at=?,key_ref=?,updated_at=? where id=?", issuer, leaf.NotAfter.UTC().Format(time.RFC3339), keyPath, now, cert.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audit(actor(r), "certificate_import", strconv.Itoa(cert.ID))
	deployed := false
	if request.Deploy {
		if err := deployCertificateToEdge(cert.ID); err != nil {
			http.Error(w, "certificate imported but Edge deploy failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		deployed = true
	}
	writeJSON(w, map[string]any{"ok": true, "certificate_id": cert.ID, "expires_at": leaf.NotAfter.UTC(), "deployed": deployed})
}

func certificateDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		CertificateID int `json:"certificate_id"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil || request.CertificateID < 1 {
		http.Error(w, "certificate_id required", http.StatusBadRequest)
		return
	}
	if err := deployCertificateToEdge(request.CertificateID); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	audit(actor(r), "certificate_deploy", strconv.Itoa(request.CertificateID))
	writeJSON(w, map[string]any{"ok": true, "certificate_id": request.CertificateID})
}

func deployCertificateToEdge(id int) error {
	cert, err := loadCertificate(id)
	if err != nil {
		return err
	}
	if !cert.Enabled || cert.Status != "issued" {
		return errors.New("certificate must be enabled and issued")
	}
	certPath, keyPath := managedCertificatePaths(cert)
	certificatePEM, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	privateKeyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	bundle, err := snapshots.SignCertificateBundle(snapshots.CertificateBundle{ID: cert.ID, Domains: cert.Domains, Certificate: string(certificatePEM), PrivateKey: string(privateKeyPEM)}, priv)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(bundle)
	client, err := edgeHTTPClient()
	if err != nil {
		return err
	}
	request, _ := http.NewRequest(http.MethodPost, edgeURL+"/api/certificates/apply", bytes.NewReader(body))
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	if response.StatusCode >= 300 {
		return errors.New(strings.TrimSpace(string(data)))
	}
	return nil
}

func managedCertificatePaths(cert certificateItem) (string, string) {
	base := filepath.Join(dataDir, "certs", strconv.Itoa(cert.ID)+"-"+safeCertFileName(cert))
	return base + ".crt", base + ".key"
}

func validateImportedCertificate(domains []string, certificatePEM, privateKeyPEM []byte, now time.Time) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, errors.New("certificate and private key do not match")
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("certificate chain required")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("invalid leaf certificate")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("certificate is not currently valid")
	}
	for _, domain := range domains {
		if err := leaf.VerifyHostname(domain); err != nil {
			return nil, errors.New("certificate does not cover " + domain)
		}
	}
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, errors.New("unencrypted PEM private key required")
	}
	return leaf, nil
}

func atomicPrivateWrite(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, body, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		os.Remove(temporary)
		return err
	}
	return os.Rename(temporary, path)
}
