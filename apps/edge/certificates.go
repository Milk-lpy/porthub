package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"sync"
	"time"
)

type certificateMetadata struct {
	ID        int      `json:"id"`
	Base      string   `json:"base"`
	Domains   []string `json:"domains"`
	AppliedAt string   `json:"applied_at"`
}

type certificateStore struct {
	mu          sync.RWMutex
	defaultCert tls.Certificate
	byName      map[string]*tls.Certificate
}

var managedCertificateMu sync.RWMutex
var managedCertificates *certificateStore

func newCertificateStore(defaultCertFile, defaultKeyFile string) (*certificateStore, error) {
	defaultCert, err := tls.LoadX509KeyPair(defaultCertFile, defaultKeyFile)
	if err != nil {
		return nil, err
	}
	store := &certificateStore{defaultCert: defaultCert, byName: map[string]*tls.Certificate{}}
	if err := store.reload(); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *certificateStore) reload() error {
	directory := filepath.Join(data, "certs")
	entries, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next := map[string]*tls.Certificate{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue
		}
		var metadata certificateMetadata
		if json.Unmarshal(body, &metadata) != nil || metadata.ID < 1 {
			continue
		}
		baseName := metadata.Base
		if baseName == "" {
			baseName = strconv.Itoa(metadata.ID)
		}
		base := filepath.Join(directory, baseName)
		pair, err := tls.LoadX509KeyPair(base+".crt", base+".key")
		if err != nil {
			continue
		}
		for _, domain := range metadata.Domains {
			next[strings.ToLower(domain)] = &pair
		}
	}
	store.mu.Lock()
	store.byName = next
	store.mu.Unlock()
	return nil
}

func (store *certificateStore) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	store.mu.RLock()
	defer store.mu.RUnlock()
	if certificate := store.byName[name]; certificate != nil {
		return certificate, nil
	}
	for pattern, certificate := range store.byName {
		if strings.HasPrefix(pattern, "*.") && wildcardMatches(pattern, name) {
			return certificate, nil
		}
	}
	return &store.defaultCert, nil
}

func wildcardMatches(pattern, name string) bool {
	suffix := strings.TrimPrefix(pattern, "*.")
	if !strings.HasSuffix(name, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(name, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

func applyCertificateBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var bundle snapshots.CertificateBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		http.Error(w, "invalid certificate bundle", http.StatusBadRequest)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if err := snapshots.VerifyCertificateBundle(bundle, pub, time.Now(), seen); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pair, err := tls.X509KeyPair([]byte(bundle.Certificate), []byte(bundle.PrivateKey))
	if err != nil || len(pair.Certificate) == 0 {
		http.Error(w, "certificate and key do not match", http.StatusBadRequest)
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		http.Error(w, "certificate is not currently valid", http.StatusBadRequest)
		return
	}
	for _, domain := range bundle.Domains {
		if leaf.VerifyHostname(domain) != nil {
			http.Error(w, "certificate domain mismatch", http.StatusBadRequest)
			return
		}
	}
	directory := filepath.Join(data, "certs")
	if err := os.MkdirAll(directory, 0700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	baseName := strconv.Itoa(bundle.ID) + "-" + bundle.SHA256[:12]
	base := filepath.Join(directory, baseName)
	if err := atomicCertificateWrite(base+".crt", []byte(bundle.Certificate), 0640); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := atomicCertificateWrite(base+".key", []byte(bundle.PrivateKey), 0600); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	metadata, _ := json.Marshal(certificateMetadata{ID: bundle.ID, Base: baseName, Domains: bundle.Domains, AppliedAt: time.Now().UTC().Format(time.RFC3339)})
	if err := atomicCertificateWrite(filepath.Join(directory, strconv.Itoa(bundle.ID)+".json"), metadata, 0640); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	managedCertificateMu.RLock()
	store := managedCertificates
	managedCertificateMu.RUnlock()
	if store != nil {
		_ = store.reload()
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "certificate_id": bundle.ID, "domains": bundle.Domains})
}

func atomicCertificateWrite(path string, body []byte, mode os.FileMode) error {
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
