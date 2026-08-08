package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const agentVersion = "0.2.0"

// coreIdentityCN is the Common Name of the Core server certificate issued by
// PortHub CA. The Core server certificate is CN=porthub-core and, in the
// current IP-based deployments (core_url points at an IP such as
// host name), carries no IP SANs. Because VerifyHostname would reject a
// legitimate CN-only cert dialed by IP, identity is bound via CN when the cert
// has no SAN covering the dialed host, mirroring the Edge identity policy in
// apps/core/deploy.go.
const coreIdentityCN = "porthub-core"

// coreHostFromURL extracts the hostname from the Core URL for TLS verification.
func coreHostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func runReporter(cfg agentConfig) {
	if err := ensureAgentIdentity(cfg); err != nil {
		log.Printf("agent enrollment pending: %v", err)
	}
	report := func() {
		if err := sendHeartbeat(cfg); err != nil {
			log.Printf("agent heartbeat failed: %v", err)
		}
	}
	report()
	ticker := time.NewTicker(time.Duration(cfg.HeartbeatSeconds) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		report()
	}
}

func ensureAgentIdentity(cfg agentConfig) error {
	if fileExists(cfg.CertificateFile) && fileExists(cfg.PrivateKeyFile) {
		return nil
	}
	if cfg.EnrollmentTokenFile == "" {
		return errors.New("certificate is missing and no enrollment token file is configured")
	}
	token, err := os.ReadFile(cfg.EnrollmentTokenFile)
	if err != nil {
		return err
	}
	key, csr, err := loadOrCreateAgentKey(cfg.PrivateKeyFile, cfg.NodeID)
	if err != nil {
		return err
	}
	requestBody, _ := json.Marshal(map[string]string{"node_id": cfg.NodeID, "token": strings.TrimSpace(string(token)), "csr": string(csr)})
	client, err := agentHTTPClient(cfg, false)
	if err != nil {
		return err
	}
	request, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.CoreURL, "/")+"/api/agents/register", bytes.NewReader(requestBody))
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 128<<10))
	if response.StatusCode >= 300 {
		return errors.New(strings.TrimSpace(string(data)))
	}
	var result struct {
		Certificate string `json:"certificate"`
	}
	if json.Unmarshal(data, &result) != nil || result.Certificate == "" {
		return errors.New("registration response did not contain a certificate")
	}
	if _, err := tls.X509KeyPair([]byte(result.Certificate), key); err != nil {
		return errors.New("issued certificate does not match agent key")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.CertificateFile), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.CertificateFile, []byte(result.Certificate), 0600); err != nil {
		return err
	}
	if err := os.Remove(cfg.EnrollmentTokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func loadOrCreateAgentKey(path, nodeID string) ([]byte, []byte, error) {
	if existing, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(existing)
		if block == nil {
			return nil, nil, errors.New("invalid existing agent private key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("agent key must be ECDSA")
		}
		csr, err := createCSR(key, nodeID)
		return existing, csr, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(path, keyPEM, 0600); err != nil {
		return nil, nil, err
	}
	csr, err := createCSR(key, nodeID)
	return keyPEM, csr, err
}

func createCSR(key *ecdsa.PrivateKey, nodeID string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "porthub-agent:" + nodeID}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func sendHeartbeat(cfg agentConfig) error {
	client, err := agentHTTPClient(cfg, true)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	body, _ := json.Marshal(map[string]any{
		"node_id": cfg.NodeID, "name": host, "os": runtime.GOOS, "arch": runtime.GOARCH, "version": agentVersion,
		"status": collectHostStatus(), "discovery": collectDiscovery(),
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(cfg.CoreURL, "/")+"/api/agents/heartbeat", bytes.NewReader(body))
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return errors.New(strings.TrimSpace(string(data)))
	}
	return nil
}

func agentHTTPClient(cfg agentConfig, withCertificate bool) (*http.Client, error) {
	caPEM, err := os.ReadFile(cfg.ServerCAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid Core server CA")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("Core server certificate missing")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		// Build intermediates pool from any additional presented certs.
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if c, err := x509.ParseCertificate(raw); err == nil {
				intermediates.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err != nil {
			return err
		}
		// Bind the peer identity to the Core host we dialed. Prefer strict
		// VerifyHostname; fall back to the pinned CN only when the cert carries
		// no SAN covering the dialed host (legacy CN-only Core certs). We never
		// silently skip the check: if neither the SAN matches nor the CN is the
		// pinned identity, the connection is rejected. When SANs ARE present and
		// cover the host type, they are authoritative and a mismatch is fatal
		// even if the CN happens to match (anti-impersonation).
		if host := coreHostFromURL(cfg.CoreURL); host != "" {
			hostnameOK := leaf.VerifyHostname(host) == nil
			cnOK := leaf.Subject.CommonName == coreIdentityCN
			// If the cert presents SANs of the dialed host's type, they are
			// authoritative: a mismatch must fail regardless of CN.
			sanConflict := false
			if ip := net.ParseIP(host); ip != nil {
				if len(leaf.IPAddresses) > 0 && !hostnameOK {
					sanConflict = true
				}
			} else if len(leaf.DNSNames) > 0 && !hostnameOK {
				sanConflict = true
			}
			if sanConflict || (!hostnameOK && !cnOK) {
				return fmt.Errorf("core certificate identity mismatch: CN=%q SANs(dns=%v ip=%v) host=%q",
					leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses, host)
			}
		}
		return nil
	}
	if withCertificate {
		certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	if parsed, err := url.Parse(cfg.CoreURL); err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("core_url must be HTTPS")
	}
	return &http.Client{Timeout: 12 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
