package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// buildTestCA returns a CA cert + key pair used to sign test edge certs.
func buildTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PortHub CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// signTestEdgeCert signs a leaf with the given CA. dnsNames and ipAddresses
// control the SANs; empty both yields a legacy CN-only certificate.
func signTestEdgeCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, dnsNames []string, ipAddresses []net.IP) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if len(dnsNames) > 0 || len(ipAddresses) > 0 {
		tmpl.DNSNames = dnsNames
		tmpl.IPAddresses = ipAddresses
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// setupEdgeTLSDir writes tls.crt/tls.key (client identity) and ca.crt into a
// temp dir and points the package globals at it. Returns cleanup.
func setupEdgeTLSDir(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	// Client identity cert signed by the same CA.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "porthub-core"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	oldDataDir, oldCAPath := dataDir, caPath
	dataDir, caPath = dir, filepath.Join(dir, "ca.crt")
	t.Cleanup(func() { dataDir, caPath = oldDataDir, oldCAPath })
}

// runEdgeTLSTest starts an HTTPS server presenting the given leaf cert and
// checks whether the edgeHTTPClient can fetch /api/health from it. edgeURL is
// pointed at the test server's host:port so verification runs against the
// real dialed address, mirroring production (IP URL + legacy CN-only cert).
func runEdgeTLSTest(t *testing.T, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey) error {
	t.Helper()
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	oldEdgeURL := edgeURL
	edgeURL = srv.URL
	defer func() { edgeURL = oldEdgeURL }()

	client, err := edgeHTTPClient()
	if err != nil {
		return err
	}
	resp, err := client.Get(srv.URL + "/api/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func TestEdgeTLSLegacyCNOnlyCert(t *testing.T) {
	ca, caKey := buildTestCA(t)
	setupEdgeTLSDir(t, ca, caKey)
	// Legacy: CN=porthub-edge, NO SANs. Must pass (CN identity binding).
	leaf, key := signTestEdgeCert(t, ca, caKey, "porthub-edge", nil, nil)
	if err := runEdgeTLSTest(t, leaf, key); err != nil {
		t.Fatalf("legacy CN-only cert should pass: %v", err)
	}
}

func TestEdgeTLSWrongCNRejected(t *testing.T) {
	ca, caKey := buildTestCA(t)
	setupEdgeTLSDir(t, ca, caKey)
	// Same CA but a DIFFERENT node CN. Must be rejected (anti-impersonation).
	leaf, key := signTestEdgeCert(t, ca, caKey, "porthub-edge-other", nil, nil)
	if err := runEdgeTLSTest(t, leaf, key); err == nil {
		t.Fatal("cert with wrong CN must be rejected")
	}
}

func TestEdgeTLSIPSanMismatchRejected(t *testing.T) {
	ca, caKey := buildTestCA(t)
	setupEdgeTLSDir(t, ca, caKey)
	// CN correct but IP SAN covers a different address (server listens on
	// 127.0.0.1 which is not among the SANs). Must be rejected.
	leaf, key := signTestEdgeCert(t, ca, caKey, "porthub-edge", nil, []net.IP{net.ParseIP("10.255.0.99")})
	if err := runEdgeTLSTest(t, leaf, key); err == nil {
		t.Fatal("cert with mismatched IP SAN must be rejected")
	}
}

func TestEdgeTLSIPSanMatchPasses(t *testing.T) {
	ca, caKey := buildTestCA(t)
	setupEdgeTLSDir(t, ca, caKey)
	// CN correct + IP SAN covers the dialed address (127.0.0.1). Must pass.
	leaf, key := signTestEdgeCert(t, ca, caKey, "porthub-edge", nil, []net.IP{net.ParseIP("127.0.0.1")})
	if err := runEdgeTLSTest(t, leaf, key); err != nil {
		t.Fatalf("cert with matching IP SAN should pass: %v", err)
	}
}

func TestEdgeTLSDNSNameURLFallback(t *testing.T) {
	ca, caKey := buildTestCA(t)
	setupEdgeTLSDir(t, ca, caKey)
	// CN correct + DNS SAN only (server dialed by IP 127.0.0.1, no IP SAN).
	// CN binding must carry verification. Must pass.
	leaf, key := signTestEdgeCert(t, ca, caKey, "porthub-edge", []string{"edge.example.test"}, nil)
	if err := runEdgeTLSTest(t, leaf, key); err != nil {
		t.Fatalf("cert with DNS SAN should pass via CN binding: %v", err)
	}
}
