package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// edgeIdentityCN is the Common Name of the Edge node certificate issued by
// PortHub CA. The Edge server certificate is CN=porthub-edge and carries no
// SANs in legacy deployments, so identity is bound via CN (plus SANs when
// present) rather than requiring IP/DNS SANs that legacy certs do not have.
const edgeIdentityCN = "porthub-edge"

func deploySnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s, err := buildSnapshot(actor(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	conflicts, err := checkEdgePortAvailability(s.Mappings)
	if err != nil {
		http.Error(w, "Edge port scan failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if len(conflicts) > 0 {
		http.Error(w, "Edge port conflict: "+strings.Join(conflicts, "; "), http.StatusConflict)
		return
	}
	if err := recordSnapshot(s, "applying", "", 0); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	coreRules, err := compileCoreForward(s)
	if err != nil {
		updateSnapshotResult(s.Version, "rejected", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	coreResult, err := applyCoreForward(coreRules)
	if err != nil {
		updateSnapshotResult(s.Version, "core_failed", err.Error())
		audit(actor(r), "core_forward_deploy_failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	res, err := postSnapshotToEdge(s)
	if err != nil {
		updateSnapshotResult(s.Version, "edge_failed", err.Error())
		audit(actor(r), "deploy_failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	updateSnapshotResult(s.Version, "applied", "core and edge accepted snapshot")
	audit(actor(r), "deploy_success", strconv.FormatInt(s.Version, 10))
	writeJSON(w, map[string]any{"ok": true, "version": s.Version, "edge": res, "core": coreResult})
}

func postSnapshotToEdge(s any) (map[string]any, error) {
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	client, err := edgeHTTPClient()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, edgeURL+"/api/apply", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, errors.New(string(data))
	}
	out, err := decodeJSONMap(data)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func getEdgeJSON(path string) (map[string]any, error) {
	client, err := edgeHTTPClient()
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(edgeURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		return nil, errors.New(string(data))
	}
	out, err := decodeJSONMap(data)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func decodeJSONMap(data []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func edgeHTTPClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dataDir, "tls.crt"), filepath.Join(dataDir, "tls.key"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("invalid edge ca")
	}
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("edge certificate missing")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now()})
			if err != nil {
				return err
			}
			// Bind the peer identity to the Edge node. The Edge server cert is
			// issued by PortHub CA with CN=porthub-edge. Require BOTH the CA
			// chain (verified above) AND a positive identity match, never a
			// silent skip:
			//   - hostnameOK: cert has a SAN covering the dialed host.
			//   - cnOK: cert is the pinned Edge identity by CN.
			// Legacy Edge certs are CN-only (CN=porthub-edge, no SANs) and are
			// accepted via cnOK. When SANs of the dialed host's type ARE
			// present, they are authoritative: a mismatch fails even if the CN
			// matches (anti-impersonation). A cert matching neither is rejected.
			if u, perr := url.Parse(edgeURL); perr == nil && u.Hostname() != "" {
				host := u.Hostname()
				hostnameOK := leaf.VerifyHostname(host) == nil
				cnOK := leaf.Subject.CommonName == edgeIdentityCN
				sanConflict := false
				if ip := net.ParseIP(host); ip != nil {
					if len(leaf.IPAddresses) > 0 && !hostnameOK {
						sanConflict = true
					}
				} else if len(leaf.DNSNames) > 0 && !hostnameOK {
					sanConflict = true
				}
				if sanConflict || (!hostnameOK && !cnOK) {
					return fmt.Errorf("edge certificate identity mismatch: CN=%q SANs(dns=%v ip=%v) host=%q",
						leaf.Subject.CommonName, leaf.DNSNames, leaf.IPAddresses, host)
				}
			}
			return nil
		},
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}, nil
}
