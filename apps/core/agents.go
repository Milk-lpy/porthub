package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/auth"
	"regexp"
	"strings"
	"time"
)

var nodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)

func agentEnrollments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		Name       string `json:"name"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request)
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 128 {
		http.Error(w, "valid enrollment name required", http.StatusBadRequest)
		return
	}
	if request.TTLMinutes == 0 {
		request.TTLMinutes = 30
	}
	if request.TTLMinutes < 5 || request.TTLMinutes > 1440 {
		http.Error(w, "ttl_minutes must be 5-1440", http.StatusBadRequest)
		return
	}
	token := "phe_" + auth.RandomPassword()
	now := time.Now().UTC()
	expires := now.Add(time.Duration(request.TTLMinutes) * time.Minute)
	result, err := db.Exec("insert into agent_enrollments(name,token_hash,created_at,expires_at) values(?,?,?,?)", request.Name, hashToken(token), now.Format(time.RFC3339), expires.Unix())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id, _ := result.LastInsertId()
	audit(actor(r), "agent_enrollment_create", request.Name)
	writeJSON(w, map[string]any{"id": id, "token": token, "expires_at": expires.Format(time.RFC3339)})
}

func agentRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request struct {
		NodeID string `json:"node_id"`
		Token  string `json:"token"`
		CSR    string `json:"csr"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&request); err != nil {
		http.Error(w, "invalid registration", http.StatusBadRequest)
		return
	}
	if !nodeIDPattern.MatchString(request.NodeID) || request.Token == "" {
		http.Error(w, "invalid node identity", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode([]byte(request.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "valid certificate request required", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "invalid certificate request", http.StatusBadRequest)
		return
	}
	if err := consumeEnrollment(request.Token, request.NodeID); err != nil {
		http.Error(w, "invalid or expired enrollment", http.StatusUnauthorized)
		return
	}
	certificate, expires, err := signAgentCSR(request.NodeID, csr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db.Exec(`insert into agent_nodes(node_id,name,certificate_expires_at,first_seen_at,last_seen_at,enabled) values(?,?,?,?,?,1)
		on conflict(node_id) do update set certificate_expires_at=excluded.certificate_expires_at,last_seen_at=excluded.last_seen_at,enabled=1`,
		request.NodeID, request.NodeID, expires.Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339))
	audit("agent:"+request.NodeID, "agent_registered", request.NodeID)
	caPEM, _ := os.ReadFile(filepath.Join(dataDir, "agent-ca.crt"))
	writeJSON(w, map[string]any{"certificate": string(certificate), "ca": string(caPEM), "expires_at": expires.Format(time.RFC3339)})
}

func consumeEnrollment(token, nodeID string) error {
	now := time.Now().UTC()
	result, err := db.Exec(`update agent_enrollments set used_at=?,used_by=?
		where token_hash=? and used_at is null and expires_at>=?`, now.Format(time.RFC3339), nodeID, hashToken(token), now.Unix())
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		return errors.New("enrollment unavailable")
	}
	return nil
}

func signAgentCSR(nodeID string, csr *x509.CertificateRequest) ([]byte, time.Time, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, err
	}
	now := time.Now().UTC()
	expires := now.AddDate(1, 0, 0)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "porthub-agent:" + nodeID},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, agentCACertificate, csr.PublicKey, agentCAPrivateKey)
	if err != nil {
		return nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), expires, nil
}

func agentHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "agent client certificate required", http.StatusUnauthorized)
		return
	}
	var request struct {
		NodeID    string          `json:"node_id"`
		Name      string          `json:"name"`
		OS        string          `json:"os"`
		Arch      string          `json:"arch"`
		Version   string          `json:"version"`
		Status    json.RawMessage `json:"status"`
		Discovery json.RawMessage `json:"discovery"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(&request); err != nil {
		http.Error(w, "invalid heartbeat", http.StatusBadRequest)
		return
	}
	if !nodeIDPattern.MatchString(request.NodeID) || r.TLS.PeerCertificates[0].Subject.CommonName != "porthub-agent:"+request.NodeID {
		http.Error(w, "agent certificate identity mismatch", http.StatusForbidden)
		return
	}
	if !json.Valid(request.Status) || !json.Valid(request.Discovery) {
		http.Error(w, "invalid agent payload", http.StatusBadRequest)
		return
	}
	address, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now().UTC().Format(time.RFC3339)
	result, err := db.Exec(`update agent_nodes set name=?,os=?,arch=?,version=?,address=?,status_json=?,discovery_json=?,last_seen_at=?
		where node_id=? and enabled=1`, request.Name, request.OS, request.Arch, request.Version, address, string(request.Status), string(request.Discovery), now, request.NodeID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	affected, _ := result.RowsAffected()
	if affected != 1 {
		http.Error(w, "agent is not registered", http.StatusForbidden)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "next_heartbeat_seconds": 30})
}
