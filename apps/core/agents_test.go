package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestAgentEnrollmentAndMTLSHeartbeat(t *testing.T) {
	oldDB, oldData := db, dataDir
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db, dataDir = testDB, t.TempDir()
	defer func() { db.Close(); db, dataDir = oldDB, oldData }()
	for _, statement := range []string{
		`create table agent_enrollments(id integer primary key, name text, token_hash text unique, created_at text, expires_at integer, used_at text, used_by text)`,
		`create table agent_nodes(node_id text primary key, name text, os text, arch text, version text, address text, status_json text, discovery_json text, certificate_expires_at text, first_seen_at text, last_seen_at text, enabled int default 1)`,
		`create table audit(ts text, actor text, action text, detail text)`,
		`create table webhooks(id integer primary key, data text, enabled int)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	ensureAgentCA(dataDir)
	token := "phe_test_enrollment"
	db.Exec("insert into agent_enrollments(name,token_hash,created_at,expires_at) values(?,?,?,?)", "test", hashToken(token), time.Now().Format(time.RFC3339), time.Now().Add(time.Hour).Unix())

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "porthub-agent:test-node"}}, key)
	body, _ := json.Marshal(map[string]string{"node_id": "test-node", "token": token, "csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	response := httptest.NewRecorder()
	agentRegister(response, httptest.NewRequest(http.MethodPost, "/api/agents/register", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("registration failed: %d %s", response.Code, response.Body.String())
	}
	var registration struct {
		Certificate string `json:"certificate"`
	}
	json.Unmarshal(response.Body.Bytes(), &registration)
	block, _ := pem.Decode([]byte(registration.Certificate))
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	heartbeatBody := []byte(`{"node_id":"test-node","name":"linux-test","os":"linux","arch":"amd64","version":"0.2.0","status":{},"discovery":{"listeners":[]}}`)
	request := httptest.NewRequest(http.MethodPost, "/api/agents/heartbeat", bytes.NewReader(heartbeatBody))
	request.RemoteAddr = "192.0.2.20:4444"
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate, agentCACertificate}}}
	response = httptest.NewRecorder()
	agentHeartbeat(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("heartbeat failed: %d %s", response.Code, response.Body.String())
	}
	var name, address string
	if err := db.QueryRow("select name,address from agent_nodes where node_id='test-node'").Scan(&name, &address); err != nil {
		t.Fatal(err)
	}
	if name != "linux-test" || address != "192.0.2.20" {
		t.Fatalf("unexpected node state: name=%s address=%s", name, address)
	}
}
