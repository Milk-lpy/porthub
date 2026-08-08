package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"math/big"
	"porthub/internal/snapshots"
	"testing"
	"time"

	"golang.org/x/crypto/acme"

	_ "github.com/mattn/go-sqlite3"
)

type fakeACMEClient struct{}

func (fakeACMEClient) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	return &acme.Account{}, nil
}
func (fakeACMEClient) AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error) {
	return &acme.Order{AuthzURLs: []string{"https://ca.example/auth/1"}, FinalizeURL: "https://ca.example/order/1/finalize"}, nil
}
func (fakeACMEClient) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{Status: acme.StatusPending, Identifier: acme.AuthzID{Type: "dns", Value: "nas.example.com"}, Challenges: []*acme.Challenge{{Type: "http-01", Token: "1234567890_token"}}}, nil
}
func (fakeACMEClient) HTTP01ChallengeResponse(token string) (string, error) {
	return token + ".account-thumbprint", nil
}
func (fakeACMEClient) DNS01ChallengeRecord(token string) (string, error) {
	return "txt-" + token, nil
}
func (fakeACMEClient) Accept(context.Context, *acme.Challenge) (*acme.Challenge, error) {
	return &acme.Challenge{Status: acme.StatusValid}, nil
}
func (fakeACMEClient) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{Status: acme.StatusValid}, nil
}
func (fakeACMEClient) CreateOrderCert(_ context.Context, _ string, csrDER []byte, _ bool) ([][]byte, string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, "", err
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortHub Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, caKey)
	return [][]byte{leafDER, caDER}, "https://ca.example/cert/1", err
}

func TestIssueACMEHTTP01StoresVerifiedCertificate(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	for _, statement := range []string{
		`create table certificates(id integer primary key,name text,domains text,issuer text,mode text,status text,expires_at text,key_ref text,dns_provider_id int default 0,enabled int,created_at text,updated_at text)`,
		`create table acme_orders(id integer primary key,certificate_id int,ts text,status text,directory_url text,error text)`,
		`create table acme_config(id integer primary key,email text,updated_at text)`,
	} {
		if _, err := testDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testDB.Exec(`insert into certificates(id,name,domains,issuer,mode,status,expires_at,key_ref,enabled) values(1,'NAS','["nas.example.com"]','acme','acme_http_01','prepared','','',1)`); err != nil {
		t.Fatal(err)
	}
	oldDB, oldData, oldEmail := db, dataDir, acmeAccountEmail
	oldFactory, oldPush, oldPreflight := newACMEClient, pushACMEChallenges, publicACMEPreflight
	db, dataDir, acmeAccountEmail = testDB, t.TempDir(), "admin@example.com"
	newACMEClient = func(crypto.Signer, string) acmeClient { return fakeACMEClient{} }
	var pushed, cleared bool
	pushACMEChallenges = func(entries []snapshots.ACMEChallenge) error {
		if len(entries) == 0 {
			cleared = true
		} else if entries[0].Domain == "nas.example.com" {
			pushed = true
		}
		return nil
	}
	publicACMEPreflight = func(context.Context, []snapshots.ACMEChallenge) error { return nil }
	defer func() {
		db, dataDir, acmeAccountEmail = oldDB, oldData, oldEmail
		newACMEClient, pushACMEChallenges, publicACMEPreflight = oldFactory, oldPush, oldPreflight
	}()

	result, err := issueACMEHTTP01(certificateItem{ID: 1, Name: "NAS", Domains: []string{"nas.example.com"}, Mode: "acme_http_01", Status: "prepared", Enabled: true}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || !pushed || !cleared || result.Deployed {
		t.Fatalf("unexpected issuance result: %+v pushed=%v cleared=%v", result, pushed, cleared)
	}
	var status, keyRef string
	if err := db.QueryRow("select status,key_ref from certificates where id=1").Scan(&status, &keyRef); err != nil || status != "issued" || keyRef == "" {
		t.Fatalf("certificate metadata not persisted status=%q key=%q err=%v", status, keyRef, err)
	}
}

func TestCertificateIssueFailurePreservesIssuedCertificate(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	for _, statement := range []string{
		`create table certificates(id integer primary key,status text,updated_at text)`,
		`create table acme_orders(id integer primary key,certificate_id int,ts text,status text,directory_url text,error text)`,
		`create table system_alerts(id integer primary key,fingerprint text unique,severity text,source text,title text,detail text,first_seen_at text,last_seen_at text,active int,resolved_at text)`,
	} {
		if _, err := testDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testDB.Exec(`insert into certificates(id,status) values(1,'issued'),(2,'pending')`); err != nil {
		t.Fatal(err)
	}
	oldDB := db
	db = testDB
	defer func() { db = oldDB }()

	setCertificateIssueFailure(1, errors.New("certificate issued but Edge deploy failed"))
	setCertificateIssueFailure(2, errors.New("authorization failed"))

	var issuedStatus, pendingStatus, deployEvent, failedEvent string
	if err := db.QueryRow("select status from certificates where id=1").Scan(&issuedStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("select status from certificates where id=2").Scan(&pendingStatus); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("select status from acme_orders where certificate_id=1").Scan(&deployEvent); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("select status from acme_orders where certificate_id=2").Scan(&failedEvent); err != nil {
		t.Fatal(err)
	}
	if issuedStatus != "issued" || pendingStatus != "failed" || deployEvent != "deploy_failed" || failedEvent != "failed" {
		t.Fatalf("unexpected statuses issued=%q pending=%q deploy=%q failed=%q", issuedStatus, pendingStatus, deployEvent, failedEvent)
	}
}
