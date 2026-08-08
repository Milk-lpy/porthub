package main

import (
	"context"
	"crypto"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/acme"

	_ "github.com/mattn/go-sqlite3"
)

type fakeDNSACMEClient struct{ fakeACMEClient }

func (fakeDNSACMEClient) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{Status: acme.StatusPending, Identifier: acme.AuthzID{Type: "dns", Value: "example.com"}, Challenges: []*acme.Challenge{{Type: "dns-01", Token: "dns-token"}}}, nil
}

func TestIssueACMEDNS01PublishesWaitsAndCleans(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	for _, statement := range []string{
		`create table certificates(id integer primary key,name text,domains text,issuer text,mode text,status text,expires_at text,key_ref text,dns_provider_id int default 0,enabled int,created_at text,updated_at text)`,
		`create table ddns_providers(id integer primary key,name text,type text,config text,secret_ref text,enabled int,created_at text,updated_at text)`,
		`create table acme_orders(id integer primary key,certificate_id int,ts text,status text,directory_url text,error text)`,
		`create table acme_config(id integer primary key,email text,updated_at text)`,
	} {
		if _, err := testDB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = testDB.Exec(`insert into certificates(id,name,domains,issuer,mode,status,expires_at,key_ref,dns_provider_id,enabled) values(3,'Wildcard','["*.example.com"]','acme','acme_dns_01','prepared','','',1,1)`)
	_, _ = testDB.Exec(`insert into ddns_providers(id,name,type,config,secret_ref,enabled) values(1,'DNS Hook','webhook','{}','',1)`)

	oldDB, oldData, oldEmail := db, dataDir, acmeAccountEmail
	oldFactory, oldPublish, oldWait := newACMEClient, publishACMEDNSTXT, waitACMEDNSTXT
	db, dataDir, acmeAccountEmail = testDB, t.TempDir(), "admin@example.com"
	newACMEClient = func(crypto.Signer, string) acmeClient { return fakeDNSACMEClient{} }
	published, waited, cleaned := false, false, false
	publishACMEDNSTXT = func(provider ddnsProviderItem, fqdn, value string) (acmeDNSCleanup, error) {
		published = provider.ID == 1 && fqdn == "_acme-challenge.example.com" && value == "txt-dns-token"
		return func() error { cleaned = true; return nil }, nil
	}
	waitACMEDNSTXT = func(_ context.Context, fqdn, value string) error {
		waited = fqdn == "_acme-challenge.example.com" && value == "txt-dns-token"
		return nil
	}
	defer func() {
		db, dataDir, acmeAccountEmail = oldDB, oldData, oldEmail
		newACMEClient, publishACMEDNSTXT, waitACMEDNSTXT = oldFactory, oldPublish, oldWait
	}()

	result, err := issueACMEDNS01(certificateItem{ID: 3, Name: "Wildcard", Domains: []string{"*.example.com"}, Mode: "acme_dns_01", DNSProviderID: 1, Enabled: true}, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || !published || !waited || !cleaned {
		t.Fatalf("unexpected DNS issue result=%+v published=%v waited=%v cleaned=%v", result, published, waited, cleaned)
	}
	var status string
	if err := db.QueryRow("select status from certificates where id=3").Scan(&status); err != nil || status != "issued" {
		t.Fatalf("certificate not issued status=%q err=%v", status, err)
	}
}

func TestACMEDNSProvidersCreateAndCleanup(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldData := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldData }()
	secretDir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "dns.token")
	if err := os.WriteFile(secretPath, []byte("test-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("cloudflare", func(t *testing.T) {
		methods := []string{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			methods = append(methods, r.Method+" "+r.URL.Path)
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("missing token")
			}
			w.Header().Set("content-type", "application/json")
			if r.Method == http.MethodPost {
				_, _ = w.Write([]byte(`{"success":true,"result":{"id":"record-1"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true}`))
		}))
		defer server.Close()
		config, _ := json.Marshal(map[string]string{"zone_id": "zone-1", "endpoint_base": server.URL})
		cleanup, err := publishCloudflareACME(ddnsProviderItem{Type: "cloudflare", Config: config, SecretRef: secretPath}, "_acme-challenge.example.com", "value")
		if err != nil {
			t.Fatal(err)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(methods, ",")
		if !strings.Contains(joined, "POST /zones/zone-1/dns_records") || !strings.Contains(joined, "DELETE /zones/zone-1/dns_records/record-1") {
			t.Fatalf("unexpected Cloudflare calls: %s", joined)
		}
	})

	t.Run("webhook", func(t *testing.T) {
		actions := []string{}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				t.Errorf("missing token")
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			actions = append(actions, body["action"].(string))
			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()
		config, _ := json.Marshal(map[string]string{"endpoint": server.URL})
		cleanup, err := publishWebhookACME(ddnsProviderItem{Type: "webhook", Config: config, SecretRef: secretPath}, "_acme-challenge.example.com", "value")
		if err != nil {
			t.Fatal(err)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		if strings.Join(actions, ",") != "present,cleanup" {
			t.Fatalf("unexpected webhook actions: %v", actions)
		}
	})
}
