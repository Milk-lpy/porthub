package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestParseWebhookConfigBounds(t *testing.T) {
	cfg, err := parseWebhookConfig(`{"event":"mapping.changed","url":"https://example.com/hook","method":"post","timeout_seconds":99,"retries":99}`)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Method != http.MethodPost || cfg.TimeoutSeconds != 30 || cfg.Retries != 5 {
		t.Fatalf("unexpected normalized config: %+v", cfg)
	}
	if _, err := parseWebhookConfig(`{"event":"mapping.changed","url":"file:///etc/passwd","method":"POST"}`); err == nil {
		t.Fatal("expected invalid url")
	}
	if _, err := parseWebhookConfig(`{"event":"mapping.changed","url":"https://example.com","method":"GET"}`); err == nil {
		t.Fatal("expected invalid method")
	}
}

func TestDeliverWebhookSignsPayload(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldData := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldData }()
	secretDir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "webhook.secret")
	if err := os.WriteFile(secretPath, []byte("shared-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var gotEvent, gotSignature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEvent = r.Header.Get("X-PortHub-Event")
		gotSignature = r.Header.Get("X-PortHub-Signature")
		defer r.Body.Close()
		var payload webhookEvent
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(payload)
		mac := hmac.New(sha256.New, []byte("shared-secret"))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if gotSignature != want {
			t.Fatalf("signature mismatch got %q want %q", gotSignature, want)
		}
	}))
	defer server.Close()
	err := deliverWebhook("notify", webhookConfig{Event: "snapshot.applied", URL: server.URL, Method: "POST", TimeoutSeconds: 2, SecretRef: secretPath}, webhookEvent{Event: "snapshot.applied", Action: "deploy_success", Actor: "admin", Detail: "1", TS: "2026-07-31T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if gotEvent != "snapshot.applied" || gotSignature == "" {
		t.Fatalf("missing headers event=%q sig=%q", gotEvent, gotSignature)
	}
}

func TestLoadEnabledWebhooksFiltersEvent(t *testing.T) {
	restore := testWebhookDB(t)
	defer restore()
	db.Exec("insert into webhooks(id,name,description,data,enabled) values(1,'match','',?,1)", `{"event":"mapping.changed","url":"https://example.com","method":"POST"}`)
	db.Exec("insert into webhooks(id,name,description,data,enabled) values(2,'other','',?,1)", `{"event":"snapshot.applied","url":"https://example.com","method":"POST"}`)
	db.Exec("insert into webhooks(id,name,description,data,enabled) values(3,'disabled','',?,0)", `{"event":"mapping.changed","url":"https://example.com","method":"POST"}`)
	items, err := loadEnabledWebhooks("mapping.changed")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Name != "match" {
		t.Fatalf("unexpected webhooks: %+v", items)
	}
}

func testWebhookDB(t *testing.T) func() {
	t.Helper()
	oldDB := db
	tmp := filepath.Join(t.TempDir(), "webhook.db")
	next, err := sql.Open("sqlite3", tmp)
	if err != nil {
		t.Fatal(err)
	}
	db = next
	if _, err := db.Exec(`create table webhooks(id integer primary key, name text, description text, data text, enabled int, created_at text, updated_at text)`); err != nil {
		t.Fatal(err)
	}
	return func() {
		db.Close()
		db = oldDB
	}
}
