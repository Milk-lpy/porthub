package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderSchemasCoverAllTypes(t *testing.T) {
	schemas := providerSchemas()
	byType := map[string]ProviderSchema{}
	for _, s := range schemas {
		byType[s.Type] = s
	}
	for _, typ := range []string{"cloudflare", "aliyun", "tencent", "huawei", "baidu", "porkbun", "webhook", "external"} {
		if _, ok := byType[typ]; !ok {
			t.Fatalf("schema missing for provider type %q", typ)
		}
	}
	// Cloudflare must expose the token secret field and zone_id text field.
	cf := byType["cloudflare"]
	var hasToken, hasZone bool
	for _, f := range cf.Fields {
		if f.Key == "token" && f.Secret && f.Type == "password" {
			hasToken = true
		}
		if f.Key == "zone_id" && !f.Secret && f.Type == "text" && f.Required {
			hasZone = true
		}
	}
	if !hasToken || !hasZone {
		t.Fatalf("cloudflare schema fields wrong: %+v", cf.Fields)
	}
}

func TestWriteProviderSecret(t *testing.T) {
	oldData := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldData }()

	// Single-secret provider.
	path, err := writeProviderSecret("cloudflare", map[string]string{"token": "cf-token-abc"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, filepath.Join(dataDir, "secrets")) {
		t.Fatalf("secret path not under secrets dir: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "cf-token-abc" {
		t.Fatalf("secret content = %q", data)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secret file mode = %v, want 0600", info.Mode().Perm())
	}

	// Porkbun two-value join.
	path2, err := writeProviderSecret("porkbun", map[string]string{"api_key": "pk1", "secret_api_key": "sk1"})
	if err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(path2)
	if string(data2) != "pk1:sk1" {
		t.Fatalf("porkbun secret = %q, want pk1:sk1", data2)
	}

	// Empty secret map -> no file, empty ref.
	path3, err := writeProviderSecret("aliyun", nil)
	if err != nil || path3 != "" {
		t.Fatalf("empty secret: path=%q err=%v", path3, err)
	}

	// Porkbun missing api_key -> error.
	if _, err := writeProviderSecret("porkbun", map[string]string{"secret_api_key": "sk1"}); err == nil {
		t.Fatal("expected error for porkbun without api_key")
	}
}

func TestTencentProviderSecretStoresCredentialBundle(t *testing.T) {
	oldDataDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = oldDataDir })
	item := ddnsProviderItem{
		Type:   "tencent",
		Config: json.RawMessage(`{"secret_id":"sid-value","domain":"example.com"}`),
		Secret: map[string]string{"secret_key": "key-value"},
	}
	ref, err := providerSecretFromItem(&item)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(ref)
	if err != nil {
		t.Fatal(err)
	}
	secretID, secretKey, err := parseTencentCredentials(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if secretID != "sid-value" || secretKey != "key-value" {
		t.Fatal("Tencent credential bundle was not preserved")
	}
}

func TestProviderSecretFromItemPreservesRef(t *testing.T) {
	item := ddnsProviderItem{Type: "aliyun", SecretRef: "/etc/porthub/secrets/old.key"}
	ref, err := providerSecretFromItem(&item)
	if err != nil {
		t.Fatal(err)
	}
	if ref != "/etc/porthub/secrets/old.key" {
		t.Fatalf("ref = %q, want preserved", ref)
	}

	oldData := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldData }()
	item2 := ddnsProviderItem{Type: "aliyun", SecretRef: "/etc/porthub/secrets/old.key",
		Secret: map[string]string{"access_secret": "new-secret"}}
	ref2, err := providerSecretFromItem(&item2)
	if err != nil {
		t.Fatal(err)
	}
	if ref2 == item2.SecretRef {
		t.Fatalf("ref unchanged after providing new secret: %q", ref2)
	}
	data, _ := os.ReadFile(ref2)
	if string(data) != "new-secret" {
		t.Fatalf("secret file = %q", data)
	}
}
