package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveDDNSValue(t *testing.T) {
	record := ddnsRecordItem{RecordType: "A", LastValue: "203.0.113.9"}
	value, err := resolveDDNSValue(record, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if value != "203.0.113.9" {
		t.Fatalf("unexpected value %q", value)
	}
	if _, err := resolveDDNSValue(record, "2001:db8::1", false); err == nil {
		t.Fatal("expected A record IPv6 rejection")
	}
	record.RecordType = "AAAA"
	if _, err := resolveDDNSValue(record, "203.0.113.9", false); err == nil {
		t.Fatal("expected AAAA record IPv4 rejection")
	}
	if value, err := resolveDDNSValue(ddnsRecordItem{RecordType: "A"}, "", true); err != nil || value != "" {
		t.Fatalf("dry-run without value should be allowed: %q %v", value, err)
	}
}

func TestResolveEdgePublicDDNSValue(t *testing.T) {
	old4, old6 := edgePublicIPv4, edgePublicIPv6
	edgePublicIPv4, edgePublicIPv6 = "198.51.100.8", "2001:db8::8"
	defer func() { edgePublicIPv4, edgePublicIPv6 = old4, old6 }()
	value, err := resolveDDNSValue(ddnsRecordItem{RecordType: "A", IPSource: "edge_public", LastValue: "192.0.2.1"}, "", false)
	if err != nil || value != "198.51.100.8" {
		t.Fatalf("IPv4 value=%q err=%v", value, err)
	}
	value, err = resolveDDNSValue(ddnsRecordItem{RecordType: "AAAA", IPSource: "edge_public"}, "", false)
	if err != nil || value != "2001:db8::8" {
		t.Fatalf("IPv6 value=%q err=%v", value, err)
	}
}

func TestExecuteDDNSSyncNoopProviders(t *testing.T) {
	record := ddnsRecordItem{ID: 7, FQDN: "edge.example.com", RecordType: "A"}
	result := executeDDNSSync(record, ddnsProviderItem{Type: "external"}, "203.0.113.9", true)
	if !result.OK || result.Action != "external_noop" {
		t.Fatalf("unexpected external result: %+v", result)
	}
}

func TestTencentDDNSDryRun(t *testing.T) {
	provider := ddnsProviderItem{Type: "tencent", Config: json.RawMessage(`{"secret_id":"sid","domain":"example.com"}`)}
	record := ddnsRecordItem{ID: 1, FQDN: "edge.example.com", RecordType: "A", TTL: 120, Enabled: true}
	result := executeDDNSSync(record, provider, "203.0.113.9", true)
	if !result.OK || result.Action != "tencent_dry_run" {
		t.Fatalf("unexpected tencent dry-run result: %+v", result)
	}
}

func TestDDNSSyncDryRunAllowsDisabledRecord(t *testing.T) {
	oldDB := db
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db = testDB
	defer func() {
		testDB.Close()
		db = oldDB
	}()
	for _, statement := range []string{
		`create table ddns_records(id integer primary key,name text,fqdn text,provider_id int,record_type text,ip_source text,last_value text,ttl int,enabled int,managed_by_lucky int,interval_seconds int,last_sync_at text,last_error text,failure_count int,created_at text,updated_at text,ip_urls text,net_interface text,ip_regex text,force_interval_seconds int,notify_webhook text,verify_dns int,manual_ip text)`,
		`create table ddns_providers(id integer primary key,name text,type text,config text,secret_ref text,enabled int,created_at text,updated_at text)`,
		`create table audit(ts text,actor text,action text,detail text)`,
		`create table webhooks(id integer primary key,name text,description text,data text,enabled int,created_at text,updated_at text)`,
		`insert into ddns_providers(id,name,type,config,enabled) values(1,'Tencent','tencent','{"secret_id":"sid","domain":"example.com"}',1)`,
		`insert into ddns_records(id,name,fqdn,provider_id,record_type,ip_source,last_value,ttl,enabled,managed_by_lucky,interval_seconds,last_sync_at,last_error,failure_count,ip_urls,net_interface,ip_regex,force_interval_seconds,notify_webhook,verify_dns,manual_ip)
		 values(1,'disabled','www.example.com',1,'AAAA','manual','',600,0,0,300,'','previous error',1,'[]','','',0,'',0,'2001:db8::10')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/ddns/sync", strings.NewReader(`{"record_id":1,"dry_run":true}`))
	recorder := httptest.NewRecorder()
	ddnsSync(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result ddnsSyncResult
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || !result.DryRun || result.Action != "tencent_dry_run" || result.TargetValue != "2001:db8::10" {
		t.Fatalf("unexpected dry-run result: %+v", result)
	}
	var enabled, failures int
	var lastError string
	if err := db.QueryRow("select enabled,last_error,failure_count from ddns_records where id=1").Scan(&enabled, &lastError, &failures); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 || lastError != "previous error" || failures != 1 {
		t.Fatalf("dry-run mutated record: enabled=%d error=%q failures=%d", enabled, lastError, failures)
	}
}

func TestTencentDDNSUpdateAndCreate(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "tencent.secret")
	if err := os.WriteFile(secretPath, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var updateSeen, createSeen, lookupSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") == "" || r.Header.Get("x-tc-version") != "2021-03-23" {
			t.Fatalf("missing tencent auth headers")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		switch r.Header.Get("x-tc-action") {
		case "DescribeRecordList":
			lookupSeen = true
			writeTestJSON(w, map[string]any{"Response": map[string]any{"RecordList": []any{}, "RequestId": "req-lookup"}})
		case "ModifyRecord":
			updateSeen = true
			if body["Domain"] != "example.com" || body["SubDomain"] != "edge" || body["RecordLine"] != "默认" {
				t.Fatalf("bad update body: %+v", body)
			}
			writeTestJSON(w, map[string]any{"Response": map[string]any{"RequestId": "req-1"}})
		case "CreateRecord":
			createSeen = true
			if body["Domain"] != "example.com" || body["SubDomain"] != "edge" {
				t.Fatalf("bad create body: %+v", body)
			}
			writeTestJSON(w, map[string]any{"Response": map[string]any{"RecordId": 42, "RequestId": "req-2"}})
		default:
			t.Fatalf("unexpected action: %s", r.Header.Get("x-tc-action"))
		}
	}))
	defer server.Close()

	record := ddnsRecordItem{ID: 1, FQDN: "edge.example.com", RecordType: "A", TTL: 120, Enabled: true}
	provider := ddnsProviderItem{Type: "tencent", SecretRef: secretPath, Config: json.RawMessage(`{"secret_id":"sid","domain":"example.com","record_id":"1001","endpoint_base":"` + server.URL + `"}`)}
	result := executeDDNSSync(record, provider, "203.0.113.9", false)
	if !result.OK || result.Action != "tencent_update" || !updateSeen {
		t.Fatalf("unexpected tencent update result: %+v update=%v", result, updateSeen)
	}

	provider.Config = json.RawMessage(`{"secret_id":"sid","domain":"example.com","endpoint_base":"` + server.URL + `"}`)
	result = executeDDNSSync(record, provider, "203.0.113.10", false)
	if !result.OK || result.Action != "tencent_create" || !lookupSeen || !createSeen {
		t.Fatalf("unexpected tencent create result: %+v lookup=%v create=%v", result, lookupSeen, createSeen)
	}
}

func TestTencentDDNSLooksUpExistingRecordBeforeUpdate(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "tencent.secret")
	if err := os.WriteFile(secretPath, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var lookupSeen, updateSeen, createSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("x-tc-action") {
		case "DescribeRecordList":
			lookupSeen = true
			writeTestJSON(w, map[string]any{"Response": map[string]any{"RecordList": []map[string]any{{
				"RecordId": 7001, "Name": "www", "Type": "AAAA", "Line": "默认",
			}}, "RequestId": "req-lookup"}})
		case "ModifyRecord":
			updateSeen = true
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["RecordId"] != float64(7001) {
				t.Fatalf("unexpected record id: %+v", body)
			}
			writeTestJSON(w, map[string]any{"Response": map[string]any{"RequestId": "req-update"}})
		case "CreateRecord":
			createSeen = true
		default:
			t.Fatalf("unexpected action: %s", r.Header.Get("x-tc-action"))
		}
	}))
	defer server.Close()
	record := ddnsRecordItem{ID: 1, FQDN: "www.example.com", RecordType: "AAAA", TTL: 600, Enabled: true}
	provider := ddnsProviderItem{Type: "tencent", SecretRef: secretPath, Config: json.RawMessage(`{"secret_id":"sid","domain":"example.com","endpoint_base":"` + server.URL + `"}`)}
	result := executeDDNSSync(record, provider, "2001:db8::1", false)
	if !result.OK || result.Action != "tencent_update" || !lookupSeen || !updateSeen || createSeen {
		t.Fatalf("unexpected lookup/update result: %+v lookup=%v update=%v create=%v", result, lookupSeen, updateSeen, createSeen)
	}
}

func TestTencentConfigRecordIDString(t *testing.T) {
	cfg, err := tencentConfig(json.RawMessage(`{"secret_id":"sid","domain":"example.com","record_id":"123"}`), ddnsRecordItem{FQDN: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RecordID != 123 || cfg.SubDomain != "@" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestParseTencentCredentialBundle(t *testing.T) {
	id, key, err := parseTencentCredentials(`{"secret_id":"sid","secret_key":"key"}`)
	if err != nil || id != "sid" || key != "key" {
		t.Fatalf("bundle parse failed: id=%q key=%q err=%v", id, key, err)
	}
	id, key, err = parseTencentCredentials("legacy-key")
	if err != nil || id != "" || key != "legacy-key" {
		t.Fatalf("legacy parse failed: id=%q key=%q err=%v", id, key, err)
	}
}

func TestAliyunDDNSDryRun(t *testing.T) {
	provider := ddnsProviderItem{Type: "aliyun", Config: json.RawMessage(`{"access_key_id":"ak","domain_name":"example.com"}`)}
	record := ddnsRecordItem{ID: 1, FQDN: "edge.example.com", RecordType: "A", TTL: 120, Enabled: true}
	result := executeDDNSSync(record, provider, "203.0.113.9", true)
	if !result.OK || result.Action != "aliyun_dry_run" {
		t.Fatalf("unexpected aliyun dry-run result: %+v", result)
	}
}

func TestAliyunDDNSUpdateAndCreate(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "aliyun.secret")
	if err := os.WriteFile(secretPath, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var updateSeen, createSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("AccessKeyId") != "ak" || r.URL.Query().Get("Signature") == "" {
			t.Fatalf("missing aliyun signature query: %s", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("Action") {
		case "UpdateDomainRecord":
			updateSeen = true
			if r.URL.Query().Get("RecordId") != "rec-1" || r.URL.Query().Get("RR") != "edge" {
				t.Fatalf("bad update query: %s", r.URL.RawQuery)
			}
			writeTestJSON(w, map[string]any{"RecordId": "rec-1"})
		case "AddDomainRecord":
			createSeen = true
			if r.URL.Query().Get("DomainName") != "example.com" || r.URL.Query().Get("RR") != "edge" {
				t.Fatalf("bad create query: %s", r.URL.RawQuery)
			}
			writeTestJSON(w, map[string]any{"RecordId": "rec-2"})
		default:
			t.Fatalf("unexpected action: %s", r.URL.RawQuery)
		}
	}))
	defer server.Close()

	record := ddnsRecordItem{ID: 1, FQDN: "edge.example.com", RecordType: "A", TTL: 120, Enabled: true}
	provider := ddnsProviderItem{Type: "aliyun", SecretRef: secretPath, Config: json.RawMessage(`{"access_key_id":"ak","domain_name":"example.com","record_id":"rec-1","endpoint_base":"` + server.URL + `"}`)}
	result := executeDDNSSync(record, provider, "203.0.113.9", false)
	if !result.OK || result.Action != "aliyun_update" || !updateSeen {
		t.Fatalf("unexpected aliyun update result: %+v update=%v", result, updateSeen)
	}

	provider.Config = json.RawMessage(`{"access_key_id":"ak","domain_name":"example.com","endpoint_base":"` + server.URL + `"}`)
	result = executeDDNSSync(record, provider, "203.0.113.10", false)
	if !result.OK || result.Action != "aliyun_create" || !createSeen {
		t.Fatalf("unexpected aliyun create result: %+v create=%v", result, createSeen)
	}
}

func TestCloudflareDDNSDryRun(t *testing.T) {
	provider := ddnsProviderItem{Type: "cloudflare", Config: json.RawMessage(`{"zone_id":"zone-1"}`)}
	record := ddnsRecordItem{ID: 1, FQDN: "edge.example.com", RecordType: "A", TTL: 120, Enabled: true}
	result := executeDDNSSync(record, provider, "203.0.113.9", true)
	if !result.OK || result.Action != "cloudflare_dry_run" {
		t.Fatalf("unexpected cloudflare dry-run result: %+v", result)
	}
}

func TestCloudflareDDNSUpdateAndCreate(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "cloudflare.token")
	if err := os.WriteFile(secretPath, []byte("token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var patched, posted, emptyLookup bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer token" {
			t.Fatalf("missing bearer token")
		}
		switch {
		case r.Method == http.MethodGet:
			if emptyLookup {
				writeTestJSON(w, map[string]any{"success": true, "result": []map[string]string{}})
				return
			}
			writeTestJSON(w, map[string]any{"success": true, "result": []map[string]string{{"id": "rec-1"}}})
		case r.Method == http.MethodPatch && r.URL.Path == "/zones/zone-1/dns_records/rec-1":
			patched = true
			writeTestJSON(w, map[string]any{"success": true})
		case r.Method == http.MethodPost && r.URL.Path == "/zones/zone-1/dns_records":
			posted = true
			writeTestJSON(w, map[string]any{"success": true})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	record := ddnsRecordItem{ID: 1, FQDN: "edge.example.com", RecordType: "A", TTL: 120, Enabled: true}
	provider := ddnsProviderItem{Type: "cloudflare", SecretRef: secretPath, Config: json.RawMessage(`{"zone_id":"zone-1","endpoint_base":"` + server.URL + `"}`)}
	result := executeDDNSSync(record, provider, "203.0.113.9", false)
	if !result.OK || result.Action != "cloudflare_update" || !patched {
		t.Fatalf("unexpected cloudflare update result: %+v patched=%v", result, patched)
	}

	emptyLookup = true
	posted = false
	result = executeDDNSSync(record, provider, "203.0.113.10", false)
	if !result.OK || result.Action != "cloudflare_create" || !posted {
		t.Fatalf("unexpected cloudflare create result: %+v posted=%v", result, posted)
	}
}

func writeTestJSON(w http.ResponseWriter, value any) {
	w.Header().Set("content-type", "application/json")
	json.NewEncoder(w).Encode(value)
}

func TestWebhookEndpointValidation(t *testing.T) {
	raw := json.RawMessage(`{"endpoint":"https://example.com/ddns","token":"********"}`)
	endpoint, err := webhookEndpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "https://example.com/ddns" {
		t.Fatalf("unexpected endpoint %q", endpoint)
	}
	if _, err := webhookEndpoint(json.RawMessage(`{"endpoint":"file:///etc/passwd"}`)); err == nil {
		t.Fatal("expected invalid endpoint")
	}
}

func TestReadProviderSecretPathRestriction(t *testing.T) {
	dataDir = t.TempDir()
	if _, err := readProviderSecret("/etc/passwd"); err == nil {
		t.Fatal("expected path restriction")
	}
	secretDir := filepath.Join(dataDir, "secrets")
	t.Setenv("HOME", dataDir)
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(secretDir, "webhook.token")
	if err := os.WriteFile(path, []byte("token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readProviderSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "token" {
		t.Fatalf("unexpected secret %q", got)
	}
}
