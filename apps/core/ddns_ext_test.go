package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolvePublicAPIValue(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			w.Write([]byte("your ip is 203.0.113.7"))
		case "/v6":
			w.Write([]byte("2001:db8::7"))
		case "/empty":
			w.Write([]byte("no ip here"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	record := ddnsRecordItem{RecordType: "A", IPURLs: []string{server.URL + "/v4"}}
	value, err := resolvePublicAPIValue(record)
	if err != nil || value != "203.0.113.7" {
		t.Fatalf("value=%q err=%v", value, err)
	}

	record = ddnsRecordItem{RecordType: "AAAA", IPURLs: []string{server.URL + "/v6"}}
	value, err = resolvePublicAPIValue(record)
	if err != nil || value != "2001:db8::7" {
		t.Fatalf("ipv6 value=%q err=%v", value, err)
	}

	record = ddnsRecordItem{RecordType: "A", IPURLs: []string{server.URL + "/empty"}}
	if _, err := resolvePublicAPIValue(record); err == nil {
		t.Fatal("expected error for empty probe result")
	}

	// Default probe URLs should be used when none configured (network may fail,
	// but the function must return an error rather than panic).
	record = ddnsRecordItem{RecordType: "A"}
	_, _ = resolvePublicAPIValue(record)
}

func TestResolveNetInterfaceValue(t *testing.T) {
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("loopback interface not available")
	}
	// Private/loopback addresses require an explicit custom selector.
	record := ddnsRecordItem{RecordType: "A", NetInterface: "lo", IPRegex: `^127\.`}
	value, err := resolveNetInterfaceValue(record)
	if err != nil {
		t.Fatal(err)
	}
	if net.ParseIP(value) == nil {
		t.Fatalf("invalid IP %q", value)
	}
	// AAAA on loopback usually has no IPv6; must return an error gracefully.
	record = ddnsRecordItem{RecordType: "AAAA", NetInterface: "lo"}
	_, err = resolveNetInterfaceValue(record)
	if err == nil {
		t.Log("loopback has IPv6, acceptable")
	}
	// Unknown interface must error.
	record = ddnsRecordItem{RecordType: "A", NetInterface: "definitely-not-an-iface"}
	if _, err := resolveNetInterfaceValue(record); err == nil {
		t.Fatal("expected error for missing interface")
	}
	_ = iface
}

func TestResolveDDNSValueNewSources(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("203.0.113.50"))
	}))
	defer server.Close()

	record := ddnsRecordItem{RecordType: "A", IPSource: "public_api", IPURLs: []string{server.URL}}
	value, err := resolveDDNSValue(record, "", false)
	if err != nil || value != "203.0.113.50" {
		t.Fatalf("public_api value=%q err=%v", value, err)
	}
	// Override wins over API probe.
	value, err = resolveDDNSValue(record, "203.0.113.99", false)
	if err != nil || value != "203.0.113.99" {
		t.Fatalf("override value=%q err=%v", value, err)
	}
	// A failing probe list must produce an error.
	record.IPURLs = []string{"http://127.0.0.1:1/ip"}
	if _, err := resolveDDNSValue(record, "", false); err == nil {
		t.Fatal("expected error when probe fails")
	}
}

func TestVerifyDNSRecord(t *testing.T) {
	// A host that cannot resolve should be treated as "not yet matching".
	matches, err := verifyDNSRecord(ddnsRecordItem{FQDN: "nonexistent.invalid.", RecordType: "A"}, "203.0.113.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matches {
		t.Fatal("nonexistent domain should not match")
	}
	// localhost resolves to 127.0.0.1
	matches, err = verifyDNSRecord(ddnsRecordItem{FQDN: "localhost", RecordType: "A"}, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matches {
		t.Fatal("localhost should match 127.0.0.1")
	}
}

func TestForceDDNSSync(t *testing.T) {
	now := time.Now().UTC()
	record := ddnsRecordItem{ForceInterval: 0}
	if forceDDNSSync(record, now) {
		t.Fatal("force interval 0 should never force")
	}
	record.ForceInterval = 600
	if !forceDDNSSync(record, now) {
		t.Fatal("missing last sync should force")
	}
	record.LastSyncAt = now.Add(-30 * time.Second).Format(time.RFC3339)
	if forceDDNSSync(record, now) {
		t.Fatal("recent sync should not force")
	}
	record.LastSyncAt = now.Add(-20 * time.Minute).Format(time.RFC3339)
	if !forceDDNSSync(record, now) {
		t.Fatal("expired force interval should force")
	}
}

func TestParseDDNSNotify(t *testing.T) {
	cfg, err := parseDDNSNotify("https://example.com/hook")
	if err != nil || cfg.URL != "https://example.com/hook" || cfg.Method != http.MethodPost {
		t.Fatalf("plain URL: %+v err=%v", cfg, err)
	}
	cfg, err = parseDDNSNotify(`{"url":"https://example.com/hook","method":"PUT","secret_ref":"/etc/porthub/secrets/tok","template":"{fqdn} {ip}"}`)
	if err != nil || cfg.Method != http.MethodPut || cfg.Template != "{fqdn} {ip}" {
		t.Fatalf("JSON config: %+v err=%v", cfg, err)
	}
	if _, err := parseDDNSNotify("file:///etc/passwd"); err == nil {
		t.Fatal("expected invalid URL rejection")
	}
	if _, err := parseDDNSNotify("not a url"); err == nil {
		t.Fatal("expected invalid URL rejection")
	}
}

func TestDeliverDDNSNotify(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	var received map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer tok" {
			t.Fatalf("missing bearer token")
		}
		json.NewDecoder(r.Body).Decode(&received)
	}))
	defer server.Close()

	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	os.MkdirAll(secretDir, 0700)
	secretPath := filepath.Join(secretDir, "hook.token")
	os.WriteFile(secretPath, []byte("tok\n"), 0600)

	cfg := ddnsNotifyConfig{URL: server.URL, SecretRef: secretPath, Method: http.MethodPost,
		Template: `{"fqdn":"{fqdn}","ip":"{ip}","status":"{status}"}`}
	record := ddnsRecordItem{FQDN: "home.example.com", RecordType: "A"}
	result := ddnsSyncResult{OK: true, Action: "cloudflare_update", Message: "ok"}
	if err := deliverDDNSNotify(cfg, record, result, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if received["fqdn"] != "home.example.com" || received["ip"] != "203.0.113.9" || received["status"] != "success" {
		t.Fatalf("unexpected payload: %+v", received)
	}
}

func TestHuaweiDDNSDryRun(t *testing.T) {
	provider := ddnsProviderItem{Type: "huawei", Config: json.RawMessage(`{"access_key":"ak","domain_name":"example.com"}`)}
	record := ddnsRecordItem{ID: 1, FQDN: "home.example.com", RecordType: "A", TTL: 120, Enabled: true}
	result := executeDDNSSync(record, provider, "203.0.113.9", true)
	if !result.OK || result.Action != "huawei_dry_run" {
		t.Fatalf("unexpected huawei dry-run result: %+v", result)
	}
}

func TestHuaweiDDNSUpdateAndCreate(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	os.MkdirAll(secretDir, 0700)
	secretPath := filepath.Join(secretDir, "huawei.secret")
	os.WriteFile(secretPath, []byte("secret\n"), 0600)

	var putSeen, postSeen, zoneLookup bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") == "" || !strings.HasPrefix(r.Header.Get("authorization"), "SDK-HMAC-SHA256") {
			t.Fatalf("missing huawei auth header: %q", r.Header.Get("authorization"))
		}
		if r.Header.Get("x-sdk-date") == "" {
			t.Fatalf("missing x-sdk-date")
		}
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zones") && r.URL.Query().Get("name") == "example.com":
			zoneLookup = true
			writeTestJSON(w, map[string]any{"zones": []map[string]string{{"id": "zone-1", "name": "example.com."}}})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/recordsets"):
			writeTestJSON(w, map[string]any{"recordsets": []map[string]string{}})
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/recordsets/rec-1"):
			putSeen = true
			writeTestJSON(w, map[string]any{"id": "rec-1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/recordsets"):
			postSeen = true
			writeTestJSON(w, map[string]any{"id": "rec-2"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	record := ddnsRecordItem{ID: 1, FQDN: "home.example.com", RecordType: "A", TTL: 120, Enabled: true}
	provider := ddnsProviderItem{Type: "huawei", SecretRef: secretPath,
		Config: json.RawMessage(`{"access_key":"ak","domain_name":"example.com","record_id":"rec-1","zone_id":"zone-1","endpoint_base":"` + server.URL + `"}`)}
	result := executeDDNSSync(record, provider, "203.0.113.9", false)
	if !result.OK || result.Action != "huawei_update" || !putSeen {
		t.Fatalf("unexpected huawei update result: %+v put=%v", result, putSeen)
	}

	// Without record_id, lookup returns empty -> create path (zone lookup then POST).
	provider.Config = json.RawMessage(`{"access_key":"ak","domain_name":"example.com","endpoint_base":"` + server.URL + `"}`)
	result = executeDDNSSync(record, provider, "203.0.113.10", false)
	if !result.OK || result.Action != "huawei_create" || !postSeen || !zoneLookup {
		t.Fatalf("unexpected huawei create result: %+v post=%v zone=%v", result, postSeen, zoneLookup)
	}
}

func TestBaiduDDNSDryRunAndUpdate(t *testing.T) {
	allowLocalProbeHosts = true
	defer func() { allowLocalProbeHosts = false }()
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	os.MkdirAll(secretDir, 0700)
	secretPath := filepath.Join(secretDir, "baidu.secret")
	os.WriteFile(secretPath, []byte("secret\n"), 0600)

	var listSeen, editSeen, addSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") == "" || !strings.HasPrefix(r.Header.Get("authorization"), "bce-auth-v1/") {
			t.Fatalf("missing baidu auth header: %q", r.Header.Get("authorization"))
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		switch {
		case strings.HasSuffix(r.URL.Path, "/resolve/list"):
			listSeen = true
			writeTestJSON(w, map[string]any{"totalCount": 1, "result": []map[string]any{{
				"recordId": 1001, "domain": "home", "view": "默认", "rdtype": "A", "ttl": 300, "rdata": "192.0.2.1", "zoneName": "example.com",
			}}})
		case strings.HasSuffix(r.URL.Path, "/resolve/edit"):
			editSeen = true
			writeTestJSON(w, map[string]any{"code": "OK"})
		case strings.HasSuffix(r.URL.Path, "/resolve/add"):
			addSeen = true
			writeTestJSON(w, map[string]any{"code": "OK"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
	}))
	defer server.Close()

	record := ddnsRecordItem{ID: 1, FQDN: "home.example.com", RecordType: "A", TTL: 120, Enabled: true}
	provider := ddnsProviderItem{Type: "baidu", SecretRef: secretPath,
		Config: json.RawMessage(`{"access_key":"ak","domain_name":"example.com","endpoint_base":"` + server.URL + `"}`)}

	// Dry run must not touch the server.
	result := executeDDNSSync(record, provider, "203.0.113.9", true)
	if !result.OK || result.Action != "baidu_dry_run" || listSeen {
		t.Fatalf("unexpected baidu dry-run result: %+v", result)
	}

	// Real sync with existing record -> edit.
	result = executeDDNSSync(record, provider, "203.0.113.9", false)
	if !result.OK || result.Action != "baidu_update" || !listSeen || !editSeen {
		t.Fatalf("unexpected baidu update result: %+v list=%v edit=%v", result, listSeen, editSeen)
	}

	// Different RR -> create.
	record.FQDN = "office.example.com"
	result = executeDDNSSync(record, provider, "203.0.113.10", false)
	if !result.OK || result.Action != "baidu_create" || !addSeen {
		t.Fatalf("unexpected baidu create result: %+v add=%v", result, addSeen)
	}
}

func TestPorkbunDDNSRejectsCustomEndpoint(t *testing.T) {
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()
	secretDir := filepath.Join(dataDir, "secrets")
	os.MkdirAll(secretDir, 0700)
	secretPath := filepath.Join(secretDir, "porkbun.secret")
	os.WriteFile(secretPath, []byte("apikey:secretkey\n"), 0600)

	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		t.Fatalf("custom endpoint should not be called: %s", r.URL.String())
	}))
	defer server.Close()

	record := ddnsRecordItem{ID: 1, FQDN: "home.example.com", RecordType: "A", TTL: 120, Enabled: true}
	provider := ddnsProviderItem{Type: "porkbun", SecretRef: secretPath,
		Config: json.RawMessage(`{"domain_name":"example.com","endpoint_base":"` + server.URL + `"}`)}

	result := executeDDNSSync(record, provider, "203.0.113.9", true)
	if result.OK || result.Action != "porkbun_invalid" || called {
		t.Fatalf("unexpected porkbun custom endpoint result: %+v called=%v", result, called)
	}
}

func TestPorkbunCredentials(t *testing.T) {
	key, skey, err := porkbunCredentials("apikey:secretkey")
	if err != nil || key != "apikey" || skey != "secretkey" {
		t.Fatalf("key=%q skey=%q err=%v", key, skey, err)
	}
	key, skey, err = porkbunCredentials("justkey")
	if err != nil || key != "justkey" || skey != "" {
		t.Fatalf("key=%q skey=%q err=%v", key, skey, err)
	}
	if _, _, err := porkbunCredentials(""); err == nil {
		t.Fatal("expected error for empty secret")
	}
}

func TestDDNSRecordValidationNewFields(t *testing.T) {
	base := ddnsRecordItem{Name: "n", FQDN: "home.example.com", ProviderID: 1, RecordType: "A", IPSource: "public_api"}
	if err := validateDDNSRecord(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.IPURLs = []string{"ftp://example.com"}
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected ip_urls scheme rejection")
	}
	bad = base
	bad.IPRegex = "["
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected invalid regex rejection")
	}
	bad = base
	bad.NotifyWebhook = "file:///etc/passwd"
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected invalid notify webhook rejection")
	}
	bad = base
	bad.ForceInterval = 5
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected force interval floor rejection")
	}
	bad = base
	bad.IPSource = "public_api"
	bad.NetInterface = "eth0"
	bad.IPRegex = `192\.0\.2\..*`
	if err := validateDDNSRecord(bad); err != nil {
		t.Fatal(err)
	}
}

func TestManualIPSource(t *testing.T) {
	// valid IPv4 manual record
	rec := ddnsRecordItem{RecordType: "A", IPSource: "manual", ManualIP: "203.0.113.10"}
	value, err := resolveDDNSValue(rec, "", false)
	if err != nil || value != "203.0.113.10" {
		t.Fatalf("value=%q err=%v", value, err)
	}
	// valid IPv6 manual record
	rec = ddnsRecordItem{RecordType: "AAAA", IPSource: "manual", ManualIP: "2001:db8::10"}
	value, err = resolveDDNSValue(rec, "", false)
	if err != nil || value != "2001:db8::10" {
		t.Fatalf("ipv6 value=%q err=%v", value, err)
	}
	// manual source with no IP must fall back to last_value then fail
	rec = ddnsRecordItem{RecordType: "A", IPSource: "manual"}
	if _, err := resolveDDNSValue(rec, "", false); err == nil {
		t.Fatal("expected error when manual IP missing")
	}
	// override wins over manual_ip (sync form value)
	rec = ddnsRecordItem{RecordType: "A", IPSource: "manual", ManualIP: "203.0.113.10"}
	value, err = resolveDDNSValue(rec, "198.51.100.7", false)
	if err != nil || value != "198.51.100.7" {
		t.Fatalf("override value=%q err=%v", value, err)
	}
}

func TestManualIPValidation(t *testing.T) {
	base := ddnsRecordItem{Name: "n", FQDN: "home.example.com", ProviderID: 1, RecordType: "A", IPSource: "manual", ManualIP: "203.0.113.10"}
	if err := validateDDNSRecord(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.ManualIP = "not-an-ip"
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected invalid manual_ip rejection")
	}
	bad = base
	bad.ManualIP = "2001:db8::1" // IPv6 for A record
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected IPv6-for-A rejection")
	}
	bad = base
	bad.RecordType = "AAAA"
	bad.ManualIP = "203.0.113.10" // IPv4 for AAAA record
	if err := validateDDNSRecord(bad); err == nil {
		t.Fatal("expected IPv4-for-AAAA rejection")
	}
}

func TestListNetworkInterfacesJSON(t *testing.T) {
	ifaces := listNetworkInterfaces()
	if len(ifaces) == 0 {
		t.Skip("no non-loopback interfaces")
	}
	raw, err := json.Marshal(ifaces)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"ipv4":null`) || strings.Contains(string(raw), `"ipv6":null`) {
		t.Fatalf("ipv4/ipv6 must serialize as [] not null: %s", string(raw))
	}
}
