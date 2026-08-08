package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

type ddnsSyncRequest struct {
	RecordID int    `json:"record_id"`
	DryRun   bool   `json:"dry_run"`
	Value    string `json:"value,omitempty"`
}

type ddnsSyncResult struct {
	OK          bool   `json:"ok"`
	DryRun      bool   `json:"dry_run"`
	Provider    string `json:"provider"`
	RecordID    int    `json:"record_id"`
	FQDN        string `json:"fqdn"`
	RecordType  string `json:"record_type"`
	TargetValue string `json:"target_value,omitempty"`
	Action      string `json:"action"`
	Message     string `json:"message"`
}

func ddnsSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ddnsSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.RecordID < 1 {
		http.Error(w, "record_id required", http.StatusBadRequest)
		return
	}
	record, err := loadDDNSRecord(req.RecordID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	if !record.Enabled && !req.DryRun {
		http.Error(w, "record disabled", http.StatusBadRequest)
		return
	}
	provider, err := loadDDNSProvider(record.ProviderID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !provider.Enabled {
		http.Error(w, "provider disabled", http.StatusBadRequest)
		return
	}
	value, err := resolveDDNSValue(record, req.Value, req.DryRun)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result := executeDDNSSync(record, provider, value, req.DryRun)
	if !result.DryRun {
		updateDDNSSyncState(record, value, result)
		notifyDDNSResult(record, result, value)
	}
	audit(actor(r), "ddns_sync", result.Action+" "+record.FQDN)
	writeJSON(w, result)
}

func loadDDNSRecord(id int) (ddnsRecordItem, error) {
	var item ddnsRecordItem
	var enabled, lucky, verify int
	var urlsJSON string
	err := db.QueryRow(`select id,name,fqdn,provider_id,record_type,ip_source,last_value,ttl,enabled,managed_by_lucky,
		coalesce(interval_seconds,300),coalesce(last_sync_at,''),coalesce(last_error,''),coalesce(failure_count,0),coalesce(created_at,''),coalesce(updated_at,''),
		coalesce(ip_urls,'[]'),coalesce(net_interface,''),coalesce(ip_regex,''),coalesce(force_interval_seconds,0),coalesce(notify_webhook,''),coalesce(verify_dns,0),coalesce(manual_ip,'')
		from ddns_records where id=?`, id).
		Scan(&item.ID, &item.Name, &item.FQDN, &item.ProviderID, &item.RecordType, &item.IPSource, &item.LastValue, &item.TTL, &enabled, &lucky,
			&item.Interval, &item.LastSyncAt, &item.LastError, &item.FailureCount, &item.CreatedAt, &item.UpdatedAt,
			&urlsJSON, &item.NetInterface, &item.IPRegex, &item.ForceInterval, &item.NotifyWebhook, &verify, &item.ManualIP)
	item.Enabled = enabled == 1
	item.ManagedByLucky = lucky == 1
	item.VerifyDNS = verify == 1
	if urlsJSON != "" {
		_ = json.Unmarshal([]byte(urlsJSON), &item.IPURLs)
	}
	return item, err
}

func loadDDNSProvider(id int) (ddnsProviderItem, error) {
	var item ddnsProviderItem
	var enabled int
	var config string
	err := db.QueryRow(`select id,name,type,coalesce(config,'{}'),coalesce(secret_ref,''),enabled,coalesce(created_at,''),coalesce(updated_at,'') from ddns_providers where id=?`, id).
		Scan(&item.ID, &item.Name, &item.Type, &config, &item.SecretRef, &enabled, &item.CreatedAt, &item.UpdatedAt)
	item.Config = json.RawMessage(config)
	item.Enabled = enabled == 1
	return item, err
}

func resolveDDNSValue(record ddnsRecordItem, override string, dryRun bool) (string, error) {
	candidate := strings.TrimSpace(override)
	switch record.IPSource {
	case "edge_public":
		if candidate == "" && record.RecordType == "AAAA" {
			candidate = strings.TrimSpace(edgePublicIPv6)
		} else if candidate == "" {
			candidate = strings.TrimSpace(edgePublicIPv4)
		}
	case "public_api", "core_public":
		if candidate == "" {
			value, err := resolvePublicAPIValue(record)
			if err != nil {
				return "", err
			}
			candidate = value
		}
	case "net_interface":
		if candidate == "" {
			value, err := resolveNetInterfaceValue(record)
			if err != nil {
				return "", err
			}
			candidate = value
		}
	case "manual":
		if candidate == "" {
			candidate = strings.TrimSpace(record.ManualIP)
		}
	}
	if candidate == "" {
		candidate = strings.TrimSpace(record.LastValue)
	}
	if candidate == "" && dryRun {
		return "", nil
	}
	ip := net.ParseIP(candidate)
	if ip == nil {
		return "", errors.New("valid current IP value required")
	}
	if record.RecordType == "A" && ip.To4() == nil {
		return "", errors.New("A record requires IPv4 value")
	}
	if record.RecordType == "AAAA" && ip.To4() != nil {
		return "", errors.New("AAAA record requires IPv6 value")
	}
	return ip.String(), nil
}

func executeDDNSSync(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool) ddnsSyncResult {
	result := ddnsSyncResult{OK: true, DryRun: dryRun, Provider: provider.Type, RecordID: record.ID, FQDN: record.FQDN, RecordType: record.RecordType, TargetValue: value}
	switch provider.Type {
	case "webhook":
		return executeWebhookDDNS(record, provider, value, dryRun, result)
	case "cloudflare":
		return executeCloudflareDDNS(record, provider, value, dryRun, result)
	case "aliyun":
		return executeAliyunDDNS(record, provider, value, dryRun, result)
	case "tencent":
		return executeTencentDDNS(record, provider, value, dryRun, result)
	case "huawei":
		return executeHuaweiDDNS(record, provider, value, dryRun, result)
	case "baidu":
		return executeBaiduDDNS(record, provider, value, dryRun, result)
	case "porkbun":
		return executePorkbunDDNS(record, provider, value, dryRun, result)
	case "external":
		result.Action = "external_noop"
		result.Message = "外部管理记录，仅保存状态"
		return result
	default:
		result.OK = false
		result.Action = "unsupported_provider"
		result.Message = "unsupported provider"
		return result
	}
}

func executeWebhookDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	endpoint, err := webhookEndpoint(provider.Config)
	if err != nil {
		result.OK = false
		result.Action = "webhook_invalid"
		result.Message = err.Error()
		return result
	}
	result.Action = "webhook_post"
	if dryRun {
		result.Action = "webhook_dry_run"
		result.Message = "Webhook 请求已生成但未发送"
		return result
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	body, _ := json.Marshal(map[string]any{
		"name":        record.Name,
		"fqdn":        record.FQDN,
		"record_type": record.RecordType,
		"value":       value,
		"ttl":         record.TTL,
	})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	req.Header.Set("content-type", "application/json")
	if secret != "" {
		req.Header.Set("authorization", "Bearer "+secret)
	}
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		result.OK = false
		result.Message = "webhook failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data)
		return result
	}
	result.Message = "Webhook 请求成功"
	return result
}

func executeCloudflareDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	cfg, err := cloudflareConfig(provider.Config)
	if err != nil {
		result.OK = false
		result.Action = "cloudflare_invalid"
		result.Message = err.Error()
		return result
	}
	if dryRun {
		result.Action = "cloudflare_dry_run"
		result.Message = "Cloudflare 请求已生成但未发送"
		return result
	}
	token, err := readProviderSecret(provider.SecretRef)
	if err != nil || token == "" {
		result.OK = false
		result.Action = "cloudflare_secret_missing"
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Message = "Cloudflare token secret_ref required"
		}
		return result
	}
	recordID := cfg.RecordID
	if recordID == "" {
		recordID, err = lookupCloudflareRecord(cfg, token, record)
		if err != nil {
			result.OK = false
			result.Action = "cloudflare_lookup_failed"
			result.Message = err.Error()
			return result
		}
	}
	method := http.MethodPatch
	endpoint := cfg.EndpointBase + "/zones/" + url.PathEscape(cfg.ZoneID) + "/dns_records/" + url.PathEscape(recordID)
	result.Action = "cloudflare_update"
	if recordID == "" {
		method = http.MethodPost
		endpoint = cfg.EndpointBase + "/zones/" + url.PathEscape(cfg.ZoneID) + "/dns_records"
		result.Action = "cloudflare_create"
	}
	body, _ := json.Marshal(map[string]any{
		"type":    record.RecordType,
		"name":    record.FQDN,
		"content": value,
		"ttl":     normalizedTTL(record.TTL),
	})
	if err := cloudflareRequest(method, endpoint, token, body, nil); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	result.Message = "Cloudflare DNS 记录已同步"
	return result
}

func executeAliyunDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	cfg, err := aliyunConfig(provider.Config, record)
	if err != nil {
		result.OK = false
		result.Action = "aliyun_invalid"
		result.Message = err.Error()
		return result
	}
	action := "UpdateDomainRecord"
	params := map[string]string{
		"RecordId": cfg.RecordID,
		"RR":       cfg.RR,
		"Type":     record.RecordType,
		"Value":    value,
	}
	result.Action = "aliyun_update"
	if cfg.RecordID == "" {
		action = "AddDomainRecord"
		params = map[string]string{
			"DomainName": cfg.DomainName,
			"RR":         cfg.RR,
			"Type":       record.RecordType,
			"Value":      value,
		}
		result.Action = "aliyun_create"
	}
	if dryRun {
		result.Action = "aliyun_dry_run"
		result.Message = "Aliyun DNS 请求已生成但未发送"
		return result
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil || secret == "" {
		result.OK = false
		result.Action = "aliyun_secret_missing"
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Message = "Aliyun access key secret_ref required"
		}
		return result
	}
	endpoint, err := aliyunSignedURL(cfg, action, params, secret)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	if err := aliyunRequest(endpoint); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	result.Message = "Aliyun DNS 记录已同步"
	return result
}

func executeTencentDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	cfg, err := tencentConfig(provider.Config, record)
	if err != nil {
		result.OK = false
		result.Action = "tencent_invalid"
		result.Message = err.Error()
		return result
	}
	if dryRun {
		result.Action = "tencent_dry_run"
		result.Message = "Tencent DNSPod 查询和更新请求已生成但未发送"
		return result
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil || secret == "" {
		result.OK = false
		result.Action = "tencent_secret_missing"
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Message = "Tencent secret key secret_ref required"
		}
		return result
	}
	secretID, secretKey, err := parseTencentCredentials(secret)
	if err != nil {
		result.OK = false
		result.Action = "tencent_secret_invalid"
		result.Message = err.Error()
		return result
	}
	if secretID != "" {
		cfg.SecretID = secretID
	}
	if cfg.RecordID == 0 {
		cfg.RecordID, err = lookupTencentRecordID(cfg, record, secretKey)
		if err != nil {
			result.OK = false
			result.Action = "tencent_lookup_failed"
			result.Message = err.Error()
			return result
		}
	}
	action := "ModifyRecord"
	payload := map[string]any{
		"Domain":     cfg.Domain,
		"RecordId":   cfg.RecordID,
		"SubDomain":  cfg.SubDomain,
		"RecordType": record.RecordType,
		"RecordLine": cfg.RecordLine,
		"Value":      value,
		"TTL":        normalizedTTL(record.TTL),
	}
	result.Action = "tencent_update"
	if cfg.RecordID == 0 {
		action = "CreateRecord"
		delete(payload, "RecordId")
		result.Action = "tencent_create"
	}
	body, _ := json.Marshal(payload)
	req, err := tencentSignedRequest(cfg, action, body, secretKey)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	if err := tencentRequest(req); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	result.Message = "Tencent DNSPod 记录已同步"
	return result
}

func parseTencentCredentials(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("Tencent credentials are empty")
	}
	if strings.HasPrefix(raw, "{") {
		var bundle struct {
			SecretID  string `json:"secret_id"`
			SecretKey string `json:"secret_key"`
		}
		if err := json.Unmarshal([]byte(raw), &bundle); err != nil {
			return "", "", errors.New("Tencent credentials are invalid")
		}
		bundle.SecretID = strings.TrimSpace(bundle.SecretID)
		bundle.SecretKey = strings.TrimSpace(bundle.SecretKey)
		if bundle.SecretID == "" || bundle.SecretKey == "" {
			return "", "", errors.New("Tencent credentials require SecretId and SecretKey")
		}
		return bundle.SecretID, bundle.SecretKey, nil
	}
	// Backward compatibility for installations that stored only SecretKey.
	return "", raw, nil
}

func lookupTencentRecordID(cfg tencentProviderConfig, record ddnsRecordItem, secret string) (int64, error) {
	payload, _ := json.Marshal(map[string]any{
		"Domain":       cfg.Domain,
		"SubDomain":    cfg.SubDomain,
		"RecordType":   record.RecordType,
		"RecordLine":   cfg.RecordLine,
		"Limit":        100,
		"ErrorOnEmpty": "no",
	})
	req, err := tencentSignedRequest(cfg, "DescribeRecordList", payload, secret)
	if err != nil {
		return 0, err
	}
	data, err := tencentRequestData(req)
	if err != nil {
		return 0, err
	}
	var response struct {
		Response struct {
			Records []struct {
				ID   int64  `json:"RecordId"`
				Name string `json:"Name"`
				Type string `json:"Type"`
				Line string `json:"Line"`
			} `json:"RecordList"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return 0, errors.New("tencent record lookup returned invalid JSON")
	}
	var matched int64
	for _, candidate := range response.Response.Records {
		if candidate.Name != cfg.SubDomain || !strings.EqualFold(candidate.Type, record.RecordType) || candidate.Line != cfg.RecordLine {
			continue
		}
		if matched != 0 && matched != candidate.ID {
			return 0, errors.New("multiple Tencent DNSPod records match this name, type and line")
		}
		matched = candidate.ID
	}
	return matched, nil
}

type tencentProviderConfig struct {
	SecretID   string
	Domain     string
	SubDomain  string
	RecordLine string
	RecordID   int64
	Endpoint   string
}

func tencentConfig(raw json.RawMessage, record ddnsRecordItem) (tencentProviderConfig, error) {
	var cfg tencentProviderConfig
	var input map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return cfg, errors.New("provider config invalid")
	}
	cfg.SecretID = rawString(input["secret_id"])
	cfg.Domain = normalizeDNSName(rawString(input["domain"]))
	cfg.SubDomain = strings.TrimSpace(rawString(input["sub_domain"]))
	cfg.RecordLine = strings.TrimSpace(rawString(input["record_line"]))
	cfg.RecordID = rawInt64(input["record_id"])
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(rawString(input["endpoint_base"])), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://dnspod.tencentcloudapi.com"
	}
	if cfg.SecretID == "" {
		return cfg, errors.New("tencent secret_id required")
	}
	if cfg.Domain == "" {
		return cfg, errors.New("tencent domain required")
	}
	if cfg.SubDomain == "" {
		rr, err := rrFromFQDN(record.FQDN, cfg.Domain)
		if err != nil {
			return cfg, err
		}
		cfg.SubDomain = rr
	}
	if cfg.RecordLine == "" {
		cfg.RecordLine = "默认"
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !localHTTP(u)) {
		return cfg, errors.New("tencent endpoint_base must be https or localhost http")
	}
	return cfg, nil
}

func tencentSignedRequest(cfg tencentProviderConfig, action string, body []byte, secret string) (*http.Request, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	timestamp := time.Now().Unix()
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	service := "dnspod"
	credentialScope := date + "/" + service + "/tc3_request"
	hashedPayload := sha256Hex(body)
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + u.Host + "\nx-tc-action:" + strings.ToLower(action) + "\n"
	signedHeaders := "content-type;host;x-tc-action"
	canonicalRequest := "POST\n" + path + "\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedPayload
	stringToSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(timestamp, 10) + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonicalRequest))
	signingKey := hmacSHA256(hmacSHA256(hmacSHA256([]byte("TC3"+secret), date), service), "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	authz := "TC3-HMAC-SHA256 Credential=" + cfg.SecretID + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	req, err := http.NewRequest(http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("authorization", authz)
	req.Header.Set("content-type", "application/json; charset=utf-8")
	req.Header.Set("host", u.Host)
	req.Header.Set("x-tc-action", action)
	req.Header.Set("x-tc-version", "2021-03-23")
	req.Header.Set("x-tc-timestamp", strconv.FormatInt(timestamp, 10))
	return req, nil
}

func tencentRequest(req *http.Request) error {
	_, err := tencentRequestData(req)
	return err
}

func tencentRequestData(req *http.Request) ([]byte, error) {
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return nil, errors.New("tencent failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	var parsed struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if len(data) > 0 && json.Unmarshal(data, &parsed) == nil && parsed.Response.Error != nil {
		return nil, fmt.Errorf("tencent failed: %s %s", parsed.Response.Error.Code, parsed.Response.Error.Message)
	}
	return data, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func rawInt64(raw json.RawMessage) int64 {
	if len(raw) == 0 {
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return n
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		n, _ = strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return n
	}
	return 0
}

type aliyunProviderConfig struct {
	AccessKeyID string `json:"access_key_id"`
	DomainName  string `json:"domain_name"`
	RR          string `json:"rr"`
	RecordID    string `json:"record_id"`
	Endpoint    string `json:"endpoint_base"`
}

func aliyunConfig(raw json.RawMessage, record ddnsRecordItem) (aliyunProviderConfig, error) {
	var cfg aliyunProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("provider config invalid")
	}
	cfg.AccessKeyID = strings.TrimSpace(cfg.AccessKeyID)
	cfg.DomainName = normalizeDNSName(cfg.DomainName)
	cfg.RR = strings.TrimSpace(cfg.RR)
	cfg.RecordID = strings.TrimSpace(cfg.RecordID)
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://alidns.aliyuncs.com"
	}
	if cfg.AccessKeyID == "" {
		return cfg, errors.New("aliyun access_key_id required")
	}
	if cfg.DomainName == "" {
		return cfg, errors.New("aliyun domain_name required")
	}
	if cfg.RR == "" {
		rr, err := rrFromFQDN(record.FQDN, cfg.DomainName)
		if err != nil {
			return cfg, err
		}
		cfg.RR = rr
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !localHTTP(u)) {
		return cfg, errors.New("aliyun endpoint_base must be https or localhost http")
	}
	return cfg, nil
}

func rrFromFQDN(fqdn, domain string) (string, error) {
	fqdn = normalizeDNSName(fqdn)
	domain = normalizeDNSName(domain)
	if fqdn == domain {
		return "@", nil
	}
	suffix := "." + domain
	if !strings.HasSuffix(fqdn, suffix) {
		return "", errors.New("fqdn must be under aliyun domain_name")
	}
	rr := strings.TrimSuffix(fqdn, suffix)
	if rr == "" {
		return "@", nil
	}
	return rr, nil
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func aliyunSignedURL(cfg aliyunProviderConfig, action string, params map[string]string, secret string) (string, error) {
	values := url.Values{}
	values.Set("Action", action)
	values.Set("Format", "JSON")
	values.Set("Version", "2015-01-09")
	values.Set("AccessKeyId", cfg.AccessKeyID)
	values.Set("SignatureMethod", "HMAC-SHA1")
	values.Set("SignatureVersion", "1.0")
	values.Set("SignatureNonce", randomNonce())
	values.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	for k, v := range params {
		if strings.TrimSpace(v) != "" {
			values.Set(k, v)
		}
	}
	canonical := values.Encode()
	stringToSign := "GET&%2F&" + url.QueryEscape(canonical)
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	if _, err := mac.Write([]byte(stringToSign)); err != nil {
		return "", err
	}
	values.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return cfg.Endpoint + "/?" + values.Encode(), nil
}

func aliyunRequest(endpoint string) error {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return errors.New("aliyun failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	var parsed map[string]any
	if len(data) > 0 && json.Unmarshal(data, &parsed) == nil {
		if code, ok := parsed["Code"].(string); ok && code != "" {
			return fmt.Errorf("aliyun failed: %s", code)
		}
	}
	return nil
}

func randomNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

type cloudflareProviderConfig struct {
	ZoneID       string `json:"zone_id"`
	RecordID     string `json:"record_id"`
	EndpointBase string `json:"endpoint_base"`
}

func cloudflareConfig(raw json.RawMessage) (cloudflareProviderConfig, error) {
	var cfg cloudflareProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("provider config invalid")
	}
	cfg.ZoneID = strings.TrimSpace(cfg.ZoneID)
	cfg.RecordID = strings.TrimSpace(cfg.RecordID)
	cfg.EndpointBase = strings.TrimRight(strings.TrimSpace(cfg.EndpointBase), "/")
	if cfg.EndpointBase == "" {
		cfg.EndpointBase = "https://api.cloudflare.com/client/v4"
	}
	if cfg.ZoneID == "" {
		return cfg, errors.New("cloudflare zone_id required")
	}
	u, err := url.Parse(cfg.EndpointBase)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !localHTTP(u)) {
		return cfg, errors.New("cloudflare endpoint_base must be https or localhost http")
	}
	return cfg, nil
}

func lookupCloudflareRecord(cfg cloudflareProviderConfig, token string, record ddnsRecordItem) (string, error) {
	endpoint := cfg.EndpointBase + "/zones/" + url.PathEscape(cfg.ZoneID) + "/dns_records?type=" + url.QueryEscape(record.RecordType) + "&name=" + url.QueryEscape(record.FQDN)
	var parsed struct {
		Success bool `json:"success"`
		Result  []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := cloudflareRequest(http.MethodGet, endpoint, token, nil, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Result) == 0 {
		return "", nil
	}
	return parsed.Result[0].ID, nil
}

func cloudflareRequest(method, endpoint, token string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, endpoint, reader)
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	// Only attach the Bearer token to Cloudflare's official API (or to
	// loopback test servers when allowLocalProbeHosts is enabled). Custom
	// endpoint_base values (proxies, mirrors, test servers) must NOT receive
	// the credential — sending it would leak the token to an attacker-chosen
	// host via the admin-configurable endpoint.
	official := false
	if u, perr := url.Parse(endpoint); perr == nil {
		host := strings.ToLower(u.Hostname())
		official = host == "api.cloudflare.com" || strings.HasSuffix(host, ".api.cloudflare.com")
	}
	if official || (allowLocalProbeHosts && strings.HasPrefix(endpoint, "http://127.0.0.1")) {
		req.Header.Set("authorization", "Bearer "+token)
	}
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return errors.New("cloudflare failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func localHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := strings.Split(u.Host, ":")[0]
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func normalizedTTL(ttl int) int {
	if ttl < 1 {
		return 1
	}
	return ttl
}

func webhookEndpoint(raw json.RawMessage) (string, error) {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", errors.New("provider config invalid")
	}
	endpoint, _ := cfg["endpoint"].(string)
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("valid webhook endpoint required")
	}
	return endpoint, nil
}

func readProviderSecret(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	clean, err := filepath.Abs(ref)
	if err != nil {
		return "", err
	}
	allowed := []string{"/etc/porthub/secrets", filepath.Join(dataDir, "secrets")}
	ok := false
	for _, base := range allowed {
		baseAbs, _ := filepath.Abs(base)
		if clean == baseAbs || strings.HasPrefix(clean, baseAbs+string(os.PathSeparator)) {
			ok = true
			break
		}
	}
	if !ok {
		return "", errors.New("secret_ref must be under /etc/porthub/secrets or Core secrets directory")
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return "", err
	}
	if len(data) > 8192 {
		return "", errors.New("secret_ref too large")
	}
	return strings.TrimSpace(string(data)), nil
}
