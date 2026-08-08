package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Huawei Cloud DNS (云解析) provider.
// API: https://dns.myhuaweicloud.com  (HWS SDK-HMAC-SHA256 signature)

const huaweiEndpoint = "https://dns.myhuaweicloud.com"

type huaweiProviderConfig struct {
	AccessKey  string `json:"access_key"`
	DomainName string `json:"domain_name"`
	RecordID   string `json:"record_id"`
	ZoneID     string `json:"zone_id"`
	Endpoint   string `json:"endpoint_base"`
}

type huaweiRecordset struct {
	ID      string   `json:"id,omitempty"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
	ZoneID  string   `json:"zone_id,omitempty"`
}

func huaweiConfig(raw json.RawMessage, record ddnsRecordItem) (huaweiProviderConfig, error) {
	var cfg huaweiProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("provider config invalid")
	}
	cfg.AccessKey = strings.TrimSpace(cfg.AccessKey)
	cfg.DomainName = normalizeDNSName(cfg.DomainName)
	cfg.RecordID = strings.TrimSpace(cfg.RecordID)
	cfg.ZoneID = strings.TrimSpace(cfg.ZoneID)
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = huaweiEndpoint
	}
	if cfg.AccessKey == "" {
		return cfg, errors.New("huawei access_key required")
	}
	if cfg.DomainName == "" {
		return cfg, errors.New("huawei domain_name required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !localHTTP(u)) {
		return cfg, errors.New("huawei endpoint_base must be https or localhost http")
	}
	return cfg, nil
}

func executeHuaweiDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	cfg, err := huaweiConfig(provider.Config, record)
	if err != nil {
		result.OK = false
		result.Action = "huawei_invalid"
		result.Message = err.Error()
		return result
	}
	if dryRun {
		result.Action = "huawei_dry_run"
		result.Message = "Huawei DNS 请求已生成但未发送"
		return result
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil || secret == "" {
		result.OK = false
		result.Action = "huawei_secret_missing"
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Message = "huawei secret_ref required"
		}
		return result
	}
	fqdn := record.FQDN
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	recordID := cfg.RecordID
	zoneID := cfg.ZoneID
	method := http.MethodPut
	path := ""
	if recordID == "" {
		foundID, foundZone, lookupErr := lookupHuaweiRecord(cfg, secret, record, fqdn)
		if lookupErr != nil {
			result.OK = false
			result.Action = "huawei_lookup_failed"
			result.Message = lookupErr.Error()
			return result
		}
		recordID = foundID
		if foundZone != "" && zoneID == "" {
			zoneID = foundZone
		}
	}
	if recordID == "" {
		// Record does not exist yet: create it, resolving the zone first.
		result.Action = "huawei_create"
		method = http.MethodPost
		if zoneID == "" {
			zoneID, err = lookupHuaweiZone(cfg, secret)
			if err != nil {
				result.OK = false
				result.Action = "huawei_zone_lookup_failed"
				result.Message = err.Error()
				return result
			}
		}
		path = "/v2/zones/" + url.PathEscape(zoneID) + "/recordsets"
	} else {
		// Existing record: update it. The zone id may have been resolved from
		// the recordset itself; resolve it explicitly when still empty so the
		// update path never uses an empty zone id.
		result.Action = "huawei_update"
		method = http.MethodPut
		if zoneID == "" {
			zoneID, err = lookupHuaweiZone(cfg, secret)
			if err != nil {
				result.OK = false
				result.Action = "huawei_zone_lookup_failed"
				result.Message = err.Error()
				return result
			}
		}
		path = "/v2/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(recordID)
	}
	body, _ := json.Marshal(huaweiRecordset{
		Name:    fqdn,
		Type:    record.RecordType,
		TTL:     normalizedTTL(record.TTL),
		Records: []string{value},
	})
	req, err := huaweiSignedRequest(method, cfg.Endpoint+path, body, cfg.AccessKey, secret)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	if err := huaweiRequest(req); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	result.Message = "Huawei DNS 记录已同步"
	return result
}

func lookupHuaweiZone(cfg huaweiProviderConfig, secret string) (string, error) {
	u := cfg.Endpoint + "/v2/zones?name=" + url.QueryEscape(cfg.DomainName)
	req, err := huaweiSignedRequest(http.MethodGet, u, nil, cfg.AccessKey, secret)
	if err != nil {
		return "", err
	}
	var parsed struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
	}
	if err := huaweiRequestInto(req, &parsed); err != nil {
		return "", err
	}
	for _, zone := range parsed.Zones {
		if strings.TrimSuffix(strings.ToLower(zone.Name), ".") == cfg.DomainName {
			return zone.ID, nil
		}
	}
	return "", errors.New("huawei zone not found for " + cfg.DomainName)
}

func lookupHuaweiRecord(cfg huaweiProviderConfig, secret string, record ddnsRecordItem, fqdn string) (recordID, zoneID string, err error) {
	u := cfg.Endpoint + "/v2/recordsets?name=" + url.QueryEscape(fqdn) + "&type=" + url.QueryEscape(record.RecordType)
	req, err := huaweiSignedRequest(http.MethodGet, u, nil, cfg.AccessKey, secret)
	if err != nil {
		return "", "", err
	}
	var parsed struct {
		Recordsets []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			ZoneID string `json:"zone_id"`
		} `json:"recordsets"`
	}
	if err := huaweiRequestInto(req, &parsed); err != nil {
		return "", "", err
	}
	for _, rs := range parsed.Recordsets {
		if strings.EqualFold(rs.Name, fqdn) {
			return rs.ID, rs.ZoneID, nil
		}
	}
	return "", "", nil
}

func huaweiSignedRequest(method, endpoint string, body []byte, accessKey, secret string) (*http.Request, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	now := time.Now().UTC().Format("20060102T150405Z")
	req.Header.Set("x-sdk-date", now)

	// Signed headers: all present headers sorted; host is always included.
	signedHeaders := []string{}
	headerMap := map[string][]string{}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		headerMap[lk] = v
		signedHeaders = append(signedHeaders, lk)
	}
	headerMap["host"] = []string{u.Host}
	signedHeaders = append(signedHeaders, "host")
	sort.Strings(signedHeaders)
	seen := map[string]bool{}
	unique := signedHeaders[:0]
	for _, h := range signedHeaders {
		if !seen[h] {
			seen[h] = true
			unique = append(unique, h)
		}
	}
	signedHeaders = unique

	// Canonical request
	payloadHash := sha256Hex(body)
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaders {
		vals := headerMap[h]
		sort.Strings(vals)
		for _, v := range vals {
			canonicalHeaders.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
		}
	}
	canonicalQuery := ""
	if u.RawQuery != "" {
		queryKeys := []string{}
		query := u.Query()
		for k := range query {
			queryKeys = append(queryKeys, k)
		}
		sort.Strings(queryKeys)
		parts := []string{}
		for _, k := range queryKeys {
			vals := query[k]
			sort.Strings(vals)
			for _, v := range vals {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		canonicalQuery = strings.Join(parts, "&")
	}
	canonicalURI := huaweiCanonicalURI(u.Path)
	canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuery + "\n" + canonicalHeaders.String() + "\n" + strings.Join(signedHeaders, ";") + "\n" + payloadHash
	hashed := sha256Hex([]byte(canonicalRequest))
	stringToSign := "SDK-HMAC-SHA256\n" + now + "\n" + hashed
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	signature := fmt.Sprintf("%x", mac.Sum(nil))
	req.Header.Set("authorization", "SDK-HMAC-SHA256 Access="+accessKey+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+signature)
	return req, nil
}

func huaweiCanonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	var uri []string
	for _, v := range parts {
		uri = append(uri, url.PathEscape(v))
	}
	joined := strings.Join(uri, "/")
	if !strings.HasSuffix(joined, "/") {
		joined += "/"
	}
	return joined
}

func huaweiRequest(req *http.Request) error {
	return huaweiRequestInto(req, nil)
}

func huaweiRequestInto(req *http.Request, out any) error {
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return errors.New("huawei failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
