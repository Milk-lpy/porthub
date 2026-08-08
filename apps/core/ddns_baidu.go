package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Baidu Cloud BCD (智能云解析) provider.
// API: https://bcd.baidubce.com  (bce-auth-v1 signature)

const baiduEndpoint = "https://bcd.baidubce.com"

type baiduProviderConfig struct {
	AccessKey  string `json:"access_key"`
	DomainName string `json:"domain_name"`
	RecordID   string `json:"record_id"`
	Endpoint   string `json:"endpoint_base"`
}

type baiduRecord struct {
	RecordID uint   `json:"recordId"`
	Domain   string `json:"domain"`
	View     string `json:"view"`
	Rdtype   string `json:"rdtype"`
	TTL      int    `json:"ttl"`
	Rdata    string `json:"rdata"`
	ZoneName string `json:"zoneName"`
}

type baiduRecordsResp struct {
	TotalCount int           `json:"totalCount"`
	Result     []baiduRecord `json:"result"`
}

func baiduConfig(raw json.RawMessage, record ddnsRecordItem) (baiduProviderConfig, error) {
	var cfg baiduProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("provider config invalid")
	}
	cfg.AccessKey = strings.TrimSpace(cfg.AccessKey)
	cfg.DomainName = normalizeDNSName(cfg.DomainName)
	cfg.RecordID = strings.TrimSpace(cfg.RecordID)
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = baiduEndpoint
	}
	if cfg.AccessKey == "" {
		return cfg, errors.New("baidu access_key required")
	}
	if cfg.DomainName == "" {
		return cfg, errors.New("baidu domain_name required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !localHTTP(u)) {
		return cfg, errors.New("baidu endpoint_base must be https or localhost http")
	}
	return cfg, nil
}

func executeBaiduDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	cfg, err := baiduConfig(provider.Config, record)
	if err != nil {
		result.OK = false
		result.Action = "baidu_invalid"
		result.Message = err.Error()
		return result
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil || secret == "" {
		result.OK = false
		result.Action = "baidu_secret_missing"
		if err != nil {
			result.Message = err.Error()
		} else {
			result.Message = "baidu secret_ref required"
		}
		return result
	}
	rr, err := rrFromFQDN(record.FQDN, cfg.DomainName)
	if err != nil {
		result.OK = false
		result.Action = "baidu_invalid"
		result.Message = err.Error()
		return result
	}
	result.Action = "baidu_update"
	if dryRun {
		result.Action = "baidu_dry_run"
		result.Message = "Baidu DNS 请求已生成但未发送"
		return result
	}
	// List records to find the one matching the subdomain.
	listBody, _ := json.Marshal(map[string]any{"domain": cfg.DomainName, "pageNum": 1, "pageSize": 1000})
	req, err := baiduSignedRequest(cfg, "POST", "/v1/domain/resolve/list", listBody, secret)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	var listed baiduRecordsResp
	if err := baiduRequest(req, &listed); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	for _, rec := range listed.Result {
		if rec.Domain == rr && rec.Rdtype == record.RecordType {
			if rec.Rdata == value {
				result.Action = "baidu_noop"
				result.Message = "Baidu DNS 记录已是最新"
				return result
			}
			modifyBody, _ := json.Marshal(map[string]any{
				"recordId": rec.RecordID, "domain": rec.Domain, "view": rec.View,
				"rdType": record.RecordType, "ttl": rec.TTL, "rdata": value, "zoneName": rec.ZoneName,
			})
			req, err := baiduSignedRequest(cfg, "POST", "/v1/domain/resolve/edit", modifyBody, secret)
			if err != nil {
				result.OK = false
				result.Message = err.Error()
				return result
			}
			if err := baiduRequest(req, nil); err != nil {
				result.OK = false
				result.Message = err.Error()
				return result
			}
			result.Message = "Baidu DNS 记录已更新"
			return result
		}
	}
	// Create a new record.
	createBody, _ := json.Marshal(map[string]any{
		"domain": rr, "rdType": record.RecordType, "ttl": normalizedTTL(record.TTL),
		"rdata": value, "zoneName": cfg.DomainName,
	})
	req, err = baiduSignedRequest(cfg, "POST", "/v1/domain/resolve/add", createBody, secret)
	if err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	if err := baiduRequest(req, nil); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	result.Action = "baidu_create"
	result.Message = "Baidu DNS 记录已创建"
	return result
}

func baiduSignedRequest(cfg baiduProviderConfig, method, path string, body []byte, secret string) (*http.Request, error) {
	u, err := url.Parse(cfg.Endpoint + path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	authPrefix := "bce-auth-v1/" + cfg.AccessKey + "/" + timestamp + "/1800"
	canonicalURI := strings.TrimSuffix(u.EscapedPath(), "/")
	canonicalQuery := ""
	if u.RawQuery != "" {
		canonicalQuery = u.RawQuery
	}
	canonicalHeaders := "host:" + u.Host
	canonicalReq := method + "\n" + canonicalURI + "\n" + canonicalQuery + "\n" + canonicalHeaders
	signingKey := hmacSHA256Hex(secret, authPrefix)
	signature := hmacSHA256Hex(signingKey, canonicalReq)
	req.Header.Set("authorization", authPrefix+"/host/"+signature)
	req.Header.Set("x-bce-date", timestamp)
	return req, nil
}

func hmacSHA256Hex(key, message string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func baiduRequest(req *http.Request, out any) error {
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return errors.New("baidu failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	var parsed map[string]any
	if len(data) > 0 && json.Unmarshal(data, &parsed) == nil {
		if code, ok := parsed["code"].(string); ok && code != "" && code != "OK" {
			return fmt.Errorf("baidu failed: %s %v", code, parsed["message"])
		}
	}
	return nil
}
