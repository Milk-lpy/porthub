package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Porkbun DNS provider (api.porkbun.com JSON v3).
// Credentials: secret_ref holds "apikey:secretapikey" or "apikey" only.

const porkbunEndpoint = "https://api.porkbun.com/api/json/v3/dns"

type porkbunProviderConfig struct {
	DomainName string `json:"domain_name"`
	Endpoint   string `json:"endpoint_base"`
}

type porkbunResp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type porkbunRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     string `json:"ttl"`
}

func porkbunConfig(raw json.RawMessage, record ddnsRecordItem) (porkbunProviderConfig, error) {
	var cfg porkbunProviderConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("provider config invalid")
	}
	cfg.DomainName = normalizeDNSName(cfg.DomainName)
	cfg.Endpoint = strings.TrimRight(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Endpoint == "" {
		cfg.Endpoint = porkbunEndpoint
	}
	if cfg.DomainName == "" {
		return cfg, errors.New("porkbun domain_name required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.Scheme != "https" || strings.ToLower(u.Hostname()) != "api.porkbun.com" {
		return cfg, errors.New("porkbun endpoint_base must be https://api.porkbun.com")
	}
	return cfg, nil
}

func porkbunCredentials(secret string) (apiKey, secretKey string, err error) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return "", "", errors.New("porkbun secret_ref required (apikey[:secretapikey])")
	}
	if idx := strings.Index(secret, ":"); idx >= 0 {
		return strings.TrimSpace(secret[:idx]), strings.TrimSpace(secret[idx+1:]), nil
	}
	return secret, "", nil
}

func executePorkbunDDNS(record ddnsRecordItem, provider ddnsProviderItem, value string, dryRun bool, result ddnsSyncResult) ddnsSyncResult {
	cfg, err := porkbunConfig(provider.Config, record)
	if err != nil {
		result.OK = false
		result.Action = "porkbun_invalid"
		result.Message = err.Error()
		return result
	}
	secret, err := readProviderSecret(provider.SecretRef)
	if err != nil {
		result.OK = false
		result.Action = "porkbun_secret_missing"
		result.Message = err.Error()
		return result
	}
	apiKey, secretKey, err := porkbunCredentials(secret)
	if err != nil {
		result.OK = false
		result.Action = "porkbun_secret_missing"
		result.Message = err.Error()
		return result
	}
	rr, err := rrFromFQDN(record.FQDN, cfg.DomainName)
	if err != nil {
		result.OK = false
		result.Action = "porkbun_invalid"
		result.Message = err.Error()
		return result
	}
	result.Action = "porkbun_update"
	if dryRun {
		result.Action = "porkbun_dry_run"
		result.Message = "Porkbun 请求已生成但未发送"
		return result
	}
	auth := map[string]string{"apikey": apiKey}
	if secretKey != "" {
		auth["secretapikey"] = secretKey
	}
	// Look up existing record by name/type.
	var found porkbunRecord
	lookupBody := map[string]any{}
	for k, v := range auth {
		lookupBody[k] = v
	}
	var lookupResp struct {
		porkbunResp
		Records []porkbunRecord `json:"records"`
	}
	if err := porkbunRequest(cfg.Endpoint+"/retrieveByNameType/"+url.PathEscape(cfg.DomainName)+"/"+url.PathEscape(record.RecordType)+"/"+url.PathEscape(rr), lookupBody, &lookupResp); err != nil {
		result.OK = false
		result.Message = err.Error()
		return result
	}
	if lookupResp.Status != "SUCCESS" {
		result.OK = false
		result.Message = "porkbun lookup failed: " + lookupResp.Message
		return result
	}
	for _, rec := range lookupResp.Records {
		if rec.Type == record.RecordType && rec.Name == rr {
			found = rec
			break
		}
	}
	if found.ID != "" && found.Content == value {
		result.Action = "porkbun_noop"
		result.Message = "Porkbun 记录已是最新"
		return result
	}
	recordBody := map[string]any{
		"type": record.RecordType, "content": value, "ttl": strconv.Itoa(normalizedTTL(record.TTL)),
	}
	for k, v := range auth {
		recordBody[k] = v
	}
	var resp porkbunResp
	if found.ID != "" {
		if err := porkbunRequest(cfg.Endpoint+"/editByNameType/"+url.PathEscape(cfg.DomainName)+"/"+url.PathEscape(record.RecordType)+"/"+url.PathEscape(rr), recordBody, &resp); err != nil {
			result.OK = false
			result.Message = err.Error()
			return result
		}
	} else {
		recordBody["name"] = rr
		if err := porkbunRequest(cfg.Endpoint+"/create/"+url.PathEscape(cfg.DomainName), recordBody, &resp); err != nil {
			result.OK = false
			result.Message = err.Error()
			return result
		}
		result.Action = "porkbun_create"
	}
	if resp.Status != "SUCCESS" {
		result.OK = false
		result.Message = "porkbun failed: " + resp.Message
		return result
	}
	result.Message = "Porkbun DNS 记录已同步"
	return result
}

func porkbunRequest(endpoint string, body map[string]any, out any) error {
	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 300 {
		return errors.New("porkbun failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
