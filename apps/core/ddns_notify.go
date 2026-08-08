package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Record-level DDNS result notification.
// notify_webhook accepts either a plain URL or a JSON object:
//
//	{"url":"https://example.com/hook","secret_ref":"/etc/porthub/secrets/hook-token","method":"POST","template":"{\"fqdn\":\"{fqdn}\",\"ip\":\"{ip}\",\"status\":\"{status}\"}"}
//
// Template placeholders: {fqdn} {ip} {type} {status} {action} {message} {time}.

type ddnsNotifyConfig struct {
	URL       string `json:"url"`
	SecretRef string `json:"secret_ref"`
	Method    string `json:"method"`
	Template  string `json:"template"`
}

func parseDDNSNotify(raw string) (ddnsNotifyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ddnsNotifyConfig{}, errors.New("empty notify webhook")
	}
	var cfg ddnsNotifyConfig
	if strings.HasPrefix(raw, "{") {
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return cfg, errors.New("invalid notify_webhook JSON")
		}
	} else {
		cfg.URL = raw
	}
	cfg.URL = strings.TrimSpace(cfg.URL)
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return cfg, errors.New("valid notify webhook URL required")
	}
	cfg.Method = strings.ToUpper(strings.TrimSpace(cfg.Method))
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.Method != http.MethodPost && cfg.Method != http.MethodGet && cfg.Method != http.MethodPut {
		return cfg, errors.New("notify webhook method must be POST/GET/PUT")
	}
	if cfg.Template == "" {
		cfg.Template = `{"fqdn":"{fqdn}","ip":"{ip}","type":"{type}","status":"{status}","action":"{action}","message":"{message}","time":"{time}"}`
	}
	return cfg, nil
}

// notifyDDNSResult delivers a result notification asynchronously. Failures are
// logged but never affect the sync result.
func notifyDDNSResult(record ddnsRecordItem, result ddnsSyncResult, value string) {
	if strings.TrimSpace(record.NotifyWebhook) == "" {
		return
	}
	cfg, err := parseDDNSNotify(record.NotifyWebhook)
	if err != nil {
		logDDNSNotifyFailure(record, err)
		return
	}
	go func() {
		if err := deliverDDNSNotify(cfg, record, result, value); err != nil {
			logDDNSNotifyFailure(record, err)
		}
	}()
}

func deliverDDNSNotify(cfg ddnsNotifyConfig, record ddnsRecordItem, result ddnsSyncResult, value string) error {
	status := "success"
	if !result.OK {
		status = "failed"
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	payload := strings.NewReplacer(
		"{fqdn}", record.FQDN,
		"{ip}", value,
		"{type}", record.RecordType,
		"{status}", status,
		"{action}", result.Action,
		"{message}", result.Message,
		"{time}", now,
	).Replace(cfg.Template)

	var bodyReader io.Reader
	if cfg.Method != http.MethodGet {
		bodyReader = bytes.NewReader([]byte(payload))
	}
	req, err := http.NewRequest(cfg.Method, cfg.URL, bodyReader)
	if err != nil {
		return err
	}
	if cfg.Method != http.MethodGet {
		req.Header.Set("content-type", "application/json")
	}
	if strings.TrimSpace(cfg.SecretRef) != "" {
		token, err := readProviderSecret(cfg.SecretRef)
		if err != nil {
			return err
		}
		if token != "" {
			req.Header.Set("authorization", "Bearer "+token)
		}
	}
	resp, err := safeOutboundClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return errors.New("ddns notify failed: " + strconv.Itoa(resp.StatusCode) + " " + string(data))
	}
	return nil
}

func logDDNSNotifyFailure(record ddnsRecordItem, err error) {
	log.Printf("ddns notify failed record=%d fqdn=%q: %v", record.ID, record.FQDN, err)
}
