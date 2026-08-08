package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type webhookConfig struct {
	Event          string         `json:"event"`
	URL            string         `json:"url"`
	Method         string         `json:"method"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	Retries        int            `json:"retries"`
	SecretRef      string         `json:"secret_ref"`
	Headers        map[string]any `json:"headers"`
}

type webhookEvent struct {
	Event  string `json:"event"`
	Action string `json:"action"`
	Actor  string `json:"actor"`
	Detail string `json:"detail"`
	TS     string `json:"ts"`
}

func dispatchWebhookEvent(actionActor, action, detail, ts string) {
	event := eventForAuditAction(action)
	if event == "" || db == nil {
		return
	}
	items, err := loadEnabledWebhooks(event)
	if err != nil {
		return
	}
	payload := webhookEvent{Event: event, Action: action, Actor: actionActor, Detail: detail, TS: ts}
	for _, item := range items {
		cfg, err := parseWebhookConfig(item.Data)
		if err != nil || cfg.Event != event {
			continue
		}
		go deliverWebhook(item.Name, cfg, payload)
	}
}

func eventForAuditAction(action string) string {
	switch {
	case action == "deploy_success":
		return "snapshot.applied"
	case action == "deploy_failed":
		return "snapshot.failed"
	case action == "ddns_sync":
		return "ddns.changed"
	case strings.HasPrefix(action, "mapping_"):
		return "mapping.changed"
	case action == "certificate_acme_prepare" || strings.HasPrefix(action, "certificate_"):
		return "certificate.changed"
	default:
		return ""
	}
}

func loadEnabledWebhooks(event string) ([]genericItem, error) {
	rows, err := db.Query("select id,name,description,data,enabled,created_at,updated_at from webhooks where enabled=1 order by id desc")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []genericItem
	for rows.Next() {
		var item genericItem
		var enabled int
		rows.Scan(&item.ID, &item.Name, &item.Description, &item.Data, &enabled, &item.CreatedAt, &item.UpdatedAt)
		item.Enabled = enabled == 1
		if webhookDataEvent(item.Data) == event {
			out = append(out, item)
		}
	}
	return out, nil
}

func webhookDataEvent(data string) string {
	var cfg webhookConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return ""
	}
	return cfg.Event
}

func parseWebhookConfig(data string) (webhookConfig, error) {
	var cfg webhookConfig
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return cfg, err
	}
	cfg.Event = strings.TrimSpace(cfg.Event)
	cfg.URL = strings.TrimSpace(cfg.URL)
	cfg.Method = strings.ToUpper(strings.TrimSpace(cfg.Method))
	if cfg.Method == "" {
		cfg.Method = http.MethodPost
	}
	if cfg.Method != http.MethodPost && cfg.Method != http.MethodPut {
		return cfg, errors.New("webhook method must be POST or PUT")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return cfg, errors.New("valid webhook https url required (http allowed only for localhost)")
	}
	isHTTPS := u.Scheme == "https"
	isLocalHTTP := u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
	if !isHTTPS && !isLocalHTTP {
		return cfg, errors.New("webhook url must use https (or http for localhost only)")
	}
	if cfg.TimeoutSeconds < 1 {
		cfg.TimeoutSeconds = 8
	}
	if cfg.TimeoutSeconds > 30 {
		cfg.TimeoutSeconds = 30
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	if cfg.Retries > 5 {
		cfg.Retries = 5
	}
	return cfg, nil
}

func deliverWebhook(name string, cfg webhookConfig, payload webhookEvent) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	secret, err := readProviderSecret(cfg.SecretRef)
	if err != nil {
		return err
	}
	client := safeOutboundClient(time.Duration(cfg.TimeoutSeconds) * time.Second)
	var lastErr error
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		req, err := http.NewRequest(cfg.Method, cfg.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("content-type", "application/json")
		req.Header.Set("X-PortHub-Event", payload.Event)
		req.Header.Set("X-PortHub-Webhook", name)
		req.Header.Set("X-PortHub-Timestamp", payload.TS)
		req.Header.Set("X-PortHub-Attempt", strconv.Itoa(attempt+1))
		for key, value := range cfg.Headers {
			if safeWebhookHeader(key) {
				req.Header.Set(key, strings.TrimSpace(toString(value)))
			}
		}
		if secret != "" {
			req.Header.Set("X-PortHub-Signature", "sha256="+webhookSignature(secret, body))
		}
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode < 500 {
				if resp.StatusCode >= 300 {
					return errors.New("webhook failed with status " + strconv.Itoa(resp.StatusCode))
				}
				return nil
			}
			lastErr = errors.New("webhook failed with status " + strconv.Itoa(resp.StatusCode))
		} else if err != nil {
			lastErr = err
		}
		if attempt < cfg.Retries {
			time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
		}
	}
	return lastErr
}

func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func safeWebhookHeader(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	lower := strings.ToLower(key)
	blocked := lower == "authorization" || lower == "cookie" || lower == "proxy-authorization" ||
		lower == "host" || strings.HasPrefix(lower, "x-porthub-")
	return !blocked
}

func toString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func scanWebhookRows(rows *sql.Rows) []genericItem {
	return scanGeneric(rows)
}
