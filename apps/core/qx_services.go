package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

var managedServiceAllowlist = map[string]bool{
	"qx-lan-socks":             true,
	"qx-lan-config-http":       true,
	"dst-wireguard":            true,
	"dst-wireguard-health":     true,
	"dst-wireguard-register":   true,
	"prefer-real-ipv6-gateway": true,
}

var managedActionAllowlist = map[string]map[string]bool{
	"qx-lan-socks":             {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"qx-lan-config-http":       {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"dst-wireguard":            {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"dst-wireguard-health":     {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"dst-wireguard-register":   {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"prefer-real-ipv6-gateway": {"restart": true, "enable": true, "disable": true},
}

type managedServiceActionRequest struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}

func managedServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		payload, err := qxNetdJSON(r.Context(), http.MethodGet, "/v1/services", nil, 8*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeRawJSON(w, payload)
	case http.MethodPost:
		var request managedServiceActionRequest
		decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !managedServiceAllowlist[request.Service] {
			http.Error(w, "service is not managed by PortHub", http.StatusForbidden)
			return
		}
		if !managedActionAllowlist[request.Service][request.Action] {
			http.Error(w, "unsupported service action", http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(request)
		payload, err := qxNetdJSON(r.Context(), http.MethodPost, "/v1/services/action", body, 15*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		audit(actor(r), "managed_service_"+request.Action, request.Service)
		writeRawJSON(w, payload)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// Keep the original route working for bookmarks and older frontend builds.
func qxServices(w http.ResponseWriter, r *http.Request) {
	managedServices(w, r)
}

func qxNetdJSON(ctx context.Context, method, path string, body []byte, timeout time.Duration) ([]byte, error) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		return dialer.DialContext(ctx, "unix", netdSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	request, err := http.NewRequestWithContext(ctx, method, "http://netd"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		request.Header.Set("content-type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("PortHub 服务管理助手不可用: %w", err)
	}
	defer response.Body.Close()
	payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		return nil, readErr
	}
	if response.StatusCode >= 300 {
		message := strings.TrimSpace(string(payload))
		if message == "" {
			message = response.Status
		}
		return nil, fmt.Errorf("本机服务操作失败: %s", message)
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("本机服务助手返回了无效响应")
	}
	return payload, nil
}

func writeRawJSON(w http.ResponseWriter, payload []byte) {
	var v any
	if err := json.Unmarshal(payload, &v); err != nil {
		http.Error(w, "invalid upstream response", http.StatusBadGateway)
		return
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
