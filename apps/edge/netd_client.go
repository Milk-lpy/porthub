package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var edgeNetdSocket = "/run/porthub/edge-netd.sock"

type edgeNetdOutput struct {
	Output string `json:"output"`
}

type edgeNetdWireGuardPeerRequest struct {
	Action     string   `json:"action"`
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	Keepalive  int      `json:"keepalive,omitempty"`
}

func edgeNetdRequest(method, path string, payload any, result any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", edgeNetdSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	request, err := http.NewRequestWithContext(ctx, method, "http://netd"+path, body)
	if err != nil {
		return err
	}
	if payload != nil {
		request.Header.Set("content-type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("porthub-netd unavailable: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("porthub-netd rejected request: %s", strings.TrimSpace(string(responseBody)))
	}
	if result != nil && len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, result); err != nil {
			return fmt.Errorf("invalid porthub-netd response: %w", err)
		}
	}
	return nil
}

func edgeNetdApplyNFT(path string) error {
	return edgeNetdRequest(http.MethodPost, "/v1/nft/apply", map[string]string{"path": path, "table": "porthub"}, nil)
}

func edgeNetdOutputRequest(path string) ([]byte, error) {
	var result edgeNetdOutput
	if err := edgeNetdRequest(http.MethodGet, path, nil, &result); err != nil {
		return nil, err
	}
	return []byte(result.Output), nil
}

func edgeNetdListNFT() ([]byte, error) {
	return edgeNetdOutputRequest("/v1/nft/list")
}

func edgeNetdListConntrack() ([]byte, error) {
	return edgeNetdOutputRequest("/v1/conntrack/list")
}

func edgeNetdWireGuardCommand(args ...string) ([]byte, error) {
	if len(args) == 3 && args[0] == "show" && args[1] == managedWireGuardInterface {
		field := url.QueryEscape(args[2])
		return edgeNetdOutputRequest("/v1/wireguard/show?field=" + field)
	}
	if len(args) < 5 || args[0] != "set" || args[1] != managedWireGuardInterface || args[2] != "peer" {
		return nil, errors.New("unsupported WireGuard operation")
	}
	request := edgeNetdWireGuardPeerRequest{PublicKey: args[3]}
	if len(args) == 5 && args[4] == "remove" {
		request.Action = "remove"
	} else {
		if (len(args) != 6 && len(args) != 8) || args[4] != "allowed-ips" {
			return nil, errors.New("unsupported WireGuard peer settings")
		}
		request.Action = "set"
		request.AllowedIPs = strings.Split(args[5], ",")
		if len(args) == 8 {
			if args[6] != "persistent-keepalive" {
				return nil, errors.New("unsupported WireGuard peer setting")
			}
			keepalive, err := strconv.Atoi(args[7])
			if err != nil {
				return nil, errors.New("invalid WireGuard keepalive")
			}
			request.Keepalive = keepalive
		}
	}
	if err := edgeNetdRequest(http.MethodPost, "/v1/wireguard/peer", request, nil); err != nil {
		return nil, err
	}
	return []byte("ok\n"), nil
}
