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
	"os"
	"path/filepath"
	"porthub/internal/nftables"
	"porthub/internal/snapshots"
	"strings"
	"time"
)

var coreForwardConfig nftables.CoreForwardConfig
var netdSocket string

func configureCoreForward(lanInterface, lanCIDRs, tunnelCIDRs string) error {
	lan, err := nftables.ParseCIDRs(lanCIDRs)
	if err != nil {
		return err
	}
	tunnel, err := nftables.ParseCIDRs(tunnelCIDRs)
	if err != nil {
		return err
	}
	if lanInterface == "" || lanInterface == "auto" {
		lanInterface, err = detectLANInterface(lan)
		if err != nil {
			return err
		}
	}
	coreForwardConfig = nftables.CoreForwardConfig{
		WGInterface: "wg-porthub", LANInterface: lanInterface, LANCIDRs: lan, TunnelCIDRs: tunnel,
	}
	return nil
}

func detectLANInterface(networks []*net.IPNet) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		if iface.Name == "wg-porthub" || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			for _, network := range networks {
				if network.Contains(ip) {
					return iface.Name, nil
				}
			}
		}
	}
	return "", errors.New("no active interface belongs to a managed LAN network")
}

func compileCoreForward(snapshot snapshots.Snapshot) (string, error) {
	return nftables.CompileCoreForward(snapshot, coreForwardConfig)
}

func applyCoreForward(rules string) (map[string]any, error) {
	directory := filepath.Join(dataDir, "netd")
	if err := os.MkdirAll(directory, 0750); err != nil {
		return nil, err
	}
	candidate := filepath.Join(directory, "core-candidate.nft")
	temporary := candidate + ".tmp"
	if err := os.WriteFile(temporary, []byte(rules), 0640); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, candidate); err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"path": candidate, "table": "porthub_core"})
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		return dialer.DialContext(ctx, "unix", netdSocket)
	}}
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	request, err := http.NewRequest(http.MethodPost, "http://netd/v1/nft/apply", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("porthub-netd unavailable: %w", err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("porthub-netd rejected rules: %s", strings.TrimSpace(string(data)))
	}
	return decodeJSONMap(data)
}
