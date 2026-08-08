//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var dockerSocketPath = "/var/run/docker.sock"

func discoverListeners() []listener {
	var listeners []listener
	listeners = append(listeners, readProcNet("tcp", "/proc/net/tcp", true)...)
	listeners = append(listeners, readProcNet("tcp6", "/proc/net/tcp6", true)...)
	listeners = append(listeners, readProcNet("udp", "/proc/net/udp", false)...)
	listeners = append(listeners, readProcNet("udp6", "/proc/net/udp6", false)...)
	return listeners
}

func discoverPlatform() string {
	if pathExists("/etc/pve") {
		return "pve"
	}
	if pathExists("/usr/trim/bin/trim_connect") || pathExists("/etc/fnos-release") {
		return "fnos"
	}
	if pathExists("/.dockerenv") {
		return "docker"
	}
	return "linux"
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func discoverContainers() []discoveredContainer {
	socket := dockerSocketPath
	if info, err := os.Stat(socket); err != nil || info.Mode()&os.ModeSocket == 0 {
		return []discoveredContainer{}
	}
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socket)
	}}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, "http://docker/v1.41/containers/json?limit=200", nil)
	response, err := client.Do(request)
	if err != nil {
		return []discoveredContainer{}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return []discoveredContainer{}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return []discoveredContainer{}
	}
	var raw []struct {
		ID     string   `json:"Id"`
		Image  string   `json:"Image"`
		State  string   `json:"State"`
		Status string   `json:"Status"`
		Names  []string `json:"Names"`
		Ports  []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	if json.Unmarshal(body, &raw) != nil {
		return []discoveredContainer{}
	}
	containers := make([]discoveredContainer, 0, len(raw))
	for _, item := range raw {
		name := "container"
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(filepath.Base(item.Names[0]), "/")
		}
		id := item.ID
		if len(id) > 12 {
			id = id[:12]
		}
		ports := make([]containerPort, 0, len(item.Ports))
		for _, port := range item.Ports {
			ports = append(ports, containerPort{IP: port.IP, PrivatePort: port.PrivatePort, PublicPort: port.PublicPort, Protocol: port.Type})
		}
		containers = append(containers, discoveredContainer{ID: id, Name: name, Image: item.Image, State: item.State, Status: item.Status, Ports: ports})
	}
	return containers
}

func readProcNet(proto, path string, requireListen bool) []listener {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []listener
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if requireListen && fields[3] != "0A" {
			continue
		}
		addr, port := parseProcAddr(fields[1])
		if port == 0 {
			continue
		}
		out = append(out, listener{Protocol: proto, Address: addr, Port: port})
	}
	return out
}

func parseProcAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}
	p, _ := strconv.ParseInt(parts[1], 16, 32)
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0
	}
	if len(raw) == 4 {
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String(), int(p)
	}
	if len(raw) == 16 {
		return net.IP(raw).String(), int(p)
	}
	return "", 0
}
