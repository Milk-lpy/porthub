package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var supportedManagedServices = map[string]bool{
	"qx-lan-socks":             true,
	"qx-lan-config-http":       true,
	"dst-wireguard":            true,
	"dst-wireguard-health":     true,
	"dst-wireguard-register":   true,
	"prefer-real-ipv6-gateway": true,
}

var managedServiceActions = map[string]map[string]bool{
	"qx-lan-socks":             {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"qx-lan-config-http":       {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"dst-wireguard":            {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"dst-wireguard-health":     {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"dst-wireguard-register":   {"start": true, "stop": true, "restart": true, "enable": true, "disable": true},
	"prefer-real-ipv6-gateway": {"restart": true, "enable": true, "disable": true},
}

// Listener discovery deliberately uses only ports owned by the fixed managed
// units. This avoids granting CAP_SYS_PTRACE merely to associate sockets with
// processes.
var managedServicePorts = map[string]map[int]bool{
	"qx-lan-socks":           {10888: true},
	"qx-lan-config-http":     {10889: true},
	"dst-wireguard":          {51821: true},
	"dst-wireguard-health":   {18080: true},
	"dst-wireguard-register": {18081: true, 51822: true},
}

type managedServiceRequest struct {
	Service string `json:"service"`
	Action  string `json:"action"`
}

type managedServiceListener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

type managedServiceState struct {
	Name          string                   `json:"name"`
	Description   string                   `json:"description"`
	ActiveState   string                   `json:"active_state"`
	SubState      string                   `json:"sub_state"`
	UnitFileState string                   `json:"unit_file_state"`
	MainPID       int                      `json:"main_pid"`
	StartedAt     string                   `json:"started_at"`
	Listeners     []managedServiceListener `json:"listeners"`
}

type managedWireGuardState struct {
	Interface       string   `json:"interface"`
	Present         bool     `json:"present"`
	Addresses       []string `json:"addresses"`
	ListenPort      int      `json:"listen_port"`
	PeerCount       int      `json:"peer_count"`
	LatestHandshake int64    `json:"latest_handshake"`
	RXBytes         int64    `json:"rx_bytes"`
	TXBytes         int64    `json:"tx_bytes"`
}

func parseManagedServices(raw string) (map[string]bool, error) {
	services := map[string]bool{}
	for _, value := range strings.Split(raw, ",") {
		name := strings.TrimSpace(value)
		if name == "" {
			continue
		}
		if !supportedManagedServices[name] {
			return nil, fmt.Errorf("service %q is not in the compiled allowlist", name)
		}
		services[name] = true
	}
	return services, nil
}

func managedServicesStatus(w http.ResponseWriter, r *http.Request, cfg serverConfig) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	states, err := readManagedServices(r.Context(), cfg.managedServices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	wireGuard := readManagedWireGuard(r.Context(), "wg-dst")
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"services": states, "wireguard": wireGuard, "updated_at": time.Now().UTC(),
	})
}

func managedServiceAction(w http.ResponseWriter, r *http.Request, cfg serverConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request managedServiceRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !cfg.managedServices[request.Service] {
		http.Error(w, "service is not managed by PortHub", http.StatusForbidden)
		return
	}
	if !managedServiceActions[request.Service][request.Action] {
		http.Error(w, "unsupported service action", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	output, exceeded, err := runBoundedCommand(ctx, "systemctl", request.Action, request.Service+".service")
	if exceeded {
		http.Error(w, "systemctl output is too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		message := strings.TrimSpace(output)
		if message == "" {
			message = err.Error()
		}
		http.Error(w, message, http.StatusServiceUnavailable)
		return
	}
	states, err := readManagedServices(r.Context(), cfg.managedServices)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	wireGuard := readManagedWireGuard(r.Context(), "wg-dst")
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "services": states, "wireguard": wireGuard, "updated_at": time.Now().UTC(),
	})
}

func readManagedServices(ctx context.Context, allowed map[string]bool) ([]managedServiceState, error) {
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)

	listenerOutput, _, listenerErr := runBoundedCommand(ctx, "ss", "-H", "-lntu")
	states := make([]managedServiceState, 0, len(names))
	for _, name := range names {
		commandCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		output, exceeded, err := runBoundedCommand(commandCtx, "systemctl", "show", "--no-pager",
			"--property=Description,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestamp", name+".service")
		cancel()
		if exceeded {
			return nil, errors.New("systemctl output is too large")
		}
		if err != nil {
			return nil, fmt.Errorf("read %s status: %s", name, strings.TrimSpace(output))
		}
		state := parseSystemctlShow(name, output)
		if listenerErr == nil && state.ActiveState == "active" {
			state.Listeners = parseServiceListeners(listenerOutput, name)
		}
		states = append(states, state)
	}
	return states, nil
}

func readManagedWireGuard(ctx context.Context, iface string) managedWireGuardState {
	state := managedWireGuardState{Interface: iface, Addresses: []string{}}
	if output, _, err := runManagedStatusCommand(ctx, "ip", "link", "show", "dev", iface); err != nil || strings.TrimSpace(output) == "" {
		return state
	}
	state.Present = true
	if output, _, err := runManagedStatusCommand(ctx, "ip", "-o", "address", "show", "dev", iface); err == nil {
		state.Addresses = parseInterfaceAddresses(output)
	}
	if output, _, err := runManagedStatusCommand(ctx, "wg", "show", iface, "listen-port"); err == nil {
		state.ListenPort, _ = strconv.Atoi(strings.TrimSpace(output))
	}
	if output, _, err := runManagedStatusCommand(ctx, "wg", "show", iface, "peers"); err == nil {
		state.PeerCount = len(strings.Fields(output))
	}
	if output, _, err := runManagedStatusCommand(ctx, "wg", "show", iface, "latest-handshakes"); err == nil {
		state.LatestHandshake = parseLatestHandshake(output)
	}
	if output, _, err := runManagedStatusCommand(ctx, "wg", "show", iface, "transfer"); err == nil {
		state.RXBytes, state.TXBytes = parseWireGuardTransfer(output)
	}
	return state
}

func runManagedStatusCommand(ctx context.Context, name string, args ...string) (string, bool, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return runBoundedCommand(commandCtx, name, args...)
}

func parseInterfaceAddresses(output string) []string {
	addresses := []string{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && (fields[2] == "inet" || fields[2] == "inet6") {
			addresses = append(addresses, fields[3])
		}
	}
	return addresses
}

func parseLatestHandshake(output string) int64 {
	var latest int64
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, _ := strconv.ParseInt(fields[1], 10, 64)
		if value > latest {
			latest = value
		}
	}
	return latest
}

func parseWireGuardTransfer(output string) (int64, int64) {
	var rx, tx int64
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		received, _ := strconv.ParseInt(fields[1], 10, 64)
		sent, _ := strconv.ParseInt(fields[2], 10, 64)
		rx += received
		tx += sent
	}
	return rx, tx
}

func parseSystemctlShow(name, output string) managedServiceState {
	values := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	pid, _ := strconv.Atoi(values["MainPID"])
	return managedServiceState{
		Name: name, Description: values["Description"], ActiveState: values["ActiveState"],
		SubState: values["SubState"], UnitFileState: values["UnitFileState"], MainPID: pid,
		StartedAt: values["ExecMainStartTimestamp"], Listeners: []managedServiceListener{},
	}
}

func parseServiceListeners(output, service string) []managedServiceListener {
	ports := managedServicePorts[service]
	if len(ports) == 0 {
		return []managedServiceListener{}
	}
	listeners := []managedServiceListener{}
	seen := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		address, port, ok := parseListenerEndpoint(fields[4])
		if !ok {
			continue
		}
		if !ports[port] {
			continue
		}
		protocol := strings.ToLower(fields[0])
		key := fmt.Sprintf("%s|%s|%d", protocol, address, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		listeners = append(listeners, managedServiceListener{Protocol: protocol, Address: address, Port: port})
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Protocol != listeners[j].Protocol {
			return listeners[i].Protocol < listeners[j].Protocol
		}
		if listeners[i].Address != listeners[j].Address {
			return listeners[i].Address < listeners[j].Address
		}
		return listeners[i].Port < listeners[j].Port
	})
	return listeners
}

func parseListenerEndpoint(value string) (string, int, bool) {
	index := strings.LastIndex(value, ":")
	if index < 0 || index == len(value)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[index+1:])
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	address := strings.Trim(value[:index], "[]")
	if address == "*" {
		address = "全部地址"
	}
	return address, port, true
}
