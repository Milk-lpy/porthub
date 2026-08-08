package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// relayRule is the validated relay rule shape accepted from Core.
type relayRule struct {
	ID              int      `json:"id"`
	Name            string   `json:"name"`
	ListenFamily    string   `json:"listen_family"`
	ListenAddress   string   `json:"listen_address"`
	ListenPortStart int      `json:"listen_port_start"`
	ListenPortEnd   int      `json:"listen_port_end"`
	Protocol        string   `json:"protocol"`
	TargetHost      string   `json:"target_host"`
	TargetPortStart int      `json:"target_port_start"`
	TargetPortEnd   int      `json:"target_port_end"`
	AllowedCIDRs    []string `json:"allowed_cidrs,omitempty"`
	DeniedCIDRs     []string `json:"denied_cidrs,omitempty"`
	RateLimitKbps   int      `json:"rate_limit_kbps"`
	UDPIdleTimeout  int      `json:"udp_idle_timeout"`
}

type relayConfig struct {
	Rules []relayRule `json:"rules"`
}

// applyRelayConfig validates a relay configuration, writes it atomically
// and restarts the relay unit. It is a structured interface: Core never
// executes arbitrary shell; netd owns the write + service restart.
func applyRelayConfig(w http.ResponseWriter, r *http.Request, cfg serverConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var config relayConfig
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		http.Error(w, "invalid relay config: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(config.Rules) > 256 {
		http.Error(w, "too many relay rules", http.StatusBadRequest)
		return
	}
	seen := []relayRule{}
	for i, rule := range config.Rules {
		if err := validateRelayRule(rule); err != nil {
			http.Error(w, fmt.Sprintf("rule %d: %v", i, err), http.StatusBadRequest)
			return
		}
		for _, other := range seen {
			if relayRulesOverlap(rule, other) {
				http.Error(w, fmt.Sprintf("rule %d collides with an earlier relay rule (%s)", i, other.Name), http.StatusBadRequest)
				return
			}
		}
		seen = append(seen, rule)
	}
	// Write config atomically.
	if err := os.MkdirAll(filepath.Dir(cfg.relayConfigPath), 0750); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, _ := json.MarshalIndent(config, "", "  ")
	tmp := cfg.relayConfigPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, cfg.relayConfigPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// The relay service runs as its own unprivileged user; make sure it can
	// read the config we just wrote (netd runs as root).
	if relayUID, relayGID, ok := relayServiceIDs(); ok {
		if err := os.Chown(cfg.relayConfigPath, relayUID, relayGID); err != nil {
			http.Error(w, "relay config chown failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Restart the relay service so it picks up the new configuration.
	if cfg.relayServiceName != "" {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		output, exceeded, err := runBoundedCommand(ctx, "systemctl", "restart", cfg.relayServiceName)
		if exceeded {
			http.Error(w, "systemctl output too large", http.StatusInternalServerError)
			return
		}
		if err != nil {
			http.Error(w, "relay restart failed: "+strings.TrimSpace(output), http.StatusBadGateway)
			return
		}
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "rules": len(config.Rules)})
}

func validateRelayRule(rule relayRule) error {
	if rule.ID < 1 {
		return errors.New("rule id required")
	}
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("name required")
	}
	if rule.ListenPortStart < 1 || rule.ListenPortStart > 65535 || rule.ListenPortEnd < 1 || rule.ListenPortEnd > 65535 {
		return errors.New("invalid listen port range")
	}
	if rule.ListenPortEnd < rule.ListenPortStart {
		return errors.New("listen port end precedes start")
	}
	if rule.TargetPortStart < 1 || rule.TargetPortStart > 65535 || rule.TargetPortEnd < 1 || rule.TargetPortEnd > 65535 {
		return errors.New("invalid target port range")
	}
	if rule.ListenPortEnd-rule.ListenPortStart != rule.TargetPortEnd-rule.TargetPortStart {
		return errors.New("listen and target port range lengths differ")
	}
	switch rule.Protocol {
	case "tcp", "udp", "both":
	default:
		return errors.New("protocol must be tcp, udp or both")
	}
	switch rule.ListenFamily {
	case "ipv4", "ipv6":
	default:
		return errors.New("listen_family must be ipv4 or ipv6")
	}
	address := strings.Trim(rule.ListenAddress, "[]")
	if address != "" && address != "*" && address != "0.0.0.0" && address != "::" {
		ip := net.ParseIP(address)
		if ip == nil {
			return errors.New("invalid listen address")
		}
		if rule.ListenFamily == "ipv4" && ip.To4() == nil {
			return errors.New("ipv6 listen address on ipv4 rule")
		}
		if rule.ListenFamily == "ipv6" && ip.To4() != nil {
			return errors.New("ipv4 listen address on ipv6 rule")
		}
	}
	target := strings.Trim(rule.TargetHost, "[]")
	if net.ParseIP(target) == nil {
		if !validHostname(target) {
			return errors.New("target host must be a valid IP or hostname")
		}
	}
	for _, cidr := range append(append([]string{}, rule.AllowedCIDRs...), rule.DeniedCIDRs...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid cidr %q", cidr)
		}
	}
	if rule.RateLimitKbps < 0 {
		return errors.New("rate_limit_kbps cannot be negative")
	}
	if rule.UDPIdleTimeout < 1 {
		return errors.New("udp_idle_timeout must be positive")
	}
	return nil
}

// relayRulesOverlap reports whether two relay rules would compete for the
// same listeners: same family, overlapping listen address, overlapping port
// range, and overlapping protocol.
func relayRulesOverlap(a, b relayRule) bool {
	if a.ListenFamily != b.ListenFamily {
		return false
	}
	if !relayAddressesOverlap(a.ListenAddress, b.ListenAddress) {
		return false
	}
	if a.ListenPortEnd < b.ListenPortStart || b.ListenPortEnd < a.ListenPortStart {
		return false
	}
	return relayProtocolsOverlap(a.Protocol, b.Protocol)
}

func relayAddressesOverlap(a, b string) bool {
	a = strings.Trim(a, "[]")
	b = strings.Trim(b, "[]")
	wild := func(v string) bool { return v == "" || v == "*" || v == "0.0.0.0" || v == "::" }
	if wild(a) || wild(b) {
		return true
	}
	return a == b
}

func relayProtocolsOverlap(a, b string) bool {
	if a == "both" || b == "both" {
		return true
	}
	return a == b
}

func validHostname(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for i, char := range part {
			ok := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-'
			if !ok {
				return false
			}
			if (i == 0 || i == len(part)-1) && char == '-' {
				return false
			}
		}
	}
	return true
}

// relayServiceIDs resolves the uid/gid of the dedicated relay service user so
// netd can hand ownership of the relay config to it. Falls back to the current
// (root) ids when the user does not exist, e.g. in tests.
func relayServiceIDs() (int, int, bool) {
	account, err := user.Lookup("porthub-relay")
	if err != nil {
		return os.Getuid(), os.Getgid(), false
	}
	uid, err1 := strconv.Atoi(account.Uid)
	gid, err2 := strconv.Atoi(account.Gid)
	if err1 != nil || err2 != nil {
		return os.Getuid(), os.Getgid(), false
	}
	return uid, gid, true
}
