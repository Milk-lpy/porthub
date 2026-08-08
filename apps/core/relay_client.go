package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// relayRule is the runtime configuration handed to the porthub-relay
// process through netd. It only carries cross-family or domain-target
// rules; same-family rules stay in nftables.
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

// relayConfig is the full configuration file written for the relay.
type relayConfig struct {
	Rules []relayRule `json:"rules"`
}

// applyRelayConfig pushes relay rules to netd, which validates them,
// writes the config file and restarts the relay service. The referenced ACL
// (acl_id) is resolved into concrete allow/deny CIDRs here so the relay
// enforces the same policy as nft rules.
func applyRelayConfig(items []portForwardItem) error {
	body, err := buildRelayConfig(items)
	if err != nil {
		return err
	}
	return netdRequest("/v1/relay/apply", body, 10*time.Second)
}

// resolveForwardACL merges the CIDRs of the item's referenced ACL (acl_id)
// into the item's own allow/deny lists, honoring ACL port/protocol scope.
// When useACL is false (a segment of the forward's port range not covered by
// the ACL), the ACL CIDRs are not applied.
func resolveForwardACL(item portForwardItem, useACL bool) (allowed, denied []string) {
	allowed = append([]string{}, item.AllowedCIDRs...)
	denied = append([]string{}, item.DeniedCIDRs...)
	if !useACL || item.ACLID <= 0 {
		return allowed, denied
	}
	for _, acl := range loadACLRules(0) {
		if acl.ID != strconv.Itoa(item.ACLID) || !acl.Enabled {
			continue
		}
		if !aclScopesPort(acl, item.ListenPortStart, item.ListenPortEnd, item.Protocol) {
			continue
		}
		cidr := strings.TrimSpace(acl.CIDR)
		if cidr == "" {
			continue
		}
		if acl.Action == "deny" || acl.Action == "block" {
			denied = append(denied, cidr)
		} else {
			allowed = append(allowed, cidr)
		}
	}
	return allowed, denied
}

// netdRequest performs a POST to the netd unix socket.
func netdRequest(path string, body []byte, timeout time.Duration) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		return dialer.DialContext(ctx, "unix", netdSocket)
	}}
	client := &http.Client{Transport: transport, Timeout: timeout}
	request, err := http.NewRequest(http.MethodPost, "http://netd"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("porthub-netd unavailable: %w", err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 300 {
		return fmt.Errorf("porthub-netd rejected relay config: %s", strings.TrimSpace(string(data)))
	}
	return nil
}
