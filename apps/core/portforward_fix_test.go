package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestBlockedOutboundHost(t *testing.T) {
	allowLocalProbeHosts = false
	defer func() { allowLocalProbeHosts = false }()
	blocked := []string{
		"127.0.0.1",
		"::1",
		"localhost",
		"10.20.30.50",
		"10.0.0.5",
		"172.16.0.5",
		"169.254.169.254", // cloud metadata
		"0.0.0.0",
	}
	for _, host := range blocked {
		if _, err := resolveVerifiedOutboundIP(host); err == nil {
			t.Fatalf("expected %s to be blocked", host)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "203.0.113.7", "2606:4700:4700::1111"}
	for _, host := range allowed {
		if _, err := resolveVerifiedOutboundIP(host); err != nil {
			t.Fatalf("expected %s to be allowed: %v", host, err)
		}
	}
}

// TestLiveListenPortsUDP verifies UDP listeners are detected (the previous
// implementation only scanned TCP). We open a real UDP socket and expect its
// port to show up in liveListenPorts under the "udp:" key.
func TestLiveListenPortsUDP(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open udp socket: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	busy := liveListenPorts("ipv4")
	if !busy["udp:ipv4:"+itoa(port)] {
		t.Fatalf("expected udp port %d to be reported busy (keys=%v)", port, busy)
	}
}

// TestRelayOwnPortExclusion verifies that re-validating a relay rule whose
// ports are already bound by porthub-relay itself does not report a false
// "port already in use" collision, while a port NOT held by the relay still
// collides.
func TestRelayOwnPortExclusion(t *testing.T) {
	setupPortForwardTestDB(t)
	oldDataDir := dataDir
	dataDir = t.TempDir()
	defer func() { dataDir = oldDataDir }()

	// A real UDP socket stands in for porthub-relay's live listener.
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot open udp socket: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	// Mock the relay status snapshot: rule 99 reports running=true with the
	// concrete endpoint "udp:<port>" and a fresh updated_at. The mock must
	// carry listen_family so the family-aware expansion can exempt the
	// exact address the candidate listens on.
	status := map[string]any{
		"running":    true,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
		"rules": []map[string]any{{
			"id": 99, "name": "relay-owned", "running": true,
			"protocol": "udp", "port": float64(port),
			"listen": "127.0.0.1", "listen_family": "ipv4",
			"endpoints": []string{"udp:" + itoa(port)},
		}},
	}
	relayDir := filepath.Join(dataDir, "relay")
	if err := os.MkdirAll(relayDir, 0750); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(status)
	if err := os.WriteFile(filepath.Join(relayDir, "status.json"), data, 0640); err != nil {
		t.Fatal(err)
	}

	rule := portForwardItem{
		ID: 99, Name: "relay-owned", NodeID: "local",
		ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: port, ListenPortEnd: port,
		Protocol: "udp", TargetHost: "::1",
		TargetPortStart: port, TargetPortEnd: port,
		ForwardMode: "relay", Enabled: true, UDPIdleTimeout: 30,
	}
	if _, err := db.Exec(`insert into port_forwards(id,name,node_id,listen_family,listen_address,listen_port_start,listen_port_end,protocol,
		target_family,target_host,target_port_start,target_port_end,forward_mode,snat_mode,enabled,acl_id,allowed_cidrs,denied_cidrs,
		rate_limit_kbps,udp_idle_timeout,health_check,last_status,created_at,updated_at)
		values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		rule.ID, rule.Name, rule.NodeID, rule.ListenFamily, rule.ListenAddress,
		rule.ListenPortStart, rule.ListenPortEnd, rule.Protocol,
		"ipv6", rule.TargetHost, rule.TargetPortStart, rule.TargetPortEnd,
		rule.ForwardMode, "auto", 1, 0, "[]", "[]", 0, rule.UDPIdleTimeout, 0, "applied", "now", "now"); err != nil {
		t.Fatal(err)
	}

	// Validating the same rule again must NOT report its own port as a
	// collision, because the relay status shows the relay actually holds it.
	if err := validatePortForwardItem(rule, rule.ID); err != nil {
		t.Fatalf("own relay port flagged as collision: %v", err)
	}

	// A DIFFERENT port on the same host must still collide (relay does not
	// hold it, so it belongs to a foreign service).
	otherRule := rule
	otherRule.ID = 100
	otherRule.Name = "foreign-port"
	// Pick a port that is definitely in use: the UDP socket's own port is
	// held by the relay in the mock, so use the TCP echo of the same range
	// by opening a TCP listener and using its port.
	tcpL, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpL.Close()
	tcpPort := tcpL.Addr().(*net.TCPAddr).Port
	otherRule.ListenPortStart = tcpPort
	otherRule.ListenPortEnd = tcpPort
	otherRule.Protocol = "tcp"
	otherRule.TargetHost = "8.8.8.8"
	if err := validatePortForwardItem(otherRule, otherRule.ID); err == nil {
		t.Fatalf("expected foreign port %d to be flagged as collision", tcpPort)
	}
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
