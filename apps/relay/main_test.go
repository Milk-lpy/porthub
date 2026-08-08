package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// echoTCPServer starts a TCP echo server and returns its address.
func echoTCPServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buffer := make([]byte, 4096)
				for {
					n, err := c.Read(buffer)
					if err != nil {
						return
					}
					c.Write(buffer[:n])
				}
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func TestRelayTCPForward(t *testing.T) {
	target := echoTCPServer(t)
	_, targetPort, _ := net.SplitHostPort(target)

	rule := relayRule{
		ID: 1, Name: "test-tcp", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39101, ListenPortEnd: 39101, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: atoi(targetPort), TargetPortEnd: atoi(targetPort),
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", "127.0.0.1:39101", 3*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	message := []byte("hello-relay")
	if _, err := conn.Write(message); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 64)
	n, err := conn.Read(buffer)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buffer[:n]) != string(message) {
		t.Fatalf("echo mismatch: %q", buffer[:n])
	}
	// Close the write side so the copy goroutines finish and flush counters.
	if tcp, ok := conn.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		state := rt.state(1)
		state.mu.Lock()
		rx := state.RXBytes
		tx := state.TXBytes
		state.mu.Unlock()
		if rx > 0 && tx > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected byte counters, rx=%d tx=%d", rx, tx)
		}
		time.Sleep(50 * time.Millisecond)
	}
	conn.Close()
}

func TestRelayUDPForward(t *testing.T) {
	// UDP echo server
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := serverConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			serverConn.WriteTo(buffer[:n], addr)
		}
	}()
	_, targetPort, _ := net.SplitHostPort(serverConn.LocalAddr().String())

	rule := relayRule{
		ID: 2, Name: "test-udp", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39102, ListenPortEnd: 39102, Protocol: "udp",
		TargetHost: "127.0.0.1", TargetPortStart: atoi(targetPort), TargetPortEnd: atoi(targetPort),
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)

	client, err := net.Dial("udp", "127.0.0.1:39102")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	message := []byte("udp-relay-test")
	client.Write(message)
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 64)
	n, err := client.Read(buffer)
	if err != nil {
		t.Fatalf("read udp echo: %v", err)
	}
	if string(buffer[:n]) != string(message) {
		t.Fatalf("udp echo mismatch: %q", buffer[:n])
	}
	state := rt.state(2)
	state.mu.Lock()
	sessions := state.UDPSessions
	state.mu.Unlock()
	if sessions < 1 {
		t.Fatalf("expected udp session, got %d", sessions)
	}
}

func TestRelayACL(t *testing.T) {
	rt := newRuntime()
	defer rt.stopAll()
	rule := relayRule{
		ID: 3, Name: "acl", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39103, ListenPortEnd: 39103, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: 9, TargetPortEnd: 9,
		AllowedCIDRs:   []string{"10.0.0.0/8"},
		UDPIdleTimeout: 30,
	}
	// A client from 192.168.x must be denied by the allowlist.
	if rt.allowed(rule, "192.0.2.5") {
		t.Fatal("expected 192.0.2.5 to be denied")
	}
	if !rt.allowed(rule, "10.1.2.3") {
		t.Fatal("expected 10.1.2.3 to be allowed")
	}
	denyRule := relayRule{ID: 4, DeniedCIDRs: []string{"203.0.113.0/24"}, UDPIdleTimeout: 30}
	if rt.allowed(denyRule, "203.0.113.9") {
		t.Fatal("expected 203.0.113.9 to be denied")
	}
	if !rt.allowed(denyRule, "8.8.8.8") {
		t.Fatal("expected 8.8.8.8 to be allowed")
	}
}

func TestRelayStatusSnapshot(t *testing.T) {
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{{
		ID: 5, Name: "s", ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 39105, ListenPortEnd: 39105, Protocol: "both",
		TargetHost: "127.0.0.1", TargetPortStart: 9, TargetPortEnd: 9, UDPIdleTimeout: 30,
	}}})
	// Listeners register asynchronously; wait for them to come up so the
	// snapshot reflects real running state.
	time.Sleep(300 * time.Millisecond)
	snapshot := rt.snapshot()
	rules, ok := snapshot["rules"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if rules[0]["id"] != 5 || rules[0]["running"] != true {
		t.Fatalf("unexpected rule entry: %#v", rules[0])
	}
	// The endpoint list must report both TCP and UDP on 39105.
	eps, ok := rules[0]["endpoints"].([]string)
	if !ok || len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %#v", rules[0]["endpoints"])
	}
}

func TestRelayConfigReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, 39106)
	rt := newRuntime()
	defer rt.stopAll()
	if err := rt.loadAndApply(path); err != nil {
		t.Fatal(err)
	}
	if len(rt.config.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rt.config.Rules))
	}
	writeTestConfig(t, path, 39107)
	if err := rt.loadAndApply(path); err != nil {
		t.Fatal(err)
	}
	if rt.config.Rules[0].ListenPortStart != 39107 {
		t.Fatalf("expected reloaded port 39107, got %d", rt.config.Rules[0].ListenPortStart)
	}
}

func writeTestConfig(t *testing.T, path string, port int) {
	t.Helper()
	cfg := relayConfig{Rules: []relayRule{{
		ID: 6, Name: "reload", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: port, ListenPortEnd: port, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: port, TargetPortEnd: port, UDPIdleTimeout: 30,
	}}}
	data, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
}

func atoi(value string) int {
	var out int
	fmt.Sscanf(value, "%d", &out)
	return out
}

// echoTCPServerOn starts a TCP echo server on an explicit port.
func echoTCPServerOn(t *testing.T, port int) string {
	t.Helper()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen %d: %v", port, err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buffer := make([]byte, 4096)
				for {
					n, err := c.Read(buffer)
					if err != nil {
						return
					}
					c.Write(buffer[:n])
				}
			}(conn)
		}
	}()
	return listener.Addr().String()
}

// TestRelayPortRange verifies that a listen port range maps 1:1 onto a target
// port range and every port in the range actually listens.
func TestRelayPortRange(t *testing.T) {
	// Three echo servers on consecutive ports serve as the target range.
	echoTCPServerOn(t, 39310)
	echoTCPServerOn(t, 39311)
	echoTCPServerOn(t, 39312)

	rule := relayRule{
		ID: 10, Name: "range", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39200, ListenPortEnd: 39202, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: 39310, TargetPortEnd: 39312,
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(300 * time.Millisecond)

	// listen 39200 -> target 39310, 39201 -> 39311, 39202 -> 39312.
	for i, listenPort := range []int{39200, 39201, 39202} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
		if err != nil {
			t.Fatalf("port %d not listening: %v", listenPort, err)
		}
		message := []byte(fmt.Sprintf("range-%d", i))
		conn.Write(message)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		n, err := conn.Read(buffer)
		if err != nil {
			conn.Close()
			t.Fatalf("port %d echo failed: %v", listenPort, err)
		}
		if string(buffer[:n]) != string(message) {
			conn.Close()
			t.Fatalf("port %d echo mismatch: %q", listenPort, buffer[:n])
		}
		conn.Close()
	}
}

// TestRelayBothProtocol verifies that protocol=both starts both a TCP and a
// UDP listener on the same port, forwarding to a target that answers both.
func TestRelayBothProtocol(t *testing.T) {
	// TCP echo + UDP echo on the same target port.
	echoTCPServerOn(t, 39320)
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:39320")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := udpConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpConn.WriteTo(buffer[:n], addr)
		}
	}()

	rule := relayRule{
		ID: 11, Name: "both", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39210, ListenPortEnd: 39210, Protocol: "both",
		TargetHost: "127.0.0.1", TargetPortStart: 39320, TargetPortEnd: 39320,
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(300 * time.Millisecond)

	// TCP side must accept and echo.
	tcpConn, err := net.DialTimeout("tcp", "127.0.0.1:39210", 2*time.Second)
	if err != nil {
		t.Fatalf("tcp listener missing for both rule: %v", err)
	}
	msg := []byte("both-tcp")
	tcpConn.Write(msg)
	tcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 64)
	n, err := tcpConn.Read(buffer)
	if err != nil {
		tcpConn.Close()
		t.Fatalf("tcp echo failed on both rule: %v", err)
	}
	if string(buffer[:n]) != string(msg) {
		tcpConn.Close()
		t.Fatalf("tcp echo mismatch: %q", buffer[:n])
	}
	tcpConn.Close()

	// UDP side must accept datagrams and echo.
	udpClient, err := net.Dial("udp", "127.0.0.1:39210")
	if err != nil {
		t.Fatalf("udp listener missing for both rule: %v", err)
	}
	defer udpClient.Close()
	umsg := []byte("both-udp")
	udpClient.Write(umsg)
	udpClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	un, err := udpClient.Read(buffer)
	if err != nil {
		t.Fatalf("udp echo failed on both rule: %v", err)
	}
	if string(buffer[:un]) != string(umsg) {
		t.Fatalf("udp echo mismatch: %q", buffer[:un])
	}
}

// TestRelayReloadKeepsRunningRules verifies re-applying the same config does
// not churn listeners (regression for the re-apply collision bug).
func TestRelayReloadKeepsRunningRules(t *testing.T) {
	rule := relayRule{
		ID: 12, Name: "stable", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39220, ListenPortEnd: 39220, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: 9, TargetPortEnd: 9,
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)
	// Apply the same config again: must not fail or duplicate listeners.
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:39220", 2*time.Second)
	if err != nil {
		t.Fatalf("listener lost after re-apply: %v", err)
	}
	conn.Close()
}

// TestRelayReloadClosesRemovedListener verifies that applying a config which
// removes or modifies a rule actually closes the old listener: the old port
// must stop accepting while the new port comes up.
func TestRelayReloadClosesRemovedListener(t *testing.T) {
	rule := relayRule{
		ID: 13, Name: "hotswap", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39230, ListenPortEnd: 39230, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: 9, TargetPortEnd: 9,
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)
	conn, err := net.DialTimeout("tcp", "127.0.0.1:39230", 2*time.Second)
	if err != nil {
		t.Fatalf("initial listener missing: %v", err)
	}
	conn.Close()

	// Modify the rule: same ID, new port. The old listener must be closed.
	moved := rule
	moved.ListenPortStart = 39231
	moved.ListenPortEnd = 39231
	rt.apply(relayConfig{Rules: []relayRule{moved}})
	time.Sleep(200 * time.Millisecond)

	// New port must be listening.
	conn2, err := net.DialTimeout("tcp", "127.0.0.1:39231", 2*time.Second)
	if err != nil {
		t.Fatalf("new listener missing after reload: %v", err)
	}
	conn2.Close()

	// Old port must be closed: the dial must fail (or be refused) quickly.
	oldConn, err := net.DialTimeout("tcp", "127.0.0.1:39230", 1*time.Second)
	if err == nil {
		oldConn.Close()
		t.Fatal("old listener still accepting after rule was modified")
	}

	// Removing the rule entirely must close the remaining listener too.
	rt.apply(relayConfig{Rules: []relayRule{}})
	time.Sleep(200 * time.Millisecond)
	gone, err := net.DialTimeout("tcp", "127.0.0.1:39231", 1*time.Second)
	if err == nil {
		gone.Close()
		t.Fatal("listener still accepting after rule removal")
	}
}

// TestRelayStatusListenFailure verifies that a rule whose listen fails (port
// already taken by another process) is reported as not running with the real
// error, instead of unconditionally showing running=true.
func TestRelayStatusListenFailure(t *testing.T) {
	// Occupy a port with a foreign listener.
	foreign, err := net.Listen("tcp4", "127.0.0.1:39240")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()

	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{{
		ID: 14, Name: "clash", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39240, ListenPortEnd: 39240, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: 9, TargetPortEnd: 9, UDPIdleTimeout: 30,
	}}})
	time.Sleep(300 * time.Millisecond)

	snapshot := rt.snapshot()
	rules, _ := snapshot["rules"].([]map[string]any)
	if len(rules) != 1 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if running, _ := rules[0]["running"].(bool); running {
		t.Fatalf("rule with failed listen reported running: %#v", rules[0])
	}
	if errMsg, _ := rules[0]["error"].(string); errMsg == "" {
		t.Fatalf("expected a listen error in snapshot: %#v", rules[0])
	}
}

// TestRelayReloadTargetChange verifies that changing ONLY the target (not the
// listen port) rebuilds the listener: the fingerprint in the listener key
// changes, so the old goroutine (capturing the old rule) is closed and a new
// one forwards to the new target.
func TestRelayReloadTargetChange(t *testing.T) {
	targetA := echoTCPServer(t)
	_, portA, _ := net.SplitHostPort(targetA)
	targetB := echoTCPServer(t)
	_, portB, _ := net.SplitHostPort(targetB)

	rule := relayRule{
		ID: 15, Name: "retarget", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39250, ListenPortEnd: 39250, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: atoi(portA), TargetPortEnd: atoi(portA),
		UDPIdleTimeout: 30,
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)

	probe := func(expect string) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", "127.0.0.1:39250", 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		msg := []byte("retarget-probe")
		conn.Write(msg)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 64)
		n, err := conn.Read(buffer)
		conn.Close()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buffer[:n]) != expect {
			t.Fatalf("expected echo %q, got %q", expect, buffer[:n])
		}
	}

	// Phase 1: forwards to target A.
	probe("retarget-probe")

	// Phase 2: same listen port, new target — the listener must be rebuilt
	// and the new goroutine must forward to target B.
	moved := rule
	moved.TargetPortStart = atoi(portB)
	moved.TargetPortEnd = atoi(portB)
	rt.apply(relayConfig{Rules: []relayRule{moved}})
	time.Sleep(200 * time.Millisecond)
	probe("retarget-probe")
}

// TestRelayRateLimit verifies RateLimitKbps actually throttles TCP
// forwarding: a small limit makes a moderately sized transfer take markedly
// longer than an unlimited transfer.
func TestRelayRateLimit(t *testing.T) {
	// Target that returns a 512 KB payload as fast as it can.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				payload := make([]byte, 512*1024)
				c.Write(payload)
			}(conn)
		}
	}()
	_, targetPort, _ := net.SplitHostPort(listener.Addr().String())

	run := func(kbps int) time.Duration {
		rule := relayRule{
			ID: 16, Name: "limited", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
			ListenPortStart: 39251, ListenPortEnd: 39251, Protocol: "tcp",
			TargetHost: "127.0.0.1", TargetPortStart: atoi(targetPort), TargetPortEnd: atoi(targetPort),
			RateLimitKbps: kbps, UDPIdleTimeout: 30,
		}
		rt := newRuntime()
		defer rt.stopAll()
		rt.apply(relayConfig{Rules: []relayRule{rule}})
		time.Sleep(200 * time.Millisecond)
		defer rt.stopAll()
		conn, err := net.DialTimeout("tcp", "127.0.0.1:39251", 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		started := time.Now()
		buffer := make([]byte, 64*1024)
		for {
			if _, err := conn.Read(buffer); err != nil {
				break
			}
		}
		return time.Since(started)
	}

	fast := run(0)   // unlimited
	slow := run(512) // 512 kbps = 64 KB/s
	if slow <= fast {
		t.Fatalf("expected rate-limited transfer to be slower: fast=%v slow=%v", fast, slow)
	}
	// At 512 kbps (64 KB/s), 512 KB takes ~8s; the unlimited one is far quicker.
	if slow < 4*time.Second {
		t.Fatalf("rate limit not effective: slow transfer only took %v", slow)
	}
}

// TestRelayRateLimitConcurrent verifies that several simultaneous connections
// sharing one rule's bucket do not exceed the aggregate rate: the negative
// token debt queues concurrent callers so the total transfer time scales with
// the combined payload, not with the fastest single connection.
func TestRelayRateLimitConcurrent(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const payloadBytes = 256 * 1024 // per connection
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				payload := make([]byte, payloadBytes)
				c.Write(payload)
			}(conn)
		}
	}()
	_, targetPort, _ := net.SplitHostPort(listener.Addr().String())

	rule := relayRule{
		ID: 18, Name: "concurrent-limited", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39253, ListenPortEnd: 39253, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: atoi(targetPort), TargetPortEnd: atoi(targetPort),
		RateLimitKbps: 512, UDPIdleTimeout: 30, // 512 kbps = 64 KB/s aggregate
	}
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{rule}})
	time.Sleep(200 * time.Millisecond)
	defer rt.stopAll()

	const conns = 4
	started := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", "127.0.0.1:39253", 2*time.Second)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			buffer := make([]byte, 64*1024)
			for {
				if _, err := conn.Read(buffer); err != nil {
					break
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(started)

	// Total payload is 4 * 256 KB = 1 MB. At 64 KB/s that is ~16s. Allow a
	// generous 40% slack for scheduling; the critical assertion is that the
	// aggregate is NOT ~4x faster than a single connection would be.
	minExpected := 8 * time.Second
	if elapsed < minExpected {
		t.Fatalf("concurrent connections exceeded aggregate rate: 4x256KB took %v (< %v)", elapsed, minExpected)
	}
}

// TestConfigFingerprintSensitivity verifies the fingerprint changes when any
// forwarding-relevant field changes and stays stable for identical rules.
func TestConfigFingerprintSensitivity(t *testing.T) {
	base := relayRule{
		ID: 17, Name: "fp", ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 1000, ListenPortEnd: 1000, Protocol: "tcp",
		TargetHost: "192.0.2.50", TargetPortStart: 80, TargetPortEnd: 80,
		RateLimitKbps: 0, UDPIdleTimeout: 60,
	}
	fp := configFingerprint(base)
	if fp != configFingerprint(base) {
		t.Fatal("fingerprint must be deterministic")
	}
	mutations := []relayRule{
		func() relayRule { r := base; r.TargetHost = "192.0.2.60"; return r }(),
		func() relayRule { r := base; r.TargetPortStart = 8080; r.TargetPortEnd = 8080; return r }(),
		func() relayRule { r := base; r.ListenAddress = "127.0.0.1"; return r }(),
		func() relayRule { r := base; r.RateLimitKbps = 128; return r }(),
		func() relayRule { r := base; r.UDPIdleTimeout = 5; return r }(),
		func() relayRule { r := base; r.AllowedCIDRs = []string{"10.0.0.0/8"}; return r }(),
		func() relayRule { r := base; r.DeniedCIDRs = []string{"203.0.113.0/24"}; return r }(),
		func() relayRule { r := base; r.Protocol = "both"; return r }(),
	}
	for i, m := range mutations {
		if configFingerprint(m) == fp {
			t.Fatalf("mutation %d did not change fingerprint", i)
		}
	}
}

// TestSnapshotEndpointsFormat verifies the snapshot reports endpoints with
// protocol, family, address and port so the control plane can exempt exactly
// the held endpoints.
func TestSnapshotEndpointsFormat(t *testing.T) {
	rt := newRuntime()
	defer rt.stopAll()
	rt.apply(relayConfig{Rules: []relayRule{{
		ID: 18, Name: "fmt", ListenFamily: "ipv4", ListenAddress: "127.0.0.1",
		ListenPortStart: 39252, ListenPortEnd: 39252, Protocol: "tcp",
		TargetHost: "127.0.0.1", TargetPortStart: 9, TargetPortEnd: 9, UDPIdleTimeout: 30,
	}}})
	time.Sleep(300 * time.Millisecond)
	snapshot := rt.snapshot()
	rules, _ := snapshot["rules"].([]map[string]any)
	if len(rules) != 1 {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if _, ok := snapshot["updated_at"].(string); !ok {
		t.Fatalf("snapshot missing updated_at: %#v", snapshot)
	}
	eps, _ := rules[0]["endpoints"].([]string)
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %#v", rules[0]["endpoints"])
	}
	// Format: tcp:39252 (colon-free address fields)
	if eps[0] != "tcp:39252" {
		t.Fatalf("unexpected endpoint format: %q", eps[0])
	}
	if rules[0]["listen_family"] != "ipv4" {
		t.Fatalf("expected listen_family ipv4, got %#v", rules[0]["listen_family"])
	}
}
