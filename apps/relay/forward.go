package main

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// listenerKey uniquely identifies one concrete listener endpoint:
// ruleID:port:proto:family:fingerprint. proto is tcp|udp, family is
// ipv4|ipv6. fingerprint is a digest of every forwarding-relevant rule
// field (target host/ports, listen address, ACLs, rate limit, UDP timeout,
// protocol), so ANY configuration change produces a different key and the
// old listener is closed and rebuilt during apply.
func listenerKey(ruleID, port int, proto, family, fingerprint string) string {
	return strconv.Itoa(ruleID) + ":" + strconv.Itoa(port) + ":" + proto + ":" + family + ":" + fingerprint
}

// listenerRuleID extracts the rule ID from a listener key.
func listenerRuleID(key string) int {
	idx := strings.IndexByte(key, ':')
	if idx < 0 {
		return 0
	}
	id, _ := strconv.Atoi(key[:idx])
	return id
}

// configFingerprint digests every field that changes how traffic is
// forwarded. Two rules with the same fingerprint behave identically even if
// unrelated metadata (name, id) differs.
func configFingerprint(rule relayRule) string {
	h := sha1.New()
	io.WriteString(h, rule.ListenFamily+"\x00")
	io.WriteString(h, strings.Trim(rule.ListenAddress, "[]")+"\x00")
	io.WriteString(h, rule.Protocol+"\x00")
	io.WriteString(h, strings.Trim(rule.TargetHost, "[]")+"\x00")
	io.WriteString(h, strconv.Itoa(rule.TargetPortStart)+"\x00")
	io.WriteString(h, strconv.Itoa(rule.TargetPortEnd)+"\x00")
	io.WriteString(h, strconv.Itoa(rule.RateLimitKbps)+"\x00")
	io.WriteString(h, strconv.Itoa(rule.UDPIdleTimeout)+"\x00")
	for _, c := range rule.AllowedCIDRs {
		io.WriteString(h, "a"+c+"\x00")
	}
	for _, c := range rule.DeniedCIDRs {
		io.WriteString(h, "d"+c+"\x00")
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// effectiveFamily resolves the concrete address family for a rule, honoring
// an explicit ipv4/ipv6 choice and falling back to the listen address shape
// for auto.
func effectiveFamily(rule relayRule) string {
	switch rule.ListenFamily {
	case "ipv4":
		return "ipv4"
	case "ipv6":
		return "ipv6"
	}
	if strings.Contains(strings.Trim(rule.ListenAddress, "[]"), ":") {
		return "ipv6"
	}
	return "ipv4"
}

// trackListener records a successfully started listener so config reloads can
// close it when the rule is removed or modified. It clears any previous error
// for the endpoint.
func (rt *relayRuntime) trackListener(key string, closer io.Closer, ruleID int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.listeners[key] = closer
	delete(rt.listenStatus, key)
	if s := rt.states[ruleID]; s != nil {
		s.mu.Lock()
		s.ListenErr = ""
		s.mu.Unlock()
	}
}

// untrackListener forgets a listener that has exited.
func (rt *relayRuntime) untrackListener(key string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	delete(rt.listeners, key)
	delete(rt.listenStatus, key)
}

// setListenError records a failed listen for a rule endpoint so status
// snapshots reflect the real runtime state instead of assuming success.
func (rt *relayRuntime) setListenError(key string, ruleID int, err error) {
	msg := err.Error()
	rt.mu.Lock()
	rt.listenStatus[key] = msg
	if s := rt.states[ruleID]; s != nil {
		s.mu.Lock()
		s.ListenErr = msg
		s.mu.Unlock()
	}
	rt.mu.Unlock()
}

// tokenBucket implements a simple token bucket for rate limiting. A nil
// bucket means unlimited (rate_limit_kbps <= 0).
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64 // may go negative (debt) to queue concurrent callers
	last   time.Time
}

func newTokenBucket(kbps int) *tokenBucket {
	if kbps <= 0 {
		return nil
	}
	// The field is documented as Kbps (kilobits per second); convert to
	// bytes per second: kbps * 1000 / 8 = kbps * 125.
	rate := float64(kbps) * 125.0
	return &tokenBucket{rate: rate, burst: rate, tokens: rate, last: time.Now()}
}

// wait blocks until n bytes of budget are available. The bucket uses a
// negative token balance as debt: a caller that cannot be served immediately
// leaves its deficit in the bucket, so concurrent goroutines queue behind
// each other (each sees a deeper debt and waits longer) instead of all
// clearing their tokens and sleeping in parallel. Aggregate rate stays at
// the configured limit regardless of connection count.
func (b *tokenBucket) wait(n int) {
	if b == nil || n <= 0 {
		return
	}
	b.mu.Lock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		b.mu.Unlock()
		return
	}
	debt := -b.tokens
	b.mu.Unlock()
	time.Sleep(time.Duration(debt / b.rate * float64(time.Second)))
}

// copyLimited copies src to dst, throttling the write side to the bucket's
// rate. With a nil bucket it behaves exactly like io.Copy.
func copyLimited(dst io.Writer, src io.Reader, bucket *tokenBucket) (int64, error) {
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			bucket.wait(n)
			wn, werr := dst.Write(buffer[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// serveTCP accepts connections on the rule's listen address/port and copies
// bytes bidirectionally to the target port. The listener is tracked so that
// config reloads can close it when the rule changes.
func (rt *relayRuntime) serveTCP(bind relayBind) {
	rule := bind.rule
	network := "tcp4"
	family := "ipv4"
	if effectiveFamily(rule) == "ipv6" {
		network = "tcp6"
		family = "ipv6"
	}
	fp := configFingerprint(rule)
	key := listenerKey(rule.ID, bind.listenPort, "tcp", family, fp)
	address := listenAddress(rule.ListenAddress, bind.listenPort, family)
	listener, err := net.Listen(network, address)
	if err != nil {
		log.Printf("rule %d tcp listen %s failed: %v", rule.ID, address, err)
		rt.setListenError(key, rule.ID, err)
		return
	}
	rt.trackListener(key, listener, rule.ID)
	defer func() {
		listener.Close()
		rt.untrackListener(key)
	}()
	bucket := newTokenBucket(rule.RateLimitKbps)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if !rt.allowed(rule, remoteIP(conn.RemoteAddr())) {
			conn.Close()
			continue
		}
		state := rt.state(rule.ID)
		state.mu.Lock()
		state.TCPConns++
		state.mu.Unlock()
		go rt.handleTCPConn(rule, conn, bind.targetPort, bucket)
	}
}

func (rt *relayRuntime) handleTCPConn(rule relayRule, client net.Conn, targetPort int, bucket *tokenBucket) {
	defer client.Close()
	state := rt.state(rule.ID)
	defer func() {
		state.mu.Lock()
		state.TCPConns--
		state.mu.Unlock()
	}()
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(strings.Trim(rule.TargetHost, "[]"), itoa(targetPort)), 10*time.Second)
	if err != nil {
		state.mu.Lock()
		state.TargetFailures++
		state.mu.Unlock()
		return
	}
	defer upstream.Close()
	rt.markActive(rule.ID)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := copyLimited(upstream, client, bucket)
		state.mu.Lock()
		state.RXBytes += n
		state.mu.Unlock()
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		n, _ := copyLimited(client, upstream, bucket)
		state.mu.Lock()
		state.TXBytes += n
		state.mu.Unlock()
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()
	wg.Wait()
}

// udpSessionTable tracks upstream sockets per client address.
type udpSessionTable struct {
	mu       sync.Mutex
	sessions map[string]*udpSession
	done     chan struct{} // closed when the owning listener is removed
}

type udpSession struct {
	upstream net.Conn
	lastSeen time.Time
}

// serveUDP forwards datagrams for the rule's listen address/port to the target
// port, maintaining one upstream socket per client address. The PacketConn is
// tracked so config reloads can close it.
func (rt *relayRuntime) serveUDP(bind relayBind) {
	rule := bind.rule
	network := "udp4"
	family := "ipv4"
	if effectiveFamily(rule) == "ipv6" {
		network = "udp6"
		family = "ipv6"
	}
	fp := configFingerprint(rule)
	key := listenerKey(rule.ID, bind.listenPort, "udp", family, fp)
	address := listenAddress(rule.ListenAddress, bind.listenPort, family)
	conn, err := net.ListenPacket(network, address)
	if err != nil {
		log.Printf("rule %d udp listen %s failed: %v", rule.ID, address, err)
		rt.setListenError(key, rule.ID, err)
		return
	}
	rt.trackListener(key, conn, rule.ID)
	table := &udpSessionTable{sessions: map[string]*udpSession{}, done: make(chan struct{})}
	rt.mu.Lock()
	rt.udpSess[rule.ID] = table
	rt.mu.Unlock()
	defer func() {
		conn.Close()
		rt.untrackListener(key)
		close(table.done) // reapUDP exits with the listener
		rt.mu.Lock()
		if rt.udpSess[rule.ID] == table {
			delete(rt.udpSess, rule.ID)
		}
		rt.mu.Unlock()
	}()
	timeout := time.Duration(rule.UDPIdleTimeout) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	bucket := newTokenBucket(rule.RateLimitKbps)
	buffer := make([]byte, 65535)
	go rt.reapUDP(rule.ID, table, timeout)
	for {
		n, clientAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			return
		}
		if !rt.allowed(rule, remoteIP(clientAddr)) {
			continue
		}
		state := rt.state(rule.ID)
		state.mu.Lock()
		state.RXBytes += int64(n)
		state.LastActive = time.Now().UTC().Format(time.RFC3339)
		state.mu.Unlock()
		key := clientAddr.String()
		table.mu.Lock()
		session, ok := table.sessions[key]
		if !ok {
			targetPort := bind.targetPort
			upstream, err := net.Dial("udp", net.JoinHostPort(strings.Trim(rule.TargetHost, "[]"), itoa(targetPort)))
			if err != nil {
				table.mu.Unlock()
				state.mu.Lock()
				state.TargetFailures++
				state.mu.Unlock()
				continue
			}
			session = &udpSession{upstream: upstream, lastSeen: time.Now()}
			table.sessions[key] = session
			state.mu.Lock()
			state.UDPSessions++
			state.mu.Unlock()
			go rt.pumpUDP(rule.ID, table, key, session, conn, clientAddr, bucket)
		} else {
			session.lastSeen = time.Now()
		}
		table.mu.Unlock()
		// 上行限速 (client -> upstream)
		bucket.wait(n)
		session.upstream.Write(buffer[:n])
	}
}

func (rt *relayRuntime) pumpUDP(ruleID int, table *udpSessionTable, key string, session *udpSession, clientConn net.PacketConn, clientAddr net.Addr, bucket *tokenBucket) {
	buffer := make([]byte, 65535)
	for {
		session.upstream.SetReadDeadline(time.Now().Add(time.Minute))
		n, err := session.upstream.Read(buffer)
		if err != nil {
			// 60s 无响应: 接收协程退出, 同时移除会话并关闭上游,
			// 避免后续响应被吞掉或会话永久残留
			table.mu.Lock()
			if table.sessions[key] == session {
				delete(table.sessions, key)
			}
			table.mu.Unlock()
			session.upstream.Close()
			return
		}
		bucket.wait(n)
		clientConn.WriteTo(buffer[:n], clientAddr)
		state := rt.state(ruleID)
		state.mu.Lock()
		state.TXBytes += int64(n)
		state.mu.Unlock()
	}
}

// reapUDP closes idle sessions. It exits when the owning listener is removed
// (table.done closed) so rule deletion does not leak the goroutine or keep
// upstream sockets alive until the global stop.
func (rt *relayRuntime) reapUDP(ruleID int, table *udpSessionTable, timeout time.Duration) {
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			table.mu.Lock()
			for key, session := range table.sessions {
				if now.Sub(session.lastSeen) > timeout {
					session.upstream.Close()
					delete(table.sessions, key)
					state := rt.state(ruleID)
					state.mu.Lock()
					state.UDPSessions--
					state.mu.Unlock()
				}
			}
			table.mu.Unlock()
		case <-table.done:
			// Close every remaining upstream socket on the way out.
			table.mu.Lock()
			for key, session := range table.sessions {
				session.upstream.Close()
				delete(table.sessions, key)
			}
			table.mu.Unlock()
			return
		case <-rt.stop:
			return
		}
	}
}

func (rt *relayRuntime) allowed(rule relayRule, ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range rule.DeniedCIDRs {
		if ipInCIDR(parsed, cidr) {
			return false
		}
	}
	if len(rule.AllowedCIDRs) == 0 {
		return true
	}
	for _, cidr := range rule.AllowedCIDRs {
		if ipInCIDR(parsed, cidr) {
			return true
		}
	}
	return false
}

func ipInCIDR(ip net.IP, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func remoteIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// listenAddress renders "host:port" for a rule listen, honoring the address
// family when the configured address is a wildcard: an empty/any address
// becomes 0.0.0.0 for ipv4 and :: for ipv6 (binding 0.0.0.0 on a tcp6
// listener fails with "no suitable address found").
func listenAddress(listen string, port int, family string) string {
	listen = strings.Trim(listen, "[]")
	if listen == "" || listen == "*" {
		if family == "ipv6" {
			listen = "::"
		} else {
			listen = "0.0.0.0"
		}
	}
	if strings.Contains(listen, ":") && !strings.HasPrefix(listen, "[") {
		return "[" + listen + "]:" + itoa(port)
	}
	return listen + ":" + itoa(port)
}

func itoa(value int) string {
	return strconv.Itoa(value)
}
