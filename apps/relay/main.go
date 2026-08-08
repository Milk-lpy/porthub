package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// relayRule mirrors the configuration pushed by netd.
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

// ruleState tracks live counters for one rule.
type ruleState struct {
	mu             sync.Mutex
	TCPConns       int64   `json:"tcp_connections"`
	UDPSessions    int64   `json:"udp_sessions"`
	RXBytes        int64   `json:"rx_bytes"`
	TXBytes        int64   `json:"tx_bytes"`
	LastActive     string  `json:"last_active"`
	TargetFailures int64   `json:"target_failures"`
	DNSResult      string  `json:"dns_result"`
	ListenErr      string  `json:"listen_error"`
}

type relayRuntime struct {
	mu           sync.Mutex
	config       relayConfig
	states       map[int]*ruleState
	udpSess      map[int]*udpSessionTable
	listeners    map[string]io.Closer // key -> live Listener or PacketConn
	listenStatus map[string]string    // key -> endpoint error message ("" = ok)
	stop         chan struct{}
}

func newRuntime() *relayRuntime {
	return &relayRuntime{
		states:       map[int]*ruleState{},
		udpSess:      map[int]*udpSessionTable{},
		listeners:    map[string]io.Closer{},
		listenStatus: map[string]string{},
		stop:         make(chan struct{}),
	}
}

func (rt *relayRuntime) state(id int) *ruleState {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	s, ok := rt.states[id]
	if !ok {
		s = &ruleState{}
		rt.states[id] = s
	}
	return s
}

func (rt *relayRuntime) markActive(id int) {
	s := rt.state(id)
	s.mu.Lock()
	s.LastActive = time.Now().UTC().Format(time.RFC3339)
	s.mu.Unlock()
}

// stopAll closes every live listener and signals the runtime to stop. Used by
// tests to release ports promptly; the production process never calls it.
func (rt *relayRuntime) stopAll() {
	rt.mu.Lock()
	var toClose []io.Closer
	for key, closer := range rt.listeners {
		toClose = append(toClose, closer)
		delete(rt.listeners, key)
		delete(rt.listenStatus, key)
	}
	rt.mu.Unlock()
	for _, closer := range toClose {
		closer.Close()
	}
	select {
	case <-rt.stop:
	default:
		close(rt.stop)
	}
}

// snapshot reports the live status of every configured rule, including the
// real state of each listener endpoint (a rule whose listen failed shows
// running=false and the error) plus per-rule counters. Endpoints carry the
// protocol, address family, concrete listen address and port so the control
// plane can exempt exactly the held endpoints from collision checks.
func (rt *relayRuntime) snapshot() map[string]any {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rules := []map[string]any{}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, rule := range rt.config.Rules {
		family := effectiveFamily(rule)
		protos := []string{"tcp"}
		if rule.Protocol == "udp" {
			protos = []string{"udp"}
		} else if rule.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}
		running := rule.ListenPortStart <= rule.ListenPortEnd
		var firstErr string
		for listenPort := rule.ListenPortStart; listenPort <= rule.ListenPortEnd && running; listenPort++ {
			for _, p := range protos {
				key := listenerKey(rule.ID, listenPort, p, family, configFingerprint(rule))
				if _, ok := rt.listeners[key]; !ok {
					running = false
					firstErr = "listener not running"
					break
				}
				if errMsg := rt.listenStatus[key]; errMsg != "" {
					running = false
					firstErr = errMsg
					break
				}
			}
		}
		entry := map[string]any{
			"id": rule.ID, "name": rule.Name, "listen": rule.ListenAddress,
			"port": rule.ListenPortStart, "protocol": rule.Protocol,
			"target": rule.TargetHost, "target_port": rule.TargetPortStart,
			"running": running, "listen_family": family,
		}
		if firstErr != "" {
			entry["error"] = firstErr
		}
		// Report the concrete endpoints the relay actually holds in a
		// colon-free form ("tcp:5666") plus the resolved listen family and
		// address as separate fields — embedding "::" or an IPv6 literal in
		// the endpoint string would break naive colon-splitting on the
		// control plane. The control plane uses these (with the freshness
		// timestamp) to exempt exactly these endpoints from collision
		// checks — nothing more.
		endpoints := []string{}
		for listenPort := rule.ListenPortStart; listenPort <= rule.ListenPortEnd; listenPort++ {
			for _, p := range protos {
				key := listenerKey(rule.ID, listenPort, p, family, configFingerprint(rule))
				if _, ok := rt.listeners[key]; ok {
					endpoints = append(endpoints, p+":"+strconv.Itoa(listenPort))
				}
			}
		}
		if len(endpoints) > 0 {
			entry["endpoints"] = endpoints
		}
		if s, ok := rt.states[rule.ID]; ok {
			s.mu.Lock()
			entry["tcp_connections"] = s.TCPConns
			entry["udp_sessions"] = s.UDPSessions
			entry["rx_bytes"] = s.RXBytes
			entry["tx_bytes"] = s.TXBytes
			entry["last_active"] = s.LastActive
			entry["target_failures"] = s.TargetFailures
			entry["dns_result"] = s.DNSResult
			if s.ListenErr != "" && firstErr == "" {
				entry["error"] = s.ListenErr
			}
			s.mu.Unlock()
		}
		rules = append(rules, entry)
	}
	return map[string]any{"running": true, "updated_at": now, "rules": rules}
}

func main() {
	configPath := flag.String("config", "/var/lib/porthub/relay/config.json", "relay configuration file")
	statusPath := flag.String("status", "/var/lib/porthub/relay/status.json", "status output file")
	pollSeconds := flag.Int("poll", 5, "configuration poll interval in seconds")
	flag.Parse()

	rt := newRuntime()
	if err := rt.loadAndApply(*configPath); err != nil {
		log.Printf("initial config load failed: %v", err)
	}
	go rt.watchConfig(*configPath, *pollSeconds)
	go rt.writeStatus(*statusPath, *pollSeconds)

	select {}
}

func (rt *relayRuntime) watchConfig(path string, seconds int) {
	ticker := time.NewTicker(time.Duration(seconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := rt.loadAndApply(path); err != nil {
				log.Printf("config reload failed: %v", err)
			}
		case <-rt.stop:
			return
		}
	}
}

func (rt *relayRuntime) writeStatus(path string, seconds int) {
	ticker := time.NewTicker(time.Duration(seconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			os.MkdirAll(filepath.Dir(path), 0750)
			data, _ := json.MarshalIndent(rt.snapshot(), "", "  ")
			os.WriteFile(path, data, 0640)
		case <-rt.stop:
			return
		}
	}
}

// loadAndApply replaces the active listener set with the latest config.
func (rt *relayRuntime) loadAndApply(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg relayConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	rt.apply(cfg)
	return nil
}

// apply reconciles the live listener set with the desired config: listeners
// for rules that were removed or modified are closed, and new listeners are
// started. The listener key embeds a fingerprint of every forwarding-relevant
// field, so changing the target host, target port, listen address, ACLs,
// rate limit or UDP timeout produces a different key and the old listener is
// closed and rebuilt. Listener closures happen outside the lock so blocking
// Close calls never stall configuration processing.
func (rt *relayRuntime) apply(cfg relayConfig) {
	// Build the set of listener keys the new config wants.
	wanted := map[string]bool{}
	for _, rule := range cfg.Rules {
		family := effectiveFamily(rule)
		fp := configFingerprint(rule)
		protos := []string{"tcp"}
		if rule.Protocol == "udp" {
			protos = []string{"udp"}
		} else if rule.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}
		for listenPort := rule.ListenPortStart; listenPort <= rule.ListenPortEnd; listenPort++ {
			for _, p := range protos {
				wanted[listenerKey(rule.ID, listenPort, p, family, fp)] = true
			}
		}
	}

	var toClose []io.Closer
	rt.mu.Lock()
	// Close listeners that are no longer wanted (rule deleted or modified).
	for key, closer := range rt.listeners {
		if !wanted[key] {
			toClose = append(toClose, closer)
			delete(rt.listeners, key)
			delete(rt.listenStatus, key)
		}
	}
	// Drop state and session bookkeeping for rules that disappeared.
	seen := map[int]bool{}
	for _, rule := range cfg.Rules {
		seen[rule.ID] = true
	}
	for id := range rt.states {
		if !seen[id] {
			delete(rt.states, id)
		}
	}
	for id := range rt.udpSess {
		if !seen[id] {
			delete(rt.udpSess, id)
		}
	}
	rt.config = cfg
	for _, rule := range cfg.Rules {
		if _, ok := rt.states[rule.ID]; !ok {
			rt.states[rule.ID] = &ruleState{}
		}
	}
	// Collect listeners that still need to start.
	var tcpStart, udpStart []relayBind
	for _, rule := range cfg.Rules {
		family := effectiveFamily(rule)
		fp := configFingerprint(rule)
		for listenPort := rule.ListenPortStart; listenPort <= rule.ListenPortEnd; listenPort++ {
			targetPort := rule.TargetPortStart + (listenPort - rule.ListenPortStart)
			switch rule.Protocol {
			case "udp":
				if _, ok := rt.listeners[listenerKey(rule.ID, listenPort, "udp", family, fp)]; !ok {
					udpStart = append(udpStart, relayBind{rule: rule, listenPort: listenPort, targetPort: targetPort})
				}
			case "both":
				if _, ok := rt.listeners[listenerKey(rule.ID, listenPort, "tcp", family, fp)]; !ok {
					tcpStart = append(tcpStart, relayBind{rule: rule, listenPort: listenPort, targetPort: targetPort})
				}
				if _, ok := rt.listeners[listenerKey(rule.ID, listenPort, "udp", family, fp)]; !ok {
					udpStart = append(udpStart, relayBind{rule: rule, listenPort: listenPort, targetPort: targetPort})
				}
			default: // tcp
				if _, ok := rt.listeners[listenerKey(rule.ID, listenPort, "tcp", family, fp)]; !ok {
					tcpStart = append(tcpStart, relayBind{rule: rule, listenPort: listenPort, targetPort: targetPort})
				}
			}
		}
	}
	rt.mu.Unlock()

	for _, closer := range toClose {
		closer.Close()
	}
	for _, bind := range tcpStart {
		rt.startTCP(bind)
	}
	for _, bind := range udpStart {
		rt.startUDP(bind)
	}
}

// relayBind is one concrete listener to start for a rule.
type relayBind struct {
	rule       relayRule
	listenPort int
	targetPort int
}

func (rt *relayRuntime) startTCP(bind relayBind) {
	fp := configFingerprint(bind.rule)
	key := listenerKey(bind.rule.ID, bind.listenPort, "tcp", effectiveFamily(bind.rule), fp)
	rt.mu.Lock()
	if _, ok := rt.listeners[key]; ok {
		rt.mu.Unlock()
		return
	}
	rt.mu.Unlock()
	go rt.serveTCP(bind)
}

func (rt *relayRuntime) startUDP(bind relayBind) {
	fp := configFingerprint(bind.rule)
	key := listenerKey(bind.rule.ID, bind.listenPort, "udp", effectiveFamily(bind.rule), fp)
	rt.mu.Lock()
	if _, ok := rt.listeners[key]; ok {
		rt.mu.Unlock()
		return
	}
	rt.mu.Unlock()
	go rt.serveUDP(bind)
}
