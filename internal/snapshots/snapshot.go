package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Protocol string

const (
	TCP    Protocol = "tcp"
	UDP    Protocol = "udp"
	TCPUDP Protocol = "tcpudp"
)

type Mapping struct {
	ID, Name, PublicIP, TargetIP                         string
	PublicStart, PublicEnd, TargetStart, TargetEnd       int
	Protocol                                             Protocol
	Enabled                                              bool
	Description                                          string
	Tags                                                 []string
	ResourceID, ServiceID, GroupID, EdgeID, TargetNodeID string
	RateLimitKbps, ConnectionLimit                       int
	LogLevel, SourceMode                                 string
	CreatedBy, CreatedAt, UpdatedAt                      string
	ACLID                                                string   `json:"acl_id,omitempty"`
	ACLIDs                                               []string `json:"acl_ids,omitempty"`
}
type ACLAction string

const (
	ACLDeny  ACLAction = "deny"
	ACLAllow ACLAction = "allow"
)

type ACLRule struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Action     ACLAction  `json:"action"`
	CIDR       string     `json:"cidr"`
	Enabled    bool       `json:"enabled"`
	Protocols  []Protocol `json:"protocols,omitempty"`
	PortStart  int        `json:"port_start,omitempty"`
	PortEnd    int        `json:"port_end,omitempty"`
	NodeIDs    []string   `json:"node_ids,omitempty"`
	ServiceIDs []string   `json:"service_ids,omitempty"`
	GroupIDs   []string   `json:"group_ids,omitempty"`
	Weekdays   []int      `json:"weekdays,omitempty"`
	StartTime  string     `json:"start_time,omitempty"`
	EndTime    string     `json:"end_time,omitempty"`
	Timezone   string     `json:"timezone,omitempty"`
}

type IPSet struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Action  ACLAction `json:"action"`
	CIDRs   []string  `json:"cidrs"`
	Enabled bool      `json:"enabled"`
}

type HTTPProxy struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Host         string            `json:"host"`
	Path         string            `json:"path,omitempty"`
	Target       string            `json:"target"`
	Targets      []string          `json:"targets,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	HealthPath   string            `json:"health_path,omitempty"`
	LoadBalance  string            `json:"load_balance,omitempty"`
	Enabled      bool              `json:"enabled"`
	ForceTLS     bool              `json:"force_tls,omitempty"`
	WebSocket    bool              `json:"websocket,omitempty"`
	PreserveHost bool              `json:"preserve_host,omitempty"`
}

type Snapshot struct {
	Version     int64       `json:"version"`
	CreatedAt   time.Time   `json:"created_at"`
	Operator    string      `json:"operator"`
	Nonce       string      `json:"nonce"`
	Mappings    []Mapping   `json:"mappings"`
	ACLRules    []ACLRule   `json:"acl_rules,omitempty"`
	IPSets      []IPSet     `json:"ip_sets,omitempty"`
	HTTPProxies []HTTPProxy `json:"http_proxies,omitempty"`
	SHA256      string      `json:"sha256"`
	Signature   string      `json:"signature"`
}

func Canonical(s Snapshot) ([]byte, error) { s.SHA256 = ""; s.Signature = ""; return json.Marshal(s) }
func Sign(s Snapshot, priv ed25519.PrivateKey) (Snapshot, error) {
	if s.Nonce == "" {
		b := make([]byte, 16)
		rand.Read(b)
		s.Nonce = base64.RawURLEncoding.EncodeToString(b)
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	c, err := Canonical(s)
	if err != nil {
		return s, err
	}
	h := sha256.Sum256(c)
	s.SHA256 = base64.StdEncoding.EncodeToString(h[:])
	sig := ed25519.Sign(priv, c)
	s.Signature = base64.StdEncoding.EncodeToString(sig)
	return s, nil
}
func Verify(s Snapshot, pub ed25519.PublicKey, lastVersion int64, seen func(string) bool) error {
	if s.Version <= lastVersion {
		return errors.New("snapshot replay: version not newer")
	}
	if time.Since(s.CreatedAt) > 10*time.Minute || time.Until(s.CreatedAt) > 2*time.Minute {
		return errors.New("snapshot timestamp outside window")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return err
	}
	c, err := Canonical(s)
	if err != nil {
		return err
	}
	h := sha256.Sum256(c)
	if base64.StdEncoding.EncodeToString(h[:]) != s.SHA256 {
		return errors.New("snapshot sha256 mismatch")
	}
	if !ed25519.Verify(pub, c, sig) {
		return errors.New("snapshot signature invalid")
	}
	// Record/check nonce only after the signature is verified, so invalid
	// payloads cannot burn a legitimate nonce.
	if seen != nil && seen(s.Nonce) {
		return errors.New("snapshot replay: nonce seen")
	}
	if err := ValidateMappings(s.Mappings); err != nil {
		return err
	}
	if err := ValidateACLRules(s.ACLRules); err != nil {
		return err
	}
	if err := ValidateACLRefs(s.Mappings, s.ACLRules); err != nil {
		return err
	}
	if err := ValidateIPSets(s.IPSets); err != nil {
		return err
	}
	return ValidateHTTPProxies(s.HTTPProxies)
}

func ValidateMappings(ms []Mapping) error {
	seen := map[string]bool{}
	for _, m := range ms {
		if !m.Enabled {
			continue
		}
		if m.PublicStart < 1 || m.PublicEnd > 65535 || m.PublicStart > m.PublicEnd || m.TargetStart < 1 || m.TargetEnd > 65535 {
			return errors.New("invalid port range")
		}
		if (m.PublicEnd - m.PublicStart) != (m.TargetEnd - m.TargetStart) {
			return errors.New("range length mismatch")
		}
		if net.ParseIP(m.TargetIP) == nil {
			return errors.New("invalid target ip")
		}
		if m.Protocol != TCP && m.Protocol != UDP && m.Protocol != TCPUDP {
			return errors.New("invalid mapping protocol")
		}
		if len(strings.TrimSpace(m.Name)) < 1 || len(m.Name) > 128 || len(m.Description) > 512 {
			return errors.New("invalid mapping name or description")
		}
		if m.PublicIP != "" {
			ip := net.ParseIP(m.PublicIP)
			if ip == nil {
				return errors.New("public listen ip must be an IP address")
			}
			if (ip.To4() == nil) != (net.ParseIP(m.TargetIP).To4() == nil) {
				return errors.New("public listen and target IP families must match")
			}
		}
		if len(m.Tags) > 20 {
			return errors.New("too many mapping tags")
		}
		for _, tag := range m.Tags {
			if len(strings.TrimSpace(tag)) < 1 || len(tag) > 48 {
				return errors.New("invalid mapping tag")
			}
		}
		if m.RateLimitKbps < 0 || m.RateLimitKbps > 10_000_000 || m.ConnectionLimit < 0 || m.ConnectionLimit > 1_000_000 {
			return errors.New("invalid mapping traffic limit")
		}
		if m.LogLevel != "" && m.LogLevel != "off" && m.LogLevel != "error" && m.LogLevel != "info" && m.LogLevel != "verbose" {
			return errors.New("invalid mapping log level")
		}
		if m.SourceMode != "" && m.SourceMode != "compat" && m.SourceMode != "preserve" {
			return errors.New("invalid source mode")
		}
		for _, id := range MappingACLIDs(m) {
			if !validID(id) {
				return errors.New("invalid mapping acl id")
			}
		}
		ps := []Protocol{m.Protocol}
		if m.Protocol == TCPUDP {
			ps = []Protocol{TCP, UDP}
		}
		for _, p := range ps {
			for port := m.PublicStart; port <= m.PublicEnd; port++ {
				family := "ipv4"
				if net.ParseIP(m.TargetIP).To4() == nil {
					family = "ipv6"
				}
				k := family + ":" + m.PublicIP + ":" + string(p) + ":" + strconv.Itoa(port)
				if seen[k] {
					return errors.New("duplicate public port")
				}
				seen[k] = true
			}
		}
	}
	return nil
}

func ValidateACLRefs(ms []Mapping, rules []ACLRule) error {
	known := map[string]bool{}
	for _, rule := range rules {
		if rule.Enabled && rule.ID != "" {
			known[rule.ID] = true
		}
	}
	for _, m := range ms {
		if !m.Enabled {
			continue
		}
		for _, id := range MappingACLIDs(m) {
			if !known[id] {
				return errors.New("mapping references missing or disabled acl rule")
			}
		}
	}
	return nil
}

func MappingACLIDs(m Mapping) []string {
	seen := map[string]bool{}
	var ids []string
	if m.ACLID != "" {
		ids = append(ids, m.ACLID)
		seen[m.ACLID] = true
	}
	for _, id := range m.ACLIDs {
		if id == "" || seen[id] {
			continue
		}
		ids = append(ids, id)
		seen[id] = true
	}
	return ids
}

func ValidateACLRules(rs []ACLRule) error {
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		if r.Action != ACLDeny && r.Action != ACLAllow {
			return errors.New("invalid acl action")
		}
		if r.ID != "" && !validID(r.ID) {
			return errors.New("invalid acl id")
		}
		if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
			ip := net.ParseIP(r.CIDR)
			if ip == nil && !validIPRange(r.CIDR) {
				return errors.New("invalid acl cidr")
			}
		}
		for _, protocol := range r.Protocols {
			if protocol != TCP && protocol != UDP {
				return errors.New("invalid acl protocol")
			}
		}
		if r.PortStart != 0 || r.PortEnd != 0 {
			if r.PortStart < 1 || r.PortEnd < r.PortStart || r.PortEnd > 65535 {
				return errors.New("invalid acl port range")
			}
		}
		for _, ids := range [][]string{r.NodeIDs, r.ServiceIDs, r.GroupIDs} {
			for _, id := range ids {
				if !validID(id) {
					return errors.New("invalid acl scope id")
				}
			}
		}
		if (r.StartTime == "") != (r.EndTime == "") {
			return errors.New("acl start_time and end_time must be used together")
		}
		if r.StartTime != "" {
			if _, err := parseClock(r.StartTime); err != nil {
				return err
			}
			if _, err := parseClock(r.EndTime); err != nil {
				return err
			}
			if r.Timezone == "" {
				return errors.New("acl timezone required for time window")
			}
			if _, err := time.LoadLocation(r.Timezone); err != nil {
				return errors.New("invalid acl timezone")
			}
		}
		for _, day := range r.Weekdays {
			if day < 0 || day > 6 {
				return errors.New("invalid acl weekday")
			}
		}
	}
	return nil
}

func ACLRuleMatches(rule ACLRule, mapping Mapping, protocol Protocol, port int, now time.Time) bool {
	if !rule.Enabled || !ACLRuleActiveAt(rule, now) {
		return false
	}
	referenced := false
	for _, id := range MappingACLIDs(mapping) {
		if id == rule.ID {
			referenced = true
			break
		}
	}
	hasScope := len(rule.NodeIDs)+len(rule.ServiceIDs)+len(rule.GroupIDs) > 0
	if !referenced && !hasScope {
		return false
	}
	if len(rule.NodeIDs) > 0 && !containsString(rule.NodeIDs, mapping.TargetNodeID) {
		return false
	}
	if len(rule.ServiceIDs) > 0 && !containsString(rule.ServiceIDs, mapping.ServiceID) {
		return false
	}
	if len(rule.GroupIDs) > 0 && !containsString(rule.GroupIDs, mapping.GroupID) {
		return false
	}
	if len(rule.Protocols) > 0 && !containsProtocol(rule.Protocols, protocol) {
		return false
	}
	return rule.PortStart == 0 || port >= rule.PortStart && port <= rule.PortEnd
}

func ACLRuleActiveAt(rule ACLRule, now time.Time) bool {
	if rule.StartTime == "" {
		return true
	}
	location, err := time.LoadLocation(rule.Timezone)
	if err != nil {
		return false
	}
	local := now.In(location)
	if len(rule.Weekdays) > 0 && !containsInt(rule.Weekdays, int(local.Weekday())) {
		return false
	}
	start, _ := parseClock(rule.StartTime)
	end, _ := parseClock(rule.EndTime)
	minute := local.Hour()*60 + local.Minute()
	if start == end {
		return true
	}
	if start < end {
		return minute >= start && minute < end
	}
	return minute >= start || minute < end
}

func validIPRange(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return false
	}
	start, end := net.ParseIP(strings.TrimSpace(parts[0])), net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil || (start.To4() == nil) != (end.To4() == nil) {
		return false
	}
	return bytesCompare(start, end) <= 0
}

func bytesCompare(left, right net.IP) int {
	if left.To4() != nil {
		left, right = left.To4(), right.To4()
	} else {
		left, right = left.To16(), right.To16()
	}
	for i := range left {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

func parseClock(value string) (int, error) {
	parsed, err := time.Parse("15:04", value)
	if err != nil {
		return 0, errors.New("invalid acl time; use HH:MM")
	}
	return parsed.Hour()*60 + parsed.Minute(), nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func containsProtocol(values []Protocol, target Protocol) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func containsInt(values []int, target int) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for _, ch := range id {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidateIPSets(sets []IPSet) error {
	for _, set := range sets {
		if !set.Enabled {
			continue
		}
		if set.Name == "" {
			return errors.New("invalid ip set name")
		}
		if set.Action != ACLDeny && set.Action != ACLAllow {
			return errors.New("invalid ip set action")
		}
		if set.Kind != "" && set.Kind != "custom" && set.Kind != "geoip" && set.Kind != "asn" {
			return errors.New("invalid ip set kind")
		}
		if len(set.CIDRs) == 0 {
			return errors.New("empty ip set")
		}
		for _, cidr := range set.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				ip := net.ParseIP(cidr)
				if ip == nil {
					return errors.New("invalid ip set cidr")
				}
			}
		}
	}
	return nil
}

func ValidateHTTPProxies(ps []HTTPProxy) error {
	seen := map[string]bool{}
	for _, p := range ps {
		if !p.Enabled {
			continue
		}
		if p.Host == "" || (p.Target == "" && len(p.Targets) == 0) {
			return errors.New("invalid http proxy")
		}
		if strings.ContainsAny(p.Host, "/\\ \t\r\n") {
			return errors.New("invalid http proxy host")
		}
		targets := append([]string(nil), p.Targets...)
		if len(targets) == 0 {
			targets = []string{p.Target}
		}
		if len(targets) > 16 {
			return errors.New("too many http proxy targets")
		}
		for _, target := range targets {
			u, err := url.Parse(target)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
				return errors.New("invalid http proxy target")
			}
		}
		if p.Path != "" && !strings.HasPrefix(p.Path, "/") {
			return errors.New("http proxy path must start with slash")
		}
		if p.HealthPath != "" && !strings.HasPrefix(p.HealthPath, "/") {
			return errors.New("http proxy health path must start with slash")
		}
		if p.LoadBalance != "" && p.LoadBalance != "round_robin" {
			return errors.New("unsupported http proxy load balancing policy")
		}
		for name, value := range p.Headers {
			if !validHTTPHeaderName(name) || strings.ContainsAny(value, "\r\n") {
				return errors.New("invalid http proxy header")
			}
		}
		key := strings.ToLower(p.Host) + "|" + p.Path
		if seen[key] {
			return errors.New("duplicate http proxy host/path")
		}
		seen[key] = true
	}
	return nil
}

func validHTTPHeaderName(value string) bool {
	if value == "" {
		return false
	}
	const token = "!#$%&'*+-.^_`|~"
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(token, r) {
			continue
		}
		return false
	}
	return true
}
