package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"porthub/internal/nftables"
	"porthub/internal/snapshots"
)

// portForwardItem is the persisted model for a generic port forward rule.
type portForwardItem struct {
	ID              int      `json:"id"`
	Name            string   `json:"name"`
	NodeID          string   `json:"node_id"`
	ListenFamily    string   `json:"listen_family"`  // auto / ipv4 / ipv6
	ListenAddress   string   `json:"listen_address"` // 0.0.0.0 / :: / specific IP / empty
	ListenPortStart int      `json:"listen_port_start"`
	ListenPortEnd   int      `json:"listen_port_end"`
	Protocol        string   `json:"protocol"`      // tcp / udp / both
	TargetFamily    string   `json:"target_family"` // auto / ipv4 / ipv6
	TargetHost      string   `json:"target_host"`   // IP or domain
	TargetPortStart int      `json:"target_port_start"`
	TargetPortEnd   int      `json:"target_port_end"`
	ForwardMode     string   `json:"forward_mode"` // auto / nft / relay
	SNATMode        string   `json:"snat_mode"`    // auto / masquerade / none
	Enabled         bool     `json:"enabled"`
	ACLID           int      `json:"acl_id"`
	AllowedCIDRs    []string `json:"allowed_cidrs,omitempty"`
	DeniedCIDRs     []string `json:"denied_cidrs,omitempty"`
	RateLimitKbps   int      `json:"rate_limit_kbps"`
	UDPIdleTimeout  int      `json:"udp_idle_timeout"`
	HealthCheck     bool     `json:"health_check"`
	LastStatus      string   `json:"last_status,omitempty"` // pending / applied / failed / disabled
	LastError       string   `json:"last_error,omitempty"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

var hostnamePattern = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

func normalizePortForward(item *portForwardItem) {
	item.Name = strings.TrimSpace(item.Name)
	item.NodeID = strings.TrimSpace(item.NodeID)
	if item.NodeID == "" {
		item.NodeID = "local"
	}
	item.ListenFamily = strings.ToLower(strings.TrimSpace(item.ListenFamily))
	item.ListenAddress = strings.TrimSpace(item.ListenAddress)
	item.Protocol = strings.ToLower(strings.TrimSpace(item.Protocol))
	item.TargetFamily = strings.ToLower(strings.TrimSpace(item.TargetFamily))
	item.TargetHost = strings.TrimSpace(item.TargetHost)
	item.ForwardMode = strings.ToLower(strings.TrimSpace(item.ForwardMode))
	item.SNATMode = strings.ToLower(strings.TrimSpace(item.SNATMode))
	switch item.ListenFamily {
	case "ipv4", "ipv6":
	case "":
		item.ListenFamily = "auto"
	default:
		item.ListenFamily = "auto"
	}
	if item.ListenPortEnd == 0 {
		item.ListenPortEnd = item.ListenPortStart
	}
	if item.TargetPortEnd == 0 {
		item.TargetPortEnd = item.TargetPortStart
	}
	switch item.Protocol {
	case "udp":
	case "both":
	default:
		item.Protocol = "tcp"
	}
	switch item.ForwardMode {
	case "nft", "relay":
	default:
		item.ForwardMode = "auto"
	}
	switch item.SNATMode {
	case "masquerade", "none":
	default:
		item.SNATMode = "auto"
	}
	if item.UDPIdleTimeout <= 0 {
		item.UDPIdleTimeout = 60
	}
}

// validatePortForwardItem checks shape, families, ranges and collisions.
func validatePortForwardItem(item portForwardItem, excludeID int) error {
	if strings.TrimSpace(item.Name) == "" {
		return errText("name required")
	}
	if item.ListenPortStart < 1 || item.ListenPortStart > 65535 || item.ListenPortEnd < 1 || item.ListenPortEnd > 65535 {
		return errText("listen port must be 1-65535")
	}
	if item.ListenPortEnd < item.ListenPortStart {
		return errText("listen port end precedes start")
	}
	if item.TargetPortStart < 1 || item.TargetPortStart > 65535 || item.TargetPortEnd < 1 || item.TargetPortEnd > 65535 {
		return errText("target port must be 1-65535")
	}
	if item.TargetPortEnd < item.TargetPortStart {
		return errText("target port end precedes start")
	}
	if item.ListenPortEnd-item.ListenPortStart != item.TargetPortEnd-item.TargetPortStart {
		return errText("listen and target port range lengths differ")
	}
	switch item.Protocol {
	case "tcp", "udp", "both":
	default:
		return errText("protocol must be tcp, udp or both")
	}
	if !validListenAddress(item.ListenFamily, item.ListenAddress) {
		return errText("invalid listen address for family")
	}
	if !validTargetHost(item.TargetHost) {
		return errText("target host must be a valid IP or domain")
	}
	if item.ForwardMode != "nft" && item.ForwardMode != "relay" && item.ForwardMode != "auto" {
		return errText("forward_mode must be auto, nft or relay")
	}
	if item.RateLimitKbps < 0 {
		return errText("rate_limit_kbps cannot be negative")
	}
	// Cross-family requires relay; nft mode requires same-family IP target.
	listenFamily := item.effectiveListenFamily()
	targetFamily := item.effectiveTargetFamily()
	if item.ForwardMode == "nft" {
		if listenFamily != targetFamily {
			return errText("nft mode cannot cross address families; use relay or auto")
		}
		if net.ParseIP(item.TargetHost) == nil {
			return errText("nft mode requires an IP target (relay mode supports domains)")
		}
	}
	// Disabled rules are migration drafts and do not own a listening endpoint.
	// Their conflicts are checked again immediately before they are enabled.
	if item.Enabled {
		if err := checkForwardPortCollisions(item, excludeID); err != nil {
			return err
		}
	}
	return nil
}

func (item portForwardItem) effectiveListenFamily() string {
	switch item.ListenFamily {
	case "ipv4":
		return "ipv4"
	case "ipv6":
		return "ipv6"
	}
	ip := net.ParseIP(strings.Trim(item.ListenAddress, "[]"))
	if ip == nil {
		return "ipv4" // 0.0.0.0 / :: / empty default to v4 for rendering
	}
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

func (item portForwardItem) effectiveTargetFamily() string {
	switch item.TargetFamily {
	case "ipv4":
		return "ipv4"
	case "ipv6":
		return "ipv6"
	}
	host := item.TargetHost
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip.To4() != nil {
			return "ipv4"
		}
		return "ipv6"
	}
	return "auto" // domain: family resolved at relay runtime
}

func validListenAddress(family, address string) bool {
	address = strings.Trim(address, "[]")
	switch address {
	case "", "*", "0.0.0.0", "::":
		return true
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return false
	}
	switch family {
	case "ipv4":
		return ip.To4() != nil
	case "ipv6":
		return ip.To4() == nil
	}
	return true
}

func validTargetHost(host string) bool {
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return hostnamePattern.MatchString(host) && len(host) <= 253
}

// checkForwardPortCollisions verifies the listen ports do not collide with
// other port-forward rules, PortHub mappings, or live listeners on this host.
func checkForwardPortCollisions(item portForwardItem, excludeID int) error {
	// 1. Other port-forward rules.
	rows, _ := db.Query(`select id,name,coalesce(listen_family,'auto'),listen_address,listen_port_start,listen_port_end,protocol from port_forwards where id != ? and enabled=1`, excludeID)
	defer rows.Close()
	for rows.Next() {
		var id int
		var name, listenFamily, listenAddr, proto string
		var start, end int
		rows.Scan(&id, &name, &listenFamily, &listenAddr, &start, &end, &proto)
		other := portForwardItem{ListenFamily: listenFamily, ListenAddress: listenAddr}
		if item.effectiveListenFamily() != other.effectiveListenFamily() {
			continue
		}
		if portRangesOverlap(item.ListenPortStart, item.ListenPortEnd, start, end) &&
			protocolsOverlap(item.Protocol, proto) &&
			listenAddressesOverlap(item.ListenAddress, listenAddr) {
			return errText(fmt.Sprintf("port %d-%d collides with forward %q (%s)", item.ListenPortStart, item.ListenPortEnd, name, proto))
		}
	}
	// 2. PortHub mappings (public side).
	for _, m := range loadMappings(0) {
		if !m.Enabled {
			continue
		}
		if portRangesOverlap(item.ListenPortStart, item.ListenPortEnd, m.PublicStart, m.PublicEnd) &&
			protocolsOverlap(item.Protocol, string(m.Protocol)) {
			return errText(fmt.Sprintf("port %d-%d collides with mapping %q", item.ListenPortStart, item.ListenPortEnd, m.Name))
		}
	}
	// 3. Live listeners on this host (PortHub, SSH, WireGuard and other services).
	//    Only endpoints porthub-relay is ACTUALLY listening on right now are
	//    exempt. A rule configured for relay but not running does NOT hold
	//    its port (it could collide with another service and fail to start).
	//    Checks are protocol-aware: a TCP listener does not block a UDP rule
	//    on the same port and vice versa.
	held := relayHeldEndpoints()
	protos := []string{"tcp"}
	if item.Protocol == "udp" {
		protos = []string{"udp"}
	} else if item.Protocol == "both" {
		protos = []string{"tcp", "udp"}
	}
	family := item.effectiveListenFamily()
	busy := liveListenPorts(family)
	for port := item.ListenPortStart; port <= item.ListenPortEnd; port++ {
		for _, p := range protos {
			portStr := strconv.Itoa(port)
			// Family-scoped key: any listener on this family/port blocks.
			famKey := p + ":" + family + ":" + portStr
			// Address-scoped key: only used when the candidate listens on a
			// concrete address (a wildcard listener is blocked by ANY
			// address binding on that port, including relay-held ones).
			addrKey := ""
			if ip := net.ParseIP(strings.Trim(item.ListenAddress, "[]")); ip != nil {
				addrKey = p + ":" + family + ":" + ip.String() + ":" + portStr
			}
			blocked := busy[famKey]
			if addrKey != "" && busy[addrKey] {
				blocked = true
			}
			if !blocked {
				continue
			}
			// The port is occupied on this family. Exempt ONLY if the relay
			// actually holds it on a compatible binding: same family on the
			// wildcard, or on the exact same address. A relay bound to a
			// concrete address does NOT exempt a wildcard candidate.
			if held[p+":"+portStr] || held[famKey] {
				continue
			}
			if addrKey != "" && held[addrKey] {
				continue
			}
			if ip := net.ParseIP(strings.Trim(item.ListenAddress, "[]")); ip != nil {
				if held[p+":"+family+":"+ip.String()+":"+portStr] {
					continue
				}
			}
			return errText(fmt.Sprintf("port %d/%s is already in use by another service on this host", port, strings.ToUpper(p)))
		}
	}
	return nil
}

func portRangesOverlap(aStart, aEnd, bStart, bEnd int) bool {
	return aStart <= bEnd && bStart <= aEnd
}

func protocolsOverlap(a, b string) bool {
	if a == "both" || b == "both" {
		return true
	}
	return a == b
}

func listenAddressesOverlap(a, b string) bool {
	a = strings.Trim(a, "[]")
	b = strings.Trim(b, "[]")
	wild := func(v string) bool { return v == "" || v == "*" || v == "0.0.0.0" || v == "::" }
	if wild(a) || wild(b) {
		return true
	}
	return a == b
}

// liveListenPorts reads /proc/net/tcp{,6} and /proc/net/udp{,6} to find
// occupied listen ports, scoped to the requested family. Keys are emitted
// at two granularities:
//
//	"tcp:ipv4:5666"          — the port is listened on that family
//	"tcp:ipv4:1.2.3.4:5666"  — listened on that concrete address
//
// TCP listeners show st=0A; UDP servers show st=07.
func liveListenPorts(family string) map[string]bool {
	out := map[string]bool{}
	tcpFiles := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	udpFiles := []string{"/proc/net/udp", "/proc/net/udp6"}
	switch family {
	case "ipv6":
		tcpFiles = []string{"/proc/net/tcp6"}
		udpFiles = []string{"/proc/net/udp6"}
	case "ipv4":
		tcpFiles = []string{"/proc/net/tcp"}
		udpFiles = []string{"/proc/net/udp"}
	}
	for _, file := range tcpFiles {
		collectListenPorts(file, out, "tcp", family)
	}
	for _, file := range udpFiles {
		collectListenPorts(file, out, "udp", family)
	}
	return out
}

// relayHeldEndpoints returns the endpoints porthub-relay is actually
// listening on right now, read from its status snapshot. Keys are emitted in
// three granularities so a collision check can match exactly:
//
//	"tcp:5666"              — the port is held on ANY family/address
//	"tcp:ipv4:5666"         — held on that family (any address)
//	"tcp:ipv4:0.0.0.0:5666" — held on that concrete address
//
// A TCP listener never exempts a UDP rule on the same port. Freshness uses a
// default-DENY policy: a missing, unparseable, or future-dated updated_at
// timestamp means the snapshot is NOT trusted and nothing is exempted.
func relayHeldEndpoints() map[string]bool {
	out := map[string]bool{}
	status := readRelayStatus()
	if status == nil {
		return out
	}
	updated, ok := status["updated_at"].(string)
	if !ok {
		return out // missing timestamp: default deny
	}
	ts, err := time.Parse(time.RFC3339, updated)
	if err != nil {
		return out // unparseable timestamp: default deny
	}
	if time.Since(ts) > 15*time.Second {
		return out // stale snapshot: do not exempt anything
	}
	if time.Since(ts) < -5*time.Second {
		return out // future-dated timestamp: clock skew, do not trust
	}
	rules, _ := status["rules"].([]any)
	for _, raw := range rules {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		running, _ := entry["running"].(bool)
		if !running {
			continue
		}
		family, _ := entry["listen_family"].(string)
		listen, _ := entry["listen"].(string)
		if family == "" {
			family = "ipv4"
		}
		if listen == "" || listen == "0.0.0.0" || listen == "::" {
			listen = ""
		}
		eps, _ := entry["endpoints"].([]any)
		for _, e := range eps {
			s, ok := e.(string)
			if !ok {
				continue
			}
			out[s] = true
			// Expand "udp:5666" into family/address-aware keys. A relay
			// listening on the wildcard holds the family-level key (any
			// address on that family); a relay bound to a concrete address
			// only holds the exact-address key, so a wildcard candidate on
			// the same port is NOT exempted.
			if idx := strings.LastIndex(s, ":"); idx > 0 {
				proto := s[:idx]
				port := s[idx+1:]
				if listen == "" {
					out[proto+":"+family+":"+port] = true
				} else {
					out[proto+":"+family+":"+listen+":"+port] = true
				}
			}
		}
	}
	return out
}

func collectListenPorts(path string, out map[string]bool, proto, family string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		state := fields[3]
		if proto == "tcp" && state != "0A" { // TCP_LISTEN
			continue
		}
		if proto == "udp" && state != "07" { // UDP unconnected (server)
			continue
		}
		local := fields[1]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.ParseInt(local[idx+1:], 16, 32)
		if err != nil {
			continue
		}
		if port <= 0 || port > 65535 {
			continue
		}
		portStr := strconv.FormatInt(port, 10)
		out[proto+":"+family+":"+portStr] = true
		// Resolve the hex local address so a concrete listener (e.g.
		// 127.0.0.1:5666) is not treated as occupying the wildcard.
		if ip := hexLocalIP(local[:idx], family); ip != "" {
			out[proto+":"+family+":"+ip+":"+portStr] = true
		}
	}
}

// hexLocalIP converts a /proc/net hex address (little-endian 32-bit for v4,
// 32 hex chars for v6) into a dotted/colon IP string, or "" when it is the
// wildcard address.
func hexLocalIP(hex string, family string) string {
	if family == "ipv4" && len(hex) == 8 {
		// /proc/net/tcp stores the 32-bit address as 4 little-endian bytes.
		ip := net.IPv4(hexByte(hex, 3), hexByte(hex, 2), hexByte(hex, 1), hexByte(hex, 0))
		if ip.Equal(net.IPv4zero) {
			return ""
		}
		return ip.String()
	}
	if family == "ipv6" && len(hex) == 32 {
		var raw [16]byte
		for i := 0; i < 16; i++ {
			hi, _ := strconv.ParseUint(hex[(15-i)*2:(15-i)*2+1], 16, 8)
			lo, _ := strconv.ParseUint(hex[(15-i)*2+1:(15-i)*2+2], 16, 8)
			raw[i] = byte(hi<<4 | lo)
		}
		ip := net.IP(raw[:])
		if ip.IsUnspecified() {
			return ""
		}
		return ip.String()
	}
	return ""
}

func hexByte(s string, idx int) byte {
	v, _ := strconv.ParseUint(s[idx*2:idx*2+2], 16, 8)
	return byte(v)
}

// portForwardToRule converts a persisted item into the nft compile model,
// resolving the referenced ACL (acl_id) into concrete allow/deny CIDRs so
// the "关联 ACL" selection has a real effect on the data plane. ACL rules
// whose port/protocol scope does not cover this forward's listen port are
// skipped, and disabled ACL rules are ignored. When the ACL covers only
// part of the forward's port range, the range is split at ACL boundaries so
// the ACL policy is applied only to the covered sub-range.
func portForwardToRule(item portForwardItem) []nftables.PortForwardRule {
	segments := splitForwardByACL(item)
	var rules []nftables.PortForwardRule
	for _, seg := range segments {
		allowed := append([]string{}, item.AllowedCIDRs...)
		denied := append([]string{}, item.DeniedCIDRs...)
		if seg.UseACL && item.ACLID > 0 {
			for _, acl := range loadACLRules(0) {
				if acl.ID != strconv.Itoa(item.ACLID) || !acl.Enabled {
					continue
				}
				if !aclScopesPort(acl, seg.ListenStart, seg.ListenEnd, item.Protocol) {
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
		}
		rules = append(rules, nftables.PortForwardRule{
			ID:              item.ID,
			ListenFamily:    item.ListenFamily,
			ListenAddress:   item.ListenAddress,
			ListenPortStart: seg.ListenStart,
			ListenPortEnd:   seg.ListenEnd,
			Protocol:        item.Protocol,
			TargetFamily:    item.TargetFamily,
			TargetHost:      item.TargetHost,
			TargetPortStart: seg.TargetStart,
			TargetPortEnd:   seg.TargetEnd,
			SNATMode:        item.SNATMode,
			AllowedCIDRs:    allowed,
			DeniedCIDRs:     denied,
			RateLimitKbps:   item.RateLimitKbps,
		})
	}
	return rules
}

// aclScopesPort reports whether an ACL rule applies to the given listen
// port and protocol. An ACL with no port scope applies to every port;
// otherwise the forward's listen port range must OVERLAP the ACL's port
// range (a range check, not a start-port check, so a forward covering
// 10000-10010 correctly honors an ACL that only covers 10005) and the
// protocol must match (empty protocol list means all protocols).
func aclScopesPort(acl snapshots.ACLRule, portStart, portEnd int, proto string) bool {
	if acl.PortStart > 0 {
		aclEnd := acl.PortEnd
		if aclEnd == 0 {
			aclEnd = acl.PortStart
		}
		if portEnd < acl.PortStart || portStart > aclEnd {
			return false // no overlap between forward range and ACL range
		}
	}
	if len(acl.Protocols) > 0 {
		matched := false
		for _, p := range acl.Protocols {
			ps := string(p)
			if ps == proto || ps == "both" {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// forwardACLSegment is one piece of a forward after splitting by ACL port
// boundaries. Only the sub-range actually covered by the referenced ACL
// carries the ACL policy; the rest of the range keeps the item's own CIDRs.
type forwardACLSegment struct {
	ListenStart int
	ListenEnd   int
	TargetStart int
	TargetEnd   int
	UseACL      bool
}

// splitForwardByACL splits a forward's port range at the ACL's port
// boundaries. A forward covering 10000-10010 with an ACL that only covers
// 10005 yields three segments: 10000-10004 (no ACL), 10005-10005 (ACL),
// 10006-10010 (no ACL). Without a referenced ACL, a single segment covering
// the whole range is returned.
func splitForwardByACL(item portForwardItem) []forwardACLSegment {
	aclStart, aclEnd := 0, 0
	if item.ACLID > 0 {
		for _, acl := range loadACLRules(0) {
			if acl.ID == strconv.Itoa(item.ACLID) && acl.Enabled && aclScopesPort(acl, item.ListenPortStart, item.ListenPortEnd, item.Protocol) {
				if acl.PortStart == 0 {
					aclStart, aclEnd = item.ListenPortStart, item.ListenPortEnd
				} else {
					aclStart, aclEnd = acl.PortStart, acl.PortEnd
				}
				if aclEnd == 0 {
					aclEnd = aclStart
				}
				break
			}
		}
	}
	lo, hi := item.ListenPortStart, item.ListenPortEnd
	if aclStart == 0 || aclEnd < lo || aclStart > hi {
		// No ACL or no overlap: single segment, no ACL policy.
		return []forwardACLSegment{{lo, hi, item.TargetPortStart, item.TargetPortEnd, false}}
	}
	var segments []forwardACLSegment
	// [lo, aclStart-1] — before the ACL range.
	if lo < aclStart {
		off := aclStart - lo
		segments = append(segments, forwardACLSegment{lo, aclStart - 1, item.TargetPortStart, item.TargetPortStart + off - 1, false})
	}
	// [max(lo,aclStart), min(hi,aclEnd)] — the ACL-covered overlap.
	ovLo, ovHi := max(lo, aclStart), min(hi, aclEnd)
	offLo := ovLo - lo
	segments = append(segments, forwardACLSegment{ovLo, ovHi, item.TargetPortStart + offLo, item.TargetPortStart + offLo + (ovHi - ovLo), true})
	// [aclEnd+1, hi] — after the ACL range.
	if hi > aclEnd {
		off := aclEnd + 1 - lo
		segments = append(segments, forwardACLSegment{aclEnd + 1, hi, item.TargetPortStart + off, item.TargetPortStart + off + (hi - aclEnd - 1), false})
	}
	return segments
}

// loadPortForwards loads all rules (or a single one by id).
func loadPortForwards(id int) []portForwardItem {
	query := "select id,name,coalesce(node_id,'local'),coalesce(listen_family,'auto'),coalesce(listen_address,''),listen_port_start,listen_port_end,coalesce(protocol,'tcp'),coalesce(target_family,'auto'),target_host,target_port_start,target_port_end,coalesce(forward_mode,'auto'),coalesce(snat_mode,'auto'),enabled,coalesce(acl_id,0),coalesce(allowed_cidrs,'[]'),coalesce(denied_cidrs,'[]'),coalesce(rate_limit_kbps,0),coalesce(udp_idle_timeout,60),coalesce(health_check,1),coalesce(last_status,'pending'),coalesce(last_error,''),coalesce(created_at,''),coalesce(updated_at,'') from port_forwards"
	args := []any{}
	if id > 0 {
		query += " where id=?"
		args = append(args, id)
	}
	query += " order by id desc"
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []portForwardItem
	for rows.Next() {
		var item portForwardItem
		var enabled, health int
		var allowedJSON, deniedJSON string
		rows.Scan(&item.ID, &item.Name, &item.NodeID, &item.ListenFamily, &item.ListenAddress,
			&item.ListenPortStart, &item.ListenPortEnd, &item.Protocol, &item.TargetFamily, &item.TargetHost,
			&item.TargetPortStart, &item.TargetPortEnd, &item.ForwardMode, &item.SNATMode, &enabled, &item.ACLID,
			&allowedJSON, &deniedJSON, &item.RateLimitKbps, &item.UDPIdleTimeout, &health,
			&item.LastStatus, &item.LastError, &item.CreatedAt, &item.UpdatedAt)
		item.Enabled = enabled == 1
		item.HealthCheck = health == 1
		_ = json.Unmarshal([]byte(allowedJSON), &item.AllowedCIDRs)
		_ = json.Unmarshal([]byte(deniedJSON), &item.DeniedCIDRs)
		out = append(out, item)
	}
	return out
}

// snapshotPortForwardRules returns enabled rules converted for compilation,
// filtering out disabled ones.
func enabledForwardRules(items []portForwardItem) []portForwardItem {
	var out []portForwardItem
	for _, item := range items {
		if item.Enabled {
			out = append(out, item)
		}
	}
	return out
}

// testForwardTarget attempts a TCP connect (or UDP dial) to the target.
func testForwardTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Port < 1 || req.Port > 65535 || !validTargetHost(req.Host) {
		http.Error(w, "valid host and port required", http.StatusBadRequest)
		return
	}
	address := net.JoinHostPort(strings.Trim(req.Host, "[]"), strconv.Itoa(req.Port))
	started := time.Now()
	if req.Protocol == "udp" {
		conn, err := net.DialTimeout("udp", address, 3*time.Second)
		if err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "latency_ms": time.Since(started).Milliseconds()})
			return
		}
		conn.Close()
		writeJSON(w, map[string]any{"ok": true, "note": "udp dial succeeded (service may not respond)", "latency_ms": time.Since(started).Milliseconds()})
		return
	}
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "error": err.Error(), "latency_ms": time.Since(started).Milliseconds()})
		return
	}
	conn.Close()
	writeJSON(w, map[string]any{"ok": true, "latency_ms": time.Since(started).Milliseconds()})
}

// helper used by tests
func forwardItemsToSnapshotRules(items []portForwardItem) []snapshots.Mapping {
	return nil
}
