package nftables

import (
	"fmt"
	"net"
	"porthub/internal/snapshots"
	"sort"
	"strconv"
	"strings"
	"time"
)

func Compile(s snapshots.Snapshot, wgIface string) (string, error) {
	return CompileAt(s, wgIface, time.Now().UTC())
}

func CompileAt(s snapshots.Snapshot, wgIface string, now time.Time) (string, error) {
	if wgIface == "" {
		wgIface = "wg-porthub"
	}
	if err := snapshots.ValidateMappings(s.Mappings); err != nil {
		return "", err
	}
	if err := snapshots.ValidateACLRules(s.ACLRules); err != nil {
		return "", err
	}
	if err := snapshots.ValidateACLRefs(s.Mappings, s.ACLRules); err != nil {
		return "", err
	}
	if err := snapshots.ValidateIPSets(s.IPSets); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("destroy table inet porthub\n")
	b.WriteString("table inet porthub {\n")
	writeIPSetDefinitions(&b, s)
	writeMappingACLSetDefinitions(&b, s, now)
	b.WriteString(" chain prerouting { type nat hook prerouting priority dstnat; policy accept;\n")
	writeIPSetACL(&b, s)
	for idx, m := range s.Mappings {
		if !m.Enabled {
			continue
		}
		protos := []snapshots.Protocol{m.Protocol}
		if m.Protocol == snapshots.TCPUDP {
			protos = []snapshots.Protocol{snapshots.TCP, snapshots.UDP}
		}
		for _, p := range protos {
			span := m.PublicEnd - m.PublicStart
			for i := 0; i <= span; i++ {
				dst := net.ParseIP(m.TargetIP)
				writeMappingACL(&b, s, m, idx, p, m.PublicStart+i, now)
				selector := mappingSelector(m, p, m.PublicStart+i)
				if m.RateLimitKbps > 0 {
					b.WriteString(fmt.Sprintf("  %s limit rate over %d kbytes/second counter drop\n", selector, m.RateLimitKbps))
				}
				if m.ConnectionLimit > 0 && p == snapshots.TCP {
					b.WriteString(fmt.Sprintf("  %s ct state new ct count over %d counter drop\n", selector, m.ConnectionLimit))
				}
				if dst.To4() == nil {
					b.WriteString(fmt.Sprintf("  %s counter dnat ip6 to [%s]:%d\n", selector, dst.String(), m.TargetStart+i))
				} else {
					b.WriteString(fmt.Sprintf("  %s counter dnat ip to %s:%d\n", selector, dst.String(), m.TargetStart+i))
				}
			}
		}
	}
	b.WriteString(" }\n chain postrouting { type nat hook postrouting priority srcnat; policy accept; oifname \"")
	b.WriteString(wgIface)
	b.WriteString("\" counter masquerade; }\n}\n")
	return b.String(), nil
}

func writeMappingACLSetDefinitions(b *strings.Builder, s snapshots.Snapshot, now time.Time) {
	for idx, m := range s.Mappings {
		if !m.Enabled {
			continue
		}
		protocols := []snapshots.Protocol{m.Protocol}
		if m.Protocol == snapshots.TCPUDP {
			protocols = []snapshots.Protocol{snapshots.TCP, snapshots.UDP}
		}
		for _, protocol := range protocols {
			for port := m.PublicStart; port <= m.PublicEnd; port++ {
				v4, v6 := splitCIDRsByFamily(mappingCIDRs(s, m, snapshots.ACLAllow, protocol, port, now))
				if len(v4) > 0 {
					b.WriteString(fmt.Sprintf(" set %s { type ipv4_addr; flags interval; elements = { %s }; }\n", mapACLSetName(idx, protocol, port, "v4"), strings.Join(v4, ", ")))
				}
				if len(v6) > 0 {
					b.WriteString(fmt.Sprintf(" set %s { type ipv6_addr; flags interval; elements = { %s }; }\n", mapACLSetName(idx, protocol, port, "v6"), strings.Join(v6, ", ")))
				}
			}
		}
	}
}

func writeMappingACL(b *strings.Builder, s snapshots.Snapshot, m snapshots.Mapping, idx int, proto snapshots.Protocol, port int, now time.Time) {
	selector := mappingSelector(m, proto, port)
	for _, cidr := range mappingCIDRs(s, m, snapshots.ACLDeny, proto, port, now) {
		family := "ip"
		if strings.Contains(cidr, ":") {
			family = "ip6"
		}
		b.WriteString(fmt.Sprintf("  %s saddr %s %s counter drop\n", family, cidr, selector))
	}
	allowCIDRs := mappingCIDRs(s, m, snapshots.ACLAllow, proto, port, now)
	v4, v6 := splitCIDRsByFamily(allowCIDRs)
	if len(v4) > 0 {
		b.WriteString(fmt.Sprintf("  ip saddr != @%s %s counter drop\n", mapACLSetName(idx, proto, port, "v4"), selector))
	}
	if len(v6) > 0 {
		b.WriteString(fmt.Sprintf("  ip6 saddr != @%s %s counter drop\n", mapACLSetName(idx, proto, port, "v6"), selector))
	}
}

func mappingCIDRs(s snapshots.Snapshot, m snapshots.Mapping, action snapshots.ACLAction, protocol snapshots.Protocol, port int, now time.Time) []string {
	var out []string
	for _, rule := range s.ACLRules {
		if rule.Action == action && snapshots.ACLRuleMatches(rule, m, protocol, port, now) {
			out = append(out, rule.CIDR)
		}
	}
	return out
}

func mapACLSetName(idx int, protocol snapshots.Protocol, port int, family string) string {
	return "mapacl_" + strconv.Itoa(idx+1) + "_" + string(protocol) + "_" + strconv.Itoa(port) + "_" + family
}

func writeIPSetDefinitions(b *strings.Builder, s snapshots.Snapshot) {
	for idx, set := range s.IPSets {
		if !set.Enabled || set.Action != snapshots.ACLDeny {
			continue
		}
		v4, v6 := splitCIDRsByFamily(set.CIDRs)
		if len(v4) > 0 {
			b.WriteString(fmt.Sprintf(" set %s { type ipv4_addr; flags interval; elements = { %s }; }\n", ipSetName(idx, "v4"), strings.Join(v4, ", ")))
		}
		if len(v6) > 0 {
			b.WriteString(fmt.Sprintf(" set %s { type ipv6_addr; flags interval; elements = { %s }; }\n", ipSetName(idx, "v6"), strings.Join(v6, ", ")))
		}
	}
}

func writeIPSetACL(b *strings.Builder, s snapshots.Snapshot) {
	ports := publicPorts(s.Mappings)
	for idx, set := range s.IPSets {
		if !set.Enabled || set.Action != snapshots.ACLDeny {
			continue
		}
		v4, v6 := splitCIDRsByFamily(set.CIDRs)
		for _, p := range ports {
			if len(v4) > 0 {
				b.WriteString(fmt.Sprintf("  ip saddr @%s %s counter drop\n", ipSetName(idx, "v4"), p.selector()))
			}
			if len(v6) > 0 {
				b.WriteString(fmt.Sprintf("  ip6 saddr @%s %s counter drop\n", ipSetName(idx, "v6"), p.selector()))
			}
		}
	}
}

func splitCIDRsByFamily(cidrs []string) ([]string, []string) {
	var v4, v6 []string
	for _, cidr := range cidrs {
		if strings.Contains(cidr, ":") {
			v6 = append(v6, cidr)
		} else {
			v4 = append(v4, cidr)
		}
	}
	return v4, v6
}

func ipSetName(idx int, family string) string {
	return "ipset_" + strconv.Itoa(idx+1) + "_" + family
}

type publicPort struct {
	proto  snapshots.Protocol
	port   int
	ip     string
	family string
}

func (p publicPort) selector() string {
	selector := fmt.Sprintf("%s dport %d", p.proto, p.port)
	if p.ip != "" {
		family := "ip"
		if strings.Contains(p.ip, ":") {
			family = "ip6"
		}
		selector = family + " daddr " + p.ip + " " + selector
	} else if p.family == "ipv6" {
		selector = "meta nfproto ipv6 " + selector
	}
	return selector
}

func mappingSelector(mapping snapshots.Mapping, protocol snapshots.Protocol, port int) string {
	family := "ipv4"
	if strings.Contains(mapping.TargetIP, ":") {
		family = "ipv6"
	}
	return publicPort{proto: protocol, port: port, ip: mapping.PublicIP, family: family}.selector()
}

func publicPorts(ms []snapshots.Mapping) []publicPort {
	seen := map[string]bool{}
	var out []publicPort
	for _, m := range ms {
		if !m.Enabled {
			continue
		}
		protos := []snapshots.Protocol{m.Protocol}
		if m.Protocol == snapshots.TCPUDP {
			protos = []snapshots.Protocol{snapshots.TCP, snapshots.UDP}
		}
		for _, proto := range protos {
			for port := m.PublicStart; port <= m.PublicEnd; port++ {
				family := "ipv4"
				if strings.Contains(m.TargetIP, ":") {
					family = "ipv6"
				}
				k := family + ":" + m.PublicIP + ":" + string(proto) + ":" + fmt.Sprint(port)
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, publicPort{proto: proto, port: port, ip: m.PublicIP, family: family})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].proto == out[j].proto {
			return out[i].port < out[j].port
		}
		return out[i].proto < out[j].proto
	})
	return out
}
