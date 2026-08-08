package nftables

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// PortForwardRule describes one same-family forwarding rule rendered into
// the inet porthub_core table. Cross-family rules are handled by the relay.
type PortForwardRule struct {
	ID              int
	ListenFamily    string // auto / ipv4 / ipv6
	ListenAddress   string // 0.0.0.0 / :: / specific address / empty
	ListenPortStart int
	ListenPortEnd   int
	Protocol        string // tcp / udp / both
	TargetFamily    string // auto / ipv4 / ipv6
	TargetHost      string // IP literal (nft mode only supports IP targets)
	TargetPortStart int
	TargetPortEnd   int
	SNATMode        string // auto / masquerade / none
	AllowedCIDRs    []string
	DeniedCIDRs     []string
	RateLimitKbps   int
}

// CompilePortForwardRules renders nft rule fragments (inside table inet
// porthub_core) for same-address-family forwards. Each rule carries a
// comment with the resource id so operators can trace rules back to
// PortHub records. Rules are grouped and sorted for deterministic output.
func CompilePortForwardRules(rules []PortForwardRule) (forwardLines, natLines, dnatLines []string, err error) {
	for _, rule := range rules {
		if err := validatePortForwardRuleShape(rule); err != nil {
			return nil, nil, nil, fmt.Errorf("forward %d: %w", rule.ID, err)
		}
		listenFamily, err := effectiveFamily(rule.ListenFamily, familyFromAddress(rule.ListenAddress))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("forward %d: %w", rule.ID, err)
		}
		targetFamily, err := effectiveFamily(rule.effectiveTargetFamily(), net.ParseIP(rule.TargetHost))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("forward %d: %w", rule.ID, err)
		}
		if listenFamily != targetFamily {
			// Cross-family rules belong to the relay; skip here.
			continue
		}
		comment := fmt.Sprintf(" # pf:%d", rule.ID)
		protocols := []string{"tcp"}
		if rule.Protocol == "udp" {
			protocols = []string{"udp"}
		} else if rule.Protocol == "both" {
			protocols = []string{"tcp", "udp"}
		}
		port := fmt.Sprintf("%d", rule.ListenPortStart)
		if rule.ListenPortEnd != rule.ListenPortStart {
			port = fmt.Sprintf("%d-%d", rule.ListenPortStart, rule.ListenPortEnd)
		}
		targetPort := fmt.Sprintf("%d", rule.TargetPortStart)
		if rule.TargetPortEnd != rule.TargetPortStart {
			targetPort = fmt.Sprintf("%d-%d", rule.TargetPortStart, rule.TargetPortEnd)
		}
		addrMatch := daddrMatch(listenFamily, rule.ListenAddress)
		target := rule.TargetHost + ":" + targetPort
		if ip := net.ParseIP(rule.TargetHost); ip != nil && ip.To4() == nil {
			target = "[" + rule.TargetHost + "]:" + targetPort
		}
		for _, proto := range protocols {
			matcher := addrMatch
			if matcher != "" {
				matcher += " "
			}
			denyMatcher := ""
			if len(rule.DeniedCIDRs) > 0 {
				denyMatcher = listenFamily + " saddr { " + strings.Join(rule.DeniedCIDRs, ", ") + " } "
			}
			allowMatcher := ""
			if len(rule.AllowedCIDRs) > 0 {
				allowMatcher = listenFamily + " saddr { " + strings.Join(rule.AllowedCIDRs, ", ") + " } "
			}
			dport := fmt.Sprintf("%s dport %s", proto, port)
			if denyMatcher != "" {
				dnatLines = append(dnatLines, fmt.Sprintf("  %s%s%s counter drop%s", matcher, denyMatcher, dport, comment))
			}
			// Rate limit: packets beyond the configured rate (kbps, converted
			// to bytes/sec as kbps*1000/8 = kbps*125) are dropped before DNAT.
			// NOTE: in byte-rate mode nft does NOT accept a `packets` burst
			// qualifier ("syntax error, unexpected packets") — bytes/second
			// mode takes an optional byte burst, so emit no burst token at all.
			if rule.RateLimitKbps > 0 {
				rateBytes := rule.RateLimitKbps * 125
				dnatLines = append(dnatLines, fmt.Sprintf("  %s%s limit rate over %d bytes/second counter drop%s", matcher, dport, rateBytes, comment))
			}
			// An inet table carries both address families, so nft requires an
			// explicit NAT family when no daddr matcher disambiguates the rule.
			dnatLines = append(dnatLines, fmt.Sprintf("  %s%s%s counter dnat %s to %s%s", matcher, allowMatcher, dport, listenFamily, target, comment))
			if len(rule.AllowedCIDRs) > 0 {
				// Whitelist mode: traffic not matching the allow set is dropped.
				dnatLines = append(dnatLines, fmt.Sprintf("  %s%s counter drop%s", matcher, dport, comment))
			}
			if rule.SNATMode != "none" {
				// SNAT must match the POST-DNAT destination (target host and
				// target port), not the original sport. `ip tcp sport` is
				// invalid nft syntax; the correct form matches family,
				// daddr=<target>, proto, dport=<target port>.
				natLines = append(natLines, fmt.Sprintf("  %s daddr %s %s dport %s counter masquerade%s", listenFamily, rule.TargetHost, proto, targetPort, comment))
			}
		}
	}
	sort.Strings(forwardLines)
	sort.Strings(natLines)
	sort.Strings(dnatLines)
	return forwardLines, natLines, dnatLines, nil
}

// effectiveTargetFamily derives the target address family from the rule's declared
// target_family or from the target host literal.
func (r PortForwardRule) effectiveTargetFamily() string {
	if r.TargetFamily != "" {
		return r.TargetFamily
	}
	if ip := net.ParseIP(r.TargetHost); ip != nil {
		if ip.To4() != nil {
			return "ipv4"
		}
		return "ipv6"
	}
	return "auto"
}

func familyFromAddress(address string) net.IP {
	if address == "" || address == "0.0.0.0" || address == "::" {
		return nil
	}
	return net.ParseIP(address)
}

func effectiveFamily(declared string, probe net.IP) (string, error) {
	switch strings.ToLower(declared) {
	case "ipv4":
		return "ip", nil
	case "ipv6":
		return "ip6", nil
	case "", "auto":
		if probe == nil {
			return "ip", nil // unspecified listen defaults to v4 in nft rendering
		}
		if probe.To4() != nil {
			return "ip", nil
		}
		return "ip6", nil
	default:
		return "", fmt.Errorf("invalid family %q", declared)
	}
}

func daddrMatch(family, listenAddress string) string {
	if listenAddress == "" || listenAddress == "0.0.0.0" || listenAddress == "::" {
		return ""
	}
	return family + " daddr " + listenAddress
}

func validatePortForwardRuleShape(rule PortForwardRule) error {
	if rule.ListenPortStart < 1 || rule.ListenPortStart > 65535 || rule.ListenPortEnd < 1 || rule.ListenPortEnd > 65535 {
		return fmt.Errorf("invalid listen port range")
	}
	if rule.ListenPortEnd < rule.ListenPortStart {
		return fmt.Errorf("listen port end precedes start")
	}
	if rule.TargetPortStart < 1 || rule.TargetPortStart > 65535 || rule.TargetPortEnd < 1 || rule.TargetPortEnd > 65535 {
		return fmt.Errorf("invalid target port range")
	}
	if rule.TargetPortEnd < rule.TargetPortStart {
		return fmt.Errorf("target port end precedes start")
	}
	listenLen := rule.ListenPortEnd - rule.ListenPortStart
	targetLen := rule.TargetPortEnd - rule.TargetPortStart
	if listenLen != targetLen {
		return fmt.Errorf("listen and target port range lengths differ")
	}
	switch rule.Protocol {
	case "tcp", "udp", "both":
	default:
		return fmt.Errorf("invalid protocol %q", rule.Protocol)
	}
	if net.ParseIP(rule.TargetHost) == nil && rule.TargetHost != "" {
		return fmt.Errorf("nft mode requires an IP target (use relay for domain targets)")
	}
	return nil
}
