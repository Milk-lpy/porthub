package nftables

import (
	"errors"
	"fmt"
	"net"
	"porthub/internal/snapshots"
	"sort"
	"strings"
)

type CoreForwardConfig struct {
	WGInterface         string
	LANInterface        string
	LANCIDRs            []*net.IPNet
	TunnelCIDRs         []*net.IPNet
	AllowSourcePreserve bool
}

func ParseCIDRs(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q", value)
		}
		out = append(out, network)
	}
	return out, nil
}

func CompileCoreForward(s snapshots.Snapshot, cfg CoreForwardConfig) (string, error) {
	if cfg.WGInterface == "" || cfg.LANInterface == "" {
		return "", errors.New("wireguard and lan interfaces are required")
	}
	if !validInterfaceName(cfg.WGInterface) || !validInterfaceName(cfg.LANInterface) {
		return "", errors.New("invalid interface name")
	}
	if len(cfg.LANCIDRs) == 0 || len(cfg.TunnelCIDRs) == 0 {
		return "", errors.New("lan and tunnel cidrs are required")
	}
	if err := ValidateForwardTargets(s.Mappings, cfg); err != nil {
		return "", err
	}

	var forwardRules []string
	var natRules []string
	for _, mapping := range s.Mappings {
		if !mapping.Enabled || !containsIP(cfg.LANCIDRs, net.ParseIP(mapping.TargetIP)) {
			continue
		}
		protocols := []snapshots.Protocol{mapping.Protocol}
		if mapping.Protocol == snapshots.TCPUDP {
			protocols = []snapshots.Protocol{snapshots.TCP, snapshots.UDP}
		}
		for _, protocol := range protocols {
			family := "ip"
			if net.ParseIP(mapping.TargetIP).To4() == nil {
				family = "ip6"
			}
			port := fmt.Sprintf("%d", mapping.TargetStart)
			if mapping.TargetEnd != mapping.TargetStart {
				port = fmt.Sprintf("%d-%d", mapping.TargetStart, mapping.TargetEnd)
			}
			forwardRules = append(forwardRules, fmt.Sprintf("  iifname \"%s\" oifname \"%s\" %s daddr %s %s dport %s counter accept", cfg.WGInterface, cfg.LANInterface, family, mapping.TargetIP, protocol, port))
			if mapping.SourceMode != "preserve" {
				natRules = append(natRules, fmt.Sprintf("  iifname \"%s\" oifname \"%s\" %s daddr %s %s dport %s counter masquerade", cfg.WGInterface, cfg.LANInterface, family, mapping.TargetIP, protocol, port))
			}
		}
	}
	sort.Strings(forwardRules)
	sort.Strings(natRules)

	var b strings.Builder
	b.WriteString("flush table inet porthub_core\n")
	b.WriteString("table inet porthub_core {\n")
	b.WriteString(" chain forward { type filter hook forward priority filter - 10; policy accept;\n")
	for _, rule := range forwardRules {
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	b.WriteString(fmt.Sprintf("  iifname \"%s\" counter drop\n", cfg.WGInterface))
	b.WriteString(" }\n chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n")
	for _, rule := range natRules {
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	b.WriteString(" }\n}\n")
	return b.String(), nil
}

// CompileCoreForwardWithForwards renders the full porthub_core table file:
// existing mapping rules plus same-family port forward rules (dnat in a
// prerouting chain, forward accept, optional masquerade). ACL allow/deny
// CIDRs are rendered as saddr matchers. Cross-family rules are skipped here
// (they belong to the relay).
func CompileCoreForwardWithForwards(s snapshots.Snapshot, forwards []PortForwardRule, cfg CoreForwardConfig) (string, error) {
	if cfg.WGInterface == "" || cfg.LANInterface == "" {
		return "", errors.New("wireguard and lan interfaces are required")
	}
	if !validInterfaceName(cfg.WGInterface) || !validInterfaceName(cfg.LANInterface) {
		return "", errors.New("invalid interface name")
	}
	if len(cfg.LANCIDRs) == 0 || len(cfg.TunnelCIDRs) == 0 {
		return "", errors.New("lan and tunnel cidrs are required")
	}
	if err := ValidateForwardTargets(s.Mappings, cfg); err != nil {
		return "", err
	}

	var forwardRules []string
	var natRules []string
	var dnatRules []string
	for _, mapping := range s.Mappings {
		if !mapping.Enabled || !containsIP(cfg.LANCIDRs, net.ParseIP(mapping.TargetIP)) {
			continue
		}
		protocols := []snapshots.Protocol{mapping.Protocol}
		if mapping.Protocol == snapshots.TCPUDP {
			protocols = []snapshots.Protocol{snapshots.TCP, snapshots.UDP}
		}
		for _, protocol := range protocols {
			family := "ip"
			if net.ParseIP(mapping.TargetIP).To4() == nil {
				family = "ip6"
			}
			port := fmt.Sprintf("%d", mapping.TargetStart)
			if mapping.TargetEnd != mapping.TargetStart {
				port = fmt.Sprintf("%d-%d", mapping.TargetStart, mapping.TargetEnd)
			}
			forwardRules = append(forwardRules, fmt.Sprintf("  iifname \"%s\" oifname \"%s\" %s daddr %s %s dport %s counter accept", cfg.WGInterface, cfg.LANInterface, family, mapping.TargetIP, protocol, port))
			if mapping.SourceMode != "preserve" {
				natRules = append(natRules, fmt.Sprintf("  iifname \"%s\" oifname \"%s\" %s daddr %s %s dport %s counter masquerade", cfg.WGInterface, cfg.LANInterface, family, mapping.TargetIP, protocol, port))
			}
		}
	}

	pfForward, pfNat, pfDnat, err := CompilePortForwardRules(forwards)
	if err != nil {
		return "", err
	}
	forwardRules = append(forwardRules, pfForward...)
	natRules = append(natRules, pfNat...)
	dnatRules = append(dnatRules, pfDnat...)
	sort.Strings(forwardRules)
	sort.Strings(natRules)
	sort.Strings(dnatRules)

	var b strings.Builder
	b.WriteString("flush table inet porthub_core\n")
	b.WriteString("table inet porthub_core {\n")
	b.WriteString(" chain forward { type filter hook forward priority filter - 10; policy accept;\n")
	for _, rule := range forwardRules {
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	b.WriteString(fmt.Sprintf("  iifname \"%s\" counter drop\n", cfg.WGInterface))
	b.WriteString(" }\n chain prerouting { type nat hook prerouting priority dstnat; policy accept;\n")
	for _, rule := range dnatRules {
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	b.WriteString(" }\n chain postrouting { type nat hook postrouting priority srcnat; policy accept;\n")
	for _, rule := range natRules {
		b.WriteString(rule)
		b.WriteByte('\n')
	}
	b.WriteString(" }\n}\n")
	return b.String(), nil
}

func ValidateForwardTargets(mappings []snapshots.Mapping, cfg CoreForwardConfig) error {
	for _, mapping := range mappings {
		if !mapping.Enabled {
			continue
		}
		ip := net.ParseIP(mapping.TargetIP)
		if ip == nil {
			return fmt.Errorf("mapping %q requires a valid IP target", mapping.Name)
		}
		if !containsIP(cfg.LANCIDRs, ip) && !containsIP(cfg.TunnelCIDRs, ip) {
			return fmt.Errorf("mapping %q target is outside managed LAN and tunnel networks", mapping.Name)
		}
		if mapping.SourceMode == "preserve" && !cfg.AllowSourcePreserve {
			return fmt.Errorf("mapping %q source preservation requires explicit Core route confirmation", mapping.Name)
		}
	}
	return nil
}

func containsIP(networks []*net.IPNet, ip net.IP) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func validInterfaceName(value string) bool {
	if len(value) < 1 || len(value) > 15 {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.' {
			continue
		}
		return false
	}
	return true
}
