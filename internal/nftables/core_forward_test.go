package nftables

import (
	"porthub/internal/snapshots"
	"strings"
	"testing"
)

func TestCompileCoreForwardLANMapping(t *testing.T) {
	lan, _ := ParseCIDRs("192.0.2.0/24")
	tunnel, _ := ParseCIDRs("10.255.0.0/24")
	rules, err := CompileCoreForward(snapshots.Snapshot{Mappings: []snapshots.Mapping{{
		Name: "NAS", TargetIP: "192.0.2.50", PublicStart: 18080, PublicEnd: 18081,
		TargetStart: 80, TargetEnd: 81, Protocol: snapshots.TCPUDP, Enabled: true,
	}}}, CoreForwardConfig{WGInterface: "wg-porthub", LANInterface: "ens18", LANCIDRs: lan, TunnelCIDRs: tunnel})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet porthub_core", "ip daddr 192.0.2.50 tcp dport 80-81", "ip daddr 192.0.2.50 udp dport 80-81", "tcp dport 80-81 counter masquerade", "iifname \"wg-porthub\" counter drop",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("missing %q in %s", want, rules)
		}
	}
	if strings.Contains(rules, "flush ruleset") || strings.Contains(rules, "table inet porthub {") {
		t.Fatalf("compiler escaped owned table: %s", rules)
	}
}

func TestCompileCoreForwardTunnelTargetNeedsNoLANRule(t *testing.T) {
	lan, _ := ParseCIDRs("192.0.2.0/24")
	tunnel, _ := ParseCIDRs("10.255.0.0/24")
	rules, err := CompileCoreForward(snapshots.Snapshot{Mappings: []snapshots.Mapping{{
		Name: "Core", TargetIP: "10.255.0.2", PublicStart: 18080, PublicEnd: 18080,
		TargetStart: 9443, TargetEnd: 9443, Protocol: snapshots.TCP, Enabled: true,
	}}}, CoreForwardConfig{WGInterface: "wg-porthub", LANInterface: "ens18", LANCIDRs: lan, TunnelCIDRs: tunnel})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "ip daddr 10.255.0.2") || strings.Contains(rules, "masquerade") {
		t.Fatalf("tunnel-local target should not be forwarded: %s", rules)
	}
}

func TestCompileCoreForwardRejectsUnmanagedTarget(t *testing.T) {
	lan, _ := ParseCIDRs("192.0.2.0/24")
	tunnel, _ := ParseCIDRs("10.255.0.0/24")
	_, err := CompileCoreForward(snapshots.Snapshot{Mappings: []snapshots.Mapping{{
		Name: "unsafe", TargetIP: "8.8.8.8", PublicStart: 53, PublicEnd: 53,
		TargetStart: 53, TargetEnd: 53, Protocol: snapshots.UDP, Enabled: true,
	}}}, CoreForwardConfig{WGInterface: "wg-porthub", LANInterface: "ens18", LANCIDRs: lan, TunnelCIDRs: tunnel})
	if err == nil {
		t.Fatal("expected unmanaged target rejection")
	}
}

func TestCompileCoreForwardIPv6AndSourcePreserve(t *testing.T) {
	lan, _ := ParseCIDRs("fd20:1::/64")
	tunnel, _ := ParseCIDRs("fd20:3::/64")
	mapping := snapshots.Mapping{Name: "v6", TargetIP: "fd20:1::50", PublicStart: 8443, PublicEnd: 8443, TargetStart: 443, TargetEnd: 443,
		Protocol: snapshots.TCP, Enabled: true, SourceMode: "preserve"}
	_, err := CompileCoreForward(snapshots.Snapshot{Mappings: []snapshots.Mapping{mapping}}, CoreForwardConfig{
		WGInterface: "wg-porthub", LANInterface: "ens18", LANCIDRs: lan, TunnelCIDRs: tunnel,
	})
	if err == nil {
		t.Fatal("source preservation was allowed without route confirmation")
	}
	rules, err := CompileCoreForward(snapshots.Snapshot{Mappings: []snapshots.Mapping{mapping}}, CoreForwardConfig{
		WGInterface: "wg-porthub", LANInterface: "ens18", LANCIDRs: lan, TunnelCIDRs: tunnel, AllowSourcePreserve: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, "ip6 daddr fd20:1::50 tcp dport 443 counter accept") || strings.Contains(rules, "masquerade") {
		t.Fatalf("bad IPv6 preserve rules: %s", rules)
	}
}
