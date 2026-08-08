package nftables

import (
	"porthub/internal/snapshots"
	"strings"
	"testing"
	"time"
)

func TestCompileOwnTableOnly(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{Mappings: []snapshots.Mapping{{Name: "range", TargetIP: "10.255.0.2", PublicStart: 1000, PublicEnd: 1002, TargetStart: 2000, TargetEnd: 2002, Protocol: snapshots.UDP, Enabled: true}}}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "flush ruleset") || !strings.Contains(out, "table inet porthub") || !strings.Contains(out, "udp dport 1002") {
		t.Fatalf("bad rules: %s", out)
	}
}

func TestCompileDenyACL(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{
		Mappings: []snapshots.Mapping{{Name: "deny", TargetIP: "10.255.0.2", PublicStart: 18080, PublicEnd: 18080, TargetStart: 9731, TargetEnd: 9731, Protocol: snapshots.TCP, Enabled: true, ACLIDs: []string{"1"}}},
		ACLRules: []snapshots.ACLRule{{ID: "1", Name: "test", Action: snapshots.ACLDeny, CIDR: "203.0.113.0/24", Enabled: true}},
	}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ip saddr 203.0.113.0/24 tcp dport 18080 counter drop") {
		t.Fatalf("missing acl drop: %s", out)
	}
	if strings.Index(out, "counter drop") > strings.Index(out, "dnat ip") {
		t.Fatalf("acl should be before dnat: %s", out)
	}
}

func TestCompileDenyIPSet(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{
		Mappings: []snapshots.Mapping{{Name: "ipset", TargetIP: "10.255.0.2", PublicStart: 18080, PublicEnd: 18080, TargetStart: 9731, TargetEnd: 9731, Protocol: snapshots.TCP, Enabled: true}},
		IPSets:   []snapshots.IPSet{{Name: "geo block", Kind: "geoip", Action: snapshots.ACLDeny, CIDRs: []string{"203.0.113.0/24", "2001:db8::/32"}, Enabled: true}},
	}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "set ipset_1_v4 { type ipv4_addr; flags interval; elements = { 203.0.113.0/24 }; }") {
		t.Fatalf("missing ipv4 set: %s", out)
	}
	if !strings.Contains(out, "set ipset_1_v6 { type ipv6_addr; flags interval; elements = { 2001:db8::/32 }; }") {
		t.Fatalf("missing ipv6 set: %s", out)
	}
	if !strings.Contains(out, "ip saddr @ipset_1_v4 tcp dport 18080 counter drop") {
		t.Fatalf("missing ip set drop: %s", out)
	}
	if strings.Index(out, "counter drop") > strings.Index(out, "dnat ip") {
		t.Fatalf("ip set drop should be before dnat: %s", out)
	}
}

func TestCompileMappingDenyACL(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{
		Mappings: []snapshots.Mapping{{Name: "bound deny", TargetIP: "10.255.0.2", PublicStart: 18080, PublicEnd: 18080, TargetStart: 9731, TargetEnd: 9731, Protocol: snapshots.TCP, Enabled: true, ACLIDs: []string{"7"}}},
		ACLRules: []snapshots.ACLRule{{ID: "7", Name: "blocked", Action: snapshots.ACLDeny, CIDR: "203.0.113.0/24", Enabled: true}},
	}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	want := "ip saddr 203.0.113.0/24 tcp dport 18080 counter drop"
	if !strings.Contains(out, want) {
		t.Fatalf("missing mapping acl drop: %s", out)
	}
	if strings.Index(out, want) > strings.Index(out, "dnat ip") {
		t.Fatalf("mapping acl should be before dnat: %s", out)
	}
}

func TestCompileMappingAllowACL(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{
		Mappings: []snapshots.Mapping{{Name: "bound allow", TargetIP: "10.255.0.2", PublicStart: 18080, PublicEnd: 18080, TargetStart: 9731, TargetEnd: 9731, Protocol: snapshots.TCP, Enabled: true, ACLIDs: []string{"8"}}},
		ACLRules: []snapshots.ACLRule{{ID: "8", Name: "office", Action: snapshots.ACLAllow, CIDR: "198.51.100.0/24", Enabled: true}},
	}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "set mapacl_1_tcp_18080_v4 { type ipv4_addr; flags interval; elements = { 198.51.100.0/24 }; }") {
		t.Fatalf("missing mapping allow set: %s", out)
	}
	want := "ip saddr != @mapacl_1_tcp_18080_v4 tcp dport 18080 counter drop"
	if !strings.Contains(out, want) {
		t.Fatalf("missing mapping allow default drop: %s", out)
	}
	if strings.Index(out, want) > strings.Index(out, "dnat ip") {
		t.Fatalf("mapping allow should be before dnat: %s", out)
	}
}

func TestUnboundDenyACLDoesNotAffectMappings(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{
		Mappings: []snapshots.Mapping{{Name: "web", TargetIP: "10.255.0.2", PublicStart: 18080, PublicEnd: 18080, TargetStart: 80, TargetEnd: 80, Protocol: snapshots.TCP, Enabled: true}},
		ACLRules: []snapshots.ACLRule{{ID: "1", Name: "unbound", Action: snapshots.ACLDeny, CIDR: "203.0.113.0/24", Enabled: true}},
	}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "203.0.113.0/24") {
		t.Fatalf("unbound ACL leaked into rules: %s", out)
	}
}

func TestScheduledACLAndProtocolScope(t *testing.T) {
	snapshot := snapshots.Snapshot{
		Mappings: []snapshots.Mapping{{Name: "game", GroupID: "games", TargetIP: "10.255.0.2", PublicStart: 11001, PublicEnd: 11001, TargetStart: 11001, TargetEnd: 11001, Protocol: snapshots.TCPUDP, Enabled: true}},
		ACLRules: []snapshots.ACLRule{{ID: "9", Name: "work hours", GroupIDs: []string{"games"}, Protocols: []snapshots.Protocol{snapshots.UDP}, Action: snapshots.ACLDeny,
			CIDR: "198.51.100.1-198.51.100.9", Enabled: true, Weekdays: []int{1}, StartTime: "09:00", EndTime: "18:00", Timezone: "UTC"}},
	}
	active, err := CompileAt(snapshot, "wg-porthub", time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(active, "ip saddr 198.51.100.1-198.51.100.9 udp dport 11001 counter drop") || strings.Contains(active, "198.51.100.1-198.51.100.9 tcp") {
		t.Fatalf("bad active scheduled ACL: %s", active)
	}
	inactive, err := CompileAt(snapshot, "wg-porthub", time.Date(2026, 8, 3, 20, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(inactive, "198.51.100.1-198.51.100.9") {
		t.Fatalf("inactive ACL remained compiled: %s", inactive)
	}
}

func TestCompileListenIPAndTrafficLimits(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{Mappings: []snapshots.Mapping{{
		Name: "limited", PublicIP: "198.51.100.10", TargetIP: "10.255.0.2",
		PublicStart: 24444, PublicEnd: 24444, TargetStart: 24444, TargetEnd: 24444,
		Protocol: snapshots.TCP, Enabled: true, RateLimitKbps: 2048, ConnectionLimit: 30,
	}}}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip daddr 198.51.100.10 tcp dport 24444 limit rate over 2048 kbytes/second counter drop",
		"ip daddr 198.51.100.10 tcp dport 24444 ct state new ct count over 30 counter drop",
		"ip daddr 198.51.100.10 tcp dport 24444 counter dnat ip to 10.255.0.2:24444",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
}

func TestCompileIPv6DNAT(t *testing.T) {
	out, err := Compile(snapshots.Snapshot{Mappings: []snapshots.Mapping{{
		Name: "v6 web", PublicIP: "2001:db8::10", TargetIP: "fd20:3::20", PublicStart: 8443, PublicEnd: 8443,
		TargetStart: 443, TargetEnd: 443, Protocol: snapshots.TCP, Enabled: true,
	}}}, "wg-porthub")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ip6 daddr 2001:db8::10 tcp dport 8443 counter dnat ip6 to [fd20:3::20]:443") {
		t.Fatalf("missing IPv6 DNAT: %s", out)
	}
}
