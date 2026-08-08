package nftables

import (
	"strings"
	"testing"
)

func TestCompilePortForwardRulesDisambiguatesInetDNATFamily(t *testing.T) {
	tests := []struct {
		name          string
		listenFamily  string
		listenAddress string
		target        string
		want          string
	}{
		{name: "IPv4", listenFamily: "ipv4", listenAddress: "0.0.0.0", target: "192.0.2.10", want: "counter dnat ip to 192.0.2.10:8080"},
		{name: "IPv6", listenFamily: "ipv6", listenAddress: "::", target: "2001:db8::10", want: "counter dnat ip6 to [2001:db8::10]:8080"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, dnat, err := CompilePortForwardRules([]PortForwardRule{{
				ID: 1, ListenFamily: test.listenFamily, ListenAddress: test.listenAddress,
				ListenPortStart: 18080, ListenPortEnd: 18080, Protocol: "tcp",
				TargetFamily: test.listenFamily, TargetHost: test.target,
				TargetPortStart: 8080, TargetPortEnd: 8080,
			}})
			if err != nil {
				t.Fatal(err)
			}
			if len(dnat) != 1 || !strings.Contains(dnat[0], test.want) {
				t.Fatalf("DNAT family is ambiguous: %v", dnat)
			}
		})
	}
}

func TestCompilePortForwardRulesAddsNATCounters(t *testing.T) {
	_, nat, dnat, err := CompilePortForwardRules([]PortForwardRule{{
		ID: 2, ListenFamily: "ipv4", ListenAddress: "0.0.0.0",
		ListenPortStart: 19000, ListenPortEnd: 19000, Protocol: "udp",
		TargetFamily: "ipv4", TargetHost: "192.0.2.20",
		TargetPortStart: 19000, TargetPortEnd: 19000, SNATMode: "masquerade",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(nat) != 1 || !strings.Contains(nat[0], "counter masquerade") {
		t.Fatalf("SNAT counter missing: %v", nat)
	}
	if len(dnat) != 1 || !strings.Contains(dnat[0], "counter dnat ip") {
		t.Fatalf("DNAT counter missing: %v", dnat)
	}
}
