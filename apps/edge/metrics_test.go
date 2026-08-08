package main

import (
	"porthub/internal/snapshots"
	"testing"
)

func TestParseCounterLine(t *testing.T) {
	line := `udp dport 18081 counter packets 0 bytes 0 dnat ip to 10.255.0.2:18081`
	rc, ok := parseCounterLine(line)
	if !ok || rc.Protocol != "udp" || rc.Port != 18081 || rc.Target != "10.255.0.2:18081" {
		t.Fatalf("bad parse: %#v ok=%v", rc, ok)
	}
}

func TestParseConntrackLineKeepsOnlyMappedMetadata(t *testing.T) {
	line := `tcp 6 431999 ESTABLISHED src=198.51.100.22 dst=203.0.113.10 sport=53000 dport=25565 packets=9 bytes=800 src=10.255.0.2 dst=198.51.100.22 sport=25565 dport=53000 packets=8 bytes=700 [ASSURED]`
	mappings := []snapshots.Mapping{{ID: "7", Name: "Minecraft", Protocol: snapshots.TCP, PublicStart: 25565, PublicEnd: 25565, TargetIP: "192.0.2.20", TargetStart: 25565, Enabled: true}}
	entry, ok := parseConntrackLine(line, mappings)
	if !ok || entry.SourceIP != "198.51.100.22" || entry.Mapping != "Minecraft" || entry.Target != "192.0.2.20:25565" || entry.Bytes != 800 {
		t.Fatalf("unexpected connection summary: %+v ok=%v", entry, ok)
	}
}

func TestParseConntrackLineAcceptsAddressFamilyPrefix(t *testing.T) {
	line := `ipv4 2 tcp 6 58 CLOSE_WAIT src=198.51.100.22 dst=203.0.113.10 sport=53000 dport=3001 packets=9 bytes=800 src=10.255.0.2 dst=198.51.100.22 sport=3001 dport=53000 packets=8 bytes=700 [ASSURED] mark=0 use=1`
	mappings := []snapshots.Mapping{{ID: "7", Name: "Hero Hub", Protocol: snapshots.TCP, PublicStart: 3001, PublicEnd: 3001, TargetIP: "192.0.2.12", TargetStart: 3001, Enabled: true}}
	entry, ok := parseConntrackLine(line, mappings)
	if !ok || entry.SourceIP != "198.51.100.22" || entry.Mapping != "Hero Hub" || entry.PublicPort != 3001 || entry.Bytes != 800 {
		t.Fatalf("unexpected family-prefixed connection summary: %+v ok=%v", entry, ok)
	}
}

func TestCounterRateHandlesReset(t *testing.T) {
	if got := counterRate(1000, 1600, 2); got != 300 {
		t.Fatalf("unexpected rate %d", got)
	}
	if got := counterRate(1000, 20, 2); got != 0 {
		t.Fatalf("counter reset should return zero, got %d", got)
	}
}

func TestParseCounterLineWithListenIP(t *testing.T) {
	line := `ip daddr 198.51.100.175 tcp dport 24444 counter packets 9 bytes 900 dnat ip to 10.255.0.2:24444`
	rule, ok := parseCounterLine(line)
	if !ok || rule.Protocol != "tcp" || rule.Port != 24444 || rule.Packets != 9 || rule.Bytes != 900 {
		t.Fatalf("unexpected rule: %+v ok=%v", rule, ok)
	}
}
