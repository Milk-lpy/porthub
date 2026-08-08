package main

import (
	"porthub/internal/snapshots"
	"testing"
)

func TestFindEdgePortConflicts(t *testing.T) {
	mappings := []snapshots.Mapping{{Name: "web", Protocol: snapshots.TCPUDP, PublicStart: 9443, PublicEnd: 9443, Enabled: true}}
	conflicts := findEdgePortConflicts(mappings, map[string]bool{"tcp:9443": true, "udp:51830": true})
	if len(conflicts) != 1 || conflicts[0] != "tcp/9443 is already listened on Edge" {
		t.Fatalf("unexpected conflicts: %+v", conflicts)
	}
}
