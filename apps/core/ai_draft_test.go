package main

import (
	"porthub/internal/snapshots"
	"testing"
)

func TestLocalAIDraftForDontStarve(t *testing.T) {
	result, err := (localRuleDraftEngine{}).Draft("开放 192.0.2.150 上的 11001 和 11002 UDP，用于饥荒")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Mappings) != 2 || result.Mappings[0].TargetIP != "192.0.2.150" || result.Mappings[0].Protocol != snapshots.UDP || result.Mappings[0].Enabled {
		t.Fatalf("unexpected draft: %+v", result)
	}
	if !result.RequiresConfirmation || len(result.Blockers) != 0 {
		t.Fatalf("draft confirmation contract missing: %+v", result)
	}
}

func TestLocalAIDraftWarnsForSSH(t *testing.T) {
	result, err := (localRuleDraftEngine{}).Draft("把 192.0.2.20 的 SSH 开放出去")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Mappings) != 1 || result.Mappings[0].PublicStart != 22 || len(result.Warnings) == 0 {
		t.Fatalf("SSH risk warning missing: %+v", result)
	}
}

func TestLocalAIDraftReturnsBlockersWithoutTarget(t *testing.T) {
	result, err := (localRuleDraftEngine{}).Draft("开放 Minecraft")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Blockers) == 0 || len(result.Mappings) != 1 {
		t.Fatalf("expected editable blocked draft: %+v", result)
	}
}
