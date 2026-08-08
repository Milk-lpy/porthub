package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainsOwnTable(t *testing.T) {
	if !containsOwnTable([]byte("table inet porthub { chain prerouting {} }")) {
		t.Fatal("expected PortHub table detection")
	}
	if containsOwnTable([]byte("table inet filter { chain input {} }")) {
		t.Fatal("unexpected non-PortHub table detection")
	}
}

func TestWriteNFTCandidateIsAtomicallyGroupReadable(t *testing.T) {
	oldData := data
	data = t.TempDir()
	defer func() { data = oldData }()
	directory := filepath.Join(data, "netd")
	if err := os.MkdirAll(directory, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "candidate.nft")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	written, err := writeNFTCandidate("candidate.nft", []byte("table inet porthub {}"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(written)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("expected mode 0640, got %04o", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temporary candidate should not remain after rename")
	}
}
