package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net"
	"porthub/internal/nftables"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestAllocateWireGuardAddressStartsAtTenAndSkipsUsed(t *testing.T) {
	testDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer testDB.Close()
	if _, err := testDB.Exec(`create table wireguard_peers(id integer primary key,address text); insert into wireguard_peers(address) values('10.255.0.10/32')`); err != nil {
		t.Fatal(err)
	}
	_, tunnel, _ := net.ParseCIDR("10.255.0.0/24")
	oldDB, oldConfig := db, coreForwardConfig
	db = testDB
	coreForwardConfig = nftables.CoreForwardConfig{TunnelCIDRs: []*net.IPNet{tunnel}}
	defer func() { db, coreForwardConfig = oldDB, oldConfig }()
	address, err := allocateWireGuardAddress(0)
	if err != nil {
		t.Fatal(err)
	}
	if address != "10.255.0.11/32" {
		t.Fatalf("unexpected address %s", address)
	}
}

func TestNormalizeWireGuardPeerNeverAcceptsPrivateMaterial(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	peer, err := normalizeWireGuardPeer(wireGuardPeerInput{
		Name: "linux-node", PublicKey: base64.StdEncoding.EncodeToString(public), Address: "10.255.0.20", Keepalive: 25,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if peer.Address != "10.255.0.20/32" || peer.PublicKey == "" {
		t.Fatalf("unexpected normalized peer: %#v", peer)
	}
}
