package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestWireGuardPeerSetSignature(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	peerKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	set, err := SignWireGuardPeerSet(WireGuardPeerSet{Peers: []WireGuardPeer{{Name: "node", PublicKey: peerKey, Address: "10.255.0.10/32", AllowedIPs: []string{"10.255.0.10/32"}, Enabled: true}}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyWireGuardPeerSet(set, publicKey, time.Now(), func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	set.Peers[0].Address = "10.255.0.11/32"
	if err := VerifyWireGuardPeerSet(set, publicKey, time.Now(), func(string) bool { return false }); err == nil {
		t.Fatal("tampered peer set accepted")
	}
}

func TestWireGuardPeerRoutesCannotOverlap(t *testing.T) {
	publicA, _, _ := ed25519.GenerateKey(rand.Reader)
	publicB, _, _ := ed25519.GenerateKey(rand.Reader)
	peers := []WireGuardPeer{
		{Name: "a", PublicKey: base64.StdEncoding.EncodeToString(publicA), Address: "10.255.0.10/32", AllowedIPs: []string{"192.168.50.0/24"}, Enabled: true},
		{Name: "b", PublicKey: base64.StdEncoding.EncodeToString(publicB), Address: "10.255.0.11/32", AllowedIPs: []string{"192.168.50.20/32"}, Enabled: true},
	}
	if err := ValidateWireGuardPeers(peers); err == nil {
		t.Fatal("overlapping peer routes should be rejected")
	}
	peers[1].AllowedIPs = nil
	peers[1].Address = "10.255.0.0/24"
	if err := ValidateWireGuardPeers(peers); err == nil {
		t.Fatal("peer address must be a host route")
	}
}
