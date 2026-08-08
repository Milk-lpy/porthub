package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"strings"
	"testing"
	"time"
)

func TestManagedWireGuardNeverMutatesProtectedPeer(t *testing.T) {
	corePublic, _, _ := ed25519.GenerateKey(rand.Reader)
	clientPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	signingPublic, signingPrivate, _ := ed25519.GenerateKey(rand.Reader)
	coreKey := base64.StdEncoding.EncodeToString(corePublic)
	clientKey := base64.StdEncoding.EncodeToString(clientPublic)

	oldData, oldPub, oldNonces, oldCommand := data, pub, nonces, wgCommand
	data, pub, nonces = t.TempDir(), signingPublic, map[string]time.Time{}
	defer func() { data, pub, nonces, wgCommand = oldData, oldPub, oldNonces, oldCommand }()
	var commands [][]string
	wgCommand = func(args ...string) ([]byte, error) {
		commands = append(commands, append([]string(nil), args...))
		switch strings.Join(args, " ") {
		case "show wg-porthub peers":
			return []byte(coreKey + "\n"), nil
		case "show wg-porthub allowed-ips":
			return []byte(coreKey + "\t10.255.0.2/32,192.0.2.0/24\n"), nil
		default:
			return nil, nil
		}
	}
	if err := captureWireGuardBaseline(); err != nil {
		t.Fatal(err)
	}

	set, err := snapshots.SignWireGuardPeerSet(snapshots.WireGuardPeerSet{Peers: []snapshots.WireGuardPeer{{
		ID: 1, Name: "client", PublicKey: clientKey, Address: "10.255.0.10/32", Keepalive: 25, Enabled: true,
	}}}, signingPrivate)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(set)
	response := httptest.NewRecorder()
	applyWireGuardPeers(response, httptest.NewRequest(http.MethodPost, "/api/wireguard/peers/apply", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("apply failed: %d %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(filepath.Join(data, "wireguard-managed.json")); err != nil {
		t.Fatal(err)
	}
	for _, command := range commands {
		if strings.Contains(strings.Join(command, " "), coreKey+" remove") {
			t.Fatal("protected Core peer was removed")
		}
	}

	nonces = map[string]time.Time{}
	protectedSet, _ := snapshots.SignWireGuardPeerSet(snapshots.WireGuardPeerSet{Peers: []snapshots.WireGuardPeer{{
		ID: 2, Name: "forbidden", PublicKey: coreKey, Address: "10.255.0.11/32", Enabled: true,
	}}}, signingPrivate)
	body, _ = json.Marshal(protectedSet)
	response = httptest.NewRecorder()
	applyWireGuardPeers(response, httptest.NewRequest(http.MethodPost, "/api/wireguard/peers/apply", bytes.NewReader(body)))
	if response.Code != http.StatusConflict {
		t.Fatalf("protected peer takeover should be rejected, got %d", response.Code)
	}
}
