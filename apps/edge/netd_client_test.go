package main

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func withFakeEdgeNetd(t *testing.T, handler http.Handler) {
	t.Helper()
	oldSocket := edgeNetdSocket
	edgeNetdSocket = filepath.Join(t.TempDir(), "netd.sock")
	listener, err := net.Listen("unix", edgeNetdSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		edgeNetdSocket = oldSocket
	})
}

func TestEdgeNetdReadOperations(t *testing.T) {
	withFakeEdgeNetd(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/nft/list":
			_ = json.NewEncoder(w).Encode(map[string]string{"output": "table inet porthub {}\n"})
		case "/v1/conntrack/list":
			_ = json.NewEncoder(w).Encode(map[string]string{"output": "udp 17 10\n"})
		default:
			http.NotFound(w, r)
		}
	}))
	nft, err := edgeNetdListNFT()
	if err != nil || string(nft) != "table inet porthub {}\n" {
		t.Fatalf("unexpected nft response %q: %v", nft, err)
	}
	conntrack, err := edgeNetdListConntrack()
	if err != nil || string(conntrack) != "udp 17 10\n" {
		t.Fatalf("unexpected conntrack response %q: %v", conntrack, err)
	}
}

func TestEdgeNetdWireGuardOperationsAreStructured(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	requests := 0
	withFakeEdgeNetd(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/v1/wireguard/show" {
			if r.URL.Query().Get("field") != "allowed-ips" {
				t.Errorf("unexpected field %q", r.URL.Query().Get("field"))
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"output": key + "\t10.255.0.2/32\n"})
			return
		}
		if r.URL.Path != "/v1/wireguard/peer" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var request edgeNetdWireGuardPeerRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Action != "set" || request.PublicKey != key || len(request.AllowedIPs) != 1 || request.Keepalive != 25 {
			t.Errorf("unexpected peer request: %+v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}))
	if _, err := edgeNetdWireGuardCommand("show", managedWireGuardInterface, "allowed-ips"); err != nil {
		t.Fatal(err)
	}
	if _, err := edgeNetdWireGuardCommand("set", managedWireGuardInterface, "peer", key, "allowed-ips", "10.255.0.2/32", "persistent-keepalive", "25"); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
	if _, err := edgeNetdWireGuardCommand("set", "wg-other", "peer", key, "remove"); err == nil {
		t.Fatal("expected unmanaged interface rejection")
	}
}
