package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/snapshots"
	"sort"
	"strconv"
	"strings"
	"time"
)

const managedWireGuardInterface = "wg-porthub"

var wgCommand = func(args ...string) ([]byte, error) {
	return edgeNetdWireGuardCommand(args...)
}

type wireGuardBaseline struct {
	CapturedAt time.Time `json:"captured_at"`
	PublicKeys []string  `json:"public_keys"`
}

func initializeManagedWireGuard() {
	if err := captureWireGuardBaseline(); err != nil {
		log.Printf("wireguard baseline unavailable: %v", err)
		return
	}
	set, err := loadManagedWireGuardPeers()
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		log.Printf("wireguard managed state invalid: %v", err)
		return
	}
	if err := replaceManagedWireGuardPeers(snapshots.WireGuardPeerSet{}, set); err != nil {
		log.Printf("wireguard managed peer restore failed: %v", err)
		return
	}
	log.Printf("restored %d managed WireGuard peers", enabledWireGuardPeerCount(set.Peers))
}

func captureWireGuardBaseline() error {
	path := filepath.Join(data, "wireguard-baseline.json")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	output, err := wgCommand("show", managedWireGuardInterface, "peers")
	if err != nil {
		return fmt.Errorf("read %s peers: %w: %s", managedWireGuardInterface, err, strings.TrimSpace(string(output)))
	}
	keys := strings.Fields(string(output))
	sort.Strings(keys)
	body, _ := json.MarshalIndent(wireGuardBaseline{CapturedAt: time.Now().UTC(), PublicKeys: keys}, "", "  ")
	return atomicCertificateWrite(path, body, 0600)
}

func applyWireGuardPeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var next snapshots.WireGuardPeerSet
	if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
		http.Error(w, "invalid wireguard peer set", http.StatusBadRequest)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if err := snapshots.VerifyWireGuardPeerSet(next, pub, time.Now(), seen); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	protected, err := loadWireGuardProtectedKeys()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, peer := range next.Peers {
		if protected[peer.PublicKey] {
			http.Error(w, "managed peer conflicts with protected baseline", http.StatusConflict)
			return
		}
	}
	previous, err := loadManagedWireGuardPeers()
	if errors.Is(err, os.ErrNotExist) {
		previous = snapshots.WireGuardPeerSet{}
	} else if err != nil {
		http.Error(w, "managed wireguard state invalid", http.StatusInternalServerError)
		return
	}
	if err := ensureWireGuardAddressAvailability(previous, next, protected); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err := replaceManagedWireGuardPeers(previous, next); err != nil {
		_ = replaceManagedWireGuardPeers(next, previous)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	body, _ := json.MarshalIndent(next, "", "  ")
	if err := atomicCertificateWrite(filepath.Join(data, "wireguard-managed.json"), body, 0600); err != nil {
		_ = replaceManagedWireGuardPeers(next, previous)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeEdgeJSON(w, map[string]any{"ok": true, "managed_peers": enabledWireGuardPeerCount(next.Peers), "sha256": next.SHA256})
}

func wireGuardStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	publicKey, keyErr := wgCommand("show", managedWireGuardInterface, "public-key")
	listenPort, portErr := wgCommand("show", managedWireGuardInterface, "listen-port")
	baseline, baselineErr := loadWireGuardBaseline()
	managed, managedErr := loadManagedWireGuardPeers()
	if keyErr != nil || portErr != nil || baselineErr != nil || (managedErr != nil && !errors.Is(managedErr, os.ErrNotExist)) {
		http.Error(w, "wireguard status unavailable", http.StatusServiceUnavailable)
		return
	}
	port, _ := strconv.Atoi(strings.TrimSpace(string(listenPort)))
	runtime := wireGuardManagedRuntime(managed)
	writeEdgeJSON(w, map[string]any{
		"interface":       managedWireGuardInterface,
		"public_key":      strings.TrimSpace(string(publicKey)),
		"listen_port":     port,
		"protected_peers": len(baseline.PublicKeys),
		"managed_peers":   enabledWireGuardPeerCount(managed.Peers),
		"peers":           runtime,
		"applied_sha256":  managed.SHA256,
	})
}

func wireGuardManagedRuntime(managed snapshots.WireGuardPeerSet) []map[string]any {
	output, err := wgCommand("show", managedWireGuardInterface, "dump")
	stats := map[string][]string{}
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, line := range lines[1:] {
			fields := strings.Split(line, "\t")
			if len(fields) >= 8 {
				stats[fields[0]] = fields
			}
		}
	}
	result := make([]map[string]any, 0, len(managed.Peers))
	for _, peer := range managed.Peers {
		if !peer.Enabled {
			continue
		}
		item := map[string]any{"id": peer.ID, "node_id": peer.NodeID, "name": peer.Name, "address": peer.Address, "online": false, "rx_bytes": int64(0), "tx_bytes": int64(0)}
		if fields := stats[peer.PublicKey]; len(fields) >= 8 {
			handshake, _ := strconv.ParseInt(fields[5], 10, 64)
			rx, _ := strconv.ParseInt(fields[6], 10, 64)
			tx, _ := strconv.ParseInt(fields[7], 10, 64)
			item["latest_handshake"] = handshake
			item["online"] = handshake > 0 && time.Since(time.Unix(handshake, 0)) < 3*time.Minute
			item["rx_bytes"], item["tx_bytes"] = rx, tx
		}
		result = append(result, item)
	}
	return result
}

func loadWireGuardBaseline() (wireGuardBaseline, error) {
	var baseline wireGuardBaseline
	body, err := os.ReadFile(filepath.Join(data, "wireguard-baseline.json"))
	if err != nil {
		return baseline, err
	}
	if err := json.Unmarshal(body, &baseline); err != nil {
		return baseline, err
	}
	return baseline, nil
}

func loadWireGuardProtectedKeys() (map[string]bool, error) {
	baseline, err := loadWireGuardBaseline()
	if err != nil {
		return nil, err
	}
	protected := make(map[string]bool, len(baseline.PublicKeys))
	for _, key := range baseline.PublicKeys {
		protected[key] = true
	}
	return protected, nil
}

func loadManagedWireGuardPeers() (snapshots.WireGuardPeerSet, error) {
	var set snapshots.WireGuardPeerSet
	body, err := os.ReadFile(filepath.Join(data, "wireguard-managed.json"))
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return set, err
	}
	if err := snapshots.ValidateWireGuardPeers(set.Peers); err != nil {
		return set, err
	}
	return set, nil
}

func ensureWireGuardAddressAvailability(previous, next snapshots.WireGuardPeerSet, protected map[string]bool) error {
	managed := map[string]bool{}
	for _, peer := range previous.Peers {
		managed[peer.PublicKey] = true
	}
	output, err := wgCommand("show", managedWireGuardInterface, "allowed-ips")
	if err != nil {
		return fmt.Errorf("read wireguard routes: %w", err)
	}
	var occupied []*net.IPNet
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || (managed[fields[0]] && !protected[fields[0]]) {
			continue
		}
		for _, value := range strings.Split(fields[1], ",") {
			_, network, parseErr := net.ParseCIDR(value)
			if parseErr == nil {
				occupied = append(occupied, network)
			}
		}
	}
	for _, peer := range next.Peers {
		if !peer.Enabled {
			continue
		}
		for _, value := range append([]string{peer.Address}, peer.AllowedIPs...) {
			ip, network, _ := net.ParseCIDR(value)
			for _, existing := range occupied {
				if existing.Contains(ip) || network.Contains(existing.IP) {
					return fmt.Errorf("wireguard route %s overlaps an existing unmanaged route", value)
				}
			}
		}
	}
	return nil
}

func replaceManagedWireGuardPeers(previous, next snapshots.WireGuardPeerSet) error {
	old := map[string]snapshots.WireGuardPeer{}
	newPeers := map[string]snapshots.WireGuardPeer{}
	for _, peer := range previous.Peers {
		if peer.Enabled {
			old[peer.PublicKey] = peer
		}
	}
	for _, peer := range next.Peers {
		if peer.Enabled {
			newPeers[peer.PublicKey] = peer
		}
	}
	for key := range old {
		if _, retained := newPeers[key]; retained {
			continue
		}
		if output, err := wgCommand("set", managedWireGuardInterface, "peer", key, "remove"); err != nil {
			return fmt.Errorf("remove managed wireguard peer: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	keys := make([]string, 0, len(newPeers))
	for key := range newPeers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		peer := newPeers[key]
		allowed := uniqueWireGuardCIDRs(append([]string{peer.Address}, peer.AllowedIPs...))
		args := []string{"set", managedWireGuardInterface, "peer", key, "allowed-ips", strings.Join(allowed, ",")}
		if peer.Keepalive > 0 {
			args = append(args, "persistent-keepalive", strconv.Itoa(peer.Keepalive))
		}
		if output, err := wgCommand(args...); err != nil {
			return fmt.Errorf("apply managed wireguard peer: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	return nil
}

func uniqueWireGuardCIDRs(values []string) []string {
	seenValues := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seenValues[value] {
			seenValues[value] = true
			result = append(result, value)
		}
	}
	return result
}

func enabledWireGuardPeerCount(peers []snapshots.WireGuardPeer) int {
	count := 0
	for _, peer := range peers {
		if peer.Enabled {
			count++
		}
	}
	return count
}

func writeEdgeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
