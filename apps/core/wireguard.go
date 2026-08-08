package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"porthub/internal/snapshots"
	"strconv"
	"strings"
	"time"
)

type wireGuardPeerInput struct {
	ID         int      `json:"id"`
	NodeID     string   `json:"node_id"`
	Name       string   `json:"name"`
	PublicKey  string   `json:"public_key"`
	Address    string   `json:"address"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive  int      `json:"persistent_keepalive"`
	Enabled    *bool    `json:"enabled"`
}

func wireGuardPeers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		peers, err := loadWireGuardPeers()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, peers)
	case http.MethodPost:
		var input wireGuardPeerInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "invalid peer", http.StatusBadRequest)
			return
		}
		peer, err := normalizeWireGuardPeer(input, 0)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		now := time.Now().UTC().Format(time.RFC3339)
		allowed, _ := json.Marshal(peer.AllowedIPs)
		result, err := db.Exec(`insert into wireguard_peers(node_id,name,public_key,address,allowed_ips,keepalive,enabled,created_at,updated_at) values(?,?,?,?,?,?,?,?,?)`,
			peer.NodeID, peer.Name, peer.PublicKey, peer.Address, string(allowed), peer.Keepalive, boolInt(peer.Enabled), now, now)
		if err != nil {
			http.Error(w, friendlyWireGuardStoreError(err), http.StatusConflict)
			return
		}
		id, _ := result.LastInsertId()
		peer.ID = int(id)
		audit(actor(r), "wireguard_peer_create", strconv.Itoa(peer.ID))
		writeJSON(w, peer)
	case http.MethodPut:
		var input wireGuardPeerInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.ID < 1 {
			http.Error(w, "peer id required", http.StatusBadRequest)
			return
		}
		peer, err := normalizeWireGuardPeer(input, input.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		allowed, _ := json.Marshal(peer.AllowedIPs)
		result, err := db.Exec(`update wireguard_peers set node_id=?,name=?,public_key=?,address=?,allowed_ips=?,keepalive=?,enabled=?,updated_at=? where id=?`,
			peer.NodeID, peer.Name, peer.PublicKey, peer.Address, string(allowed), peer.Keepalive, boolInt(peer.Enabled), time.Now().UTC().Format(time.RFC3339), peer.ID)
		if err != nil {
			http.Error(w, friendlyWireGuardStoreError(err), http.StatusConflict)
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			http.Error(w, "peer not found", http.StatusNotFound)
			return
		}
		audit(actor(r), "wireguard_peer_update", strconv.Itoa(peer.ID))
		writeJSON(w, peer)
	case http.MethodDelete:
		id, _ := strconv.Atoi(r.URL.Query().Get("id"))
		if id < 1 {
			http.Error(w, "peer id required", http.StatusBadRequest)
			return
		}
		result, err := db.Exec("delete from wireguard_peers where id=?", id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if affected, _ := result.RowsAffected(); affected == 0 {
			http.Error(w, "peer not found", http.StatusNotFound)
			return
		}
		audit(actor(r), "wireguard_peer_delete", strconv.Itoa(id))
		writeJSON(w, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func wireGuardPeersDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	peers, err := loadWireGuardPeers()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	set, err := snapshots.SignWireGuardPeerSet(snapshots.WireGuardPeerSet{Peers: peers}, priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(set)
	client, err := edgeHTTPClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	request, _ := http.NewRequest(http.MethodPost, edgeURL+"/api/wireguard/peers/apply", bytes.NewReader(body))
	request.Header.Set("content-type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		audit(actor(r), "wireguard_peer_deploy_failed", err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode >= 300 {
		detail := strings.TrimSpace(string(responseBody))
		audit(actor(r), "wireguard_peer_deploy_failed", detail)
		http.Error(w, detail, http.StatusBadGateway)
		return
	}
	audit(actor(r), "wireguard_peer_deploy", set.SHA256)
	result, err := decodeJSONMap(responseBody)
	if err != nil {
		result = map[string]any{"ok": true}
	}
	writeJSON(w, result)
}

func wireGuardStatusProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status, err := getEdgeJSON("/api/wireguard/status")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, status)
}

func normalizeWireGuardPeer(input wireGuardPeerInput, excludeID int) (snapshots.WireGuardPeer, error) {
	peer := snapshots.WireGuardPeer{
		ID: input.ID, NodeID: strings.TrimSpace(input.NodeID), Name: strings.TrimSpace(input.Name),
		PublicKey: strings.TrimSpace(input.PublicKey), Address: strings.TrimSpace(input.Address),
		AllowedIPs: normalizeStringList(input.AllowedIPs), Keepalive: input.Keepalive, Enabled: true,
	}
	if input.Enabled != nil {
		peer.Enabled = *input.Enabled
	}
	if peer.Keepalive == 0 {
		peer.Keepalive = 25
	}
	if peer.Address == "" {
		address, err := allocateWireGuardAddress(excludeID)
		if err != nil {
			return peer, err
		}
		peer.Address = address
	}
	if ip := net.ParseIP(peer.Address); ip != nil {
		if ip.To4() != nil {
			peer.Address = ip.String() + "/32"
		} else {
			peer.Address = ip.String() + "/128"
		}
	}
	if err := snapshots.ValidateWireGuardPeers([]snapshots.WireGuardPeer{peer}); err != nil {
		return peer, err
	}
	return peer, nil
}

func allocateWireGuardAddress(excludeID int) (string, error) {
	used := map[uint32]bool{}
	rows, err := db.Query("select id,address from wireguard_peers")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var value string
		if rows.Scan(&id, &value) == nil && id != excludeID {
			ip, _, parseErr := net.ParseCIDR(value)
			if parseErr == nil && ip.To4() != nil {
				used[binary.BigEndian.Uint32(ip.To4())] = true
			}
		}
	}
	for _, network := range coreForwardConfig.TunnelCIDRs {
		baseIP := network.IP.To4()
		if baseIP == nil {
			continue
		}
		base := binary.BigEndian.Uint32(baseIP)
		ones, bits := network.Mask.Size()
		if bits != 32 || ones > 28 {
			continue
		}
		size := uint32(1) << uint32(32-ones)
		for offset := uint32(10); offset < size-1; offset++ {
			candidate := base + offset
			if !used[candidate] {
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, candidate)
				return ip.String() + "/32", nil
			}
		}
	}
	return "", errors.New("no available IPv4 address in the PortHub tunnel network")
}

func loadWireGuardPeers() ([]snapshots.WireGuardPeer, error) {
	rows, err := db.Query(`select id,node_id,name,public_key,address,allowed_ips,keepalive,enabled from wireguard_peers order by id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	peers := []snapshots.WireGuardPeer{}
	for rows.Next() {
		var peer snapshots.WireGuardPeer
		var allowed string
		var enabled int
		if err := rows.Scan(&peer.ID, &peer.NodeID, &peer.Name, &peer.PublicKey, &peer.Address, &allowed, &peer.Keepalive, &enabled); err != nil {
			return nil, err
		}
		peer.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(allowed), &peer.AllowedIPs)
		peers = append(peers, peer)
	}
	return peers, rows.Err()
}

func normalizeStringList(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func friendlyWireGuardStoreError(err error) string {
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "public_key") {
		return "this WireGuard public key already exists"
	}
	if strings.Contains(message, "address") {
		return "this WireGuard address already exists"
	}
	return fmt.Sprintf("save wireguard peer: %v", err)
}
