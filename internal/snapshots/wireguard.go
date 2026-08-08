package snapshots

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"time"
)

type WireGuardPeer struct {
	ID         int      `json:"id"`
	NodeID     string   `json:"node_id"`
	Name       string   `json:"name"`
	PublicKey  string   `json:"public_key"`
	Address    string   `json:"address"`
	AllowedIPs []string `json:"allowed_ips"`
	Keepalive  int      `json:"persistent_keepalive"`
	Enabled    bool     `json:"enabled"`
}

type WireGuardPeerSet struct {
	Peers     []WireGuardPeer `json:"peers"`
	CreatedAt time.Time       `json:"created_at"`
	Nonce     string          `json:"nonce"`
	SHA256    string          `json:"sha256"`
	Signature string          `json:"signature"`
}

func SignWireGuardPeerSet(set WireGuardPeerSet, privateKey ed25519.PrivateKey) (WireGuardPeerSet, error) {
	if err := ValidateWireGuardPeers(set.Peers); err != nil {
		return set, err
	}
	set.CreatedAt = time.Now().UTC()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return set, err
	}
	set.Nonce = base64.RawURLEncoding.EncodeToString(nonce)
	canonical, _ := canonicalWireGuardPeerSet(set)
	hash := sha256.Sum256(canonical)
	set.SHA256 = hex.EncodeToString(hash[:])
	set.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, hash[:]))
	return set, nil
}

func VerifyWireGuardPeerSet(set WireGuardPeerSet, publicKey ed25519.PublicKey, now time.Time, nonceSeen func(string) bool) error {
	if err := ValidateWireGuardPeers(set.Peers); err != nil {
		return err
	}
	if set.Nonce == "" {
		return errors.New("wireguard peer set replay rejected")
	}
	if set.CreatedAt.After(now.Add(time.Minute)) || set.CreatedAt.Before(now.Add(-5*time.Minute)) {
		return errors.New("wireguard peer set timestamp rejected")
	}
	canonical, _ := canonicalWireGuardPeerSet(set)
	hash := sha256.Sum256(canonical)
	if hex.EncodeToString(hash[:]) != set.SHA256 {
		return errors.New("wireguard peer set hash mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(set.Signature)
	if err != nil || !ed25519.Verify(publicKey, hash[:], signature) {
		return errors.New("wireguard peer set signature invalid")
	}
	// Record/check nonce only after the signature is verified, so invalid
	// payloads cannot burn a legitimate nonce.
	if nonceSeen(set.Nonce) {
		return errors.New("wireguard peer set replay rejected")
	}
	return nil
}

func ValidateWireGuardPeers(peers []WireGuardPeer) error {
	keys, addresses := map[string]bool{}, map[string]bool{}
	type ownedRoute struct {
		owner   string
		network *net.IPNet
	}
	routes := []ownedRoute{}
	for _, peer := range peers {
		if !peer.Enabled {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(peer.PublicKey)
		if err != nil || len(decoded) != 32 || peer.Name == "" {
			return errors.New("invalid wireguard peer identity")
		}
		if keys[peer.PublicKey] {
			return errors.New("duplicate wireguard public key")
		}
		keys[peer.PublicKey] = true
		ip, network, err := net.ParseCIDR(peer.Address)
		if err != nil || !ip.Equal(network.IP) {
			return errors.New("invalid wireguard peer address")
		}
		ones, bits := network.Mask.Size()
		if (bits != 32 || ones != 32) && (bits != 128 || ones != 128) {
			return errors.New("wireguard peer address must identify one host")
		}
		if addresses[peer.Address] {
			return errors.New("duplicate wireguard peer address")
		}
		addresses[peer.Address] = true
		if peer.Keepalive < 0 || peer.Keepalive > 65535 {
			return errors.New("invalid wireguard keepalive")
		}
		for _, allowed := range append([]string{peer.Address}, peer.AllowedIPs...) {
			_, allowedNetwork, err := net.ParseCIDR(allowed)
			if err != nil {
				return errors.New("invalid wireguard allowed IP")
			}
			for _, existing := range routes {
				if existing.owner != peer.PublicKey && networksOverlap(existing.network, allowedNetwork) {
					return errors.New("wireguard peer routes overlap")
				}
			}
			routes = append(routes, ownedRoute{owner: peer.PublicKey, network: allowedNetwork})
		}
	}
	return nil
}

func networksOverlap(left, right *net.IPNet) bool {
	return left.Contains(right.IP) || right.Contains(left.IP)
}

func canonicalWireGuardPeerSet(set WireGuardPeerSet) ([]byte, error) {
	set.SHA256, set.Signature = "", ""
	return json.Marshal(set)
}
