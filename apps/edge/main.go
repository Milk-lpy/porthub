package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"porthub/internal/nftables"
	"porthub/internal/snapshots"
	"strings"
	"sync"
	"time"
)

var data string
var pub ed25519.PublicKey
var mu sync.Mutex

// nonceMu guards the nonces map and its persistence. It is intentionally a
// separate lock from mu: seen() is invoked from snapshot/certificate/wireguard
// verification that already runs while the caller holds mu, so reusing mu here
// would deadlock (Go's sync.Mutex is not reentrant). A dedicated lock lets
// seen() serialize all nonce access without touching mu.
var nonceMu sync.Mutex
var last int64
var nonces = map[string]time.Time{}
var current snapshots.Snapshot

// nonceFile persists seen nonces across restarts so a captured snapshot
// cannot be replayed against a freshly started edge (the in-memory map
// alone would forget everything on reboot).
const nonceFile = "/var/lib/porthub/edge/nonces.json"

func main() {
	listen := flag.String("listen", ":9443", "")
	proxyListen := flag.String("proxy-listen", ":18090", "")
	httpsProxyListen := flag.String("https-proxy-listen", ":18443", "")
	httpsProxyCert := flag.String("https-proxy-cert", "/etc/porthub/edge.crt", "")
	httpsProxyKey := flag.String("https-proxy-key", "/etc/porthub/edge.key", "")
	flag.StringVar(&proxyHTTPSPort, "https-public-port", "18443", "public HTTPS proxy port used for redirects")
	flag.StringVar(&data, "data", "/var/lib/porthub/edge", "")
	flag.StringVar(&edgeNetdSocket, "netd-socket", "/run/porthub/edge-netd.sock", "PortHub Edge netd Unix socket")
	pubPath := flag.String("core-pub", "/etc/porthub/core-ed25519.pub", "")
	flag.Parse()
	if err := os.MkdirAll(filepath.Join(data, "netd"), 0750); err != nil {
		log.Fatal(err)
	}
	b, err := os.ReadFile(*pubPath)
	if err != nil {
		log.Fatal(err)
	}
	pk, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		log.Fatal(err)
	}
	pub = ed25519.PublicKey(pk)
	loadLast()
	restoreCurrentNFT()
	loadACMEChallenges()
	initializeManagedWireGuard()
	go serveHTTPProxy(*proxyListen)
	go serveHTTPSProxy(*httpsProxyListen, *httpsProxyCert, *httpsProxyKey)
	go startProxyHealthChecks(20 * time.Second)
	go scheduledACLRefresh()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "component": "edge", "version": last})
	})
	mux.HandleFunc("/api/apply", apply)
	mux.HandleFunc("/api/status", status)
	mux.HandleFunc("/api/metrics", metrics)
	mux.HandleFunc("/api/port-usage", portUsage)
	mux.HandleFunc("/api/proxy-health", proxyHealth)
	mux.HandleFunc("/api/certificates/apply", applyCertificateBundle)
	mux.HandleFunc("/api/acme/challenges/apply", applyACMEChallenges)
	mux.HandleFunc("/api/wireguard/peers/apply", applyWireGuardPeers)
	mux.HandleFunc("/api/wireguard/status", wireGuardStatus)
	mux.HandleFunc("/api/rollback", rollback)
	log.Println("porthub-edge", *listen)
	ca, err := os.ReadFile("/etc/porthub/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		log.Fatal("invalid client ca")
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		TLSConfig:         &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServeTLS("/etc/porthub/edge.crt", "/etc/porthub/edge.key"))
}
func loadLast() {
	b, _ := os.ReadFile(filepath.Join(data, "current.json"))
	var s snapshots.Snapshot
	if json.Unmarshal(b, &s) == nil {
		last = s.Version
		current = s
	}
}

func restoreCurrentNFT() {
	path := filepath.Join(data, "current.nft")
	rules, err := os.ReadFile(path)
	if err != nil {
		return
	}
	if !containsOwnTable(rules) {
		log.Println("skip nft restore: current.nft does not contain PortHub table")
		return
	}
	temporary, err := writeNFTCandidate("restore.nft", rules)
	if err != nil {
		log.Println("skip nft restore:", err)
		return
	}
	if err := edgeNetdApplyNFT(temporary); err != nil {
		log.Println("skip nft restore: apply failed:", err)
		return
	}
	log.Println("restored current PortHub nft rules")
}

func writeNFTCandidate(name string, rules []byte) (string, error) {
	path := filepath.Join(data, "netd", name)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, rules, 0640); err != nil {
		return "", err
	}
	if err := os.Chmod(temporary, 0640); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, path); err != nil {
		return "", err
	}
	return path, nil
}

func containsOwnTable(rules []byte) bool {
	return strings.Contains(string(rules), "table inet porthub")
}
func seen(n string) bool {
	// 加载/清理: 启动时从磁盘恢复, 运行中定期清理超过 1 小时的 nonce.
	// All access to the nonces map is serialized under nonceMu, and a new
	// nonce is persisted synchronously before we return so a crash/restart
	// cannot forget it and allow a replay.
	nonceMu.Lock()
	defer nonceMu.Unlock()
	if len(nonces) == 0 {
		loadNoncesLocked()
	}
	if _, ok := nonces[n]; ok {
		return true
	}
	nonces[n] = time.Now()
	persistNoncesLocked()
	if len(nonces)%64 == 0 {
		sweepNoncesLocked()
	}
	return false
}

// loadNoncesLocked restores persisted nonces. Callers must hold nonceMu.
func loadNoncesLocked() {
	raw, err := os.ReadFile(nonceFile)
	if err != nil {
		return
	}
	var stored map[string]time.Time
	if json.Unmarshal(raw, &stored) != nil {
		return
	}
	now := time.Now()
	for k, v := range stored {
		if now.Sub(v) < time.Hour {
			nonces[k] = v
		}
	}
}

// persistNoncesLocked writes the nonce set to disk atomically (temp + rename)
// so a crash mid-write cannot corrupt the file. Callers must hold nonceMu.
func persistNoncesLocked() {
	os.MkdirAll(filepath.Dir(nonceFile), 0700)
	raw, _ := json.Marshal(nonces)
	tmp := nonceFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return
	}
	if err := os.Rename(tmp, nonceFile); err != nil {
		os.Remove(tmp)
	}
}

// sweepNoncesLocked evicts nonces older than one hour. Callers must hold
// nonceMu. It persists the pruned set so the on-disk copy stays bounded.
func sweepNoncesLocked() {
	now := time.Now()
	for k, v := range nonces {
		if now.Sub(v) > time.Hour {
			delete(nonces, k)
		}
	}
	persistNoncesLocked()
}
func apply(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	var s snapshots.Snapshot
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := snapshots.Verify(s, pub, last, seen); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	rules, err := nftables.Compile(s, "wg-porthub")
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	tmp, err := writeNFTCandidate("candidate.nft", []byte(rules))
	if err != nil {
		http.Error(w, "cannot stage nft candidate", http.StatusInternalServerError)
		return
	}
	prev, _ := os.ReadFile(filepath.Join(data, "current.json"))
	if len(prev) > 0 {
		os.WriteFile(filepath.Join(data, "previous.json"), prev, 0600)
	}
	if err := edgeNetdApplyNFT(tmp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	os.WriteFile(filepath.Join(data, "current.json"), b, 0600)
	os.WriteFile(filepath.Join(data, "current.nft"), []byte(rules), 0600)
	last = s.Version
	current = s
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": last})
}
func rollback(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	b, err := os.ReadFile(filepath.Join(data, "previous.json"))
	if err != nil {
		http.Error(w, "no previous", 404)
		return
	}
	var s snapshots.Snapshot
	json.Unmarshal(b, &s)
	rules, _ := nftables.Compile(s, "wg-porthub")
	tmp, err := writeNFTCandidate("rollback.nft", []byte(rules))
	if err != nil {
		http.Error(w, "cannot stage rollback", http.StatusInternalServerError)
		return
	}
	if err := edgeNetdApplyNFT(tmp); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	os.WriteFile(filepath.Join(data, "current.json"), b, 0600)
	last = s.Version
	current = s
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "version": last})
}
func status(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{"role": "edge", "last_version": last, "time": time.Now()})
}
