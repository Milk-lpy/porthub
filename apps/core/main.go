package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var priv ed25519.PrivateKey
var dataDir string
var edgeURL string
var caPath string
var frontendDir string
var trafficRetentionDays int
var backupDir string
var edgePublicIPv4 string
var edgePublicIPv6 string

func main() {
	listen := flag.String("listen", ":9443", "")
	data := flag.String("data", "/var/lib/porthub/core", "")
	flag.StringVar(&edgeURL, "edge-url", "https://10.255.0.1:9443", "")
	flag.StringVar(&caPath, "ca", "/var/lib/porthub/core/ca.crt", "")
	flag.StringVar(&frontendDir, "frontend-dir", "", "")
	flag.IntVar(&trafficRetentionDays, "traffic-retention-days", 30, "")
	flag.StringVar(&backupDir, "backup-dir", "/var/backups/porthub", "")
	flag.IntVar(&backupRetention, "backup-retention", 14, "number of scheduled Core backups to retain")
	flag.IntVar(&backupHourUTC, "backup-hour-utc", 3, "daily backup hour in UTC")
	flag.StringVar(&edgePublicIPv4, "edge-public-ipv4", "", "Edge public IPv4 used by DDNS records")
	flag.StringVar(&edgePublicIPv6, "edge-public-ipv6", "", "Edge public IPv6 used by DDNS records")
	flag.StringVar(&updateManifestURL, "update-manifest-url", "", "signed PortHub update manifest URL")
	flag.StringVar(&updatePublicKeyPath, "update-public-key", "/etc/porthub/update-signing.pub", "Ed25519 update signing public key")
	flag.StringVar(&updateStageDir, "update-stage-dir", "/var/lib/porthub/updates", "verified update staging directory")
	flag.StringVar(&acmeDirectoryURL, "acme-directory-url", acmeDirectoryURL, "ACME directory URL")
	flag.StringVar(&acmeAccountEmail, "acme-email", "", "ACME account contact email")
	lanInterface := flag.String("lan-interface", "auto", "LAN interface used for managed forwarding")
	lanCIDRs := flag.String("lan-cidrs", "192.0.2.0/24", "comma-separated managed LAN networks")
	tunnelCIDRs := flag.String("tunnel-cidrs", "10.255.0.0/24", "comma-separated PortHub tunnel networks")
	allowSourcePreserve := flag.Bool("allow-source-preserve", false, "allow mappings that require externally managed return routes")
	flag.StringVar(&netdSocket, "netd-socket", "/run/porthub/netd.sock", "PortHub netd unix socket")
	flag.Parse()
	dataDir = *data
	if err := configureCoreForward(*lanInterface, *lanCIDRs, *tunnelCIDRs); err != nil {
		log.Fatal(err)
	}
	coreForwardConfig.AllowSourcePreserve = *allowSourcePreserve

	if err := os.MkdirAll(*data, 0700); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(updateStageDir, 0750); err != nil {
		log.Fatal(err)
	}
	var err error
	db, err = sql.Open("sqlite3", *data+"/core.db?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		log.Fatal(err)
	}
	// Ensure the database file is not world-readable regardless of process umask.
	_ = os.Chmod(filepath.Join(*data, "core.db"), 0600)
	initDB(*data)
	resumeLanScan()
	go trafficCollector(60 * time.Second)
	go backupScheduler()
	go ddnsScheduler(time.Minute)
	go ipFeedScheduler(10 * time.Minute)
	go acmeRenewalScheduler(6 * time.Hour)
	go lanScanScheduler(6 * time.Hour)

	mux := http.NewServeMux()
	registerRoutes(mux)
	log.Println("porthub-core", *listen)
	agentCAPEM, err := os.ReadFile(*data + "/agent-ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	agentPool := x509.NewCertPool()
	if !agentPool.AppendCertsFromPEM(agentCAPEM) {
		log.Fatal("invalid agent ca certificate")
	}
	server := &http.Server{Addr: *listen, Handler: mux, TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: agentPool,
	}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(server.ListenAndServeTLS(*data+"/tls.crt", *data+"/tls.key"))
}
