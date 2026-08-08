package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	// Default to loopback: Core polls its local agent at 127.0.0.1:9731 and
	// remote agents push heartbeats to Core over mTLS, so the agent API never
	// needs a public/LAN-facing bind. The status/discovery endpoints are
	// unauthenticated, so a wildcard bind would leak host and topology data.
	// Override with -listen only for an explicitly authenticated deployment.
	listen := flag.String("listen", "127.0.0.1:9731", "listen address")
	configPath := flag.String("config", "", "optional JSON config path")
	flag.Parse()

	cfg, err := loadConfig(*configPath, *listen)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"status": "ok", "component": "agent"})
	})
	mux.HandleFunc("/api/agent/status", status)
	mux.HandleFunc("/api/agent/discovery", discovery)
	registerTaskHandlers(mux, cfg)
	if cfg.CoreURL != "" {
		go runReporter(cfg)
	}
	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
