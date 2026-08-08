package main

import (
	_ "embed"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

//go:embed openapi.yaml
var openAPISpec []byte

func health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": "ok", "component": "core", "time": time.Now().UTC()})
}

func readiness(w http.ResponseWriter, r *http.Request) {
	checks := map[string]bool{"database": false, "netd": false, "wireguard": false}
	checks["database"] = db != nil && db.Ping() == nil
	if _, err := os.Stat(netdSocket); err == nil {
		checks["netd"] = true
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", coreForwardConfig.WGInterface)); err == nil {
		checks["wireguard"] = true
	}
	ready := checks["database"] && checks["netd"] && checks["wireguard"]
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	writeJSON(w, map[string]any{"ready": ready, "checks": checks})
}

func openAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/yaml; charset=utf-8")
	_, _ = w.Write(openAPISpec)
}
