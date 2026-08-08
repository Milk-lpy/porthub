//go:build linux

package main

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

func TestDiscoverContainersUsesReadOnlyDockerAPI(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requests := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`[{"Id":"1234567890abcdef","Names":["/nas"],"Image":"example/nas:1","State":"running","Status":"Up","Ports":[{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}],"Labels":{"secret":"must-not-leak"}}]`))
	})}
	go server.Serve(listener)
	defer server.Close()
	old := dockerSocketPath
	dockerSocketPath = socket
	defer func() { dockerSocketPath = old }()
	containers := discoverContainers()
	if request := <-requests; request != "GET /v1.41/containers/json" {
		t.Fatalf("unexpected Docker request %s", request)
	}
	if len(containers) != 1 || containers[0].ID != "1234567890ab" || containers[0].Name != "nas" || len(containers[0].Ports) != 1 || containers[0].Ports[0].PublicPort != 8080 {
		t.Fatalf("unexpected containers: %+v", containers)
	}
}
