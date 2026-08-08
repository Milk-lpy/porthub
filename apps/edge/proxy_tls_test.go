package main

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestForwardedProto(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test", nil)
	if forwardedProto(r) != "http" {
		t.Fatal("expected http")
	}
	r.TLS = &tls.ConnectionState{}
	if forwardedProto(r) != "https" {
		t.Fatal("expected https")
	}
}
