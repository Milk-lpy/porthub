package main

import (
	"net/http"
	"testing"
)

func TestManagedServicePermissionsAndAllowlists(t *testing.T) {
	if !roleAllowed("readonly", http.MethodGet, "/api/managed-services") {
		t.Fatal("readonly users should be able to inspect managed service status")
	}
	if roleAllowed("operator", http.MethodPost, "/api/managed-services") {
		t.Fatal("operators must not control host services")
	}
	if !roleAllowed("admin", http.MethodPost, "/api/managed-services") {
		t.Fatal("administrators should be able to control allowlisted host services")
	}
	if !managedServiceAllowlist["qx-lan-socks"] || !managedServiceAllowlist["dst-wireguard"] || managedServiceAllowlist["ssh"] {
		t.Fatalf("unexpected managed service allowlist: %#v", managedServiceAllowlist)
	}
	if managedActionAllowlist["prefer-real-ipv6-gateway"]["stop"] || !managedActionAllowlist["dst-wireguard"]["restart"] {
		t.Fatalf("unexpected managed action allowlist: %#v", managedActionAllowlist)
	}
}
